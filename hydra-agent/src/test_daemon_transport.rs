//! Real local transport fixtures: Unix sockets or same-process Windows named pipes.
//! Protocol scripts stay identical; the production Windows client still authenticates the server.

use std::path::{Path, PathBuf};

#[cfg(unix)]
pub(crate) use tokio::net::UnixListener as AsyncListener;

#[cfg(windows)]
pub(crate) struct AsyncListener {
    path: PathBuf,
    pending: tokio::sync::Mutex<tokio::net::windows::named_pipe::NamedPipeServer>,
}

#[cfg(windows)]
impl AsyncListener {
    pub(crate) fn bind(path: &Path) -> std::io::Result<Self> {
        use tokio::net::windows::named_pipe::ServerOptions;
        Ok(Self {
            path: path.to_owned(),
            pending: tokio::sync::Mutex::new(
                ServerOptions::new()
                    .first_pipe_instance(true)
                    .reject_remote_clients(true)
                    .create(path)?,
            ),
        })
    }

    pub(crate) async fn accept(
        &self,
    ) -> std::io::Result<(tokio::net::windows::named_pipe::NamedPipeServer, ())> {
        use tokio::{io::AsyncReadExt, net::windows::named_pipe::ServerOptions};
        let mut pending = self.pending.lock().await;
        pending.connect().await?;
        let next = ServerOptions::new()
            .reject_remote_clients(true)
            .create(&self.path)?;
        let mut accepted = std::mem::replace(&mut *pending, next);
        drop(pending);
        let mut prelude = [0u8; 1];
        accepted.read_exact(&mut prelude).await?;
        assert_eq!(prelude, *b"\n", "Windows client authentication prelude");
        Ok((accepted, ()))
    }
}

pub(crate) fn endpoint(directory: &Path, name: &str) -> PathBuf {
    #[cfg(unix)]
    {
        directory.join(name)
    }
    #[cfg(windows)]
    {
        use std::hash::{Hash, Hasher};
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        directory.hash(&mut hash);
        name.hash(&mut hash);
        PathBuf::from(format!(
            r"\\.\pipe\Hydra.Maestro.remote-test-{}-{:016x}",
            std::process::id(),
            hash.finish()
        ))
    }
}

#[cfg(unix)]
pub(crate) use std::os::unix::net::UnixListener as Listener;
#[cfg(windows)]
pub(crate) use windows::Listener;

#[cfg(windows)]
mod windows {
    use std::cell::Cell;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        ERROR_BROKEN_PIPE, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
        INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, PIPE_NOWAIT,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    };

    pub(crate) struct Listener {
        file: Mutex<File>,
        path: PathBuf,
        nonblocking: Cell<bool>,
    }
    pub(crate) struct Stream {
        file: File,
        read_timeout: Arc<Mutex<Duration>>,
    }

    impl Listener {
        pub(crate) fn bind(path: &Path) -> io::Result<Self> {
            Self::create(path, true)
        }
        fn create(path: &Path, first: bool) -> io::Result<Self> {
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            // Fresh first-instance local endpoint. Default DACL belongs to this test process's
            // token; the actual client independently verifies the creating process and token.
            let raw = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    PIPE_ACCESS_DUPLEX
                        | if first {
                            FILE_FLAG_FIRST_PIPE_INSTANCE
                        } else {
                            0
                        },
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    255,
                    65536,
                    65536,
                    0,
                    std::ptr::null(),
                )
            };
            if raw == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: the successful call transferred one owned synchronous server handle.
            Ok(Self {
                file: Mutex::new(unsafe { File::from_raw_handle(raw) }),
                path: path.to_owned(),
                nonblocking: Cell::new(false),
            })
        }

        pub(crate) fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
            self.nonblocking.set(enabled);
            Ok(())
        }

        pub(crate) fn accept(&self) -> io::Result<(Stream, ())> {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match self.try_accept() {
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock && !self.nonblocking.get() => {
                    }
                    result => return result,
                }
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }

        fn try_accept(&self) -> io::Result<(Stream, ())> {
            let mut pending = self.file.lock().unwrap();
            // PIPE_NOWAIT makes this probe nonblocking, including the no-connect assertions.
            let connected =
                unsafe { ConnectNamedPipe(pending.as_raw_handle(), std::ptr::null_mut()) };
            if connected == 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error().map(|value| value as u32) {
                    Some(ERROR_PIPE_CONNECTED) => {}
                    Some(ERROR_PIPE_LISTENING) => return Err(io::ErrorKind::WouldBlock.into()),
                    Some(ERROR_NO_DATA) => {
                        // A probe can connect and close before this nonblocking accept. That
                        // closed instance cannot accept again; keep the endpoint published by
                        // replacing it before releasing the old handle, just as after accept.
                        *pending = Self::create(&self.path, false)?.file.into_inner().unwrap();
                        return Err(io::ErrorKind::WouldBlock.into());
                    }
                    _ => return Err(error),
                }
            }
            let mut client_pid = 0;
            // In PIPE_NOWAIT mode a successful ConnectNamedPipe may merely make the instance
            // available. Only hand the stream to the script once a client is actually attached.
            if unsafe { GetNamedPipeClientProcessId(pending.as_raw_handle(), &mut client_pid) } == 0
                || client_pid == 0
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let mut stream = Stream {
                file: pending.try_clone()?,
                read_timeout: Arc::new(Mutex::new(Duration::from_secs(10))),
            };
            // Reserve the next instance even if this client closes during the prelude.
            *pending = Self::create(&self.path, false)?.file.into_inner().unwrap();
            drop(pending);
            // Production Windows clients send this byte before JSON to establish the server's
            // impersonation identity. Assert exactly one prelude, never skip arbitrary frames.
            let mut prelude = [0u8; 1];
            if let Err(error) = stream.read_exact(&mut prelude) {
                return Err(match error.kind() {
                    io::ErrorKind::UnexpectedEof
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::ConnectionReset => io::ErrorKind::WouldBlock.into(),
                    _ => error,
                });
            }
            assert_eq!(prelude, *b"\n", "Windows client authentication prelude");
            Ok((stream, ()))
        }
    }

    impl Stream {
        pub(crate) fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
            assert!(!enabled, "fixture uses bounded blocking reads");
            Ok(())
        }
        pub(crate) fn try_clone(&self) -> io::Result<Self> {
            Ok(Self {
                file: self.file.try_clone()?,
                read_timeout: Arc::clone(&self.read_timeout),
            })
        }
    }

    impl Read for Stream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if bytes.is_empty() {
                return Ok(0);
            }
            let deadline = Instant::now() + *self.read_timeout.lock().unwrap();
            loop {
                let mut count = 0;
                // Use the synchronous pipe API directly: File is a regular-file abstraction and
                // may perform offset/EOF handling unsuitable for a PIPE_NOWAIT byte stream.
                let result = unsafe {
                    ReadFile(
                        self.file.as_raw_handle(),
                        bytes.as_mut_ptr(),
                        bytes.len().min(u32::MAX as usize) as u32,
                        &mut count,
                        std::ptr::null_mut(),
                    )
                };
                if result != 0 && count != 0 {
                    return Ok(count as usize);
                }
                if result == 0 {
                    let error = io::Error::last_os_error();
                    match error.raw_os_error().map(|value| value as u32) {
                        Some(ERROR_NO_DATA) => {}
                        Some(ERROR_BROKEN_PIPE) => return Ok(0),
                        _ => return Err(error),
                    }
                }
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    }

    impl Write for Stream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.is_empty() {
                return Ok(0);
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let mut count = 0;
                let result = unsafe {
                    WriteFile(
                        self.file.as_raw_handle(),
                        bytes.as_ptr(),
                        bytes.len().min(u32::MAX as usize) as u32,
                        &mut count,
                        std::ptr::null_mut(),
                    )
                };
                if result == 0 {
                    return Err(io::Error::last_os_error());
                }
                if count != 0 {
                    return Ok(count as usize);
                }
                if Instant::now() >= deadline {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        // File::flush maps to FlushFileBuffers, which waits for the peer to consume data and
        // can deadlock a request/reply test. Unbuffered WriteFile needs no user-space flush.
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;

        fn client(path: &Path) -> File {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match File::options().read(true).write(true).open(path) {
                    Ok(file) => return file,
                    Err(error)
                        if error.raw_os_error() == Some(ERROR_PIPE_BUSY as i32)
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("fixture client connect: {error}"),
                }
            }
        }

        #[test]
        fn disconnected_probe_before_accept_does_not_poison_next_connection() {
            let path = super::super::endpoint(&std::env::temp_dir(), "closed-before-accept");
            let listener = Listener::bind(&path).unwrap();
            listener.set_nonblocking(true).unwrap();
            drop(client(&path));
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
            );

            listener.set_nonblocking(false).unwrap();
            let peer = std::thread::spawn(move || {
                let mut client = client(&path);
                client.write_all(b"\nrequest").unwrap();
                let mut reply = [0; 5];
                client.read_exact(&mut reply).unwrap();
                assert_eq!(&reply, b"reply");
            });
            let (mut accepted, ()) = listener.accept().unwrap();
            let mut request = [0; 7];
            accepted.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"request");
            accepted.write_all(b"reply").unwrap();
            peer.join().unwrap();
        }

        #[test]
        fn disconnected_probe_during_prelude_does_not_poison_next_connection() {
            let path = super::super::endpoint(&std::env::temp_dir(), "closed-during-prelude");
            let listener = Listener::bind(&path).unwrap();
            let abandoned = client(&path);
            let acceptor = std::thread::spawn(move || {
                let (mut stream, ()) = listener.accept().unwrap();
                let mut request = [0; 7];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(&request, b"request");
                stream.write_all(b"reply").unwrap();
                let mut consumed = [0; 4];
                stream.read_exact(&mut consumed).unwrap();
                assert_eq!(&consumed, b"done");
            });
            // The second client can open only after accept has reserved the next instance,
            // while the first stream is still waiting for its authentication prelude.
            let mut next = client(&path);
            drop(abandoned);
            next.write_all(b"\nrequest").unwrap();
            let mut reply = [0; 5];
            next.read_exact(&mut reply).unwrap();
            assert_eq!(&reply, b"reply");
            next.write_all(b"done").unwrap();
            acceptor.join().unwrap();
        }
    }
}
