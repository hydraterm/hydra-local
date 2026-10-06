//! Real local transport fixtures: Unix sockets or same-process Windows named pipes.
//! Protocol scripts stay identical; the production Windows client still authenticates the server.

use std::path::{Path, PathBuf};

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
            r"\\.\pipe\Hydra.Maestro.renderer-test-{}-{:016x}",
            std::process::id(),
            hash.finish()
        ))
    }
}

#[cfg(unix)]
pub(crate) use std::os::unix::net::{UnixListener as Listener, UnixStream as Stream};
#[cfg(windows)]
pub(crate) use windows::{Listener, Stream};

/// An actual authenticated connection for owner-loop tests that intentionally keep outbound
/// protocol requests in a drainable queue. The server must live as long as the client witness.
#[cfg(windows)]
pub(crate) fn authenticated_pair() -> std::io::Result<(maestro_shell::WindowsPipeStream, Stream)> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = endpoint(
        Path::new("owner-loop-witness"),
        &NEXT.fetch_add(1, Ordering::Relaxed).to_string(),
    );
    let listener = Listener::bind(&path)?;
    let client = maestro_shell::WindowsPipeStream::connect_until(
        &path,
        std::time::Instant::now() + std::time::Duration::from_secs(3),
    )?;
    let (server, _) = listener.accept()?;
    Ok((client, server))
}

pub(crate) fn replace_listener(path: &Path) -> std::io::Result<Listener> {
    #[cfg(unix)]
    {
        std::fs::remove_file(path)?;
        Listener::bind(path)
    }
    #[cfg(windows)]
    {
        Listener::additional_instance(path)
    }
}

#[cfg(windows)]
mod windows {
    use std::cell::Cell;
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
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
        file: File,
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
        pub(crate) fn additional_instance(path: &Path) -> io::Result<Self> {
            Self::create(path, false)
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
                file: unsafe { File::from_raw_handle(raw) },
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
            // PIPE_NOWAIT makes this probe nonblocking, including the no-connect assertions.
            let connected =
                unsafe { ConnectNamedPipe(self.file.as_raw_handle(), std::ptr::null_mut()) };
            if connected == 0 {
                let error = io::Error::last_os_error();
                match error.raw_os_error().map(|value| value as u32) {
                    Some(ERROR_PIPE_CONNECTED) => {}
                    Some(ERROR_PIPE_LISTENING) => return Err(io::ErrorKind::WouldBlock.into()),
                    _ => return Err(error),
                }
            }
            let mut client_pid = 0;
            // In PIPE_NOWAIT mode a successful ConnectNamedPipe may merely make the instance
            // available. Only hand the stream to the script once a client is actually attached.
            if unsafe { GetNamedPipeClientProcessId(self.file.as_raw_handle(), &mut client_pid) }
                == 0
                || client_pid == 0
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let mut stream = Stream {
                file: self.file.try_clone()?,
                read_timeout: Arc::new(Mutex::new(Duration::from_secs(10))),
            };
            // Production Windows clients send this byte before JSON to establish the server's
            // impersonation identity. Assert exactly one prelude, never skip arbitrary frames.
            let mut prelude = [0u8; 1];
            stream.read_exact(&mut prelude)?;
            assert_eq!(prelude, *b"\n", "Windows client authentication prelude");
            Ok((stream, ()))
        }
    }

    impl Stream {
        pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            *self.read_timeout.lock().unwrap() = timeout.unwrap_or(Duration::from_secs(10));
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
}
