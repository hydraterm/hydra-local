//! Real local transport fixtures: Unix sockets or same-process Windows named pipes.
//! Protocol scripts stay identical; the production Windows client still authenticates the server.

use std::path::{Path, PathBuf};

pub(super) fn endpoint(directory: &Path, name: &str) -> PathBuf {
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
            r"\\.\pipe\Hydra.Maestro.app-test-{}-{:016x}",
            std::process::id(),
            hash.finish()
        ))
    }
}

#[cfg(unix)]
pub(super) use std::os::unix::net::{UnixListener as Listener, UnixStream as Stream};
#[cfg(windows)]
pub(super) use windows::{Listener, Stream};

#[cfg(windows)]
mod windows {
    use std::fs::File;
    use std::io::{self, Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
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

    pub(in crate::new_tab) struct Listener(File);
    pub(in crate::new_tab) struct Stream(File);

    impl Listener {
        pub(in crate::new_tab) fn bind(path: &Path) -> io::Result<Self> {
            let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
            // Fresh first-instance local endpoint. Default DACL belongs to this test process's
            // token; the actual client independently verifies the creating process and token.
            let raw = unsafe {
                CreateNamedPipeW(
                    wide.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
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
            Ok(Self(unsafe { File::from_raw_handle(raw) }))
        }

        pub(in crate::new_tab) fn set_nonblocking(&self, enabled: bool) -> io::Result<()> {
            assert!(enabled, "test listener is deliberately nonblocking");
            Ok(())
        }

        pub(in crate::new_tab) fn accept(&self) -> io::Result<(Stream, ())> {
            // PIPE_NOWAIT makes this probe nonblocking, including the no-connect assertions.
            let connected =
                unsafe { ConnectNamedPipe(self.0.as_raw_handle(), std::ptr::null_mut()) };
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
            if unsafe { GetNamedPipeClientProcessId(self.0.as_raw_handle(), &mut client_pid) } == 0
                || client_pid == 0
            {
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let mut stream = Stream(self.0.try_clone()?);
            // Production WindowsPipeStream writes exactly one blank line so the server can
            // acquire the client's impersonation token. Prove that transport prelude once;
            // protocol scripts still require daemon_info as their very first JSON request.
            let mut prelude = [0u8; 1];
            stream.read_exact(&mut prelude)?;
            assert_eq!(prelude, *b"\n", "Windows client authentication prelude");
            Ok((stream, ()))
        }
    }

    impl Stream {
        pub(in crate::new_tab) fn try_clone(&self) -> io::Result<Self> {
            self.0.try_clone().map(Self)
        }
    }

    impl Read for Stream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if bytes.is_empty() {
                return Ok(0);
            }
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let mut count = 0;
                // Use the synchronous pipe API directly: File is a regular-file abstraction and
                // may perform offset/EOF handling unsuitable for a PIPE_NOWAIT byte stream.
                let result = unsafe {
                    ReadFile(
                        self.0.as_raw_handle(),
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
                        self.0.as_raw_handle(),
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
