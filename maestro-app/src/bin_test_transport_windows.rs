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
    ERROR_PIPE_NOT_CONNECTED, INVALID_HANDLE_VALUE,
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
                    if error.kind() == io::ErrorKind::WouldBlock && !self.nonblocking.get() => {}
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
        let connected = unsafe { ConnectNamedPipe(pending.as_raw_handle(), std::ptr::null_mut()) };
        if connected == 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error().map(|value| value as u32) {
                Some(ERROR_PIPE_CONNECTED) => {}
                Some(ERROR_PIPE_LISTENING) => return Err(io::ErrorKind::WouldBlock.into()),
                Some(ERROR_NO_DATA | ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => {
                    // A connect-only readiness probe may already have closed this instance.
                    *pending = Self::create(&self.path, false)?.file.into_inner().unwrap();
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                _ => return Err(error),
            }
        }
        let mut client_pid = 0;
        // In PIPE_NOWAIT mode a successful ConnectNamedPipe may merely make the instance
        // available. Only hand the stream to the script once a client is actually attached.
        if unsafe { GetNamedPipeClientProcessId(pending.as_raw_handle(), &mut client_pid) } == 0 {
            let error = io::Error::last_os_error();
            match error.raw_os_error().map(|value| value as u32) {
                Some(ERROR_NO_DATA | ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => {
                    *pending = Self::create(&self.path, false)?.file.into_inner().unwrap();
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Some(ERROR_PIPE_LISTENING) => return Err(io::ErrorKind::WouldBlock.into()),
                _ => return Err(error),
            }
        }
        if client_pid == 0 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut stream = Stream {
            file: pending.try_clone()?,
            read_timeout: Arc::new(Mutex::new(Duration::from_secs(10))),
        };
        // Production Windows clients send this byte before JSON to establish the server's
        // impersonation identity. Assert exactly one prelude, never skip arbitrary frames.
        let mut prelude = [0u8; 1];
        if let Err(error) = stream.read_exact(&mut prelude) {
            if error.kind() == io::ErrorKind::UnexpectedEof
                || matches!(
                    error.raw_os_error().map(|value| value as u32),
                    Some(ERROR_NO_DATA | ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED)
                )
            {
                *pending = Self::create(&self.path, false)?.file.into_inner().unwrap();
                return Err(io::ErrorKind::WouldBlock.into());
            }
            return Err(error);
        }
        assert_eq!(prelude, *b"\n", "Windows client authentication prelude");
        // Reserve the next pipe instance before releasing this accepted connection.
        // Unlike a Unix listener, one Windows pipe handle serves only one client.
        *pending = Self::create(&self.path, false)?.file.into_inner().unwrap();
        Ok((stream, ()))
    }
}

impl Stream {
    pub(crate) fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        assert_eq!(how, std::net::Shutdown::Both);
        if unsafe {
            windows_sys::Win32::System::Pipes::DisconnectNamedPipe(self.file.as_raw_handle())
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
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
