//! Direct Win32 client transport for Hydra's current-user PTY daemon.
//!
//! Existing DaemonClient operations use this stream instead of a Unix socket on Windows.
//! It is not a general named-pipe API: names are restricted to Hydra's local
//! namespace, the connected server process token must match the caller's user/elevation/integrity
//! authority, and every I/O operation is overlapped, deadline-aware, and cancellation-safe.

use crate::windows_identity::OwnedSid;
use crate::windows_pipe_endpoint::validate_local_pipe_name;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::net::Shutdown;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    DuplicateHandle, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_NO_DATA,
    ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_NOT_CONNECTED, ERROR_SEM_TIMEOUT,
    GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, TokenElevation, TokenIntegrityLevel, TOKEN_ELEVATION,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, OPEN_EXISTING, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcess, OpenProcessToken, SetEvent,
    WaitForMultipleObjects, WaitForSingleObject, INFINITE, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_SYNCHRONIZE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(20);

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

fn owned_handle(handle: HANDLE, operation: &'static str) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(format!(
            "{operation} returned an invalid Windows handle"
        )));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn duplicate_handle(handle: &OwnedHandle) -> io::Result<OwnedHandle> {
    let process = unsafe { GetCurrentProcess() };
    let mut duplicate = null_mut();
    if unsafe {
        DuplicateHandle(
            process,
            raw_handle(handle),
            process,
            &mut duplicate,
            0,
            0,
            windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    owned_handle(duplicate, "DuplicateHandle")
}

fn create_event(manual_reset: bool) -> io::Result<OwnedHandle> {
    owned_handle(
        unsafe { CreateEventW(null(), i32::from(manual_reset), 0, null()) },
        "CreateEventW",
    )
}

fn process_is_alive(process: &OwnedHandle) -> io::Result<bool> {
    match unsafe { WaitForSingleObject(raw_handle(process), 0) } {
        WAIT_TIMEOUT => Ok(true),
        WAIT_OBJECT_0 => Ok(false),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        _ => Err(io::Error::other(
            "unexpected named-pipe server process wait result",
        )),
    }
}

fn duration_millis(duration: Duration, zero_is_zero: bool) -> u32 {
    if duration.is_zero() && zero_is_zero {
        return 0;
    }
    duration.as_millis().max(1).min((u32::MAX - 1) as u128) as u32
}

fn wait_timeout(timeout: Option<Duration>) -> u32 {
    timeout.map_or(INFINITE, |value| duration_millis(value, true))
}

fn open_process_token(process: HANDLE) -> io::Result<OwnedHandle> {
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    owned_handle(token, "OpenProcessToken")
}

struct TokenAuthority {
    user_sid: OwnedSid,
    integrity_sid: OwnedSid,
    elevated: bool,
}

impl TokenAuthority {
    fn from_token(token: HANDLE) -> io::Result<Self> {
        Ok(Self {
            user_sid: OwnedSid::from_token(token)?,
            integrity_sid: token_integrity_sid(token)?,
            elevated: token_is_elevated(token)?,
        })
    }

    fn current_process() -> io::Result<Self> {
        let token = open_process_token(unsafe { GetCurrentProcess() })?;
        Self::from_token(raw_handle(&token))
    }

    fn matches(&self, other: &Self) -> bool {
        (unsafe { EqualSid(self.user_sid.as_ptr(), other.user_sid.as_ptr()) }) != 0
            && self.elevated == other.elevated
            && (unsafe { EqualSid(self.integrity_sid.as_ptr(), other.integrity_sid.as_ptr()) }) != 0
    }
}

fn token_is_elevated(token: HANDLE) -> io::Result<bool> {
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned < size_of::<TOKEN_ELEVATION>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned truncated token elevation information",
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn token_integrity_sid(token: HANDLE) -> io::Result<OwnedSid> {
    let mut needed = 0u32;
    unsafe {
        GetTokenInformation(token, TokenIntegrityLevel, null_mut(), 0, &mut needed);
    }
    if needed < size_of::<TOKEN_MANDATORY_LABEL>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned no token integrity information",
        ));
    }
    let word_count = (needed as usize)
        .checked_add(size_of::<usize>() - 1)
        .and_then(|bytes| bytes.checked_div(size_of::<usize>()))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "token integrity size overflow")
        })?;
    let mut words = vec![0usize; word_count];
    let buffer_bytes = words
        .len()
        .checked_mul(size_of::<usize>())
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "token integrity size overflow")
        })?;
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            words.as_mut_ptr().cast(),
            buffer_bytes,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned < size_of::<TOKEN_MANDATORY_LABEL>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned truncated token integrity information",
        ));
    }
    let label = unsafe { &*(words.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
    OwnedSid::copy_from(
        label.Label.Sid,
        "Windows token did not contain an integrity SID",
    )
}

struct ConnectionState {
    pipe: Mutex<Option<OwnedHandle>>,
    abort_event: OwnedHandle,
    io_reaper: mpsc::Sender<usize>,
    server_process: Arc<OwnedHandle>,
    server_pid: u32,
}

impl ConnectionState {
    fn signal_abort(&self) -> io::Result<()> {
        if unsafe { SetEvent(raw_handle(&self.abort_event)) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn shutdown(&self) -> io::Result<()> {
        // This mutex is also the I/O issuance gate. Once shutdown acquires it, no operation can
        // duplicate the base handle and cross into ReadFile/WriteFile after the abort boundary.
        let mut pipe = self
            .pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let signalled = self.signal_abort();
        // All idle clones share this one base handle. In-flight operations own bounded duplicate
        // handles and release them only after terminal completion, so taking the base gives the
        // daemon EOF as soon as those cancellation reapers finish.
        pipe.take();
        signalled
    }

    fn is_aborted(&self) -> bool {
        (unsafe { WaitForSingleObject(raw_handle(&self.abort_event), 0) }) == WAIT_OBJECT_0
    }

    fn server_is_alive_checked(&self) -> io::Result<bool> {
        process_is_alive(&self.server_process)
    }
}

/// One cloneable byte-stream handle for a single authenticated named-pipe connection.
pub struct WindowsPipeStream {
    state: Arc<ConnectionState>,
    read_timeout: Mutex<Option<Duration>>,
    write_timeout: Mutex<Option<Duration>>,
    #[cfg(test)]
    read_pending_hook: Mutex<Option<mpsc::Sender<()>>>,
}

impl WindowsPipeStream {
    /// Connect before `deadline`, authenticate the server process token, and retain its exact
    /// process handle for the lifetime of every stream clone.
    pub fn connect_until(endpoint: &Path, deadline: Instant) -> io::Result<Self> {
        let name = validate_local_pipe_name(endpoint.as_os_str())?;
        let wide: Vec<u16> = name.encode_wide().chain(std::iter::once(0)).collect();
        let pipe = loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "daemon connect deadline elapsed")
                })?;
            let raw = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    null_mut(),
                )
            };
            if raw != INVALID_HANDLE_VALUE {
                break owned_handle(raw, "CreateFileW")?;
            }
            let error = io::Error::last_os_error();
            match error.raw_os_error().map(|value| value as u32) {
                Some(ERROR_PIPE_BUSY) => {
                    let wait = duration_millis(remaining.min(CONNECT_RETRY_INTERVAL), false);
                    if unsafe { WaitNamedPipeW(wide.as_ptr(), wait) } == 0 {
                        let wait_error = io::Error::last_os_error();
                        match wait_error.raw_os_error().map(|value| value as u32) {
                            Some(ERROR_SEM_TIMEOUT | ERROR_FILE_NOT_FOUND | ERROR_PIPE_BUSY) => {}
                            _ => return Err(wait_error),
                        }
                    }
                }
                Some(ERROR_FILE_NOT_FOUND) => {
                    std::thread::sleep(remaining.min(CONNECT_RETRY_INTERVAL));
                }
                _ => return Err(error),
            }
        };

        let mut server_pid = 0u32;
        if unsafe { GetNamedPipeServerProcessId(raw_handle(&pipe), &mut server_pid) } == 0
            || server_pid == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "named-pipe server process identity was unavailable",
            ));
        }
        let server_process = owned_handle(
            unsafe {
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                    0,
                    server_pid,
                )
            },
            "OpenProcess",
        )
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("could not open named-pipe server process: {error}"),
            )
        })?;
        match process_is_alive(&server_process) {
            Ok(true) => {}
            Ok(false) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "named-pipe server process was not live",
                ));
            }
            Err(error) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("could not query named-pipe server process lifetime: {error}"),
                ));
            }
        }
        let server_token = open_process_token(raw_handle(&server_process)).map_err(|error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("could not inspect named-pipe server token: {error}"),
            )
        })?;
        let expected = TokenAuthority::current_process().map_err(|error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("could not inspect named-pipe client token: {error}"),
            )
        })?;
        let observed = TokenAuthority::from_token(raw_handle(&server_token)).map_err(|error| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("could not read named-pipe server token authority: {error}"),
            )
        })?;
        if !expected.matches(&observed) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "named-pipe server token authority did not match the client",
            ));
        }

        let io_reaper = start_io_reaper()?;
        let mut stream = Self {
            state: Arc::new(ConnectionState {
                pipe: Mutex::new(Some(pipe)),
                abort_event: create_event(true)?,
                io_reaper,
                server_process: Arc::new(server_process),
                server_pid,
            }),
            read_timeout: Mutex::new(None),
            write_timeout: Mutex::new(None),
            #[cfg(test)]
            read_pending_hook: Mutex::new(None),
        };

        // The server must read one byte before Win32 will expose this client's impersonation token.
        // Send a blank protocol line inside the caller's connect budget; the daemon authenticates
        // from that read, replays it, and its framing loop deliberately ignores the empty line.
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "daemon authentication deadline elapsed",
                )
            })?;
        stream.set_write_timeout(Some(remaining))?;
        stream.write_all(b"\n")?;
        stream.set_write_timeout(None)?;
        Ok(stream)
    }

    pub fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            state: self.state.clone(),
            read_timeout: Mutex::new(self.read_timeout()?),
            write_timeout: Mutex::new(self.write_timeout()?),
            #[cfg(test)]
            read_pending_hook: Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn arm_read_pending_probe_for_test(&self) -> mpsc::Receiver<()> {
        let (sender, receiver) = mpsc::channel();
        *self
            .read_pending_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(sender);
        receiver
    }

    #[cfg(test)]
    fn notify_read_pending_for_test(&self) {
        if let Some(sender) = self
            .read_pending_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            let _ = sender.send(());
        }
    }

    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        // Match std socket validation: a zero timeout is not a usable per-operation deadline.
        if timeout.is_some_and(|value| value.is_zero()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero read timeout is invalid",
            ));
        }
        *self
            .read_timeout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = timeout;
        Ok(())
    }

    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        if timeout.is_some_and(|value| value.is_zero()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero write timeout is invalid",
            ));
        }
        *self
            .write_timeout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = timeout;
        Ok(())
    }

    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(*self
            .read_timeout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        Ok(*self
            .write_timeout
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    pub fn shutdown(&self, _how: Shutdown) -> io::Result<()> {
        self.state.shutdown()
    }

    pub fn server_pid(&self) -> u32 {
        self.state.server_pid
    }

    fn wait_for_io(
        &self,
        operation: Box<PendingIo>,
        timeout: Option<Duration>,
    ) -> io::Result<Box<PendingIo>> {
        let handles = [
            raw_handle(&operation.event),
            raw_handle(&self.state.abort_event),
        ];
        let waited = unsafe {
            WaitForMultipleObjects(
                handles.len() as u32,
                handles.as_ptr(),
                0,
                wait_timeout(timeout),
            )
        };
        if waited == WAIT_OBJECT_0 {
            return complete_io(operation);
        }

        let error = if waited == WAIT_OBJECT_0 + 1 {
            io::Error::new(io::ErrorKind::BrokenPipe, "named-pipe connection aborted")
        } else if waited == WAIT_TIMEOUT {
            let _ = self.state.shutdown();
            io::Error::new(io::ErrorKind::TimedOut, "named-pipe I/O deadline elapsed")
        } else if waited == WAIT_FAILED {
            let error = io::Error::last_os_error();
            let _ = self.state.shutdown();
            error
        } else {
            let _ = self.state.shutdown();
            io::Error::other("unexpected named-pipe wait result")
        };
        abandon_io(operation, &self.state.io_reaper);
        Err(error)
    }
}

struct PendingIo {
    handle: OwnedHandle,
    event: OwnedHandle,
    overlapped: OVERLAPPED,
    buffer: Vec<u8>,
    transferred: u32,
}

fn complete_io(mut operation: Box<PendingIo>) -> io::Result<Box<PendingIo>> {
    let mut transferred = 0u32;
    if unsafe {
        GetOverlappedResult(
            raw_handle(&operation.handle),
            &operation.overlapped,
            &mut transferred,
            0,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error().map(|value| value as u32) == Some(ERROR_OPERATION_ABORTED) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "named-pipe I/O aborted",
            ));
        }
        return Err(error);
    }
    operation.transferred = transferred;
    Ok(operation)
}

impl PendingIo {
    fn new(handle: OwnedHandle, buffer: Vec<u8>) -> io::Result<Box<Self>> {
        // Microsoft recommends a manual-reset event for OVERLAPPED synchronization. It also lets
        // the cancellation reaper prove completion without racing an auto-reset consumer.
        let event = create_event(true)?;
        let mut operation = Box::new(Self {
            handle,
            event,
            overlapped: unsafe { std::mem::zeroed() },
            buffer,
            transferred: 0,
        });
        operation.overlapped.hEvent = raw_handle(&operation.event);
        Ok(operation)
    }
}

fn start_io_reaper() -> io::Result<mpsc::Sender<usize>> {
    let (sender, receiver) = mpsc::channel();
    std::thread::Builder::new()
        .name("hydra-pipe-io-reaper".into())
        .spawn(move || {
            while let Ok(operation_pointer) = receiver.recv() {
                // SAFETY: the queue is the only owner after a successful send.
                let operation = unsafe { Box::from_raw(operation_pointer as *mut PendingIo) };
                finish_abandoned_io(operation);
            }
        })
        .map_err(|error| io::Error::other(format!("start named-pipe I/O reaper: {error}")))?;
    Ok(sender)
}

fn abandon_io(operation: Box<PendingIo>, reaper: &mpsc::Sender<usize>) {
    unsafe {
        CancelIoEx(raw_handle(&operation.handle), &operation.overlapped);
    }
    // The allocation, OVERLAPPED, event, duplicate pipe handle, and buffer stay at stable addresses
    // until the connection's prestarted reaper observes terminal kernel completion.
    let operation_pointer = Box::into_raw(operation) as usize;
    if let Err(error) = reaper.send(operation_pointer) {
        // The worker has no normal exit while a sender exists. If it nevertheless disappeared,
        // synchronously reap rather than leak a duplicated pipe authority forever.
        let operation = unsafe { Box::from_raw(error.0 as *mut PendingIo) };
        finish_abandoned_io(operation);
    }
}

fn finish_abandoned_io(operation: Box<PendingIo>) {
    let waited = unsafe { WaitForSingleObject(raw_handle(&operation.event), INFINITE) };
    if waited != WAIT_OBJECT_0 {
        // Without a signalled completion event the kernel may still reference OVERLAPPED and its
        // buffer. Leak the complete operation rather than risk use-after-free.
        std::mem::forget(operation);
        return;
    }
    let mut transferred = 0u32;
    // Event signalling is the kernel's terminal completion proof. The result may report a
    // successful transfer or the expected cancellation error; either way storage is safe to
    // release after this query.
    unsafe {
        GetOverlappedResult(
            raw_handle(&operation.handle),
            &operation.overlapped,
            &mut transferred,
            0,
        );
    }
}

impl Read for WindowsPipeStream {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        if destination.is_empty() {
            return Ok(0);
        }
        // A fallible timeout lookup must finish before the kernel can borrow the I/O allocation.
        let timeout = self.read_timeout()?;
        let size = destination.len().min(u32::MAX as usize);
        let (mut operation, started, immediate_error) = {
            let pipe = self
                .state
                .pipe
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.state.is_aborted() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "named-pipe connection is closed",
                ));
            }
            let pipe = pipe.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "named-pipe connection is closed")
            })?;
            let mut operation = PendingIo::new(duplicate_handle(pipe)?, vec![0u8; size])?;
            let started = unsafe {
                ReadFile(
                    raw_handle(&operation.handle),
                    operation.buffer.as_mut_ptr(),
                    size as u32,
                    null_mut(),
                    &mut operation.overlapped,
                )
            };
            let immediate_error = (started == 0).then(io::Error::last_os_error);
            (operation, started, immediate_error)
        };
        if started == 0 {
            let error = immediate_error.expect("failed ReadFile captured its Windows error");
            match error.raw_os_error().map(|value| value as u32) {
                Some(ERROR_IO_PENDING) => {
                    #[cfg(test)]
                    self.notify_read_pending_for_test();
                    operation = match self.wait_for_io(operation, timeout) {
                        Ok(operation) => operation,
                        Err(error)
                            if matches!(
                                error.raw_os_error().map(|value| value as u32),
                                Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED)
                            ) =>
                        {
                            return Ok(0)
                        }
                        Err(error) => return Err(error),
                    };
                }
                Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED) => return Ok(0),
                _ => return Err(error),
            }
        } else {
            operation = match complete_io(operation) {
                Ok(operation) => operation,
                Err(error)
                    if matches!(
                        error.raw_os_error().map(|value| value as u32),
                        Some(ERROR_BROKEN_PIPE | ERROR_NO_DATA | ERROR_PIPE_NOT_CONNECTED)
                    ) =>
                {
                    return Ok(0)
                }
                Err(error) => return Err(error),
            };
        }
        let read = operation.transferred as usize;
        destination[..read].copy_from_slice(&operation.buffer[..read]);
        Ok(read)
    }
}

impl Write for WindowsPipeStream {
    fn write(&mut self, source: &[u8]) -> io::Result<usize> {
        if source.is_empty() {
            return Ok(0);
        }
        let timeout = self.write_timeout()?;
        let size = source.len().min(u32::MAX as usize);
        let (mut operation, started, immediate_error) = {
            let pipe = self
                .state
                .pipe
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if self.state.is_aborted() || !self.state.server_is_alive_checked()? {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "named-pipe connection is closed",
                ));
            }
            let pipe = pipe.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::BrokenPipe, "named-pipe connection is closed")
            })?;
            let mut operation = PendingIo::new(duplicate_handle(pipe)?, source[..size].to_vec())?;
            let started = unsafe {
                WriteFile(
                    raw_handle(&operation.handle),
                    operation.buffer.as_ptr(),
                    size as u32,
                    null_mut(),
                    &mut operation.overlapped,
                )
            };
            let immediate_error = (started == 0).then(io::Error::last_os_error);
            (operation, started, immediate_error)
        };
        if started == 0 {
            let error = immediate_error.expect("failed WriteFile captured its Windows error");
            if error.raw_os_error().map(|value| value as u32) == Some(ERROR_IO_PENDING) {
                operation = self.wait_for_io(operation, timeout)?;
            } else {
                return Err(error);
            }
        } else {
            operation = complete_io(operation)?;
        }
        Ok(operation.transferred as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod transport_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeout_conversion_preserves_infinite_and_zero_meanings() {
        assert_eq!(wait_timeout(None), INFINITE);
        assert_eq!(wait_timeout(Some(Duration::ZERO)), 0);
        assert_eq!(duration_millis(Duration::ZERO, false), 1);
        assert_eq!(duration_millis(Duration::from_nanos(1), true), 1);
        assert_eq!(duration_millis(Duration::MAX, true), u32::MAX - 1);
    }
}
