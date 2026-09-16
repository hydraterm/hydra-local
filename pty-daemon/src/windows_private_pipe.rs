//! The final backend's private transport: overlapped Hydra end, synchronous ConPTY end.
//! Shared Session's ConPTY backend consumes this factory; daemon listener wiring is separate.

use crate::windows_job::{owned_handle, raw_handle};
use crate::windows_pipe_security::CurrentUserSecurityAttributes;
use anyhow::Result;
use std::io;
use std::os::windows::io::OwnedHandle;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    OPEN_EXISTING, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, SetEvent};
use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

#[derive(Clone, Copy)]
pub(super) enum PipeDirection {
    HydraReads,
    HydraWrites,
}

pub(super) fn private_pipe(direction: PipeDirection) -> Result<(OwnedHandle, OwnedHandle)> {
    let name = format!(
        r"\\.\pipe\Hydra.ConPTY.{}.{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    );
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut security = CurrentUserSecurityAttributes::new()?;
    let access = match direction {
        PipeDirection::HydraReads => PIPE_ACCESS_INBOUND,
        PipeDirection::HydraWrites => PIPE_ACCESS_OUTBOUND,
    } | FILE_FLAG_OVERLAPPED
        | FILE_FLAG_FIRST_PIPE_INSTANCE;
    let server = unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            access,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            security.as_ptr(),
        )
    };
    let server = unsafe { owned_handle(server, "private ConPTY server pipe")? };

    let desired_access = match direction {
        PipeDirection::HydraReads => GENERIC_WRITE,
        PipeDirection::HydraWrites => GENERIC_READ,
    };
    let client = unsafe {
        CreateFileW(
            wide_name.as_ptr(),
            desired_access,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    let client = unsafe { owned_handle(client, "private synchronous ConPTY pipe")? };
    finish_pipe_connection(&server)?;

    Ok((server, client))
}

fn finish_pipe_connection(server: &OwnedHandle) -> io::Result<()> {
    let event = Event::manual_reset()?;
    let mut operation = OVERLAPPED {
        hEvent: event.raw(),
        ..OVERLAPPED::default()
    };
    if unsafe { ConnectNamedPipe(raw_handle(server), &mut operation) } != 0 {
        return Ok(());
    }
    let error = unsafe { GetLastError() };
    match error {
        ERROR_PIPE_CONNECTED => Ok(()),
        ERROR_IO_PENDING => {
            let mut transferred = 0u32;
            if unsafe { GetOverlappedResult(raw_handle(server), &operation, &mut transferred, 1) }
                == 0
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
        _ => Err(io::Error::from_raw_os_error(error as i32)),
    }
}

pub(super) struct Event(OwnedHandle);

impl Event {
    pub(super) fn manual_reset() -> io::Result<Self> {
        Self::new(true)
    }

    fn new(manual_reset: bool) -> io::Result<Self> {
        let handle = unsafe { CreateEventW(null(), manual_reset.into(), 0, null()) };
        Ok(Self(unsafe { owned_handle(handle, "event")? }))
    }

    pub(super) fn raw(&self) -> HANDLE {
        raw_handle(&self.0)
    }

    pub(super) fn set(&self) -> io::Result<()> {
        if unsafe { SetEvent(self.raw()) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use windows_sys::Win32::Foundation::{
        GetHandleInformation, ERROR_BROKEN_PIPE, ERROR_OPERATION_ABORTED, HANDLE_FLAG_INHERIT,
        WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
    use windows_sys::Win32::System::Threading::WaitForSingleObject;
    use windows_sys::Win32::System::IO::CancelIoEx;

    // Heap-pinned OVERLAPPED and buffer stay owned until the exact kernel operation completes.
    // Dropping a failed assertion also cancels/drains before either allocation or event is freed.
    struct OwnedTestIo<'a> {
        handle: &'a OwnedHandle,
        operation: Box<OVERLAPPED>,
        event: Event,
        buffer: Vec<u8>,
        started: bool,
        pending: bool,
    }

    impl<'a> OwnedTestIo<'a> {
        fn new(handle: &'a OwnedHandle, buffer: Vec<u8>) -> io::Result<Self> {
            let event = Event::manual_reset()?;
            Ok(Self {
                handle,
                operation: Box::new(OVERLAPPED {
                    hEvent: event.raw(),
                    ..OVERLAPPED::default()
                }),
                event,
                buffer,
                started: false,
                pending: false,
            })
        }

        fn start(&mut self, read: bool) -> io::Result<bool> {
            if self.started {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "fixture I/O is one-shot; allocate a fresh operation",
                ));
            }
            self.started = true;
            let started = unsafe {
                if read {
                    ReadFile(
                        raw_handle(self.handle),
                        self.buffer.as_mut_ptr(),
                        self.buffer.len() as u32,
                        null_mut(),
                        &mut *self.operation,
                    )
                } else {
                    WriteFile(
                        raw_handle(self.handle),
                        self.buffer.as_ptr(),
                        self.buffer.len() as u32,
                        null_mut(),
                        &mut *self.operation,
                    )
                }
            };
            if started != 0 {
                return Ok(false);
            }
            let error = unsafe { GetLastError() };
            if error != ERROR_IO_PENDING {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            self.pending = true;
            Ok(true)
        }

        fn complete(&mut self) -> io::Result<usize> {
            if self.pending {
                match unsafe { WaitForSingleObject(self.event.raw(), 5_000) } {
                    WAIT_OBJECT_0 => {}
                    WAIT_TIMEOUT => {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "fixture I/O wait"))
                    }
                    WAIT_FAILED => return Err(io::Error::last_os_error()),
                    result => {
                        return Err(io::Error::other(format!(
                            "unexpected fixture wait: {result}"
                        )))
                    }
                }
            }
            let mut transferred = 0;
            let completed = unsafe {
                GetOverlappedResult(
                    raw_handle(self.handle),
                    &*self.operation,
                    &mut transferred,
                    0,
                )
            };
            let error = (completed == 0).then(io::Error::last_os_error);
            // An event-signaled result is terminal, including cancellation/EOF failures.
            self.pending = false;
            match error {
                Some(error) => Err(error),
                None => Ok(transferred as usize),
            }
        }

        fn cancel(&self) -> io::Result<()> {
            if unsafe { CancelIoEx(raw_handle(self.handle), &*self.operation) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    impl Drop for OwnedTestIo<'_> {
        fn drop(&mut self) {
            if self.pending {
                unsafe { CancelIoEx(raw_handle(self.handle), &*self.operation) };
                let mut transferred = 0;
                // Not a hard timeout: memory safety requires terminal completion before storage
                // release, even when Windows delays cancellation beyond the observation deadline.
                unsafe {
                    GetOverlappedResult(
                        raw_handle(self.handle),
                        &*self.operation,
                        &mut transferred,
                        1,
                    );
                }
            }
        }
    }

    #[test]
    fn synchronous_conpty_writer_reaches_overlapped_hydra_reader() -> Result<()> {
        let (server, client) = private_pipe(PipeDirection::HydraReads)?;
        let mut client = File::from(client);
        let bytes = b"owned ConPTY output";
        client.write_all(bytes)?;
        let mut read = OwnedTestIo::new(&server, vec![0; bytes.len()])?;
        read.start(true)?;
        assert_eq!(read.complete()?, bytes.len());
        assert_eq!(read.buffer, bytes);
        assert_eq!(
            read.start(true)
                .expect_err("completed I/O cannot reuse a stale event")
                .kind(),
            io::ErrorKind::InvalidInput,
        );
        Ok(())
    }

    #[test]
    fn overlapped_hydra_writer_reaches_synchronous_conpty_reader() -> Result<()> {
        let (server, client) = private_pipe(PipeDirection::HydraWrites)?;
        let mut client = File::from(client);
        let bytes = b"owned ConPTY input";
        let mut write = OwnedTestIo::new(&server, bytes.to_vec())?;
        write.start(false)?;
        assert_eq!(write.complete()?, bytes.len());
        let mut observed = vec![0; bytes.len()];
        client.read_exact(&mut observed)?;
        assert_eq!(observed, bytes);
        Ok(())
    }

    #[test]
    fn actual_pending_read_cancels_before_owned_storage_is_released() -> Result<()> {
        let (server, _client) = private_pipe(PipeDirection::HydraReads)?;
        let mut read = OwnedTestIo::new(&server, vec![0; 16])?;
        assert!(
            read.start(true)?,
            "connected silent peer must leave ReadFile pending"
        );
        read.cancel()?;
        let error = read
            .complete()
            .expect_err("exact pending read was cancelled");
        assert_eq!(error.raw_os_error(), Some(ERROR_OPERATION_ABORTED as i32));
        assert!(!read.pending);
        Ok(())
    }

    #[test]
    fn closing_synchronous_peer_yields_eof_and_both_handles_are_non_inherited() -> Result<()> {
        let (server, client) = private_pipe(PipeDirection::HydraReads)?;
        for handle in [&server, &client] {
            let mut flags = 0;
            if unsafe { GetHandleInformation(raw_handle(handle), &mut flags) } == 0 {
                return Err(io::Error::last_os_error().into());
            }
            assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        }
        drop(client);
        let mut read = OwnedTestIo::new(&server, vec![0; 16])?;
        let result = read.start(true).and_then(|_| read.complete());
        match result {
            Ok(count) => assert_eq!(count, 0),
            Err(error) => assert_eq!(error.raw_os_error(), Some(ERROR_BROKEN_PIPE as i32)),
        }
        Ok(())
    }

    #[test]
    fn dropping_pending_read_drains_before_the_same_pipe_is_reused() -> Result<()> {
        let (server, client) = private_pipe(PipeDirection::HydraReads)?;
        let mut client = File::from(client);
        let mut abandoned = OwnedTestIo::new(&server, vec![0; 16])?;
        assert!(abandoned.start(true)?);
        drop(abandoned); // The real Drop path cancels and awaits terminal completion.
        let bytes = b"replacement read";
        client.write_all(bytes)?;
        let mut replacement = OwnedTestIo::new(&server, vec![0; bytes.len()])?;
        replacement.start(true)?;
        assert_eq!(replacement.complete()?, bytes.len());
        assert_eq!(replacement.buffer, bytes);
        Ok(())
    }
}
