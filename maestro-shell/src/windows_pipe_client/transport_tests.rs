#![cfg(windows)]

//! Native tests for the production synchronous Windows named-pipe client.
//!
//! Ordinary cases use a raw Win32 server handle created in this process. The server-death case
//! runs the same test binary as a short-lived child because Windows reports the process that
//! created the server handle; ending a server thread cannot make that process handle non-live.

use super::{validate_local_pipe_name, WindowsPipeStream};
use crate::windows_identity::OwnedSid;
use std::ffi::{c_void, OsStr};
use std::io::{self, Read as _, Write as _};
use std::mem::size_of;
use std::net::Shutdown;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{
    LocalFree, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{
    ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

const CONNECT_WITHIN: Duration = Duration::from_secs(10);
const SERVER_IO_WITHIN: Duration = Duration::from_secs(5);
const CLIENT_IO_TIMEOUT: Duration = Duration::from_millis(200);
const CLIENT_IO_BOUND: Duration = Duration::from_secs(3);
const PIPE_BUFFER_BYTES: u32 = 4 * 1024;
const DEATH_HELPER_ENV: &str = "HYDRA_WINDOWS_PIPE_CLIENT_DEATH_HELPER";
const DEATH_HELPER_ENABLED: &str = "raw-pipe-server-v1";
const DEATH_TEST_NAME: &str =
    "windows_pipe_client::transport_tests::windows_pipe_server_death_child";
const DEATH_ENDPOINT_ENV: &str = "HYDRA_WINDOWS_PIPE_CLIENT_DEATH_ENDPOINT";

fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

fn owned_handle(raw: HANDLE, operation: &'static str) -> io::Result<OwnedHandle> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(format!(
            "{operation} returned an invalid handle"
        )));
    }
    // SAFETY: the Win32 call returned a distinct owned handle and both invalid sentinel values
    // were rejected above.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: converted security descriptors are LocalAlloc-owned.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct CurrentUserSecurity {
    _descriptor: LocalAllocation,
    attributes: SECURITY_ATTRIBUTES,
}

impl CurrentUserSecurity {
    fn new() -> io::Result<Self> {
        let sid = OwnedSid::current_process()?.to_string()?;
        // Protected DACL with one full-access ACE for the exact current user. The SID is used only
        // to build the descriptor and is never included in test output.
        let sddl = format!("D:P(A;;GA;;;{sid})");
        let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut raw_descriptor = null_mut();
        // SAFETY: `wide` is NUL terminated and both output pointers are valid for the call.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut raw_descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let descriptor = LocalAllocation(raw_descriptor);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        Ok(Self {
            _descriptor: descriptor,
            attributes,
        })
    }

    fn as_ptr(&self) -> *const SECURITY_ATTRIBUTES {
        &self.attributes
    }
}

fn unique_endpoint(tag: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nonce = NEXT.fetch_add(1, Ordering::Relaxed);
    PathBuf::from(format!(
        r"\\.\pipe\Hydra.Maestro.test-{tag}-{}-{nonce}",
        std::process::id()
    ))
}

fn create_server(endpoint: &Path) -> io::Result<OwnedHandle> {
    let name = validate_local_pipe_name(endpoint.as_os_str())?;
    let wide: Vec<u16> = name.encode_wide().chain(std::iter::once(0)).collect();
    let security = CurrentUserSecurity::new()?;
    // SAFETY: the endpoint and security descriptor remain live for the complete call; Windows
    // copies the descriptor into the new kernel object before returning.
    let raw = unsafe {
        CreateNamedPipeW(
            wide.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            security.as_ptr(),
        )
    };
    owned_handle(raw, "CreateNamedPipeW")
}

fn create_event() -> io::Result<OwnedHandle> {
    // SAFETY: default security, manual reset, initially nonsignalled, and no name are valid here.
    owned_handle(
        unsafe { CreateEventW(null(), 1, 0, null()) },
        "CreateEventW",
    )
}

fn await_pending(
    handle: &OwnedHandle,
    operation: &OVERLAPPED,
    event: &OwnedHandle,
) -> io::Result<u32> {
    match unsafe {
        WaitForSingleObject(
            raw_handle(event),
            SERVER_IO_WITHIN.as_millis().min(u32::MAX as u128) as u32,
        )
    } {
        WAIT_OBJECT_0 => {
            // SAFETY: the event proves terminal completion and all operation storage is still live.
            completed_count(handle, operation)
        }
        WAIT_TIMEOUT => {
            // SAFETY: cancel this exact operation, then wait for terminal kernel completion before
            // returning and allowing its OVERLAPPED/event/buffer storage to leave scope.
            unsafe {
                CancelIoEx(raw_handle(handle), operation);
                let mut ignored = 0u32;
                GetOverlappedResult(raw_handle(handle), operation, &mut ignored, 1);
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "raw named-pipe server I/O timed out",
            ))
        }
        WAIT_FAILED => {
            let wait_error = io::Error::last_os_error();
            // SAFETY: retain every operation resource until cancellation reaches terminal state.
            unsafe {
                CancelIoEx(raw_handle(handle), operation);
                let mut ignored = 0u32;
                GetOverlappedResult(raw_handle(handle), operation, &mut ignored, 1);
            }
            Err(wait_error)
        }
        _ => {
            // SAFETY: retain every operation resource until cancellation reaches terminal state.
            unsafe {
                CancelIoEx(raw_handle(handle), operation);
                let mut ignored = 0u32;
                GetOverlappedResult(raw_handle(handle), operation, &mut ignored, 1);
            }
            Err(io::Error::other(
                "unexpected raw named-pipe server wait result",
            ))
        }
    }
}

fn completed_count(handle: &OwnedHandle, operation: &OVERLAPPED) -> io::Result<u32> {
    let mut transferred = 0u32;
    if unsafe { GetOverlappedResult(raw_handle(handle), operation, &mut transferred, 0) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(transferred)
    }
}

fn connect_server(handle: &OwnedHandle) -> io::Result<()> {
    let event = create_event()?;
    let mut operation = OVERLAPPED {
        hEvent: raw_handle(&event),
        ..OVERLAPPED::default()
    };
    // SAFETY: the overlapped server handle and operation storage remain live through completion.
    if unsafe { ConnectNamedPipe(raw_handle(handle), &mut operation) } != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    match error.raw_os_error().map(|value| value as u32) {
        Some(ERROR_PIPE_CONNECTED) => Ok(()),
        Some(ERROR_IO_PENDING) => await_pending(handle, &operation, &event).map(|_| ()),
        _ => Err(error),
    }
}

fn read_some(handle: &OwnedHandle, destination: &mut [u8]) -> io::Result<usize> {
    let event = create_event()?;
    let mut operation = OVERLAPPED {
        hEvent: raw_handle(&event),
        ..OVERLAPPED::default()
    };
    // SAFETY: the destination, OVERLAPPED, handle, and event stay live through completion.
    if unsafe {
        ReadFile(
            raw_handle(handle),
            destination.as_mut_ptr(),
            destination.len().min(u32::MAX as usize) as u32,
            null_mut(),
            &mut operation,
        )
    } != 0
    {
        return completed_count(handle, &operation).map(|count| count as usize);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error().map(|value| value as u32) == Some(ERROR_IO_PENDING) {
        await_pending(handle, &operation, &event).map(|count| count as usize)
    } else {
        Err(error)
    }
}

fn read_exact(handle: &OwnedHandle, mut destination: &mut [u8]) -> io::Result<()> {
    while !destination.is_empty() {
        let read = read_some(handle, destination)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "raw named-pipe peer closed early",
            ));
        }
        destination = &mut destination[read..];
    }
    Ok(())
}

fn write_some(handle: &OwnedHandle, source: &[u8]) -> io::Result<usize> {
    let event = create_event()?;
    let mut operation = OVERLAPPED {
        hEvent: raw_handle(&event),
        ..OVERLAPPED::default()
    };
    // SAFETY: the source, OVERLAPPED, handle, and event stay live through completion.
    if unsafe {
        WriteFile(
            raw_handle(handle),
            source.as_ptr(),
            source.len().min(u32::MAX as usize) as u32,
            null_mut(),
            &mut operation,
        )
    } != 0
    {
        return completed_count(handle, &operation).map(|count| count as usize);
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error().map(|value| value as u32) == Some(ERROR_IO_PENDING) {
        await_pending(handle, &operation, &event).map(|count| count as usize)
    } else {
        Err(error)
    }
}

fn write_all(handle: &OwnedHandle, mut source: &[u8]) -> io::Result<()> {
    while !source.is_empty() {
        let written = write_some(handle, source)?;
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "raw named-pipe server wrote no bytes",
            ));
        }
        source = &source[written..];
    }
    Ok(())
}

fn consume_authentication_byte(handle: &OwnedHandle) -> io::Result<()> {
    let mut byte = [0u8; 1];
    read_exact(handle, &mut byte)?;
    if byte[0] != b'\n' {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client authentication prelude was not the expected blank line",
        ));
    }
    Ok(())
}

struct ServerThread {
    release: Option<Sender<()>>,
    join: Option<JoinHandle<io::Result<()>>>,
}

impl ServerThread {
    fn finish(mut self) -> io::Result<()> {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        join.join()
            .map_err(|_| io::Error::other("raw named-pipe server thread panicked"))?
    }
}

impl Drop for ServerThread {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn spawn_server(
    endpoint: &Path,
    handler: impl FnOnce(&OwnedHandle, Receiver<()>) -> io::Result<()> + Send + 'static,
) -> io::Result<ServerThread> {
    let pipe = create_server(endpoint)?;
    let (release, released) = mpsc::channel();
    let join = thread::Builder::new()
        .name("hydra-raw-pipe-server".into())
        .spawn(move || {
            connect_server(&pipe)?;
            handler(&pipe, released)
        })?;
    Ok(ServerThread {
        release: Some(release),
        join: Some(join),
    })
}

fn connect_client(endpoint: &Path) -> io::Result<WindowsPipeStream> {
    WindowsPipeStream::connect_until(endpoint, Instant::now() + CONNECT_WITHIN)
}

fn expect_client_eof(pipe: &OwnedHandle) -> io::Result<()> {
    match read_some(pipe, &mut [0u8; 1]) {
        Ok(0) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other("aborted client sent unexpected bytes")),
    }
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn spawn_death_server(endpoint: &OsStr) -> io::Result<Self> {
        let child = Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                DEATH_TEST_NAME,
                "--nocapture",
                "--test-threads=1",
            ])
            .env(DEATH_HELPER_ENV, DEATH_HELPER_ENABLED)
            .env(DEATH_ENDPOINT_ENV, endpoint)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(Self(Some(child)))
    }

    fn id(&self) -> u32 {
        self.0.as_ref().expect("child is still owned").id()
    }

    fn wait_for_success(&mut self) -> io::Result<()> {
        let deadline = Instant::now() + CONNECT_WITHIN;
        loop {
            let child = self.0.as_mut().expect("child is still owned");
            if let Some(status) = child.try_wait()? {
                self.0.take();
                return if status.success() {
                    Ok(())
                } else {
                    Err(io::Error::other("raw named-pipe server child failed"))
                };
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "raw named-pipe server child did not exit",
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn same_token_client_connects_reads_and_writes() {
    const REQUEST: &[u8] = b"client-to-server";
    const RESPONSE: &[u8] = b"server-to-client";

    let endpoint = unique_endpoint("roundtrip");
    let server = spawn_server(&endpoint, |pipe, _released| {
        consume_authentication_byte(pipe)?;
        let mut request = [0u8; REQUEST.len()];
        read_exact(pipe, &mut request)?;
        if request != REQUEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "raw server received unexpected test payload",
            ));
        }
        write_all(pipe, RESPONSE)
    })
    .expect("start protected raw named-pipe server");

    let mut client = connect_client(&endpoint).expect("connect production named-pipe client");
    assert_eq!(client.server_pid(), std::process::id());
    assert!(client
        .state
        .server_is_alive_checked()
        .expect("query same-process server lifetime"));
    client
        .write_all(REQUEST)
        .expect("write through production named-pipe client");
    let mut response = [0u8; RESPONSE.len()];
    client
        .read_exact(&mut response)
        .expect("read through production named-pipe client");
    assert!(
        response == RESPONSE,
        "client received unexpected test payload"
    );
    drop(client);
    server.finish().expect("join raw named-pipe server");
}

#[test]
fn silent_server_read_is_bounded_by_client_timeout() {
    let endpoint = unique_endpoint("read-timeout");
    let (ready, ready_rx) = mpsc::channel();
    let server = spawn_server(&endpoint, move |pipe, released| {
        consume_authentication_byte(pipe)?;
        ready
            .send(())
            .map_err(|_| io::Error::other("read-timeout client disappeared"))?;
        let _ = released.recv_timeout(SERVER_IO_WITHIN);
        Ok(())
    })
    .expect("start silent raw named-pipe server");

    let mut client = connect_client(&endpoint).expect("connect production named-pipe client");
    ready_rx
        .recv_timeout(SERVER_IO_WITHIN)
        .expect("raw server consumed authentication byte");
    client
        .set_read_timeout(Some(CLIENT_IO_TIMEOUT))
        .expect("set production-client read timeout");
    let started = Instant::now();
    let error = client
        .read(&mut [0u8; 1])
        .expect_err("silent read must time out");
    let elapsed = started.elapsed();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        elapsed >= CLIENT_IO_TIMEOUT / 2,
        "silent read returned before its configured deadline"
    );
    assert!(
        elapsed < CLIENT_IO_BOUND,
        "silent read exceeded its test occupancy bound"
    );
    drop(client);
    server.finish().expect("join silent raw named-pipe server");
}

#[test]
fn abort_from_clone_wakes_a_blocked_read() {
    let endpoint = unique_endpoint("clone-abort");
    let (ready, ready_rx) = mpsc::channel();
    let (eof_seen, eof_rx) = mpsc::channel();
    let server = spawn_server(&endpoint, move |pipe, _released| {
        consume_authentication_byte(pipe)?;
        ready
            .send(())
            .map_err(|_| io::Error::other("abort client disappeared"))?;
        expect_client_eof(pipe)?;
        eof_seen
            .send(())
            .map_err(|_| io::Error::other("abort EOF observer disappeared"))
    })
    .expect("start silent raw named-pipe server");

    let mut reader = connect_client(&endpoint).expect("connect production named-pipe client");
    ready_rx
        .recv_timeout(SERVER_IO_WITHIN)
        .expect("raw server consumed authentication byte");
    let aborter = reader.try_clone().expect("clone production pipe stream");
    reader
        .set_read_timeout(Some(SERVER_IO_WITHIN))
        .expect("set defensive reader timeout");
    let pending = reader.arm_read_pending_probe_for_test();
    let (finished, finished_rx) = mpsc::channel();
    let reader_thread = thread::Builder::new()
        .name("hydra-pipe-blocked-reader".into())
        .spawn(move || {
            let result = reader.read(&mut [0u8; 1]);
            let _ = finished.send(result);
        })
        .expect("spawn blocked production-client reader");
    pending
        .recv_timeout(SERVER_IO_WITHIN)
        .expect("production ReadFile reached ERROR_IO_PENDING");

    let abort_started = Instant::now();
    aborter
        .shutdown(Shutdown::Both)
        .expect("abort cloned pipe stream");
    let result = match finished_rx.recv_timeout(CLIENT_IO_BOUND) {
        Ok(result) => result,
        Err(error) => {
            drop(reader_thread);
            panic!("aborted reader did not finish within bound: {error}");
        }
    };
    let abort_elapsed = abort_started.elapsed();
    reader_thread.join().expect("join production-client reader");
    let error = result.expect_err("aborted read must fail");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert!(
        abort_elapsed < CLIENT_IO_BOUND,
        "clone abort did not wake the blocked reader within bound"
    );
    eof_rx
        .recv_timeout(CLIENT_IO_BOUND)
        .expect("cancelled operations release pipe authority while the idle clone is still alive");
    drop(aborter);
    server.finish().expect("join silent raw named-pipe server");
}

#[test]
fn server_process_death_yields_eof_broken_pipe_and_false_liveness() {
    let endpoint = unique_endpoint("server-death");
    let mut child = ChildGuard::spawn_death_server(endpoint.as_os_str())
        .expect("spawn raw named-pipe server child");
    let expected_pid = child.id();
    let mut client = connect_client(&endpoint).expect("connect production named-pipe client");
    assert_eq!(client.server_pid(), expected_pid);
    assert!(client
        .state
        .server_is_alive_checked()
        .expect("query live server child"));

    client
        .write_all(b"exit")
        .expect("signal raw named-pipe server child");
    child
        .wait_for_success()
        .expect("raw named-pipe server child exited cleanly");
    assert!(!client
        .state
        .server_is_alive_checked()
        .expect("query exited server child"));

    assert_eq!(
        client
            .read(&mut [0u8; 1])
            .expect("server closure must map to stream EOF"),
        0
    );
    let error = client
        .write(b"after-exit")
        .expect_err("write after server process death must fail");
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
}

#[test]
fn windows_pipe_server_death_child() {
    let mode = std::env::var_os(DEATH_HELPER_ENV);
    if mode.as_deref() != Some(OsStr::new(DEATH_HELPER_ENABLED)) {
        return;
    }
    let endpoint = PathBuf::from(
        std::env::var_os(DEATH_ENDPOINT_ENV).expect("death helper endpoint was provided"),
    );
    let pipe = create_server(&endpoint).expect("create protected raw named-pipe server");
    connect_server(&pipe).expect("accept production named-pipe client");
    consume_authentication_byte(&pipe).expect("consume client authentication prelude");
    let mut exit_signal = [0u8; 4];
    read_exact(&pipe, &mut exit_signal).expect("read server-child exit signal");
    assert!(
        exit_signal == *b"exit",
        "server child received unexpected control payload"
    );
}
