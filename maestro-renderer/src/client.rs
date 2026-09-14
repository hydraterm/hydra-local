//! Socket client. Runs on a background thread: connects to the daemon's Unix
//! socket, sends Attach, then reads newline-delimited JSON events. The latest
//! `GridSnapshot` is published into shared state for the UI thread to paint.
//!
//! The client is event-driven: after a validated state change it wakes
//! the OWNER event loop via the platform-neutral [`UserEventSender`] (the winit
//! proxy on macOS, the Tao/GTK proxy on Linux) instead of the UI thread polling
//! on a timer. The reader thread issues snapshot requests only for live output
//! (an Output revision advance) and resync — never on a periodic clock.

use crate::host_event::{HostKey, HostModifiers, HostNamedKey};
use crate::sync::{Action, DamageOutcome, SyncState};
#[cfg(test)]
use crate::wire::decode_event;
use crate::wire::{
    decode_event_with_route, Cell, ClientRequest, CursorShape, DaemonEvent, DecodeError,
    EventRouteKind, EventRouteMetadata, GridSnapshot, Revision, SessionGeneration, MAX_LINE_BYTES,
};
use crate::{UserEvent, UserEventSender};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::TryLockError;
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

const OUTBOUND_WRITE_TIMEOUT: Duration = Duration::from_secs(2);
const DAEMON_PROBE_TIMEOUT: Duration = Duration::from_secs(1);
const REQUIRED_MUTATION_PROTOCOL_VERSION: u32 = 3;

/// One indivisible Claim proof copied from an owned shell handoff authority. Keeping these fields
/// together prevents a caller from accidentally checking daemon A while publishing daemon B's
/// token. Debug is deliberately opaque.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AttachmentHandoffClaim {
    pub(crate) authority: maestro_shell::AttachmentHandoffAuthority,
    pub(crate) session_id: String,
    pub(crate) token: maestro_shell::AttachmentHandoffToken,
    pub(crate) expected_daemon_instance: maestro_shell::DaemonInstanceId,
    pub(crate) expected_server_pid: Option<u32>,
    pub(crate) expected_generation: String,
}

impl std::fmt::Debug for AttachmentHandoffClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("AttachmentHandoffClaim(<redacted>)")
    }
}

#[derive(Clone)]
struct DaemonPeerProof {
    daemon_instance_id: Option<maestro_shell::DaemonInstanceId>,
    server_pid: Option<u32>,
    mutation_capable: bool,
    legacy_attach_compatible: bool,
    attachment_handoff_capable: bool,
}

struct DaemonTransport {
    stream: UnixStream,
    mutation_capable: bool,
    legacy_attach_compatible: bool,
    peer: DaemonPeerProof,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LinuxPeerCredentials {
    pid: i32,
    uid: u32,
    gid: u32,
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn geteuid() -> u32;
    fn getsockopt(
        socket: i32,
        level: i32,
        option_name: i32,
        option_value: *mut std::ffi::c_void,
        option_len: *mut u32,
    ) -> i32;
}

#[cfg(not(target_os = "linux"))]
unsafe extern "C" {
    fn geteuid() -> u32;
    fn getpeereid(socket: i32, effective_uid: *mut u32, effective_gid: *mut u32) -> i32;
    fn getsockopt(
        socket: i32,
        level: i32,
        option_name: i32,
        option_value: *mut std::ffi::c_void,
        option_len: *mut u32,
    ) -> i32;
}

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[cfg(target_os = "linux")]
type PollCount = usize;
#[cfg(not(target_os = "linux"))]
type PollCount = u32;

#[cfg(target_os = "linux")]
#[repr(C)]
struct UnixSocketAddress {
    family: u16,
    path: [i8; 108],
}

#[cfg(not(target_os = "linux"))]
#[repr(C)]
struct UnixSocketAddress {
    length: u8,
    family: u8,
    path: [i8; 104],
}

unsafe extern "C" {
    fn socket(domain: i32, socket_type: i32, protocol: i32) -> i32;
    fn connect(socket: i32, address: *const std::ffi::c_void, address_len: u32) -> i32;
    fn poll(fds: *mut PollFd, count: PollCount, timeout_ms: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { geteuid() }
}

/// Verify the kernel-authenticated server owner before any protocol bytes cross the socket and
/// return the Linux peer PID used for exact handoff comparison.
fn reviewed_server_pid(stream: &UnixStream) -> io::Result<Option<u32>> {
    #[cfg(target_os = "linux")]
    {
        const SOL_SOCKET: i32 = 1;
        const SO_PEERCRED: i32 = 17;
        let mut credentials = LinuxPeerCredentials {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut length = std::mem::size_of::<LinuxPeerCredentials>() as u32;
        // SAFETY: the stream owns a connected AF_UNIX fd and both output pointers reference
        // correctly sized live storage for Linux SO_PEERCRED.
        let status = unsafe {
            getsockopt(
                stream.as_raw_fd(),
                SOL_SOCKET,
                SO_PEERCRED,
                (&mut credentials as *mut LinuxPeerCredentials).cast(),
                &mut length,
            )
        };
        if status != 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != std::mem::size_of::<LinuxPeerCredentials>()
            || credentials.pid <= 0
            || credentials.uid != effective_uid()
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Unix daemon peer identity was unavailable or did not match the effective uid",
            ));
        }
        return Ok(Some(credentials.pid as u32));
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut uid = 0u32;
        let mut gid = 0u32;
        // SAFETY: the stream owns a connected AF_UNIX fd and both pointers reference writable ids.
        if unsafe { getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if uid != effective_uid() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Unix daemon peer uid did not match the effective uid",
            ));
        }
        Ok(None)
    }
}

/// Terminal teardown must complete even if another thread panicked while holding authority/cache
/// state. Recover the value and clear the poison bit so the neutral draw/owner paths that run after
/// `ConnectionClosed` can inspect the now-cleared state without panicking again. Normal mutation
/// paths deliberately keep ordinary poison semantics; this helper is teardown-only.
fn teardown_lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            mutex.clear_poison();
            poisoned.into_inner()
        }
    }
}

/// Write one already-framed request under a single wall-clock deadline. A socket-level timeout is
/// normally restarted after every partial `write`, which lets a trickling peer hold the connection
/// forever; recomputing the remaining budget gives the whole JSON line one bounded lifetime.
fn write_frame_before_deadline(
    stream: &mut UnixStream,
    frame: &[u8],
    timeout: Duration,
) -> io::Result<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "outbound deadline overflow"))?;
    write_frame_until(stream, frame, deadline)
}

fn write_frame_until(
    stream: &mut UnixStream,
    mut frame: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !frame.is_empty() {
        let now = Instant::now();
        if now >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "outbound frame deadline elapsed",
            ));
        }
        let remaining = deadline.saturating_duration_since(now);
        stream.set_write_timeout(Some(remaining))?;
        match stream.write(frame) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket accepted no outbound bytes",
                ));
            }
            Ok(written) => frame = &frame[written..],
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn connect_unix_until(socket_path: &str, deadline: Instant) -> io::Result<UnixStream> {
    const AF_UNIX: i32 = 1;
    const SOCK_STREAM: i32 = 1;
    const F_GETFD: i32 = 1;
    const F_SETFD: i32 = 2;
    const FD_CLOEXEC: i32 = 1;
    const POLLOUT: i16 = 0x0004;
    #[cfg(target_os = "linux")]
    const SOL_SOCKET: i32 = 1;
    #[cfg(not(target_os = "linux"))]
    const SOL_SOCKET: i32 = 0xffff;
    #[cfg(target_os = "linux")]
    const SO_ERROR: i32 = 4;
    #[cfg(not(target_os = "linux"))]
    const SO_ERROR: i32 = 0x1007;

    let path = socket_path.as_bytes();
    let max_path = unsafe { std::mem::zeroed::<UnixSocketAddress>() }
        .path
        .len();
    if path.is_empty() || path.len() >= max_path || path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Unix daemon socket path is empty or too long",
        ));
    }
    // SAFETY: socket returns a new fd. Wrapping it immediately transfers cleanup to UnixStream on
    // every subsequent return path.
    let fd = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    // SAFETY: fcntl reads/sets descriptor flags on this owned live fd.
    let descriptor_flags = unsafe { fcntl(fd, F_GETFD) };
    if descriptor_flags < 0 || unsafe { fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    stream.set_nonblocking(true)?;

    let mut address = unsafe { std::mem::zeroed::<UnixSocketAddress>() };
    #[cfg(target_os = "linux")]
    {
        address.family = AF_UNIX as u16;
    }
    #[cfg(not(target_os = "linux"))]
    {
        address.family = AF_UNIX as u8;
    }
    for (destination, source) in address.path.iter_mut().zip(path.iter().copied()) {
        *destination = source as i8;
    }
    let address_len = std::mem::offset_of!(UnixSocketAddress, path)
        .checked_add(path.len() + 1)
        .and_then(|length| u32::try_from(length).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket path overflow"))?;
    #[cfg(not(target_os = "linux"))]
    {
        address.length = u8::try_from(address_len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket address overflow"))?;
    }
    // SAFETY: address points to a correctly initialized platform sockaddr_un prefix for address_len.
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "daemon connect deadline elapsed",
        ));
    }
    let status = unsafe {
        connect(
            fd,
            (&address as *const UnixSocketAddress).cast(),
            address_len,
        )
    };
    if status != 0 {
        let error = io::Error::last_os_error();
        #[cfg(target_os = "linux")]
        let in_progress = error.raw_os_error() == Some(115);
        #[cfg(not(target_os = "linux"))]
        let in_progress = error.raw_os_error() == Some(36);
        if !in_progress {
            return Err(error);
        }
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "daemon connect deadline elapsed")
                })?;
            let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut descriptor = PollFd {
                fd,
                events: POLLOUT,
                revents: 0,
            };
            // SAFETY: descriptor points to one live pollfd for the duration of this call.
            let polled = unsafe { poll(&mut descriptor, 1 as PollCount, timeout_ms) };
            if polled > 0 {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "daemon connect deadline elapsed",
                    ));
                }
                break;
            }
            if polled == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "daemon connect deadline elapsed",
                ));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        let mut socket_error = 0i32;
        let mut socket_error_len = std::mem::size_of::<i32>() as u32;
        // SAFETY: socket_error and length are correctly sized outputs for SO_ERROR.
        if unsafe {
            getsockopt(
                fd,
                SOL_SOCKET,
                SO_ERROR,
                (&mut socket_error as *mut i32).cast(),
                &mut socket_error_len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if socket_error != 0 {
            return Err(io::Error::from_raw_os_error(socket_error));
        }
    }
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "daemon connect deadline elapsed",
        ));
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}

fn read_frame_until(stream: &UnixStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = Vec::new();
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "daemon probe deadline elapsed")
            })?;
        reader.get_ref().set_read_timeout(Some(remaining))?;
        let available = loop {
            match reader.fill_buf() {
                Ok(bytes) => break bytes,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        };
        if available.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "daemon closed during capability probe",
            ));
        }
        let take = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |index| index + 1);
        if line.len().saturating_add(take) > MAX_LINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "daemon capability reply exceeded the frame bound",
            ));
        }
        line.extend_from_slice(&available[..take]);
        let terminated = available[take - 1] == b'\n';
        reader.consume(take);
        if terminated {
            return Ok(line);
        }
    }
}

/// Probe one candidate socket without mutating daemon state, then keep that exact connection for
/// every admitted follow-up. A valid legacy DaemonInfo or typed legacy Error may downgrade this
/// same socket to read-only; framing/EOF/invalid replies fail closed. Never reconnect between the
/// capability decision and Attach: a path replacement must not receive an id-only legacy request.
fn connect_daemon_transport(
    socket_path: &str,
    handoff: Option<&AttachmentHandoffClaim>,
) -> io::Result<DaemonTransport> {
    let deadline = Instant::now()
        .checked_add(DAEMON_PROBE_TIMEOUT)
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "daemon probe deadline overflow"))?;
    let mut candidate = connect_unix_until(socket_path, deadline)?;
    let server_pid = reviewed_server_pid(&candidate)?;

    let probe = (|| -> io::Result<Option<DaemonPeerProof>> {
        let mut frame = serde_json::to_vec(&ClientRequest::DaemonInfo)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        frame.push(b'\n');
        write_frame_until(&mut candidate, &frame, deadline)?;

        let line = read_frame_until(&candidate, deadline)?;
        let event: DaemonEvent = serde_json::from_slice(&line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        match event {
            DaemonEvent::DaemonInfo {
                protocol_version,
                daemon_instance_id,
                output_generation_echo,
                generation_conditional_mutations,
                attachment_aware_conditional_kill,
                generation_conditional_attach,
                ..
            } => {
                let mutation_capable = protocol_version == REQUIRED_MUTATION_PROTOCOL_VERSION
                    && generation_conditional_mutations;
                Ok(Some(DaemonPeerProof {
                    daemon_instance_id,
                    server_pid,
                    mutation_capable,
                    legacy_attach_compatible: protocol_version < REQUIRED_MUTATION_PROTOCOL_VERSION,
                    attachment_handoff_capable: mutation_capable
                        && output_generation_echo
                        && attachment_aware_conditional_kill
                        && generation_conditional_attach,
                }))
            }
            DaemonEvent::Error { .. } => Ok(None),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "daemon capability probe returned an unrelated event",
            )),
        }
    })()?;

    if let Some(peer) = probe {
        if peer.attachment_handoff_capable {
            if let Some(expected) = handoff {
                if peer.daemon_instance_id.as_ref() != Some(&expected.expected_daemon_instance)
                    || peer.server_pid != expected.expected_server_pid
                    || cfg!(target_os = "linux") && peer.server_pid.is_none()
                {
                    let _ = candidate.shutdown(Shutdown::Both);
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "daemon did not prove the exact attachment handoff peer",
                    ));
                }
            }
            candidate.set_read_timeout(None)?;
            candidate.set_write_timeout(None)?;
            return Ok(DaemonTransport {
                stream: candidate,
                mutation_capable: peer.mutation_capable,
                legacy_attach_compatible: peer.legacy_attach_compatible,
                peer,
            });
        }
        if handoff.is_some() {
            let _ = candidate.shutdown(Shutdown::Both);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "daemon does not support exact attachment handoff",
            ));
        }
        candidate.set_read_timeout(None)?;
        candidate.set_write_timeout(None)?;
        return Ok(DaemonTransport {
            stream: candidate,
            mutation_capable: peer.mutation_capable,
            legacy_attach_compatible: peer.legacy_attach_compatible,
            peer,
        });
    }

    if handoff.is_some() {
        let _ = candidate.shutdown(Shutdown::Both);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "daemon does not support exact attachment handoff",
        ));
    }
    candidate.set_read_timeout(None)?;
    candidate.set_write_timeout(None)?;
    Ok(DaemonTransport {
        stream: candidate,
        mutation_capable: false,
        legacy_attach_compatible: true,
        peer: DaemonPeerProof {
            daemon_instance_id: None,
            server_pid,
            mutation_capable: false,
            legacy_attach_compatible: true,
            attachment_handoff_capable: false,
        },
    })
}

/// Hard cap on the outbound queue's buffered bytes. The daemon's socket can stall
/// (a busy daemon, a slow consumer); rather than let the UI thread block on a raw
/// `write_all` syscall under the paint path, requests are enqueued here and a
/// dedicated writer thread drains them in order. 1 MiB is generous for control
/// frames + a capped paste; reaching it means the daemon is badly wedged.
pub const OUTBOUND_CAP_BYTES: usize = 1024 * 1024;

/// A serialized, byte-bounded outbound queue draining to one writer thread.
///
/// ORDER: strict FIFO — the daemon's protocol is order-sensitive (Attach must
/// precede the Snapshots/Writes that depend on it), so requests are dequeued in
/// the exact order they were enqueued. A single writer thread owns the socket, so
/// no two writers can interleave bytes at the kernel.
///
/// OVERLOAD: owner-loop and reader producers never wait on this queue. A request or
/// ordered batch is admitted in full only when the queue mutex and byte capacity are
/// immediately available; otherwise the typed refusal arms one level-triggered
/// [`UserEvent::OutboundWritable`] wake when the writer next frees room. This keeps
/// local ClearViewport/input handling live even when the daemon or socket is wedged.
struct OutboundQueue {
    inner: Mutex<OutboundInner>,
    /// Signalled when an item is enqueued (work available) or `closed` flips.
    work: Condvar,
    /// A producer observed contention/capacity refusal. The writer swaps this bit when dequeue
    /// creates a writable transition and emits one owner-loop retry wake, coalescing any number of
    /// refused requests while the queue remains unwritable.
    retry_wake_armed: AtomicBool,
}

struct OutboundInner {
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    /// Set when the socket is gone; producers stop blocking and return.
    closed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TryEnqueueOutcome {
    Admitted,
    Contended { wake_now: bool },
    Full,
    TooLarge,
    Closed,
    Poisoned,
}

/// Why a nonblocking outbound admission did not occur. Low-cardinality by design: callers may
/// surface this locally without including terminal text, session ids, or user data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundUnavailable {
    Contended,
    Full,
    /// One read-only Scrollback query for this exact binding is already admitted. The owner retains
    /// only its latest desired query; consuming any reply emits OutboundWritable to retry it.
    ScrollbackInFlight,
    TooLarge,
    Closed,
    NotConnected,
    /// The retained daemon did not prove exact protocol-v3 generation-conditional mutation
    /// support. Attach/Snapshot remain available, but terminal mutation never falls back to id.
    MutationUnsupported,
    Poisoned,
    Serialize,
}

#[must_use = "outbound admission must be retained/retried or surfaced explicitly"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestAdmission {
    Admitted,
    Unavailable {
        reason: OutboundUnavailable,
        /// The queue-lock contention raced a completed dequeue after wake registration. No future
        /// capacity transition is guaranteed, so this producer must schedule one immediate retry.
        wake_now: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActiveBindFailure {
    Admission(RequestAdmission),
    AuthorityExhausted,
    /// The operational socket is not the exact UID/instance/PID peer bound into the authority.
    HandoffPeerMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryRequestResult {
    Admitted,
    Pending { wake_now: bool },
    AlreadyAdmitted,
    Stale,
    Refused(RequestAdmission),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RecoveryRetryResult {
    pub wake_now: bool,
    pub terminal: bool,
}

#[derive(Clone, Debug)]
struct PendingRecovery {
    binding: ViewportBindingToken,
    admitted: bool,
}

impl RequestAdmission {
    pub fn is_admitted(self) -> bool {
        matches!(self, Self::Admitted)
    }

    pub fn wake_now(self) -> bool {
        matches!(self, Self::Unavailable { wake_now: true, .. })
    }

    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::Unavailable {
                reason: OutboundUnavailable::Contended
                    | OutboundUnavailable::Full
                    | OutboundUnavailable::ScrollbackInFlight,
                ..
            }
        )
    }

    pub fn is_connection_terminal(self) -> bool {
        matches!(
            self,
            Self::Unavailable {
                reason: OutboundUnavailable::Closed
                    | OutboundUnavailable::NotConnected
                    | OutboundUnavailable::Poisoned
                    | OutboundUnavailable::Serialize,
                ..
            }
        )
    }

    pub fn is_mutation_unsupported(self) -> bool {
        matches!(
            self,
            Self::Unavailable {
                reason: OutboundUnavailable::MutationUnsupported,
                ..
            }
        )
    }
}

#[derive(Clone, Debug)]
pub struct DesiredPaneBinding {
    pub session_id: String,
    pub expected_generation: SessionGeneration,
    pub dims: Option<(u16, u16)>,
}

#[derive(Clone, Debug)]
pub struct DesiredViewportBinding {
    pub primary_session_id: String,
    pub primary_expected_generation: SessionGeneration,
    // Initial admission is Attach/Snapshot-only: generation-bound Resize follows the exact
    // baseline. Retain the desired geometry with the aggregate request until that point.
    #[allow(dead_code)]
    pub primary_dims: Option<(u16, u16)>,
    pub panes: Vec<DesiredPaneBinding>,
}

impl OutboundQueue {
    fn new() -> Self {
        OutboundQueue {
            inner: Mutex::new(OutboundInner {
                queue: VecDeque::new(),
                bytes: 0,
                closed: false,
            }),
            work: Condvar::new(),
            retry_wake_armed: AtomicBool::new(false),
        }
    }

    /// Admit a frame only when it fits immediately. Reader-side recovery requests use this while
    /// holding their binding authority, so ClearViewport can never be stranded behind outbound
    /// backpressure and no stale request can cross the clear linearization point.
    fn try_enqueue(&self, line: Vec<u8>) -> TryEnqueueOutcome {
        self.try_enqueue_batch(vec![line])
    }

    /// All-or-none nonblocking admission for one protocol transaction. No prefix can become visible
    /// to the writer: capacity is checked against the aggregate framed bytes before the first push.
    fn try_enqueue_batch(&self, lines: Vec<Vec<u8>>) -> TryEnqueueOutcome {
        let len = lines.iter().map(Vec::len).sum::<usize>();
        if len > OUTBOUND_CAP_BYTES {
            return TryEnqueueOutcome::TooLarge;
        }
        let mut inner = match self.inner.try_lock() {
            Ok(inner) => inner,
            Err(TryLockError::WouldBlock) => {
                // No registration handshake can order against an already-completed final dequeue
                // while its guard is still held. Always make the producer schedule one immediate
                // retry. Duplicates are harmless/level-triggered; zero wake is impossible.
                return TryEnqueueOutcome::Contended { wake_now: true };
            }
            Err(TryLockError::Poisoned(_)) => return TryEnqueueOutcome::Poisoned,
        };
        if inner.closed {
            return TryEnqueueOutcome::Closed;
        }
        if inner.bytes.saturating_add(len) > OUTBOUND_CAP_BYTES {
            self.retry_wake_armed.store(true, Ordering::Release);
            return TryEnqueueOutcome::Full;
        }
        inner.queue.extend(lines);
        inner.bytes += len;
        self.work.notify_one();
        TryEnqueueOutcome::Admitted
    }

    /// Block until an item is available, then pop it (FIFO). Closing is an abort,
    /// not a graceful drain: once the peer is untrusted/dead, queued terminal input
    /// and topology frames must never be written afterward.
    fn dequeue(&self) -> Option<(Vec<u8>, bool)> {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            if inner.closed {
                return None;
            }
            if let Some(item) = inner.queue.pop_front() {
                inner.bytes -= item.len();
                let wake_retry = self.retry_wake_armed.swap(false, Ordering::AcqRel);
                return Some((item, wake_retry));
            }
            inner = self
                .work
                .wait(inner)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Abort the queue and wake the writer. Poison recovery is deliberately fail closed: teardown
    /// itself must not panic and preserve queued secrets merely because a producer panicked while
    /// holding the queue mutex.
    fn close(&self) {
        let mut inner = teardown_lock(&self.inner);
        inner.closed = true;
        inner.queue.clear();
        inner.bytes = 0;
        self.retry_wake_armed.store(false, Ordering::Release);
        self.work.notify_all();
    }

    /// Number of frames currently queued (not yet drained by the writer). Test-only:
    /// lets a unit test assert that a code path enqueued exactly N requests without
    /// spinning up the writer thread / socket.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    /// Pop every queued line and parse each back into a [`ClientRequest`], FIFO. Test-only: lets a
    /// unit test assert the exact requests a `send_request`-driven code path enqueued.
    #[cfg(test)]
    fn drain_requests(&self) -> Vec<ClientRequest> {
        let mut inner = self.inner.lock().unwrap();
        let lines: Vec<Vec<u8>> = inner.queue.drain(..).collect();
        inner.bytes = 0;
        lines
            .iter()
            .map(|l| serde_json::from_slice(l).expect("framed line parses as ClientRequest"))
            .collect()
    }

    #[cfg(test)]
    fn saturate_raw(&self) {
        assert_eq!(
            self.try_enqueue(vec![0; OUTBOUND_CAP_BYTES]),
            TryEnqueueOutcome::Admitted
        );
    }

    #[cfg(test)]
    fn discard_all(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.queue.clear();
        inner.bytes = 0;
        self.retry_wake_armed.store(false, Ordering::Release);
    }
}

/// Renderer-owned scrollback VIEW state. The daemon is stateless about
/// the viewport — it pins its live grid at the bottom and only answers read-only
/// `Scrollback` queries. This struct is the renderer's entire notion of "where the
/// user has scrolled to". Touched by BOTH threads: the UI thread writes `view_offset`
/// on wheel/key and reads `historical` in `draw`; the reader thread writes
/// `historical`/`history_len` when a `ScrollbackRows` reply arrives. Hence the Mutex.
#[derive(Default)]
pub struct ScrollbackState {
    /// How far the viewport is scrolled UP from the live bottom, in rows. `0` means
    /// "live" (paint `Shared.grid` exactly as before). `> 0` means paint `historical`.
    /// Normally clamped to the last-known `history_len`. An explicit upward gesture at
    /// that cached ceiling may move provisionally by at most one page so the daemon can
    /// report a newer depth after live output grows history.
    pub view_offset: u32,
    /// Total history length, IF known. `None` until the first `ScrollbackRows` reply —
    /// distinct from `Some(0)` ("there was no history at the last reply"). The
    /// distinction matters at bootstrap: the very first wheel/PageUp from the live
    /// bottom happens BEFORE any reply, so `history_len` is `None` and we must still send one
    /// provisional `Scrollback` request to learn the real length.
    pub history_len: Option<u32>,
    /// The synthetic snapshot built from the latest `ScrollbackRows` window, ready to
    /// paint through the SAME render path as a live grid. `None` until a reply arrives
    /// (or after returning to live, where it is cleared).
    pub historical: Option<Arc<GridSnapshot>>,
    /// The live grid generation the `historical` rows belong to. A `ScrollbackRows`
    /// for a different (older/newer) generation than the live grid is stale and ignored.
    pub historical_generation: Option<SessionGeneration>,
    /// Monotonic owner-local view intent. Replies are untagged by the daemon, so this epoch plus the
    /// single exactly-correlated admitted query prevents an older clamped reply from overwriting a
    /// newer scroll or return-to-live intent.
    pub(crate) intent_epoch: u64,
    pub(crate) intent_exhausted: bool,
    pub(crate) admitted_request: Option<(u64, u32, SessionGeneration)>,
    /// A live generation/screen transition occurred after the admitted untagged reply
    /// was requested. The reply must still retire ordering, but none of its old history
    /// metadata may be installed into the new screen context.
    pub(crate) discard_admitted_reply_metadata: bool,
}

impl ScrollbackState {
    /// Are we currently showing history (vs. the live bottom)?
    pub fn is_scrolled(&self) -> bool {
        self.view_offset > 0
    }

    /// Snap back to the live bottom and drop the cached historical window.
    pub fn reset_to_live(&mut self) {
        let _ = self.advance_intent();
        self.view_offset = 0;
        self.historical = None;
        self.historical_generation = None;
    }

    pub(crate) fn advance_intent(&mut self) -> Option<u64> {
        if self.intent_exhausted {
            return None;
        }
        let Some(next) = self.intent_epoch.checked_add(1) else {
            self.intent_exhausted = true;
            return None;
        };
        self.intent_epoch = next;
        Some(next)
    }

    /// A new PTY generation or primary/alternate-screen transition invalidates every
    /// historical pixel, cached depth, and desired offset immediately. Preserve the one
    /// admitted query until its ordered reply retires the correlation; the advanced intent
    /// prevents that reply from reviving the stale view.
    fn reset_for_live_context_change(&mut self) {
        let _ = self.advance_intent();
        self.discard_admitted_reply_metadata = self.admitted_request.is_some();
        self.view_offset = 0;
        self.history_len = None;
        self.historical = None;
        self.historical_generation = None;
    }
}

/// Clamp a desired view offset against the KNOWN history length, if any.
/// - `Some(n)`: clamp into `[0, n]` (the authoritative bound the daemon also enforces).
/// - `None` (length not yet known): clamp into `[0, provisional_cap]`. This lets the
///   first scroll-up from the bottom move to a provisional offset and fire one request
///   to learn the real length, without overshooting wildly. The reply re-clamps to the
///   true length (and snaps back to live if there is no history at all). A caller deliberately
///   re-probing a last-known ceiling passes `None` with a cap extending from its current offset.
pub fn clamp_view_offset(desired: i64, history_len: Option<u32>, provisional_cap: u32) -> u32 {
    let ceiling = match history_len {
        Some(n) => n as i64,
        None => provisional_cap as i64,
    };
    desired.clamp(0, ceiling) as u32
}

/// Build the overlay scroll indicator from the current view state. Returns `None` at the
/// live bottom (offset 0) so the overlay shows nothing extra. When scrolled we always show
/// the offset; the depth (`/N`) and percent are appended ONLY when the history length is
/// known and positive (`Some(n>0)`) — before the first reply (`None`) or with no history
/// (`Some(0)`) we cannot honestly compute a fraction, so we show the bare offset. Percent
/// is `round(offset / n * 100)` clamped to `[0, 100]` (offset is already clamped to `n` by
/// `clamp_view_offset`, so this is belt-and-suspenders). Pure, unit-tested.
pub fn scroll_indicator_label(view_offset: u32, history_len: Option<u32>) -> Option<String> {
    if view_offset == 0 {
        return None;
    }
    match history_len {
        Some(n) if n > 0 => {
            let pct = ((view_offset as f64 / n as f64) * 100.0).round() as i64;
            let pct = pct.clamp(0, 100);
            Some(format!("[scroll {view_offset}/{n} {pct}%]"))
        }
        _ => Some(format!("[scroll +{view_offset}]")),
    }
}

/// A user-initiated viewport movement. Positive deltas scroll UP into history; the
/// page/home/end variants are resolved against the visible row count and history length.
/// These are VIEW actions only — never PTY input (mouse reporting is out of scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollAction {
    /// Move by `rows` lines: positive = up into history, negative = down toward live.
    Lines(i64),
    /// One visible page up (into history).
    PageUp,
    /// One visible page down (toward live).
    PageDown,
    /// Jump to the oldest available history (top).
    Home,
    /// Jump to the live bottom.
    End,
}

/// Exact scroll-query intent captured in the same authority/PTY-generation critical section that
/// mutates the local viewport. A later queue retry must validate this tuple unchanged; it may never
/// re-stamp an old gesture with a newer intent epoch or PTY generation after a Grid rollover.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScrollRequestIntent {
    pub(crate) intent_epoch: u64,
    pub(crate) requested_offset: u32,
    pub(crate) expected_generation: SessionGeneration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PreparedScrollAction {
    Unavailable,
    AlternateScreen,
    NoMove,
    ToLive,
    Moved {
        binding: ViewportBindingToken,
        request: ScrollRequestIntent,
        count: u16,
    },
}

fn prepare_bound_scroll_action(
    binding: ViewportBindingToken,
    grid: &GridSnapshot,
    scrollback: &mut ScrollbackState,
    action: ScrollAction,
) -> PreparedScrollAction {
    if grid.alt_screen {
        scrollback.reset_to_live();
        return PreparedScrollAction::AlternateScreen;
    }
    let page = grid.rows.min(u16::MAX as usize) as u32;
    let next = next_view_offset(scrollback.view_offset, scrollback.history_len, page, action);
    if next == scrollback.view_offset {
        return PreparedScrollAction::NoMove;
    }
    if next == 0 {
        scrollback.reset_to_live();
        return PreparedScrollAction::ToLive;
    }
    let Some(intent_epoch) = scrollback.advance_intent() else {
        scrollback.reset_to_live();
        return PreparedScrollAction::ToLive;
    };
    scrollback.view_offset = next;
    PreparedScrollAction::Moved {
        binding,
        request: ScrollRequestIntent {
            intent_epoch,
            requested_offset: next,
            expected_generation: grid.generation.clone(),
        },
        count: page as u16,
    }
}

/// Resolve a `ScrollAction` against the current offset into a new clamped offset.
/// `page` is the visible row count used for PageUp/PageDown. `history_len` is `None`
/// until the first reply; in that bootstrap case the offset is clamped to one page so a
/// first scroll-up can move (and fire a request) without overshooting. A cached length is
/// point-in-time metadata, so an upward gesture at that ceiling likewise gets one bounded
/// page to re-probe. Pure so it is unit-tested without a window. Alt-screen suppression and
/// request dispatch are handled by the caller; this only does the offset arithmetic.
pub fn next_view_offset(
    current: u32,
    history_len: Option<u32>,
    page: u32,
    action: ScrollAction,
) -> u32 {
    let cur = current as i64;
    let page_i = page.max(1) as i64;
    // `history_len` is authoritative for the reply that supplied it, but it is not an
    // eternal ceiling: live output can add history afterwards.  In particular, caching
    // `Some(0)` must not make a pane permanently unscrollable.  When the user explicitly
    // scrolls UP while already at the last-known ceiling, allow one bounded page of
    // provisional movement so the normal Scrollback request re-probes the daemon.  The
    // reply immediately clamps/echoes the real current depth.  Downward movement keeps
    // using the known bound and can never probe away from the live bottom.
    let moves_up = match action {
        ScrollAction::Lines(delta) => delta > 0,
        ScrollAction::PageUp | ScrollAction::Home => true,
        ScrollAction::PageDown | ScrollAction::End => false,
    };
    let probes_above_cached_ceiling = moves_up && history_len.is_some_and(|known| current >= known);
    let effective_history_len = if probes_above_cached_ceiling {
        None
    } else {
        history_len
    };
    let desired = match action {
        ScrollAction::Lines(d) => cur + d,
        ScrollAction::PageUp => cur + page_i,
        ScrollAction::PageDown => cur - page_i,
        // Home jumps to the oldest line; when length is unknown, clamping pins it to the
        // provisional cap so we move up and learn the real length from the reply.
        ScrollAction::Home => effective_history_len.map(|n| n as i64).unwrap_or(i64::MAX),
        ScrollAction::End => 0,
    };
    // If a previously-known ceiling became stale while already scrolled, the provisional
    // cap must extend FROM the current offset rather than snap back to the first page.
    let provisional_cap = current.saturating_add(page.max(1));
    clamp_view_offset(desired, effective_history_len, provisional_cap)
}

/// Pixels of trackpad/precision scroll that equal one line step. macOS delivers a
/// stream of small `PixelDelta` events (often 1–10px each) during a normal scroll;
/// converting each one independently and rounding loses every sub-threshold event,
/// so a gentle scroll never moves at all. We instead accumulate pixels and emit whole
/// line steps as the total crosses each multiple, retaining the remainder.
pub const WHEEL_PIXELS_PER_LINE: f64 = 16.0;

/// Accumulates fractional wheel/trackpad scroll into whole line steps without losing
/// sub-line motion between events. `add_lines` (mouse wheels, already in line units)
/// and `add_pixels` (trackpads, in pixels) both feed the same residue, so a slow
/// trackpad scroll eventually crosses a line boundary instead of rounding to zero on
/// every event. Pure and window-free so it is unit-testable.
///
/// Sign convention matches `ScrollAction::Lines`: positive = up into history (which is
/// winit's "positive y reveals content above"), negative = down toward live.
#[derive(Debug, Default, Clone)]
pub struct WheelAccumulator {
    residue: f64,
}

impl WheelAccumulator {
    /// Drop any fractional motion owned by the previously focused pane. A partial
    /// trackpad gesture must never cross the pane-focus boundary and become input
    /// for a different terminal.
    pub fn reset(&mut self) {
        self.residue = 0.0;
    }

    /// Feed a `LineDelta` y (already in line units). Returns the whole line steps to
    /// apply now (sign = direction), carrying any fraction forward.
    pub fn add_lines(&mut self, lines: f64) -> i64 {
        self.residue += lines;
        self.take_whole()
    }

    /// Feed a `PixelDelta` y (in pixels). Returns the whole line steps to apply now,
    /// carrying the sub-line remainder forward so consecutive small events accumulate.
    pub fn add_pixels(&mut self, pixels: f64) -> i64 {
        self.residue += pixels / WHEEL_PIXELS_PER_LINE;
        self.take_whole()
    }

    /// Extract the integer part of the residue toward zero, leaving the fraction.
    fn take_whole(&mut self) -> i64 {
        let whole = self.residue.trunc();
        self.residue -= whole;
        whole as i64
    }
}

/// Maximum whole-line steps one host wheel event may turn into. Precision-device
/// residue is accumulated before this policy runs; this cap only bounds a single
/// resulting PTY/report/view mutation burst.
pub const MAX_WHEEL_STEPS_PER_EVENT: u8 = 16;

/// Direction shared by mouse-report and alternate-screen key fallbacks. The sign
/// convention matches [`ScrollAction::Lines`]: positive host y is Up, negative is Down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WheelDirection {
    Up,
    Down,
}

/// One resolved wheel-input disposition. The event loop gathers focused-pane state;
/// [`wheel_input_action_for`] is the sole policy that chooses which owner receives the gesture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WheelInputAction {
    /// The focused TUI negotiated terminal mouse reporting; emit xterm wheel reports.
    MouseReport {
        direction: WheelDirection,
        steps: u8,
    },
    /// A focused alternate-screen TUI did not negotiate mouse reporting; synthesize
    /// conventional unmodified cursor Up/Down keys under its current cursor-key mode.
    AlternateScrollKeys {
        direction: WheelDirection,
        steps: u8,
    },
    /// The normal-screen renderer owns the scrollback viewport.
    RendererScrollback(ScrollAction),
    /// A sub-line gesture has not crossed the accumulator threshold yet.
    NoOp,
}

/// Select exactly one owner for an accumulated whole-line wheel gesture.
///
/// Precedence is intentional: negotiated mouse reporting wins even on the alternate
/// screen; otherwise alternate-screen applications receive bounded Up/Down keys; the
/// normal screen moves renderer history. Zero is a no-op. This function never inspects
/// a process/provider and never changes scrollback content.
pub fn wheel_input_action_for(
    lines: i64,
    mouse_reporting: bool,
    alt_screen: bool,
) -> WheelInputAction {
    let cap = i64::from(MAX_WHEEL_STEPS_PER_EVENT);
    let bounded = lines.clamp(-cap, cap);
    if bounded == 0 {
        return WheelInputAction::NoOp;
    }
    let direction = if bounded > 0 {
        WheelDirection::Up
    } else {
        WheelDirection::Down
    };
    let steps = bounded.unsigned_abs() as u8;
    if mouse_reporting {
        WheelInputAction::MouseReport { direction, steps }
    } else if alt_screen {
        WheelInputAction::AlternateScrollKeys { direction, steps }
    } else {
        WheelInputAction::RendererScrollback(ScrollAction::Lines(bounded))
    }
}

/// The four navigation keys that may drive renderer scrollback. The caller maps a
/// winit `NamedKey` to this so the policy below is pure and unit-testable without a
/// window or a winit key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollKey {
    PageUp,
    PageDown,
    Home,
    End,
}

/// Decide whether a navigation key is consumed as a renderer-scrollback VIEW action,
/// or `None` if it must pass through to the PTY. This is the single source of truth
/// for the PageUp/PageDown/Home/End policy:
///
/// - **alt-screen (TUI):** always `None`. Full-screen apps own paging; the renderer
///   must never intercept these keys, so they reach the PTY unmodified.
/// - **normal + scrolled up:** all four control the scrollback viewport.
/// - **normal + live bottom:** only PageUp enters scrollback (there is history above);
///   PageDown/Home/End have nothing to scroll into and belong to the shell/pager, so
///   they pass to the PTY.
/// - any modifier held (Ctrl/Alt/Super/Shift): `None` — modified chords are out of
///   scope and belong to the application.
///
/// `modified` is true if any of Ctrl/Alt/Super/Shift is held.
pub fn scroll_key_action_for(
    key: ScrollKey,
    alt_screen: bool,
    scrolled: bool,
    modified: bool,
) -> Option<ScrollAction> {
    if alt_screen || modified {
        return None;
    }
    match key {
        ScrollKey::PageUp => Some(ScrollAction::PageUp),
        ScrollKey::PageDown if scrolled => Some(ScrollAction::PageDown),
        ScrollKey::Home if scrolled => Some(ScrollAction::Home),
        ScrollKey::End if scrolled => Some(ScrollAction::End),
        // At the live bottom, PageDown/Home/End have nothing to scroll into -> PTY.
        ScrollKey::PageDown | ScrollKey::Home | ScrollKey::End => None,
    }
}

/// Build a SYNTHETIC `GridSnapshot` from a `ScrollbackRows` window so historical rows
/// flow through the exact same `render()` path as a live grid. The rows already use the
/// identical `Cell` shape; we only wrap them with grid geometry and a hidden cursor
/// (history has no live cursor). This snapshot is NEVER fed to `SyncState` — it is a
/// display artifact, not part of the authoritative generation/revision timeline. We carry
/// the source `generation`/`revision` purely so the overlay can show them and so a stale
/// window (wrong generation) can be rejected by the caller before this is built.
type CopyRows = (
    Vec<Vec<Cell>>,
    Option<Vec<maestro_protocol::row_copy::RowCopy>>,
);

fn scrollback_snapshot(
    generation: SessionGeneration,
    revision: Revision,
    (rows, row_copy): CopyRows,
) -> GridSnapshot {
    let row_count = rows.len();
    let cols = rows.first().map(|r| r.len()).unwrap_or(0);
    GridSnapshot {
        row_copy,
        version: crate::sync::SUPPORTED_VERSION,
        generation,
        revision,
        base_revision: revision,
        cols,
        rows: row_count,
        rows_cells: rows,
        // History is read-only: no cursor is drawn while scrolled up.
        cursor_line: 0,
        cursor_col: 0,
        cursor_visible: false,
        cursor_shape: CursorShape::Block,
        // A scrollback window is, by construction, primary-screen history — never the
        // alternate screen (alt-screen disables scrollback). Input modes are irrelevant
        // to painting and never read from a historical snapshot.
        alt_screen: false,
        app_cursor: false,
        bracketed_paste: false,
        focus_reporting: false,
        // Historical rows are read-only: mouse reporting is never active over a scrollback
        // view (the live grid owns input modes); a click in history is local selection only.
        mouse_report: false,
        mouse_drag: false,
        mouse_motion: false,
        mouse_sgr: false,
    }
}

/// Accept-or-reject a `ScrollbackRows` reply and fold it into `Shared.scrollback`.
/// Pure of any event loop so it is unit-testable. Returns `true` if the renderer should
/// repaint (the caller wakes the UI). Reject rules, in order:
///
/// - wrong session id -> ignore (false);
/// - generation no longer matches the live grid (re-baselined since we asked), or no
///   live grid yet -> stale, ignore (false);
/// - user has already returned to the live bottom -> record `history_len` only and do
///   NOT resurrect a historical view; still repaint so the overlay's history is fresh.
///
/// On accept we echo the daemon's actually-served offset (it may have clamped ours).
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn apply_scrollback_rows(
    shared: &Arc<Shared>,
    session_id: &str,
    id: &str,
    generation: SessionGeneration,
    revision: Revision,
    history_len: u32,
    offset_from_top: u32,
    rows: Vec<Vec<Cell>>,
) -> bool {
    let Some(token) = shared.active_token() else {
        return false;
    };
    if token.session_id != session_id || id != session_id {
        return false;
    }
    shared.commit_active_scrollback(
        &token,
        generation,
        revision,
        history_len,
        offset_from_top,
        (rows, None),
    )
}

fn apply_scrollback_payload(
    live_generation: Option<SessionGeneration>,
    sb: &mut ScrollbackState,
    generation: SessionGeneration,
    revision: Revision,
    history_len: u32,
    offset_from_top: u32,
    (rows, row_copy): CopyRows,
) -> bool {
    // ScrollbackRows are request replies on the ordered connection. Always retire the one admitted
    // request before applying generation gates: an old-generation reply after a new Grid must release
    // the slot so the owner can admit its coalesced current-generation intent.
    let discard_metadata = std::mem::take(&mut sb.discard_admitted_reply_metadata);
    let Some((reply_intent_epoch, requested_offset, expected_generation)) =
        sb.admitted_request.take()
    else {
        return false;
    };
    if expected_generation != generation || live_generation.as_ref() != Some(&generation) {
        return false;
    }
    if discard_metadata {
        return false;
    }
    if !crate::wire::terminal_link_cells_within_cap(&rows)
        || !crate::wire::row_copy_cells_valid(&rows, row_copy.as_deref())
    {
        return false;
    }
    let snap = Arc::new(scrollback_snapshot(
        generation.clone(),
        revision,
        (rows, row_copy),
    ));
    // We now KNOW the history length (distinct from the `None` bootstrap state).
    sb.history_len = Some(history_len);
    // No history at all (the bootstrap request found an empty scrollback): snap back to
    // the live bottom so a provisional offset can't strand us in scrolled mode.
    if history_len == 0 {
        if reply_intent_epoch == sb.intent_epoch {
            sb.reset_to_live();
        }
        return true;
    }
    if reply_intent_epoch == sb.intent_epoch && sb.is_scrolled() {
        let desired = clamp_view_offset(requested_offset as i64, Some(history_len), history_len);
        let served = clamp_view_offset(offset_from_top as i64, Some(history_len), history_len);
        // Replies are not request-id tagged. The latest local desired offset is therefore the only
        // safe correlation: an older in-flight reply after another scroll (or return-to-live) must
        // not overwrite the new viewport.
        if served != desired
            || clamp_view_offset(sb.view_offset as i64, Some(history_len), history_len) != desired
        {
            return false;
        }
        sb.view_offset = served;
        sb.historical = Some(snap);
        sb.historical_generation = Some(generation);
    }
    true
}

/// The renderer's CURRENT active session, shared between the UI thread (which
/// rebinds it on a tab switch) and the reader thread (which filters every event
/// against it). `epoch` bumps on each rebind so the reader can detect a switch and
/// rebuild its `SyncState` for the new id, even though it captured the original id
/// in a thread-local. The id is the single source of truth for "whose events do we
/// honor"; the reader copies it into its `SyncState` and its own filter on each bump.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActiveSession {
    pub id: Option<String>,
    pub epoch: u64,
    /// Exact daemon-stream fence allocated from the one connection-global monotonic namespace.
    /// This is protocol evidence, not a second local binding authority: every local commit still
    /// requires `id + epoch`, while an absent generation can never authorize inbound bytes.
    pub output_generation: Option<u64>,
    /// Durable PTY lifetime authorized by the immutable exact viewport cohort.
    pub expected_generation: Option<SessionGeneration>,
}

/// Exact authority for one incarnation of the primary renderer binding. Session ids may be
/// reused after a viewport is cleared, so the id alone is never sufficient authorization to
/// publish a frame or deliver a terminal side effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActiveBindingToken {
    pub session_id: String,
    pub epoch: u64,
    pub output_generation: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ExactViewportRouteBinding {
    token: ViewportBindingToken,
    expected_generation: SessionGeneration,
    primary: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExactViewportAdmissionStatus {
    Pending,
    Complete,
    FailedBeforePrimaryProof,
    FailedAfterPrimaryProof,
}

#[derive(Default)]
struct ExactViewportAdmissionProgress {
    proven_output_generations: std::collections::BTreeSet<u64>,
    failed: bool,
}

struct ExactViewportAdmissionProof {
    routes: Vec<ExactViewportRouteBinding>,
    progress: Mutex<ExactViewportAdmissionProgress>,
    primary_authority: Option<maestro_shell::AttachmentHandoffAuthority>,
    primary_claim_proven: AtomicBool,
}

impl ExactViewportAdmissionProof {
    fn note_grid(&self, token: &ViewportBindingToken, generation: &SessionGeneration) -> bool {
        let Some(route) = self.routes.iter().find(|route| &route.token == token) else {
            return false;
        };
        if &route.expected_generation != generation {
            self.fail();
            return false;
        }
        let mut progress = self.progress.lock().unwrap();
        if progress.failed {
            return false;
        }
        if route.primary && !self.primary_claim_proven.swap(true, Ordering::AcqRel) {
            if let Some(authority) = self.primary_authority.as_ref() {
                authority.mark_claimed();
            }
        }
        progress
            .proven_output_generations
            .insert(token_output_generation(token));
        true
    }

    fn fail(&self) {
        self.progress.lock().unwrap().failed = true;
    }

    fn status(&self) -> ExactViewportAdmissionStatus {
        let progress = self.progress.lock().unwrap();
        if progress.failed {
            if self.primary_claim_proven.load(Ordering::Acquire) {
                ExactViewportAdmissionStatus::FailedAfterPrimaryProof
            } else {
                ExactViewportAdmissionStatus::FailedBeforePrimaryProof
            }
        } else if progress.proven_output_generations.len() == self.routes.len() {
            ExactViewportAdmissionStatus::Complete
        } else {
            ExactViewportAdmissionStatus::Pending
        }
    }
}

fn token_output_generation(token: &ViewportBindingToken) -> u64 {
    match token {
        ViewportBindingToken::Active(token) => token.output_generation,
        ViewportBindingToken::Pane {
            output_generation, ..
        } => *output_generation,
    }
}

/// Immutable receipt for every route admitted by one all-or-none exact viewport batch. Re-querying
/// Shared by session id is ABA-unsafe, so the owner retains these exact tokens until all baselines
/// prove or the connection is neutralized.
#[derive(Clone)]
pub(crate) struct ViewportBindingSet {
    primary: ActiveBindingToken,
    proof: Arc<ExactViewportAdmissionProof>,
}

impl std::fmt::Debug for ViewportBindingSet {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ViewportBindingSet")
            .field("primary", &self.primary)
            .field("route_count", &self.proof.routes.len())
            .finish()
    }
}

impl ViewportBindingSet {
    pub(crate) fn primary(&self) -> &ActiveBindingToken {
        &self.primary
    }

    pub(crate) fn status(&self) -> ExactViewportAdmissionStatus {
        self.proof.status()
    }
}

/// Route-aware authority carried by queued bell/title/OSC52 notifications. A pane token also
/// captures the active viewport epoch: clearing or switching the containing viewport invalidates
/// every queued pane effect even if that pane's own store still happens to exist.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewportBindingToken {
    Active(ActiveBindingToken),
    Pane {
        session_id: String,
        pane_epoch: u64,
        pane_kind: PaneKind,
        viewport_epoch: u64,
        output_generation: u64,
    },
}

/// The renderer's cache of the ONE inactive split-pane sibling session, kept entirely
/// separate from the active session ([`Shared::active`]/[`Shared::grid`]). This turn
/// only ATTACHES and CACHES the sibling — it is not rendered and receives no input —
/// so this is a passive store the UI thread fills via [`Shared::sync_sibling_session`]
/// and (later) a reader path will write grids into.
///
/// Phase A: the UNIFORM per-session store. Every non-active session id — the rendered
/// split sibling AND every extra non-active pane of a three-or-more-pane layout — gets one
/// `PaneStore` keyed by its session id in [`Shared::stores`]. This replaces the two formerly
/// separate stores (`SiblingSession` and the `PaneCaches` map): both are now the SAME shape
/// with the SAME capabilities, distinguished only by the [`PaneStore::kind`] tag so the
/// sibling-binding ops and the multi-pane membership reconcile each touch only their own
/// entries.
///
/// `epoch` increments every time this id is (re)bound (sibling rebind / pane re-add) so a late
/// grid/exit stamped with a stale epoch is dropped instead of overwriting the current binding.
/// `scrollback` is carried for uniformity (every session WILL own a viewport in a later phase);
/// it is unused by the sibling/pane ingest paths this phase.
#[derive(Default)]
pub struct PaneStore {
    /// Whether this entry is the rendered split sibling or one of the extra cached panes. Lets
    /// `set_sibling_session`/`clear_sibling_session` and `set_pane_sessions`/`clear_pane_sessions`
    /// operate on disjoint subsets of the one map without clobbering each other's entries.
    pub kind: PaneKind,
    /// Bumped whenever this id is (re)bound, so a frame stamped with a stale epoch is dropped.
    pub epoch: u64,
    /// Connection-global Attach generation echoed/tagged by the canonical daemon. It is allocated
    /// independently of role-local epochs so active↔pane and pane↔sibling transitions cannot
    /// collide for the same session id.
    pub output_generation: Option<u64>,
    /// Durable PTY lifetime expected on every Grid accepted for this route.
    pub expected_generation: Option<SessionGeneration>,
    /// The session's latest accepted grid, or `None` until its first frame (or after a rebind).
    pub grid: Option<Arc<GridSnapshot>>,
    /// `Some(code)` once this session's process exits; `None` while it is live.
    pub exited: Option<Option<i32>>,
    /// Renderer-owned scrollback view state, read by the uniform pane paint path.
    pub scrollback: ScrollbackState,
}

type PaneBindingsSnapshot = (
    u64,
    Vec<(String, u64, Option<u64>, Option<SessionGeneration>)>,
);

/// Which class of session a [`PaneStore`] entry represents in the unified [`Shared::stores`]
/// map. The two binding surfaces (the single rendered sibling vs. the N-pane membership set)
/// each manage only entries of their own kind, so collapsing them into one map cannot let a
/// pane reconcile evict the sibling (or vice versa).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PaneKind {
    /// One of the extra non-active panes (membership-managed via `set_pane_sessions`).
    #[default]
    Pane,
    /// The single rendered split sibling (bound via `set_sibling_session`).
    Sibling,
}

/// Snapshot of the rendered sibling, returned by [`Shared::sibling_snapshot`]. Mirrors the
/// fields the UI/reader read from the sibling entry of the unified store. `id` is the currently
/// bound sibling id (the [`Shared::sibling_id`] pointer), or `None` when there is no split.
#[derive(Clone, Default)]
pub struct SiblingSession {
    /// The session id currently bound to the inactive pane, or `None` when there is no split.
    pub id: Option<String>,
    /// The sibling entry's rebind epoch (0 when unbound).
    pub epoch: u64,
    pub output_generation: Option<u64>,
    /// The sibling's latest accepted grid, or `None` until its first frame (or after a rebind).
    pub grid: Option<Arc<GridSnapshot>>,
    /// `Some(code)` once the sibling session process exits; `None` while it is live.
    pub exited: Option<Option<i32>>,
}

/// A pane's painting snapshot read from the cache: its latest `(grid, exited)` — `grid` is `None`
/// until baselined; `exited` is `Some(code)` once the session exited. Returned by
/// [`Shared::pane_snapshot`] for the render path to paint a cached pane or a pending/exited
/// placeholder.
#[cfg(test)]
pub type PaneSnapshot = (Option<Arc<GridSnapshot>>, Option<Option<i32>>);

/// Uniform per-pane paint resolution, the single source the draw path reads for every
/// visible pane — the primary/focused session AND every other pane — so painting has no privileged
/// "the active grid" special case. Every field is OWNED (the `live`/`historical` grids are `Arc`
/// clones, a refcount bump only), captured under ONE short lock and returned, so the caller holds NO
/// mutex across shaping/GPU submission (see the lock-lifetime contract in `draw`) and the
/// guard-across-statements hazard that blocked moving the active scrollback is gone.
///
/// `live` is the pane's latest accepted live grid (`None` until its first frame). `exited` is
/// `Some(code)` once its process exited. The remaining fields are the pane's OWN scrollback view
/// (`PaneStore::scrollback` for a non-primary pane; the primary's dedicated [`Shared::scrollback`]
/// for the primary), so paint reads the scrollback of the pane being drawn: `scrolled_offset > 0`
/// means paint `historical` (a cut window already fetched for THIS pane) and show the scroll label;
/// `0` means paint `live`.
#[derive(Clone, Default)]
pub struct PanePaint {
    /// The pane's latest accepted LIVE grid, or `None` until its first frame.
    pub live: Option<Arc<GridSnapshot>>,
    /// `Some(code)` once this pane's process exited; `None` while live.
    pub exited: Option<Option<i32>>,
    /// The pane's scrollback offset from the live bottom (0 = live). Drives the paint-source choice.
    pub scrolled_offset: u32,
    /// Known history length for this pane (for the scroll-indicator fraction), if a reply has landed.
    pub history_len: Option<u32>,
    /// The pane's cached historical window to paint while `scrolled_offset > 0`, or `None`.
    pub historical: Option<Arc<GridSnapshot>>,
}

impl PanePaint {
    /// The grid to actually paint for this pane: the historical window while scrolled up (and a cut
    /// has arrived), else the live grid. The same choice is applied uniformly per pane.
    pub fn paint_grid(&self) -> Option<Arc<GridSnapshot>> {
        if self.scrolled_offset > 0 {
            self.historical
                .as_ref()
                .filter(|historical| {
                    self.live
                        .as_ref()
                        .is_some_and(|live| historical.generation == live.generation)
                })
                .cloned()
                .or_else(|| self.live.clone())
        } else {
            self.live.clone()
        }
    }

    /// The scroll-indicator label for this pane, or `None` at the live bottom. Pure projection of the
    /// owned offset/length so the caller needs no scrollback lock.
    pub fn scroll_label(&self) -> Option<String> {
        scroll_indicator_label(self.scrolled_offset, self.history_len)
    }
}

/// Shared, lock-protected view the UI thread paints from.
#[derive(Default)]
pub struct Shared {
    /// The session the renderer is CURRENTLY bound to (id + rebind epoch). Written by
    /// the UI thread on a tab switch ([`Shared::set_active_session`]), read by the
    /// reader thread before each event so it rebinds its `SyncState` to a new id and
    /// rejects late frames from the old one. `None`-equivalent is the empty default
    /// (`id == None`) for connection failures and any explicitly cleared viewport.
    pub active: Mutex<ActiveSession>,
    /// Last allocated connection-local Attach generation. Zero means none allocated yet. Allocation
    /// uses checked monotonic increments; reaching `u64::MAX` permanently fails closed instead of
    /// wrapping and making an ancient forwarder authoritative again.
    next_output_generation: AtomicU64,
    /// Coalesces the fixed local outbound-stall diagnostic until any later admission succeeds.
    outbound_unavailable_logged: AtomicBool,
    /// Writer and reader can discover the same socket death. Exactly one wins fail-closed teardown
    /// and owner notification; later observations are idempotent no-ops.
    connection_closed: AtomicBool,
    /// True only when DaemonInfo on this exact operational socket proved protocol v3 and the
    /// explicit generation-conditional mutation capability. False keeps retained daemons
    /// attach/read-only; no request path may infer mutation support from version alone.
    generation_conditional_mutations: AtomicBool,
    /// Identity/capability proof captured from DaemonInfo on this exact operational socket. A
    /// runtime handoff Claim is refused before serialization unless all immutable facts match.
    operational_daemon_instance: OnceLock<Option<maestro_shell::DaemonInstanceId>>,
    operational_server_pid: OnceLock<Option<u32>>,
    attachment_handoff_capable: AtomicBool,
    /// Current all-route baseline receipt. The owner retains a clone across Shared teardown; the
    /// reader marks primary Claim proof here before any later sibling refusal/EOF can clear caches.
    exact_viewport_admission: Mutex<Option<Arc<ExactViewportAdmissionProof>>>,
    /// Exact-token local recovery intents. `Pending` survives a transient full/contended queue until
    /// OutboundWritable; `admitted` stays coalesced until an exact Grid clears it, preventing a burst
    /// of gap/malformed frames from enqueueing duplicate Snapshots.
    pending_recoveries: Mutex<Vec<PendingRecovery>>,
    /// The most recent grid snapshot (None until the first Grid event), stored
    /// behind an `Arc` so the UI thread can clone-and-release under a short lock
    /// and then shape/submit to the GPU without holding the mutex —
    /// the reader thread is never blocked by a slow frame.
    pub grid: Mutex<Option<Arc<GridSnapshot>>>,
    /// Latest revision seen from any Output/Grid event + when we saw it. Retained
    /// for diagnostics/overlay; it does not drive a poll cadence because the renderer is event-driven.
    pub last_revision: Mutex<Option<(Revision, Instant)>>,
    /// Set when the session process exits; carries the exit code.
    pub exited: Mutex<Option<Option<i32>>>,
    /// Renderer-owned scrollback view state. Read by the UI paint path, written
    /// by both the UI (wheel/key) and the reader (ScrollbackRows reply).
    pub scrollback: Mutex<ScrollbackState>,
    /// The bounded outbound queue. ALL requests — the reader thread's
    /// Attach/Snapshot AND the UI thread's Write/Resize — are framed and pushed
    /// here; one dedicated writer thread (spawned in `spawn`) drains them to the
    /// socket in strict order. Installed exactly once after connect; the handle itself is immutable
    /// so owner-loop admission never contends on an outer handle mutex. Socket teardown marks the
    /// queue closed in place. An unset handle is a typed `NotConnected` refusal (e.g. demo mode).
    outbound: OnceLock<Arc<OutboundQueue>>,
    /// A shutdown-only clone of the connected socket. No reads or writes use this handle; it exists
    /// solely so either owner, reader, or writer failure can interrupt a peer-stalled writer and
    /// force the daemon to tear down every forwarder for this client.
    shutdown_stream: OnceLock<UnixStream>,
    /// Phase A UNIFIED per-session store. ONE map holding a [`PaneStore`] for every non-active
    /// session id: the single rendered split sibling (`kind == Sibling`) AND every extra
    /// non-active pane of a three-or-more-pane layout (`kind == Pane`). Replaces the two
    /// formerly separate stores (`sibling: Mutex<SiblingSession>` + `panes: Mutex<PaneCaches>`)
    /// with one uniform keyed store. Wholly independent of `active`/`grid`/`exited`/`scrollback`
    /// (which remain the live active-session paint path): writing this never disturbs
    /// the active session, and active-session frames never touch it. The reader's former Sibling
    /// and Pane routes both collapse into one keyed lookup of this map.
    pub stores: Mutex<BTreeMap<String, PaneStore>>,
    /// Which id in [`Self::stores`] is the rendered split sibling, or `None` when there is no
    /// split. The pointer half of the sibling binding; the bound entry's grid/exit live in the
    /// map under this id.
    pub sibling_id: Mutex<Option<String>>,
    /// SINGLE monotonic counter for the rendered sibling, preserving the pre-unification
    /// `SiblingSession::epoch` semantics: it bumps on EVERY sibling bind AND clear (even across a
    /// rebind to a brand-new id, where the old map entry is gone), so a late frame from any prior
    /// sibling binding is always rejected by a strictly-greater epoch. Stamped onto the bound
    /// entry's `epoch` so the existing per-entry epoch gate keeps working.
    pub sibling_epoch: Mutex<u64>,
    /// Membership generation for the multi-pane (`kind == Pane`) set, bumped on every membership
    /// change so the reader rebuilds its per-pane `SyncState` map. Independent of the sibling
    /// pointer (which has no generation — it is a single slot).
    pub pane_generation: Mutex<u64>,
    /// Monotonic namespace for pane-role binding epochs. It is deliberately independent of the
    /// membership generation: deriving entry epochs from membership/count can collide after a
    /// remove/re-add (for example initial panes 1..4, clear generation 2, re-add pane epoch 3).
    /// Exhaustion refuses the whole membership mutation rather than wrapping.
    next_pane_epoch: AtomicU64,
}

impl Shared {
    #[inline]
    pub(crate) fn connection_is_closed(&self) -> bool {
        self.connection_closed.load(Ordering::Acquire)
    }

    fn closed_admission() -> RequestAdmission {
        RequestAdmission::Unavailable {
            reason: OutboundUnavailable::Closed,
            wake_now: false,
        }
    }

    fn mutation_unsupported_admission() -> RequestAdmission {
        RequestAdmission::Unavailable {
            reason: OutboundUnavailable::MutationUnsupported,
            wake_now: false,
        }
    }

    fn request_is_terminal_mutation(request: &ClientRequest) -> bool {
        matches!(
            request,
            ClientRequest::Write { .. } | ClientRequest::Resize { .. }
        )
    }

    fn mutations_match_generation(
        requests: &[ClientRequest],
        expected_generation: &SessionGeneration,
    ) -> bool {
        requests.iter().all(|request| match request {
            ClientRequest::Write {
                expected_generation: request_generation,
                ..
            }
            | ClientRequest::Resize {
                expected_generation: request_generation,
                ..
            } => request_generation == expected_generation,
            _ => true,
        })
    }

    fn shutdown_transport_socket(&self) {
        if let Some(stream) = self.shutdown_stream.get() {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }

    fn abort_outbound_queue(&self) {
        if let Some(queue) = self.outbound.get() {
            queue.close();
        }
    }

    fn abort_transport(&self) {
        self.shutdown_transport_socket();
        self.abort_outbound_queue();
    }

    fn fail_closed_connection(&self, proxy: &dyn UserEventSender) {
        if self.connection_closed.swap(true, Ordering::AcqRel) {
            return;
        }
        self.fail_exact_viewport_admission();
        // Socket shutdown cannot wait on an authority or queue mutex. Publish the owner wake before
        // queue abort/cache teardown, either of which may briefly wait on an in-flight guard. Every
        // grant predicate is latch-gated, so the owner can clear projections and present a neutral
        // frame immediately while teardown finishes erasing the physical leaves.
        self.shutdown_transport_socket();
        let _ = proxy.send(UserEvent::ConnectionClosed);
        self.abort_outbound_queue();
        self.clear_viewport();
    }

    #[cfg(test)]
    pub(crate) fn fail_closed_connection_for_test(&self, proxy: &dyn UserEventSender) {
        self.fail_closed_connection(proxy);
    }

    /// Owner-side terminal admission failure. The caller is already on the event loop and performs
    /// its App projection clear synchronously, so no proxy wake is required here.
    pub fn abort_connection(&self) {
        self.connection_closed.store(true, Ordering::Release);
        self.abort_transport();
        self.clear_viewport();
    }

    /// Allocate one socket-global Attach generation. Zero is reserved as the initial counter value;
    /// every successful allocation is therefore non-zero and unique for this connection. Once the
    /// namespace is exhausted, `fetch_update` leaves it at `u64::MAX` and every future bind fails
    /// closed instead of reusing an old forwarder's tag.
    fn allocate_output_generation(&self) -> Option<u64> {
        self.next_output_generation
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |last| {
                last.checked_add(1)
            })
            .ok()
            .and_then(|last| last.checked_add(1))
    }

    fn allocate_pane_epoch(&self) -> Option<u64> {
        self.next_pane_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |last| {
                last.checked_add(1)
            })
            .ok()
            .and_then(|last| last.checked_add(1))
    }

    fn frame_request(req: &ClientRequest) -> Option<Vec<u8>> {
        match serde_json::to_string(req) {
            Ok(mut line) => {
                line.push('\n');
                Some(line.into_bytes())
            }
            Err(e) => {
                eprintln!("maestro-renderer: serialize failed: {e}");
                None
            }
        }
    }

    fn frame_requests(reqs: &[ClientRequest]) -> Option<Vec<Vec<u8>>> {
        reqs.iter().map(Self::frame_request).collect()
    }

    fn admission_from(outcome: TryEnqueueOutcome) -> RequestAdmission {
        match outcome {
            TryEnqueueOutcome::Admitted => RequestAdmission::Admitted,
            TryEnqueueOutcome::Contended { wake_now } => RequestAdmission::Unavailable {
                reason: OutboundUnavailable::Contended,
                wake_now,
            },
            TryEnqueueOutcome::Full => RequestAdmission::Unavailable {
                reason: OutboundUnavailable::Full,
                wake_now: false,
            },
            TryEnqueueOutcome::TooLarge => RequestAdmission::Unavailable {
                reason: OutboundUnavailable::TooLarge,
                wake_now: false,
            },
            TryEnqueueOutcome::Closed => RequestAdmission::Unavailable {
                reason: OutboundUnavailable::Closed,
                wake_now: false,
            },
            TryEnqueueOutcome::Poisoned => RequestAdmission::Unavailable {
                reason: OutboundUnavailable::Poisoned,
                wake_now: false,
            },
        }
    }

    fn note_admission(&self, admission: RequestAdmission) -> RequestAdmission {
        match admission {
            RequestAdmission::Admitted => {
                self.outbound_unavailable_logged
                    .store(false, Ordering::Release);
            }
            RequestAdmission::Unavailable { reason, .. } => {
                if !self
                    .outbound_unavailable_logged
                    .swap(true, Ordering::AcqRel)
                {
                    eprintln!(
                        "maestro-renderer: terminal outbound unavailable ({reason:?}); local viewport remains responsive"
                    );
                }
            }
        }
        admission
    }

    /// Nonblockingly admit one owner/reader request. The returned typed outcome must drive either
    /// local coalescing/retry or an explicit user-visible refusal; this method never waits for the
    /// queue mutex, capacity, a condvar, or socket I/O.
    #[cfg(test)]
    pub fn send_request(&self, req: &ClientRequest) -> RequestAdmission {
        self.send_request_batch(std::slice::from_ref(req))
    }

    pub(crate) fn operational_handoff_peer_matches(&self, claim: &AttachmentHandoffClaim) -> bool {
        self.attachment_handoff_capable.load(Ordering::Acquire)
            && self
                .operational_daemon_instance
                .get()
                .and_then(Option::as_ref)
                == Some(&claim.expected_daemon_instance)
            && self.operational_server_pid.get().copied().flatten() == claim.expected_server_pid
            && (!cfg!(target_os = "linux") || claim.expected_server_pid.is_some())
    }

    pub(crate) fn operational_daemon_instance(&self) -> Option<maestro_shell::DaemonInstanceId> {
        self.operational_daemon_instance
            .get()
            .and_then(Option::as_ref)
            .cloned()
    }

    /// All-or-none nonblocking admission for an ordered protocol transaction. Serialization happens
    /// before queue lookup; an unavailable queue admits zero frames, so Detach/Attach/Resize/Snapshot
    /// plans can never leave a partial prefix that callers mistake for a bound viewport.
    #[cfg(test)]
    pub fn send_request_batch(&self, reqs: &[ClientRequest]) -> RequestAdmission {
        if self.connection_is_closed() {
            return Self::closed_admission();
        }
        if reqs.iter().any(Self::request_is_terminal_mutation)
            && !self
                .generation_conditional_mutations
                .load(Ordering::Acquire)
        {
            return self.note_admission(Self::mutation_unsupported_admission());
        }
        let Some(lines) = Self::frame_requests(reqs) else {
            return self.note_admission(RequestAdmission::Unavailable {
                reason: OutboundUnavailable::Serialize,
                wake_now: false,
            });
        };
        let Some(queue) = self.outbound.get() else {
            return self.note_admission(RequestAdmission::Unavailable {
                reason: OutboundUnavailable::NotConnected,
                wake_now: false,
            });
        };
        if self.connection_is_closed() {
            return Self::closed_admission();
        }
        let admission = Self::admission_from(queue.try_enqueue_batch(lines));
        if self.connection_is_closed() {
            return Self::closed_admission();
        }
        self.note_admission(admission)
    }

    /// Admit one Detach-only cleanup transaction iff the connection is alive and the viewport is
    /// still neutral at the queue linearization point. This is deliberately separate from
    /// [`Self::clear_viewport`]: Clear revokes paint/input authority synchronously, while the owner
    /// retains the exact old attachment set and retries this fail-fast daemon cleanup on capacity.
    /// Holding `active` through the queue try-lock prevents a later published bind from being cut by
    /// a delayed id-only Detach. A ready aggregate bind may instead consume these same ids as its
    /// cleanup prefix.
    pub(crate) fn try_detach_while_neutral(&self, ids: &[String]) -> Option<RequestAdmission> {
        if self.connection_is_closed() {
            return Some(Self::closed_admission());
        }
        let requests: Vec<ClientRequest> = ids
            .iter()
            .filter(|id| !id.is_empty())
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|id| ClientRequest::Detach { id })
            .collect();
        if requests.is_empty() {
            return Some(RequestAdmission::Admitted);
        }
        let Some(lines) = Self::frame_requests(&requests) else {
            return Some(RequestAdmission::Unavailable {
                reason: OutboundUnavailable::Serialize,
                wake_now: false,
            });
        };
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return Some(Self::closed_admission());
        }
        if active.id.is_some() {
            return None;
        }
        let admission = self.outbound.get().map_or(
            RequestAdmission::Unavailable {
                reason: OutboundUnavailable::NotConnected,
                wake_now: false,
            },
            |queue| Self::admission_from(queue.try_enqueue_batch(lines)),
        );
        drop(active);
        if self.connection_is_closed() {
            Some(Self::closed_admission())
        } else {
            Some(self.note_admission(admission))
        }
    }

    /// Register/coalesce one exact-token recovery Snapshot and try its first nonblocking admission.
    /// Reader SyncState remains unchanged on refusal; this registry supplies deterministic retry even
    /// if the daemon emits no later event.
    fn request_recovery_snapshot(&self, token: &ViewportBindingToken) -> RecoveryRequestResult {
        if self.connection_is_closed() {
            return RecoveryRequestResult::Refused(Self::closed_admission());
        }
        let id = match token {
            ViewportBindingToken::Active(token) => token.session_id.clone(),
            ViewportBindingToken::Pane { session_id, .. } => session_id.clone(),
        };
        let Some(line) = Self::frame_request(&ClientRequest::Snapshot { id }) else {
            return RecoveryRequestResult::Refused(self.note_admission(
                RequestAdmission::Unavailable {
                    reason: OutboundUnavailable::Serialize,
                    wake_now: false,
                },
            ));
        };
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return RecoveryRequestResult::Refused(Self::closed_admission());
        }
        let pane_guard = match token {
            ViewportBindingToken::Active(token) => {
                if active.epoch != token.epoch
                    || active.id.as_deref() != Some(token.session_id.as_str())
                    || active.output_generation != Some(token.output_generation)
                {
                    return RecoveryRequestResult::Stale;
                }
                None
            }
            ViewportBindingToken::Pane {
                session_id,
                pane_epoch,
                pane_kind,
                viewport_epoch,
                output_generation,
            } => {
                if active.id.is_none() || active.epoch != *viewport_epoch {
                    return RecoveryRequestResult::Stale;
                }
                let sibling_id = self.sibling_id.lock().unwrap();
                let stores = self.stores.lock().unwrap();
                if !stores.get(session_id).is_some_and(|entry| {
                    entry.kind == *pane_kind
                        && (*pane_kind != PaneKind::Sibling
                            || sibling_id.as_deref() == Some(session_id.as_str()))
                        && entry.epoch == *pane_epoch
                        && entry.output_generation == Some(*output_generation)
                }) {
                    return RecoveryRequestResult::Stale;
                }
                Some((sibling_id, stores))
            }
        };
        let mut recoveries = self.pending_recoveries.lock().unwrap();
        if self.connection_is_closed() {
            return RecoveryRequestResult::Refused(Self::closed_admission());
        }
        if let Some(existing) = recoveries.iter().find(|entry| entry.binding == *token) {
            return if existing.admitted {
                RecoveryRequestResult::AlreadyAdmitted
            } else {
                RecoveryRequestResult::Pending { wake_now: false }
            };
        }
        let admission = self.outbound.get().map_or(
            RequestAdmission::Unavailable {
                reason: OutboundUnavailable::NotConnected,
                wake_now: false,
            },
            |queue| Self::admission_from(queue.try_enqueue(line)),
        );
        if self.connection_is_closed() {
            return RecoveryRequestResult::Refused(Self::closed_admission());
        }
        if admission.is_admitted() || admission.is_retryable() {
            // The number of live routes bounds this naturally. Keep a defensive cap so a corrupted
            // membership cannot turn recovery bookkeeping into unbounded memory.
            if recoveries.len() >= 256 {
                drop(recoveries);
                drop(pane_guard);
                drop(active);
                return RecoveryRequestResult::Refused(RequestAdmission::Unavailable {
                    reason: OutboundUnavailable::TooLarge,
                    wake_now: false,
                });
            }
            recoveries.push(PendingRecovery {
                binding: token.clone(),
                admitted: admission.is_admitted(),
            });
        }
        drop(recoveries);
        drop(pane_guard);
        drop(active);
        let admission = self.note_admission(admission);
        if admission.is_admitted() {
            RecoveryRequestResult::Admitted
        } else if admission.is_retryable() {
            RecoveryRequestResult::Pending {
                wake_now: admission.wake_now(),
            }
        } else {
            RecoveryRequestResult::Refused(admission)
        }
    }

    /// Retry all exact pending recoveries after a writable/immediate wake. Each entry transitions
    /// Pending→Admitted under active(+store)→registry→nonblocking-queue locks, so reader events cannot
    /// enqueue a duplicate in the handoff window. Stale bindings are removed without side effects.
    pub fn retry_pending_recoveries(&self) -> RecoveryRetryResult {
        if self.connection_is_closed() {
            return RecoveryRetryResult {
                wake_now: false,
                terminal: true,
            };
        }
        let candidates: Vec<ViewportBindingToken> = self
            .pending_recoveries
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| !entry.admitted)
            .map(|entry| entry.binding.clone())
            .collect();
        let mut result = RecoveryRetryResult::default();
        for token in candidates {
            let id = match &token {
                ViewportBindingToken::Active(token) => token.session_id.clone(),
                ViewportBindingToken::Pane { session_id, .. } => session_id.clone(),
            };
            let Some(line) = Self::frame_request(&ClientRequest::Snapshot { id }) else {
                result.terminal = true;
                break;
            };
            let active = self.active.lock().unwrap();
            if self.connection_is_closed() {
                result.terminal = true;
                break;
            }
            let pane_guard = match &token {
                ViewportBindingToken::Active(active_token) => {
                    if active.epoch != active_token.epoch
                        || active.id.as_deref() != Some(active_token.session_id.as_str())
                        || active.output_generation != Some(active_token.output_generation)
                    {
                        drop(active);
                        self.clear_recovery(&token);
                        continue;
                    }
                    None
                }
                ViewportBindingToken::Pane {
                    session_id,
                    pane_epoch,
                    pane_kind,
                    viewport_epoch,
                    output_generation,
                } => {
                    if active.id.is_none() || active.epoch != *viewport_epoch {
                        drop(active);
                        self.clear_recovery(&token);
                        continue;
                    }
                    let sibling_id_guard = self.sibling_id.lock().unwrap();
                    let stores = self.stores.lock().unwrap();
                    if !stores.get(session_id).is_some_and(|entry| {
                        entry.kind == *pane_kind
                            && (*pane_kind != PaneKind::Sibling
                                || sibling_id_guard.as_deref() == Some(session_id.as_str()))
                            && entry.epoch == *pane_epoch
                            && entry.output_generation == Some(*output_generation)
                    }) {
                        drop(stores);
                        drop(active);
                        self.clear_recovery(&token);
                        continue;
                    }
                    Some((sibling_id_guard, stores))
                }
            };
            let mut recoveries = self.pending_recoveries.lock().unwrap();
            let Some(entry) = recoveries
                .iter_mut()
                .find(|entry| entry.binding == token && !entry.admitted)
            else {
                continue;
            };
            if self.connection_is_closed() {
                result.terminal = true;
                break;
            }
            let admission = self.outbound.get().map_or(
                RequestAdmission::Unavailable {
                    reason: OutboundUnavailable::NotConnected,
                    wake_now: false,
                },
                |queue| Self::admission_from(queue.try_enqueue(line)),
            );
            if self.connection_is_closed() {
                result.terminal = true;
                break;
            }
            if admission.is_admitted() {
                entry.admitted = true;
            }
            drop(recoveries);
            drop(pane_guard);
            drop(active);
            let admission = self.note_admission(admission);
            if admission.wake_now() {
                result.wake_now = true;
            }
            if admission.is_connection_terminal() {
                result.terminal = true;
                break;
            }
        }
        result
    }

    fn clear_recovery(&self, token: &ViewportBindingToken) {
        self.pending_recoveries
            .lock()
            .unwrap()
            .retain(|entry| entry.binding != *token);
    }

    /// Atomically validate one captured binding and nonblockingly admit an ordered request batch.
    /// `None` means the incarnation is stale and must be discarded; `Some` carries the queue's typed
    /// admission result. Serialization happens before locking. The active guard spans validation
    /// through the approved fail-fast queue try-lock, so clear cannot linearize between check and
    /// admission. No authority guard survives into logging, proxy work, or socket I/O.
    pub fn send_request_batch_for_binding(
        &self,
        token: &ViewportBindingToken,
        reqs: &[ClientRequest],
        expected_generation: &SessionGeneration,
        scroll_intent: Option<&ScrollRequestIntent>,
    ) -> Option<RequestAdmission> {
        if self.connection_is_closed() {
            return Some(Self::closed_admission());
        }
        if reqs.iter().any(Self::request_is_terminal_mutation)
            && !self
                .generation_conditional_mutations
                .load(Ordering::Acquire)
        {
            return Some(self.note_admission(Self::mutation_unsupported_admission()));
        }
        if !Self::mutations_match_generation(reqs, expected_generation) {
            return None;
        }
        let Some(lines) = Self::frame_requests(reqs) else {
            return Some(self.note_admission(RequestAdmission::Unavailable {
                reason: OutboundUnavailable::Serialize,
                wake_now: false,
            }));
        };
        // A Scrollback correlation is part of the same exact admission transaction. It must be
        // installed before the frame becomes visible to the writer, and removed again on any queue
        // refusal. Only one query per exact route may be in flight; later gestures coalesce in App
        // until consuming any matching/mismatched reply emits OutboundWritable.
        let scroll_request = scroll_intent.and_then(|intent| match reqs {
            [ClientRequest::Scrollback {
                id,
                offset_from_top,
                ..
            }] if *offset_from_top == intent.requested_offset => Some((id.as_str(), intent)),
            _ => None,
        });
        let has_scrollback = reqs
            .iter()
            .any(|request| matches!(request, ClientRequest::Scrollback { .. }));
        if scroll_intent.is_some() != has_scrollback || scroll_request.is_some() != has_scrollback {
            return Some(self.note_admission(RequestAdmission::Unavailable {
                reason: OutboundUnavailable::Serialize,
                wake_now: false,
            }));
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return Some(Self::closed_admission());
        }
        let admission = match token {
            ViewportBindingToken::Active(token) => {
                if active.epoch != token.epoch
                    || active.id.as_deref() != Some(token.session_id.as_str())
                    || active.output_generation != Some(token.output_generation)
                {
                    return None;
                }
                let grid = self.grid.lock().unwrap();
                if self.connection_is_closed() {
                    return Some(Self::closed_admission());
                }
                if grid.as_ref().map(|grid| &grid.generation) != Some(expected_generation) {
                    return None;
                }
                if let Some((request_id, intent)) = scroll_request {
                    if request_id != token.session_id {
                        return None;
                    }
                    if expected_generation != &intent.expected_generation {
                        return None;
                    }
                    let mut scrollback = self.scrollback.lock().unwrap();
                    if self.connection_is_closed() {
                        return Some(Self::closed_admission());
                    }
                    if scrollback.intent_epoch != intent.intent_epoch
                        || scrollback.view_offset != intent.requested_offset
                    {
                        return None;
                    }
                    if scrollback.admitted_request.is_some() {
                        drop(scrollback);
                        drop(active);
                        return Some(RequestAdmission::Unavailable {
                            reason: OutboundUnavailable::ScrollbackInFlight,
                            wake_now: false,
                        });
                    }
                    scrollback.discard_admitted_reply_metadata = false;
                    scrollback.admitted_request = Some((
                        intent.intent_epoch,
                        intent.requested_offset,
                        intent.expected_generation.clone(),
                    ));
                    let admission = self.outbound.get().map_or(
                        RequestAdmission::Unavailable {
                            reason: OutboundUnavailable::NotConnected,
                            wake_now: false,
                        },
                        |queue| Self::admission_from(queue.try_enqueue_batch(lines)),
                    );
                    if self.connection_is_closed() {
                        scrollback.admitted_request = None;
                        return Some(Self::closed_admission());
                    }
                    if !admission.is_admitted() {
                        scrollback.admitted_request = None;
                    }
                    admission
                } else {
                    let admission = self.outbound.get().map_or(
                        RequestAdmission::Unavailable {
                            reason: OutboundUnavailable::NotConnected,
                            wake_now: false,
                        },
                        |queue| Self::admission_from(queue.try_enqueue_batch(lines)),
                    );
                    if self.connection_is_closed() {
                        return Some(Self::closed_admission());
                    }
                    admission
                }
            }
            ViewportBindingToken::Pane {
                session_id,
                pane_epoch,
                pane_kind,
                viewport_epoch,
                output_generation,
            } => {
                if active.id.is_none() || active.epoch != *viewport_epoch {
                    return None;
                }
                let sibling_id = self.sibling_id.lock().unwrap();
                let mut stores = self.stores.lock().unwrap();
                if self.connection_is_closed() {
                    return Some(Self::closed_admission());
                }
                let entry = stores.get_mut(session_id)?;
                if !(entry.kind == *pane_kind
                    && (*pane_kind != PaneKind::Sibling
                        || sibling_id.as_deref() == Some(session_id.as_str()))
                    && entry.epoch == *pane_epoch
                    && entry.output_generation == Some(*output_generation))
                {
                    return None;
                }
                if entry.grid.as_ref().map(|grid| &grid.generation) != Some(expected_generation) {
                    return None;
                }
                if let Some((request_id, intent)) = scroll_request {
                    if request_id != session_id {
                        return None;
                    }
                    if expected_generation != &intent.expected_generation
                        || entry.scrollback.intent_epoch != intent.intent_epoch
                        || entry.scrollback.view_offset != intent.requested_offset
                    {
                        return None;
                    }
                    if entry.scrollback.admitted_request.is_some() {
                        drop(stores);
                        drop(sibling_id);
                        drop(active);
                        return Some(RequestAdmission::Unavailable {
                            reason: OutboundUnavailable::ScrollbackInFlight,
                            wake_now: false,
                        });
                    }
                    entry.scrollback.discard_admitted_reply_metadata = false;
                    entry.scrollback.admitted_request = Some((
                        intent.intent_epoch,
                        intent.requested_offset,
                        intent.expected_generation.clone(),
                    ));
                    let admission = self.outbound.get().map_or(
                        RequestAdmission::Unavailable {
                            reason: OutboundUnavailable::NotConnected,
                            wake_now: false,
                        },
                        |queue| Self::admission_from(queue.try_enqueue_batch(lines)),
                    );
                    if self.connection_is_closed() {
                        entry.scrollback.admitted_request = None;
                        return Some(Self::closed_admission());
                    }
                    if !admission.is_admitted() {
                        entry.scrollback.admitted_request = None;
                    }
                    admission
                } else {
                    let admission = self.outbound.get().map_or(
                        RequestAdmission::Unavailable {
                            reason: OutboundUnavailable::NotConnected,
                            wake_now: false,
                        },
                        |queue| Self::admission_from(queue.try_enqueue_batch(lines)),
                    );
                    if self.connection_is_closed() {
                        return Some(Self::closed_admission());
                    }
                    admission
                }
            }
        };
        // This is the sole narrow authority→outbound critical section. Both handle lookup and
        // byte admission are fail-fast try-locks: never replace either with `lock`/`enqueue`, a
        // condvar wait, or socket/proxy work while `active`/`stores` are held. The writer path has
        // no queue/outbound→authority acquisition, so there is no reverse edge.
        drop(active);
        if self.connection_is_closed() {
            Some(Self::closed_admission())
        } else {
            Some(self.note_admission(admission))
        }
    }

    /// Read the current active session (id + epoch) under a short lock.
    pub fn active_snapshot(&self) -> ActiveSession {
        self.active_snapshot_after_precheck(|| {})
    }

    fn active_snapshot_after_precheck(&self, before_lock: impl FnOnce()) -> ActiveSession {
        if self.connection_is_closed() {
            return ActiveSession::default();
        }
        before_lock();
        let snapshot = self.active.lock().unwrap().clone();
        if self.connection_is_closed() {
            ActiveSession::default()
        } else {
            snapshot
        }
    }

    #[cfg(test)]
    fn active_snapshot_with_prelock_hook(&self, before_lock: impl FnOnce()) -> ActiveSession {
        self.active_snapshot_after_precheck(before_lock)
    }

    /// Capture the exact current primary binding, or `None` while the viewport is neutral.
    #[cfg(test)]
    pub fn active_token(&self) -> Option<ActiveBindingToken> {
        if self.connection_is_closed() {
            return None;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return None;
        }
        active
            .id
            .as_ref()
            .zip(active.output_generation)
            .map(|(session_id, output_generation)| ActiveBindingToken {
                session_id: session_id.clone(),
                epoch: active.epoch,
                output_generation,
            })
    }

    /// Whether `token` still names the exact live primary incarnation.
    pub fn active_token_is_current(&self, token: &ActiveBindingToken) -> bool {
        if self.connection_is_closed() {
            return false;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return false;
        }
        active.epoch == token.epoch
            && active.id.as_deref() == Some(token.session_id.as_str())
            && active.output_generation == Some(token.output_generation)
    }

    /// Consumer-side validation for queued terminal effects.
    pub fn viewport_token_is_current(&self, token: &ViewportBindingToken) -> bool {
        if self.connection_is_closed() {
            return false;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return false;
        }
        let current = match token {
            ViewportBindingToken::Active(token) => {
                active.epoch == token.epoch
                    && active.id.as_deref() == Some(token.session_id.as_str())
                    && active.output_generation == Some(token.output_generation)
            }
            ViewportBindingToken::Pane {
                session_id,
                pane_epoch,
                pane_kind,
                viewport_epoch,
                output_generation,
            } => {
                if active.id.is_none() || active.epoch != *viewport_epoch {
                    return false;
                }
                let sibling_id = self.sibling_id.lock().unwrap();
                let stores = self.stores.lock().unwrap();
                stores.get(session_id).is_some_and(|entry| {
                    entry.kind == *pane_kind
                        && (*pane_kind != PaneKind::Sibling
                            || sibling_id.as_deref() == Some(session_id.as_str()))
                        && entry.epoch == *pane_epoch
                        && entry.output_generation == Some(*output_generation)
                })
            }
        };
        !self.connection_is_closed() && current
    }

    /// Resolve the exact current route authority for `session_id` in one fixed lock order. Active
    /// wins over the store roles, matching reader dispatch. Used after a blocking socket read to
    /// detect same-id ABA without stamping old bytes with a newly rebuilt binding.
    pub(crate) fn binding_token_for_session(
        &self,
        session_id: &str,
    ) -> Option<ViewportBindingToken> {
        if self.connection_is_closed() {
            return None;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return None;
        }
        if active.id.as_deref() == Some(session_id) {
            let output_generation = active.output_generation?;
            let token = ViewportBindingToken::Active(ActiveBindingToken {
                session_id: session_id.to_string(),
                epoch: active.epoch,
                output_generation,
            });
            return (!self.connection_is_closed()).then_some(token);
        }
        active.id.as_ref()?;
        let sibling_id = self.sibling_id.lock().unwrap();
        let stores = self.stores.lock().unwrap();
        let entry = stores.get(session_id)?;
        if entry.kind == PaneKind::Sibling && sibling_id.as_deref() != Some(session_id) {
            return None;
        }
        let token = ViewportBindingToken::Pane {
            session_id: session_id.to_string(),
            pane_epoch: entry.epoch,
            pane_kind: entry.kind,
            viewport_epoch: active.epoch,
            output_generation: entry.output_generation?,
        };
        (!self.connection_is_closed()).then_some(token)
    }

    /// Clear the primary leaves while the caller holds `active`. The lock order is deliberately
    /// active -> one leaf at a time; no leaf guard survives into the next acquisition.
    fn clear_primary_state_while_active(&self) {
        *self.last_revision.lock().unwrap() = None;
        *self.grid.lock().unwrap() = None;
        *self.exited.lock().unwrap() = None;
        *self.scrollback.lock().unwrap() = ScrollbackState::default();
    }

    /// Initialize the first active binding and allocate its exact daemon-stream generation. Called
    /// once before the initial Attach is enqueued. Allocation/epoch exhaustion leaves the viewport
    /// neutral and returns `None` (fail closed; never reuse an ancient incarnation).
    pub(crate) fn init_active_session(&self, id: &str) -> Option<ActiveBindingToken> {
        self.init_active_session_with_generation(id, None)
    }

    fn init_active_session_with_generation(
        &self,
        id: &str,
        expected_generation: Option<SessionGeneration>,
    ) -> Option<ActiveBindingToken> {
        if self.connection_is_closed() {
            return None;
        }
        let output_generation = self.allocate_output_generation()?;
        let mut active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return None;
        }
        let epoch = active.epoch.checked_add(1)?;
        active.id = Some(id.to_string());
        active.epoch = epoch;
        active.output_generation = Some(output_generation);
        active.expected_generation = expected_generation;
        Some(ActiveBindingToken {
            session_id: id.to_string(),
            epoch,
            output_generation,
        })
    }

    /// Rebind the renderer to `new_id`, bumping the epoch so the reader thread rebuilds
    /// its `SyncState` and rejects late frames from the old session. Returns the bumped
    /// epoch. Called from the UI thread on a real tab switch (see
    /// [`crate::App::attach_session`]); the reader notices the epoch change on its next
    /// event and rebases. A no-op-detecting caller must compare ids BEFORE calling this
    /// (this always bumps the epoch).
    #[cfg(test)]
    pub fn set_active_session(&self, new_id: &str) -> Option<ActiveBindingToken> {
        if self.connection_is_closed() {
            return None;
        }
        let Some(output_generation) = self.allocate_output_generation() else {
            self.clear_viewport();
            return None;
        };
        let epoch = {
            let mut active = self.active.lock().unwrap();
            if self.connection_is_closed() {
                return None;
            }
            let Some(epoch) = active.epoch.checked_add(1) else {
                active.id = None;
                active.output_generation = None;
                active.expected_generation = None;
                self.clear_primary_state_while_active();
                drop(active);
                // Revocation is mandatory even when no next epoch exists. Stores cannot survive a
                // failed bind and later paint/reconcile as if the old viewport were still live.
                self.clear_sibling_session();
                self.clear_pane_sessions();
                return None;
            };
            active.epoch = epoch;
            active.id = Some(new_id.to_string());
            active.output_generation = Some(output_generation);
            active.expected_generation = None;
            self.clear_primary_state_while_active();
            epoch
        };
        Some(ActiveBindingToken {
            session_id: new_id.to_string(),
            epoch,
            output_generation,
        })
    }

    /// Admit one complete viewport topology transaction before publishing any new role authority.
    /// Every old/pending Detach precedes every primary/pane Attach; each new role gets a unique
    /// connection-global output generation; and App/reader mirrors advance only after the aggregate
    /// byte batch is admitted. The fixed lock order is active→sibling_id→pane_generation→stores,
    /// followed only by the approved nonblocking queue try-lock.
    pub fn try_bind_viewport(
        &self,
        desired: &DesiredViewportBinding,
        detach_ids: &[String],
        primary_handoff: Option<&AttachmentHandoffClaim>,
    ) -> Result<ViewportBindingSet, ActiveBindFailure> {
        if self.connection_is_closed() {
            return Err(ActiveBindFailure::Admission(Self::closed_admission()));
        }
        if !self.attachment_handoff_capable.load(Ordering::Acquire) {
            return Err(ActiveBindFailure::HandoffPeerMismatch);
        }
        if desired.primary_session_id.is_empty()
            || desired.primary_expected_generation.0.is_empty()
            || desired.primary_expected_generation.0.len() > 128
            || desired.panes.iter().any(|pane| {
                pane.session_id.is_empty()
                    || pane.expected_generation.0.is_empty()
                    || pane.expected_generation.0.len() > 128
            })
        {
            return Err(ActiveBindFailure::AuthorityExhausted);
        }
        if primary_handoff.is_some_and(|claim| {
            claim.session_id != desired.primary_session_id
                || claim.expected_generation != desired.primary_expected_generation.0
                || !self.operational_handoff_peer_matches(claim)
        }) {
            return Err(ActiveBindFailure::HandoffPeerMismatch);
        }
        let mut unique_ids = std::collections::BTreeSet::new();
        unique_ids.insert(desired.primary_session_id.as_str());
        if desired
            .panes
            .iter()
            .any(|pane| !unique_ids.insert(pane.session_id.as_str()))
        {
            return Err(ActiveBindFailure::AuthorityExhausted);
        }
        let Some(primary_output_generation) = self.allocate_output_generation() else {
            return Err(ActiveBindFailure::AuthorityExhausted);
        };
        let mut pane_authority = Vec::with_capacity(desired.panes.len());
        for pane in &desired.panes {
            let Some(output_generation) = self.allocate_output_generation() else {
                return Err(ActiveBindFailure::AuthorityExhausted);
            };
            let Some(epoch) = self.allocate_pane_epoch() else {
                return Err(ActiveBindFailure::AuthorityExhausted);
            };
            pane_authority.push((pane.clone(), epoch, output_generation));
        }

        let unique_detaches: std::collections::BTreeSet<String> = detach_ids
            .iter()
            .filter(|id| !id.is_empty())
            .cloned()
            .collect();
        let mut plan = Vec::with_capacity(unique_detaches.len() + 2 * (pane_authority.len() + 1));
        plan.extend(
            unique_detaches
                .into_iter()
                .map(|id| ClientRequest::Detach { id }),
        );
        plan.push(ClientRequest::Attach {
            id: desired.primary_session_id.clone(),
            want_raw_output: false,
            expected_session_generation: Some(desired.primary_expected_generation.0.clone()),
            output_generation: Some(primary_output_generation),
            handoff: primary_handoff.map(|claim| maestro_shell::AttachmentHandoff::Claim {
                token: claim.token.clone(),
            }),
        });
        plan.push(ClientRequest::Snapshot {
            id: desired.primary_session_id.clone(),
        });
        for (pane, _, output_generation) in &pane_authority {
            plan.push(ClientRequest::Attach {
                id: pane.session_id.clone(),
                want_raw_output: false,
                expected_session_generation: Some(pane.expected_generation.0.clone()),
                output_generation: Some(*output_generation),
                handoff: None,
            });
            plan.push(ClientRequest::Snapshot {
                id: pane.session_id.clone(),
            });
        }
        let Some(lines) = Self::frame_requests(&plan) else {
            return Err(ActiveBindFailure::Admission(
                RequestAdmission::Unavailable {
                    reason: OutboundUnavailable::Serialize,
                    wake_now: false,
                },
            ));
        };

        let mut active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return Err(ActiveBindFailure::Admission(Self::closed_admission()));
        }
        let Some(epoch) = active.epoch.checked_add(1) else {
            return Err(ActiveBindFailure::AuthorityExhausted);
        };
        let mut sibling_id = self.sibling_id.lock().unwrap();
        let mut pane_generation = self.pane_generation.lock().unwrap();
        let Some(next_pane_generation) = pane_generation.checked_add(1) else {
            return Err(ActiveBindFailure::AuthorityExhausted);
        };
        let mut stores = self.stores.lock().unwrap();
        if self.connection_is_closed() {
            return Err(ActiveBindFailure::Admission(Self::closed_admission()));
        }
        let Some(queue) = self.outbound.get() else {
            return Err(ActiveBindFailure::Admission(
                RequestAdmission::Unavailable {
                    reason: OutboundUnavailable::NotConnected,
                    wake_now: false,
                },
            ));
        };
        let primary_token = ActiveBindingToken {
            session_id: desired.primary_session_id.clone(),
            epoch,
            output_generation: primary_output_generation,
        };
        let mut routes = Vec::with_capacity(pane_authority.len() + 1);
        routes.push(ExactViewportRouteBinding {
            token: ViewportBindingToken::Active(primary_token.clone()),
            expected_generation: desired.primary_expected_generation.clone(),
            primary: true,
        });
        for (pane, pane_epoch, output_generation) in &pane_authority {
            routes.push(ExactViewportRouteBinding {
                token: ViewportBindingToken::Pane {
                    session_id: pane.session_id.clone(),
                    pane_epoch: *pane_epoch,
                    pane_kind: PaneKind::Pane,
                    viewport_epoch: epoch,
                    output_generation: *output_generation,
                },
                expected_generation: pane.expected_generation.clone(),
                primary: false,
            });
        }
        let proof = Arc::new(ExactViewportAdmissionProof {
            routes,
            progress: Mutex::new(ExactViewportAdmissionProgress::default()),
            primary_authority: primary_handoff.map(|claim| claim.authority.clone()),
            primary_claim_proven: AtomicBool::new(false),
        });
        if let Some(previous) = self
            .exact_viewport_admission
            .lock()
            .unwrap()
            .replace(Arc::clone(&proof))
        {
            previous.fail();
        }
        if let Some(claim) = primary_handoff {
            // This shared authority bit is deliberately set before queue admission. Every clone,
            // including a concurrently cancelling duplicate, must classify the Claim as possibly
            // applied from this publication boundary onward, even if this local enqueue refuses.
            claim.authority.mark_claim_admitted();
        }
        let admission = Self::admission_from(queue.try_enqueue_batch(lines));
        if !admission.is_admitted() {
            proof.fail();
            self.exact_viewport_admission.lock().unwrap().take();
            drop(stores);
            drop(pane_generation);
            drop(sibling_id);
            drop(active);
            let _ = self.note_admission(admission);
            return Err(ActiveBindFailure::Admission(admission));
        }
        if self.connection_is_closed() {
            proof.fail();
            drop(stores);
            drop(pane_generation);
            drop(sibling_id);
            drop(active);
            let _ = self.note_admission(admission);
            return Ok(ViewportBindingSet {
                primary: primary_token,
                proof,
            });
        }

        active.epoch = epoch;
        active.id = Some(desired.primary_session_id.clone());
        active.output_generation = Some(primary_output_generation);
        active.expected_generation = Some(desired.primary_expected_generation.clone());
        self.clear_primary_state_while_active();
        *sibling_id = None;
        *pane_generation = next_pane_generation;
        stores.clear();
        for (pane, pane_epoch, output_generation) in pane_authority {
            stores.insert(
                pane.session_id,
                PaneStore {
                    kind: PaneKind::Pane,
                    epoch: pane_epoch,
                    output_generation: Some(output_generation),
                    expected_generation: Some(pane.expected_generation),
                    grid: None,
                    exited: None,
                    scrollback: ScrollbackState::default(),
                },
            );
        }
        self.pending_recoveries.lock().unwrap().clear();
        drop(stores);
        drop(pane_generation);
        drop(sibling_id);
        drop(active);
        let _ = self.note_admission(admission);
        Ok(ViewportBindingSet {
            primary: primary_token,
            proof,
        })
    }

    /// Linearize a viewport clear locally. This never contacts the daemon: it first revokes the
    /// active binding and clears every primary leaf while holding `active`, then releases that lock
    /// before clearing the independent sibling/pane stores. Repeated calls remain neutral and merely
    /// advance the epoch, invalidating any queued work captured between them.
    pub fn clear_viewport(&self) -> u64 {
        self.fail_exact_viewport_admission();
        let epoch = {
            let mut active = teardown_lock(&self.active);
            active.epoch = active.epoch.saturating_add(1);
            active.id = None;
            active.output_generation = None;
            active.expected_generation = None;
            *teardown_lock(&self.last_revision) = None;
            *teardown_lock(&self.grid) = None;
            *teardown_lock(&self.exited) = None;
            *teardown_lock(&self.scrollback) = ScrollbackState::default();
            active.epoch
        };
        let mut sibling_id = teardown_lock(&self.sibling_id);
        let had_sibling = sibling_id.take().is_some();
        let mut sibling_epoch = teardown_lock(&self.sibling_epoch);
        if had_sibling {
            if let Some(next) = sibling_epoch.checked_add(1) {
                *sibling_epoch = next;
            }
        }
        let mut pane_generation = teardown_lock(&self.pane_generation);
        let mut stores = teardown_lock(&self.stores);
        let had_panes = stores.values().any(|entry| entry.kind == PaneKind::Pane);
        stores.clear();
        if had_panes {
            if let Some(next) = pane_generation.checked_add(1) {
                *pane_generation = next;
            }
        }
        drop(stores);
        drop(pane_generation);
        drop(sibling_epoch);
        drop(sibling_id);
        teardown_lock(&self.pending_recoveries).clear();
        epoch
    }

    fn fail_exact_viewport_admission(&self) {
        if let Some(proof) = self.exact_viewport_admission.lock().unwrap().take() {
            proof.fail();
        }
    }

    fn note_exact_viewport_grid(
        &self,
        token: &ViewportBindingToken,
        generation: &SessionGeneration,
    ) -> Option<bool> {
        let proof = self.exact_viewport_admission.lock().unwrap().clone()?;
        Some(proof.note_grid(token, generation))
    }

    /// Read the primary grid only if `token` remains current. The active guard stays held through
    /// the one leaf read so ClearViewport is the linearization point.
    fn active_grid_for(&self, token: &ActiveBindingToken) -> Option<Arc<GridSnapshot>> {
        if self.connection_is_closed() {
            return None;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return None;
        }
        if active.epoch != token.epoch
            || active.id.as_deref() != Some(token.session_id.as_str())
            || active.output_generation != Some(token.output_generation)
        {
            return None;
        }
        let grid = self.grid.lock().unwrap().clone();
        (!self.connection_is_closed()).then_some(grid).flatten()
    }

    /// Commit an accepted active grid under the exact captured binding. Each leaf is touched alone
    /// under the active guard; no proxy wake or outbound request happens while either lock is held.
    fn commit_active_grid(
        &self,
        token: &ActiveBindingToken,
        revision: Revision,
        grid: Arc<GridSnapshot>,
    ) -> bool {
        if self.connection_is_closed() {
            return false;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return false;
        }
        if active.epoch != token.epoch
            || active.id.as_deref() != Some(token.session_id.as_str())
            || active.output_generation != Some(token.output_generation)
        {
            return false;
        }
        {
            let mut last_revision = self.last_revision.lock().unwrap();
            if self.connection_is_closed() {
                return false;
            }
            *last_revision = Some((revision, Instant::now()));
        }
        let live_context_changed = {
            let mut held = self.grid.lock().unwrap();
            if self.connection_is_closed() {
                return false;
            }
            let changed = held.as_ref().is_some_and(|previous| {
                previous.generation != grid.generation || previous.alt_screen != grid.alt_screen
            });
            *held = Some(grid);
            changed
        };
        if live_context_changed {
            let mut scrollback = self.scrollback.lock().unwrap();
            if self.connection_is_closed() {
                return false;
            }
            scrollback.reset_for_live_context_change();
        }
        !self.connection_is_closed()
    }

    fn commit_active_resync(&self, token: &ActiveBindingToken) -> bool {
        if self.connection_is_closed() {
            return false;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return false;
        }
        if active.epoch != token.epoch
            || active.id.as_deref() != Some(token.session_id.as_str())
            || active.output_generation != Some(token.output_generation)
        {
            return false;
        }
        let mut last_revision = self.last_revision.lock().unwrap();
        if self.connection_is_closed() {
            return false;
        }
        *last_revision = Some((Revision(u64::MAX), Instant::now()));
        !self.connection_is_closed()
    }

    fn commit_active_exit(&self, token: &ActiveBindingToken, code: Option<i32>) -> bool {
        if self.connection_is_closed() {
            return false;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return false;
        }
        if active.epoch != token.epoch
            || active.id.as_deref() != Some(token.session_id.as_str())
            || active.output_generation != Some(token.output_generation)
        {
            return false;
        }
        let mut exited = self.exited.lock().unwrap();
        if self.connection_is_closed() {
            return false;
        }
        *exited = Some(code);
        !self.connection_is_closed()
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_active_scrollback(
        &self,
        token: &ActiveBindingToken,
        generation: SessionGeneration,
        revision: Revision,
        history_len: u32,
        offset_from_top: u32,
        rows: CopyRows,
    ) -> bool {
        if self.connection_is_closed() {
            return false;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return false;
        }
        if active.epoch != token.epoch
            || active.id.as_deref() != Some(token.session_id.as_str())
            || active.output_generation != Some(token.output_generation)
        {
            return false;
        }
        let live_generation = {
            let grid = self.grid.lock().unwrap();
            if self.connection_is_closed() {
                return false;
            }
            grid.as_ref().map(|grid| grid.generation.clone())
        };
        let mut scrollback = self.scrollback.lock().unwrap();
        if self.connection_is_closed() {
            return false;
        }
        let applied = apply_scrollback_payload(
            live_generation,
            &mut scrollback,
            generation,
            revision,
            history_len,
            offset_from_top,
            rows,
        );
        !self.connection_is_closed() && applied
    }

    /// Snapshot the rendered sibling (id + epoch + grid + exit) from the unified store under a
    /// short lock. Shim over [`Self::stores`]: reads the [`Self::sibling_id`] pointer, then the
    /// matching `kind == Sibling` entry. Returns the empty default when there is no split.
    pub fn sibling_snapshot(&self) -> SiblingSession {
        if self.connection_is_closed() {
            return SiblingSession::default();
        }
        let id = self.sibling_id.lock().unwrap().clone();
        let stores = self.stores.lock().unwrap();
        let snapshot = match id {
            Some(id) => match stores.get(&id) {
                Some(entry) if entry.kind == PaneKind::Sibling => SiblingSession {
                    id: Some(id),
                    epoch: entry.epoch,
                    output_generation: entry.output_generation,
                    grid: entry.grid.clone(),
                    exited: entry.exited,
                },
                // Pointer set but entry missing/wrong-kind (shouldn't happen): report the id with
                // an empty payload so callers see the binding but no stale grid.
                _ => SiblingSession {
                    id: Some(id),
                    epoch: 0,
                    output_generation: None,
                    grid: None,
                    exited: None,
                },
            },
            None => SiblingSession::default(),
        };
        if self.connection_is_closed() {
            SiblingSession::default()
        } else {
            snapshot
        }
    }

    /// Run one pane-store mutation only while the complete routed binding is still current. Lock
    /// order is always `active -> sibling_id -> stores`; the active viewport guard makes
    /// ClearViewport the linearization point, while role/entry epoch/output-generation prevent
    /// remove/re-add and Pane↔Sibling ABA. The closure performs one leaf mutation and no proxy,
    /// host, outbound, or socket work.
    fn with_current_pane_store(
        &self,
        token: &ViewportBindingToken,
        expected_kind: PaneKind,
        f: impl FnOnce(&mut PaneStore) -> bool,
    ) -> bool {
        if self.connection_is_closed() {
            return false;
        }
        let ViewportBindingToken::Pane {
            session_id,
            pane_epoch,
            pane_kind,
            viewport_epoch,
            output_generation,
        } = token
        else {
            return false;
        };
        if *pane_kind != expected_kind {
            return false;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return false;
        }
        if active.id.is_none() || active.epoch != *viewport_epoch {
            return false;
        }
        let sibling_id = self.sibling_id.lock().unwrap();
        if expected_kind == PaneKind::Sibling && sibling_id.as_deref() != Some(session_id.as_str())
        {
            return false;
        }
        let mut stores = self.stores.lock().unwrap();
        if self.connection_is_closed() {
            return false;
        }
        let applied = match stores.get_mut(session_id) {
            Some(entry)
                if entry.kind == expected_kind
                    && entry.epoch == *pane_epoch
                    && entry.output_generation == Some(*output_generation) =>
            {
                f(entry)
            }
            _ => false,
        };
        !self.connection_is_closed() && applied
    }

    /// Clone the held pane grid under the same full token gate used by commits. This closes the
    /// accept→clear/rebind→held-read race before Damage is applied.
    fn pane_grid_for_binding(
        &self,
        token: &ViewportBindingToken,
        expected_kind: PaneKind,
    ) -> Option<Arc<GridSnapshot>> {
        let mut grid = None;
        self.with_current_pane_store(token, expected_kind, |entry| {
            grid = entry.grid.clone();
            true
        })
        .then_some(grid)
        .flatten()
    }

    /// Bind the sibling slot of the unified store to `new_id`, bumping its epoch and clearing the
    /// cached grid/exit so a fresh sibling starts empty. Returns the bumped epoch. Idempotent on a
    /// same-id call is the CALLER's job to avoid (this always bumps, dropping any late frame from
    /// the previous binding). Never touches the active session.
    ///
    /// Shim: moves the [`Self::sibling_id`] pointer to `new_id` and (re)installs a fresh
    /// `kind == Sibling` entry. The PRIOR sibling entry (if a different id) is removed so the map
    /// never accumulates orphaned sibling slots.
    #[allow(dead_code)]
    pub fn set_sibling_session(&self, new_id: &str) -> Option<u64> {
        if self.connection_is_closed() {
            return None;
        }
        let Some(output_generation) = self.allocate_output_generation() else {
            self.clear_sibling_session();
            return None;
        };
        let mut sibling_id = self.sibling_id.lock().unwrap();
        let mut sibling_epoch = self.sibling_epoch.lock().unwrap();
        let mut stores = self.stores.lock().unwrap();
        if self.connection_is_closed() {
            return None;
        }
        let Some(next_epoch) = sibling_epoch.checked_add(1) else {
            // Exhaustion permanently closes this role. Revoke the old pointer/cache even though no
            // fresh epoch can be minted; callers observe `None` and must not enqueue an Attach.
            if let Some(old_id) = sibling_id.take() {
                if stores
                    .get(&old_id)
                    .is_some_and(|entry| entry.kind == PaneKind::Sibling)
                {
                    stores.remove(&old_id);
                }
            }
            return None;
        };
        // Drop the previous sibling entry when rebinding to a different id so only one
        // `kind == Sibling` entry ever exists. (A same-id rebind reuses the slot below.)
        if let Some(prev) = sibling_id.as_deref() {
            if prev != new_id {
                if let Some(e) = stores.get(prev) {
                    if e.kind == PaneKind::Sibling {
                        stores.remove(prev);
                    }
                }
            }
        }
        // Bump the single monotonic counter and stamp it (matches old `SiblingSession::epoch`).
        *sibling_epoch = next_epoch;
        let entry = stores.entry(new_id.to_string()).or_default();
        entry.kind = PaneKind::Sibling;
        entry.epoch = *sibling_epoch;
        entry.output_generation = Some(output_generation);
        entry.grid = None;
        entry.exited = None;
        entry.scrollback.reset_to_live();
        *sibling_id = Some(new_id.to_string());
        Some(*sibling_epoch)
    }

    /// Drop the sibling binding entirely (no split → no sibling to cache), bumping the epoch so any
    /// in-flight old-sibling grid is rejected, and removing its entry. Never touches the active
    /// session. Shim: clears the [`Self::sibling_id`] pointer and removes the `kind == Sibling`
    /// entry from the unified store.
    pub fn clear_sibling_session(&self) {
        let mut sibling_id = self.sibling_id.lock().unwrap();
        let mut sibling_epoch = self.sibling_epoch.lock().unwrap();
        let mut stores = self.stores.lock().unwrap();
        let Some(id) = sibling_id.take() else {
            return;
        };
        // Bump the monotonic counter on unbind too, so a late frame from the just-cleared sibling
        // (or any later rebind of the same id) is rejected by a strictly-greater epoch.
        if let Some(next_epoch) = sibling_epoch.checked_add(1) {
            *sibling_epoch = next_epoch;
        }
        if let Some(e) = stores.get(&id) {
            if e.kind == PaneKind::Sibling {
                stores.remove(&id);
            }
        }
    }

    /// Apply a sibling grid IF it belongs to the currently-bound sibling at `for_epoch`.
    /// A grid whose `for_id`/`for_epoch` does not match the live binding is a late frame
    /// from a previous sibling and is dropped (returns `false`). Never touches the active
    /// grid. Returns `true` when the sibling cache was updated. Shim over the unified store
    /// (the `kind == Sibling` entry under `for_id`).
    fn commit_sibling_grid(&self, token: &ViewportBindingToken, grid: Arc<GridSnapshot>) -> bool {
        self.with_current_pane_store(token, PaneKind::Sibling, |entry| {
            let live_context_changed = entry.grid.as_ref().is_some_and(|previous| {
                previous.generation != grid.generation || previous.alt_screen != grid.alt_screen
            });
            entry.grid = Some(grid);
            if live_context_changed {
                entry.scrollback.reset_for_live_context_change();
            }
            true
        })
    }

    /// Record the sibling session's exit IF it belongs to the currently-bound sibling at
    /// `for_epoch`. An exit for a previous sibling is dropped (returns `false`). Never touches
    /// the active session. Returns `true` when recorded. Shim over the unified store.
    fn commit_sibling_exit(&self, token: &ViewportBindingToken, code: Option<i32>) -> bool {
        self.with_current_pane_store(token, PaneKind::Sibling, |entry| {
            entry.exited = Some(code);
            true
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_sibling_scrollback(
        &self,
        token: &ViewportBindingToken,
        generation: SessionGeneration,
        revision: Revision,
        history_len: u32,
        offset_from_top: u32,
        rows: CopyRows,
    ) -> bool {
        self.with_current_pane_store(token, PaneKind::Sibling, |entry| {
            let live_generation = entry.grid.as_ref().map(|g| g.generation.clone());
            apply_scrollback_payload(
                live_generation,
                &mut entry.scrollback,
                generation,
                revision,
                history_len,
                offset_from_top,
                rows,
            )
        })
    }

    // Legacy-shaped test seams keep pre-existing cache tests concise while production handlers
    // must pass their captured full token to the `commit_*` methods above. These wrappers still
    // resolve and validate a live exact token; a neutral viewport or stale epoch returns false.
    #[cfg(test)]
    pub fn apply_sibling_grid(&self, id: &str, epoch: u64, grid: Arc<GridSnapshot>) -> bool {
        let Some(
            token @ ViewportBindingToken::Pane {
                pane_epoch,
                pane_kind: PaneKind::Sibling,
                ..
            },
        ) = self.binding_token_for_session(id)
        else {
            return false;
        };
        pane_epoch == epoch && self.commit_sibling_grid(&token, grid)
    }

    #[cfg(test)]
    pub fn apply_sibling_exit(&self, id: &str, epoch: u64, code: Option<i32>) -> bool {
        let Some(
            token @ ViewportBindingToken::Pane {
                pane_epoch,
                pane_kind: PaneKind::Sibling,
                ..
            },
        ) = self.binding_token_for_session(id)
        else {
            return false;
        };
        pane_epoch == epoch && self.commit_sibling_exit(&token, code)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn apply_sibling_scrollback(
        &self,
        id: &str,
        epoch: u64,
        generation: SessionGeneration,
        revision: Revision,
        history_len: u32,
        offset_from_top: u32,
        rows: Vec<Vec<Cell>>,
    ) -> bool {
        let Some(
            token @ ViewportBindingToken::Pane {
                pane_epoch,
                pane_kind: PaneKind::Sibling,
                ..
            },
        ) = self.binding_token_for_session(id)
        else {
            return false;
        };
        pane_epoch == epoch
            && self.commit_sibling_scrollback(
                &token,
                generation,
                revision,
                history_len,
                offset_from_top,
                (rows, None),
            )
    }

    /// The current generation of the multi-pane membership (bumped on every membership change).
    /// The reader compares this to its local generation to know when to rebuild its per-pane
    /// `SyncState` set.
    #[cfg(test)]
    pub fn pane_generation(&self) -> u64 {
        if self.connection_is_closed() {
            return u64::MAX;
        }
        let generation = *self.pane_generation.lock().unwrap();
        if self.connection_is_closed() {
            u64::MAX
        } else {
            generation
        }
    }

    /// The `kind == Pane` session ids currently bound in the unified store, in sorted order
    /// (`BTreeMap` iteration order). The sibling entry is excluded.
    #[cfg(test)]
    pub fn pane_ids(&self) -> Vec<String> {
        if self.connection_is_closed() {
            return Vec::new();
        }
        let ids = self
            .stores
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, e)| e.kind == PaneKind::Pane)
            .map(|(id, _)| id.clone())
            .collect();
        if self.connection_is_closed() {
            Vec::new()
        } else {
            ids
        }
    }

    /// Snapshot pane membership generation and every pane's binding epoch under one lock-order
    /// consistent observation (`pane_generation` -> `stores`). Reader reconciliation must never
    /// combine a generation from one membership with store epochs from another.
    fn pane_bindings_snapshot(&self) -> PaneBindingsSnapshot {
        if self.connection_is_closed() {
            return (u64::MAX, Vec::new());
        }
        let generation = *self.pane_generation.lock().unwrap();
        let stores = self.stores.lock().unwrap();
        let bindings = stores
            .iter()
            .filter(|(_, entry)| entry.kind == PaneKind::Pane)
            .map(|(id, entry)| {
                (
                    id.clone(),
                    entry.epoch,
                    entry.output_generation,
                    entry.expected_generation.clone(),
                )
            })
            .collect();
        if self.connection_is_closed() {
            (u64::MAX, Vec::new())
        } else {
            (generation, bindings)
        }
    }

    /// Reconcile the multi-pane (`kind == Pane`) membership to exactly `ids` (the visible
    /// non-active pane session ids). Removes pane entries no longer present and inserts fresh
    /// (empty) entries for new ids, bumping each new id's `epoch` so a late frame from a prior
    /// binding of the same id is dropped. Bumps `generation` (and returns the new value) ONLY when
    /// membership actually changed. NEVER touches the active session or the rendered sibling entry
    /// (the `kind == Sibling` filter keeps the reconcile disjoint from the sibling slot).
    #[cfg(test)]
    pub fn set_pane_sessions(&self, ids: &[&str]) -> Option<u64> {
        if self.connection_is_closed() {
            return None;
        }
        let mut generation = self.pane_generation.lock().unwrap();
        let mut stores = self.stores.lock().unwrap();
        if self.connection_is_closed() {
            return None;
        }
        let wanted: std::collections::HashSet<&str> = ids.iter().copied().collect();
        // Remove only PANE entries no longer wanted; the sibling slot is untouched.
        let before: Vec<String> = stores
            .iter()
            .filter(|(id, e)| e.kind == PaneKind::Pane && !wanted.contains(id.as_str()))
            .map(|(id, _)| id.clone())
            .collect();
        let additions: Vec<&str> = ids
            .iter()
            .copied()
            .filter(|id| {
                !stores
                    .get(*id)
                    .is_some_and(|entry| entry.kind == PaneKind::Pane)
            })
            .collect();
        if before.is_empty() && additions.is_empty() {
            return Some(*generation);
        }
        let Some(next_generation) = generation.checked_add(1) else {
            // No representable membership incarnation remains. Revoke every pane cache now and
            // permanently refuse re-adds; keeping the prior stores would preserve stale authority.
            stores.retain(|_, entry| entry.kind != PaneKind::Pane);
            return None;
        };
        // Pre-allocate every proof before mutating the membership. Exhaustion leaves the old set
        // byte-for-byte intact; no partially bound pane can escape without exact authorities.
        let mut allocated = Vec::with_capacity(additions.len());
        for id in additions {
            let Some(epoch) = self.allocate_pane_epoch() else {
                stores.retain(|_, entry| entry.kind != PaneKind::Pane);
                *generation = next_generation;
                return None;
            };
            let Some(output_generation) = self.allocate_output_generation() else {
                stores.retain(|_, entry| entry.kind != PaneKind::Pane);
                *generation = next_generation;
                return None;
            };
            allocated.push((id.to_string(), epoch, output_generation));
        }
        for id in &before {
            stores.remove(id);
        }
        for (id, epoch, output_generation) in allocated {
            let entry = stores.entry(id).or_default();
            entry.kind = PaneKind::Pane;
            entry.epoch = epoch;
            entry.output_generation = Some(output_generation);
            entry.grid = None;
            entry.exited = None;
            entry.scrollback.reset_to_live();
        }
        *generation = next_generation;
        Some(*generation)
    }

    /// Drop ALL multi-pane (`kind == Pane`) entries (e.g. the layout collapsed back to two panes
    /// or no split), bumping `generation` so the reader drops every per-pane `SyncState`. No-op
    /// when there are no pane entries. Never touches the active session or the rendered sibling.
    #[cfg(test)]
    pub fn clear_pane_sessions(&self) {
        let mut generation = self.pane_generation.lock().unwrap();
        let mut stores = self.stores.lock().unwrap();
        let panes: Vec<String> = stores
            .iter()
            .filter(|(_, e)| e.kind == PaneKind::Pane)
            .map(|(id, _)| id.clone())
            .collect();
        if panes.is_empty() {
            return;
        }
        for id in &panes {
            stores.remove(id);
        }
        if let Some(next_generation) = generation.checked_add(1) {
            *generation = next_generation;
        }
    }

    /// The epoch currently bound to pane `id` in the unified store, or `None` when `id` is not a
    /// `kind == Pane` member. The reader stamps each frame it ingests with this so
    /// [`Self::apply_pane_grid`]/[`Self::apply_pane_exit`] can reject a frame whose id was removed
    /// and re-added since.
    #[cfg(test)]
    pub fn pane_epoch(&self, id: &str) -> Option<u64> {
        if self.connection_is_closed() {
            return None;
        }
        let epoch = self
            .stores
            .lock()
            .unwrap()
            .get(id)
            .filter(|e| e.kind == PaneKind::Pane)
            .map(|e| e.epoch);
        (!self.connection_is_closed()).then_some(epoch).flatten()
    }

    /// Snapshot pane `id`'s cached `(grid, exited)` for painting, or `None` when `id` is not a
    /// `kind == Pane` member. `grid` is the last cached structured snapshot (`None` until its
    /// first baseline); `exited` is `Some(code)` once the pane's process exited.
    #[cfg(test)]
    pub fn pane_snapshot(&self, id: &str) -> Option<PaneSnapshot> {
        if self.connection_is_closed() {
            return None;
        }
        let snapshot = self
            .stores
            .lock()
            .unwrap()
            .get(id)
            .filter(|e| e.kind == PaneKind::Pane)
            .map(|e| (e.grid.clone(), e.exited));
        (!self.connection_is_closed()).then_some(snapshot).flatten()
    }

    /// Phase B UNIFORM per-pane paint resolution: the single source `draw` reads for EVERY visible
    /// pane, primary or not. `primary_id` is [`Self::active`]'s id (the pane the dedicated
    /// `grid`/`exited`/`scrollback` fields back); any other id resolves from its [`Self::stores`]
    /// entry. All grid `Arc`s + scrollback values are CLONED under short locks and returned OWNED, so
    /// the caller holds no mutex across shaping/GPU submission (#gate9) — this is also how the
    /// active-session scrollback finally moves into the symmetric path without the
    /// guard-across-statements hazard: we snapshot, then drop the guard.
    ///
    /// For the primary pane the live grid/exit come from the dedicated fields and the scrollback view
    /// from [`Self::scrollback`] (byte-identical paint source to the pre-Phase-B active path). For a
    /// non-primary pane they come from its `PaneStore` (sibling OR extra pane — same shape), including
    /// that pane's OWN `scrollback`, so paint reads the scrollback of the pane being drawn. A non-primary
    /// pane with no scrollback reply yet simply reports offset 0 and paints live — the symmetric
    /// "live until you scroll" state. Returns the empty default for an unknown id (paints nothing).
    pub fn pane_paint(&self, id: &str, primary_id: &str) -> PanePaint {
        if self.connection_is_closed() {
            return PanePaint::default();
        }
        // Hold active through the one leaf snapshot. A neutral viewport (or an App still naming a
        // retired primary id) paints nothing even if a stale store/grid was injected by queued work.
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return PanePaint::default();
        }
        if active.id.as_deref() != Some(primary_id) {
            return PanePaint::default();
        }
        if id == primary_id {
            // Primary: snapshot the dedicated fields under short, sequential locks and release each
            // before the next so we never hold two at once and never hold any past return.
            let live = self.grid.lock().unwrap().clone();
            let exited = *self.exited.lock().unwrap();
            let (scrolled_offset, history_len, historical) = {
                let sb = self.scrollback.lock().unwrap();
                (sb.view_offset, sb.history_len, sb.historical.clone())
            };
            let paint = PanePaint {
                live,
                exited,
                scrolled_offset,
                history_len,
                historical,
            };
            return if self.connection_is_closed() {
                PanePaint::default()
            } else {
                paint
            };
        }
        // Non-primary: one short lock over the store yields this pane's live grid, exit, and its OWN
        // scrollback view, all cloned out before the guard drops.
        let stores = self.stores.lock().unwrap();
        let paint = match stores.get(id) {
            Some(entry) => PanePaint {
                live: entry.grid.clone(),
                exited: entry.exited,
                scrolled_offset: entry.scrollback.view_offset,
                history_len: entry.scrollback.history_len,
                historical: entry.scrollback.historical.clone(),
            },
            None => PanePaint::default(),
        };
        if self.connection_is_closed() {
            PanePaint::default()
        } else {
            paint
        }
    }

    /// Run `f` against pane `id`'s OWN scrollback view under a short lock and return its result, then
    /// release. The primary pane uses the dedicated [`Self::scrollback`]; any other id uses its
    /// `PaneStore::scrollback` (the wheel acts on the FOCUSED pane's scrollback, whichever pane that is).
    /// An unknown non-primary id runs `f` against a throwaway default (a no-op edit, default reads) so a
    /// stale focus never panics. The guard never escapes `f`, so the caller holds no scrollback lock
    /// across a redraw/request (#gate9).
    pub fn with_pane_scrollback<R>(
        &self,
        id: &str,
        primary_id: &str,
        f: impl FnOnce(&mut ScrollbackState) -> R,
    ) -> R {
        if self.connection_is_closed() {
            return f(&mut ScrollbackState::default());
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return f(&mut ScrollbackState::default());
        }
        if active.id.as_deref() != Some(primary_id) {
            return f(&mut ScrollbackState::default());
        }
        if id == primary_id {
            let mut sb = self.scrollback.lock().unwrap();
            if self.connection_is_closed() {
                return f(&mut ScrollbackState::default());
            }
            return f(&mut sb);
        }
        let mut stores = self.stores.lock().unwrap();
        if self.connection_is_closed() {
            return f(&mut ScrollbackState::default());
        }
        match stores.get_mut(id) {
            Some(entry) => f(&mut entry.scrollback),
            None => f(&mut ScrollbackState::default()),
        }
    }

    /// Resolve the exact focused route, read its live PTY generation/geometry, and mutate its
    /// scroll intent as one authority transaction. Grid generation rollover uses the same
    /// active→grid→scrollback or active→sibling→stores lock order, so a gesture can never be
    /// returned with generation A's offset and generation B's authority.
    pub(crate) fn prepare_scroll_action(
        &self,
        id: &str,
        primary_id: &str,
        action: ScrollAction,
    ) -> PreparedScrollAction {
        if self.connection_is_closed() {
            return PreparedScrollAction::Unavailable;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return PreparedScrollAction::Unavailable;
        }
        if active.id.as_deref() != Some(primary_id) {
            return PreparedScrollAction::Unavailable;
        }
        if id == primary_id {
            let Some(output_generation) = active.output_generation else {
                return PreparedScrollAction::Unavailable;
            };
            let grid = self.grid.lock().unwrap();
            let Some(grid) = grid.as_deref() else {
                return PreparedScrollAction::Unavailable;
            };
            let mut scrollback = self.scrollback.lock().unwrap();
            if self.connection_is_closed() {
                return PreparedScrollAction::Unavailable;
            }
            return prepare_bound_scroll_action(
                ViewportBindingToken::Active(ActiveBindingToken {
                    session_id: id.to_string(),
                    epoch: active.epoch,
                    output_generation,
                }),
                grid,
                &mut scrollback,
                action,
            );
        }

        let sibling_id = self.sibling_id.lock().unwrap();
        let mut stores = self.stores.lock().unwrap();
        if self.connection_is_closed() {
            return PreparedScrollAction::Unavailable;
        }
        let Some(entry) = stores.get_mut(id) else {
            return PreparedScrollAction::Unavailable;
        };
        if entry.kind == PaneKind::Sibling && sibling_id.as_deref() != Some(id) {
            return PreparedScrollAction::Unavailable;
        }
        let Some(output_generation) = entry.output_generation else {
            return PreparedScrollAction::Unavailable;
        };
        let Some(grid) = entry.grid.as_deref() else {
            return PreparedScrollAction::Unavailable;
        };
        let binding = ViewportBindingToken::Pane {
            session_id: id.to_string(),
            pane_epoch: entry.epoch,
            pane_kind: entry.kind,
            viewport_epoch: active.epoch,
            output_generation,
        };
        prepare_bound_scroll_action(binding, grid, &mut entry.scrollback, action)
    }

    /// Accepted PTY generation for one exact current binding. Owner-loop batches retain this proof
    /// across queue pressure and are discarded if a later Grid changes the lifetime before retry.
    pub(crate) fn live_generation_for_binding(
        &self,
        token: &ViewportBindingToken,
    ) -> Option<SessionGeneration> {
        if self.connection_is_closed() {
            return None;
        }
        let active = self.active.lock().unwrap();
        if self.connection_is_closed() {
            return None;
        }
        let generation = match token {
            ViewportBindingToken::Active(token)
                if active.epoch == token.epoch
                    && active.id.as_deref() == Some(token.session_id.as_str())
                    && active.output_generation == Some(token.output_generation) =>
            {
                self.grid
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|grid| grid.generation.clone())
            }
            ViewportBindingToken::Pane {
                session_id,
                pane_epoch,
                pane_kind,
                viewport_epoch,
                output_generation,
            } if active.id.is_some() && active.epoch == *viewport_epoch => {
                let sibling_id = self.sibling_id.lock().unwrap();
                self.stores
                    .lock()
                    .unwrap()
                    .get(session_id)
                    .filter(|entry| {
                        entry.kind == *pane_kind
                            && (*pane_kind != PaneKind::Sibling
                                || sibling_id.as_deref() == Some(session_id.as_str()))
                            && entry.epoch == *pane_epoch
                            && entry.output_generation == Some(*output_generation)
                    })
                    .and_then(|entry| entry.grid.as_ref())
                    .map(|grid| grid.generation.clone())
            }
            _ => None,
        };
        if self.connection_is_closed() {
            None
        } else {
            generation
        }
    }

    /// Apply a grid to pane `id` IF it is still a `kind == Pane` member at `for_epoch`. A frame for
    /// a removed pane (no entry) or a stale epoch (the id was re-added) is dropped (`false`). Never
    /// touches the active or sibling grid. Returns `true` when the pane cache was updated.
    fn commit_pane_grid(&self, token: &ViewportBindingToken, grid: Arc<GridSnapshot>) -> bool {
        self.with_current_pane_store(token, PaneKind::Pane, |entry| {
            let live_context_changed = entry.grid.as_ref().is_some_and(|previous| {
                previous.generation != grid.generation || previous.alt_screen != grid.alt_screen
            });
            entry.grid = Some(grid);
            if live_context_changed {
                entry.scrollback.reset_for_live_context_change();
            }
            true
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_pane_scrollback(
        &self,
        token: &ViewportBindingToken,
        generation: SessionGeneration,
        revision: Revision,
        history_len: u32,
        offset_from_top: u32,
        rows: CopyRows,
    ) -> bool {
        self.with_current_pane_store(token, PaneKind::Pane, |entry| {
            let live_generation = entry.grid.as_ref().map(|g| g.generation.clone());
            apply_scrollback_payload(
                live_generation,
                &mut entry.scrollback,
                generation,
                revision,
                history_len,
                offset_from_top,
                rows,
            )
        })
    }

    /// Record pane `id`'s exit IF it is still a `kind == Pane` member at `for_epoch`. A late exit
    /// for a removed or replaced pane is dropped (`false`). Returns `true` when recorded.
    fn commit_pane_exit(&self, token: &ViewportBindingToken, code: Option<i32>) -> bool {
        self.with_current_pane_store(token, PaneKind::Pane, |entry| {
            entry.exited = Some(code);
            true
        })
    }

    #[cfg(test)]
    pub fn apply_pane_grid(&self, id: &str, epoch: u64, grid: Arc<GridSnapshot>) -> bool {
        let Some(
            token @ ViewportBindingToken::Pane {
                pane_epoch,
                pane_kind: PaneKind::Pane,
                ..
            },
        ) = self.binding_token_for_session(id)
        else {
            return false;
        };
        pane_epoch == epoch && self.commit_pane_grid(&token, grid)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub fn apply_pane_scrollback(
        &self,
        id: &str,
        epoch: u64,
        generation: SessionGeneration,
        revision: Revision,
        history_len: u32,
        offset_from_top: u32,
        rows: Vec<Vec<Cell>>,
    ) -> bool {
        let Some(
            token @ ViewportBindingToken::Pane {
                pane_epoch,
                pane_kind: PaneKind::Pane,
                ..
            },
        ) = self.binding_token_for_session(id)
        else {
            return false;
        };
        pane_epoch == epoch
            && self.commit_pane_scrollback(
                &token,
                generation,
                revision,
                history_len,
                offset_from_top,
                (rows, None),
            )
    }

    #[cfg(test)]
    pub fn apply_pane_exit(&self, id: &str, epoch: u64, code: Option<i32>) -> bool {
        let Some(
            token @ ViewportBindingToken::Pane {
                pane_epoch,
                pane_kind: PaneKind::Pane,
                ..
            },
        ) = self.binding_token_for_session(id)
        else {
            return false;
        };
        pane_epoch == epoch && self.commit_pane_exit(&token, code)
    }

    /// Install a fresh, drainable outbound queue and hand back a handle to it, so a
    /// unit test can run `send_request`-driven code and then inspect what got enqueued
    /// without a socket or writer thread. Test-only.
    #[cfg(test)]
    fn with_test_queue() -> (Arc<Shared>, Arc<OutboundQueue>) {
        let shared = Arc::new(Shared::default());
        shared
            .generation_conditional_mutations
            .store(true, Ordering::Release);
        let queue = Arc::new(OutboundQueue::new());
        assert!(shared.outbound.set(Arc::clone(&queue)).is_ok());
        (shared, queue)
    }

    /// Crate-level test seam for App tests: install a fresh queue without exposing the private
    /// queue type across the module boundary. Production builds have no such accessor.
    #[cfg(test)]
    pub(crate) fn with_test_outbound() -> Arc<Shared> {
        Self::with_test_queue().0
    }

    #[cfg(test)]
    pub(crate) fn with_test_handoff_peer(
        authority: &maestro_shell::AttachmentHandoffAuthority,
    ) -> Arc<Shared> {
        Self::with_test_handoff_peer_facts(
            Some(authority.expected_daemon_instance().clone()),
            authority.expected_server_pid(),
        )
    }

    #[cfg(test)]
    pub(crate) fn with_test_handoff_peer_facts(
        daemon_instance: Option<maestro_shell::DaemonInstanceId>,
        server_pid: Option<u32>,
    ) -> Arc<Shared> {
        let shared = Self::with_test_outbound();
        shared
            .attachment_handoff_capable
            .store(true, Ordering::Release);
        assert!(shared
            .operational_daemon_instance
            .set(daemon_instance)
            .is_ok());
        assert!(shared.operational_server_pid.set(server_pid).is_ok());
        shared
    }

    /// Drain and decode all requests currently queued by App. Returns empty if a test did not
    /// install the queue. Keeps the production outbound internals private.
    #[cfg(test)]
    pub(crate) fn drain_test_requests(&self) -> Vec<ClientRequest> {
        self.outbound
            .get()
            .map(|queue| queue.drain_requests())
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub(crate) fn exhaust_test_output_generations(&self) {
        self.next_output_generation
            .store(u64::MAX, Ordering::Release);
    }

    #[cfg(test)]
    pub(crate) fn set_test_generation_conditional_mutations(&self, supported: bool) {
        self.generation_conditional_mutations
            .store(supported, Ordering::Release);
    }

    /// Test-only mirror of the reader's post-commit exact-Grid proof hook. Owner-loop tests use it
    /// to drive aggregate publication without forging a production viewport authority or exposing
    /// the private route receipt.
    #[cfg(test)]
    pub(crate) fn prove_test_exact_viewport_grid(&self, id: &str, generation: &str) -> bool {
        let Some(token) = self.binding_token_for_session(id) else {
            return false;
        };
        self.note_exact_viewport_grid(&token, &SessionGeneration(generation.to_string()))
            == Some(true)
    }

    #[cfg(test)]
    pub(crate) fn fail_test_exact_viewport_admission(&self) {
        self.fail_exact_viewport_admission();
    }

    #[cfg(test)]
    pub(crate) fn saturate_test_outbound(&self) {
        self.outbound
            .get()
            .expect("test queue installed")
            .saturate_raw();
    }

    #[cfg(test)]
    pub(crate) fn discard_test_outbound(&self) {
        self.outbound
            .get()
            .expect("test queue installed")
            .discard_all();
    }

    #[cfg(test)]
    pub(crate) fn with_test_outbound_contended<R>(&self, f: impl FnOnce() -> R) -> R {
        let queue = self.outbound.get().expect("test queue installed");
        let _guard = queue.inner.lock().unwrap();
        f()
    }

    /// Clone one pane (`kind == Pane`) entry's `(epoch, grid, exited)` by id for assertions, or
    /// `None` when not a pane member. Test-only.
    #[cfg(test)]
    fn pane_entry(&self, id: &str) -> Option<PaneEntryView> {
        self.stores
            .lock()
            .unwrap()
            .get(id)
            .filter(|e| e.kind == PaneKind::Pane)
            .map(|e| PaneEntryView {
                grid: e.grid.clone(),
                exited: e.exited,
            })
    }
}

/// Test-only flattened view of a pane entry's assertion-relevant fields, so existing tests keep
/// reading `.grid`/`.exited` after the backing store unification. (Epoch is asserted via
/// [`Shared::pane_epoch`].)
#[cfg(test)]
#[derive(Clone)]
struct PaneEntryView {
    grid: Option<Arc<GridSnapshot>>,
    exited: Option<Option<i32>>,
}

/// The ordered outbound requests a single-session renderer must enqueue to rebind
/// from `old_id` to `new_id`. Pure so the FIFO ordering is unit-tested without a
/// socket. The order is load-bearing — the daemon's protocol is order-sensitive:
///
/// 1. `Detach { old_id }` — stop the daemon forwarding the old session first, so no
///    further old-session frames are produced after we rebase.
/// 2. `Attach { new_id, want_raw_output: false }` — structured-only attach; the daemon
///    installs the live notification/damage forwarder before any geometry mutation.
/// 3. `Snapshot { new_id }` — completes the read-only baseline transaction. Geometry is deliberately
///    absent: the matching Grid supplies the exact PTY generation, after which the owner sends a
///    generation-conditional Resize. No id-only/pre-baseline geometry mutation is possible.
///
/// A same-session switch is the caller's responsibility to short-circuit BEFORE
/// calling this (see [`crate::App::attach_session`]); this helper always assumes a
/// real change and never emits a no-op.
#[cfg(test)]
fn plan_attach_switch(
    old_id: &str,
    new_id: &str,
    _dims: Option<(u16, u16)>,
    output_generation: u64,
) -> Vec<ClientRequest> {
    let mut plan = Vec::with_capacity(4);
    if !old_id.is_empty() {
        plan.push(ClientRequest::Detach {
            id: old_id.to_string(),
        });
    }
    plan.push(ClientRequest::Attach {
        id: new_id.to_string(),
        want_raw_output: false,
        expected_session_generation: None,
        output_generation: Some(output_generation),
        handoff: None,
    });
    // Always finish the one FIFO bind plan with an authoritative direct reply, even before the UI
    // knows geometry or when external winsize ownership suppresses Resize.
    plan.push(ClientRequest::Snapshot {
        id: new_id.to_string(),
    });
    plan
}

/// The ordered outbound requests to bind the inactive pane's sibling session, given the
/// previously-bound sibling (`old_id`, `None` when there was no split) and the new one
/// (`new_id`). Pure so the FIFO ordering is unit-tested without a socket. It NEVER
/// detaches the active session — only the prior SIBLING — so attaching/replacing the
/// inactive pane can never disrupt the active pane:
///
/// 1. `Detach { old_id }` — ONLY when there was a different prior sibling, so the daemon
///    stops forwarding the old sibling before we rebind. Skipped when `old_id` is `None`
///    (first sibling) or equals `new_id` (same sibling — the caller should have
///    short-circuited, but we still never emit a redundant detach+reattach of it).
/// 2. `Attach { new_id, want_raw_output: false }` — structured-only attach of the new
///    sibling; the daemon replies with its authoritative baseline `Grid`.
/// 3. No Resize is sent until an exact Grid proves the new lifetime. The caller reconciles desired
///    geometry afterward through the generation-conditional owner path.
///
/// A same-sibling rebind (`old_id == Some(new_id)`) yields ONLY the optional Resize: no
/// detach, no reattach — so a pane-size change for the unchanged sibling just resizes it.
#[cfg(test)]
fn plan_sibling_attach(
    old_id: Option<&str>,
    new_id: &str,
    _dims: Option<(u16, u16)>,
    output_generation: u64,
) -> Vec<ClientRequest> {
    let same_sibling = old_id == Some(new_id);
    let mut plan = Vec::new();
    if let Some(old) = old_id {
        if !same_sibling {
            plan.push(ClientRequest::Detach {
                id: old.to_string(),
            });
        }
    }
    if !same_sibling {
        plan.push(ClientRequest::Attach {
            id: new_id.to_string(),
            want_raw_output: false,
            expected_session_generation: None,
            output_generation: Some(output_generation),
            handoff: None,
        });
    }
    if !same_sibling {
        plan.push(ClientRequest::Snapshot {
            id: new_id.to_string(),
        });
    }
    plan
}

/// Reset the renderer's per-session published state so NO stale row from the old
/// session can paint as the new one. Clears the live grid, the exit overlay, and the
/// scrollback view. Pure of the event loop / socket so a unit test can drive it on a
/// `Shared` and assert grid/exit/scrollback are cleared. Called by the reader thread
/// on a session rebind (the UI thread already cleared its own selection/view state in
/// [`crate::App::attach_session`]; this clears the reader-owned shared fields).
#[cfg(test)]
pub fn reset_session_state(shared: &Shared) {
    *shared.grid.lock().unwrap() = None;
    *shared.exited.lock().unwrap() = None;
    *shared.last_revision.lock().unwrap() = None;
    // This is an IDENTITY rebind, not an ordinary viewport reset.  `history_len` belongs
    // to the old PTY just as much as its grid does; retaining it can clamp the new session
    // to another pane's stale depth (including a permanent `Some(0)` fixed point).
    *shared.scrollback.lock().unwrap() = ScrollbackState::default();
}

/// Wire ownership state for one exact renderer binding. The canonical daemon proves the handoff by
/// echoing `output_generation` on the Attach restore Grid; only then may untagged direct replies
/// (Snapshot/Scrollback) inherit this route. Every live-forwarder event must always carry the exact
/// top-level tag. The sole compatibility exception is the first binding on a fresh socket: with no
/// older forwarder or request backlog, its first untagged Grid may establish a legacy route. Any
/// later clear/rebind starts `ExactPending` and therefore stays blank on an echo-less old daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StreamProof {
    InitialPending,
    ExactPending,
    ExactConfirmed,
    LegacyInitial,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DecodeFailureAction {
    Ignore,
    Recover,
    FailClosed,
}

struct RoutedSyncState {
    session_id: String,
    output_generation: u64,
    expected_generation: Option<SessionGeneration>,
    proof: StreamProof,
    legacy_incompatibility_reported: bool,
    sync: SyncState,
}

impl RoutedSyncState {
    fn new(session_id: String, output_generation: u64, initial: bool) -> Self {
        Self::new_with_expected_generation(session_id, output_generation, None, initial)
    }

    fn new_with_expected_generation(
        session_id: String,
        output_generation: u64,
        expected_generation: Option<SessionGeneration>,
        initial: bool,
    ) -> Self {
        Self {
            sync: SyncState::new(session_id.clone()),
            session_id,
            output_generation,
            expected_generation,
            legacy_incompatibility_reported: false,
            proof: if initial {
                StreamProof::InitialPending
            } else {
                StreamProof::ExactPending
            },
        }
    }

    fn event_generation_is_authorized(&self, event: &DaemonEvent) -> bool {
        let Some(expected) = self.expected_generation.as_ref() else {
            return true;
        };
        match event {
            DaemonEvent::Grid { grid, .. } => &grid.generation == expected,
            DaemonEvent::Damage { frame } => &frame.generation == expected,
            DaemonEvent::ScrollbackRows { generation, .. } => generation == expected,
            _ => true,
        }
    }

    /// Whether this line claims the currently bound forwarder/direct-reply route. A conflicting
    /// PTY generation is terminal only with this causal proof. Untagged or differently tagged
    /// bytes observed while a new exact Attach is still pending can belong to the retired route and
    /// must remain inert rather than tearing down the replacement connection.
    fn event_claims_current_route(&self, route: EventRouteMetadata) -> bool {
        match (route.output_generation, route.live_output_generation) {
            (Some(_), Some(_)) => false,
            (Some(generation), None) | (None, Some(generation)) => {
                generation == self.output_generation
            }
            (None, None) => matches!(
                self.proof,
                StreamProof::ExactConfirmed | StreamProof::LegacyInitial
            ),
        }
    }

    /// Admit one line into this binding's SyncState. Confirmation occurs at the exact FIFO point of
    /// the matching Attach restore Grid, never when the request was merely queued. Before that cut,
    /// old tagged live frames and old untagged Snapshot replies are both rejected.
    fn accepts(&mut self, event: &DaemonEvent, route: EventRouteMetadata) -> bool {
        if event_session_id(event) != Some(self.session_id.as_str()) {
            return false;
        }
        if !self.event_generation_is_authorized(event) {
            return false;
        }
        let is_grid = matches!(event, DaemonEvent::Grid { .. });
        let is_direct_reply = is_grid || matches!(event, DaemonEvent::ScrollbackRows { .. });

        match self.proof {
            StreamProof::InitialPending | StreamProof::ExactPending => {
                // Confirmation is transactional with baseline validation. Probe a clone first so a
                // typed-but-invalid matching echo (bad dimensions/version/wide layout/retired PTY
                // generation) cannot open the route proof and authorize later untagged replies.
                let baseline_is_valid = match event {
                    DaemonEvent::Grid { id, grid } => {
                        let mut probe = self.sync.clone();
                        probe.on_grid(id, grid).is_ok()
                    }
                    _ => false,
                };
                if is_grid
                    && baseline_is_valid
                    && route.live_output_generation.is_none()
                    && route.output_generation == Some(self.output_generation)
                {
                    self.proof = StreamProof::ExactConfirmed;
                    return true;
                }
                if self.proof == StreamProof::InitialPending
                    && is_grid
                    && baseline_is_valid
                    && route.output_generation.is_none()
                    && route.live_output_generation.is_none()
                {
                    self.proof = StreamProof::LegacyInitial;
                    return true;
                }
                if self.proof == StreamProof::ExactPending
                    && is_grid
                    && route.output_generation.is_none()
                    && route.live_output_generation.is_none()
                    && !self.legacy_incompatibility_reported
                {
                    // Fixed, low-cardinality diagnostic: no session id, payload, or generation is
                    // logged, and each affected binding reports at most once.
                    eprintln!(
                        "maestro-renderer: retained daemon lacks output-generation echo; rebound viewport remains blank"
                    );
                    self.legacy_incompatibility_reported = true;
                }
                false
            }
            StreamProof::ExactConfirmed => {
                if let Some(live) = route.live_output_generation {
                    return route.output_generation.is_none() && live == self.output_generation;
                }
                if let Some(echoed) = route.output_generation {
                    return is_grid && echoed == self.output_generation;
                }
                // Only request/reply events are legitimately untagged after confirmation. Canonical
                // live Damage/resync/title/bell/OSC52/exit lines always carry the forwarder tag.
                is_direct_reply
            }
            StreamProof::LegacyInitial => {
                route.output_generation.is_none() && route.live_output_generation.is_none()
            }
        }
    }

    fn exact_token_generation(&self) -> u64 {
        self.output_generation
    }

    /// Classify a decode failure only from its bounded envelope proof. A malformed exact Attach echo
    /// cannot confirm a pending binding, and the following untagged Snapshot cannot repair that proof,
    /// so the connection must fail closed. Likewise a generation-proven malformed Scrollback reply
    /// cannot safely leave the route's sole admitted correlation occupied forever. Stale, conflicting,
    /// and untagged failures remain inert; they may never perturb a revived same-id binding.
    fn decode_failure_action(
        &self,
        session_id: &str,
        kind: EventRouteKind,
        route: EventRouteMetadata,
    ) -> DecodeFailureAction {
        if session_id != self.session_id
            || (route.output_generation.is_some() && route.live_output_generation.is_some())
        {
            return DecodeFailureAction::Ignore;
        }
        match self.proof {
            StreamProof::InitialPending | StreamProof::ExactPending
                if kind == EventRouteKind::Grid
                    && route.output_generation == Some(self.output_generation)
                    && route.live_output_generation.is_none() =>
            {
                DecodeFailureAction::FailClosed
            }
            StreamProof::ExactConfirmed => {
                if kind == EventRouteKind::ScrollbackRows
                    && route.output_generation == Some(self.output_generation)
                    && route.live_output_generation.is_none()
                {
                    return DecodeFailureAction::FailClosed;
                }
                if kind == EventRouteKind::ScrollbackRows
                    && route.output_generation.is_none()
                    && route.live_output_generation.is_none()
                {
                    // Canonical ScrollbackRows replies are direct, untagged FIFO replies. Once the
                    // exact Attach echo has crossed this socket's FIFO cut they cannot belong to an
                    // older route; fail closed rather than strand the sole correlation slot.
                    return DecodeFailureAction::FailClosed;
                }
                if kind == EventRouteKind::Grid {
                    return match (route.output_generation, route.live_output_generation) {
                        (Some(generation), None) | (None, Some(generation))
                            if generation == self.output_generation =>
                        {
                            DecodeFailureAction::FailClosed
                        }
                        // Canonical Snapshot replies are likewise untagged direct replies ordered
                        // after the exact Attach echo. A malformed current reply can strand both
                        // SyncState and the Shared recovery registry, so terminate the connection.
                        (None, None) => DecodeFailureAction::FailClosed,
                        _ => DecodeFailureAction::Ignore,
                    };
                }
                if kind != EventRouteKind::Damage {
                    return DecodeFailureAction::Ignore;
                }
                match (route.output_generation, route.live_output_generation) {
                    (None, Some(live)) if live == self.output_generation => {
                        DecodeFailureAction::Recover
                    }
                    _ => DecodeFailureAction::Ignore,
                }
            }
            // Once the only permitted legacy incarnation has accepted its first untagged Grid,
            // there cannot be an older route on this fresh connection. An untagged malformed
            // Damage addressed to that exact session is therefore safe to recover through the
            // current binding token. No other untagged legacy failure has enough causal proof.
            StreamProof::LegacyInitial
                if kind == EventRouteKind::Damage
                    && route.output_generation.is_none()
                    && route.live_output_generation.is_none() =>
            {
                DecodeFailureAction::Recover
            }
            StreamProof::LegacyInitial
                if matches!(kind, EventRouteKind::Grid | EventRouteKind::ScrollbackRows)
                    && route.output_generation.is_none()
                    && route.live_output_generation.is_none() =>
            {
                // The first connection has no older direct-reply route. A malformed Grid can
                // otherwise strand an admitted recovery, while malformed ScrollbackRows can
                // strand its single correlation slot; both are terminal protocol failures.
                DecodeFailureAction::FailClosed
            }
            StreamProof::LegacyInitial
            | StreamProof::InitialPending
            | StreamProof::ExactPending => DecodeFailureAction::Ignore,
        }
    }
}

const MAX_RETIRED_EXIT_BINDINGS: usize = 256;

/// Bounded durable-exit authority for bindings retired by clear/reconcile. A canonical daemon may
/// finish one already-admitted tagged exit after Detach/Attach, so dropping the old SyncState at the
/// paint boundary would lose the only lifecycle observation. We retain only the accepted PTY
/// generation and exact socket generation—never a grid or side-effect authority. The cap bounds a
/// pathological switch storm; normal app inventory reconciliation remains the eventual fallback for
/// an entry old enough to be evicted before its process exits.
#[derive(Default)]
struct RetiredExitBindings {
    order: VecDeque<u64>,
    by_output_generation: HashMap<u64, RoutedSyncState>,
}

impl RetiredExitBindings {
    fn retain(&mut self, state: RoutedSyncState) {
        // Legacy post-clear lines are deliberately unprovable, so never create an untagged retired
        // authority. ExactPending is retained: Clear may retire it while its echoed baseline and
        // one-shot exit are already queued; the echo may advance only this off-paint tombstone.
        if state.proof == StreamProof::LegacyInitial {
            return;
        }
        let output_generation = state.output_generation;
        // Output generations are connection-global and never reused. Repeated reconciliation of
        // a transiently lingering Shared store must not replace an already-retired Confirmed state
        // with a freshly recreated ExactPending state or duplicate its eviction-order entry.
        if self.by_output_generation.contains_key(&output_generation) {
            return;
        }
        self.order.push_back(output_generation);
        self.by_output_generation.insert(output_generation, state);
        while self.by_output_generation.len() > MAX_RETIRED_EXIT_BINDINGS {
            if let Some(oldest) = self.order.pop_front() {
                self.by_output_generation.remove(&oldest);
            }
        }
    }

    fn event_generation_contradicted(
        &self,
        event: &DaemonEvent,
        route: EventRouteMetadata,
    ) -> bool {
        let Some(output_generation) = route.output_generation.or(route.live_output_generation)
        else {
            return false;
        };
        self.by_output_generation
            .get(&output_generation)
            .is_some_and(|retired| !retired.event_generation_is_authorized(event))
    }

    /// Consume only the two lifecycle events needed after retirement: an exact Attach echo may
    /// establish the PTY generation off-paint, and its exact tagged exit may then emit one durable
    /// observation. No retired Grid reaches a cache and no retired Damage/notification is acted on.
    fn observe_durable_event(
        &mut self,
        event: &DaemonEvent,
        route: EventRouteMetadata,
        proxy: &dyn UserEventSender,
    ) -> bool {
        if route.output_generation.is_some() && route.live_output_generation.is_some() {
            return false;
        }
        let Some(output_generation) = route.output_generation.or(route.live_output_generation)
        else {
            return false;
        };
        let Some(retired) = self.by_output_generation.get_mut(&output_generation) else {
            return false;
        };
        if event_session_id(event) != Some(retired.session_id.as_str()) {
            return false;
        }
        match event {
            DaemonEvent::Grid { id, grid } => {
                if route.output_generation != Some(output_generation)
                    || !retired.accepts(event, route)
                {
                    return false;
                }
                // Validate the same schema/generation invariants as a live baseline, but deliberately
                // discard the grid instead of touching any renderer cache.
                let _ = retired.sync.on_grid(id, grid);
                true
            }
            DaemonEvent::SessionExited { id, code } => {
                if route.live_output_generation != Some(output_generation)
                    || !retired.accepts(event, route)
                    || !matches!(retired.sync.on_session_exited(id), Ok(Action::Exited))
                {
                    return false;
                }
                let observed_generation = retired.sync.accepted_generation().map(str::to_string);
                notify_session_exit(proxy, id, *code, observed_generation.as_deref());
                self.by_output_generation.remove(&output_generation);
                self.order
                    .retain(|generation| *generation != output_generation);
                true
            }
            _ => false,
        }
    }
}

/// If the UI thread switched the active session since the reader last checked
/// (`shared.active.epoch` advanced past `local_epoch`), rebind the reader's
/// thread-local `session_id` and `SyncState` to the new id and reset the shared
/// published state. A no-op when the epoch is unchanged (the common per-event path).
/// Returns `true` if a rebind happened (test hook).
///
/// This is the reader-side half of a tab switch: the UI thread bumps the epoch and
/// enqueues Detach/Attach/optional-Resize+Snapshot; the reader, on its next event, adopts the new id so
/// (a) a fresh `SyncState` AwaitingBaseline accepts the new session's first Grid, and
/// (b) any late frame from the OLD session is rejected as `WrongSession`.
fn sync_active_session(
    shared: &Shared,
    session_id: &mut Option<String>,
    sync: &mut Option<RoutedSyncState>,
    local_epoch: &mut u64,
    retired: &mut RetiredExitBindings,
) -> bool {
    let active = shared.active_snapshot();
    let local_output_generation = sync.as_ref().map(|state| state.output_generation);
    let local_expected_generation = sync
        .as_ref()
        .and_then(|state| state.expected_generation.as_ref());
    if active.epoch == *local_epoch
        && active.id.as_ref() == session_id.as_ref()
        && active.output_generation == local_output_generation
        && active.expected_generation.as_ref() == local_expected_generation
    {
        return false;
    }
    if let Some(previous) = sync.take() {
        retired.retain(previous);
    }
    *local_epoch = active.epoch;
    match (
        active.id,
        active.output_generation,
        active.expected_generation,
    ) {
        (Some(id), Some(output_generation), expected_generation) => {
            *sync = Some(RoutedSyncState::new_with_expected_generation(
                id.clone(),
                output_generation,
                expected_generation,
                false,
            ));
            *session_id = Some(id);
        }
        _ => {
            *session_id = None;
            *sync = None;
        }
    }
    true
}

/// Reader-side half of binding the inactive split-pane SIBLING. The UI thread fills
/// `shared.sibling` (id + epoch) from the split frame; the reader, on its next event,
/// adopts that binding so a fresh sibling `SyncState` (AwaitingBaseline) accepts the
/// sibling's first Grid and any late frame from a PREVIOUS sibling is rejected.
///
/// Mirrors [`sync_active_session`] but for the sibling, and is wholly independent of it:
/// it reads only `shared.sibling`, never touches the active session, and on unbind
/// (no split → `id == None`) drops the sibling `SyncState` so no frames are ingested.
/// The sibling grid/exit cache is owned by `Shared` (cleared on bind/unbind there); this
/// only manages the reader-local id/sync/epoch. Returns `true` if the binding changed.
fn sync_sibling_session(
    shared: &Shared,
    sibling_id: &mut Option<String>,
    sibling_sync: &mut Option<RoutedSyncState>,
    local_epoch: &mut u64,
    retired: &mut RetiredExitBindings,
) -> bool {
    let mut sib = shared.sibling_snapshot();
    let active = shared.active_snapshot();
    if active.id.is_none() || active.id.as_ref() == sib.id.as_ref() {
        // Active/neutral authority wins even while the UI has not yet torn down the old sibling
        // store. Exclude it before constructing a new RoutedSyncState so repeated reconciles cannot
        // shadow or dilute the retired lifecycle proof.
        sib.id = None;
        sib.output_generation = None;
        sib.grid = None;
        sib.exited = None;
    }
    let local_output_generation = sibling_sync.as_ref().map(|state| state.output_generation);
    if sib.epoch == *local_epoch
        && sib.id.as_ref() == sibling_id.as_ref()
        && sib.output_generation == local_output_generation
    {
        return false;
    }
    if let Some(previous) = sibling_sync.take() {
        retired.retain(previous);
    }
    *local_epoch = sib.epoch;
    match (sib.id, sib.output_generation) {
        (Some(id), Some(output_generation)) => {
            *sibling_sync = Some(RoutedSyncState::new(id.clone(), output_generation, false));
            *sibling_id = Some(id);
        }
        _ => {
            *sibling_id = None;
            *sibling_sync = None;
        }
    }
    true
}

/// Reader-side membership reconcile for the MULTI-PANE cache (the N-pane generalization of
/// [`sync_sibling_session`]). The UI thread reconciles `shared.panes` from the non-active panes
/// of [`compute_split_layout`](crate::compute_split_layout); on a generation bump the reader
/// rebuilds `pane_syncs` so each currently-bound pane has a fresh `SyncState` (AwaitingBaseline)
/// and a removed pane's `SyncState` is dropped — so a late frame from a removed/replaced pane is
/// never ingested. The per-pane grid/exit cache itself lives in `Shared` (membership + epoch
/// gated there); this only maintains the reader-local sync map and generation. Socket attachment
/// lifecycle belongs exclusively to the UI-side pane-role reconcile: emitting Attach/Detach here
/// as well races a pane-to-primary promotion and can detach the newly-active session's one daemon
/// forwarder. Returns `true` when the membership changed.
fn sync_pane_sessions(
    shared: &Shared,
    pane_syncs: &mut HashMap<String, PaneSyncState>,
    local_generation: &mut u64,
    retired: &mut RetiredExitBindings,
) -> bool {
    let (generation, mut bindings) = shared.pane_bindings_snapshot();
    let active = shared.active_snapshot();
    match active.id.as_deref() {
        Some(active_id) => bindings.retain(|(id, _, _, _)| id != active_id),
        None => bindings.clear(),
    }
    let bindings_unchanged = generation == *local_generation
        && bindings.len() == pane_syncs.len()
        && bindings
            .iter()
            .all(|(id, epoch, output_generation, expected_generation)| {
                pane_syncs.get(id).is_some_and(|state| {
                    state.epoch == *epoch
                        && Some(state.routed.output_generation) == *output_generation
                        && state.routed.expected_generation.as_ref() == expected_generation.as_ref()
                })
            });
    if bindings_unchanged {
        return false;
    }
    *local_generation = generation;
    let mut next = HashMap::with_capacity(bindings.len());
    for (id, epoch, output_generation, expected_generation) in bindings {
        let Some(output_generation) = output_generation else {
            continue;
        };
        let state = match pane_syncs.remove(&id) {
            Some(existing)
                if existing.epoch == epoch
                    && existing.routed.output_generation == output_generation
                    && existing.routed.expected_generation == expected_generation =>
            {
                existing
            }
            Some(existing) => {
                retired.retain(existing.routed);
                PaneSyncState {
                    epoch,
                    routed: RoutedSyncState::new_with_expected_generation(
                        id.clone(),
                        output_generation,
                        expected_generation.clone(),
                        false,
                    ),
                }
            }
            _ => PaneSyncState {
                epoch,
                routed: RoutedSyncState::new_with_expected_generation(
                    id.clone(),
                    output_generation,
                    expected_generation,
                    false,
                ),
            },
        };
        next.insert(id, state);
    }
    for (_, removed) in pane_syncs.drain() {
        retired.retain(removed.routed);
    }
    *pane_syncs = next;
    true
}

/// Enforce the reader's one-route-per-session invariant after observing a binding snapshot. Active
/// wins over sibling, which wins over pane. Most importantly, a neutral active viewport retires
/// every non-active route immediately—even if UI clear has not yet removed Shared stores—and an
/// active promotion retires the former pane/sibling route before the old exact tagged exit is
/// dispatched. Retired states retain lifecycle authority only; they can never paint or emit OSC.
fn retire_shadowed_reader_routes(
    active_id: Option<&str>,
    sibling_id: &mut Option<String>,
    sibling_sync: &mut Option<RoutedSyncState>,
    pane_syncs: &mut HashMap<String, PaneSyncState>,
    retired: &mut RetiredExitBindings,
) {
    let Some(active_id) = active_id else {
        if let Some(state) = sibling_sync.take() {
            retired.retain(state);
        }
        *sibling_id = None;
        for (_, state) in pane_syncs.drain() {
            retired.retain(state.routed);
        }
        return;
    };

    if sibling_id.as_deref() == Some(active_id) {
        if let Some(state) = sibling_sync.take() {
            retired.retain(state);
        }
        *sibling_id = None;
    }
    if let Some(state) = pane_syncs.remove(active_id) {
        retired.retain(state.routed);
    }
    if let Some(sibling) = sibling_id.as_deref() {
        if let Some(state) = pane_syncs.remove(sibling) {
            retired.retain(state.routed);
        }
    }
}

/// Reader-local state for one exact pane-store incarnation. Same-id removal/re-add must rebuild the
/// sync machine even when routing still finds the same map key.
struct PaneSyncState {
    epoch: u64,
    routed: RoutedSyncState,
}

/// Resolve one event id against the reader's PRE-block binding table. Comparing this with
/// [`Shared::binding_token_for_session`] after `read_until` detects only a change to this exact
/// route; an unrelated pane membership update cannot make us discard a valid active line.
#[allow(clippy::too_many_arguments)]
fn local_binding_token_for_session(
    event_id: &str,
    session_id: Option<&str>,
    active_sync: Option<&RoutedSyncState>,
    active_epoch: u64,
    sibling_id: Option<&str>,
    sibling_sync: Option<&RoutedSyncState>,
    sibling_epoch: u64,
    pane_syncs: &HashMap<String, PaneSyncState>,
) -> Option<ViewportBindingToken> {
    if session_id == Some(event_id) {
        let routed = active_sync?;
        return Some(ViewportBindingToken::Active(ActiveBindingToken {
            session_id: event_id.to_string(),
            epoch: active_epoch,
            output_generation: routed.exact_token_generation(),
        }));
    }
    if sibling_id == Some(event_id) {
        let routed = sibling_sync?;
        return Some(ViewportBindingToken::Pane {
            session_id: event_id.to_string(),
            pane_epoch: sibling_epoch,
            pane_kind: PaneKind::Sibling,
            viewport_epoch: active_epoch,
            output_generation: routed.exact_token_generation(),
        });
    }
    let pane = pane_syncs.get(event_id)?;
    Some(ViewportBindingToken::Pane {
        session_id: event_id.to_string(),
        pane_epoch: pane.epoch,
        pane_kind: PaneKind::Pane,
        viewport_epoch: active_epoch,
        output_generation: pane.routed.exact_token_generation(),
    })
}

fn request_local_recovery(
    shared: &Arc<Shared>,
    sync: &mut SyncState,
    proxy: &dyn UserEventSender,
    binding: &ViewportBindingToken,
    id: &str,
) {
    if !sync.can_request_local_resync(id) {
        return;
    }
    match shared.request_recovery_snapshot(binding) {
        RecoveryRequestResult::Admitted | RecoveryRequestResult::AlreadyAdmitted => {
            let _ = sync.local_resync_request_admitted(id);
        }
        RecoveryRequestResult::Pending { wake_now } => {
            if wake_now {
                let _ = proxy.send(UserEvent::OutboundWritable);
            }
        }
        RecoveryRequestResult::Stale => {}
        RecoveryRequestResult::Refused(admission) => {
            // Recovery registry exhaustion is not safely droppable: without a retained Snapshot
            // transaction this exact route can remain stale forever. Treat every hard refusal as a
            // fail-closed connection outcome; only Pending/Full/Contended is retryable.
            if admission.is_connection_terminal() || !admission.is_retryable() {
                shared.fail_closed_connection(proxy);
            }
        }
    }
}

fn request_snapshot_after_grid(
    shared: &Arc<Shared>,
    sync: &mut SyncState,
    proxy: &dyn UserEventSender,
    binding: &ViewportBindingToken,
) {
    match shared.request_recovery_snapshot(binding) {
        RecoveryRequestResult::Admitted | RecoveryRequestResult::AlreadyAdmitted => {}
        RecoveryRequestResult::Pending { wake_now } => {
            sync.snapshot_request_not_admitted();
            if wake_now {
                let _ = proxy.send(UserEvent::OutboundWritable);
            }
        }
        RecoveryRequestResult::Stale => {
            sync.snapshot_request_not_admitted();
        }
        RecoveryRequestResult::Refused(admission) => {
            sync.snapshot_request_not_admitted();
            if admission.is_connection_terminal() || !admission.is_retryable() {
                shared.fail_closed_connection(proxy);
            }
        }
    }
}

/// Ingest a frame for one of the extra non-active panes into the multi-pane cache. The N-pane
/// analogue of [`handle_sibling_event`]: it ONLY maintains the cache (no render, no input). The
/// pane's `SyncState` gates every Grid/Damage, and the resulting grid is published via
/// [`Shared::apply_pane_grid`] (membership + epoch gated, so a frame for a removed/replaced pane
/// is dropped). Scrollback rows update the pane's own renderer-owned viewport state; raw Output
/// stays ignored on structured-only attaches. The UI is woken only on an accepted grid, exit, or
/// scrollback update.
#[allow(clippy::too_many_arguments)]
fn handle_pane_event_for_binding(
    shared: &Arc<Shared>,
    sync: &mut SyncState,
    proxy: &dyn UserEventSender,
    pane_id: &str,
    pane_epoch: u64,
    viewport_epoch: u64,
    output_generation: u64,
    ev: DaemonEvent,
) {
    let binding = ViewportBindingToken::Pane {
        session_id: pane_id.to_string(),
        pane_epoch,
        pane_kind: PaneKind::Pane,
        viewport_epoch,
        output_generation,
    };
    match ev {
        DaemonEvent::Grid { id, grid } => match sync.on_grid(&id, &grid) {
            Ok(outcome) => {
                shared.clear_recovery(&binding);
                if outcome.repaint && shared.commit_pane_grid(&binding, Arc::new(grid)) {
                    wake(proxy);
                }
                if outcome.request_snapshot {
                    request_snapshot_after_grid(shared, sync, proxy, &binding);
                }
            }
            Err(reason) => eprintln!("maestro-renderer: rejected pane snapshot: {reason:?}"),
        },
        DaemonEvent::Damage { frame } => {
            if frame.id.as_str() != pane_id {
                return;
            }
            let held = shared.pane_grid_for_binding(&binding, PaneKind::Pane);
            let Some(held) = held else {
                request_local_recovery(shared, sync, proxy, &binding, pane_id);
                return;
            };
            match sync.on_damage(&frame.id, &frame, &held) {
                DamageOutcome::Applied(grid) => {
                    if shared.commit_pane_grid(&binding, Arc::from(grid)) {
                        shared.clear_recovery(&binding);
                        wake(proxy);
                    }
                }
                DamageOutcome::Ignore => {}
                DamageOutcome::Resync { reason } => {
                    eprintln!(
                        "maestro-renderer: pane damage not applicable ({reason:?}); resyncing"
                    );
                    request_local_recovery(shared, sync, proxy, &binding, pane_id);
                }
            }
        }
        DaemonEvent::ResyncRequired { id } => {
            if let Err(reason) = sync.on_resync_required(&id) {
                eprintln!("maestro-renderer: ignored pane resync: {reason:?}");
            }
        }
        DaemonEvent::SessionExited { id, code } => {
            if let Ok(Action::Exited) = sync.on_session_exited(&id) {
                // Paint-cache authority may have been revoked after read, but the durable app
                // observation remains generation-guarded and must not be lost for stashed records.
                shared.commit_pane_exit(&binding, code);
                notify_session_exit(proxy, pane_id, code, sync.accepted_generation());
            }
        }
        DaemonEvent::ScrollbackRows {
            generation,
            revision,
            history_len,
            offset_from_top,
            rows,
            row_copy,
            ..
        } => {
            let repaint = shared.commit_pane_scrollback(
                &binding,
                generation,
                revision,
                history_len,
                offset_from_top,
                (rows, row_copy),
            );
            // Consuming even a stale/mismatched reply releases the route's single in-flight slot.
            // Retry the one coalesced latest owner intent without waiting for another daemon event.
            let _ = proxy.send(UserEvent::OutboundWritable);
            if repaint {
                wake(proxy);
            }
        }
        DaemonEvent::TerminalBell { id }
            if id == pane_id && sync.accepted_generation().is_some() =>
        {
            let _ = proxy.send(UserEvent::TerminalBell {
                binding: binding.clone(),
            });
        }
        DaemonEvent::TerminalTitle { id, title }
            if id == pane_id && sync.accepted_generation().is_some() =>
        {
            let _ = proxy.send(UserEvent::TerminalTitle {
                binding: binding.clone(),
                title,
            });
        }
        DaemonEvent::TerminalClipboardStore { id, text }
            if id == pane_id && sync.accepted_generation().is_some() =>
        {
            let _ = proxy.send(UserEvent::TerminalClipboardStore { binding, text });
        }
        DaemonEvent::TerminalBell { .. }
        | DaemonEvent::TerminalTitle { .. }
        | DaemonEvent::TerminalClipboardStore { .. }
        | DaemonEvent::Output { .. }
        | DaemonEvent::DaemonInfo { .. }
        | DaemonEvent::SessionAttachRefused { .. }
        | DaemonEvent::Error { .. }
        | DaemonEvent::Other => {}
    }
}

#[cfg(test)]
fn handle_pane_event(
    shared: &Arc<Shared>,
    sync: &mut SyncState,
    proxy: &dyn UserEventSender,
    pane_id: &str,
    ev: DaemonEvent,
) {
    let Some(ViewportBindingToken::Pane {
        pane_epoch,
        pane_kind: PaneKind::Pane,
        viewport_epoch,
        output_generation,
        ..
    }) = shared.binding_token_for_session(pane_id)
    else {
        return;
    };
    handle_pane_event_for_binding(
        shared,
        sync,
        proxy,
        pane_id,
        pane_epoch,
        viewport_epoch,
        output_generation,
        ev,
    );
}

pub(crate) struct SpawnedClient {
    pub(crate) shared: Arc<Shared>,
    /// Immutable queue-publication proof captured before either worker can clear mutable Shared
    /// state. `Some` means the initial Attach+Snapshot batch entered the writer FIFO.
    pub(crate) initial_binding: Option<ActiveBindingToken>,
    pub(crate) initial_exact_viewport: Option<ViewportBindingSet>,
}

/// Spawn the reader thread and retain immutable initial publication proof for the renderer owner.
/// The reader validates every
/// event, publishes accepted snapshots, and wakes the OWNER event loop via `proxy`
/// (the platform-neutral [`UserEventSender`]) only after a validated state change
/// (#gate8). It also owns a write handle so it can request a fresh snapshot when
/// live output advances the revision or a resync is needed.
pub(crate) fn spawn_with_initial_binding(
    socket_path: String,
    session_id: String,
    exact_viewport: Option<DesiredViewportBinding>,
    attachment_handoff: Option<AttachmentHandoffClaim>,
    proxy: Box<dyn UserEventSender>,
) -> SpawnedClient {
    let shared = Arc::new(Shared::default());

    let transport = match connect_daemon_transport(&socket_path, attachment_handoff.as_ref()) {
        Ok(transport) => transport,
        Err(e) => {
            eprintln!("maestro-renderer: failed to connect to {socket_path}: {e}");
            // Return empty shared state; the window will show nothing.
            shared.connection_closed.store(true, Ordering::Release);
            return SpawnedClient {
                shared,
                initial_binding: None,
                initial_exact_viewport: None,
            };
        }
    };
    let DaemonTransport {
        stream,
        mutation_capable,
        legacy_attach_compatible,
        peer,
    } = transport;
    shared
        .generation_conditional_mutations
        .store(mutation_capable, Ordering::Release);
    shared
        .attachment_handoff_capable
        .store(peer.attachment_handoff_capable, Ordering::Release);
    assert!(shared
        .operational_daemon_instance
        .set(peer.daemon_instance_id)
        .is_ok());
    assert!(shared.operational_server_pid.set(peer.server_pid).is_ok());

    let shutdown_stream = match stream.try_clone() {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("maestro-renderer: failed to clone shutdown handle: {e}");
            let _ = stream.shutdown(Shutdown::Both);
            return SpawnedClient {
                shared,
                initial_binding: None,
                initial_exact_viewport: None,
            };
        }
    };
    assert!(shared.shutdown_stream.set(shutdown_stream).is_ok());

    // The dedicated writer's own socket handle. One thread owns it and drains the
    // bounded outbound queue in strict FIFO order — no other thread touches the
    // write half, so bytes can never interleave at the kernel.
    let mut write_half = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("maestro-renderer: failed to clone stream: {e}");
            return SpawnedClient {
                shared,
                initial_binding: None,
                initial_exact_viewport: None,
            };
        }
    };
    if let Err(e) = write_half.set_write_timeout(Some(OUTBOUND_WRITE_TIMEOUT)) {
        eprintln!("maestro-renderer: failed to bound socket writes: {e}");
        let _ = write_half.shutdown(Shutdown::Both);
        return SpawnedClient {
            shared,
            initial_binding: None,
            initial_exact_viewport: None,
        };
    }

    // Publish the queue so producers (reader + UI) can enqueue, then start the
    // writer thread that drains it.
    let outbound = Arc::new(OutboundQueue::new());
    assert!(shared.outbound.set(Arc::clone(&outbound)).is_ok());

    // Exact startup uses the same aggregate Detach/Attach receipt as every runtime topology change.
    // A canonical mutation-capable peer never accepts a textual id without an immutable generation
    // cohort. A retained peer that failed the v3 capability proof may still receive the original
    // read-only Attach shape on this same reviewed socket; terminal mutations remain disabled
    // for the entire connection and a later clear/rebind cannot recreate that legacy authority.
    let (initial_token, initial_exact_viewport) = if let Some(desired) = exact_viewport {
        if desired.primary_session_id != session_id {
            shared.abort_connection();
            return SpawnedClient {
                shared,
                initial_binding: None,
                initial_exact_viewport: None,
            };
        }
        match shared.try_bind_viewport(&desired, &[], attachment_handoff.as_ref()) {
            Ok(binding) => (binding.primary().clone(), Some(binding)),
            Err(_) => {
                shared.abort_connection();
                return SpawnedClient {
                    shared,
                    initial_binding: None,
                    initial_exact_viewport: None,
                };
            }
        }
    } else if attachment_handoff.is_none() && legacy_attach_compatible {
        let Some(token) = shared.init_active_session(&session_id) else {
            shared.abort_connection();
            return SpawnedClient {
                shared,
                initial_binding: None,
                initial_exact_viewport: None,
            };
        };
        let initial_plan = [
            ClientRequest::Attach {
                id: session_id.clone(),
                want_raw_output: false,
                expected_session_generation: None,
                output_generation: Some(token.output_generation),
                handoff: None,
            },
            ClientRequest::Snapshot {
                id: session_id.clone(),
            },
        ];
        let Some(initial_lines) = Shared::frame_requests(&initial_plan) else {
            shared.abort_connection();
            return SpawnedClient {
                shared,
                initial_binding: None,
                initial_exact_viewport: None,
            };
        };
        // `Attach` is conservatively classified with terminal mutations everywhere else. This one
        // bypass is narrower: the same freshly probed socket already failed canonical capability,
        // no handoff exists, the writer has not started, and only Attach+Snapshot bytes are present.
        let admission = shared.note_admission(Shared::admission_from(
            outbound.try_enqueue_batch(initial_lines),
        ));
        if !admission.is_admitted() {
            shared.abort_connection();
            return SpawnedClient {
                shared,
                initial_binding: None,
                initial_exact_viewport: None,
            };
        }
        (token, None)
    } else {
        shared.abort_connection();
        return SpawnedClient {
            shared,
            initial_binding: None,
            initial_exact_viewport: None,
        };
    };
    let initial_binding = initial_token.clone();

    // Only now start the writer. The initial Attach+Snapshot transaction was admitted into an empty,
    // uncontended queue, so startup cannot fail because the writer happened to hold the queue mutex.
    {
        let outbound = Arc::clone(&outbound);
        let writer_shared = Arc::clone(&shared);
        let writer_proxy = proxy.clone_sender();
        std::thread::spawn(move || {
            while let Some((line, wake_retry)) = outbound.dequeue() {
                if wake_retry {
                    let _ = writer_proxy.send(UserEvent::OutboundWritable);
                }
                if let Err(e) =
                    write_frame_before_deadline(&mut write_half, &line, OUTBOUND_WRITE_TIMEOUT)
                {
                    eprintln!("maestro-renderer: bounded socket write failed: {e}");
                    // A timeout may leave a partial JSON frame on the stream. Tear down the whole
                    // client connection so the daemon drops every forwarder and no later frame can
                    // be misparsed as a continuation.
                    let _ = write_half.shutdown(Shutdown::Both);
                    writer_shared.fail_closed_connection(writer_proxy.as_ref());
                    return;
                }
            }
            outbound.close();
        });
    }

    // Reader thread: parse events, validate, publish accepted snapshots, wake the
    // UI on validated change. The SyncState is owned solely by this thread (sole
    // writer of `shared.grid`), so it needs no lock of its own. `session_id`/`sync`
    // are REBOUND in-place when the UI thread switches the active session (a tab
    // switch): `sync_active_session` rebuilds the `SyncState` for the new id and
    // resets the shared grid/exit/scrollback so stale old-session rows can't paint.
    let initial_expected_generation = shared.active_snapshot().expected_generation;
    let initial_is_exact = initial_exact_viewport.is_some();
    {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream);
            let mut session_id = Some(session_id.clone());
            let mut sync = Some(RoutedSyncState::new_with_expected_generation(
                session_id
                    .as_ref()
                    .expect("initial reader session is bound")
                    .clone(),
                initial_token.output_generation,
                initial_expected_generation,
                !initial_is_exact,
            ));
            let mut epoch = initial_token.epoch;
            // Reader-local sibling binding, independent of the active session above. The
            // UI thread fills `shared.sibling` from the split frame; `sync_sibling_session`
            // adopts it here so sibling frames are ingested into the sibling cache. `None`
            // until/unless there is a split with a resolved inactive session.
            let mut sibling_id: Option<String> = None;
            let mut sibling_sync: Option<RoutedSyncState> = None;
            let mut sibling_epoch: u64 = 0;
            // Reader-local multi-pane cache binding (the extra non-active panes beyond the
            // rendered sibling). One `SyncState` per bound pane id, rebuilt on a membership
            // generation bump by `sync_pane_sessions`. Empty for the two-pane case.
            let mut pane_syncs: HashMap<String, PaneSyncState> = HashMap::new();
            let mut pane_generation: u64 = 0;
            let mut retired = RetiredExitBindings::default();
            let mut line_buf: Vec<u8> = Vec::new();
            'reader: loop {
                // Rebase to the active session if the UI switched it since the last
                // event. Done at the TOP of the loop so the first frame after a switch
                // is already filtered against the new id and a late old-session frame
                // is rejected by the fresh `SyncState`/filter.
                sync_active_session(
                    &shared,
                    &mut session_id,
                    &mut sync,
                    &mut epoch,
                    &mut retired,
                );
                sync_sibling_session(
                    &shared,
                    &mut sibling_id,
                    &mut sibling_sync,
                    &mut sibling_epoch,
                    &mut retired,
                );
                sync_pane_sessions(&shared, &mut pane_syncs, &mut pane_generation, &mut retired);
                retire_shadowed_reader_routes(
                    session_id.as_deref(),
                    &mut sibling_id,
                    &mut sibling_sync,
                    &mut pane_syncs,
                    &mut retired,
                );
                line_buf.clear();
                // Bounded framing: cap one line at MAX_LINE_BYTES + 1 so a peer can't
                // make us buffer an unbounded line before parsing. An oversized,
                // unterminated line is a framing violation — stop reading.
                let n = match (&mut reader)
                    .take((MAX_LINE_BYTES + 1) as u64)
                    .read_until(b'\n', &mut line_buf)
                {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if n == 0 {
                    break; // EOF
                }
                let terminated = line_buf.last() == Some(&b'\n');
                if !terminated && line_buf.len() > MAX_LINE_BYTES {
                    eprintln!(
                        "maestro-renderer: event line exceeds {MAX_LINE_BYTES} bytes; closing"
                    );
                    break;
                }
                let line = match std::str::from_utf8(&line_buf) {
                    Ok(s) => s.trim(),
                    Err(_) => {
                        eprintln!("maestro-renderer: event line is not valid UTF-8");
                        break;
                    }
                };
                if line.is_empty() {
                    continue;
                }
                // Decode via the bounded discriminator: it reads the `ev` tag from a
                // minimal envelope and enforces MAX_DAMAGE_BYTES BEFORE fully parsing a
                // damage payload's nested cells.
                let decoded = decode_event_with_route(line);
                let (mut ev, event_route) = match decoded {
                    Ok(decoded) => decoded,
                    Err(err) => {
                        // A line we can't decode is a frame we've lost on the wire. On the
                        // structured-only path the dropped frame may have been a Damage
                        // mutation, so merely logging would leave the screen permanently
                        // stale. Every decode failure therefore drops to resync to pull a
                        // fresh authoritative grid — see `decode_error_requires_resync`.
                        eprintln!("maestro-renderer: {}", describe_decode_error(&err.error));
                        let unattributable_protocol_failure = err.route.is_none()
                            || err.kind.is_none()
                            || (matches!(
                                err.kind,
                                Some(
                                    EventRouteKind::Grid
                                        | EventRouteKind::Damage
                                        | EventRouteKind::ScrollbackRows
                                )
                            ) && err.session_id.is_none());
                        if unattributable_protocol_failure {
                            // Without a bounded route/id proof we cannot know whether the lost line
                            // mutated the current terminal. Continuing could preserve stale pixels
                            // indefinitely or let later buffered effects run after a corrupted frame.
                            shared.fail_closed_connection(proxy.as_ref());
                            break 'reader;
                        }
                        let pre_token = err.session_id.as_deref().and_then(|id| {
                            local_binding_token_for_session(
                                id,
                                session_id.as_deref(),
                                sync.as_ref(),
                                epoch,
                                sibling_id.as_deref(),
                                sibling_sync.as_ref(),
                                sibling_epoch,
                                &pane_syncs,
                            )
                        });
                        let post_token = err
                            .session_id
                            .as_deref()
                            .and_then(|id| shared.binding_token_for_session(id));
                        sync_active_session(
                            &shared,
                            &mut session_id,
                            &mut sync,
                            &mut epoch,
                            &mut retired,
                        );
                        sync_sibling_session(
                            &shared,
                            &mut sibling_id,
                            &mut sibling_sync,
                            &mut sibling_epoch,
                            &mut retired,
                        );
                        sync_pane_sessions(
                            &shared,
                            &mut pane_syncs,
                            &mut pane_generation,
                            &mut retired,
                        );
                        retire_shadowed_reader_routes(
                            session_id.as_deref(),
                            &mut sibling_id,
                            &mut sibling_sync,
                            &mut pane_syncs,
                            &mut retired,
                        );
                        // Never inject a reader Snapshot across a binding handoff: it could overtake
                        // the UI owner's Detach→Attach→Resize→Snapshot FIFO plan. On an unchanged,
                        // already-proven route, a decode loss may still request one token-gated
                        // recovery baseline.
                        if decode_error_requires_resync(&err.error) && pre_token == post_token {
                            if let (Some(route), Some(kind), Some(id), Some(token)) = (
                                err.route,
                                err.kind,
                                err.session_id.as_deref(),
                                post_token.as_ref(),
                            ) {
                                let action = match token {
                                    ViewportBindingToken::Active(_) => sync
                                        .as_ref()
                                        .map(|routed| routed.decode_failure_action(id, kind, route))
                                        .unwrap_or(DecodeFailureAction::Ignore),
                                    ViewportBindingToken::Pane {
                                        pane_kind: PaneKind::Sibling,
                                        ..
                                    } => sibling_sync
                                        .as_ref()
                                        .map(|routed| routed.decode_failure_action(id, kind, route))
                                        .unwrap_or(DecodeFailureAction::Ignore),
                                    ViewportBindingToken::Pane {
                                        pane_kind: PaneKind::Pane,
                                        ..
                                    } => pane_syncs
                                        .get(id)
                                        .map(|pane| {
                                            pane.routed.decode_failure_action(id, kind, route)
                                        })
                                        .unwrap_or(DecodeFailureAction::Ignore),
                                };
                                match action {
                                    DecodeFailureAction::FailClosed => {
                                        shared.fail_closed_connection(proxy.as_ref());
                                        break 'reader;
                                    }
                                    DecodeFailureAction::Recover => match token {
                                        ViewportBindingToken::Active(_) => {
                                            if let Some(routed) = sync.as_mut() {
                                                if routed.sync.can_request_local_resync(id) {
                                                    request_local_recovery(
                                                        &shared,
                                                        &mut routed.sync,
                                                        proxy.as_ref(),
                                                        token,
                                                        id,
                                                    );
                                                }
                                            }
                                        }
                                        ViewportBindingToken::Pane {
                                            pane_kind: PaneKind::Sibling,
                                            ..
                                        } => {
                                            if let Some(routed) = sibling_sync.as_mut() {
                                                if routed.sync.can_request_local_resync(id) {
                                                    request_local_recovery(
                                                        &shared,
                                                        &mut routed.sync,
                                                        proxy.as_ref(),
                                                        token,
                                                        id,
                                                    );
                                                }
                                            }
                                        }
                                        ViewportBindingToken::Pane {
                                            pane_kind: PaneKind::Pane,
                                            ..
                                        } => {
                                            if let Some(pane) = pane_syncs.get_mut(id) {
                                                if pane.routed.sync.can_request_local_resync(id) {
                                                    request_local_recovery(
                                                        &shared,
                                                        &mut pane.routed.sync,
                                                        proxy.as_ref(),
                                                        token,
                                                        id,
                                                    );
                                                }
                                            }
                                        }
                                    },
                                    DecodeFailureAction::Ignore => {}
                                }
                            }
                        }
                        continue;
                    }
                };
                if matches!(ev, DaemonEvent::SessionAttachRefused { .. }) {
                    // A handoff Claim's daemon-atomic lifetime precondition failed before Grid.
                    // No renderer projection may survive or process later queued frames.
                    shared.fail_closed_connection(proxy.as_ref());
                    break 'reader;
                }
                if retired.event_generation_contradicted(&ev, event_route) {
                    shared.fail_closed_connection(proxy.as_ref());
                    break 'reader;
                }
                // Compatibility for retained daemons started by an older Hydra build: alternate-
                // screen shrink could serialize a lone wide lead/spacer at a viewport boundary.
                // Repair ONLY those two provably malformed boundary cells. Interior corruption
                // remains untouched and is rejected by SyncState's strict wide-layout gate.
                if let DaemonEvent::Grid { grid, .. } = &mut ev {
                    let repaired = normalize_legacy_snapshot_wide_boundaries(grid);
                    if cfg!(debug_assertions) && repaired > 0 {
                        eprintln!(
                            "maestro-renderer: normalized {repaired} legacy wide boundary cell(s)"
                        );
                    }
                }

                let event_id = event_session_id(&ev).map(str::to_string);
                let pre_token = event_id.as_deref().and_then(|id| {
                    local_binding_token_for_session(
                        id,
                        session_id.as_deref(),
                        sync.as_ref(),
                        epoch,
                        sibling_id.as_deref(),
                        sibling_sync.as_ref(),
                        sibling_epoch,
                        &pane_syncs,
                    )
                });
                let post_token = event_id
                    .as_deref()
                    .and_then(|id| shared.binding_token_for_session(id));

                // Reconcile only after capturing the pre-block route. Removed states move into the
                // bounded durable-exit table; no local cache write occurs during reconciliation.
                sync_active_session(
                    &shared,
                    &mut session_id,
                    &mut sync,
                    &mut epoch,
                    &mut retired,
                );
                sync_sibling_session(
                    &shared,
                    &mut sibling_id,
                    &mut sibling_sync,
                    &mut sibling_epoch,
                    &mut retired,
                );
                sync_pane_sessions(&shared, &mut pane_syncs, &mut pane_generation, &mut retired);
                retire_shadowed_reader_routes(
                    session_id.as_deref(),
                    &mut sibling_id,
                    &mut sibling_sync,
                    &mut pane_syncs,
                    &mut retired,
                );

                let is_exact_post_attach_echo = matches!(ev, DaemonEvent::Grid { .. })
                    && event_route.live_output_generation.is_none()
                    && post_token.as_ref().is_some_and(|token| {
                        let expected = match token {
                            ViewportBindingToken::Active(token) => token.output_generation,
                            ViewportBindingToken::Pane {
                                output_generation, ..
                            } => *output_generation,
                        };
                        event_route.output_generation == Some(expected)
                    });
                if pre_token != post_token && !is_exact_post_attach_echo {
                    // Ambiguous/stale bytes may still carry the sole exact durable exit, but they
                    // can never paint or emit terminal side effects under the new binding.
                    retired.observe_durable_event(&ev, event_route, proxy.as_ref());
                    continue;
                }
                // Never re-stamp an already-read line with a fresh Shared token during dispatch.
                // This captured authority is the exact pre/post-equal route (or the exact post-bind
                // Attach echo). A clear/rebind after this point makes commit-time validation fail;
                // fetching `shared.active_token()` later would let an A line commit under B.
                let dispatch_token = post_token.clone();

                // Dispatch by the event's session id. A frame for the active session takes the
                // existing active path; a frame for the rendered sibling takes the sibling path;
                // a frame for one of the EXTRA non-active panes takes the multi-pane cache path;
                // anything else is ignored/rejected exactly as `handle_event`'s own id filters
                // would. The route is resolved BEFORE consuming `ev` so the id borrow does not
                // outlive the move into the handler. Active wins over sibling wins over pane, so a
                // pane id can never shadow the live active/sibling path.
                enum Route {
                    Active,
                    Sibling,
                    Pane(String),
                }
                let route = match event_id.as_deref() {
                    Some(id) if session_id.as_deref() == Some(id) => Route::Active,
                    Some(id) if sibling_id.as_deref() == Some(id) => Route::Sibling,
                    Some(id) if pane_syncs.contains_key(id) => Route::Pane(id.to_string()),
                    _ => Route::Active,
                };
                match route {
                    Route::Sibling => {
                        if let (Some(routed), Some(s_id)) =
                            (sibling_sync.as_mut(), sibling_id.as_deref())
                        {
                            if !routed.event_generation_is_authorized(&ev)
                                && routed.event_claims_current_route(event_route)
                            {
                                shared.fail_closed_connection(proxy.as_ref());
                                break 'reader;
                            }
                            if routed.accepts(&ev, event_route) {
                                if let (DaemonEvent::Grid { grid, .. }, Some(token)) =
                                    (&ev, dispatch_token.as_ref())
                                {
                                    if shared.note_exact_viewport_grid(token, &grid.generation)
                                        == Some(false)
                                    {
                                        shared.fail_closed_connection(proxy.as_ref());
                                        break 'reader;
                                    }
                                }
                                let output_generation = routed.output_generation;
                                handle_sibling_event_for_binding(
                                    &shared,
                                    &mut routed.sync,
                                    proxy.as_ref(),
                                    s_id,
                                    sibling_epoch,
                                    epoch,
                                    output_generation,
                                    ev,
                                );
                            } else {
                                retired.observe_durable_event(&ev, event_route, proxy.as_ref());
                            }
                        }
                    }
                    Route::Pane(id) => {
                        if let Some(pane) = pane_syncs.get_mut(&id) {
                            if !pane.routed.event_generation_is_authorized(&ev)
                                && pane.routed.event_claims_current_route(event_route)
                            {
                                shared.fail_closed_connection(proxy.as_ref());
                                break 'reader;
                            }
                            if pane.routed.accepts(&ev, event_route) {
                                if let (DaemonEvent::Grid { grid, .. }, Some(token)) =
                                    (&ev, dispatch_token.as_ref())
                                {
                                    if shared.note_exact_viewport_grid(token, &grid.generation)
                                        == Some(false)
                                    {
                                        shared.fail_closed_connection(proxy.as_ref());
                                        break 'reader;
                                    }
                                }
                                let output_generation = pane.routed.output_generation;
                                handle_pane_event_for_binding(
                                    &shared,
                                    &mut pane.routed.sync,
                                    proxy.as_ref(),
                                    &id,
                                    pane.epoch,
                                    epoch,
                                    output_generation,
                                    ev,
                                );
                            } else {
                                retired.observe_durable_event(&ev, event_route, proxy.as_ref());
                            }
                        }
                    }
                    Route::Active => {
                        if let (Some(routed), Some(ViewportBindingToken::Active(token))) =
                            (sync.as_mut(), dispatch_token)
                        {
                            if !routed.event_generation_is_authorized(&ev)
                                && routed.event_claims_current_route(event_route)
                            {
                                shared.fail_closed_connection(proxy.as_ref());
                                break 'reader;
                            }
                            if routed.accepts(&ev, event_route) {
                                if let DaemonEvent::Grid { grid, .. } = &ev {
                                    if shared.note_exact_viewport_grid(
                                        &ViewportBindingToken::Active(token.clone()),
                                        &grid.generation,
                                    ) == Some(false)
                                    {
                                        shared.fail_closed_connection(proxy.as_ref());
                                        break 'reader;
                                    }
                                }
                                handle_event_for_binding(
                                    &shared,
                                    &mut routed.sync,
                                    proxy.as_ref(),
                                    &token,
                                    ev,
                                );
                            } else {
                                retired.observe_durable_event(&ev, event_route, proxy.as_ref());
                            }
                        } else {
                            retired.observe_durable_event(&ev, event_route, proxy.as_ref());
                        }
                    }
                }
            }
            // EOF, read error, or framing termination all revoke the exact connection authority.
            // Any accepted SessionExited notifications were already delivered in FIFO order before
            // reaching this point; teardown only removes paint/input/effect authority.
            // Reader EOF/framing failure invalidates the whole client connection. Shutdown first
            // to interrupt a writer clone that may be inside a bounded partial write, then abort
            // queued frames, revoke all local paint authority, and wake the owner exactly once.
            let _ = reader.get_ref().shutdown(Shutdown::Both);
            shared.fail_closed_connection(proxy.as_ref());
        });
    }

    SpawnedClient {
        shared,
        initial_binding: Some(initial_binding),
        initial_exact_viewport,
    }
}

/// Compatibility entrypoint used by ordinary callers and existing client tests that need only the
/// live shared state. Startup handoff ownership uses [`spawn_with_initial_binding`] so it never
/// reconstructs publication from mutable state after worker launch.
#[cfg(test)]
pub fn spawn(
    socket_path: String,
    session_id: String,
    attachment_handoff: Option<AttachmentHandoffClaim>,
    proxy: Box<dyn UserEventSender>,
) -> Arc<Shared> {
    spawn_with_initial_binding(socket_path, session_id, None, attachment_handoff, proxy).shared
}

/// Wake the owner event loop to repaint. A closed event loop (window gone) is not
/// an error here — the reader simply stops mattering once the UI has exited.
fn wake(proxy: &dyn UserEventSender) {
    let _ = proxy.send(UserEvent::Redraw);
}

/// Deliver one accepted daemon exit to the owner loop. Unlike an ordinary repaint wake, this
/// preserves the session id, exit code, and the generation proven by the last accepted grid so
/// app/domain state can perform a guarded targeted update. `None` is deliberately forwarded when
/// the daemon exits before any baseline; the durable layer must not guess a generation.
fn notify_session_exit(
    proxy: &dyn UserEventSender,
    session_id: &str,
    code: Option<i32>,
    observed_generation: Option<&str>,
) {
    let _ = proxy.send(UserEvent::SessionExited {
        session_id: session_id.to_string(),
        code,
        observed_generation: observed_generation.map(str::to_string),
    });
}

/// Decide what (if anything) a raw `Output` event should trigger on the
/// structured-only renderer path. The renderer attached `want_raw_output: false`, so
/// the daemon should not send Output at all; if one arrives anyway it is a stray
/// (a daemon that ignored our opt-out, or an in-flight frame from before the opt-out
/// took effect). The structured-only contract is: NEVER resurrect the Output->Snapshot
/// bridge — Damage drives live updates. So this always returns `None`. Extracted as a
/// pure fn purely so the "no Snapshot request on Output" invariant is unit-testable
/// without standing up a winit event loop.
/// Whether a framing/payload failure requires route-classified state repair. This does not mean
/// every error requests a Snapshot: an exact current Damage may recover, a current malformed
/// baseline/direct reply or unattributable envelope fails the connection closed, and a proven
/// stale/wrong-route frame stays inert.
fn decode_error_requires_resync(err: &DecodeError) -> bool {
    match err {
        DecodeError::DamageTooLarge { .. } | DecodeError::BadEnvelope | DecodeError::BadPayload => {
            true
        }
    }
}

/// Narrow compatibility repair for a retained daemon from before wide-boundary normalization.
/// A width-0 cell in the first column and a width-2 cell in the last column can never form a valid
/// in-row pair, so replacing just those cells with styled blanks is unambiguous. All visual style
/// fields are preserved; only text/width change. We deliberately do not repair interior layout so
/// malformed or hostile snapshots still fail the strict [`SyncState`] validation gate.
fn normalize_legacy_snapshot_wide_boundaries(grid: &mut GridSnapshot) -> usize {
    let mut repaired = 0;
    for row in &mut grid.rows_cells {
        if row.is_empty() {
            continue;
        }
        if row[0].width == 0 {
            row[0].text = " ".to_string();
            row[0].width = 1;
            repaired += 1;
        }
        let last = row.len() - 1;
        if row[last].width == 2 {
            row[last].text = " ".to_string();
            row[last].width = 1;
            repaired += 1;
        }
    }
    repaired
}

/// Fixed, low-cardinality diagnostic category for a decode failure. Never include the raw line,
/// session id, generation, or serde's error text: malformed terminal-controlled fields may contain
/// user secrets. The route-specific Recover/Ignore/FailClosed action is logged separately by flow.
fn describe_decode_error(err: &DecodeError) -> &'static str {
    match err {
        DecodeError::DamageTooLarge { .. } => "structured damage frame exceeds limit",
        DecodeError::BadEnvelope => "structured event envelope decode failed",
        DecodeError::BadPayload => "structured event payload decode failed",
    }
}

fn on_structured_output(revision: Revision) -> Option<ClientRequest> {
    #[cfg(debug_assertions)]
    eprintln!(
        "maestro-renderer: unexpected Output (rev {}) on a structured-only attach; ignoring",
        revision.0
    );
    let _ = revision;
    None
}

fn handle_event_for_binding(
    shared: &Arc<Shared>,
    sync: &mut SyncState,
    proxy: &dyn UserEventSender,
    token: &ActiveBindingToken,
    ev: DaemonEvent,
) {
    let session_id = token.session_id.as_str();
    let binding = ViewportBindingToken::Active(token.clone());
    match ev {
        DaemonEvent::Grid { id, grid } => {
            // Gate every snapshot through the sync state machine. A wrong-session,
            // unsupported-version, invalid-dimension, invalid-wide-layout, retired-,
            // or stale-revision frame must never reach the paint path. On rejection we
            // keep showing the last accepted grid and DO NOT wake — an invalid frame is
            // not a state change worth a repaint: wake only after validation.
            //
            // A single Grid can require BOTH actions: paint the accepted grid AND
            // request one more snapshot when live output has already run past it
            // (trailing output the daemon hasn't shipped us yet). We honor both.
            match sync.on_grid(&id, &grid) {
                Ok(outcome) => {
                    shared.clear_recovery(&binding);
                    if outcome.repaint {
                        let rev = grid.revision;
                        if shared.commit_active_grid(token, rev, Arc::new(grid)) {
                            wake(proxy);
                        }
                    }
                    if outcome.request_snapshot {
                        request_snapshot_after_grid(shared, sync, proxy, &binding);
                    }
                }
                Err(reason) => eprintln!("maestro-renderer: rejected snapshot: {reason:?}"),
            }
        }
        // This renderer attaches `want_raw_output: false`, so the daemon does
        // NOT send raw Output — live updates arrive as structured `Damage`. The old
        // Output->Snapshot bridge is gone. An Output event here is unexpected (a daemon
        // that ignored our opt-out, or a stale frame); debug-ignore it. Crucially we do
        // NOT request a Snapshot — doing so would resurrect the polling bridge and
        // defeat the structured-only path. Damage drives all live updates; Snapshots
        // are reserved for attach and resync/resize/generation recovery.
        DaemonEvent::Output { revision, .. } => {
            // Delegate the decision to a pure helper so the "never request a Snapshot"
            // invariant is unit-testable without an event loop. It returns the request
            // (if any) the Output should trigger — structured-only, that is always None.
            debug_assert!(on_structured_output(revision).is_none());
        }
        DaemonEvent::ResyncRequired { id } => {
            // After lag our view is stale. The daemon GUARANTEES ResyncRequired is
            // followed by a fresh authoritative Grid, so we do NOT request one
            // ourselves — we just move to AwaitingResync and wait for that baseline.
            if let Err(reason) = sync.on_resync_required(&id) {
                eprintln!("maestro-renderer: ignored resync: {reason:?}");
            } else {
                shared.commit_active_resync(token);
            }
        }
        DaemonEvent::SessionExited { id, code } => {
            if let Ok(Action::Exited) = sync.on_session_exited(&id) {
                // Local paint commit is binding-gated; the app observation is independently guarded
                // by the accepted daemon generation and survives viewport clear/rebind races.
                shared.commit_active_exit(token, code);
                notify_session_exit(proxy, session_id, code, sync.accepted_generation());
            }
        }
        DaemonEvent::Damage { frame } => {
            // Apply the structured frame against the grid we currently hold,
            // SCRATCH-FIRST. `on_damage` validates the frame and applies its ops onto
            // a CLONE of the held grid; only a fully-applied frame yields a new grid to
            // commit. The held grid is never mutated by an invalid/partial frame.
            //
            // Wrong-session frames are ignored OUTRIGHT — before we read the held grid
            // or contemplate a resync. An unrelated session's frame is not a sync
            // failure of ours; resyncing here (e.g. via the no-baseline path below)
            // would pull a needless snapshot for OUR session over a foreign frame.
            if frame.id.as_str() != session_id {
                return;
            }
            // Clone the held Arc under a short lock so we don't hold `grid` across the
            // apply. (The reader thread is the sole writer of `shared.grid`, so the
            // value can't change underneath us between this read and the commit below.)
            let held = shared.active_grid_for(token);
            let Some(held) = held else {
                if !shared.active_token_is_current(token) {
                    return;
                }
                // No baseline yet — a damage frame (for OUR session) before the first
                // Grid can't be applied. Resync once to pull an authoritative baseline.
                request_local_recovery(shared, sync, proxy, &binding, session_id);
                return;
            };
            match sync.on_damage(&frame.id, &frame, &held) {
                DamageOutcome::Applied(grid) => {
                    let rev = grid.revision;
                    if shared.commit_active_grid(token, rev, Arc::from(grid)) {
                        shared.clear_recovery(&binding);
                        wake(proxy);
                    }
                }
                DamageOutcome::Ignore => {
                    // Duplicate/stale frame — keep the current screen, no resync.
                }
                DamageOutcome::Resync { reason } => {
                    eprintln!("maestro-renderer: damage not applicable ({reason:?}); resyncing");
                    request_local_recovery(shared, sync, proxy, &binding, session_id);
                }
            }
        }
        DaemonEvent::Error { message } => {
            eprintln!("maestro-renderer: daemon error: {message}");
        }
        // Scrollback reply. A read-only historical window — NOT a Grid, so it never
        // enters `SyncState` (no generation/revision continuity gating, no damage path).
        // We turn it into a synthetic snapshot for the paint path and stash it in the
        // renderer-owned `ScrollbackState`. Rejected outright if it is for another session
        // or a generation that no longer matches the live grid (stale after a resync).
        DaemonEvent::ScrollbackRows {
            id,
            generation,
            revision,
            history_len,
            offset_from_top,
            rows,
            row_copy,
        } => {
            // The accept/reject + state-update decision is pure (no proxy/event loop), so
            // it is unit-tested directly. We only translate its result into a wake here.
            if id == session_id {
                let repaint = shared.commit_active_scrollback(
                    token,
                    generation,
                    revision,
                    history_len,
                    offset_from_top,
                    (rows, row_copy),
                );
                let _ = proxy.send(UserEvent::OutboundWritable);
                if repaint {
                    wake(proxy);
                }
            }
        }
        DaemonEvent::TerminalBell { id }
            if id == session_id && sync.accepted_generation().is_some() =>
        {
            let _ = proxy.send(UserEvent::TerminalBell {
                binding: binding.clone(),
            });
        }
        DaemonEvent::TerminalTitle { id, title }
            if id == session_id && sync.accepted_generation().is_some() =>
        {
            let _ = proxy.send(UserEvent::TerminalTitle {
                binding: binding.clone(),
                title,
            });
        }
        DaemonEvent::TerminalClipboardStore { id, text }
            if id == session_id && sync.accepted_generation().is_some() =>
        {
            let _ = proxy.send(UserEvent::TerminalClipboardStore { binding, text });
        }
        DaemonEvent::DaemonInfo { .. }
        | DaemonEvent::SessionAttachRefused { .. }
        | DaemonEvent::TerminalBell { .. }
        | DaemonEvent::TerminalTitle { .. }
        | DaemonEvent::TerminalClipboardStore { .. } => {}
        DaemonEvent::Other => {}
    }
}

#[cfg(test)]
fn handle_event(
    shared: &Arc<Shared>,
    sync: &mut SyncState,
    proxy: &dyn UserEventSender,
    session_id: &str,
    ev: DaemonEvent,
) {
    let Some(token) = shared.active_token() else {
        return;
    };
    if token.session_id != session_id {
        return;
    }
    handle_event_for_binding(shared, sync, proxy, &token, ev);
}

/// The session id a daemon event is addressed to, used to route a frame to the active
/// session vs the attached sibling. `None` for events that carry no id (`Error`,
/// `Other`) — those fall through to the active path, which already ignores them.
fn event_session_id(ev: &DaemonEvent) -> Option<&str> {
    match ev {
        DaemonEvent::Grid { id, .. }
        | DaemonEvent::Output { id, .. }
        | DaemonEvent::ResyncRequired { id }
        | DaemonEvent::SessionExited { id, .. }
        | DaemonEvent::ScrollbackRows { id, .. }
        | DaemonEvent::TerminalBell { id }
        | DaemonEvent::TerminalTitle { id, .. }
        | DaemonEvent::TerminalClipboardStore { id, .. } => Some(id.as_str()),
        DaemonEvent::Damage { frame } => Some(frame.id.as_str()),
        DaemonEvent::DaemonInfo { .. } | DaemonEvent::Error { .. } | DaemonEvent::Other => None,
        DaemonEvent::SessionAttachRefused { id, .. } => Some(id.as_str()),
    }
}

/// Ingest a frame for the attached SIBLING session into the sibling cache. This is the
/// sibling analogue of [`handle_event`]'s active path, but it ONLY maintains the cache —
/// the sibling is not rendered yet (the inactive pane keeps its placeholder), receives no
/// input, and never drives the active session's `SyncState`/grid.
///
/// Gating mirrors the active path: every Grid/Damage goes through the sibling `SyncState`,
/// and the resulting grid is published via [`Shared::apply_sibling_grid`] (id+epoch gated
/// so a late frame from a previous sibling is dropped). Scrollback rows update the sibling's
/// own renderer-owned viewport state; raw Output stays ignored on structured-only attaches.
/// The UI is woken only on an accepted sibling grid, exit, or scrollback update (#gate8).
#[allow(clippy::too_many_arguments)]
fn handle_sibling_event_for_binding(
    shared: &Arc<Shared>,
    sync: &mut SyncState,
    proxy: &dyn UserEventSender,
    sibling_id: &str,
    sibling_epoch: u64,
    viewport_epoch: u64,
    output_generation: u64,
    ev: DaemonEvent,
) {
    let binding = ViewportBindingToken::Pane {
        session_id: sibling_id.to_string(),
        pane_epoch: sibling_epoch,
        pane_kind: PaneKind::Sibling,
        viewport_epoch,
        output_generation,
    };
    match ev {
        DaemonEvent::Grid { id, grid } => match sync.on_grid(&id, &grid) {
            Ok(outcome) => {
                shared.clear_recovery(&binding);
                if outcome.repaint && shared.commit_sibling_grid(&binding, Arc::new(grid)) {
                    wake(proxy);
                }
                if outcome.request_snapshot {
                    request_snapshot_after_grid(shared, sync, proxy, &binding);
                }
            }
            Err(reason) => eprintln!("maestro-renderer: rejected sibling snapshot: {reason:?}"),
        },
        DaemonEvent::Damage { frame } => {
            // A damage frame can only apply against a baseline. The sibling's held grid
            // lives in the cache (not `shared.grid`); read it under the same id+epoch.
            if frame.id.as_str() != sibling_id {
                return;
            }
            let held = shared.pane_grid_for_binding(&binding, PaneKind::Sibling);
            let Some(held) = held else {
                // No sibling baseline yet — request one snapshot to seed the cache.
                request_local_recovery(shared, sync, proxy, &binding, sibling_id);
                return;
            };
            match sync.on_damage(&frame.id, &frame, &held) {
                DamageOutcome::Applied(grid) => {
                    if shared.commit_sibling_grid(&binding, Arc::from(grid)) {
                        shared.clear_recovery(&binding);
                        wake(proxy);
                    }
                }
                DamageOutcome::Ignore => {}
                DamageOutcome::Resync { reason } => {
                    eprintln!(
                        "maestro-renderer: sibling damage not applicable ({reason:?}); resyncing"
                    );
                    request_local_recovery(shared, sync, proxy, &binding, sibling_id);
                }
            }
        }
        DaemonEvent::ResyncRequired { id } => {
            if let Err(reason) = sync.on_resync_required(&id) {
                eprintln!("maestro-renderer: ignored sibling resync: {reason:?}");
            }
        }
        DaemonEvent::SessionExited { id, code } => {
            if let Ok(Action::Exited) = sync.on_session_exited(&id) {
                shared.commit_sibling_exit(&binding, code);
                notify_session_exit(proxy, sibling_id, code, sync.accepted_generation());
            }
        }
        DaemonEvent::ScrollbackRows {
            generation,
            revision,
            history_len,
            offset_from_top,
            rows,
            row_copy,
            ..
        } => {
            let repaint = shared.commit_sibling_scrollback(
                &binding,
                generation,
                revision,
                history_len,
                offset_from_top,
                (rows, row_copy),
            );
            let _ = proxy.send(UserEvent::OutboundWritable);
            if repaint {
                wake(proxy);
            }
        }
        DaemonEvent::TerminalBell { id }
            if id == sibling_id && sync.accepted_generation().is_some() =>
        {
            let _ = proxy.send(UserEvent::TerminalBell {
                binding: binding.clone(),
            });
        }
        DaemonEvent::TerminalTitle { id, title }
            if id == sibling_id && sync.accepted_generation().is_some() =>
        {
            let _ = proxy.send(UserEvent::TerminalTitle {
                binding: binding.clone(),
                title,
            });
        }
        DaemonEvent::TerminalClipboardStore { id, text }
            if id == sibling_id && sync.accepted_generation().is_some() =>
        {
            let _ = proxy.send(UserEvent::TerminalClipboardStore { binding, text });
        }
        DaemonEvent::TerminalBell { .. }
        | DaemonEvent::TerminalTitle { .. }
        | DaemonEvent::TerminalClipboardStore { .. }
        | DaemonEvent::Output { .. }
        | DaemonEvent::DaemonInfo { .. }
        | DaemonEvent::SessionAttachRefused { .. }
        | DaemonEvent::Error { .. }
        | DaemonEvent::Other => {}
    }
}

#[cfg(test)]
fn handle_sibling_event(
    shared: &Arc<Shared>,
    sync: &mut SyncState,
    proxy: &dyn UserEventSender,
    sibling_id: &str,
    sibling_epoch: u64,
    ev: DaemonEvent,
) {
    let Some(ViewportBindingToken::Pane {
        pane_epoch,
        pane_kind: PaneKind::Sibling,
        viewport_epoch,
        output_generation,
        ..
    }) = shared.binding_token_for_session(sibling_id)
    else {
        return;
    };
    if pane_epoch != sibling_epoch {
        return;
    }
    handle_sibling_event_for_binding(
        shared,
        sync,
        proxy,
        sibling_id,
        pane_epoch,
        viewport_epoch,
        output_generation,
        ev,
    );
}

// ============================================================================
// C2 input encoding (pure, unit-testable). These functions PRODUCE bytes for
// the PTY; they do not parse output, so the "no second VT parser" rule does not
// apply here. Correct encoding depends on the terminal's current input modes,
// which the daemon owns and now ships on every SnapshotV2 (#C2).
// ============================================================================

/// The terminal input modes the encoder needs, mirrored from the latest accepted
/// `GridSnapshot`. The UI thread refreshes this whenever a grid is accepted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TermModes {
    /// DECCKM: arrows/Home/End emit `\x1bO_` instead of `\x1b[_`.
    pub app_cursor: bool,
    /// Pasted text must be wrapped in `\x1b[200~`/`\x1b[201~`.
    pub bracketed_paste: bool,
    /// Window focus changes emit `\x1b[I` (in) / `\x1b[O` (out).
    pub focus_reporting: bool,
    /// Mouse modes (click/drag/motion/SGR) the app has enabled.
    pub mouse: MouseModes,
}

/// The mouse-reporting modes the terminal app has requested, mirrored from the daemon
/// snapshot. Drives whether a click/drag/wheel is encoded as a PTY mouse report (so TUIs
/// like vim, htop, tmux receive mouse input) instead of being consumed as local selection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MouseModes {
    /// DECSET 1000: report button press/release.
    pub report: bool,
    /// DECSET 1002: also report motion while a button is held (button-drag tracking).
    pub drag: bool,
    /// DECSET 1003: report motion even with no button held (any-motion tracking).
    pub motion: bool,
    /// DECSET 1006: SGR encoding (`\x1b[<b;x;yM`/`m`) instead of legacy X10 byte-triple.
    pub sgr: bool,
}

impl MouseModes {
    /// Is ANY button-event reporting active? When false, mouse events are local-only
    /// (selection/scroll) and never sent to the PTY.
    pub fn any(&self) -> bool {
        self.report || self.drag || self.motion
    }
}

impl TermModes {
    pub fn from_snapshot(g: &GridSnapshot) -> Self {
        TermModes {
            app_cursor: g.app_cursor,
            bracketed_paste: g.bracketed_paste,
            focus_reporting: g.focus_reporting,
            mouse: MouseModes {
                report: g.mouse_report,
                drag: g.mouse_drag,
                motion: g.mouse_motion,
                sgr: g.mouse_sgr,
            },
        }
    }
}

/// Abstracts clipboard access so the platform surface (arboard) is isolated and
/// tests can inject a fake. `read_text` returns `None` when the clipboard is
/// empty, holds non-text, or the read errors (errors are non-fatal — log+None).
#[cfg(any(not(target_os = "linux"), test))]
pub trait Clipboard {
    fn read_text(&mut self) -> Option<String>;
    /// Write text to the clipboard. Returns `true` on success; errors are
    /// non-fatal (log + `false`) so a copy never crashes the renderer.
    fn write_text(&mut self, text: String) -> bool;
}

/// macOS clipboard backed by `arboard`. Linux deliberately does not compile this
/// backend: arboard's text-only Unix configuration is X11-only, while the Linux
/// DashboardHost uses GTK's native asynchronous Wayland/X11 clipboard service.
#[cfg(not(target_os = "linux"))]
pub struct SystemClipboard {
    inner: Option<arboard::Clipboard>,
}

#[cfg(not(target_os = "linux"))]
impl SystemClipboard {
    pub fn new() -> Self {
        let inner = match arboard::Clipboard::new() {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("maestro-renderer: clipboard unavailable: {e}");
                None
            }
        };
        SystemClipboard { inner }
    }
}

#[cfg(not(target_os = "linux"))]
impl Default for SystemClipboard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_os = "linux"))]
impl Clipboard for SystemClipboard {
    fn read_text(&mut self) -> Option<String> {
        let cb = self.inner.as_mut()?;
        match cb.get_text() {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("maestro-renderer: clipboard read failed: {e}");
                None
            }
        }
    }

    fn write_text(&mut self, text: String) -> bool {
        let Some(cb) = self.inner.as_mut() else {
            return false;
        };
        match cb.set_text(text) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("maestro-renderer: clipboard write failed: {e}");
                false
            }
        }
    }
}

/// Encode a key press into the bytes to send to the PTY, honoring the terminal's
/// current modes. Returns `None` when nothing should be sent (e.g. a Command/Super
/// shortcut, or a key with no PTY meaning). Call only on `ElementState::Pressed`.
///
/// `text` is the OS-composed text for the event (reflects Shift/AltGr, and on macOS
/// the Option-composed glyph). `base_text` is the key WITHOUT modifiers applied —
/// on macOS this is what recovers `b` from Option-b (whose `text` is the glyph `∫`).
/// It comes from winit's `key_without_modifiers()`; when unavailable, pass `None`.
///
/// Order matters: platform-shortcut suppression FIRST (#3) — when Super/Command is
/// held we never leak printable input into the PTY, so Cmd-C/V/W behave as app
/// shortcuts. Then Ctrl chords, then mode-aware named keys, then Alt/Option-as-Meta
/// (ESC prefix), then plain printable text.
pub fn encode_key(
    key: &HostKey,
    text: Option<&str>,
    base_text: Option<&str>,
    mods: &HostModifiers,
    modes: TermModes,
) -> Option<String> {
    // #3: Command/Super suppresses PTY encoding entirely. Application shortcut
    // handling (copy/paste/close) precedes the terminal.
    if mods.super_key {
        return None;
    }

    // Ctrl chords: control characters from letters and a handful of symbols.
    if mods.control {
        if let HostKey::Character(s) = key {
            if let Some(b) = ctrl_byte(s.as_str()) {
                return Some((b as char).to_string());
            }
        }
        if let HostKey::Named(HostNamedKey::Space) = key {
            return Some("\u{0}".to_string());
        }
    }

    // Named keys. Arrows + Home/End are mode-dependent (DECCKM); the rest are not.
    if let HostKey::Named(named) = key {
        if let Some(seq) = encode_named(*named, modes.app_cursor, mods) {
            return Some(seq);
        }
    }

    // Alt/Option-as-Meta: emit ESC + the base printable so Option-b -> ESC b for
    // readline word-motion etc. We use `base_text` (the key with NO modifiers)
    // rather than `text`, because on macOS `text` is the Option-composed glyph
    // (Option-b -> `∫`) — sending that would defeat the purpose. We DELIBERATELY
    // do not guess a base from the composed glyph: if `base_text` is absent or not
    // a single printable char, the Alt branch falls through (the OS text path may
    // still emit the glyph, matching prior behavior). Super and Ctrl are handled
    // above, so this only fires for Alt without those; Alt+named keys (arrows, etc.)
    // already returned from `encode_named` and never reach here.
    if mods.alt {
        if let Some(c) = single_printable(base_text) {
            let mut out = String::with_capacity(1 + c.len_utf8());
            out.push('\u{1b}');
            out.push(c);
            return Some(out);
        }
    }

    // Printable text last. The OS-provided `text` already reflects Shift/AltGr.
    if let Some(s) = text {
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }

    None
}

/// Return the single character of `s` if it is exactly one non-control character,
/// else `None`. Used to gate Alt-as-Meta: we only ESC-prefix a real printable base
/// key, never a multi-char string or a control char.
fn single_printable(s: Option<&str>) -> Option<char> {
    let s = s?;
    let mut chars = s.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return None; // more than one char: not a simple printable key
    }
    if c.is_control() {
        return None;
    }
    Some(c)
}

/// Map a single-character `Key::Character` to its Ctrl control byte, or `None`
/// if it is not a recognized Ctrl chord. Ctrl-A..Z = 0x01..0x1a; the symbol
/// chords cover `[ \ ] ^ _` (0x1b..0x1f); Ctrl-Space (0x00) is handled by caller.
fn ctrl_byte(s: &str) -> Option<u8> {
    let mut chars = s.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return None; // multi-char string is not a Ctrl chord
    }
    match c {
        'a'..='z' => Some((c as u8) & 0x1f),
        'A'..='Z' => Some((c.to_ascii_lowercase() as u8) & 0x1f),
        ' ' => Some(0x00),
        '[' => Some(0x1b),
        '\\' => Some(0x1c),
        ']' => Some(0x1d),
        '^' => Some(0x1e),
        '_' => Some(0x1f),
        _ => None,
    }
}

/// Xterm's modifier parameter: 1 + Shift + 2*Alt + 4*Ctrl.
fn xterm_modifier(mods: &HostModifiers) -> u8 {
    1 + u8::from(mods.shift) + 2 * u8::from(mods.alt) + 4 * u8::from(mods.control)
}

/// Encode terminal named keys using the xterm-256color contract advertised to
/// child processes. This includes the function keys used heavily by htop/mc and
/// modifier-aware CSI sequences used by editors and shells.
fn encode_named(named: HostNamedKey, app_cursor: bool, mods: &HostModifiers) -> Option<String> {
    let modifier = xterm_modifier(mods);
    let modified = modifier != 1;
    let literal = |s: &'static str| Some(s.to_string());

    match named {
        HostNamedKey::Enter => literal("\r"),
        HostNamedKey::Tab if mods.shift && !mods.alt && !mods.control => literal("\x1b[Z"),
        HostNamedKey::Tab => literal("\t"),
        HostNamedKey::Backspace => literal("\x7f"),
        HostNamedKey::Escape => literal("\x1b"),
        HostNamedKey::ArrowUp => {
            if modified {
                Some(format!("\x1b[1;{modifier}A"))
            } else if app_cursor {
                literal("\x1bOA")
            } else {
                literal("\x1b[A")
            }
        }
        HostNamedKey::ArrowDown => {
            if modified {
                Some(format!("\x1b[1;{modifier}B"))
            } else if app_cursor {
                literal("\x1bOB")
            } else {
                literal("\x1b[B")
            }
        }
        HostNamedKey::ArrowRight => {
            if modified {
                Some(format!("\x1b[1;{modifier}C"))
            } else if app_cursor {
                literal("\x1bOC")
            } else {
                literal("\x1b[C")
            }
        }
        HostNamedKey::ArrowLeft => {
            if modified {
                Some(format!("\x1b[1;{modifier}D"))
            } else if app_cursor {
                literal("\x1bOD")
            } else {
                literal("\x1b[D")
            }
        }
        HostNamedKey::Home => {
            if modified {
                Some(format!("\x1b[1;{modifier}H"))
            } else if app_cursor {
                literal("\x1bOH")
            } else {
                literal("\x1b[H")
            }
        }
        HostNamedKey::End => {
            if modified {
                Some(format!("\x1b[1;{modifier}F"))
            } else if app_cursor {
                literal("\x1bOF")
            } else {
                literal("\x1b[F")
            }
        }
        HostNamedKey::Insert => Some(if modified {
            format!("\x1b[2;{modifier}~")
        } else {
            "\x1b[2~".to_string()
        }),
        HostNamedKey::Delete => Some(if modified {
            format!("\x1b[3;{modifier}~")
        } else {
            "\x1b[3~".to_string()
        }),
        HostNamedKey::PageUp => Some(if modified {
            format!("\x1b[5;{modifier}~")
        } else {
            "\x1b[5~".to_string()
        }),
        HostNamedKey::PageDown => Some(if modified {
            format!("\x1b[6;{modifier}~")
        } else {
            "\x1b[6~".to_string()
        }),
        HostNamedKey::F1 | HostNamedKey::F2 | HostNamedKey::F3 | HostNamedKey::F4 => {
            let final_byte = match named {
                HostNamedKey::F1 => 'P',
                HostNamedKey::F2 => 'Q',
                HostNamedKey::F3 => 'R',
                _ => 'S',
            };
            Some(if modified {
                format!("\x1b[1;{modifier}{final_byte}")
            } else {
                format!("\x1bO{final_byte}")
            })
        }
        HostNamedKey::F5
        | HostNamedKey::F6
        | HostNamedKey::F7
        | HostNamedKey::F8
        | HostNamedKey::F9
        | HostNamedKey::F10
        | HostNamedKey::F11
        | HostNamedKey::F12 => {
            let code = match named {
                HostNamedKey::F5 => 15,
                HostNamedKey::F6 => 17,
                HostNamedKey::F7 => 18,
                HostNamedKey::F8 => 19,
                HostNamedKey::F9 => 20,
                HostNamedKey::F10 => 21,
                HostNamedKey::F11 => 23,
                _ => 24,
            };
            Some(if modified {
                format!("\x1b[{code};{modifier}~")
            } else {
                format!("\x1b[{code}~")
            })
        }
        _ => None,
    }
}

/// Hard cap on the bytes we will forward from a single paste. A hostile or
/// runaway clipboard must not be able to shove an unbounded write at the PTY in
/// one frame; the payload is truncated (on a UTF-8 char boundary) to this many
/// bytes after sanitizing. 1 MiB matches the outbound queue's per-frame budget.
pub const MAX_PASTE_BYTES: usize = 1024 * 1024;

/// Build the bytes for a paste of `raw` clipboard text under the current modes.
/// Returns `None` (send nothing) when the text is empty after sanitizing.
///
/// Sanitizing, in order:
/// - NUL bytes are stripped (terminals reject them).
/// - In `bracketed_paste` mode the clipboard could itself contain the literal
///   bracketed-paste markers `\x1b[200~`/`\x1b[201~`. A clipboard-supplied
///   `\x1b[201~` would prematurely close OUR wrapper, letting everything after
///   it be interpreted as keystrokes/commands rather than pasted data — a
///   classic paste-injection. We therefore strip any embedded `\x1b[200~` and
///   `\x1b[201~` so the wrapper we add is the ONLY pair the terminal sees.
///   Stripping runs to a FIXPOINT: a single non-overlapping `str::replace`
///   pass is not idempotent, so a nested payload like `\x1b[201\x1b[201~~`
///   would reconstitute a live `\x1b[201~` after one pass. We loop until no
///   marker remains.
/// - The result is truncated to `MAX_PASTE_BYTES` on a char boundary.
///
/// All other Unicode and newlines are preserved. Under `bracketed_paste` the
/// final result is wrapped EXACTLY once with `\x1b[200~` … `\x1b[201~`. The
/// caller emits this as ONE atomic `Write`.
pub fn encode_paste(raw: &str, bracketed_paste: bool) -> Option<String> {
    let mut cleaned: String = raw.chars().filter(|&c| c != '\0').collect();
    if bracketed_paste {
        loop {
            let stripped = cleaned.replace("\x1b[200~", "").replace("\x1b[201~", "");
            if stripped.len() == cleaned.len() {
                cleaned = stripped;
                break;
            }
            cleaned = stripped;
        }
    }
    if cleaned.len() > MAX_PASTE_BYTES {
        let mut end = MAX_PASTE_BYTES;
        while end > 0 && !cleaned.is_char_boundary(end) {
            end -= 1;
        }
        cleaned.truncate(end);
    }
    if cleaned.is_empty() {
        return None;
    }
    if bracketed_paste {
        Some(format!("\x1b[200~{cleaned}\x1b[201~"))
    } else {
        Some(cleaned)
    }
}

/// Read the clipboard once and produce the single paste payload to write, or
/// `None` if there is nothing to send (empty/unavailable clipboard). Errors are
/// already swallowed by the `Clipboard` impl. Never simulates paste as key events.
#[cfg(any(not(target_os = "linux"), test))]
pub fn paste_payload(clipboard: &mut dyn Clipboard, modes: TermModes) -> Option<String> {
    let raw = clipboard.read_text()?;
    encode_paste(&raw, modes.bracketed_paste)
}

/// Focus change encoding (#8): `\x1b[I` on focus-in, `\x1b[O` on focus-out, but
/// ONLY when focus-reporting mode is enabled; otherwise send nothing.
pub fn encode_focus(focused: bool, modes: TermModes) -> Option<String> {
    if !modes.focus_reporting {
        return None;
    }
    Some(if focused { "\x1b[I" } else { "\x1b[O" }.to_string())
}

/// Direction of a command-palette overlay selection move. The overlay is a foreground modal: while
/// visible, unmodified Up/Down arrows move the highlighted action row and every key is consumed so
/// none reaches the PTY, scrollback, or copy/paste shortcuts (the consume policy lives in the caller;
/// this enum only names the two navigation directions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandPaletteNavKey {
    Up,
    Down,
}

/// Compute the next selected LINE index for command-palette overlay navigation, or `None` when the
/// selection would not change (so the caller can skip the redraw). Pure so it is unit-testable without
/// a window or GPU.
///
/// `lines` are the composed overlay lines; only `selectable` lines (action rows) are navigable —
/// title/query header and the empty-state line are skipped. The returned `usize` is an index INTO
/// `lines` (not into the action-row sub-sequence), so the caller can flip `selected` flags directly.
///
/// Behavior (matches the slice's contract):
/// - With no selectable lines: always `None` (keys are still consumed by the caller, but nothing moves).
/// - `Down` advances to the next selectable line, wrapping the last selectable line to the first.
/// - `Up` retreats to the previous selectable line, wrapping the first selectable line to the last.
/// - When no line is currently `selected` (missing selection) but selectable lines exist, `Down`
///   selects the FIRST selectable line and `Up` selects the LAST.
/// - When the move lands on the line that is already selected (e.g. a single selectable line, which
///   wraps onto itself), returns `None` — no change, no redraw.
pub fn command_palette_nav(
    lines: &[crate::RendererCommandPaletteOverlayLine],
    key: CommandPaletteNavKey,
) -> Option<usize> {
    let selectable: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.selectable)
        .map(|(i, _)| i)
        .collect();
    if selectable.is_empty() {
        return None;
    }

    // Position of the currently-selected line within `selectable` (if any selectable line is
    // selected). A `selected` flag on a non-selectable line is ignored by construction.
    let current = lines
        .iter()
        .position(|l| l.selectable && l.selected)
        .and_then(|line_idx| selectable.iter().position(|&i| i == line_idx));

    let next_pos = match (current, key) {
        // Missing selection: Down -> first selectable, Up -> last selectable.
        (None, CommandPaletteNavKey::Down) => 0,
        (None, CommandPaletteNavKey::Up) => selectable.len() - 1,
        (Some(pos), CommandPaletteNavKey::Down) => (pos + 1) % selectable.len(),
        (Some(pos), CommandPaletteNavKey::Up) => (pos + selectable.len() - 1) % selectable.len(),
    };

    let next_line = selectable[next_pos];
    // No-op move (single selectable wrapping onto itself, or already there): report no change.
    if current == Some(next_pos) {
        return None;
    }
    Some(next_line)
}

/// Pure key policy for the command-palette overlay's modal Escape: return `true` only when an
/// UNMODIFIED `Escape` should dismiss the overlay. Modified `Escape` (any of Ctrl/Alt/Super/Shift held)
/// is swallowed by the modal but must NOT dismiss, so this returns `false` for it. The caller still
/// consumes the key regardless of this result — this helper only decides the dismiss action, mirroring
/// `command_palette_nav`'s split of policy (here) from consumption (the caller). Pure so it is
/// unit-testable without a window.
pub fn command_palette_escape_dismisses(is_escape: bool, any_modifier_held: bool) -> bool {
    is_escape && !any_modifier_held
}

/// Which mouse button a report concerns. The numeric values are the low 2 bits of the
/// xterm button byte: left=0, middle=1, right=2. Wheel up/down are encoded separately
/// (bit 6 set, codes 64/65) and have no `MouseButton`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
}

impl MouseButton {
    fn code(self) -> u8 {
        match self {
            MouseButton::Left => 0,
            MouseButton::Middle => 1,
            MouseButton::Right => 2,
        }
    }
}

/// A normalized mouse interaction to (maybe) report to the PTY. The renderer maps winit
/// events to these; `encode_mouse` turns them into the xterm wire sequence under the
/// active mouse modes. `Move` carries the button held during a drag (`None` if no button).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEvent {
    Press(MouseButton),
    Release(MouseButton),
    /// Pointer motion to a new cell. `held` is the button down during the motion, if any.
    Move {
        held: Option<MouseButton>,
    },
    WheelUp,
    WheelDown,
}

/// Encode a mouse event into the bytes to send to the PTY, honoring the active mouse modes
/// and modifier keys. Returns `None` when nothing should be reported:
///
/// - no button-event mode active (`!modes.mouse.any()`),
/// - a bare `Move` while only click-reporting (1000) is on (motion requires 1002/1003),
/// - a no-button `Move` while only button-drag (1002) is on (1002 reports motion only
///   while a button is held; any-motion needs 1003),
/// - legacy (non-SGR) coordinates/buttons whose `value + 32` would exceed 127 — see below.
///
/// WIRE BYTE-SAFETY: `Write.data` is a JSON String carried as UTF-8, and the daemon writes
/// `data.into_bytes()` (the UTF-8 encoding) to the PTY. SGR (1006) reports are pure ASCII,
/// so they always round-trip as single bytes. Legacy X10 reports use raw bytes `value + 32`;
/// any byte ≥ 128 would be re-encoded by UTF-8 into TWO bytes and corrupt the report. We
/// therefore only emit a legacy report when every byte stays ≤ 127 (cells 1..=95); beyond
/// that, or when the app has not negotiated SGR, we drop the report rather than send garbage.
/// Essentially all modern TUIs negotiate SGR (1006), so this limit is rarely hit in practice.
///
/// `col`/`row` are 0-based cell coordinates; the wire format is 1-based. `shift`/`alt`/
/// `ctrl` set the xterm modifier bits (4/8/16). Pure and unit-tested.
pub fn encode_mouse(
    event: MouseEvent,
    col: usize,
    row: usize,
    modes: TermModes,
    shift: bool,
    alt: bool,
    ctrl: bool,
) -> Option<String> {
    let m = modes.mouse;
    if !m.any() {
        return None;
    }

    // Resolve the base button code and whether this is a release (only meaningful for the
    // legacy/X10 path, where release is button 3 / `m` in SGR).
    let (base, is_release) = match event {
        MouseEvent::Press(b) => (b.code(), false),
        MouseEvent::Release(b) => (b.code(), true),
        MouseEvent::WheelUp => (64, false),
        MouseEvent::WheelDown => (65, false),
        MouseEvent::Move { held } => {
            // Motion is only reported under 1002 (button held) or 1003 (any motion).
            if !m.drag && !m.motion {
                return None;
            }
            match held {
                // Button held: 1002 (drag) or 1003 (motion) both report it. The motion
                // flag (bit 5 = 32) is added; the low 2 bits identify the button.
                Some(b) => (b.code() + 32, false),
                // No-button motion requires any-motion mode (1003). 3 = "no button".
                None => {
                    if !m.motion {
                        return None;
                    }
                    (3 + 32, false)
                }
            }
        }
    };

    // Modifier bits: shift=4, alt(meta)=8, ctrl=16.
    let mods = (shift as u8) * 4 + (alt as u8) * 8 + (ctrl as u8) * 16;
    let cb = base | mods;

    // Wire coordinates are 1-based.
    let x = col.saturating_add(1);
    let y = row.saturating_add(1);

    if m.sgr {
        // SGR (1006): `\x1b[<cb;x;y` then `M` (press/motion/wheel) or `m` (release).
        let final_byte = if is_release { 'm' } else { 'M' };
        Some(format!("\x1b[<{cb};{x};{y}{final_byte}"))
    } else {
        // Legacy X10: `\x1b[M` + 3 bytes (cb+32, x+32, y+32). Release is button 3 (low 2
        // bits = 3), keeping the motion/modifier bits.
        let cb_legacy = if is_release { (cb & !0b11) | 0b11 } else { cb };
        // Byte-safety: each `value + 32` must stay ASCII (≤ 127) or UTF-8 would split it
        // into two bytes on the wire and corrupt the report. That caps cells at 95.
        let bb = 32usize + cb_legacy as usize;
        let bx = 32usize + x;
        let by = 32usize + y;
        if bb > 127 || bx > 127 || by > 127 {
            return None;
        }
        let bytes = [0x1b, b'[', b'M', bb as u8, bx as u8, by as u8];
        Some(bytes.iter().map(|&b| b as char).collect())
    }
}

/// Upper bound on a dimension we will claim. Mirrors the daemon's `MAX_DIMENSION`
/// (pty-daemon grid.rs): the daemon clamps anyway, but the renderer must not claim
/// a geometry the daemon will silently reduce, or our painted grid and the PTY
/// would disagree on size.
pub const MAX_DIMENSION: u16 = 2000;

/// Legacy convenience wrapper for computing daemon `(cols, rows)` from physical window and cell
/// dimensions while reserving one chrome row. New runtime paths whose visible chrome is dynamic use
/// [`compute_dims_with_chrome_rows`] directly so daemon geometry matches the rows actually painted.
/// Result is clamped to `[1, MAX_DIMENSION]` so neither dimension is ever 0 (a 1px window) nor
/// exceeds the daemon's cap.
#[cfg_attr(not(test), allow(dead_code))]
pub fn compute_dims(phys_w: f32, phys_h: f32, cell_phys_w: f32, cell_phys_h: f32) -> (u16, u16) {
    // Preserve this helper's historical one-row contract for legacy callers and focused tests.
    compute_dims_with_chrome_rows(phys_w, phys_h, cell_phys_w, cell_phys_h, 1)
}

/// Like [`compute_dims`], but reserves `chrome_rows` cell rows of height for renderer
/// chrome instead of hardcoding a single row. `compute_dims` delegates here with
/// `chrome_rows = 1` to preserve that wrapper's legacy contract. Each reserved chrome row removes
/// one cell row of terminal height WHEN the window is tall enough; the terminal still
/// keeps at least one row regardless. All math is in physical space (matching
/// `render()` and `compute_dims`); the result is clamped to `[1, MAX_DIMENSION]`.
///
/// This is a PURE geometry helper: it reserves only the row count supplied by the caller and does
/// not itself decide which chrome is visible or draw any chrome.
pub fn compute_dims_with_chrome_rows(
    phys_w: f32,
    phys_h: f32,
    cell_phys_w: f32,
    cell_phys_h: f32,
    chrome_rows: u16,
) -> (u16, u16) {
    // Degenerate cell metrics (renderer not ready) -> minimum viable grid.
    if cell_phys_w <= 0.0 || cell_phys_h <= 0.0 {
        return (1, 1);
    }
    let chrome_h = cell_phys_h * chrome_rows as f32;
    let terminal_h = (phys_h - chrome_h).max(cell_phys_h);
    let rows = (terminal_h / cell_phys_h).floor();
    let cols = (phys_w / cell_phys_w).floor();
    let clamp = |v: f32| -> u16 {
        if v < 1.0 {
            1
        } else if v > MAX_DIMENSION as f32 {
            MAX_DIMENSION
        } else {
            v as u16
        }
    };
    (clamp(cols), clamp(rows))
}

/// A grid cell coordinate (column, row), 0-based. Produced by hit-testing a
/// pixel position against the painted grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CellPos {
    pub col: usize,
    pub row: usize,
}

/// Map a physical pixel position to the grid cell it falls in, clamped to the grid bounds
/// `[0, cols) x [0, rows)`. Callers that paint chrome outside those bounds must intercept that band
/// before calling this helper; otherwise any pixel below/right of the grid clamps to its last cell.
///
/// `cell_phys_w/h` are the physical cell metrics (logical * scale_factor). A
/// click left/above the grid clamps to `(0, 0)`; right/below clamps to the last
/// cell. Degenerate metrics or an empty grid yield `None`.
pub fn pixel_to_cell(
    x: f32,
    y: f32,
    cell_phys_w: f32,
    cell_phys_h: f32,
    cols: usize,
    rows: usize,
) -> Option<CellPos> {
    if cell_phys_w <= 0.0 || cell_phys_h <= 0.0 || cols == 0 || rows == 0 {
        return None;
    }
    let cx = (x.max(0.0) / cell_phys_w).floor() as usize;
    let cy = (y.max(0.0) / cell_phys_h).floor() as usize;
    Some(CellPos {
        col: cx.min(cols - 1),
        row: cy.min(rows - 1),
    })
}

/// Map a physical pixel position to a grid cell when the painted grid is translated DOWN by
/// `top_offset` physical pixels (the reserved top tab-bar row) and RIGHT by `left_offset` physical
/// pixels (the reserved left dock column). A pixel inside the top band (`y < top_offset`) or the left
/// dock (`x < left_offset`) belongs to renderer chrome, NOT the grid, so this returns `None` there
/// instead of clamping to row/col 0 — that lets the caller consume the click as chrome rather than
/// leaking it into selection or PTY mouse reporting. Inside the grid, both offsets are removed and
/// [`pixel_to_cell`] maps the remainder, so the first grid cell just past the chrome is (0,0). With
/// both offsets `== 0.0` this is exactly [`pixel_to_cell`].
#[allow(clippy::too_many_arguments)]
pub fn pixel_to_cell_with_top_offset(
    x: f32,
    y: f32,
    left_offset: f32,
    top_offset: f32,
    cell_phys_w: f32,
    cell_phys_h: f32,
    cols: usize,
    rows: usize,
) -> Option<CellPos> {
    if top_offset > 0.0 && y < top_offset {
        return None;
    }
    if left_offset > 0.0 && x < left_offset {
        return None;
    }
    pixel_to_cell(
        x - left_offset.max(0.0),
        y - top_offset.max(0.0),
        cell_phys_w,
        cell_phys_h,
        cols,
        rows,
    )
}

/// Extract the text covered by the selection `[anchor, focus]` (inclusive, order
/// independent) from the painted grid, row by row. Rows are joined with `'\n'`.
/// Full right-edge ASCII padding is trimmed; explicitly partial final selections
/// retain spaces. Intersected wide/combining graphemes are copied whole and once.
/// A selection containing only ASCII spaces remains empty, avoiding clipboard overwrite.
///
/// The selection is row-major and contiguous: the first row starts at the
/// anchor column and runs to the row end; intermediate rows are full width; the
/// last row runs from the start to the focus column. A single-row selection runs
/// from the lower to the higher column on that row.
pub fn extract_selection(rows_cells: &[Vec<Cell>], anchor: CellPos, focus: CellPos) -> String {
    extract_selection_rows(rows_cells, None, anchor, focus)
}

/// Copy from the exact painted snapshot; malformed or missing metadata falls back
/// to physical row boundaries, never a previous view's copy semantics.
pub fn extract_grid_selection(grid: &GridSnapshot, anchor: CellPos, focus: CellPos) -> String {
    let Some(metadata) = grid.row_copy.as_deref().filter(|metadata| {
        grid.rows == grid.rows_cells.len()
            && grid.rows_cells.iter().all(|row| row.len() == grid.cols)
            && crate::wire::row_copy_cells_valid(&grid.rows_cells, Some(metadata))
    }) else {
        return extract_selection(&grid.rows_cells, anchor, focus);
    };
    extract_selection_rows(&grid.rows_cells, Some(metadata), anchor, focus)
}

fn extract_selection_rows(
    rows_cells: &[Vec<Cell>],
    metadata: Option<&[maestro_protocol::row_copy::RowCopy]>,
    anchor: CellPos,
    focus: CellPos,
) -> String {
    if rows_cells.is_empty() {
        return String::new();
    }
    let (start, end) = if (anchor.row, anchor.col) <= (focus.row, focus.col) {
        (anchor, focus)
    } else {
        (focus, anchor)
    };
    let last_row = rows_cells.len() - 1;
    let r0 = start.row.min(last_row);
    let r1 = end.row.min(last_row);

    let wraps = |row: usize| {
        metadata.is_some_and(|metadata| {
            metadata
                .get(row)
                .zip(metadata.get(row + 1))
                .is_some_and(|(current, next)| current.soft_wrap && next.starts_line == Some(false))
        })
    };
    let mut out = String::new();
    for (r, row) in rows_cells.iter().enumerate().take(r1 + 1).skip(r0) {
        if r > r0 && !wraps(r - 1) {
            out.push('\n');
        }
        let ncols = row.len();
        if ncols == 0 {
            continue;
        }
        let col_start = if r == r0 { start.col } else { 0 };
        let col_end = if r == r1 { end.col } else { ncols - 1 };
        let mut col_start = col_start.min(ncols - 1);
        let col_end = col_end.min(ncols - 1);
        // An inclusive selection of the continuation intersects its preceding glyph.
        if col_start > 0 && row[col_start].width == 0 && row[col_start - 1].width == 2 {
            col_start -= 1;
        }

        let mut line = String::new();
        for (col, cell) in row.iter().enumerate().take(col_end + 1).skip(col_start) {
            if cell.width == 0
                || metadata.is_some_and(|metadata| {
                    metadata[r]
                        .excluded_columns
                        .binary_search_by_key(&col, |col| usize::from(*col))
                        .is_ok()
                })
            {
                continue;
            }
            line.push_str(&cell.text);
        }
        if col_end == ncols - 1 && !wraps(r) {
            out.push_str(line.trim_end_matches(' '));
        } else {
            out.push_str(&line);
        }
    }
    if out.bytes().all(|byte| byte == b' ') {
        out.clear();
    }
    out
}

/// Latest-wins resize throttle (#7). A burst of distinct geometries during a drag
/// collapses to at most one send per `min_interval`, and the settled geometry is
/// always flushed by a trailing call. Time is injected (`now`) so the policy is
/// pure and unit-testable without a real clock or window.
#[derive(Debug, Default)]
pub struct ResizeCoalescer {
    pending: Option<(u16, u16)>,
    last_sent: Option<(u16, u16)>,
    last_sent_at: Option<std::time::Instant>,
}

impl ResizeCoalescer {
    /// Record a freshly computed target geometry. Dedups against the last sent
    /// size (no-op if unchanged) and overwrites any earlier pending value
    /// (latest-wins). Returns the geometry to send NOW if the interval allows,
    /// else `None` (it stays pending for a trailing `flush`).
    pub fn record(
        &mut self,
        dims: (u16, u16),
        now: std::time::Instant,
        min_interval: std::time::Duration,
    ) -> Option<(u16, u16)> {
        if Some(dims) == self.last_sent {
            self.pending = None;
            return None;
        }
        self.pending = Some(dims);
        self.flush(now, min_interval)
    }

    /// Send the pending geometry if `min_interval` has elapsed since the last send.
    /// Returns the geometry to send (the LATEST pending, not intermediates), or
    /// `None` if nothing is due. Call from the idle path for the trailing send.
    pub fn flush(
        &mut self,
        now: std::time::Instant,
        min_interval: std::time::Duration,
    ) -> Option<(u16, u16)> {
        let dims = self.pending?;
        let due = self
            .last_sent_at
            .map(|t| now.duration_since(t) >= min_interval)
            .unwrap_or(true);
        if !due {
            return None;
        }
        if Some(dims) == self.last_sent {
            self.pending = None;
            return None;
        }
        self.last_sent = Some(dims);
        self.last_sent_at = Some(now);
        self.pending = None;
        Some(dims)
    }

    /// Forget the last-sent geometry so the next `record` of the SAME window size is not deduped away.
    /// Used when the SPLIT geometry changes without a window resize (a tab split toggles, or the active
    /// pane switches sides): the window dims are unchanged but the active session must be re-sized to its
    /// new pane region. Leaves any pending value and the last-sent timestamp intact (the throttle still
    /// applies), so this only defeats the value-equality dedup, not the rate limit.
    pub fn invalidate_last_sent(&mut self) {
        self.last_sent = None;
    }

    /// Roll back the optimistic `flush` bookkeeping when owner-loop admission was refused. The
    /// latest target stays pending and is immediately retryable; it is not described as daemon-sent.
    pub fn request_not_admitted(&mut self, dims: (u16, u16)) {
        self.last_sent = None;
        self.last_sent_at = None;
        self.pending = Some(dims);
    }

    /// Whether a geometry is still waiting for a trailing flush.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// When the last send happened (drives the trailing-flush wake time).
    pub fn last_sent_at(&self) -> Option<std::time::Instant> {
        self.last_sent_at
    }
}

#[cfg(test)]
mod input_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// C3.7: on the structured-only path a stray `Output` event must be ignored and
    /// must NOT enqueue a Snapshot request (which would resurrect the polling bridge).
    /// We drive the exact decision the Output arm makes and assert it produces no
    /// request, then confirm the outbound queue stays empty even if we route the
    /// (None) result through `send_request`'s call site.
    #[test]
    fn unexpected_output_requests_nothing_and_enqueues_nothing() {
        let (shared, queue) = Shared::with_test_queue();

        // The pure decision: a stray Output yields no follow-up request.
        assert!(
            on_structured_output(Revision(123)).is_none(),
            "structured-only Output must not trigger any request"
        );

        // Mirror the production call site: only enqueue if the helper returned Some.
        if let Some(req) = on_structured_output(Revision(123)) {
            assert_eq!(shared.send_request(&req), RequestAdmission::Admitted);
        }
        assert_eq!(
            queue.len(),
            0,
            "no request must be enqueued for an unexpected Output"
        );

        // Sanity: the queue DOES enqueue when something is actually sent — proves the
        // empty assertion above is meaningful, not a dead queue.
        assert_eq!(
            shared.send_request(&ClientRequest::Snapshot {
                id: "s1".to_string(),
            }),
            RequestAdmission::Admitted
        );
        assert_eq!(queue.len(), 1, "a real request enqueues exactly one frame");
    }

    /// Build a command-palette overlay line for nav tests.
    fn cp_line(
        text: &str,
        selectable: bool,
        selected: bool,
    ) -> crate::RendererCommandPaletteOverlayLine {
        crate::RendererCommandPaletteOverlayLine {
            text: text.to_string(),
            selectable,
            selected,
            // Nav operates purely on the `selectable` flag; a placeholder index keeps selectable lines
            // realistic (every selectable action line carries `Some(_)`) without affecting nav results.
            action_index: if selectable { Some(0) } else { None },
        }
    }

    /// Title + two action rows; the first action row is selected.
    fn cp_lines_two_actions_first_selected() -> Vec<crate::RendererCommandPaletteOverlayLine> {
        vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, true),
            cp_line("New Workspace", true, false),
        ]
    }

    #[test]
    fn command_palette_nav_down_moves_first_action_to_second() {
        let lines = cp_lines_two_actions_first_selected();
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Down),
            Some(2)
        );
    }

    #[test]
    fn command_palette_nav_up_moves_second_action_to_first() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, false),
            cp_line("New Workspace", true, true),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Up),
            Some(1)
        );
    }

    #[test]
    fn command_palette_nav_down_wraps_last_action_to_first() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, false),
            cp_line("New Workspace", true, true),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Down),
            Some(1)
        );
    }

    #[test]
    fn command_palette_nav_up_wraps_first_action_to_last() {
        let lines = cp_lines_two_actions_first_selected();
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Up),
            Some(2)
        );
    }

    #[test]
    fn command_palette_nav_missing_selection_down_selects_first_action() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, false),
            cp_line("New Workspace", true, false),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Down),
            Some(1)
        );
    }

    #[test]
    fn command_palette_nav_missing_selection_up_selects_last_action() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, false),
            cp_line("New Workspace", true, false),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Up),
            Some(2)
        );
    }

    #[test]
    fn command_palette_nav_no_selectable_rows_reports_no_change() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("(no commands)", false, false),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Down),
            None
        );
        assert_eq!(command_palette_nav(&lines, CommandPaletteNavKey::Up), None);
    }

    #[test]
    fn command_palette_nav_single_selectable_row_reports_no_change() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, true),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Down),
            None
        );
        assert_eq!(command_palette_nav(&lines, CommandPaletteNavKey::Up), None);
    }

    #[test]
    fn command_palette_unmodified_escape_dismisses() {
        // Unmodified Escape (no modifier held) is the dismiss trigger.
        assert!(command_palette_escape_dismisses(true, false));
    }

    #[test]
    fn command_palette_modified_escape_does_not_dismiss() {
        // Any modifier held (Ctrl/Alt/Super/Shift collapses to `true` at the call site) -> no dismiss.
        assert!(!command_palette_escape_dismisses(true, true));
    }

    #[test]
    fn command_palette_non_escape_key_does_not_dismiss() {
        // A non-Escape key never dismisses, regardless of modifiers.
        assert!(!command_palette_escape_dismisses(false, false));
        assert!(!command_palette_escape_dismisses(false, true));
    }

    /// Build a `HostModifiers` from bool flags for tests.
    fn host_mods(control: bool, alt: bool, shift: bool, super_key: bool) -> HostModifiers {
        HostModifiers {
            control,
            alt,
            shift,
            super_key,
        }
    }

    fn no_mods() -> HostModifiers {
        HostModifiers::default()
    }

    fn modes(app_cursor: bool, bracketed: bool, focus: bool) -> TermModes {
        TermModes {
            app_cursor,
            bracketed_paste: bracketed,
            focus_reporting: focus,
            mouse: MouseModes::default(),
        }
    }

    /// Build `TermModes` carrying only the given mouse modes (other modes off).
    fn mouse_modes(report: bool, drag: bool, motion: bool, sgr: bool) -> TermModes {
        TermModes {
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse: MouseModes {
                report,
                drag,
                motion,
                sgr,
            },
        }
    }

    struct FakeClipboard(Option<String>);
    impl Clipboard for FakeClipboard {
        fn read_text(&mut self) -> Option<String> {
            self.0.clone()
        }
        fn write_text(&mut self, text: String) -> bool {
            self.0 = Some(text);
            true
        }
    }

    #[test]
    fn super_key_suppresses_printable_input() {
        // Cmd-C / Cmd-V etc. must never leak into the PTY.
        let m = host_mods(false, false, false, true);
        let out = encode_key(
            &HostKey::Character("c".to_string()),
            Some("c"),
            Some("c"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(out, None, "Super-held printable must not encode");
    }

    #[test]
    fn unicode_text_round_trips_as_utf8() {
        let out = encode_key(
            &HostKey::Character("é".to_string()),
            Some("é"),
            Some("é"),
            &no_mods(),
            modes(false, false, false),
        );
        assert_eq!(out.as_deref(), Some("é"));
        assert_eq!(out.unwrap().as_bytes(), "é".as_bytes());
    }

    #[test]
    fn ctrl_letter_chords() {
        let m = host_mods(true, false, false, false);
        let c = encode_key(
            &HostKey::Character("c".to_string()),
            Some("c"),
            Some("c"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(c.as_deref(), Some("\u{3}"), "Ctrl-C = 0x03");
        let a = encode_key(
            &HostKey::Character("a".to_string()),
            Some("a"),
            Some("a"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(a.as_deref(), Some("\u{1}"), "Ctrl-A = 0x01");
    }

    #[test]
    fn ctrl_space_is_nul() {
        let m = host_mods(true, false, false, false);
        let out = encode_key(
            &HostKey::Named(HostNamedKey::Space),
            None,
            None,
            &m,
            modes(false, false, false),
        );
        assert_eq!(out.as_deref(), Some("\u{0}"));
    }

    #[test]
    fn arrows_respect_application_cursor_mode() {
        // Normal mode -> CSI sequences.
        let up = encode_key(
            &HostKey::Named(HostNamedKey::ArrowUp),
            None,
            None,
            &no_mods(),
            modes(false, false, false),
        );
        assert_eq!(up.as_deref(), Some("\x1b[A"));
        // Application cursor mode -> SS3 sequences.
        let up_app = encode_key(
            &HostKey::Named(HostNamedKey::ArrowUp),
            None,
            None,
            &no_mods(),
            modes(true, false, false),
        );
        assert_eq!(up_app.as_deref(), Some("\x1bOA"));
        // Home/End follow the same rule.
        let home = encode_key(
            &HostKey::Named(HostNamedKey::Home),
            None,
            None,
            &no_mods(),
            modes(false, false, false),
        );
        assert_eq!(home.as_deref(), Some("\x1b[H"));
        let home_app = encode_key(
            &HostKey::Named(HostNamedKey::Home),
            None,
            None,
            &no_mods(),
            modes(true, false, false),
        );
        assert_eq!(home_app.as_deref(), Some("\x1bOH"));
    }

    #[test]
    fn mode_independent_named_keys() {
        for (key, want) in [
            (HostNamedKey::Enter, "\r"),
            (HostNamedKey::Tab, "\t"),
            (HostNamedKey::Backspace, "\x7f"),
            (HostNamedKey::Escape, "\x1b"),
            (HostNamedKey::Delete, "\x1b[3~"),
            (HostNamedKey::PageUp, "\x1b[5~"),
        ] {
            let out = encode_key(
                &HostKey::Named(key),
                None,
                None,
                &no_mods(),
                modes(true, false, false),
            );
            assert_eq!(
                out.as_deref(),
                Some(want),
                "{key:?} should be mode-independent"
            );
        }
    }

    #[test]
    fn function_keys_match_xterm_sequences() {
        for (key, want) in [
            (HostNamedKey::F1, "\x1bOP"),
            (HostNamedKey::F2, "\x1bOQ"),
            (HostNamedKey::F3, "\x1bOR"),
            (HostNamedKey::F4, "\x1bOS"),
            (HostNamedKey::F5, "\x1b[15~"),
            (HostNamedKey::F10, "\x1b[21~"),
            (HostNamedKey::F12, "\x1b[24~"),
        ] {
            let out = encode_key(
                &HostKey::Named(key),
                None,
                None,
                &no_mods(),
                modes(false, false, false),
            );
            assert_eq!(out.as_deref(), Some(want), "{key:?}");
        }
    }

    #[test]
    fn modified_navigation_and_function_keys_match_xterm() {
        let ctrl = host_mods(true, false, false, false);
        let ctrl_up = encode_key(
            &HostKey::Named(HostNamedKey::ArrowUp),
            None,
            None,
            &ctrl,
            modes(true, false, false),
        );
        assert_eq!(ctrl_up.as_deref(), Some("\x1b[1;5A"));

        let shift = host_mods(false, false, true, false);
        let shift_tab = encode_key(
            &HostKey::Named(HostNamedKey::Tab),
            None,
            None,
            &shift,
            modes(false, false, false),
        );
        assert_eq!(shift_tab.as_deref(), Some("\x1b[Z"));

        let alt = host_mods(false, true, false, false);
        let alt_f5 = encode_key(
            &HostKey::Named(HostNamedKey::F5),
            None,
            None,
            &alt,
            modes(false, false, false),
        );
        assert_eq!(alt_f5.as_deref(), Some("\x1b[15;3~"));
    }

    /// Table-driven coverage of the xterm named-key contract (keyboard spec):
    /// F1–F12, Tab / Shift-Tab, Insert / Delete, and the plain/Shift/Alt/Ctrl
    /// modifier matrix on the arrows + Home/End. Every expected sequence is the
    /// literal output of the current encoder — no invented values.
    #[test]
    fn named_key_xterm_contract_table() {
        // --- Function keys, unmodified (SS3 for F1–F4, CSI ~ for F5–F12). ---
        for (named, want) in [
            (HostNamedKey::F1, "\x1bOP"),
            (HostNamedKey::F2, "\x1bOQ"),
            (HostNamedKey::F3, "\x1bOR"),
            (HostNamedKey::F4, "\x1bOS"),
            (HostNamedKey::F5, "\x1b[15~"),
            (HostNamedKey::F6, "\x1b[17~"),
            (HostNamedKey::F7, "\x1b[18~"),
            (HostNamedKey::F8, "\x1b[19~"),
            (HostNamedKey::F9, "\x1b[20~"),
            (HostNamedKey::F10, "\x1b[21~"),
            (HostNamedKey::F11, "\x1b[23~"),
            (HostNamedKey::F12, "\x1b[24~"),
        ] {
            let out = encode_named(named, false, &no_mods());
            assert_eq!(out.as_deref(), Some(want), "unmodified {named:?}");
        }

        // --- Tab and Shift-Tab (back-tab). ---
        assert_eq!(
            encode_named(HostNamedKey::Tab, false, &no_mods()).as_deref(),
            Some("\t"),
            "Tab -> \\t"
        );
        assert_eq!(
            encode_named(
                HostNamedKey::Tab,
                false,
                &host_mods(false, false, true, false)
            )
            .as_deref(),
            Some("\x1b[Z"),
            "Shift-Tab -> CSI Z"
        );

        // --- Insert / Delete (CSI 2 ~ / CSI 3 ~), mode-independent. ---
        assert_eq!(
            encode_named(HostNamedKey::Insert, false, &no_mods()).as_deref(),
            Some("\x1b[2~"),
            "Insert"
        );
        assert_eq!(
            encode_named(HostNamedKey::Delete, false, &no_mods()).as_deref(),
            Some("\x1b[3~"),
            "Delete"
        );

        // --- Modifier matrix on arrows + Home/End (app_cursor off). ---
        // Rows: (mods, xterm modifier param). plain=1, Shift=2, Alt=3, Ctrl=5.
        let plain = no_mods();
        let shift = host_mods(false, false, true, false);
        let alt = host_mods(false, true, false, false);
        let ctrl = host_mods(true, false, false, false);
        // (named, final byte)
        for (named, fin) in [
            (HostNamedKey::ArrowUp, 'A'),
            (HostNamedKey::ArrowDown, 'B'),
            (HostNamedKey::ArrowRight, 'C'),
            (HostNamedKey::ArrowLeft, 'D'),
            (HostNamedKey::Home, 'H'),
            (HostNamedKey::End, 'F'),
        ] {
            // Plain: bare CSI <final>.
            assert_eq!(
                encode_named(named, false, &plain).as_deref(),
                Some(format!("\x1b[{fin}").as_str()),
                "plain {named:?}"
            );
            // Modified: CSI 1 ; <param> <final>.
            for (m, param) in [(&shift, 2u8), (&alt, 3), (&ctrl, 5)] {
                assert_eq!(
                    encode_named(named, false, m).as_deref(),
                    Some(format!("\x1b[1;{param}{fin}").as_str()),
                    "modified {named:?} param {param}"
                );
            }
        }

        // --- Same matrix routed through encode_key (named keys are not swallowed
        //     by the Ctrl/Alt printable branches). ---
        assert_eq!(
            encode_key(
                &HostKey::Named(HostNamedKey::ArrowLeft),
                None,
                None,
                &ctrl,
                modes(false, false, false),
            )
            .as_deref(),
            Some("\x1b[1;5D"),
            "Ctrl-Left via encode_key"
        );
        assert_eq!(
            encode_key(
                &HostKey::Named(HostNamedKey::Home),
                None,
                None,
                &alt,
                modes(false, false, false),
            )
            .as_deref(),
            Some("\x1b[1;3H"),
            "Alt-Home via encode_key"
        );
    }

    #[test]
    fn alt_letter_emits_esc_prefix() {
        // macOS Option-b: `text`/logical_key carry the composed glyph `∫`, but the
        // base key (key_without_modifiers) is `b`. We must emit ESC + b, NOT `∫`.
        let m = host_mods(false, true, false, false);
        let b = encode_key(
            &HostKey::Character("∫".to_string()),
            Some("∫"),
            Some("b"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(b.as_deref(), Some("\x1bb"), "Alt-b -> ESC b");

        // Option-f: composed glyph is `ƒ`, base is `f`.
        let f = encode_key(
            &HostKey::Character("ƒ".to_string()),
            Some("ƒ"),
            Some("f"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(f.as_deref(), Some("\x1bf"), "Alt-f -> ESC f");
    }

    #[test]
    fn alt_unicode_base_emits_esc_plus_that_char() {
        // Decision: when the BASE key itself is a (single) non-ASCII printable, we
        // ESC-prefix that exact character. Meta-encoding is defined as ESC + the
        // intended key, and the intended key here is the base char, not ASCII-only.
        let m = host_mods(false, true, false, false);
        let out = encode_key(
            &HostKey::Character("é".to_string()),
            Some("é"),
            Some("é"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(out.as_deref(), Some("\x1bé"));
        assert_eq!(out.unwrap().as_bytes(), "\x1bé".as_bytes());
    }

    #[test]
    fn alt_without_base_text_does_not_guess() {
        // If winit gives us only the composed glyph and NO base text, we must NOT
        // guess a letter back from `∫`. The Alt branch falls through; the OS `text`
        // path emits the glyph as-is (prior behavior), never a fabricated ESC b.
        let m = host_mods(false, true, false, false);
        let out = encode_key(
            &HostKey::Character("∫".to_string()),
            Some("∫"),
            None,
            &m,
            modes(false, false, false),
        );
        assert_eq!(
            out.as_deref(),
            Some("∫"),
            "no base -> emit glyph, do not guess"
        );
    }

    #[test]
    fn ctrl_takes_precedence_over_alt() {
        // Ctrl-C must stay 0x03 even if Alt is also (spuriously) reported; it must
        // NOT become ESC + c. Ctrl chords are resolved before the Alt branch.
        let m = host_mods(true, true, false, false);
        let out = encode_key(
            &HostKey::Character("c".to_string()),
            Some("c"),
            Some("c"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(out.as_deref(), Some("\u{3}"), "Ctrl wins: 0x03, not ESC c");
    }

    #[test]
    fn super_takes_precedence_over_alt() {
        // Cmd held (even with Alt) still suppresses PTY input entirely.
        let m = host_mods(false, true, false, true);
        let out = encode_key(
            &HostKey::Character("∫".to_string()),
            Some("∫"),
            Some("b"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(out, None, "Super suppresses, even with Alt");
    }

    #[test]
    fn plain_text_unchanged_without_alt() {
        // No Alt: a normal letter is emitted verbatim, never ESC-prefixed.
        let out = encode_key(
            &HostKey::Character("b".to_string()),
            Some("b"),
            Some("b"),
            &no_mods(),
            modes(false, false, false),
        );
        assert_eq!(out.as_deref(), Some("b"));
    }

    #[test]
    fn paste_normal_mode_is_raw() {
        let out = encode_paste("hello\nworld", false);
        assert_eq!(out.as_deref(), Some("hello\nworld"), "normal paste is raw");
    }

    #[test]
    fn paste_bracketed_wraps_exactly_once() {
        let out = encode_paste("hi", true).unwrap();
        assert_eq!(out, "\x1b[200~hi\x1b[201~");
        // Exactly one wrapping: the markers appear once each.
        assert_eq!(out.matches("\x1b[200~").count(), 1);
        assert_eq!(out.matches("\x1b[201~").count(), 1);
    }

    #[test]
    fn paste_strips_nul_preserves_unicode_and_newlines() {
        let out = encode_paste("a\0b\nça\0", false).unwrap();
        assert_eq!(out, "ab\nça", "NUL stripped; Unicode + newline preserved");
    }

    #[test]
    fn paste_empty_or_all_nul_sends_nothing() {
        assert_eq!(encode_paste("", false), None);
        assert_eq!(
            encode_paste("\0\0", true),
            None,
            "all-NUL collapses to empty -> None"
        );
    }

    #[test]
    fn paste_bracketed_strips_embedded_terminator_injection() {
        // A hostile clipboard embeds a literal ESC[201~ to escape our wrapper.
        // After sanitizing, only the single wrapper we add may remain.
        let out = encode_paste("rm -rf /\x1b[201~malicious", true).unwrap();
        assert_eq!(
            out, "\x1b[200~rm -rf /malicious\x1b[201~",
            "embedded terminator stripped; one wrapper only"
        );
        assert_eq!(
            out.matches("\x1b[201~").count(),
            1,
            "exactly one terminator"
        );
        assert_eq!(
            out.matches("\x1b[200~").count(),
            1,
            "exactly one introducer"
        );
    }

    #[test]
    fn paste_bracketed_strips_embedded_introducer_injection() {
        let out = encode_paste("a\x1b[200~b", true).unwrap();
        assert_eq!(out, "\x1b[200~ab\x1b[201~");
        assert_eq!(out.matches("\x1b[200~").count(), 1);
    }

    #[test]
    fn paste_bracketed_strips_nested_reconstituting_terminator() {
        // A single non-overlapping replace pass is not idempotent: removing the
        // inner ESC[201~ from ESC[201<ESC[201~>~ leaves a fresh live ESC[201~.
        // The fixpoint loop must keep stripping until none remains, so the only
        // terminator the terminal sees is the one wrapper we add.
        let out = encode_paste("before\x1b[201\x1b[201~~after", true).unwrap();
        assert!(
            out.starts_with("\x1b[200~") && out.ends_with("\x1b[201~"),
            "wrapped exactly by our markers"
        );
        let inner = &out["\x1b[200~".len()..out.len() - "\x1b[201~".len()];
        assert!(
            !inner.contains("\x1b[201~"),
            "no terminator survives inside the wrapper after fixpoint strip"
        );
        assert_eq!(
            out.matches("\x1b[201~").count(),
            1,
            "exactly one terminator overall"
        );
    }

    #[test]
    fn paste_bracketed_strips_nested_reconstituting_introducer() {
        // Same reconstitution trick for the introducer ESC[200~.
        let out = encode_paste("x\x1b[200\x1b[200~~y", true).unwrap();
        assert_eq!(
            out.matches("\x1b[200~").count(),
            1,
            "only our single introducer remains"
        );
        let inner = &out["\x1b[200~".len()..out.len() - "\x1b[201~".len()];
        assert!(
            !inner.contains("\x1b[200~"),
            "no introducer survives inside the wrapper after fixpoint strip"
        );
    }

    #[test]
    fn paste_normal_mode_does_not_strip_markers() {
        // Outside bracketed mode there is no wrapper to protect, so leave the
        // bytes verbatim — stripping would corrupt legitimate content.
        let out = encode_paste("x\x1b[201~y", false).unwrap();
        assert_eq!(out, "x\x1b[201~y");
    }

    #[test]
    fn paste_caps_oversized_payload_on_char_boundary() {
        // Multi-byte chars so truncation must land on a boundary, never split.
        let big = "é".repeat(MAX_PASTE_BYTES); // 2 bytes each -> 2x the cap
        let out = encode_paste(&big, false).unwrap();
        assert!(out.len() <= MAX_PASTE_BYTES, "truncated to the cap");
        assert!(out.chars().all(|c| c == 'é'), "no split/replacement chars");
    }

    #[test]
    fn paste_payload_reads_clipboard_once_and_wraps() {
        let mut cb = FakeClipboard(Some("x".into()));
        let out = paste_payload(&mut cb, modes(false, true, false));
        assert_eq!(out.as_deref(), Some("\x1b[200~x\x1b[201~"));
    }

    #[test]
    fn paste_payload_unavailable_clipboard_sends_nothing() {
        let mut cb = FakeClipboard(None);
        assert_eq!(paste_payload(&mut cb, modes(false, true, false)), None);
    }

    #[test]
    fn focus_only_when_reporting_enabled() {
        // Disabled: nothing on either transition.
        assert_eq!(encode_focus(true, modes(false, false, false)), None);
        assert_eq!(encode_focus(false, modes(false, false, false)), None);
        // Enabled: in/out sequences.
        assert_eq!(
            encode_focus(true, modes(false, false, true)).as_deref(),
            Some("\x1b[I")
        );
        assert_eq!(
            encode_focus(false, modes(false, false, true)).as_deref(),
            Some("\x1b[O")
        );
    }

    #[test]
    fn tiny_window_clamps_to_one_by_one() {
        // A 1px window with sane cell metrics must never claim a 0 dimension.
        let (cols, rows) = compute_dims(1.0, 1.0, 9.0, 20.0);
        assert_eq!((cols, rows), (1, 1));
    }

    #[test]
    fn degenerate_cell_metrics_clamp_to_one_by_one() {
        // Renderer not ready (zero cell size) -> minimum viable grid, not a divide.
        assert_eq!(compute_dims(800.0, 600.0, 0.0, 0.0), (1, 1));
    }

    #[test]
    fn fractional_dpi_computes_consistent_integers() {
        // Logical cell 9x20 at scale 1.5 -> physical cell 13.5x30. An 1080x720
        // physical window: cols = floor(1080/13.5)=80; rows = floor((720-30)/30)=23.
        let scale = 1.5_f32;
        let (cw, ch) = (9.0 * scale, 20.0 * scale);
        let (cols, rows) = compute_dims(1080.0, 720.0, cw, ch);
        assert_eq!((cols, rows), (80, 23));
    }

    #[test]
    fn dims_clamp_to_max_dimension() {
        // An absurdly large window must not claim past the daemon's cap.
        let (cols, rows) = compute_dims(1_000_000.0, 1_000_000.0, 1.0, 1.0);
        assert_eq!(cols, MAX_DIMENSION);
        assert_eq!(rows, MAX_DIMENSION);
    }

    #[test]
    fn overlay_row_is_reserved() {
        // With an exact integer number of cells, the overlay steals exactly one row.
        // cell 10x10, window 100x100 phys: cols=10; rows=floor((100-10)/10)=9.
        let (cols, rows) = compute_dims(100.0, 100.0, 10.0, 10.0);
        assert_eq!((cols, rows), (10, 9));
    }

    #[test]
    fn compute_dims_one_row_matches_chrome_rows_one() {
        // The public one-row path must equal the generalized helper with chrome_rows = 1.
        for (w, h, cw, ch) in [
            (100.0, 100.0, 10.0, 10.0),
            (800.0, 600.0, 9.0, 20.0),
            (1080.0, 720.0, 8.5, 17.0),
        ] {
            assert_eq!(
                compute_dims(w, h, cw, ch),
                compute_dims_with_chrome_rows(w, h, cw, ch, 1),
            );
        }
    }

    #[test]
    fn more_chrome_rows_reserve_more_terminal_rows() {
        // cell 10x10, window 100x100: 1 row -> 9 terminal rows; 3 rows -> 7 terminal rows.
        let (_, rows1) = compute_dims_with_chrome_rows(100.0, 100.0, 10.0, 10.0, 1);
        let (_, rows3) = compute_dims_with_chrome_rows(100.0, 100.0, 10.0, 10.0, 3);
        assert_eq!(rows1, 9);
        assert_eq!(rows3, 7);
        assert!(rows3 < rows1);
    }

    #[test]
    fn chrome_rows_still_clamp_to_at_least_one_row() {
        // A tiny window with several reserved chrome rows still leaves at least one terminal row.
        let (cols, rows) = compute_dims_with_chrome_rows(10.0, 10.0, 10.0, 10.0, 5);
        assert!(cols >= 1);
        assert_eq!(rows, 1, "terminal must keep at least one row");
    }

    #[test]
    fn chrome_rows_clamp_to_max_dimension() {
        // Huge window: rows clamp to MAX_DIMENSION regardless of chrome rows reserved.
        let (cols, rows) = compute_dims_with_chrome_rows(1_000_000.0, 1_000_000.0, 1.0, 1.0, 4);
        assert_eq!(cols, MAX_DIMENSION);
        assert_eq!(rows, MAX_DIMENSION);
    }

    #[test]
    fn chrome_rows_bad_dimensions_are_degenerate() {
        // Non-positive cell metrics produce the (1, 1) degenerate result for any chrome_rows.
        assert_eq!(
            compute_dims_with_chrome_rows(800.0, 600.0, 0.0, 0.0, 2),
            (1, 1)
        );
    }

    #[test]
    fn resize_burst_coalesces_to_latest() {
        let mut c = ResizeCoalescer::default();
        let t0 = Instant::now();
        let interval = Duration::from_millis(33);
        // First geometry sends immediately (no prior send).
        assert_eq!(c.record((80, 24), t0, interval), Some((80, 24)));
        // A burst of intermediates within the interval: none send; latest pends.
        assert_eq!(
            c.record((81, 24), t0 + Duration::from_millis(5), interval),
            None
        );
        assert_eq!(
            c.record((82, 25), t0 + Duration::from_millis(10), interval),
            None
        );
        assert_eq!(
            c.record((83, 26), t0 + Duration::from_millis(15), interval),
            None
        );
        assert!(
            c.has_pending(),
            "latest geometry waits for the trailing flush"
        );
        // After the interval elapses, the trailing flush sends only the LATEST.
        assert_eq!(
            c.flush(t0 + Duration::from_millis(40), interval),
            Some((83, 26))
        );
        assert!(!c.has_pending());
    }

    #[test]
    fn resize_trailing_send_flushes_settled_geometry() {
        let mut c = ResizeCoalescer::default();
        let t0 = Instant::now();
        let interval = Duration::from_millis(33);
        assert_eq!(c.record((80, 24), t0, interval), Some((80, 24)));
        // Drag settles at (90, 30) just after the first send; under interval -> pends.
        assert_eq!(
            c.record((90, 30), t0 + Duration::from_millis(2), interval),
            None
        );
        // Even much later, exactly one trailing send delivers the settled size.
        assert_eq!(
            c.flush(t0 + Duration::from_secs(1), interval),
            Some((90, 30))
        );
        // A second flush with nothing new is a no-op.
        assert_eq!(c.flush(t0 + Duration::from_secs(2), interval), None);
    }

    #[test]
    fn resize_dedups_unchanged_geometry() {
        let mut c = ResizeCoalescer::default();
        let t0 = Instant::now();
        let interval = Duration::from_millis(33);
        assert_eq!(c.record((80, 24), t0, interval), Some((80, 24)));
        // Re-recording the same size well after the interval sends NOTHING.
        assert_eq!(
            c.record((80, 24), t0 + Duration::from_secs(1), interval),
            None
        );
        assert!(!c.has_pending());
    }

    #[test]
    fn resize_invalidate_last_sent_re_emits_same_window_size() {
        // When the split geometry changes at the SAME window size, the renderer invalidates the last-sent
        // value so the active session is re-sized to its new pane region. After invalidate, re-recording
        // the same window dims sends again (instead of being deduped to None).
        let mut c = ResizeCoalescer::default();
        let t0 = Instant::now();
        let interval = Duration::from_millis(33);
        assert_eq!(c.record((80, 24), t0, interval), Some((80, 24)));
        // Without invalidation the same size would dedup to None (see resize_dedups_unchanged_geometry).
        c.invalidate_last_sent();
        assert_eq!(
            c.record((80, 24), t0 + Duration::from_secs(1), interval),
            Some((80, 24)),
            "after invalidate, the same window size re-emits so the active pane resizes"
        );
        // The rate limit still applies: a same-size record within the interval pends rather than sending.
        c.invalidate_last_sent();
        assert_eq!(
            c.record(
                (80, 24),
                t0 + Duration::from_secs(1) + Duration::from_millis(5),
                interval
            ),
            None
        );
        assert!(c.has_pending());
    }

    // ---- Outbound queue (#55) ----

    #[test]
    fn outbound_preserves_strict_fifo_order() {
        let q = OutboundQueue::new();
        for i in 0..5u8 {
            assert_eq!(q.try_enqueue(vec![i]), TryEnqueueOutcome::Admitted);
        }
        for i in 0..5u8 {
            assert_eq!(
                q.dequeue().map(|(frame, _)| frame),
                Some(vec![i]),
                "FIFO order must be preserved"
            );
        }
    }

    #[test]
    fn outbound_full_refuses_promptly_then_admits_after_drain_wake() {
        // Owner/reader producers never wait. A queue at capacity returns typed Full and arms the
        // next dequeue wake; the caller retains its batch and retries after that transition.
        let q = OutboundQueue::new();
        // Fill to just under the cap with one big item, plus one more that fits.
        let big = vec![0u8; OUTBOUND_CAP_BYTES - 1];
        assert_eq!(q.try_enqueue(big), TryEnqueueOutcome::Admitted);
        assert_eq!(q.try_enqueue(vec![1u8]), TryEnqueueOutcome::Admitted);
        assert_eq!(q.try_enqueue(vec![2u8, 3u8]), TryEnqueueOutcome::Full);

        let (first, wake) = q.dequeue().expect("writer drains first frame");
        assert_eq!(first.len(), OUTBOUND_CAP_BYTES - 1);
        assert!(wake, "the capacity transition wakes the retained producer");
        assert_eq!(q.try_enqueue(vec![2u8, 3u8]), TryEnqueueOutcome::Admitted);
        assert_eq!(q.dequeue().map(|(frame, _)| frame), Some(vec![1u8]));
        assert_eq!(q.dequeue().map(|(frame, _)| frame), Some(vec![2u8, 3u8]));
    }

    #[test]
    fn outbound_rejects_oversized_item_even_when_empty() {
        let q = OutboundQueue::new();
        let huge = vec![7u8; OUTBOUND_CAP_BYTES + 4096];
        assert_eq!(
            q.try_enqueue(huge),
            TryEnqueueOutcome::TooLarge,
            "the documented 1MiB limit is a hard cap"
        );
        assert_eq!(q.len(), 0, "TooLarge admission is all-or-none");
    }

    #[test]
    fn outbound_close_aborts_buffered_frames_and_refuses_later_admission() {
        let q = OutboundQueue::new();
        assert_eq!(q.try_enqueue(vec![1u8]), TryEnqueueOutcome::Admitted);
        assert_eq!(q.try_enqueue(vec![2u8]), TryEnqueueOutcome::Admitted);
        q.close();
        assert_eq!(
            q.len(),
            0,
            "fail-closed teardown discards queued secret writes"
        );
        assert_eq!(
            q.dequeue(),
            None,
            "closed queue exits without draining frames"
        );
        assert_eq!(q.try_enqueue(vec![3u8]), TryEnqueueOutcome::Closed);
    }

    #[test]
    fn outbound_mutex_contention_is_fail_fast_and_requests_immediate_retry() {
        let q = OutboundQueue::new();
        let guard = q.inner.lock().unwrap();
        assert_eq!(
            q.try_enqueue(vec![1u8]),
            TryEnqueueOutcome::Contended { wake_now: true }
        );
        drop(guard);
        assert_eq!(q.len(), 0);
    }

    // ---- P2: selection hit-test + extraction + copy/interrupt ----

    fn sel_cell(text: &str, width: u8) -> Cell {
        Cell {
            text: text.to_string(),
            fg: crate::wire::Color::Named {
                name: crate::wire::NamedColor::Foreground,
            },
            bg: crate::wire::Color::Named {
                name: crate::wire::NamedColor::Background,
            },
            bold: false,
            italic: false,
            underline: Default::default(),
            inverse: false,
            strikeout: false,
            dim: false,
            hidden: false,
            hyperlink: None,
            width,
        }
    }

    /// Build a row from a string, padding with blank cells to `cols`.
    fn sel_row(text: &str, cols: usize) -> Vec<Cell> {
        let mut r: Vec<Cell> = text.chars().map(|c| sel_cell(&c.to_string(), 1)).collect();
        while r.len() < cols {
            r.push(sel_cell(" ", 1));
        }
        r.truncate(cols);
        r
    }

    #[test]
    fn pixel_to_cell_maps_and_clamps() {
        // 10x20 px cells, 8 cols x 4 rows.
        assert_eq!(
            pixel_to_cell(0.0, 0.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 0, row: 0 })
        );
        assert_eq!(
            pixel_to_cell(25.0, 41.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 2, row: 2 })
        );
        // Far beyond the grid clamps to the last cell, never out of bounds.
        assert_eq!(
            pixel_to_cell(9999.0, 9999.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 7, row: 3 })
        );
        // Negative-ish (left/above) clamps to origin.
        assert_eq!(
            pixel_to_cell(-5.0, -5.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 0, row: 0 })
        );
    }

    #[test]
    fn pixel_to_cell_rejects_degenerate() {
        assert_eq!(pixel_to_cell(5.0, 5.0, 0.0, 20.0, 8, 4), None);
        assert_eq!(pixel_to_cell(5.0, 5.0, 10.0, 20.0, 0, 4), None);
        assert_eq!(pixel_to_cell(5.0, 5.0, 10.0, 20.0, 8, 0), None);
    }

    #[test]
    fn top_offset_zero_equals_plain_pixel_to_cell() {
        // With no left/top chrome offsets the translated helper is exactly pixel_to_cell.
        for (x, y) in [(0.0, 0.0), (25.0, 41.0), (9999.0, 9999.0), (-5.0, -5.0)] {
            assert_eq!(
                pixel_to_cell_with_top_offset(x, y, 0.0, 0.0, 10.0, 20.0, 8, 4),
                pixel_to_cell(x, y, 10.0, 20.0, 8, 4),
            );
        }
    }

    #[test]
    fn top_offset_first_row_below_bar_is_row_zero() {
        // 20px top band, 10x20 cells. A pixel exactly at the band bottom maps to grid row 0;
        // one cell-row lower maps to row 1.
        assert_eq!(
            pixel_to_cell_with_top_offset(5.0, 20.0, 0.0, 20.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 0, row: 0 })
        );
        assert_eq!(
            pixel_to_cell_with_top_offset(5.0, 40.0, 0.0, 20.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 0, row: 1 })
        );
    }

    #[test]
    fn top_offset_inside_band_returns_none() {
        // A pixel inside the reserved top band is renderer chrome, NOT a grid cell: None,
        // never clamped to grid row 0 (which would leak the click into selection/PTY reporting).
        assert_eq!(
            pixel_to_cell_with_top_offset(5.0, 0.0, 0.0, 20.0, 10.0, 20.0, 8, 4),
            None
        );
        assert_eq!(
            pixel_to_cell_with_top_offset(5.0, 19.9, 0.0, 20.0, 10.0, 20.0, 8, 4),
            None
        );
    }

    #[test]
    fn left_offset_first_col_past_dock_is_col_zero() {
        // 30px left dock, 10x20 cells. A pixel exactly at the dock's right edge maps to grid col 0;
        // one cell-col further right maps to col 1. (top_offset 0 so y maps straight.)
        assert_eq!(
            pixel_to_cell_with_top_offset(30.0, 5.0, 30.0, 0.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 0, row: 0 })
        );
        assert_eq!(
            pixel_to_cell_with_top_offset(40.0, 5.0, 30.0, 0.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 1, row: 0 })
        );
    }

    #[test]
    fn left_offset_inside_dock_returns_none() {
        // A pixel inside the reserved left dock is renderer chrome, NOT a grid cell: None, never
        // clamped to grid col 0 (which would leak the click into selection/PTY reporting).
        assert_eq!(
            pixel_to_cell_with_top_offset(0.0, 5.0, 30.0, 0.0, 10.0, 20.0, 8, 4),
            None
        );
        assert_eq!(
            pixel_to_cell_with_top_offset(29.9, 5.0, 30.0, 0.0, 10.0, 20.0, 8, 4),
            None
        );
    }

    #[test]
    fn extract_row_copy_soft_hard_unknown_and_invalid_metadata() {
        use maestro_protocol::row_copy::RowCopy;
        let rows = vec![sel_row("ab  ", 4), sel_row("x", 4)];
        let mut grid = scrollback_snapshot(
            SessionGeneration("copy-fixture".into()),
            Revision(1),
            (rows, None),
        );
        let start = CellPos { row: 0, col: 0 };
        let end = CellPos { row: 1, col: 0 };
        assert_eq!(extract_grid_selection(&grid, start, end), "ab\nx");
        grid.row_copy = Some(vec![
            RowCopy {
                starts_line: None,
                soft_wrap: true,
                excluded_columns: vec![],
            },
            RowCopy {
                starts_line: Some(false),
                soft_wrap: false,
                excluded_columns: vec![],
            },
        ]);
        assert_eq!(extract_grid_selection(&grid, start, end), "ab  x");
        assert_eq!(extract_grid_selection(&grid, end, start), "ab  x");
        assert_eq!(
            extract_grid_selection(&grid, start, CellPos { row: 0, col: 3 }),
            "ab  "
        );
        grid.row_copy.as_mut().unwrap()[1].starts_line = None;
        assert_eq!(extract_grid_selection(&grid, start, end), "ab\nx");
        grid.row_copy.as_mut().unwrap()[1].starts_line = Some(true);
        assert_eq!(extract_grid_selection(&grid, start, end), "ab\nx");
        grid.row_copy.as_mut().unwrap()[1].starts_line = Some(false);
        grid.row_copy.as_mut().unwrap()[0].excluded_columns = vec![0];
        assert_eq!(extract_grid_selection(&grid, start, end), "ab\nx");
        grid.row_copy.as_mut().unwrap()[0].excluded_columns = vec![2, 3];
        assert_eq!(extract_grid_selection(&grid, start, end), "abx");
        grid.cols = 5;
        assert_eq!(extract_grid_selection(&grid, start, end), "ab\nx");
    }

    #[test]
    fn extract_row_copy_preserves_partial_spaces_unicode_and_intersected_graphemes() {
        assert_eq!(
            extract_selection(
                &[sel_row("", 4)],
                CellPos { row: 0, col: 0 },
                CellPos { row: 0, col: 2 }
            ),
            ""
        );
        assert_eq!(
            extract_selection(
                &[sel_row("", 4), sel_row("", 4)],
                CellPos { row: 0, col: 0 },
                CellPos { row: 1, col: 3 }
            ),
            "\n"
        );
        assert_eq!(
            extract_selection(
                &[vec![sel_cell("\u{a0}", 1)]],
                CellPos { row: 0, col: 0 },
                CellPos { row: 0, col: 0 }
            ),
            "\u{a0}"
        );
        let rows = vec![sel_row("ab  ", 4)];
        assert_eq!(
            extract_selection(
                &rows,
                CellPos { row: 0, col: 1 },
                CellPos { row: 0, col: 2 }
            ),
            "b "
        );
        assert_eq!(
            extract_selection(
                &rows,
                CellPos { row: 0, col: 0 },
                CellPos { row: 0, col: 3 }
            ),
            "ab"
        );
        let rows = vec![vec![
            sel_cell("e\u{301}", 1),
            sel_cell("👩‍💻", 2),
            sel_cell("", 0),
            sel_cell("\u{a0}", 1),
        ]];
        assert_eq!(
            extract_selection(
                &rows,
                CellPos { row: 0, col: 2 },
                CellPos { row: 0, col: 2 }
            ),
            "👩‍💻"
        );
        assert_eq!(
            extract_selection(
                &rows,
                CellPos { row: 0, col: 2 },
                CellPos { row: 0, col: 1 }
            ),
            "👩‍💻"
        );
        assert_eq!(
            extract_selection(
                &rows,
                CellPos { row: 0, col: 0 },
                CellPos { row: 0, col: 3 }
            ),
            "e\u{301}👩‍💻\u{a0}"
        );
        let mut hidden = sel_cell("unchanged", 1);
        hidden.hidden = true;
        assert_eq!(
            extract_selection(
                &[vec![hidden]],
                CellPos { row: 0, col: 0 },
                CellPos { row: 0, col: 0 }
            ),
            "unchanged"
        );
    }

    #[test]
    fn extract_single_row_selection() {
        let grid = vec![sel_row("hello world", 11)];
        // cols 0..=4 = "hello".
        let out = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 4, row: 0 },
        );
        assert_eq!(out, "hello");
    }

    #[test]
    fn extract_selection_order_independent() {
        let grid = vec![sel_row("hello world", 11)];
        let a = extract_selection(
            &grid,
            CellPos { col: 4, row: 0 },
            CellPos { col: 0, row: 0 },
        );
        assert_eq!(a, "hello", "reversed anchor/focus yields same text");
    }

    #[test]
    fn extract_multi_row_joins_with_newline_and_trims() {
        // Row 0 trailing blanks, row 1 short. Multi-row: row0 from col2 to end,
        // row1 from start to col2.
        let grid = vec![sel_row("ab    ", 6), sel_row("xyz", 6)];
        let out = extract_selection(
            &grid,
            CellPos { col: 2, row: 0 },
            CellPos { col: 2, row: 1 },
        );
        // Row0 col2.. is all blanks -> trimmed to ""; row1 col0..=2 = "xyz".
        assert_eq!(out, "\nxyz");
    }

    #[test]
    fn extract_skips_wide_spacers_keeps_wide_lead() {
        // A wide glyph occupies a lead cell (width 2) + a spacer (width 0).
        let mut row = vec![sel_cell("a", 1), sel_cell("世", 2), sel_cell("", 0)];
        row.push(sel_cell("b", 1));
        let grid = vec![row];
        let out = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 3, row: 0 },
        );
        assert_eq!(
            out, "a世b",
            "spacer skipped, wide lead glyph preserved once"
        );
    }

    #[test]
    fn extract_clamps_out_of_range_coords() {
        let grid = vec![sel_row("abc", 3)];
        // Focus row/col beyond bounds clamps to the grid.
        let out = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 99, row: 99 },
        );
        assert_eq!(out, "abc");
    }

    #[test]
    fn extract_empty_grid_is_empty() {
        let grid: Vec<Vec<Cell>> = Vec::new();
        let out = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 0, row: 0 },
        );
        assert_eq!(out, "");
    }

    #[test]
    fn copy_writes_extracted_selection_to_clipboard() {
        // Simulate the copy flow: extract from the painted grid, write to clipboard.
        let grid = vec![sel_row("copy me", 7)];
        let text = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 3, row: 0 },
        );
        let mut cb = FakeClipboard(None);
        assert!(cb.write_text(text));
        assert_eq!(cb.read_text().as_deref(), Some("copy"));
    }

    #[test]
    fn empty_selection_text_not_written() {
        // An all-blank selection extracts to "" — the copy path must not write it.
        let grid = vec![sel_row("       ", 7)];
        let text = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 6, row: 0 },
        );
        assert_eq!(text, "");
        // Caller guards on is_empty(); clipboard stays untouched.
        let mut cb = FakeClipboard(Some("prev".into()));
        if !text.is_empty() {
            cb.write_text(text);
        }
        assert_eq!(cb.read_text().as_deref(), Some("prev"));
    }

    #[test]
    fn ctrl_c_still_emits_interrupt_not_copy() {
        // Ctrl-C (no Super, no Shift) must encode the 0x03 interrupt — it is NOT the
        // copy chord (Cmd-C / Ctrl-Shift-C), which is intercepted before encoding.
        let m = host_mods(true, false, false, false);
        let out = encode_key(
            &HostKey::Character("c".to_string()),
            Some("c"),
            Some("c"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(out, Some("\u{03}".to_string()), "Ctrl-C -> 0x03");
    }

    // ---- mouse reporting (TUI) ----

    #[test]
    fn mouse_no_report_when_no_mode_active() {
        // With no mouse mode negotiated, every event encodes to nothing.
        let off = mouse_modes(false, false, false, false);
        for ev in [
            MouseEvent::Press(MouseButton::Left),
            MouseEvent::Release(MouseButton::Left),
            MouseEvent::Move { held: None },
            MouseEvent::WheelUp,
        ] {
            assert_eq!(encode_mouse(ev, 0, 0, off, false, false, false), None);
        }
    }

    #[test]
    fn mouse_sgr_press_and_release_left() {
        // SGR (1006), click reporting (1000). Left press at cell (0,0) -> 1-based (1,1),
        // button 0, `M`. Release -> same coords, `m`.
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                0,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<0;1;1M".to_string())
        );
        assert_eq!(
            encode_mouse(
                MouseEvent::Release(MouseButton::Left),
                0,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<0;1;1m".to_string())
        );
    }

    #[test]
    fn mouse_sgr_right_and_middle_button_codes() {
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Middle),
                4,
                2,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<1;5;3M".to_string())
        );
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Right),
                4,
                2,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<2;5;3M".to_string())
        );
    }

    #[test]
    fn mouse_sgr_modifier_bits() {
        // shift=4, alt=8, ctrl=16 added to the button code. Left(0) + all three = 28.
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                0,
                0,
                m,
                true,
                true,
                true
            ),
            Some("\x1b[<28;1;1M".to_string())
        );
    }

    #[test]
    fn mouse_sgr_wheel_up_down() {
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(MouseEvent::WheelUp, 0, 0, m, false, false, false),
            Some("\x1b[<64;1;1M".to_string())
        );
        assert_eq!(
            encode_mouse(MouseEvent::WheelDown, 0, 0, m, false, false, false),
            Some("\x1b[<65;1;1M".to_string())
        );
    }

    #[test]
    fn mouse_click_mode_does_not_report_motion() {
        // Click-only (1000) reports press/release but never motion (needs 1002/1003).
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Move {
                    held: Some(MouseButton::Left)
                },
                1,
                1,
                m,
                false,
                false,
                false
            ),
            None
        );
        assert_eq!(
            encode_mouse(
                MouseEvent::Move { held: None },
                1,
                1,
                m,
                false,
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn mouse_drag_mode_reports_held_motion_only() {
        // Button-drag (1002): motion WITH a button held is reported (button + motion bit
        // 32); no-button motion is not.
        let m = mouse_modes(true, true, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Move {
                    held: Some(MouseButton::Left)
                },
                2,
                3,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<32;3;4M".to_string())
        );
        assert_eq!(
            encode_mouse(
                MouseEvent::Move { held: None },
                2,
                3,
                m,
                false,
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn mouse_any_motion_reports_no_button_move() {
        // Any-motion (1003): no-button motion reports button 3 + motion bit 32 = 35.
        let m = mouse_modes(true, true, true, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Move { held: None },
                0,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<35;1;1M".to_string())
        );
    }

    #[test]
    fn mouse_legacy_x10_byte_triple() {
        // Legacy (no SGR): `\x1b[M` + (cb+32, x+32, y+32). Left press at (0,0) ->
        // bytes 32, 33, 33 = space, '!', '!'.
        let m = mouse_modes(true, false, false, false);
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                0,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[M\x20\x21\x21".to_string())
        );
    }

    #[test]
    fn mouse_legacy_release_is_button_three() {
        // Legacy release uses button 3 (low 2 bits): cb = 3, byte = 35 = '#'.
        let m = mouse_modes(true, false, false, false);
        assert_eq!(
            encode_mouse(
                MouseEvent::Release(MouseButton::Left),
                0,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[M\x23\x21\x21".to_string())
        );
    }

    #[test]
    fn mouse_legacy_drops_coords_beyond_ascii_safe_range() {
        // Cells past 95 would push a byte >= 128, which UTF-8 would split into two wire
        // bytes and corrupt the report — so legacy mode drops them.
        let m = mouse_modes(true, false, false, false);
        // col 95 -> x=96 -> byte 128: dropped.
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                95,
                0,
                m,
                false,
                false,
                false
            ),
            None
        );
        // col 94 -> x=95 -> byte 127: still emitted (boundary).
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                94,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[M\x20\x7f\x21".to_string())
        );
    }

    #[test]
    fn mouse_sgr_handles_large_coords() {
        // SGR is ASCII decimal, so it has no 223/95-cell ceiling — large coords are fine.
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                499,
                199,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<0;500;200M".to_string())
        );
    }

    #[test]
    fn mouse_legacy_sequences_are_single_byte_ascii() {
        // Every byte of a legacy report must be < 128 so it round-trips as ONE byte
        // through the UTF-8 Write channel (the daemon does `data.into_bytes()`).
        let m = mouse_modes(true, true, false, false);
        let s = encode_mouse(
            MouseEvent::Move {
                held: Some(MouseButton::Right),
            },
            94,
            94,
            m,
            true,
            true,
            true,
        )
        .expect("boundary coords still encode");
        assert!(s.is_ascii(), "legacy report must be ASCII, got {s:?}");
        assert_eq!(s.len(), s.chars().count(), "one byte per char");
    }
}

#[cfg(test)]
mod scrollback_view_tests {
    use super::*;

    // --- fixtures -----------------------------------------------------------

    fn color() -> crate::wire::Color {
        crate::wire::Color::Named {
            name: crate::wire::NamedColor::Foreground,
        }
    }

    fn cell(text: &str) -> Cell {
        Cell {
            text: text.to_string(),
            fg: color(),
            bg: color(),
            bold: false,
            italic: false,
            underline: Default::default(),
            inverse: false,
            strikeout: false,
            dim: false,
            hidden: false,
            hyperlink: None,
            width: 1,
        }
    }

    fn row(text: &str, cols: usize) -> Vec<Cell> {
        let mut r: Vec<Cell> = text.chars().map(|c| cell(&c.to_string())).collect();
        while r.len() < cols {
            r.push(cell(" "));
        }
        r.truncate(cols);
        r
    }

    fn live_grid(gen: &str, cols: usize, rows: usize, alt: bool) -> GridSnapshot {
        let rows_cells: Vec<Vec<Cell>> =
            (0..rows).map(|i| row(&format!("live{i}"), cols)).collect();
        GridSnapshot {
            row_copy: None,
            version: crate::sync::SUPPORTED_VERSION,
            generation: SessionGeneration(gen.to_string()),
            revision: Revision(100),
            base_revision: Revision(100),
            cols,
            rows,
            rows_cells,
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
            alt_screen: alt,
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_report: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_sgr: false,
        }
    }

    /// A `Shared` whose live grid is set to `gen`, with an installed test queue so
    /// any `send_request` is observable. Returns the shared state.
    fn shared_with_live(gen: &str, cols: usize, rows: usize) -> Arc<Shared> {
        let (shared, _q) = Shared::with_test_queue();
        shared
            .init_active_session("my-session")
            .expect("fixture installs exact active authority");
        *shared.grid.lock().unwrap() = Some(Arc::new(live_grid(gen, cols, rows, false)));
        shared
    }

    fn hist_rows(cols: usize, rows: usize) -> Vec<Vec<Cell>> {
        (0..rows).map(|i| row(&format!("hist{i}"), cols)).collect()
    }

    fn admit_scrollback_reply(shared: &Arc<Shared>, offset: u32, expected_generation: &str) {
        let mut scrollback = shared.scrollback.lock().unwrap();
        let intent = scrollback
            .advance_intent()
            .expect("test scroll intent remains representable");
        scrollback.view_offset = offset;
        scrollback.admitted_request = Some((
            intent,
            offset,
            SessionGeneration(expected_generation.to_string()),
        ));
    }

    // --- 1: view_offset clamps to [0, history_len] --------------------------

    #[test]
    fn view_offset_clamps_to_zero_history_len_range() {
        // Known length: below zero clamps to 0; above history clamps to history_len.
        assert_eq!(clamp_view_offset(-5, Some(40), 6), 0);
        assert_eq!(clamp_view_offset(0, Some(40), 6), 0);
        assert_eq!(clamp_view_offset(40, Some(40), 6), 40);
        assert_eq!(clamp_view_offset(999, Some(40), 6), 40);
        // Below the cached ceiling, next_view_offset still clamps to the known range.
        assert_eq!(
            next_view_offset(0, Some(40), 6, ScrollAction::Lines(-10)),
            0
        );
        assert_eq!(
            next_view_offset(38, Some(40), 6, ScrollAction::Lines(10)),
            40
        );
    }

    // --- 2: wheel up moves up into history (would send a request) ------------

    #[test]
    fn wheel_up_moves_offset_into_history() {
        // From the live bottom, scrolling up by 3 lines lands at offset 3 (history is
        // deep enough), which is the offset the renderer would request from the daemon.
        let new = next_view_offset(0, Some(100), 6, ScrollAction::Lines(3));
        assert_eq!(new, 3, "wheel up enters scrollback at the moved-to offset");
        assert!(new > 0, "a positive offset triggers a Scrollback request");
    }

    // --- 3: wheel down toward zero returns to live --------------------------

    #[test]
    fn wheel_down_to_zero_returns_to_live() {
        // Scrolled up at 2; a downward wheel of 5 clamps to 0 = live bottom.
        let new = next_view_offset(2, Some(100), 6, ScrollAction::Lines(-5));
        assert_eq!(new, 0, "wheel down past bottom returns to live (offset 0)");
    }

    // --- 4: PageUp/PageDown/Home/End adjust offset --------------------------

    #[test]
    fn page_and_home_end_adjust_offset() {
        let page = 6;
        let h = Some(100);
        // PageUp from bottom moves up one page.
        assert_eq!(next_view_offset(0, h, page, ScrollAction::PageUp), 6);
        // PageDown from 6 returns to live.
        assert_eq!(next_view_offset(6, h, page, ScrollAction::PageDown), 0);
        // PageDown cannot go negative.
        assert_eq!(next_view_offset(3, h, page, ScrollAction::PageDown), 0);
        // Home jumps to the oldest history.
        assert_eq!(next_view_offset(6, h, page, ScrollAction::Home), 100);
        // End jumps to the live bottom.
        assert_eq!(next_view_offset(50, h, page, ScrollAction::End), 0);
    }

    // --- 4a: selection invalidation predicate on scroll --------------------
    // `apply_scroll` clears the selection iff the viewport actually moves, i.e.
    // `next_view_offset(...) != cur`. The no-op early-return (offset unchanged)
    // runs BEFORE either clear site, so an unchanged viewport keeps the
    // selection. These tests pin that decision without needing a window.

    #[test]
    fn scroll_that_moves_viewport_changes_offset_and_clears() {
        let page = 6;
        let h = Some(100);
        // A moving wheel scroll up: offset changes -> selection cleared.
        let cur = 0;
        let next = next_view_offset(cur, h, page, ScrollAction::Lines(3));
        assert_ne!(next, cur, "moving scroll changes the offset -> clear");
        // PageUp from the bottom also moves.
        assert_ne!(next_view_offset(0, h, page, ScrollAction::PageUp), 0);
        // End from a scrolled position returns to live (still a change).
        assert_ne!(next_view_offset(50, h, page, ScrollAction::End), 50);
    }

    #[test]
    fn downward_no_op_keeps_selection_but_upward_at_cached_ceiling_reprobes() {
        let page = 6;
        let h = Some(40);
        // At the live bottom, scrolling DOWN / PageDown / End is a no-op.
        assert_eq!(next_view_offset(0, h, page, ScrollAction::Lines(-5)), 0);
        assert_eq!(next_view_offset(0, h, page, ScrollAction::PageDown), 0);
        assert_eq!(next_view_offset(0, h, page, ScrollAction::End), 0);
        // The cached upper bound is only a point-in-time daemon reply. An explicit upward
        // gesture at it moves provisionally (bounded to one page) so a fresh Scrollback
        // request can discover history produced since that reply.
        assert_eq!(next_view_offset(40, h, page, ScrollAction::PageUp), 46);
        assert_eq!(next_view_offset(40, h, page, ScrollAction::Home), 46);
        assert_eq!(next_view_offset(40, h, page, ScrollAction::Lines(10)), 46);
    }

    // --- 4b: PageUp/PageDown/Home/End consume policy (TUI-aware) ------------

    #[test]
    fn alt_screen_passes_all_nav_keys_to_pty() {
        // On the alternate screen every nav key returns None (-> PTY), regardless of
        // scrolled state (which is forced live on alt-screen anyway).
        for key in [
            ScrollKey::PageUp,
            ScrollKey::PageDown,
            ScrollKey::Home,
            ScrollKey::End,
        ] {
            assert_eq!(
                scroll_key_action_for(key, true, false, false),
                None,
                "{key:?} must reach the PTY on alt-screen"
            );
        }
    }

    #[test]
    fn live_bottom_only_pageup_enters_scrollback() {
        // Normal screen, at the live bottom (not scrolled): PageUp enters scrollback;
        // PageDown/Home/End have nothing above to scroll into -> PTY.
        assert_eq!(
            scroll_key_action_for(ScrollKey::PageUp, false, false, false),
            Some(ScrollAction::PageUp)
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::PageDown, false, false, false),
            None,
            "PageDown at the live bottom belongs to the PTY (pager)"
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::Home, false, false, false),
            None
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::End, false, false, false),
            None
        );
    }

    #[test]
    fn scrolled_up_all_nav_keys_control_scrollback() {
        // Normal screen, already scrolled up: all four drive the renderer viewport.
        assert_eq!(
            scroll_key_action_for(ScrollKey::PageUp, false, true, false),
            Some(ScrollAction::PageUp)
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::PageDown, false, true, false),
            Some(ScrollAction::PageDown)
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::Home, false, true, false),
            Some(ScrollAction::Home)
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::End, false, true, false),
            Some(ScrollAction::End)
        );
    }

    #[test]
    fn modified_nav_keys_pass_to_pty() {
        // Any modifier held -> the chord belongs to the application, even PageUp and
        // even when scrolled. Alt-screen is irrelevant here.
        for &scrolled in &[false, true] {
            for key in [
                ScrollKey::PageUp,
                ScrollKey::PageDown,
                ScrollKey::Home,
                ScrollKey::End,
            ] {
                assert_eq!(
                    scroll_key_action_for(key, false, scrolled, true),
                    None,
                    "modified {key:?} (scrolled={scrolled}) must reach the PTY"
                );
            }
        }
    }

    // --- 1a: scroll indicator label math/clamping ---------------------------

    #[test]
    fn scroll_indicator_hidden_at_live_bottom() {
        // Offset 0 = live; no indicator regardless of known length.
        assert_eq!(scroll_indicator_label(0, None), None);
        assert_eq!(scroll_indicator_label(0, Some(0)), None);
        assert_eq!(scroll_indicator_label(0, Some(100)), None);
    }

    #[test]
    fn scroll_indicator_known_length_shows_depth_and_percent() {
        assert_eq!(
            scroll_indicator_label(8, Some(100)).as_deref(),
            Some("[scroll 8/100 8%]")
        );
        // Percent rounds.
        assert_eq!(
            scroll_indicator_label(1, Some(3)).as_deref(),
            Some("[scroll 1/3 33%]")
        );
        // At the very top, percent is 100.
        assert_eq!(
            scroll_indicator_label(100, Some(100)).as_deref(),
            Some("[scroll 100/100 100%]")
        );
    }

    #[test]
    fn scroll_indicator_unknown_or_empty_shows_bare_offset() {
        // Before the first reply (None) we cannot honestly compute a fraction.
        assert_eq!(
            scroll_indicator_label(6, None).as_deref(),
            Some("[scroll +6]")
        );
        // Some(0) = daemon says no history; show the bare provisional offset.
        assert_eq!(
            scroll_indicator_label(3, Some(0)).as_deref(),
            Some("[scroll +3]")
        );
    }

    #[test]
    fn scroll_indicator_percent_clamps_to_100() {
        // Defensive: even if offset somehow exceeds the length, percent never exceeds 100.
        assert_eq!(
            scroll_indicator_label(150, Some(100)).as_deref(),
            Some("[scroll 150/100 100%]")
        );
    }

    // --- 1b: bootstrap — unknown history_len permits a provisional first move ---

    #[test]
    fn unknown_history_len_permits_provisional_first_scroll() {
        // history_len == None means "not yet known" (distinct from Some(0) = no history).
        // The very first wheel/PageUp from the live bottom must move so a request fires.
        let page = 6;
        // Wheel up by 3 from bottom with unknown length: moves to 3 (within one page).
        assert_eq!(next_view_offset(0, None, page, ScrollAction::Lines(3)), 3);
        // PageUp from bottom with unknown length: clamps to one provisional page.
        assert_eq!(next_view_offset(0, None, page, ScrollAction::PageUp), 6);
        // Home with unknown length: pin to the provisional cap, not 0 (so we move + ask).
        assert_eq!(next_view_offset(0, None, page, ScrollAction::Home), 6);
        // A big wheel-up does not overshoot past the provisional one-page cap.
        assert_eq!(next_view_offset(0, None, page, ScrollAction::Lines(999)), 6);
        // Down/End still return to live even when length is unknown.
        assert_eq!(next_view_offset(4, None, page, ScrollAction::End), 0);
    }

    #[test]
    fn known_empty_history_does_not_permanently_lock_future_scrolls() {
        // A daemon reply of zero is true only at that instant. Later shell output can create
        // history, so the next explicit upward gesture must issue a bounded fresh probe instead
        // of remaining forever at Step::NoMove.
        let page = 8;
        assert_eq!(
            next_view_offset(0, Some(0), page, ScrollAction::Lines(1)),
            1
        );
        assert_eq!(next_view_offset(0, Some(0), page, ScrollAction::PageUp), 8);
        assert_eq!(next_view_offset(0, Some(0), page, ScrollAction::Home), 8);
        // The opposite direction remains pinned to the live bottom.
        assert_eq!(
            next_view_offset(0, Some(0), page, ScrollAction::Lines(-1)),
            0
        );
    }

    #[test]
    fn cached_positive_ceiling_reprobe_extends_from_current_without_jump_back() {
        // If a scrolled pane learned depth 100 and live output later grew it, probe one
        // additional page from 100. Never reuse the initial page as an absolute cap.
        assert_eq!(
            next_view_offset(100, Some(100), 12, ScrollAction::PageUp),
            112
        );
        assert_eq!(
            next_view_offset(100, Some(100), 12, ScrollAction::Lines(99)),
            112
        );
    }

    // --- 5: alt-screen forces scrollback off --------------------------------

    #[test]
    fn alt_screen_forces_view_off() {
        // The alt-screen gate in App::apply_scroll/draw resets to live. We assert the
        // state transition it performs: a scrolled state with a cached window snaps back
        // to the live bottom and drops the historical snapshot.
        let mut sb = ScrollbackState {
            view_offset: 7,
            history_len: Some(100),
            historical: Some(Arc::new(scrollback_snapshot(
                SessionGeneration("g".into()),
                Revision(1),
                (hist_rows(40, 6), None),
            ))),
            historical_generation: Some(SessionGeneration("g".into())),
            ..ScrollbackState::default()
        };
        assert!(sb.is_scrolled());
        sb.reset_to_live();
        assert_eq!(sb.view_offset, 0, "alt-screen reset clears the offset");
        assert!(
            sb.historical.is_none(),
            "alt-screen reset drops history window"
        );
        assert!(!sb.is_scrolled());
    }

    #[test]
    fn primary_and_sibling_screen_transitions_reset_only_their_own_history() {
        fn seed(sb: &mut ScrollbackState, offset: u32, generation: &str) {
            sb.view_offset = offset;
            sb.history_len = Some(100);
            sb.historical = Some(Arc::new(live_grid(generation, 40, 6, false)));
            sb.historical_generation = Some(SessionGeneration(generation.to_string()));
        }

        fn assert_reset(sb: &ScrollbackState) {
            assert_eq!(sb.view_offset, 0);
            assert!(sb.history_len.is_none());
            assert!(sb.historical.is_none());
            assert!(sb.historical_generation.is_none());
        }

        let (shared, _queue) = Shared::with_test_queue();
        let active = shared.init_active_session("primary").unwrap();
        assert!(shared.commit_active_grid(
            &active,
            Revision(1),
            Arc::new(live_grid("primary-gen", 40, 6, false)),
        ));
        let sibling_epoch = shared.set_sibling_session("sibling").unwrap();
        assert!(shared.apply_sibling_grid(
            "sibling",
            sibling_epoch,
            Arc::new(live_grid("sibling-gen", 40, 6, false)),
        ));

        {
            let mut primary = shared.scrollback.lock().unwrap();
            seed(&mut primary, 5, "primary-gen");
            let intent = primary.advance_intent().unwrap();
            primary.admitted_request =
                Some((intent, 5, SessionGeneration("primary-gen".to_string())));
        }
        shared.with_pane_scrollback("sibling", "primary", |sibling| {
            seed(sibling, 7, "sibling-gen");
        });

        assert!(shared.commit_active_grid(
            &active,
            Revision(2),
            Arc::new(live_grid("primary-gen", 40, 6, true)),
        ));
        assert_reset(&shared.scrollback.lock().unwrap());
        assert!(!shared.commit_active_scrollback(
            &active,
            SessionGeneration("primary-gen".to_string()),
            Revision(2),
            100,
            5,
            (hist_rows(40, 6), None),
        ));
        assert_reset(&shared.scrollback.lock().unwrap());
        assert!(shared.scrollback.lock().unwrap().admitted_request.is_none());
        assert_eq!(
            shared.with_pane_scrollback("sibling", "primary", |sibling| sibling.view_offset),
            7,
            "primary transition must not leak into the sibling viewport"
        );

        seed(&mut shared.scrollback.lock().unwrap(), 4, "primary-gen");
        assert!(shared.commit_active_grid(
            &active,
            Revision(3),
            Arc::new(live_grid("primary-gen", 40, 6, false)),
        ));
        assert_reset(&shared.scrollback.lock().unwrap());

        seed(&mut shared.scrollback.lock().unwrap(), 3, "primary-gen");
        assert!(shared.apply_sibling_grid(
            "sibling",
            sibling_epoch,
            Arc::new(live_grid("sibling-gen", 40, 6, true)),
        ));
        shared.with_pane_scrollback("sibling", "primary", |sibling| {
            assert_reset(sibling);
            seed(sibling, 2, "sibling-gen");
        });
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 3);

        assert!(shared.apply_sibling_grid(
            "sibling",
            sibling_epoch,
            Arc::new(live_grid("sibling-gen", 40, 6, false)),
        ));
        shared.with_pane_scrollback("sibling", "primary", |sibling| assert_reset(sibling));
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 3);
    }

    // --- 6: resize forces scrollback off ------------------------------------

    #[test]
    fn resize_forces_view_off() {
        // Resize uses the same reset path; from any scrolled state we return to live.
        let mut sb = ScrollbackState {
            view_offset: 12,
            history_len: Some(100),
            historical: Some(Arc::new(scrollback_snapshot(
                SessionGeneration("g".into()),
                Revision(1),
                (hist_rows(40, 6), None),
            ))),
            historical_generation: None,
            ..ScrollbackState::default()
        };
        sb.reset_to_live();
        assert_eq!(sb.view_offset, 0);
        assert!(sb.historical.is_none());
        assert!(sb.historical_generation.is_none());
    }

    // --- 7: ScrollbackRows for wrong session / generation ignored -----------

    #[test]
    fn row_copy_history_owns_dimensions_revision_and_clears_absence() {
        use maestro_protocol::row_copy::RowCopy;
        let generation = SessionGeneration("gen-a".into());
        let mut sb = ScrollbackState::default();
        let metadata = vec![RowCopy {
            starts_line: Some(false),
            soft_wrap: false,
            excluded_columns: vec![],
        }];
        for (revision, row_copy) in [(50, Some(metadata.clone())), (51, None)] {
            let intent = sb.advance_intent().unwrap();
            sb.view_offset = 1;
            sb.admitted_request = Some((intent, 1, generation.clone()));
            assert!(apply_scrollback_payload(
                Some(generation.clone()),
                &mut sb,
                generation.clone(),
                Revision(revision),
                100,
                1,
                (vec![vec![cell("h"), cell(" ")]], row_copy.clone())
            ));
            let snap = sb.historical.as_ref().unwrap();
            assert_eq!(
                (snap.cols, snap.rows, snap.revision),
                (2, 1, Revision(revision))
            );
            assert_eq!(snap.row_copy, row_copy);
        }
        let old = sb.historical.clone();
        let intent = sb.advance_intent().unwrap();
        sb.admitted_request = Some((intent, 1, generation.clone()));
        let mut bad = metadata;
        bad[0].excluded_columns = vec![0];
        assert!(!apply_scrollback_payload(
            Some(generation.clone()),
            &mut sb,
            generation,
            Revision(52),
            900,
            1,
            (vec![vec![cell("h")]], Some(bad))
        ));
        assert!(Arc::ptr_eq(
            sb.historical.as_ref().unwrap(),
            old.as_ref().unwrap()
        ));
        assert_eq!(sb.history_len, Some(100));
    }

    #[test]
    fn scrollback_rows_over_terminal_hyperlink_cell_cap_are_rejected() {
        let generation = SessionGeneration("gen-a".into());
        let mut scrollback = ScrollbackState::default();
        let intent = scrollback.advance_intent().unwrap();
        scrollback.view_offset = 1;
        scrollback.admitted_request = Some((intent, 1, generation.clone()));
        let mut linked = cell("x");
        linked.hyperlink = Some("https://scrollback-cap.example.test".to_owned());

        assert!(!apply_scrollback_payload(
            Some(generation.clone()),
            &mut scrollback,
            generation,
            Revision(50),
            100,
            1,
            (
                vec![vec![
                    linked;
                    maestro_protocol::MAX_TERMINAL_LINK_CELLS_PER_FRAME + 1
                ]],
                None
            ),
        ));
        assert!(scrollback.admitted_request.is_none());
        assert!(scrollback.historical.is_none());
        assert_eq!(scrollback.history_len, None);
    }

    #[test]
    fn scrollback_rows_wrong_session_ignored() {
        let shared = shared_with_live("gen-a", 40, 6);
        // Scroll up so a valid reply WOULD be adopted.
        admit_scrollback_reply(&shared, 5, "gen-a");

        let woke = apply_scrollback_rows(
            &shared,
            "my-session",
            "OTHER-session",
            SessionGeneration("gen-a".into()),
            Revision(50),
            100,
            5,
            hist_rows(40, 6),
        );
        assert!(!woke, "wrong-session reply does not repaint");
        let sb = shared.scrollback.lock().unwrap();
        assert!(sb.historical.is_none(), "wrong-session reply not adopted");
        assert_eq!(
            sb.history_len, None,
            "wrong-session reply leaves history_len unknown (untouched)"
        );
    }

    #[test]
    fn scrollback_rows_stale_generation_ignored() {
        let shared = shared_with_live("gen-a", 40, 6);
        admit_scrollback_reply(&shared, 5, "gen-b");

        // Live grid is gen-a; this reply is for gen-b (session was re-baselined).
        let woke = apply_scrollback_rows(
            &shared,
            "my-session",
            "my-session",
            SessionGeneration("gen-b".into()),
            Revision(50),
            100,
            5,
            hist_rows(40, 6),
        );
        assert!(!woke, "stale-generation reply does not repaint");
        assert!(
            shared.scrollback.lock().unwrap().historical.is_none(),
            "stale-generation reply not adopted"
        );
    }

    #[test]
    fn stale_generation_reply_retires_single_slot_before_current_reply() {
        let mut scrollback = ScrollbackState::default();

        let old_intent = scrollback.advance_intent().unwrap();
        scrollback.view_offset = 5;
        scrollback.admitted_request = Some((old_intent, 5, SessionGeneration("gen-old".into())));

        // A new baseline arrives, the user explicitly returns to live, then starts a new scroll
        // intent against that baseline. The old ordered reply must release the sole admission slot.
        scrollback.reset_to_live();
        let current_intent = scrollback.advance_intent().unwrap();
        scrollback.view_offset = 9;
        // The single-in-flight transaction cannot admit this until the old reply retires. Model the
        // owner wake by installing the coalesced current request immediately after that retirement.
        let pending_current = (current_intent, 9, SessionGeneration("gen-current".into()));

        assert!(!apply_scrollback_payload(
            Some(SessionGeneration("gen-current".into())),
            &mut scrollback,
            SessionGeneration("gen-old".into()),
            Revision(50),
            10,
            5,
            (hist_rows(40, 6), None),
        ));
        assert!(
            scrollback.admitted_request.is_none(),
            "the rejected old-generation response retires the one exact in-flight slot"
        );
        assert_eq!(scrollback.view_offset, 9);
        assert!(scrollback.historical.is_none());

        scrollback.admitted_request = Some(pending_current);
        assert!(apply_scrollback_payload(
            Some(SessionGeneration("gen-current".into())),
            &mut scrollback,
            SessionGeneration("gen-current".into()),
            Revision(51),
            100,
            9,
            (hist_rows(40, 6), None),
        ));
        assert!(scrollback.admitted_request.is_none());
        assert_eq!(scrollback.view_offset, 9);
        assert_eq!(
            scrollback
                .historical_generation
                .as_ref()
                .map(|generation| generation.0.as_str()),
            Some("gen-current")
        );
    }

    // --- 8: ScrollbackRows while offset>0 becomes the painted window --------

    #[test]
    fn scrollback_rows_while_scrolled_becomes_historical_window() {
        let shared = shared_with_live("gen-a", 40, 6);
        admit_scrollback_reply(&shared, 10, "gen-a");

        let woke = apply_scrollback_rows(
            &shared,
            "my-session",
            "my-session",
            SessionGeneration("gen-a".into()),
            Revision(50),
            100,
            10,
            hist_rows(40, 6),
        );
        assert!(woke, "a valid reply triggers a repaint");
        let sb = shared.scrollback.lock().unwrap();
        assert_eq!(sb.history_len, Some(100));
        assert_eq!(sb.view_offset, 10, "echoes the served offset");
        let snap = sb.historical.as_ref().expect("historical window adopted");
        assert_eq!(snap.rows, 6);
        assert_eq!(snap.cols, 40);
        assert_eq!(
            snap.rows_cells[0][0].text, "h",
            "painted rows are the history rows"
        );
        assert!(
            !snap.cursor_visible,
            "history snapshot draws no live cursor"
        );
    }

    /// A late reply that arrives AFTER the user returned to the live bottom must not
    /// resurrect a historical view (offset stays 0, no window), but may refresh
    /// history_len.
    #[test]
    fn scrollback_rows_after_return_to_live_does_not_resurrect() {
        let shared = shared_with_live("gen-a", 40, 6);
        // One query was admitted while scrolled, then a newer local intent returned to live.
        admit_scrollback_reply(&shared, 5, "gen-a");
        shared.scrollback.lock().unwrap().reset_to_live();
        let woke = apply_scrollback_rows(
            &shared,
            "my-session",
            "my-session",
            SessionGeneration("gen-a".into()),
            Revision(50),
            100,
            5,
            hist_rows(40, 6),
        );
        assert!(woke);
        let sb = shared.scrollback.lock().unwrap();
        assert_eq!(sb.view_offset, 0, "stays at the live bottom");
        assert!(sb.historical.is_none(), "no historical window resurrected");
        assert_eq!(sb.history_len, Some(100), "history_len still refreshed");
    }

    // --- bootstrap: first scroll from bottom with UNKNOWN history dispatches -

    /// The very first wheel/PageUp from the live bottom happens before any reply, so
    /// `history_len` is `None`. The renderer must still move to a provisional offset and
    /// dispatch one `Scrollback` request to learn the real length. We assert the exact
    /// offset-resolution + request the `App::apply_scroll` flow performs, without a window.
    #[test]
    fn first_scroll_with_unknown_history_dispatches_request() {
        let (shared, queue) = Shared::with_test_queue();
        *shared.grid.lock().unwrap() = Some(Arc::new(live_grid("gen-a", 40, 6, false)));
        // Fresh state: at the live bottom, history length not yet known.
        {
            let sb = shared.scrollback.lock().unwrap();
            assert_eq!(sb.view_offset, 0);
            assert_eq!(sb.history_len, None, "length unknown at bootstrap");
        }

        // Mirror App::apply_scroll's core: resolve the new offset (rows=6 = one page),
        // see it move off zero, store it, and enqueue a Scrollback for it.
        let page = 6u32;
        let new_offset = next_view_offset(0, None, page, ScrollAction::PageUp);
        assert!(
            new_offset > 0,
            "first PageUp moves even with unknown history"
        );
        shared.scrollback.lock().unwrap().view_offset = new_offset;
        assert_eq!(
            shared.send_request(&ClientRequest::Scrollback {
                id: "my-session".to_string(),
                offset_from_top: new_offset,
                count: page as u16,
            }),
            RequestAdmission::Admitted
        );

        assert_eq!(
            queue.len(),
            1,
            "first scroll-up dispatches exactly one Scrollback request"
        );
    }

    /// If the bootstrap request comes back with `history_len = 0` (no scrollback exists),
    /// the provisional offset must NOT strand us in scrolled mode: we snap back to live.
    #[test]
    fn no_history_reply_returns_to_live() {
        let shared = shared_with_live("gen-a", 40, 6);
        // We provisionally scrolled up (offset 6) before knowing the length.
        admit_scrollback_reply(&shared, 6, "gen-a");

        let woke = apply_scrollback_rows(
            &shared,
            "my-session",
            "my-session",
            SessionGeneration("gen-a".into()),
            Revision(50),
            0, // the daemon reports: there is no history
            0,
            vec![], // no rows
        );
        assert!(woke, "a reply still repaints");
        let sb = shared.scrollback.lock().unwrap();
        assert_eq!(sb.history_len, Some(0), "length now known to be zero");
        assert_eq!(sb.view_offset, 0, "no-history reply snaps back to live");
        assert!(!sb.is_scrolled(), "not stuck in scrolled mode");
        assert!(sb.historical.is_none(), "no historical window adopted");
    }

    // --- 9: live updates while scrolled don't move the historical viewport ---

    #[test]
    fn live_update_while_scrolled_keeps_historical_viewport() {
        let shared = shared_with_live("gen-a", 40, 6);
        // Adopt a historical window at offset 10.
        admit_scrollback_reply(&shared, 10, "gen-a");
        apply_scrollback_rows(
            &shared,
            "my-session",
            "my-session",
            SessionGeneration("gen-a".into()),
            Revision(50),
            100,
            10,
            hist_rows(40, 6),
        );
        let painted_before = shared
            .scrollback
            .lock()
            .unwrap()
            .historical
            .clone()
            .unwrap();

        // Simulate live Damage: the reader updates shared.grid (same generation, newer
        // content). This is exactly what handle_event does for a Damage frame.
        let mut newer = live_grid("gen-a", 40, 6, false);
        newer.revision = Revision(200);
        newer.rows_cells = (0..6).map(|i| row(&format!("NEW{i}"), 40)).collect();
        *shared.grid.lock().unwrap() = Some(Arc::new(newer));

        // The historical viewport the UI paints from is unchanged: scrollback view state
        // is independent of the live grid mutation.
        let sb = shared.scrollback.lock().unwrap();
        assert_eq!(sb.view_offset, 10, "live update does not move the viewport");
        assert!(
            Arc::ptr_eq(sb.historical.as_ref().unwrap(), &painted_before),
            "the historical window the UI paints is the same Arc, untouched by live damage"
        );
    }

    // --- 10: returning to the bottom paints the current live grid -----------

    #[test]
    fn returning_to_bottom_paints_live_grid() {
        let shared = shared_with_live("gen-a", 40, 6);
        // Scrolled up with a cached window.
        {
            let mut sb = shared.scrollback.lock().unwrap();
            sb.view_offset = 8;
            sb.historical = Some(Arc::new(scrollback_snapshot(
                SessionGeneration("gen-a".into()),
                Revision(1),
                (hist_rows(40, 6), None),
            )));
            sb.historical_generation = Some(SessionGeneration("gen-a".into()));
        }
        // Returning to the bottom: offset reaches 0, reset_to_live drops the window so
        // draw() falls through to the live grid.
        let new = next_view_offset(8, Some(100), 6, ScrollAction::End);
        assert_eq!(new, 0);
        {
            let mut sb = shared.scrollback.lock().unwrap();
            sb.reset_to_live();
            assert!(!sb.is_scrolled(), "back at the live bottom");
            assert!(sb.historical.is_none(), "draw paints the live grid now");
        }
        // The live grid is still present and current — that is what draw() will paint.
        assert!(shared.grid.lock().unwrap().is_some());
    }

    // --- WheelAccumulator: sub-line trackpad/wheel delta accumulation ---

    #[test]
    fn wheel_pixels_below_one_line_accumulate_then_step() {
        // A gentle macOS trackpad delivers a stream of small (<16px) PixelDelta events.
        // Each alone rounds to nothing, but together they must cross a line boundary.
        let mut w = WheelAccumulator::default();
        assert_eq!(w.add_pixels(5.0), 0, "5px < one line, no step yet");
        assert_eq!(w.add_pixels(5.0), 0, "10px accumulated, still < 16");
        assert_eq!(w.add_pixels(5.0), 0, "15px accumulated, still < 16");
        assert_eq!(
            w.add_pixels(5.0),
            1,
            "20px crosses one line: emit 1 step up"
        );
    }

    #[test]
    fn wheel_pixel_remainder_carries_forward() {
        // After emitting a whole step the fractional remainder must persist so the next
        // small event builds on it rather than restarting from zero.
        let mut w = WheelAccumulator::default();
        assert_eq!(
            w.add_pixels(20.0),
            1,
            "20px -> 1 step, 4px remainder retained"
        );
        // 12px + 4px carried = 16px = exactly one more line.
        assert_eq!(
            w.add_pixels(12.0),
            1,
            "carried remainder completes the next line"
        );
    }

    #[test]
    fn wheel_negative_pixels_step_toward_live() {
        // Negative y = scroll down toward live; sign must pass through to ScrollAction.
        let mut w = WheelAccumulator::default();
        assert_eq!(w.add_pixels(-20.0), -1, "down past one line -> -1 step");
    }

    #[test]
    fn wheel_line_delta_passes_whole_lines() {
        // Classic wheels deliver LineDelta already in line units.
        let mut w = WheelAccumulator::default();
        assert_eq!(w.add_lines(3.0), 3, "whole lines pass straight through");
        assert_eq!(w.add_lines(-1.0), -1, "negative line delta toward live");
    }

    #[test]
    fn wheel_line_delta_fraction_accumulates_with_pixels() {
        // LineDelta and PixelDelta feed the same residue, so a fractional line plus a
        // few pixels can complete a step together.
        let mut w = WheelAccumulator::default();
        assert_eq!(w.add_lines(0.5), 0, "half a line is not yet a step");
        // 0.5 line residue + 8px (=0.5 line) = 1.0 line.
        assert_eq!(
            w.add_pixels(8.0),
            1,
            "fractional line + pixels complete a step"
        );
    }

    #[test]
    fn wheel_focus_change_discards_prior_pane_residue() {
        let mut wheel = WheelAccumulator::default();
        assert_eq!(wheel.add_pixels(WHEEL_PIXELS_PER_LINE / 2.0), 0);

        wheel.reset();

        assert_eq!(
            wheel.add_pixels(WHEEL_PIXELS_PER_LINE / 2.0),
            0,
            "half a line from the old pane must not complete half a line in the new pane"
        );
        assert_eq!(wheel.add_pixels(WHEEL_PIXELS_PER_LINE / 2.0), 1);
    }

    #[test]
    fn wheel_sign_matches_scroll_action_up_into_history() {
        // Positive accumulated delta maps to ScrollAction::Lines positive = up into
        // history; negative = down toward live. Lock that mapping in.
        let mut w = WheelAccumulator::default();
        let up = w.add_pixels(32.0);
        assert!(up > 0, "positive delta is up into history");
        let mut w2 = WheelAccumulator::default();
        let down = w2.add_pixels(-32.0);
        assert!(down < 0, "negative delta is down toward live");
    }

    #[test]
    fn wheel_input_policy_selects_one_bounded_owner_with_mouse_precedence() {
        assert_eq!(
            wheel_input_action_for(0, false, false),
            WheelInputAction::NoOp
        );
        assert_eq!(
            wheel_input_action_for(0, true, true),
            WheelInputAction::NoOp,
            "mouse/alternate modes cannot manufacture a step before accumulation"
        );
        assert_eq!(
            wheel_input_action_for(3, true, true),
            WheelInputAction::MouseReport {
                direction: WheelDirection::Up,
                steps: 3,
            }
        );
        assert_eq!(
            wheel_input_action_for(-2, true, true),
            WheelInputAction::MouseReport {
                direction: WheelDirection::Down,
                steps: 2,
            }
        );
        let cap = MAX_WHEEL_STEPS_PER_EVENT;
        assert_eq!(
            wheel_input_action_for(i64::MAX, false, true),
            WheelInputAction::AlternateScrollKeys {
                direction: WheelDirection::Up,
                steps: cap,
            }
        );
        assert_eq!(
            wheel_input_action_for(i64::MIN, false, true),
            WheelInputAction::AlternateScrollKeys {
                direction: WheelDirection::Down,
                steps: cap,
            }
        );
        assert_eq!(
            wheel_input_action_for(i64::MAX, false, false),
            WheelInputAction::RendererScrollback(ScrollAction::Lines(i64::from(cap)))
        );
        assert_eq!(
            wheel_input_action_for(i64::MIN, false, false),
            WheelInputAction::RendererScrollback(ScrollAction::Lines(-i64::from(cap)))
        );
    }
}

#[cfg(test)]
mod decode_error_tests {
    use super::*;

    fn route(output: Option<u64>, live: Option<u64>) -> EventRouteMetadata {
        EventRouteMetadata {
            output_generation: output,
            live_output_generation: live,
        }
    }

    #[test]
    fn every_decode_error_requires_resync() {
        // Each category requires route-aware repair. The caller still decides between an exact
        // Snapshot recovery, inert stale-frame rejection, and terminal fail-close.
        assert!(decode_error_requires_resync(&DecodeError::BadEnvelope));
        assert!(decode_error_requires_resync(&DecodeError::BadPayload));
        assert!(decode_error_requires_resync(&DecodeError::DamageTooLarge {
            bytes: 999_999,
        }));
    }

    #[test]
    fn malformed_damage_line_decodes_to_resync_decision() {
        // End-to-end through the real decoder: a damage event with a structurally
        // broken payload fails to decode, and that failure is classified as needing a
        // route-classified repair (not a silent unconditional skip). This guards BadPayload.
        let line =
            r#"{"ev":"damage","id":"s1","base_revision":1,"revision":2,"ops":[{"bogus":true}]}"#;
        let err = decode_event(line).expect_err("malformed damage payload must not decode");
        assert!(
            decode_error_requires_resync(&err),
            "a malformed damage frame must trigger resync, got {err:?}"
        );
    }

    #[test]
    fn payload_decode_diagnostic_never_contains_terminal_controlled_value() {
        const SENTINEL: &str = "TOP_SECRET_TERMINAL_SENTINEL";
        let line = format!(r#"{{"ev":"damage","frame":{{"id":"s1","revision":"{SENTINEL}"}}}}"#);
        let err = decode_event(&line).expect_err("typed Damage field is malformed");
        assert_eq!(err, DecodeError::BadPayload);
        assert!(!describe_decode_error(&err).contains(SENTINEL));
        assert!(
            !format!("{err:?}").contains(SENTINEL),
            "DecodeError itself must not retain serde text or raw terminal values"
        );
    }

    #[test]
    fn pending_exact_attach_echo_failure_is_terminal_but_ambiguous_frames_are_inert() {
        let routed = RoutedSyncState::new("same".to_string(), 41, false);

        assert_eq!(
            routed.decode_failure_action("same", EventRouteKind::Grid, route(Some(41), None),),
            DecodeFailureAction::FailClosed,
            "a malformed exact Attach echo cannot leave the rebound route blank forever"
        );
        assert_eq!(
            routed.decode_failure_action("same", EventRouteKind::Grid, route(None, None),),
            DecodeFailureAction::Ignore,
            "an untagged legacy Grid must not repair or perturb a rebound route"
        );
        assert_eq!(
            routed.decode_failure_action("same", EventRouteKind::Grid, route(Some(40), None),),
            DecodeFailureAction::Ignore,
            "an old exact echo is stale, not authority for the new route"
        );
        assert_eq!(
            routed.decode_failure_action("other", EventRouteKind::Grid, route(Some(41), None),),
            DecodeFailureAction::Ignore,
            "even a matching generation cannot authorize the wrong session id"
        );
    }

    #[test]
    fn confirmed_exact_decode_failures_use_generation_aware_terminal_or_recovery_policy() {
        let mut routed = RoutedSyncState::new("same".to_string(), 41, false);
        routed.proof = StreamProof::ExactConfirmed;

        for route in [route(Some(41), None), route(None, Some(41))] {
            assert_eq!(
                routed.decode_failure_action("same", EventRouteKind::Grid, route),
                DecodeFailureAction::FailClosed,
                "a generation-proven malformed Grid could strand recovery bookkeeping"
            );
        }
        assert_eq!(
            routed.decode_failure_action(
                "same",
                EventRouteKind::ScrollbackRows,
                route(Some(41), None),
            ),
            DecodeFailureAction::FailClosed,
            "a malformed exact Scrollback reply cannot leave its sole slot occupied"
        );
        assert_eq!(
            routed.decode_failure_action("same", EventRouteKind::Damage, route(None, Some(41)),),
            DecodeFailureAction::Recover,
        );

        for kind in [EventRouteKind::Grid, EventRouteKind::ScrollbackRows] {
            assert_eq!(
                routed.decode_failure_action("same", kind, route(None, None)),
                DecodeFailureAction::FailClosed,
                "current untagged direct replies are ordered after the exact Attach echo"
            );
        }
        for (kind, stale_route) in [
            (EventRouteKind::Grid, route(Some(40), None)),
            (EventRouteKind::ScrollbackRows, route(Some(40), None)),
            (EventRouteKind::Damage, route(None, None)),
            (EventRouteKind::Damage, route(None, Some(40))),
        ] {
            assert_eq!(
                routed.decode_failure_action("same", kind, stale_route),
                DecodeFailureAction::Ignore,
                "untagged or old-generation malformed input must not perturb the current route"
            );
        }
    }

    #[test]
    fn initial_legacy_route_recovers_only_matching_untagged_damage() {
        let mut routed = RoutedSyncState::new("initial".to_string(), 1, true);
        routed.proof = StreamProof::LegacyInitial;

        assert_eq!(
            routed.decode_failure_action("initial", EventRouteKind::Damage, route(None, None),),
            DecodeFailureAction::Recover,
            "the first connection has no older route, so its exact untagged Damage is recoverable"
        );
        for (id, kind, route) in [
            ("other", EventRouteKind::Damage, route(None, None)),
            ("initial", EventRouteKind::Damage, route(Some(1), None)),
            ("initial", EventRouteKind::Other, route(None, None)),
        ] {
            assert_eq!(
                routed.decode_failure_action(id, kind, route),
                DecodeFailureAction::Ignore,
                "only the exact untagged legacy Damage route is recoverable"
            );
        }
        for kind in [EventRouteKind::Grid, EventRouteKind::ScrollbackRows] {
            assert_eq!(
                routed.decode_failure_action("initial", kind, route(None, None)),
                DecodeFailureAction::FailClosed,
                "a malformed direct reply on the sole legacy route is terminal"
            );
        }
    }
}

#[cfg(test)]
mod reader_terminal_failure_tests {
    use super::*;
    use std::fs;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::thread;

    static NEXT_SOCKET: AtomicU64 = AtomicU64::new(1);

    #[derive(Clone)]
    struct ChannelSender(mpsc::Sender<UserEvent>);

    impl UserEventSender for ChannelSender {
        fn send(&self, event: UserEvent) -> Result<(), UserEvent> {
            self.0.send(event).map_err(|error| error.0)
        }

        fn clone_sender(&self) -> Box<dyn UserEventSender> {
            Box::new(self.clone())
        }
    }

    fn socket_path(_label: &str) -> PathBuf {
        // macOS limits AF_UNIX paths to 104 bytes, while the per-user TMPDIR can already be quite
        // long. Keep this test fixture in the system's short, process-unique `/tmp` namespace.
        PathBuf::from("/tmp").join(format!(
            "mr-{}-{}.sock",
            std::process::id(),
            NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn spawn_exact_test_client(
        socket_path: String,
        session_id: &str,
        expected_generation: &str,
        proxy: Box<dyn UserEventSender>,
    ) -> Arc<Shared> {
        spawn_with_initial_binding(
            socket_path,
            session_id.to_string(),
            Some(DesiredViewportBinding {
                primary_session_id: session_id.to_string(),
                primary_expected_generation: SessionGeneration(expected_generation.to_string()),
                primary_dims: None,
                panes: Vec::new(),
            }),
            None,
            proxy,
        )
        .shared
    }

    fn cell() -> Cell {
        Cell {
            text: "x".to_string(),
            fg: crate::wire::Color::Named {
                name: crate::wire::NamedColor::Foreground,
            },
            bg: crate::wire::Color::Named {
                name: crate::wire::NamedColor::Background,
            },
            bold: false,
            italic: false,
            underline: Default::default(),
            inverse: false,
            strikeout: false,
            dim: false,
            hidden: false,
            hyperlink: None,
            width: 1,
        }
    }

    fn grid(generation: &str, revision: u64) -> GridSnapshot {
        GridSnapshot {
            row_copy: None,
            version: crate::sync::SUPPORTED_VERSION,
            generation: SessionGeneration(generation.to_string()),
            revision: Revision(revision),
            base_revision: Revision(revision),
            cols: 1,
            rows: 1,
            rows_cells: vec![vec![cell()]],
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
            alt_screen: false,
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_report: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_sgr: false,
        }
    }

    fn damage(id: &str, generation: &str, base: u64, revision: u64) -> crate::wire::DamageFrame {
        use crate::wire::{CursorState, DamageOp, ModeState, DAMAGE_SCHEMA};
        crate::wire::DamageFrame {
            row_copy: None,
            schema: DAMAGE_SCHEMA,
            id: id.to_string(),
            generation: SessionGeneration(generation.to_string()),
            base_revision: Revision(base),
            revision: Revision(revision),
            cols: 1,
            rows: 1,
            cursor: CursorState {
                line: 0,
                col: 0,
                visible: true,
                shape: CursorShape::Block,
            },
            modes: ModeState {
                alt_screen: false,
                app_cursor: false,
                bracketed_paste: false,
                focus_reporting: false,
                mouse_report: false,
                mouse_drag: false,
                mouse_motion: false,
                mouse_sgr: false,
            },
            ops: vec![DamageOp::ClearAll {
                cell: Cell {
                    text: " ".to_string(),
                    ..cell()
                },
            }],
        }
    }

    fn write_event(stream: &mut UnixStream, event: DaemonEvent, output_generation: Option<u64>) {
        let mut value = serde_json::to_value(event).expect("event serializes");
        if let Some(generation) = output_generation {
            value["output_generation"] = serde_json::json!(generation);
        }
        serde_json::to_writer(&mut *stream, &value).expect("event writes");
        stream.write_all(b"\n").expect("event delimiter writes");
    }

    fn write_live_event(stream: &mut UnixStream, event: DaemonEvent, live_output_generation: u64) {
        let mut value = serde_json::to_value(event).expect("event serializes");
        value["live_output_generation"] = serde_json::json!(live_output_generation);
        serde_json::to_writer(&mut *stream, &value).expect("event writes");
        stream.write_all(b"\n").expect("event delimiter writes");
    }

    fn oversized_damage_line(id: &str, live_output_generation: u64) -> Vec<u8> {
        let prefix = format!(
            "{{\"ev\":\"damage\",\"frame\":{{\"id\":{}}},\"live_output_generation\":{},\"padding\":\"",
            serde_json::to_string(id).unwrap(),
            live_output_generation
        );
        let mut line = Vec::with_capacity(crate::wire::MAX_DAMAGE_BYTES + prefix.len() + 16);
        line.extend_from_slice(prefix.as_bytes());
        line.resize(line.len() + crate::wire::MAX_DAMAGE_BYTES, b'x');
        line.extend_from_slice(b"\"}\n");
        line
    }

    fn assert_no_request_before_timeout(reader: &mut BufReader<UnixStream>) {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Ok(0) => panic!("renderer connection closed while proving request inactivity"),
            Ok(_) => panic!("unexpected renderer request: {line}"),
            Err(error) => panic!("unexpected request read failure: {error}"),
        }
    }

    fn read_request(reader: &mut BufReader<UnixStream>) -> ClientRequest {
        let mut line = String::new();
        reader.read_line(&mut line).expect("request line reads");
        assert!(!line.is_empty(), "client closed before expected request");
        serde_json::from_str(&line).expect("request decodes")
    }

    fn read_initial_plan(reader: &mut BufReader<UnixStream>, stream: &mut UnixStream) -> u64 {
        assert!(matches!(read_request(reader), ClientRequest::DaemonInfo));
        write_event(
            stream,
            DaemonEvent::DaemonInfo {
                protocol_version: REQUIRED_MUTATION_PROTOCOL_VERSION,
                build_version: "test-v3".into(),
                daemon_instance_id: Some("22222222222242228222222222222222".parse().unwrap()),
                output_generation_echo: true,
                child_environment: true,
                generation_conditional_mutations: true,
                attachment_aware_conditional_kill: true,
                generation_conditional_attach: true,
            },
            None,
        );
        let attach = read_request(reader);
        let generation = match attach {
            ClientRequest::Attach {
                id,
                output_generation: Some(generation),
                ..
            } => {
                assert_eq!(id, "s");
                generation
            }
            other => panic!("initial request must be exact Attach, got {other:?}"),
        };
        assert!(matches!(
            read_request(reader),
            ClientRequest::Snapshot { id } if id == "s"
        ));
        generation
    }

    #[test]
    fn legacy_v2_probe_and_attach_share_socket_across_path_replacement_and_stay_read_only() {
        let path = socket_path("legacy-v2-read-only");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let replacement_path = path.clone();
        let (mutation_window_tx, mutation_window_rx) = mpsc::channel();
        let (painted_tx, painted_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            // A v2 reply downgrades this exact reviewed socket to read-only. Attach/Snapshot must
            // follow on the same connection so a path replacement cannot receive textual Attach.
            let (mut probe, _) = listener.accept().expect("accept capability probe");
            probe
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut probe_reader = BufReader::new(probe.try_clone().unwrap());
            assert!(matches!(
                read_request(&mut probe_reader),
                ClientRequest::DaemonInfo
            ));
            write_event(
                &mut probe,
                DaemonEvent::DaemonInfo {
                    protocol_version: 2,
                    build_version: "retained-v2".into(),
                    daemon_instance_id: None,
                    output_generation_echo: false,
                    child_environment: false,
                    generation_conditional_mutations: false,
                    attachment_aware_conditional_kill: false,
                    generation_conditional_attach: false,
                },
                None,
            );
            fs::remove_file(&replacement_path).expect("unlink probed socket path");
            let replacement = UnixListener::bind(&replacement_path)
                .expect("bind current-v3 replacement between probe and attach");
            replacement.set_nonblocking(true).unwrap();

            probe
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            let mut stream = probe;
            let mut reader = probe_reader;
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Attach { id, .. } if id == "s"
            ));
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Snapshot { id } if id == "s"
            ));
            write_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("legacy-pty", 1),
                },
                None,
            );

            // The client attempts both key input and automatic geometry reconciliation while the
            // read-only socket is live. Neither request may reach this legacy daemon.
            assert_no_request_before_timeout(&mut reader);
            mutation_window_tx.send(()).unwrap();

            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Snapshot { id } if id == "s"
            ));
            write_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("legacy-pty", 2),
                },
                None,
            );
            painted_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("reader consumed later read-only event");
            assert!(
                matches!(
                    replacement.accept(),
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
                ),
                "renderer reconnected through the replaced socket path"
            );
        });

        let (tx, rx) = mpsc::channel();
        let shared = spawn(
            path.to_string_lossy().into_owned(),
            "s".to_string(),
            None,
            Box::new(ChannelSender(tx)),
        );
        let first = recv_until(&rx, |event| matches!(event, UserEvent::Redraw));
        assert!(first
            .iter()
            .all(|event| !matches!(event, UserEvent::ConnectionClosed)));
        assert_eq!(
            shared
                .grid
                .lock()
                .unwrap()
                .as_ref()
                .map(|grid| grid.revision),
            Some(Revision(1))
        );
        let binding = shared
            .binding_token_for_session("s")
            .expect("legacy grid establishes exact local binding");
        let generation = shared
            .live_generation_for_binding(&binding)
            .expect("legacy grid carries PTY generation");
        let refusal = shared
            .send_request_batch_for_binding(
                &binding,
                &[
                    ClientRequest::Write {
                        id: "s".to_string(),
                        expected_generation: generation.clone(),
                        data: "keypress".to_string(),
                    },
                    ClientRequest::Resize {
                        id: "s".to_string(),
                        expected_generation: generation.clone(),
                        cols: 120,
                        rows: 40,
                    },
                ],
                &generation,
                None,
            )
            .expect("binding remains current");
        assert!(refusal.is_mutation_unsupported());
        mutation_window_rx
            .recv_timeout(Duration::from_secs(3))
            .expect("server observed zero mutation wire bytes");
        assert!(!shared.connection_is_closed());

        assert!(shared
            .send_request_batch_for_binding(
                &binding,
                &[ClientRequest::Snapshot {
                    id: "s".to_string(),
                }],
                &generation,
                None,
            )
            .is_some_and(RequestAdmission::is_admitted));
        let second = recv_until(&rx, |_| {
            shared
                .grid
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|grid| grid.revision == Revision(2))
        });
        assert!(second
            .iter()
            .all(|event| !matches!(event, UserEvent::ConnectionClosed)));
        assert!(!shared.connection_is_closed());
        painted_tx.send(()).unwrap();
        server.join().unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    fn aligned_legacy_error_probe_keeps_same_socket_attach_only() {
        let path = socket_path("aligned-legacy-error-read-only");
        let listener = UnixListener::bind(&path).expect("bind legacy error test socket");
        let (mutation_attempt_tx, mutation_attempt_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept capability probe");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::DaemonInfo
            ));
            write_event(
                &mut stream,
                DaemonEvent::Error {
                    message: "unknown request: daemon_info".to_string(),
                },
                None,
            );
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Attach { id, .. } if id == "s"
            ));
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Snapshot { id } if id == "s"
            ));
            write_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("legacy-error-pty", 1),
                },
                None,
            );
            mutation_attempt_rx
                .recv_timeout(Duration::from_secs(3))
                .expect("client attempted locally refused mutations");
            stream
                .set_read_timeout(Some(Duration::from_millis(300)))
                .unwrap();
            assert_no_request_before_timeout(&mut reader);
        });

        let (tx, rx) = mpsc::channel();
        let shared = spawn(
            path.to_string_lossy().into_owned(),
            "s".to_string(),
            None,
            Box::new(ChannelSender(tx)),
        );
        let observed = recv_until(&rx, |event| matches!(event, UserEvent::Redraw));
        assert!(observed
            .iter()
            .all(|event| !matches!(event, UserEvent::ConnectionClosed)));
        let binding = shared
            .binding_token_for_session("s")
            .expect("legacy grid establishes the local binding");
        let generation = shared
            .live_generation_for_binding(&binding)
            .expect("legacy grid carries the PTY generation");
        let refusal = shared
            .send_request_batch_for_binding(
                &binding,
                &[
                    ClientRequest::Write {
                        id: "s".to_string(),
                        expected_generation: generation.clone(),
                        data: "keypress".to_string(),
                    },
                    ClientRequest::Resize {
                        id: "s".to_string(),
                        expected_generation: generation.clone(),
                        cols: 120,
                        rows: 40,
                    },
                ],
                &generation,
                None,
            )
            .expect("binding remains current");
        assert!(refusal.is_mutation_unsupported());
        mutation_attempt_tx.send(()).unwrap();
        server.join().unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    fn current_v3_without_exact_authority_never_downgrades_to_textual_attach() {
        for generation_capable in [false, true] {
            let path = socket_path(if generation_capable {
                "current-v3-no-authority-full"
            } else {
                "current-v3-no-authority-incomplete"
            });
            let listener = UnixListener::bind(&path).expect("bind current-v3 test socket");
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().expect("accept capability probe");
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                assert!(matches!(
                    read_request(&mut reader),
                    ClientRequest::DaemonInfo
                ));
                write_event(
                    &mut stream,
                    DaemonEvent::DaemonInfo {
                        protocol_version: REQUIRED_MUTATION_PROTOCOL_VERSION,
                        build_version: "current-v3".into(),
                        daemon_instance_id: Some(
                            "22222222222242228222222222222222".parse().unwrap(),
                        ),
                        output_generation_echo: generation_capable,
                        child_environment: generation_capable,
                        generation_conditional_mutations: generation_capable,
                        attachment_aware_conditional_kill: generation_capable,
                        generation_conditional_attach: generation_capable,
                    },
                    None,
                );
                stream.flush().unwrap();
                let mut remainder = String::new();
                reader.read_to_string(&mut remainder).unwrap();
                remainder
            });

            let (tx, _rx) = mpsc::channel();
            let spawned = spawn_with_initial_binding(
                path.to_string_lossy().into_owned(),
                "s".to_string(),
                None,
                None,
                Box::new(ChannelSender(tx)),
            );
            assert!(spawned.initial_binding.is_none());
            assert!(spawned.initial_exact_viewport.is_none());
            assert!(spawned.shared.connection_is_closed());
            assert_eq!(
                server.join().unwrap(),
                "",
                "current v3 received an authority-free Attach/Snapshot"
            );
            let _ = fs::remove_file(path);
        }
    }

    fn recv_until(
        rx: &mpsc::Receiver<UserEvent>,
        predicate: impl Fn(&UserEvent) -> bool,
    ) -> Vec<UserEvent> {
        let mut observed = Vec::new();
        loop {
            let event = rx
                .recv_timeout(Duration::from_secs(3))
                .expect("reader emitted expected owner event before deadline");
            let done = predicate(&event);
            observed.push(event);
            if done {
                return observed;
            }
        }
    }

    fn assert_terminally_neutral(shared: &Shared, observed: &[UserEvent]) {
        assert!(shared.active_snapshot().id.is_none());
        assert!(shared.grid.lock().unwrap().is_none());
        assert_eq!(
            observed
                .iter()
                .filter(|event| matches!(event, UserEvent::ConnectionClosed))
                .count(),
            1,
            "terminal corruption emits one idempotent owner close"
        );
        assert!(
            observed
                .iter()
                .all(|event| !matches!(event, UserEvent::TerminalBell { .. })),
            "buffered effects after a terminal frame must never escape"
        );
    }

    #[test]
    fn same_id_rebind_rejects_multiple_old_frames_but_preserves_exact_retired_exit() {
        enum ServerCommand {
            ReadRebindAndSendOld,
            SendNewBaseline,
            Close,
        }

        let path = socket_path("same-id-generation-barrier");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let (server_tx, server_rx) = mpsc::channel();
        let (generation_tx, generation_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept exact renderer");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let generation_a = read_initial_plan(&mut reader, &mut stream);
            write_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("pty-a", 1),
                },
                Some(generation_a),
            );

            assert!(matches!(
                server_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
                ServerCommand::ReadRebindAndSendOld
            ));
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Detach { id } if id == "s"
            ));
            let generation_b = match read_request(&mut reader) {
                ClientRequest::Attach {
                    id,
                    output_generation: Some(generation),
                    ..
                } => {
                    assert_eq!(id, "s");
                    generation
                }
                other => panic!("same-id rebind requires exact Attach, got {other:?}"),
            };
            assert_ne!(generation_a, generation_b);
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Snapshot { id } if id == "s"
            ));
            generation_tx.send((generation_a, generation_b)).unwrap();

            // This untagged direct Grid can have been queued before the Detach/Attach FIFO cut. The
            // new ExactPending binding must not mistake it for its baseline. Every later tagged A
            // event is likewise rejected by generation, including all terminal side effects.
            write_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("pty-a", 2),
                },
                None,
            );
            write_live_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("pty-a", 3),
                },
                generation_a,
            );
            write_live_event(
                &mut stream,
                DaemonEvent::Damage {
                    frame: damage("s", "pty-a", 1, 2),
                },
                generation_a,
            );
            write_live_event(
                &mut stream,
                DaemonEvent::TerminalTitle {
                    id: "s".to_string(),
                    title: Some("stale-title".to_string()),
                },
                generation_a,
            );
            write_live_event(
                &mut stream,
                DaemonEvent::TerminalBell {
                    id: "s".to_string(),
                },
                generation_a,
            );
            write_live_event(
                &mut stream,
                DaemonEvent::TerminalClipboardStore {
                    id: "s".to_string(),
                    text: "stale-clipboard".to_string(),
                },
                generation_a,
            );
            for _ in 0..2 {
                write_live_event(
                    &mut stream,
                    DaemonEvent::SessionExited {
                        id: "s".to_string(),
                        code: Some(17),
                    },
                    generation_a,
                );
            }

            assert!(matches!(
                server_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
                ServerCommand::SendNewBaseline
            ));
            write_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("pty-b", 1),
                },
                Some(generation_b),
            );
            write_live_event(
                &mut stream,
                DaemonEvent::Damage {
                    frame: damage("s", "pty-b", 1, 2),
                },
                generation_b,
            );
            assert!(matches!(
                server_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
                ServerCommand::Close
            ));
        });

        let (event_tx, event_rx) = mpsc::channel();
        let shared = spawn_exact_test_client(
            path.to_string_lossy().into_owned(),
            "s",
            "pty-a",
            Box::new(ChannelSender(event_tx)),
        );
        let initial = recv_until(&event_rx, |event| matches!(event, UserEvent::Redraw));
        assert!(initial.iter().all(|event| !matches!(
            event,
            UserEvent::TerminalBell { .. }
                | UserEvent::TerminalTitle { .. }
                | UserEvent::TerminalClipboardStore { .. }
        )));
        assert_eq!(
            shared
                .grid
                .lock()
                .unwrap()
                .as_ref()
                .map(|grid| grid.generation.0.as_str()),
            Some("pty-a")
        );

        shared.clear_viewport();
        let token_b = shared
            .try_bind_viewport(
                &DesiredViewportBinding {
                    primary_session_id: "s".to_string(),
                    primary_expected_generation: SessionGeneration("pty-b".to_string()),
                    primary_dims: None,
                    panes: Vec::new(),
                },
                &["s".to_string()],
                None,
            )
            .expect("same-id aggregate rebind admits");
        server_tx.send(ServerCommand::ReadRebindAndSendOld).unwrap();
        let (generation_a, generation_b) =
            generation_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(token_b.primary().output_generation, generation_b);
        assert_ne!(generation_a, generation_b);

        let old_observed = recv_until(&event_rx, |event| {
            matches!(event, UserEvent::SessionExited { .. })
        });
        assert!(
            shared.grid.lock().unwrap().is_none(),
            "B remains blank until its exact Attach echo"
        );
        assert_eq!(
            old_observed
                .iter()
                .filter(|event| matches!(event, UserEvent::SessionExited { .. }))
                .count(),
            1,
            "the exact retired A exit is durable but idempotent"
        );
        assert!(old_observed.iter().any(|event| matches!(
            event,
            UserEvent::SessionExited {
                session_id,
                code: Some(17),
                observed_generation: Some(observed),
            } if session_id == "s" && observed == "pty-a"
        )));
        assert!(old_observed.iter().all(|event| !matches!(
            event,
            UserEvent::TerminalBell { .. }
                | UserEvent::TerminalTitle { .. }
                | UserEvent::TerminalClipboardStore { .. }
        )));

        server_tx.send(ServerCommand::SendNewBaseline).unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            assert!(
                Instant::now() < deadline,
                "B baseline/damage did not commit"
            );
            let event = event_rx.recv_timeout(Duration::from_millis(100)).unwrap();
            assert!(
                matches!(event, UserEvent::Redraw | UserEvent::OutboundWritable),
                "no duplicate retired exit or stale effect may precede B's redraw: {event:?}"
            );
            if matches!(event, UserEvent::Redraw)
                && shared.grid.lock().unwrap().as_ref().is_some_and(|grid| {
                    grid.generation.0 == "pty-b" && grid.revision == Revision(2)
                })
            {
                break;
            }
        }
        server_tx.send(ServerCommand::Close).unwrap();
        server.join().unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    fn oversized_damage_recovers_only_for_the_exact_current_live_generation() {
        enum ServerCommand {
            ReadRebind,
            SendStaleOversize,
            Close,
        }
        enum ServerStatus {
            ExactRecovered(u64),
            Rebound(u64),
            StaleInert,
        }

        let path = socket_path("oversized-damage-route");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let (server_tx, server_rx) = mpsc::channel();
        let (status_tx, status_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept renderer");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let generation_a = read_initial_plan(&mut reader, &mut stream);
            write_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("pty-a", 1),
                },
                Some(generation_a),
            );

            stream
                .write_all(&oversized_damage_line("s", generation_a))
                .unwrap();
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Snapshot { id } if id == "s"
            ));
            stream
                .set_read_timeout(Some(Duration::from_millis(250)))
                .unwrap();
            assert_no_request_before_timeout(&mut reader);
            status_tx
                .send(ServerStatus::ExactRecovered(generation_a))
                .unwrap();

            assert!(matches!(
                server_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
                ServerCommand::ReadRebind
            ));
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Detach { id } if id == "s"
            ));
            let generation_b = match read_request(&mut reader) {
                ClientRequest::Attach {
                    id,
                    output_generation: Some(generation),
                    ..
                } => {
                    assert_eq!(id, "s");
                    generation
                }
                other => panic!("rebind Attach expected, got {other:?}"),
            };
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Snapshot { id } if id == "s"
            ));
            write_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("pty-b", 1),
                },
                Some(generation_b),
            );
            status_tx.send(ServerStatus::Rebound(generation_b)).unwrap();

            assert!(matches!(
                server_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
                ServerCommand::SendStaleOversize
            ));
            stream
                .write_all(&oversized_damage_line("s", generation_a))
                .unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            assert_no_request_before_timeout(&mut reader);
            status_tx.send(ServerStatus::StaleInert).unwrap();
            assert!(matches!(
                server_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
                ServerCommand::Close
            ));
        });

        let (event_tx, event_rx) = mpsc::channel();
        let shared = spawn_exact_test_client(
            path.to_string_lossy().into_owned(),
            "s",
            "pty-a",
            Box::new(ChannelSender(event_tx)),
        );
        let _ = recv_until(&event_rx, |event| matches!(event, UserEvent::Redraw));
        let generation_a = match status_rx.recv_timeout(Duration::from_secs(3)).unwrap() {
            ServerStatus::ExactRecovered(generation) => generation,
            _ => unreachable!(),
        };

        shared.clear_viewport();
        let token_b = shared
            .try_bind_viewport(
                &DesiredViewportBinding {
                    primary_session_id: "s".to_string(),
                    primary_expected_generation: SessionGeneration("pty-b".to_string()),
                    primary_dims: None,
                    panes: Vec::new(),
                },
                &["s".to_string()],
                None,
            )
            .expect("same-id B rebind admits");
        server_tx.send(ServerCommand::ReadRebind).unwrap();
        let generation_b = match status_rx.recv_timeout(Duration::from_secs(3)).unwrap() {
            ServerStatus::Rebound(generation) => generation,
            _ => unreachable!(),
        };
        assert_eq!(token_b.primary().output_generation, generation_b);
        assert_ne!(generation_a, generation_b);
        let _ = recv_until(&event_rx, |event| matches!(event, UserEvent::Redraw));
        assert_eq!(
            shared
                .grid
                .lock()
                .unwrap()
                .as_ref()
                .map(|grid| grid.generation.0.as_str()),
            Some("pty-b")
        );

        server_tx.send(ServerCommand::SendStaleOversize).unwrap();
        assert!(matches!(
            status_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ServerStatus::StaleInert
        ));
        assert_eq!(
            shared
                .grid
                .lock()
                .unwrap()
                .as_ref()
                .map(|grid| grid.generation.0.as_str()),
            Some("pty-b"),
            "stale oversized A cannot perturb B's SyncState or paint cache"
        );
        server_tx.send(ServerCommand::Close).unwrap();
        server.join().unwrap();
        let _ = fs::remove_file(path);
    }

    #[test]
    fn output_generation_and_active_epoch_exhaustion_never_publish_or_preserve_authority() {
        let daemon_instance: maestro_shell::DaemonInstanceId =
            "44444444444444448444444444444444".parse().unwrap();
        let shared = Shared::with_test_handoff_peer_facts(Some(daemon_instance), None);
        shared
            .next_output_generation
            .store(u64::MAX, Ordering::Release);
        assert!(matches!(
            shared.try_bind_viewport(
                &DesiredViewportBinding {
                    primary_session_id: "never-bound".to_string(),
                    primary_expected_generation: SessionGeneration("never-generation".to_string()),
                    primary_dims: Some((80, 24)),
                    panes: Vec::new(),
                },
                &[],
                None,
            ),
            Err(ActiveBindFailure::AuthorityExhausted)
        ));
        assert!(shared.active_snapshot().id.is_none());
        assert!(shared.drain_test_requests().is_empty());

        let shared = Shared::with_test_outbound();
        let active = shared.init_active_session("old").unwrap();
        assert!(shared.commit_active_grid(&active, Revision(1), Arc::new(grid("pty-old", 1))));
        shared.set_sibling_session("sibling").unwrap();
        shared.set_pane_sessions(&["pane"]).unwrap();
        shared.active.lock().unwrap().epoch = u64::MAX;
        assert!(shared.set_active_session("new").is_none());
        assert!(shared.active_snapshot().id.is_none());
        assert!(shared.grid.lock().unwrap().is_none());
        assert!(shared.sibling_snapshot().id.is_none());
        assert!(shared.pane_ids().is_empty());
        assert!(shared.drain_test_requests().is_empty());

        // Clear is authority revocation even when no numeric successor exists. MAX remains a
        // terminal-neutral sentinel; it is never wrapped/reused for a later live incarnation.
        shared.clear_viewport();
        assert_eq!(shared.active.lock().unwrap().epoch, u64::MAX);
        assert!(shared.active_snapshot().id.is_none());
        assert!(shared.set_active_session("still-refused").is_none());
        assert!(shared.active_snapshot().id.is_none());
    }

    #[test]
    fn exact_three_route_viewport_is_one_all_or_none_generation_bound_batch() {
        let daemon_instance: maestro_shell::DaemonInstanceId =
            "33333333333343338333333333333333".parse().unwrap();
        let shared = Shared::with_test_handoff_peer_facts(Some(daemon_instance), None);
        let desired = DesiredViewportBinding {
            primary_session_id: "primary".to_string(),
            primary_expected_generation: SessionGeneration("gen-primary".to_string()),
            primary_dims: Some((120, 40)),
            panes: vec![
                DesiredPaneBinding {
                    session_id: "pane-b".to_string(),
                    expected_generation: SessionGeneration("gen-b".to_string()),
                    dims: Some((60, 40)),
                },
                DesiredPaneBinding {
                    session_id: "pane-c".to_string(),
                    expected_generation: SessionGeneration("gen-c".to_string()),
                    dims: Some((60, 40)),
                },
            ],
        };

        let binding = shared
            .try_bind_viewport(
                &desired,
                &[
                    "old-z".to_string(),
                    "old-a".to_string(),
                    "old-z".to_string(),
                ],
                None,
            )
            .expect("the complete exact cohort admits atomically");
        assert_eq!(binding.status(), ExactViewportAdmissionStatus::Pending);

        let requests = shared.drain_test_requests();
        assert_eq!(requests.len(), 8);
        assert!(matches!(
            &requests[0],
            ClientRequest::Detach { id } if id == "old-a"
        ));
        assert!(matches!(
            &requests[1],
            ClientRequest::Detach { id } if id == "old-z"
        ));

        let mut attaches = Vec::new();
        for pair in requests[2..].chunks_exact(2) {
            let ClientRequest::Attach {
                id,
                expected_session_generation: Some(expected_generation),
                output_generation: Some(output_generation),
                handoff: None,
                ..
            } = &pair[0]
            else {
                panic!("each route must begin with one exact Attach: {:?}", pair[0]);
            };
            assert!(matches!(
                &pair[1],
                ClientRequest::Snapshot { id: snapshot_id } if snapshot_id == id
            ));
            attaches.push((
                id.as_str(),
                expected_generation.as_str(),
                *output_generation,
            ));
        }
        assert_eq!(
            attaches
                .iter()
                .map(|(id, generation, _)| (*id, *generation))
                .collect::<Vec<_>>(),
            vec![
                ("primary", "gen-primary"),
                ("pane-b", "gen-b"),
                ("pane-c", "gen-c"),
            ]
        );
        let output_generations = attaches
            .iter()
            .map(|(_, _, output_generation)| *output_generation)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(output_generations.len(), 3);
        assert!(output_generations.iter().all(|generation| *generation != 0));
        assert!(requests
            .iter()
            .all(|request| !matches!(request, ClientRequest::Resize { .. })));

        let active = shared.active.lock().unwrap();
        assert_eq!(active.id.as_deref(), Some("primary"));
        assert_eq!(
            active
                .expected_generation
                .as_ref()
                .map(|generation| generation.0.as_str()),
            Some("gen-primary")
        );
        drop(active);
        for (id, expected) in [("pane-b", "gen-b"), ("pane-c", "gen-c")] {
            let stores = shared.stores.lock().unwrap();
            let pane = stores.get(id).expect("exact pane store");
            assert_eq!(
                pane.expected_generation
                    .as_ref()
                    .map(|generation| generation.0.as_str()),
                Some(expected)
            );
            assert!(pane.grid.is_none(), "no partial viewport is paintable");
        }
    }

    #[test]
    fn exact_viewport_refuses_missing_capability_or_duplicate_role_before_wire() {
        let desired = DesiredViewportBinding {
            primary_session_id: "primary".to_string(),
            primary_expected_generation: SessionGeneration("gen-primary".to_string()),
            primary_dims: None,
            panes: vec![DesiredPaneBinding {
                session_id: "pane".to_string(),
                expected_generation: SessionGeneration("gen-pane".to_string()),
                dims: None,
            }],
        };
        let unsupported = Shared::with_test_outbound();
        assert!(matches!(
            unsupported.try_bind_viewport(&desired, &[], None),
            Err(ActiveBindFailure::HandoffPeerMismatch)
        ));
        assert!(unsupported.drain_test_requests().is_empty());
        assert!(unsupported.active_snapshot().id.is_none());

        let daemon_instance: maestro_shell::DaemonInstanceId =
            "33333333333343338333333333333333".parse().unwrap();
        let supported = Shared::with_test_handoff_peer_facts(Some(daemon_instance), None);
        let duplicate = DesiredViewportBinding {
            primary_session_id: "same".to_string(),
            primary_expected_generation: SessionGeneration("gen-a".to_string()),
            primary_dims: None,
            panes: vec![DesiredPaneBinding {
                session_id: "same".to_string(),
                expected_generation: SessionGeneration("gen-b".to_string()),
                dims: None,
            }],
        };
        assert!(matches!(
            supported.try_bind_viewport(&duplicate, &[], None),
            Err(ActiveBindFailure::AuthorityExhausted)
        ));
        assert!(supported.drain_test_requests().is_empty());
        assert!(supported.active_snapshot().id.is_none());
    }

    #[test]
    fn pane_and_sibling_counter_exhaustion_revokes_caches_without_epoch_collision() {
        let shared = Shared::with_test_outbound();
        shared.init_active_session("primary").unwrap();

        shared.set_sibling_session("old-sibling").unwrap();
        *shared.sibling_epoch.lock().unwrap() = u64::MAX;
        assert!(shared.set_sibling_session("new-sibling").is_none());
        assert!(shared.sibling_snapshot().id.is_none());
        assert!(shared
            .stores
            .lock()
            .unwrap()
            .values()
            .all(|entry| entry.kind != PaneKind::Sibling));
        shared.clear_sibling_session();
        assert_eq!(*shared.sibling_epoch.lock().unwrap(), u64::MAX);

        shared.set_pane_sessions(&["old-pane"]).unwrap();
        *shared.pane_generation.lock().unwrap() = u64::MAX;
        shared.clear_pane_sessions();
        assert!(shared.pane_ids().is_empty());
        assert_eq!(*shared.pane_generation.lock().unwrap(), u64::MAX);
        assert!(shared.set_pane_sessions(&["new-pane"]).is_none());
        assert!(shared.pane_ids().is_empty());

        let shared = Shared::with_test_outbound();
        shared.init_active_session("primary").unwrap();
        shared.next_pane_epoch.store(u64::MAX, Ordering::Release);
        assert!(shared.set_pane_sessions(&["never-authorized"]).is_none());
        assert!(shared.pane_ids().is_empty());
        assert_eq!(shared.next_pane_epoch.load(Ordering::Acquire), u64::MAX);
    }

    #[test]
    fn reader_reconcile_uses_full_binding_when_saturated_epoch_is_numerically_equal() {
        let shared = Shared::with_test_outbound();
        {
            let mut active = shared.active.lock().unwrap();
            active.id = Some("new".to_string());
            active.epoch = u64::MAX;
            active.output_generation = Some(22);
        }
        let mut session_id = Some("old".to_string());
        let mut sync = Some(RoutedSyncState::new("old".to_string(), 11, false));
        let mut local_epoch = u64::MAX;
        let mut retired = RetiredExitBindings::default();

        assert!(sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut local_epoch,
            &mut retired,
        ));
        assert_eq!(session_id.as_deref(), Some("new"));
        assert_eq!(sync.as_ref().map(|state| state.output_generation), Some(22));
        assert!(retired.by_output_generation.contains_key(&11));
        assert_eq!(local_epoch, u64::MAX);
    }

    #[test]
    fn unattributable_bad_envelope_fails_closed_before_later_buffered_effect() {
        let path = socket_path("bad-envelope");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept renderer");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let generation = read_initial_plan(&mut reader, &mut stream);
            stream
                .write_all(
                    format!(
                        "not-json\n{{\"ev\":\"terminal_bell\",\"id\":\"s\",\"live_output_generation\":{generation}}}\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let (tx, rx) = mpsc::channel();
        let shared = spawn_exact_test_client(
            path.to_string_lossy().into_owned(),
            "s",
            "pty-a",
            Box::new(ChannelSender(tx)),
        );
        let observed = recv_until(&rx, |event| matches!(event, UserEvent::ConnectionClosed));
        server.join().unwrap();
        let _ = fs::remove_file(path);
        assert_terminally_neutral(&shared, &observed);
    }

    #[test]
    fn stateful_damage_envelope_missing_frame_id_fails_closed() {
        let path = socket_path("damage-missing-id");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept renderer");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let generation = read_initial_plan(&mut reader, &mut stream);
            stream
                .write_all(
                    format!(
                        "{{\"ev\":\"damage\",\"frame\":{{\"bad\":true}}}}\n{{\"ev\":\"terminal_bell\",\"id\":\"s\",\"live_output_generation\":{generation}}}\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let (tx, rx) = mpsc::channel();
        let shared = spawn_exact_test_client(
            path.to_string_lossy().into_owned(),
            "s",
            "pty-a",
            Box::new(ChannelSender(tx)),
        );
        let observed = recv_until(&rx, |event| matches!(event, UserEvent::ConnectionClosed));
        server.join().unwrap();
        let _ = fs::remove_file(path);
        assert_terminally_neutral(&shared, &observed);
    }

    #[test]
    fn exact_confirmed_untagged_malformed_grid_is_terminal_and_stops_buffered_effects() {
        let path = socket_path("bad-grid");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept renderer");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let generation = read_initial_plan(&mut reader, &mut stream);
            write_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("pty-a", 1),
                },
                Some(generation),
            );
            stream
                .write_all(
                    format!(
                        "{{\"ev\":\"grid\",\"id\":\"s\",\"grid\":{{\"bad\":true}}}}\n{{\"ev\":\"terminal_bell\",\"id\":\"s\",\"live_output_generation\":{generation}}}\n"
                    )
                    .as_bytes(),
                )
                .unwrap();
        });
        let (tx, rx) = mpsc::channel();
        let shared = spawn_exact_test_client(
            path.to_string_lossy().into_owned(),
            "s",
            "pty-a",
            Box::new(ChannelSender(tx)),
        );
        let observed = recv_until(&rx, |event| matches!(event, UserEvent::ConnectionClosed));
        server.join().unwrap();
        let _ = fs::remove_file(path);
        assert!(observed
            .iter()
            .any(|event| matches!(event, UserEvent::Redraw)));
        assert_terminally_neutral(&shared, &observed);
    }

    #[test]
    fn canonical_untagged_malformed_scrollback_reply_fails_closed() {
        let path = socket_path("bad-scrollback");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept renderer");
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let generation = read_initial_plan(&mut reader, &mut stream);
            write_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("pty-a", 1),
                },
                Some(generation),
            );
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Scrollback { id, .. } if id == "s"
            ));
            stream
                .write_all(b"{\"ev\":\"scrollback_rows\",\"id\":\"s\",\"rows\":\"bad\"}\n")
                .unwrap();
        });
        let (tx, rx) = mpsc::channel();
        let shared = spawn_exact_test_client(
            path.to_string_lossy().into_owned(),
            "s",
            "pty-a",
            Box::new(ChannelSender(tx)),
        );
        let _ = recv_until(&rx, |event| matches!(event, UserEvent::Redraw));
        let PreparedScrollAction::Moved {
            binding,
            request,
            count,
        } = shared.prepare_scroll_action("s", "s", ScrollAction::Lines(1))
        else {
            panic!("baseline permits one scroll request");
        };
        assert!(shared
            .send_request_batch_for_binding(
                &binding,
                &[ClientRequest::Scrollback {
                    id: "s".to_string(),
                    offset_from_top: request.requested_offset,
                    count,
                }],
                &request.expected_generation,
                Some(&request),
            )
            .is_some_and(RequestAdmission::is_admitted));
        let observed = recv_until(&rx, |event| matches!(event, UserEvent::ConnectionClosed));
        server.join().unwrap();
        let _ = fs::remove_file(path);
        assert_terminally_neutral(&shared, &observed);
    }

    #[test]
    fn initial_legacy_malformed_damage_recovers_then_malformed_grid_fails_closed() {
        let path = socket_path("legacy-recovery");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let server = thread::spawn(move || {
            let (mut probe, _) = listener.accept().expect("accept capability probe");
            probe
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut probe_reader = BufReader::new(probe.try_clone().unwrap());
            assert!(matches!(
                read_request(&mut probe_reader),
                ClientRequest::DaemonInfo
            ));
            write_event(
                &mut probe,
                DaemonEvent::DaemonInfo {
                    protocol_version: 2,
                    build_version: "retained-v2".into(),
                    daemon_instance_id: None,
                    output_generation_echo: false,
                    child_environment: false,
                    generation_conditional_mutations: false,
                    attachment_aware_conditional_kill: false,
                    generation_conditional_attach: false,
                },
                None,
            );

            probe
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut stream = probe;
            let mut reader = probe_reader;
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Attach {
                    id,
                    expected_session_generation: None,
                    handoff: None,
                    ..
                } if id == "s"
            ));
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Snapshot { id } if id == "s"
            ));
            write_event(
                &mut stream,
                DaemonEvent::Grid {
                    id: "s".to_string(),
                    grid: grid("legacy-pty", 1),
                },
                None,
            );
            stream
                .write_all(b"{\"ev\":\"damage\",\"frame\":{\"id\":\"s\",\"bad\":true}}\n")
                .unwrap();
            assert!(matches!(
                read_request(&mut reader),
                ClientRequest::Snapshot { id } if id == "s"
            ));
            stream
                .write_all(b"{\"ev\":\"grid\",\"id\":\"s\",\"grid\":{\"bad\":true}}\n")
                .unwrap();
        });
        let (tx, rx) = mpsc::channel();
        let shared = spawn(
            path.to_string_lossy().into_owned(),
            "s".to_string(),
            None,
            Box::new(ChannelSender(tx)),
        );
        let observed = recv_until(&rx, |event| matches!(event, UserEvent::ConnectionClosed));
        server.join().unwrap();
        let _ = fs::remove_file(path);
        assert!(observed
            .iter()
            .any(|event| matches!(event, UserEvent::Redraw)));
        assert_terminally_neutral(&shared, &observed);
    }

    #[test]
    fn fail_closed_teardown_recovers_poisoned_authority_grid_and_store_locks() {
        let (shared, queue) = Shared::with_test_queue();
        shared.init_active_session("s").unwrap();
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("pty-a", 1)));
        shared.set_pane_sessions(&["pane"]).unwrap();
        assert!(shared
            .send_request(&ClientRequest::Write {
                id: "s".to_string(),
                expected_generation: SessionGeneration("pty-a".into()),
                data: "queued-secret".to_string(),
            })
            .is_admitted());

        for poison in [
            {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    let _guard = shared.active.lock().unwrap();
                    panic!("poison active authority");
                })
            },
            {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    let _guard = shared.grid.lock().unwrap();
                    panic!("poison primary grid");
                })
            },
            {
                let shared = Arc::clone(&shared);
                thread::spawn(move || {
                    let _guard = shared.stores.lock().unwrap();
                    panic!("poison pane stores");
                })
            },
        ] {
            assert!(poison.join().is_err());
        }

        let (tx, rx) = mpsc::channel();
        let sender = ChannelSender(tx);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            shared.fail_closed_connection(&sender)
        }))
        .expect("terminal teardown must recover poison rather than panic");

        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            UserEvent::ConnectionClosed
        ));
        assert!(shared.active_snapshot().id.is_none());
        assert!(shared.grid.lock().unwrap().is_none());
        assert!(shared.stores.lock().unwrap().is_empty());
        assert!(
            queue.drain_requests().is_empty(),
            "queued secret was aborted"
        );
        assert!(matches!(
            shared.send_request(&ClientRequest::Snapshot {
                id: "s".to_string()
            }),
            RequestAdmission::Unavailable {
                reason: OutboundUnavailable::Closed,
                ..
            }
        ));

        // The connection latch remains exactly-once even after poison recovery.
        shared.fail_closed_connection(&sender);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn connection_latch_projects_neutral_before_teardown_can_acquire_active_lock() {
        let (shared, queue) = Shared::with_test_queue();
        let active_token = shared.init_active_session("s").unwrap();
        assert!(shared.commit_active_grid(&active_token, Revision(1), Arc::new(grid("pty-a", 1))));
        shared.set_pane_sessions(&["pane"]).unwrap();
        let pane_token = shared.binding_token_for_session("pane").unwrap();
        let active_binding = ViewportBindingToken::Active(active_token.clone());

        // Hold the authority mutex so terminal teardown must stop after publishing its atomic latch.
        let held_active = shared.active.lock().unwrap();
        let held_queue = queue.inner.lock().unwrap();
        let (tx, rx) = mpsc::channel();
        let closing = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || shared.fail_closed_connection(&ChannelSender(tx)))
        };
        let deadline = Instant::now() + Duration::from_secs(1);
        while !shared.connection_closed.load(Ordering::Acquire) {
            assert!(
                Instant::now() < deadline,
                "fail-close did not publish its latch"
            );
            thread::yield_now();
        }

        // Every new authority/paint/effect/input predicate observes neutral from the latch without
        // waiting for the deliberately-held mutex. Teardown will erase the physical leaves later.
        let started = Instant::now();
        assert!(shared.active_snapshot().id.is_none());
        assert!(shared.active_token().is_none());
        assert!(!shared.active_token_is_current(&active_token));
        assert!(!shared.viewport_token_is_current(&active_binding));
        assert!(!shared.viewport_token_is_current(&pane_token));
        assert!(shared.binding_token_for_session("s").is_none());
        assert!(shared.pane_paint("s", "s").paint_grid().is_none());
        assert!(!shared.commit_active_grid(
            &active_token,
            Revision(2),
            Arc::new(grid("must-not-commit", 2))
        ));
        assert!(matches!(
            shared.send_request(&ClientRequest::Write {
                id: "s".to_string(),
                expected_generation: SessionGeneration("pty-a".into()),
                data: "must-not-send".to_string(),
            }),
            RequestAdmission::Unavailable {
                reason: OutboundUnavailable::Closed,
                ..
            }
        ));
        assert!(started.elapsed() < Duration::from_millis(200));

        assert!(matches!(
            rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            UserEvent::ConnectionClosed
        ));
        assert!(rx.try_recv().is_err());

        drop(held_queue);
        // After the queue abort completes, teardown is still deliberately blocked on active.
        assert!(shared.active_snapshot().id.is_none());
        drop(held_active);
        closing.join().unwrap();
        assert!(rx.try_recv().is_err());
        assert!(shared.grid.lock().unwrap().is_none());
        assert!(shared.stores.lock().unwrap().is_empty());
    }

    #[test]
    fn active_snapshot_that_prechecked_before_fail_close_cannot_return_stale_authority() {
        let (shared, _queue) = Shared::with_test_queue();
        shared.init_active_session("s").unwrap();

        let held_active = shared.active.lock().unwrap();
        let (prechecked_tx, prechecked_rx) = mpsc::channel();
        let snapshot = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                shared.active_snapshot_with_prelock_hook(|| prechecked_tx.send(()).unwrap())
            })
        };
        prechecked_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("snapshot passed its initial latch check before blocking on active");

        let (event_tx, event_rx) = mpsc::channel();
        let closing = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || shared.fail_closed_connection(&ChannelSender(event_tx)))
        };
        assert!(matches!(
            event_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
            UserEvent::ConnectionClosed
        ));
        assert!(shared.connection_is_closed());

        drop(held_active);
        assert!(
            snapshot.join().unwrap().id.is_none(),
            "the post-lock latch check must erase authority captured after fail-close"
        );
        closing.join().unwrap();
        assert!(event_rx.try_recv().is_err());
    }

    #[test]
    fn active_scroll_intent_captured_on_generation_a_cannot_be_admitted_after_b() {
        let (shared, queue) = Shared::with_test_queue();
        let token = shared.init_active_session("s").unwrap();
        assert!(shared.commit_active_grid(&token, Revision(1), Arc::new(grid("pty-a", 1))));
        let PreparedScrollAction::Moved {
            binding,
            request,
            count,
        } = shared.prepare_scroll_action("s", "s", ScrollAction::Lines(1))
        else {
            panic!("generation A produces one scroll intent");
        };

        // Deterministic pause point: the gesture already mutated A's view, but queue admission has
        // not run. A live Grid rolls the exact binding to generation B and resets the viewport.
        assert!(shared.commit_active_grid(&token, Revision(1), Arc::new(grid("pty-b", 1))));
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);
        assert!(shared
            .send_request_batch_for_binding(
                &binding,
                &[ClientRequest::Scrollback {
                    id: "s".to_string(),
                    offset_from_top: request.requested_offset,
                    count,
                }],
                &request.expected_generation,
                Some(&request),
            )
            .is_none());
        assert!(queue.drain_requests().is_empty());
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);
    }

    #[test]
    fn pane_scroll_intent_captured_on_generation_a_cannot_be_admitted_after_b() {
        let (shared, queue) = Shared::with_test_queue();
        shared.init_active_session("primary").unwrap();
        shared.set_pane_sessions(&["pane"]).unwrap();
        let epoch = shared.pane_epoch("pane").unwrap();
        assert!(shared.apply_pane_grid("pane", epoch, Arc::new(grid("pty-a", 1))));
        let PreparedScrollAction::Moved {
            binding,
            request,
            count,
        } = shared.prepare_scroll_action("pane", "primary", ScrollAction::Lines(1))
        else {
            panic!("pane generation A produces one scroll intent");
        };

        assert!(shared.apply_pane_grid("pane", epoch, Arc::new(grid("pty-b", 1))));
        assert_eq!(
            shared.with_pane_scrollback("pane", "primary", |scrollback| scrollback.view_offset),
            0
        );
        assert!(shared
            .send_request_batch_for_binding(
                &binding,
                &[ClientRequest::Scrollback {
                    id: "pane".to_string(),
                    offset_from_top: request.requested_offset,
                    count,
                }],
                &request.expected_generation,
                Some(&request),
            )
            .is_none());
        assert!(queue.drain_requests().is_empty());
    }

    #[test]
    fn retained_owner_batch_generation_proof_drops_write_and_resize_after_pty_rollover() {
        let (shared, queue) = Shared::with_test_queue();
        let token = shared.init_active_session("s").unwrap();
        assert!(shared.commit_active_grid(&token, Revision(1), Arc::new(grid("pty-a", 1))));
        let binding = ViewportBindingToken::Active(token.clone());
        let expected = SessionGeneration("pty-a".to_string());

        assert!(shared.commit_active_grid(&token, Revision(1), Arc::new(grid("pty-b", 1))));
        assert!(shared
            .send_request_batch_for_binding(
                &binding,
                &[
                    ClientRequest::Write {
                        id: "s".to_string(),
                        expected_generation: expected.clone(),
                        data: "old-input".to_string(),
                    },
                    ClientRequest::Resize {
                        id: "s".to_string(),
                        expected_generation: expected.clone(),
                        cols: 80,
                        rows: 24,
                    },
                ],
                &expected,
                None,
            )
            .is_none());
        assert!(queue.drain_requests().is_empty());
    }
}

// ============================================================================
// Session-rebind tests (the single-renderer tab-switch primitive). These cover
// the pure switch-plan ordering, the reader-side `SyncState` rebind, and that a
// late old-session frame is rejected while the new session's baseline is accepted
// into a fresh `SyncState`. No window / event loop / socket is needed.
// ============================================================================
#[cfg(test)]
mod rebind_tests {
    use super::*;
    use crate::sync::{Reject, SyncPhase};

    struct SinkSender;

    impl UserEventSender for SinkSender {
        fn send(&self, _event: UserEvent) -> Result<(), UserEvent> {
            Ok(())
        }

        fn clone_sender(&self) -> Box<dyn UserEventSender> {
            Box::new(SinkSender)
        }
    }

    fn color() -> crate::wire::Color {
        crate::wire::Color::Named {
            name: crate::wire::NamedColor::Foreground,
        }
    }

    fn cell() -> Cell {
        Cell {
            text: "x".to_string(),
            fg: color(),
            bg: color(),
            bold: false,
            italic: false,
            underline: Default::default(),
            inverse: false,
            strikeout: false,
            dim: false,
            hidden: false,
            hyperlink: None,
            width: 1,
        }
    }

    fn grid(gen: &str, rev: u64) -> GridSnapshot {
        GridSnapshot {
            row_copy: None,
            version: crate::sync::SUPPORTED_VERSION,
            generation: SessionGeneration(gen.to_string()),
            revision: Revision(rev),
            base_revision: Revision(rev),
            cols: 2,
            rows: 1,
            rows_cells: vec![vec![cell(), cell()]],
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
            alt_screen: false,
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_report: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_sgr: false,
        }
    }

    fn admit_scrollback_query(
        shared: &Arc<Shared>,
        id: &str,
        primary_id: &str,
        action: ScrollAction,
        expected_offset: u32,
    ) {
        let PreparedScrollAction::Moved {
            binding,
            request,
            count,
        } = shared.prepare_scroll_action(id, primary_id, action)
        else {
            panic!("scroll action for {id} must produce one exact query");
        };
        assert_eq!(request.requested_offset, expected_offset);
        let queued = ClientRequest::Scrollback {
            id: id.to_string(),
            offset_from_top: request.requested_offset,
            count,
        };
        let admission = shared
            .send_request_batch_for_binding(
                &binding,
                std::slice::from_ref(&queued),
                &request.expected_generation,
                Some(&request),
            )
            .expect("binding remains exact through admission");
        assert!(admission.is_admitted());
        assert_eq!(shared.drain_test_requests(), vec![queued]);
    }

    fn damage(id: &str, gen: &str, base: u64, rev: u64) -> crate::wire::DamageFrame {
        use crate::wire::{CursorState, DamageOp, ModeState};
        let mut blank = cell();
        blank.text = " ".to_string();
        crate::wire::DamageFrame {
            row_copy: None,
            schema: crate::wire::DAMAGE_SCHEMA,
            id: id.to_string(),
            generation: SessionGeneration(gen.to_string()),
            base_revision: Revision(base),
            revision: Revision(rev),
            cols: 2,
            rows: 1,
            cursor: CursorState {
                line: 0,
                col: 1,
                visible: true,
                shape: CursorShape::Block,
            },
            modes: ModeState {
                alt_screen: false,
                app_cursor: false,
                bracketed_paste: false,
                focus_reporting: false,
                mouse_report: false,
                mouse_drag: false,
                mouse_motion: false,
                mouse_sgr: false,
            },
            ops: vec![DamageOp::ClearAll { cell: blank }],
        }
    }

    // --- pure switch-plan ordering ------------------------------------------

    #[test]
    fn switch_plan_with_dims_is_read_only_detach_attach_snapshot_in_order() {
        let plan = plan_attach_switch("old", "new", Some((120, 40)), 77);
        assert_eq!(plan.len(), 3);
        match &plan[0] {
            ClientRequest::Detach { id } => assert_eq!(id, "old"),
            other => panic!("first request must be Detach{{old}}, got {other:?}"),
        }
        match &plan[1] {
            ClientRequest::Attach {
                id,
                want_raw_output,
                output_generation,
                handoff,
                ..
            } => {
                assert_eq!(id, "new");
                assert!(!want_raw_output, "switch attach must be structured-only");
                assert_eq!(*output_generation, Some(77));
                assert!(handoff.is_none());
            }
            other => panic!("second request must be Attach{{new}}, got {other:?}"),
        }
        match &plan[2] {
            ClientRequest::Snapshot { id } => assert_eq!(id, "new"),
            other => panic!("third request must be Snapshot{{new}}, got {other:?}"),
        }
        assert!(!plan.iter().any(Shared::request_is_terminal_mutation));
    }

    #[test]
    fn switch_plan_never_emits_an_empty_detach_id() {
        let plan = plan_attach_switch("", "new", None, 77);
        assert_eq!(plan.len(), 2);
        assert!(matches!(
            &plan[0],
            ClientRequest::Attach { id, output_generation: Some(77), .. } if id == "new"
        ));
        assert!(matches!(
            &plan[1],
            ClientRequest::Snapshot { id } if id == "new"
        ));
        assert!(!plan
            .iter()
            .any(|request| matches!(request, ClientRequest::Detach { id } if id.is_empty())));
    }

    #[test]
    fn switch_plan_without_dims_omits_resize() {
        let plan = plan_attach_switch("old", "new", None, 78);
        assert_eq!(plan.len(), 3, "no geometry omits Resize but keeps baseline");
        assert!(matches!(&plan[0], ClientRequest::Detach { id } if id == "old"));
        assert!(
            matches!(&plan[1], ClientRequest::Attach { id, want_raw_output, output_generation: Some(78), .. } if id == "new" && !*want_raw_output)
        );
        assert!(matches!(&plan[2], ClientRequest::Snapshot { id } if id == "new"));
    }

    #[test]
    fn legacy_snapshot_boundary_orphans_are_repaired_before_strict_sync_validation() {
        let mut snap = grid("g", 1);
        snap.rows_cells[0][0].text.clear();
        snap.rows_cells[0][0].width = 0;
        snap.rows_cells[0][1].text = "中".to_string();
        snap.rows_cells[0][1].width = 2;

        assert_eq!(
            SyncState::new("sid").on_grid("sid", &snap),
            Err(Reject::InvalidWideLayout { row: 0, col: 0 }),
            "the unmodified legacy snapshot demonstrates the retained-daemon failure"
        );
        assert_eq!(normalize_legacy_snapshot_wide_boundaries(&mut snap), 2);
        assert_eq!(
            (
                snap.rows_cells[0][0].text.as_str(),
                snap.rows_cells[0][0].width
            ),
            (" ", 1)
        );
        assert_eq!(
            (
                snap.rows_cells[0][1].text.as_str(),
                snap.rows_cells[0][1].width
            ),
            (" ", 1)
        );
        assert!(
            SyncState::new("sid").on_grid("sid", &snap).is_ok(),
            "the narrow boundary repair must restore a valid authoritative baseline"
        );
    }

    #[test]
    fn legacy_snapshot_compatibility_leaves_valid_wide_pairs_byte_for_byte_unchanged() {
        let mut snap = grid("g", 1);
        snap.rows_cells[0][0].text = "中".to_string();
        snap.rows_cells[0][0].width = 2;
        snap.rows_cells[0][1].text.clear();
        snap.rows_cells[0][1].width = 0;
        let before = snap.rows_cells.clone();

        assert_eq!(normalize_legacy_snapshot_wide_boundaries(&mut snap), 0);
        assert_eq!(snap.rows_cells, before);
        assert!(SyncState::new("sid").on_grid("sid", &snap).is_ok());
    }

    #[test]
    fn legacy_snapshot_compatibility_does_not_hide_interior_wide_corruption() {
        let mut snap = grid("g", 1);
        snap.cols = 3;
        snap.rows_cells[0].push(cell());
        snap.rows_cells[0][1].text = "中".to_string();
        snap.rows_cells[0][1].width = 2;

        assert_eq!(normalize_legacy_snapshot_wide_boundaries(&mut snap), 0);
        assert_eq!(
            SyncState::new("sid").on_grid("sid", &snap),
            Err(Reject::InvalidWideLayout { row: 0, col: 1 })
        );
    }

    // --- active-session state + reader rebind --------------------------------

    #[test]
    fn set_active_session_bumps_epoch_and_swaps_id() {
        let shared = Arc::new(Shared::default());
        let old = shared.init_active_session("s-old").unwrap();
        let before = shared.active_snapshot();
        assert_eq!(
            before,
            ActiveSession {
                id: Some("s-old".into()),
                epoch: old.epoch,
                output_generation: Some(old.output_generation),
                expected_generation: None,
            }
        );

        let token = shared.set_active_session("s-new").unwrap();
        assert_eq!(token.epoch, old.epoch + 1);
        assert_eq!(
            shared.active_snapshot(),
            ActiveSession {
                id: Some("s-new".into()),
                epoch: token.epoch,
                output_generation: Some(token.output_generation),
                expected_generation: None,
            }
        );
    }

    #[test]
    fn sync_active_session_rebinds_reader_id_and_sync_and_resets_state() {
        let shared = Arc::new(Shared::default());
        let old = shared.init_active_session("s-old").unwrap();

        // The reader's thread-locals, as in `spawn`.
        let mut session_id = Some("s-old".to_string());
        let mut sync = Some(RoutedSyncState::new(
            "s-old".to_string(),
            old.output_generation,
            true,
        ));
        let mut epoch = old.epoch;
        let mut retired = RetiredExitBindings::default();

        // Bring the old session to Synchronized and seed shared state that a switch
        // must clear so stale rows can't paint as the new session.
        sync.as_mut()
            .unwrap()
            .sync
            .on_grid("s-old", &grid("gen-old", 100))
            .unwrap();
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-old", 100)));
        *shared.exited.lock().unwrap() = Some(Some(0));
        shared.scrollback.lock().unwrap().view_offset = 5;

        // No switch yet: a sync is a no-op.
        assert!(!sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut epoch,
            &mut retired,
        ));

        // The UI thread switches.
        shared.set_active_session("s-new");
        assert!(sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut epoch,
            &mut retired,
        ));

        // Reader thread-locals now follow the new session.
        assert_eq!(session_id.as_deref(), Some("s-new"));
        assert_eq!(epoch, shared.active_snapshot().epoch);
        assert_eq!(
            sync.as_ref().unwrap().sync.phase(),
            SyncPhase::AwaitingBaseline
        );

        // Shared published state was reset (no stale old-session rows survive).
        assert!(shared.grid.lock().unwrap().is_none());
        assert!(shared.exited.lock().unwrap().is_none());
        assert!(shared.last_revision.lock().unwrap().is_none());
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);
    }

    #[test]
    fn old_session_frame_rejected_and_new_session_baseline_accepted_after_switch() {
        let shared = Arc::new(Shared::default());
        let old = shared.init_active_session("s-old").unwrap();
        let mut session_id = Some("s-old".to_string());
        let mut sync = Some(RoutedSyncState::new(
            "s-old".to_string(),
            old.output_generation,
            true,
        ));
        let mut epoch = old.epoch;
        let mut retired = RetiredExitBindings::default();
        sync.as_mut()
            .unwrap()
            .sync
            .on_grid("s-old", &grid("gen-old", 100))
            .unwrap();

        // Switch to the new session; the reader rebases on its next event.
        shared.set_active_session("s-new");
        sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut epoch,
            &mut retired,
        );

        // A LATE frame still tagged with the old session id is rejected — it cannot
        // repaint over the new session.
        let stale = sync
            .as_mut()
            .unwrap()
            .sync
            .on_grid("s-old", &grid("gen-old", 101));
        assert_eq!(stale, Err(Reject::WrongSession));

        // The new session's baseline is accepted into the fresh `SyncState`.
        let outcome = sync
            .as_mut()
            .unwrap()
            .sync
            .on_grid("s-new", &grid("gen-new", 1))
            .expect("new-session baseline must be accepted");
        assert!(outcome.repaint, "the new baseline must paint");
        assert_eq!(sync.as_ref().unwrap().sync.phase(), SyncPhase::Synchronized);
    }

    #[test]
    fn pane_to_active_promotion_reader_reconcile_cannot_detach_or_freeze_new_primary() {
        let (shared, queue) = Shared::with_test_queue();
        let old = shared.init_active_session("C").unwrap();

        // SetTabStrip arrives before AttachSession: while C is still primary, the just-created D is
        // temporarily a non-primary pane member. The UI owns its Attach; reader adoption is local.
        shared.set_pane_sessions(&["A", "B", "D"]);
        let mut pane_syncs = HashMap::new();
        let mut pane_generation = 0;
        let mut retired = RetiredExitBindings::default();
        assert!(sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut pane_generation,
            &mut retired,
        ));
        assert!(pane_syncs.contains_key("D"));
        assert!(queue.drain_requests().is_empty());

        // AttachSession promotes D. The next role reconcile demotes C into the cache and removes D's
        // old Pane role. Before the fix, this reader path emitted Detach(D), cancelling the active
        // daemon forwarder and leaving D frozen at its initial blank baseline.
        shared.set_active_session("D");
        shared.set_pane_sessions(&["A", "B", "C"]);
        let mut active_id = Some("C".to_string());
        let mut active_sync = Some(RoutedSyncState::new(
            "C".to_string(),
            old.output_generation,
            true,
        ));
        let mut active_epoch = old.epoch;
        assert!(sync_active_session(
            &shared,
            &mut active_id,
            &mut active_sync,
            &mut active_epoch,
            &mut retired,
        ));
        assert!(sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut pane_generation,
            &mut retired,
        ));
        assert_eq!(active_id.as_deref(), Some("D"));
        assert!(!pane_syncs.contains_key("D"));
        assert!(pane_syncs.contains_key("C"));
        assert!(
            queue.drain_requests().is_empty(),
            "reader role transition must never emit the fatal Detach(D)"
        );

        // With the active subscription left alive, both its baseline and subsequent structured
        // damage continue through the dedicated primary grid.
        handle_event_for_binding(
            &shared,
            &mut active_sync.as_mut().unwrap().sync,
            &SinkSender,
            &shared.active_token().unwrap(),
            DaemonEvent::Grid {
                id: "D".to_string(),
                grid: grid("gen-D", 1),
            },
        );
        handle_event_for_binding(
            &shared,
            &mut active_sync.as_mut().unwrap().sync,
            &SinkSender,
            &shared.active_token().unwrap(),
            DaemonEvent::Damage {
                frame: damage("D", "gen-D", 1, 2),
            },
        );
        assert_eq!(
            shared
                .grid
                .lock()
                .unwrap()
                .as_ref()
                .map(|grid| grid.revision),
            Some(Revision(2)),
            "promoted D remains live after its old Pane role is removed"
        );
    }

    #[test]
    fn reset_session_state_clears_grid_exit_revision_scrollback() {
        let shared = Arc::new(Shared::default());
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("g", 1)));
        *shared.exited.lock().unwrap() = Some(Some(7));
        *shared.last_revision.lock().unwrap() = Some((Revision(9), Instant::now()));
        {
            let mut scrollback = shared.scrollback.lock().unwrap();
            scrollback.view_offset = 3;
            scrollback.history_len = Some(42);
            scrollback.historical_generation = Some(SessionGeneration("old-session".into()));
        }

        reset_session_state(&shared);

        assert!(shared.grid.lock().unwrap().is_none());
        assert!(shared.exited.lock().unwrap().is_none());
        assert!(shared.last_revision.lock().unwrap().is_none());
        let scrollback = shared.scrollback.lock().unwrap();
        assert_eq!(scrollback.view_offset, 0);
        assert_eq!(
            scrollback.history_len, None,
            "a new session must not inherit the old PTY's cached history ceiling"
        );
        assert!(scrollback.historical.is_none());
        assert!(scrollback.historical_generation.is_none());
    }

    // Reader-switch race: the reader rebases at the TOP of the loop, then
    // blocks in `read_until`. If the UI switches the active session WHILE the reader is
    // blocked, the just-read frame must be filtered against the NEW session. The reader
    // therefore rebases AGAIN after the read, before decode/handle. This test reproduces
    // the window: top-of-loop rebase runs first (no switch yet), then the UI switches
    // mid-block, then the new session's baseline arrives. Without the post-read rebase the
    // baseline would be wrongly rejected as `WrongSession`; with it, the baseline is
    // accepted.
    #[test]
    fn reader_rebases_after_blocked_read_then_accepts_new_baseline() {
        let shared = Arc::new(Shared::default());
        let old = shared.init_active_session("s-old").unwrap();
        let mut session_id = Some("s-old".to_string());
        let mut sync = Some(RoutedSyncState::new(
            "s-old".to_string(),
            old.output_generation,
            true,
        ));
        let mut epoch = old.epoch;
        let mut retired = RetiredExitBindings::default();
        sync.as_mut()
            .unwrap()
            .sync
            .on_grid("s-old", &grid("gen-old", 100))
            .unwrap();

        // Top-of-loop rebase: no switch yet, so it is a no-op and we stay on s-old.
        assert!(!sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut epoch,
            &mut retired,
        ));
        assert_eq!(session_id.as_deref(), Some("s-old"));

        // The reader is now "blocked in read_until". The UI switches the active session.
        shared.set_active_session("s-new");

        // A new-session baseline `Grid` is delivered. WITHOUT the post-read rebase the
        // reader is still bound to s-old, so the new baseline would be rejected:
        assert_eq!(
            sync.as_mut()
                .unwrap()
                .sync
                .on_grid("s-new", &grid("gen-new", 1)),
            Err(Reject::WrongSession),
            "control: pre-rebase the new baseline is rejected as wrong-session"
        );

        // The post-read rebase (the fix) runs before decode/handle of the just-read line.
        assert!(sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut epoch,
            &mut retired,
        ));
        assert_eq!(session_id.as_deref(), Some("s-new"));
        assert_eq!(
            sync.as_ref().unwrap().sync.phase(),
            SyncPhase::AwaitingBaseline
        );

        // Now the SAME just-read new-session baseline is accepted into the fresh state.
        let outcome = sync
            .as_mut()
            .unwrap()
            .sync
            .on_grid("s-new", &grid("gen-new", 1))
            .expect("post-rebase the new baseline must be accepted");
        assert!(outcome.repaint);
        assert_eq!(sync.as_ref().unwrap().sync.phase(), SyncPhase::Synchronized);
    }

    // UI-switch race: `App::attach_session` must clear the SHARED
    // published state immediately on the UI thread, before its `request_redraw`, so the
    // window cannot repaint stale old-session rows in the gap before the reader thread
    // wakes and rebases. This test mirrors the UI-thread mutation order from
    // `App::attach_session` (reset_session_state + set_active_session) and asserts the
    // shared state is already clear WITHOUT the reader having run `sync_active_session`.
    #[test]
    fn ui_switch_clears_shared_state_before_reader_runs() {
        let shared = Arc::new(Shared::default());
        let old = shared.init_active_session("s-old").unwrap();

        // Seed shared published state as if s-old were live and Synchronized.
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-old", 100)));
        *shared.exited.lock().unwrap() = Some(Some(0));
        *shared.last_revision.lock().unwrap() = Some((Revision(100), Instant::now()));
        shared.scrollback.lock().unwrap().view_offset = 5;

        // UI-thread switch path (matches `App::attach_session`): clear shared state
        // immediately, THEN bump the epoch. The reader has NOT run yet.
        reset_session_state(&shared);
        shared.set_active_session("s-new");

        // Shared state is already clear — a redraw in this gap paints nothing stale.
        assert!(shared.grid.lock().unwrap().is_none());
        assert!(shared.exited.lock().unwrap().is_none());
        assert!(shared.last_revision.lock().unwrap().is_none());
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);

        // The reader's later rebase is idempotent: it observes the epoch, rebinds, and
        // resetting again leaves the shared state clear (no panic, still empty).
        let mut session_id = Some("s-old".to_string());
        let mut sync = Some(RoutedSyncState::new(
            "s-old".to_string(),
            old.output_generation,
            true,
        ));
        let mut epoch = old.epoch;
        let mut retired = RetiredExitBindings::default();
        assert!(sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut epoch,
            &mut retired,
        ));
        assert_eq!(session_id.as_deref(), Some("s-new"));
        assert!(shared.grid.lock().unwrap().is_none());
        assert!(shared.exited.lock().unwrap().is_none());
    }

    // --- inactive-pane sibling session cache (attach + cache only) -----------

    #[test]
    fn sibling_attach_plan_is_read_only_without_detaching_active() {
        // First sibling (no prior sibling): Attach(new) then Snapshot(new) — and crucially NO
        // Detach of anything, so the active session is never disturbed by binding the sibling.
        let plan = plan_sibling_attach(None, "sib-1", Some((40, 12)), 81);
        assert_eq!(plan.len(), 2);
        assert!(
            matches!(&plan[0], ClientRequest::Attach { id, want_raw_output, output_generation: Some(81), .. } if id == "sib-1" && !*want_raw_output)
        );
        assert!(matches!(&plan[1], ClientRequest::Snapshot { id } if id == "sib-1"));
        assert!(
            !plan
                .iter()
                .any(|r| matches!(r, ClientRequest::Detach { .. })),
            "binding the first sibling must never detach (the active session stays attached)"
        );
    }

    #[test]
    fn sibling_replace_detaches_only_the_old_sibling_then_attaches_new() {
        // Replacing the sibling detaches the OLD SIBLING only (never the active session),
        // then attaches+snapshots the new sibling.
        let plan = plan_sibling_attach(Some("sib-old"), "sib-new", Some((30, 10)), 82);
        assert_eq!(plan.len(), 3);
        assert!(matches!(&plan[0], ClientRequest::Detach { id } if id == "sib-old"));
        assert!(
            matches!(&plan[1], ClientRequest::Attach { id, want_raw_output, output_generation: Some(82), .. } if id == "sib-new" && !*want_raw_output)
        );
        assert!(matches!(&plan[2], ClientRequest::Snapshot { id } if id == "sib-new"));
    }

    #[test]
    fn same_sibling_replan_defers_resize_until_generation_bound_owner_path() {
        let plan = plan_sibling_attach(Some("sib-1"), "sib-1", Some((50, 14)), 83);
        assert!(plan.is_empty());
    }

    #[test]
    fn changing_inactive_session_replaces_cache_and_ignores_late_old_sibling_frame() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active").unwrap();
        // Bind sibling A, cache a grid for it.
        let epoch_a = shared.set_sibling_session("sib-a").unwrap();
        assert!(shared.apply_sibling_grid("sib-a", epoch_a, Arc::new(grid("gen-a", 1))));
        assert!(shared.sibling_snapshot().grid.is_some());

        // Inactive pane changes to sibling B: cache is replaced (cleared) and epoch bumps.
        let epoch_b = shared.set_sibling_session("sib-b").unwrap();
        assert_ne!(epoch_a, epoch_b);
        let snap = shared.sibling_snapshot();
        assert_eq!(snap.id.as_deref(), Some("sib-b"));
        assert!(
            snap.grid.is_none(),
            "rebinding must clear the prior sibling grid"
        );

        // A late frame from the OLD sibling (its id AND its stale epoch) is dropped.
        assert!(!shared.apply_sibling_grid("sib-a", epoch_a, Arc::new(grid("gen-a", 2))));
        assert!(shared.sibling_snapshot().grid.is_none());

        // A frame for the current sibling at the current epoch is accepted.
        assert!(shared.apply_sibling_grid("sib-b", epoch_b, Arc::new(grid("gen-b", 1))));
        assert!(shared.sibling_snapshot().grid.is_some());
    }

    #[test]
    fn active_and_sibling_grids_update_independent_caches() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-active");
        let epoch = shared.set_sibling_session("s-sibling").unwrap();

        // An active-session grid lands in `shared.grid` and must NOT touch the sibling cache.
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-active", 1)));
        assert!(shared.grid.lock().unwrap().is_some());
        assert!(
            shared.sibling_snapshot().grid.is_none(),
            "an active-session frame must never populate the sibling cache"
        );

        // A sibling grid lands in the sibling cache and must NOT touch the active grid's revision.
        let before_active = shared.grid.lock().unwrap().clone();
        assert!(shared.apply_sibling_grid("s-sibling", epoch, Arc::new(grid("gen-sib", 7))));
        assert!(shared.sibling_snapshot().grid.is_some());
        let after_active = shared.grid.lock().unwrap().clone();
        assert!(
            Arc::ptr_eq(&before_active.unwrap(), &after_active.unwrap()),
            "a sibling frame must leave the active grid Arc untouched"
        );
    }

    #[test]
    fn clearing_sibling_does_not_disrupt_active_session() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-active");
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-active", 1)));
        *shared.exited.lock().unwrap() = Some(None);
        let active_before = shared.active_snapshot();

        // Bind then clear the sibling (split torn down): sibling cache empties, epoch bumps,
        // but the active session id/epoch/grid/exit are all untouched.
        shared.set_sibling_session("s-sibling");
        shared.clear_sibling_session();
        let snap = shared.sibling_snapshot();
        assert!(snap.id.is_none());
        assert!(snap.grid.is_none());

        assert_eq!(shared.active_snapshot(), active_before);
        assert!(shared.grid.lock().unwrap().is_some());
        assert_eq!(*shared.exited.lock().unwrap(), Some(None));
    }

    // --- sibling frame ingest (reader teaches the sibling cache) --------------
    //
    // `handle_sibling_event` needs a live `EventLoopProxy`, which can't be built without
    // an event loop in a unit test — so (like the active path) these exercise the exact
    // composable pieces the handler runs: `event_session_id` routing, `sync_sibling_session`
    // rebind, the sibling `SyncState` gate, and `apply_sibling_grid`/`apply_sibling_exit`.

    /// A `ClearAll` damage frame over the 2-col x 1-row shape `grid()` produces,
    /// advancing `base` -> `rev` for `gen`. Sized/shaped to apply cleanly onto a
    /// `grid(gen, base)` baseline so `on_damage` yields `Applied`.
    fn damage_frame(id: &str, gen: &str, base: u64, rev: u64) -> crate::wire::DamageFrame {
        use crate::wire::{CursorState, DamageOp, ModeState};
        crate::wire::DamageFrame {
            row_copy: None,
            schema: crate::wire::DAMAGE_SCHEMA,
            id: id.to_string(),
            generation: SessionGeneration(gen.to_string()),
            base_revision: Revision(base),
            revision: Revision(rev),
            cols: 2,
            rows: 1,
            cursor: CursorState {
                line: 0,
                col: 0,
                visible: true,
                shape: CursorShape::Block,
            },
            modes: ModeState {
                alt_screen: false,
                app_cursor: false,
                bracketed_paste: false,
                focus_reporting: false,
                mouse_report: false,
                mouse_drag: false,
                mouse_motion: false,
                mouse_sgr: false,
            },
            ops: vec![DamageOp::ClearAll {
                cell: Cell {
                    text: " ".to_string(),
                    width: 1,
                    ..cell()
                },
            }],
        }
    }

    #[test]
    fn sibling_grid_baseline_populates_sibling_cache_and_leaves_active_untouched() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-active");
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-active", 1)));
        let active_before = shared.grid.lock().unwrap().clone();

        let epoch = shared.set_sibling_session("s-sib").unwrap();
        let mut sync = SyncState::new("s-sib".to_string());

        // A sibling baseline Grid: gate through the sibling SyncState, then publish.
        let snap = grid("gen-sib", 5);
        let outcome = sync.on_grid("s-sib", &snap).expect("baseline accepted");
        assert!(outcome.repaint);
        assert!(shared.apply_sibling_grid("s-sib", epoch, Arc::new(snap)));

        // Sibling cache is populated; the active grid Arc is byte-for-byte untouched.
        assert!(shared.sibling_snapshot().grid.is_some());
        let after = shared.grid.lock().unwrap().clone();
        assert!(Arc::ptr_eq(&active_before.unwrap(), &after.unwrap()));
    }

    #[test]
    fn sibling_damage_updates_cache_only_after_sibling_baseline() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active").unwrap();
        let epoch = shared.set_sibling_session("s-sib").unwrap();
        let mut sync = SyncState::new("s-sib".to_string());

        // BEFORE baseline: the sibling cache holds no grid. `handle_sibling_event`'s
        // damage arm reads the cached grid and short-circuits when it is `None`, so a
        // pre-baseline damage frame can never produce a cached grid.
        assert!(shared.sibling_snapshot().grid.is_none());

        // Seed a baseline Grid into the cache (the only way `grid` becomes `Some`).
        let base = grid("gen-sib", 5);
        sync.on_grid("s-sib", &base).expect("baseline accepted");
        assert!(shared.apply_sibling_grid("s-sib", epoch, Arc::new(base)));
        let held = shared.sibling_snapshot().grid.clone().unwrap();

        // AFTER baseline: a damage frame applies onto the cached grid and advances it.
        let frame = damage_frame("s-sib", "gen-sib", 5, 6);
        match sync.on_damage(&frame.id, &frame, &held) {
            DamageOutcome::Applied(g) => {
                assert!(shared.apply_sibling_grid("s-sib", epoch, Arc::from(g)));
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        assert_eq!(
            shared.sibling_snapshot().grid.unwrap().revision,
            Revision(6)
        );
    }

    #[test]
    fn late_old_sibling_frame_ignored_after_sibling_epoch_changes() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active").unwrap();
        let epoch_a = shared.set_sibling_session("sib-a").unwrap();

        // The inactive pane changes to sibling B (epoch bumps, cache cleared).
        let epoch_b = shared.set_sibling_session("sib-b").unwrap();
        assert_ne!(epoch_a, epoch_b);

        // A late Grid from the OLD sibling routes by id, but `apply_sibling_grid` drops it:
        // both its id (sib-a) and its stale epoch fail the live binding gate.
        assert!(!shared.apply_sibling_grid("sib-a", epoch_a, Arc::new(grid("gen-a", 9))));
        assert!(shared.sibling_snapshot().grid.is_none());

        // The current sibling's frame at the current epoch is accepted.
        assert!(shared.apply_sibling_grid("sib-b", epoch_b, Arc::new(grid("gen-b", 1))));
        assert!(shared.sibling_snapshot().grid.is_some());
    }

    #[test]
    fn sibling_session_exited_updates_exit_state() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active").unwrap();
        let epoch = shared.set_sibling_session("s-sib").unwrap();
        let mut sync = SyncState::new("s-sib".to_string());
        // A baseline so the SyncState is past AwaitingBaseline before the exit.
        sync.on_grid("s-sib", &grid("gen-sib", 1)).unwrap();

        assert!(matches!(
            sync.on_session_exited("s-sib"),
            Ok(Action::Exited)
        ));
        assert!(shared.apply_sibling_exit("s-sib", epoch, Some(0)));

        let snap = shared.sibling_snapshot();
        assert_eq!(snap.exited, Some(Some(0)));
        // The active session's exit state is untouched.
        assert!(shared.exited.lock().unwrap().is_none());
    }

    #[test]
    fn late_old_sibling_exit_ignored_after_epoch_change() {
        let shared = Arc::new(Shared::default());
        let epoch_a = shared.set_sibling_session("sib-a").unwrap();
        shared.set_sibling_session("sib-b"); // rebind: epoch bumps, exit cleared
        assert!(!shared.apply_sibling_exit("sib-a", epoch_a, Some(1)));
        assert!(shared.sibling_snapshot().exited.is_none());
    }

    #[test]
    fn event_session_id_routes_frames_to_active_vs_sibling() {
        // Frames carry the id used for routing; Error/Other carry none.
        assert_eq!(
            event_session_id(&DaemonEvent::Grid {
                id: "x".into(),
                grid: grid("g", 1)
            }),
            Some("x")
        );
        assert_eq!(
            event_session_id(&DaemonEvent::Damage {
                frame: damage_frame("y", "g", 1, 2)
            }),
            Some("y")
        );
        assert_eq!(
            event_session_id(&DaemonEvent::SessionExited {
                id: "z".into(),
                code: None
            }),
            Some("z")
        );
        assert_eq!(
            event_session_id(&DaemonEvent::Error {
                message: "boom".into()
            }),
            None
        );
        assert_eq!(event_session_id(&DaemonEvent::Other), None);
    }

    #[test]
    fn sync_sibling_session_rebinds_on_epoch_change_and_drops_on_unbind() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active").unwrap();
        let mut sib_id: Option<String> = None;
        let mut sib_sync: Option<RoutedSyncState> = None;
        let mut local_epoch = 0u64;
        let mut retired = RetiredExitBindings::default();

        // No sibling yet (epoch 0 default): no rebind.
        assert!(!sync_sibling_session(
            &shared,
            &mut sib_id,
            &mut sib_sync,
            &mut local_epoch,
            &mut retired,
        ));
        assert!(sib_sync.is_none());

        // UI binds a sibling: the reader adopts it (fresh SyncState, AwaitingBaseline).
        shared.set_sibling_session("s-sib");
        assert!(sync_sibling_session(
            &shared,
            &mut sib_id,
            &mut sib_sync,
            &mut local_epoch,
            &mut retired,
        ));
        assert_eq!(sib_id.as_deref(), Some("s-sib"));
        assert!(sib_sync.is_some());

        // Unbind (split torn down): the reader drops the sibling SyncState so no frames ingest.
        shared.clear_sibling_session();
        assert!(sync_sibling_session(
            &shared,
            &mut sib_id,
            &mut sib_sync,
            &mut local_epoch,
            &mut retired,
        ));
        assert!(sib_id.is_none());
        assert!(sib_sync.is_none());
    }

    // --- multi-pane session cache (N non-active panes; attach + cache only) ---

    #[test]
    fn three_pane_membership_binds_a_cache_entry_per_non_active_pane() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active").unwrap();
        // A 3-pane layout's two non-active panes are bound as cache members; the generation bumps.
        let gen = shared.set_pane_sessions(&["pane-b", "pane-c"]).unwrap();
        assert!(gen > 0);
        let mut ids = shared.pane_ids();
        ids.sort();
        assert_eq!(ids, vec!["pane-b".to_string(), "pane-c".to_string()]);
        assert!(shared.pane_entry("pane-b").is_some());
        assert!(shared.pane_entry("pane-c").is_some());

        // Each member caches a grid INDEPENDENTLY, gated by its own epoch.
        let eb = shared.pane_epoch("pane-b").unwrap();
        let ec = shared.pane_epoch("pane-c").unwrap();
        assert!(shared.apply_pane_grid("pane-b", eb, Arc::new(grid("gen-b", 1))));
        assert!(shared.apply_pane_grid("pane-c", ec, Arc::new(grid("gen-c", 1))));
        assert!(shared.pane_entry("pane-b").unwrap().grid.is_some());
        assert!(shared.pane_entry("pane-c").unwrap().grid.is_some());

        // A frame for an id that was never a member is dropped (no entry to write).
        assert!(!shared.apply_pane_grid("pane-x", 1, Arc::new(grid("gen-x", 1))));
    }

    #[test]
    fn removing_a_pane_clears_only_its_cache_entry() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active").unwrap();
        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        let eb = shared.pane_epoch("pane-b").unwrap();
        let ec = shared.pane_epoch("pane-c").unwrap();
        shared.apply_pane_grid("pane-b", eb, Arc::new(grid("gen-b", 1)));
        shared.apply_pane_grid("pane-c", ec, Arc::new(grid("gen-c", 1)));

        // Remove only pane-c (layout collapsed it). pane-b's entry + grid survive untouched;
        // pane-c's entry is gone and its epoch lookup returns None.
        shared.set_pane_sessions(&["pane-b"]);
        assert!(shared.pane_entry("pane-b").unwrap().grid.is_some());
        assert!(shared.pane_entry("pane-c").is_none());
        assert!(shared.pane_epoch("pane-c").is_none());
        // pane-b keeps the SAME epoch (it was never re-bound), so its in-flight frames still apply.
        assert_eq!(shared.pane_epoch("pane-b"), Some(eb));
        assert!(shared.apply_pane_grid("pane-b", eb, Arc::new(grid("gen-b", 2))));
        assert_eq!(
            shared.pane_entry("pane-b").unwrap().grid.unwrap().revision,
            Revision(2)
        );
    }

    #[test]
    fn late_frame_from_removed_or_replaced_pane_is_dropped() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active").unwrap();
        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        let ec_old = shared.pane_epoch("pane-c").unwrap();

        // Remove pane-c, then later re-add it (a pane replaced by a fresh session reusing the slot):
        // its epoch is bumped, so a frame stamped with the OLD epoch is dropped, while a frame at the
        // NEW epoch is accepted.
        shared.set_pane_sessions(&["pane-b"]);
        assert!(!shared.apply_pane_grid("pane-c", ec_old, Arc::new(grid("gen-c", 9))));

        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        let ec_new = shared.pane_epoch("pane-c").unwrap();
        assert_ne!(ec_old, ec_new);
        assert!(!shared.apply_pane_grid("pane-c", ec_old, Arc::new(grid("gen-c", 10))));
        assert!(shared.apply_pane_grid("pane-c", ec_new, Arc::new(grid("gen-c", 11))));

        // A late EXIT from the stale epoch is likewise dropped; the live epoch is recorded.
        assert!(!shared.apply_pane_exit("pane-c", ec_old, Some(1)));
        assert!(shared.apply_pane_exit("pane-c", ec_new, Some(0)));
        assert_eq!(shared.pane_entry("pane-c").unwrap().exited, Some(Some(0)));
    }

    #[test]
    fn unchanged_membership_does_not_bump_generation_and_clear_empties_cache() {
        let shared = Arc::new(Shared::default());
        let g1 = shared.set_pane_sessions(&["pane-b", "pane-c"]).unwrap();
        // Re-binding the SAME set is a no-op: the generation does not move.
        let g2 = shared.set_pane_sessions(&["pane-c", "pane-b"]).unwrap();
        assert_eq!(g1, g2);
        // clear_pane_sessions empties the cache and bumps the generation.
        shared.clear_pane_sessions();
        assert!(shared.pane_ids().is_empty());
        assert!(shared.pane_generation() > g2);
    }

    #[test]
    fn pane_cache_is_independent_of_active_and_sibling_caches() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-active");
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-active", 1)));
        shared.set_sibling_session("s-sib");
        shared.set_pane_sessions(&["pane-b"]);

        // A pane frame never touches the active grid nor the rendered sibling.
        let eb = shared.pane_epoch("pane-b").unwrap();
        assert!(shared.apply_pane_grid("pane-b", eb, Arc::new(grid("gen-b", 1))));
        assert!(shared.grid.lock().unwrap().is_some());
        assert!(shared.sibling_snapshot().grid.is_none());
        assert!(shared.pane_entry("pane-b").unwrap().grid.is_some());
    }

    #[test]
    fn sibling_scrollback_rows_update_sibling_view_state() {
        let shared = Shared::with_test_outbound();
        shared.init_active_session("s-active").unwrap();
        let epoch = shared.set_sibling_session("s-sib").unwrap();
        assert!(shared.apply_sibling_grid("s-sib", epoch, Arc::new(grid("gen-sib", 1))));
        shared.with_pane_scrollback("s-sib", "s-active", |sb| {
            sb.history_len = Some(20);
        });
        admit_scrollback_query(&shared, "s-sib", "s-active", ScrollAction::Lines(3), 3);

        assert!(shared.apply_sibling_scrollback(
            "s-sib",
            epoch,
            SessionGeneration("gen-sib".to_string()),
            Revision(2),
            20,
            3,
            vec![vec![cell(), cell()]],
        ));
        let paint = shared.pane_paint("s-sib", "s-active");
        assert_eq!(paint.scrolled_offset, 3);
        assert!(paint.historical.is_some());
    }

    #[test]
    fn extra_pane_scrollback_rows_update_that_pane_only() {
        let shared = Shared::with_test_outbound();
        shared.init_active_session("s-active").unwrap();
        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        let eb = shared.pane_epoch("pane-b").unwrap();
        let ec = shared.pane_epoch("pane-c").unwrap();
        assert!(shared.apply_pane_grid("pane-b", eb, Arc::new(grid("gen-b", 1))));
        assert!(shared.apply_pane_grid("pane-c", ec, Arc::new(grid("gen-c", 1))));
        shared.with_pane_scrollback("pane-b", "s-active", |sb| {
            sb.history_len = Some(30);
        });
        admit_scrollback_query(&shared, "pane-b", "s-active", ScrollAction::Lines(4), 4);

        assert!(shared.apply_pane_scrollback(
            "pane-b",
            eb,
            SessionGeneration("gen-b".to_string()),
            Revision(2),
            30,
            4,
            vec![vec![cell(), cell()]],
        ));
        let pane_b = shared.pane_paint("pane-b", "s-active");
        let pane_c = shared.pane_paint("pane-c", "s-active");
        assert_eq!(pane_b.scrolled_offset, 4);
        assert!(pane_b.historical.is_some());
        assert_eq!(pane_c.scrolled_offset, 0);
        assert!(pane_c.historical.is_none());
    }

    #[test]
    fn sync_pane_sessions_rebuilds_only_reader_state_on_generation_change() {
        let (shared, queue) = Shared::with_test_queue();
        shared.init_active_session("active").unwrap();
        let mut pane_syncs: HashMap<String, PaneSyncState> = HashMap::new();
        let mut local_generation = 0u64;
        let mut retired = RetiredExitBindings::default();

        // No panes yet: no rebuild.
        assert!(!sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut local_generation,
            &mut retired,
        ));
        assert!(pane_syncs.is_empty());

        // Bind two panes: the reader gains a fresh SyncState per id. The UI-side role reconcile is
        // the sole owner of daemon Attach/Detach, so this asynchronous reader emits no wire request.
        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        assert!(sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut local_generation,
            &mut retired,
        ));
        assert!(pane_syncs.contains_key("pane-b"));
        assert!(pane_syncs.contains_key("pane-c"));
        assert!(
            queue.drain_requests().is_empty(),
            "reader membership adoption must not duplicate UI-owned Attach"
        );

        // Re-reconcile with the SAME membership: the generation is unchanged so this is a no-op
        // (no rebuild, no new Attach — only NEW ids attach).
        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        assert!(!sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut local_generation,
            &mut retired,
        ));
        assert_eq!(
            queue.drain_requests().len(),
            0,
            "an unchanged pane membership re-attaches nothing"
        );

        // Remove pane-c: its reader-local SyncState is dropped, but no Detach is emitted here. This
        // is load-bearing for Pane -> Active promotion: a late reader reconcile must not cancel the
        // newly-active role's one daemon forwarder.
        shared.set_pane_sessions(&["pane-b"]);
        assert!(sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut local_generation,
            &mut retired,
        ));
        assert!(pane_syncs.contains_key("pane-b"));
        assert!(!pane_syncs.contains_key("pane-c"));
        assert!(
            queue.drain_requests().is_empty(),
            "reader membership removal must not duplicate UI-owned Detach"
        );
    }

    // --- Phase B: uniform per-pane paint resolution --------------------------

    #[test]
    fn pane_paint_rejects_historical_pixels_from_another_live_generation() {
        let paint = PanePaint {
            live: Some(Arc::new(grid("gen-b", 9))),
            scrolled_offset: 4,
            history_len: Some(20),
            historical: Some(Arc::new(grid("gen-a", 5))),
            ..PanePaint::default()
        };

        let painted = paint.paint_grid().expect("live grid remains paintable");
        assert_eq!(painted.generation.0, "gen-b");
        assert_eq!(painted.revision, Revision(9));
    }

    #[test]
    fn active_grid_generation_change_drops_history_but_retires_old_reply() {
        let shared = Arc::new(Shared::default());
        let token = shared.init_active_session("primary").unwrap();
        assert!(shared.commit_active_grid(&token, Revision(1), Arc::new(grid("gen-a", 1))));
        {
            let mut scrollback = shared.scrollback.lock().unwrap();
            let old_intent = scrollback.advance_intent().unwrap();
            scrollback.view_offset = 4;
            scrollback.history_len = Some(20);
            scrollback.historical = Some(Arc::new(grid("gen-a", 5)));
            scrollback.historical_generation = Some(SessionGeneration("gen-a".into()));
            scrollback.admitted_request = Some((old_intent, 4, SessionGeneration("gen-a".into())));
        }
        assert_eq!(
            shared
                .pane_paint("primary", "primary")
                .paint_grid()
                .unwrap()
                .revision,
            Revision(5)
        );

        assert!(shared.commit_active_grid(&token, Revision(9), Arc::new(grid("gen-b", 9))));
        {
            let scrollback = shared.scrollback.lock().unwrap();
            assert_eq!(scrollback.view_offset, 0);
            assert!(scrollback.history_len.is_none());
            assert!(scrollback.historical.is_none());
            assert!(scrollback.historical_generation.is_none());
            assert!(
                scrollback.admitted_request.is_some(),
                "the old ordered reply must still be able to release its admission slot"
            );
        }
        let painted = shared
            .pane_paint("primary", "primary")
            .paint_grid()
            .unwrap();
        assert_eq!(painted.generation.0, "gen-b");
        assert_eq!(painted.revision, Revision(9));

        assert!(!shared.commit_active_scrollback(
            &token,
            SessionGeneration("gen-a".into()),
            Revision(10),
            20,
            4,
            (vec![vec![cell(), cell()]], None),
        ));
        assert!(shared.scrollback.lock().unwrap().admitted_request.is_none());
        assert_eq!(
            shared
                .pane_paint("primary", "primary")
                .paint_grid()
                .unwrap()
                .generation
                .0,
            "gen-b"
        );

        {
            let mut scrollback = shared.scrollback.lock().unwrap();
            let current_intent = scrollback.advance_intent().unwrap();
            scrollback.view_offset = 2;
            scrollback.admitted_request =
                Some((current_intent, 2, SessionGeneration("gen-b".into())));
        }
        assert!(shared.commit_active_scrollback(
            &token,
            SessionGeneration("gen-b".into()),
            Revision(11),
            30,
            2,
            (vec![vec![cell(), cell()]], None),
        ));
        let painted = shared
            .pane_paint("primary", "primary")
            .paint_grid()
            .unwrap();
        assert_eq!(painted.generation.0, "gen-b");
        assert_eq!(painted.revision, Revision(11));
    }

    #[test]
    fn pane_grid_generation_change_drops_history_but_retires_old_reply() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("primary").unwrap();
        shared.set_pane_sessions(&["pane-x"]).unwrap();
        let token = shared.binding_token_for_session("pane-x").unwrap();
        assert!(shared.commit_pane_grid(&token, Arc::new(grid("gen-a", 1))));
        shared.with_pane_scrollback("pane-x", "primary", |scrollback| {
            let old_intent = scrollback.advance_intent().unwrap();
            scrollback.view_offset = 4;
            scrollback.history_len = Some(20);
            scrollback.historical = Some(Arc::new(grid("gen-a", 5)));
            scrollback.historical_generation = Some(SessionGeneration("gen-a".into()));
            scrollback.admitted_request = Some((old_intent, 4, SessionGeneration("gen-a".into())));
        });

        assert!(shared.commit_pane_grid(&token, Arc::new(grid("gen-b", 9))));
        shared.with_pane_scrollback("pane-x", "primary", |scrollback| {
            assert_eq!(scrollback.view_offset, 0);
            assert!(scrollback.history_len.is_none());
            assert!(scrollback.historical.is_none());
            assert!(scrollback.historical_generation.is_none());
            assert!(scrollback.admitted_request.is_some());
        });
        let painted = shared.pane_paint("pane-x", "primary").paint_grid().unwrap();
        assert_eq!(painted.generation.0, "gen-b");
        assert_eq!(painted.revision, Revision(9));

        assert!(!shared.commit_pane_scrollback(
            &token,
            SessionGeneration("gen-a".into()),
            Revision(10),
            20,
            4,
            (vec![vec![cell(), cell()]], None),
        ));
        shared.with_pane_scrollback("pane-x", "primary", |scrollback| {
            assert!(scrollback.admitted_request.is_none());
            let current_intent = scrollback.advance_intent().unwrap();
            scrollback.view_offset = 2;
            scrollback.admitted_request =
                Some((current_intent, 2, SessionGeneration("gen-b".into())));
        });
        assert!(shared.commit_pane_scrollback(
            &token,
            SessionGeneration("gen-b".into()),
            Revision(11),
            30,
            2,
            (vec![vec![cell(), cell()]], None),
        ));
        let painted = shared.pane_paint("pane-x", "primary").paint_grid().unwrap();
        assert_eq!(painted.generation.0, "gen-b");
        assert_eq!(painted.revision, Revision(11));
    }

    #[test]
    fn pane_paint_resolves_primary_from_dedicated_fields() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("primary");
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-p", 7)));
        *shared.exited.lock().unwrap() = Some(Some(3));
        {
            let mut sb = shared.scrollback.lock().unwrap();
            sb.view_offset = 4;
            sb.history_len = Some(20);
            sb.historical = Some(Arc::new(grid("gen-p", 5)));
        }

        let pp = shared.pane_paint("primary", "primary");
        assert_eq!(pp.live.as_ref().unwrap().revision.0, 7, "primary live grid");
        assert_eq!(pp.exited, Some(Some(3)), "primary exit");
        assert_eq!(pp.scrolled_offset, 4, "primary's own scrollback offset");
        assert_eq!(pp.history_len, Some(20));
        // Scrolled up with a cut present -> paints the historical window, not live.
        assert_eq!(pp.paint_grid().unwrap().revision.0, 5);
        assert!(pp.scroll_label().is_some());
    }

    #[test]
    fn pane_paint_resolves_non_primary_from_its_own_store_entry() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("primary");
        // A non-primary (extra) pane with its OWN grid + scrollback view.
        shared.set_pane_sessions(&["pane-x"]);
        let epoch = shared.pane_epoch("pane-x").unwrap();
        assert!(shared.apply_pane_grid("pane-x", epoch, Arc::new(grid("gen-x", 11))));
        shared.with_pane_scrollback("pane-x", "primary", |sb| {
            sb.view_offset = 2;
            sb.history_len = Some(9);
            sb.historical = Some(Arc::new(grid("gen-x", 8)));
        });

        let pp = shared.pane_paint("pane-x", "primary");
        assert_eq!(pp.live.as_ref().unwrap().revision.0, 11, "pane's live grid");
        assert_eq!(pp.scrolled_offset, 2, "pane's OWN scrollback offset");
        assert_eq!(
            pp.paint_grid().unwrap().revision.0,
            8,
            "paints pane's history"
        );

        // The primary's dedicated scrollback is UNTOUCHED by the pane's edit (per-pane isolation).
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);

        // An unknown id resolves to the empty default (paints nothing).
        let empty = shared.pane_paint("ghost", "primary");
        assert!(empty.live.is_none() && empty.paint_grid().is_none());
    }

    #[test]
    fn pane_paint_resolves_sibling_store_even_when_not_a_pane_member() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("primary");
        let epoch = shared.set_sibling_session("sibling-x").unwrap();
        assert!(shared.apply_sibling_grid("sibling-x", epoch, Arc::new(grid("gen-sibling", 17))));

        assert!(
            shared.pane_snapshot("sibling-x").is_none(),
            "pane_snapshot intentionally excludes the sibling store"
        );
        let pp = shared.pane_paint("sibling-x", "primary");
        assert_eq!(
            pp.live.as_ref().unwrap().revision.0,
            17,
            "uniform paint must still resolve sibling grids"
        );
        assert!(pp.paint_grid().is_some());
    }

    #[test]
    fn with_pane_scrollback_routes_to_focused_pane_not_always_primary() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("primary");
        shared.set_pane_sessions(&["pane-y"]);

        // Editing the focused NON-primary pane writes the store entry, leaving the primary at live.
        shared.with_pane_scrollback("pane-y", "primary", |sb| sb.view_offset = 6);
        assert_eq!(
            shared.with_pane_scrollback("pane-y", "primary", |sb| sb.view_offset),
            6
        );
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);

        // Editing with the primary as focus writes the dedicated field.
        shared.with_pane_scrollback("primary", "primary", |sb| sb.view_offset = 3);
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 3);

        // An unknown focused id edits a throwaway default and never panics.
        let read = shared.with_pane_scrollback("ghost", "primary", |sb| {
            sb.view_offset = 99;
            sb.view_offset
        });
        assert_eq!(read, 99, "edit applies to the throwaway only");
    }
}

// ============================================================================
// UserEventSender wake-path tests — possible now that the reader handlers take
// the platform-neutral sender instead of a live winit `EventLoopProxy` (which
// could not be built in a unit test). These prove the delivery contract the
// owner loops (winit on macOS, Tao/GTK on Linux) rely on: every VALIDATED
// state change requests its UserEvent once, in event order; rejected/foreign
// frames wake nothing; and a sender whose loop has already shut down is
// harmless — shared state still updates, nothing panics, nothing retries.
// Linux's sender may coalesce payloadless Redraw requests after this producer
// boundary while one redraw is already pending; typed/non-redraw events remain
// exact FIFO.
// ============================================================================
#[cfg(test)]
mod user_event_sender_tests {
    use super::*;

    // --- test senders -------------------------------------------------------

    /// Records every event in send order — the "live owner loop" double.
    #[derive(Clone)]
    struct RecordingSender(Arc<Mutex<Vec<UserEvent>>>);

    impl UserEventSender for RecordingSender {
        fn send(&self, event: UserEvent) -> Result<(), UserEvent> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
        fn clone_sender(&self) -> Box<dyn UserEventSender> {
            Box::new(self.clone())
        }
    }

    /// Always refuses — the "owner loop already shut down" double.
    struct ClosedSender;

    impl UserEventSender for ClosedSender {
        fn send(&self, event: UserEvent) -> Result<(), UserEvent> {
            Err(event)
        }
        fn clone_sender(&self) -> Box<dyn UserEventSender> {
            Box::new(ClosedSender)
        }
    }

    /// Compact comparable form of a recorded event (`UserEvent` derives no `PartialEq`).
    fn tag(ev: &UserEvent) -> String {
        match ev {
            UserEvent::Redraw => "redraw".to_string(),
            UserEvent::SessionExited {
                session_id,
                code,
                observed_generation,
            } => format!(
                "exit:{session_id}:{code:?}:{}",
                observed_generation.as_deref().unwrap_or("<none>")
            ),
            UserEvent::TerminalBell { .. } => "bell".to_string(),
            UserEvent::TerminalTitle { title, .. } => {
                format!("title:{}", title.clone().unwrap_or_default())
            }
            UserEvent::TerminalClipboardStore { text, .. } => format!("clipboard:{text}"),
            other => format!("other:{other:?}"),
        }
    }

    fn tags(log: &Arc<Mutex<Vec<UserEvent>>>) -> Vec<String> {
        log.lock().unwrap().iter().map(tag).collect()
    }

    // --- fixtures (the same shapes the sibling-ingest tests use) -------------

    fn color() -> crate::wire::Color {
        crate::wire::Color::Named {
            name: crate::wire::NamedColor::Foreground,
        }
    }

    fn cell() -> Cell {
        Cell {
            text: "x".to_string(),
            fg: color(),
            bg: color(),
            bold: false,
            italic: false,
            underline: Default::default(),
            inverse: false,
            strikeout: false,
            dim: false,
            hidden: false,
            hyperlink: None,
            width: 1,
        }
    }

    fn grid(gen: &str, rev: u64) -> GridSnapshot {
        GridSnapshot {
            row_copy: None,
            version: crate::sync::SUPPORTED_VERSION,
            generation: SessionGeneration(gen.to_string()),
            revision: Revision(rev),
            base_revision: Revision(rev),
            cols: 2,
            rows: 1,
            rows_cells: vec![vec![cell(), cell()]],
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
            alt_screen: false,
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_report: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_sgr: false,
        }
    }

    fn app_for_shared(shared: Arc<Shared>, session_id: &str) -> crate::App {
        let generation = shared
            .grid
            .lock()
            .unwrap()
            .as_ref()
            .expect("scroll fixture has an accepted primary Grid")
            .generation
            .0
            .clone();
        let target = crate::RendererExactSessionTarget {
            session_id: session_id.to_string(),
            generation,
        };
        let mut app = crate::App::new(
            shared,
            session_id.to_string(),
            crate::DEFAULT_WINDOW_TITLE.to_string(),
            None,
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        app.exact_viewport = Some(crate::RendererExactViewport {
            window_id: "scroll-test-window".to_string(),
            primary_tab_id: "scroll-test-tab".to_string(),
            primary: target.clone(),
            roles: vec![crate::RendererExactViewportRole {
                tab_id: "scroll-test-tab".to_string(),
                target: target.clone(),
            }],
            unique_targets: vec![target],
        });
        app
    }

    /// A `ClearAll` damage frame over the 2-col x 1-row shape `grid()` produces,
    /// advancing `base` -> `rev` for `gen`, sized to apply cleanly onto a
    /// `grid(gen, base)` baseline so `on_damage` yields `Applied`.
    fn damage_frame(id: &str, gen: &str, base: u64, rev: u64) -> crate::wire::DamageFrame {
        use crate::wire::{CursorState, DamageOp, ModeState};
        crate::wire::DamageFrame {
            row_copy: None,
            schema: crate::wire::DAMAGE_SCHEMA,
            id: id.to_string(),
            generation: SessionGeneration(gen.to_string()),
            base_revision: Revision(base),
            revision: Revision(rev),
            cols: 2,
            rows: 1,
            cursor: CursorState {
                line: 0,
                col: 0,
                visible: true,
                shape: CursorShape::Block,
            },
            modes: ModeState {
                alt_screen: false,
                app_cursor: false,
                bracketed_paste: false,
                focus_reporting: false,
                mouse_report: false,
                mouse_drag: false,
                mouse_motion: false,
                mouse_sgr: false,
            },
            ops: vec![DamageOp::ClearAll {
                cell: Cell {
                    text: " ".to_string(),
                    width: 1,
                    ..cell()
                },
            }],
        }
    }

    // --- delivery order + exactly-once ---------------------------------------

    #[test]
    fn validated_changes_deliver_user_events_once_and_in_order() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a".to_string());
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());
        let id = || "s-a".to_string();

        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: id(),
                grid: grid("gen", 1),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalBell { id: id() },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalTitle {
                id: id(),
                title: Some("t".to_string()),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Damage {
                frame: damage_frame("s-a", "gen", 1, 2),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalClipboardStore {
                id: id(),
                text: "x".to_string(),
            },
        );

        assert_eq!(
            tags(&log),
            vec!["redraw", "bell", "title:t", "redraw", "clipboard:x"],
            "the producer requests one event per validated change, in event order"
        );
    }

    #[test]
    fn applied_live_damage_completes_recovery_even_when_older_snapshot_arrives_late() {
        let (shared, queue) = Shared::with_test_queue();
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a");
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log);

        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-a".to_string(),
                grid: grid("gen", 1),
            },
        );

        // A gap admits one recovery Snapshot and raises SyncState's local in-flight bit.
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Damage {
                frame: damage_frame("s-a", "gen", 2, 3),
            },
        );
        let first_recovery = queue.drain_requests();
        assert!(matches!(
            first_recovery.as_slice(),
            [ClientRequest::Snapshot { id }] if id == "s-a"
        ));
        assert!(sync.request_in_flight());

        // The live stream catches us up before that Snapshot reply. This Applied commit is an
        // equally authoritative recovery completion and must clear the Shared registry entry.
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Damage {
                frame: damage_frame("s-a", "gen", 1, 2),
            },
        );
        assert!(!sync.request_in_flight());
        assert!(shared.pending_recoveries.lock().unwrap().is_empty());

        // The older recovery Grid is now stale and changes neither pixels nor bookkeeping.
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-a".to_string(),
                grid: grid("gen", 1),
            },
        );
        assert!(queue.drain_requests().is_empty());

        // A later independent gap must start a second recovery cycle, not wedge behind an orphaned
        // `AlreadyAdmitted` registry record from the first cycle.
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Damage {
                frame: damage_frame("s-a", "gen", 3, 4),
            },
        );
        let second_recovery = queue.drain_requests();
        assert!(matches!(
            second_recovery.as_slice(),
            [ClientRequest::Snapshot { id }] if id == "s-a"
        ));
        assert!(sync.request_in_flight());
    }

    #[test]
    fn old_generation_scrollback_reply_wakes_app_to_admit_latest_generation_intent() {
        let (shared, queue) = Shared::with_test_queue();
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a");
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-a".to_string(),
                grid: grid("gen-a", 1),
            },
        );
        let mut app = app_for_shared(shared.clone(), "s-a");

        // A query for generation A is admitted and owns the route's sole reply slot.
        assert!(app.apply_scroll(ScrollAction::Lines(1)));
        let first = queue.drain_requests();
        assert!(matches!(
            first.as_slice(),
            [ClientRequest::Scrollback { id, .. }] if id == "s-a"
        ));

        // A new PTY lifetime resets visible history but deliberately preserves A's admitted slot
        // until its FIFO reply arrives. The user's new B gesture is retained behind that slot.
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-a".to_string(),
                grid: grid("gen-b", 1),
            },
        );
        assert!(app.apply_scroll(ScrollAction::Lines(1)));
        assert_eq!(app.pending_owner_requests.len(), 1);
        assert!(queue.drain_requests().is_empty());

        log.lock().unwrap().clear();
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::ScrollbackRows {
                id: "s-a".to_string(),
                row_copy: None,
                generation: SessionGeneration("gen-a".to_string()),
                revision: Revision(1),
                history_len: 10,
                offset_from_top: 1,
                rows: vec![vec![cell(), cell()]],
            },
        );
        let events = std::mem::take(&mut *log.lock().unwrap());
        assert!(events
            .iter()
            .any(|event| matches!(event, UserEvent::OutboundWritable)));
        assert!(events
            .iter()
            .all(|event| !matches!(event, UserEvent::Redraw)));
        for event in events {
            if matches!(event, UserEvent::OutboundWritable) {
                app.handle_user_event(event);
            }
        }

        let retried = queue.drain_requests();
        assert!(matches!(
            retried.as_slice(),
            [ClientRequest::Scrollback {
                id,
                offset_from_top: 1,
                ..
            }] if id == "s-a"
        ));
        assert!(app.pending_owner_requests.is_empty());
        assert!(matches!(
            shared.scrollback.lock().unwrap().admitted_request.as_ref(),
            Some((_, 1, generation)) if generation.0 == "gen-b"
        ));

        // The current reply now paints B history; A never reopened the viewport.
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::ScrollbackRows {
                id: "s-a".to_string(),
                row_copy: None,
                generation: SessionGeneration("gen-b".to_string()),
                revision: Revision(1),
                history_len: 10,
                offset_from_top: 1,
                rows: vec![vec![cell(), cell()]],
            },
        );
        let scrollback = shared.scrollback.lock().unwrap();
        assert_eq!(
            scrollback
                .historical
                .as_ref()
                .map(|grid| grid.generation.0.as_str()),
            Some("gen-b")
        );
    }

    #[test]
    fn hundreds_of_gestures_behind_one_admitted_scroll_query_keep_one_bounded_latest_intent() {
        let (shared, queue) = Shared::with_test_queue();
        let token = shared.init_active_session("s-a").unwrap();
        assert!(shared.commit_active_grid(&token, Revision(1), Arc::new(grid("gen-a", 1))));
        let mut app = app_for_shared(shared.clone(), "s-a");

        assert!(app.apply_scroll(ScrollAction::Lines(1)));
        assert!(matches!(
            queue.drain_requests().as_slice(),
            [ClientRequest::Scrollback { id, .. }] if id == "s-a"
        ));
        for _ in 0..300 {
            assert!(app.apply_scroll(ScrollAction::Lines(1)));
        }

        let scrollback = shared.scrollback.lock().unwrap();
        assert!(
            scrollback.admitted_request.is_some(),
            "exactly one wire reply slot"
        );
        let desired = scrollback.view_offset;
        drop(scrollback);
        assert_eq!(
            app.pending_owner_requests.len(),
            1,
            "latest-wins coalescing"
        );
        let pending = app.pending_owner_requests.front().unwrap();
        assert!(matches!(
            pending.requests.as_slice(),
            [ClientRequest::Scrollback { offset_from_top, .. }] if *offset_from_top == desired
        ));
        assert!(app.pending_owner_request_bytes <= OUTBOUND_CAP_BYTES);
        assert!(queue.drain_requests().is_empty());
    }

    #[test]
    fn canonical_reply_immediately_after_request_visibility_finds_registered_correlation() {
        let (shared, queue) = Shared::with_test_queue();
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a");
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log);
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-a".to_string(),
                grid: grid("gen-a", 1),
            },
        );
        let mut app = app_for_shared(shared.clone(), "s-a");

        assert!(app.apply_scroll(ScrollAction::Lines(1)));
        let visible = queue.drain_requests();
        assert!(matches!(
            visible.as_slice(),
            [ClientRequest::Scrollback {
                id,
                offset_from_top: 1,
                ..
            }] if id == "s-a"
        ));
        assert!(
            shared.scrollback.lock().unwrap().admitted_request.is_some(),
            "correlation is installed before the request can become writer-visible"
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::ScrollbackRows {
                id: "s-a".to_string(),
                row_copy: None,
                generation: SessionGeneration("gen-a".to_string()),
                revision: Revision(1),
                history_len: 10,
                offset_from_top: 1,
                rows: vec![vec![cell(), cell()]],
            },
        );
        assert_eq!(
            shared
                .scrollback
                .lock()
                .unwrap()
                .historical
                .as_ref()
                .map(|grid| grid.generation.0.as_str()),
            Some("gen-a")
        );
    }

    #[test]
    fn full_queue_coalesced_scroll_then_end_cannot_be_resurrected_by_old_reply() {
        let (shared, queue) = Shared::with_test_queue();
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a");
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-a".to_string(),
                grid: grid("gen-a", 1),
            },
        );
        let mut app = app_for_shared(shared.clone(), "s-a");

        assert!(app.apply_scroll(ScrollAction::Lines(1)));
        queue.drain_requests();
        queue.saturate_raw();
        for _ in 0..8 {
            assert!(app.apply_scroll(ScrollAction::Lines(1)));
        }
        assert_eq!(app.pending_owner_requests.len(), 1);
        assert!(app.apply_scroll(ScrollAction::End));
        assert!(app.pending_owner_requests.is_empty());
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);

        queue.discard_all();
        log.lock().unwrap().clear();
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::ScrollbackRows {
                id: "s-a".to_string(),
                row_copy: None,
                generation: SessionGeneration("gen-a".to_string()),
                revision: Revision(1),
                history_len: 10,
                offset_from_top: 1,
                rows: vec![vec![cell(), cell()]],
            },
        );
        for event in std::mem::take(&mut *log.lock().unwrap()) {
            app.handle_user_event(event);
        }
        let scrollback = shared.scrollback.lock().unwrap();
        assert_eq!(scrollback.view_offset, 0);
        assert!(scrollback.historical.is_none());
        assert!(scrollback.admitted_request.is_none());
        drop(scrollback);
        assert!(app.pending_owner_requests.is_empty());
        assert!(queue.drain_requests().is_empty());
    }

    #[test]
    fn active_exit_delivers_identity_code_and_generation_exactly_once() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a".to_string());
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());

        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-a".to_string(),
                grid: grid("gen-a", 1),
            },
        );
        log.lock().unwrap().clear();

        for _ in 0..2 {
            handle_event(
                &shared,
                &mut sync,
                &sender,
                "s-a",
                DaemonEvent::SessionExited {
                    id: "s-a".to_string(),
                    code: Some(7),
                },
            );
        }

        assert_eq!(tags(&log), vec!["exit:s-a:Some(7):gen-a"]);
        assert_eq!(*shared.exited.lock().unwrap(), Some(Some(7)));
    }

    #[test]
    fn sibling_and_extra_pane_exits_preserve_their_accepted_generations() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active");
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());

        let sibling_epoch = shared.set_sibling_session("sibling").unwrap();
        let mut sibling_sync = SyncState::new("sibling");
        handle_sibling_event(
            &shared,
            &mut sibling_sync,
            &sender,
            "sibling",
            sibling_epoch,
            DaemonEvent::Grid {
                id: "sibling".to_string(),
                grid: grid("gen-sibling", 1),
            },
        );

        shared.set_pane_sessions(&["pane"]);
        let mut pane_sync = SyncState::new("pane");
        handle_pane_event(
            &shared,
            &mut pane_sync,
            &sender,
            "pane",
            DaemonEvent::Grid {
                id: "pane".to_string(),
                grid: grid("gen-pane", 1),
            },
        );
        log.lock().unwrap().clear();

        handle_sibling_event(
            &shared,
            &mut sibling_sync,
            &sender,
            "sibling",
            sibling_epoch,
            DaemonEvent::SessionExited {
                id: "sibling".to_string(),
                code: Some(0),
            },
        );
        handle_pane_event(
            &shared,
            &mut pane_sync,
            &sender,
            "pane",
            DaemonEvent::SessionExited {
                id: "pane".to_string(),
                code: None,
            },
        );

        assert_eq!(
            tags(&log),
            vec![
                "exit:sibling:Some(0):gen-sibling",
                "exit:pane:None:gen-pane"
            ]
        );
        assert_eq!(shared.sibling_snapshot().exited, Some(Some(0)));
        assert_eq!(shared.pane_snapshot("pane").unwrap().1, Some(None));
    }

    #[test]
    fn stale_pane_epoch_drops_exit_without_notifying_owner() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active");
        shared.set_pane_sessions(&["pane"]);
        let stale_epoch = shared.pane_epoch("pane").unwrap();
        let mut stale_sync = SyncState::new("pane");
        stale_sync.on_grid("pane", &grid("stale-gen", 1)).unwrap();

        shared.clear_pane_sessions();
        shared.set_pane_sessions(&["pane"]);
        assert_ne!(shared.pane_epoch("pane"), Some(stale_epoch));

        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());
        // Call the lower-level accepted-exit path with the stale epoch to model an in-flight frame
        // from the replaced binding. The cache gate refuses it, so no lifecycle event escapes.
        if let Ok(Action::Exited) = stale_sync.on_session_exited("pane") {
            if shared.apply_pane_exit("pane", stale_epoch, Some(1)) {
                notify_session_exit(&sender, "pane", Some(1), stale_sync.accepted_generation());
            }
        }
        assert!(tags(&log).is_empty());
        assert_eq!(shared.pane_snapshot("pane").unwrap().1, None);
    }

    #[test]
    fn rejected_and_foreign_frames_never_wake() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a".to_string());
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());

        // A foreign session's grid is rejected by the SyncState gate; its bell/title/
        // clipboard fall through the id guards; a foreign damage frame short-circuits.
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-b".to_string(),
                grid: grid("gen", 1),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalBell {
                id: "s-b".to_string(),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalTitle {
                id: "s-b".to_string(),
                title: Some("t".to_string()),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Damage {
                frame: damage_frame("s-b", "gen", 1, 2),
            },
        );

        assert!(
            tags(&log).is_empty(),
            "no wake without a validated state change (exactly-once also means never-spurious)"
        );
    }

    #[test]
    fn sibling_ingest_wakes_through_the_neutral_sender() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-active");
        let epoch = shared.set_sibling_session("s-sib").unwrap();
        let mut sync = SyncState::new("s-sib".to_string());
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());

        handle_sibling_event(
            &shared,
            &mut sync,
            &sender,
            "s-sib",
            epoch,
            DaemonEvent::Grid {
                id: "s-sib".to_string(),
                grid: grid("gen-sib", 5),
            },
        );

        assert_eq!(tags(&log), vec!["redraw"]);
        assert!(
            shared.sibling_snapshot().grid.is_some(),
            "the accepted sibling grid is cached before the wake"
        );
    }

    // --- closed owner loop is harmless ---------------------------------------

    #[test]
    fn sends_after_owner_loop_closure_are_harmless_and_state_still_updates() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a".to_string());
        let sender = ClosedSender;

        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-a".to_string(),
                grid: grid("gen", 1),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Damage {
                frame: damage_frame("s-a", "gen", 1, 2),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalBell {
                id: "s-a".to_string(),
            },
        );

        // Every wake failed (loop gone) — no panic, and the validated state was still
        // published: teardown is nonfatal for the reader.
        let published = shared.grid.lock().unwrap().clone().expect("grid published");
        assert_eq!(published.revision, Revision(2));
    }

    // --- clone fan-out shares one ordered stream ------------------------------

    #[test]
    fn clone_sender_fans_out_into_one_ordered_stream() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let a: Box<dyn UserEventSender> = Box::new(RecordingSender(log.clone()));
        let b = a.clone_sender();
        let binding = ViewportBindingToken::Active(ActiveBindingToken {
            session_id: "s".to_string(),
            epoch: 1,
            output_generation: 1,
        });

        let _ = a.send(UserEvent::Redraw);
        let _ = b.send(UserEvent::TerminalBell {
            binding: binding.clone(),
        });
        let _ = a.send(UserEvent::TerminalClipboardStore {
            binding,
            text: "x".to_string(),
        });

        assert_eq!(
            tags(&log),
            vec!["redraw", "bell", "clipboard:x"],
            "clones (client reader + command bridge) feed the same ordered stream"
        );
    }
}
