//! A MINIMAL, synchronous daemon client over the Unix-domain-socket protocol. It deliberately does
//! the SMALLEST useful thing: connect to a caller-supplied
//! socket, prove mutation compatibility with a read-only `DaemonInfo` request, drive one
//! `StartSession -> Attach{want_raw_output:false} -> Grid` flow, attach read-only to an existing
//! retained session, read the live session set with `ListSessions`, and request a single session be
//! killed and confirmed gone with `kill_session`
//! (over the daemon's existing `Kill` request). Everything else the daemon protocol can do (write,
//! resize, scrollback, channels, raw output) is out of scope here.
//!
//! All wire types come from `maestro-protocol`: requests via [`ClientRequest`], the framing cap via
//! [`MAX_LINE_BYTES`], and replies via the lightweight [`ShellEvent`] decoder. This client never
//! models the daemon's full event/grid types, so it stays decoupled from daemon runtime internals
//! exactly as the shared-crate design intended.
//!
//! ## Safety / robustness invariants
//!
//! - **Bounded lines, both directions.** A reply line is read with a hard cap of [`MAX_LINE_BYTES`];
//!   a longer, unterminated line is a framing violation that errors
//!   ([`DaemonClientError::LineTooLong`] with [`Direction::Inbound`]) rather than growing memory
//!   without limit — mirroring the daemon's own `read_until` cap. The SAME cap is applied to
//!   outbound request lines: an oversized request is rejected ([`Direction::Outbound`]) BEFORE any
//!   bytes are written, so a pathological request never lands a partial/oversized line on the wire.
//! - **Timeouts.** Read and write deadlines are set on the socket so a silent or wedged daemon
//!   surfaces as [`DaemonClientError::Timeout`] instead of hanging the caller forever.
//! - **Mutual local identity.** The daemon already checks every client's kernel peer UID. The
//!   client likewise reads the connected server's kernel peer UID before sending any request and
//!   rejects a different or unidentifiable OS user. A planted socket in a shared temporary
//!   directory therefore cannot impersonate the user's daemon.
//! - **Clean teardown.** The `UnixStream` is owned by [`DaemonClient`]; every method returns by
//!   value or error and the stream is dropped (closing the fd) when the client is dropped — there is
//!   no path that leaks the socket.
//! - **No daemon lifecycle.** This client never spawns, supervises, or kills a daemon process, never
//!   opens a PTY, never runs git, and never creates directories. It only checks that a caller-given
//!   cwd is an existing directory before sending `StartSession`.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use maestro_protocol::{ClientRequest, SessionId, SessionListInfo, ShellEvent, MAX_LINE_BYTES};
/// A response-wait operation may tolerate additive/unrelated events, but never an unbounded stream
/// of them. The byte budget admits several maximum-sized legacy grid snapshots while still placing
/// one finite resource ceiling over a whole public operation.
pub const MAX_REPLY_EVENTS_PER_OPERATION: usize = 256;
pub const MAX_REPLY_BYTES_PER_OPERATION: usize = 4 * MAX_LINE_BYTES;

/// Which side of the framed connection a [`DaemonClientError::LineTooLong`] applies to: an inbound
/// reply line the daemon sent us, or an outbound request line we were about to send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    /// A reply line read FROM the daemon.
    Inbound,
    /// A request line we were about to write TO the daemon.
    Outbound,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::Inbound => write!(f, "reply"),
            Direction::Outbound => write!(f, "request"),
        }
    }
}

/// Everything that can go wrong driving the daemon, as TYPED variants so a caller (and the tests)
/// can distinguish "daemon isn't there" from "daemon said no" from "my cwd is bad" without string
/// matching.
#[derive(Debug)]
pub enum DaemonClientError {
    /// The socket could not be connected (refused / missing path / not a socket). The daemon is not
    /// reachable; this is distinct from a daemon that answered with an error.
    DaemonUnavailable {
        path: String,
        source: std::io::Error,
    },
    /// A socket accepted the connection, but the kernel could not prove that its server endpoint
    /// belongs to this effective OS user. No protocol bytes are sent to an untrusted endpoint.
    UntrustedDaemon {
        path: String,
        expected_uid: u32,
        observed_uid: Option<u32>,
        detail: String,
    },
    /// The caller-supplied cwd is not an existing directory. Returned BEFORE any request is written,
    /// so a bad cwd never reaches the daemon as a half-issued `StartSession`. This matches the
    /// daemon's own `Path::is_dir()` boundary: a missing path OR an existing non-directory (e.g. a
    /// regular file) is rejected here.
    InvalidCwd { cwd: String },
    /// A read or write exceeded its deadline — a silent/wedged daemon. Surfaced rather than hanging.
    Timeout { during: &'static str },
    /// A framed line exceeded [`MAX_LINE_BYTES`]: a framing violation. For `Inbound`, an unterminated
    /// reply over the cap is abandoned without buffering further (mirroring the daemon's read cap);
    /// for `Outbound`, an oversized request is rejected BEFORE any bytes are written.
    LineTooLong { direction: Direction, limit: usize },
    /// The peer kept sending bounded but irrelevant frames until the whole-operation event/byte
    /// budget was exhausted. This closes the liveness gap left by per-read socket deadlines.
    ReplyBudgetExceeded { during: &'static str },
    /// The daemon replied with an `Error { message }` event.
    DaemonError { message: String },
    /// The connected retained daemon is attach-compatible but does not implement the mutation
    /// semantics required to start a session without risking unrelated retained snapshots.
    MutationProtocolUnsupported {
        required: u32,
        observed: Option<u32>,
    },
    /// An attach-only upgrade requested a stable retained id that the daemon did not report. The
    /// client never substitutes another session implicitly and never sends `StartSession` here.
    RetainedSessionUnavailable { id: SessionId },
    /// The session exited before the awaited `Grid` arrived (e.g. the command failed immediately).
    SessionExited { id: SessionId, code: Option<i32> },
    /// The connection closed (EOF) before the awaited reply arrived.
    UnexpectedEof { during: &'static str },
    /// A reply line was not valid UTF-8 or not valid JSON for any modeled/tolerated event.
    Protocol { detail: String },
    /// A lower-level IO error not covered by the more specific variants above.
    Io(std::io::Error),
}

impl std::fmt::Display for DaemonClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonClientError::DaemonUnavailable { path, source } => {
                write!(f, "daemon unavailable at {path}: {source}")
            }
            DaemonClientError::UntrustedDaemon {
                path,
                expected_uid,
                observed_uid,
                detail,
            } => match observed_uid {
                Some(observed_uid) => write!(
                    f,
                    "untrusted daemon at {path}: peer uid {observed_uid} does not match client uid {expected_uid} ({detail})"
                ),
                None => write!(
                    f,
                    "untrusted daemon at {path}: kernel peer identity was unavailable for client uid {expected_uid} ({detail})"
                ),
            },
            DaemonClientError::InvalidCwd { cwd } => {
                write!(f, "cwd is not an existing directory: {cwd}")
            }
            DaemonClientError::Timeout { during } => {
                write!(f, "timed out while {during}")
            }
            DaemonClientError::LineTooLong { direction, limit } => {
                write!(f, "{direction} line exceeds {limit} bytes; closing")
            }
            DaemonClientError::ReplyBudgetExceeded { during } => {
                write!(f, "reply budget exhausted while {during}")
            }
            DaemonClientError::DaemonError { message } => {
                write!(f, "daemon error: {message}")
            }
            DaemonClientError::MutationProtocolUnsupported { required, observed } => match observed {
                Some(observed) => write!(
                    f,
                    "retained daemon protocol {observed} is attach-only; session creation requires protocol {required}"
                ),
                None => write!(
                    f,
                    "legacy retained daemon is attach-only; session creation requires protocol {required}"
                ),
            },
            DaemonClientError::RetainedSessionUnavailable { id } => {
                write!(f, "retained session {id} is not available for attach-only launch")
            }
            DaemonClientError::SessionExited { id, code } => {
                write!(f, "session {id} exited before grid (code {code:?})")
            }
            DaemonClientError::UnexpectedEof { during } => {
                write!(f, "connection closed while {during}")
            }
            DaemonClientError::Protocol { detail } => {
                write!(f, "protocol error: {detail}")
            }
            DaemonClientError::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for DaemonClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DaemonClientError::DaemonUnavailable { source, .. } => Some(source),
            DaemonClientError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Map an IO error to a typed timeout when the kernel reports the deadline elapsed, otherwise keep
/// it as a generic IO error. A socket read/write timeout surfaces as `WouldBlock` or `TimedOut`
/// depending on platform, so both are treated as a deadline hit.
fn classify_io(e: std::io::Error, during: &'static str) -> DaemonClientError {
    match e.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            DaemonClientError::Timeout { during }
        }
        _ => DaemonClientError::Io(e),
    }
}

/// Ask the kernel which effective UID owns the process at the connected server end.
#[cfg(not(target_os = "linux"))]
fn connected_server_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `stream` owns a connected Unix-domain socket for the duration of this call and both
    // output pointers refer to correctly sized live values.
    let status = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if status != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(uid as u32)
}

/// Linux exposes the connected server identity through `SO_PEERCRED`.
#[cfg(target_os = "linux")]
fn connected_server_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `stream` owns a connected socket and `credentials`/`length` are correctly sized
    // writable outputs for `SO_PEERCRED`.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut credentials as *mut libc::ucred as *mut libc::c_void,
            &mut length,
        )
    };
    if status != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(credentials.uid)
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    unsafe { libc::geteuid() as u32 }
}

fn verify_connected_server_identity(
    path: &Path,
    expected_uid: u32,
    observed: std::io::Result<u32>,
) -> Result<(), DaemonClientError> {
    match observed {
        Ok(observed_uid) if observed_uid == expected_uid => Ok(()),
        Ok(observed_uid) => Err(DaemonClientError::UntrustedDaemon {
            path: path.display().to_string(),
            expected_uid,
            observed_uid: Some(observed_uid),
            detail: "kernel peer credential mismatch".into(),
        }),
        Err(error) => Err(DaemonClientError::UntrustedDaemon {
            path: path.display().to_string(),
            expected_uid,
            observed_uid: None,
            detail: error.to_string(),
        }),
    }
}

/// The result of a successful `start_and_attach`: the session is live and the daemon has delivered
/// its authoritative grid baseline. Carries only the lightweight identity the shell needs — never
/// the cell payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttachedSession {
    /// The session id the attach baseline arrived for (echoes the requested id).
    pub id: SessionId,
    /// The grid lifetime id. A change across attaches means the daemon respawned a fresh grid; the
    /// shell persists this to detect that on a later reattach.
    pub generation: String,
    /// The revision the baseline snapshot is at, when the daemon included it.
    pub revision: Option<u64>,
}

/// The result of a successful [`DaemonClient::kill_session`]: the named session is no longer in the
/// daemon's live session list. This is a "session is no longer live" confirmation, NOT a claim that
/// this client personally killed it — an already-absent session yields the same `Ok` (idempotent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KilledSession {
    /// The session id that is confirmed absent from the daemon's live list.
    pub id: SessionId,
}

/// One atomic `ListSessions` reply. `ids` remains the compatibility authority for retained legacy
/// daemons; `sessions` carries additive generation identity when the running daemon supports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedSessions {
    pub ids: Vec<SessionId>,
    pub sessions: Vec<SessionListInfo>,
}

/// How many `ListSessions` confirmations `kill_session` will read before giving up. The daemon
/// removes a killed session synchronously, so the FIRST `Sessions` reply after `Kill` normally
/// already excludes it; the extra rounds only cover a daemon that interleaves an in-flight
/// `Sessions` snapshot taken before the kill landed. Bounded so a daemon that keeps reporting the
/// id can never wedge the caller — once the rounds are spent the existing timeout/EOF path triggers.
const KILL_CONFIRM_ROUNDS: usize = 4;

/// Default read/write deadline. Generous enough for a local daemon to answer a snapshot, short
/// enough that a silent daemon fails fast instead of wedging the caller.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

struct ReplyBudget {
    during: &'static str,
    events: usize,
    bytes: usize,
}

impl ReplyBudget {
    fn new(during: &'static str) -> Self {
        Self {
            during,
            events: 0,
            bytes: 0,
        }
    }

    fn observe(&mut self, bytes: usize) -> Result<(), DaemonClientError> {
        self.events = self.events.saturating_add(1);
        self.bytes = self.bytes.saturating_add(bytes);
        if self.events > MAX_REPLY_EVENTS_PER_OPERATION
            || self.bytes > MAX_REPLY_BYTES_PER_OPERATION
        {
            return Err(DaemonClientError::ReplyBudgetExceeded {
                during: self.during,
            });
        }
        Ok(())
    }
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
    overflowed: bool,
}

impl BoundedJsonWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(limit.min(8 * 1024)),
            limit,
            overflowed: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let Some(new_len) = self.bytes.len().checked_add(bytes.len()) else {
            self.overflowed = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bounded JSON frame length overflow",
            ));
        };
        if new_len > self.limit {
            self.overflowed = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "bounded JSON frame exceeds limit",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A synchronous, single-connection client to a running `pty-daemon`. Owns one `UnixStream`; the
/// socket is closed when this value is dropped. Not `Clone` — one connection, one owner.
pub struct DaemonClient {
    writer: UnixStream,
    reader: BufReader<UnixStream>,
}

impl DaemonClient {
    /// Connect to the daemon at `socket_path` with the default timeout.
    ///
    /// A refused/missing socket returns [`DaemonClientError::DaemonUnavailable`] — the daemon isn't
    /// there — so a caller can distinguish "no daemon" from "daemon said no".
    pub fn connect(socket_path: impl AsRef<Path>) -> Result<Self, DaemonClientError> {
        Self::connect_with_timeout(socket_path, DEFAULT_TIMEOUT)
    }

    /// Connect with an explicit read/write deadline. Splits the connected stream into a buffered
    /// reader and a writer half (cloned fds onto the same socket) so reads and writes don't share a
    /// cursor; both carry the same timeout.
    pub fn connect_with_timeout(
        socket_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Self, DaemonClientError> {
        let path = socket_path.as_ref();
        let stream =
            UnixStream::connect(path).map_err(|source| DaemonClientError::DaemonUnavailable {
                path: path.display().to_string(),
                source,
            })?;
        verify_connected_server_identity(path, effective_uid(), connected_server_uid(&stream))?;
        // A silent daemon must not hang us: bound every read and write by the deadline.
        stream
            .set_read_timeout(Some(timeout))
            .map_err(DaemonClientError::Io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(DaemonClientError::Io)?;
        // A second handle on the SAME socket for the buffered reader, so writing a request and then
        // reading replies never trips over a shared stream position.
        let reader_stream = stream.try_clone().map_err(DaemonClientError::Io)?;
        Ok(DaemonClient {
            writer: stream,
            reader: BufReader::new(reader_stream),
        })
    }

    /// Serialize a request and write it as one newline-delimited JSON line. A request never exceeds
    /// the line cap in practice (these are tiny control messages), so the cap is enforced on the
    /// READ side where an adversarial/buggy daemon could send an unbounded line.
    fn send(&mut self, req: &ClientRequest) -> Result<(), DaemonClientError> {
        // Stream serde into a capped writer. `to_string` would first allocate the complete hostile
        // request and only then notice it exceeded the wire limit.
        let mut encoded = BoundedJsonWriter::new(MAX_LINE_BYTES.saturating_sub(1));
        if let Err(error) = serde_json::to_writer(&mut encoded, req) {
            if encoded.overflowed {
                return Err(DaemonClientError::LineTooLong {
                    direction: Direction::Outbound,
                    limit: MAX_LINE_BYTES,
                });
            }
            return Err(DaemonClientError::Protocol {
                detail: error.to_string(),
            });
        }
        encoded.bytes.push(b'\n');
        self.writer
            .write_all(&encoded.bytes)
            .map_err(|e| classify_io(e, "writing request"))?;
        self.writer
            .flush()
            .map_err(|e| classify_io(e, "flushing request"))
    }

    /// Read ONE newline-delimited reply line, bounded to [`MAX_LINE_BYTES`], and decode it into a
    /// [`ShellEvent`]. The cap is enforced by reading at most `MAX_LINE_BYTES + 1` bytes: if that
    /// many arrive without a newline, the line is over the limit and we stop — never buffering more.
    /// Returns `Ok(None)` on a clean EOF (connection closed with no partial line).
    fn read_event(
        &mut self,
        during: &'static str,
        budget: &mut ReplyBudget,
    ) -> Result<Option<ShellEvent>, DaemonClientError> {
        let mut buf: Vec<u8> = Vec::new();
        // `take` caps consumption at one over the limit, so an unterminated oversized line is
        // detected without growing `buf` past the cap — the same bound the daemon applies to us.
        let mut limited = (&mut self.reader).take((MAX_LINE_BYTES + 1) as u64);
        let n = limited
            .read_until(b'\n', &mut buf)
            .map_err(|e| classify_io(e, during))?;
        if n == 0 {
            return Ok(None); // clean EOF
        }
        if buf.len() > MAX_LINE_BYTES {
            // The cap includes a trailing newline. Reject both unterminated overflow and a newline
            // arriving in byte MAX_LINE_BYTES + 1.
            return Err(DaemonClientError::LineTooLong {
                direction: Direction::Inbound,
                limit: MAX_LINE_BYTES,
            });
        }
        budget.observe(buf.len())?;
        let line = std::str::from_utf8(&buf)
            .map_err(|e| DaemonClientError::Protocol {
                detail: e.to_string(),
            })?
            .trim();
        if line.is_empty() {
            // A blank keepalive-ish line: nothing to decode, but not EOF. Surface as Other so the
            // caller's loop simply continues.
            return Ok(Some(ShellEvent::Other));
        }
        let ev = ShellEvent::from_line(line).map_err(|e| DaemonClientError::Protocol {
            detail: e.to_string(),
        })?;
        Ok(Some(ev))
    }

    /// Non-mutating identity probe used before reusing a retained daemon.
    pub fn daemon_info(&mut self) -> Result<(u32, String), DaemonClientError> {
        self.send(&ClientRequest::DaemonInfo)?;
        let mut budget = ReplyBudget::new("reading daemon_info reply");
        loop {
            match self.read_event("reading daemon_info reply", &mut budget)? {
                Some(ShellEvent::DaemonInfo {
                    protocol_version,
                    build_version,
                    ..
                }) => return Ok((protocol_version, build_version)),
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(_) => continue,
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "reading daemon_info reply",
                    })
                }
            }
        }
    }

    /// Require the exact mutation protocol before any `StartSession` is sent. Retained older
    /// daemons remain useful for attach/read/write/resize, but their historical start semantics can
    /// reap unrelated exited snapshots. Probe on this connection and fail closed; callers run this
    /// before writing durable session state.
    pub fn require_start_session_protocol(&mut self) -> Result<(), DaemonClientError> {
        let required = maestro_protocol::DAEMON_PROTOCOL_VERSION;
        match self.daemon_info() {
            Ok((observed, _)) if observed == required => Ok(()),
            Ok((observed, _)) => Err(DaemonClientError::MutationProtocolUnsupported {
                required,
                observed: Some(observed),
            }),
            Err(_) => Err(DaemonClientError::MutationProtocolUnsupported {
                required,
                observed: None,
            }),
        }
    }

    /// List the daemon's live session ids. Sends `ListSessions`, then reads until the `Sessions`
    /// reply, tolerating any unrelated events ([`ShellEvent::Other`]) that arrive first. A daemon
    /// `Error` reply is surfaced as [`DaemonClientError::DaemonError`].
    pub fn list_sessions(&mut self) -> Result<Vec<SessionId>, DaemonClientError> {
        Ok(self.list_sessions_snapshot()?.ids)
    }

    /// Read one atomic live-session snapshot, including additive generation metadata when supplied
    /// by a new daemon. Old retained daemons decode with an empty `sessions` vector.
    pub fn list_sessions_snapshot(&mut self) -> Result<ListedSessions, DaemonClientError> {
        self.send(&ClientRequest::ListSessions)?;
        let mut budget = ReplyBudget::new("reading list_sessions reply");
        loop {
            match self.read_event("reading list_sessions reply", &mut budget)? {
                Some(ShellEvent::Sessions { ids, sessions }) => {
                    return Ok(ListedSessions { ids, sessions })
                }
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                Some(ShellEvent::Other) => continue,
                // A Grid / SessionExited here is unrelated to our query — tolerate and keep reading.
                Some(_) => continue,
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "reading list_sessions reply",
                    })
                }
            }
        }
    }

    /// Start a session and attach to it structured-only, returning once the daemon delivers the
    /// session's grid baseline.
    ///
    /// Flow: validate the cwd is an existing directory -> send `StartSession` -> send
    /// `Attach{want_raw_output:false}` -> read until the first `Grid` whose id matches, tolerating
    /// unrelated events. The structured opt-out means NO raw PTY bytes reach this client — it never
    /// paints, it only needs the grid's generation/revision to confirm the session is live.
    ///
    /// Cwd policy: the cwd is a caller-supplied EXISTING DIRECTORY (or one already resolved by the
    /// workspace policy layer). If it is not an existing directory — missing, or an existing non-directory such as
    /// a regular file — [`DaemonClientError::InvalidCwd`] is returned BEFORE any request is written.
    /// This mirrors the daemon's own `Path::is_dir()` boundary, so the client rejects the same cwds
    /// the daemon would. This client never CREATES the cwd (no scratch-dir mkdir) and never runs
    /// git — directory/worktree creation belongs to the workspace execution layer.
    pub fn start_and_attach(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<AttachedSession, DaemonClientError> {
        self.start_and_attach_with_restart(id, cwd, command, args, (cols, rows), false)
    }

    /// Explicitly replace a retained exited same-id session, then attach to the replacement.
    ///
    /// Callers must obtain user restart authority before reaching this boundary. The protocol-v2
    /// capability check belongs in the runtime so this request is never sent to an older daemon
    /// whose historical same-id mutation semantics were ambiguous.
    pub fn restart_exited_and_attach(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        cols: u16,
        rows: u16,
    ) -> Result<AttachedSession, DaemonClientError> {
        self.start_and_attach_with_restart(id, cwd, command, args, (cols, rows), true)
    }

    fn start_and_attach_with_restart(
        &mut self,
        id: SessionId,
        cwd: &str,
        command: &str,
        args: &[String],
        dimensions: (u16, u16),
        restart_exited: bool,
    ) -> Result<AttachedSession, DaemonClientError> {
        let (cols, rows) = dimensions;
        // The cwd is checked FIRST, before any byte is written, so a bad cwd never leaves a dangling
        // StartSession on the wire. `is_dir()` matches the daemon's boundary (`daemon.rs`: it
        // rejects a non-directory cwd with `Path::is_dir()`), so a missing path OR an existing
        // regular file is rejected here rather than round-tripping to a daemon error. We only
        // INSPECT — we do NOT create the directory.
        if !Path::new(cwd).is_dir() {
            return Err(DaemonClientError::InvalidCwd {
                cwd: cwd.to_string(),
            });
        }

        self.send(&ClientRequest::StartSession {
            id: id.clone(),
            cwd: cwd.to_string(),
            command: command.to_string(),
            args: args.to_vec(),
            cols,
            rows,
            restart_exited,
        })?;
        self.attach_existing(id)
    }

    /// Attach to an already-retained session without sending any mutation request, returning after
    /// its first structured grid baseline. This is the safe app-upgrade path for an older daemon:
    /// legacy daemons remain useful for list/attach/read/write/resize even though their historical
    /// `StartSession` semantics are no longer trusted.
    pub fn attach_existing(&mut self, id: SessionId) -> Result<AttachedSession, DaemonClientError> {
        self.send(&ClientRequest::Attach {
            id: id.clone(),
            want_raw_output: false,
            output_generation: None,
        })?;

        let mut budget = ReplyBudget::new("awaiting grid baseline");
        loop {
            match self.read_event("awaiting grid baseline", &mut budget)? {
                Some(ShellEvent::Grid { id: got, grid }) if got == id => {
                    return Ok(AttachedSession {
                        id: got,
                        generation: grid.generation,
                        revision: grid.revision,
                    });
                }
                // A grid for a different session (the daemon may multiplex) is not ours — skip it.
                Some(ShellEvent::Grid { .. }) => continue,
                Some(ShellEvent::SessionExited { id: got, code }) if got == id => {
                    return Err(DaemonClientError::SessionExited { id: got, code });
                }
                Some(ShellEvent::SessionExited { .. }) => continue,
                Some(ShellEvent::Error { message }) => {
                    return Err(DaemonClientError::DaemonError { message })
                }
                // Sessions reply / damage / output / future events before our grid: tolerate.
                Some(ShellEvent::Sessions { .. })
                | Some(ShellEvent::DaemonInfo { .. })
                | Some(ShellEvent::Other) => continue,
                None => {
                    return Err(DaemonClientError::UnexpectedEof {
                        during: "awaiting grid baseline",
                    })
                }
            }
        }
    }

    /// Kill and remove one live session, then confirm it is no longer in the daemon's live list.
    ///
    /// Reuses the existing daemon `Kill` wire request (`{"op":"kill","id":"..."}`) — this adds NO
    /// new protocol. Because `Kill` has no direct ack for a non-attached client, success is NOT
    /// inferred from the send succeeding; it is confirmed by a subsequent `ListSessions` whose
    /// `Sessions` reply does not contain `id`.
    ///
    /// Flow: send `Kill{id}` -> send `ListSessions` -> read until `Sessions`. If `id` is absent,
    /// return `Ok(KilledSession{id})`. If it is still present (a daemon `Sessions` snapshot taken
    /// before the kill landed), send another `ListSessions` and re-check, up to
    /// [`KILL_CONFIRM_ROUNDS`] times. Unrelated `Grid` / `SessionExited` / `Other` events are
    /// tolerated while waiting. A daemon `Error` becomes [`DaemonClientError::DaemonError`]; EOF,
    /// timeout, oversized line, protocol, and I/O faults surface through the existing typed errors.
    ///
    /// Idempotent: an already-absent session is `Ok` — this means "no longer live", not "this client
    /// killed it". That is the right shape for tab-close cleanup, where repeated cleanup or a
    /// naturally exited session must not become a fatal user-facing error. Bounded by the connection
    /// timeout; it never blocks forever.
    pub fn kill_session(&mut self, id: SessionId) -> Result<KilledSession, DaemonClientError> {
        // 1) Ask the daemon to kill and drop the session. No ack is expected for a non-attached
        //    client, so this is fire-and-confirm: the ListSessions round below is the source of
        //    truth, not the success of this write.
        self.send(&ClientRequest::Kill { id: id.clone() })?;

        // 2) Confirm absence via ListSessions. Re-issue a bounded number of times so a daemon that
        //    answers with a pre-kill snapshot on the first round still converges, while a daemon
        //    that keeps reporting the id cannot wedge us — the rounds are finite and each read is
        //    timeout-bounded.
        let mut budget = ReplyBudget::new("confirming kill via list_sessions");
        for _ in 0..KILL_CONFIRM_ROUNDS {
            self.send(&ClientRequest::ListSessions)?;
            loop {
                match self.read_event("confirming kill via list_sessions", &mut budget)? {
                    Some(ShellEvent::Sessions { ids, .. }) => {
                        if !ids.contains(&id) {
                            return Ok(KilledSession { id });
                        }
                        // Still present: break to the outer loop and re-issue ListSessions.
                        break;
                    }
                    Some(ShellEvent::Error { message }) => {
                        return Err(DaemonClientError::DaemonError { message })
                    }
                    // A Grid / SessionExited / blank line here is unrelated to our confirmation —
                    // tolerate and keep reading for the Sessions reply.
                    Some(_) => continue,
                    None => {
                        return Err(DaemonClientError::UnexpectedEof {
                            during: "confirming kill via list_sessions",
                        })
                    }
                }
            }
        }

        // The id was still present after every bounded confirmation round. Surface this as a
        // protocol-level failure rather than blocking — the kill did not take effect within the
        // confirmation budget.
        Err(DaemonClientError::Protocol {
            detail: format!(
                "session {id:?} still present after {KILL_CONFIRM_ROUNDS} kill confirmation rounds"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream as StdUnixStream};
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread::JoinHandle;

    #[test]
    fn kernel_peer_identity_accepts_only_the_same_effective_uid() {
        let path = Path::new("/tmp/synthetic-daemon.sock");
        assert!(verify_connected_server_identity(path, 501, Ok(501)).is_ok());

        let mismatch = verify_connected_server_identity(path, 501, Ok(502))
            .expect_err("a different OS user must never be accepted as the daemon");
        assert!(matches!(
            mismatch,
            DaemonClientError::UntrustedDaemon {
                expected_uid: 501,
                observed_uid: Some(502),
                ..
            }
        ));

        let unavailable = verify_connected_server_identity(
            path,
            501,
            Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "synthetic missing peer credentials",
            )),
        )
        .expect_err("an unidentifiable server must fail closed");
        assert!(matches!(
            unavailable,
            DaemonClientError::UntrustedDaemon {
                expected_uid: 501,
                observed_uid: None,
                ..
            }
        ));
    }

    #[test]
    fn connected_local_stub_reports_this_process_as_its_server_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("peer-identity.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let connector = std::thread::spawn({
            let path = path.clone();
            move || StdUnixStream::connect(path).unwrap()
        });
        let (server, _) = listener.accept().unwrap();
        let client = connector.join().unwrap();

        assert_eq!(connected_server_uid(&client).unwrap(), effective_uid());
        assert_eq!(connected_server_uid(&server).unwrap(), effective_uid());
    }

    /// A loopback stub daemon: a real Unix socket on a temp path, served by one accept thread that
    /// runs a caller-supplied script `(reader, writer) -> ()`. This is NOT the real daemon — it lets
    /// us assert exactly what the client writes and control exactly what it reads, with no PTY, no
    /// git, and no `pty-daemon` process. The captured request lines are sent back over an mpsc so the
    /// test can assert their JSON shape.
    struct StubDaemon {
        path: PathBuf,
        // Kept so the socket file + temp dir outlive the test; dropping cleans them up.
        _dir: tempfile::TempDir,
        handle: Option<JoinHandle<()>>,
        requests: mpsc::Receiver<String>,
    }

    impl StubDaemon {
        /// Spawn a stub that, on the first connection, runs `serve(reader_lines_tx, writer)`. The
        /// closure receives a channel to publish each request line it reads (for assertions) and the
        /// write half to push replies.
        fn spawn<F>(serve: F) -> StubDaemon
        where
            F: FnOnce(&mpsc::Sender<String>, &mut StdUnixStream) + Send + 'static,
        {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("stub.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let (req_tx, req_rx) = mpsc::channel::<String>();
            let handle = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    serve(&req_tx, &mut stream);
                    // Dropping the stream closes the peer (the client sees EOF).
                    drop(stream);
                }
            });
            StubDaemon {
                path,
                _dir: dir,
                handle: Some(handle),
                requests: req_rx,
            }
        }

        /// Collect all request lines the stub recorded (after the serve closure has finished).
        fn collected_requests(&self) -> Vec<String> {
            self.requests.try_iter().collect()
        }
    }

    impl Drop for StubDaemon {
        fn drop(&mut self) {
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    /// Read one newline-delimited request line from `stream` and publish it on `tx`. Returns the
    /// parsed line (trimmed), or None on EOF.
    fn read_request(reader: &mut impl BufRead, tx: &mpsc::Sender<String>) -> Option<String> {
        let mut line = String::new();
        let n = reader.read_line(&mut line).unwrap();
        if n == 0 {
            return None;
        }
        let trimmed = line.trim().to_string();
        let _ = tx.send(trimmed.clone());
        Some(trimmed)
    }

    fn sid(s: &str) -> SessionId {
        SessionId(s.to_string())
    }

    /// A canonical full daemon `Grid` line for session `id` at the given generation/revision — the
    /// heavy snapshot the client must read `generation`/`revision` out of without modeling cells.
    fn grid_line(id: &str, generation: &str, revision: u64) -> String {
        format!(
            r#"{{"ev":"grid","id":"{id}","grid":{{"version":2,"generation":"{generation}","revision":{revision},"base_revision":0,"cols":1,"rows":1,"rows_cells":[[{{"text":"x","fg":{{"kind":"named","name":"foreground"}},"bg":{{"kind":"named","name":"background"}},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}}]],"cursor_line":0,"cursor_col":0,"cursor_visible":true,"cursor_shape":"block","alt_screen":false,"app_cursor":false,"bracketed_paste":false,"focus_reporting":false,"mouse_report":false,"mouse_drag":false,"mouse_motion":false,"mouse_sgr":false}}}}"#
        )
    }

    /// The core happy path: `start_and_attach` writes `StartSession` then
    /// `Attach{want_raw_output:false}` IN ORDER with the exact daemon JSON shape, and a `Grid` reply
    /// returns the expected generation/revision.
    #[test]
    fn start_and_attach_sends_requests_in_order_and_returns_grid() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();

        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            // First request: StartSession.
            read_request(&mut reader, tx);
            // Second request: Attach.
            read_request(&mut reader, tx);
            // Reply with the grid baseline.
            stream
                .write_all(format!("{}\n", grid_line("s1", "gen-aaa", 7)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let attached = client
            .start_and_attach(sid("s1"), &cwd_path, "bash", &["-l".to_string()], 80, 24)
            .unwrap();
        assert_eq!(
            attached,
            AttachedSession {
                id: sid("s1"),
                generation: "gen-aaa".to_string(),
                revision: Some(7),
            }
        );
        drop(client); // close our side so the stub's reader sees EOF and the thread joins.

        let reqs = stub.collected_requests();
        assert_eq!(reqs.len(), 2, "expected StartSession then Attach: {reqs:?}");
        assert_eq!(
            reqs[0],
            format!(
                r#"{{"op":"start_session","id":"s1","cwd":"{cwd_path}","command":"bash","args":["-l"],"cols":80,"rows":24}}"#
            )
        );
        assert_eq!(
            reqs[1],
            r#"{"op":"attach","id":"s1","want_raw_output":false}"#
        );
    }

    #[test]
    fn explicit_exited_restart_sets_protocol_authority_before_attach() {
        let cwd = tempfile::TempDir::new().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
            stream
                .write_all(format!("{}\n", grid_line("s1", "gen-restarted", 1)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let attached = client
            .restart_exited_and_attach(sid("s1"), &cwd_path, "bash", &[], 80, 24)
            .unwrap();
        assert_eq!(attached.generation, "gen-restarted");
        drop(client);

        let reqs = stub.collected_requests();
        assert_eq!(reqs.len(), 2);
        assert_eq!(
            reqs[0],
            format!(
                r#"{{"op":"start_session","id":"s1","cwd":"{cwd_path}","command":"bash","args":[],"cols":80,"rows":24,"restart_exited":true}}"#
            )
        );
        assert_eq!(
            reqs[1],
            r#"{"op":"attach","id":"s1","want_raw_output":false}"#
        );
    }

    #[test]
    fn attach_existing_sends_no_start_session_mutation() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            stream
                .write_all(format!("{}\n", grid_line("kept", "gen-kept", 9)).as_bytes())
                .unwrap();
            stream.flush().unwrap();
        });

        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let attached = client.attach_existing(sid("kept")).unwrap();
        assert_eq!(attached.id, sid("kept"));
        assert_eq!(attached.generation, "gen-kept");
        assert_eq!(attached.revision, Some(9));
        drop(client);

        assert_eq!(
            stub.collected_requests(),
            vec![r#"{"op":"attach","id":"kept","want_raw_output":false}"#.to_string()]
        );
    }

    /// A `Grid` whose snapshot omits `revision` still attaches; generation is the only required
    /// field, revision comes back `None`.
    #[test]
    fn grid_without_revision_returns_none_revision() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
            stream
                .write_all(br#"{"ev":"grid","id":"s1","grid":{"generation":"g-only"}}"#)
                .unwrap();
            stream.write_all(b"\n").unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let attached = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap();
        assert_eq!(attached.generation, "g-only");
        assert_eq!(attached.revision, None);
    }

    /// `list_sessions` sends `{"op":"list_sessions"}` and decodes the live ids from the `Sessions`
    /// reply.
    #[test]
    fn list_sessions_decodes_live_ids() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"a\",\"b\",\"c\"]}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let ids = client.list_sessions().unwrap();
        assert_eq!(ids, vec![sid("a"), sid("b"), sid("c")]);
        drop(client);
        let reqs = stub.collected_requests();
        assert_eq!(reqs, vec![r#"{"op":"list_sessions"}"#.to_string()]);
    }

    #[test]
    fn list_sessions_snapshot_decodes_generation_metadata_and_legacy_default() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            stream
                .write_all(
                    b"{\"ev\":\"sessions\",\"ids\":[\"a\"],\"sessions\":[{\"id\":\"a\",\"cwd\":\"/tmp\",\"generation\":\"gen-a\"}]}\n",
                )
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let snapshot = client.list_sessions_snapshot().unwrap();
        assert_eq!(snapshot.ids, vec![sid("a")]);
        assert_eq!(snapshot.sessions.len(), 1);
        assert_eq!(snapshot.sessions[0].id, sid("a"));
        assert_eq!(snapshot.sessions[0].generation.as_deref(), Some("gen-a"));
    }

    /// An `Error` reply is surfaced as a typed `DaemonError`, not swallowed.
    #[test]
    fn error_reply_is_surfaced() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
            stream
                .write_all(b"{\"ev\":\"error\",\"message\":\"boom\"}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::DaemonError { message } => assert_eq!(message, "boom"),
            other => panic!("expected DaemonError, got {other:?}"),
        }
    }

    /// A `SessionExited` for our session BEFORE any `Grid` is surfaced as a typed `SessionExited`
    /// (e.g. the command failed to launch / exited immediately).
    #[test]
    fn session_exited_before_grid_is_surfaced() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
            stream
                .write_all(b"{\"ev\":\"session_exited\",\"id\":\"s1\",\"code\":3}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::SessionExited { id, code } => {
                assert_eq!(id, sid("s1"));
                assert_eq!(code, Some(3));
            }
            other => panic!("expected SessionExited, got {other:?}"),
        }
    }

    /// Unrelated events streamed BEFORE the grid (a structured attach emits damage continuously,
    /// plus output/resync/channel/scrollback and even a grid for a DIFFERENT session) are all
    /// tolerated; the client keeps reading until ITS grid arrives.
    #[test]
    fn unrelated_events_before_grid_are_tolerated() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
            let mut send = |s: &str| {
                stream.write_all(s.as_bytes()).unwrap();
                stream.write_all(b"\n").unwrap();
            };
            // A grab-bag of events the client must skip.
            send(r#"{"ev":"output","id":"s1","generation":"g","revision":1,"data":"aGk="}"#);
            send(r#"{"ev":"resync_required","id":"s1"}"#);
            send(
                r#"{"ev":"channel","event":{"channel":"c1","from":null,"kind":"chat_msg","text":"hi","ts":1}}"#,
            );
            send(r#"{"ev":"some_future_event","x":1}"#);
            // A grid for a DIFFERENT session — not ours, must be skipped.
            send(&grid_line("other", "gen-other", 99));
            // A sessions reply mid-stream — also tolerated.
            send(r#"{"ev":"sessions","ids":["s1"]}"#);
            // Finally OUR grid.
            send(&grid_line("s1", "gen-mine", 42));
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let attached = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap();
        assert_eq!(attached.id, sid("s1"));
        assert_eq!(attached.generation, "gen-mine");
        assert_eq!(attached.revision, Some(42));
    }

    #[test]
    fn endless_unrelated_events_exhaust_one_operation_budget() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            for _ in 0..=MAX_REPLY_EVENTS_PER_OPERATION {
                if stream
                    .write_all(b"{\"ev\":\"some_future_event\"}\n")
                    .is_err()
                {
                    break;
                }
            }
            let _ = stream.flush();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        assert!(matches!(
            client.list_sessions(),
            Err(DaemonClientError::ReplyBudgetExceeded {
                during: "reading list_sessions reply"
            })
        ));
    }

    #[test]
    fn newline_in_byte_after_frame_limit_is_still_oversized() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            let mut line = vec![b' '; MAX_LINE_BYTES + 1];
            *line.last_mut().unwrap() = b'\n';
            let _ = stream.write_all(&line);
            let _ = stream.flush();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        assert!(matches!(
            client.list_sessions(),
            Err(DaemonClientError::LineTooLong {
                direction: Direction::Inbound,
                limit: MAX_LINE_BYTES,
            })
        ));
    }

    /// An oversized reply line (no newline within the cap) is rejected as `LineTooLong` WITHOUT the
    /// client buffering the whole thing — it stops at one byte over the limit. We prove rejection;
    /// the bound is structural (the `take(MAX_LINE_BYTES + 1)` cap).
    #[test]
    fn oversized_line_is_rejected_without_unbounded_buffering() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
            // Start a JSON line and never terminate it; push more than the cap so the client's
            // bounded read trips. Write in chunks; ignore a broken pipe once the client gives up.
            let chunk = vec![b'a'; 1024 * 1024];
            let mut written = 0usize;
            stream
                .write_all(b"{\"ev\":\"grid\",\"id\":\"s1\",\"junk\":\"")
                .unwrap();
            while written <= MAX_LINE_BYTES + 1 {
                if stream.write_all(&chunk).is_err() {
                    break;
                }
                written += chunk.len();
            }
            let _ = stream.flush();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::LineTooLong { direction, limit } => {
                assert_eq!(direction, Direction::Inbound);
                assert_eq!(limit, MAX_LINE_BYTES);
            }
            other => panic!("expected inbound LineTooLong, got {other:?}"),
        }
    }

    /// An oversized OUTBOUND request (here a `StartSession` with enormous args) is rejected before
    /// any bytes reach the daemon: the stub records ZERO requests and the error is an `Outbound`
    /// `LineTooLong`. This is the request-side mirror of the inbound cap.
    #[test]
    fn oversized_request_is_rejected_before_any_bytes_written() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let stub = StubDaemon::spawn(|tx, stream| {
            // The client must NOT write anything; if it does, capture it so the assertion fails.
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        // One arg larger than the whole line cap guarantees the serialized request exceeds it.
        let huge_arg = "a".repeat(MAX_LINE_BYTES + 1);
        let err = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[huge_arg], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::LineTooLong { direction, limit } => {
                assert_eq!(direction, Direction::Outbound);
                assert_eq!(limit, MAX_LINE_BYTES);
            }
            other => panic!("expected outbound LineTooLong, got {other:?}"),
        }
        drop(client); // close so the stub's read sees EOF.
        assert!(
            stub.collected_requests().is_empty(),
            "no request bytes must be written when the request line is oversized"
        );
    }

    /// Connecting to a nonexistent socket path returns the typed daemon-unavailable error, distinct
    /// from a daemon that answered with an error.
    #[test]
    fn connect_to_missing_socket_is_daemon_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        // `DaemonClient` owns a socket and is not `Debug`, so match on the `Result` directly rather
        // than `unwrap_err()` (which would require `Ok` to be `Debug`).
        match DaemonClient::connect(&missing) {
            Err(DaemonClientError::DaemonUnavailable { path, .. }) => {
                assert!(path.contains("does-not-exist.sock"), "path was {path}");
            }
            Err(other) => panic!("expected DaemonUnavailable, got {other:?}"),
            Ok(_) => panic!("expected DaemonUnavailable, got a connected client"),
        }
    }

    /// A missing cwd returns `InvalidCwd` BEFORE any request is written — the stub records zero
    /// requests, proving the check is pre-flight (no half-issued StartSession on the wire).
    #[test]
    fn missing_cwd_returns_invalid_cwd_before_any_request() {
        let stub = StubDaemon::spawn(|tx, stream| {
            // If the client (incorrectly) sent anything, capture it so the assertion below fails.
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            // Non-blocking-ish: try to read one line; on EOF (the expected case) this returns None.
            read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .start_and_attach(sid("s1"), "/no/such/dir/anywhere-xyz", "sh", &[], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::InvalidCwd { cwd } => {
                assert_eq!(cwd, "/no/such/dir/anywhere-xyz")
            }
            other => panic!("expected InvalidCwd, got {other:?}"),
        }
        drop(client); // close so the stub's read sees EOF.
        assert!(
            stub.collected_requests().is_empty(),
            "no request must be written when cwd is invalid"
        );
    }

    /// An EXISTING regular file (not a directory) is rejected as `InvalidCwd` BEFORE any request is
    /// written — the stub records zero requests. This is the `is_dir()` boundary: `exists()` would
    /// have wrongly accepted the file, but the daemon rejects a non-directory cwd, so the client
    /// must too.
    #[test]
    fn existing_file_cwd_returns_invalid_cwd_before_any_request() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("not-a-dir.txt");
        std::fs::write(&file_path, b"i am a file").unwrap();
        let file_cwd = file_path.to_string_lossy().to_string();
        assert!(Path::new(&file_cwd).exists() && !Path::new(&file_cwd).is_dir());

        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client
            .start_and_attach(sid("s1"), &file_cwd, "sh", &[], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::InvalidCwd { cwd } => assert_eq!(cwd, file_cwd),
            other => panic!("expected InvalidCwd, got {other:?}"),
        }
        drop(client); // close so the stub's read sees EOF.
        assert!(
            stub.collected_requests().is_empty(),
            "no request must be written when cwd is an existing file"
        );
    }

    /// A silent daemon (accepts, then never replies) makes a read hit the deadline, surfaced as a
    /// typed `Timeout` rather than hanging the caller. We use a very short timeout to keep the test
    /// fast.
    #[test]
    fn silent_daemon_times_out() {
        let cwd = tempfile::tempdir().unwrap();
        let cwd_path = cwd.path().to_string_lossy().to_string();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx);
            read_request(&mut reader, tx);
            // Deliberately send NOTHING. Hold the connection open until the test releases us, so the
            // client's read blocks and then times out.
            let _ = release_rx.recv();
        });
        let mut client =
            DaemonClient::connect_with_timeout(&stub.path, Duration::from_millis(150)).unwrap();
        let err = client
            .start_and_attach(sid("s1"), &cwd_path, "sh", &[], 80, 24)
            .unwrap_err();
        match err {
            DaemonClientError::Timeout { .. } => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
        // Let the stub thread exit.
        let _ = release_tx.send(());
    }

    /// `kill_session` writes the EXACT existing daemon `Kill` wire shape (`{"op":"kill","id":"s1"}`)
    /// FOLLOWED by `{"op":"list_sessions"}`, then returns `Ok(KilledSession{id})` once the post-kill
    /// `Sessions` reply no longer contains the id. This pins the no-new-protocol guarantee: kill
    /// reuses `ClientRequest::Kill` and confirmation reuses `ListSessions`.
    #[test]
    fn kill_session_sends_kill_then_list_and_confirms_absent() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            // First request: Kill.
            read_request(&mut reader, tx);
            // Second request: ListSessions.
            read_request(&mut reader, tx);
            // Reply with a session list that does NOT contain s1 (the others survive).
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"s2\",\"s3\"]}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let killed = client.kill_session(sid("s1")).unwrap();
        assert_eq!(killed, KilledSession { id: sid("s1") });
        drop(client);
        let reqs = stub.collected_requests();
        assert_eq!(reqs.len(), 2, "expected Kill then ListSessions: {reqs:?}");
        assert_eq!(reqs[0], r#"{"op":"kill","id":"s1"}"#);
        assert_eq!(reqs[1], r#"{"op":"list_sessions"}"#);
    }

    /// Idempotent already-absent: killing a session the daemon already doesn't know about returns
    /// `Ok` — "no longer live", not an error. The first `Sessions` reply omits it (e.g. it exited on
    /// its own), and the method succeeds without retrying.
    #[test]
    fn kill_session_already_absent_is_ok() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
                                           // s1 was never (or no longer) in the list.
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[]}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let killed = client.kill_session(sid("s1")).unwrap();
        assert_eq!(killed.id, sid("s1"));
    }

    /// If the FIRST `Sessions` snapshot still lists the id (a daemon reply taken before the kill
    /// landed), the method re-issues `ListSessions` and confirms on a later round. Here the first
    /// reply still contains s1, the second does not — success, with exactly two ListSessions sent.
    #[test]
    fn kill_session_present_then_absent_retries_and_succeeds() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions (round 1)
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"s1\"]}\n")
                .unwrap();
            stream.flush().unwrap();
            read_request(&mut reader, tx); // ListSessions (round 2)
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[]}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let killed = client.kill_session(sid("s1")).unwrap();
        assert_eq!(killed.id, sid("s1"));
        drop(client);
        let reqs = stub.collected_requests();
        assert_eq!(
            reqs,
            vec![
                r#"{"op":"kill","id":"s1"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
            ]
        );
    }

    /// Unrelated `Grid` / `SessionExited` / blank events arriving before the `Sessions` reply are
    /// tolerated; the confirmation loop keeps reading until it sees the session list.
    #[test]
    fn kill_session_tolerates_unrelated_events_before_sessions() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
            let mut send = |s: &str| {
                stream.write_all(s.as_bytes()).unwrap();
                stream.write_all(b"\n").unwrap();
            };
            // A SessionExited for the very session we killed — informational, must be tolerated.
            send(r#"{"ev":"session_exited","id":"s1","code":0}"#);
            // A grid for a different session mid-stream.
            send(&grid_line("other", "gen-other", 5));
            // A blank line (decoded as Other).
            send("");
            // Finally the sessions reply with s1 absent.
            send(r#"{"ev":"sessions","ids":["other"]}"#);
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let killed = client.kill_session(sid("s1")).unwrap();
        assert_eq!(killed.id, sid("s1"));
    }

    /// A daemon `Error` reply during confirmation is surfaced as a typed `DaemonError`, not
    /// swallowed or treated as success.
    #[test]
    fn kill_session_daemon_error_is_surfaced() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
            stream
                .write_all(b"{\"ev\":\"error\",\"message\":\"nope\"}\n")
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client.kill_session(sid("s1")).unwrap_err();
        match err {
            DaemonClientError::DaemonError { message } => assert_eq!(message, "nope"),
            other => panic!("expected DaemonError, got {other:?}"),
        }
    }

    /// A daemon that keeps reporting the killed id on EVERY confirmation round eventually gives up
    /// with a bounded `Protocol` error rather than blocking forever. The stub answers every
    /// `ListSessions` with the id still present; the method must stop after `KILL_CONFIRM_ROUNDS`.
    #[test]
    fn kill_session_persistently_present_is_bounded_protocol_error() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // Kill
                                           // Answer every ListSessions with s1 still present, until the client gives up and EOFs.
            while read_request(&mut reader, tx).is_some() {
                if stream
                    .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"s1\"]}\n")
                    .is_err()
                {
                    break;
                }
                let _ = stream.flush();
            }
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client.kill_session(sid("s1")).unwrap_err();
        match err {
            DaemonClientError::Protocol { detail } => {
                assert!(detail.contains("still present"), "detail was {detail}");
            }
            other => panic!("expected bounded Protocol error, got {other:?}"),
        }
        drop(client);
        // Exactly one Kill + KILL_CONFIRM_ROUNDS ListSessions were written — the loop is bounded.
        let reqs = stub.collected_requests();
        assert_eq!(reqs[0], r#"{"op":"kill","id":"s1"}"#);
        assert_eq!(
            reqs.len(),
            1 + KILL_CONFIRM_ROUNDS,
            "expected 1 Kill + {KILL_CONFIRM_ROUNDS} ListSessions: {reqs:?}"
        );
    }

    /// An oversized `Sessions` reply (no newline within the cap) during kill confirmation is still
    /// bounded by `MAX_LINE_BYTES`: the client rejects it as inbound `LineTooLong` rather than
    /// buffering unboundedly.
    #[test]
    fn kill_session_oversized_reply_is_bounded() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
                                           // Begin a never-terminated line and push past the cap.
            let chunk = vec![b'a'; 1024 * 1024];
            stream
                .write_all(b"{\"ev\":\"sessions\",\"junk\":\"")
                .unwrap();
            let mut written = 0usize;
            while written <= MAX_LINE_BYTES + 1 {
                if stream.write_all(&chunk).is_err() {
                    break;
                }
                written += chunk.len();
            }
            let _ = stream.flush();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client.kill_session(sid("s1")).unwrap_err();
        match err {
            DaemonClientError::LineTooLong { direction, limit } => {
                assert_eq!(direction, Direction::Inbound);
                assert_eq!(limit, MAX_LINE_BYTES);
            }
            other => panic!("expected inbound LineTooLong, got {other:?}"),
        }
    }

    /// `kill_session` against a missing socket never gets a client at all: connect fails with
    /// `DaemonUnavailable` BEFORE any Kill request can be written.
    #[test]
    fn kill_session_missing_socket_is_daemon_unavailable_before_request() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist.sock");
        match DaemonClient::connect(&missing) {
            Err(DaemonClientError::DaemonUnavailable { path, .. }) => {
                assert!(path.contains("does-not-exist.sock"), "path was {path}");
            }
            Err(other) => panic!("expected DaemonUnavailable, got {other:?}"),
            Ok(_) => panic!("expected DaemonUnavailable, got a connected client"),
        }
    }

    /// A silent daemon during kill confirmation (accepts Kill + ListSessions, then never replies)
    /// hits the read deadline and surfaces a typed `Timeout` rather than hanging.
    #[test]
    fn kill_session_silent_daemon_times_out() {
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let stub = StubDaemon::spawn(move |tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
                                           // Send nothing; hold the connection open so the client's read blocks then times out.
            let _ = release_rx.recv();
        });
        let mut client =
            DaemonClient::connect_with_timeout(&stub.path, Duration::from_millis(150)).unwrap();
        let err = client.kill_session(sid("s1")).unwrap_err();
        match err {
            DaemonClientError::Timeout { .. } => {}
            other => panic!("expected Timeout, got {other:?}"),
        }
        let _ = release_tx.send(());
    }

    /// A daemon that drops the connection (clean EOF) during kill confirmation surfaces
    /// `UnexpectedEof`, not a hang or a false success.
    #[test]
    fn kill_session_eof_during_confirm_is_unexpected_eof() {
        let stub = StubDaemon::spawn(|tx, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            read_request(&mut reader, tx); // Kill
            read_request(&mut reader, tx); // ListSessions
                                           // Return without replying: the accept thread drops the owned stream, so the
                                           // client sees a clean EOF while awaiting the Sessions reply.
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let err = client.kill_session(sid("s1")).unwrap_err();
        match err {
            DaemonClientError::UnexpectedEof { .. } => {}
            other => panic!("expected UnexpectedEof, got {other:?}"),
        }
    }
}
