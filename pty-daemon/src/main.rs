//! pty-daemon entrypoint: a long-lived process that owns PTYs (sessions) and a
//! channel bus, and serves a newline-delimited JSON protocol over a Unix
//! domain socket. The UI attaches/detaches; the daemon and its agent processes
//! live on, giving tier-(a) session survival across UI restarts.

mod channel;
mod daemon;
mod grid;
mod ids;
mod outbound;
mod peercred;
mod protocol;
mod revision;
mod session;
mod socket;

use crate::daemon::{ConditionalSessionTake, Daemon, SessionAttachmentAcquireError, SharedDaemon};
use crate::ids::SessionId;
use crate::protocol::{
    AttachmentHandoff, AttachmentHandoffToken, ClientRequest, DaemonEvent, SessionAttachRefusal,
    SessionStartOperationToken, MAX_LINE_BYTES,
};
use crate::session::AttachmentGuard;
use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::task::AbortHandle;

/// Secondary per-client event-count guard. The authoritative memory limit is
/// [`OUT_QUEUE_BYTES`], enforced against exact newline-JSON bytes.
const OUT_QUEUE_CAP: usize = 4096;
/// Exact encoded bytes retained per client. Once full, revision-dependent sends await permits;
/// their broadcast receiver then lags and uses the existing atomic resync path. An individual event
/// larger than this cannot be represented safely, so the affected client connection is retired.
const OUT_QUEUE_BYTES: usize = 32 * 1024 * 1024;
const _: () = assert!(OUT_QUEUE_BYTES >= MAX_LINE_BYTES);

/// Default socket path. The UI passes the same path; one daemon per user.
fn default_socket_path() -> PathBuf {
    // SAFETY: geteuid has no preconditions and does not dereference memory.
    default_socket_path_for_uid(|key| std::env::var_os(key), unsafe { libc::geteuid() })
}

/// Testable form of [`default_socket_path`]. Empty environment values are absent, matching the
/// installed launcher and `maestro-shell` endpoint resolver rather than producing a relative path.
fn default_socket_path_for_uid(
    get_env: impl Fn(&str) -> Option<OsString>,
    effective_uid: u32,
) -> PathBuf {
    let base = ["XDG_RUNTIME_DIR", "TMPDIR"]
        .into_iter()
        .find_map(|key| get_env(key).filter(|value| !value.is_empty()))
        .unwrap_or_else(|| OsString::from("/tmp"));
    PathBuf::from(base).join(maestro_protocol::daemon_socket_filename(effective_uid))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pty_daemon=info".into()),
        )
        .init();

    let socket_path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(default_socket_path);

    // Socket-clobber guard: never blindly unlink the socket — a second
    // daemon doing that would orphan the first daemon's live sessions
    // (split-brain). `prepare_socket_path` probes the existing path with a
    // bounded timeout and only unlinks a socket proven STALE (connect refused),
    // refusing a live, foreign-owned, insecure, or ambiguous one. See socket.rs.
    socket::prepare_socket_path(&socket_path)?;
    // Lock the socket to the owner (0600). Anyone who can connect can spawn
    // arbitrary commands as this user, so a world-/group-reachable socket in a
    // shared /tmp (or on macOS, which has no XDG_RUNTIME_DIR) is a local-RCE
    // gap. `bind_secure` tightens the umask to 077 around the bind so the socket
    // is never momentarily group/world reachable, then pins 0600 as verification.
    let listener = socket::bind_secure(&socket_path, |p| UnixListener::bind(p))?;
    tracing::info!(socket = %socket_path.display(), "pty-daemon listening");

    let shared = Daemon::shared();

    // Race the accept loop against a termination signal. On SIGINT/SIGTERM we stop
    // accepting and run graceful shutdown: kill + reap every owned child so the
    // daemon does not leave orphans/zombies behind. The accept loop only returns
    // on a hard error, which we surface; the normal exit path is the signal.
    tokio::select! {
        accept_result = accept_loop(&listener, &shared) => {
            // accept_loop loops forever unless `accept()` errors; reaching here
            // means a fatal listener error. Still run shutdown so children aren't
            // orphaned, then propagate the error.
            let report = shared.lock().await.shutdown();
            log_shutdown_report(&report);
            let _ = std::fs::remove_file(&socket_path);
            return accept_result;
        }
        signal = wait_for_shutdown_signal() => {
            match signal {
                Some(name) => tracing::info!(signal = name, "received termination signal; shutting down"),
                None => tracing::warn!("signal handler unavailable; shutting down"),
            }
        }
    }

    // Graceful shutdown: terminate and reap owned children, then report whether
    // every one confirmed reaped before we exit.
    let report = shared.lock().await.shutdown();
    log_shutdown_report(&report);
    // Best-effort: remove our own socket so a restart sees a clean path rather
    // than a stale one it must probe.
    let _ = std::fs::remove_file(&socket_path);

    if report.all_reaped() {
        Ok(())
    } else {
        // A degraded shutdown (a child didn't confirm reaped) exits non-zero so a
        // supervisor can notice, rather than silently claiming a clean exit.
        Err(anyhow::anyhow!(
            "shutdown could not confirm {} of {} child(ren) reaped within the timeout",
            report.unconfirmed.len(),
            report.total
        ))
    }
}

/// The connection accept loop. Loops forever, spawning a handler per accepted
/// connection; returns only if `accept()` itself errors (a fatal listener fault).
async fn accept_loop(listener: &UnixListener, shared: &SharedDaemon) -> Result<()> {
    loop {
        let (stream, _addr) = listener.accept().await?;
        // Peer-credential check (defense-in-depth over the 0600 socket perms): only
        // a process running as THIS user may drive the daemon, since a connection can
        // spawn arbitrary commands as us. A mismatched or unreadable credential drops
        // the connection before any request is parsed.
        match peercred::authorize(&stream) {
            Ok(_uid) => {}
            Err(e) => {
                tracing::warn!(error = %e, "rejecting connection: peer credential check failed");
                drop(stream);
                continue;
            }
        }
        let shared = shared.clone();
        tokio::spawn(async move {
            // Split here so handle_client stays transport-agnostic over the read/write halves.
            let (read_half, write_half) = stream.into_split();
            if let Err(e) = handle_client(read_half, write_half, shared).await {
                tracing::warn!(error = %e, "client connection ended");
            }
        });
    }
}

/// Await the first of SIGINT or SIGTERM. Resolves to the signal name, or `None`
/// if the signal handlers could not be installed (we then shut down anyway,
/// rather than hang ignoring termination). On non-unix this never resolves;
/// the daemon is unix-only, so that branch is unreachable in practice.
async fn wait_for_shutdown_signal() -> Option<&'static str> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigint = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to install SIGINT handler");
            return None;
        }
    };
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to install SIGTERM handler");
            return None;
        }
    };
    tokio::select! {
        _ = sigint.recv() => Some("SIGINT"),
        _ = sigterm.recv() => Some("SIGTERM"),
    }
}

/// Log the outcome of a graceful shutdown at an appropriate level: info when
/// every child confirmed reaped, warn (with the offending ids) otherwise.
fn log_shutdown_report(report: &crate::daemon::ShutdownReport) {
    if report.all_reaped() {
        tracing::info!(
            total = report.total,
            reaped = report.reaped,
            "graceful shutdown: all children reaped"
        );
    } else {
        tracing::warn!(
            total = report.total,
            reaped = report.reaped,
            unconfirmed = ?report.unconfirmed,
            "graceful shutdown: some children did not confirm reaped within the timeout"
        );
    }
}

static NEXT_ATTACHMENT_OWNER_NONCE: AtomicU64 = AtomicU64::new(0);

fn allocate_attachment_owner_nonce(counter: &AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .ok()?
        .checked_add(1)
}

/// One connection-local attachment. The non-cloneable guard owns the exact Session lifetime; the
/// optional abort handle owns its live forwarder. Every connection-exit path drops this value, so
/// EOF, framing/read error, outbound failure, and request cancellation all release by RAII.
struct ClientAttachment {
    guard: Option<AttachmentGuard>,
    forwarder: Option<AbortHandle>,
    offered_token: Option<AttachmentHandoffToken>,
}

impl ClientAttachment {
    fn new(
        guard: AttachmentGuard,
        forwarder: Option<AbortHandle>,
        offered_token: Option<AttachmentHandoffToken>,
    ) -> Self {
        Self {
            guard: Some(guard),
            forwarder,
            offered_token,
        }
    }

    fn detach(mut self) {
        if let Some(handle) = self.forwarder.take() {
            handle.abort();
        }
        if let Some(guard) = self.guard.take() {
            guard.detach();
        }
    }

    /// Relinquish only this connection's exact Session guard before its own conditional Kill. The
    /// forwarder remains subscribed long enough to deliver `SessionExited` after the child is
    /// signalled. Any guard owned by another client remains in the Session fence and still makes
    /// the daemon's generation-CAS take fail closed.
    fn release_guard_for_own_kill(&mut self) {
        if let Some(guard) = self.guard.take() {
            guard.detach();
        }
        self.offered_token = None;
    }
}

impl Drop for ClientAttachment {
    fn drop(&mut self) {
        if let Some(handle) = self.forwarder.take() {
            handle.abort();
        }
        // The guard's raw Drop stays non-retiring solely for `ClientState::install`'s same-client
        // acquire-before-release replacement. Connection EOF goes through `ClientState::drop`,
        // which explicitly detaches and retires every pending Offer.
    }
}

/// Per-connection state. A client has at most one live forwarder/guard per Session. A replacement
/// Attach acquires its new guard before this map swaps and drops the old one, so a repeat request
/// never creates an ownerless instant.
struct ClientState {
    owner_nonce: u64,
    attachments: HashMap<SessionId, ClientAttachment>,
    /// A refused conditional Start invalidates any already-queued Attach on this connection. The
    /// typed refusal remains readable, but a client cannot ignore it and bind the old/foreign grid.
    conditional_start_refused: Option<(SessionId, SessionStartOperationToken)>,
    /// A handoff-bearing generation-conditional Attach refusal is delivered before the connection
    /// is retired. This latch prevents any already-buffered request from overtaking that refusal.
    conditional_attach_refused: bool,
}

impl ClientState {
    fn new() -> Option<Self> {
        let owner_nonce = allocate_attachment_owner_nonce(&NEXT_ATTACHMENT_OWNER_NONCE)?;
        Some(Self {
            owner_nonce,
            attachments: HashMap::new(),
            conditional_start_refused: None,
            conditional_attach_refused: false,
        })
    }

    fn install(&mut self, id: SessionId, attachment: ClientAttachment) {
        // `attachment` already owns its guard. Only now may the old guard/forwarder drop.
        let preserves_same_offer = attachment.offered_token.is_some()
            && self
                .attachments
                .get(&id)
                .is_some_and(|old| old.offered_token == attachment.offered_token);
        if let Some(old) = self.attachments.insert(id, attachment) {
            if preserves_same_offer {
                // A repeated same-client Offer keeps the one shared Pending token. Unexpected
                // guard release deliberately leaves it for the replacement guard.
                drop(old);
            } else {
                // Switching to ordinary/Claim/a different Offer is an explicit replacement; retire
                // any pending token owned by the old attachment after the new guard is installed.
                old.detach();
            }
        }
    }

    /// Stop and explicitly retire this client's forwarder/guard for `id`, if any.
    fn detach(&mut self, id: &SessionId) {
        if let Some(attachment) = self.attachments.remove(id) {
            attachment.detach();
        }
    }

    fn release_guard_for_own_kill(&mut self, id: &SessionId) {
        if let Some(attachment) = self.attachments.get_mut(id) {
            attachment.release_guard_for_own_kill();
        }
    }

    fn set_forwarder(&mut self, id: &SessionId, forwarder: AbortHandle) {
        self.attachments
            .get_mut(id)
            .expect("provisional attachment is installed before its forwarder")
            .forwarder = Some(forwarder);
    }
}

impl Drop for ClientState {
    fn drop(&mut self) {
        for (_, attachment) in self.attachments.drain() {
            // Connection EOF/error/task cancellation is now an explicit retirement boundary for
            // every supported Offer owner. Same-client replacement remains non-retiring in
            // `ClientState::install`, where the replacement guard is already held first.
            attachment.detach();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestDisposition {
    Continue,
    CloseClient,
}

/// Serve one client over any newline-JSON byte transport. The connection is provided as already-split
/// read/write halves, so this is transport-AGNOSTIC: the unix accept loop passes `UnixStream`'s split
/// halves today; a future TCP/WSS gateway passes its own `AsyncRead`/`AsyncWrite` halves and reuses ALL
/// of this framing/parsing/forwarding logic unchanged. Transport-specific concerns (peer-credential auth
/// for unix; TLS + token auth for the network) live in the CALLER, before the halves reach here.
async fn handle_client<R, W>(read_half: R, mut write_half: W, shared: SharedDaemon) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Bounded framing: read newline-delimited lines but refuse to buffer more than
    // MAX_LINE_BYTES for a single line, so a peer can't force unbounded memory growth
    // before we even attempt to parse. A line over the cap drops the connection.
    let mut reader = BufReader::new(read_half);
    let mut line_buf: Vec<u8> = Vec::new();
    let mut state = ClientState::new()
        .ok_or_else(|| anyhow::anyhow!("attachment owner nonce space exhausted"))?;

    // Outbound queue: every DaemonEvent destined for this client funnels here,
    // so PTY pump tasks and request replies share one writer. Each event is serialized exactly once
    // before enqueue and charged against OUT_QUEUE_BYTES until its socket write completes.
    let (out_tx, mut out_rx, mut outbound_failed) =
        outbound::channel(OUT_QUEUE_CAP, OUT_QUEUE_BYTES);

    let writer = tokio::spawn(async move {
        while let Some(line) = out_rx.recv().await {
            if write_half.write_all(line.bytes()).await.is_err() {
                out_rx.fail();
                break;
            }
        }
    });

    loop {
        line_buf.clear();
        // `take` caps how many bytes one `read_until` may consume to one over the
        // limit: if we read MAX_LINE_BYTES + 1 without seeing '\n', the line is too
        // long. This bounds the buffer regardless of what the peer sends.
        let mut limited_reader = (&mut reader).take((MAX_LINE_BYTES + 1) as u64);
        let n = tokio::select! {
            biased;
            _ = outbound_failed.changed() => break,
            read = limited_reader.read_until(b'\n', &mut line_buf) => read?,
        };
        if n == 0 {
            break; // EOF
        }
        let terminated = line_buf.last() == Some(&b'\n');
        if !terminated && line_buf.len() > MAX_LINE_BYTES {
            // Oversized, unterminated line: framing violation. Drop the connection
            // rather than buffer more or emit an unscoped Error that a mutation client could
            // mistake for an acknowledgement.
            break;
        }
        let line = match std::str::from_utf8(&line_buf) {
            Ok(s) => s.trim(),
            Err(_) => break,
        };
        if line.is_empty() {
            continue;
        }
        let req: ClientRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            // Protocol v3 treats an unparseable request as a connection framing failure. This is
            // both simpler and safer than attempting to prove malformed JSON was non-mutating;
            // especially, an id-only/malformed generation mutation receives EOF and no unscoped
            // Error that could be mistaken for an acknowledgement.
            Err(_) => break,
        };
        let disposition = tokio::select! {
            biased;
            _ = outbound_failed.changed() => break,
            disposition = handle_request(req, &shared, &out_tx, &mut state) => disposition,
        };
        if disposition == RequestDisposition::CloseClient {
            break;
        }
    }

    // Dropping state aborts every forwarder, explicitly releases every exact Session guard, and
    // retires each still-unclaimed Offer owned by this connection. Supported transfer paths keep
    // this original socket alive until Claim/cancel; a raw token never outlives its owner socket.
    drop(state);
    // Once the request owner exits, no queued response has a live request stream to belong to. An
    // attachment abort is asynchronous and could still publish a fatal after any one-time flag
    // sample, so never attempt to drain into a half-closed or non-reading peer here. Aborting the
    // writer drops its current line and receiver immediately and releases all byte permits.
    drop(out_tx);
    finish_client_writer(writer).await;
    Ok(())
}

async fn finish_client_writer(writer: tokio::task::JoinHandle<()>) {
    writer.abort();
    let _ = writer.await;
}

async fn handle_request(
    req: ClientRequest,
    shared: &SharedDaemon,
    out_tx: &outbound::OutboundSender,
    state: &mut ClientState,
) -> RequestDisposition {
    let exact_refused_start_replay = !state.conditional_attach_refused
        && matches!(
            (&state.conditional_start_refused, &req),
            (
                Some((refused_id, refused_token)),
                ClientRequest::StartSession {
                    id,
                    conditional_start: Some(conditional),
                    ..
                }
            ) if id == refused_id && &conditional.operation_token == refused_token
        );
    if (state.conditional_attach_refused || state.conditional_start_refused.is_some())
        && !matches!(
            &req,
            ClientRequest::DaemonInfo
                | ClientRequest::LookupStartOperation { .. }
                | ClientRequest::RetireStartOperation { .. }
        )
        && !exact_refused_start_replay
    {
        // Keep the writer alive until the already-queued exact refusal reaches the peer. Every
        // pipelined terminal/session mutation is discarded, so Snapshot/Attach cannot overtake or
        // expose a Grid. Content-blind Lookup and Retire remain available for exact cleanup.
        return RequestDisposition::Continue;
    }
    match req {
        ClientRequest::DaemonInfo => {
            let daemon_instance_id = {
                let daemon = shared.lock().await;
                daemon.instance_id().clone()
            };
            let _ = out_tx
                .send(DaemonEvent::DaemonInfo {
                    protocol_version: protocol::DAEMON_PROTOCOL_VERSION,
                    build_version: env!("CARGO_PKG_VERSION").to_string(),
                    daemon_instance_id: Some(daemon_instance_id),
                    output_generation_echo: true,
                    child_environment: true,
                    generation_conditional_mutations: true,
                    attachment_aware_conditional_kill: true,
                    generation_conditional_start: true,
                    start_operation_ledger: true,
                    generation_conditional_attach: true,
                })
                .await;
        }
        ClientRequest::ReserveStartOperation {
            id,
            operation_token,
        } => {
            let (daemon_instance_id, outcome) = {
                let mut daemon = shared.lock().await;
                let daemon_instance_id = daemon.instance_id().clone();
                let outcome = daemon.reserve_start_operation(id.clone(), operation_token.clone());
                (daemon_instance_id, outcome)
            };
            if out_tx
                .send(DaemonEvent::StartOperationReserved {
                    id,
                    operation_token,
                    daemon_instance_id,
                    outcome,
                })
                .await
                .is_err()
            {
                return RequestDisposition::CloseClient;
            }
        }
        ClientRequest::StartSession {
            id,
            cwd,
            command,
            args,
            child_environment,
            cols,
            rows,
            restart_exited,
            conditional_start,
        } => {
            if let Some(conditional_start) = conditional_start {
                let (daemon_instance_id, outcome) = {
                    let mut daemon = shared.lock().await;
                    let daemon_instance_id = daemon.instance_id().clone();
                    let outcome = daemon.start_session_conditionally(
                        id.clone(),
                        &cwd,
                        &command,
                        &args,
                        child_environment.as_ref(),
                        cols,
                        rows,
                        &conditional_start,
                    );
                    (daemon_instance_id, outcome)
                };
                let refused = matches!(
                    outcome,
                    maestro_protocol::ConditionalSessionStartOutcome::Refused { .. }
                );
                let refused_operation =
                    refused.then(|| (id.clone(), conditional_start.operation_token.clone()));
                let sent = out_tx
                    .send(DaemonEvent::ConditionalSessionStart {
                        id,
                        operation_token: conditional_start.operation_token,
                        daemon_instance_id,
                        outcome,
                    })
                    .await;
                state.conditional_start_refused = refused_operation;
                if sent.is_err() {
                    return RequestDisposition::CloseClient;
                }
                return RequestDisposition::Continue;
            }
            let result = {
                let mut d = shared.lock().await;
                if restart_exited {
                    if let Some(environment) = child_environment.as_ref() {
                        d.start_session_with_restart_and_environment(
                            id,
                            &cwd,
                            &command,
                            &args,
                            Some(environment),
                            cols,
                            rows,
                            true,
                        )
                    } else {
                        d.start_session_with_restart(id, &cwd, &command, &args, cols, rows, true)
                    }
                } else if let Some(environment) = child_environment.as_ref() {
                    d.start_session_with_environment(
                        id,
                        &cwd,
                        &command,
                        &args,
                        Some(environment),
                        cols,
                        rows,
                    )
                } else {
                    d.start_session(id, &cwd, &command, &args, cols, rows)
                }
            };
            if let Err(e) = result {
                let _ = out_tx.try_send(DaemonEvent::Error {
                    message: e.to_string(),
                });
            }
        }
        ClientRequest::LookupStartOperation {
            id,
            operation_token,
        } => {
            let (daemon_instance_id, status) = {
                let daemon = shared.lock().await;
                (
                    daemon.instance_id().clone(),
                    daemon.lookup_start_operation(&id, &operation_token),
                )
            };
            if out_tx
                .send(DaemonEvent::StartOperationStatus {
                    id,
                    operation_token,
                    daemon_instance_id,
                    status,
                })
                .await
                .is_err()
            {
                return RequestDisposition::CloseClient;
            }
        }
        ClientRequest::RetireStartOperation {
            id,
            operation_token,
            expected,
        } => {
            let (daemon_instance_id, outcome) = {
                let mut daemon = shared.lock().await;
                let daemon_instance_id = daemon.instance_id().clone();
                let outcome = daemon.retire_start_operation(&id, &operation_token, &expected);
                (daemon_instance_id, outcome)
            };
            if out_tx
                .send(DaemonEvent::StartOperationRetired {
                    id,
                    operation_token,
                    daemon_instance_id,
                    outcome,
                })
                .await
                .is_err()
            {
                return RequestDisposition::CloseClient;
            }
        }
        // `want_raw_output` selects this attacher's live-update channel: the
        // forwarder below branches on it (raw Output bytes when true/omitted, vs
        // structured Damage only when false — see the send guard in the pump).
        ClientRequest::Attach {
            id,
            want_raw_output,
            expected_session_generation,
            output_generation,
            handoff,
        } => {
            if state.conditional_start_refused.is_some() {
                return RequestDisposition::CloseClient;
            }
            let offered_token = match handoff.as_ref() {
                Some(AttachmentHandoff::Offer { token }) => Some(token.clone()),
                Some(AttachmentHandoff::Claim { .. }) | None => None,
            };
            // Restore from the authoritative grid (a clean screen), then stream
            // live output. The snapshot and the live subscription are taken
            // atomically (Session::attach_state) at one revision boundary:
            //   - subscribe + snapshot happen under the grid lock, which the PTY
            //     reader also holds while it advances the grid and broadcasts —
            //     so no frame is lost (every later send reaches us) and none can
            //     slip in unaccounted between the two.
            //   - the snapshot is the GRID, not raw scrollback bytes. Raw bytes
            //     can begin mid-escape / mid-utf8 / inside an alt-screen txn and
            //     reproduce the corrupted or blank histories this path avoids.
            //   - every frame already folded into the snapshot satisfies
            //     `frame.revision <= snapshot.revision`; the forwarder drops
            //     those, so a chunk is delivered exactly once (no harmless-double
            //     reliance — that timing gap was the flaky reconnect test).
            // Acquire the exact Session guard before releasing the daemon mutex. Conditional Kill
            // and exited-session restart use that same mutex, so either they remove A first and
            // this Attach fails, or this guard exists before either mutation can inspect A.
            let (daemon_instance_id, acquired) = {
                let d = shared.lock().await;
                let daemon_instance_id = d.instance_id().clone();
                let guard = match expected_session_generation.as_deref() {
                    Some(expected_generation)
                        if !expected_generation.is_empty() && expected_generation.len() <= 128 =>
                    {
                        d.acquire_session_attachment_if_generation(
                            &id,
                            expected_generation,
                            handoff.as_ref(),
                            state.owner_nonce,
                        )
                    }
                    Some(_) => Err(SessionAttachmentAcquireError::Refused(
                        SessionAttachRefusal::GenerationMismatch,
                    )),
                    None => d
                        .acquire_session_attachment(&id, handoff.as_ref(), state.owner_nonce)
                        .map_err(SessionAttachmentAcquireError::Invalid),
                };
                let acquired = match guard {
                    Ok(guard) => {
                        match d.session(&id) {
                            Ok(s) => {
                                let attach = s.attach_state();
                                let grid = s.grid_handle();
                                // Generation is fixed for this grid's lifetime (a respawn builds a
                                // fresh Session, including a fresh ownership fence).
                                let generation = attach.snapshot.generation;
                                Ok((
                                    guard,
                                    attach.output_rx,
                                    attach.exit_rx,
                                    attach.snapshot,
                                    generation,
                                    attach.already_exited,
                                    grid,
                                ))
                            }
                            Err(error) => Err(Err(error.to_string())),
                        }
                    }
                    Err(SessionAttachmentAcquireError::Refused(reason)) => Err(Ok(reason)),
                    Err(SessionAttachmentAcquireError::Invalid(error)) => {
                        Err(Err(error.to_string()))
                    }
                };
                (daemon_instance_id, acquired)
            };
            let (guard, mut rx, mut exit_rx, snapshot, generation, already_exited, grid) =
                match acquired {
                    Ok(acquired) => acquired,
                    Err(Ok(reason)) => {
                        let expected_generation = expected_session_generation
                            .expect("typed conditional Attach refusal has an expected generation");
                        if out_tx
                            .send(DaemonEvent::SessionAttachRefused {
                                id,
                                expected_generation,
                                daemon_instance_id,
                                reason,
                            })
                            .await
                            .is_err()
                        {
                            return RequestDisposition::CloseClient;
                        }
                        if handoff.is_some() {
                            state.conditional_attach_refused = true;
                        }
                        return RequestDisposition::Continue;
                    }
                    Err(Err(message)) => {
                        // A handoff-bearing Attach is an ownership mutation boundary. On a wrong,
                        // retired, duplicate, or over-cap token, close without any unscoped Error
                        // and without parsing a queued Snapshot: otherwise a renderer could bind a
                        // Grid despite never acquiring the exact Session guard.
                        if handoff.is_some() {
                            return RequestDisposition::CloseClient;
                        }
                        // Ordinary Attach retains its compatibility behavior: report no-session or
                        // other read-only lookup errors and keep the connection usable.
                        let _ = out_tx.try_send(DaemonEvent::Error { message });
                        return RequestDisposition::Continue;
                    }
                };

            // Install the exact guard before the first awaited outbound baseline. If that send is
            // blocked, fails, or this request task is cancelled, ClientState still owns an explicit
            // retirement path for the Offer; no token lives outside the connection's EOF boundary.
            state.install(
                id.clone(),
                ClientAttachment::new(guard, None, offered_token.clone()),
            );

            let snapshot_revision = snapshot.revision;
            // Damage baseline: the diff source for live damage frames. It
            // starts at the SAME authoritative snapshot the client restores from
            // (so the first damage frame's `base_revision` is exactly the restore
            // grid's revision) and is advanced to each fresh snapshot we diff or
            // resync from. Cloned here because `snapshot` is moved into the restore
            // Grid send below.
            let mut prev_snapshot = snapshot.clone();
            // Guaranteed delivery: the restore baseline must reach the
            // client — a dropped Grid leaves the renderer with no baseline and
            // every subsequent Output undecodable. Await a queue slot rather than
            // try_send-and-drop.
            if out_tx
                .send(DaemonEvent::Grid {
                    id: id.clone(),
                    output_generation,
                    grid: snapshot,
                })
                .await
                .is_err()
            {
                state.detach(&id);
                return RequestDisposition::Continue;
            }

            // If the session had already exited before this attach, the latch is
            // set and the broadcast was missed. Emit SessionExited now (after the
            // restore Grid) and skip the live forwarder entirely — there is no
            // more output coming.
            if let Some(code) = already_exited {
                if out_tx
                    .send_for_attachment(
                        DaemonEvent::SessionExited {
                            id: id.clone(),
                            code,
                        },
                        output_generation,
                    )
                    .await
                    .is_err()
                {
                    state.detach(&id);
                }
                return RequestDisposition::Continue;
            }
            let out_tx = out_tx.clone();
            let id2 = id.clone();
            // Local baseline boundary. Starts at the attach snapshot's revision and
            // is advanced on every resync so post-lag output stays continuous.
            let mut baseline_revision = snapshot_revision;
            // Notification delivery has a separate boundary from grid content. A lag resync folds
            // content into a fresh Grid, but title/bell/OSC52 are not encoded in that snapshot.
            // Keep draining notifications from retained frames even when their content revision is
            // now <= baseline_revision; this boundary prevents duplicates for frames delivered
            // before the lag.
            let mut notifications_through_revision = snapshot_revision;
            let handle = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        // The reader thread broadcasts each OutputFrame before
                        // it latches/broadcasts child exit. If both receivers
                        // are ready, drain that already-ordered output first so
                        // the command's final damage and terminal notifications
                        // cannot be stranded behind SessionExited.
                        biased;
                        out = rx.recv() => match out {
                            Ok(frame) => {
                                if frame.revision > notifications_through_revision {
                                    for notification in &frame.notifications {
                                        let event = match notification {
                                            grid::TerminalNotification::Bell => {
                                                DaemonEvent::TerminalBell { id: id2.clone() }
                                            }
                                            grid::TerminalNotification::Title(title) => {
                                                DaemonEvent::TerminalTitle {
                                                    id: id2.clone(),
                                                    title: title.clone(),
                                                }
                                            }
                                            grid::TerminalNotification::ClipboardStore(text) => {
                                                const MAX_OSC52_BYTES: usize = 64 * 1024;
                                                let mut text = text.clone();
                                                if text.len() > MAX_OSC52_BYTES {
                                                    let mut end = MAX_OSC52_BYTES;
                                                    while !text.is_char_boundary(end) {
                                                        end -= 1;
                                                    }
                                                    text.truncate(end);
                                                }
                                                DaemonEvent::TerminalClipboardStore {
                                                    id: id2.clone(),
                                                    text,
                                                }
                                            }
                                        };
                                        if out_tx
                                            .send_for_attachment(event, output_generation)
                                            .await
                                            .is_err()
                                        {
                                            return;
                                        }
                                    }
                                    notifications_through_revision = frame.revision;
                                }
                                // Drop frames already folded into the current
                                // baseline (the attach snapshot, or the most
                                // recent post-lag resync snapshot). Notifications
                                // were handled independently above because Grid
                                // does not encode those side effects.
                                if frame.revision <= baseline_revision {
                                    continue;
                                }
                                // The raw Output bridge is opt-in. Legacy and
                                // logging clients (`want_raw_output` true or omitted)
                                // still get raw bytes; a structured-only client
                                // (`want_raw_output: false`, e.g. the native renderer)
                                // skips Output and lives off Damage alone. The skip is
                                // ONLY the send — damage generation below is
                                // unconditional, so a structured-only client still gets
                                // its live updates.
                                //
                                // base64 the raw bytes so split multibyte chars
                                // survive intact. Await a queue slot: this
                                // backpressures a slow client instead of growing
                                // memory; while we wait the broadcast fills and
                                // the next recv() lags → atomic resync below.
                                if want_raw_output
                                    && out_tx
                                        .send_for_attachment(
                                            DaemonEvent::Output {
                                                id: id2.clone(),
                                                generation,
                                                revision: frame.revision,
                                                data: B64.encode(&frame.bytes),
                                            },
                                            output_generation,
                                        )
                                        .await
                                        .is_err()
                                {
                                    break;
                                }
                                // After the raw Output bridge, emit structured
                                // damage for clients that consume it. Diff the held
                                // baseline snapshot against a fresh authoritative one
                                // (the SAME grid the snapshot path produces — never a
                                // second VT parse). `generate_damage` yields the
                                // `prev.revision -> next.revision` change. A
                                // `want_raw_output:true` client may receive both Output
                                // and Damage and remains correct (revision gates drop
                                // the redundant one). `DamageFrame.id` arrives as a
                                // placeholder and is stamped with the real session id
                                // before sending.
                                let cur = grid.snapshot();
                                match grid::generate_damage(&prev_snapshot, &cur) {
                                    grid::DamageGen::NoChange => {}
                                    grid::DamageGen::Frame(mut f) => {
                                        f.id = id2.clone();
                                        if out_tx
                                            .send_for_attachment(
                                                DaemonEvent::Damage { frame: f },
                                                output_generation,
                                            )
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                        prev_snapshot = cur;
                                    }
                                    // A generation/geometry change cannot be bridged
                                    // with in-place ops — ship a full snapshot as a
                                    // fresh baseline (the resize/full-clear contract),
                                    // never invented partial damage. Advance both the
                                    // damage baseline and the Output baseline so the
                                    // resynced revision is not re-shipped as Output.
                                    grid::DamageGen::Resync => {
                                        baseline_revision = cur.revision;
                                        let _ = out_tx
                                            .send_for_attachment(
                                                DaemonEvent::ResyncRequired { id: id2.clone() },
                                                output_generation,
                                            )
                                            .await;
                                        if out_tx
                                            .send_for_attachment(
                                                DaemonEvent::Grid {
                                                    id: id2.clone(),
                                                    output_generation: None,
                                                    grid: cur.clone(),
                                                },
                                                output_generation,
                                            )
                                            .await
                                            .is_err()
                                        {
                                            break;
                                        }
                                        prev_snapshot = cur;
                                    }
                                }
                            }
                            // A lagged client has lost ANSI bytes; its parser is
                            // now inconsistent. Make resync atomic: take a
                            // fresh authoritative snapshot as the new baseline and
                            // ship it (ResyncRequired then the Grid) BEFORE any more
                            // Output flows. Advancing baseline_revision to the
                            // snapshot's revision means every frame already folded
                            // into it — and any that raced in during the gap — is
                            // dropped by the guard above, so the client never sees
                            // discontinuous output spanning the lost bytes.
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                let snap = grid.snapshot();
                                baseline_revision = snap.revision;
                                // The resync snapshot is the new damage
                                // baseline too, so the next live frame diffs against
                                // the grid the client just restored — not a stale
                                // pre-lag snapshot that would mis-compute base_revision.
                                prev_snapshot = snap.clone();
                                let _ = out_tx
                                    .send_for_attachment(
                                        DaemonEvent::ResyncRequired { id: id2.clone() },
                                        output_generation,
                                    )
                                    .await;
                                if out_tx
                                    .send_for_attachment(
                                        DaemonEvent::Grid {
                                            id: id2.clone(),
                                            output_generation: None,
                                            grid: snap,
                                        },
                                        output_generation,
                                    )
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            // The output broadcast closed (Session dropped on
                            // kill/teardown). This means the child has ended, but
                            // the exit broadcast and this close race: if `select!`
                            // observes the close first, breaking here would drop
                            // SessionExited and leave the client waiting forever.
                            // Recover the exit code from the latch and emit it so
                            // end-of-session is delivered exactly once regardless of
                            // which signal wins.
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                                let code = grid.exit_state().flatten();
                                let _ = out_tx
                                    .send_for_attachment(
                                        DaemonEvent::SessionExited { id: id2.clone(), code },
                                        output_generation,
                                    )
                                    .await;
                                break;
                            }
                        },
                        exit = exit_rx.recv() => {
                            let code = exit.ok().flatten();
                            let _ = out_tx
                                .send_for_attachment(
                                    DaemonEvent::SessionExited { id: id2.clone(), code },
                                    output_generation,
                                )
                                .await;
                            break;
                        }
                    }
                }
            });
            state.set_forwarder(&id, handle.abort_handle());
        }
        ClientRequest::Detach { id } => {
            state.detach(&id);
        }
        ClientRequest::CancelAttachmentHandoff {
            id,
            token,
            expected_daemon_instance,
        } => {
            let daemon_instance_id = {
                let daemon = shared.lock().await;
                if daemon.instance_id() != &expected_daemon_instance {
                    return RequestDisposition::CloseClient;
                }
                daemon.cancel_session_attachment_handoff(&id, &token);
                daemon.instance_id().clone()
            };
            if out_tx
                .send(DaemonEvent::AttachmentHandoffCancelled {
                    id,
                    token,
                    daemon_instance_id,
                })
                .await
                .is_err()
            {
                return RequestDisposition::CloseClient;
            }
        }
        ClientRequest::Write {
            id,
            expected_generation,
            data,
        } => {
            // P4 lock isolation: a PTY write can BLOCK on a full kernel buffer
            // (child not draining). Doing it under the daemon lock would stall
            // every unrelated request. So resolve the session to its cheap
            // `PtyHandle` under the lock, RELEASE the lock, then do the blocking
            // write. Per-session ordering is preserved by the handle's own
            // `writer` mutex.
            let handle = {
                let d = shared.lock().await;
                match d.session(&id) {
                    Ok(s)
                        if s.live_generation().as_deref() == Some(expected_generation.as_str()) =>
                    {
                        s.pty_handle()
                    }
                    Ok(_) | Err(_) => return RequestDisposition::CloseClient,
                }
            };
            // The blocking write must not run on the async worker thread,
            // or it starves every other task on that thread while a child stalls.
            // Move it to the blocking pool; the cloneable handle + owned bytes
            // satisfy the closure's 'static + Send requirements.
            let bytes = data.into_bytes();
            let result = tokio::task::spawn_blocking(move || handle.write_input(&bytes)).await;
            let write_err = match result {
                Ok(Ok(())) => None,
                Ok(Err(e)) => Some(e.to_string()),
                Err(e) => Some(e.to_string()),
            };
            if let Some(message) = write_err {
                let _ = out_tx.try_send(DaemonEvent::Error { message });
            }
        }
        ClientRequest::Resize {
            id,
            expected_generation,
            cols,
            rows,
        } => {
            // P4 lock isolation: the resize ioctl can block, so resolve the
            // handle under the daemon lock, release it, then resize off-lock.
            let handle = {
                let d = shared.lock().await;
                match d.session(&id) {
                    Ok(s)
                        if s.live_generation().as_deref() == Some(expected_generation.as_str()) =>
                    {
                        s.pty_handle()
                    }
                    Ok(_) | Err(_) => return RequestDisposition::CloseClient,
                }
            };
            // Like Write, run the blocking resize ioctl on the blocking
            // pool instead of the async worker thread.
            let _ = tokio::task::spawn_blocking(move || handle.resize(cols, rows)).await;
        }
        ClientRequest::Snapshot { id } => {
            // Take the snapshot under the lock, then release it BEFORE the
            // Guaranteed-delivery send: a Snapshot reply is a baseline
            // just like attach, so it must not be dropped by try_send. We can't
            // await while holding the daemon Mutex, so capture then send.
            let snapshot = {
                let d = shared.lock().await;
                match d.session(&id) {
                    Ok(s) => s.grid_snapshot(),
                    Err(e) => {
                        let _ = out_tx.try_send(DaemonEvent::Error {
                            message: e.to_string(),
                        });
                        return RequestDisposition::Continue;
                    }
                }
            };
            let _ = out_tx
                .send(DaemonEvent::Grid {
                    id: id.clone(),
                    output_generation: None,
                    grid: snapshot,
                })
                .await;
        }
        ClientRequest::Scrollback {
            id,
            offset_from_top,
            count,
        } => {
            // Structured scrollback is a READ-ONLY query. Capture the window
            // under the lock (like Snapshot), release the lock, then guarantee-deliver the
            // reply. The reply is `ScrollbackRows` (NEVER a `Grid`) and is not part of the
            // snapshot/damage timeline; the daemon never mutates its `display_offset`.
            let read = {
                let d = shared.lock().await;
                match d.session(&id) {
                    Ok(s) => s.scrollback(offset_from_top, count),
                    Err(e) => {
                        let _ = out_tx.try_send(DaemonEvent::Error {
                            message: e.to_string(),
                        });
                        return RequestDisposition::Continue;
                    }
                }
            };
            let _ = out_tx
                .send(DaemonEvent::ScrollbackRows {
                    id: id.clone(),
                    generation: read.generation,
                    revision: read.revision,
                    history_len: read.history_len as u32,
                    offset_from_top: read.offset_from_top as u32,
                    rows: read.rows,
                })
                .await;
        }
        ClientRequest::Kill {
            id,
            expected_generation,
        } => {
            // An attached client may explicitly kill the exact generation it is currently
            // observing. Release only this connection's guard while retaining its forwarder for
            // the terminal event. A different client's guard is untouched and still blocks take.
            state.release_guard_for_own_kill(&id);
            let taken = {
                let mut d = shared.lock().await;
                d.take_session_if_generation(&id, &expected_generation)
            };
            match taken {
                ConditionalSessionTake::Absent => {}
                ConditionalSessionTake::GenerationMismatch
                | ConditionalSessionTake::AttachmentInUse => {
                    // Close without a best-effort Error. In particular, an attached exited A is
                    // omitted from live Sessions; allowing this release connection to continue to
                    // ListSessions could misclassify A as confirmed absent after Kill was refused.
                    return RequestDisposition::CloseClient;
                }
                ConditionalSessionTake::Taken(session) => {
                    // The exact A Session was removed while the map lock was held. Kill only that
                    // detached handle after unlock; a concurrently inserted B cannot be touched.
                    session.kill_child();
                }
            }
        }
        ClientRequest::ListSessions => {
            let sessions = {
                let d = shared.lock().await;
                d.session_infos()
            };
            // Derive both legacy `ids` and richer metadata from one snapshot.
            // A reader thread can latch exit without taking the daemon mutex;
            // two separate filtered walks could therefore disagree even while
            // this request holds that mutex.
            let ids = sessions.iter().map(|session| session.id.clone()).collect();
            let _ = out_tx.send(DaemonEvent::Sessions { ids, sessions }).await;
        }
        ClientRequest::OpenChannel { id } => {
            let result = {
                let mut d = shared.lock().await;
                d.open_channel(id)
            };
            if let Err(e) = result {
                let _ = out_tx.try_send(DaemonEvent::Error {
                    message: e.to_string(),
                });
            }
        }
        ClientRequest::JoinChannel { channel, session } => {
            let result = {
                let mut d = shared.lock().await;
                d.join_channel(&channel, &session)
            };
            if let Err(e) = result {
                let _ = out_tx.try_send(DaemonEvent::Error {
                    message: e.to_string(),
                });
            }
        }
        ClientRequest::Publish { event } => {
            let result = {
                let mut d = shared.lock().await;
                d.publish(event.clone())
            };
            if let Err(e) = result {
                let _ = out_tx.try_send(DaemonEvent::Error {
                    message: e.to_string(),
                });
            } else {
                let _ = out_tx.send(DaemonEvent::Channel { event }).await;
            }
        }
    }
    RequestDisposition::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    fn sid(s: &str) -> SessionId {
        SessionId(s.to_string())
    }

    fn handoff_token(value: &str) -> AttachmentHandoffToken {
        value.parse().expect("test token is fixed lowercase hex")
    }

    #[test]
    fn attachment_owner_nonce_exhaustion_is_fail_closed_without_wrap_or_reuse() {
        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(allocate_attachment_owner_nonce(&counter), Some(u64::MAX));
        assert_eq!(allocate_attachment_owner_nonce(&counter), None);
        assert_eq!(allocate_attachment_owner_nonce(&counter), None);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[tokio::test]
    async fn conditional_offer_refusal_is_exact_and_pipelined_snapshot_is_discarded() {
        let shared = Daemon::shared();
        let id = sid("conditional-attach-refusal");
        let daemon_instance_id = {
            let mut daemon = shared.lock().await;
            daemon
                .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
                .unwrap();
            daemon.instance_id().clone()
        };
        let mut state = ClientState::new().unwrap();
        let (tx, mut rx, _failed) = outbound::channel(OUT_QUEUE_CAP, OUT_QUEUE_BYTES);
        let expected_generation = "not-the-live-generation".to_string();
        let token = handoff_token("01000000000000000000000000000001");

        assert_eq!(
            handle_request(
                ClientRequest::Attach {
                    id: id.clone(),
                    want_raw_output: false,
                    expected_session_generation: Some(expected_generation.clone()),
                    output_generation: Some(41),
                    handoff: Some(AttachmentHandoff::Offer { token }),
                },
                &shared,
                &tx,
                &mut state,
            )
            .await,
            RequestDisposition::Continue
        );
        assert!(state.conditional_attach_refused);
        assert!(matches!(
            rx.recv_event().await,
            Some(DaemonEvent::SessionAttachRefused {
                id: ref got_id,
                expected_generation: ref got_generation,
                daemon_instance_id: ref got_instance,
                reason: SessionAttachRefusal::GenerationMismatch,
            }) if got_id == &id
                && got_generation == &expected_generation
                && got_instance == &daemon_instance_id
        ));
        assert_eq!(
            shared
                .lock()
                .await
                .session(&id)
                .unwrap()
                .attachment_fence_counts(),
            (0, 0),
            "refusal occurs before guard acquisition"
        );

        assert_eq!(
            handle_request(
                ClientRequest::Snapshot { id: id.clone() },
                &shared,
                &tx,
                &mut state,
            )
            .await,
            RequestDisposition::Continue
        );
        assert!(
            rx.try_recv_event().is_err(),
            "a queued Snapshot cannot overtake the terminal refusal or expose Grid bytes"
        );
        shared.lock().await.kill_session(&id);
    }

    #[test]
    fn same_client_repeat_has_no_zero_owner_and_replacement_retires_old_offer() {
        let mut daemon = Daemon::default();
        let id = sid("same-client-repeat");
        daemon
            .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
            .unwrap();
        let mut state = ClientState::new().unwrap();
        let first_token = handoff_token("10000000000000000000000000000001");
        let second_token = handoff_token("10000000000000000000000000000002");

        let first_offer = AttachmentHandoff::Offer {
            token: first_token.clone(),
        };
        let first = daemon
            .acquire_session_attachment(&id, Some(&first_offer), state.owner_nonce)
            .unwrap();
        state.install(
            id.clone(),
            ClientAttachment::new(first, None, Some(first_token.clone())),
        );

        let repeated = daemon
            .acquire_session_attachment(&id, Some(&first_offer), state.owner_nonce)
            .unwrap();
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (2, 1),
            "new repeat guard exists before the old guard can drop"
        );
        state.install(
            id.clone(),
            ClientAttachment::new(repeated, None, Some(first_token)),
        );
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (1, 1),
            "same-token repeat preserves exactly one pending handoff"
        );

        let second_offer = AttachmentHandoff::Offer {
            token: second_token.clone(),
        };
        let second = daemon
            .acquire_session_attachment(&id, Some(&second_offer), state.owner_nonce)
            .unwrap();
        state.install(
            id.clone(),
            ClientAttachment::new(second, None, Some(second_token)),
        );
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (1, 1),
            "T1 is explicitly retired while T2 remains pending"
        );

        let ordinary = daemon
            .acquire_session_attachment(&id, None, state.owner_nonce)
            .unwrap();
        state.install(id.clone(), ClientAttachment::new(ordinary, None, None));
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (1, 0),
            "switching to ordinary Attach retires the old pending offer"
        );
        state.detach(&id);
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (0, 0)
        );
        daemon.kill_session(&id);
    }

    #[test]
    fn client_state_eof_retires_its_pending_offer_before_late_claim() {
        let mut daemon = Daemon::default();
        let id = sid("ordinary-does-not-consume-handoff");
        daemon
            .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
            .unwrap();
        let value = handoff_token("20000000000000000000000000000001");
        let offer = AttachmentHandoff::Offer {
            token: value.clone(),
        };

        let mut starter = ClientState::new().unwrap();
        let starter_guard = daemon
            .acquire_session_attachment(&id, Some(&offer), starter.owner_nonce)
            .unwrap();
        starter.install(
            id.clone(),
            ClientAttachment::new(starter_guard, None, Some(value.clone())),
        );
        drop(starter);
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (0, 0),
            "connection EOF explicitly retires the Offer it owned"
        );

        let late_claim = AttachmentHandoff::Claim {
            token: value.clone(),
        };
        assert!(daemon
            .acquire_session_attachment(&id, Some(&late_claim), 999)
            .is_err());

        let mut unrelated = ClientState::new().unwrap();
        let ordinary_guard = daemon
            .acquire_session_attachment(&id, None, unrelated.owner_nonce)
            .unwrap();
        unrelated.install(
            id.clone(),
            ClientAttachment::new(ordinary_guard, None, None),
        );
        drop(unrelated);
        assert_eq!(
            daemon.session(&id).unwrap().attachment_fence_counts(),
            (0, 0)
        );
        daemon.kill_session(&id);
    }

    #[tokio::test]
    async fn attach_and_conditional_kill_linearize_in_both_mutex_winner_orders() {
        // Attach wins: its guard is installed before the map mutex unlocks, so exact Kill refuses
        // and closes only the release client while A remains mapped.
        let shared = Daemon::shared();
        let id = sid("attach-wins-linearization");
        let generation = {
            let mut daemon = shared.lock().await;
            daemon
                .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
                .unwrap();
            daemon.session(&id).unwrap().generation()
        };
        let (attach_tx, mut attach_rx, _failed) = outbound::channel(OUT_QUEUE_CAP, OUT_QUEUE_BYTES);
        let mut attach_state = ClientState::new().unwrap();
        assert_eq!(
            handle_request(
                ClientRequest::Attach {
                    id: id.clone(),
                    want_raw_output: false,
                    expected_session_generation: None,
                    output_generation: None,
                    handoff: None,
                },
                &shared,
                &attach_tx,
                &mut attach_state,
            )
            .await,
            RequestDisposition::Continue
        );
        assert!(matches!(
            attach_rx.recv_event().await,
            Some(DaemonEvent::Grid { .. })
        ));
        let (kill_tx, _kill_rx, _failed) = outbound::channel(OUT_QUEUE_CAP, OUT_QUEUE_BYTES);
        let mut kill_state = ClientState::new().unwrap();
        assert_eq!(
            handle_request(
                ClientRequest::Kill {
                    id: id.clone(),
                    expected_generation: generation,
                },
                &shared,
                &kill_tx,
                &mut kill_state,
            )
            .await,
            RequestDisposition::CloseClient
        );
        assert!(shared.lock().await.session(&id).is_ok());
        drop(attach_state);
        shared.lock().await.kill_session(&id);

        // Kill wins: it removes exact A under the map mutex. The later Attach cannot install a
        // guard or emit Grid; it receives only a no-session Error and leaves the map absent.
        let killed_id = sid("kill-wins-linearization");
        let killed_generation = {
            let mut daemon = shared.lock().await;
            daemon
                .start_session(killed_id.clone(), ".", "sleep", &["30".into()], 80, 24)
                .unwrap();
            daemon.session(&killed_id).unwrap().generation()
        };
        let (first_kill_tx, _rx, _failed) = outbound::channel(OUT_QUEUE_CAP, OUT_QUEUE_BYTES);
        let mut first_kill_state = ClientState::new().unwrap();
        assert_eq!(
            handle_request(
                ClientRequest::Kill {
                    id: killed_id.clone(),
                    expected_generation: killed_generation,
                },
                &shared,
                &first_kill_tx,
                &mut first_kill_state,
            )
            .await,
            RequestDisposition::Continue
        );
        assert!(shared.lock().await.session(&killed_id).is_err());

        let (late_attach_tx, mut late_attach_rx, _failed) =
            outbound::channel(OUT_QUEUE_CAP, OUT_QUEUE_BYTES);
        let mut late_attach_state = ClientState::new().unwrap();
        assert_eq!(
            handle_request(
                ClientRequest::Attach {
                    id: killed_id,
                    want_raw_output: false,
                    expected_session_generation: None,
                    output_generation: None,
                    handoff: None,
                },
                &shared,
                &late_attach_tx,
                &mut late_attach_state,
            )
            .await,
            RequestDisposition::Continue
        );
        assert!(matches!(
            late_attach_rx.recv_event().await,
            Some(DaemonEvent::Error { .. })
        ));
        assert!(
            late_attach_rx.try_recv_event().is_err(),
            "Kill-first Attach emitted Grid"
        );
    }

    async fn replace_test_session(shared: &SharedDaemon, id: &str) -> (String, String) {
        let id = sid(id);
        let mut daemon = shared.lock().await;
        daemon
            .start_session(id.clone(), ".", "cat", &[], 80, 24)
            .expect("spawn generation A");
        let generation_a = daemon.session(&id).unwrap().generation();
        daemon.kill_session(&id);
        daemon
            .start_session(id.clone(), ".", "cat", &[], 80, 24)
            .expect("spawn generation B");
        let generation_b = daemon.session(&id).unwrap().generation();
        assert_ne!(
            generation_a, generation_b,
            "replacement must be a new PTY lifetime"
        );
        (generation_a, generation_b)
    }

    async fn send_raw_request(
        writer: &mut tokio::io::WriteHalf<tokio::io::DuplexStream>,
        request: serde_json::Value,
    ) {
        writer
            .write_all(serde_json::to_string(&request).unwrap().as_bytes())
            .await
            .unwrap();
        writer.write_all(b"\n").await.unwrap();
        writer.flush().await.unwrap();
    }

    async fn read_event_line(
        reader: &mut BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    ) -> serde_json::Value {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(1), reader.read_line(&mut line))
            .await
            .expect("timed out waiting for daemon event")
            .expect("failed to read daemon event");
        serde_json::from_str(&line).expect("daemon event is JSON")
    }

    async fn stale_mutation_closes_only_its_client_and_lists_replacement(
        id: &str,
        request_for_generation: impl FnOnce(String) -> serde_json::Value,
    ) -> (SharedDaemon, String) {
        let shared = Daemon::shared();
        let (generation_a, generation_b) = replace_test_session(&shared, id).await;

        let (server_a, client_a) = tokio::io::duplex(4096);
        let (server_a_read, server_a_write) = tokio::io::split(server_a);
        let (client_a_read, mut client_a_write) = tokio::io::split(client_a);
        let handler_a_shared = shared.clone();
        let handler_a = tokio::spawn(async move {
            handle_client(server_a_read, server_a_write, handler_a_shared).await
        });

        let (server_b, client_b) = tokio::io::duplex(4096);
        let (server_b_read, server_b_write) = tokio::io::split(server_b);
        let (client_b_read, mut client_b_write) = tokio::io::split(client_b);
        let handler_b_shared = shared.clone();
        let handler_b = tokio::spawn(async move {
            handle_client(server_b_read, server_b_write, handler_b_shared).await
        });

        send_raw_request(&mut client_a_write, request_for_generation(generation_a)).await;
        let mut client_a_read = BufReader::new(client_a_read);
        let mut byte = [0_u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), client_a_read.read(&mut byte))
                .await
                .expect("stale mutation client was not closed")
                .expect("stale mutation client read failed"),
            0,
            "generation mismatch must be connection EOF, never an unscoped ack/error"
        );

        send_raw_request(
            &mut client_b_write,
            serde_json::json!({"op": "list_sessions"}),
        )
        .await;
        let mut client_b_read = BufReader::new(client_b_read);
        let sessions = read_event_line(&mut client_b_read).await;
        assert_eq!(sessions["ev"], "sessions");
        let listed_generation = sessions["sessions"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["id"] == id)
            .and_then(|entry| entry["generation"].as_str());
        assert_eq!(listed_generation, Some(generation_b.as_str()));

        drop(client_a_write);
        drop(client_b_write);
        drop(client_b_read);
        tokio::time::timeout(Duration::from_secs(1), handler_a)
            .await
            .expect("stale client handler did not retire")
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), handler_b)
            .await
            .expect("unrelated client handler did not retire")
            .unwrap()
            .unwrap();
        (shared, generation_b)
    }

    #[tokio::test]
    async fn stale_generation_kill_closes_only_that_client_and_preserves_replacement() {
        let (shared, _) = stale_mutation_closes_only_its_client_and_lists_replacement(
            "generation-kill",
            |generation_a| {
                serde_json::json!({
                    "op": "kill",
                    "id": "generation-kill",
                    "expected_generation": generation_a,
                })
            },
        )
        .await;
        shared.lock().await.kill_session(&sid("generation-kill"));
    }

    #[tokio::test]
    async fn attached_exited_session_refuses_kill_with_eof_and_remains_retained() {
        let shared = Daemon::shared();
        let id = sid("attached-exited-kill");
        {
            let mut daemon = shared.lock().await;
            daemon
                .start_session(id.clone(), ".", "true", &[], 80, 24)
                .unwrap();
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if shared
                .lock()
                .await
                .session(&id)
                .unwrap()
                .exit_state()
                .is_some()
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "short-lived test session did not exit"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let generation = shared.lock().await.session(&id).unwrap().generation();

        let (attach_server, attach_client) = tokio::io::duplex(1024 * 1024);
        let (attach_server_read, attach_server_write) = tokio::io::split(attach_server);
        let (attach_client_read, mut attach_client_write) = tokio::io::split(attach_client);
        let attach_shared = shared.clone();
        let attach_handler = tokio::spawn(async move {
            handle_client(attach_server_read, attach_server_write, attach_shared).await
        });
        send_raw_request(
            &mut attach_client_write,
            serde_json::json!({
                "op": "attach",
                "id": id.0.clone(),
                "want_raw_output": false,
            }),
        )
        .await;
        let mut attach_client_read = BufReader::new(attach_client_read);
        assert_eq!(read_event_line(&mut attach_client_read).await["ev"], "grid");
        assert_eq!(
            read_event_line(&mut attach_client_read).await["ev"],
            "session_exited"
        );
        assert_eq!(
            shared
                .lock()
                .await
                .session(&id)
                .unwrap()
                .attachment_fence_counts(),
            (1, 0),
            "late exited Attach must retain its guard after replaying SessionExited"
        );

        let (kill_server, kill_client) = tokio::io::duplex(4096);
        let (kill_server_read, kill_server_write) = tokio::io::split(kill_server);
        let (mut kill_client_read, mut kill_client_write) = tokio::io::split(kill_client);
        let kill_shared = shared.clone();
        let kill_handler = tokio::spawn(async move {
            handle_client(kill_server_read, kill_server_write, kill_shared).await
        });
        send_raw_request(
            &mut kill_client_write,
            serde_json::json!({
                "op": "kill",
                "id": id.0.clone(),
                "expected_generation": generation.clone(),
            }),
        )
        .await;
        let mut byte = [0_u8; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), kill_client_read.read(&mut byte))
                .await
                .expect("in-use Kill did not close its release connection")
                .expect("in-use Kill read failed"),
            0,
            "in-use Kill must return EOF with no unscoped Error or subsequent Sessions reply"
        );
        assert!(
            shared.lock().await.session(&id).is_ok(),
            "attached exited A remains retained after refused Kill"
        );
        assert!(
            shared
                .lock()
                .await
                .session_infos()
                .iter()
                .all(|info| info.id != id),
            "the proof exercises the dangerous exited-but-omitted-from-Sessions case"
        );

        drop(kill_client_write);
        tokio::time::timeout(Duration::from_secs(1), kill_handler)
            .await
            .expect("Kill handler did not retire")
            .unwrap()
            .unwrap();
        drop(attach_client_write);
        drop(attach_client_read);
        tokio::time::timeout(Duration::from_secs(1), attach_handler)
            .await
            .expect("Attach handler did not retire")
            .unwrap()
            .unwrap();

        let removed = shared
            .lock()
            .await
            .take_session_if_generation(&id, &generation);
        let ConditionalSessionTake::Taken(session) = removed else {
            panic!("EOF must release the last attachment guard");
        };
        session.kill_child();
    }

    #[tokio::test]
    async fn failed_handoff_claim_with_queued_snapshot_closes_without_any_event() {
        let shared = Daemon::shared();
        let id = sid("failed-handoff-claim-snapshot");
        let exact_pending = handoff_token("30000000000000000000000000000001");
        let wrong = handoff_token("30000000000000000000000000000002");
        let retired = handoff_token("30000000000000000000000000000003");
        {
            let mut daemon = shared.lock().await;
            daemon
                .start_session(id.clone(), ".", "sleep", &["30".into()], 80, 24)
                .unwrap();
            let pending_offer = AttachmentHandoff::Offer {
                token: exact_pending.clone(),
            };
            drop(
                daemon
                    .acquire_session_attachment(&id, Some(&pending_offer), 30_001)
                    .unwrap(),
            );
            let retired_offer = AttachmentHandoff::Offer {
                token: retired.clone(),
            };
            daemon
                .acquire_session_attachment(&id, Some(&retired_offer), 30_002)
                .unwrap()
                .detach();
            assert_eq!(
                daemon.session(&id).unwrap().attachment_fence_counts(),
                (0, 1)
            );
        }

        for (label, token) in [("wrong", wrong), ("retired", retired)] {
            let (server, client) = tokio::io::duplex(4096);
            let (server_read, server_write) = tokio::io::split(server);
            let (mut client_read, mut client_write) = tokio::io::split(client);
            let handler_shared = shared.clone();
            let handler = tokio::spawn(async move {
                handle_client(server_read, server_write, handler_shared).await
            });

            let mut queued = serde_json::to_vec(&ClientRequest::Attach {
                id: id.clone(),
                want_raw_output: false,
                expected_session_generation: None,
                output_generation: None,
                handoff: Some(AttachmentHandoff::Claim { token }),
            })
            .unwrap();
            queued.push(b'\n');
            queued.extend(serde_json::to_vec(&ClientRequest::Snapshot { id: id.clone() }).unwrap());
            queued.push(b'\n');
            client_write.write_all(&queued).await.unwrap();
            client_write.flush().await.unwrap();

            let mut byte = [0_u8; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), client_read.read(&mut byte))
                    .await
                    .unwrap_or_else(|_| panic!("{label} Claim did not close"))
                    .unwrap(),
                0,
                "{label} Claim must yield EOF with no Error/Grid from queued Snapshot"
            );
            drop(client_write);
            tokio::time::timeout(Duration::from_secs(1), handler)
                .await
                .unwrap_or_else(|_| panic!("{label} Claim handler did not retire"))
                .unwrap()
                .unwrap();
            assert_eq!(
                shared
                    .lock()
                    .await
                    .session(&id)
                    .unwrap()
                    .attachment_fence_counts(),
                (0, 1),
                "{label} Claim must not consume the unrelated exact Pending token"
            );
        }

        let mut daemon = shared.lock().await;
        daemon.cancel_session_attachment_handoff(&id, &exact_pending);
        daemon.kill_session(&id);
    }

    #[tokio::test]
    async fn stale_generation_resize_cannot_touch_replacement_geometry() {
        let (shared, generation_b) = stale_mutation_closes_only_its_client_and_lists_replacement(
            "generation-resize",
            |generation_a| {
                serde_json::json!({
                    "op": "resize",
                    "id": "generation-resize",
                    "expected_generation": generation_a,
                    "cols": 121,
                    "rows": 37,
                })
            },
        )
        .await;
        let snapshot = shared
            .lock()
            .await
            .session(&sid("generation-resize"))
            .unwrap()
            .grid_snapshot();
        assert_eq!(snapshot.generation.to_string(), generation_b);
        assert_eq!((snapshot.cols, snapshot.rows), (80, 24));
        shared.lock().await.kill_session(&sid("generation-resize"));
    }

    #[tokio::test]
    async fn stale_generation_write_cannot_reach_replacement_pty() {
        let (shared, generation_b) = stale_mutation_closes_only_its_client_and_lists_replacement(
            "generation-write",
            |generation_a| {
                serde_json::json!({
                    "op": "write",
                    "id": "generation-write",
                    "expected_generation": generation_a,
                    "data": "STALE_GENERATION_MARKER\n",
                })
            },
        )
        .await;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let snapshot = shared
                .lock()
                .await
                .session(&sid("generation-write"))
                .unwrap()
                .grid_snapshot();
            assert_eq!(snapshot.generation.to_string(), generation_b);
            let text = snapshot
                .rows_cells
                .iter()
                .flat_map(|row| row.iter())
                .map(|cell| cell.text.as_str())
                .collect::<String>();
            assert!(
                !text.contains("STALE_GENERATION_MARKER"),
                "stale client input reached the replacement PTY"
            );
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        shared.lock().await.kill_session(&sid("generation-write"));
    }

    #[tokio::test]
    async fn matching_generation_write_resize_and_kill_touch_only_that_lifetime() {
        let shared = Daemon::shared();
        let generation = {
            let mut daemon = shared.lock().await;
            daemon
                .start_session(sid("generation-match"), ".", "cat", &[], 80, 24)
                .expect("spawn matching lifetime");
            daemon
                .session(&sid("generation-match"))
                .unwrap()
                .generation()
        };
        let (tx, _rx, _failed) = outbound::channel(OUT_QUEUE_CAP, OUT_QUEUE_BYTES);
        let mut state = ClientState::new().unwrap();
        assert_eq!(
            handle_request(
                ClientRequest::Resize {
                    id: sid("generation-match"),
                    expected_generation: generation.clone(),
                    cols: 103,
                    rows: 31,
                },
                &shared,
                &tx,
                &mut state,
            )
            .await,
            RequestDisposition::Continue
        );
        assert_eq!(
            {
                let daemon = shared.lock().await;
                let snapshot = daemon
                    .session(&sid("generation-match"))
                    .unwrap()
                    .grid_snapshot();
                (
                    snapshot.cols,
                    snapshot.rows,
                    snapshot.generation.to_string(),
                )
            },
            (103, 31, generation.clone())
        );
        assert_eq!(
            handle_request(
                ClientRequest::Write {
                    id: sid("generation-match"),
                    expected_generation: generation.clone(),
                    data: "MATCHING_GENERATION_MARKER\n".into(),
                },
                &shared,
                &tx,
                &mut state,
            )
            .await,
            RequestDisposition::Continue
        );
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
        loop {
            let text = {
                let daemon = shared.lock().await;
                daemon
                    .session(&sid("generation-match"))
                    .unwrap()
                    .grid_snapshot()
                    .rows_cells
                    .iter()
                    .flat_map(|row| row.iter())
                    .map(|cell| cell.text.as_str())
                    .collect::<String>()
            };
            if text.contains("MATCHING_GENERATION_MARKER") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "matching generation Write never reached its own PTY"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            handle_request(
                ClientRequest::Kill {
                    id: sid("generation-match"),
                    expected_generation: generation,
                },
                &shared,
                &tx,
                &mut state,
            )
            .await,
            RequestDisposition::Continue
        );
        assert!(shared
            .lock()
            .await
            .session(&sid("generation-match"))
            .is_err());
    }

    #[tokio::test]
    async fn conditional_kill_is_idempotent_when_id_is_already_absent() {
        let shared = Daemon::shared();
        let (tx, _rx, _failed) = outbound::channel(OUT_QUEUE_CAP, OUT_QUEUE_BYTES);
        let mut state = ClientState::new().unwrap();
        assert_eq!(
            handle_request(
                ClientRequest::Kill {
                    id: sid("already-absent"),
                    expected_generation: "observed-before-exit".into(),
                },
                &shared,
                &tx,
                &mut state,
            )
            .await,
            RequestDisposition::Continue
        );
    }

    #[tokio::test]
    async fn unparseable_request_framing_closes_without_error_reply() {
        for (label, request) in [
            (
                "id-only mutation",
                b"{\"op\":\"resize\",\"id\":\"s\",\"cols\":90,\"rows\":30}\n".as_slice(),
            ),
            ("malformed json", b"{\"op\":\"list_sessions\"\n".as_slice()),
            ("invalid utf8", b"\xff\xfe\n".as_slice()),
        ] {
            let shared = Daemon::shared();
            let (server, client) = tokio::io::duplex(4096);
            let (server_read, server_write) = tokio::io::split(server);
            let (mut client_read, mut client_write) = tokio::io::split(client);
            let handler =
                tokio::spawn(async move { handle_client(server_read, server_write, shared).await });
            client_write.write_all(request).await.unwrap();
            client_write.flush().await.unwrap();
            let mut byte = [0_u8; 1];
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(1), client_read.read(&mut byte))
                    .await
                    .unwrap_or_else(|_| panic!("{label} did not close"))
                    .unwrap(),
                0,
                "{label} must produce EOF with no Error frame"
            );
            drop(client_write);
            tokio::time::timeout(Duration::from_secs(1), handler)
                .await
                .unwrap_or_else(|_| panic!("{label} handler did not retire"))
                .unwrap()
                .unwrap();
        }
    }

    fn env_of<'a>(entries: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |key| {
            entries
                .iter()
                .find_map(|(name, value)| (*name == key).then(|| OsString::from(value)))
        }
    }

    #[test]
    fn default_socket_path_uses_first_non_empty_runtime_directory() {
        assert_eq!(
            default_socket_path_for_uid(
                env_of(&[
                    ("XDG_RUNTIME_DIR", "/run/user/1000"),
                    ("TMPDIR", "/var/tmp")
                ]),
                1000,
            ),
            PathBuf::from("/run/user/1000/hydra-maestro-1000.sock")
        );
        assert_eq!(
            default_socket_path_for_uid(
                env_of(&[("XDG_RUNTIME_DIR", ""), ("TMPDIR", "/var/tmp")]),
                1000,
            ),
            PathBuf::from("/var/tmp/hydra-maestro-1000.sock")
        );
        assert_eq!(
            default_socket_path_for_uid(env_of(&[("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")]), 1000,),
            PathBuf::from("/tmp/hydra-maestro-1000.sock")
        );
    }

    #[tokio::test]
    async fn list_sessions_legacy_ids_match_the_metadata_snapshot() {
        let shared = Daemon::shared();
        {
            let mut daemon = shared.lock().await;
            daemon
                .start_session(sid("list-a"), ".", "sleep", &["30".to_string()], 80, 24)
                .expect("spawn list-a");
            daemon
                .start_session(sid("list-b"), ".", "sleep", &["30".to_string()], 80, 24)
                .expect("spawn list-b");
        }

        let (tx, mut rx, _failed) = outbound::channel(OUT_QUEUE_CAP, OUT_QUEUE_BYTES);
        let mut state = ClientState::new().unwrap();
        handle_request(ClientRequest::ListSessions, &shared, &tx, &mut state).await;

        let DaemonEvent::Sessions { ids, sessions } =
            rx.recv_event().await.expect("ListSessions response")
        else {
            panic!("expected Sessions response");
        };
        assert!(
            sessions.iter().all(|session| session
                .generation
                .as_deref()
                .is_some_and(|value| !value.is_empty())),
            "new-daemon live metadata must identify each grid lifetime"
        );
        let metadata_ids: Vec<_> = sessions.into_iter().map(|session| session.id).collect();
        assert_eq!(
            ids, metadata_ids,
            "legacy ids and metadata must come from one ordered live snapshot"
        );

        let mut daemon = shared.lock().await;
        daemon.kill_session(&sid("list-a"));
        daemon.kill_session(&sid("list-b"));
    }

    #[tokio::test]
    async fn guaranteed_reply_backpressure_never_holds_the_daemon_mutex() {
        // Leave less than one maximum-line reservation available. A guaranteed Sessions reply
        // must therefore wait in OutboundSender::send; the daemon mutex must already be released
        // while it does so, otherwise an arbitrarily slow client can stall every local session.
        let cap = MAX_LINE_BYTES + 1024 * 1024;
        let (tx, _rx, _failed) = outbound::channel(4, cap);
        tx.send(DaemonEvent::Error {
            message: "x".repeat(2 * 1024 * 1024),
        })
        .await
        .unwrap();

        let shared = Daemon::shared();
        let request_shared = shared.clone();
        let request_tx = tx.clone();
        let request = tokio::spawn(async move {
            let mut state = ClientState::new().unwrap();
            handle_request(
                ClientRequest::ListSessions,
                &request_shared,
                &request_tx,
                &mut state,
            )
            .await;
        });

        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        assert!(
            !request.is_finished(),
            "the reply should be waiting for the deliberately exhausted byte budget"
        );
        let guard = tokio::time::timeout(Duration::from_secs(1), shared.lock())
            .await
            .expect("guaranteed reply held the global daemon mutex while awaiting queue capacity");
        drop(guard);
        request.abort();
        let _ = request.await;
    }

    #[tokio::test]
    async fn socket_writer_failure_interrupts_an_in_progress_request() {
        let shared = Daemon::shared();
        {
            let mut daemon = shared.lock().await;
            daemon
                .start_session(
                    sid("writer-failure"),
                    ".",
                    "sleep",
                    &["30".to_string()],
                    80,
                    24,
                )
                .expect("spawn writer-failure session");
        }

        // A one-byte transport buffer keeps the Attach Grid write in progress. Once its first byte
        // is observable, Attach has released the daemon mutex and the handler can accept a second
        // request. We then hold that mutex, making ListSessions stay in progress, and drop the peer's
        // read half. The socket writer failure must cancel that request and retire the client without
        // waiting for this guard to be released.
        let (server, client) = tokio::io::duplex(1);
        let (server_read, server_write) = tokio::io::split(server);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let handler_shared = shared.clone();
        let handler =
            tokio::spawn(
                async move { handle_client(server_read, server_write, handler_shared).await },
            );

        let attach = serde_json::to_vec(&ClientRequest::Attach {
            id: sid("writer-failure"),
            want_raw_output: false,
            expected_session_generation: None,
            output_generation: None,
            handoff: None,
        })
        .unwrap();
        client_write.write_all(&attach).await.unwrap();
        client_write.write_all(b"\n").await.unwrap();
        client_write.flush().await.unwrap();

        let mut first_response_byte = [0_u8; 1];
        tokio::time::timeout(
            Duration::from_secs(1),
            client_read.read_exact(&mut first_response_byte),
        )
        .await
        .expect("Attach response did not reach the transport")
        .unwrap();

        let daemon_guard = shared.lock().await;
        let list = serde_json::to_vec(&ClientRequest::ListSessions).unwrap();
        client_write.write_all(&list).await.unwrap();
        client_write.write_all(b"\n").await.unwrap();
        client_write.flush().await.unwrap();
        for _ in 0..10 {
            tokio::task::yield_now().await;
        }
        drop(client_write);
        drop(client_read);

        tokio::time::timeout(Duration::from_secs(1), handler)
            .await
            .expect("writer failure did not interrupt the in-progress request")
            .expect("handler task panicked")
            .expect("handler should retire the failed client cleanly");

        drop(daemon_guard);
        shared.lock().await.kill_session(&sid("writer-failure"));
    }

    #[tokio::test]
    async fn producer_fatal_aborts_a_writer_blocked_on_a_non_reading_peer() {
        let (tx, mut rx, mut failed) = outbound::channel(4, OUT_QUEUE_BYTES);
        let budget_probe = tx.clone();
        let (mut peer, mut socket) = tokio::io::duplex(1);
        let writer = tokio::spawn(async move {
            while let Some(line) = rx.recv().await {
                if socket.write_all(line.bytes()).await.is_err() {
                    rx.fail();
                    break;
                }
            }
        });

        tx.send(DaemonEvent::Error {
            message: "queued-before-fatal".repeat(128 * 1024),
        })
        .await
        .unwrap();
        let mut first_byte = [0_u8; 1];
        tokio::time::timeout(Duration::from_secs(1), peer.read_exact(&mut first_byte))
            .await
            .expect("writer never reached the deliberately tiny transport")
            .unwrap();

        let oversized = "x".repeat(MAX_LINE_BYTES);
        assert_eq!(
            tx.send(DaemonEvent::Error { message: oversized }).await,
            Err(outbound::SendError::TooLarge)
        );
        tokio::time::timeout(Duration::from_secs(1), failed.changed())
            .await
            .expect("producer fatal did not wake the client owner")
            .expect("fatal watch sender disappeared");
        assert!(*failed.borrow());

        // Exercise the same cleanup helper as handle_client. Graceful queue drain would hang here
        // because the peer intentionally stopped reading after one byte.
        drop(tx);
        tokio::time::timeout(Duration::from_secs(1), finish_client_writer(writer))
            .await
            .expect("fatal writer abort did not complete");
        assert_eq!(budget_probe.available_bytes(), OUT_QUEUE_BYTES);
    }

    // The blocking PTY write must run via spawn_blocking, not
    // synchronously on the async worker. We prove it by stalling the write (a
    // background thread holds the session's writer lock for ~1s) and then,
    // *while that write is in flight*, driving an unrelated ListSessions request
    // on a SINGLE-worker (current-thread) runtime.
    //
    // - With spawn_blocking: the in-flight write parks on the blocking pool and
    //   the lone worker yields, so ListSessions runs and the runtime thread
    //   delivers its result well within the deadline.
    // - With a direct `handle.write_input(..)` call: once the Write task starts
    //   it owns the ONLY worker thread and never yields until the lock releases
    //   ~1s later -- so ListSessions cannot run and the runtime thread is wedged.
    //
    // We run the runtime on its OWN thread and gate it from the main thread with
    // a `recv_timeout`. That way the starvation case surfaces as a clean,
    // bounded test FAILURE ("runtime thread wedged") instead of an infinite hang
    // (a synchronous worker-starving call would also stall the runtime's timer,
    // so an in-runtime timeout could not fire).
    #[test]
    fn write_does_not_starve_other_requests_on_single_worker() {
        let shared = Daemon::shared();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        let (handle, generation) = rt.block_on(async {
            let mut d = shared.lock().await;
            d.start_session(sid("w"), ".", "sleep", &["30".to_string()], 80, 24)
                .expect("spawn session");
            let session = d.session(&sid("w")).unwrap();
            (session.pty_handle(), session.generation())
        });

        // Stall every PTY write: hold the session's writer lock for ~1s. This
        // thread is independent of the tokio worker, so the lock stays held even
        // if the worker is wedged.
        let writer_lock = handle.writer_lock_for_test();
        let barrier = Arc::new(Barrier::new(2));
        let b2 = barrier.clone();
        let stall = std::thread::spawn(move || {
            let _guard = writer_lock.lock().unwrap();
            b2.wait();
            std::thread::sleep(Duration::from_secs(1));
        });
        barrier.wait(); // writer lock is now held

        // Run the runtime on its own thread; report ListSessions completion back
        // to the main thread, which enforces the deadline.
        let (done_tx, done_rx) = std::sync::mpsc::channel::<Vec<SessionId>>();
        let rt_shared = shared.clone();
        let rt_thread = std::thread::spawn(move || {
            rt.block_on(async {
                // Fire the Write through the real handler as a task; its blocking
                // write hits the held writer lock.
                let (tx, _rx, _failed) = outbound::channel(OUT_QUEUE_CAP, OUT_QUEUE_BYTES);
                let mut wstate = ClientState::new().unwrap();
                let wshared = rt_shared.clone();
                let write_task = tokio::spawn(async move {
                    handle_request(
                        ClientRequest::Write {
                            id: sid("w"),
                            expected_generation: generation,
                            data: "ls\n".to_string(),
                        },
                        &wshared,
                        &tx,
                        &mut wstate,
                    )
                    .await;
                });

                // Let the Write task get scheduled and reach its blocking
                // section before we try the unrelated request.
                tokio::task::yield_now().await;

                let (ltx, mut lrx, _failed) = outbound::channel(OUT_QUEUE_CAP, OUT_QUEUE_BYTES);
                let mut lstate = ClientState::new().unwrap();
                handle_request(ClientRequest::ListSessions, &rt_shared, &ltx, &mut lstate).await;

                if let Ok(DaemonEvent::Sessions { ids, .. }) = lrx.try_recv_event() {
                    let _ = done_tx.send(ids);
                }

                write_task.abort();
            });
            rt
        });

        // The unrelated request must complete well before the ~1s write stall.
        let ids = done_rx
            .recv_timeout(Duration::from_millis(500))
            .expect("ListSessions did not complete while a PTY write was in flight -- the blocking write is starving the single async worker (spawn_blocking missing)");
        assert!(ids.contains(&sid("w")), "session should be listed: {ids:?}");

        stall.join().unwrap();
        let rt = rt_thread.join().unwrap();
        rt.block_on(async { shared.lock().await.kill_session(&sid("w")) });
    }
}
