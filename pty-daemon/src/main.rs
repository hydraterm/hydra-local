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

use crate::daemon::{Daemon, SharedDaemon};
use crate::ids::SessionId;
use crate::protocol::{ClientRequest, DaemonEvent, MAX_LINE_BYTES};
use anyhow::Result;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::PathBuf;
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

/// Per-connection state. The key invariant is that a client has at most
/// ONE live forwarder per session, so a repeat Attach (UI reconnect, double
/// attach) can't double every byte.
#[derive(Default)]
struct ClientState {
    attachments: HashMap<SessionId, AbortHandle>,
}

impl ClientState {
    /// Stop and forget this client's forwarder for `id`, if any.
    fn detach(&mut self, id: &SessionId) {
        if let Some(handle) = self.attachments.remove(id) {
            handle.abort();
        }
    }
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

    let mut state = ClientState::default();

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
            // rather than buffer more.
            let _ = out_tx.try_send(DaemonEvent::Error {
                message: format!("request line exceeds {MAX_LINE_BYTES} bytes; closing"),
            });
            break;
        }
        let line = match std::str::from_utf8(&line_buf) {
            Ok(s) => s.trim(),
            Err(_) => {
                let _ = out_tx.try_send(DaemonEvent::Error {
                    message: "request line is not valid UTF-8".into(),
                });
                continue;
            }
        };
        if line.is_empty() {
            continue;
        }
        let req: ClientRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                let _ = out_tx.try_send(DaemonEvent::Error {
                    message: format!("bad request: {e}"),
                });
                continue;
            }
        };
        tokio::select! {
            biased;
            _ = outbound_failed.changed() => break,
            _ = handle_request(req, &shared, &out_tx, &mut state) => {}
        }
    }

    // Client disconnected: stop all of its forwarders. spawned tasks outlive a
    // dropped JoinHandle, so we must abort explicitly or they leak (and keep
    // pushing into a dead out_tx).
    for (_, handle) in state.attachments.drain() {
        handle.abort();
    }
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
) {
    match req {
        ClientRequest::DaemonInfo => {
            let _ = out_tx
                .send(DaemonEvent::DaemonInfo {
                    protocol_version: protocol::DAEMON_PROTOCOL_VERSION,
                    build_version: env!("CARGO_PKG_VERSION").to_string(),
                    output_generation_echo: true,
                    child_environment: true,
                })
                .await;
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
        } => {
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
        // `want_raw_output` selects this attacher's live-update channel: the
        // forwarder below branches on it (raw Output bytes when true/omitted, vs
        // structured Damage only when false — see the send guard in the pump).
        ClientRequest::Attach {
            id,
            want_raw_output,
            output_generation,
        } => {
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
            // Attach deduplication: if this client already has a forwarder for the session,
            // stop it before starting a new one, or a repeat Attach would double.
            state.detach(&id);

            let (mut rx, mut exit_rx, snapshot, generation, already_exited, grid) = {
                let d = shared.lock().await;
                match d.session(&id) {
                    Ok(s) => {
                        let attach = s.attach_state();
                        let grid = s.grid_handle();
                        // Generation is fixed for this grid's lifetime (a respawn
                        // builds a new Session with a new broadcast channel), so
                        // capture it once and stamp every Output frame with it.
                        let generation = attach.snapshot.generation;
                        // Hand the snapshot OUT of the lock scope: the restore Grid
                        // is delivered with guaranteed-delivery
                        // `.send().await`, which cannot be awaited while holding the
                        // daemon Mutex. Atomicity is preserved: output_rx subscribed
                        // under the lock at this snapshot's revision, and the
                        // forwarder drops every frame <= that revision regardless of
                        // when the snapshot bytes physically land.
                        (
                            attach.output_rx,
                            attach.exit_rx,
                            attach.snapshot,
                            generation,
                            attach.already_exited,
                            grid,
                        )
                    }
                    Err(e) => {
                        // Error replies are best-effort; a dropped one is not a
                        // correctness hazard the way a missing baseline is.
                        let _ = out_tx.try_send(DaemonEvent::Error {
                            message: e.to_string(),
                        });
                        return;
                    }
                }
            };

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
                return;
            }

            // If the session had already exited before this attach, the latch is
            // set and the broadcast was missed. Emit SessionExited now (after the
            // restore Grid) and skip the live forwarder entirely — there is no
            // more output coming.
            if let Some(code) = already_exited {
                let _ = out_tx
                    .send_for_attachment(
                        DaemonEvent::SessionExited {
                            id: id.clone(),
                            code,
                        },
                        output_generation,
                    )
                    .await;
                return;
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
            state.attachments.insert(id, handle.abort_handle());
        }
        ClientRequest::Detach { id } => {
            state.detach(&id);
        }
        ClientRequest::Write { id, data } => {
            // A PTY write can BLOCK on a full kernel buffer
            // (child not draining). Doing it under the daemon lock would stall
            // every unrelated request. So resolve the session to its cheap
            // `PtyHandle` under the lock, RELEASE the lock, then do the blocking
            // write. Per-session ordering is preserved by the handle's own
            // `writer` mutex.
            let handle = {
                let d = shared.lock().await;
                match d.session(&id) {
                    Ok(s) => s.pty_handle(),
                    Err(e) => {
                        let _ = out_tx.try_send(DaemonEvent::Error {
                            message: e.to_string(),
                        });
                        return;
                    }
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
        ClientRequest::Resize { id, cols, rows } => {
            // The resize ioctl can block, so resolve the
            // handle under the daemon lock, release it, then resize off-lock.
            let handle = {
                let d = shared.lock().await;
                match d.session(&id) {
                    Ok(s) => s.pty_handle(),
                    Err(_) => return,
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
                        return;
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
                        return;
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
        ClientRequest::Kill { id } => {
            let mut d = shared.lock().await;
            d.kill_session(&id);
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::time::Duration;

    fn sid(s: &str) -> SessionId {
        SessionId(s.to_string())
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
        let mut state = ClientState::default();
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
            let mut state = ClientState::default();
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
            output_generation: None,
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

        let handle = rt.block_on(async {
            let mut d = shared.lock().await;
            d.start_session(sid("w"), ".", "sleep", &["30".to_string()], 80, 24)
                .expect("spawn session");
            d.session(&sid("w")).unwrap().pty_handle()
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
                let mut wstate = ClientState::default();
                let wshared = rt_shared.clone();
                let write_task = tokio::spawn(async move {
                    handle_request(
                        ClientRequest::Write {
                            id: sid("w"),
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
                let mut lstate = ClientState::default();
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
