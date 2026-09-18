//! Local supervisor (Slice C, v1 — child processes). Productizes the proven `live-smoke-guided.sh` flow as
//! one `hydra-agent supervise` command that the launchd plist (Slice B) invokes: it starts + monitors
//! `pty-daemon`, ensures the default session(s) exist, and starts + monitors `remote-peer` (identity loads
//! from `device.json` — no `--account`/`--device-id` needed). Local-only; no install/launchctl here.
//!
//! Design for testability: the PURE pieces — command builders, the start-session line, the stale-socket
//! DECISION, enrollment validation, and the dry-run plan — have no I/O and are unit-tested. The runtime loop
//! (`run`) is a thin shell that spawns/monitors using those pieces. Logs are metadata-only (no PTY payload).

use std::path::{Path, PathBuf};

use crate::device_identity;

/// Resolved options for one supervise run. Paths are explicit; the CLI fills defaults.
#[derive(Debug, Clone)]
pub struct SuperviseOptions {
    pub agent_dir: PathBuf,
    pub socket_path: String,
    pub sessions: Vec<String>,
    /// Path to the `pty-daemon` binary (defaults to a sibling of the hydra-agent binary).
    pub pty_daemon_bin: String,
    /// Path to the `hydra-agent` binary (defaults to the current executable) — used to spawn `remote-peer`.
    pub hydra_agent_bin: String,
    /// When true (default) supervise OWNS the pty-daemon: it spawns + monitors it and seeds sessions. When false,
    /// `socket_path` is the DESKTOP APP's already-running daemon (resolved from endpoint.json) — supervise does NOT
    /// spawn a daemon or seed sessions; it only runs remote-peer against the shared socket so the browser sees the
    /// desktop's live projects/sessions.
    pub own_daemon: bool,
    /// Attach to exactly `socket_path` and never follow a desktop-published endpoint. Headless server units set
    /// this so stale desktop state cannot redirect connectivity away from the independently managed daemon.
    pub fixed_external_daemon: bool,
}

impl SuperviseOptions {
    pub fn sessions_arg(&self) -> String {
        self.sessions.join(",")
    }
}

/// A child command spec (program + args) — returned WITHOUT spawning so it's testable. The runtime turns
/// these into `std::process::Command`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildCommand {
    pub program: String,
    pub args: Vec<String>,
}

/// `pty-daemon <socket>` — the daemon takes the socket path as a positional arg.
pub fn pty_daemon_command(opts: &SuperviseOptions) -> ChildCommand {
    ChildCommand {
        program: opts.pty_daemon_bin.clone(),
        args: vec![opts.socket_path.clone()],
    }
}

/// `hydra-agent remote-peer --dir <agent-dir> --sock <s> [--sessions <s1,s2>]`.
/// Cloud, token-verifier, and browser-origin trust are owned by the child binary
/// and therefore never cross the process boundary in argv.
/// E4: `--sessions` is OMITTED when no sessions are configured (the default) — the daemon starts with zero
/// sessions and the browser creates them on demand. It's only passed when sessions were explicitly seeded.
pub fn remote_peer_command(opts: &SuperviseOptions) -> ChildCommand {
    let mut args = vec![
        "remote-peer".to_string(),
        "--dir".to_string(),
        opts.agent_dir.display().to_string(),
        "--sock".to_string(),
        opts.socket_path.clone(),
    ];
    if opts.fixed_external_daemon {
        args.push("--headless-server".to_string());
    }
    if !opts.sessions.is_empty() {
        args.push("--sessions".to_string());
        args.push(opts.sessions_arg());
    }
    ChildCommand {
        program: opts.hydra_agent_bin.clone(),
        args,
    }
}

/// The exact newline-terminated `start_session` request for one session (matches the daemon protocol + the
/// smoke helper). `home` is the session cwd. Content-blind: this is a control message, no PTY payload.
pub fn start_session_line(session_id: &str, home: &str) -> String {
    start_session_line_with(session_id, home, "bash", &["--norc", "-i"])
}

/// `start_session` with a validated command + discrete argv. Used for KnownSafe agent resumes only; never pass a
/// free-form command line here. Args are encoded as JSON string elements, so opaque ids/paths cannot become shell.
pub fn start_session_line_with(
    session_id: &str,
    home: &str,
    command: &str,
    args: &[&str],
) -> String {
    start_session_line_with_size(session_id, home, command, args, 80, 24)
}

/// `start_session` with an explicit, already-normalized initial terminal geometry. Remote browser
/// creation uses this only after validating a paired `(cols, rows)` request. The established local
/// and supervisor builders remain [`start_session_line`] / [`start_session_line_with`], whose exact
/// legacy geometry and bytes stay 80×24.
pub(crate) fn start_session_line_with_size(
    session_id: &str,
    home: &str,
    command: &str,
    args: &[&str],
    cols: u16,
    rows: u16,
) -> String {
    start_session_line_with_size_and_restart_authority(
        session_id, home, command, args, cols, rows, false,
    )
}

fn start_session_line_with_restart_authority(
    session_id: &str,
    home: &str,
    command: &str,
    args: &[&str],
    restart_exited: bool,
) -> String {
    start_session_line_with_size_and_restart_authority(
        session_id,
        home,
        command,
        args,
        80,
        24,
        restart_exited,
    )
}

fn start_session_line_with_size_and_restart_authority(
    session_id: &str,
    home: &str,
    command: &str,
    args: &[&str],
    cols: u16,
    rows: u16,
    restart_exited: bool,
) -> String {
    let restart = if restart_exited {
        ",\"restart_exited\":true"
    } else {
        ""
    };
    format!(
        "{{\"op\":\"start_session\",\"id\":\"{id}\",\"cwd\":\"{cwd}\",\"command\":\"{command}\",\"args\":{args},\"cols\":{cols},\"rows\":{rows}{restart}}}\n",
        id = json_escape(session_id),
        cwd = json_escape(home),
        command = json_escape(command),
        args = json_string_array(args),
    )
}

fn json_string_array(args: &[&str]) -> String {
    let items = args
        .iter()
        .map(|arg| format!("\"{}\"", json_escape(arg)))
        .collect::<Vec<_>>()
        .join(",");
    format!("[{items}]")
}

/// Minimal JSON string escaping for the two interpolated fields (id/home) so a path with a quote/backslash
/// can't break the control message.
fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

/// What to do about an existing socket file before starting the daemon. Pure decision; the runtime supplies
/// the probe result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketState {
    /// No socket file present → just start the daemon.
    Absent,
    /// A daemon is responding on the socket → reuse it (don't start a second daemon).
    HealthyReuse,
    /// A socket file exists but nothing responds → stale; remove it, then start the daemon.
    StaleRemove,
}

/// Decide the socket handling from two facts the runtime gathers: does the socket path exist, and (if so)
/// did a daemon respond to a `list_sessions` probe? Pure.
pub fn socket_decision(socket_exists: bool, daemon_responds: bool) -> SocketState {
    if !socket_exists {
        SocketState::Absent
    } else if daemon_responds {
        SocketState::HealthyReuse
    } else {
        SocketState::StaleRemove
    }
}

/// Initial remote-peer restart backoff (also the value to RESET to after a clean daemon-restart).
pub const BACKOFF_START: Duration = Duration::from_secs(1);
/// Backoff ceiling — never wait longer than this between remote-peer restart attempts.
pub const BACKOFF_CAP: Duration = Duration::from_secs(30);

/// The NEXT restart backoff after a remote-peer death: double the current, capped at BACKOFF_CAP. Pure so the
/// escalation curve (1→2→4→…→30→30) is testable without driving the supervise loop. A too-fast curve hammers the
/// cloud on a flapping peer; a runaway curve never recovers — both are reliability bugs worth pinning.
pub fn next_backoff(current: Duration) -> Duration {
    (current * 2).min(BACKOFF_CAP)
}

/// Is a configured binary a FILESYSTEM PATH (contains a separator) vs a bare name resolved via $PATH? Only the
/// former can be existence-checked up front; a bare name is left to the OS/PATH lookup at spawn time.
fn is_path_like(bin: &str) -> bool {
    bin.contains('/') || bin.contains('\\')
}

/// Preflight: of the configured binaries that are filesystem PATHS, which don't exist? Pure (takes an
/// `exists(path) -> bool` so it's testable without touching the disk). A missing daemon/agent binary otherwise
/// fails MID-startup with a raw "No such file" from spawn — pre-checking lets `run()` say exactly which binary is
/// missing + how to build it, before doing any work. Bare PATH-resolved names are skipped (left to spawn).
pub fn missing_binary_paths(
    pty_daemon_bin: &str,
    hydra_agent_bin: &str,
    exists: impl Fn(&str) -> bool,
) -> Vec<String> {
    let mut missing = Vec::new();
    for (name, bin) in [
        ("pty-daemon", pty_daemon_bin),
        ("hydra-agent", hydra_agent_bin),
    ] {
        if is_path_like(bin) && !exists(bin) {
            missing.push(format!("{name} binary not found at {bin}"));
        }
    }
    missing
}

/// Enrollment check: a device.json must exist (the user ran enroll once). Returns the loaded record or a
/// clear, actionable error — never requires `--account`/`--device-id`.
pub fn validate_enrollment(agent_dir: &Path) -> Result<device_identity::DeviceRecord, String> {
    match device_identity::load_record(agent_dir) {
        Ok(Some(rec)) => Ok(rec),
        Ok(None) | Err(_) => Err(format!(
            "this desktop is not enrolled (no {}). Use Add Desktop in the app",
            device_identity::record_path(agent_dir).display()
        )),
    }
}

pub fn validate_enrollment_binding(
    agent_dir: &Path,
) -> Result<device_identity::DeviceRecord, String> {
    let record = validate_enrollment(agent_dir)?;
    crate::release_trust::active()
        .validate_enrollment(&record)
        .map_err(|_| {
            "enrollment does not match this Hydra agent release; remove remote access and re-enroll"
                .to_string()
        })?;
    device_identity::require_passkey_for_remote_authority(&record)
        .map_err(|error| error.to_string())?;
    Ok(record)
}

/// A content identity for every authority-bearing field in `device.json`.
///
/// The old supervisor compared only `(mtime, length)`. A device A -> B replacement, or a
/// passkey-only replacement, can preserve both values and leave an already-running peer serving
/// the old authority. The supervisor therefore compares the complete accepted record. This digest
/// is never used as authority by itself: the record is parsed and release-bound first, and the
/// digest only tells us whether the child still corresponds to that validated record.
type EnrollmentAuthorityFingerprint = [u8; 32];

#[derive(Debug, Clone)]
struct EffectiveEnrollmentBinding {
    fingerprint: EnrollmentAuthorityFingerprint,
}

fn enrollment_authority_fingerprint(
    record: &device_identity::DeviceRecord,
) -> EnrollmentAuthorityFingerprint {
    use sha2::{Digest as _, Sha256};

    // Struct serialization is deterministic for DeviceRecord and includes the complete passkey
    // object. Length-prefix the domain and payload so the input cannot be reinterpreted.
    let payload = serde_json::to_vec(record)
        .expect("serializing the in-memory enrollment record cannot fail");
    let mut digest = Sha256::new();
    let domain = b"hydra.effective-enrollment-binding.v1";
    digest.update((domain.len() as u64).to_be_bytes());
    digest.update(domain);
    digest.update((payload.len() as u64).to_be_bytes());
    digest.update(payload);
    digest.finalize().into()
}

fn validate_effective_enrollment_binding(
    agent_dir: &Path,
) -> Result<EffectiveEnrollmentBinding, String> {
    let record = validate_enrollment_binding(agent_dir)?;
    Ok(EffectiveEnrollmentBinding {
        fingerprint: enrollment_authority_fingerprint(&record),
    })
}

/// `consistency.rs` retains its historical metadata-only tuple shape. The supervisor's security
/// decisions compare the full 256-bit digest; this 192-bit projection is only an observability
/// input for the redundant five-second consistency report.
fn consistency_enrollment_fingerprint(fingerprint: EnrollmentAuthorityFingerprint) -> (u128, u64) {
    let high = u128::from_be_bytes(fingerprint[..16].try_into().expect("fixed digest prefix"));
    let low = u64::from_be_bytes(fingerprint[16..24].try_into().expect("fixed digest suffix"));
    (high, low)
}

/// The dry-run plan: a human-readable description of exactly what supervise WOULD do, with NO secrets (the
/// cloud-pubkey is public; no token/private key is ever involved). Used by `--dry-run` + tested.
pub fn dry_run_plan(opts: &SuperviseOptions) -> String {
    let d = pty_daemon_command(opts);
    let r = remote_peer_command(opts);
    let mut out = String::new();
    out.push_str("supervise plan (dry-run — nothing started):\n");
    out.push_str(&format!(
        "  1. ensure socket {} (remove if stale)\n",
        opts.socket_path
    ));
    out.push_str(&format!(
        "  2. start pty-daemon: {} {}\n",
        d.program,
        d.args.join(" ")
    ));
    if opts.sessions.is_empty() {
        out.push_str(
            "  3. no pre-seeded sessions (the browser creates them on demand via New session)\n",
        );
    } else {
        for s in &opts.sessions {
            out.push_str(&format!(
                "  3. ensure session {s} (start_session over the daemon socket)\n"
            ));
        }
    }
    out.push_str(&format!(
        "  4. start remote-peer: {} {}\n",
        r.program,
        r.args.join(" ")
    ));
    out.push_str(
        "  (identity loads from device.json; remote-peer restarts with bounded backoff; owned pty-daemon restarts rebuild the local tree)\n",
    );
    out
}

/// Content-blind identity of the complete release-bound remote trust tuple. The installed service and its
/// readiness handshake compute this independently from their own argv, so a stale process cannot echo a new
/// request and falsely qualify.
fn service_binding_stamp_for(
    environment: &str,
    expected_cloud_base: &str,
    cloud_pubkey: &str,
    allowed_origin: &str,
) -> String {
    use sha2::{Digest as _, Sha256};
    let mut digest = Sha256::new();
    for value in [
        "hydra.remote-service-binding.v1",
        environment,
        expected_cloud_base,
        cloud_pubkey,
        allowed_origin,
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value.as_bytes());
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Content-blind identity of the private build's compiled trust. Callers have
/// no parameters with which to substitute another environment or verifier.
pub fn service_binding_stamp() -> String {
    let trust = crate::release_trust::active();
    service_binding_stamp_for(
        trust.environment,
        trust.cloud_base,
        trust.cloud_pubkey,
        trust.allowed_origin,
    )
}

// ---- runtime (I/O; the pure pieces above carry the logic + tests) ----

use anyhow::{anyhow, Context, Result};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
struct EnrollmentWithdrawn(String);

/// Removes live readiness evidence on every normal supervisor exit. A hard kill
/// can leave a record behind, but readiness consumers reject it by freshness.
struct ServiceReadinessGuard<'a> {
    agent_dir: &'a Path,
    supervisor_pid: u32,
}

impl Drop for ServiceReadinessGuard<'_> {
    fn drop(&mut self) {
        let _ = crate::service_readiness::remove_service_readiness_if_supervisor(
            self.agent_dir,
            self.supervisor_pid,
        );
    }
}

fn clear_service_readiness(agent_dir: &Path) {
    if let Err(error) = crate::service_readiness::remove_service_readiness_if_supervisor(
        agent_dir,
        std::process::id(),
    ) {
        tracing::warn!(%error, "supervise: could not clear local readiness evidence");
    }
}

/// Enrollment removal invalidates every readiness answer, including a record left by a supervisor
/// that was killed before its Drop guard ran. This stronger withdrawal is reserved for authority
/// loss and startup/wait convergence; ordinary restarts still use PID-scoped cleanup above so an
/// overlapping old process cannot erase a newer healthy supervisor's answer.
fn withdraw_all_service_readiness(agent_dir: &Path) -> Result<()> {
    crate::service_readiness::remove_all_service_readiness(agent_dir)
        .context("withdraw all local service-readiness evidence")
}

fn effective_binding_or_withdraw(agent_dir: &Path) -> Result<EffectiveEnrollmentBinding> {
    match validate_effective_enrollment_binding(agent_dir) {
        Ok(binding) => Ok(binding),
        Err(binding_error) => {
            withdraw_all_service_readiness(agent_dir).with_context(|| {
                format!("{binding_error}; enrollment is invalid but readiness withdrawal failed")
            })?;
            Err(EnrollmentWithdrawn(binding_error).into())
        }
    }
}

fn stop_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Validate a running child's effective authority before observing its exit state, answering
/// readiness, or considering any restart. Invalid enrollment always withdraws readiness and reaps
/// the child before returning.
fn validate_running_enrollment_or_withdraw(
    agent_dir: &Path,
    child: &mut Child,
) -> Result<EffectiveEnrollmentBinding> {
    match validate_effective_enrollment_binding(agent_dir) {
        Ok(binding) => Ok(binding),
        Err(binding_error) => {
            let readiness_result = withdraw_all_service_readiness(agent_dir);
            stop_and_reap(child);
            readiness_result.with_context(|| {
                format!("{binding_error}; enrollment is invalid but readiness withdrawal failed")
            })?;
            Err(EnrollmentWithdrawn(binding_error).into())
        }
    }
}

/// Start a child only across one stable, validated enrollment snapshot. The second read closes the
/// replacement-during-spawn race: if A becomes B (including passkey-only replacement), the
/// candidate is reaped and cannot publish readiness as either identity.
fn start_for_current_binding<T>(
    agent_dir: &Path,
    start: impl FnOnce() -> Result<T>,
    mut stop: impl FnMut(&mut T),
) -> Result<(T, EffectiveEnrollmentBinding)> {
    let before = effective_binding_or_withdraw(agent_dir)?;
    let mut candidate = start()?;
    let after = match effective_binding_or_withdraw(agent_dir) {
        Ok(binding) if binding.fingerprint == before.fingerprint => binding,
        Ok(_) => {
            stop(&mut candidate);
            withdraw_all_service_readiness(agent_dir)?;
            anyhow::bail!("enrollment changed while starting remote-peer; candidate was reaped");
        }
        Err(error) => {
            stop(&mut candidate);
            return Err(error).context(
                "enrollment became invalid while starting remote-peer; candidate was reaped",
            );
        }
    };
    Ok((candidate, after))
}

fn ensure_readiness_binding_current(
    agent_dir: &Path,
    peer_start_fingerprint: EnrollmentAuthorityFingerprint,
) -> Result<()> {
    let current = effective_binding_or_withdraw(agent_dir)?;
    if current.fingerprint != peer_start_fingerprint {
        withdraw_all_service_readiness(agent_dir)?;
        anyhow::bail!("enrollment changed since remote-peer started");
    }
    Ok(())
}

fn answer_service_readiness_request(
    opts: &SuperviseOptions,
    peer: &mut Child,
    socket_path: &str,
    peer_start_fingerprint: EnrollmentAuthorityFingerprint,
) -> Result<()> {
    let agent_dir = &opts.agent_dir;
    ensure_readiness_binding_current(agent_dir, peer_start_fingerprint).inspect_err(|_| {
        stop_and_reap(peer);
    })?;
    let request = match crate::service_readiness::load_service_readiness_request(agent_dir) {
        Ok(Some(request)) => request,
        Ok(None) => return Ok(()),
        Err(error) => {
            tracing::warn!(%error, "supervise: invalid local readiness request");
            return Ok(());
        }
    };
    if request.socket_path != Path::new(socket_path)
        || request.build_stamp != crate::build_stamp()
        || request.binding_stamp != service_binding_stamp()
        || request.expected_supervisor_pid != std::process::id()
        || !daemon_responds(socket_path)
    {
        return Ok(());
    }
    let record = crate::service_readiness::ServiceReadinessRecord::answer(
        &request,
        std::process::id(),
        peer.id(),
        now_ms(),
    );
    match crate::service_readiness::write_service_readiness(agent_dir, &record) {
        Ok(()) => {
            // Close the replacement-during-write window before consuming the request. If the
            // effective record changed, this removes both the just-written stale answer and its
            // request; the manager can issue a fresh request after the peer has restarted.
            if let Err(error) = ensure_readiness_binding_current(agent_dir, peer_start_fingerprint)
            {
                stop_and_reap(peer);
                tracing::warn!(%error, "supervise: enrollment changed while answering readiness");
                return Err(error);
            }
            let _ = crate::service_readiness::remove_service_readiness_request_if(
                agent_dir,
                &request.request_id,
            );
        }
        Err(error) => {
            tracing::warn!(%error, "supervise: could not answer local readiness request")
        }
    }
    Ok(())
}

/// Probe the daemon: connect to the socket, send `{"op":"list_sessions"}`, and see if it answers. Used only
/// to classify an EXISTING socket file (healthy vs stale). Never logs PTY payload.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The desktop app's CURRENTLY-published daemon socket (from `<MAESTRO_APP_SUPPORT_DIR>/daemon/endpoint.json`), if
/// any. The consistency runner re-reads this each tick: the app republishes it with a NEW socket every restart, so a
/// remote-peer bound to the old one is talking to a dead daemon. None = no MAESTRO_APP_SUPPORT_DIR / nothing
/// published (the `--sock` fallback case; nothing to reconcile). Mirrors `resolve_desktop_daemon_sock` in main.rs but
/// returns Option (the runner decides), and never logs (the runner does).
fn live_daemon_socket() -> Option<String> {
    let base = std::env::var_os("MAESTRO_APP_SUPPORT_DIR")?;
    if base.is_empty() {
        return None;
    }
    let paths = maestro_shell::AppPaths::with_base(PathBuf::from(base));
    match maestro_shell::load_endpoint(&paths) {
        Ok(Some(ep)) if !ep.socket_path.trim().is_empty() => Some(ep.socket_path),
        _ => None,
    }
}

fn daemon_responds(socket_path: &str) -> bool {
    let Ok(mut stream) = UnixStream::connect(socket_path) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    if stream.write_all(b"{\"op\":\"list_sessions\"}\n").is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    matches!(stream.read(&mut buf), Ok(n) if n > 0)
}

/// Resolve socket handling, removing a stale socket file. Returns whether we should start our own daemon
/// (false = a healthy daemon is already there to reuse).
fn prepare_socket(socket_path: &str) -> Result<bool> {
    let exists = Path::new(socket_path).exists();
    match socket_decision(exists, exists && daemon_responds(socket_path)) {
        SocketState::Absent => Ok(true),
        SocketState::HealthyReuse => {
            tracing::info!("supervise: reusing healthy pty-daemon on {socket_path}");
            Ok(false)
        }
        SocketState::StaleRemove => {
            tracing::info!("supervise: removing stale socket {socket_path}");
            let _ = std::fs::remove_file(socket_path);
            Ok(true)
        }
    }
}

/// Wait until the socket accepts a daemon connection (bounded). Returns Err on timeout.
fn wait_for_socket(socket_path: &str, attempts: u32) -> Result<()> {
    for _ in 0..attempts {
        if UnixStream::connect(socket_path).is_ok() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    Err(anyhow!("pty-daemon socket {socket_path} did not come up"))
}

/// Send one `start_session` for `session_id` (idempotent: the daemon ignores a duplicate id). Content-blind:
/// we write the control line and do NOT log the daemon's response.
fn ensure_session(socket_path: &str, session_id: &str, home: &str) -> Result<()> {
    let mut stream =
        UnixStream::connect(socket_path).context("connect daemon for start_session")?;
    stream
        .set_read_timeout(Some(Duration::from_millis(300)))
        .context("set configured-session probe timeout")?;
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .context("clone daemon socket for configured-session probe")?,
    );
    // Existing configured sessions need no mutation at all. Check first so an owned supervisor can
    // keep its remote peer available while reusing an older attach-compatible daemon whose PTYs
    // already exist.
    stream
        .write_all(b"{\"op\":\"list_sessions\"}\n")
        .context("write list_sessions before configured-session ensure")?;
    stream.flush().context("flush list_sessions")?;
    let mut sessions_line = String::new();
    reader
        .read_line(&mut sessions_line)
        .context("read list_sessions before configured-session ensure")?;
    match daemon_lists_session(&sessions_line, session_id) {
        Some(true) => return Ok(()),
        Some(false) => {}
        None => anyhow::bail!("retained daemon returned an invalid session list"),
    }

    // A reused legacy daemon's historical StartSession implementation could reap unrelated exited
    // snapshots. Seeded supervisor sessions have explicit restart authority, but may exercise it
    // only against the protocol that understands that authority. Probe on the same connection and
    // fail closed before sending any mutation.
    stream
        .write_all(b"{\"op\":\"daemon_info\"}\n")
        .context("write daemon_info before start_session")?;
    stream.flush().context("flush daemon_info")?;
    let mut info_line = String::new();
    reader
        .read_line(&mut info_line)
        .context("read daemon_info before start_session")?;
    let observed = daemon_protocol_from_info(&info_line).ok_or_else(|| {
        anyhow!(
            "retained daemon is attach-only; configured-session restart requires protocol {}",
            maestro_protocol::DAEMON_PROTOCOL_VERSION
        )
    })?;
    if observed != maestro_protocol::DAEMON_PROTOCOL_VERSION {
        anyhow::bail!(
            "retained daemon protocol {observed} is attach-only; configured-session restart requires protocol {}",
            maestro_protocol::DAEMON_PROTOCOL_VERSION
        );
    }
    stream
        .write_all(
            start_session_line_with_restart_authority(
                session_id,
                home,
                "bash",
                &["--norc", "-i"],
                true,
            )
            .as_bytes(),
        )
        .context("write start_session")?;
    let _ = stream.flush();
    // brief read to let the daemon process it; response intentionally discarded (no PTY payload in logs).
    let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
    let mut buf = [0u8; 64];
    let _ = stream.read(&mut buf);
    Ok(())
}

fn daemon_lists_session(line: &str, session_id: &str) -> Option<bool> {
    let value: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    if value.get("ev")?.as_str()? != "sessions" {
        return None;
    }
    Some(
        value
            .get("ids")?
            .as_array()?
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(|id| id == session_id),
    )
}

fn daemon_protocol_from_info(line: &str) -> Option<u32> {
    let value: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
    (value.get("ev")?.as_str()? == "daemon_info"
        && value
            .get("generation_conditional_mutations")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        && value
            .get("attachment_aware_conditional_kill")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false))
    .then(|| value.get("protocol_version")?.as_u64()?.try_into().ok())
    .flatten()
}

fn spawn(cmd: &ChildCommand) -> Result<Child> {
    Command::new(&cmd.program)
        .args(&cmd.args)
        .spawn()
        .with_context(|| format!("spawn {}", cmd.program))
}

fn ensure_daemon_available(opts: &SuperviseOptions) -> Result<Option<Child>> {
    if prepare_socket(&opts.socket_path)? {
        let child = spawn(&pty_daemon_command(opts)).context("start pty-daemon")?;
        wait_for_socket(&opts.socket_path, 40)?;
        Ok(Some(child))
    } else {
        Ok(None)
    }
}

fn ensure_configured_sessions(opts: &SuperviseOptions, home: &str) -> Result<()> {
    for s in &opts.sessions {
        ensure_session(&opts.socket_path, s, home)?;
    }
    Ok(())
}

/// Spawn remote-peer bound to a SPECIFIC socket (used by the consistency runner when the desktop republishes a new
/// daemon socket). Same command as `remote_peer_command` but with `socket_path` overridden.
fn spawn_remote_peer_at(opts: &SuperviseOptions, socket: &str) -> Result<Child> {
    let mut o = opts.clone();
    o.socket_path = socket.to_string();
    spawn(&remote_peer_command(&o))
}

fn spawn_bound_remote_peer_at(
    opts: &SuperviseOptions,
    socket: &str,
) -> Result<(Child, EffectiveEnrollmentBinding)> {
    start_for_current_binding(
        &opts.agent_dir,
        || spawn_remote_peer_at(opts, socket),
        stop_and_reap,
    )
    .context("start release-bound remote-peer")
}

fn spawn_bound_peer_or_stop_owned_daemon(
    opts: &SuperviseOptions,
    socket: &str,
    owned_daemon: &mut Option<Child>,
) -> Result<(Child, EffectiveEnrollmentBinding)> {
    match spawn_bound_remote_peer_at(opts, socket) {
        Ok(started) => Ok(started),
        Err(error) => {
            if let Some(daemon) = owned_daemon.as_mut() {
                stop_and_reap(daemon);
            }
            *owned_daemon = None;
            Err(error)
        }
    }
}

const DAEMON_FAILURE_GRACE_PROBES: u8 = 3;

fn observe_daemon_probe(consecutive_failures: u8, responds: bool) -> (u8, bool) {
    if responds {
        return (0, false);
    }
    let failures = consecutive_failures.saturating_add(1);
    (failures, failures >= DAEMON_FAILURE_GRACE_PROBES)
}

/// An attach-only connectivity service must not advertise presence before its
/// terminal daemon is actually usable. Desktop mode may follow the endpoint
/// published by the GUI. Fixed headless mode must probe only the reviewed
/// socket supplied by its independent systemd user unit.
fn wait_for_external_daemon(opts: &SuperviseOptions, fallback: &str) -> Result<String> {
    wait_for_external_daemon_with(opts, fallback, live_daemon_socket, daemon_responds, || {
        std::thread::sleep(Duration::from_millis(500))
    })
}

fn wait_for_external_daemon_with(
    opts: &SuperviseOptions,
    fallback: &str,
    mut published_socket: impl FnMut() -> Option<String>,
    mut responds: impl FnMut(&str) -> bool,
    mut pause: impl FnMut(),
) -> Result<String> {
    // A readiness file from an earlier killed supervisor must not remain visible while this
    // supervisor is waiting for the GUI-owned daemon. No peer exists during this wait.
    withdraw_all_service_readiness(&opts.agent_dir)?;
    loop {
        let before_probe = effective_binding_or_withdraw(&opts.agent_dir)
            .context("enrollment became invalid while waiting for the desktop daemon")?;
        if !Path::new(&opts.hydra_agent_bin).is_file() {
            anyhow::bail!("installed Hydra agent binary was removed; stopping remote service");
        }
        let responding_socket = if opts.fixed_external_daemon {
            // This branch deliberately never evaluates `published_socket`.
            // A stale or hostile desktop endpoint cannot redirect a headless
            // service away from the socket bound to its reviewed user unit.
            responds(fallback).then(|| fallback.to_string())
        } else if let Some(live) = published_socket().filter(|socket| responds(socket)) {
            Some(live)
        } else {
            responds(fallback).then(|| fallback.to_string())
        };
        if let Some(socket) = responding_socket {
            // The socket probe can block briefly. Re-read enrollment before returning so an A -> B
            // replacement during that probe never starts a peer under an ambiguous identity.
            let after_probe = effective_binding_or_withdraw(&opts.agent_dir)
                .context("enrollment became invalid while waiting for the desktop daemon")?;
            if after_probe.fingerprint == before_probe.fingerprint {
                return Ok(socket);
            }
        }
        pause();
    }
}

/// Run the supervisor: start pty-daemon (unless a healthy one exists), ensure sessions, start remote-peer,
/// then monitor. Policy: if an owned pty-daemon exits, rebuild the local tree in-process so the guided
/// SUPERVISE=1 path self-recovers; if remote-peer exits, restart it with bounded backoff (network/cloud
/// blips are normal). A healthy pre-existing daemon is reused but not owned/monitored.
pub fn run(opts: &SuperviseOptions, home: &str) -> Result<()> {
    if opts.fixed_external_daemon && opts.own_daemon {
        anyhow::bail!("a fixed external daemon cannot also be supervisor-owned")
    }
    match run_active(opts, home) {
        Err(error) if error.downcast_ref::<EnrollmentWithdrawn>().is_some() => {
            // launchd KeepAlive/SuccessfulExit=false and systemd Restart=on-failure both leave a
            // successful exit inert. Removal, corruption, and a wrong release environment have
            // already withdrawn all readiness and reaped children before reaching this boundary.
            tracing::warn!(%error, "supervise: enrollment authority is absent; exiting inertly");
            Ok(())
        }
        result => result,
    }
}

fn run_active(opts: &SuperviseOptions, home: &str) -> Result<()> {
    // Clear a record left by any prior killed supervisor before validating enrollment. Missing,
    // corrupt, or wrong-environment enrollment must converge to an inert service even when stale
    // readiness predates this process.
    withdraw_all_service_readiness(&opts.agent_dir)?;
    let _initial_binding = effective_binding_or_withdraw(&opts.agent_dir)?;
    let _readiness_guard = ServiceReadinessGuard {
        agent_dir: &opts.agent_dir,
        supervisor_pid: std::process::id(),
    };
    // The app and agent share one migration lock and durable completion marker. A failed import
    // leaves legacy JSON authoritative, so the agent must stop rather than creating or serving a
    // new empty SQLite store beside it.
    let paths = maestro_shell::paths::AppPaths::production()
        .context("resolve local data directory for legacy migration")?;
    maestro_shell::migrate::migrate_json_to_sqlite(&paths).map_err(|error| {
        anyhow!("legacy local data was left untouched; supervisor stopped: {error}")
    })?;
    // Fail CLEARLY up front if a configured binary path is missing, instead of a raw "No such file" mid-startup.
    // When attaching to the desktop app's daemon we don't run our own pty-daemon, so only the hydra-agent binary
    // must exist; otherwise both are required.
    let missing = if opts.own_daemon {
        missing_binary_paths(&opts.pty_daemon_bin, &opts.hydra_agent_bin, |p| {
            std::path::Path::new(p).exists()
        })
    } else {
        missing_binary_paths(&opts.hydra_agent_bin, &opts.hydra_agent_bin, |p| {
            std::path::Path::new(p).exists()
        })
    };
    if !missing.is_empty() {
        anyhow::bail!(
            "{}\n  build the workspace first: cargo build -p pty-daemon && cargo build -p hydra-agent --features webrtc",
            missing.join("\n")
        );
    }
    if opts.own_daemon {
        tracing::info!(sock = %opts.socket_path, "supervise: starting (owns pty-daemon)");
    } else if opts.fixed_external_daemon {
        tracing::info!(sock = %opts.socket_path, "supervise: starting (attached to fixed headless pty-daemon)");
    } else {
        tracing::info!(sock = %opts.socket_path, "supervise: starting (attached to the desktop app's daemon)");
    }

    // own_daemon=false → the desktop app owns the daemon: don't spawn one, don't seed sessions.
    let mut daemon = if opts.own_daemon {
        let d = ensure_daemon_available(opts)?;
        ensure_configured_sessions(opts, home)?;
        d
    } else {
        None
    };
    let mut current_socket = if opts.own_daemon {
        opts.socket_path.clone()
    } else {
        wait_for_external_daemon(opts, &opts.socket_path)?
    };
    let (mut peer, started_binding) =
        spawn_bound_peer_or_stop_owned_daemon(opts, &current_socket, &mut daemon)?;
    // Consistency runner state: the socket the CURRENT peer is bound to, the enrollment fp it started with, and the
    // last time we ran a pass. See consistency.rs. Only meaningful when attached to the desktop's daemon
    // (own_daemon=false) — an owned daemon is monitored directly above.
    let mut peer_start_fp = started_binding.fingerprint;
    let mut last_consistency = std::time::Instant::now();
    let mut last_daemon_probe = std::time::Instant::now();
    let mut daemon_probe_failures = 0u8;
    // Debounce a churning desktop socket: count how many consecutive consistency ticks the SAME live socket value has
    // been observed, so we only migrate remote-peer once the new socket has settled (see consistency.rs). Without
    // this, a desktop cycling sockets made us restart the peer every tick and kill the browser session forever.
    let mut last_live_socket: Option<String> = None;
    let mut live_socket_stable_ticks: u32 = 0;

    let mut backoff = BACKOFF_START;
    loop {
        std::thread::sleep(Duration::from_millis(500));
        // Enrollment is checked before child exit inspection. This ordering is deliberate: if
        // Remove Remote and child exit happen together, no restart may be attempted from the old
        // authority. A valid A -> B replacement also reaps A before B is started.
        let observed_binding =
            match validate_running_enrollment_or_withdraw(&opts.agent_dir, &mut peer) {
                Ok(binding) => binding,
                Err(error) => {
                    if let Some(daemon) = daemon.as_mut() {
                        stop_and_reap(daemon);
                    }
                    return Err(error).context(
                        "effective enrollment was withdrawn; supervisor converged to inert",
                    );
                }
            };
        if observed_binding.fingerprint != peer_start_fp {
            clear_service_readiness(&opts.agent_dir);
            stop_and_reap(&mut peer);
            let (replacement, binding) =
                spawn_bound_peer_or_stop_owned_daemon(opts, &current_socket, &mut daemon)
                    .context("restart remote-peer after enrollment authority replacement")?;
            peer = replacement;
            peer_start_fp = binding.fingerprint;
            backoff = BACKOFF_START;
            continue;
        }
        if !Path::new(&opts.hydra_agent_bin).is_file() {
            clear_service_readiness(&opts.agent_dir);
            stop_and_reap(&mut peer);
            if let Some(daemon) = daemon.as_mut() {
                stop_and_reap(daemon);
            }
            anyhow::bail!("installed Hydra agent binary was removed; stopping remote service");
        }
        // A manager job is not ready merely because the supervisor exists. The
        // exact remote-peer child must survive and advance scoped local evidence.
        match peer.try_wait() {
            Ok(Some(status)) => {
                clear_service_readiness(&opts.agent_dir);
                tracing::warn!(
                    "supervise: remote-peer exited ({status}); restarting in {:?}",
                    backoff
                );
                std::thread::sleep(backoff);
                backoff = next_backoff(backoff);
                if !opts.own_daemon {
                    current_socket = wait_for_external_daemon(opts, &current_socket)?;
                }
                let (replacement, binding) =
                    spawn_bound_peer_or_stop_owned_daemon(opts, &current_socket, &mut daemon)
                        .context("restart remote-peer")?;
                peer = replacement;
                peer_start_fp = binding.fingerprint;
                continue;
            }
            Err(error) => {
                clear_service_readiness(&opts.agent_dir);
                return Err(error).context("inspect remote-peer child state");
            }
            Ok(None) => {}
        }
        if !opts.own_daemon && last_daemon_probe.elapsed() >= Duration::from_secs(2) {
            last_daemon_probe = std::time::Instant::now();
            let (failures, sustained_loss) =
                observe_daemon_probe(daemon_probe_failures, daemon_responds(&current_socket));
            daemon_probe_failures = failures;
            if sustained_loss {
                clear_service_readiness(&opts.agent_dir);
                tracing::warn!(
                    socket = %current_socket,
                    "supervise: retained daemon unavailable; withdrawing remote presence"
                );
                stop_and_reap(&mut peer);
                current_socket = wait_for_external_daemon(opts, &current_socket)?;
                let (replacement, binding) =
                    spawn_bound_peer_or_stop_owned_daemon(opts, &current_socket, &mut daemon)
                        .context("restart remote-peer after retained daemon returned")?;
                peer = replacement;
                peer_start_fp = binding.fingerprint;
                backoff = BACKOFF_START;
                daemon_probe_failures = 0;
                continue;
            }
        }
        if let Err(error) =
            answer_service_readiness_request(opts, &mut peer, &current_socket, peer_start_fp)
        {
            if let Some(daemon) = daemon.as_mut() {
                stop_and_reap(daemon);
            }
            return Err(error).context("remote-peer lost enrollment while answering readiness");
        }
        // CONSISTENCY PASS (~5s): reconcile the stale-prone desktop state (daemon socket freshness, enrollment identity,
        // heartbeat liveness), self-heal the safe cases (restart remote-peer onto the live socket / fresh identity),
        // and LOG every pass to consistency.jsonl so sync problems are observable. Only when attached to the
        // desktop's daemon. Owned and fixed headless daemons are monitored directly above.
        if !opts.own_daemon
            && !opts.fixed_external_daemon
            && last_consistency.elapsed() >= crate::consistency::CONSISTENCY_INTERVAL
        {
            last_consistency = std::time::Instant::now();
            let live = live_daemon_socket();
            let responds = live.as_deref().map(daemon_responds).unwrap_or(false);
            // Update the stability counter: same live socket as last tick → increment; changed → reset to 1.
            if live == last_live_socket {
                live_socket_stable_ticks = live_socket_stable_ticks.saturating_add(1);
            } else {
                last_live_socket = live.clone();
                live_socket_stable_ticks = 1;
            }
            let hb = crate::heartbeat_status::load(&opts.agent_dir);
            let hb_age = hb.map(|s| now_ms().saturating_sub(s.ts_ms));
            let report = crate::consistency::evaluate(&crate::consistency::ConsistencyInputs {
                running_socket: current_socket.clone(),
                live_socket: live.clone(),
                live_socket_responds: responds,
                live_socket_stable_ticks,
                enrollment_fp_at_start: Some(consistency_enrollment_fingerprint(peer_start_fp)),
                enrollment_fp_now: Some(consistency_enrollment_fingerprint(
                    observed_binding.fingerprint,
                )),
                heartbeat_age_ms: hb_age,
                heartbeat_interval_ms: crate::heartbeat::DEFAULT_INTERVAL.as_millis() as u64,
            });
            // Log every pass (append-only, content-blind) so staleness + heals are visible historically.
            crate::consistency::append_log(&opts.agent_dir, &report, now_ms());
            match &report.heal {
                crate::consistency::Heal::RestartPeerForSocket { live_socket } => {
                    clear_service_readiness(&opts.agent_dir);
                    tracing::warn!(
                        "consistency: daemon socket stale → restarting remote-peer onto the live socket"
                    );
                    stop_and_reap(&mut peer);
                    current_socket = live_socket.clone();
                    let (replacement, binding) =
                        spawn_bound_peer_or_stop_owned_daemon(opts, &current_socket, &mut daemon)
                            .context("restart remote-peer for stale daemon socket")?;
                    peer = replacement;
                    peer_start_fp = binding.fingerprint;
                    backoff = BACKOFF_START;
                    continue;
                }
                crate::consistency::Heal::RestartPeerForEnrollment => {
                    clear_service_readiness(&opts.agent_dir);
                    // The full authority check above normally catches this first; this remains a
                    // defensive backstop for the separate consistency evaluator.
                    tracing::warn!("consistency: enrollment changed → restarting remote-peer");
                    stop_and_reap(&mut peer);
                    let (replacement, binding) =
                        spawn_bound_peer_or_stop_owned_daemon(opts, &current_socket, &mut daemon)
                            .context("restart remote-peer for enrollment change (consistency)")?;
                    peer = replacement;
                    peer_start_fp = binding.fingerprint;
                    backoff = BACKOFF_START;
                    continue;
                }
                crate::consistency::Heal::None => {}
            }
        }
        // Owned pty-daemon death → rebuild daemon + sessions + remote-peer in-process.
        if let Some(d) = daemon.as_mut() {
            if let Ok(Some(status)) = d.try_wait() {
                clear_service_readiness(&opts.agent_dir);
                tracing::warn!(
                    "supervise: pty-daemon exited ({status}); restarting daemon and remote-peer"
                );
                stop_and_reap(&mut peer);
                daemon = ensure_daemon_available(opts).context("restart pty-daemon")?;
                ensure_configured_sessions(opts, home)
                    .context("re-ensure sessions after daemon restart")?;
                let (replacement, binding) =
                    spawn_bound_peer_or_stop_owned_daemon(opts, &opts.socket_path, &mut daemon)
                        .context("restart remote-peer after daemon restart")?;
                peer = replacement;
                peer_start_fp = binding.fingerprint;
                backoff = BACKOFF_START; // a clean daemon-restart resets the peer backoff
                continue;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp(label: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = std::fs::canonicalize("/tmp").unwrap().join(format!(
            "hydra-supervise-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    fn valid_record(
        device_id: &str,
        account_id: &str,
        passkey: Option<crate::browser_cert::PasskeyPublicKey>,
    ) -> crate::device_identity::DeviceRecord {
        crate::device_identity::DeviceRecord {
            device_id: device_id.to_string(),
            account_id: account_id.to_string(),
            cloud_base: crate::release_trust::active().cloud_base.to_string(),
            passkey,
        }
    }

    fn valid_passkey() -> crate::browser_cert::PasskeyPublicKey {
        crate::browser_cert::PasskeyPublicKey {
            spki_b64: "AAAA".to_string(),
            alg: "es256".to_string(),
            rp_id: "hydraterms.com".to_string(),
        }
    }

    fn write_stale_readiness(dir: &Path, supervisor_pid: u32, peer_pid: u32) {
        let request = crate::service_readiness::ServiceReadinessRequest::new(
            supervisor_pid,
            PathBuf::from("/tmp/hydra-stale-readiness.sock"),
            crate::build_stamp(),
            service_binding_stamp(),
            1_000,
        );
        crate::service_readiness::write_service_readiness_request(dir, &request).unwrap();
        let record = crate::service_readiness::ServiceReadinessRecord::answer(
            &request,
            supervisor_pid,
            peer_pid,
            1_100,
        );
        crate::service_readiness::write_service_readiness(dir, &record).unwrap();
    }

    fn assert_no_readiness(dir: &Path) {
        assert!(crate::service_readiness::load_service_readiness(dir)
            .unwrap()
            .is_none());
        assert!(
            crate::service_readiness::load_service_readiness_request(dir)
                .unwrap()
                .is_none()
        );
    }

    fn opts() -> SuperviseOptions {
        SuperviseOptions {
            agent_dir: PathBuf::from("/tmp/agent-dir"),
            socket_path: "/tmp/hydra-maestro-4242.sock".to_string(),
            sessions: vec!["s1".to_string()],
            pty_daemon_bin: "/usr/local/bin/pty-daemon".to_string(),
            hydra_agent_bin: "/usr/local/bin/hydra-agent".to_string(),
            own_daemon: true,
            fixed_external_daemon: false,
        }
    }

    #[test]
    fn builds_pty_daemon_command() {
        let c = pty_daemon_command(&opts());
        assert_eq!(c.program, "/usr/local/bin/pty-daemon");
        assert_eq!(c.args, vec!["/tmp/hydra-maestro-4242.sock".to_string()]);
    }

    #[test]
    fn attach_mode_only_requires_the_hydra_agent_binary_not_pty_daemon() {
        // own_daemon=false → the desktop app owns the daemon; a MISSING pty-daemon binary must not block startup,
        // only a missing hydra-agent binary should. (Mirrors run()'s missing-binary gate.)
        let missing_pty =
            missing_binary_paths("/no/such/pty-daemon", "/usr/local/bin/hydra-agent", |p| {
                p == "/usr/local/bin/hydra-agent"
            });
        // In OWN-daemon mode the missing pty-daemon IS reported.
        assert!(missing_pty.iter().any(|m| m.contains("pty-daemon")));
        // In ATTACH mode we only check the agent binary, so a present agent → nothing missing.
        let attach_missing = missing_binary_paths(
            "/usr/local/bin/hydra-agent",
            "/usr/local/bin/hydra-agent",
            |p| p == "/usr/local/bin/hydra-agent",
        );
        assert!(attach_missing.is_empty());
    }

    #[test]
    fn builds_remote_peer_command_without_account_or_device_id() {
        let c = remote_peer_command(&opts());
        assert_eq!(c.program, "/usr/local/bin/hydra-agent");
        assert_eq!(
            c.args,
            vec![
                "remote-peer",
                "--dir",
                "/tmp/agent-dir",
                "--sock",
                "/tmp/hydra-maestro-4242.sock",
                "--sessions",
                "s1",
            ]
        );
        // identity comes from device.json — these must NOT be passed
        assert!(!c
            .args
            .iter()
            .any(|a| a == "--account" || a == "--device-id"));
    }

    #[test]
    fn fixed_external_daemon_marks_only_its_remote_peer_as_headless() {
        let desktop = remote_peer_command(&opts());
        assert!(!desktop.args.iter().any(|arg| arg == "--headless-server"));

        let mut headless = opts();
        headless.own_daemon = false;
        headless.fixed_external_daemon = true;
        let headless = remote_peer_command(&headless);
        assert_eq!(
            headless
                .args
                .iter()
                .filter(|arg| arg.as_str() == "--headless-server")
                .count(),
            1
        );
    }

    #[test]
    fn service_binding_stamp_uses_the_compiled_tuple_only() {
        let base = service_binding_stamp();
        let other_environment = if crate::release_trust::ENVIRONMENT == "staging" {
            "production"
        } else {
            "staging"
        };
        let reconstructed = service_binding_stamp_for(
            "production",
            crate::launchd::DEFAULT_CLOUD_BASE,
            crate::launchd::DEFAULT_CLOUD_PUBKEY,
            crate::launchd::DEFAULT_ALLOWED_ORIGIN,
        );
        assert_eq!(base.len(), 64);
        if crate::release_trust::ENVIRONMENT == "production" {
            assert_eq!(base, reconstructed);
        }
        for changed in [
            service_binding_stamp_for(
                other_environment,
                crate::launchd::DEFAULT_CLOUD_BASE,
                crate::launchd::DEFAULT_CLOUD_PUBKEY,
                crate::launchd::DEFAULT_ALLOWED_ORIGIN,
            ),
            service_binding_stamp_for(
                "production",
                "https://api.staging.hydraterms.com",
                crate::launchd::DEFAULT_CLOUD_PUBKEY,
                crate::launchd::DEFAULT_ALLOWED_ORIGIN,
            ),
            service_binding_stamp_for(
                "production",
                crate::launchd::DEFAULT_CLOUD_BASE,
                "different-public-verifier",
                crate::launchd::DEFAULT_ALLOWED_ORIGIN,
            ),
            service_binding_stamp_for(
                "production",
                crate::launchd::DEFAULT_CLOUD_BASE,
                crate::launchd::DEFAULT_CLOUD_PUBKEY,
                "https://staging.hydraterms.com",
            ),
        ] {
            assert_ne!(changed, base);
        }
    }

    #[test]
    fn enrollment_binding_rejects_another_release_environment() {
        let temp = unique_temp("binding");
        let wrong_cloud = if crate::release_trust::CLOUD_BASE.contains("staging") {
            "https://api.hydraterms.com"
        } else {
            "https://api.staging.hydraterms.com"
        };
        crate::device_identity::save_record(
            &temp,
            &crate::device_identity::DeviceRecord {
                device_id: "desktop-1".to_string(),
                account_id: "account-1".to_string(),
                cloud_base: wrong_cloud.to_string(),
                passkey: None,
            },
        )
        .unwrap();
        assert!(validate_enrollment_binding(&temp)
            .unwrap_err()
            .contains("does not match"));
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn legacy_enrollment_without_passkey_is_refused_without_deleting_local_identity() {
        let temp = unique_temp("legacy-no-passkey");
        let record = valid_record("device-legacy", "account-legacy", None);
        crate::device_identity::save_record(&temp, &record).unwrap();

        let error = validate_enrollment_binding(&temp).unwrap_err();
        assert!(error.contains("predates required passkey authorization"));
        assert!(error.contains("hydraterms remove-remote --apply"));
        assert!(error.contains("Add Desktop"));
        assert!(error.contains("hydraterms remote"));
        assert!(error.contains("local terminal sessions were not changed"));
        let retained = crate::device_identity::load_record(&temp)
            .unwrap()
            .expect("validation must not silently delete the identity");
        assert_eq!(retained.device_id, record.device_id);
        assert_eq!(retained.account_id, record.account_id);
        assert_eq!(retained.cloud_base, record.cloud_base);
        assert!(retained.passkey.is_none());
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn legacy_desktop_and_headless_services_exit_before_daemon_or_peer_start() {
        for headless in [false, true] {
            let temp = unique_temp(if headless {
                "legacy-headless-inert"
            } else {
                "legacy-desktop-inert"
            });
            let record = valid_record("device-legacy", "account-legacy", None);
            crate::device_identity::save_record(&temp, &record).unwrap();
            write_stale_readiness(&temp, 999_101, 999_102);

            let socket = temp.join("must-not-be-created.sock");
            let mut options = opts();
            options.agent_dir = temp.clone();
            options.socket_path = socket.display().to_string();
            options.pty_daemon_bin = temp.join("must-not-run-daemon").display().to_string();
            options.hydra_agent_bin = temp.join("must-not-run-peer").display().to_string();
            options.own_daemon = !headless;
            options.fixed_external_daemon = headless;

            run(&options, "/tmp").expect("legacy authority withdrawal is an inert service exit");
            assert!(!socket.exists(), "no local terminal socket may be created");
            assert_no_readiness(&temp);
            let retained = crate::device_identity::load_record(&temp)
                .unwrap()
                .expect("owner must explicitly remove/re-enroll the legacy identity");
            assert_eq!(retained.device_id, record.device_id);
            assert!(retained.passkey.is_none());
            let _ = std::fs::remove_dir_all(temp);
        }
    }

    #[test]
    fn full_authority_fingerprint_detects_a_to_b_account_and_passkey_only_replacement() {
        let passkey_a = crate::browser_cert::PasskeyPublicKey {
            spki_b64: "AAAA".to_string(),
            alg: "es256".to_string(),
            rp_id: "hydraterms.com".to_string(),
        };
        let mut passkey_b = passkey_a.clone();
        passkey_b.spki_b64 = "BBBB".to_string();

        let a = valid_record("device-A", "account-A", Some(passkey_a.clone()));
        let same = valid_record("device-A", "account-A", Some(passkey_a));
        let device_b = valid_record("device-B", "account-A", Some(passkey_b.clone()));
        let account_b = valid_record("device-A", "account-B", Some(passkey_b.clone()));
        let passkey_only_b = valid_record("device-A", "account-A", Some(passkey_b));

        let baseline = enrollment_authority_fingerprint(&a);
        assert_eq!(baseline, enrollment_authority_fingerprint(&same));
        assert_ne!(baseline, enrollment_authority_fingerprint(&device_b));
        assert_ne!(baseline, enrollment_authority_fingerprint(&account_b));
        assert_ne!(baseline, enrollment_authority_fingerprint(&passkey_only_b));
    }

    #[test]
    fn missing_corrupt_or_wrong_environment_binding_withdraws_readiness_and_reaps_peer() {
        for case in ["missing", "corrupt", "wrong-environment"] {
            let dir = unique_temp(case);
            std::fs::create_dir_all(&dir).unwrap();
            write_stale_readiness(&dir, 999_001, 999_002);
            match case {
                "missing" => {}
                "corrupt" => {
                    std::fs::write(crate::device_identity::record_path(&dir), b"not-json").unwrap();
                }
                "wrong-environment" => {
                    let wrong_cloud = if crate::release_trust::active()
                        .cloud_base
                        .contains("staging")
                    {
                        "https://api.hydraterms.com"
                    } else {
                        "https://api.staging.hydraterms.com"
                    };
                    let mut record = valid_record("device-A", "account-A", Some(valid_passkey()));
                    record.cloud_base = wrong_cloud.to_string();
                    crate::device_identity::save_record(&dir, &record).unwrap();
                }
                _ => unreachable!(),
            }

            let mut child = Command::new("sh").args(["-c", "sleep 30"]).spawn().unwrap();
            let error = validate_running_enrollment_or_withdraw(&dir, &mut child)
                .expect_err("invalid authority must withdraw the running peer");
            assert!(
                error.to_string().contains("not enrolled")
                    || error.to_string().contains("does not match")
            );
            assert!(child.try_wait().unwrap().is_some(), "peer must be reaped");
            assert_no_readiness(&dir);
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn missing_enrollment_makes_the_manager_owned_supervisor_exit_inertly() {
        let dir = unique_temp("missing-inert-exit");
        write_stale_readiness(&dir, 999_006, 999_007);
        let mut options = opts();
        options.agent_dir = dir.clone();

        run(&options, "/tmp").expect("authority withdrawal is a successful inert exit");
        assert_no_readiness(&dir);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn simultaneous_enrollment_removal_and_peer_exit_never_attempts_restart() {
        let dir = unique_temp("remove-and-exit");
        crate::device_identity::save_record(
            &dir,
            &valid_record("device-A", "account-A", Some(valid_passkey())),
        )
        .unwrap();
        write_stale_readiness(&dir, 999_011, 999_012);
        let mut exited_peer = Command::new("sh").args(["-c", "exit 0"]).spawn().unwrap();
        exited_peer.wait().unwrap();
        crate::device_identity::remove_record(&dir).unwrap();

        let mut restart_attempted = false;
        let decision =
            validate_running_enrollment_or_withdraw(&dir, &mut exited_peer).and_then(|_| {
                // This is the exact ordering used by run(): only a valid binding reaches exit
                // inspection and the restart branch.
                if exited_peer.try_wait()?.is_some() {
                    restart_attempted = true;
                }
                Ok(())
            });
        assert!(decision.is_err());
        assert!(!restart_attempted);
        assert_no_readiness(&dir);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn same_owner_device_replacement_during_spawn_reaps_candidate_before_readiness() {
        let dir = unique_temp("replace-during-spawn");
        crate::device_identity::save_record(
            &dir,
            &valid_record("device-A", "account-A", Some(valid_passkey())),
        )
        .unwrap();
        write_stale_readiness(&dir, 999_021, 999_022);
        let replacement_dir = dir.clone();
        let stopped = std::rc::Rc::new(std::cell::Cell::new(false));
        let stopped_by_cleanup = stopped.clone();
        let result = start_for_current_binding(
            &dir,
            move || {
                crate::device_identity::save_record(
                    &replacement_dir,
                    &valid_record("device-B", "account-A", Some(valid_passkey())),
                )?;
                Ok(())
            },
            move |_| stopped_by_cleanup.set(true),
        );
        assert!(result.is_err());
        assert!(stopped.get(), "ambiguous child candidate must be reaped");
        assert_no_readiness(&dir);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn readiness_is_withdrawn_when_enrollment_no_longer_matches_the_peer() {
        let dir = unique_temp("readiness-replacement");
        let a = valid_record("device-A", "account-A", Some(valid_passkey()));
        crate::device_identity::save_record(&dir, &a).unwrap();
        let peer_fingerprint = enrollment_authority_fingerprint(&a);
        write_stale_readiness(&dir, 999_031, 999_032);
        crate::device_identity::save_record(
            &dir,
            &valid_record("device-B", "account-A", Some(valid_passkey())),
        )
        .unwrap();

        assert!(ensure_readiness_binding_current(&dir, peer_fingerprint).is_err());
        assert_no_readiness(&dir);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn external_daemon_wait_exits_on_enrollment_removal_and_clears_stale_readiness() {
        let dir = unique_temp("external-wait-remove");
        crate::device_identity::save_record(
            &dir,
            &valid_record("device-A", "account-A", Some(valid_passkey())),
        )
        .unwrap();
        write_stale_readiness(&dir, 999_041, 999_042);
        let agent_bin = dir.join("hydra-agent");
        std::fs::write(&agent_bin, b"test-binary-placeholder").unwrap();
        let mut options = opts();
        options.agent_dir = dir.clone();
        options.hydra_agent_bin = agent_bin.display().to_string();
        options.own_daemon = false;
        let removal_dir = dir.clone();
        let mut pauses = 0usize;
        let result = wait_for_external_daemon_with(
            &options,
            "/tmp/absent-hydra.sock",
            || None,
            |_| false,
            || {
                pauses += 1;
                crate::device_identity::remove_record(&removal_dir).unwrap();
            },
        );
        assert!(result.is_err());
        assert_eq!(pauses, 1);
        assert_no_readiness(&dir);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn external_daemon_wait_converges_after_same_owner_device_replacement_during_probe() {
        let dir = unique_temp("external-wait-replace");
        crate::device_identity::save_record(
            &dir,
            &valid_record("device-A", "account-A", Some(valid_passkey())),
        )
        .unwrap();
        write_stale_readiness(&dir, 999_051, 999_052);
        let agent_bin = dir.join("hydra-agent");
        std::fs::write(&agent_bin, b"test-binary-placeholder").unwrap();
        let mut options = opts();
        options.agent_dir = dir.clone();
        options.hydra_agent_bin = agent_bin.display().to_string();
        options.own_daemon = false;
        let replacement_dir = dir.clone();
        let mut probes = 0usize;
        let socket = wait_for_external_daemon_with(
            &options,
            "/tmp/fallback.sock",
            || Some("/tmp/live.sock".to_string()),
            |_| {
                probes += 1;
                if probes == 1 {
                    crate::device_identity::save_record(
                        &replacement_dir,
                        &valid_record("device-B", "account-A", Some(valid_passkey())),
                    )
                    .unwrap();
                }
                true
            },
            || {},
        )
        .unwrap();
        assert_eq!(socket, "/tmp/live.sock");
        assert_eq!(probes, 2, "the ambiguous A probe must not be accepted");
        assert_no_readiness(&dir);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn fixed_external_daemon_never_follows_a_published_desktop_socket() {
        let dir = unique_temp("fixed-external-wait");
        crate::device_identity::save_record(
            &dir,
            &valid_record("device-A", "account-A", Some(valid_passkey())),
        )
        .unwrap();
        let agent_bin = dir.join("hydra-agent");
        std::fs::write(&agent_bin, b"test-binary-placeholder").unwrap();
        let mut options = opts();
        options.agent_dir = dir.clone();
        options.hydra_agent_bin = agent_bin.display().to_string();
        options.own_daemon = false;
        options.fixed_external_daemon = true;

        let published_calls = std::cell::Cell::new(0usize);
        let fixed_socket = "/tmp/fixed-headless.sock";
        let socket = wait_for_external_daemon_with(
            &options,
            fixed_socket,
            || {
                published_calls.set(published_calls.get() + 1);
                Some("/tmp/responding-desktop.sock".to_string())
            },
            |candidate| candidate == fixed_socket,
            || {},
        )
        .unwrap();

        assert_eq!(socket, fixed_socket);
        assert_eq!(
            published_calls.get(),
            0,
            "fixed headless mode must not even consult desktop endpoint publication"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn remote_peer_joins_multiple_sessions() {
        let mut o = opts();
        o.sessions = vec!["s1".to_string(), "s2".to_string()];
        let c = remote_peer_command(&o);
        assert!(c
            .args
            .windows(2)
            .any(|w| w[0] == "--sessions" && w[1] == "s1,s2"));
    }

    #[test]
    fn remote_peer_omits_sessions_flag_by_default_e4() {
        // E4: no pre-seeded sessions → remote-peer is started WITHOUT --sessions (daemon starts empty;
        // the browser creates sessions on demand).
        let mut o = opts();
        o.sessions = vec![];
        let c = remote_peer_command(&o);
        assert!(!c.args.iter().any(|a| a == "--sessions"));
        // Resource arguments remain; trust arguments do not cross argv.
        assert!(c.args.windows(2).any(|w| w[0] == "--sock"));
        for forbidden in [
            "--environment",
            "--expected-cloud",
            "--cloud-pubkey",
            "--allowed-origin",
        ] {
            assert!(!c.args.iter().any(|arg| arg == forbidden));
        }
    }

    #[test]
    fn remote_peer_still_passes_sessions_when_explicitly_seeded() {
        let mut o = opts();
        o.sessions = vec!["s1".to_string()];
        let c = remote_peer_command(&o);
        assert!(c
            .args
            .windows(2)
            .any(|w| w[0] == "--sessions" && w[1] == "s1"));
    }

    #[test]
    fn dry_run_plan_notes_no_seeded_sessions_when_empty() {
        let mut o = opts();
        o.sessions = vec![];
        let plan = dry_run_plan(&o);
        assert!(plan.contains("no pre-seeded sessions"));
        assert!(!plan.contains("ensure session")); // nothing to ensure
        assert!(!plan.contains("--sessions")); // remote-peer line has no --sessions either
    }

    #[test]
    fn dry_run_plan_documents_restart_policy() {
        let plan = dry_run_plan(&opts());
        assert!(plan.contains("remote-peer restarts with bounded backoff"));
        assert!(plan.contains("owned pty-daemon restarts rebuild the local tree"));
    }

    #[test]
    fn start_session_line_is_newline_terminated_and_well_formed() {
        let line = start_session_line("s1", "/Users/test/home");
        assert_eq!(
            line,
            "{\"op\":\"start_session\",\"id\":\"s1\",\"cwd\":\"/Users/test/home\",\"command\":\"bash\",\"args\":[\"--norc\",\"-i\"],\"cols\":80,\"rows\":24}\n"
        );
        assert!(line.ends_with('\n'));
        assert!(line.contains("\"op\":\"start_session\""));
        assert!(line.contains("\"id\":\"s1\""));
        assert!(line.contains("\"cwd\":\"/Users/test/home\""));
        // it parses as JSON (sans the trailing newline)
        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["op"], "start_session");
        assert_eq!(parsed["id"], "s1");
    }

    #[test]
    fn start_session_escapes_quotes_in_paths() {
        let line = start_session_line("s1", "/Users/test/a\"b");
        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["cwd"], "/Users/test/a\"b"); // round-trips correctly → escaping worked
    }

    #[test]
    fn start_session_line_with_uses_discrete_escaped_args() {
        let line = start_session_line_with(
            "s1",
            "/Users/test/home",
            "claude",
            &["--resume", "id; rm -rf /", "quote\"slash\\"],
        );
        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["command"], "claude");
        assert_eq!(parsed["args"][0], "--resume");
        assert_eq!(parsed["args"][1], "id; rm -rf /");
        assert_eq!(parsed["args"][2], "quote\"slash\\");
        assert_eq!(parsed.get("restart_exited"), None);
    }

    #[test]
    fn explicit_initial_size_is_encoded_without_changing_local_defaults() {
        let line =
            start_session_line_with_size("remote", "/Users/test/home", "codex", &[], 132, 43);
        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["cols"], 132);
        assert_eq!(parsed["rows"], 43);

        let local: serde_json::Value =
            serde_json::from_str(start_session_line("local", "/Users/test/home").trim_end())
                .unwrap();
        assert_eq!(local["cols"], 80);
        assert_eq!(local["rows"], 24);
    }

    #[test]
    fn configured_session_ensure_carries_explicit_restart_authority() {
        let line = start_session_line_with_restart_authority(
            "seeded",
            "/home/test/user",
            "bash",
            &["--norc", "-i"],
            true,
        );
        let parsed: serde_json::Value = serde_json::from_str(line.trim_end()).unwrap();
        assert_eq!(parsed["restart_exited"], true);
    }

    #[test]
    fn configured_session_restart_probe_accepts_only_typed_current_protocol_info() {
        let current = maestro_protocol::DAEMON_PROTOCOL_VERSION;
        assert_eq!(
            daemon_protocol_from_info(&format!(
                "{{\"ev\":\"daemon_info\",\"protocol_version\":{current},\"build_version\":\"x\",\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":true}}"
            )),
            Some(current)
        );
        assert_eq!(
            daemon_protocol_from_info(
                "{\"ev\":\"daemon_info\",\"protocol_version\":1,\"build_version\":\"old\"}"
            ),
            None
        );
        assert_eq!(
            daemon_protocol_from_info(&format!(
                "{{\"ev\":\"daemon_info\",\"protocol_version\":{current},\"build_version\":\"partial\",\"generation_conditional_mutations\":false}}"
            )),
            None,
            "exact version without explicit CAS capability remains attach-only"
        );
        assert_eq!(
            daemon_protocol_from_info(&format!(
                "{{\"ev\":\"daemon_info\",\"protocol_version\":{current},\"build_version\":\"partial\",\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":false}}"
            )),
            None,
            "generation CAS without the attachment-owner fence remains attach-only"
        );
        assert_eq!(
            daemon_protocol_from_info("{\"ev\":\"error\",\"message\":\"unknown op\"}"),
            None
        );
        assert_eq!(daemon_protocol_from_info("not-json"), None);
    }

    #[test]
    fn configured_session_list_probe_is_typed_and_exact() {
        let line = r#"{"ev":"sessions","ids":["seeded","other"]}"#;
        assert_eq!(daemon_lists_session(line, "seeded"), Some(true));
        assert_eq!(daemon_lists_session(line, "seed"), Some(false));
        assert_eq!(daemon_lists_session(r#"{"ev":"error"}"#, "seeded"), None);
        assert_eq!(daemon_lists_session("not-json", "seeded"), None);
    }

    #[test]
    fn existing_configured_session_on_v1_needs_no_mutation_probe() {
        let socket = std::path::PathBuf::from("/tmp").join(format!(
            "hydra-supervise-v1-existing-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            assert_eq!(request.trim(), r#"{"op":"list_sessions"}"#);
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"seeded\"]}\n")
                .unwrap();
            stream.flush().unwrap();
            request.clear();
            assert_eq!(reader.read_line(&mut request).unwrap(), 0);
        });

        ensure_session(socket.to_str().unwrap(), "seeded", "/home/test/user").unwrap();
        server.join().unwrap();
        let _ = std::fs::remove_file(socket);
    }

    #[test]
    fn missing_configured_session_on_v1_fails_before_start_session() {
        let socket = std::path::PathBuf::from("/tmp").join(format!(
            "hydra-supervise-v1-missing-{}.sock",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&socket);
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            reader.read_line(&mut request).unwrap();
            assert_eq!(request.trim(), r#"{"op":"list_sessions"}"#);
            stream
                .write_all(b"{\"ev\":\"sessions\",\"ids\":[\"other\"]}\n")
                .unwrap();
            stream.flush().unwrap();
            request.clear();
            reader.read_line(&mut request).unwrap();
            assert_eq!(request.trim(), r#"{"op":"daemon_info"}"#);
            stream
                .write_all(
                    b"{\"ev\":\"daemon_info\",\"protocol_version\":1,\"build_version\":\"legacy\"}\n",
                )
                .unwrap();
            stream.flush().unwrap();
            request.clear();
            assert_eq!(reader.read_line(&mut request).unwrap(), 0);
        });

        let error = ensure_session(socket.to_str().unwrap(), "seeded", "/home/test/user")
            .expect_err("missing v1 session must remain attach-only");
        assert!(error.to_string().contains("attach-only"));
        server.join().unwrap();
        let _ = std::fs::remove_file(socket);
    }

    #[test]
    fn socket_decision_covers_absent_healthy_stale() {
        assert_eq!(socket_decision(false, false), SocketState::Absent);
        assert_eq!(socket_decision(true, true), SocketState::HealthyReuse);
        assert_eq!(socket_decision(true, false), SocketState::StaleRemove);
    }

    #[test]
    fn next_backoff_doubles_then_caps_at_30s() {
        // the escalation a flapping remote-peer follows: 1 → 2 → 4 → 8 → 16 → 30 (capped) → 30 …
        let mut b = BACKOFF_START;
        assert_eq!(b, Duration::from_secs(1));
        let expected = [2, 4, 8, 16, 30, 30, 30];
        for want in expected {
            b = next_backoff(b);
            assert_eq!(
                b,
                Duration::from_secs(want),
                "after doubling from the prior step"
            );
        }
        // never exceeds the cap, even from an already-large value.
        assert_eq!(next_backoff(Duration::from_secs(1000)), BACKOFF_CAP);
    }

    #[test]
    fn transient_daemon_probe_misses_do_not_flap_the_remote_peer() {
        let (failures, close) = observe_daemon_probe(0, false);
        assert_eq!(failures, 1);
        assert!(!close);
        let (failures, close) = observe_daemon_probe(failures, false);
        assert_eq!(failures, 2);
        assert!(!close);
        let (failures, close) = observe_daemon_probe(failures, true);
        assert_eq!(failures, 0);
        assert!(!close);
        let (_, close) = observe_daemon_probe(2, false);
        assert!(close, "only sustained loss crosses the grace threshold");
    }

    #[test]
    fn missing_binary_paths_reports_path_like_binaries_that_dont_exist() {
        // both present → nothing missing
        assert!(missing_binary_paths(
            "./target/debug/pty-daemon",
            "./target/debug/hydra-agent",
            |_| true
        )
        .is_empty());
        // pty-daemon path missing → one clear, named message
        let m = missing_binary_paths(
            "./target/debug/pty-daemon",
            "./target/debug/hydra-agent",
            |p| p == "./target/debug/hydra-agent",
        );
        assert_eq!(m.len(), 1);
        assert!(m[0].contains("pty-daemon binary not found at ./target/debug/pty-daemon"));
        // both missing → both reported
        assert_eq!(
            missing_binary_paths("/a/pty-daemon", "/b/hydra-agent", |_| false).len(),
            2
        );
    }

    #[test]
    fn missing_binary_paths_skips_bare_path_resolved_names() {
        // bare names (no separator) rely on $PATH; we don't existence-check them even if `exists` says false.
        assert!(missing_binary_paths("pty-daemon", "hydra-agent", |_| false).is_empty());
    }

    #[test]
    fn missing_enrollment_returns_a_clear_error() {
        let tmp = std::env::temp_dir().join(format!("supervise-noenroll-{}", std::process::id()));
        let err = validate_enrollment(&tmp).unwrap_err();
        assert!(err.contains("not enrolled"));
        assert!(err.contains("enroll")); // tells the user what to do
    }

    #[test]
    fn dry_run_plan_has_no_secrets() {
        let plan = dry_run_plan(&opts()).to_lowercase();
        for bad in [
            "token",
            "secret",
            "private",
            "device-key",
            "bearer",
            "password",
        ] {
            assert!(!plan.contains(bad), "dry-run plan must not contain {bad:?}");
        }
        // It describes only process/resource steps. Trust never crosses argv.
        assert!(dry_run_plan(&opts()).contains("pty-daemon"));
        assert!(dry_run_plan(&opts()).contains("remote-peer"));
        assert!(!dry_run_plan(&opts()).contains(crate::launchd::DEFAULT_CLOUD_PUBKEY));
    }
}
