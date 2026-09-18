//! Same-user, content-blind viewport control plane between the installed public desktop host and
//! the live private remote peer.
//!
//! The public host invokes a one-shot `hydra-agent extension` child. That child proxies only the
//! negotiated typed viewport requests to this fixed private Unix socket; it cannot select a path,
//! cloud, account, key, or origin. The live peer is the sole owner of the in-memory remote viewport
//! state. Kernel peer credentials and strict socket metadata prevent a different OS user from
//! impersonating either end.

use maestro_extension_api::{
    negotiate, validate_remote_desktop_response, Capability, ExtensionHello, LeaseCursor, LeaseId,
    RemoteDesktopErrorCode, RemoteDesktopExtensionResponse, RemoteDesktopHostRequest,
    RemoteDesktopRequestId, RemoteDesktopResponseError, RemoteDesktopViewport,
    RemoteDesktopViewportList, SessionKey, ViewportGeometry, MAX_EXTENSION_FRAME_BYTES,
    MAX_LEASE_TTL_MS,
};
use rand::RngCore as _;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, Read as _, Write};
use std::os::fd::AsRawFd as _;
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

pub const VIEWPORT_CONTROL_SOCKET_NAME: &str = "viewport-control-v1.sock";
const SOCKET_MODE: u32 = 0o600;
const IO_TIMEOUT: Duration = Duration::from_millis(750);
const ACCEPT_POLL: Duration = Duration::from_millis(10);
/// The host polls every five seconds. Seven seconds tolerates one delayed poll without retaining
/// authority anywhere near the public contract's thirty-second ceiling.
const SNAPSHOT_REFRESH_TTL_MS: u32 = 7_000;

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublishedLease {
    lease_id: LeaseId,
    cursor: LeaseCursor,
    geometry: ViewportGeometry,
    authority_generation: crate::winsize_owner::AuthorityGeneration,
}

#[derive(Debug)]
struct ViewportControlState {
    epoch: u64,
    sequence: u64,
    next_lease_id: u64,
    leases: BTreeMap<String, PublishedLease>,
}

impl ViewportControlState {
    fn new(epoch: u64) -> Result<Self, ViewportControlError> {
        if epoch == 0 {
            return Err(ViewportControlError::InvalidState);
        }
        Ok(Self {
            epoch,
            sequence: 0,
            next_lease_id: 1,
            leases: BTreeMap::new(),
        })
    }

    fn advance(&mut self) -> Result<LeaseCursor, ViewportControlError> {
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(ViewportControlError::InvalidState)?;
        LeaseCursor::new(self.epoch, self.sequence).map_err(|_| ViewportControlError::InvalidState)
    }

    fn allocate_lease_id(&mut self) -> Result<LeaseId, ViewportControlError> {
        let serial = self.next_lease_id;
        self.next_lease_id = self
            .next_lease_id
            .checked_add(1)
            .ok_or(ViewportControlError::InvalidState)?;
        LeaseId::new(format!("viewport-{:016x}-{:016x}", self.epoch, serial))
            .map_err(|_| ViewportControlError::InvalidState)
    }

    fn reconcile(
        &mut self,
        current: &[crate::winsize_owner::RemoteOwnedViewport],
    ) -> Result<(), ViewportControlError> {
        let sessions = current
            .iter()
            .map(|viewport| viewport.session_id.as_str())
            .collect::<BTreeSet<_>>();
        let removed = self
            .leases
            .keys()
            .filter(|session| !sessions.contains(session.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        for session in removed {
            self.leases.remove(&session);
            let _ = self.advance()?;
        }

        for viewport in current {
            let authority_changed = self
                .leases
                .get(&viewport.session_id)
                .map(|lease| lease.authority_generation != viewport.authority_generation)
                .unwrap_or(true);
            if authority_changed {
                // A new authenticated claimant must receive a fresh exact identity even when its
                // geometry matches the prior owner. Otherwise a delayed reclaim for that prior
                // owner could revoke the new claim.
                let cursor = self.advance()?;
                let lease_id = self.allocate_lease_id()?;
                self.leases.insert(
                    viewport.session_id.clone(),
                    PublishedLease {
                        lease_id,
                        cursor,
                        geometry: viewport.geometry,
                        authority_generation: viewport.authority_generation,
                    },
                );
                continue;
            }
            let geometry_changed = self
                .leases
                .get(&viewport.session_id)
                .is_some_and(|lease| lease.geometry != viewport.geometry);
            if !geometry_changed {
                continue;
            }
            let cursor = self.advance()?;
            if let Some(lease) = self.leases.get_mut(&viewport.session_id) {
                lease.cursor = cursor;
                lease.geometry = viewport.geometry;
                continue;
            }
            return Err(ViewportControlError::InvalidState);
        }
        Ok(())
    }

    fn snapshot(
        &mut self,
        request_id: RemoteDesktopRequestId,
        current: &[crate::winsize_owner::RemoteOwnedViewport],
        now_ms: u64,
    ) -> Result<RemoteDesktopExtensionResponse, ViewportControlError> {
        self.reconcile(current)?;
        // Every accepted snapshot advances the connection-global cursor. Replaying an older/equal
        // response therefore cannot renew the public host's cache TTL indefinitely.
        let cursor = self.advance()?;
        let ttl_ms = current.iter().try_fold(
            SNAPSHOT_REFRESH_TTL_MS.min(MAX_LEASE_TTL_MS),
            |ttl, viewport| {
                let remaining = match viewport.valid_until_ms {
                    None => u64::from(SNAPSHOT_REFRESH_TTL_MS),
                    Some(deadline) => deadline.saturating_sub(now_ms),
                };
                if remaining == 0 {
                    return Err(ViewportControlError::StaleLease);
                }
                Ok(ttl.min(remaining.min(u64::from(u32::MAX)) as u32))
            },
        )?;
        if ttl_ms == 0 || ttl_ms > MAX_LEASE_TTL_MS {
            return Err(ViewportControlError::InvalidState);
        }

        let viewports = current
            .iter()
            .map(|current| {
                let lease = self
                    .leases
                    .get(&current.session_id)
                    .ok_or(ViewportControlError::InvalidState)?;
                Ok(RemoteDesktopViewport::new(
                    SessionKey::new(current.session_id.clone())
                        .map_err(|_| ViewportControlError::InvalidState)?,
                    lease.lease_id.clone(),
                    lease.cursor,
                    current.geometry,
                ))
            })
            .collect::<Result<Vec<_>, ViewportControlError>>()?;
        Ok(RemoteDesktopExtensionResponse::ViewportSnapshot {
            request_id,
            cursor,
            ttl_ms,
            viewports: RemoteDesktopViewportList::new(viewports)
                .map_err(|_| ViewportControlError::InvalidState)?,
        })
    }

    fn reclaim(
        &mut self,
        request_id: RemoteDesktopRequestId,
        session_id: &SessionKey,
        lease_id: &LeaseId,
        cursor: LeaseCursor,
        current: &[crate::winsize_owner::RemoteOwnedViewport],
        owner: &mut crate::winsize_owner::WinsizeOwner,
    ) -> Result<RemoteDesktopExtensionResponse, ViewportControlError> {
        // Reconcile while holding the same owner lock used for the mutation. Any remote transition
        // since the host's snapshot changes/removes the lease before exact-match validation.
        self.reconcile(current)?;
        let Some(lease) = self.leases.get(session_id.as_str()) else {
            return Err(ViewportControlError::StaleLease);
        };
        if &lease.lease_id != lease_id || lease.cursor != cursor {
            return Err(ViewportControlError::StaleLease);
        }
        if !owner.reclaim_viewport(session_id.as_str()) {
            return Err(ViewportControlError::StaleLease);
        }
        self.leases.remove(session_id.as_str());
        let _ = self.advance()?;
        Ok(RemoteDesktopExtensionResponse::ViewportReclaimed {
            request_id,
            session_id: session_id.clone(),
            lease_id: lease_id.clone(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewportControlError {
    Unavailable,
    UnsafeSocket,
    Timeout,
    Malformed,
    UnexpectedRequest,
    StaleLease,
    InvalidState,
}

fn response_error(
    request_id: RemoteDesktopRequestId,
    error: ViewportControlError,
) -> RemoteDesktopExtensionResponse {
    let (code, message, retryable) = match error {
        ViewportControlError::StaleLease => (
            RemoteDesktopErrorCode::ViewportUnavailable,
            "remote viewport lease is stale",
            false,
        ),
        ViewportControlError::UnexpectedRequest | ViewportControlError::Malformed => (
            RemoteDesktopErrorCode::InvalidRequest,
            "remote viewport request was refused",
            false,
        ),
        _ => (
            RemoteDesktopErrorCode::RemoteUnavailable,
            "remote viewport service is unavailable",
            true,
        ),
    };
    RemoteDesktopExtensionResponse::Error {
        request_id,
        error: RemoteDesktopResponseError::new(code, message, retryable)
            .expect("fixed viewport errors satisfy public bounds"),
    }
}

fn negotiated_contract() -> maestro_extension_api::NegotiatedExtension {
    let hello = ExtensionHello::host([
        Capability::remote_desktop_lifecycle_v1(),
        Capability::external_viewport_lease_v1(),
    ])
    .expect("fixed capabilities are valid");
    negotiate(&hello, &hello).expect("identical fixed protocol ranges overlap")
}

fn read_frame(reader: &mut impl BufRead) -> Result<Vec<u8>, ViewportControlError> {
    let mut bytes = Vec::new();
    let mut bounded = reader.take((MAX_EXTENSION_FRAME_BYTES + 2) as u64);
    bounded.read_until(b'\n', &mut bytes).map_err(classify_io)?;
    if bytes.last() != Some(&b'\n') {
        return Err(ViewportControlError::Malformed);
    }
    bytes.pop();
    if bytes.is_empty() || bytes.len() > MAX_EXTENSION_FRAME_BYTES || bytes.last() == Some(&b'\r') {
        return Err(ViewportControlError::Malformed);
    }
    Ok(bytes)
}

fn write_frame(
    writer: &mut impl Write,
    response: &RemoteDesktopExtensionResponse,
) -> Result<(), ViewportControlError> {
    let bytes = serde_json::to_vec(response).map_err(|_| ViewportControlError::Malformed)?;
    if bytes.is_empty() || bytes.len() > MAX_EXTENSION_FRAME_BYTES {
        return Err(ViewportControlError::Malformed);
    }
    writer.write_all(&bytes).map_err(classify_io)?;
    writer.write_all(b"\n").map_err(classify_io)?;
    writer.flush().map_err(classify_io)
}

fn classify_io(error: std::io::Error) -> ViewportControlError {
    match error.kind() {
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut => {
            ViewportControlError::Timeout
        }
        _ => ViewportControlError::Unavailable,
    }
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() as u32 }
}

#[cfg(not(target_os = "linux"))]
fn connected_peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: the descriptor is a connected Unix socket and both outputs are live and sized.
    let status = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if status == 0 {
        Ok(uid as u32)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn connected_peer_uid(stream: &UnixStream) -> std::io::Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the descriptor is a connected Unix socket and the output buffer/length are valid.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    if status == 0 {
        Ok(credentials.uid)
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn validate_socket_metadata(path: &Path) -> Result<std::fs::Metadata, ViewportControlError> {
    let metadata =
        std::fs::symlink_metadata(path).map_err(|_| ViewportControlError::Unavailable)?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o777 != SOCKET_MODE
    {
        return Err(ViewportControlError::UnsafeSocket);
    }
    Ok(metadata)
}

fn configure_stream(stream: &UnixStream) -> Result<(), ViewportControlError> {
    stream
        // BSD/macOS may inherit O_NONBLOCK from the listener onto accepted sockets. Clear it
        // before applying bounded blocking deadlines, otherwise an accept/write race fails as an
        // immediate WouldBlock instead of waiting for the request frame.
        .set_nonblocking(false)
        .and_then(|()| stream.set_read_timeout(Some(IO_TIMEOUT)))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(classify_io)
}

fn handle_stream(
    mut stream: UnixStream,
    owner: &Arc<Mutex<crate::winsize_owner::WinsizeOwner>>,
    state: &mut ViewportControlState,
) -> Result<(), ViewportControlError> {
    configure_stream(&stream)?;
    if connected_peer_uid(&stream).map_err(classify_io)? != effective_uid() {
        return Err(ViewportControlError::UnsafeSocket);
    }
    let request_frame = read_frame(&mut std::io::BufReader::new(
        stream.try_clone().map_err(classify_io)?,
    ))?;
    let request = negotiated_contract()
        .decode_remote_desktop_host_frame(&request_frame)
        .map_err(|_| ViewportControlError::Malformed)?;
    let request_id = request.request_id();
    let now_ms = unix_now_ms();
    let response = {
        let mut owner = owner.lock().unwrap_or_else(|error| error.into_inner());
        let current = owner.remote_owned_viewports(now_ms);
        let result = match request {
            RemoteDesktopHostRequest::SnapshotViewports { request_id } => {
                state.snapshot(request_id, &current, now_ms)
            }
            RemoteDesktopHostRequest::ReclaimViewport {
                request_id,
                session_id,
                lease_id,
                cursor,
                ..
            } => state.reclaim(
                request_id,
                &session_id,
                &lease_id,
                cursor,
                &current,
                &mut owner,
            ),
            _ => Err(ViewportControlError::UnexpectedRequest),
        };
        result.unwrap_or_else(|error| response_error(request_id, error))
    };
    write_frame(&mut stream, &response)
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn random_epoch() -> u64 {
    loop {
        let epoch = rand::rngs::OsRng.next_u64();
        if epoch != 0 {
            return epoch;
        }
    }
}

fn remove_stale_socket(path: &Path) -> Result<(), ViewportControlError> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(ViewportControlError::Unavailable),
        Ok(_) => {}
    }
    validate_socket_metadata(path)?;
    if UnixStream::connect(path).is_ok() {
        return Err(ViewportControlError::Unavailable);
    }
    std::fs::remove_file(path).map_err(|_| ViewportControlError::Unavailable)
}

/// RAII owner for the live peer's fixed private control socket.
pub struct ViewportControlServer {
    stop: Arc<AtomicBool>,
    socket_path: PathBuf,
    socket_identity: (u64, u64),
    thread: Option<JoinHandle<()>>,
}

impl ViewportControlServer {
    pub fn start(
        agent_dir: &Path,
        owner: Arc<Mutex<crate::winsize_owner::WinsizeOwner>>,
    ) -> Result<Self, ViewportControlError> {
        std::fs::create_dir_all(agent_dir).map_err(|_| ViewportControlError::Unavailable)?;
        let socket_path = agent_dir.join(VIEWPORT_CONTROL_SOCKET_NAME);
        remove_stale_socket(&socket_path)?;
        let listener =
            UnixListener::bind(&socket_path).map_err(|_| ViewportControlError::Unavailable)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(SOCKET_MODE))
            .map_err(|_| ViewportControlError::Unavailable)?;
        let metadata = validate_socket_metadata(&socket_path)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| ViewportControlError::Unavailable)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let thread = std::thread::Builder::new()
            .name("hydra-viewport-control".to_string())
            .spawn(move || {
                let mut state = ViewportControlState::new(random_epoch())
                    .expect("a nonzero random epoch is a valid control state");
                while !thread_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = handle_stream(stream, &owner, &mut state);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(ACCEPT_POLL);
                        }
                        Err(_) => break,
                    }
                }
            })
            .map_err(|_| ViewportControlError::Unavailable)?;
        Ok(Self {
            stop,
            socket_path,
            socket_identity: (metadata.dev(), metadata.ino()),
            thread: Some(thread),
        })
    }
}

impl Drop for ViewportControlServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        if let Ok(metadata) = std::fs::symlink_metadata(&self.socket_path) {
            if (metadata.dev(), metadata.ino()) == self.socket_identity {
                let _ = std::fs::remove_file(&self.socket_path);
            }
        }
    }
}

/// Proxy one typed viewport request from the one-shot extension child to the live peer.
pub fn request(
    agent_dir: &Path,
    request: &RemoteDesktopHostRequest,
) -> Result<RemoteDesktopExtensionResponse, ViewportControlError> {
    if !matches!(
        request,
        RemoteDesktopHostRequest::SnapshotViewports { .. }
            | RemoteDesktopHostRequest::ReclaimViewport { .. }
    ) {
        return Err(ViewportControlError::UnexpectedRequest);
    }
    let socket_path = agent_dir.join(VIEWPORT_CONTROL_SOCKET_NAME);
    validate_socket_metadata(&socket_path)?;
    let mut stream = UnixStream::connect(&socket_path).map_err(classify_io)?;
    configure_stream(&stream)?;
    if connected_peer_uid(&stream).map_err(classify_io)? != effective_uid() {
        return Err(ViewportControlError::UnsafeSocket);
    }
    let encoded = serde_json::to_vec(request).map_err(|_| ViewportControlError::Malformed)?;
    if encoded.is_empty() || encoded.len() > MAX_EXTENSION_FRAME_BYTES {
        return Err(ViewportControlError::Malformed);
    }
    stream.write_all(&encoded).map_err(classify_io)?;
    stream.write_all(b"\n").map_err(classify_io)?;
    stream.flush().map_err(classify_io)?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(classify_io)?;
    let response_frame = read_frame(&mut std::io::BufReader::new(stream))?;
    let response = negotiated_contract()
        .decode_remote_desktop_extension_frame(&response_frame)
        .map_err(|_| ViewportControlError::Malformed)?;
    validate_remote_desktop_response(request, &response)
        .map_err(|_| ViewportControlError::Malformed)?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use maestro_extension_api::ViewportReclaimReason;

    fn viewport(
        session_id: &str,
        cols: u16,
        deadline: Option<u64>,
        authority_generation: u64,
    ) -> crate::winsize_owner::RemoteOwnedViewport {
        crate::winsize_owner::RemoteOwnedViewport {
            session_id: session_id.to_string(),
            geometry: ViewportGeometry::new(cols, 24, u32::from(cols) * 8, 384).unwrap(),
            valid_until_ms: deadline,
            authority_generation: crate::winsize_owner::AuthorityGeneration::for_test(
                authority_generation,
            ),
        }
    }

    #[test]
    fn snapshot_cursor_is_global_while_each_lease_keeps_its_own_upsert_cursor() {
        let mut state = ViewportControlState::new(7).unwrap();
        let first = state
            .snapshot(
                RemoteDesktopRequestId::new(1).unwrap(),
                &[viewport("s1", 80, None, 1)],
                1_000,
            )
            .unwrap();
        let RemoteDesktopExtensionResponse::ViewportSnapshot { cursor, .. } = first else {
            panic!("snapshot expected")
        };
        assert_eq!(cursor.sequence(), 2);

        let second = state
            .snapshot(
                RemoteDesktopRequestId::new(2).unwrap(),
                &[viewport("s1", 80, None, 1), viewport("s2", 100, None, 2)],
                1_010,
            )
            .unwrap();
        let RemoteDesktopExtensionResponse::ViewportSnapshot {
            cursor, viewports, ..
        } = second
        else {
            panic!("snapshot expected")
        };
        assert_eq!(cursor.epoch(), 7);
        assert_eq!(cursor.sequence(), 4);
        let cursors = viewports
            .iter()
            .map(|entry| entry.cursor().sequence())
            .collect::<Vec<_>>();
        assert_eq!(cursors, vec![1, 3]);
    }

    #[test]
    fn snapshot_ttl_never_outlives_the_earliest_lease() {
        let mut state = ViewportControlState::new(9).unwrap();
        let response = state
            .snapshot(
                RemoteDesktopRequestId::new(1).unwrap(),
                &[
                    viewport("s1", 80, Some(2_250), 1),
                    viewport("s2", 100, Some(9_000), 2),
                ],
                2_000,
            )
            .unwrap();
        assert!(matches!(
            response,
            RemoteDesktopExtensionResponse::ViewportSnapshot { ttl_ms: 250, .. }
        ));
    }

    #[test]
    fn exact_reclaim_rejects_replay_and_stale_cursor() {
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        {
            let mut owner = owner.lock().unwrap();
            owner.set_serving(1, 0);
            owner.note_remote_viewing_with_geometry("c1", "s1", 80, 24);
        }
        let mut state = ViewportControlState::new(11).unwrap();
        let current = owner.lock().unwrap().remote_owned_viewports(1_000);
        let snapshot = state
            .snapshot(RemoteDesktopRequestId::new(1).unwrap(), &current, 1_000)
            .unwrap();
        let RemoteDesktopExtensionResponse::ViewportSnapshot { viewports, .. } = snapshot else {
            panic!("snapshot expected")
        };
        let lease = viewports.iter().next().unwrap().clone();
        let mut locked = owner.lock().unwrap();
        let current = locked.remote_owned_viewports(1_001);
        assert!(state
            .reclaim(
                RemoteDesktopRequestId::new(2).unwrap(),
                lease.session_id(),
                lease.lease_id(),
                LeaseCursor::new(11, lease.cursor().sequence() + 1).unwrap(),
                &current,
                &mut locked,
            )
            .is_err());
        assert!(state
            .reclaim(
                RemoteDesktopRequestId::new(3).unwrap(),
                lease.session_id(),
                lease.lease_id(),
                lease.cursor(),
                &current,
                &mut locked,
            )
            .is_ok());
        assert!(state
            .reclaim(
                RemoteDesktopRequestId::new(4).unwrap(),
                lease.session_id(),
                lease.lease_id(),
                lease.cursor(),
                &current,
                &mut locked,
            )
            .is_err());
    }

    #[test]
    fn same_geometry_authority_handoff_rotates_exact_lease_and_rejects_prior_owner() {
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        {
            let mut locked = owner.lock().unwrap();
            locked.set_serving(2, 0);
            assert!(locked.note_remote_viewing_with_geometry("conn-a", "s1", 80, 24));
        }
        let mut state = ViewportControlState::new(13).unwrap();
        let current_a = owner.lock().unwrap().remote_owned_viewports(1_000);
        let snapshot_a = state
            .snapshot(RemoteDesktopRequestId::new(1).unwrap(), &current_a, 1_000)
            .unwrap();
        let RemoteDesktopExtensionResponse::ViewportSnapshot {
            viewports: viewports_a,
            ..
        } = snapshot_a
        else {
            panic!("snapshot expected")
        };
        let lease_a = viewports_a.iter().next().unwrap().clone();

        let mut locked = owner.lock().unwrap();
        assert!(locked.note_remote_viewing_with_geometry("conn-b", "s1", 80, 24));
        let current_b = locked.remote_owned_viewports(1_001);
        let stale = state.reclaim(
            RemoteDesktopRequestId::new(2).unwrap(),
            lease_a.session_id(),
            lease_a.lease_id(),
            lease_a.cursor(),
            &current_b,
            &mut locked,
        );
        assert_eq!(stale, Err(ViewportControlError::StaleLease));
        assert_eq!(
            locked.remote_owned_sessions(1_001),
            vec!["s1".to_string()],
            "a delayed exact reclaim from conn-a cannot revoke conn-b",
        );
        drop(locked);

        let snapshot_b = state
            .snapshot(
                RemoteDesktopRequestId::new(3).unwrap(),
                &owner.lock().unwrap().remote_owned_viewports(1_002),
                1_002,
            )
            .unwrap();
        let RemoteDesktopExtensionResponse::ViewportSnapshot {
            viewports: viewports_b,
            ..
        } = snapshot_b
        else {
            panic!("snapshot expected")
        };
        let lease_b = viewports_b.iter().next().unwrap();
        assert_ne!(lease_b.lease_id(), lease_a.lease_id());
        assert!(lease_b.cursor().sequence() > lease_a.cursor().sequence());
    }

    #[test]
    fn private_owner_reexposure_invalidates_a_cached_exact_reclaim() {
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        {
            let mut locked = owner.lock().unwrap();
            locked.set_serving(1, 0);
            locked.note_remote_viewing_with_geometry("conn-a", "s1", 80, 24);
        }
        let mut state = ViewportControlState::new(17).unwrap();
        let current = owner.lock().unwrap().remote_owned_viewports(1_000);
        let snapshot = state
            .snapshot(RemoteDesktopRequestId::new(1).unwrap(), &current, 1_000)
            .unwrap();
        let RemoteDesktopExtensionResponse::ViewportSnapshot { viewports, .. } = snapshot else {
            panic!("snapshot expected")
        };
        let old = viewports.iter().next().unwrap().clone();

        let mut locked = owner.lock().unwrap();
        assert!(locked.set_remote_selected(Some(false)));
        assert!(locked.set_remote_selected(None));
        let reexposed = locked.remote_owned_viewports(1_001);
        assert_eq!(
            state.reclaim(
                RemoteDesktopRequestId::new(2).unwrap(),
                old.session_id(),
                old.lease_id(),
                old.cursor(),
                &reexposed,
                &mut locked,
            ),
            Err(ViewportControlError::StaleLease),
        );
        assert_eq!(locked.remote_owned_sessions(1_001), vec!["s1"]);
    }

    #[test]
    fn fixed_socket_round_trip_and_unsafe_metadata_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        {
            let mut locked = owner.lock().unwrap();
            locked.set_serving(1, 0);
            locked.note_remote_viewing_with_geometry("c1", "s1", 90, 30);
        }
        let server = ViewportControlServer::start(dir.path(), owner).unwrap();
        let request_frame = RemoteDesktopHostRequest::SnapshotViewports {
            request_id: RemoteDesktopRequestId::new(8).unwrap(),
        };
        assert!(matches!(
            request(dir.path(), &request_frame).unwrap(),
            RemoteDesktopExtensionResponse::ViewportSnapshot { .. }
        ));
        std::fs::set_permissions(
            dir.path().join(VIEWPORT_CONTROL_SOCKET_NAME),
            std::fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert_eq!(
            request(dir.path(), &request_frame),
            Err(ViewportControlError::UnsafeSocket)
        );
        drop(server);
    }

    #[test]
    fn reclaim_request_stays_typed_and_contains_no_private_authority_fields() {
        let request = RemoteDesktopHostRequest::ReclaimViewport {
            request_id: RemoteDesktopRequestId::new(1).unwrap(),
            session_id: SessionKey::new("s1").unwrap(),
            lease_id: LeaseId::new("l1").unwrap(),
            cursor: LeaseCursor::new(1, 1).unwrap(),
            reason: ViewportReclaimReason::UserRequested,
        };
        let encoded = serde_json::to_string(&request).unwrap();
        for forbidden in ["cloud", "origin", "account", "token", "key"] {
            assert!(!encoded.contains(forbidden));
        }

        let mut state = ViewportControlState::new(23).unwrap();
        let snapshot = state
            .snapshot(
                RemoteDesktopRequestId::new(2).unwrap(),
                &[viewport("s1", 80, None, 9_999)],
                1_000,
            )
            .unwrap();
        let encoded = serde_json::to_string(&snapshot).unwrap();
        assert!(
            !encoded.contains("authority"),
            "the private authority generation must never enter the extension wire contract",
        );
    }
}
