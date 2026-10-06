//! Windows transport only; authority state and typed request dispatch remain in the parent.
use super::*;
use sha2::{Digest as _, Sha256};
use std::os::windows::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Instant;
use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _};

// This is the same source as the retained daemon listener, not a second authentication policy.
#[path = "../../pty-daemon/src/windows_pipe.rs"]
mod transport;

fn endpoint(agent_dir: &Path) -> Result<PathBuf, ViewportControlError> {
    let canonical = agent_dir.canonicalize().map_err(classify_io)?;
    let mut digest = Sha256::new();
    digest.update(b"hydra-viewport-control-v1\0");
    for unit in canonical.as_os_str().encode_wide() {
        digest.update(unit.to_le_bytes());
    }
    let mut name = transport::default_pipe_name().map_err(classify_io)?;
    name.push(format!(".viewport-v1-{:x}", digest.finalize()));
    Ok(PathBuf::from(name))
}

pub(super) fn connect(
    agent_dir: &Path,
) -> Result<maestro_shell::WindowsPipeStream, ViewportControlError> {
    let stream = maestro_shell::WindowsPipeStream::connect_until(
        &endpoint(agent_dir)?,
        Instant::now() + IO_TIMEOUT,
    )
    .map_err(classify_io)?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(classify_io)?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(classify_io)?;
    Ok(stream)
}

async fn handle_pipe(
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    owner: &Arc<Mutex<crate::winsize_owner::WinsizeOwner>>,
    state: &mut ViewportControlState,
) -> Result<(), ViewportControlError> {
    // WindowsPipeStream sends exactly one newline to establish the impersonation context.
    // Consume ONLY that known transport prelude, not an arbitrary blank JSON frame. The caller
    // bounds the ENTIRE exchange, including authentication, under one deadline.
    let (mut pipe, first) = transport::authenticate_client(pipe)
        .await
        .map_err(classify_io)?;
    if first != [b'\n'] {
        return Err(ViewportControlError::Malformed);
    }
    let mut encoded = Vec::new();
    {
        let mut bounded =
            tokio::io::BufReader::new(&mut pipe).take((MAX_EXTENSION_FRAME_BYTES + 2) as u64);
        bounded
            .read_until(b'\n', &mut encoded)
            .await
            .map_err(classify_io)?;
    }
    let frame = read_frame(&mut encoded.as_slice())?;
    let response = handle_request_frame(&frame, owner, state)?;
    let encoded = serde_json::to_vec(&response).map_err(|_| ViewportControlError::Malformed)?;
    if encoded.is_empty() || encoded.len() > MAX_EXTENSION_FRAME_BYTES {
        return Err(ViewportControlError::Malformed);
    }
    pipe.write_all(&encoded).await.map_err(classify_io)?;
    pipe.write_all(b"\n").await.map_err(classify_io)?;
    pipe.flush().await.map_err(classify_io)?;
    // Keep the server handle alive until the one-shot client consumes its reply and closes.
    // Closing a pipe immediately after a buffered write can discard unread reply bytes.
    // There is no second request on this connection; the same overall deadline still applies.
    let mut ignored = [0u8; 1];
    let _ = pipe.read(&mut ignored).await;
    Ok(())
}

pub(super) fn start(
    agent_dir: &Path,
    owner: Arc<Mutex<crate::winsize_owner::WinsizeOwner>>,
) -> Result<ViewportControlServer, ViewportControlError> {
    std::fs::create_dir_all(agent_dir).map_err(classify_io)?;
    let name = endpoint(agent_dir)?.into_os_string();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(classify_io)?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let (ready, result) = mpsc::sync_channel(1);
    let thread = std::thread::Builder::new()
        .name("hydra-viewport-control".into())
        .spawn(move || {
            runtime.block_on(async move {
                let mut listener = match transport::Listener::bind(name) {
                    Ok(listener) => listener,
                    Err(error) => {
                        let _ = ready.send(Err(classify_io(error)));
                        return;
                    }
                };
                if ready.send(Ok(())).is_err() {
                    return;
                }
                let mut state = ViewportControlState::new(random_epoch())
                    .expect("a nonzero random epoch is a valid control state");
                while !thread_stop.load(Ordering::Acquire) {
                    tokio::select! {
                        accepted = listener.accept() => {
                            let Ok(pipe) = accepted else { break };
                            let _ = tokio::time::timeout(IO_TIMEOUT, handle_pipe(pipe, &owner, &mut state)).await;
                        }
                        _ = tokio::time::sleep(ACCEPT_POLL) => {}
                    }
                }
            });
        })
        .map_err(classify_io)?;
    match result.recv_timeout(IO_TIMEOUT) {
        Ok(Ok(())) => Ok(ViewportControlServer {
            stop,
            thread: Some(thread),
        }),
        outcome => {
            stop.store(true, Ordering::Release);
            let _ = thread.join();
            Err(outcome
                .ok()
                .and_then(Result::err)
                .unwrap_or(ViewportControlError::Timeout))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Arc<Mutex<crate::winsize_owner::WinsizeOwner>> {
        let owner = Arc::new(Mutex::new(crate::winsize_owner::WinsizeOwner::new()));
        {
            let mut locked = owner.lock().unwrap();
            locked.set_serving(1, 0);
            locked.note_remote_viewing_with_geometry("c1", "s1", 90, 30);
        }
        owner
    }

    fn snapshot() -> RemoteDesktopHostRequest {
        RemoteDesktopHostRequest::SnapshotViewports {
            request_id: RemoteDesktopRequestId::new(8).unwrap(),
        }
    }

    #[test]
    fn windows_pipe_round_trip_reclaim_and_single_owner_restart() {
        let dir = tempfile::tempdir().unwrap();
        let owner = owner();
        let server = ViewportControlServer::start(dir.path(), Arc::clone(&owner)).unwrap();
        assert!(ViewportControlServer::start(dir.path(), Arc::clone(&owner)).is_err());
        let RemoteDesktopExtensionResponse::ViewportSnapshot { viewports, .. } =
            request(dir.path(), &snapshot()).unwrap()
        else {
            panic!("expected viewport snapshot")
        };
        let lease = viewports.iter().next().unwrap();
        let reclaim = RemoteDesktopHostRequest::ReclaimViewport {
            request_id: RemoteDesktopRequestId::new(9).unwrap(),
            session_id: lease.session_id().clone(),
            lease_id: lease.lease_id().clone(),
            cursor: lease.cursor(),
            reason: maestro_extension_api::ViewportReclaimReason::UserRequested,
        };
        assert!(matches!(
            request(dir.path(), &reclaim).unwrap(),
            RemoteDesktopExtensionResponse::ViewportReclaimed { .. }
        ));
        assert!(matches!(
            request(dir.path(), &reclaim).unwrap(),
            RemoteDesktopExtensionResponse::Error { .. }
        ));
        drop(server);
        assert!(request(dir.path(), &snapshot()).is_err());
        let _replacement = ViewportControlServer::start(dir.path(), owner).unwrap();
        assert!(request(dir.path(), &snapshot()).is_ok());
    }

    #[test]
    fn windows_endpoint_is_local_stable_and_agent_directory_scoped() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let name = endpoint(first.path()).unwrap();
        assert_eq!(name, endpoint(first.path()).unwrap());
        assert_ne!(name, endpoint(second.path()).unwrap());
        assert!(name
            .to_str()
            .unwrap()
            .starts_with(r"\\.\pipe\Hydra.Maestro."));
        assert!(name.as_os_str().encode_wide().count() <= 256);
    }

    #[test]
    fn windows_silent_and_malformed_clients_cannot_wedge_control() {
        let dir = tempfile::tempdir().unwrap();
        let _server = ViewportControlServer::start(dir.path(), owner()).unwrap();
        let silent = connect(dir.path()).unwrap();
        std::thread::sleep(IO_TIMEOUT + Duration::from_millis(100));
        drop(silent);
        assert!(request(dir.path(), &snapshot()).is_ok());
        // connect already sent the one transport newline. Another empty line is malformed,
        // not a second authentication prelude to skip before a later JSON request.
        for bytes in [b"{}\n".as_slice(), b"\r\n".as_slice(), b"\n".as_slice()] {
            let mut stream = connect(dir.path()).unwrap();
            stream.write_all(bytes).unwrap();
            assert!(read_frame(&mut std::io::BufReader::new(stream)).is_err());
            assert!(request(dir.path(), &snapshot()).is_ok());
        }
        let mut oversized = connect(dir.path()).unwrap();
        let _ = oversized.write_all(&vec![b'x'; MAX_EXTENSION_FRAME_BYTES + 2]);
        assert!(read_frame(&mut std::io::BufReader::new(oversized)).is_err());
        assert!(request(dir.path(), &snapshot()).is_ok());
    }

    #[test]
    fn windows_server_drop_is_bounded_with_a_silent_connected_client() {
        let dir = tempfile::tempdir().unwrap();
        let server = ViewportControlServer::start(dir.path(), owner()).unwrap();
        let _silent = connect(dir.path()).unwrap();
        let before = Instant::now();
        drop(server);
        assert!(before.elapsed() < Duration::from_secs(2));
    }
}
