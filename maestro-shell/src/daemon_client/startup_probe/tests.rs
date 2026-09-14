use super::*;
use std::os::unix::net::UnixListener;

fn socket() -> (tempfile::TempDir, PathBuf, UnixListener) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("probe.sock");
    let listener = UnixListener::bind(&path).unwrap();
    (temp, path, listener)
}

#[test]
fn startup_probe_deadline_bounds_silence_partial_lines_and_unrelated_events() {
    for payload in [b"".as_slice(), b" ".as_slice(), b"\n".as_slice()] {
        let (_temp, path, listener) = socket();
        let deadline = Instant::now() + Duration::from_millis(150);
        let mut client = DaemonClient::connect_before(&path, deadline).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut input = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            input.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), r#"{"op":"daemon_info"}"#);
            if payload.is_empty() {
                let mut rest = Vec::new();
                assert_eq!(input.read_to_end(&mut rest).unwrap(), 0);
            } else {
                let stop = Instant::now() + Duration::from_secs(1);
                while Instant::now() < stop && stream.write_all(payload).is_ok() {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
        });
        assert!(matches!(
            client.daemon_info_before(deadline),
            Err(DaemonClientError::Timeout { .. })
        ));
        assert!(Instant::now() < deadline + Duration::from_secs(1));
        assert!(path.exists(), "probe cannot remove the retained socket");
        worker.join().unwrap();
    }
}

#[test]
fn startup_probe_write_backpressure_obeys_the_same_deadline() {
    let (_temp, path, listener) = socket();
    let mut client =
        DaemonClient::connect_before(&path, Instant::now() + Duration::from_secs(1)).unwrap();
    let (_peer, _) = listener.accept().unwrap();
    client.writer.set_nonblocking(true).unwrap();
    let bytes = [b'x'; 8192];
    loop {
        match client.writer.write(&bytes) {
            Ok(0) => panic!("nonempty owned-socket write made no progress"),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            other => panic!("unexpected owned-socket fill result: {other:?}"),
        }
    }
    client.writer.set_nonblocking(false).unwrap();
    let deadline = Instant::now() + Duration::from_millis(100);
    assert!(matches!(
        client.daemon_info_before(deadline),
        Err(DaemonClientError::Timeout {
            during: "writing daemon_info startup probe"
        })
    ));
    assert!(Instant::now() < deadline + Duration::from_secs(1));
    assert!(path.exists());
}

#[test]
fn startup_probe_expired_connect_emits_no_connection() {
    let (_temp, path, listener) = socket();
    listener.set_nonblocking(true).unwrap();
    assert!(matches!(
        DaemonClient::connect_before(&path, Instant::now()),
        Err(DaemonClientError::Timeout { .. })
    ));
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn startup_probe_preserves_legacy_error_connection_and_attach_idle_timeout() {
    let (_temp, path, listener) = socket();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut input = BufReader::new(stream.try_clone().unwrap());
        for reply in [
            r#"{"ev":"error","message":"unknown operation"}"#,
            r#"{"ev":"daemon_info","protocol_version":2,"build_version":"legacy"}"#,
        ] {
            let mut line = String::new();
            input.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), r#"{"op":"daemon_info"}"#);
            writeln!(stream, "{reply}").unwrap();
        }
        // This fixture represents a retained daemon, not a peer that exits after
        // its identity reply. Keep it alive through client timeout restoration.
        let mut rest = Vec::new();
        input.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut client = DaemonClient::connect_before(&path, deadline).unwrap();
    assert!(matches!(
        client.daemon_info_before(deadline),
        Err(DaemonClientError::DaemonError { .. })
    ));
    assert_eq!(
        client.reader.get_ref().read_timeout().unwrap(),
        Some(DEFAULT_TIMEOUT)
    );
    assert_eq!(
        client.writer.write_timeout().unwrap(),
        Some(DEFAULT_TIMEOUT)
    );
    assert_eq!(
        client.daemon_info_before(deadline).unwrap(),
        (2, "legacy".into())
    );
    drop(client);
    worker.join().unwrap();
}

#[test]
fn startup_readiness_rejects_legacy_identity_without_mutating_it() {
    let (_temp, path, listener) = socket();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut input = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        input.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), r#"{"op":"daemon_info"}"#);
        writeln!(
            stream,
            r#"{{"ev":"daemon_info","protocol_version":2,"build_version":"legacy"}}"#
        )
        .unwrap();
        let mut rest = Vec::new();
        input.read_to_end(&mut rest).unwrap();
        assert!(rest.is_empty());
    });
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut client = DaemonClient::connect_before(&path, deadline).unwrap();
    assert!(matches!(
        client.conditional_start_peer_identity_before(deadline),
        Err(DaemonClientError::MutationProtocolUnsupported {
            observed: Some(2),
            ..
        })
    ));
    drop(client);
    worker.join().unwrap();
}

#[test]
fn startup_readiness_keeps_exact_capabilities_and_no_unrelated_event_count_ceiling() {
    for conditional_attach in [true, false] {
        let (_temp, path, listener) = socket();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut input = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            input.read_line(&mut line).unwrap();
            assert_eq!(line.trim(), r#"{"op":"daemon_info"}"#);
            stream.write_all(&[b'\n'; 512]).unwrap();
            let reply = serde_json::json!({
                "ev": "daemon_info",
                "protocol_version": maestro_protocol::DAEMON_PROTOCOL_VERSION,
                "build_version": "owned-probe-fixture",
                "daemon_instance_id": "22222222222242228222222222222222",
                "output_generation_echo": true,
                "child_environment": true,
                "generation_conditional_mutations": true,
                "attachment_aware_conditional_kill": true,
                "generation_conditional_start": true,
                "start_operation_ledger": true,
                "generation_conditional_attach": conditional_attach,
            });
            writeln!(stream, "{reply}").unwrap();
            let mut rest = Vec::new();
            input.read_to_end(&mut rest).unwrap();
            assert!(rest.is_empty(), "readiness must send no mutation");
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        let mut client = DaemonClient::connect_before(&path, deadline).unwrap();
        let proof = client.conditional_start_peer_identity_before(deadline);
        if conditional_attach {
            assert!(proof.is_ok(), "readiness identity: {proof:?}");
        } else {
            assert!(matches!(
                proof,
                Err(DaemonClientError::MutationProtocolUnsupported {
                    observed: Some(_),
                    ..
                })
            ));
        }
        drop(client);
        worker.join().unwrap();
    }
}
