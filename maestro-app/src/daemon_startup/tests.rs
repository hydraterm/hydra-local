use super::*;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::{fs::MetadataExt, net::UnixListener};

#[test]
fn retained_daemon_probe_deadline_surfaces_failure_without_spawn_or_socket_changes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("retained.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let inode = std::fs::metadata(&path).unwrap().ino();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut input = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        input.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), r#"{"op":"daemon_info"}"#);
        let stop = Instant::now() + Duration::from_secs(1);
        while Instant::now() < stop && stream.write_all(b" ").is_ok() {
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    let deadline = Instant::now() + Duration::from_millis(150);
    let failure = ensure_daemon_before(
        &path,
        Path::new("/not-a-daemon-and-must-not-be-spawned"),
        None,
        deadline,
    )
    .err()
    .expect("trickled reply must time out");
    assert_eq!(failure.error_kind, "daemon_probe_failed");
    assert!(failure.message.contains("timed out"));
    assert!(failure.message.contains("sessions were left untouched"));
    assert!(Instant::now() < deadline + Duration::from_secs(1));
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    assert_eq!(serde_json::to_value(&failure).unwrap()["command"], "launch");
    server.join().unwrap();
}

#[test]
fn retained_legacy_and_v2_daemons_keep_the_exact_attach_only_connection() {
    for (reply, expected) in [
        (
            r#"{"ev":"error","message":"unknown operation"}"#,
            ReusedDaemonProtocol::Legacy,
        ),
        (
            r#"{"ev":"daemon_info","protocol_version":2,"build_version":"legacy"}"#,
            ReusedDaemonProtocol::Version(2),
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("retained.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut input = BufReader::new(stream.try_clone().unwrap());
            for _ in 0..2 {
                let mut line = String::new();
                input.read_line(&mut line).unwrap();
                assert_eq!(line.trim(), r#"{"op":"daemon_info"}"#);
                writeln!(stream, "{reply}").unwrap();
            }
        });
        let (spawned, protocol, retained) = ensure_daemon_before(
            &path,
            Path::new("/not-a-daemon-and-must-not-be-spawned"),
            None,
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        assert!(spawned.is_none());
        assert_eq!(protocol, expected);
        let mut client = retained.expect("exact legacy connection retained for attach");
        match expected {
            ReusedDaemonProtocol::Legacy => assert!(matches!(
                client.daemon_info(),
                Err(DaemonClientError::DaemonError { .. })
            )),
            _ => assert_eq!(client.daemon_info().unwrap(), (2, "legacy".into())),
        }
        server.join().unwrap();
    }
}

#[test]
fn elapsed_startup_deadline_never_treats_an_unknown_socket_as_absent() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("missing.sock");
    let failure = ensure_daemon_before(
        &path,
        Path::new("/not-a-daemon-and-must-not-be-spawned"),
        None,
        Instant::now(),
    )
    .err()
    .expect("expired probe cannot authorize spawn");
    assert_eq!(failure.error_kind, "daemon_probe_failed");
    assert!(!path.exists());
}
