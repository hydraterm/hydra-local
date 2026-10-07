use super::*;

fn pair() -> (DaemonClient, UnixStream) {
    let (stream, peer) = UnixStream::pair().unwrap();
    let client = DaemonClient::from_connected_stream(
        Path::new("owned-interrupted-io-fixture"),
        stream,
        DEFAULT_TIMEOUT,
        None,
    )
    .unwrap();
    (client, peer)
}

fn budget() -> GenerationKillBudget {
    GenerationKillBudget::with_deadline(
        Some(DEFAULT_TIMEOUT),
        Some(DEFAULT_TIMEOUT),
        Instant::now() + Duration::from_secs(1),
    )
}

fn interrupted() -> std::io::Error {
    std::io::Error::from(std::io::ErrorKind::Interrupted)
}

#[test]
fn interrupted_read_retains_partial_frame_and_next_frame() {
    let (mut client, mut peer) = pair();
    client.reader = BufReader::with_capacity(3, client.reader.into_inner());
    peer.write_all(b"first-frame\nnext-frame\n").unwrap();
    let budget = budget();
    let deadline = budget.deadline;
    let mut calls = 0;
    let frame = client
        .read_frame_before_using(&budget, "fixture read", 64, |reader| {
            calls += 1;
            if matches!(calls, 1 | 3 | 4) {
                Err(interrupted())
            } else {
                reader.fill_buf()
            }
        })
        .unwrap();
    assert!(calls > 4);
    assert_eq!(frame.unwrap(), b"first-frame\n");
    assert_eq!(budget.deadline, deadline);
    assert_eq!(
        client.read_frame_before(&budget, "next frame", 64).unwrap(),
        Some(b"next-frame\n".to_vec())
    );
}

#[test]
fn interrupted_write_retains_offset_without_repeating_request_prefix() {
    let (mut client, mut peer) = pair();
    let budget = budget();
    let deadline = budget.deadline;
    let line = b"one-request\n";
    let mut calls = 0;
    let result = client.write_encoded_request_before_using(
        line,
        &budget,
        "fixture write",
        |writer, remaining| {
            calls += 1;
            match calls {
                1 | 3 | 4 => Err(interrupted()),
                2 => writer.write(&remaining[..3]),
                _ => {
                    assert_eq!(remaining, &line[3..]);
                    writer.write(remaining)
                }
            }
        },
    );
    assert!(result.is_ok());
    assert_eq!(calls, 5);
    assert_eq!(budget.deadline, deadline);
    drop(client);
    let mut received = Vec::new();
    peer.read_to_end(&mut received).unwrap();
    assert_eq!(received, line);
}

#[test]
fn interrupted_read_cannot_renew_expired_deadline() {
    let (mut client, _peer) = pair();
    let budget = budget();
    let deadline = budget.deadline;
    let mut calls = 0;
    let error = client
        .read_frame_before_using(&budget, "fixture read", 64, |_| {
            calls += 1;
            if calls == 3 {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            }
            Err(interrupted())
        })
        .unwrap_err();
    assert_eq!(calls, 3, "an expired retry must not attempt another read");
    assert!(matches!(
        error,
        DaemonClientError::Timeout {
            during: "fixture read"
        }
    ));
    assert_eq!(budget.deadline, deadline);
}

#[test]
fn interrupted_partial_write_cannot_renew_deadline_or_reset_attempted_flag() {
    let (mut client, mut peer) = pair();
    let budget = budget();
    let deadline = budget.deadline;
    let mut calls = 0;
    let result = client.write_encoded_request_before_using(
        b"one-request\n",
        &budget,
        "fixture write",
        |writer, remaining| {
            calls += 1;
            if calls == 1 {
                writer.write(&remaining[..3])
            } else {
                assert_eq!(remaining, b"-request\n");
                if calls == 4 {
                    std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
                }
                Err(interrupted())
            }
        },
    );
    let failure = result.expect_err("expired write must fail");
    assert_eq!(calls, 4);
    assert!(failure.write_attempted);
    assert!(matches!(
        failure.source,
        DaemonClientError::Timeout {
            during: "fixture write"
        }
    ));
    assert_eq!(budget.deadline, deadline);
    drop(client);
    let mut received = Vec::new();
    peer.read_to_end(&mut received).unwrap();
    assert_eq!(received, b"one");
}

#[test]
fn interrupted_retry_does_not_swallow_other_io_errors() {
    let (mut client, _peer) = pair();
    let budget = budget();
    let mut reads = 0;
    let error = client
        .read_frame_before_using(&budget, "fixture read", 64, |_| {
            reads += 1;
            Err(std::io::Error::from(std::io::ErrorKind::ConnectionReset))
        })
        .unwrap_err();
    assert_eq!(reads, 1);
    assert!(
        matches!(error, DaemonClientError::Io(e) if e.kind() == std::io::ErrorKind::ConnectionReset)
    );
    let mut writes = 0;
    let result = client.write_encoded_request_before_using(
        b"one-request\n",
        &budget,
        "fixture write",
        |_, _| {
            writes += 1;
            Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
        },
    );
    let failure = result.expect_err("broken pipe must fail");
    assert_eq!(writes, 1);
    assert!(failure.write_attempted);
    assert!(
        matches!(failure.source, DaemonClientError::Io(e) if e.kind() == std::io::ErrorKind::BrokenPipe)
    );
}
