//! Portable private-authority lifecycle qualification. No service manager or live cloud is used.
use hydra_agent::{
    device_identity as identity, lifecycle_cleanup as cleanup, service::LifecycleLockSet,
};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::TcpListener,
    time::{Duration, Instant},
};

#[test]
fn normal_remove_clears_journal_and_fresh_code_changes_owner_without_rotating_key() {
    let temp = tempfile::tempdir().unwrap();
    let base = fs::canonicalize(temp.path()).unwrap();
    let agent = base.join("hydra-agent");
    hydra_agent::agent_dir::ensure_owned_safe_authority_directory(&agent).unwrap();
    let locks = LifecycleLockSet::acquire([agent.clone()]).unwrap();
    let key = identity::load_or_create_key(&agent).unwrap();
    let public_key = identity::public_key_b64(&key);
    let key_bytes = fs::read(agent.join("device-key")).unwrap();
    identity::save_record(
        &agent,
        &identity::DeviceRecord {
            device_id: "fixture-device-a".into(),
            account_id: "fixture-account-a".into(),
            cloud_base: hydra_agent::release_trust::active()
                .validate()
                .unwrap()
                .cloud_base
                .to_string(),
            passkey: None,
        },
    )
    .unwrap();
    let sentinel = base.join("unrelated-project");
    fs::write(&sentinel, b"must survive remote removal").unwrap();
    let record_path = identity::record_path(&agent);
    let record = cleanup::ExactFileEvidence::capture(
        &agent,
        &record_path,
        cleanup::LifecycleFileKind::CanonicalRecord,
        &locks,
    )
    .unwrap()
    .unwrap();
    let authority = cleanup::AuthorityEvidence::target_from_exact_record(&record, &locks).unwrap();
    // An uninstalled definition binds the journal; this does not qualify a Windows service manager.
    let unit = if cfg!(target_os = "macos") {
        base.join("LaunchAgents/com.hydra.agent.plist")
    } else {
        base.join("systemd/hydra-agent.service")
    };
    let roots = BTreeSet::from([agent.clone()]);
    let proposed = cleanup::CleanupTombstone::new(
        cleanup::CleanupIntent::Remove,
        cleanup::PriorActivation::ProvenClosed,
        authority,
        &agent,
        &roots,
        &roots,
        [],
        [record],
        cleanup::DesiredUnit::from_bytes(&unit, b"synthetic uninstalled definition").unwrap(),
        None,
        &locks,
    )
    .unwrap();
    let journal = cleanup::store(&agent, &proposed, &locks).unwrap();
    let journal =
        cleanup::execute_planned_deletion(&agent, &journal, &record_path, &locks).unwrap();
    assert!(journal.all_deletions_proven());
    let target = journal.revocation_target().unwrap().clone();
    let journal = cleanup::handoff_revocation(&agent, &target, &locks).unwrap();
    #[cfg(windows)]
    {
        // An old completed flag is not permission to erase a replacement after restart.
        let directory = maestro_shell::WindowsPrivateDirectory::open(&agent).unwrap();
        directory
            .publish(
                std::ffi::OsStr::new("device.json"),
                b"replacement must survive",
                false,
            )
            .unwrap();
        assert!(cleanup::clear(&agent, &journal, &locks).is_err());
        assert!(cleanup::load(&agent).unwrap().is_some());
        assert_eq!(fs::read(&record_path).unwrap(), b"replacement must survive");
        let replacement = directory
            .open_file(std::ffi::OsStr::new("device.json"), false)
            .unwrap();
        directory.remove_opened_file(replacement).unwrap();
    }
    cleanup::clear(&agent, &journal, &locks).unwrap();
    assert!(cleanup::load(&agent).unwrap().is_none());
    assert!(!record_path.exists());
    // Simulate the retry worker's already-confirmed provider completion, without live cloud I/O.
    cleanup::complete_revocation(&agent, target.device_id(), locks.lock_for(&agent).unwrap())
        .unwrap();
    assert!(cleanup::load_revocation_outbox(&agent)
        .unwrap()
        .targets()
        .next()
        .is_none());
    assert!(fs::read(agent.join("device-key")).unwrap() == key_bytes);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let cloud = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < deadline,
                        "enrollment fixture was not contacted"
                    );
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("fixture accept failed: {error}"),
            }
        };
        // Accepted sockets inherit nonblocking mode on macOS. The bounded
        // request/response reads below must block until data or their timeout.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let (body_start, length) = loop {
            let mut chunk = [0; 1024];
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0 && request.len() + count <= 16384);
            request.extend_from_slice(&chunk[..count]);
            if let Some(offset) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                let header = std::str::from_utf8(&request[..offset]).unwrap();
                let length: usize = header
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse().unwrap())
                    })
                    .unwrap();
                assert!(offset + 4 + length <= 16384);
                break (offset + 4, length);
            }
        };
        while request.len() < body_start + length {
            let mut chunk = [0; 1024];
            let count = stream.read(&mut chunk).unwrap();
            assert!(count > 0 && request.len() + count <= 16384);
            request.extend_from_slice(&chunk[..count]);
        }
        let body: serde_json::Value =
            serde_json::from_slice(&request[body_start..body_start + length]).unwrap();
        assert_eq!(body["publicKey"], public_key);
        assert!(body.get("expectedAccountId").is_none());
        let response = serde_json::json!({
            "device": {"deviceId":"fixture-device-b", "accountId":"fixture-account-b",
                "label":"test desktop", "publicKey":public_key, "kind":"desktop",
                "createdAtMs":1_786_000_000_000u64, "revoked":false},
            "passkey":{"spki_b64":"MAA=", "alg":"es256", "rp_id":"hydraterms.com",
                "credential_id":"Y3JlZGVudGlhbA"},
            "enrollment_authorization":{"version":"passkey-uv-v1",
                "credential_id":"Y3JlZGVudGlhbA", "generation":1}
        })
        .to_string();
        write!(stream, "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
        stream.flush().unwrap();
    });
    let result = identity::enroll_with_code_with_diagnostics(
        &agent,
        &cloud,
        "A2B3C4D5",
        "test desktop",
        &locks,
        None,
    );
    server.join().unwrap();
    let enrolled = result.unwrap();
    assert_eq!(enrolled.account_id, "fixture-account-b");
    assert_eq!(
        identity::load_record(&agent).unwrap().unwrap().device_id,
        "fixture-device-b"
    );
    assert!(fs::read(agent.join("device-key")).unwrap() == key_bytes);
    assert_eq!(fs::read(&sentinel).unwrap(), b"must survive remote removal");
}
