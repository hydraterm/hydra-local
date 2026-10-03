use super::*;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::process::{Child, Command, Stdio};

struct Fixture {
    _dir: tempfile::TempDir,
    path: PathBuf,
    child: Child,
}

impl Fixture {
    fn start(name: &str) -> Self {
        Self::with_mode(name, "incompatible")
    }

    fn with_mode(name: &str, mode: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join(name);
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let path = dir.path().join("retained.sock");
        let child = Command::new(executable)
            .args([
                "--exact",
                "daemon_startup::recovery::tests::owned_retained_fixture",
                "--nocapture",
            ])
            .env("HYDRA_OWNED_RECOVERY_FIXTURE_SOCKET", &path)
            .env("HYDRA_OWNED_RECOVERY_FIXTURE_MODE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut fixture = Self {
            _dir: dir,
            path,
            child,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while socket_identity(&fixture.path).is_err() {
            assert!(
                fixture.child.try_wait().unwrap().is_none(),
                "fixture exited before ready"
            );
            assert!(Instant::now() < deadline, "fixture readiness timeout");
            std::thread::sleep(Duration::from_millis(10));
        }
        fixture
    }
    fn client(&self) -> maestro_shell::DaemonClient {
        maestro_shell::DaemonClient::connect_before(
            &self.path,
            Instant::now() + Duration::from_secs(2),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Only a child created by this exact test; never a discovered process.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn owned_retained_fixture() {
    let Some(path) = std::env::var_os("HYDRA_OWNED_RECOVERY_FIXTURE_SOCKET") else {
        return;
    };
    let path = PathBuf::from(path);
    let mode = std::env::var("HYDRA_OWNED_RECOVERY_FIXTURE_MODE").unwrap_or_default();
    if mode == "ignore-term" {
        // SAFETY: fixture-only process with no user sessions; the owned Child guard kills it.
        unsafe {
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
    }
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    for socket in listener.incoming() {
        let mut socket = socket.unwrap();
        let mode = mode.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(socket.try_clone().unwrap());
            let mut request = String::new();
            while reader.read_line(&mut request).unwrap_or(0) > 0 {
                if mode == "silent" {
                    request.clear();
                    continue;
                }
                let reply = r#"{"ev":"daemon_info","protocol_version":4294967295,"build_version":"owned-recovery-test"}"#;
                let _ = writeln!(socket, "{reply}");
                request.clear();
            }
        });
    }
}

#[test]
fn confirmed_recovery_stops_only_the_verified_owner_and_preserves_saved_bytes() {
    let mut fixture = Fixture::start("pty-daemon");
    let mut other = Fixture::start("pty-daemon");
    let saved = fixture._dir.path().join("saved-project-and-history");
    std::fs::write(&saved, b"saved project file and provider history sentinel").unwrap();
    let original_inode = socket_identity(&fixture.path).unwrap();
    let recovery = RetainedRecovery::capture(&fixture.client(), &fixture.path).unwrap();
    recovery
        .stop_confirmed(Instant::now() + Duration::from_secs(2))
        .unwrap();
    assert!(fixture.child.wait().unwrap().code().is_none());
    assert!(other.child.try_wait().unwrap().is_none());
    assert_eq!(
        socket_identity(&fixture.path).unwrap(),
        original_inode,
        "app must not unlink even its stopped peer socket"
    );
    assert_eq!(
        std::fs::read(saved).unwrap(),
        b"saved project file and provider history sentinel"
    );
}

#[test]
fn cancel_preserves_process_socket_and_never_attempts_spawn() {
    let mut fixture = Fixture::start("pty-daemon");
    let original_inode = socket_identity(&fixture.path).unwrap();
    let mut confirmations = 0;
    let error = crate::daemon_startup::ensure_daemon_with_confirmation(
        &fixture.path,
        &std::env::current_exe().unwrap(),
        None,
        Instant::now() + Duration::from_secs(2),
        &mut |_| {
            confirmations += 1;
            false
        },
    )
    .err()
    .unwrap();
    assert_eq!(error.error_kind, "stale_daemon");
    assert_eq!(confirmations, 1);
    assert!(fixture.child.try_wait().unwrap().is_none());
    assert_eq!(socket_identity(&fixture.path).unwrap(), original_inode);
}

#[test]
fn headless_retained_failure_keeps_exact_nonrecovery_contract() {
    let mut fixture = Fixture::start("pty-daemon");
    let error = crate::daemon_startup::ensure_daemon(
        &fixture.path,
        Path::new("/must-not-be-spawned"),
        None,
    )
    .err()
    .unwrap();
    assert_eq!(error.error_kind, "stale_daemon");
    assert_eq!(error.message, format!("retained daemon protocol 4294967295 (build owned-recovery-test) is newer than supported protocol {}; its live sessions were left untouched", maestro_protocol::DAEMON_PROTOCOL_VERSION));
    assert!(fixture.child.try_wait().unwrap().is_none());
}

fn unavailable_replacement_preserves_retained_owner(kind: &str) {
    let mut fixture = Fixture::with_mode("pty-daemon", "silent");
    let replacement = fixture._dir.path().join("replacement-daemon");
    match kind {
        "missing" => {}
        "non-executable" => {
            std::fs::write(&replacement, b"not executable").unwrap();
            std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        "directory" => std::fs::create_dir(&replacement).unwrap(),
        _ => panic!("unknown test case"),
    }
    let saved = fixture._dir.path().join("saved-project-and-history");
    std::fs::write(&saved, b"saved project and provider history").unwrap();
    let original_inode = socket_identity(&fixture.path).unwrap();
    let mut confirmations = 0;
    let error = crate::daemon_startup::ensure_daemon_with_confirmation(
        &fixture.path,
        &replacement,
        None,
        Instant::now() + Duration::from_millis(150),
        &mut |failure| {
            assert_eq!(failure.error_kind, "daemon_probe_failed");
            confirmations += 1;
            true
        },
    )
    .err()
    .unwrap();
    assert!(
        fixture.child.try_wait().unwrap().is_none(),
        "{kind}: owner was stopped"
    );
    assert_eq!(socket_identity(&fixture.path).unwrap(), original_inode);
    assert_eq!(
        std::fs::read(saved).unwrap(),
        b"saved project and provider history"
    );
    assert_eq!(confirmations, 0, "do not offer a known-unavailable restart");
    assert_eq!(error.error_kind, "daemon_recovery_failed");
    assert!(
        error
            .message
            .contains("retained terminal service was left running"),
        "{error:?}"
    );
    assert!(error.message.contains("Reinstall or restore"), "{error:?}");
}

#[test]
fn missing_replacement_after_bounded_probe_preserves_retained_owner() {
    unavailable_replacement_preserves_retained_owner("missing");
}

#[test]
fn nonexecutable_replacement_preserves_retained_owner() {
    unavailable_replacement_preserves_retained_owner("non-executable");
}

#[test]
fn directory_replacement_preserves_retained_owner() {
    unavailable_replacement_preserves_retained_owner("directory");
}

#[test]
fn replacement_removed_during_confirmation_preserves_retained_owner() {
    let mut fixture = Fixture::start("pty-daemon");
    let replacement = fixture._dir.path().join("replacement-daemon");
    std::fs::copy(std::env::current_exe().unwrap(), &replacement).unwrap();
    let saved = fixture._dir.path().join("saved-project-and-history");
    std::fs::write(&saved, b"saved project and provider history").unwrap();
    let original_inode = socket_identity(&fixture.path).unwrap();
    let mut confirmations = 0;
    let error = crate::daemon_startup::ensure_daemon_with_confirmation(
        &fixture.path,
        &replacement,
        None,
        Instant::now() + Duration::from_secs(2),
        &mut |_| {
            confirmations += 1;
            std::fs::remove_file(&replacement).unwrap();
            true
        },
    )
    .err()
    .unwrap();
    assert!(
        fixture.child.try_wait().unwrap().is_none(),
        "owner was stopped"
    );
    assert_eq!(confirmations, 1);
    assert_eq!(socket_identity(&fixture.path).unwrap(), original_inode);
    assert_eq!(
        std::fs::read(saved).unwrap(),
        b"saved project and provider history"
    );
    assert_eq!(error.error_kind, "daemon_recovery_failed");
    assert!(error
        .message
        .contains("retained terminal service was left running"));
}

#[test]
fn slow_stop_is_bounded_and_does_not_unlink_or_escalate() {
    let mut fixture = Fixture::with_mode("pty-daemon", "ignore-term");
    let recovery = RetainedRecovery::capture(&fixture.client(), &fixture.path).unwrap();
    let deadline = Instant::now() + Duration::from_millis(150);
    let error = recovery.stop_confirmed(deadline).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(Instant::now() < deadline + Duration::from_secs(1));
    assert!(fixture.child.try_wait().unwrap().is_none());
    assert!(fixture.path.exists());
}

#[test]
#[ignore = "requires HYDRA_RECOVERY_TEST_DAEMON pointing to a separately built current pty-daemon"]
fn confirmed_recovery_reaches_a_fresh_current_daemon() {
    let daemon =
        std::env::var_os("HYDRA_RECOVERY_TEST_DAEMON").expect("set the current daemon executable");
    let mut fixture = Fixture::with_mode("pty-daemon", "silent");
    let saved = fixture._dir.path().join("saved-history");
    std::fs::write(&saved, b"retained saved bytes").unwrap();
    let (spawned, protocol, retained) = crate::daemon_startup::ensure_daemon_with_confirmation(
        &fixture.path,
        Path::new(&daemon),
        None,
        Instant::now() + Duration::from_millis(150),
        &mut |_| true,
    )
    .unwrap();
    assert!(spawned.is_some());
    assert_eq!(protocol, crate::ReusedDaemonProtocol::NotReused);
    assert!(retained.is_none());
    assert!(fixture.child.wait().unwrap().code().is_none());
    let mut client = fixture.client();
    assert_eq!(
        client.daemon_info().unwrap().0,
        maestro_protocol::DAEMON_PROTOCOL_VERSION
    );
    assert_eq!(std::fs::read(saved).unwrap(), b"retained saved bytes");
    drop(spawned); // Only the newly spawned test daemon is cleaned up.
}

#[test]
fn unrelated_socket_owner_never_receives_a_confirmation_or_signal() {
    let mut fixture = Fixture::start("not-a-hydra-daemon");
    let error = crate::daemon_startup::ensure_daemon_with_confirmation(
        &fixture.path,
        Path::new("/must-not-be-spawned"),
        None,
        Instant::now() + Duration::from_secs(2),
        &mut |_| panic!("unproven owner cannot offer restart"),
    )
    .err()
    .unwrap();
    assert_eq!(error.error_kind, "stale_daemon");
    assert!(error.message.contains("Safe restart is unavailable"));
    assert!(fixture.child.try_wait().unwrap().is_none());
}

#[test]
fn socket_replacement_during_confirmation_is_preserved_and_refused() {
    let mut fixture = Fixture::start("pty-daemon");
    let original = fixture._dir.path().join("original.sock");
    let mut replacement = None;
    let error = crate::daemon_startup::ensure_daemon_with_confirmation(
        &fixture.path,
        &std::env::current_exe().unwrap(),
        None,
        Instant::now() + Duration::from_secs(2),
        &mut |_| {
            std::fs::rename(&fixture.path, &original).unwrap();
            replacement = Some(UnixListener::bind(&fixture.path).unwrap());
            std::fs::set_permissions(&fixture.path, std::fs::Permissions::from_mode(0o600))
                .unwrap();
            true
        },
    )
    .err()
    .unwrap();
    assert_eq!(error.error_kind, "daemon_recovery_failed");
    assert!(error.message.contains("socket changed"));
    assert!(replacement.is_some());
    assert!(fixture.path.exists());
    assert!(fixture.child.try_wait().unwrap().is_none());
}

#[cfg(target_os = "macos")]
#[test]
fn older_macos_confirmed_fallback_revalidates_and_stops_owned_process() {
    let mut fixture = Fixture::start("pty-daemon");
    let mut recovery = RetainedRecovery::capture(&fixture.client(), &fixture.path).unwrap();
    recovery.process.signal = None;
    recovery
        .stop_confirmed(Instant::now() + Duration::from_secs(2))
        .unwrap();
    assert!(fixture.child.wait().unwrap().code().is_none());
}
