//! Genuine owned ConPTY/Daemon fixtures; Windows execution is pending, not implied by compilation.

use super::*;
use crate::daemon::Daemon;
use crate::windows_overlapped_io::tests::run_exact_owned_child;
use std::io::Write as _;
use tokio::sync::oneshot;

const CHILD: &str = "windows_session_retirement::tests::child";
const READY: &str = "HYDRA_RETIREMENT_CHILD_READY";
const OBSERVE: Duration = Duration::from_secs(5);

fn gate() -> (Pause, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let (entered, observed) = oneshot::channel();
    let (release, resumed) = oneshot::channel();
    (Some((entered, resumed)), observed, release)
}

async fn entered(observed: oneshot::Receiver<()>) {
    tokio::time::timeout(OBSERVE, observed)
        .await
        .unwrap()
        .unwrap();
}

async fn start(shared: &SharedDaemon, id: &SessionId) -> String {
    let executable = std::env::current_exe().unwrap();
    let cwd = std::env::current_dir().unwrap();
    shared
        .lock()
        .await
        .start_session(
            id.clone(),
            cwd.to_str().unwrap(),
            executable.to_str().unwrap(),
            &["--exact", CHILD, "--ignored", "--nocapture"].map(str::to_owned),
            100,
            30,
        )
        .unwrap();
    tokio::time::timeout(OBSERVE, async {
        loop {
            let daemon = shared.lock().await;
            let session = daemon.session(id).unwrap();
            if String::from_utf8(session.scrollback_snapshot())
                .unwrap()
                .contains(READY)
            {
                return session.generation();
            }
            drop(daemon);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap()
}

async fn completed(completion: Completion) -> Outcome {
    tokio::time::timeout(OBSERVE, wait(completion))
        .await
        .unwrap()
}

fn assert_conditional_refusal(daemon: &mut Daemon, id: &SessionId, generation: &str) {
    use maestro_protocol::{
        ConditionalSessionStart, ConditionalSessionStartOutcome, SessionStartPrecondition,
    };
    let operation_token: maestro_protocol::SessionStartOperationToken =
        uuid::Uuid::new_v4().simple().to_string().parse().unwrap();
    daemon.reserve_start_operation(id.clone(), operation_token.clone());
    let operation = ConditionalSessionStart {
        operation_token,
        precondition: SessionStartPrecondition::ExitedGeneration {
            expected_generation: generation.into(),
        },
    };
    assert!(matches!(
        daemon.start_session_conditionally(
            id.clone(),
            ".",
            "ignored",
            &[],
            None,
            80,
            24,
            &operation,
        ),
        ConditionalSessionStartOutcome::Refused { .. }
    ));
}

#[tokio::test]
async fn mapped_owner_preserves_attach_restart_and_finalization_order() {
    const CASE: &str = "windows_session_retirement::tests::mapped_owner_preserves_attach_restart_and_finalization_order";
    if run_exact_owned_child(CASE) {
        return;
    }
    let shared = Daemon::shared();
    let id = SessionId("retirement-order".into());
    let generation = start(&shared, &id).await;
    let guard = shared
        .lock()
        .await
        .acquire_session_attachment(&id, None, 901)
        .unwrap();
    assert!(kill(&shared, &id, &generation).await.is_err());
    assert_eq!(
        shared.lock().await.session(&id).unwrap().live_generation(),
        Some(generation.clone())
    );
    guard.detach();
    let (before_signal, signal_seen, signal_release) = gate();
    let (before_finish, finish_seen, finish_release) = gate();
    let completion = admit(
        &shared,
        &id,
        &generation,
        false,
        Some(TestControl {
            before_signal,
            before_finish,
            ..TestControl::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();
    entered(signal_seen).await;
    let owner = shared
        .lock()
        .await
        .session(&id)
        .unwrap()
        .retirement
        .clone()
        .unwrap();
    let second = admit(&shared, &id, &generation, false, None)
        .await
        .unwrap()
        .unwrap();
    {
        let mut daemon = shared.lock().await;
        let session = daemon.session(&id).unwrap();
        assert!(Arc::ptr_eq(session.retirement.as_ref().unwrap(), &owner));
        assert_eq!(session.grid_snapshot().generation.to_string(), generation);
        assert!(!session.can_reclaim());
        assert!(daemon.acquire_session_attachment(&id, None, 902).is_err());
        assert!(daemon
            .start_session_with_restart(id.clone(), ".", "ignored", &[], 80, 24, true)
            .is_err());
        assert!(daemon
            .finish_retirement(&id, "wrong-generation", &owner, Ok(()))
            .is_err());
    }
    signal_release.send(()).unwrap();
    entered(finish_seen).await;
    {
        let mut daemon = shared.lock().await;
        assert!(daemon.session(&id).unwrap().exit_state().is_some());
        assert!(!daemon.session(&id).unwrap().can_reclaim());
        daemon.reap_exited_sessions();
        assert!(
            daemon.session(&id).is_ok(),
            "final-latch/finisher gap cannot reclaim A"
        );
        assert!(daemon
            .start_session_with_restart(id.clone(), ".", "ignored", &[], 80, 24, true)
            .is_err());
        assert_conditional_refusal(&mut daemon, &id, &generation);
        let (sender, _) = watch::channel(None);
        let foreign_owner = Arc::new(Retirement { completed: sender });
        assert!(daemon
            .finish_retirement(&id, &generation, &foreign_owner, Ok(()))
            .is_err());
    }
    finish_release.send(()).unwrap();
    completed(completion).await.unwrap();
    completed(second).await.unwrap();
    assert!(shared.lock().await.session(&id).is_err());
    kill(&shared, &id, &generation).await.unwrap();
    let replacement = start(&shared, &id).await;
    assert_ne!(generation, replacement);
    assert!(kill(&shared, &id, &generation).await.is_err());
    assert_eq!(
        shared.lock().await.session(&id).unwrap().generation(),
        replacement
    );
    kill(&shared, &id, &replacement).await.unwrap();
    println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
}

#[tokio::test]
async fn admitted_native_resize_settles_across_kill_without_sentinel_or_replacement_bleed() {
    const CASE: &str = "windows_session_retirement::tests::admitted_native_resize_settles_across_kill_without_sentinel_or_replacement_bleed";
    if run_exact_owned_child(CASE) {
        return;
    }
    let shared = Daemon::shared();
    let id = SessionId("resize-retirement".into());
    let sentinel_id = SessionId("resize-independent-sentinel".into());
    let generation = start(&shared, &id).await;
    let sentinel_generation = start(&shared, &sentinel_id).await;
    let (old_handle, target_lifetime, sentinel_lifetime, sentinel_grid) = {
        let daemon = shared.lock().await;
        let target = daemon.session(&id).unwrap();
        let sentinel = daemon.session(&sentinel_id).unwrap();
        (
            target.pty_handle(),
            target.native_lifetime(),
            sentinel.native_lifetime(),
            sentinel.grid_snapshot(),
        )
    };
    let (resize_seen, resize_release) = target_lifetime.hold_next_resize_for_test();
    let resize_handle = old_handle.clone();
    let resize = tokio::task::spawn_blocking(move || resize_handle.resize(131, 41));
    entered(resize_seen).await;
    assert!(
        !resize.is_finished(),
        "native resize must still be admitted"
    );
    {
        let daemon = shared.lock().await;
        let grid = daemon.session(&id).unwrap().grid_snapshot();
        assert_eq!((grid.cols, grid.rows), (100, 30));
    }

    let (before_finish, finish_seen, finish_release) = gate();
    let completion = admit(
        &shared,
        &id,
        &generation,
        false,
        Some(TestControl {
            before_finish,
            ..TestControl::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::timeout(OBSERVE, async {
        while !target_lifetime.is_retired().unwrap() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("exact Job termination must progress while native resize is admitted");
    assert!(!resize.is_finished());
    assert!(!sentinel_lifetime.is_retired().unwrap());
    assert!(shared
        .lock()
        .await
        .session(&id)
        .unwrap()
        .retirement
        .is_some());

    // Now execute the real ResizePseudoConsole call against the closing, still worker-owned
    // HPCON. Either native success or native refusal must settle; never publish guessed geometry.
    resize_release.send(()).unwrap();
    let resized = tokio::time::timeout(OBSERVE, resize)
        .await
        .expect("native resize did not settle after exact Job termination")
        .unwrap();
    entered(finish_seen).await;
    {
        let mut daemon = shared.lock().await;
        let target = daemon.session(&id).unwrap();
        let grid = target.grid_snapshot();
        assert_eq!(grid.generation.to_string(), generation);
        assert_eq!(
            (grid.cols, grid.rows),
            if resized.is_ok() {
                (131, 41)
            } else {
                (100, 30)
            }
        );
        assert!(
            target.exit_state().is_some(),
            "final output and exit must settle"
        );
        assert_conditional_refusal(&mut daemon, &id, &generation);
        let sentinel = daemon.session(&sentinel_id).unwrap();
        assert_eq!(
            sentinel.live_generation(),
            Some(sentinel_generation.clone())
        );
        let grid = sentinel.grid_snapshot();
        assert_eq!(
            (grid.cols, grid.rows),
            (sentinel_grid.cols, sentinel_grid.rows)
        );
        assert!(!sentinel_lifetime.is_retired().unwrap());
    }
    finish_release.send(()).unwrap();
    completed(completion).await.unwrap();
    assert!(shared.lock().await.session(&id).is_err());

    let replacement = start(&shared, &id).await;
    assert_ne!(replacement, generation);
    let stale_resize = tokio::task::spawn_blocking(move || old_handle.resize(77, 19));
    assert!(tokio::time::timeout(OBSERVE, stale_resize)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    {
        let daemon = shared.lock().await;
        let grid = daemon.session(&id).unwrap().grid_snapshot();
        assert_eq!(grid.generation.to_string(), replacement);
        assert_eq!((grid.cols, grid.rows), (100, 30));
        assert_eq!(
            daemon.session(&sentinel_id).unwrap().live_generation(),
            Some(sentinel_generation.clone())
        );
        assert!(!sentinel_lifetime.is_retired().unwrap());
    }
    tokio::time::timeout(OBSERVE, kill(&shared, &id, &replacement))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(OBSERVE, kill(&shared, &sentinel_id, &sentinel_generation))
        .await
        .unwrap()
        .unwrap();
    assert!(sentinel_lifetime.is_retired().unwrap());
    assert!(shared.lock().await.session_ids().is_empty());
    println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
}

#[tokio::test]
async fn cancelled_waiters_do_not_cancel_exact_retirement() {
    const CASE: &str =
        "windows_session_retirement::tests::cancelled_waiters_do_not_cancel_exact_retirement";
    if run_exact_owned_child(CASE) {
        return;
    }
    let shared = Daemon::shared();
    let id = SessionId("cancel-waiter".into());
    let generation = start(&shared, &id).await;
    let (before_signal, seen, release) = gate();
    let completion = admit(
        &shared,
        &id,
        &generation,
        false,
        Some(TestControl {
            before_signal,
            ..TestControl::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();
    entered(seen).await;
    let waiter = tokio::spawn(wait(completion));
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    assert!(shared
        .lock()
        .await
        .session(&id)
        .unwrap()
        .retirement
        .is_some());
    release.send(()).unwrap();
    tokio::time::timeout(OBSERVE, async {
        loop {
            if shared.lock().await.session(&id).is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
}

#[tokio::test]
async fn failed_termination_keeps_live_mapping_until_explicit_retry() {
    const CASE: &str = "windows_session_retirement::tests::failed_termination_keeps_live_mapping_until_explicit_retry";
    if run_exact_owned_child(CASE) {
        return;
    }
    let shared = Daemon::shared();
    let id = SessionId("failed-retirement".into());
    let generation = start(&shared, &id).await;
    for panic_signal in [false, true] {
        let completion = admit(
            &shared,
            &id,
            &generation,
            false,
            Some(TestControl {
                fail_signal: !panic_signal,
                panic_signal,
                ..TestControl::default()
            }),
        )
        .await
        .unwrap()
        .unwrap();
        let error = completed(completion).await.unwrap_err();
        assert!(error.contains(if panic_signal {
            "native termination worker failed"
        } else {
            "injected native termination failure"
        }));
        assert!(shared
            .lock()
            .await
            .session(&id)
            .unwrap()
            .retirement
            .is_none());
    }
    {
        let daemon = shared.lock().await;
        let session = daemon.session(&id).unwrap();
        assert_eq!(session.live_generation(), Some(generation.clone()));
        assert!(session.retirement.is_none());
        assert_eq!(session.grid_snapshot().generation.to_string(), generation);
    }
    kill(&shared, &id, &generation).await.unwrap();
    assert!(shared.lock().await.session(&id).is_err());
    println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
}

#[tokio::test]
async fn shutdown_budget_retains_unconfirmed_owner_and_closes_start_admission() {
    const CASE: &str = "windows_session_retirement::tests::shutdown_budget_retains_unconfirmed_owner_and_closes_start_admission";
    if run_exact_owned_child(CASE) {
        return;
    }
    let shared = Daemon::shared();
    let id = SessionId("shutdown-retirement".into());
    let generation = start(&shared, &id).await;
    let (before_signal, seen, release) = gate();
    let completion = admit(
        &shared,
        &id,
        &generation,
        false,
        Some(TestControl {
            before_signal,
            ..TestControl::default()
        }),
    )
    .await
    .unwrap()
    .unwrap();
    entered(seen).await;
    let report = shutdown_with_budget(&shared, Duration::ZERO).await;
    assert_eq!(report.total, 1);
    assert_eq!(report.reaped, 0);
    assert_eq!(report.unconfirmed, vec![id.clone()]);
    {
        let mut daemon = shared.lock().await;
        assert_eq!(daemon.session(&id).unwrap().generation(), generation);
        assert!(daemon.acquire_session_attachment(&id, None, 903).is_err());
        assert!(daemon
            .start_session(SessionId("late-start".into()), ".", "ignored", &[], 80, 24)
            .is_err());
    }
    release.send(()).unwrap();
    completed(completion).await.unwrap();
    assert!(shared.lock().await.session(&id).is_err());
    let clean = Daemon::shared();
    start(&clean, &id).await;
    let report = shutdown(&clean).await;
    assert!(report.all_reaped());
    assert_eq!(report.reaped, 1);
    println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
}

#[test]
#[ignore = "owned ConPTY retirement fixture child"]
fn child() {
    std::io::stdout()
        .write_all(format!("\n{READY}\n").as_bytes())
        .unwrap();
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}
