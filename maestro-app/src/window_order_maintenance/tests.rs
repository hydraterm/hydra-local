use super::*;

#[test]
fn full_completion_channel_retains_the_only_changed_result() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("profile"));
    let windows = WindowLayoutService::new(&paths);
    windows.create_empty("first", 1).unwrap();
    maestro_app::reconcile_window_presentation_order(&paths, None).unwrap();
    windows.create_empty("next", 2).unwrap();
    let (wake, requests) = sync_channel(1);
    let (results, result) = sync_channel(1);
    results.send(Ok(false)).unwrap(); // An older unchanged result already occupies the only slot.
    let worker_paths = paths.clone();
    let handle = std::thread::spawn(move || {
        run_worker(
            &worker_paths,
            requests,
            results,
            &std::sync::atomic::AtomicBool::new(false),
        )
    });
    wake.send(()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let saved: serde_json::Value = serde_json::from_slice(
            &std::fs::read(maestro_app::settings_file_path(paths.base())).unwrap(),
        )
        .unwrap();
        if saved["global_window_order"] == serde_json::json!(["first", "next"]) {
            break;
        }
        assert!(Instant::now() < deadline, "metadata was not reconciled");
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(!result.recv().unwrap().unwrap());
    assert!(result
        .recv_timeout(Duration::from_secs(2))
        .unwrap()
        .unwrap());
    drop(wake);
    handle.join().unwrap();
}

#[test]
fn unadmitted_lifecycle_does_not_start_worker_and_metadata_completion_never_launches() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("profile"));
    let mut maintenance = WindowOrderMaintenance::default();
    assert!(maintenance.poll(&paths, false).is_none());
    assert!(maintenance.worker.is_none());
    assert!(!paths.base().exists());
    WindowLayoutService::new(&paths)
        .create_empty("original", 1)
        .unwrap();
    assert!(maintenance.poll(&paths, true).is_none());
    let deadline = Instant::now() + Duration::from_secs(5);
    let worker_id = maintenance.worker.as_ref().unwrap().handle.thread().id();
    // Pending/stop gates defer completion publication and admit no further wake.
    assert!(maintenance.poll(&paths, false).is_none());
    loop {
        if let Some(result) = maintenance.poll(&paths, true) {
            assert!(result.unwrap());
            break;
        }
        assert!(Instant::now() < deadline, "metadata worker did not finish");
        std::thread::sleep(Duration::from_millis(5));
    }
    let worker = maintenance.worker.take().unwrap();
    assert_eq!(
        worker.handle.thread().id(),
        worker_id,
        "one persistent worker"
    );
    drop(worker.wake);
    worker.handle.join().unwrap(); // Closing the wake channel exits an idle worker.
    assert_eq!(
        maestro_shell::store::window_ids_in_creation_order(&paths).unwrap(),
        vec!["original"]
    );
}

#[test]
fn unchanged_windows_skip_settings_lock_even_after_unrelated_sql_writes() {
    use std::os::fd::AsRawFd;
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("profile"));
    let windows = WindowLayoutService::new(&paths);
    windows.create_empty("first", 1).unwrap();
    let mut discovery = Discovery::default();
    assert!(discovery.check(&paths).unwrap());
    assert!(!discovery.check(&paths).unwrap()); // Confirm our own atomic settings save.
    let lock =
        std::fs::File::open(maestro_app::settings_dir(paths.base()).join(".settings-writer.lock"))
            .unwrap();
    // SAFETY: this test owns the open descriptor until drop releases its advisory lock.
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let worker_paths = paths.clone();
    let (send, recv) = sync_channel(1);
    let check = std::thread::spawn(move || {
        assert!(!discovery.check(&worker_paths).unwrap());
        WindowLayoutService::new(&worker_paths)
            .rename_window("first", "renamed", 2)
            .unwrap();
        assert!(!discovery.check(&worker_paths).unwrap());
        send.send(discovery).unwrap();
    });
    let completed = recv.recv_timeout(Duration::from_secs(2));
    drop(lock); // Release even if the test catches an unintended JSON lock wait.
    check.join().unwrap();
    let mut discovery = completed.expect("unchanged windows must not acquire settings lock");
    windows.create_empty("next", 3).unwrap();
    assert!(discovery.check(&paths).unwrap());
    let settings = maestro_app::settings_file_path(paths.base());
    let bytes = std::fs::read(&settings).unwrap();
    std::fs::write(&settings, "broken json").unwrap();
    for _ in 0..2 {
        assert!(discovery.check(&paths).is_err());
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), "broken json");
    }
    std::fs::write(&settings, bytes).unwrap();
    assert!(
        !discovery.check(&paths).unwrap(),
        "repair clears failure without creating anything"
    );
}

#[test]
fn exact_order_save_warning_survives_model_refreshes_and_clears_on_metadata_success() {
    let (mut runtime, receiver) = RendererTabRuntime::new();
    let error = || {
        Err(maestro_app::SettingsFailure::new(
            "io_error",
            "atomic rename failed",
        ))
    };
    assert!(apply_result(&mut runtime, error()));
    assert!(!apply_result(&mut runtime, error()));
    let model = serde_json::json!({"active_window_id": "created", "active_tab_id": "original"});
    for _ in 0..2 {
        runtime.set_react_chrome_model(&model).unwrap();
        let maestro_renderer::RendererCommand::SetReactChromeModel { model_json } =
            receiver.recv().unwrap()
        else {
            panic!("expected model only, never creation or viewport change")
        };
        let sent: serde_json::Value = serde_json::from_str(&model_json).unwrap();
        assert_eq!(sent["active_window_id"], "created");
        assert_eq!(sent["active_tab_id"], "original");
        assert_eq!(
            sent["window_order_warning"],
            "Window order wasn't saved: atomic rename failed"
        );
    }
    assert!(apply_result(&mut runtime, Ok(false)));
    runtime.set_react_chrome_model(&model).unwrap();
    let maestro_renderer::RendererCommand::SetReactChromeModel { model_json } =
        receiver.recv().unwrap()
    else {
        panic!("expected model")
    };
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&model_json).unwrap(),
        model
    );
    assert!(receiver.try_recv().is_err());
}
