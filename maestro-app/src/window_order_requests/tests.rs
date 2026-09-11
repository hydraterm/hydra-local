use super::*;

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

fn fixture() -> (tempfile::TempDir, AppPaths) {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("profile"));
    let projects = maestro_shell::ProjectService::new(&paths);
    for project in ["p1", "p2"] {
        projects
            .create(
                project,
                project,
                temp.path().to_string_lossy(),
                maestro_shell::NewProject::default(),
                1,
            )
            .unwrap();
    }
    for (id, owner) in [("a", "p1"), ("c", "p1"), ("b", "p2"), ("hidden", "p2")] {
        let windows = WindowLayoutService::new(&paths);
        windows.create_empty(id, 2).unwrap();
        windows
            .open_tab(
                id,
                &format!("tab-{id}"),
                &format!("session-{id}"),
                id,
                false,
                AttentionState::default(),
                3,
            )
            .unwrap();
        maestro_shell::store::set_window_project(&paths, id, owner).unwrap();
    }
    projects
        .reorder_owned_windows("p1", &ids(&["a", "c"]), 4)
        .unwrap();
    projects
        .reorder_owned_windows("p2", &ids(&["b", "hidden"]), 4)
        .unwrap();
    maestro_app::reorder_window_presentation(&paths, &ids(&["a", "hidden", "b", "c"])).unwrap();
    (temp, paths)
}

fn reply(commands: &mpsc::Receiver<maestro_renderer::RendererCommand>) -> serde_json::Value {
    let maestro_renderer::RendererCommand::EvaluateReactChromeScript { script, .. } =
        commands.recv_timeout(Duration::from_secs(2)).unwrap()
    else {
        panic!("only a correlated reply may be sent")
    };
    let arguments = script
        .strip_prefix("window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_ORDER__?.(")
        .unwrap()
        .strip_suffix(");")
        .unwrap();
    serde_json::from_str(&format!("[{arguments}]")).unwrap()
}

fn finish(requests: &mut WindowOrderRequests, runtime: &mut RendererTabRuntime) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !requests.poll(runtime) {
        assert!(Instant::now() < deadline, "order save did not complete");
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(!requests.poll(runtime), "no duplicate completion");
}

#[test]
fn global_request_preserves_unmentioned_slots_and_all_sql_records() {
    let (_temp, paths) = fixture();
    let before = DashboardSnapshotService::new(&paths)
        .snapshot(None)
        .unwrap();
    let (mut runtime, commands) = RendererTabRuntime::new();
    let mut requests = WindowOrderRequests::default();
    requests.submit(
        &paths,
        &mut runtime,
        Some("cross-project".into()),
        None,
        ids(&["c", "a", "b"]),
    );
    finish(&mut requests, &mut runtime);
    assert_eq!(
        reply(&commands),
        serde_json::json!(["cross-project", {"status": "saved"}])
    );
    let settings: serde_json::Value = serde_json::from_slice(
        &std::fs::read(maestro_app::settings_file_path(paths.base())).unwrap(),
    )
    .unwrap();
    assert_eq!(
        settings["global_window_order"],
        serde_json::json!(["c", "hidden", "a", "b"])
    );
    assert_eq!(
        DashboardSnapshotService::new(&paths)
            .snapshot(None)
            .unwrap(),
        before
    );
    assert!(commands.try_recv().is_err());
}

#[test]
fn busy_rejects_before_sql_and_partial_save_preserves_accepted_project_order() {
    let (_temp, paths) = fixture();
    let (mut runtime, commands) = RendererTabRuntime::new();
    let (release, held) = mpsc::channel();
    let mut requests = WindowOrderRequests {
        pending: Some(Pending {
            request_id: None,
            worker: std::thread::spawn(move || {
                held.recv().unwrap();
                SaveResult::Saved
            }),
        }),
    };
    let projects = maestro_shell::ProjectService::new(&paths);
    let before = projects.load("p1").unwrap().unwrap();
    let file = maestro_app::settings_file_path(paths.base());
    let bytes = std::fs::read(&file).unwrap();
    requests.submit(
        &paths,
        &mut runtime,
        Some("busy".into()),
        Some("p1"),
        ids(&["c", "a"]),
    );
    assert_eq!(reply(&commands)[1]["status"], "failed");
    assert_eq!(projects.load("p1").unwrap().unwrap(), before);
    assert_eq!(std::fs::read(&file).unwrap(), bytes);
    release.send(()).unwrap();
    finish(&mut requests, &mut runtime);
    std::fs::write(&file, b"{malformed").unwrap();
    requests.submit(
        &paths,
        &mut runtime,
        Some("partial".into()),
        Some("p1"),
        ids(&["c", "a"]),
    );
    finish(&mut requests, &mut runtime);
    let result = reply(&commands);
    assert_eq!(result[0], "partial");
    assert_eq!(result[1]["status"], "partial");
    assert!(result[1]["message"]
        .as_str()
        .unwrap()
        .contains("Project order was accepted"));
    assert_eq!(
        projects.load("p1").unwrap().unwrap().window_order,
        ids(&["c", "a"])
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"{malformed");
    // A foreign-owned member must still fail the existing synchronous cohort gate.
    let accepted = projects.load("p1").unwrap().unwrap();
    requests.submit(
        &paths,
        &mut runtime,
        Some("foreign".into()),
        Some("p1"),
        ids(&["c", "b"]),
    );
    assert_eq!(reply(&commands)[1]["status"], "failed");
    assert!(requests.pending.is_none());
    assert_eq!(projects.load("p1").unwrap().unwrap(), accepted);
}

#[test]
fn typed_requests_keep_exact_correlation_at_early_gates_and_reject_unknown_fields() {
    let (mut runtime, commands) = RendererTabRuntime::new();
    for kind in ["updateWindowOrder", "reorderWindowPresentation"] {
        let mut value = serde_json::json!({"type": kind, "request_id": "quoted\"id", "ordered_window_ids": ["a", "b"]});
        if kind == "updateWindowOrder" {
            value["project_id"] = "p1".into();
        }
        let intent = parse_react_chrome_intent(&value.to_string()).unwrap();
        assert!(!react_chrome_intent_requires_window_context(&intent));
        decline_json(&mut runtime, &value.to_string(), "Viewport changing");
        assert_eq!(
            reply(&commands),
            serde_json::json!(["quoted\"id", {"status":"failed", "message":"Viewport changing"}])
        );
        value["ordered_window_ids"] = serde_json::json!([PRODUCT_RECOVERY_WINDOW_ID]);
        assert!(product_recovery_blocks_react_intent(
            &parse_react_chrome_intent(&value.to_string()).unwrap(),
            "a"
        ));
        value["unexpected"] = true.into();
        decline_json(&mut runtime, &value.to_string(), "ignored");
        assert!(commands.try_recv().is_err());
    }
}
