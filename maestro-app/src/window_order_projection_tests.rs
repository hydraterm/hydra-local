use super::*;
use maestro_shell::ProjectService;

#[test]
fn saved_order_reaches_real_dashboard_and_close_fallback_without_exposing_unassigned_ids() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("profile"));
    for (id, now) in [("p1", 20), ("p2", 10), (PRODUCT_RECOVERY_PROJECT_ID, 1)] {
        ProjectService::new(&paths)
            .create(
                id,
                id,
                temp.path().to_string_lossy(),
                maestro_shell::NewProject::default(),
                now,
            )
            .unwrap();
    }
    for (id, owner) in [
        ("a", Some("p1")),
        ("c", Some("p1")),
        ("b", Some("p2")),
        ("native-recovery", Some(PRODUCT_RECOVERY_PROJECT_ID)),
        ("unassigned", None),
    ] {
        let windows = WindowLayoutService::new(&paths);
        windows.create_empty(id, 1).unwrap();
        windows
            .open_tab(
                id,
                &format!("tab-{id}"),
                &format!("session-{id}"),
                id,
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        if let Some(owner) = owner {
            maestro_shell::store::set_window_project(&paths, id, owner).unwrap();
        }
    }
    let requested = ["unassigned", "native-recovery", "b", "c", "a"].map(String::from);
    maestro_app::reorder_window_presentation(&paths, &requested).unwrap();
    let file = maestro_app::settings_file_path(paths.base());
    let saved = std::fs::read(&file).unwrap();
    let before = DashboardSnapshotService::new(&paths)
        .snapshot(None)
        .unwrap();
    let model =
        dashboard_react_model_with_active_and_report(&paths, Some("a"), Some("tab-a"), None);
    assert_eq!(
        model["global_window_order"],
        serde_json::json!(["b", "c", "a"])
    );
    assert_eq!(model["active_window_id"], "a");
    assert_eq!(model["active_tab_id"], "tab-a");
    assert_eq!(model["details"]["p1"]["windows"][0]["window_id"], "c");
    assert_eq!(
        first_visible_window_id_except(&paths, "p1", "a"),
        Some(VisibleWindowTarget {
            project_id: "p1".into(),
            window_id: "c".into()
        })
    );
    assert_eq!(
        first_visible_window_id_except(&paths, "missing", "a"),
        Some(VisibleWindowTarget {
            project_id: "p2".into(),
            window_id: "b".into()
        })
    );
    assert_eq!(
        DashboardSnapshotService::new(&paths)
            .snapshot(None)
            .unwrap(),
        before
    );
    ProjectService::new(&paths).touch("p2", 99).unwrap();
    let model =
        dashboard_react_model_with_active_and_report(&paths, Some("b"), Some("tab-b"), None);
    assert_eq!(
        model["global_window_order"],
        serde_json::json!(["b", "c", "a"])
    );
    assert_eq!(model["active_window_id"], "b");
    assert_eq!(std::fs::read(file).unwrap(), saved);
}
