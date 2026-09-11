use super::*;
use maestro_shell::{store, AttentionState, NewProject, ProjectService, WindowLayoutService};
use std::sync::mpsc;
use std::time::Duration;

#[path = "maintenance_tests.rs"]
mod maintenance_tests;

fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).into()).collect()
}

fn fixture() -> (tempfile::TempDir, AppPaths) {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("profile"));
    let projects = ProjectService::new(&paths);
    for (project, now) in [("p1", 20), ("p2", 10)] {
        projects
            .create(
                project,
                project,
                temp.path().to_string_lossy(),
                NewProject::default(),
                now,
            )
            .unwrap();
    }
    for (window, project) in [
        ("a", Some("p1")),
        ("c", Some("p1")),
        ("b", Some("p2")),
        ("u", None),
    ] {
        let service = WindowLayoutService::new(&paths);
        service.create_empty(window, 1).unwrap();
        service
            .open_tab(
                window,
                &format!("tab-{window}"),
                &format!("session-{window}"),
                window,
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        if let Some(project) = project {
            store::set_window_project(&paths, window, project).unwrap();
        }
    }
    projects
        .reorder_owned_windows("p1", &ids(&["a", "c"]), 21)
        .unwrap();
    projects
        .reorder_owned_windows("p2", &ids(&["b"]), 21)
        .unwrap();
    (temp, paths)
}

fn persisted(paths: &AppPaths) -> PersistedSettings {
    let LoadedSettings::Honored(value) = load_persisted(&settings_file_path(paths.base())) else {
        panic!("expected saved settings")
    };
    value
}

#[test]
fn presentation_is_read_only_and_preserves_absent_ids_hierarchy_and_panes() {
    let (_temp, paths) = fixture();
    reorder_window_presentation(&paths, &ids(&["b", "c", "a", "u"])).unwrap();
    let saved_path = settings_file_path(paths.base());
    let saved = std::fs::read(&saved_path).unwrap();
    let mut snapshot = DashboardSnapshotService::new(&paths)
        .snapshot(None)
        .unwrap();
    // A transient projection omission must not prune the durable vector.
    snapshot.unassigned_windows.clear();
    let original = snapshot.clone();
    let order = apply_window_presentation_order(&paths, &mut snapshot);
    assert_eq!(order, ids(&["b", "c", "a"]));
    assert_eq!(snapshot.projects[0].project_id, "p1");
    assert_eq!(snapshot.projects[1].project_id, "p2");
    assert_eq!(snapshot.projects[0].windows[0].window_id, "c");
    for (before, after) in original.projects.iter().zip(&snapshot.projects) {
        let mut restored = after.clone();
        restored.windows = before.windows.clone();
        assert_eq!(restored, *before, "only window order may change");
        for window in &before.windows {
            assert_eq!(
                after
                    .windows
                    .iter()
                    .find(|item| item.window_id == window.window_id),
                Some(window)
            );
        }
    }
    let expanded: std::collections::HashSet<String> = ids(&["p1", "p2"]).into_iter().collect();
    let dock = crate::build_dock_model(&snapshot, false, &expanded, 268);
    assert_eq!(
        dock.rows
            .iter()
            .filter(|row| row.depth == 1)
            .map(|row| row.label.as_str())
            .collect::<Vec<_>>(),
        vec!["c", "a", "b"]
    );
    ProjectService::new(&paths).touch("p2", 99).unwrap();
    let mut fresh = DashboardSnapshotService::new(&paths)
        .snapshot(None)
        .unwrap();
    assert_eq!(fresh.projects[0].project_id, "p2");
    assert_eq!(
        apply_window_presentation_order(&paths, &mut fresh),
        ids(&["b", "c", "a", "u"])
    );
    assert_eq!(std::fs::read(saved_path).unwrap(), saved);
}

#[test]
fn absent_foreign_malformed_and_invalid_order_leave_legacy_projection_and_bytes_unchanged() {
    let (_temp, paths) = fixture();
    let file = settings_file_path(paths.base());
    let snapshot = DashboardSnapshotService::new(&paths)
        .snapshot(None)
        .unwrap();
    assert!(!file.exists());
    assert_eq!(
        apply_window_presentation_order(&paths, &mut snapshot.clone()),
        ids(&["a", "c", "b", "u"])
    );
    assert!(!file.exists(), "presentation must not seed preferences");
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    for bytes in [
        "not json",
        r#"{"schema_version":999,"global_window_order":["b","a"]}"#,
        r#"{"schema_version":1,"global_window_order":["a","a"]}"#,
        r#"{"schema_version":1,"global_window_order":["../foreign"]}"#,
    ] {
        std::fs::write(&file, bytes).unwrap();
        let mut view = snapshot.clone();
        assert_eq!(
            apply_window_presentation_order(&paths, &mut view),
            ids(&["a", "c", "b", "u"])
        );
        assert_eq!(view, snapshot);
        assert_eq!(std::fs::read_to_string(&file).unwrap(), bytes);
    }
}

#[test]
fn subset_reorder_preserves_owners_panes_schema_and_explicit_order_across_activation() {
    let (_temp, paths) = fixture();
    let before = DashboardSnapshotService::new(&paths)
        .snapshot(None)
        .unwrap();
    let connection = maestro_shell::db::conn_for(paths.base()).unwrap();
    let schema_version: i64 = connection
        .lock()
        .unwrap()
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    set_font_size_px(paths.base(), 24).unwrap();
    let seed = reorder_window_presentation(&paths, &ids(&["a"])).unwrap();
    assert_eq!(seed.window_order, ids(&["a", "c", "b", "u"]));
    assert!(seed.changed);
    let changed = reorder_window_presentation(&paths, &ids(&["c", "b", "a"])).unwrap();
    assert_eq!(changed.window_order, ids(&["c", "b", "a", "u"]));
    assert_eq!(
        serde_json::to_value(before).unwrap(),
        serde_json::to_value(
            DashboardSnapshotService::new(&paths)
                .snapshot(None)
                .unwrap()
        )
        .unwrap()
    );
    assert_eq!(
        schema_version,
        connection
            .lock()
            .unwrap()
            .pragma_query_value(None, "user_version", |row| row.get::<_, i64>(0))
            .unwrap()
    );
    ProjectService::new(&paths).touch("p2", 99).unwrap();
    assert!(
        !reorder_window_presentation(&paths, &ids(&["a"]))
            .unwrap()
            .changed
    );
    assert_eq!(
        persisted(&paths).global_window_order,
        Some(changed.window_order)
    );
    assert_eq!(effective_settings(paths.base()).appearance.font_size_px, 24);
}

#[test]
fn omitted_hidden_stashed_and_absent_slots_survive_and_new_ids_append() {
    let (_temp, paths) = fixture();
    reorder_window_presentation(&paths, &ids(&["a"])).unwrap();
    let project = ProjectService::new(&paths).touch("p2", 30).unwrap();
    ProjectService::new(&paths)
        .set_hidden_if_unchanged(&project, true, 31)
        .unwrap();
    WindowLayoutService::new(&paths)
        .set_tab_stashed("a", "tab-a", true, 32)
        .unwrap();
    {
        let writer = writer::SettingsWriteGuard::acquire(paths.base()).unwrap();
        let mut value = persisted(&paths);
        value
            .global_window_order
            .as_mut()
            .unwrap()
            .insert(2, "unseen".into());
        write_settings_atomic(paths.base(), &value, &writer).unwrap();
    }
    WindowLayoutService::new(&paths)
        .create_empty("new", 32)
        .unwrap();
    let result = reorder_window_presentation(&paths, &ids(&["u", "c"])).unwrap();
    assert_eq!(result.window_order, ids(&["a", "u", "b", "c", "new"]));
    assert_eq!(
        persisted(&paths).global_window_order,
        Some(ids(&["a", "u", "unseen", "b", "c", "new"]))
    );
}

#[test]
fn preference_resets_preserve_layout_and_legacy_files_still_reset_normally() {
    let (_temp, paths) = fixture();
    set_theme(paths.base(), THEME_HIGH_CONTRAST_DARK).unwrap();
    let legacy = persisted(&paths);
    assert!(legacy.global_window_order.is_none());
    assert!(!serde_json::to_value(&legacy)
        .unwrap()
        .as_object()
        .unwrap()
        .contains_key("global_window_order"));
    let order = reorder_window_presentation(&paths, &ids(&["b", "a"]))
        .unwrap()
        .window_order;
    let keyed = reset_appearance_setting(paths.base(), SettingsResetTarget::Theme).unwrap();
    assert_eq!(keyed.layout_preserved, Some(true));
    assert_eq!(persisted(&paths).global_window_order, Some(order.clone()));
    set_font_size_px(paths.base(), 25).unwrap();
    let all = reset_all_settings(paths.base()).unwrap();
    assert!(all.changed);
    assert_eq!(all.layout_preserved, Some(true));
    assert_eq!(persisted(&paths).global_window_order, Some(order));
    assert_eq!(
        effective_settings(paths.base()).appearance.font_size_px,
        DEFAULT_FONT_SIZE_PX
    );
    let layout_only = reset_all_settings(paths.base()).unwrap();
    assert!(!layout_only.changed);
    assert_eq!(layout_only.layout_preserved, Some(true));
    let other = tempfile::tempdir().unwrap();
    let set = set_font_size_px(other.path(), 25).unwrap();
    assert!(serde_json::to_value(set)
        .unwrap()
        .get("layout_preserved")
        .is_none());
    let legacy_reset = reset_all_settings(other.path()).unwrap();
    assert!(legacy_reset.layout_preserved.is_none());
    assert!(serde_json::to_value(legacy_reset)
        .unwrap()
        .get("layout_preserved")
        .is_none());
    assert!(!settings_file_path(other.path()).exists());
}

#[test]
fn invalid_missing_and_conflicting_requests_never_replace_settings() {
    let (_temp, paths) = fixture();
    reorder_window_presentation(&paths, &ids(&["a"])).unwrap();
    let file = settings_file_path(paths.base());
    let before = std::fs::read(&file).unwrap();
    for requested in [
        ids(&[]),
        ids(&["a", "a"]),
        ids(&["../a"]),
        ids(&["missing"]),
    ] {
        assert!(reorder_window_presentation(&paths, &requested).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), before);
    }
    for value in ["broken".to_string(), serde_json::json!({"schema_version": 999, "appearance": {"font_size_px": 16}}).to_string(),
        serde_json::json!({"schema_version": 1, "appearance": {"font_size_px": 16}, "global_window_order": ["a", "a"]}).to_string()] {
        std::fs::write(&file, &value).unwrap();
        assert_eq!(reorder_window_presentation(&paths, &ids(&["a"])).unwrap_err().error_kind, "settings_conflict");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), value);
    }
}

#[test]
fn new_order_writer_reads_sibling_preferences_only_after_shared_lock() {
    let (_temp, paths) = fixture();
    set_font_size_px(paths.base(), 20).unwrap();
    let writer = writer::SettingsWriteGuard::acquire(paths.base()).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let child_paths = paths.clone();
    let child = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        done_tx
            .send(reorder_window_presentation(&child_paths, &ids(&["b", "a"])))
            .unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    assert!(matches!(
        done_rx.recv_timeout(Duration::from_millis(100)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    let mut value = persisted(&paths);
    value.appearance.font_size_px = 27;
    write_settings_atomic(paths.base(), &value, &writer).unwrap();
    drop(writer);
    done_rx
        .recv_timeout(Duration::from_secs(3))
        .unwrap()
        .unwrap();
    child.join().unwrap();
    assert_eq!(effective_settings(paths.base()).appearance.font_size_px, 27);
    assert!(persisted(&paths).global_window_order.is_some());
}
