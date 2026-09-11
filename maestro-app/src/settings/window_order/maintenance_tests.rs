use super::super::*;
use super::{fixture, ids, persisted};
use maestro_shell::{store, ProjectService, WindowLayoutService};

#[test]
fn seed_legacy_once_then_append_insertion_order_without_pruning_or_reordering_saved_ids() {
    let (_temp, paths) = fixture();
    let projects = ProjectService::new(&paths);
    projects
        .reorder_owned_windows("p1", &ids(&["c", "a"]), 30)
        .unwrap();
    set_font_size_px(paths.base(), 23).unwrap();
    assert!(reconcile_window_presentation_order(&paths, None).unwrap());
    assert_eq!(
        persisted(&paths).global_window_order,
        Some(ids(&["c", "a", "b", "u"]))
    );
    projects.touch("p2", 50).unwrap();
    let windows = WindowLayoutService::new(&paths);
    windows.rename_window("a", "renamed", 51).unwrap();
    windows.create_empty("z-last", 52).unwrap();
    windows.create_empty("d-after-z", 53).unwrap();
    store::delete_record(&paths, RecordKind::WindowLayout, "u").unwrap();
    assert!(reconcile_window_presentation_order(&paths, None).unwrap());
    let expected = ids(&["c", "a", "b", "u", "z-last", "d-after-z"]);
    assert_eq!(
        persisted(&paths).global_window_order,
        Some(expected.clone())
    );
    assert_eq!(persisted(&paths).appearance.font_size_px, 23);
    // Same-ID recreation has a new rowid, but rowid is not authority to move a saved slot.
    windows.create_empty("u", 54).unwrap();
    let before = DashboardSnapshotService::new(&paths)
        .snapshot(None)
        .unwrap();
    let saved = std::fs::read(settings_file_path(paths.base())).unwrap();
    assert!(!reconcile_window_presentation_order(&paths, None).unwrap());
    assert_eq!(persisted(&paths).global_window_order, Some(expected));
    assert_eq!(
        std::fs::read(settings_file_path(paths.base())).unwrap(),
        saved
    );
    assert_eq!(
        DashboardSnapshotService::new(&paths)
            .snapshot(None)
            .unwrap(),
        before
    );
}

#[test]
fn empty_profile_waits_for_real_rows_and_first_created_row_follows_legacy_cohort() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("empty"));
    assert!(!reconcile_window_presentation_order(&paths, None).unwrap());
    assert!(!settings_file_path(paths.base()).exists());
    let (_temp, paths) = fixture();
    WindowLayoutService::new(&paths)
        .create_empty("new-first-name", 60)
        .unwrap();
    store::set_window_project(&paths, "new-first-name", "p1").unwrap();
    ProjectService::new(&paths)
        .reorder_owned_windows("p1", &ids(&["new-first-name", "a", "c"]), 61)
        .unwrap();
    assert!(reconcile_window_presentation_order(&paths, Some("new-first-name")).unwrap());
    assert_eq!(
        persisted(&paths).global_window_order,
        Some(ids(&["a", "c", "b", "u", "new-first-name"]))
    );
}

#[test]
fn maintenance_rejects_malformed_foreign_or_invalid_settings_without_overwriting() {
    let (_temp, paths) = fixture();
    let file = settings_file_path(paths.base());
    std::fs::create_dir_all(file.parent().unwrap()).unwrap();
    for bytes in [
        "broken json",
        r#"{"schema_version":999,"global_window_order":["a"]}"#,
        r#"{"schema_version":1,"global_window_order":["a","a"]}"#,
        r#"{"schema_version":1,"global_window_order":["../a"]}"#,
    ] {
        std::fs::write(&file, bytes).unwrap();
        let error = reconcile_window_presentation_order(&paths, None).unwrap_err();
        assert_eq!(error.error_kind, "settings_conflict");
        assert_eq!(std::fs::read_to_string(&file).unwrap(), bytes);
        assert_eq!(
            store::window_ids_in_creation_order(&paths).unwrap(),
            ids(&["a", "c", "b", "u"])
        );
    }
}

#[test]
fn maintenance_loads_preferences_only_after_the_existing_writer_lock() {
    let (_temp, paths) = fixture();
    let writer = writer::SettingsWriteGuard::acquire(paths.base()).unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let worker_paths = paths.clone();
    let worker = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        reconcile_window_presentation_order(&worker_paths, None).unwrap()
    });
    ready_rx.recv().unwrap();
    let mut settings = default_persisted();
    settings.appearance.font_size_px = 27;
    write_settings_atomic(paths.base(), &settings, &writer).unwrap();
    drop(writer);
    assert!(worker.join().unwrap());
    assert_eq!(persisted(&paths).appearance.font_size_px, 27);
    assert_eq!(
        persisted(&paths).global_window_order,
        Some(ids(&["a", "c", "b", "u"]))
    );
}
