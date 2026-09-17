use super::*;
use maestro_shell::{
    store, AgentTask, AgentTaskState, AppPaths, Attention, AttentionSource, AttentionState,
    LaunchSpec, NewProject, ProjectService, RecordKind, SessionKind, SessionRecord, SessionStatus,
    WindowLayoutService, Workspace, WorkspacePolicy,
};

fn fixture() -> (tempfile::TempDir, AppPaths) {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("base"));
    let cwd = temp.path().to_string_lossy().into_owned();
    ProjectService::new(&paths)
        .create(
            "project",
            "Synthetic attention",
            &cwd,
            NewProject::default(),
            1,
        )
        .unwrap();
    store::write_record(
        &paths,
        RecordKind::Workspace,
        "workspace",
        1,
        &Workspace {
            workspace_id: "workspace".into(),
            project_id: "project".into(),
            root: cwd.clone(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: Default::default(),
        },
    )
    .unwrap();
    store::write_record(
        &paths,
        RecordKind::AgentTask,
        "task",
        2,
        &AgentTask {
            agent_task_id: "task".into(),
            project_id: "project".into(),
            goal: "Synthetic wait".into(),
            state: AgentTaskState::WaitingOnUser,
            current_session_id: Some("session".into()),
            session_history: vec![],
            created_at_ms: 1,
            updated_at_ms: 2,
            result_summary: None,
        },
    )
    .unwrap();
    store::write_record(
        &paths,
        RecordKind::Session,
        "session",
        3,
        &SessionRecord {
            session_id: "session".into(),
            workspace_id: "workspace".into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::OptOut,
            cwd_resolved: cwd,
            agent_task_id: Some("task".into()),
            created_at_ms: 1,
            last_attached_at_ms: 3,
            last_known_generation: Some("generation".into()),
            status: SessionStatus::Live,
        },
    )
    .unwrap();
    let service = WindowLayoutService::new(&paths);
    service.create_empty("window", 4).unwrap();
    service
        .open_tab(
            "window",
            "tab",
            "session",
            "Synthetic wait",
            false,
            AttentionState {
                attention: Attention::Done,
                unseen: true,
                since_ms: 1,
                source: AttentionSource::Process,
            },
            4,
        )
        .unwrap();
    (temp, paths)
}

// Compare serialized owned rows (including all persisted timestamps) and SQLite's write count.
fn records(paths: &AppPaths) -> (Vec<u8>, u64) {
    let db = maestro_shell::db::conn_for(paths.base()).unwrap();
    let conn = db.lock().unwrap();
    let values: Vec<_> = [
        RecordKind::WindowLayout,
        RecordKind::AgentTask,
        RecordKind::Session,
    ]
    .into_iter()
    .map(|kind| maestro_shell::store_sqlite::load_all(&conn, kind).unwrap())
    .collect();
    (serde_json::to_vec(&values).unwrap(), conn.total_changes())
}

#[test]
fn live_refresh_waiting_task_overrides_stale_done_without_writes() {
    let (_temp, paths) = fixture();
    let before = records(&paths);
    let model = rebuild_live_tab_strip_model(&paths, "window", Some("tab")).unwrap();
    let payload = crate::window::renderer_tab_strip(&model);
    assert_eq!(
        records(&paths),
        before,
        "refresh must not alter records or timestamps"
    );
    assert!(payload.tabs[0].needs_attention);
    assert_eq!(payload.tabs[0].attention.unwrap().marker, '?');
    assert_eq!(model.tabs[0].attention.attention, "done", "display only");
}

#[test]
fn joined_waiting_marker_preserves_other_authorities() {
    let (_temp, paths) = fixture();
    let report = maestro_shell::agent_task_reconcile::AgentTaskReconciler::new(&paths)
        .reconcile()
        .unwrap();
    let views = WindowLayoutService::new(&paths)
        .tab_view("window", &report)
        .unwrap();
    let base = window_tab_view_to_json(&views[0]);
    let project = |tab: WindowViewTabJson| {
        let model = build_tab_strip_model_from_window_view("window", &[tab], Some("tab")).unwrap();
        crate::window::renderer_tab_strip(&model).tabs[0]
            .attention
            .map(|a| a.marker)
    };
    for (kind, expected) in [
        ("done", Some('?')),
        ("activity", Some('?')),
        ("needs_input", Some('?')),
        ("error", Some('!')),
        ("none", None),
    ] {
        let mut tab = base.clone();
        tab.attention.attention = kind.into();
        assert_eq!(project(tab), expected, "persisted kind {kind}");
    }
    let exclusions: [fn(&mut WindowViewTabJson); 10] = [
        |t| t.agent_task_id = None,
        |t| t.agent_task_state = None,
        |t| t.agent_task_state = Some("blocked".into()),
        |t| t.agent_task_state = Some("running".into()),
        |t| t.agent_task_state = Some("succeeded".into()),
        |t| t.session_status = Some("exited".into()),
        |t| t.session_status = Some("unknown".into()),
        |t| t.session_status = None,
        |t| t.session_record_missing = true,
        |t| t.needs_attention = false,
    ];
    for exclude in exclusions {
        let mut tab = base.clone();
        exclude(&mut tab);
        assert_eq!(project(tab), Some('='));
    }
    let mut seen = base;
    seen.attention.unseen = false;
    assert_eq!(
        project(seen),
        None,
        "seen notifications retain the legacy fallback"
    );
}
