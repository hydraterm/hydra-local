//! SQLite-backed replay of a real typed OpenCode exit, without any PTY/provider installed.
use super::*;
use maestro_shell::{
    store, LaunchSpec, SessionExitObservation, SessionKind, SessionService, WindowLayoutService,
};

const ID: &str = "qa-real-provider-error";
const GENERATION: &str = "accepted-grid-generation";

fn fixture() -> (tempfile::TempDir, AppPaths) {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("base"));
    let cwd = temp.path().to_string_lossy().into_owned();
    maestro_shell::ProjectService::new(&paths)
        .create(
            "project",
            "Synthetic exit replay",
            &cwd,
            Default::default(),
            1,
        )
        .unwrap();
    store::write_record(
        &paths,
        RecordKind::Workspace,
        "workspace",
        1,
        &maestro_shell::Workspace {
            workspace_id: "workspace".into(),
            project_id: "project".into(),
            root: cwd.clone(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: Default::default(),
        },
    )
    .unwrap();
    store::write_record(
        &paths,
        RecordKind::Session,
        ID,
        1,
        &SessionRecord {
            session_id: ID.into(),
            workspace_id: "workspace".into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "opencode".into(),
                params: vec![],
            },
            cwd_resolved: cwd,
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: Some(GENERATION.into()),
            status: SessionStatus::Live,
        },
    )
    .unwrap();
    let layout = WindowLayoutService::new(&paths);
    layout.create_empty("window", 1).unwrap();
    layout
        .open_tab(
            "window",
            "tab",
            ID,
            "Synthetic exit",
            false,
            AttentionState::default(),
            1,
        )
        .unwrap();
    (temp, paths)
}

fn replay(paths: &AppPaths, code: Option<i32>, generation: Option<&str>, now: u64) {
    if let outcome
    @ (SessionExitObservation::MarkedExited | SessionExitObservation::AlreadyExited) =
        SessionService::new(paths)
            .observe_exit(ID, generation, now)
            .unwrap()
    {
        observe_exit(paths, ID, code, generation, outcome, now);
    }
}

fn projection(paths: &AppPaths) -> AttentionState {
    let mut snapshot = DashboardSnapshotService::new(paths).snapshot(None).unwrap();
    apply_dashboard(paths, &mut snapshot);
    snapshot
        .projects
        .iter()
        .flat_map(|p| &p.windows)
        .chain(&snapshot.unassigned_windows)
        .flat_map(|w| &w.tabs)
        .find(|tab| tab.session_id == ID)
        .unwrap()
        .attention
}

fn record(paths: &AppPaths) -> SessionRecord {
    records(paths).unwrap().remove(ID).unwrap()
}

fn save(paths: &AppPaths, record: &SessionRecord) {
    store::write_record(paths, RecordKind::Session, ID, 1, record).unwrap();
}

fn changes(paths: &AppPaths) -> u64 {
    maestro_shell::db::conn_for(paths.base())
        .unwrap()
        .lock()
        .unwrap()
        .total_changes()
}

#[test]
fn recorded_nonzero_exit_projects_process_error_without_attention_or_task_writes() {
    let (_temp, paths) = fixture();
    let event: serde_json::Value = serde_json::from_str(include_str!(
        "../../maestro-shell/tests/fixtures/opencode/1.18.23/process-error-exit.json"
    ))
    .unwrap();
    assert_eq!(event["ev"], "session_exited");
    assert_eq!(event["id"], ID);
    assert_eq!(event["code"], 1);
    let outcome = SessionService::new(&paths)
        .observe_exit(ID, Some(GENERATION), 10)
        .unwrap();
    let before = changes(&paths);
    observe_exit(
        &paths,
        ID,
        event["code"].as_i64().map(|code| code as i32),
        Some(GENERATION),
        outcome,
        10,
    );
    assert_eq!(
        projection(&paths),
        AttentionState {
            attention: Attention::Error,
            unseen: true,
            since_ms: 10,
            source: AttentionSource::Process,
        }
    );
    let model = crate::rebuild_live_tab_strip_model(&paths, "window", Some("tab")).unwrap();
    assert_eq!(model.tabs[0].attention.attention, "error");
    assert_eq!(record(&paths).status, SessionStatus::Exited);
    assert!(record(&paths).agent_task_id.is_none());
    assert_eq!(
        changes(&paths),
        before,
        "projection cannot persist attention or task state"
    );
}

#[test]
fn zero_unknown_and_unproved_exits_cannot_infer_failure() {
    for (code, generation) in [
        (Some(0), Some(GENERATION)),
        (None, Some(GENERATION)),
        (Some(1), None),
        (Some(1), Some("stale")),
    ] {
        let (_temp, paths) = fixture();
        replay(&paths, code, generation, 10);
        assert_eq!(projection(&paths), AttentionState::default());
    }
    let (_temp, paths) = fixture();
    let mut exited = record(&paths);
    exited.status = SessionStatus::Exited;
    save(&paths, &exited); // Background inventory alone has no process exit code.
    assert_eq!(projection(&paths), AttentionState::default());
    observe_exit(
        &paths,
        ID,
        Some(1),
        Some("stale"),
        SessionExitObservation::AlreadyExited,
        10,
    );
    assert_eq!(projection(&paths), AttentionState::default());
}

#[test]
fn shell_custom_and_invalid_provider_recipes_do_not_become_opencode_errors() {
    for launch in [
        LaunchSpec::KnownSafe {
            launch_spec_id: "shell".into(),
            params: vec!["opencode".into()],
        },
        LaunchSpec::KnownSafe {
            launch_spec_id: "opencode".into(),
            params: vec!["--invented-selector".into()],
        },
        LaunchSpec::BoundProvider {
            launch_spec_id: "opencode".into(),
            params: vec![],
            executable: "relative".into(),
        },
        LaunchSpec::AdHocRedacted {
            argv: vec!["opencode".into()],
            redacted: false,
            restart_requires_user: true,
        },
        LaunchSpec::OptOut,
    ] {
        let (_temp, paths) = fixture();
        let mut session = record(&paths);
        session.launch = launch;
        save(&paths, &session);
        replay(&paths, Some(1), Some(GENERATION), 10);
        assert_eq!(projection(&paths), AttentionState::default());
    }
}

#[test]
fn duplicate_after_user_ack_does_not_rearm_and_replacement_invalidates_error() {
    let (_temp, paths) = fixture();
    replay(&paths, Some(1), Some(GENERATION), 10);
    assert_eq!(projection(&paths).attention, Attention::Error);
    let ack = AttentionState {
        source: AttentionSource::User,
        since_ms: 11,
        ..Default::default()
    };
    WindowLayoutService::new(&paths)
        .update_attention("window", "tab", ack, 11)
        .unwrap();
    replay(&paths, Some(1), Some(GENERATION), 20);
    assert_eq!(projection(&paths), ack);
    let mut replacement = record(&paths);
    replacement.last_known_generation = Some("replacement".into());
    replacement.status = SessionStatus::Live;
    save(&paths, &replacement);
    assert_eq!(projection(&paths), ack);
    replay(&paths, Some(1), Some(GENERATION), 30);
    assert_eq!(projection(&paths), ack);
    replay(&paths, Some(1), Some("replacement"), 40);
    assert_eq!(projection(&paths).attention, Attention::Error);
    assert_eq!(projection(&paths).since_ms, 40);
}

#[test]
fn already_exited_replay_after_gui_restart_preserves_durable_user_ack() {
    let (_temp, paths) = fixture();
    replay(&paths, Some(1), Some(GENERATION), 10);
    let ack = AttentionState {
        source: AttentionSource::User,
        since_ms: 11,
        ..Default::default()
    };
    WindowLayoutService::new(&paths)
        .update_attention("window", "tab", ack, 11)
        .unwrap();
    // Simulate another GUI's empty process cache. The record has no durable original exit time;
    // receiving the retained event again must not reinterpret the new observation time as failure.
    broker(&paths).lock().unwrap().exit_signals.clear();
    replay(&paths, Some(1), Some(GENERATION), 100);
    assert_eq!(projection(&paths), ack);
    assert_eq!(
        crate::rebuild_live_tab_strip_model(&paths, "window", Some("tab"))
            .unwrap()
            .tabs[0]
            .attention
            .attention,
        "none"
    );
}

#[test]
fn retained_nonzero_without_ack_is_visible_but_never_task_failure() {
    let (_temp, paths) = fixture();
    assert_eq!(
        SessionService::new(&paths)
            .observe_exit(ID, Some(GENERATION), 5)
            .unwrap(),
        SessionExitObservation::MarkedExited
    );
    replay(&paths, Some(1), Some(GENERATION), 10);
    assert_eq!(projection(&paths).attention, Attention::Error);
    assert!(record(&paths).agent_task_id.is_none());
    let shared = broker(&paths);
    next_batch(&mut shared.lock().unwrap(), BTreeMap::new());
    assert_eq!(
        projection(&paths).attention,
        Attention::Error,
        "live-permission cohort removal cannot erase typed exit evidence"
    );
    let mut last_published = 0;
    service(
        &paths,
        &paths.base().join("never-connect.sock"),
        &mut last_published,
        || true,
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while shared.lock().unwrap().busy {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(last_published > 0);
    assert_eq!(
        projection(&paths).attention,
        Attention::Error,
        "initial socket binding and idle cadence preserve an exact typed exit"
    );
}

#[test]
fn stable_bound_and_fresh_launchers_are_provider_identity_not_wrapper_basenames() {
    #[cfg(windows)]
    let executable = r"C:\synthetic\stable-wrapper.exe";
    #[cfg(not(windows))]
    let executable = "/synthetic/stable-wrapper";
    for launch in [
        LaunchSpec::BoundProvider {
            launch_spec_id: "opencode".into(),
            params: vec!["--session".into(), "fixture-session".into()],
            executable: executable.into(),
        },
        LaunchSpec::FreshProvider {
            launch_spec_id: "opencode".into(),
            params: vec![],
            executable: executable.into(),
        },
    ] {
        let (_temp, paths) = fixture();
        let mut session = record(&paths);
        session.launch = launch;
        save(&paths, &session);
        replay(&paths, Some(1), Some(GENERATION), 10);
        assert_eq!(projection(&paths).attention, Attention::Error);
    }
}

#[test]
fn explicit_error_user_and_task_states_win_over_process_exit_projection() {
    let (_temp, paths) = fixture();
    replay(&paths, Some(1), Some(GENERATION), 10);
    for original in [
        AttentionState {
            attention: Attention::Error,
            unseen: false,
            since_ms: 2,
            source: AttentionSource::Agent,
        },
        AttentionState {
            attention: Attention::Activity,
            unseen: true,
            since_ms: 2,
            source: AttentionSource::User,
        },
        AttentionState {
            since_ms: 12,
            source: AttentionSource::User,
            ..Default::default()
        },
    ] {
        WindowLayoutService::new(&paths)
            .update_attention("window", "tab", original, 12)
            .unwrap();
        assert_eq!(projection(&paths), original);
    }
    for task in [
        AgentTaskState::Draft,
        AgentTaskState::WaitingOnUser,
        AgentTaskState::Blocked,
        AgentTaskState::Succeeded,
        AgentTaskState::Failed,
        AgentTaskState::Cancelled,
    ] {
        let mut attention = AttentionState::default();
        let mut needs = false;
        project_attention(
            10,
            Attention::Error,
            AttentionSource::Process,
            false,
            &mut attention,
            Some(task),
            &mut needs,
        );
        assert_eq!(attention, AttentionState::default());
        assert!(!needs);
    }
}

#[test]
fn genuine_live_tui_error_text_does_not_infer_exit_or_task_failure() {
    let (_temp, paths) = fixture();
    let rows: Vec<String> = serde_json::from_str(include_str!(
        "../../maestro-shell/tests/fixtures/opencode/1.18.23/error-ui.json"
    ))
    .unwrap();
    let observation = maestro_shell::provider_attention::classify_opencode_grid(
        &rows.iter().map(String::as_str).collect::<Vec<_>>(),
    );
    assert_eq!(observation, Observation::Idle);
    accept(
        &mut broker(&paths).lock().unwrap().signals,
        ID.into(),
        GENERATION.into(),
        ObservedProvider::OpenCode,
        1,
        observation,
        10,
    );
    assert_eq!(projection(&paths), AttentionState::default());
    // Even a direct call cannot grant an error while the durable lifetime is still Live.
    observe_exit(
        &paths,
        ID,
        Some(1),
        Some(GENERATION),
        SessionExitObservation::AlreadyExited,
        11,
    );
    assert_eq!(projection(&paths), AttentionState::default());
    assert_eq!(record(&paths).status, SessionStatus::Live);
}

#[test]
fn linked_task_remains_running_after_typed_process_failure() {
    let (_temp, paths) = fixture();
    let task = maestro_shell::AgentTask {
        agent_task_id: "task".into(),
        project_id: "project".into(),
        goal: "Synthetic task".into(),
        state: AgentTaskState::Running,
        current_session_id: Some(ID.into()),
        session_history: vec![],
        created_at_ms: 1,
        updated_at_ms: 1,
        result_summary: None,
    };
    store::write_record(&paths, RecordKind::AgentTask, "task", 1, &task).unwrap();
    let mut session = record(&paths);
    session.agent_task_id = Some("task".into());
    save(&paths, &session);
    let outcome = SessionService::new(&paths)
        .observe_exit(ID, Some(GENERATION), 10)
        .unwrap();
    let before = changes(&paths);
    observe_exit(&paths, ID, Some(1), Some(GENERATION), outcome, 10);
    assert_eq!(projection(&paths).attention, Attention::Error);
    let report = maestro_shell::agent_task_reconcile::AgentTaskReconciler::new(&paths)
        .reconcile()
        .unwrap();
    assert_eq!(report.tasks[0].state, AgentTaskState::Running);
    let Some(LoadOutcome::Loaded(retained)) =
        store::load_one::<maestro_shell::AgentTask>(&paths, RecordKind::AgentTask, "task").unwrap()
    else {
        panic!("task missing")
    };
    assert_eq!(
        serde_json::to_vec(&retained).unwrap(),
        serde_json::to_vec(&task).unwrap()
    );
    assert_eq!(
        changes(&paths),
        before,
        "no failure/completion transition or attention write"
    );
}
