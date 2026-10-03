//! Real production broker + database + local socket; synthetic wire wraps recorded provider rows.
//! No PTY, provider invocation, Attach, or task mutation is involved.
use super::*;
use maestro_shell::{store, LaunchSpec, SessionKind, SessionService, WindowLayoutService};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};

fn accept_bounded(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < deadline,
                    "observer fixture accept deadline"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("observer fixture socket: {error}"),
        }
    }
}

fn read(reader: &mut BufReader<UnixStream>) -> serde_json::Value {
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn frame(fixture: &str, revision: u64) -> serde_json::Value {
    let rows: Vec<String> = serde_json::from_str(fixture).unwrap();
    let cols = rows.iter().map(|row| row.chars().count()).max().unwrap();
    let cells = rows
        .iter()
        .map(|row| {
            row.chars()
                .chain(std::iter::repeat(' '))
                .take(cols)
                .map(|ch| {
                    serde_json::json!({"text":ch.to_string(),"width":1,
            "fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"}})
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    serde_json::json!({"ev":"grid","id":"session","grid":{
        "version":2,"generation":"generation","revision":revision,"base_revision":revision,
        "rows":rows.len(),"cols":cols,"rows_cells":cells,"cursor_line":0,"cursor_col":0,
        "cursor_visible":true,"cursor_shape":"block","alt_screen":true,"app_cursor":false,
        "bracketed_paste":true,"focus_reporting":false}})
}

fn await_idle(shared: &SharedBroker) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while shared.lock().unwrap().busy {
        assert!(
            Instant::now() < deadline,
            "bounded observer worker did not finish"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn serve_inventory(listener: &UnixListener, live: bool) {
    let mut stream = accept_bounded(listener);
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    assert_eq!(read(&mut reader), serde_json::json!({"op":"daemon_info"}));
    writeln!(stream, "{}", serde_json::json!({"ev":"daemon_info","protocol_version":3,
        "build_version":"synthetic-attention-test","daemon_instance_id":"22222222222242228222222222222222",
        "generation_conditional_mutations":true,"attachment_aware_conditional_kill":true})).unwrap();
    assert_eq!(read(&mut reader), serde_json::json!({"op":"list_sessions"}));
    let sessions = if live {
        serde_json::json!({"ev":"sessions","ids":["session"],
            "sessions":[{"id":"session","generation":"generation"}]})
    } else {
        serde_json::json!({"ev":"sessions","ids":[],"sessions":[]})
    };
    writeln!(stream, "{sessions}").unwrap();
    let mut remainder = String::new();
    assert_eq!(reader.read_line(&mut remainder).unwrap(), 0);
}

#[test]
fn retained_stashed_unlinked_session_is_observed_once_and_recovery_never_writes_records() {
    recorded_prompt_recovery(
        include_str!("../../maestro-shell/tests/fixtures/opencode/1.18.23/permission.json"),
        include_str!("../../maestro-shell/tests/fixtures/opencode/1.18.23/resumed.json"),
    );
}

#[test]
fn recorded_plan_yes_and_no_clear_only_observer_attention_for_unlinked_session() {
    for recovery in [
        include_str!("../../maestro-shell/tests/fixtures/opencode/1.18.23/plan-accepted.json"),
        include_str!("../../maestro-shell/tests/fixtures/opencode/1.18.23/plan-rejected.json"),
    ] {
        recorded_prompt_recovery(
            include_str!("../../maestro-shell/tests/fixtures/opencode/1.18.23/plan-approval.json"),
            recovery,
        );
    }
}

fn recorded_prompt_recovery(waiting: &'static str, recovery: &'static str) {
    recorded_prompt_recovery_for_launch(
        waiting,
        recovery,
        LaunchSpec::KnownSafe {
            launch_spec_id: "opencode".into(),
            params: vec![],
        },
    );
}

pub(super) fn recorded_prompt_recovery_for_launch(
    waiting: &'static str,
    recovery: &'static str,
    launch: LaunchSpec,
) {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("base"));
    maestro_shell::ProjectService::new(&paths)
        .create(
            "project",
            "Synthetic observer",
            temp.path().to_string_lossy().as_ref(),
            maestro_shell::NewProject::default(),
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
            root: temp.path().to_string_lossy().into_owned(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: Default::default(),
        },
    )
    .unwrap();
    let record = SessionRecord {
        session_id: "session".into(),
        workspace_id: "workspace".into(),
        kind: SessionKind::Agent,
        launch,
        cwd_resolved: temp.path().to_string_lossy().into_owned(),
        agent_task_id: None,
        created_at_ms: 1,
        last_attached_at_ms: 1,
        last_known_generation: Some("generation".into()),
        status: SessionStatus::Live,
    };
    store::write_record(&paths, RecordKind::Session, "session", 1, &record).unwrap();
    let service = WindowLayoutService::new(&paths);
    service.create_empty("window", 1).unwrap();
    for (tab, session) in [("provider-tab", "session"), ("other-tab", "unobserved")] {
        service
            .open_tab(
                "window",
                tab,
                session,
                tab,
                false,
                AttentionState::default(),
                1,
            )
            .unwrap();
    }
    service.stash_pane("window", "provider-tab", 2).unwrap();
    let socket = temp.path().join("observe.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = std::thread::spawn(move || {
        serve_inventory(&listener, true); // existing reconcile; never drives the observer
        for (index, fixture) in [waiting, recovery, waiting].into_iter().enumerate() {
            serve_inventory(&listener, true);
            let mut encoded = serde_json::to_vec(&frame(fixture, index as u64 + 1)).unwrap();
            encoded.push(b'\n');
            let mut stream = accept_bounded(&listener);
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert_eq!(
                read(&mut reader),
                serde_json::json!({"op":"snapshot","id":"session"})
            );
            stream.write_all(&encoded).unwrap();
            let mut remainder = String::new();
            assert_eq!(reader.read_line(&mut remainder).unwrap(), 0);
        }
        // The daemon retains the last permission grid, but the process is no longer live. A
        // correct observer must remove attention after this empty inventory WITHOUT a grid read.
        serve_inventory(&listener, false);
        listener.set_nonblocking(true).unwrap();
        assert!(
            listener.accept().is_err(),
            "duplicate listener must not add a grid request"
        );
    });
    let mut client = DaemonClient::connect_with_timeout(&socket, Duration::from_secs(1)).unwrap();
    let report = SessionService::new(&paths).reconcile(&mut client).unwrap();
    drop(client);
    let cohort = observation_cohort(&paths).unwrap();
    assert_eq!(
        cohort,
        BTreeMap::from([(
            "session".into(),
            ProviderLifetime {
                provider: provider_identity(&record).unwrap(),
                generation: "generation".into(),
            }
        )])
    );
    let before = serde_json::to_vec(&records(&paths).unwrap()["session"]).unwrap();
    let changes = || {
        maestro_shell::db::conn_for(paths.base())
            .unwrap()
            .lock()
            .unwrap()
            .query_row("SELECT total_changes()", [], |row| row.get::<_, u64>(0))
            .unwrap()
    };
    let writes_before = changes();
    let shared = broker(&paths);
    schedule(&paths, &socket);
    schedule(&paths, &socket); // second window's same cadence
    await_idle(&shared);
    assert!(shared.lock().unwrap().signals["session"]
        .waiting_since
        .is_some());
    let mut snapshot = DashboardSnapshotService::new(&paths)
        .snapshot(Some(&report))
        .unwrap();
    apply_dashboard(&paths, &mut snapshot);
    let tab = snapshot
        .projects
        .iter()
        .flat_map(|p| &p.windows)
        .chain(&snapshot.unassigned_windows)
        .flat_map(|w| &w.tabs)
        .find(|t| t.session_id == "session")
        .unwrap();
    assert!(tab.stashed);
    assert_eq!(tab.attention.attention, Attention::NeedsInput);
    assert!(tab.agent_task_id.is_none());
    shared.lock().unwrap().last_started = None;
    schedule(&paths, &socket);
    await_idle(&shared);
    assert_eq!(
        shared.lock().unwrap().signals["session"].waiting_since,
        None
    );
    let mut snapshot = DashboardSnapshotService::new(&paths)
        .snapshot(Some(&report))
        .unwrap();
    apply_dashboard(&paths, &mut snapshot);
    let tab = snapshot
        .projects
        .iter()
        .flat_map(|p| &p.windows)
        .chain(&snapshot.unassigned_windows)
        .flat_map(|w| &w.tabs)
        .find(|t| t.session_id == "session")
        .unwrap();
    assert_ne!(tab.attention.attention, Attention::NeedsInput);
    assert_ne!(tab.attention.attention, Attention::Done);

    // Exercise the actual per-iteration service with a continuously nonempty event receiver.
    // There is no timeout/idle branch. Both new wait and empty-inventory clear must publish.
    let (events_tx, events_rx) = std::sync::mpsc::channel();
    for event in 0..8 {
        events_tx.send(event).unwrap();
    }
    let mut last_published = shared.lock().unwrap().projection_revision;
    let mut projected = Vec::new();
    for expected_wait in [true, false] {
        shared.lock().unwrap().last_started = None;
        schedule(&paths, &socket);
        await_idle(&shared);
        for _ in 0..4 {
            super::service(&paths, &socket, &mut last_published, || {
                let mut snapshot = DashboardSnapshotService::new(&paths)
                    .snapshot(None)
                    .unwrap();
                apply_dashboard(&paths, &mut snapshot);
                let tab = snapshot
                    .projects
                    .iter()
                    .flat_map(|p| &p.windows)
                    .chain(&snapshot.unassigned_windows)
                    .flat_map(|w| &w.tabs)
                    .find(|tab| tab.session_id == "session")
                    .unwrap();
                projected.push(tab.attention.attention == Attention::NeedsInput);
                true
            });
            assert!(events_rx.recv_timeout(Duration::ZERO).is_ok());
        }
        assert_eq!(projected.last(), Some(&expected_wait));
    }
    assert_eq!(projected, [true, false], "only semantic changes publish");
    server.join().unwrap();
    assert_eq!(
        serde_json::to_vec(&records(&paths).unwrap()["session"]).unwrap(),
        before
    );
    assert_eq!(
        changes(),
        writes_before,
        "observer/projection cannot persist attention or task transitions"
    );

    // A late cached result for an old lifetime cannot be projected after durable replacement.
    shared.lock().unwrap().signals.insert(
        "session".into(),
        Signal {
            provider: provider_identity(&record).unwrap(),
            generation: "generation".into(),
            revision: 99,
            waiting_since: Some(20),
        },
    );
    let mut replacement = record;
    replacement.last_known_generation = Some("replacement".into());
    store::write_record(&paths, RecordKind::Session, "session", 3, &replacement).unwrap();
    assert!(current_signals(&paths).is_empty());
}

#[test]
fn no_represented_provider_never_connects_or_publishes() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("base"));
    maestro_shell::ProjectService::new(&paths)
        .create(
            "project",
            "No provider",
            temp.path().to_str().unwrap(),
            Default::default(),
            1,
        )
        .unwrap();
    let socket = temp.path().join("unused.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut revision = 0;
    service(&paths, &socket, &mut revision, || {
        panic!("no semantic change")
    });
    await_idle(&broker(&paths));
    assert!(
        listener.accept().is_err(),
        "zero providers means zero daemon requests"
    );
}
