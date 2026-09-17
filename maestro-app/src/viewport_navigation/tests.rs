use super::*;
use maestro_shell::{NewProject, ProjectService, SplitAxis};

fn pane_intent(project: &str, window: &str, tab: &str, session: &str) -> ReactChromeIntent {
    ReactChromeIntent::FocusSessionOrPane {
        project_id: project.into(),
        window_id: window.into(),
        tab_id: tab.into(),
        session_id: session.into(),
    }
}

fn pane_destination() -> Destination {
    let mut queue = PendingNavigation::default();
    queue.retain(&pane_intent("p-b", "w-b", "tab-b-2", "session-b-2"), None);
    queue.take_ready(false, true, false).unwrap()
}

fn fixture() -> (tempfile::TempDir, AppPaths) {
    let tmp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(tmp.path().join("base"));
    for suffix in ["a", "b"] {
        let project = format!("p-{suffix}");
        let window = format!("w-{suffix}");
        let workspace = format!("workspace-{suffix}");
        ProjectService::new(&paths)
            .create(&project, "Navigation", "/tmp", NewProject::default(), 1)
            .unwrap();
        write_record(
            &paths,
            RecordKind::Workspace,
            &workspace,
            1,
            &Workspace {
                workspace_id: workspace.clone(),
                project_id: project.clone(),
                root: "/tmp".into(),
                policy: maestro_shell::WorkspacePolicy::ScratchCwd,
                consent: WorkspaceConsent::default(),
            },
        )
        .unwrap();
        let windows = WindowLayoutService::new(&paths);
        windows.create_empty(&window, 1).unwrap();
        for index in 1..=2 {
            let session = format!("session-{suffix}-{index}");
            write_record(
                &paths,
                RecordKind::Session,
                &session,
                1,
                &SessionRecord {
                    session_id: session.clone(),
                    workspace_id: workspace.clone(),
                    kind: SessionKind::Shell,
                    launch: LaunchSpec::OptOut,
                    cwd_resolved: "/tmp".into(),
                    agent_task_id: None,
                    created_at_ms: 1,
                    last_attached_at_ms: 1,
                    last_known_generation: Some(format!("generation-{suffix}-{index}")),
                    status: SessionStatus::Live,
                },
            )
            .unwrap();
            let tab = format!("tab-{suffix}-{index}");
            if index == 1 {
                windows
                    .open_tab(
                        &window,
                        &tab,
                        &session,
                        "First",
                        false,
                        Default::default(),
                        1,
                    )
                    .unwrap();
            } else {
                windows
                    .split_tab(
                        &window,
                        &format!("tab-{suffix}-1"),
                        &tab,
                        &session,
                        "Second",
                        SplitAxis::Right,
                        1,
                    )
                    .unwrap();
            }
        }
        windows
            .ensure_project_assignment(&window, &project, 1)
            .unwrap();
    }
    (tmp, paths)
}

fn changes(paths: &AppPaths) -> u64 {
    maestro_shell::db::conn_for(paths.base())
        .unwrap()
        .lock()
        .unwrap()
        .total_changes()
}

#[test]
fn rapid_a_b_c_retains_only_latest_typed_navigation_until_settlement() {
    let mut queue = PendingNavigation::default();
    queue.retain(
        &ReactChromeIntent::FocusWindow {
            project_id: "p-a".into(),
            window_id: "w-a".into(),
        },
        None,
    );
    let a = queue.take_ready(false, true, false).unwrap();
    assert_eq!(a.window_id, "w-a");
    for (window, tab, session) in [("w-b", "b-2", "s-b"), ("w-c", "c-2", "s-c")] {
        let json = serde_json::json!({
            "type": "focusSessionOrPane", "project_id": "p-c", "window_id": window,
            "tab_id": tab, "session_id": session,
        });
        queue.retain_pending_json(&json.to_string(), None, true, "w-a", false);
        assert!(queue.take_ready(true, false, false).is_none());
    }
    queue.retain_pending_json(r#"{"type":"focusTerminal"}"#, None, true, "w-a", false);
    queue.retain_pending_json(
        r#"{"type":"focusWindow","project_id":"p"}"#,
        None,
        true,
        "w-a",
        false,
    );
    let c = queue.take_ready(false, true, false).unwrap();
    assert_eq!(c.window_id, "w-c");
    assert_eq!(c.pane, Some(("c-2".into(), "s-c".into())));
    assert!(queue.take_ready(false, true, false).is_none());
}

#[test]
fn shutdown_unbound_and_neutral_settlements_never_release_queued_navigation() {
    let json = r#"{"type":"focusWindow","project_id":"p-b","window_id":"w-b"}"#;
    let mut queue = PendingNavigation::default();
    queue.retain_pending_json(json, None, false, "w-a", false);
    assert!(queue.take_ready(false, true, false).is_none());
    queue.retain_pending_json(json, None, true, "w-a", false);
    assert!(queue.take_ready(true, false, true).is_none());
    assert!(queue.take_ready(false, true, false).is_none());
    queue.retain_pending_json(json, None, true, "w-a", false);
    assert!(queue.take_ready(false, false, false).is_none());
    assert!(queue.take_ready(false, true, false).is_none());
}

#[test]
fn persistent_navigation_keeps_latest_destination_and_ticket_together() {
    let (tx, rx) = mpsc::channel();
    let stop = AtomicBool::new(false);
    let mut queue = PendingNavigation::default();
    queue.retain(
        &pane_intent("p-b", "w-b", "tab-b-2", "session-b-2"),
        Some(4),
    );
    assert_eq!(queue.0.as_ref().unwrap().dialog_focus_ticket, Some(4));
    for ticket in [Some(9), None] {
        queue.retain(
            &pane_intent("p-b", "w-b", "tab-b-2", "session-b-2"),
            Some(4),
        );
        tx.send(maestro_renderer::RendererEvent::ReactChromeIntent {
            json: r#"{"type":"focusWindow","project_id":"p-a","window_id":"w-a"}"#.into(),
            dialog_focus_ticket: ticket,
        })
        .unwrap();
        let Frontier::Ready(destination) =
            queue.drain_frontier(&rx, &stop, false, true, true, "w-b")
        else {
            panic!("latest navigation should leave the real event frontier");
        };
        assert_eq!(destination.window_id, "w-a");
        assert_eq!(
            destination.dialog_focus_ticket, ticket,
            "None must not inherit an older ticket"
        );
    }
    let json = r#"{"type":"focusSessionOrPane","project_id":"p-b","window_id":"w-b","tab_id":"tab-b-2","session_id":"session-b-2"}"#;
    assert!(queue.retain_pending_json(json, Some(11), true, "w-a", false));
    assert!(queue.take_ready(true, false, false).is_none());
    let destination = queue.take_ready(false, true, false).unwrap();
    assert_eq!(destination.dialog_focus_ticket, Some(11));
    let (_tmp, paths) = fixture();
    let (layout, tab) = destination.prepare(&paths, 42).unwrap();
    assert_eq!(
        destination
            .bind_primary(&layout, &tab)
            .unwrap()
            .dialog_focus_ticket,
        Some(11)
    );
}

#[test]
fn persistent_navigation_prepared_request_carries_only_explicit_focus() {
    let (_tmp, paths) = fixture();
    let projection = pane_destination().projection(&paths, "tab-b-2").unwrap();
    for ticket in [None, Some(17)] {
        let (mut runtime, commands) = RendererTabRuntime::new();
        let (events, _received) = mpsc::channel();
        runtime.bind_renderer_events(events);
        assert!(request_prepared_renderer_viewport_with_focus(
            &mut runtime,
            projection.clone(),
            None,
            ticket,
        )
        .unwrap()
        .is_none());
        let maestro_renderer::RendererCommand::AttachExactViewport { request } =
            commands.try_recv().unwrap()
        else {
            panic!("navigation must request exact publication, not blind terminal focus");
        };
        assert_eq!(request.dialog_focus_ticket(), ticket);
        let Some(maestro_app::PendingRendererViewport::Ordinary { target, .. }) =
            runtime.pending_viewport()
        else {
            panic!("exact navigation must retain its pending projection");
        };
        assert_eq!(target.target(), projection.target());
        assert!(
            runtime.active_viewport().is_none(),
            "delivery is not publication"
        );
        assert!(
            commands.try_recv().is_err(),
            "persistent navigation never hides an overlay"
        );
    }
    let (mut runtime, commands) = RendererTabRuntime::new();
    let (events, _received) = mpsc::channel();
    runtime.bind_renderer_events(events);
    drop(commands);
    assert!(request_prepared_renderer_viewport_with_focus(
        &mut runtime,
        projection,
        None,
        Some(17),
    )
    .is_err());
    assert!(
        !runtime.handoff_is_pending(),
        "failed send grants no pending authority"
    );
}

#[test]
fn cross_project_nonfirst_pane_preserves_exact_identity_siblings_and_recency() {
    let (_tmp, paths) = fixture();
    let windows = WindowLayoutService::new(&paths);
    let a_before = windows.load_snapshot("w-a").unwrap().unwrap();
    let b_before = windows.load_snapshot("w-b").unwrap().unwrap();
    let destination = pane_destination();
    let (layout, tab) = destination.prepare(&paths, 42).unwrap();
    assert_eq!(layout, b_before.layout);
    assert_eq!(tab, "tab-b-2");
    let projection = destination.projection(&paths, &tab).unwrap();
    assert_eq!(projection.target().window_id, "w-b");
    assert_eq!(projection.target().tab_id, "tab-b-2");
    assert_eq!(projection.target().session_id, "session-b-2");
    assert_eq!(projection.selection().len(), 2);
    assert_eq!(windows.load("w-a").unwrap().unwrap(), a_before.layout);
    assert_eq!(windows.load("w-b").unwrap().unwrap(), b_before.layout);
    assert_eq!(
        ProjectService::new(&paths)
            .load("p-a")
            .unwrap()
            .unwrap()
            .last_active_at_ms,
        1
    );
    assert_eq!(
        ProjectService::new(&paths)
            .load("p-b")
            .unwrap()
            .unwrap()
            .last_active_at_ms,
        42
    );
}

#[test]
fn pane_stashed_while_pending_is_declined_without_fallback_or_writes() {
    let (_tmp, paths) = fixture();
    let mut queue = PendingNavigation::default();
    queue.retain(&pane_intent("p-b", "w-b", "tab-b-2", "session-b-2"), None);
    assert!(queue.take_ready(true, false, false).is_none());
    WindowLayoutService::new(&paths)
        .set_tab_stashed("w-b", "tab-b-2", true, 2)
        .unwrap();
    let before = changes(&paths);
    let (mut runtime, commands) = RendererTabRuntime::new();
    let error = queue
        .take_ready(false, true, false)
        .unwrap()
        .focus(
            &paths,
            Path::new("/nonexistent-navigation-test-socket"),
            None,
            RecordedPaneOpenPolicy::Ordinary,
            &mut runtime,
        )
        .unwrap_err();
    assert!(error.contains("absent, stashed"), "{error}");
    assert_eq!(changes(&paths), before);
    assert!(commands.try_recv().is_err());
}

#[test]
fn mismatched_project_session_or_missing_pane_is_declined_before_any_write() {
    let (_tmp, paths) = fixture();
    let correct = pane_destination();
    for destination in [
        Destination {
            project_id: "p-a".into(),
            ..correct.clone()
        },
        Destination {
            pane: Some(("tab-b-2".into(), "session-b-1".into())),
            ..correct.clone()
        },
        Destination {
            pane: Some(("missing-pane".into(), "session-b-2".into())),
            ..correct.clone()
        },
        Destination {
            window_id: "missing-window".into(),
            ..correct.clone()
        },
    ] {
        let before = changes(&paths);
        assert!(destination.prepare(&paths, 77).is_err());
        assert_eq!(changes(&paths), before);
    }
    let mut wrong_snapshot = WindowLayoutService::new(&paths)
        .load_snapshot("w-b")
        .unwrap()
        .unwrap();
    wrong_snapshot.layout.window_id = "w-a".into();
    assert!(correct.validate(&paths, &wrong_snapshot).is_err());
}

#[test]
fn window_and_pane_focus_reject_primary_session_rebinding_during_preflight() {
    for explicit_pane in [false, true] {
        let (_tmp, paths) = fixture();
        let mut destination = pane_destination();
        if !explicit_pane {
            destination.pane = None;
        }
        let (layout, tab_id) = destination.prepare(&paths, 42).unwrap();
        let bound = destination.bind_primary(&layout, &tab_id).unwrap();
        assert_eq!(destination.pane.is_some(), explicit_pane);
        assert_eq!(
            bound.projection(&paths, &tab_id).unwrap().target().tab_id,
            tab_id
        );

        // A competing writer commits after preparation but before the coherent final projection.
        // Reuse an existing retained Session; neither navigation nor this test invents an identity.
        let mut rebound = layout.clone();
        rebound
            .tabs
            .iter_mut()
            .find(|tab| tab.tab_id == tab_id)
            .unwrap()
            .session_id = "session-a-1".into();
        let other_paths = paths.clone();
        std::thread::spawn(move || {
            write_record(&other_paths, RecordKind::WindowLayout, "w-b", 43, &rebound).unwrap();
        })
        .join()
        .unwrap();

        let before = changes(&paths);
        let error = bound.projection(&paths, &tab_id).unwrap_err();
        assert!(error.contains("another session"), "{error}");
        assert_eq!(changes(&paths), before);
        let current = WindowLayoutService::new(&paths)
            .load("w-b")
            .unwrap()
            .unwrap();
        for sibling in layout.tabs.iter().filter(|tab| tab.tab_id != tab_id) {
            assert_eq!(
                current.tabs.iter().find(|tab| tab.tab_id == sibling.tab_id),
                Some(sibling)
            );
        }
    }
}

fn focus_event(window: &str) -> maestro_renderer::RendererEvent {
    maestro_renderer::RendererEvent::ReactChromeIntent {
        dialog_focus_ticket: None,
        json: serde_json::json!({
            "type": "focusWindow", "project_id": "p-b", "window_id": window,
        })
        .to_string(),
    }
}

#[test]
fn settled_receiver_coalesces_c_before_b_and_preserves_other_events_once_in_order() {
    let (tx, rx) = mpsc::channel();
    let stop = AtomicBool::new(false);
    let mut queue = PendingNavigation(Some(pane_destination()));
    // This is the caller seam immediately after A's Published has been handled: pending=false,
    // activated=true. C is already behind that disposition in the real receiver, not in the slot.
    tx.send(focus_event("w-c")).unwrap();
    let Frontier::Ready(c) = queue.drain_frontier(&rx, &stop, false, true, true, "w-a") else {
        panic!("C must replace B before any activation");
    };
    assert_eq!(c.window_id, "w-c");

    queue.0 = Some(pane_destination());
    tx.send(maestro_renderer::RendererEvent::SessionExited {
        session_id: "existing-session".into(),
        code: Some(1),
        observed_generation: Some("g1".into()),
    })
    .unwrap();
    tx.send(focus_event("w-c")).unwrap();
    let other = r#"{"type":"openWorkspace","project_id":"p-a"}"#;
    tx.send(maestro_renderer::RendererEvent::ReactChromeIntent {
        json: other.into(),
        dialog_focus_ticket: Some(42),
    })
    .unwrap();
    assert!(matches!(
        queue.drain_frontier(&rx, &stop, false, true, true, "w-a"),
        Frontier::Event(maestro_renderer::RendererEvent::SessionExited { code: Some(1), .. })
    ));
    assert_eq!(
        queue.0.as_ref().unwrap().window_id,
        "w-b",
        "must not scan past lifecycle"
    );
    let Frontier::Event(maestro_renderer::RendererEvent::ReactChromeIntent {
        json,
        dialog_focus_ticket,
    }) = queue.drain_frontier(&rx, &stop, false, true, true, "w-a")
    else {
        panic!("non-navigation intent must return to normal dispatch");
    };
    assert_eq!(json, other);
    assert_eq!(
        dialog_focus_ticket,
        Some(42),
        "frontier preserves native launch ownership"
    );
    let Frontier::Ready(c) = queue.drain_frontier(&rx, &stop, false, true, true, "w-a") else {
        panic!("latest navigation remains available after normal event dispatch");
    };
    assert_eq!(c.window_id, "w-c");
    assert!(rx.try_recv().is_err());
    assert!(matches!(
        queue.drain_frontier(&rx, &stop, false, true, true, "w-a"),
        Frontier::NotReady
    ));
}

#[test]
fn frontier_batch_limit_yields_without_admitting_stale_target_and_rechecks_shutdown() {
    let (tx, rx) = mpsc::channel();
    let stop = AtomicBool::new(false);
    let mut queue = PendingNavigation(Some(pane_destination()));
    for index in 0..33 {
        tx.send(focus_event(&format!("w-{index}"))).unwrap();
    }
    assert!(matches!(
        queue.drain_frontier(&rx, &stop, false, true, true, "w-a"),
        Frontier::Yield
    ));
    let Frontier::Ready(last) = queue.drain_frontier(&rx, &stop, false, true, true, "w-a") else {
        panic!("only the latest click may be admitted after the frontier is drained");
    };
    assert_eq!(last.window_id, "w-32");
    queue.0 = Some(pane_destination());
    tx.send(focus_event("w-never")).unwrap();
    stop.store(true, Ordering::Release);
    assert!(matches!(
        queue.drain_frontier(&rx, &stop, false, true, true, "w-a"),
        Frontier::NotReady
    ));
    assert!(queue.0.is_none());
    assert!(
        rx.try_recv().is_ok(),
        "shutdown must not start consuming a new batch"
    );
}

#[test]
fn legacy_displayed_owner_is_readable_but_valid_foreign_fk_still_wins() {
    let (_tmp, paths) = fixture();
    let destination = pane_destination();
    for owner in [None, Some("missing-project"), Some("p-a")] {
        {
            // Reproduce a legacy writer's NULL/dangling FK without touching provider/session rows.
            let conn = maestro_shell::db::conn_for(paths.base()).unwrap();
            let conn = conn.lock().unwrap();
            conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
            conn.execute(
                "UPDATE windows SET project_id = ?1 WHERE window_id = 'w-b'",
                [owner],
            )
            .unwrap();
            conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        }
        let before = changes(&paths);
        if owner == Some("p-a") {
            assert!(destination.resolve(&paths).is_err());
            assert!(destination.projection(&paths, "tab-b-2").is_err());
            let foreign = Destination {
                project_id: "p-a".into(),
                ..destination.clone()
            };
            assert_eq!(foreign.resolve(&paths).unwrap().1, "tab-b-2");
        } else {
            assert_eq!(destination.resolve(&paths).unwrap().1, "tab-b-2");
            assert_eq!(
                destination
                    .projection(&paths, "tab-b-2")
                    .unwrap()
                    .target()
                    .session_id,
                "session-b-2"
            );
            let wrong_pane = Destination {
                pane: Some(("tab-b-2".into(), "session-b-1".into())),
                ..destination.clone()
            };
            assert!(wrong_pane.resolve(&paths).is_err());
        }
        assert_eq!(
            changes(&paths),
            before,
            "ownership lookup must not repair or retarget"
        );
        assert_eq!(
            WindowLayoutService::new(&paths)
                .load_snapshot("w-b")
                .unwrap()
                .unwrap()
                .project_id
                .as_deref(),
            owner
        );
    }
}
