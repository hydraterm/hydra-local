use super::*;

struct RejectingClipboard;

#[cfg(not(target_os = "linux"))]
impl crate::Clipboard for RejectingClipboard {
    fn read_text(&mut self) -> Option<String> {
        panic!("program copy must never read clipboard contents")
    }

    fn write_text(&mut self, _: String) -> bool {
        false
    }
}

#[cfg(target_os = "linux")]
impl crate::host_services::TerminalClipboardHostServices for RejectingClipboard {
    fn request_text(&self, _: u64) {
        panic!("program copy must never read clipboard contents")
    }

    fn set_text(&self, _: &str) -> bool {
        false
    }

    fn show_context_menu(&self, _: bool) -> bool {
        false
    }
}

#[test]
fn focused_program_copy_is_enabled_by_default_without_hidden_environment() {
    let (mut app, shared) = app_with_primary_grid();
    let writes = super::copy_on_select::record_copies(&mut app);
    app.handle_host_event(HostEvent::Focused(true));
    let binding = shared
        .binding_token_for_session("primary")
        .expect("current viewport");
    app.handle_user_event(UserEvent::TerminalClipboardStore {
        binding,
        text: "program-copy-fixture".into(),
    });
    assert_eq!(&*writes.borrow(), &["program-copy-fixture"]);
    assert!(shared.drain_test_requests().is_empty());
}

fn program_copy(app: &mut App, shared: &Shared, session: &str) {
    app.handle_user_event(UserEvent::TerminalClipboardStore {
        binding: shared.binding_token_for_session(session).unwrap(),
        text: format!("copy-{session}"),
    });
}

#[test]
fn program_copy_obeys_both_user_choices_without_disabling_manual_copy() {
    let (mut app, shared) = app_with_primary_grid();
    let writes = super::copy_on_select::record_copies(&mut app);
    app.handle_host_event(HostEvent::Focused(true));
    for enabled in [false, true] {
        let event =
            crate::user_event_for_command(crate::RendererCommand::SetProgramClipboard { enabled });
        assert!(
            matches!(event, UserEvent::SetProgramClipboard { enabled: actual } if actual == enabled)
        );
        app.handle_user_event(event);
        program_copy(&mut app, &shared, "primary");
        assert_eq!(writes.borrow().len(), usize::from(enabled));
    }
    app.handle_user_event(UserEvent::SetProgramClipboard { enabled: false });
    app.begin_local_selection(Some(CellPos { col: 0, row: 0 }));
    app.sel_focus = Some(CellPos { col: 4, row: 0 });
    app.copy_selection();
    assert_eq!(&*writes.borrow(), &["copy-primary", "hello"]);
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn program_copy_accepts_only_focused_pane_in_focused_window() {
    let (mut app, shared, _) = app_with_right_child();
    let writes = super::copy_on_select::record_copies(&mut app);
    app.handle_host_event(HostEvent::Focused(true));
    program_copy(&mut app, &shared, "primary");
    assert!(writes.borrow().is_empty(), "background primary cannot copy");
    program_copy(&mut app, &shared, "child");
    assert_eq!(&*writes.borrow(), &["copy-child"]);
    app.handle_host_event(HostEvent::Focused(false));
    program_copy(&mut app, &shared, "child");
    assert_eq!(writes.borrow().len(), 1, "background window cannot copy");
    app.handle_host_event(HostEvent::Focused(true));
    app.focused_pane_session = None;
    program_copy(&mut app, &shared, "child");
    program_copy(&mut app, &shared, "primary");
    assert_eq!(&*writes.borrow(), &["copy-child", "copy-primary"]);
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn program_copy_rejects_stale_binding_and_cleared_viewport() {
    let (mut app, shared) = app_with_primary_grid();
    let writes = super::copy_on_select::record_copies(&mut app);
    app.handle_host_event(HostEvent::Focused(true));
    let old = shared.binding_token_for_session("primary").unwrap();
    bind_exact_fixture_viewport(
        &mut app,
        &shared,
        RendererTabStrip {
            window_id: "replacement".into(),
            tabs: vec![tab("tab-primary", "primary", true, None, None)],
        },
        vec![("primary", grid("replacement-gen", 20, 6, "replacement"))],
    );
    app.handle_user_event(UserEvent::TerminalClipboardStore {
        binding: old,
        text: "stale".into(),
    });
    assert!(writes.borrow().is_empty());
    let current = shared.binding_token_for_session("primary").unwrap();
    app.handle_user_event(UserEvent::ClearViewport);
    // Clearing performs its own detach; clipboard handling must add no requests.
    shared.drain_test_requests();
    app.handle_user_event(UserEvent::TerminalClipboardStore {
        binding: current,
        text: "cleared".into(),
    });
    assert!(writes.borrow().is_empty());
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn native_focus_before_first_viewport_is_retained_without_terminal_writes() {
    let shared = Shared::with_test_handoff_peer_facts(None, None);
    let mut app = selection_fixture_app(shared.clone());
    let writes = super::copy_on_select::record_copies(&mut app);
    app.handle_host_event(HostEvent::Focused(true));
    assert!(!app.viewport_is_bound());
    assert!(shared.drain_test_requests().is_empty());
    bind_exact_fixture_viewport(
        &mut app,
        &shared,
        RendererTabStrip {
            window_id: "window".into(),
            tabs: vec![tab("tab-primary", "primary", true, None, None)],
        },
        vec![("primary", grid("primary-gen", 20, 6, "hello"))],
    );
    program_copy(&mut app, &shared, "primary");
    assert_eq!(&*writes.borrow(), &["copy-primary"]);
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn rejected_native_copy_shows_actionable_status_without_claiming_success() {
    let (mut app, shared) = app_with_primary_grid();
    app.status_label = Some("Original window status".into());
    app.handle_host_event(HostEvent::Focused(true));
    #[cfg(not(target_os = "linux"))]
    {
        app.clipboard = Box::new(RejectingClipboard);
    }
    #[cfg(target_os = "linux")]
    {
        app.clipboard_host = Some(std::rc::Rc::new(RejectingClipboard));
    }
    program_copy(&mut app, &shared, "primary");
    assert_eq!(
        app.clipboard_status_label(),
        Some("Copy failed: OS clipboard unavailable. Restart Hydra, then copy again.")
    );
    let writes = super::copy_on_select::record_copies(&mut app);
    program_copy(&mut app, &shared, "primary");
    assert_eq!(&*writes.borrow(), &["copy-primary"]);
    assert_eq!(app.clipboard_status_label(), Some("Original window status"));
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn startup_preferences_apply_before_first_copy_with_or_without_live_command_channels() {
    // The same entrypoint accepts channels for normal windows and None for retained
    // attach-only windows. Both apply these preferences before entering the host loop.
    let _entrypoint: fn(
        crate::RendererLaunch,
        Option<std::sync::mpsc::Receiver<crate::RendererCommand>>,
        Option<std::sync::mpsc::Sender<crate::RendererEvent>>,
        bool,
        bool,
    ) -> Result<(), crate::RendererRunError> = crate::run_renderer_with_clipboard_settings;
    for retained_read_only in [false, true] {
        let (mut app, shared) = app_with_primary_grid();
        let writes = super::copy_on_select::record_copies(&mut app);
        app.set_initial_clipboard_settings(true, false);
        if retained_read_only {
            app.enter_mutation_read_only();
        }
        app.handle_host_event(HostEvent::Focused(true));
        program_copy(&mut app, &shared, "primary");
        assert!(
            writes.borrow().is_empty(),
            "explicit startup opt-out applies immediately"
        );
        assert!(app.copy_on_select);
        app.set_initial_clipboard_settings(false, true);
        program_copy(&mut app, &shared, "primary");
        assert_eq!(&*writes.borrow(), &["copy-primary"]);
        assert!(!app.copy_on_select);
        assert!(shared.drain_test_requests().is_empty());
    }
}
