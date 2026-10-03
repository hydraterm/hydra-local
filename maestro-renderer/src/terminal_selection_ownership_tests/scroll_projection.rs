use super::*;
use crate::client::ScrollAction;
use crate::host_event::HostScrollDelta;

fn select_hello(app: &mut App) {
    app.begin_local_selection(Some(CellPos { col: 0, row: 0 }));
    app.extend_local_selection(Some(CellPos { col: 4, row: 0 }));
    app.selecting = false;
    assert_eq!(app.selected_text().as_deref(), Some("hello"));
}

#[test]
fn live_selection_output_before_first_scroll_preserves_original_copy_and_anchor() {
    let (mut app, shared) = app_with_primary_grid();
    let copies = super::copy_on_select::record_copies(&mut app);
    select_hello(&mut app);
    let anchor = app.sel_anchor;
    app.copy_selection();
    let mut output = grid("primary-gen", 20, 6, "later-primary");
    output.revision = Revision(2);
    *shared.grid.lock().unwrap() = Some(Arc::new(output));
    app.copy_selection();
    assert_eq!(&*copies.borrow(), &["hello", "hello"]);
    assert_eq!(
        app.current_selection(),
        None,
        "new pixels cannot inherit the highlight"
    );

    app.apply_scroll(ScrollAction::Lines(3));
    install_selection_history(&shared, 3, 2);
    shared.drain_test_requests();
    app.modifiers.shift = true;
    app.begin_local_selection_gesture(Some(CellPos { col: 4, row: 0 }), Instant::now());
    assert_eq!(app.sel_anchor, anchor);
    assert_eq!(app.selected_text().as_deref(), Some("hello"));
    assert!(
        app.sel_span.is_none(),
        "a new revision cannot prove the old anchor"
    );
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn live_selection_output_during_drag_keeps_accepted_range() {
    let (mut app, shared) = app_with_primary_grid();
    app.begin_local_selection(Some(CellPos { col: 0, row: 0 }));
    app.extend_local_selection(Some(CellPos { col: 4, row: 0 }));
    let mut output = grid("primary-gen", 20, 6, "later-primary");
    output.revision = Revision(2);
    *shared.grid.lock().unwrap() = Some(Arc::new(output));
    app.extend_local_selection(Some(CellPos { col: 8, row: 0 }));
    assert_eq!(app.sel_focus, Some(CellPos { col: 4, row: 0 }));
    assert_eq!(app.selected_text().as_deref(), Some("hello"));
}

#[test]
fn live_selection_output_before_first_motion_does_not_retarget_press() {
    let (mut app, shared) = app_with_primary_grid();
    let press = CellPos { col: 0, row: 0 };
    app.begin_local_selection(Some(press));
    let mut output = grid("primary-gen", 20, 6, "later-primary");
    output.revision = Revision(2);
    *shared.grid.lock().unwrap() = Some(Arc::new(output));
    app.extend_local_selection(Some(CellPos { col: 4, row: 0 }));
    assert_eq!(app.sel_anchor, Some(press));
    assert_eq!(app.sel_focus, Some(press));
    assert_eq!(app.selected_text(), None);
}

fn install_selection_history(shared: &Shared, offset: u32, revision: u64) {
    let mut historical = grid("primary-gen", 20, 6, "unrelated older row");
    historical.revision = Revision(revision);
    if offset < 6 {
        historical.rows_cells[offset as usize] =
            grid("primary-gen", 20, 6, "hello-primary").rows_cells[0].clone();
    }
    let mut sb = shared.scrollback.lock().unwrap();
    sb.view_offset = offset;
    sb.history_len = Some(40);
    sb.historical = Some(crate::client::HistoricalView::new(
        Arc::new(historical),
        offset,
        40,
    ));
}

#[test]
fn selection_scroll_retains_copy_and_maps_only_exact_revision_pixels() {
    let (mut app, shared) = app_with_primary_grid();
    select_hello(&mut app);
    app.apply_scroll(ScrollAction::Lines(3));
    assert_eq!(
        app.selected_text().as_deref(),
        Some("hello"),
        "pending scroll retains exact source"
    );
    install_selection_history(&shared, 3, 1);
    assert_eq!(
        app.current_selection(),
        Some((CellPos { col: 0, row: 3 }, CellPos { col: 4, row: 3 }))
    );
    assert_eq!(app.selected_text().as_deref(), Some("hello"));
    install_selection_history(&shared, 3, 2);
    assert_eq!(
        app.current_selection(),
        None,
        "new revision cannot prove row identity"
    );
    assert_eq!(
        app.selected_text().as_deref(),
        Some("hello"),
        "copy does not switch to replacement rows"
    );
}

#[test]
fn selection_scroll_offscreen_shift_preserves_original_anchor_and_text() {
    let (mut app, shared) = app_with_primary_grid();
    select_hello(&mut app);
    let anchor = app.sel_anchor;
    app.apply_scroll(ScrollAction::Lines(8));
    install_selection_history(&shared, 8, 1);
    assert_eq!(app.current_selection(), None);
    app.modifiers.shift = true;
    app.begin_local_selection_gesture(Some(CellPos { col: 4, row: 0 }), Instant::now());
    assert_eq!(
        app.sel_anchor, anchor,
        "unavailable span is not a fresh selection"
    );
    assert_eq!(app.selected_text().as_deref(), Some("hello"));
}

#[test]
fn selection_span_shift_requests_missing_rows_without_mutating_view_or_copy() {
    let (mut app, shared) = app_with_primary_grid();
    select_hello(&mut app);
    shared.scrollback.lock().unwrap().history_len = Some(40);
    app.apply_scroll(ScrollAction::Lines(8));
    assert!(matches!(
        shared.drain_test_requests().as_slice(),
        [ClientRequest::Scrollback {
            offset_from_top: 8,
            count: 6,
            ..
        }]
    ));
    // Retire the preceding viewport query, then install its accepted same-revision pixels.
    shared.scrollback.lock().unwrap().admitted_request = None;
    install_selection_history(&shared, 8, 1);
    let before = shared
        .scrollback
        .lock()
        .unwrap()
        .historical
        .clone()
        .unwrap();
    app.modifiers.shift = true;
    app.begin_local_selection_gesture(Some(CellPos { col: 4, row: 0 }), Instant::now());
    assert_eq!(app.selected_text().as_deref(), Some("hello"));
    assert_eq!(shared.scrollback.lock().unwrap().view_offset, 8);
    assert!(Arc::ptr_eq(
        &before.grid,
        &shared
            .scrollback
            .lock()
            .unwrap()
            .historical
            .as_ref()
            .unwrap()
            .grid,
    ));
    assert_eq!(
        shared.drain_test_requests(),
        vec![ClientRequest::Scrollback {
            id: "primary".into(),
            offset_from_top: 8,
            count: 9,
        }],
        "Shift must acquire the complete missing span without moving the viewport"
    );
}

#[test]
fn selection_scroll_shift_extends_only_within_frozen_source_and_returns_live() {
    let (mut app, shared) = app_with_primary_grid();
    select_hello(&mut app);
    app.apply_scroll(ScrollAction::Lines(3));
    install_selection_history(&shared, 3, 1);
    app.modifiers.shift = true;
    app.begin_local_selection_gesture(Some(CellPos { col: 12, row: 3 }), Instant::now());
    assert_eq!(app.sel_anchor, Some(CellPos { col: 0, row: 0 }));
    assert_eq!(app.selected_text().as_deref(), Some("hello-primary"));
    app.apply_scroll(ScrollAction::Lines(-3));
    assert_eq!(app.selected_text().as_deref(), Some("hello-primary"));
    assert_eq!(
        app.current_selection(),
        Some((CellPos { col: 0, row: 0 }, CellPos { col: 12, row: 0 }))
    );
}

#[test]
fn selection_scroll_partial_clip_never_changes_copied_range() {
    let (mut app, shared) = app_with_primary_grid();
    app.begin_local_selection(Some(CellPos { col: 4, row: 0 }));
    app.extend_local_selection(Some(CellPos { col: 2, row: 4 }));
    let original = app.selected_text();
    app.apply_scroll(ScrollAction::Lines(3));
    install_selection_history(&shared, 3, 1);
    assert_eq!(
        app.current_selection(),
        Some((CellPos { col: 4, row: 3 }, CellPos { col: 19, row: 5 }))
    );
    assert_eq!(app.selected_text(), original);
    let source = app.sel_scrolled.as_ref().unwrap();
    let newer = grid("primary-gen", 20, 6, "");
    // Reverse-direction selection clipping remains the same visual inclusive interval.
    assert_eq!(
        source.project(app.sel_focus.unwrap(), app.sel_anchor.unwrap(), &newer, 3),
        app.current_selection()
    );
}

#[test]
fn selection_scroll_unavailable_shift_retains_single_cell_word() {
    let (mut app, shared) = app_with_primary_grid();
    let pos = CellPos { col: 0, row: 0 };
    app.begin_local_selection(Some(pos));
    app.sel_unit_anchor = Some((pos, pos, crate::SelectionUnit::Word));
    app.apply_scroll(ScrollAction::Lines(3));
    install_selection_history(&shared, 3, 1);
    app.modifiers.shift = true;
    app.begin_local_selection_gesture(Some(CellPos { col: 0, row: 0 }), Instant::now());
    app.handle_host_event(HostEvent::MouseInput {
        button: HostPointerButton::Left,
        pressed: false,
    });
    assert_eq!(app.selected_text().as_deref(), Some("h"));
    assert_eq!(app.sel_anchor, Some(pos));
    assert!(app.sel_unit_anchor.is_some());
}

#[test]
fn selection_scroll_frozen_copy_obeys_revocation_generation_and_screen() {
    for invalidation in 0..3 {
        let (mut app, shared) = app_with_primary_grid();
        let copies = super::copy_on_select::record_copies(&mut app);
        select_hello(&mut app);
        app.apply_scroll(ScrollAction::Lines(3));
        install_selection_history(&shared, 3, 2);
        app.copy_selection();
        assert_eq!(&*copies.borrow(), &["hello"]);
        match invalidation {
            0 => shared.active.lock().unwrap().id = None,
            1 => *shared.grid.lock().unwrap() = Some(Arc::new(grid("replacement", 20, 6, "wrong"))),
            _ => {
                let mut changed = grid("primary-gen", 20, 6, "alternate");
                changed.alt_screen = true;
                *shared.grid.lock().unwrap() = Some(Arc::new(changed));
            }
        }
        assert_eq!(app.selected_text(), None);
        app.copy_selection();
        assert_eq!(copies.borrow().len(), 1);
    }
}

#[test]
fn selection_scroll_offscreen_copy_survives_output_but_escape_clears() {
    let (mut app, shared) = app_with_primary_grid();
    select_hello(&mut app);
    app.apply_scroll(ScrollAction::Lines(3));
    install_selection_history(&shared, 8, 2);
    assert!(app.has_owned_selection());
    assert!(app.current_selection().is_none());
    let escape = crate::host_event::HostKeyEvent {
        key: HostKey::Named(crate::host_event::HostNamedKey::Escape),
        text: None,
        base_text: None,
        location: crate::host_event::HostKeyLocation::Standard,
        pressed: true,
        repeat: false,
    };
    app.handle_host_event(HostEvent::Keyboard(escape));
    assert!(app.sel_scrolled.is_none());
    assert!(app.selected_text().is_none());
    assert!(!app.has_owned_selection());
}

#[test]
fn selection_scroll_history_to_live_captures_before_history_is_dropped() {
    let (mut app, shared) = scrolled_app();
    app.begin_local_selection(Some(CellPos { col: 0, row: 0 }));
    app.extend_local_selection(Some(CellPos { col: 4, row: 0 }));
    app.apply_scroll(ScrollAction::End);
    assert!(shared.scrollback.lock().unwrap().historical.is_none());
    assert!(
        app.current_selection().is_none(),
        "selected history is above live top"
    );
    assert_eq!(app.selected_text().as_deref(), Some("older"));
    app.apply_scroll(ScrollAction::Lines(3));
    let source = app.sel_scrolled.as_ref().unwrap().grid.clone();
    shared.scrollback.lock().unwrap().historical =
        Some(crate::client::HistoricalView::new(source, 3, 40));
    assert_eq!(
        app.current_selection(),
        Some((CellPos { col: 0, row: 0 }, CellPos { col: 4, row: 0 }))
    );
    assert_eq!(app.selected_text().as_deref(), Some("older"));
}

#[test]
fn selection_scroll_split_copy_stays_owned_and_real_focus_change_clears() {
    let (mut app, shared, origin) = app_with_right_child();
    let copies = super::copy_on_select::record_copies(&mut app);
    app.begin_local_selection(Some(origin));
    app.extend_local_selection(Some(CellPos {
        col: origin.col + 4,
        row: origin.row,
    }));
    assert_eq!(app.selected_text().as_deref(), Some("child"));
    app.apply_scroll(ScrollAction::Lines(3));
    assert_eq!(app.sel_session_id.as_deref(), Some("child"));
    app.copy_selection();
    assert_eq!(&*copies.borrow(), &["child"]);
    let (mut panes, _) = app.current_pane_paints();
    attach_selection_to_owner(
        &mut panes,
        app.sel_session_id.as_deref(),
        app.current_selection(),
    );
    assert!(panes
        .iter()
        .filter(|pane| pane.selection.is_some())
        .all(|pane| pane.session_id == "child"));
    assert!(app.move_pane_focus(PaneFocusDirection::Left));
    assert!(app.sel_scrolled.is_none());
    assert!(app.selected_text().is_none());
    assert!(!shared
        .drain_test_requests()
        .iter()
        .any(|r| matches!(r, ClientRequest::Write { .. })));
}

#[test]
fn selection_scroll_frozen_snapshot_keeps_rowcopy_and_wide_glyphs() {
    use maestro_protocol::row_copy::RowCopy;
    let (mut app, shared) = app_with_primary_grid();
    let mut source = grid("primary-gen", 20, 6, "ABCDEFGHIJKLMNOPQRS ");
    source.rows_cells[1][0] = cell("界");
    source.rows_cells[1][0].width = 2;
    source.rows_cells[1][1] = cell("");
    source.rows_cells[1][1].width = 0;
    let mut metadata = vec![
        RowCopy {
            starts_line: None,
            soft_wrap: false,
            excluded_columns: vec![]
        };
        6
    ];
    metadata[0].soft_wrap = true;
    metadata[0].excluded_columns = vec![19];
    metadata[1].starts_line = Some(false);
    source.row_copy = Some(metadata);
    *shared.grid.lock().unwrap() = Some(Arc::new(source));
    app.begin_local_selection(Some(CellPos { col: 0, row: 0 }));
    app.extend_local_selection(Some(CellPos { col: 1, row: 1 }));
    app.apply_scroll(ScrollAction::Lines(3));
    install_selection_history(&shared, 3, 2);
    assert_eq!(
        app.selected_text().as_deref(),
        Some("ABCDEFGHIJKLMNOPQRS界")
    );
    assert!(app.current_selection().is_none());
}

#[test]
fn selection_scroll_reply_race_does_not_project_new_offset_over_old_frame() {
    let (mut app, shared) = app_with_primary_grid();
    select_hello(&mut app);
    app.apply_scroll(ScrollAction::Lines(3));
    install_selection_history(&shared, 3, 1);
    let planned = app.focused_pane_grid("primary").unwrap();
    assert!(app.selection_for_painted_grid(&planned).is_some());
    // Same revision, different accepted viewport: the already planned Arc remains on screen.
    install_selection_history(&shared, 4, 1);
    assert!(app.selection_for_painted_grid(&planned).is_none());
    assert_eq!(
        app.current_selection(),
        Some((CellPos { col: 0, row: 4 }, CellPos { col: 4, row: 4 }))
    );
    assert_eq!(app.selected_text().as_deref(), Some("hello"));
    // Desired (not yet served) scroll intent must not move the highlight.
    shared.scrollback.lock().unwrap().view_offset = 30;
    assert_eq!(
        app.current_selection(),
        Some((CellPos { col: 0, row: 4 }, CellPos { col: 4, row: 4 }))
    );
}

#[test]
fn selection_scroll_pointer_wheel_then_shift_keeps_same_pane_anchor() {
    let (mut app, shared) = app_with_primary_grid();
    app.host = Some(Box::new(RecordingNeutralHost {
        titles: Arc::new(Mutex::new(Vec::new())),
    }));
    app.test_cell_size_logical = Some((10.0, 20.0));
    let point = |app: &mut App, col: usize, row: usize| {
        app.handle_host_event(HostEvent::CursorMoved {
            x: col as f64 * 10.0 + 5.0,
            y: row as f64 * 20.0 + 5.0,
        });
    };
    let button = |app: &mut App, pressed| {
        app.handle_host_event(HostEvent::MouseInput {
            button: HostPointerButton::Left,
            pressed,
        });
    };
    point(&mut app, 0, 0);
    button(&mut app, true);
    point(&mut app, 4, 0);
    button(&mut app, false);
    assert_eq!(app.selected_text().as_deref(), Some("hello"));
    app.handle_host_event(HostEvent::MouseWheel {
        delta: HostScrollDelta::Lines { x: 0.0, y: 3.0 },
    });
    install_selection_history(&shared, 3, 1);
    app.modifiers.shift = true;
    point(&mut app, 4, 0);
    button(&mut app, true);
    button(&mut app, false);
    assert_eq!(app.selected_text().as_deref(), Some("hello"));
    assert_eq!(app.sel_anchor, Some(CellPos { col: 0, row: 0 }));
    point(&mut app, 12, 3);
    button(&mut app, true);
    button(&mut app, false);
    assert_eq!(app.selected_text().as_deref(), Some("hello-primary"));
    assert_eq!(app.sel_anchor, Some(CellPos { col: 0, row: 0 }));
    assert!(!shared
        .drain_test_requests()
        .iter()
        .any(|r| matches!(r, ClientRequest::Write { .. })));
}

#[test]
fn selection_scroll_history_width_is_not_the_live_geometry_witness() {
    let (mut app, shared) = app_with_primary_grid();
    // A read-only historical reply has its own current width, while the separately accepted
    // live baseline can still have the earlier width. Copy must retain the history pixels.
    let history = Arc::new(grid("primary-gen", 22, 8, "historical"));
    {
        let mut sb = shared.scrollback.lock().unwrap();
        sb.view_offset = 3;
        sb.history_len = Some(40);
        sb.historical = Some(crate::client::HistoricalView::new(history, 3, 40));
    }
    app.begin_local_selection(Some(CellPos { col: 0, row: 0 }));
    app.extend_local_selection(Some(CellPos { col: 4, row: 0 }));
    assert_eq!(app.selected_text().as_deref(), Some("histo"));
    app.apply_scroll(ScrollAction::Lines(3));
    assert_eq!(app.selected_text().as_deref(), Some("histo"));
    // A delayed live baseline catching up is not a new host/layout resize.
    *shared.grid.lock().unwrap() = Some(Arc::new(grid("primary-gen", 22, 8, "caught up")));
    assert_eq!(app.selected_text().as_deref(), Some("histo"));
    app.handle_host_event(HostEvent::Resized {
        width: 1000,
        height: 800,
    });
    assert!(app.selected_text().is_none());
    assert!(app.sel_scrolled.is_none());
}

#[test]
fn selection_scroll_live_height_catchup_preserves_copy_but_host_scale_clears() {
    let (mut app, shared) = app_with_primary_grid();
    select_hello(&mut app);
    app.apply_scroll(ScrollAction::Lines(3));
    // Cache freshness is independent from the owner-observed host allocation.
    *shared.grid.lock().unwrap() = Some(Arc::new(grid("primary-gen", 20, 8, "later frame")));
    assert_eq!(app.selected_text().as_deref(), Some("hello"));
    app.handle_host_event(HostEvent::ScaleFactorChanged { scale: 2.0 });
    assert!(app.selected_text().is_none());
    assert!(app.sel_scrolled.is_none());
}

fn scrolled_app() -> (App, Arc<Shared>) {
    let (mut app, shared) = app_with_primary_grid();
    app.primary_pane_dims = Some((20, 6));
    app.handle_host_event(HostEvent::MouseWheel {
        delta: HostScrollDelta::Lines { x: 0.0, y: 3.0 },
    });
    assert!(matches!(
        shared.drain_test_requests().as_slice(),
        [ClientRequest::Scrollback {
            id,
            offset_from_top: 3,
            ..
        }] if id == "primary"
    ));
    let mut scrollback = shared.scrollback.lock().unwrap();
    assert_eq!(scrollback.view_offset, 3);
    scrollback.history_len = Some(40);
    scrollback.historical = Some(crate::client::HistoricalView::new(
        Arc::new(grid("primary-gen", 20, 6, "older transcript")),
        3,
        40,
    ));
    drop(scrollback);
    (app, shared)
}

fn flush_scheduled_refit(app: &mut App) {
    if app.pending_resize_refit_at.is_some() {
        app.pending_resize_refit_at = Some(Instant::now());
        app.flush_resize_refit_if_due();
    }
}

#[test]
fn periodic_remote_status_keeps_scrolled_transcript_and_sends_no_resize() {
    let (mut app, shared) = scrolled_app();
    let historical = shared
        .pane_paint("primary", "primary")
        .paint_grid()
        .unwrap();
    for (available, open, remote_winsize) in [
        (false, false, false),
        (true, false, false),
        (true, true, false),
        (true, true, true),
        (true, true, true),
    ] {
        app.handle_user_event(UserEvent::SetRemoteExtensionState {
            available,
            open,
            remote_winsize,
            remote_owned_sessions: vec![],
        });
        flush_scheduled_refit(&mut app);
        let paint = shared.pane_paint("primary", "primary");
        assert_eq!(
            paint.scrolled_offset(),
            3,
            "status refresh must not return to live"
        );
        assert!(Arc::ptr_eq(&paint.paint_grid().unwrap(), &historical));
        assert!(
            shared.drain_test_requests().is_empty(),
            "status refresh must not resize a PTY"
        );
    }
}

#[test]
fn legacy_display_only_owner_summary_cannot_resize_or_reset_scrollback() {
    let (mut app, shared) = scrolled_app();
    for remote in [false, true, true, false] {
        app.handle_user_event(UserEvent::SetWinsizeOwner { remote });
        flush_scheduled_refit(&mut app);
        assert_eq!(shared.pane_paint("primary", "primary").scrolled_offset(), 3);
        assert!(shared.drain_test_requests().is_empty());
    }
}

#[test]
fn equal_normalized_ownership_keeps_history_but_real_reclaim_still_refits() {
    let (mut app, shared) = scrolled_app();
    app.external_winsize_sessions = ["primary".into(), "other-pane".into()].into();
    app.handle_user_event(UserEvent::SetRemoteExtensionState {
        available: true,
        open: true,
        remote_winsize: true,
        remote_owned_sessions: vec!["other-pane".into(), "primary".into(), "primary".into()],
    });
    assert!(app.pending_resize_refit_at.is_none());
    assert_eq!(shared.pane_paint("primary", "primary").scrolled_offset(), 3);
    assert!(shared.drain_test_requests().is_empty());

    // A negotiated ownership release, unlike its display-only summary, must still
    // schedule the established exact-generation local geometry/reflow path.
    app.handle_user_event(UserEvent::SetRemoteExtensionState {
        available: true,
        open: true,
        remote_winsize: false,
        remote_owned_sessions: vec![],
    });
    assert!(app.pending_resize_refit_at.is_some());
    flush_scheduled_refit(&mut app);
    assert_eq!(shared.pane_paint("primary", "primary").scrolled_offset(), 0);
    let requests = shared.drain_test_requests();
    let resized: Vec<_> = requests
        .iter()
        .filter_map(|request| match request {
            ClientRequest::Resize {
                id,
                expected_generation,
                cols,
                rows,
            } => {
                assert_eq!(id, "primary");
                assert_eq!(expected_generation.0, "primary-gen");
                Some((*cols, *rows))
            }
            _ => None,
        })
        .collect();
    assert_eq!(resized, vec![(19, 6), (20, 6)]);
    assert!(matches!(requests.last(), Some(ClientRequest::Snapshot { id }) if id == "primary"));
    assert!(!requests
        .iter()
        .any(|request| matches!(request, ClientRequest::Write { .. })));
}
