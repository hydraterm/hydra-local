use super::*;

fn release(app: &mut App) {
    app.handle_host_event(HostEvent::MouseInput {
        button: HostPointerButton::Left,
        pressed: false,
    });
}

fn double_click(app: &mut App, pos: CellPos) {
    let now = Instant::now();
    app.begin_local_selection_gesture(Some(pos), now);
    release(app);
    app.begin_local_selection_gesture(Some(pos), now + Duration::from_millis(100));
    release(app);
}

#[test]
fn word_ranges_keep_paths_combining_and_wide_cells_without_crossing_punctuation() {
    for (text, col, expected) in [
        ("(~/src/a-b_v2.rs)", 5, "~/src/a-b_v2.rs"),
        ("(~/src/a-b_v2.rs)", 0, "("),
        ("a,word;z", 3, "word"),
        ("one  two", 4, ""),
        ("x", 0, "x"),
    ] {
        let cells = vec![text.chars().map(|c| cell(&c.to_string())).collect()];
        let (a, b) = crate::terminal_selection::word_range(&cells, CellPos { col, row: 0 })
            .expect("selected cell");
        assert_eq!(crate::client::extract_selection(&cells, a, b), expected);
    }
    let mut wide = cell("界");
    wide.width = 2;
    let mut spacer = cell("");
    spacer.width = 0;
    let cells = vec![vec![cell("("), cell("e\u{301}"), wide, spacer, cell(")")]];
    let (a, b) = crate::terminal_selection::word_range(&cells, CellPos { col: 3, row: 0 })
        .expect("wide spacer belongs to lead");
    assert_eq!(crate::client::extract_selection(&cells, a, b), "e\u{301}界");
    assert!(crate::terminal_selection::word_range(&cells, CellPos { col: 99, row: 0 }).is_none());
}

#[test]
fn double_click_survives_release_and_word_drag_uses_whole_tokens() {
    let (mut app, shared) = app_with_primary_grid();
    *shared.grid.lock().unwrap() = Some(Arc::new(grid("primary-gen", 20, 6, "one two three")));
    double_click(&mut app, CellPos { col: 5, row: 0 });
    assert_eq!(app.selected_text().as_deref(), Some("two"));
    app.extend_local_selection(Some(CellPos { col: 5, row: 0 }));
    assert_eq!(app.selected_text().as_deref(), Some("two"));
    app.extend_local_selection(Some(CellPos { col: 10, row: 0 }));
    assert_eq!(app.selected_text().as_deref(), Some("two three"));
    app.extend_local_selection(Some(CellPos { col: 1, row: 0 }));
    assert_eq!(app.selected_text().as_deref(), Some("one two"));
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn double_click_can_select_one_character_but_plain_click_still_cannot() {
    let (mut app, shared) = app_with_primary_grid();
    *shared.grid.lock().unwrap() = Some(Arc::new(grid("primary-gen", 20, 6, "x (y)")));
    for col in [0, 2] {
        app.clear_selection();
        let pos = CellPos { col, row: 0 };
        app.begin_local_selection_gesture(Some(pos), Instant::now());
        release(&mut app);
        assert!(app.current_selection().is_none());
        double_click(&mut app, pos);
        assert_eq!(
            app.selected_text().as_deref(),
            Some(if col == 0 { "x" } else { "(" })
        );
    }
}

#[test]
fn shift_click_extends_the_original_anchor_and_stale_owners_start_fresh() {
    let (mut app, shared) = app_with_primary_grid();
    app.begin_local_selection(Some(CellPos { col: 0, row: 0 }));
    app.extend_local_selection(Some(CellPos { col: 4, row: 0 }));
    release(&mut app);
    app.modifiers.shift = true;
    app.begin_local_selection_gesture(Some(CellPos { col: 8, row: 0 }), Instant::now());
    release(&mut app);
    assert_eq!(app.sel_anchor, Some(CellPos { col: 0, row: 0 }));
    assert_eq!(app.selected_text().as_deref(), Some("hello-pri"));
    *shared.grid.lock().unwrap() = Some(Arc::new(grid("replacement", 20, 6, "fresh")));
    app.begin_local_selection_gesture(Some(CellPos { col: 2, row: 0 }), Instant::now());
    assert_eq!(app.sel_anchor, Some(CellPos { col: 2, row: 0 }));
    assert!(app.current_selection().is_none());
}

#[test]
fn double_click_uses_split_owner_and_historical_grid() {
    let (mut app, shared, origin) = app_with_right_child();
    double_click(&mut app, origin);
    let selected = app.selected_text().expect("child word");
    assert!(selected.starts_with("child"));
    assert!(!selected.contains("primary"));
    app.focused_pane_session = Some("primary".into());
    assert!(app.current_selection().is_none());
    assert!(shared.drain_test_requests().is_empty());

    let (mut app, shared) = app_with_primary_grid();
    {
        let mut history = shared.scrollback.lock().unwrap();
        history.view_offset = 1;
        history.history_len = Some(1);
        history.historical_generation = Some(SessionGeneration("primary-gen".into()));
        history.historical = Some(Arc::new(grid("primary-gen", 20, 6, "historical")));
    }
    double_click(&mut app, CellPos { col: 2, row: 0 });
    assert_eq!(app.selected_text().as_deref(), Some("historical"));
}

#[test]
fn stale_or_distant_click_is_not_reused_as_a_double_click() {
    for replacement in [false, true] {
        let (mut app, shared) = app_with_primary_grid();
        let now = Instant::now();
        let pos = CellPos { col: 2, row: 0 };
        app.begin_local_selection_gesture(Some(pos), now);
        release(&mut app);
        if replacement {
            *shared.grid.lock().unwrap() = Some(Arc::new(grid("replacement", 20, 6, "fresh")));
        }
        app.begin_local_selection_gesture(
            Some(pos),
            now + Duration::from_millis(if replacement { 100 } else { 600 }),
        );
        release(&mut app);
        assert!(app.current_selection().is_none());
    }
}

#[test]
fn native_pointer_events_select_and_copy_word_and_intervening_press_breaks_chain() {
    let (mut app, shared) = app_with_primary_grid();
    app.host = Some(Box::new(RecordingNeutralHost {
        titles: Arc::new(Mutex::new(Vec::new())),
    }));
    app.test_cell_size_logical = Some((10.0, 20.0));
    let writes = super::copy_on_select::record_copies(&mut app);
    app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
    app.handle_host_event(HostEvent::CursorMoved { x: 25.0, y: 5.0 });
    assert_eq!(
        app.hit_test(app.cursor_px),
        Some(CellPos { col: 2, row: 0 })
    );
    let click = |app: &mut App, button| {
        for pressed in [true, false] {
            app.handle_host_event(HostEvent::MouseInput { button, pressed });
        }
    };
    click(&mut app, HostPointerButton::Left);
    assert!(writes.borrow().is_empty());
    click(&mut app, HostPointerButton::Left);
    assert_eq!(&*writes.borrow(), &["hello-primary"]);
    assert_eq!(app.selected_text().as_deref(), Some("hello-primary"));
    click(&mut app, HostPointerButton::Right);
    click(&mut app, HostPointerButton::Left);
    assert!(app.current_selection().is_none());
    assert_eq!(writes.borrow().len(), 1);
    assert!(shared.drain_test_requests().is_empty());
}
