use super::*;
use maestro_protocol::row_copy::RowCopy;

fn clicks(app: &mut App, pos: CellPos, count: u32) {
    let now = Instant::now();
    for index in 0..count {
        app.begin_local_selection_gesture(
            Some(pos),
            now + Duration::from_millis(100 * index as u64),
        );
        app.handle_host_event(HostEvent::MouseInput {
            button: HostPointerButton::Left,
            pressed: false,
        });
    }
}

fn wrapped_grid() -> crate::wire::GridSnapshot {
    let mut value = grid("primary-gen", 20, 6, "before");
    for (row, text) in [
        (1, "one two three four  "),
        (2, "five six seven eight"),
        (3, " nine"),
        (4, "after"),
    ] {
        for (col, character) in text.chars().enumerate() {
            value.rows_cells[row][col] = cell(&character.to_string());
        }
    }
    let mut metadata = vec![
        RowCopy {
            starts_line: Some(true),
            soft_wrap: false,
            excluded_columns: vec![],
        };
        6
    ];
    metadata[1].soft_wrap = true;
    metadata[2].starts_line = Some(false);
    metadata[2].soft_wrap = true;
    metadata[3].starts_line = Some(false);
    value.row_copy = Some(metadata);
    value
}

#[test]
fn native_three_clicks_copy_the_proven_logical_line_without_daemon_input() {
    let (mut app, shared) = app_with_primary_grid();
    *shared.grid.lock().unwrap() = Some(Arc::new(wrapped_grid()));
    app.host = Some(Box::new(RecordingNeutralHost {
        titles: Arc::new(Mutex::new(Vec::new())),
    }));
    app.test_cell_size_logical = Some((10.0, 20.0));
    let writes = super::copy_on_select::record_copies(&mut app);
    app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
    app.handle_host_event(HostEvent::CursorMoved { x: 55.0, y: 45.0 });
    assert_eq!(
        app.hit_test(app.cursor_px),
        Some(CellPos { col: 5, row: 2 })
    );
    for _ in 0..3 {
        for pressed in [true, false] {
            app.handle_host_event(HostEvent::MouseInput {
                button: HostPointerButton::Left,
                pressed,
            });
        }
    }
    let expected = "one two three four  five six seven eight nine";
    assert_eq!(app.selected_text().as_deref(), Some(expected));
    assert_eq!(&*writes.borrow(), &["six", expected]);
    for pressed in [true, false] {
        app.handle_host_event(HostEvent::MouseInput {
            button: HostPointerButton::Left,
            pressed,
        });
    }
    assert!(
        app.current_selection().is_none(),
        "fourth click starts a new chain"
    );
    assert_eq!(writes.borrow().len(), 2);
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn logical_boundaries_require_the_same_complete_valid_snapshot() {
    let pos = CellPos { col: 5, row: 2 };
    let range = crate::terminal_selection::logical_line_range;
    let original = wrapped_grid();
    assert_eq!(
        range(&original, pos),
        Some((CellPos { col: 0, row: 1 }, CellPos { col: 19, row: 3 }))
    );
    for row in [0, 4] {
        assert_eq!(
            range(&original, CellPos { col: 2, row }),
            Some((CellPos { col: 0, row }, CellPos { col: 19, row }))
        );
    }
    for case in 0..7 {
        let mut value = wrapped_grid();
        match case {
            0 => value.row_copy = None,
            1 => value.row_copy.as_mut().unwrap()[1].starts_line = None,
            2 => value.row_copy.as_mut().unwrap()[2].starts_line = Some(true),
            3 => value.row_copy.as_mut().unwrap()[1].excluded_columns = vec![0],
            4 => {
                value.row_copy.as_mut().unwrap().pop();
            }
            5 => {
                value.rows_cells[0].pop();
            }
            _ => {
                value.rows = 3;
                value.rows_cells.truncate(3);
                value.row_copy.as_mut().unwrap().truncate(3);
            }
        }
        assert_eq!(
            range(&value, pos),
            Some((CellPos { col: 0, row: 2 }, CellPos { col: 19, row: 2 })),
            "fallback case {case}"
        );
    }
    let mut wide = wrapped_grid();
    wide.row_copy.as_mut().unwrap()[1].excluded_columns = vec![19];
    wide.rows_cells[2][0] = cell("界");
    wide.rows_cells[2][0].width = 2;
    wide.rows_cells[2][1] = cell("");
    wide.rows_cells[2][1].width = 0;
    let (a, b) = range(&wide, pos).unwrap();
    assert_eq!(
        crate::client::extract_grid_selection(&wide, a, b),
        "one two three four 界ve six seven eight nine"
    );
    assert!(range(&wide, CellPos { col: 20, row: 2 }).is_none());
}

#[test]
fn logical_line_drag_preserves_whole_units_and_shift_remains_characterwise() {
    let (mut app, shared) = app_with_primary_grid();
    *shared.grid.lock().unwrap() = Some(Arc::new(wrapped_grid()));
    clicks(&mut app, CellPos { col: 5, row: 2 }, 3);
    let line = app.selected_text().unwrap();
    app.extend_local_selection(Some(CellPos { col: 9, row: 2 }));
    assert_eq!(app.selected_text().as_deref(), Some(line.as_str()));
    app.extend_local_selection(Some(CellPos { col: 2, row: 4 }));
    assert_eq!(app.selected_text(), Some(format!("{line}\nafter")));
    app.extend_local_selection(Some(CellPos { col: 2, row: 0 }));
    assert_eq!(app.selected_text(), Some(format!("before\n{line}")));
    app.modifiers.shift = true;
    app.begin_local_selection_gesture(Some(CellPos { col: 2, row: 4 }), Instant::now());
    assert!(app.sel_unit_anchor.is_none());
    assert_eq!(app.sel_focus, Some(CellPos { col: 2, row: 4 }));
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn triple_click_uses_painted_history_and_split_owner_not_primary() {
    let (mut app, shared) = app_with_primary_grid();
    {
        let mut history = shared.scrollback.lock().unwrap();
        history.view_offset = 1;
        history.history_len = Some(1);
        history.historical_generation = Some(SessionGeneration("primary-gen".into()));
        history.historical = Some(Arc::new(wrapped_grid()));
    }
    clicks(&mut app, CellPos { col: 5, row: 2 }, 3);
    assert_eq!(app.sel_anchor, Some(CellPos { col: 0, row: 1 }));
    assert!(app.selected_text().unwrap().starts_with("one two"));
    assert!(shared.drain_test_requests().is_empty());

    let (mut app, shared, origin) = app_with_right_child();
    let child = app.focused_pane_grid("child").unwrap();
    let expected = crate::client::extract_grid_selection(
        &child,
        CellPos { col: 0, row: 0 },
        CellPos {
            col: child.cols - 1,
            row: 0,
        },
    );
    clicks(&mut app, origin, 3);
    assert_eq!(app.selected_text().as_deref(), Some(expected.as_str()));
    assert_eq!(app.sel_anchor, Some(origin));
    assert_eq!(
        app.sel_focus,
        Some(CellPos {
            col: origin.col + child.cols - 1,
            row: origin.row
        })
    );
    app.focused_pane_session = Some("primary".into());
    assert!(app.current_selection().is_none());
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn changed_generation_cannot_complete_an_old_three_click_chain() {
    let (mut app, shared) = app_with_primary_grid();
    let pos = CellPos { col: 5, row: 2 };
    *shared.grid.lock().unwrap() = Some(Arc::new(wrapped_grid()));
    clicks(&mut app, pos, 2);
    let mut replacement = wrapped_grid();
    replacement.generation = SessionGeneration("replacement".into());
    *shared.grid.lock().unwrap() = Some(Arc::new(replacement));
    clicks(&mut app, pos, 1);
    assert!(app.current_selection().is_none());
    assert!(shared.drain_test_requests().is_empty());
}
