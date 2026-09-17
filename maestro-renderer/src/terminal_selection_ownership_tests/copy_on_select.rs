use super::*;
use std::cell::RefCell;
use std::rc::Rc;

struct ClipboardRecorder(Rc<RefCell<Vec<String>>>);

#[cfg(target_os = "linux")]
impl crate::host_services::TerminalClipboardHostServices for ClipboardRecorder {
    fn request_text(&self, _: u64) {}

    fn set_text(&self, text: &str) -> bool {
        self.0.borrow_mut().push(text.to_string());
        true
    }

    fn show_context_menu(&self, _: bool) -> bool {
        false
    }
}

#[cfg(not(target_os = "linux"))]
impl crate::Clipboard for ClipboardRecorder {
    fn read_text(&mut self) -> Option<String> {
        None
    }

    fn write_text(&mut self, text: String) -> bool {
        self.0.borrow_mut().push(text);
        true
    }
}

pub(super) fn record_copies(app: &mut App) -> Rc<RefCell<Vec<String>>> {
    let writes = Rc::new(RefCell::new(Vec::new()));
    let recorder = ClipboardRecorder(writes.clone());
    #[cfg(target_os = "linux")]
    {
        app.clipboard_host = Some(Rc::new(recorder));
    }
    #[cfg(not(target_os = "linux"))]
    {
        app.clipboard = Box::new(recorder);
    }
    writes
}

fn drag(app: &mut App, end: CellPos) {
    app.begin_local_selection(Some(CellPos { col: 0, row: 0 }));
    app.sel_focus = Some(end);
}

fn release(app: &mut App) {
    app.handle_host_event(HostEvent::MouseInput {
        button: HostPointerButton::Left,
        pressed: false,
    });
}

#[test]
fn explicit_copy_uses_same_owner_live_or_history_row_metadata() {
    use maestro_protocol::row_copy::RowCopy;
    for historical in [false, true] {
        let (mut app, shared) = app_with_primary_grid();
        let writes = record_copies(&mut app);
        let mut selected_grid = grid("primary-gen", 20, 6, "ABCDEFGHIJKLMNOPQRS ");
        selected_grid.rows_cells[1][0] = cell("界");
        selected_grid.rows_cells[1][0].width = 2;
        selected_grid.rows_cells[1][1] = cell("");
        selected_grid.rows_cells[1][1].width = 0;
        selected_grid.rows_cells[1][2] = cell("x");
        let mut rows = vec![
            RowCopy {
                starts_line: None,
                soft_wrap: false,
                excluded_columns: vec![]
            };
            6
        ];
        rows[0].soft_wrap = true;
        rows[0].excluded_columns = vec![19];
        rows[1].starts_line = Some(false);
        selected_grid.row_copy = Some(rows);
        if historical {
            let mut scrollback = shared.scrollback.lock().unwrap();
            scrollback.view_offset = 1;
            scrollback.history_len = Some(1);
            scrollback.historical = Some(crate::client::HistoricalView::new(
                Arc::new(selected_grid),
                1,
                1,
            ));
        } else {
            *shared.grid.lock().unwrap() = Some(Arc::new(selected_grid));
        }
        drag(&mut app, CellPos { col: 2, row: 1 });
        app.copy_selection();
        assert_eq!(&*writes.borrow(), &["ABCDEFGHIJKLMNOPQRS界x"]);
        assert!(shared.drain_test_requests().is_empty());
    }
}

#[test]
fn copy_on_select_typed_command_preserves_both_choices() {
    for enabled in [false, true] {
        assert!(matches!(
            crate::user_event_for_command(crate::RendererCommand::SetCopyOnSelect { enabled }),
            UserEvent::SetCopyOnSelect { enabled: received } if received == enabled
        ));
    }
}

#[test]
fn copy_on_select_is_off_by_default_and_disabling_preserves_explicit_copy() {
    let (mut app, shared) = app_with_primary_grid();
    let writes = record_copies(&mut app);
    assert!(!app.copy_on_select);
    drag(&mut app, CellPos { col: 5, row: 0 });
    release(&mut app);
    assert!(writes.borrow().is_empty());
    app.copy_selection();
    assert_eq!(writes.borrow().len(), 1);
    app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
    app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: false });
    drag(&mut app, CellPos { col: 5, row: 0 });
    release(&mut app);
    assert_eq!(writes.borrow().len(), 1);
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn copy_on_select_matches_explicit_copy_for_live_and_historical_cells() {
    for historical in [false, true] {
        let (mut app, shared) = app_with_primary_grid();
        let writes = record_copies(&mut app);
        let mut selected_grid = grid("primary-gen", 20, 6, "A");
        let cells = &mut selected_grid.rows_cells[0];
        cells[1] = cell("界");
        cells[1].width = 2;
        cells[2] = cell("");
        cells[2].width = 0;
        cells[3] = cell("secret");
        cells[3].hidden = true;
        cells[4] = cell("B");
        selected_grid.rows_cells[1][0] = cell("C");
        if historical {
            let mut scrollback = shared.scrollback.lock().unwrap();
            scrollback.view_offset = 1;
            scrollback.history_len = Some(1);
            scrollback.historical = Some(crate::client::HistoricalView::new(
                Arc::new(selected_grid),
                1,
                1,
            ));
        } else {
            *shared.grid.lock().unwrap() = Some(Arc::new(selected_grid));
        }
        let end = CellPos { col: 19, row: 1 };
        drag(&mut app, end);
        let expected = app.selected_text().expect("painted cells selected");
        assert!(expected.contains('界'));
        assert!(expected.contains('C'));
        // Keep the explicit-copy serializer's handling of hidden cells unchanged too.
        assert!(expected.lines().all(|line| !line.ends_with(' ')));
        app.copy_selection();
        app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
        drag(&mut app, end);
        release(&mut app);
        assert_eq!(&*writes.borrow(), &[expected.clone(), expected]);
        release(&mut app);
        assert_eq!(writes.borrow().len(), 2, "duplicate release is not a drag");
        assert!(shared.drain_test_requests().is_empty());
    }
}

#[test]
fn copy_on_select_ignores_click_empty_and_stale_owner() {
    let (mut app, shared) = app_with_primary_grid();
    let writes = record_copies(&mut app);
    app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
    drag(&mut app, CellPos { col: 0, row: 0 });
    release(&mut app);
    assert!(app.current_selection().is_none());
    app.begin_local_selection(Some(CellPos { col: 0, row: 2 }));
    app.sel_focus = Some(CellPos { col: 5, row: 2 });
    release(&mut app);
    drag(&mut app, CellPos { col: 5, row: 0 });
    *shared.grid.lock().unwrap() = Some(Arc::new(grid("replaced-gen", 20, 6, "other")));
    release(&mut app);
    assert!(writes.borrow().is_empty());
}

#[test]
fn copy_on_select_never_copies_a_tui_owned_release_or_a_stale_drag() {
    let (mut app, shared) = app_with_primary_grid();
    let writes = record_copies(&mut app);
    app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
    drag(&mut app, CellPos { col: 5, row: 0 });
    let mut reporting = grid("primary-gen", 20, 6, "hello-primary");
    reporting.mouse_report = true;
    *shared.grid.lock().unwrap() = Some(Arc::new(reporting));
    assert!(app.mouse_reporting_active());
    release(&mut app);
    assert!(!app.copy_drag_started);
    assert!(writes.borrow().is_empty());
    app.modifiers.shift = true;
    release(&mut app);
    assert!(
        writes.borrow().is_empty(),
        "a mode change cannot reuse an old drag"
    );
    app.modifiers.shift = false;
    app.handle_host_event(HostEvent::MouseInput {
        button: HostPointerButton::Left,
        pressed: true,
    });
    release(&mut app);
    assert!(writes.borrow().is_empty());
    assert!(!app.copy_drag_started);
    app.modifiers.shift = true;
    drag(&mut app, CellPos { col: 5, row: 0 });
    release(&mut app);
    assert_eq!(
        writes.borrow().len(),
        1,
        "a fresh Shift override is Hydra-owned"
    );
}

#[test]
fn copy_on_select_does_not_add_middle_click_copy_or_paste() {
    let (mut app, shared) = app_with_primary_grid();
    let writes = record_copies(&mut app);
    app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
    drag(&mut app, CellPos { col: 5, row: 0 });
    release(&mut app);
    for pressed in [true, false] {
        app.handle_host_event(HostEvent::MouseInput {
            button: HostPointerButton::Middle,
            pressed,
        });
    }
    assert_eq!(writes.borrow().len(), 1);
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn copy_on_select_copies_an_explicit_single_character_word_once() {
    let (mut app, shared) = app_with_primary_grid();
    let writes = record_copies(&mut app);
    *shared.grid.lock().unwrap() = Some(Arc::new(grid("primary-gen", 20, 6, "x y")));
    app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
    let now = Instant::now();
    let pos = CellPos { col: 0, row: 0 };
    app.begin_local_selection_gesture(Some(pos), now);
    release(&mut app);
    assert!(writes.borrow().is_empty());
    app.begin_local_selection_gesture(Some(pos), now + Duration::from_millis(100));
    release(&mut app);
    assert_eq!(&*writes.borrow(), &["x"]);
    release(&mut app);
    assert_eq!(writes.borrow().len(), 1);
    app.begin_local_selection_gesture(
        Some(CellPos { col: 2, row: 0 }),
        now + Duration::from_millis(700),
    );
    release(&mut app);
    assert_eq!(writes.borrow().len(), 1);
}
