use super::*;
use maestro_protocol::row_copy::RowCopy;

struct LinkHost(Arc<Mutex<Vec<String>>>);

impl HostServices for LinkHost {
    fn request_redraw(&self) {}
    fn inner_size(&self) -> (u32, u32) {
        (800, 600)
    }
    fn scale_factor(&self) -> f64 {
        1.0
    }
    fn set_cursor(&self, _icon: HostCursorIcon) {}
    fn set_title(&self, _title: &str) {}
    fn request_attention(&self) {}
    fn set_ime_allowed(&self, _allowed: bool) {}
    fn terminal_surface_scope(&self) -> TerminalSurfaceScope {
        TerminalSurfaceScope::TerminalSlot
    }
    fn open_http_url(&self, url: &str) -> bool {
        self.0.lock().unwrap().push(url.to_owned());
        true
    }
}

fn install_host(app: &mut App) -> Arc<Mutex<Vec<String>>> {
    let opened = Arc::new(Mutex::new(Vec::new()));
    app.host = Some(Box::new(LinkHost(opened.clone())));
    app.test_cell_size_logical = Some((10.0, 20.0));
    app.modifiers.super_key = cfg!(target_os = "macos");
    app.modifiers.control = !cfg!(target_os = "macos");
    opened
}

fn wrapped(mut value: GridSnapshot) -> GridSnapshot {
    let url = "https://example.test/a/long/path?q=42";
    assert!(value.cols < url.len() && value.cols * value.rows > url.len());
    value.rows_cells = vec![vec![cell(" "); value.cols]; value.rows];
    let mut metadata = vec![
        RowCopy {
            starts_line: Some(true),
            soft_wrap: false,
            excluded_columns: vec![]
        };
        value.rows
    ];
    for (index, ch) in url.chars().enumerate() {
        let row = index / value.cols;
        value.rows_cells[row][index % value.cols] = cell(&ch.to_string());
        if row > 0 {
            metadata[row - 1].soft_wrap = true;
            metadata[row].starts_line = Some(false);
        }
    }
    value.row_copy = Some(metadata);
    value
}

fn click(app: &mut App, row: usize, col: usize) {
    app.handle_host_event(HostEvent::CursorMoved {
        x: col as f64 * 10.0 + 5.0,
        y: row as f64 * 20.0 + 5.0,
    });
    for pressed in [true, false] {
        app.handle_host_event(HostEvent::MouseInput {
            button: HostPointerButton::Left,
            pressed,
        });
    }
}

#[test]
fn modifier_click_uses_complete_wrapped_url_from_painted_history() {
    let (mut app, shared) = app_with_primary_grid();
    let opened = install_host(&mut app);
    {
        let mut history = shared.scrollback.lock().unwrap();
        history.view_offset = 1;
        history.history_len = Some(1);
        history.historical = Some(crate::client::HistoricalView::new(
            Arc::new(wrapped(grid("primary-gen", 20, 6, ""))),
            1,
            1,
        ));
    }
    click(&mut app, 1, 2);
    assert_eq!(
        &*opened.lock().unwrap(),
        &["https://example.test/a/long/path?q=42"]
    );
    assert!(
        shared.drain_test_requests().is_empty(),
        "link click sends no PTY input"
    );
    assert!(app.current_selection().is_none());
}

#[test]
fn modifier_click_uses_pointer_pane_and_keeps_highlight_inside_its_content() {
    let (mut app, shared, origin) = app_with_right_child();
    let opened = install_host(&mut app);
    let child = app.focused_pane_grid("child").unwrap();
    let cols = child.cols;
    let epoch = shared.pane_epoch("child").unwrap();
    assert!(shared.apply_pane_grid("child", epoch, Arc::new(wrapped((*child).clone()))));
    app.focused_pane_session = Some("primary".into());
    shared.drain_test_requests();
    click(&mut app, origin.row + 1, origin.col + 2);
    assert_eq!(
        &*opened.lock().unwrap(),
        &["https://example.test/a/long/path?q=42"]
    );
    let hover = app.hovered_terminal_link.as_ref().unwrap();
    assert_eq!(hover.highlight.row, origin.row + 1);
    assert!(hover.highlight.start_col >= origin.col);
    assert!(hover.highlight.end_col <= origin.col + cols);
    assert!(
        shared.drain_test_requests().is_empty(),
        "link click sends no PTY input"
    );
}
