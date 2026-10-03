use super::*;
use crate::client::{HistoryRequestIntent, ScrollAction};
use crate::selection_span::{Acquisition, Failure, PageResult};
use crate::terminal_selection::ScrolledSelection;
use maestro_protocol::row_copy::RowCopy;

fn numbered(start: i64, rows: usize) -> GridSnapshot {
    let mut value = grid("primary-gen", 20, rows, "");
    for (index, row) in value.rows_cells.iter_mut().enumerate() {
        for (col, ch) in format!("r{:05}", 5000 + start + index as i64)
            .chars()
            .enumerate()
        {
            row[col] = cell(&ch.to_string());
        }
    }
    value.row_copy = Some(vec![
        RowCopy {
            starts_line: Some(true),
            soft_wrap: false,
            excluded_columns: vec![]
        };
        rows
    ]);
    value
}

fn start_span(offset: u32) -> (App, Arc<Shared>, Arc<GridSnapshot>) {
    let (mut app, shared) = app_with_primary_grid();
    *shared.grid.lock().unwrap() = Some(Arc::new(numbered(0, 6)));
    app.begin_local_selection(Some(CellPos { col: 5, row: 0 }));
    app.extend_local_selection(Some(CellPos { col: 0, row: 0 }));
    app.selecting = false;
    assert_eq!(app.selected_text().as_deref(), Some("r05000"));
    shared.scrollback.lock().unwrap().history_len = Some(5000);
    app.apply_scroll(ScrollAction::Lines(i64::from(offset)));
    let binding = shared.binding_token_for_session("primary").unwrap();
    assert_eq!(shared.drain_test_requests().len(), 1);
    assert!(shared.commit_test_history_reply(
        &binding,
        numbered(-i64::from(offset), 6),
        5000,
        offset
    ));
    let painted = shared
        .scrollback
        .lock()
        .unwrap()
        .historical
        .as_ref()
        .unwrap()
        .grid
        .clone();
    app.modifiers.shift = true;
    app.begin_local_selection_gesture(Some(CellPos { col: 0, row: 0 }), Instant::now());
    (app, shared, painted)
}

fn deliver(app: &mut App, shared: &Shared, revision: u64, short_rows: Option<usize>) {
    let pending = app.sel_span.as_ref().unwrap();
    let request = pending.request.clone();
    let mut page = numbered(
        -i64::from(request.offset),
        short_rows.unwrap_or(usize::from(request.count)),
    );
    page.revision = Revision(revision);
    assert!(
        !shared.commit_test_history_reply(&pending.binding, page, 5000, request.offset),
        "selection reply must not request a viewport repaint"
    );
    app.handle_user_event(UserEvent::OutboundWritable);
}

#[test]
fn selection_span_over_256_rows_replaces_atomically_without_viewport_mutation() {
    let (mut app, shared, painted) = start_span(400);
    assert!(matches!(
        shared.drain_test_requests().as_slice(),
        [ClientRequest::Scrollback {
            offset_from_top: 400,
            count: 256,
            ..
        }]
    ));
    deliver(&mut app, &shared, 1, None);
    assert_eq!(
        app.selected_text().as_deref(),
        Some("r05000"),
        "no partial copy after first page"
    );
    assert!(matches!(
        shared.drain_test_requests().as_slice(),
        [ClientRequest::Scrollback {
            offset_from_top: 144,
            count: 145,
            ..
        }]
    ));
    deliver(&mut app, &shared, 1, None);
    assert_eq!(app.sel_span_outcome, Some(Ok(())));
    assert_eq!(
        app.selected_text(),
        Some(
            (4600..=5000)
                .map(|row| format!("r{row:05}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
    );
    let scrollback = shared.scrollback.lock().unwrap();
    assert_eq!(scrollback.view_offset, 400);
    assert_eq!(scrollback.history_len, Some(5000));
    assert!(Arc::ptr_eq(
        &painted,
        &scrollback.historical.as_ref().unwrap().grid
    ));
    assert!(shared.drain_test_requests().is_empty());
}

#[test]
fn selection_span_stale_second_page_keeps_original_copy_and_anchor() {
    let (mut app, shared, _) = start_span(400);
    let anchor = app.sel_anchor;
    shared.drain_test_requests();
    deliver(&mut app, &shared, 1, None);
    shared.drain_test_requests();
    deliver(&mut app, &shared, 2, None);
    assert_eq!(app.selected_text().as_deref(), Some("r05000"));
    assert_eq!(app.sel_anchor, anchor);
    assert_eq!(app.sel_span_outcome, Some(Err(Failure::Stale)));
    assert!(app.sel_span.is_none());
    assert!(shared.scrollback.lock().unwrap().admitted_request.is_none());
}

#[test]
fn selection_span_cancelled_admitted_page_retires_before_new_view() {
    let (mut app, shared, _) = start_span(400);
    let request = app.sel_span.as_ref().unwrap().request.clone();
    let binding = app.sel_span.as_ref().unwrap().binding.clone();
    shared.drain_test_requests();
    app.cancel_selection_span(Failure::Cancelled);
    assert_eq!(app.selected_text().as_deref(), Some("r05000"));
    assert_eq!(
        shared.scrollback.lock().unwrap().admitted_request,
        Some(HistoryRequestIntent::Selection(request.clone()))
    );
    app.apply_scroll(ScrollAction::Lines(2));
    assert!(
        shared.drain_test_requests().is_empty(),
        "one FIFO slot remains occupied"
    );
    assert!(!shared.commit_test_history_reply(&binding, numbered(-400, 256), 5000, 400));
    app.handle_user_event(UserEvent::OutboundWritable);
    assert!(matches!(
        shared.drain_test_requests().as_slice(),
        [ClientRequest::Scrollback {
            offset_from_top: 402,
            count: 6,
            ..
        }]
    ));
    assert_eq!(app.selected_text().as_deref(), Some("r05000"));
}

#[test]
fn selection_span_pages_and_foreground_scroll_do_not_coalesce_each_other() {
    let (mut app, shared, _) = start_span(400);
    shared.drain_test_requests();
    app.apply_scroll(ScrollAction::Lines(1));
    app.apply_scroll(ScrollAction::Lines(1));
    assert_eq!(
        app.pending_owner_requests.len(),
        1,
        "only foreground scroll coalesces"
    );
    deliver(&mut app, &shared, 1, None);
    assert!(matches!(
        shared.drain_test_requests().as_slice(),
        [ClientRequest::Scrollback {
            offset_from_top: 402,
            count: 6,
            ..
        }]
    ));
    assert_eq!(
        app.pending_owner_requests.len(),
        1,
        "selection's second page remains queued"
    );
    let binding = shared.binding_token_for_session("primary").unwrap();
    assert!(shared.commit_test_history_reply(&binding, numbered(-402, 6), 5000, 402));
    app.handle_user_event(UserEvent::OutboundWritable);
    assert!(matches!(
        shared.drain_test_requests().as_slice(),
        [ClientRequest::Scrollback {
            offset_from_top: 144,
            count: 145,
            ..
        }]
    ));
    deliver(&mut app, &shared, 1, None);
    assert_eq!(app.sel_span_outcome, Some(Ok(())));
    assert_eq!(shared.scrollback.lock().unwrap().view_offset, 402);
    assert_eq!(app.selected_text().unwrap().lines().count(), 401);
}

fn acquisition(
    source_offset: u32,
    source_rows: usize,
    end_offset: u32,
    end_rows: usize,
    end_row: usize,
) -> Acquisition {
    let source = ScrolledSelection {
        grid: Arc::new(numbered(-i64::from(source_offset), source_rows)),
        served_offset: source_offset,
        origin: CellPos { col: 0, row: 0 },
        live_alt_screen: false,
    };
    Acquisition::new(
        1,
        source,
        CellPos { col: 0, row: 0 },
        Arc::new(numbered(-i64::from(end_offset), end_rows)),
        end_offset,
        CellPos {
            col: 5,
            row: end_row,
        },
    )
    .unwrap()
}

fn accept(acquisition: &mut Acquisition, rows: usize) -> Result<(), Failure> {
    let request = acquisition.request().unwrap();
    let grid = numbered(-i64::from(request.offset), rows);
    acquisition.accept(PageResult {
        request,
        history_len: 5000,
        result: Ok(Arc::new(grid)),
    })
}

#[test]
fn selection_span_short_page_then_offset_zero_overlap_has_no_duplicates() {
    let mut pages = acquisition(5, 6, 0, 40, 20);
    assert_eq!(pages.request().unwrap().count, 26);
    accept(&mut pages, 10).unwrap();
    let next = pages.request().unwrap();
    assert_eq!((next.offset, next.count), (0, 21));
    accept(&mut pages, 21).unwrap();
    let (source, anchor, focus) = pages.finish().unwrap();
    assert_eq!(source.grid.rows, 26);
    let copied = crate::client::extract_grid_selection(&source.grid, anchor, focus);
    assert_eq!(
        copied,
        (4995..=5020)
            .map(|row| format!("r{row:05}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn selection_span_large_live_tail_uses_only_frozen_exact_pixels() {
    let mut pages = acquisition(0, 6, 0, 600, 500);
    accept(&mut pages, 256).unwrap();
    assert!(pages.request().is_none());
    let (source, _, _) = pages.finish().unwrap();
    assert_eq!(source.grid.rows, 501);
}

#[test]
fn selection_span_cell_limited_zero_offset_uses_frozen_positive_tail_without_retry() {
    let mut pages = acquisition(0, 6, 0, 201, 200);
    assert_eq!(pages.request().unwrap().count, 201);
    accept(&mut pages, 16).unwrap();
    assert!(
        pages.request().is_none(),
        "positive tail cannot be addressed by another offset0 query"
    );
    let (source, anchor, focus) = pages.finish().unwrap();
    assert_eq!(source.grid.rows, 201);
    assert_eq!(
        crate::client::extract_grid_selection(&source.grid, anchor, focus)
            .lines()
            .count(),
        201
    );

    let mut pages = acquisition(5, 6, 0, 201, 200);
    accept(&mut pages, 25).unwrap(); // -5 through19; the next query must begin at0 again.
    assert_eq!(pages.request().unwrap().offset, 0);
    accept(&mut pages, 16).unwrap(); // Short prefix does not even reach the already acquired row20.
    assert!(pages.request().is_none());
    assert_eq!(pages.finish().unwrap().0.grid.rows, 206);
}

#[test]
fn selection_span_unknown_seam_and_changed_depth_are_rejected() {
    for changed_depth in [false, true] {
        let mut pages = acquisition(400, 6, 0, 6, 0);
        accept(&mut pages, 256).unwrap();
        let request = pages.request().unwrap();
        let mut grid = numbered(-i64::from(request.offset), usize::from(request.count));
        if !changed_depth {
            grid.row_copy.as_mut().unwrap()[0].starts_line = None;
        }
        assert_eq!(
            pages.accept(PageResult {
                request,
                history_len: if changed_depth { 4999 } else { 5000 },
                result: Ok(Arc::new(grid))
            }),
            Err(if changed_depth {
                Failure::Stale
            } else {
                Failure::InvalidPage
            })
        );
        assert!(pages.finish().is_none());
    }
}

#[test]
fn selection_span_new_gesture_revokes_old_reply_without_losing_fifo() {
    let (mut app, shared, _) = start_span(400);
    let old = app.sel_span.as_ref().unwrap().request.clone();
    let binding = app.sel_span.as_ref().unwrap().binding.clone();
    shared.drain_test_requests();
    // A second Shift endpoint supersedes the first ticket, but cannot reuse its admitted slot.
    app.begin_local_selection_gesture(Some(CellPos { col: 0, row: 1 }), Instant::now());
    let new_ticket = app.sel_span.as_ref().unwrap().request.ticket;
    assert_ne!(old.ticket, new_ticket);
    assert!(shared.drain_test_requests().is_empty());
    assert_eq!(app.pending_owner_requests.len(), 1);
    assert!(!shared.commit_test_history_reply(&binding, numbered(-400, 256), 5000, 400));
    app.handle_user_event(UserEvent::OutboundWritable);
    assert_eq!(app.sel_span.as_ref().unwrap().request.ticket, new_ticket);
    assert_eq!(app.selected_text().as_deref(), Some("r05000"));
    assert!(matches!(
        shared.drain_test_requests().as_slice(),
        [ClientRequest::Scrollback {
            offset_from_top: 399,
            count: 256,
            ..
        }]
    ));
    deliver(&mut app, &shared, 1, None);
    shared.drain_test_requests();
    deliver(&mut app, &shared, 1, None);
    assert_eq!(app.sel_span_outcome, Some(Ok(())));
    assert_eq!(app.selected_text().unwrap().lines().count(), 400);
}

#[test]
fn selection_span_cancel_removes_queued_page_without_cancelling_view_request() {
    let (mut app, shared, _) = start_span(400);
    shared.drain_test_requests();
    app.apply_scroll(ScrollAction::Lines(1));
    deliver(&mut app, &shared, 1, None);
    shared.drain_test_requests();
    assert_eq!(app.pending_owner_requests.len(), 1);
    app.cancel_selection_span(Failure::Cancelled);
    assert!(app.pending_owner_requests.is_empty());
    assert_eq!(app.pending_owner_request_bytes, 0);
    assert!(matches!(
        shared.scrollback.lock().unwrap().admitted_request,
        Some(HistoryRequestIntent::View(_))
    ));
    assert_eq!(app.selected_text().as_deref(), Some("r05000"));
}

#[test]
fn selection_span_real_generation_or_screen_transition_revokes_pending_copy() {
    for screen in [false, true] {
        let (mut app, shared, _) = start_span(400);
        let mut replacement = numbered(0, 6);
        if screen {
            replacement.alt_screen = true;
        } else {
            replacement.generation = SessionGeneration("replacement".into());
        }
        *shared.grid.lock().unwrap() = Some(Arc::new(replacement));
        app.poll_selection_span();
        assert!(app.sel_span.is_none());
        assert_eq!(app.sel_span_outcome, Some(Err(Failure::Stale)));
        assert!(app.selected_text().is_none());
    }
}

#[test]
fn selection_span_malformed_or_missing_rows_never_publish_partial_copy() {
    for corruption in 0..4 {
        let (mut app, shared, painted) = start_span(400);
        let pending = app.sel_span.as_ref().unwrap();
        let mut page = numbered(-400, 256);
        let offset = if corruption == 0 { 399 } else { 400 };
        if corruption == 1 {
            page.row_copy = None;
        }
        if corruption == 2 {
            page.rows_cells[0].pop();
        }
        if corruption == 3 {
            page.rows_cells.clear();
            page.row_copy = Some(vec![]);
        }
        assert!(!shared.commit_test_history_reply(&pending.binding, page, 5000, offset));
        app.handle_user_event(UserEvent::OutboundWritable);
        assert_eq!(app.sel_span_outcome, Some(Err(Failure::InvalidPage)));
        assert_eq!(app.selected_text().as_deref(), Some("r05000"));
        assert!(Arc::ptr_eq(
            &painted,
            &shared
                .scrollback
                .lock()
                .unwrap()
                .historical
                .as_ref()
                .unwrap()
                .grid
        ));
    }
}

#[test]
fn selection_span_wrap_and_wide_glyph_at_page_seam_keep_exact_copy() {
    let mut pages = acquisition(400, 6, 0, 6, 0);
    let first = pages.request().unwrap();
    let mut grid = numbered(-400, 256);
    grid.rows_cells[255] = "ABCDEFGHIJKLMNOPQRS "
        .chars()
        .map(|ch| cell(&ch.to_string()))
        .collect();
    grid.row_copy.as_mut().unwrap()[255].soft_wrap = true;
    grid.row_copy.as_mut().unwrap()[255].excluded_columns = vec![19];
    pages
        .accept(PageResult {
            request: first,
            history_len: 5000,
            result: Ok(Arc::new(grid)),
        })
        .unwrap();
    let request = pages.request().unwrap();
    let mut grid = numbered(-144, usize::from(request.count));
    grid.rows_cells[0] = vec![cell(" "); 20];
    grid.rows_cells[0][0] = cell("界");
    grid.rows_cells[0][0].width = 2;
    grid.rows_cells[0][1] = cell("");
    grid.rows_cells[0][1].width = 0;
    grid.row_copy.as_mut().unwrap()[0].starts_line = Some(false);
    pages
        .accept(PageResult {
            request,
            history_len: 5000,
            result: Ok(Arc::new(grid)),
        })
        .unwrap();
    let (source, anchor, focus) = pages.finish().unwrap();
    let copied = crate::client::extract_grid_selection(&source.grid, anchor, focus);
    assert!(copied.contains("ABCDEFGHIJKLMNOPQRS界\n"));
    assert!(!copied.contains("ABCDEFGHIJKLMNOPQRS \n"));
    assert_eq!(copied.lines().count(), 400);
}

#[test]
fn selection_span_request_count_is_part_of_exact_admission() {
    let (mut app, shared, _) = start_span(400);
    let pending = app.sel_span.as_ref().unwrap();
    let binding = pending.binding.clone();
    let request = pending.request.clone();
    app.cancel_selection_span(Failure::Cancelled);
    shared.scrollback.lock().unwrap().admitted_request = None;
    let admission = shared
        .send_history_batch_for_binding(
            &binding,
            &[ClientRequest::Scrollback {
                id: "primary".into(),
                offset_from_top: 400,
                count: 255,
            }],
            &request.generation,
            Some(&HistoryRequestIntent::Selection(request.clone())),
        )
        .unwrap();
    assert!(!admission.is_admitted());
    assert!(shared.scrollback.lock().unwrap().admitted_request.is_none());
}

#[test]
fn selection_span_secondary_pane_reply_cannot_mutate_primary_or_survive_focus_change() {
    let (mut app, shared, origin) = app_with_right_child();
    app.sync_pane_cache();
    shared.drain_test_requests();
    let child = shared.pane_paint("child", "primary").paint_grid().unwrap();
    let make_child = |start, rows| {
        let mut value = numbered(start, rows);
        value.cols = child.cols;
        value.generation = child.generation.clone();
        for row in &mut value.rows_cells {
            row.resize(child.cols, cell(" "));
        }
        value
    };
    let epoch = shared.pane_epoch("child").unwrap();
    assert!(shared.apply_pane_grid("child", epoch, Arc::new(make_child(0, child.rows))));
    app.begin_local_selection(Some(CellPos {
        col: origin.col + 5,
        row: origin.row,
    }));
    app.extend_local_selection(Some(origin));
    app.selecting = false;
    assert_eq!(app.selected_text().as_deref(), Some("r05000"));
    shared.with_pane_scrollback("child", "primary", |sb| sb.history_len = Some(5000));
    app.apply_scroll(ScrollAction::Lines(400));
    shared.drain_test_requests();
    let binding = shared.binding_token_for_session("child").unwrap();
    assert!(shared.commit_test_history_reply(&binding, make_child(-400, child.rows), 5000, 400));
    app.modifiers.shift = true;
    app.begin_local_selection_gesture(Some(origin), Instant::now());
    assert!(
        matches!(shared.drain_test_requests().as_slice(), [ClientRequest::Scrollback {
        id, offset_from_top: 400, count: 256,
    }] if id == "child")
    );
    assert!(!shared.commit_test_history_reply(&binding, make_child(-400, 256), 5000, 400));
    app.handle_user_event(UserEvent::OutboundWritable);
    shared.drain_test_requests();
    assert!(!shared.commit_test_history_reply(&binding, make_child(-144, 145), 5000, 144));
    app.handle_user_event(UserEvent::OutboundWritable);
    assert_eq!(app.sel_span_outcome, Some(Ok(())));
    assert_eq!(app.selected_text().unwrap().lines().count(), 401);
    let primary = shared.scrollback.lock().unwrap();
    assert_eq!(primary.view_offset, 0);
    assert!(primary.historical.is_none());
    assert!(primary.selection_result.is_none());
    drop(primary);
    assert!(app.move_pane_focus(PaneFocusDirection::Left));
    assert!(app.selected_text().is_none());
    assert!(app.sel_span.is_none());
}

#[test]
fn selection_span_copy_on_select_waits_for_both_complete_data_and_real_release_once() {
    for data_first in [false, true] {
        let (mut app, shared, _) = start_span(100);
        let copies = super::copy_on_select::record_copies(&mut app);
        app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
        let release = |app: &mut App| {
            app.handle_host_event(HostEvent::MouseInput {
                button: HostPointerButton::Left,
                pressed: false,
            });
        };
        if !data_first {
            release(&mut app);
        }
        assert!(copies.borrow().is_empty());
        deliver(&mut app, &shared, 1, None);
        if data_first {
            assert!(
                copies.borrow().is_empty(),
                "data arrival alone cannot authorize clipboard"
            );
            release(&mut app);
        }
        assert_eq!(
            copies.borrow().len(),
            1,
            "one copy after both barriers, data_first={data_first}"
        );
        assert_eq!(copies.borrow()[0].lines().count(), 101);
        release(&mut app);
        assert_eq!(
            copies.borrow().len(),
            1,
            "duplicate release cannot copy again"
        );
    }
}

fn release_span(app: &mut App) {
    app.handle_host_event(HostEvent::MouseInput {
        button: HostPointerButton::Left,
        pressed: false,
    });
}

#[test]
fn selection_span_consumed_release_cannot_be_reauthorized_by_duplicate_release() {
    for data_first in [false, true] {
        let (mut app, shared, _) = start_span(100);
        let copies = super::copy_on_select::record_copies(&mut app);
        app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
        if data_first {
            deliver(&mut app, &shared, 1, None);
        }
        app.picker_rows = Some(vec![]);
        release_span(&mut app);
        app.picker_rows = None;
        release_span(&mut app);
        if !data_first {
            deliver(&mut app, &shared, 1, None);
        }
        release_span(&mut app);
        assert!(copies.borrow().is_empty());
        assert_eq!(app.selected_text().unwrap().lines().count(), 101);
    }
}

#[test]
fn selection_span_optout_revokes_completed_release_even_if_enabled_again() {
    for enabled_at_release in [false, true] {
        let (mut app, shared, _) = start_span(100);
        let copies = super::copy_on_select::record_copies(&mut app);
        app.handle_user_event(UserEvent::SetCopyOnSelect {
            enabled: enabled_at_release,
        });
        release_span(&mut app);
        app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: false });
        app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
        deliver(&mut app, &shared, 1, None);
        release_span(&mut app);
        assert!(copies.borrow().is_empty());
        app.copy_selection();
        assert_eq!(copies.borrow().len(), 1, "explicit Copy remains available");
    }
}

#[test]
fn selection_span_failed_page_preserves_old_copy_without_automatic_clipboard_write() {
    let (mut app, shared, _) = start_span(100);
    let copies = super::copy_on_select::record_copies(&mut app);
    app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
    release_span(&mut app);
    deliver(&mut app, &shared, 2, None);
    release_span(&mut app);
    assert!(copies.borrow().is_empty());
    assert_eq!(app.selected_text().as_deref(), Some("r05000"));
    app.copy_selection();
    assert_eq!(&*copies.borrow(), &["r05000"]);
}

#[test]
fn selection_span_intervening_chrome_press_cancels_pending_clipboard_authority() {
    for button in [HostPointerButton::Left, HostPointerButton::Right] {
        let (mut app, shared, _) = start_span(100);
        let copies = super::copy_on_select::record_copies(&mut app);
        app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
        release_span(&mut app);
        let pending = app.sel_span.as_ref().unwrap();
        let binding = pending.binding.clone();
        let request = pending.request.clone();
        app.picker_rows = Some(vec![]);
        app.handle_host_event(HostEvent::MouseInput {
            button,
            pressed: true,
        });
        assert!(app.sel_span.is_none());
        assert!(!shared.commit_test_history_reply(
            &binding,
            numbered(-100, usize::from(request.count)),
            5000,
            request.offset
        ));
        app.handle_user_event(UserEvent::OutboundWritable);
        app.picker_rows = None;
        release_span(&mut app);
        assert!(copies.borrow().is_empty());
        assert_eq!(app.selected_text().as_deref(), Some("r05000"));
    }
}

#[test]
fn selection_span_released_copy_cannot_cross_a_focus_owner_change() {
    let (mut app, shared, origin) = app_with_right_child();
    app.sync_pane_cache();
    shared.drain_test_requests();
    let child = shared.pane_paint("child", "primary").paint_grid().unwrap();
    let make_child = |start, rows| {
        let mut value = numbered(start, rows);
        value.cols = child.cols;
        value.generation = child.generation.clone();
        for row in &mut value.rows_cells {
            row.resize(child.cols, cell(" "));
        }
        value
    };
    let epoch = shared.pane_epoch("child").unwrap();
    assert!(shared.apply_pane_grid("child", epoch, Arc::new(make_child(0, child.rows))));
    app.begin_local_selection(Some(CellPos {
        col: origin.col + 5,
        row: origin.row,
    }));
    app.extend_local_selection(Some(origin));
    app.selecting = false;
    shared.with_pane_scrollback("child", "primary", |sb| sb.history_len = Some(5000));
    app.apply_scroll(ScrollAction::Lines(100));
    shared.drain_test_requests();
    let binding = shared.binding_token_for_session("child").unwrap();
    assert!(shared.commit_test_history_reply(&binding, make_child(-100, child.rows), 5000, 100));
    app.modifiers.shift = true;
    app.begin_local_selection_gesture(Some(origin), Instant::now());
    assert!(app.sel_span.is_some());
    let copies = super::copy_on_select::record_copies(&mut app);
    app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
    release_span(&mut app);
    assert!(app.move_pane_focus(PaneFocusDirection::Left));
    assert!(!shared.commit_test_history_reply(&binding, make_child(-100, 101), 5000, 100));
    app.handle_user_event(UserEvent::OutboundWritable);
    assert!(copies.borrow().is_empty());
    assert_eq!(app.sel_span_outcome, Some(Err(Failure::Cancelled)));
    assert!(app.move_pane_focus(PaneFocusDirection::Right));
    release_span(&mut app);
    assert!(copies.borrow().is_empty());
    assert!(app.selected_text().is_none());
}

#[test]
fn selection_span_preference_at_actual_release_applies_before_any_release_proof() {
    for data_first in [false, true] {
        let (mut app, shared, _) = start_span(100);
        let copies = super::copy_on_select::record_copies(&mut app);
        app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: false });
        if data_first {
            deliver(&mut app, &shared, 1, None);
        }
        app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
        assert!(copies.borrow().is_empty());
        release_span(&mut app);
        if !data_first {
            deliver(&mut app, &shared, 1, None);
        }
        assert_eq!(copies.borrow().len(), 1);
        assert_eq!(copies.borrow()[0].lines().count(), 101);
    }
}

#[test]
fn selection_span_intervening_scroll_keeps_fetch_but_revokes_automatic_copy() {
    let (mut app, shared, _) = start_span(100);
    let copies = super::copy_on_select::record_copies(&mut app);
    app.handle_user_event(UserEvent::SetCopyOnSelect { enabled: true });
    release_span(&mut app);
    app.apply_scroll(ScrollAction::Lines(1));
    assert!(app.sel_span.is_some());
    deliver(&mut app, &shared, 1, None);
    release_span(&mut app);
    assert!(copies.borrow().is_empty());
    assert_eq!(app.selected_text().unwrap().lines().count(), 101);
}
