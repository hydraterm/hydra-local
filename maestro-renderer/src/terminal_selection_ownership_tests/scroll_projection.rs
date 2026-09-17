use super::*;
use crate::host_event::HostScrollDelta;

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
