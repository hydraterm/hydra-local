//! Windows child-WebView and terminal geometry share one temporary sidebar allocation.
//! This never changes the user's requested width or imposes a minimum window size.

use std::cell::Cell;

/// WRY bounds/visibility updates contain more than one native operation. A failed
/// update may have partially applied, so even the previous value needs a retry.
pub(crate) fn apply_changed<T: Copy + Eq, E>(
    applied: &Cell<Option<T>>,
    requested: T,
    apply: impl FnOnce() -> Result<(), E>,
) -> Result<(), E> {
    if applied.get() == Some(requested) {
        return Ok(());
    }
    applied.set(None);
    apply()?;
    applied.set(Some(requested));
    Ok(())
}

/// Only a changed, non-minimized allocation needs a new native buffer. The caller
/// also verifies that Renderer accepted it before presenting.
pub(crate) fn allocation_changed(previous: (u32, u32), requested: (u32, u32)) -> bool {
    requested.0 != 0 && requested.1 != 0 && requested != previous
}

pub(crate) fn surface_extent_is_valid(requested: (u32, u32), maximum: u32) -> bool {
    requested.0 > 0 && requested.1 > 0 && requested.0 <= maximum && requested.1 <= maximum
}

/// winit can replay older WM_SIZE dimensions after the HWND has already resized.
/// A zero current extent is intentional (minimized), not grounds to replay a stale
/// nonzero event; Renderer::resize keeps its last accepted allocation in that case.
pub(crate) fn resize_extent(event: (u32, u32), current: Option<(u32, u32)>) -> (u32, u32) {
    current.unwrap_or(event)
}

/// Once WGPU has accepted an allocation, all frame geometry uses it. Only the
/// pre-renderer mount path needs a live HWND observation. Keep that fallback lazy
/// so a frame never mixes an accepted allocation with a later client rectangle.
pub(crate) fn frame_extent(
    accepted: Option<(u32, u32)>,
    current: impl FnOnce() -> Option<(u32, u32)>,
) -> Option<(u32, u32)> {
    accepted.or_else(current)
}

pub(crate) fn sidebar_width_logical(requested: u32, window_width_px: u32, scale: f64) -> u32 {
    const COLLAPSED: u32 = 24;
    const EXPANDED_MIN: u32 = 220;
    // Leaves room for the icon-only toolbar and a useful terminal at narrow widths.
    const CONTENT_MIN: u32 = 320;
    if !scale.is_finite() || scale <= 0.0 {
        return 0;
    }
    let available = (f64::from(window_width_px) / scale).floor() as u32;
    if requested <= COLLAPSED {
        return requested.min(available);
    }
    if available < EXPANDED_MIN + CONTENT_MIN {
        return COLLAPSED.min(available);
    }
    requested.min(available - CONTENT_MIN)
}

#[cfg(test)]
mod tests {
    use super::{
        allocation_changed, apply_changed, frame_extent, resize_extent, sidebar_width_logical,
        surface_extent_is_valid,
    };
    use std::cell::Cell;

    #[test]
    fn physical_bounds_skip_duplicates_but_apply_position_size_and_dpi_changes() {
        let applied = Cell::new(None);
        let calls = Cell::new(0);
        for bounds in [
            (0, 0, 220, 900),
            (0, 0, 220, 900), // replay/restore of the accepted allocation
            (220, 0, 680, 29),
            (220, 0, 681, 29),
            (440, 0, 1362, 58), // same logical allocation at a new DPI
        ] {
            apply_changed(&applied, bounds, || {
                calls.set(calls.get() + 1);
                Ok::<_, ()>(())
            })
            .unwrap();
        }
        assert_eq!(calls.get(), 4);
        assert_eq!(applied.get(), Some((440, 0, 1362, 58)));
    }

    #[test]
    fn partial_failure_retries_both_new_and_previously_successful_values() {
        let applied = Cell::new(Some(false));
        assert_eq!(
            apply_changed(&applied, true, || Err("partial show")),
            Err("partial show")
        );
        assert_eq!(applied.get(), None);
        let calls = Cell::new(0);
        apply_changed(&applied, false, || {
            calls.set(calls.get() + 1);
            Ok::<_, ()>(())
        })
        .unwrap();
        apply_changed(&applied, false, || -> Result<(), ()> {
            panic!("unchanged hide must be skipped")
        })
        .unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(applied.get(), Some(false));
        assert!(apply_changed(&applied, true, || Err("retry show")).is_err());
        apply_changed(&applied, true, || Ok::<_, ()>(())).unwrap();
        assert_eq!(applied.get(), Some(true));
    }

    #[test]
    fn immediate_allocation_present_requires_changed_nonzero_extent() {
        let previous = (1200, 900);
        assert!(!allocation_changed(previous, previous));
        for minimized in [(0, 0), (0, 900), (1200, 0)] {
            assert!(!allocation_changed(previous, minimized));
        }
        assert!(allocation_changed(previous, (1201, 900)));
        assert!(allocation_changed(previous, (1200, 901)));
        assert!(allocation_changed(previous, (1199, 899)));
    }

    #[test]
    fn chrome_preallocation_excludes_minimized_and_rejected_gpu_extents() {
        for size in [(0, 0), (0, 900), (1200, 0), (8193, 900), (1200, 8193)] {
            assert!(!surface_extent_is_valid(size, 8192));
        }
        for size in [(1, 1), (1200, 900), (8192, 8192)] {
            assert!(surface_extent_is_valid(size, 8192));
        }
        assert!(!surface_extent_is_valid((1, 1), 0));
    }

    #[test]
    fn stale_resize_and_advancing_client_do_not_split_frame_authorities() {
        let stale_event = (1000, 800);
        let current_client = (1200, 900);
        let scale = 2.0;
        let requested_sidebar = 460;
        assert_eq!(
            sidebar_width_logical(requested_sidebar, stale_event.0, scale),
            24
        );

        let accepted = resize_extent(stale_event, Some(current_client));
        assert_eq!(accepted, current_client);
        let frame = frame_extent(Some(accepted), || {
            panic!("frame geometry must not sample a newer client extent")
        })
        .unwrap();
        // This one allocation is passed to child bounds, dock reservation and
        // split-frame geometry. Crossing the narrow-window threshold cannot make
        // one reserve the collapsed rail while another reserves an expanded one.
        let sidebar = sidebar_width_logical(requested_sidebar, frame.0, scale);
        assert_eq!(sidebar, 280);
        assert_eq!(frame.0 - sidebar * 2, 640);
        assert_eq!(frame.1, 900);
    }

    #[test]
    fn unavailable_host_and_zero_client_keep_explicit_resize_semantics() {
        assert_eq!(resize_extent((1200, 900), None), (1200, 900));
        assert_eq!(resize_extent((1200, 900), Some((0, 0))), (0, 0));
        assert_eq!(frame_extent(None, || Some((1200, 900))), Some((1200, 900)));
        assert_eq!(frame_extent(None, || None), None);
        // A rejected/minimized resize keeps the previous accepted GPU extent.
        assert_eq!(
            frame_extent(Some((1200, 900)), || Some((0, 0))),
            Some((1200, 900))
        );
    }

    #[test]
    fn narrow_sidebar_yields_to_terminal_then_restores_requested_width() {
        let preferred = 720;
        assert_eq!(sidebar_width_logical(preferred, 1400, 1.0), preferred);
        assert_eq!(sidebar_width_logical(preferred, 900, 1.0), 580);
        assert_eq!(sidebar_width_logical(preferred, 540, 1.0), 220);
        assert_eq!(sidebar_width_logical(preferred, 539, 1.0), 24);
        assert_eq!(sidebar_width_logical(preferred, 1400, 1.0), preferred);
    }

    #[test]
    fn physical_width_and_dpi_resolve_the_same_logical_allocation() {
        for scale in [1.0, 1.25, 1.5, 2.0] {
            for (logical, expected) in [(1400, 720), (900, 580), (540, 220), (400, 24)] {
                assert_eq!(
                    sidebar_width_logical(720, (f64::from(logical) * scale) as u32, scale),
                    expected
                );
            }
        }
        assert_eq!(sidebar_width_logical(720, 900, 1.0), 580);
        assert_eq!(sidebar_width_logical(720, 900, 2.0), 24);
        assert_eq!(sidebar_width_logical(720, 900, 1.0), 580);
    }

    #[test]
    fn collapsed_preference_and_degenerate_windows_stay_bounded() {
        for width in [0, 1, 23, 24, 400, 1400] {
            assert_eq!(sidebar_width_logical(24, width, 1.0), width.min(24));
            assert!(sidebar_width_logical(720, width, 1.0) <= width);
        }
        for scale in [0.0, -1.0, f64::NAN, f64::INFINITY] {
            assert_eq!(sidebar_width_logical(720, 900, scale), 0);
        }
    }
}
