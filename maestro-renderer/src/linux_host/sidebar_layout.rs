//! Noninteractive GTK allocator for the Linux dashboard sidebar and terminal column.
//!
//! React owns the desired sidebar width. GTK owns the realized allocation. This container keeps those
//! responsibilities separate: it remembers React's logical width, clamps only the visible allocation when the
//! top-level is too narrow, and restores the desired width automatically when space returns. Child natural-size
//! requests never participate in the split, so a realized WebKit view cannot retain stale sidebar space.

#![cfg(target_os = "linux")]

use std::cell::Cell;

use gtk::glib;
use gtk::prelude::*;
use gtk::subclass::prelude::*;

/// Always preserve at least one logical pixel for the terminal column. GTK itself enforces a 1x1 minimum
/// allocation, and the real application window cannot become this small because of its native decorations.
const MIN_TERMINAL_LOGICAL_PX: i32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SidebarSplit {
    pub sidebar: i32,
    pub terminal: i32,
}

/// Compute exact sibling widths from React's retained desired width and GTK's current allocation.
///
/// `desired_sidebar` is intentionally not overwritten when the window is narrow. Calling this again after the
/// top-level grows therefore restores the desired width without relying on a divider's previous position.
pub(super) fn sidebar_split(
    desired_sidebar: u32,
    total_width: i32,
    has_sidebar: bool,
) -> SidebarSplit {
    let total = total_width.max(MIN_TERMINAL_LOGICAL_PX);
    let desired = i32::try_from(desired_sidebar).unwrap_or(i32::MAX).max(0);
    let sidebar = if has_sidebar {
        desired.min(total.saturating_sub(MIN_TERMINAL_LOGICAL_PX))
    } else {
        0
    };
    SidebarSplit {
        sidebar,
        terminal: total.saturating_sub(sidebar).max(MIN_TERMINAL_LOGICAL_PX),
    }
}

mod imp {
    use super::*;

    #[derive(Default)]
    pub struct SidebarLayout {
        pub desired_sidebar: Cell<u32>,
        pub has_sidebar: Cell<bool>,
        pub sidebar: glib::WeakRef<gtk::Widget>,
        pub terminal: glib::WeakRef<gtk::Widget>,
    }

    #[glib::object_subclass]
    impl ObjectSubclass for SidebarLayout {
        const NAME: &'static str = "HydraSidebarLayout";
        type Type = super::SidebarLayout;
        type ParentType = gtk::Container;
    }

    impl ObjectImpl for SidebarLayout {
        fn constructed(&self) {
            self.parent_constructed();
            // This layout must not create another native surface or enter the focus/accessibility chain. Its
            // direct children preserve the proven WebKit/WGPU window topology used by the previous split.
            self.obj().set_has_window(false);
            self.obj().set_can_focus(false);
        }
    }

    impl WidgetImpl for SidebarLayout {
        fn request_mode(&self) -> gtk::SizeRequestMode {
            gtk::SizeRequestMode::ConstantSize
        }

        // The Tao top-level supplies the product's explicit default size. Returning a neutral request here is
        // deliberate: neither WebKit's natural width nor the retained sidebar width should become a window
        // manager minimum that prevents narrowing the terminal.
        fn preferred_width(&self) -> (i32, i32) {
            (MIN_TERMINAL_LOGICAL_PX, MIN_TERMINAL_LOGICAL_PX)
        }

        fn preferred_width_for_height(&self, _height: i32) -> (i32, i32) {
            self.preferred_width()
        }

        fn preferred_height(&self) -> (i32, i32) {
            let mut minimum = 1;
            let mut natural = 1;
            for child in [self.sidebar.upgrade(), self.terminal.upgrade()]
                .into_iter()
                .flatten()
                .filter(|child| child.is_visible() && child.is_child_visible())
            {
                let (child_minimum, child_natural) = child.preferred_height();
                minimum = minimum.max(child_minimum);
                natural = natural.max(child_natural);
            }
            (minimum, natural.max(minimum))
        }

        fn preferred_height_for_width(&self, width: i32) -> (i32, i32) {
            let split = sidebar_split(self.desired_sidebar.get(), width, self.has_sidebar.get());
            let mut minimum = 1;
            let mut natural = 1;
            if split.sidebar > 0 {
                if let Some(sidebar) = self
                    .sidebar
                    .upgrade()
                    .filter(|child| child.is_visible() && child.is_child_visible())
                {
                    let (child_minimum, child_natural) =
                        sidebar.preferred_height_for_width(split.sidebar);
                    minimum = minimum.max(child_minimum);
                    natural = natural.max(child_natural);
                }
            }
            if let Some(terminal) = self
                .terminal
                .upgrade()
                .filter(|child| child.is_visible() && child.is_child_visible())
            {
                let (child_minimum, child_natural) =
                    terminal.preferred_height_for_width(split.terminal);
                minimum = minimum.max(child_minimum);
                natural = natural.max(child_natural);
            }
            (minimum, natural.max(minimum))
        }

        fn size_allocate(&self, allocation: &gtk::Allocation) {
            // GtkContainer has no child-allocation policy. Chaining sets this no-window widget's own allocation
            // exactly once; the two children below are then allocated exactly once, avoiding a stale-size pass
            // and duplicate WGPU/PTy resize events.
            self.parent_size_allocate(allocation);

            let split = sidebar_split(
                self.desired_sidebar.get(),
                allocation.width(),
                self.has_sidebar.get(),
            );
            let height = allocation.height().max(1);

            if let Some(sidebar) = self.sidebar.upgrade() {
                let showing = split.sidebar > 0;
                if sidebar.is_child_visible() != showing {
                    sidebar.set_child_visible(showing);
                }
                if showing && sidebar.is_visible() {
                    // Prime GTK's request cache to preserve request-before-allocate ordering, but never use the
                    // result to choose the rectangle. GTK/WebKit receives this exact allocation just as it did
                    // as a shrinkable direct child of the previously qualified GtkPaned composition.
                    let _ = sidebar.preferred_width();
                    let _ = sidebar.preferred_height_for_width(split.sidebar);
                    sidebar.size_allocate(&gtk::Allocation::new(
                        allocation.x(),
                        allocation.y(),
                        split.sidebar,
                        height,
                    ));
                }
            }

            if let Some(terminal) = self.terminal.upgrade() {
                if terminal.is_visible() {
                    let _ = terminal.preferred_width();
                    let _ = terminal.preferred_height_for_width(split.terminal);
                    terminal.size_allocate(&gtk::Allocation::new(
                        allocation.x().saturating_add(split.sidebar),
                        allocation.y(),
                        split.terminal,
                        height,
                    ));
                }
            }
        }
    }

    impl ContainerImpl for SidebarLayout {
        fn add(&self, widget: &gtk::Widget) {
            if widget.parent().is_some() {
                eprintln!("linux-host sidebar layout rejected already-parented child");
                return;
            }

            let target = if self.has_sidebar.get() && self.sidebar.upgrade().is_none() {
                &self.sidebar
            } else if self.terminal.upgrade().is_none() {
                &self.terminal
            } else {
                eprintln!("linux-host sidebar layout rejected unexpected third child");
                return;
            };
            target.set(Some(widget));
            widget.set_parent(&*self.obj());
            self.obj().queue_resize();
        }

        fn remove(&self, widget: &gtk::Widget) {
            let mut removed = false;
            if self.sidebar.upgrade().as_ref() == Some(widget) {
                self.sidebar.set(None);
                removed = true;
            }
            if self.terminal.upgrade().as_ref() == Some(widget) {
                self.terminal.set(None);
                removed = true;
            }
            if removed {
                widget.unparent();
                self.obj().queue_resize();
            }
        }

        fn forall(&self, _include_internals: bool, callback: &gtk::subclass::container::Callback) {
            // Snapshot strong references before invoking arbitrary callbacks: destroy/remove is allowed to
            // mutate the container while GTK walks it.
            let children = [self.sidebar.upgrade(), self.terminal.upgrade()];
            for child in children.into_iter().flatten() {
                callback.call(&child);
            }
        }

        fn child_type(&self) -> glib::Type {
            gtk::Widget::static_type()
        }
    }
}

glib::wrapper! {
    /// Exact, noninteractive horizontal allocator owned by the Linux DashboardHost.
    pub struct SidebarLayout(ObjectSubclass<imp::SidebarLayout>)
        @extends gtk::Container, gtk::Widget,
        @implements gtk::Buildable;
}

impl SidebarLayout {
    pub(super) fn new(
        sidebar: Option<&gtk::Box>,
        terminal: &gtk::Box,
        desired_sidebar: u32,
    ) -> Self {
        let layout: Self = glib::Object::new();
        let imp = layout.imp();
        imp.desired_sidebar.set(desired_sidebar);
        imp.has_sidebar.set(sidebar.is_some());
        if let Some(sidebar) = sidebar {
            layout.add(sidebar);
        }
        layout.add(terminal);
        layout
    }

    pub(super) fn set_desired_sidebar_width(&self, width_logical_px: u32) {
        let imp = self.imp();
        if imp.desired_sidebar.replace(width_logical_px) != width_logical_px {
            self.queue_resize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{sidebar_split, SidebarSplit};

    #[test]
    fn expanded_and_collapsed_widths_are_exact_without_separator_tax() {
        assert_eq!(
            sidebar_split(460, 1280, true),
            SidebarSplit {
                sidebar: 460,
                terminal: 820,
            }
        );
        assert_eq!(
            sidebar_split(24, 1280, true),
            SidebarSplit {
                sidebar: 24,
                terminal: 1256,
            }
        );
    }

    #[test]
    fn narrow_allocation_clamps_actual_width_without_losing_desired_width() {
        let desired = 460;
        assert_eq!(
            sidebar_split(desired, 300, true),
            SidebarSplit {
                sidebar: 299,
                terminal: 1,
            }
        );
        assert_eq!(
            sidebar_split(desired, 1280, true),
            SidebarSplit {
                sidebar: 460,
                terminal: 820,
            }
        );
    }

    #[test]
    fn hostile_or_degenerate_dimensions_remain_bounded() {
        assert_eq!(
            sidebar_split(u32::MAX, 80, true),
            SidebarSplit {
                sidebar: 79,
                terminal: 1,
            }
        );
        assert_eq!(
            sidebar_split(460, 1, true),
            SidebarSplit {
                sidebar: 0,
                terminal: 1,
            }
        );
        assert_eq!(
            sidebar_split(460, 0, true),
            SidebarSplit {
                sidebar: 0,
                terminal: 1,
            }
        );
    }

    #[test]
    fn no_sidebar_gives_the_entire_allocation_to_terminal() {
        assert_eq!(
            sidebar_split(460, 1280, false),
            SidebarSplit {
                sidebar: 0,
                terminal: 1280,
            }
        );
    }
}
