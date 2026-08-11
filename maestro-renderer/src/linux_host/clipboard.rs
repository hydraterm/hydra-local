//! Native GTK terminal clipboard + context menu for Linux.
//!
//! Reads are strictly asynchronous (`gtk_clipboard_request_text`): no nested GTK loop and no
//! blocking `wait_for_text`, so a slow/missing Wayland clipboard owner cannot freeze Hydra.
//! Results and menu actions return through the existing Tao owner-loop proxy as typed
//! `HostEvent::Clipboard` values. This object owns no PTY/session/WebView state.

#![cfg(target_os = "linux")]

use std::cell::Cell;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use gtk::gdk;
use gtk::prelude::*;

use super::wake::LinuxLoopEvent;
use crate::client::MAX_PASTE_BYTES;
use crate::host_event::{HostClipboardEvent, HostEvent};
use crate::host_services::TerminalClipboardHostServices;

/// Leave a little room for marker-shaped text while bounding the owner-loop allocation. The
/// canonical sanitizer/cap still runs in `encode_paste`; this is only a transport allocation cap.
const CLIPBOARD_RESPONSE_BYTES: usize = MAX_PASTE_BYTES + 64;
const CLIPBOARD_READ_TIMEOUT: Duration = Duration::from_secs(3);

fn bounded_clipboard_text(text: &str) -> String {
    if text.len() <= CLIPBOARD_RESPONSE_BYTES {
        return text.to_string();
    }
    let mut end = CLIPBOARD_RESPONSE_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn claim_native_read_slot(read_in_flight: &Cell<bool>) -> bool {
    !read_in_flight.replace(true)
}

/// GTK-backed clipboard service. All handles remain on the GTK owner thread (`!Send`).
pub struct GtkTerminalClipboardHost {
    clipboard: gtk::Clipboard,
    menu: gtk::Menu,
    copy_item: gtk::MenuItem,
    /// A REAL right-button GDK event is required by Wayland so the popup carries a valid seat
    /// serial/time. The terminal-slot callback records it before sending the neutral MouseInput.
    context_trigger: Rc<RefCell<Option<gdk::EventButton>>>,
    wake_proxy: tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
    /// GTK does not expose cancellation for an outstanding `request_text`. Bound native work to one
    /// request even after App's 3s UX timeout; a wedged owner can make paste unavailable, but cannot
    /// accumulate callbacks/resources with repeated shortcuts.
    read_in_flight: Rc<Cell<bool>>,
    /// The one live timeout source, owned by the host so teardown can cancel it explicitly.
    timeout_source: Rc<RefCell<Option<glib::SourceId>>>,
}

impl GtkTerminalClipboardHost {
    pub fn new(
        display: &gdk::Display,
        wake_proxy: tao::event_loop::EventLoopProxy<LinuxLoopEvent>,
    ) -> Self {
        let clipboard = gtk::Clipboard::for_display(display, &gdk::SELECTION_CLIPBOARD);
        let menu = gtk::Menu::new();
        let copy_item = gtk::MenuItem::with_label("Copy");
        let paste_item = gtk::MenuItem::with_label("Paste");
        menu.append(&copy_item);
        menu.append(&paste_item);
        menu.show_all();

        {
            let proxy = wake_proxy.clone();
            copy_item.connect_activate(move |_| {
                let _ = proxy.send_event(LinuxLoopEvent::Host(HostEvent::Clipboard(
                    HostClipboardEvent::CopyRequested,
                )));
            });
        }
        {
            let proxy = wake_proxy.clone();
            paste_item.connect_activate(move |_| {
                let _ = proxy.send_event(LinuxLoopEvent::Host(HostEvent::Clipboard(
                    HostClipboardEvent::PasteRequested,
                )));
            });
        }

        let context_trigger = Rc::new(RefCell::new(None));
        {
            let proxy = wake_proxy.clone();
            let trigger = context_trigger.clone();
            menu.connect_deactivate(move |_| {
                trigger.borrow_mut().take();
                let _ = proxy.send_event(LinuxLoopEvent::Host(HostEvent::Clipboard(
                    HostClipboardEvent::ContextMenuClosed,
                )));
            });
        }

        Self {
            clipboard,
            menu,
            copy_item,
            context_trigger,
            wake_proxy,
            read_in_flight: Rc::new(Cell::new(false)),
            timeout_source: Rc::new(RefCell::new(None)),
        }
    }

    /// Record the real native button event while its Wayland seat serial/time is valid. GTK types
    /// stay inside the Linux adapter; App later asks only to show the menu through the neutral trait.
    pub fn record_context_trigger(&self, event: &gdk::EventButton) {
        *self.context_trigger.borrow_mut() = Some(event.clone());
    }
}

impl TerminalClipboardHostServices for GtkTerminalClipboardHost {
    fn request_text(&self, request_id: u64) {
        if !claim_native_read_slot(&self.read_in_flight) {
            // App treats `None` as a completed no-op. The original native request remains the sole
            // in-flight GTK operation until its callback eventually arrives (or the host is dropped).
            let _ = self
                .wake_proxy
                .send_event(LinuxLoopEvent::Host(HostEvent::Clipboard(
                    HostClipboardEvent::Text {
                        request_id,
                        text: None,
                    },
                )));
            return;
        }
        // Exactly one completion: a missing/wedged clipboard owner clears App's pending request
        // after a bounded wait; a late GTK callback is ignored. The timeout is one-shot, only while
        // this request is live (never a heartbeat).
        let completed = Rc::new(Cell::new(false));
        let timeout_source = self.timeout_source.clone();
        {
            let completed = completed.clone();
            let timeout_on_fire = timeout_source.clone();
            let proxy = self.wake_proxy.clone();
            let source = glib::timeout_add_local_once(CLIPBOARD_READ_TIMEOUT, move || {
                timeout_on_fire.borrow_mut().take();
                if completed.replace(true) {
                    return;
                }
                let _ = proxy.send_event(LinuxLoopEvent::Host(HostEvent::Clipboard(
                    HostClipboardEvent::Text {
                        request_id,
                        text: None,
                    },
                )));
            });
            *timeout_source.borrow_mut() = Some(source);
        }

        let proxy = self.wake_proxy.clone();
        let completed_for_callback = completed.clone();
        let timeout_for_callback = timeout_source.clone();
        let read_in_flight = self.read_in_flight.clone();
        self.clipboard.request_text(move |_, text| {
            read_in_flight.set(false);
            if completed_for_callback.replace(true) {
                return;
            }
            if let Some(source) = timeout_for_callback.borrow_mut().take() {
                source.remove();
            }
            let text = text.map(bounded_clipboard_text);
            let _ = proxy.send_event(LinuxLoopEvent::Host(HostEvent::Clipboard(
                HostClipboardEvent::Text { request_id, text },
            )));
        });
    }

    fn set_text(&self, text: &str) -> bool {
        self.clipboard.set_text(text);
        true
    }

    fn show_context_menu(&self, can_copy: bool) -> bool {
        let Some(trigger) = self.context_trigger.borrow_mut().take() else {
            eprintln!("linux-host clipboard menu skipped: no native right-button trigger");
            return false;
        };
        self.copy_item.set_sensitive(can_copy);
        // `EventButton` derefs to its `gdk::Event`; passing the REAL event is required on native
        // Wayland (a serial-less synthetic popup can be rejected by the compositor).
        self.menu.popup_at_pointer(Some(&*trigger));
        true
    }
}

impl Drop for GtkTerminalClipboardHost {
    fn drop(&mut self) {
        if let Some(source) = self.timeout_source.borrow_mut().take() {
            source.remove();
        }
        self.read_in_flight.set(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_bound_preserves_utf8_boundary() {
        let raw = format!("{}é", "x".repeat(CLIPBOARD_RESPONSE_BYTES));
        let bounded = bounded_clipboard_text(&raw);
        assert_eq!(bounded.len(), CLIPBOARD_RESPONSE_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert!(bounded.chars().all(|c| c == 'x'));
    }

    #[test]
    fn response_under_bound_is_byte_identical() {
        let raw = "hello\nça\0";
        assert_eq!(bounded_clipboard_text(raw), raw);
    }

    #[test]
    fn native_read_slot_bounds_wedged_owner_to_one_request() {
        let in_flight = Cell::new(false);
        assert!(claim_native_read_slot(&in_flight));
        assert!(!claim_native_read_slot(&in_flight));
        assert!(!claim_native_read_slot(&in_flight));
        in_flight.set(false); // the real GTK callback releases the slot.
        assert!(claim_native_read_slot(&in_flight));
    }
}
