//! Tao/GTK → [`HostEvent`](crate::host_event::HostEvent) adapter (Linux path).
//!
//! Translates the Tao/GTK events the DashboardHost receives into the SAME platform-neutral [`HostEvent`] model
//! the macOS winit adapter produces, so the renderer's `App` consumes one event type on both platforms and no
//! `tao`/`gtk` type reaches it. Geometry (resize) is reported from the GTK terminal-slot `size_allocate` (the
//! authority), not Tao's top-level size; scale is the realized GTK terminal-widget scale.
//!
//! Keyboard input arrives at the GTK terminal slot (the WGPU child is input-transparent) as GDK key-press /
//! key-release events plus IM-context `commit`/`preedit` signals. This module maps a GDK keyval to the neutral
//! [`HostKey`]/[`HostNamedKey`], the GDK modifier mask to [`HostModifiers`], and IM commits/preedits to
//! [`HostIme`], producing exactly the neutral events `App::handle_host_event` acts on. Unknown events are
//! dropped (controlled ignore), never mistranslated.

#![cfg(target_os = "linux")]

use gtk::gdk;
use gtk::gdk::keys::constants as key;

// The neutral event model lives in the platform-neutral crate module so both adapters share it.
pub use crate::host_event::HostEvent;
use crate::host_event::{
    HostIme, HostKey, HostKeyEvent, HostKeyLocation, HostModifiers, HostNamedKey,
    HostPointerButton, HostScrollDelta,
};

/// Map a GDK modifier mask to the neutral [`HostModifiers`] (the four the renderer checks). `MOD1` is the
/// customary X11/Wayland "Alt"; `SUPER`/`META` both map to the neutral super/command bit so an Alt-as-Meta or
/// super-chord matches the macOS path.
pub fn host_modifiers(state: gdk::ModifierType) -> HostModifiers {
    HostModifiers {
        control: state.contains(gdk::ModifierType::CONTROL_MASK),
        alt: state.contains(gdk::ModifierType::MOD1_MASK),
        shift: state.contains(gdk::ModifierType::SHIFT_MASK),
        super_key: state.contains(gdk::ModifierType::SUPER_MASK)
            || state.contains(gdk::ModifierType::META_MASK),
    }
}

/// Map a GDK keyval to the neutral named key the renderer special-cases, or `None` (→ `HostKey::Other`) when the
/// renderer does not act on it. Covers exactly the set the winit adapter maps: arrows, editing/navigation keys,
/// Tab/Enter/Escape/Space/Backspace, and F1–F12. `KP_Enter` folds to `Enter` and `ISO_Left_Tab` (Shift-Tab) to
/// `Tab`, matching the logical keys winit reports, so PTY encoding stays byte-identical.
fn host_named_key(keyval: gdk::keys::Key) -> Option<HostNamedKey> {
    let v = *keyval;
    Some(match v {
        _ if v == *key::Up => HostNamedKey::ArrowUp,
        _ if v == *key::Down => HostNamedKey::ArrowDown,
        _ if v == *key::Left => HostNamedKey::ArrowLeft,
        _ if v == *key::Right => HostNamedKey::ArrowRight,
        _ if v == *key::BackSpace => HostNamedKey::Backspace,
        _ if v == *key::Return || v == *key::KP_Enter => HostNamedKey::Enter,
        _ if v == *key::Escape => HostNamedKey::Escape,
        _ if v == *key::space => HostNamedKey::Space,
        _ if v == *key::Tab || v == *key::ISO_Left_Tab => HostNamedKey::Tab,
        _ if v == *key::Home => HostNamedKey::Home,
        _ if v == *key::End => HostNamedKey::End,
        _ if v == *key::Insert => HostNamedKey::Insert,
        _ if v == *key::Delete => HostNamedKey::Delete,
        _ if v == *key::Page_Up => HostNamedKey::PageUp,
        _ if v == *key::Page_Down => HostNamedKey::PageDown,
        _ if v == *key::F1 => HostNamedKey::F1,
        _ if v == *key::F2 => HostNamedKey::F2,
        _ if v == *key::F3 => HostNamedKey::F3,
        _ if v == *key::F4 => HostNamedKey::F4,
        _ if v == *key::F5 => HostNamedKey::F5,
        _ if v == *key::F6 => HostNamedKey::F6,
        _ if v == *key::F7 => HostNamedKey::F7,
        _ if v == *key::F8 => HostNamedKey::F8,
        _ if v == *key::F9 => HostNamedKey::F9,
        _ if v == *key::F10 => HostNamedKey::F10,
        _ if v == *key::F11 => HostNamedKey::F11,
        _ if v == *key::F12 => HostNamedKey::F12,
        _ => return None,
    })
}

/// Translate one GDK key event into the neutral [`HostKeyEvent`].
///
/// * `key` is the named key (if the renderer special-cases it) or the produced character; otherwise `Other`.
/// * `text` is the printable character the keyval yields, if any (used for PTY encoding of printable input).
///   For a plain named/control key GDK reports no unicode, so `text` is `None`, matching winit.
/// * `base_text` is the character WITHOUT modifiers — GDK keyvals are already the composed logical key, and the
///   Alt-as-Meta base recovery that macOS needs (Option-b → `b`) does not arise on X11/Wayland, so it mirrors
///   `text` for a printable character key and is `None` otherwise. This keeps Alt-as-Meta ESC-prefixing the
///   intended base key on Linux the same way the winit path does on macOS.
/// * `location` distinguishes numpad Enter so the renderer's numpad encoding matches.
pub fn host_key_event(keyval: gdk::keys::Key, is_press: bool, is_repeat: bool) -> HostKeyEvent {
    let unicode = keyval.to_unicode().filter(|c| !c.is_control());
    let text = unicode.map(|c| c.to_string());
    let key = match host_named_key(keyval) {
        Some(named) => HostKey::Named(named),
        None => match &text {
            // A printable key with no special-case name is a character key (letters, digits, punctuation).
            Some(t) => HostKey::Character(t.clone()),
            None => HostKey::Other,
        },
    };
    let location = if *keyval == *key::KP_Enter {
        HostKeyLocation::Numpad
    } else {
        HostKeyLocation::Standard
    };
    HostKeyEvent {
        key,
        text: text.clone(),
        // On X11/Wayland the un-modified base equals the produced character for a printable key; there is no
        // macOS-style dead-key composition to strip, so mirroring `text` is correct and non-lossy.
        base_text: text,
        location,
        pressed: is_press,
        repeat: is_repeat,
    }
}

/// A full GDK key event → [`HostEvent::Keyboard`] (press or release). The window host also emits the
/// preceding [`HostEvent::ModifiersChanged`] when the mask changes; this only builds the key event itself.
pub fn key_host_event(event: &gdk::EventKey, is_press: bool, is_repeat: bool) -> HostEvent {
    HostEvent::Keyboard(host_key_event(event.keyval(), is_press, is_repeat))
}

/// Decide ownership after the terminal slot receives a key event.
///
/// The terminal owns every key while it is focused. A non-IME key is forwarded exactly once to the
/// neutral owner loop, then GTK propagation is stopped; otherwise GTK interprets arrows as directional
/// focus navigation (Left moves into the sidebar WebView). An IM-consumed key produces its text through
/// the IM context's commit/preedit signals, so it emits no duplicate keyboard event and is also stopped.
pub fn route_terminal_key(
    event: HostEvent,
    im_consumed: bool,
) -> (Option<HostEvent>, glib::Propagation) {
    let forwarded = if im_consumed { None } else { Some(event) };
    (forwarded, glib::Propagation::Stop)
}

/// GDK button number → neutral pointer button (1=left, 2=middle, 3=right; everything else `Other`).
pub fn host_button(button: u32) -> HostPointerButton {
    match button {
        1 => HostPointerButton::Left,
        2 => HostPointerButton::Middle,
        3 => HostPointerButton::Right,
        _ => HostPointerButton::Other,
    }
}

/// A GDK scroll event → the neutral scroll delta. GTK smooth scrolling reports pixel-ish deltas; the discrete
/// Up/Down/Left/Right directions map to one line each (sign matching winit: up = +1 line on Y). The neutral
/// `Lines`/`Pixels` split is preserved so the renderer's wheel accumulator behaves as on macOS.
pub fn host_scroll(event: &gdk::EventScroll) -> HostScrollDelta {
    match event.direction() {
        gdk::ScrollDirection::Smooth => {
            let (dx, dy) = event.delta();
            // GDK smooth deltas grow DOWN/RIGHT positive; winit pixel deltas grow the opposite way for Y
            // (scroll up = positive). Negate to match the renderer's expected sign.
            HostScrollDelta::Pixels { x: -dx, y: -dy }
        }
        gdk::ScrollDirection::Up => HostScrollDelta::Lines { x: 0.0, y: 1.0 },
        gdk::ScrollDirection::Down => HostScrollDelta::Lines { x: 0.0, y: -1.0 },
        gdk::ScrollDirection::Left => HostScrollDelta::Lines { x: 1.0, y: 0.0 },
        gdk::ScrollDirection::Right => HostScrollDelta::Lines { x: -1.0, y: 0.0 },
        _ => HostScrollDelta::Lines { x: 0.0, y: 0.0 },
    }
}

/// Build a neutral [`HostEvent::CursorMoved`] from a logical position and the terminal-slot scale, so cursor
/// coordinates reach the renderer in PHYSICAL pixels (matching the winit adapter and the WGPU surface size).
pub fn cursor_moved_event(logical_x: f64, logical_y: f64, scale: i32) -> HostEvent {
    let s = scale.max(1) as f64;
    HostEvent::CursorMoved {
        x: logical_x * s,
        y: logical_y * s,
    }
}

/// An IM-context commit string → the neutral commit IME event (the only IME event the renderer acts on).
pub fn ime_commit_event(text: &str) -> HostEvent {
    HostEvent::Ime(HostIme::Commit(text.to_string()))
}

/// An IM-context preedit string → the neutral preedit IME event (display-only in the renderer, represented so
/// the adapter never silently drops it).
pub fn ime_preedit_event(text: &str) -> HostEvent {
    HostEvent::Ime(HostIme::Preedit(text.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_keys_map_to_neutral() {
        assert_eq!(host_named_key(key::Left), Some(HostNamedKey::ArrowLeft));
        assert_eq!(host_named_key(key::Right), Some(HostNamedKey::ArrowRight));
        assert_eq!(host_named_key(key::Escape), Some(HostNamedKey::Escape));
        assert_eq!(host_named_key(key::Return), Some(HostNamedKey::Enter));
        assert_eq!(host_named_key(key::KP_Enter), Some(HostNamedKey::Enter));
        assert_eq!(host_named_key(key::ISO_Left_Tab), Some(HostNamedKey::Tab));
        assert_eq!(host_named_key(key::F1), Some(HostNamedKey::F1));
        assert_eq!(host_named_key(key::F12), Some(HostNamedKey::F12));
        assert_eq!(host_named_key(key::Page_Up), Some(HostNamedKey::PageUp));
        // A key the renderer does not special-case falls through to None (→ Other in host_key_event).
        assert_eq!(host_named_key(key::a), None);
    }

    #[test]
    fn character_key_carries_text_and_base_text() {
        let ev = host_key_event(key::a, true, false);
        assert_eq!(ev.key, HostKey::Character("a".to_string()));
        assert_eq!(ev.text.as_deref(), Some("a"));
        assert_eq!(ev.base_text.as_deref(), Some("a"));
        assert!(ev.pressed);
        assert!(!ev.repeat);
        assert_eq!(ev.location, HostKeyLocation::Standard);
    }

    #[test]
    fn named_key_has_no_text() {
        let ev = host_key_event(key::Escape, true, false);
        assert_eq!(ev.key, HostKey::Named(HostNamedKey::Escape));
        assert_eq!(ev.text, None);
        assert_eq!(ev.base_text, None);
    }

    #[test]
    fn numpad_enter_reports_numpad_location() {
        let ev = host_key_event(key::KP_Enter, true, false);
        assert_eq!(ev.key, HostKey::Named(HostNamedKey::Enter));
        assert_eq!(ev.location, HostKeyLocation::Numpad);
    }

    #[test]
    fn modifiers_map_control_alt_shift_super() {
        let m = host_modifiers(gdk::ModifierType::CONTROL_MASK | gdk::ModifierType::MOD1_MASK);
        assert!(m.control);
        assert!(m.alt);
        assert!(!m.shift);
        assert!(!m.super_key);
        let m2 = host_modifiers(gdk::ModifierType::SUPER_MASK | gdk::ModifierType::SHIFT_MASK);
        assert!(m2.super_key);
        assert!(m2.shift);
    }

    #[test]
    fn buttons_and_discrete_scroll_map() {
        assert_eq!(host_button(1), HostPointerButton::Left);
        assert_eq!(host_button(2), HostPointerButton::Middle);
        assert_eq!(host_button(3), HostPointerButton::Right);
        assert_eq!(host_button(8), HostPointerButton::Other);
    }

    #[test]
    fn terminal_key_route_forwards_once_and_always_stops_gtk_navigation() {
        let press = HostEvent::Keyboard(host_key_event(key::Left, true, false));
        let (forwarded, propagation) = route_terminal_key(press.clone(), false);
        assert_eq!(forwarded, Some(press));
        assert_eq!(propagation, glib::Propagation::Stop);

        let release = HostEvent::Keyboard(host_key_event(key::Left, false, false));
        let (forwarded, propagation) = route_terminal_key(release.clone(), false);
        assert_eq!(forwarded, Some(release));
        assert_eq!(propagation, glib::Propagation::Stop);

        let ime_key = HostEvent::Keyboard(host_key_event(key::dead_acute, true, false));
        let (forwarded, propagation) = route_terminal_key(ime_key, true);
        assert_eq!(forwarded, None);
        assert_eq!(propagation, glib::Propagation::Stop);
    }

    #[test]
    fn cursor_moved_scales_to_physical() {
        assert_eq!(
            cursor_moved_event(10.0, 20.0, 2),
            HostEvent::CursorMoved { x: 20.0, y: 40.0 }
        );
        // scale 0 is clamped to 1 (never divides/zeroes coordinates).
        assert_eq!(
            cursor_moved_event(10.0, 20.0, 0),
            HostEvent::CursorMoved { x: 10.0, y: 20.0 }
        );
    }
}
