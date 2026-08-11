//! winit → [`HostEvent`] adapter (macOS path).
//!
//! Translates the winit events `App` acts on into the platform-neutral [`HostEvent`] model, preserving the
//! exact meaning of the current winit `App::window_event` arms. Native events `App` does not handle translate
//! to `None` (controlled ignore) — they are never mistranslated into a different event.
//!
//! This keeps `winit` types out of `App`: `App` consumes only [`HostEvent`]. The macOS event ORDER is
//! unchanged because the winit event loop still delivers events in the same order; only their type at the
//! `App` boundary changes.

#![cfg(not(target_os = "linux"))]

use crate::host_event::{
    HostEvent, HostIme, HostKey, HostKeyEvent, HostKeyLocation, HostModifiers, HostNamedKey,
    HostPointerButton, HostScrollDelta,
};
use winit::event::{ElementState, Ime, Modifiers, MouseButton, MouseScrollDelta, WindowEvent};
use winit::keyboard::{Key, KeyLocation, NamedKey};
use winit::platform::modifier_supplement::KeyEventExtModifierSupplement;

/// Translate one winit `WindowEvent` into a [`HostEvent`], or `None` if `App` does not act on it. The mapping
/// is 1:1 with the current `App::window_event` arms.
pub fn host_event_from_winit(event: &WindowEvent) -> Option<HostEvent> {
    Some(match event {
        WindowEvent::CloseRequested => HostEvent::CloseRequested,
        WindowEvent::Resized(size) => HostEvent::Resized {
            width: size.width,
            height: size.height,
        },
        WindowEvent::ScaleFactorChanged { scale_factor, .. } => HostEvent::ScaleFactorChanged {
            scale: *scale_factor,
        },
        WindowEvent::RedrawRequested => HostEvent::RedrawRequested,
        WindowEvent::Focused(f) => HostEvent::Focused(*f),
        WindowEvent::CursorLeft { .. } => HostEvent::CursorLeft,
        WindowEvent::CursorMoved { position, .. } => HostEvent::CursorMoved {
            x: position.x,
            y: position.y,
        },
        WindowEvent::ModifiersChanged(m) => HostEvent::ModifiersChanged(host_modifiers(m)),
        WindowEvent::MouseInput { state, button, .. } => HostEvent::MouseInput {
            button: host_button(*button),
            pressed: *state == ElementState::Pressed,
        },
        WindowEvent::MouseWheel { delta, .. } => HostEvent::MouseWheel {
            delta: host_scroll(*delta),
        },
        // Neutral keyboard/IME: translate winit's key/IME events to the platform-neutral model so `App`
        // never sees a winit type. `host_key_event` preserves logical key + produced text + base text
        // (key_without_modifiers) + location + pressed/repeat, so the PTY encoding is byte-identical.
        WindowEvent::Ime(ime) => HostEvent::Ime(host_ime(ime)),
        WindowEvent::KeyboardInput { event, .. } => HostEvent::Keyboard(host_key_event(event)),
        // Everything else (moved, occluded, touch, etc.) is not acted on by App: controlled ignore.
        _ => return None,
    })
}

pub fn host_modifiers(m: &Modifiers) -> HostModifiers {
    let s = m.state();
    HostModifiers {
        control: s.control_key(),
        alt: s.alt_key(),
        shift: s.shift_key(),
        super_key: s.super_key(),
    }
}

fn host_button(b: MouseButton) -> HostPointerButton {
    match b {
        MouseButton::Left => HostPointerButton::Left,
        MouseButton::Middle => HostPointerButton::Middle,
        MouseButton::Right => HostPointerButton::Right,
        _ => HostPointerButton::Other,
    }
}

fn host_scroll(d: MouseScrollDelta) -> HostScrollDelta {
    match d {
        MouseScrollDelta::LineDelta(x, y) => HostScrollDelta::Lines { x, y },
        MouseScrollDelta::PixelDelta(p) => HostScrollDelta::Pixels { x: p.x, y: p.y },
    }
}

fn host_ime(ime: &Ime) -> HostIme {
    match ime {
        Ime::Commit(t) => HostIme::Commit(t.clone()),
        Ime::Preedit(t, _) => HostIme::Preedit(t.clone()),
        Ime::Enabled => HostIme::Enabled,
        Ime::Disabled => HostIme::Disabled,
    }
}

/// Map every `winit::keyboard::NamedKey` the renderer special-cases (in `handle_key`, the shortcut
/// matchers, or `encode_key`) to its neutral `HostNamedKey`. The full set — arrows, editing keys,
/// navigation, Tab/Enter/Escape/Space/Backspace, and F1–F12 — is mapped so the neutral path produces
/// byte-identical PTY encoding (xterm F-keys, Insert/Delete/PageUp/PageDown, Shift-Tab) as the old
/// winit-typed handler. A `NamedKey` the renderer does not act on maps to `None`, becoming `HostKey::Other`.
fn host_named_key(n: NamedKey) -> Option<HostNamedKey> {
    Some(match n {
        NamedKey::ArrowUp => HostNamedKey::ArrowUp,
        NamedKey::ArrowDown => HostNamedKey::ArrowDown,
        NamedKey::ArrowLeft => HostNamedKey::ArrowLeft,
        NamedKey::ArrowRight => HostNamedKey::ArrowRight,
        NamedKey::Backspace => HostNamedKey::Backspace,
        NamedKey::Enter => HostNamedKey::Enter,
        NamedKey::Escape => HostNamedKey::Escape,
        NamedKey::Space => HostNamedKey::Space,
        NamedKey::Tab => HostNamedKey::Tab,
        NamedKey::Home => HostNamedKey::Home,
        NamedKey::End => HostNamedKey::End,
        NamedKey::Insert => HostNamedKey::Insert,
        NamedKey::Delete => HostNamedKey::Delete,
        NamedKey::PageUp => HostNamedKey::PageUp,
        NamedKey::PageDown => HostNamedKey::PageDown,
        NamedKey::F1 => HostNamedKey::F1,
        NamedKey::F2 => HostNamedKey::F2,
        NamedKey::F3 => HostNamedKey::F3,
        NamedKey::F4 => HostNamedKey::F4,
        NamedKey::F5 => HostNamedKey::F5,
        NamedKey::F6 => HostNamedKey::F6,
        NamedKey::F7 => HostNamedKey::F7,
        NamedKey::F8 => HostNamedKey::F8,
        NamedKey::F9 => HostNamedKey::F9,
        NamedKey::F10 => HostNamedKey::F10,
        NamedKey::F11 => HostNamedKey::F11,
        NamedKey::F12 => HostNamedKey::F12,
        _ => return None,
    })
}

fn host_location(l: KeyLocation) -> HostKeyLocation {
    match l {
        KeyLocation::Standard => HostKeyLocation::Standard,
        KeyLocation::Numpad => HostKeyLocation::Numpad,
        KeyLocation::Left => HostKeyLocation::Left,
        KeyLocation::Right => HostKeyLocation::Right,
    }
}

pub fn host_key_event(event: &winit::event::KeyEvent) -> HostKeyEvent {
    let key = match &event.logical_key {
        Key::Named(n) => match host_named_key(*n) {
            Some(hn) => HostKey::Named(hn),
            None => HostKey::Other,
        },
        Key::Character(c) => HostKey::Character(c.as_str().to_string()),
        _ => HostKey::Other,
    };
    // `base_text` is the key WITHOUT modifiers (winit `key_without_modifiers()`), used by Alt-as-Meta to
    // ESC-prefix the intended base key (Option-b -> `b`, not the composed glyph `∫`). Only a `Character`
    // base carries text; a named/other base has none, matching the old `handle_key` `base_text` derivation.
    let base_text = match event.key_without_modifiers() {
        Key::Character(c) => Some(c.as_str().to_string()),
        _ => None,
    };
    HostKeyEvent {
        key,
        text: event.text.as_ref().map(|t| t.as_str().to_string()),
        base_text,
        location: host_location(event.location),
        pressed: event.state == ElementState::Pressed,
        repeat: event.repeat,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use winit::dpi::{PhysicalPosition, PhysicalSize};

    #[test]
    fn resized_and_close_map_directly() {
        assert_eq!(
            host_event_from_winit(&WindowEvent::Resized(PhysicalSize::new(800, 600))),
            Some(HostEvent::Resized {
                width: 800,
                height: 600
            })
        );
        assert_eq!(
            host_event_from_winit(&WindowEvent::CloseRequested),
            Some(HostEvent::CloseRequested)
        );
    }

    #[test]
    fn cursor_moved_carries_physical_position() {
        let ev = WindowEvent::CursorMoved {
            device_id: winit::event::DeviceId::dummy(),
            position: PhysicalPosition::new(12.5, 34.0),
        };
        assert_eq!(
            host_event_from_winit(&ev),
            Some(HostEvent::CursorMoved { x: 12.5, y: 34.0 })
        );
    }

    #[test]
    fn mouse_button_and_state_map() {
        let ev = WindowEvent::MouseInput {
            device_id: winit::event::DeviceId::dummy(),
            state: ElementState::Pressed,
            button: MouseButton::Right,
        };
        assert_eq!(
            host_event_from_winit(&ev),
            Some(HostEvent::MouseInput {
                button: HostPointerButton::Right,
                pressed: true
            })
        );
    }

    #[test]
    fn named_and_character_keys_map() {
        assert_eq!(host_named_key(NamedKey::Escape), Some(HostNamedKey::Escape));
        assert_eq!(host_named_key(NamedKey::Enter), Some(HostNamedKey::Enter));
        // Every named key the renderer encodes maps (F-keys, Tab, Insert/Delete included) so the neutral
        // path stays byte-identical with the old winit handler.
        assert_eq!(host_named_key(NamedKey::F1), Some(HostNamedKey::F1));
        assert_eq!(host_named_key(NamedKey::F12), Some(HostNamedKey::F12));
        assert_eq!(host_named_key(NamedKey::Tab), Some(HostNamedKey::Tab));
        assert_eq!(host_named_key(NamedKey::Delete), Some(HostNamedKey::Delete));
        // A named key App doesn't special-case falls through to None (→ Other in host_key_event).
        assert_eq!(host_named_key(NamedKey::PrintScreen), None);
    }

    #[test]
    fn ime_commit_and_preedit_distinct() {
        assert_eq!(
            host_ime(&Ime::Commit("aé".into())),
            HostIme::Commit("aé".into())
        );
        assert_eq!(
            host_ime(&Ime::Preedit("x".into(), None)),
            HostIme::Preedit("x".into())
        );
    }

    #[test]
    fn scroll_line_vs_pixel_preserved() {
        assert_eq!(
            host_scroll(MouseScrollDelta::LineDelta(0.0, -3.0)),
            HostScrollDelta::Lines { x: 0.0, y: -3.0 }
        );
        assert_eq!(
            host_scroll(MouseScrollDelta::PixelDelta(PhysicalPosition::new(
                1.0, 2.0,
            ))),
            HostScrollDelta::Pixels { x: 1.0, y: 2.0 }
        );
    }

    #[test]
    fn unhandled_event_is_controlled_none() {
        // Moved is not something App acts on → None (never mistranslated).
        assert_eq!(
            host_event_from_winit(&WindowEvent::Moved(PhysicalPosition::new(0, 0))),
            None
        );
    }
}
