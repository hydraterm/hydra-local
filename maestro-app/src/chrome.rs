//! Default one-window attach-tab chrome resolver.
//!
//! PURE policy that turns the raw `attach-tab` chrome flags into the EFFECTIVE chrome the foreground
//! one-window experience should show. The foreground window is meant to feel like a real app, so the
//! top tab bar and the lightweight dashboard status suffix default ON when their flags are absent;
//! the heavier dashboard panel defaults OFF but is configurable (a persisted
//! `chrome.dashboard_panel_default` can flip it ON). The picker overlay is also configurable (a
//! persisted `chrome.picker_overlay_default` can flip it ON), but ONLY in the foreground in-process
//! renderer: unlike the dashboard panel, a persisted-on picker overlay never makes `--no-run-renderer`
//! (`RendererMode::None`) or a detached renderer resolve it true. The new-tab launch policy stays
//! strictly opt-in. A detached renderer carries NONE of this app-owned chrome, so every effective value
//! is `false` there. This is the ONLY place the foreground defaults live — `main.rs` resolves once and
//! threads the result through the renderer launch and the success JSON.

use crate::RendererMode;

/// Raw `attach-tab` chrome flags, distinguishing an absent tri-state flag from an explicit
/// enable/disable. `top_tab_bar` / `dashboard_status` / `dashboard_panel` / `picker_overlay` are all
/// `Option<bool>` (`None` = absent, `Some(true)` = explicit enable, `Some(false)` = explicit disable).
/// Pure input to [`resolve_attach_tab_chrome`]; constructed by the parsed
/// [`AttachTabArgs`](crate::AttachTabArgs).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AttachTabChromeFlags {
    /// `--top-tab-bar` / `--no-top-tab-bar`: `None` absent, `Some(true)` enable, `Some(false)` disable.
    pub top_tab_bar: Option<bool>,
    /// `--dashboard-status` / `--no-dashboard-status`: `None` absent, `Some(true)` enable, `Some(false)` disable.
    pub dashboard_status: Option<bool>,
    /// `--dashboard-panel` / `--no-dashboard-panel`: `None` absent, `Some(true)` enable, `Some(false)` disable.
    pub dashboard_panel: Option<bool>,
    /// `--picker-overlay` / `--no-picker-overlay`: `None` absent, `Some(true)` enable, `Some(false)` disable.
    /// Only consulted in foreground mode; None/detached always resolve picker overlay `false`.
    pub picker_overlay: Option<bool>,
}

/// The effective `attach-tab` chrome after applying the mode-aware default policy. Every field is a
/// resolved bool the caller acts on directly: build the dashboard snapshot/status/panel, set the
/// renderer's `top_tab_bar`, and stamp the success JSON.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EffectiveAttachTabChrome {
    pub top_tab_bar: bool,
    pub dashboard_status: bool,
    pub dashboard_panel: bool,
    pub picker_overlay: bool,
}

/// The foreground default ON/OFF for the configurable chrome defaults, resolved from the effective
/// settings (built-in `(true, true, false, false)` merged with any persisted `chrome.*_default` override).
/// Supplied by `main.rs` so an ABSENT `--top-tab-bar` / `--dashboard-status` / `--dashboard-panel` /
/// `--picker-overlay` flag falls back to the persisted (or built-in) default rather than a hardcoded value.
/// `picker_overlay` is consulted ONLY in foreground mode (None/detached always resolve `false`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttachTabChromeDefaults {
    pub top_tab_bar: bool,
    pub dashboard_status: bool,
    pub dashboard_panel: bool,
    pub picker_overlay: bool,
}

impl Default for AttachTabChromeDefaults {
    /// The built-in defaults: top tab bar / dashboard status ON, dashboard panel / picker overlay OFF.
    fn default() -> Self {
        Self {
            top_tab_bar: true,
            dashboard_status: true,
            dashboard_panel: false,
            picker_overlay: false,
        }
    }
}

/// Resolve the effective foreground/no-run/detached `attach-tab` chrome from the raw flags and the
/// supplied foreground defaults.
///
/// - [`RendererMode::Foreground`] and [`RendererMode::None`] (`--no-run-renderer`, a faithful
///   inspection of what the foreground window would show) share one default policy for top tab bar /
///   dashboard status / dashboard panel: an ABSENT flag falls back to `defaults` (the
///   persisted-or-built-in default); an explicit enable/disable always wins.
/// - `picker_overlay` is the exception: it is a FOREGROUND-ONLY overlay. In [`RendererMode::Foreground`]
///   an absent `--picker-overlay` flag falls back to `defaults.picker_overlay` and an explicit
///   enable/disable wins; but in [`RendererMode::None`] it ALWAYS resolves `false` regardless of the
///   flag or default (a persisted-on default must never leak into `--no-run-renderer`, which is
///   in-process but does not host the picker overlay surface).
/// - [`RendererMode::Detached`] carries NO app-owned chrome: every effective value is `false`
///   regardless of the flags or defaults (the parser already rejects explicit chrome ENABLES with
///   `--detach-renderer`; explicit DISABLES are accepted as harmless no-ops that resolve to `false`
///   here anyway).
pub fn resolve_attach_tab_chrome(
    mode: RendererMode,
    flags: AttachTabChromeFlags,
    defaults: AttachTabChromeDefaults,
) -> EffectiveAttachTabChrome {
    match mode {
        RendererMode::Foreground | RendererMode::None => EffectiveAttachTabChrome {
            top_tab_bar: flags.top_tab_bar.unwrap_or(defaults.top_tab_bar),
            dashboard_status: flags.dashboard_status.unwrap_or(defaults.dashboard_status),
            dashboard_panel: flags.dashboard_panel.unwrap_or(defaults.dashboard_panel),
            // Foreground-only: None never hosts the picker overlay, so it always resolves false there.
            picker_overlay: match mode {
                RendererMode::Foreground => flags.picker_overlay.unwrap_or(defaults.picker_overlay),
                _ => false,
            },
        },
        RendererMode::Detached => EffectiveAttachTabChrome::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_chrome_foreground_absent_defaults_on() {
        let eff = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            AttachTabChromeFlags::default(),
            AttachTabChromeDefaults::default(),
        );
        assert!(eff.top_tab_bar);
        assert!(eff.dashboard_status);
        assert!(!eff.dashboard_panel);
        assert!(!eff.picker_overlay);
    }

    #[test]
    fn resolve_chrome_none_matches_foreground_defaults() {
        let eff = resolve_attach_tab_chrome(
            RendererMode::None,
            AttachTabChromeFlags::default(),
            AttachTabChromeDefaults::default(),
        );
        assert!(eff.top_tab_bar);
        assert!(eff.dashboard_status);
        assert!(!eff.dashboard_panel);
        assert!(!eff.picker_overlay);
    }

    #[test]
    fn resolve_chrome_detached_all_false() {
        let flags = AttachTabChromeFlags {
            top_tab_bar: Some(true),
            dashboard_status: Some(true),
            dashboard_panel: Some(true),
            picker_overlay: Some(true),
        };
        let eff = resolve_attach_tab_chrome(
            RendererMode::Detached,
            flags,
            AttachTabChromeDefaults::default(),
        );
        assert!(!eff.top_tab_bar);
        assert!(!eff.dashboard_status);
        assert!(!eff.dashboard_panel);
        assert!(!eff.picker_overlay);
    }

    #[test]
    fn resolve_chrome_explicit_disable_wins_foreground() {
        let flags = AttachTabChromeFlags {
            top_tab_bar: Some(false),
            dashboard_status: Some(false),
            ..Default::default()
        };
        let eff = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            flags,
            AttachTabChromeDefaults::default(),
        );
        assert!(!eff.top_tab_bar);
        assert!(!eff.dashboard_status);
    }

    #[test]
    fn resolve_chrome_explicit_enable_wins_foreground() {
        let flags = AttachTabChromeFlags {
            top_tab_bar: Some(true),
            dashboard_status: Some(true),
            dashboard_panel: Some(true),
            picker_overlay: Some(true),
        };
        let eff = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            flags,
            AttachTabChromeDefaults::default(),
        );
        assert!(eff.top_tab_bar);
        assert!(eff.dashboard_status);
        assert!(eff.dashboard_panel);
        assert!(eff.picker_overlay);
    }

    #[test]
    fn resolve_chrome_absent_flags_follow_supplied_defaults_off() {
        // Persisted defaults OFF: an absent flag resolves to the supplied default, not a hardcoded ON.
        let defaults = AttachTabChromeDefaults {
            top_tab_bar: false,
            dashboard_status: false,
            dashboard_panel: false,
            picker_overlay: false,
        };
        let eff = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            AttachTabChromeFlags::default(),
            defaults,
        );
        assert!(!eff.top_tab_bar);
        assert!(!eff.dashboard_status);
    }

    #[test]
    fn resolve_chrome_explicit_enable_overrides_default_off() {
        // An explicit enable still wins even when the supplied default is OFF.
        let defaults = AttachTabChromeDefaults {
            top_tab_bar: false,
            dashboard_status: false,
            dashboard_panel: false,
            picker_overlay: false,
        };
        let flags = AttachTabChromeFlags {
            top_tab_bar: Some(true),
            dashboard_status: Some(true),
            ..Default::default()
        };
        let eff = resolve_attach_tab_chrome(RendererMode::Foreground, flags, defaults);
        assert!(eff.top_tab_bar);
        assert!(eff.dashboard_status);
    }

    #[test]
    fn resolve_chrome_explicit_disable_overrides_default_on() {
        // An explicit disable still wins even when the supplied default is ON.
        let flags = AttachTabChromeFlags {
            top_tab_bar: Some(false),
            dashboard_status: Some(false),
            ..Default::default()
        };
        let eff = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            flags,
            AttachTabChromeDefaults::default(),
        );
        assert!(!eff.top_tab_bar);
        assert!(!eff.dashboard_status);
    }

    #[test]
    fn resolve_chrome_detached_ignores_defaults() {
        // Detached carries no app chrome regardless of the supplied defaults.
        let defaults = AttachTabChromeDefaults {
            top_tab_bar: true,
            dashboard_status: true,
            dashboard_panel: true,
            picker_overlay: false,
        };
        let eff = resolve_attach_tab_chrome(
            RendererMode::Detached,
            AttachTabChromeFlags::default(),
            defaults,
        );
        assert!(!eff.top_tab_bar);
        assert!(!eff.dashboard_status);
    }

    #[test]
    fn resolve_chrome_dashboard_panel_absent_follows_default() {
        // Absent flag with a persisted default ON resolves ON; with default OFF resolves OFF.
        let on = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            AttachTabChromeFlags::default(),
            AttachTabChromeDefaults {
                top_tab_bar: true,
                dashboard_status: true,
                dashboard_panel: true,
                picker_overlay: false,
            },
        );
        assert!(on.dashboard_panel);
        let off = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            AttachTabChromeFlags::default(),
            AttachTabChromeDefaults::default(),
        );
        assert!(!off.dashboard_panel);
    }

    #[test]
    fn resolve_chrome_dashboard_panel_explicit_enable_overrides_default_off() {
        let flags = AttachTabChromeFlags {
            dashboard_panel: Some(true),
            ..Default::default()
        };
        let eff = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            flags,
            AttachTabChromeDefaults::default(),
        );
        assert!(eff.dashboard_panel);
    }

    #[test]
    fn resolve_chrome_dashboard_panel_explicit_disable_overrides_default_on() {
        let flags = AttachTabChromeFlags {
            dashboard_panel: Some(false),
            ..Default::default()
        };
        let eff = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            flags,
            AttachTabChromeDefaults {
                top_tab_bar: true,
                dashboard_status: true,
                dashboard_panel: true,
                picker_overlay: false,
            },
        );
        assert!(!eff.dashboard_panel);
    }

    #[test]
    fn resolve_chrome_dashboard_panel_detached_ignores_default_on() {
        // Detached carries no app chrome even when the persisted panel default is ON.
        let eff = resolve_attach_tab_chrome(
            RendererMode::Detached,
            AttachTabChromeFlags::default(),
            AttachTabChromeDefaults {
                top_tab_bar: true,
                dashboard_status: true,
                dashboard_panel: true,
                picker_overlay: false,
            },
        );
        assert!(!eff.dashboard_panel);
    }

    #[test]
    fn resolve_chrome_dashboard_panel_none_mode_follows_default_on() {
        // --no-run-renderer (None) mirrors the foreground default policy: a persisted ON shows ON.
        let eff = resolve_attach_tab_chrome(
            RendererMode::None,
            AttachTabChromeFlags::default(),
            AttachTabChromeDefaults {
                top_tab_bar: true,
                dashboard_status: true,
                dashboard_panel: true,
                picker_overlay: false,
            },
        );
        assert!(eff.dashboard_panel);
    }

    #[test]
    fn resolve_chrome_picker_overlay_foreground_absent_follows_default() {
        // Foreground: an absent flag resolves the supplied default ON, and OFF when default OFF.
        let on = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            AttachTabChromeFlags::default(),
            AttachTabChromeDefaults {
                top_tab_bar: true,
                dashboard_status: true,
                dashboard_panel: false,
                picker_overlay: true,
            },
        );
        assert!(on.picker_overlay);
        let off = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            AttachTabChromeFlags::default(),
            AttachTabChromeDefaults::default(),
        );
        assert!(!off.picker_overlay);
    }

    #[test]
    fn resolve_chrome_picker_overlay_explicit_enable_overrides_default_off() {
        let flags = AttachTabChromeFlags {
            picker_overlay: Some(true),
            ..Default::default()
        };
        let eff = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            flags,
            AttachTabChromeDefaults::default(),
        );
        assert!(eff.picker_overlay);
    }

    #[test]
    fn resolve_chrome_picker_overlay_explicit_disable_overrides_default_on() {
        let flags = AttachTabChromeFlags {
            picker_overlay: Some(false),
            ..Default::default()
        };
        let eff = resolve_attach_tab_chrome(
            RendererMode::Foreground,
            flags,
            AttachTabChromeDefaults {
                top_tab_bar: true,
                dashboard_status: true,
                dashboard_panel: false,
                picker_overlay: true,
            },
        );
        assert!(!eff.picker_overlay);
    }

    #[test]
    fn resolve_chrome_picker_overlay_none_mode_always_false_even_with_default_on() {
        // FOREGROUND-ONLY: --no-run-renderer (None) never hosts the picker overlay, so a persisted
        // default ON must NOT leak through — it always resolves false regardless of the default.
        let eff = resolve_attach_tab_chrome(
            RendererMode::None,
            AttachTabChromeFlags::default(),
            AttachTabChromeDefaults {
                top_tab_bar: true,
                dashboard_status: true,
                dashboard_panel: false,
                picker_overlay: true,
            },
        );
        assert!(!eff.picker_overlay);
    }

    #[test]
    fn resolve_chrome_picker_overlay_detached_always_false_even_with_default_on() {
        // Detached carries no app chrome even when the persisted picker-overlay default is ON.
        let eff = resolve_attach_tab_chrome(
            RendererMode::Detached,
            AttachTabChromeFlags::default(),
            AttachTabChromeDefaults {
                top_tab_bar: true,
                dashboard_status: true,
                dashboard_panel: false,
                picker_overlay: true,
            },
        );
        assert!(!eff.picker_overlay);
    }
}
