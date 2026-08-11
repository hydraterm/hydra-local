//! NamedColor / Indexed / Rgb -> RGB resolution against a launch-time palette.
//!
//! A [`Palette`] carries the foreground/background/cursor roles plus the 16 ANSI colors for one
//! launch-time theme. The renderer resolves every wire `Color` against its instance palette via
//! [`resolve_with_palette`], so two windows launched with different themes never share global color
//! state. [`palette`] maps a [`RendererTheme`] to its concrete `Palette`; `BuiltInDark` reproduces the
//! historical dark-metallic default byte-for-byte, while `HighContrastDark` is a deliberately
//! higher-contrast dark palette.

use crate::wire::{Color, NamedColor};

pub type Rgb = [u8; 3];

/// The launch-time renderer theme. Selected once by the app-shell caller (resolved from the persisted
/// `appearance.theme` setting) and carried on `RendererLaunch`; the renderer never reads settings
/// itself and never re-applies a theme at runtime. `BuiltInDark` is the historical default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RendererTheme {
    BuiltInDark,
    HighContrastDark,
}

/// The stable id for [`RendererTheme::BuiltInDark`] — the historical default, matching the
/// `maestro-app` `appearance.theme` default.
pub const THEME_ID_BUILT_IN_DARK: &str = "built_in_dark";
/// The stable id for [`RendererTheme::HighContrastDark`].
pub const THEME_ID_HIGH_CONTRAST_DARK: &str = "high_contrast_dark";

impl RendererTheme {
    /// Parse a stable theme id into a [`RendererTheme`]. Returns `None` for any unknown id so the
    /// caller can reject it (the renderer CLI exits 2; the app validates against its settings range).
    pub fn parse(id: &str) -> Option<Self> {
        match id {
            THEME_ID_BUILT_IN_DARK => Some(RendererTheme::BuiltInDark),
            THEME_ID_HIGH_CONTRAST_DARK => Some(RendererTheme::HighContrastDark),
            _ => None,
        }
    }

    /// The stable id for this theme. Round-trips with [`RendererTheme::parse`].
    pub fn id(self) -> &'static str {
        match self {
            RendererTheme::BuiltInDark => THEME_ID_BUILT_IN_DARK,
            RendererTheme::HighContrastDark => THEME_ID_HIGH_CONTRAST_DARK,
        }
    }
}

/// Dark-metallic foreground role: the historical default text color. Kept as a `pub const` so app-owned
/// chrome (top bar, picker overlay) that is theme-independent keeps its existing values.
pub const FOREGROUND: Rgb = [0xd0, 0xd0, 0xd0];
/// Dark-metallic background role: near-black with a faint cool cast. The historical default surface.
pub const BACKGROUND: Rgb = [0x05, 0x06, 0x07];
/// Dark-metallic cursor role.
pub const CURSOR: Rgb = [0xd0, 0xd0, 0xd0];

// The 16 ANSI colors for the built-in dark theme (standard xterm-ish values).
const ANSI_BUILT_IN_DARK: [Rgb; 16] = [
    [0x00, 0x00, 0x00], // black
    [0xcd, 0x00, 0x00], // red
    [0x00, 0xcd, 0x00], // green
    [0xcd, 0xcd, 0x00], // yellow
    [0x00, 0x00, 0xee], // blue
    [0xcd, 0x00, 0xcd], // magenta
    [0x00, 0xcd, 0xcd], // cyan
    [0xe5, 0xe5, 0xe5], // white
    [0x7f, 0x7f, 0x7f], // bright black
    [0xff, 0x00, 0x00], // bright red
    [0x00, 0xff, 0x00], // bright green
    [0xff, 0xff, 0x00], // bright yellow
    [0x5c, 0x5c, 0xff], // bright blue
    [0xff, 0x00, 0xff], // bright magenta
    [0x00, 0xff, 0xff], // bright cyan
    [0xff, 0xff, 0xff], // bright white
];

// The high-contrast dark theme: pure-black background and pure-white foreground/cursor for maximal
// separation, and brighter, more saturated ANSI primaries so colored text stays legible against black.
const HC_FOREGROUND: Rgb = [0xff, 0xff, 0xff];
const HC_BACKGROUND: Rgb = [0x00, 0x00, 0x00];
const HC_CURSOR: Rgb = [0xff, 0xff, 0xff];
const ANSI_HIGH_CONTRAST_DARK: [Rgb; 16] = [
    [0x00, 0x00, 0x00], // black
    [0xff, 0x40, 0x40], // red (brighter than built-in)
    [0x40, 0xff, 0x40], // green
    [0xff, 0xff, 0x40], // yellow
    [0x60, 0x80, 0xff], // blue (lifted off pure blue for legibility on black)
    [0xff, 0x60, 0xff], // magenta
    [0x40, 0xff, 0xff], // cyan
    [0xff, 0xff, 0xff], // white
    [0xa8, 0xa8, 0xa8], // bright black (lighter than built-in for visible "dim")
    [0xff, 0x60, 0x60], // bright red
    [0x60, 0xff, 0x60], // bright green
    [0xff, 0xff, 0x60], // bright yellow
    [0x80, 0xa0, 0xff], // bright blue
    [0xff, 0x80, 0xff], // bright magenta
    [0x60, 0xff, 0xff], // bright cyan
    [0xff, 0xff, 0xff], // bright white
];

/// One launch-time theme's concrete colors: the foreground/background/cursor roles plus the 16 ANSI
/// colors. A `Renderer` stores exactly one of these and resolves every wire `Color` against it, so
/// color resolution is per-instance and free of global mutable state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    pub foreground: Rgb,
    pub background: Rgb,
    pub cursor: Rgb,
    pub ansi: [Rgb; 16],
}

/// The concrete [`Palette`] for a launch-time theme.
pub fn palette(theme: RendererTheme) -> Palette {
    match theme {
        RendererTheme::BuiltInDark => Palette {
            foreground: FOREGROUND,
            background: BACKGROUND,
            cursor: CURSOR,
            ansi: ANSI_BUILT_IN_DARK,
        },
        RendererTheme::HighContrastDark => Palette {
            foreground: HC_FOREGROUND,
            background: HC_BACKGROUND,
            cursor: HC_CURSOR,
            ansi: ANSI_HIGH_CONTRAST_DARK,
        },
    }
}

/// The default palette used when no launch theme is supplied (`RendererLaunch.theme == None`) and by
/// the demo/stress paths. Equal to the built-in dark palette, preserving historical bare-renderer
/// behavior byte-for-byte.
pub fn default_palette() -> Palette {
    palette(RendererTheme::BuiltInDark)
}

/// Scale a color toward black for the dim_* variants and the `dim` attribute (60% of base).
/// Theme-independent: dimming is a uniform transform applied to an already-resolved color.
fn dim(c: Rgb) -> Rgb {
    [
        (c[0] as f32 * 0.6) as u8,
        (c[1] as f32 * 0.6) as u8,
        (c[2] as f32 * 0.6) as u8,
    ]
}

fn named(n: NamedColor, p: &Palette) -> Rgb {
    use NamedColor::*;
    match n {
        Black => p.ansi[0],
        Red => p.ansi[1],
        Green => p.ansi[2],
        Yellow => p.ansi[3],
        Blue => p.ansi[4],
        Magenta => p.ansi[5],
        Cyan => p.ansi[6],
        White => p.ansi[7],
        BrightBlack => p.ansi[8],
        BrightRed => p.ansi[9],
        BrightGreen => p.ansi[10],
        BrightYellow => p.ansi[11],
        BrightBlue => p.ansi[12],
        BrightMagenta => p.ansi[13],
        BrightCyan => p.ansi[14],
        BrightWhite => p.ansi[15],
        Foreground => p.foreground,
        Background => p.background,
        Cursor => p.cursor,
        DimBlack => dim(p.ansi[0]),
        DimRed => dim(p.ansi[1]),
        DimGreen => dim(p.ansi[2]),
        DimYellow => dim(p.ansi[3]),
        DimBlue => dim(p.ansi[4]),
        DimMagenta => dim(p.ansi[5]),
        DimCyan => dim(p.ansi[6]),
        DimWhite => dim(p.ansi[7]),
        BrightForeground => [0xff, 0xff, 0xff],
        DimForeground => dim(p.foreground),
    }
}

/// Resolve an xterm 256-color index to RGB: 0..16 the palette's ANSI colors, 16..232 the 6x6x6 cube,
/// 232..256 the grayscale ramp. The cube and ramp are theme-independent (standard xterm math); only
/// the first 16 entries follow the palette.
fn indexed(i: u8, p: &Palette) -> Rgb {
    let i = i as usize;
    if i < 16 {
        p.ansi[i]
    } else if i < 232 {
        let n = i - 16;
        let r = n / 36;
        let g = (n % 36) / 6;
        let b = n % 6;
        let chan = |v: usize| -> u8 {
            if v == 0 {
                0
            } else {
                (v * 40 + 55) as u8
            }
        };
        [chan(r), chan(g), chan(b)]
    } else {
        let level = (8 + (i - 232) * 10) as u8;
        [level, level, level]
    }
}

/// Resolve any wire `Color` to an RGB triple against the supplied launch-time palette.
pub fn resolve_with_palette(c: Color, p: &Palette) -> Rgb {
    match c {
        Color::Named { name } => named(name, p),
        Color::Indexed { index } => indexed(index, p),
        Color::Rgb { r, g, b } => [r, g, b],
    }
}

/// Apply the `dim` attribute: scale a resolved color to 60%. Theme-independent.
pub fn apply_dim(c: Rgb) -> Rgb {
    dim(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Color, NamedColor};

    #[test]
    fn theme_id_round_trips_both_supported_ids() {
        for t in [RendererTheme::BuiltInDark, RendererTheme::HighContrastDark] {
            assert_eq!(RendererTheme::parse(t.id()), Some(t));
        }
        assert_eq!(
            RendererTheme::parse("built_in_dark"),
            Some(RendererTheme::BuiltInDark)
        );
        assert_eq!(
            RendererTheme::parse("high_contrast_dark"),
            Some(RendererTheme::HighContrastDark)
        );
    }

    #[test]
    fn unknown_theme_id_is_rejected() {
        assert_eq!(RendererTheme::parse("solarized"), None);
        assert_eq!(RendererTheme::parse(""), None);
        assert_eq!(RendererTheme::parse("BUILT_IN_DARK"), None);
    }

    #[test]
    fn built_in_dark_palette_preserves_historical_defaults() {
        let p = palette(RendererTheme::BuiltInDark);
        assert_eq!(p.foreground, FOREGROUND);
        assert_eq!(p.background, BACKGROUND);
        assert_eq!(p.cursor, CURSOR);
        assert_eq!(p.ansi, ANSI_BUILT_IN_DARK);
        // The default palette (no launch theme) is byte-identical to built-in dark.
        assert_eq!(default_palette(), p);
    }

    /// A live theme swap re-resolves the palette purely from the theme id, so swapping away and back
    /// restores the byte-identical palette. This is the invariant `Renderer::set_theme` relies on.
    #[test]
    fn theme_swap_round_trips_to_byte_identical_palette() {
        let built_in = palette(RendererTheme::BuiltInDark);
        let high = palette(RendererTheme::HighContrastDark);
        assert_ne!(built_in, high, "the two palettes must differ");
        // Swapping back to a previously-active theme yields the exact same palette.
        assert_eq!(palette(RendererTheme::BuiltInDark), built_in);
        assert_eq!(palette(RendererTheme::HighContrastDark), high);
    }

    #[test]
    fn built_in_and_high_contrast_palettes_differ() {
        let built_in = palette(RendererTheme::BuiltInDark);
        let high = palette(RendererTheme::HighContrastDark);
        // They must differ in at least one of the principal roles.
        assert!(
            built_in.foreground != high.foreground
                || built_in.background != high.background
                || built_in.cursor != high.cursor,
            "built-in and high-contrast palettes must differ in fg/bg/cursor"
        );
        // Concretely: high-contrast is pure white on pure black.
        assert_eq!(high.background, [0x00, 0x00, 0x00]);
        assert_eq!(high.foreground, [0xff, 0xff, 0xff]);
    }

    #[test]
    fn resolution_is_deterministic_for_named_indexed_and_rgb() {
        for theme in [RendererTheme::BuiltInDark, RendererTheme::HighContrastDark] {
            let p = palette(theme);
            // Named roles resolve to the palette roles.
            assert_eq!(
                resolve_with_palette(
                    Color::Named {
                        name: NamedColor::Foreground
                    },
                    &p
                ),
                p.foreground
            );
            assert_eq!(
                resolve_with_palette(
                    Color::Named {
                        name: NamedColor::Red
                    },
                    &p
                ),
                p.ansi[1]
            );
            // Indexed 0..16 follows the palette ANSI; the 6x6x6 cube and ramp are theme-independent.
            assert_eq!(
                resolve_with_palette(Color::Indexed { index: 1 }, &p),
                p.ansi[1]
            );
            assert_eq!(
                resolve_with_palette(Color::Indexed { index: 196 }, &p),
                [0xff, 0x00, 0x00]
            );
            assert_eq!(
                resolve_with_palette(Color::Indexed { index: 232 }, &p),
                [0x08, 0x08, 0x08]
            );
            // Direct RGB is identity regardless of theme.
            assert_eq!(
                resolve_with_palette(Color::Rgb { r: 1, g: 2, b: 3 }, &p),
                [1, 2, 3]
            );
        }
    }
}
