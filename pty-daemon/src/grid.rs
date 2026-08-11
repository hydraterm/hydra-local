//! The authoritative terminal grid. This is the heart of the rewrite: instead
//! of three state authorities (tmux grid, xterm buffer, the TUI's own size)
//! that drift apart, the daemon parses PTY output through one VT engine
//! (`alacritty_terminal`) and holds the single canonical grid. The renderer
//! paints a snapshot of this grid; it never re-parses bytes, so it cannot
//! disagree about the screen.

use crate::ids::SessionId;
use crate::protocol::{
    CursorState, DamageFrame, DamageOp, ModeState, DAMAGE_SCHEMA, MAX_DAMAGE_CELLS, MAX_DAMAGE_OPS,
    MAX_SCROLLBACK_ROWS_PER_REQUEST,
};
use crate::revision::{Revision, SessionGeneration};
use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::{Cell as AlacrittyCell, Flags};
use alacritty_terminal::term::{Config, Term, TermDamage, TermMode};
use alacritty_terminal::vte::ansi::{
    Color as AnsiColor, CursorShape as AnsiCursorShape, NamedColor as AnsiNamedColor, Processor,
    Rgb,
};
use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

/// Dimensions handed to `Term`. alacritty wants total lines (scrollback +
/// screen); we keep a fixed history so reattach has context to repaint.
#[derive(Clone, Copy)]
struct GridSize {
    cols: usize,
    screen_lines: usize,
    history: usize,
}

impl Dimensions for GridSize {
    fn total_lines(&self) -> usize {
        self.screen_lines + self.history
    }
    fn screen_lines(&self) -> usize {
        self.screen_lines
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

/// Alacritty emits terminal-generated replies (DA/DSR/mode reports, size and
/// color queries) as events because its normal application owns the PTY writer.
/// Hydra's parser lives in the daemon, so queue those events for `Session` to
/// write back to the same PTY. Display-only events remain intentionally ignored.
#[derive(Clone)]
struct GridEventListener {
    pending: Arc<Mutex<Vec<Event>>>,
}
impl EventListener for GridEventListener {
    fn send_event(&self, event: Event) {
        match event {
            Event::PtyWrite(_)
            | Event::TextAreaSizeRequest(_)
            | Event::ColorRequest(_, _)
            | Event::Bell
            | Event::Title(_)
            | Event::ResetTitle
            | Event::ClipboardStore(_, _)
            | Event::ClipboardLoad(_, _) => {
                self.pending.lock().unwrap().push(event);
            }
            _ => {}
        }
    }
}

/// Scrollback history kept by the grid, in lines. Bounded so a long-running
/// agent can't grow memory without limit; deeper history is the agent's own
/// concern (it resumes via --continue on a cold start).
///
/// This is the row-count ceiling only. `MAX_SCROLLBACK_CELLS` below additionally
/// caps total CELLS (rows × cols) so a wide grid can't multiply this row count by
/// thousands of columns. Neither bounds bytes-per-cell (see the note on
/// `MAX_SCROLLBACK_CELLS`).
const HISTORY_LINES: usize = 5000;

/// Hard cap on total scrollback cells (history rows × columns) the grid retains.
///
/// `HISTORY_LINES` alone bounds rows but not cell count: at the `MAX_DIMENSION`
/// (2000) column ceiling, 5000 history rows would hold 10M cells. Capping total
/// cells makes the retained-cell count independent of column count: the effective
/// history-row budget is `MAX_SCROLLBACK_CELLS / cols`, so a wider grid keeps fewer
/// history rows and a narrow grid keeps up to `HISTORY_LINES`.
///
/// 2000 cols × 5000 rows would be 10M cells; we hold history to a fifth of that.
/// At the 80-col common case this is far more than `HISTORY_LINES`, so the row
/// budget clamps to `HISTORY_LINES` and the cell cap never bites; it only
/// engages for unusually wide grids, which is exactly where cell count blows up.
///
/// NOTE — this is a retained-CELL-COUNT cap. [`TermGrid::advance`] separately trims the
/// VT engine's own per-cell combining-mark storage to `MAX_CELL_TEXT_BYTES` after every
/// bounded parser advance. The cap therefore applies to retained daemon memory, not only
/// to the later wire projection.
const MAX_SCROLLBACK_CELLS: usize = 2_000_000;

/// Maximum PTY-output slice handed to the VT parser before the daemon enforces its
/// per-cell retained-text cap. A single malicious write can contain arbitrarily many
/// combining marks; chunking prevents the engine's private `Vec<char>` from growing by
/// the full caller-controlled input size before we get a chance to trim it.
const MAX_PARSER_ADVANCE_BYTES: usize = 4 * 1024;

/// Effective scrollback history-row budget for a grid `cols` wide: the largest
/// row count whose total cells stay within `MAX_SCROLLBACK_CELLS`, clamped to
/// `[1, HISTORY_LINES]`. `cols` is always ≥ 1 (clamped by `clamp_dim`), so the
/// division never traps; the `max(1)` guarantees at least one history row even at
/// the widest grid so reattach still has some context.
fn history_budget(cols: usize) -> usize {
    (MAX_SCROLLBACK_CELLS / cols.max(1)).clamp(1, HISTORY_LINES)
}

/// Upper bound on grid dimensions. A client controls cols/rows, and alacritty
/// allocates a grid of `cols * (rows + history)` cells eagerly — an unchecked
/// 65535×65535 request would try to allocate billions of cells and OOM the
/// daemon. Clamp to a generous ceiling no real terminal exceeds.
const MAX_DIMENSION: u16 = 2000;

/// Clamp a client-supplied dimension into `[1, MAX_DIMENSION]`.
fn clamp_dim(v: u16) -> usize {
    v.clamp(1, MAX_DIMENSION) as usize
}

/// Conservative worst-case serialized byte cost of ONE snapshot/damage `Cell` on the
/// wire, used to derive `MAX_SNAPSHOT_CELLS`. A maximal cell carries 64-byte `text`,
/// two `{"kind":"rgb","r":255,"g":255,"b":255}` colors, every boolean attribute set
/// true, an underline variant, and `width`. The real serialization of such a cell is
/// ~180 bytes; we round UP to 256 for headroom (JSON whitespace variations, future
/// additive fields). Intentionally pessimistic — it only shrinks the guaranteed grid.
const WORST_CASE_CELL_BYTES: usize = 256;

/// Fixed per-line overhead budget for snapshot envelope/header bytes outside the cell
/// array (version, generation UUID, revisions, cursor, mode flags, the `rows_cells`
/// nesting, the `"ev"`/`"grid"`/`"id"` wrapping). 4 KiB is far more than the header
/// ever needs; reserving it keeps the cell budget honest.
const SNAPSHOT_HEADER_BYTES: usize = 4 * 1024;

/// Maximum total cells (cols * rows) whose worst-case JSON snapshot is GUARANTEED to
/// fit within `protocol::MAX_LINE_BYTES` (the framing cap), with a 2x safety margin.
/// A snapshot is shipped as ONE newline-delimited JSON line, so a grid that would
/// serialize past the line cap can never cross the socket — it would be dropped as a
/// framing violation. We therefore bound the grid that the daemon will ACCEPT to this
/// budget at `StartSession`/`Resize`, so the authoritative grid is always wire-shippable.
/// Derivation: `(MAX_LINE_BYTES / 2 - SNAPSHOT_HEADER_BYTES) / WORST_CASE_CELL_BYTES`.
/// Larger grids require a future length-prefixed or chunked binary snapshot transport.
pub const MAX_SNAPSHOT_CELLS: usize =
    (crate::protocol::MAX_LINE_BYTES / 2 - SNAPSHOT_HEADER_BYTES) / WORST_CASE_CELL_BYTES;

// Compile-time proof of the derivation: the budget is positive and its worst-case
// serialized footprint stays within the line cap with the 2x safety margin. If a future
// edit to the inputs breaks this, the crate fails to compile rather than shipping an
// un-shippable grid budget.
const _: () = {
    assert!(MAX_SNAPSHOT_CELLS > 0);
    assert!(
        MAX_SNAPSHOT_CELLS * WORST_CASE_CELL_BYTES + SNAPSHOT_HEADER_BYTES
            <= crate::protocol::MAX_LINE_BYTES / 2
    );
};

/// Does a `cols * rows` grid fit the snapshot cell budget? Guards the multiplication
/// against overflow (returns `false` on overflow rather than wrapping to a small
/// product that would falsely pass). Zero dims are not this function's concern
/// (callers clamp to >= 1).
pub fn fits_snapshot_budget(cols: u16, rows: u16) -> bool {
    match (cols as usize).checked_mul(rows as usize) {
        Some(cells) => cells <= MAX_SNAPSHOT_CELLS,
        None => false,
    }
}

/// Clamp a `(cols, rows)` request down to the snapshot cell budget while preserving
/// aspect ratio as closely as integer math allows. Used by the native UI resize path
/// (which should clamp rather than be rejected). If the grid already fits, it is
/// returned unchanged. Both returned dims are guaranteed >= 1 and their product <=
/// `MAX_SNAPSHOT_CELLS`.
pub fn clamp_to_snapshot_budget(cols: u16, rows: u16) -> (u16, u16) {
    let c = clamp_dim(cols);
    let r = clamp_dim(rows);
    if c * r <= MAX_SNAPSHOT_CELLS {
        return (c as u16, r as u16);
    }
    // Scale both dims by sqrt(budget / area), preserving aspect ratio. Use f64 for the
    // factor, then floor and re-clamp to >= 1, and finally trim one dim if rounding
    // still left us a hair over budget.
    let area = (c * r) as f64;
    let factor = (MAX_SNAPSHOT_CELLS as f64 / area).sqrt();
    let mut nc = ((c as f64 * factor).floor() as usize).max(1);
    let mut nr = ((r as f64 * factor).floor() as usize).max(1);
    while nc * nr > MAX_SNAPSHOT_CELLS {
        if nc >= nr {
            nc -= 1;
        } else {
            nr -= 1;
        }
        nc = nc.max(1);
        nr = nr.max(1);
        if nc == 1 && nr == 1 {
            break;
        }
    }
    (nc as u16, nr as u16)
}

/// Normalize a (cols, rows) pair to the canonical dimensions the daemon will use,
/// as `u16`. This is the SINGLE place dimensions are clamped, so the PTY and the
/// grid can be sized from one identical pair — sizing the PTY from raw
/// client values while the grid silently clamps would drift them apart, breaking
/// the "one authoritative geometry" invariant. Returns values guaranteed to fit
/// `u16` because `MAX_DIMENSION` does.
pub fn normalize_dims(cols: u16, rows: u16) -> (u16, u16) {
    (clamp_dim(cols) as u16, clamp_dim(rows) as u16)
}

/// Wire schema version for `GridSnapshot`. Bump when the shape changes so a
/// renderer can refuse a snapshot it doesn't understand. v1 = first rich-cell
/// snapshot (fg/bg/attrs/width per cell, cursor shape+visibility, alt-screen).
/// v2 = adds terminal input modes (app_cursor/bracketed_paste/focus_reporting)
/// so the renderer can encode keys/paste/focus correctly. This is a SEMANTIC
/// change: a v1 snapshot carries no mode info, so a renderer must refuse it
/// rather than default the modes to false and silently mis-encode arrows/paste.
///
/// CONTRACT: the daemon and renderer must share the same protocol MAJOR version. Shared
/// request-side wire types live in `maestro-protocol`; grid snapshots remain daemon-owned and
/// are cross-checked against the renderer fixtures.
pub const SNAPSHOT_VERSION: u32 = 2;

/// A semantic palette slot, named in Maestro's own vocabulary rather than by
/// alacritty's numeric discriminant. The wire used to ship the raw `NamedColor`
/// integer (Foreground = 256, etc.), which silently coupled the protocol to
/// alacritty's enum layout — a dependency bump could renumber it and break every
/// renderer. These stable string-tagged names are ours: the renderer resolves
/// each against its theme palette (the 16 ANSI colors, the fg/bg/cursor roles,
/// and the dim/bright role variants a terminal can request).
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NamedColor {
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    BrightBlack,
    BrightRed,
    BrightGreen,
    BrightYellow,
    BrightBlue,
    BrightMagenta,
    BrightCyan,
    BrightWhite,
    Foreground,
    Background,
    Cursor,
    DimBlack,
    DimRed,
    DimGreen,
    DimYellow,
    DimBlue,
    DimMagenta,
    DimCyan,
    DimWhite,
    BrightForeground,
    DimForeground,
}

impl From<AnsiNamedColor> for NamedColor {
    fn from(c: AnsiNamedColor) -> Self {
        match c {
            AnsiNamedColor::Black => NamedColor::Black,
            AnsiNamedColor::Red => NamedColor::Red,
            AnsiNamedColor::Green => NamedColor::Green,
            AnsiNamedColor::Yellow => NamedColor::Yellow,
            AnsiNamedColor::Blue => NamedColor::Blue,
            AnsiNamedColor::Magenta => NamedColor::Magenta,
            AnsiNamedColor::Cyan => NamedColor::Cyan,
            AnsiNamedColor::White => NamedColor::White,
            AnsiNamedColor::BrightBlack => NamedColor::BrightBlack,
            AnsiNamedColor::BrightRed => NamedColor::BrightRed,
            AnsiNamedColor::BrightGreen => NamedColor::BrightGreen,
            AnsiNamedColor::BrightYellow => NamedColor::BrightYellow,
            AnsiNamedColor::BrightBlue => NamedColor::BrightBlue,
            AnsiNamedColor::BrightMagenta => NamedColor::BrightMagenta,
            AnsiNamedColor::BrightCyan => NamedColor::BrightCyan,
            AnsiNamedColor::BrightWhite => NamedColor::BrightWhite,
            AnsiNamedColor::Foreground => NamedColor::Foreground,
            AnsiNamedColor::Background => NamedColor::Background,
            AnsiNamedColor::Cursor => NamedColor::Cursor,
            AnsiNamedColor::DimBlack => NamedColor::DimBlack,
            AnsiNamedColor::DimRed => NamedColor::DimRed,
            AnsiNamedColor::DimGreen => NamedColor::DimGreen,
            AnsiNamedColor::DimYellow => NamedColor::DimYellow,
            AnsiNamedColor::DimBlue => NamedColor::DimBlue,
            AnsiNamedColor::DimMagenta => NamedColor::DimMagenta,
            AnsiNamedColor::DimCyan => NamedColor::DimCyan,
            AnsiNamedColor::DimWhite => NamedColor::DimWhite,
            AnsiNamedColor::BrightForeground => NamedColor::BrightForeground,
            AnsiNamedColor::DimForeground => NamedColor::DimForeground,
        }
    }
}

/// A terminal color on the wire, in Maestro's own vocabulary:
/// - `Named` is a semantic palette slot the renderer resolves against its theme.
/// - `Indexed(u8)` is a 256-color palette index.
/// - `Rgb { r, g, b }` is a literal truecolor value.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Color {
    Named { name: NamedColor },
    Indexed { index: u8 },
    Rgb { r: u8, g: u8, b: u8 },
}

impl From<AnsiColor> for Color {
    fn from(c: AnsiColor) -> Self {
        match c {
            AnsiColor::Named(named) => Color::Named { name: named.into() },
            AnsiColor::Indexed(i) => Color::Indexed { index: i },
            AnsiColor::Spec(rgb) => Color::Rgb {
                r: rgb.r,
                g: rgb.g,
                b: rgb.b,
            },
        }
    }
}

/// Cursor shape on the wire. Maps from alacritty's `CursorShape`; the renderer
/// only needs the three visually distinct forms, so HollowBlock collapses to
/// Block and Hidden is represented via `cursor_visible: false`.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CursorShape {
    Block,
    Underline,
    Beam,
}

impl From<AnsiCursorShape> for CursorShape {
    fn from(s: AnsiCursorShape) -> Self {
        match s {
            AnsiCursorShape::Block | AnsiCursorShape::HollowBlock | AnsiCursorShape::Hidden => {
                CursorShape::Block
            }
            AnsiCursorShape::Underline => CursorShape::Underline,
            AnsiCursorShape::Beam => CursorShape::Beam,
        }
    }
}

/// Underline style on the wire. alacritty tracks the kind of underline in
/// `cell.flags`; we collapse those flags to one of these variants so the
/// renderer can pick the right line decoration. `None` = no underline.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnderlineStyle {
    #[default]
    None,
    Single,
    Double,
    Curly,
    Dotted,
    Dashed,
}

impl UnderlineStyle {
    /// Map alacritty's underline flags to a single wire variant. The flags are
    /// mutually exclusive in practice (the parser sets one at a time); we check
    /// in a fixed order and default to `None` when no underline flag is set.
    fn from_flags(flags: Flags) -> Self {
        if flags.contains(Flags::DOUBLE_UNDERLINE) {
            UnderlineStyle::Double
        } else if flags.contains(Flags::UNDERCURL) {
            UnderlineStyle::Curly
        } else if flags.contains(Flags::DOTTED_UNDERLINE) {
            UnderlineStyle::Dotted
        } else if flags.contains(Flags::DASHED_UNDERLINE) {
            UnderlineStyle::Dashed
        } else if flags.contains(Flags::UNDERLINE) {
            UnderlineStyle::Single
        } else {
            UnderlineStyle::None
        }
    }
}

/// Hard cap on the UTF-8 byte length of a single `Cell::text` (one grapheme cluster:
/// a base char plus any combining / zero-width marks). 64 bytes is already extremely
/// generous — even a long ZWJ emoji sequence stays well under it. Enforced DURING
/// deserialization (a custom visitor rejects an over-long string before the whole
/// frame is built), so a peer can't inflate a frame with megabyte "cells".
/// NOTE: `protocol::MAX_LINE_BYTES` remains the hard pre-parse memory bound — serde_json
/// may still allocate a temporary for an escaped string before this visitor sees it;
/// this cap bounds the STORED value and rejects early, it does not replace the line cap.
pub const MAX_CELL_TEXT_BYTES: usize = 64;

/// One cell of the authoritative grid with its visual attributes. `width`:
/// 1 = normal, 2 = lead cell of a wide (CJK/emoji) glyph, 0 = the spacer that
/// follows a wide lead cell (the renderer should skip drawing it).
///
/// `text` is the full grapheme for this cell: the base character followed by any
/// combining / zero-width chars alacritty attached to it (so an accented letter
/// or an emoji ZWJ sequence survives losslessly). For a wide-char spacer cell
/// (`width == 0`) `text` is the empty string.
///
/// `text` is a `CompactString`: it inlines up to 24 bytes on the stack, so the common
/// cell (one ASCII/BMP grapheme, well under 24 bytes) carries its text with NO heap
/// allocation. It serializes byte-identically to a plain JSON string, so the wire shape
/// is unchanged. `MAX_CELL_TEXT_BYTES` (64) can exceed the inline threshold; an unusually
/// long grapheme cluster spills to the heap exactly as a `String` would — correct, just
/// not allocation-free.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Cell {
    #[serde(deserialize_with = "deserialize_cell_text")]
    pub text: CompactString,
    pub fg: Color,
    pub bg: Color,
    #[serde(default)]
    pub bold: bool,
    #[serde(default)]
    pub italic: bool,
    #[serde(default)]
    pub underline: UnderlineStyle,
    #[serde(default)]
    pub inverse: bool,
    #[serde(default)]
    pub strikeout: bool,
    #[serde(default)]
    pub dim: bool,
    #[serde(default)]
    pub hidden: bool,
    pub width: u8,
}

/// Deserialize `Cell::text`, rejecting any string longer than `MAX_CELL_TEXT_BYTES`
/// AS IT IS READ — the visitor checks the borrowed/owned `&str` length before storing
/// it, so an over-long cell text fails the parse early rather than after the whole
/// frame is constructed. (serde_json may still allocate a temporary for an escaped
/// string internally; `MAX_LINE_BYTES` is the hard pre-parse memory bound. This guard
/// bounds the value we KEEP and the per-cell amplification a frame can carry.)
fn deserialize_cell_text<'de, D>(de: D) -> Result<CompactString, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, Visitor};
    use std::fmt;

    struct TextVisitor;
    impl Visitor<'_> for TextVisitor {
        type Value = CompactString;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a cell text string up to {MAX_CELL_TEXT_BYTES} bytes")
        }
        fn visit_str<E: Error>(self, v: &str) -> Result<CompactString, E> {
            if v.len() > MAX_CELL_TEXT_BYTES {
                return Err(E::custom(format!(
                    "cell text {} bytes exceeds {MAX_CELL_TEXT_BYTES}",
                    v.len()
                )));
            }
            Ok(CompactString::from(v))
        }
        fn visit_string<E: Error>(self, v: String) -> Result<CompactString, E> {
            if v.len() > MAX_CELL_TEXT_BYTES {
                return Err(E::custom(format!(
                    "cell text {} bytes exceeds {MAX_CELL_TEXT_BYTES}",
                    v.len()
                )));
            }
            Ok(CompactString::from(v))
        }
    }
    de.deserialize_str(TextVisitor)
}

/// One screen of the authoritative grid, as rich cells, for the wire. Rows are
/// the visible viewport top-to-bottom; each inner Vec is exactly `cols` long
/// (no trailing-blank trimming — the renderer needs full rows so it can paint
/// every cell's background color). The renderer paints these directly.
///
/// Wire contract: `rows_cells` is row-major, top row first; each inner Vec is
/// exactly `cols` long. Consumers MUST ignore unknown fields for forward
/// compatibility (new cell/snapshot attributes may be added under the same
/// `version` only when they are additive and default-safe).
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GridSnapshot {
    /// Wire schema version (see `SNAPSHOT_VERSION`).
    pub version: u32,
    /// The grid lifetime this snapshot belongs to. A renderer that later sees a
    /// different generation must discard and re-snapshot (see `revision` module).
    pub generation: SessionGeneration,
    /// The revision this snapshot was taken at. Subsequent incremental damage is
    /// applied only if the renderer's revision matches the damage's base.
    pub revision: Revision,
    /// The revision this snapshot continues FROM: the grid's revision immediately
    /// before the mutation that produced `revision`. It encodes strict continuity
    /// — a renderer already holding `base_revision` can fast-forward to `revision`
    /// without a gap; a renderer holding anything else (or a different generation)
    /// must take this snapshot as a fresh baseline. For the initial snapshot of a
    /// generation (no prior mutation) `base_revision == revision`, marking it
    /// self-baselining: it depends on nothing earlier.
    pub base_revision: Revision,
    pub cols: usize,
    pub rows: usize,
    /// Visible cells, top-to-bottom, each row exactly `cols` cells wide.
    pub rows_cells: Vec<Vec<Cell>>,
    pub cursor_line: usize,
    pub cursor_col: usize,
    /// Whether the terminal currently shows its cursor (DECTCEM / `Mode::SHOW_CURSOR`).
    pub cursor_visible: bool,
    pub cursor_shape: CursorShape,
    /// Whether the grid is currently on the alternate screen (full-screen TUI).
    pub alt_screen: bool,
    /// DECCKM application-cursor mode: arrows/Home/End emit `\x1bO_` not `\x1b[_`.
    pub app_cursor: bool,
    /// Bracketed-paste mode: pasted text must be wrapped in `\x1b[200~`/`\x1b[201~`.
    pub bracketed_paste: bool,
    /// Focus-reporting mode: window focus changes emit `\x1b[I`/`\x1b[O`.
    pub focus_reporting: bool,
    /// Mouse click reporting (DECSET 1000): the app wants button press/release events.
    /// `#[serde(default)]` keeps older frames (which lack the field) decodable as `false`,
    /// so the mirrored renderer protocol stays backward-compatible across deploys.
    #[serde(default)]
    pub mouse_report: bool,
    /// Mouse button-drag reporting (DECSET 1002): also report motion WHILE a button is held.
    #[serde(default)]
    pub mouse_drag: bool,
    /// Mouse any-motion reporting (DECSET 1003): report motion even with no button held.
    #[serde(default)]
    pub mouse_motion: bool,
    /// SGR extended mouse encoding (DECSET 1006): report as `\x1b[<b;x;yM`/`m` instead of
    /// the legacy X10 `\x1b[M` byte-triple (which cannot address coords past 223).
    #[serde(default)]
    pub mouse_sgr: bool,
    /// DAEMON-INTERNAL, OFF-WIRE per-row content stamps (one per visible row, same length
    /// as `rows_cells`). A row's stamp is bumped to a fresh monotonic value each time the
    /// VT engine reports that row as damaged during `advance`/`resize`. `generate_damage`
    /// uses it as a NARROWING HINT: two snapshots of the same grid whose stamp for row `i`
    /// is EQUAL are guaranteed to have identical content at row `i`, so that row can be
    /// skipped without a cell-by-cell compare. It is purely an optimization — when it is
    /// empty or its length does not match `rows` (e.g. a snapshot decoded from the wire,
    /// where this field is absent) the diff falls back to scanning every row, which is
    /// always correct.
    ///
    /// `#[serde(skip)]` keeps it entirely off the wire: it is never serialized and decodes
    /// to an empty Vec, so the protocol shape and the renderer's view are unchanged.
    #[serde(skip)]
    pub row_stamps: Vec<u64>,
}

/// Owns the VT parser + the alacritty Term. Feed it PTY bytes; read snapshots.
/// Tracks `generation` + `revision` so a renderer can tell whether its screen is
/// still a contiguous view of this grid (see the `revision` module).
pub struct TermGrid {
    parser: Processor,
    term: Term<GridEventListener>,
    pending_events: Arc<Mutex<Vec<Event>>>,
    cols: usize,
    rows: usize,
    generation: SessionGeneration,
    revision: Revision,
    /// The revision immediately before the most recent committed mutation. A
    /// snapshot reports this as `base_revision` so a renderer can prove strict
    /// continuity (it already holds `base_revision` ⇒ no gap). Equals `revision`
    /// for a fresh generation (self-baselining: nothing precedes it).
    base_revision: Revision,
    /// Per-visible-row content stamps (length == `rows`). After each mutation we read the
    /// VT engine's line damage and bump the stamp of every row it reports as changed to a
    /// fresh `stamp_counter` value. Two snapshots agreeing on a row's stamp are guaranteed
    /// to agree on that row's content, which lets `generate_damage` skip unchanged rows.
    /// See `GridSnapshot::row_stamps`.
    row_stamps: Vec<u64>,
    /// Monotonic source for `row_stamps`. Bumped once per damage-collection pass; the new
    /// value is written into every row the pass marks dirty, so a row's stamp changes IFF
    /// its content may have changed since the previous pass.
    stamp_counter: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalNotification {
    Bell,
    Title(Option<String>),
    ClipboardStore(String),
}

impl TermGrid {
    pub fn new(cols: u16, rows: u16) -> Self {
        let cols = clamp_dim(cols);
        let rows = clamp_dim(rows);
        // Cap history by total cells, not just rows: a wide grid keeps fewer history
        // rows so worst-case memory stays bounded regardless of column count.
        let history = history_budget(cols);
        let size = GridSize {
            cols,
            screen_lines: rows,
            history,
        };
        // alacritty's scroll-eviction limit (`max_scroll_limit`) comes from
        // `Config::scrolling_history`, NOT from `GridSize::total_lines`. Leaving it at the
        // crate default (10000) would let history grow past our intended bound, so set
        // it explicitly to the cell-derived budget to actually cap memory.
        let config = Config {
            scrolling_history: history,
            ..Config::default()
        };
        let pending_events = Arc::new(Mutex::new(Vec::new()));
        let listener = GridEventListener {
            pending: pending_events.clone(),
        };
        let term = Term::new(config, &size, listener);
        TermGrid {
            parser: Processor::new(),
            term,
            pending_events,
            cols,
            rows,
            generation: SessionGeneration::new(),
            revision: Revision::ZERO,
            base_revision: Revision::ZERO,
            // A brand-new grid starts fully blank; stamp 0 across all rows. The first
            // mutation bumps the counter to 1 and re-stamps whatever it touches, so the
            // initial all-zero state never aliases a later real change.
            row_stamps: vec![0; rows],
            stamp_counter: 0,
        }
    }

    pub fn revision(&self) -> Revision {
        self.revision
    }

    /// Current process/grid lifetime identifier without cloning a full snapshot.
    pub fn generation(&self) -> SessionGeneration {
        self.generation
    }

    /// Advance the revision after a committed mutation, recording the revision we
    /// came from as `base_revision` so the next snapshot encodes strict continuity
    /// (`base_revision -> revision`). On overflow we roll a new generation (and
    /// reset both to ZERO) rather than wrap to an ambiguous 0 — a renderer reads
    /// the generation change as "re-snapshot" and stays correct.
    fn bump_revision(&mut self) {
        match self.revision.next() {
            Some(next) => {
                self.base_revision = self.revision;
                self.revision = next;
            }
            None => {
                self.generation = SessionGeneration::new();
                self.revision = Revision::ZERO;
                self.base_revision = Revision::ZERO;
            }
        }
    }

    /// Pull the VT engine's accumulated line damage and fold it into `row_stamps`, then
    /// reset the engine's damage so the next mutation starts clean. Called after every
    /// committed mutation. `TermDamage::Full` (scroll, alt-screen swap, insert mode, …)
    /// re-stamps EVERY row — the conservative, always-correct choice — so any change the
    /// engine can't localize forces a full re-compare downstream. A `Partial` pass stamps
    /// only the rows the engine reports, which is the common single-line-output case.
    ///
    /// We bump `stamp_counter` ONCE per pass and write that single value into every dirty
    /// row, so a row's stamp changes IFF it was dirty this pass. (The engine yields each
    /// damaged line at most once per pass, so there is no double counting.)
    fn collect_row_damage(&mut self) {
        // Geometry can have changed (resize); keep stamps aligned to the current row count
        // before indexing. A fresh length is treated as fully dirty below via the Full arm
        // when resize marked full damage, but resize re-creates the Vec explicitly anyway.
        if self.row_stamps.len() != self.rows {
            self.row_stamps = vec![0; self.rows];
        }
        self.stamp_counter = self.stamp_counter.wrapping_add(1);
        let stamp = self.stamp_counter;
        let rows = self.rows;
        match self.term.damage() {
            TermDamage::Full => {
                for s in self.row_stamps.iter_mut() {
                    *s = stamp;
                }
            }
            TermDamage::Partial(iter) => {
                for line in iter {
                    if line.line < rows {
                        self.row_stamps[line.line] = stamp;
                    }
                }
            }
        }
        self.term.reset_damage();
    }

    /// Feed raw PTY output through the VT engine, updating the grid. Every
    /// non-empty chunk is a committed mutation, so it advances the revision.
    pub fn advance(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        for chunk in bytes.chunks(MAX_PARSER_ADVANCE_BYTES) {
            self.parser.advance(&mut self.term, chunk);
            self.enforce_retained_cell_text_budget();
        }
        // Output that scrolls lines into history can grow `history_size` up to
        // `max_scroll_limit`. Re-clamp to the cell-derived budget so repeated output
        // evicts the oldest rows and memory stays bounded. (`update_history` shrinks
        // the raw buffer from its oldest end and lowers `max_scroll_limit`.)
        self.enforce_history_budget();
        self.collect_row_damage();
        self.bump_revision();
    }

    /// Trim combining marks in the VT engine's own dirty visible cells. Alacritty keeps
    /// these marks in a private, heap-backed `CellExtra::zerowidth`; truncating only while
    /// serializing snapshots leaves the retained allocation unbounded. Rebuilding the
    /// rare overflowing `extra` preserves underline colour and hyperlink metadata while
    /// retaining only whole UTF-8 characters that fit the public cell-text byte cap.
    ///
    /// Only visible dirty rows need inspection: a combining mark can be appended only at
    /// the live cursor, and we trim it before that row can scroll into history. Full VT
    /// damage scans the visible screen; partial damage scans the exact reported rows.
    fn enforce_retained_cell_text_budget(&mut self) {
        let dirty_rows: Vec<usize> = match self.term.damage() {
            TermDamage::Full => (0..self.rows).collect(),
            TermDamage::Partial(iter) => iter
                .filter_map(|bounds| (bounds.line < self.rows).then_some(bounds.line))
                .collect(),
        };

        let grid = self.term.grid_mut();
        for row in dirty_rows {
            for col in 0..self.cols {
                trim_alacritty_cell_text(&mut grid[Point::new(Line(row as i32), Column(col))]);
            }
        }
    }

    /// Drain replies generated by terminal queries in the most recent parser
    /// advances. The caller writes these bytes to the PTY input side. Returning
    /// owned byte vectors keeps all potentially blocking PTY I/O outside the
    /// grid lock and outside alacritty's parser callback.
    pub fn take_terminal_effects(&mut self) -> (Vec<Vec<u8>>, Vec<TerminalNotification>) {
        let events = std::mem::take(&mut *self.pending_events.lock().unwrap());
        let mut replies = Vec::new();
        let mut notifications = Vec::new();
        for event in events {
            match event {
                Event::PtyWrite(text) => replies.push(text.into_bytes()),
                Event::TextAreaSizeRequest(formatter) => replies.push(
                    formatter(alacritty_terminal::event::WindowSize {
                        num_lines: self.rows as u16,
                        num_cols: self.cols as u16,
                        // The daemon owns cell geometry, not physical window pixels.
                        // A zero pixel answer is truthful while the character-size
                        // query (CSI 18 t) still reports exact rows/columns directly.
                        cell_width: 0,
                        cell_height: 0,
                    })
                    .into_bytes(),
                ),
                Event::ColorRequest(index, formatter) => {
                    // Stable xterm-like query answer. Color rendering itself remains
                    // theme-owned by the renderer; this prevents applications waiting
                    // on OSC 10/11/etc. from hanging at startup.
                    let rgb = if index == AnsiNamedColor::Background as usize {
                        Rgb {
                            r: 0x05,
                            g: 0x06,
                            b: 0x07,
                        }
                    } else if index == AnsiNamedColor::Cursor as usize {
                        Rgb {
                            r: 0xd0,
                            g: 0xd0,
                            b: 0xd0,
                        }
                    } else {
                        // Foreground and uncommon dynamic palette queries get a
                        // readable stable default rather than no response.
                        Rgb {
                            r: 0xd0,
                            g: 0xd0,
                            b: 0xd0,
                        }
                    };
                    replies.push(formatter(rgb).into_bytes());
                }
                Event::Bell => notifications.push(TerminalNotification::Bell),
                Event::Title(title) => notifications.push(TerminalNotification::Title(Some(title))),
                Event::ResetTitle => notifications.push(TerminalNotification::Title(None)),
                Event::ClipboardStore(_, text) => {
                    notifications.push(TerminalNotification::ClipboardStore(text))
                }
                // Never disclose the system clipboard to a PTY. Replying with an
                // empty value satisfies OSC 52 queries without leaking local data.
                Event::ClipboardLoad(_, formatter) => {
                    replies.push(formatter("").into_bytes());
                }
                _ => {}
            }
        }
        (replies, notifications)
    }

    #[cfg(test)]
    pub fn take_terminal_replies(&mut self) -> Vec<Vec<u8>> {
        self.take_terminal_effects().0
    }

    /// Clamp the grid's scrollback history to the cell-derived budget for the current
    /// column count. `update_history` evicts the oldest rows when history exceeds the
    /// budget and always lowers `max_scroll_limit`, so future growth stays bounded even
    /// when current history is already under budget. Idempotent.
    fn enforce_history_budget(&mut self) {
        let budget = history_budget(self.cols);
        self.term.grid_mut().update_history(budget);
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        let cols = clamp_dim(cols);
        let rows = clamp_dim(rows);
        if cols == self.cols && rows == self.rows {
            return;
        }
        self.cols = cols;
        self.rows = rows;
        // Re-derive the history budget for the new width: a wider grid must keep fewer
        // history rows to stay within the total-cell cap.
        let history = history_budget(cols);
        let size = GridSize {
            cols,
            screen_lines: rows,
            history,
        };
        self.term.resize(size);
        // `Term::resize` re-lays the grid but does NOT touch `max_scroll_limit`, so a
        // width change won't re-clamp history on its own. Apply the new budget explicitly,
        // evicting oldest rows if the narrower budget now holds more than allowed.
        self.enforce_history_budget();
        // A resize re-lays the whole grid; rebuild stamps at the new row count, all dirty.
        // (alacritty also marks full damage on resize.) generate_damage treats any geometry
        // change as Resync regardless, so this is belt-and-suspenders for stamp consistency.
        self.row_stamps = vec![0; self.rows];
        self.collect_row_damage();
        // Resize is a committed geometry mutation; a snapshot before vs. after
        // differs, so it must advance the revision like any other mutation.
        self.bump_revision();
    }

    /// Render the visible viewport into a rich wire snapshot: every cell carries
    /// its grapheme plus the visual attributes alacritty already tracks
    /// (fg/bg/bold/italic/underline/inverse/strikeout/dim/hidden/width), and the
    /// snapshot carries cursor shape+visibility and the alternate-screen flag.
    pub fn snapshot(&self) -> GridSnapshot {
        let grid = self.term.grid();
        let mode = self.term.mode();
        let alt_screen = mode.contains(TermMode::ALT_SCREEN);
        let cursor_visible = mode.contains(TermMode::SHOW_CURSOR);
        let cursor_shape: CursorShape = self.term.cursor_style().shape.into();

        let mut rows_cells = Vec::with_capacity(self.rows);
        for row in 0..self.rows {
            rows_cells.push(line_to_cells(grid, Line(row as i32), self.cols));
        }
        let cursor = grid.cursor.point;
        GridSnapshot {
            version: SNAPSHOT_VERSION,
            generation: self.generation,
            revision: self.revision,
            base_revision: self.base_revision,
            cols: self.cols,
            rows: self.rows,
            rows_cells,
            cursor_line: (cursor.line.0.max(0) as usize).min(self.rows.saturating_sub(1)),
            // Clamp the column into the grid just like the line. alacritty parks the
            // cursor one past the last column while a wrap is pending (DECAWM), so an
            // unclamped cursor_col can equal `cols` and address a cell the renderer's
            // row buffer (exactly `cols` wide) does not have.
            cursor_col: cursor.column.0.min(self.cols.saturating_sub(1)),
            cursor_visible,
            cursor_shape,
            alt_screen,
            app_cursor: mode.contains(TermMode::APP_CURSOR),
            bracketed_paste: mode.contains(TermMode::BRACKETED_PASTE),
            focus_reporting: mode.contains(TermMode::FOCUS_IN_OUT),
            mouse_report: mode.contains(TermMode::MOUSE_REPORT_CLICK),
            mouse_drag: mode.contains(TermMode::MOUSE_DRAG),
            mouse_motion: mode.contains(TermMode::MOUSE_MOTION),
            mouse_sgr: mode.contains(TermMode::SGR_MOUSE),
            // Off-wire narrowing hint for daemon-side damage generation. Cloned here so the
            // snapshot is a self-contained value; it is dropped by serde on the wire.
            row_stamps: self.row_stamps.clone(),
        }
    }

    /// Total scrollback history rows available right now (lines that scrolled above the
    /// live screen, excluding it). Bounded near `HISTORY_LINES`: alacritty's storage grows
    /// in blocks, so this can sit slightly above the requested limit but never scales with
    /// total input — old rows are evicted.
    pub fn history_len(&self) -> usize {
        self.term.grid().history_size()
    }

    /// Read a window of STRUCTURED historical rows. Read-only: it
    /// NEVER mutates `display_offset` (the live grid stays pinned at the bottom) and is
    /// not part of the snapshot/damage timeline.
    ///
    /// Addressing: `offset_from_top` counts rows ABOVE the visible screen top.
    /// `offset_from_top == 1` starts at the row just above the screen (`Line(-1)`);
    /// `offset_from_top == 0` starts at the top visible row (`Line(0)`). It is clamped
    /// to `history_len()` so it never addresses past the oldest row. Rows are returned
    /// top-to-bottom, each exactly `self.cols` wide (same `Cell` model as `snapshot`).
    ///
    /// Caps: `count` is clamped to `MAX_SCROLLBACK_ROWS_PER_REQUEST` AND to the cell
    /// budget (`MAX_SNAPSHOT_CELLS / cols`) so the reply always fits `MAX_LINE_BYTES`.
    /// `cols == 0` yields zero rows (never divides by zero).
    pub fn scrollback(&self, offset_from_top: u32, count: u16) -> ScrollbackRead {
        let history = self.history_len();
        // Clamp the start so we never read past the oldest history row. The deepest
        // row is `Line(-history)`, addressed by `offset_from_top == history`.
        let offset = (offset_from_top as usize).min(history);

        let grid = self.term.grid();
        let cols = self.cols;

        // Per-request row cap, then the wire-budget cap. If cols is 0 we can emit no
        // meaningful cells, so cap rows at 0 rather than dividing by zero.
        let count_cap = (count as usize).min(MAX_SCROLLBACK_ROWS_PER_REQUEST as usize);
        // `cols == 0` can't happen for a real grid (`clamp_dim` floors at 1), but guard the
        // division anyway: `checked_div` yields `None` for a zero divisor -> zero rows.
        let cell_cap_rows = MAX_SNAPSHOT_CELLS.checked_div(cols).unwrap_or(0);
        let max_rows = count_cap.min(cell_cap_rows);

        // Available rows from the start point down to the bottommost visible row.
        // First row is `Line(-offset)`; the last addressable line is `Line(rows-1)`.
        let available = offset + self.rows;
        let row_count = max_rows.min(available);

        let mut rows = Vec::with_capacity(row_count);
        for i in 0..row_count {
            let line = Line(-(offset as i32) + i as i32);
            rows.push(line_to_cells(grid, line, cols));
        }

        ScrollbackRead {
            generation: self.generation,
            revision: self.revision,
            history_len: history,
            offset_from_top: offset,
            rows,
        }
    }
}

/// The result of a read-only scrollback query (see `TermGrid::scrollback`). Carries
/// structured rows plus the identity/clamp metadata the daemon echoes on the wire.
pub struct ScrollbackRead {
    pub generation: SessionGeneration,
    pub revision: Revision,
    /// Total history rows available when the window was read.
    pub history_len: usize,
    /// The start offset actually used (clamped down from the request if it exceeded
    /// `history_len`).
    pub offset_from_top: usize,
    /// Rows top-to-bottom, each exactly `cols` wide.
    pub rows: Vec<Vec<Cell>>,
}

/// Extract one grid line into `cols` wire `Cell`s, exactly as the snapshot path
/// renders the visible viewport. `line` is an alacritty `Line`: `Line(0..)` are
/// visible rows, NEGATIVE lines address scrollback history (`Line(-1)` is the row
/// just above the screen). Shared by `snapshot()` (visible rows) and the
/// scrollback read (historical rows) so both produce byte-identical cells.
/// Append combining / zero-width chars to a cell's text, bounding the total to
/// `MAX_CELL_TEXT_BYTES`. alacritty stores per-cell combining marks in an unbounded
/// `CellExtra::zerowidth: Vec<char>`, so a pathological stream of marks aimed at one cell
/// would otherwise grow that cell's text without limit (a daemon-side memory amplification
/// that the row/cell scrollback cap cannot catch — it counts cells, not bytes).
///
/// Policy is TRUNCATE, not reject: the base char (already pushed by the caller) is always
/// kept so the cell never loses its glyph, and combining marks are appended only while the
/// next one fits whole. `char`s are atomic (no UTF-8 boundary split), so the result is
/// always valid and deterministic for a given cell. The cap equals the wire deserializer's
/// `MAX_CELL_TEXT_BYTES`, so every cell the daemon emits is guaranteed to be accepted by
/// the renderer's `deserialize_cell_text` (which REJECTS over-long text) — closing the
/// asymmetry where the daemon could emit a snapshot/damage cell its own mirror would drop.
///
/// The base char is at most 4 bytes (one `char`) and `MAX_CELL_TEXT_BYTES` is 64, so the
/// base always fits and at least some marks are retained.
fn append_zerowidth_capped(text: &mut CompactString, zerowidth: &[char]) {
    for &zw in zerowidth {
        if text.len() + zw.len_utf8() > MAX_CELL_TEXT_BYTES {
            break;
        }
        text.push(zw);
    }
}

/// Bound the VT engine's retained combining-mark allocation for one cell. Returns
/// `true` only when an overflowing cell was rebuilt.
fn trim_alacritty_cell_text(cell: &mut AlacrittyCell) -> bool {
    let base_bytes = if cell.c == '\0' { 1 } else { cell.c.len_utf8() };
    let Some(zerowidth) = cell.zerowidth() else {
        return false;
    };

    let mut retained_bytes = base_bytes;
    let mut kept = Vec::with_capacity(zerowidth.len().min(MAX_CELL_TEXT_BYTES));
    let mut overflowed = false;
    for &mark in zerowidth {
        let mark_bytes = mark.len_utf8();
        if retained_bytes + mark_bytes > MAX_CELL_TEXT_BYTES {
            overflowed = true;
            break;
        }
        retained_bytes += mark_bytes;
        kept.push(mark);
    }
    if !overflowed {
        return false;
    }

    let underline_color = cell.underline_color();
    let hyperlink = cell.hyperlink();
    cell.extra = None;
    for mark in kept {
        cell.push_zerowidth(mark);
    }
    cell.set_underline_color(underline_color);
    cell.set_hyperlink(hyperlink);
    true
}

fn line_to_cells(
    grid: &alacritty_terminal::grid::Grid<alacritty_terminal::term::cell::Cell>,
    line: Line,
    cols: usize,
) -> Vec<Cell> {
    let mut cells = Vec::with_capacity(cols);
    for col in 0..cols {
        let cell = &grid[Point::new(line, Column(col))];
        let flags = cell.flags;
        // Translate only COMPLETE in-row wide pairs onto the wire. Primary-screen reflow can
        // use LEADING_WIDE_CHAR_SPACER as a right-edge placeholder; alternate-screen shrink
        // can truncate a pair's spacer and leave a lone WIDE_CHAR in the last column. Neither
        // state satisfies our wire contract (width-2 must be followed by width-0 in the same
        // row), so serialize malformed boundary cells as canonical styled blanks instead of
        // emitting a snapshot the renderer must reject.
        let leading_placeholder = flags.contains(Flags::LEADING_WIDE_CHAR_SPACER);
        let valid_wide_lead = !leading_placeholder
            && flags.contains(Flags::WIDE_CHAR)
            && !flags.contains(Flags::WIDE_CHAR_SPACER)
            && col + 1 < cols
            && {
                let next = grid[Point::new(line, Column(col + 1))].flags;
                next.contains(Flags::WIDE_CHAR_SPACER)
                    && !next.contains(Flags::WIDE_CHAR)
                    && !next.contains(Flags::LEADING_WIDE_CHAR_SPACER)
            };
        let valid_wide_spacer = !leading_placeholder
            && flags.contains(Flags::WIDE_CHAR_SPACER)
            && !flags.contains(Flags::WIDE_CHAR)
            && col > 0
            && {
                let previous = grid[Point::new(line, Column(col - 1))].flags;
                previous.contains(Flags::WIDE_CHAR)
                    && !previous.contains(Flags::WIDE_CHAR_SPACER)
                    && !previous.contains(Flags::LEADING_WIDE_CHAR_SPACER)
            };
        let malformed_wide_boundary = flags.intersects(
            Flags::WIDE_CHAR | Flags::WIDE_CHAR_SPACER | Flags::LEADING_WIDE_CHAR_SPACER,
        ) && !valid_wide_lead
            && !valid_wide_spacer;

        // Wide-cell width: lead cell = 2, the spacer after it = 0, else 1.
        let width: u8 = if valid_wide_lead {
            2
        } else if valid_wide_spacer {
            0
        } else {
            1
        };
        // A wide-char spacer carries no glyph of its own; emit empty text.
        // Otherwise build the full grapheme: base char plus any combining /
        // zero-width chars alacritty stashed on the cell. `CompactString` keeps the
        // common single-grapheme text inline (no heap allocation); a long cluster
        // spills to the heap as a String would.
        let text = if valid_wide_spacer {
            CompactString::default()
        } else if malformed_wide_boundary {
            CompactString::from(CANONICAL_BLANK_TEXT)
        } else {
            let base = if cell.c == '\0' { ' ' } else { cell.c };
            let mut buf = [0u8; 4];
            let base_str: &str = base.encode_utf8(&mut buf);
            match cell.zerowidth() {
                // Overwhelmingly common: a bare base char (no combining marks). Build the
                // `CompactString` from the encoded base in one shot. `compact_str` 0.8 has no
                // `From<char>`, so we encode into a stack buffer first; this is also the
                // single-allocation fast path (no per-char `push` re-checking the inline tag).
                None => CompactString::from(base_str),
                Some(zerowidth) => {
                    let mut text = CompactString::from(base_str);
                    append_zerowidth_capped(&mut text, zerowidth);
                    text
                }
            }
        };
        cells.push(Cell {
            text,
            fg: cell.fg.into(),
            bg: cell.bg.into(),
            bold: flags.contains(Flags::BOLD),
            italic: flags.contains(Flags::ITALIC),
            underline: UnderlineStyle::from_flags(flags),
            inverse: flags.contains(Flags::INVERSE),
            strikeout: flags.contains(Flags::STRIKEOUT),
            dim: flags.contains(Flags::DIM),
            hidden: flags.contains(Flags::HIDDEN),
            width,
        });
    }
    cells
}

// Damage generation consumed live by the forwarder: it calls
// `generate_damage` after each PTY-advanced grid and ships `Damage` events. The raw `Output`
// bridge remains available only to clients that explicitly request it or omit the compatibility flag.

/// The canonical blank cell text the snapshot path emits for an erased cell: a single
/// space (the grid normalizes a NUL glyph to `' '`). A `ClearAll` fill MUST use exactly
/// this representation (width 1, text `" "`), per the damage contract.
const CANONICAL_BLANK_TEXT: &str = " ";

/// Is this cell the canonical blank fill (width 1, a single space, any styling)? Used to
/// recognise when an entire next-grid is blank so we can emit one `ClearAll` instead of a
/// `RowSpan` per row. Styling (fg/bg/attrs) is free — terminal erase fills with the
/// ACTIVE background — but the glyph and width must be the canonical blank.
fn is_canonical_blank(cell: &Cell) -> bool {
    cell.width == 1 && cell.text == CANONICAL_BLANK_TEXT
}

/// Outcome of diffing two authoritative snapshots into damage.
///
/// Damage is generated by diffing the SAME authoritative `GridSnapshot`s the snapshot
/// path produces — never a second VT parse — so "baseline + emitted frames" reconstructs
/// the daemon's full snapshot exactly (the equivalence guarantee). The generator emits
/// only `RowSpan` and `ClearAll` when scroll compression does not apply.
#[derive(Debug, Clone, PartialEq)]
pub enum DamageGen {
    /// The two snapshots are identical screens at the same revision — nothing to send.
    /// (Used to suppress no-op frames: a mutation that did not change the visible grid,
    /// cursor, or modes produces no damage.)
    NoChange,
    /// Damage cannot be expressed as in-place ops against the previous grid — the
    /// generation changed or the geometry differs (a resize). Per the damage contract the
    /// daemon ships a FULL SNAPSHOT for these, not invented partial-resize damage. The
    /// caller must send `prev`/`next`'s snapshot as a fresh baseline.
    Resync,
    /// A structured incremental frame carrying the `prev.revision -> next.revision`
    /// change as `RowSpan`/`ClearAll` ops plus absolute post-frame cursor/mode state.
    Frame(DamageFrame),
}

/// Did the cursor or any tracked mode flag differ between two snapshots? A frame whose
/// only change is cursor/mode (no cell changed) is still real damage — it carries the new
/// header and advances the revision — so we must not suppress it as NoChange.
fn header_changed(prev: &GridSnapshot, next: &GridSnapshot) -> bool {
    prev.cursor_line != next.cursor_line
        || prev.cursor_col != next.cursor_col
        || prev.cursor_visible != next.cursor_visible
        || prev.cursor_shape != next.cursor_shape
        || prev.alt_screen != next.alt_screen
        || prev.app_cursor != next.app_cursor
        || prev.bracketed_paste != next.bracketed_paste
        || prev.focus_reporting != next.focus_reporting
        || prev.mouse_report != next.mouse_report
        || prev.mouse_drag != next.mouse_drag
        || prev.mouse_motion != next.mouse_motion
        || prev.mouse_sgr != next.mouse_sgr
}

/// Build the absolute post-frame cursor header from the next snapshot.
fn cursor_state_of(next: &GridSnapshot) -> CursorState {
    CursorState {
        line: next.cursor_line,
        col: next.cursor_col,
        visible: next.cursor_visible,
        shape: next.cursor_shape,
    }
}

/// Build the absolute post-frame mode header from the next snapshot.
fn mode_state_of(next: &GridSnapshot) -> ModeState {
    ModeState {
        alt_screen: next.alt_screen,
        app_cursor: next.app_cursor,
        bracketed_paste: next.bracketed_paste,
        focus_reporting: next.focus_reporting,
        mouse_report: next.mouse_report,
        mouse_drag: next.mouse_drag,
        mouse_motion: next.mouse_motion,
        mouse_sgr: next.mouse_sgr,
    }
}

/// For one row, find the minimal `[start, end)` column span that differs between the two
/// equal-length rows, or `None` if the rows are identical. Diffing the minimal span keeps
/// a `RowSpan` as small as the change actually was (a one-char edit ships one cell).
fn row_diff_span(prev: &[Cell], next: &[Cell]) -> Option<(usize, usize)> {
    let mut first = None;
    let mut last = 0usize;
    for (col, (p, n)) in prev.iter().zip(next.iter()).enumerate() {
        if p != n {
            if first.is_none() {
                first = Some(col);
            }
            last = col;
        }
    }
    first.map(|f| (f, last + 1))
}

/// Apply a single scroll op to a row-vector IN PLACE, the canonical movement semantics
/// shared by the daemon's self-verify, `apply_damage_for_test`, and (mirrored) the
/// renderer's `sync.rs::apply_ops`. A scroll op is PURE DATA MOVEMENT: it shifts whole
/// rows within `[top, bottom_exclusive)` by `lines` and leaves the vacated rows
/// UNCHANGED (the frame's RowSpans overwrite them next). No implied clear.
///
/// `ScrollUp`: row `i` in `[top, bottom_exclusive - lines)` takes the content that was at
/// `i + lines`; iterate FORWARD so a source is read before it is overwritten.
/// `ScrollDown`: row `i` in `[top + lines, bottom_exclusive)` takes the content from
/// `i - lines`; iterate BACKWARD for the same reason.
///
/// Returns `Err` (never panics, never partially-applies observably to a caller that
/// discards on error) if the op is not a scroll or its bounds don't fit `rows`. Bounds
/// are normally pre-validated by `DamageFrame::validate`, but this is defensive so the
/// renderer's scratch-first rule holds even on an unexpected sender.
pub(crate) fn apply_scroll(
    rows_cells: &mut [Vec<Cell>],
    op: &DamageOp,
) -> Result<(), &'static str> {
    let (top, bottom_exclusive, lines, up) = match op {
        DamageOp::ScrollUp {
            top,
            bottom_exclusive,
            lines,
        } => (
            *top as usize,
            *bottom_exclusive as usize,
            *lines as usize,
            true,
        ),
        DamageOp::ScrollDown {
            top,
            bottom_exclusive,
            lines,
        } => (
            *top as usize,
            *bottom_exclusive as usize,
            *lines as usize,
            false,
        ),
        _ => return Err("apply_scroll called on a non-scroll op"),
    };
    // Half-open region within the grid, non-empty, lines within the region height.
    if !(top < bottom_exclusive && bottom_exclusive <= rows_cells.len() && lines > 0)
        || lines > bottom_exclusive - top
    {
        return Err("scroll region out of bounds");
    }
    if up {
        for i in top..(bottom_exclusive - lines) {
            rows_cells[i] = rows_cells[i + lines].clone();
        }
    } else {
        for i in (top + lines..bottom_exclusive).rev() {
            rows_cells[i] = rows_cells[i - lines].clone();
        }
    }
    Ok(())
}

/// A detected single full-width contiguous vertical scroll: the region and direction
/// whose pure row-movement (via `apply_scroll`) accounts for the surviving content of
/// `next`, leaving only the `lines` exposed rows (and possibly a few unrelated repainted
/// rows) to be described by RowSpans. Conservative by construction — see `detect_scroll`.
struct ScrollPlan {
    op: DamageOp,
}

/// Conservatively detect ONE full-width contiguous vertical scroll between two
/// equal-geometry grids. Returns the single `ScrollUp`/`ScrollDown` op whose movement
/// best explains the diff, or `None` if the diff is not cleanly a whole-grid vertical
/// shift. We only ever consider the WHOLE grid as the region (`[0, rows)`), which covers
/// the overwhelmingly common terminal scroll (a new line at the bottom shifts everything
/// up); a partial scroll region, multi-region scroll, or any ambiguity yields `None` and
/// the caller falls back to the always-correct RowSpan path.
///
/// Soundness does NOT rest on this function — the caller MUST self-verify the resulting
/// frame reproduces `next` before emitting it. This only proposes a candidate; a false
/// positive costs a missed optimization (fallback), never wrong pixels.
fn detect_scroll(prev: &GridSnapshot, next: &GridSnapshot) -> Option<ScrollPlan> {
    let rows = prev.rows_cells.len();
    if rows < 2 || next.rows_cells.len() != rows {
        return None;
    }
    // Real terminal scroll (bash/Claude) is rarely a perfectly clean whole-grid shift: a single
    // snapshot→snapshot diff can span an echoed command + the newline-scroll + a fresh prompt, so a
    // few "surviving" rows also change. Requiring EVERY surviving row to match (the original strict
    // rule) missed those and fell back to a RowSpan-per-row frame (the streaming "wave"). Instead we
    // pick the shift with the MOST matching surviving rows above a strong-majority threshold; the
    // caller RowSpans the mismatched rows over the scrolled grid AND self-verifies the result is
    // cell-for-cell `next` before emitting — so a loose match never corrupts pixels, it only ever
    // degrades to the plain RowSpan fallback. The op-count gate (`scroll_ops.len() < ops.len()`) keeps
    // a marginal match from bloating the frame.
    let best_shift = |matches_at: &dyn Fn(usize) -> usize| -> Option<(usize, usize)> {
        let mut best: Option<(usize, usize)> = None; // (lines, matches)
        for lines in 1..rows {
            let survivors = rows - lines;
            let m = matches_at(lines);
            // Need a strong majority of survivors to line up — otherwise it's not really a shift.
            // (At least 2 rows, and ≥ ~3/4 of the surviving span.)
            if m >= 2 && m * 4 >= survivors * 3 {
                // Prefer the SMALLEST lines (usual scroll is 1) among acceptable shifts; on a tie
                // prefer more matches. Iterating ascending, take the first acceptable.
                if best.is_none() {
                    best = Some((lines, m));
                    break;
                }
            }
        }
        best
    };

    let up_matches = |lines: usize| -> usize {
        (0..rows - lines)
            .filter(|&i| next.rows_cells[i] == prev.rows_cells[i + lines])
            .count()
    };
    if let Some((lines, _)) = best_shift(&up_matches) {
        return Some(ScrollPlan {
            op: DamageOp::ScrollUp {
                top: 0,
                bottom_exclusive: rows as u16,
                lines: lines as u16,
            },
        });
    }

    let down_matches = |lines: usize| -> usize {
        (lines..rows)
            .filter(|&i| next.rows_cells[i] == prev.rows_cells[i - lines])
            .count()
    };
    if let Some((lines, _)) = best_shift(&down_matches) {
        return Some(ScrollPlan {
            op: DamageOp::ScrollDown {
                top: 0,
                bottom_exclusive: rows as u16,
                lines: lines as u16,
            },
        });
    }
    None
}

// Diagnostic instrumentation that lets regression tests observe two internals of the most
// recent `generate_damage` call on THIS thread:
//   - `rows_compared`: how many rows the plain RowSpan path actually cell-compared. With
//     the dirty-row hint this is the number of stamp-differing candidate rows; without it
//     (no/short stamps, scroll, resync) it falls back to every row. A test reads it to
//     prove a single-line update compares a handful of rows (`<= 3`), not the whole grid.
//   - `detect_scroll_attempted`: whether the scroll gate (`ops.len() > 1`) let the
//     O(rows²) `detect_scroll` scan run. A test reads it to prove a single-row edit skips
//     scroll detection while a real scroll still enters it.
//
// THREAD-LOCAL (not a process-global atomic) so a value recorded by one test thread's
// `generate_damage` cannot be clobbered by another thread running tests concurrently —
// `cargo test` (default parallel) reads only its own thread's record. Compiled only under
// `cfg(test)`; the record sites below are no-ops in production, so release behavior and
// timing are unchanged.
#[cfg(test)]
thread_local! {
    static LAST_ROWS_COMPARED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static LAST_DETECT_SCROLL_ATTEMPTED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Record the row-compare count for this thread's most recent `generate_damage`. No-op in
/// non-test builds.
#[inline]
fn record_rows_compared(_n: usize) {
    #[cfg(test)]
    LAST_ROWS_COMPARED.with(|c| c.set(_n));
}

/// Record whether this thread's most recent `generate_damage` attempted `detect_scroll`.
/// No-op in non-test builds.
#[inline]
fn record_detect_scroll_attempted(_attempted: bool) {
    #[cfg(test)]
    LAST_DETECT_SCROLL_ATTEMPTED.with(|c| c.set(_attempted));
}

/// Read this thread's row-compare count from its last `generate_damage` call. Test only.
#[cfg(test)]
pub(crate) fn last_rows_compared() -> usize {
    LAST_ROWS_COMPARED.with(|c| c.get())
}

/// Read whether this thread's last `generate_damage` attempted `detect_scroll`. Test only.
#[cfg(test)]
pub(crate) fn last_detect_scroll_attempted() -> bool {
    LAST_DETECT_SCROLL_ATTEMPTED.with(|c| c.get())
}

/// Decide which rows could possibly differ between `prev` and `next`, as a NARROWING HINT.
///
/// Returns `Some(rows)` listing every row whose per-row content stamp differs (those are
/// the only rows a mutation could have touched; all others are byte-identical and may be
/// skipped). Returns `None` — meaning "no usable hint, treat every row as a candidate" —
/// whenever the stamps are missing or untrustworthy: either snapshot's `row_stamps` is
/// empty (e.g. decoded from the wire) or not exactly `rows` long. `None` preserves the
/// original always-correct full-scan behavior.
///
/// SOUNDNESS: a stamp is bumped whenever the VT engine reports a row as damaged, and any
/// content change damages its row, so equal stamps ⇒ identical content. The converse need
/// not hold (a redraw with identical bytes still bumps the stamp), which only costs a
/// redundant compare — never a missed change.
fn candidate_rows(prev: &GridSnapshot, next: &GridSnapshot) -> Option<Vec<usize>> {
    let rows = next.rows_cells.len();
    if prev.row_stamps.len() != rows || next.row_stamps.len() != rows || rows == 0 {
        return None;
    }
    Some(
        (0..rows)
            .filter(|&i| prev.row_stamps[i] != next.row_stamps[i])
            .collect(),
    )
}

/// True if any candidate row's cells actually differ. With a hint this compares only the
/// listed rows; without one (`None`) it falls back to the full-grid compare. Equivalent to
/// `prev.rows_cells != next.rows_cells` but skips rows the stamps prove unchanged.
fn grid_changed_hinted(
    prev: &GridSnapshot,
    next: &GridSnapshot,
    candidates: &Option<Vec<usize>>,
) -> bool {
    match candidates {
        Some(rows) => rows
            .iter()
            .any(|&i| prev.rows_cells[i] != next.rows_cells[i]),
        None => prev.rows_cells != next.rows_cells,
    }
}

/// Build per-row minimal-span `RowSpan` ops for every row where `base` differs from
/// `next`, appending to `ops`. Returns `Err(())` if the running totals would exceed the
/// damage caps (caller maps that to `Resync`). Shared by the scroll path (to describe
/// exposed/repainted rows after the scroll op) and the plain fallback path.
///
/// `candidates`: when `Some(rows)`, ONLY those row indices are compared — every other row
/// is proven identical by its content stamp, so skipping it is sound (see `candidate_rows`)
/// and is the purpose of dirty-row narrowing. When `None`, every row is compared;
/// used by the scroll path, which has no per-row hint over its scratch grid). The number of
/// rows compared is recorded via `record_rows_compared` for the optimization's regression
/// test (a `<= 3` bound under the dirty-row hint; see `last_rows_compared`).
fn append_rowspan_diffs(
    base: &[Vec<Cell>],
    next: &[Vec<Cell>],
    ops: &mut Vec<DamageOp>,
    total_cells: &mut usize,
    candidates: &Option<Vec<usize>>,
) -> Result<(), ()> {
    let compared = match candidates {
        Some(rows) => rows.len(),
        None => base.len().min(next.len()),
    };
    record_rows_compared(compared);

    // A tiny closure so the two iteration shapes share one body.
    let mut emit = |row: usize| -> Result<(), ()> {
        let (base_row, next_row) = match (base.get(row), next.get(row)) {
            (Some(b), Some(n)) => (b, n),
            _ => return Ok(()),
        };
        if let Some((start, end)) = row_diff_span(base_row, next_row) {
            let cells = next_row[start..end].to_vec();
            *total_cells += cells.len();
            ops.push(DamageOp::RowSpan {
                row: row as u16,
                start: start as u16,
                cells,
            });
            if ops.len() > MAX_DAMAGE_OPS || *total_cells > MAX_DAMAGE_CELLS {
                return Err(());
            }
        }
        Ok(())
    };

    match candidates {
        Some(rows) => {
            for &row in rows {
                emit(row)?;
            }
        }
        None => {
            for row in 0..base.len().min(next.len()) {
                emit(row)?;
            }
        }
    }
    Ok(())
}

/// Generate structured damage from `prev` to `next`, both authoritative snapshots of the
/// SAME session's grid (so the equivalence guarantee holds by construction). Returns:
/// - `NoChange` if the visible grid, cursor, and modes are all identical;
/// - `Resync` if the generation or geometry differs (caller ships a full snapshot, per
///   the resize/full-clear contract — never invented partial-resize damage);
/// - `Frame(_)` otherwise, carrying minimal `RowSpan`s (or one `ClearAll` when the whole
///   next grid is the canonical blank) plus the absolute post-frame cursor/mode header.
///
/// Revision ordering: the frame's `base_revision = prev.revision` and
/// `revision = next.revision`. The caller MUST only diff snapshots where
/// `next.revision > prev.revision` (a committed forward mutation); if they are equal the
/// grids are identical and this returns `NoChange`. A frame is never emitted that would
/// violate the strict-advance invariant `DamageFrame::validate` enforces.
///
/// Caps: if the diff would exceed `MAX_DAMAGE_OPS` or `MAX_DAMAGE_CELLS`, the generator
/// gives up on incremental damage and returns `Resync` — a frame that large is cheaper
/// and safer as a full snapshot, and would be rejected by the renderer's caps anyway.
pub fn generate_damage(prev: &GridSnapshot, next: &GridSnapshot) -> DamageGen {
    record_detect_scroll_attempted(false);

    // Generation change or geometry change cannot be bridged with in-place ops.
    if prev.generation != next.generation || prev.cols != next.cols || prev.rows != next.rows {
        return DamageGen::Resync;
    }

    // Narrowing hint: the rows whose content stamp differs are the only rows that can have
    // changed (see `candidate_rows`). `None` ⇒ no usable hint ⇒ scan every row (the original
    // behavior). Computed once and reused for the change test and the RowSpan diff.
    let candidates = candidate_rows(prev, next);
    let grid_changed = grid_changed_hinted(prev, next, &candidates);
    let any_change = grid_changed || header_changed(prev, next);

    // A real damage frame must STRICTLY advance the revision (it represents >= 1 committed
    // mutation). If there is any visible/header change but the revision did not advance,
    // we cannot construct a valid frame — refuse with Resync rather than emit something
    // `DamageFrame::validate` would reject. (The live path always advances the revision on
    // a committed mutation; this guards the pure function against a malformed input pair.)
    if any_change && next.revision.0 <= prev.revision.0 {
        return DamageGen::Resync;
    }

    let cursor = cursor_state_of(next);
    let modes = mode_state_of(next);

    // Whole-grid clear → a single ClearAll. This is only valid when EVERY next cell is
    // EXACTLY EQUAL to the chosen fill cell (so applying ClearAll reproduces the grid
    // cell-for-cell) AND that fill is the canonical blank (width 1, text " "). If blank
    // cells carry MIXED styling (different bg per cell/row), one ClearAll cannot
    // reproduce them — we must fall through to the per-row RowSpan diff. `grid_changed`
    // gates against emitting on an unchanged grid (NoChange handles that).
    if grid_changed {
        if let Some(fill) = next.rows_cells.first().and_then(|r| r.first()) {
            let uniform_blank = is_canonical_blank(fill)
                && next
                    .rows_cells
                    .iter()
                    .all(|row| row.iter().all(|c| c == fill));
            if uniform_blank {
                return DamageGen::Frame(DamageFrame {
                    schema: DAMAGE_SCHEMA,
                    id: SessionId(String::new()),
                    generation: next.generation,
                    base_revision: prev.revision,
                    revision: next.revision,
                    cols: next.cols as u16,
                    rows: next.rows as u16,
                    cursor,
                    modes,
                    ops: vec![DamageOp::ClearAll { cell: fill.clone() }],
                });
            }
        }
    }

    // Per-row minimal-span diff → one RowSpan per changed row. This is the always-correct
    // fallback; we compute it first so the scroll path below can be gated on producing
    // STRICTLY fewer ops (otherwise a scroll op is pure overhead).
    let mut ops = Vec::new();
    let mut total_cells = 0usize;
    if append_rowspan_diffs(
        &prev.rows_cells,
        &next.rows_cells,
        &mut ops,
        &mut total_cells,
        &candidates,
    )
    .is_err()
    {
        // Over caps: an incremental frame this large is better shipped as a snapshot.
        return DamageGen::Resync;
    }

    // Scroll compression: if the visible change is a single full-width vertical
    // shift, ship ONE scroll op + RowSpans for the exposed/repainted rows instead of a
    // RowSpan per moved row (O(1) vs O(rows)). The scroll op MOVES rows; the exposed rows
    // and any unrelated repaint are then RowSpan'd over the scrolled grid. We take this
    // branch ONLY when it (a) self-verifies — applying the candidate ops to a clone of
    // `prev` reproduces `next` cell-for-cell, a runtime check (NOT debug_assert) so a
    // detector false positive degrades to the RowSpan fallback, never wrong pixels — AND
    // (b) yields STRICTLY fewer ops than the plain RowSpan diff, so a degenerate match
    // (e.g. shifting all-blank rows) never bloats the frame with a useless scroll op.
    //
    // Gate `ops.len() > 1`: `detect_scroll` is O(rows²) full-grid work. A scroll op can
    // never be smaller than a single RowSpan, so when the plain RowSpan path already emitted
    // <= 1 op (the common case — an ordinary single-row edit) scroll compression cannot
    // possibly produce STRICTLY fewer ops (gate (b) above). Skipping detect_scroll there
    // costs nothing in frame size and avoids the full-grid scan on every narrow edit.
    if grid_changed && ops.len() > 1 {
        record_detect_scroll_attempted(true);
        if let Some(plan) = detect_scroll(prev, next) {
            // Op order is explicit: scroll FIRST, then RowSpans for exposed/leftover rows.
            let mut scratch = prev.rows_cells.clone();
            if apply_scroll(&mut scratch, &plan.op).is_ok() {
                let mut scroll_ops = vec![plan.op.clone()];
                let mut scroll_cells = 0usize;
                if append_rowspan_diffs(
                    &scratch,
                    &next.rows_cells,
                    &mut scroll_ops,
                    &mut scroll_cells,
                    // Scroll MOVED rows, so the stamp↔row correspondence is broken against
                    // `scratch`; scan every row (None) — correctness over the micro-opt. The
                    // scroll path is rare and already does an O(rows) detect/self-verify.
                    &None,
                )
                .is_ok()
                    && scroll_ops.len() < ops.len()
                {
                    // Self-verify: applying the SAME ops we will ship must reproduce next.
                    let mut verify = prev.rows_cells.clone();
                    let applied_ok = scroll_ops.iter().all(|op| match op {
                        DamageOp::ScrollUp { .. } | DamageOp::ScrollDown { .. } => {
                            apply_scroll(&mut verify, op).is_ok()
                        }
                        DamageOp::RowSpan { row, start, cells } => {
                            match verify.get_mut(*row as usize) {
                                Some(r) if (*start as usize) + cells.len() <= r.len() => {
                                    let s = *start as usize;
                                    r[s..s + cells.len()].clone_from_slice(cells);
                                    true
                                }
                                _ => false,
                            }
                        }
                        DamageOp::ClearAll { .. } => false,
                    });
                    if applied_ok && verify == next.rows_cells {
                        return DamageGen::Frame(DamageFrame {
                            schema: DAMAGE_SCHEMA,
                            id: SessionId(String::new()),
                            generation: next.generation,
                            base_revision: prev.revision,
                            revision: next.revision,
                            cols: next.cols as u16,
                            rows: next.rows as u16,
                            cursor,
                            modes,
                            ops: scroll_ops,
                        });
                    }
                    // Self-verify failed → fall through to the plain RowSpan path below.
                }
            }
        }
    }

    if ops.is_empty() {
        // No cell changed. A cursor/mode-only change is still real damage (empty ops,
        // fresh header, advances the revision); identical header → genuinely nothing.
        if header_changed(prev, next) {
            return DamageGen::Frame(DamageFrame {
                schema: DAMAGE_SCHEMA,
                id: SessionId(String::new()),
                generation: next.generation,
                base_revision: prev.revision,
                revision: next.revision,
                cols: next.cols as u16,
                rows: next.rows as u16,
                cursor,
                modes,
                ops: Vec::new(),
            });
        }
        return DamageGen::NoChange;
    }

    DamageGen::Frame(DamageFrame {
        schema: DAMAGE_SCHEMA,
        id: SessionId(String::new()),
        generation: next.generation,
        base_revision: prev.revision,
        revision: next.revision,
        cols: next.cols as u16,
        rows: next.rows as u16,
        cursor,
        modes,
        ops,
    })
}

/// The canonical blank cell with default fg/bg styling, used as a fallback `ClearAll`
/// fill for a degenerate empty grid (no cells to read styling from). Width 1, text `" "`.
#[allow(dead_code)]
fn blank_cell() -> Cell {
    Cell {
        text: CompactString::from(CANONICAL_BLANK_TEXT),
        fg: Color::Named {
            name: NamedColor::Foreground,
        },
        bg: Color::Named {
            name: NamedColor::Background,
        },
        bold: false,
        italic: false,
        underline: UnderlineStyle::None,
        inverse: false,
        strikeout: false,
        dim: false,
        hidden: false,
        width: 1,
    }
}

/// Apply a damage frame's ops to a snapshot in place, reproducing what a renderer would do
/// when it accepts the frame. Test-only: the equivalence tests use this to prove
/// "baseline + emitted frames == final full snapshot". Ops are applied in order; the
/// header (cursor/modes) is overwritten with the frame's absolute post-frame state.
#[cfg(test)]
pub fn apply_damage_for_test(base: &mut GridSnapshot, frame: &DamageFrame) {
    for op in &frame.ops {
        match op {
            DamageOp::ClearAll { cell } => {
                for row in base.rows_cells.iter_mut() {
                    for c in row.iter_mut() {
                        *c = cell.clone();
                    }
                }
            }
            DamageOp::RowSpan { row, start, cells } => {
                let r = &mut base.rows_cells[*row as usize];
                for (i, cell) in cells.iter().enumerate() {
                    r[*start as usize + i] = cell.clone();
                }
            }
            DamageOp::ScrollUp { .. } | DamageOp::ScrollDown { .. } => {
                apply_scroll(&mut base.rows_cells, op).expect("valid scroll op in test frame");
            }
        }
    }
    base.cursor_line = frame.cursor.line;
    base.cursor_col = frame.cursor.col;
    base.cursor_visible = frame.cursor.visible;
    base.cursor_shape = frame.cursor.shape;
    base.alt_screen = frame.modes.alt_screen;
    base.app_cursor = frame.modes.app_cursor;
    base.bracketed_paste = frame.modes.bracketed_paste;
    base.focus_reporting = frame.modes.focus_reporting;
    base.mouse_report = frame.modes.mouse_report;
    base.mouse_drag = frame.modes.mouse_drag;
    base.mouse_motion = frame.modes.mouse_motion;
    base.mouse_sgr = frame.modes.mouse_sgr;
    base.base_revision = frame.base_revision;
    base.revision = frame.revision;
}

#[cfg(test)]
mod budget_tests {
    use super::*;

    #[test]
    fn narrow_and_wide_valid_grids_fit() {
        // A typical terminal and degenerate-but-legal narrow/wide grids all fit.
        assert!(fits_snapshot_budget(80, 24));
        assert!(fits_snapshot_budget(1, 1));
        // A very wide single row and a very tall single column, sized to the budget.
        let wide = MAX_SNAPSHOT_CELLS.min(2000);
        assert!(fits_snapshot_budget(wide as u16, 1));
        assert!(fits_snapshot_budget(1, wide as u16));
    }

    #[test]
    fn over_budget_grid_is_rejected() {
        // 2000x2000 (4e6 cells) is far over the snapshot budget.
        assert!(!fits_snapshot_budget(2000, 2000));
    }

    #[test]
    fn fits_budget_guards_multiplication_overflow() {
        // u16::MAX * u16::MAX = ~4.29e9 fits in usize on 64-bit, but is way over budget;
        // the point is it must return false (over budget), never wrap to a small product.
        assert!(!fits_snapshot_budget(u16::MAX, u16::MAX));
    }

    #[test]
    fn clamp_preserves_fit_and_aspect_ratio() {
        // An over-budget request clamps to something that FITS and stays >= 1x1.
        let (c, r) = clamp_to_snapshot_budget(2000, 2000);
        assert!(fits_snapshot_budget(c, r));
        assert!(c >= 1 && r >= 1);
        // Square in, roughly square out (aspect ratio preserved within rounding).
        let ratio = c as f64 / r as f64;
        assert!((0.5..2.0).contains(&ratio), "ratio drifted: {c}x{r}");
        // An already-fitting request is returned unchanged.
        assert_eq!(clamp_to_snapshot_budget(80, 24), (80, 24));
    }

    #[test]
    fn clamp_preserves_wide_aspect() {
        // A very wide over-budget request stays wider-than-tall after clamping.
        let (c, r) = clamp_to_snapshot_budget(2000, 200);
        assert!(fits_snapshot_budget(c, r));
        assert!(c > r, "expected wide grid to stay wide: {c}x{r}");
    }
}

#[cfg(test)]
mod terminal_reply_tests {
    use super::*;

    #[test]
    fn primary_device_attributes_are_returned_to_the_pty() {
        let mut grid = TermGrid::new(80, 24);
        grid.advance(b"\x1b[c");
        assert_eq!(grid.take_terminal_replies(), vec![b"\x1b[?6c".to_vec()]);
        assert!(grid.take_terminal_replies().is_empty(), "drain is one-shot");
    }

    #[test]
    fn character_size_query_reports_authoritative_geometry() {
        let mut grid = TermGrid::new(101, 37);
        grid.advance(b"\x1b[18t");
        assert_eq!(
            grid.take_terminal_replies(),
            vec![b"\x1b[8;37;101t".to_vec()]
        );
    }

    #[test]
    fn bell_title_and_clipboard_store_are_extracted_as_notifications() {
        let mut grid = TermGrid::new(80, 24);
        grid.advance(b"\x07\x1b]2;build logs\x07\x1b]52;c;aGVsbG8=\x07");
        let (replies, notifications) = grid.take_terminal_effects();
        assert!(replies.is_empty());
        assert!(notifications.contains(&TerminalNotification::Bell));
        assert!(notifications.contains(&TerminalNotification::Title(Some("build logs".into()))));
        assert!(notifications.contains(&TerminalNotification::ClipboardStore("hello".into())));
    }
}

#[cfg(test)]
mod power_user_compat_tests {
    use super::*;

    #[test]
    fn vim_less_and_tmux_mode_sequences_are_reflected() {
        let mut grid = TermGrid::new(120, 40);
        // vim/less alternate screen + application cursor + bracketed paste;
        // tmux/TUIs focus and SGR mouse modes.
        grid.advance(b"\x1b[?1049h\x1b[?1h\x1b[?2004h\x1b[?1004h\x1b[?1000h\x1b[?1002h\x1b[?1006h");
        let snap = grid.snapshot();
        assert!(snap.alt_screen);
        assert!(snap.app_cursor);
        assert!(snap.bracketed_paste);
        assert!(snap.focus_reporting);
        // DECSET 1002 supersedes 1000 in alacritty's mutually-exclusive mouse
        // tracking mode; drag + SGR is the effective tmux/TUI contract.
        assert!(snap.mouse_drag && snap.mouse_sgr);

        grid.advance(b"\x1b[?1049l\x1b[?1l\x1b[?2004l\x1b[?1004l\x1b[?1000l\x1b[?1002l\x1b[?1006l");
        let snap = grid.snapshot();
        assert!(!snap.alt_screen);
        assert!(!snap.app_cursor);
        assert!(!snap.bracketed_paste);
        assert!(!snap.focus_reporting);
        assert!(!snap.mouse_report && !snap.mouse_drag && !snap.mouse_sgr);
    }
}

#[cfg(test)]
mod damage_gen_tests {
    use super::*;

    /// Assert that a snapshot's visible grid + cursor + modes match another's, ignoring
    /// generation/revision bookkeeping (which `apply_damage_for_test` sets from the frame,
    /// not the grid). This is the "screens are equal" predicate for equivalence tests.
    fn assert_screens_eq(a: &GridSnapshot, b: &GridSnapshot) {
        assert_eq!(a.cols, b.cols, "cols");
        assert_eq!(a.rows, b.rows, "rows");
        assert_eq!(a.rows_cells, b.rows_cells, "cells");
        assert_eq!(a.cursor_line, b.cursor_line, "cursor_line");
        assert_eq!(a.cursor_col, b.cursor_col, "cursor_col");
        assert_eq!(a.cursor_visible, b.cursor_visible, "cursor_visible");
        assert_eq!(a.cursor_shape, b.cursor_shape, "cursor_shape");
        assert_eq!(a.alt_screen, b.alt_screen, "alt_screen");
        assert_eq!(a.app_cursor, b.app_cursor, "app_cursor");
        assert_eq!(a.bracketed_paste, b.bracketed_paste, "bracketed_paste");
        assert_eq!(a.focus_reporting, b.focus_reporting, "focus_reporting");
        assert_eq!(a.mouse_report, b.mouse_report, "mouse_report");
        assert_eq!(a.mouse_drag, b.mouse_drag, "mouse_drag");
        assert_eq!(a.mouse_motion, b.mouse_motion, "mouse_motion");
        assert_eq!(a.mouse_sgr, b.mouse_sgr, "mouse_sgr");
    }

    /// Feed `bytes`, then prove: baseline snapshot + generated damage frame reconstructs
    /// the final full snapshot exactly. Returns the `DamageGen` so callers can assert its
    /// shape (Frame/ClearAll/NoChange) too.
    fn drive_and_reconstruct(grid: &mut TermGrid, bytes: &[u8]) -> DamageGen {
        let before = grid.snapshot();
        grid.advance(bytes);
        let after = grid.snapshot();
        let gen = generate_damage(&before, &after);
        if let DamageGen::Frame(frame) = &gen {
            // The frame must be structurally valid on its own (caps, bounds, ordering).
            assert_eq!(frame.validate(), Ok(()), "generated frame must validate");
            let mut reconstructed = before.clone();
            apply_damage_for_test(&mut reconstructed, frame);
            assert_screens_eq(&reconstructed, &after);
        }
        gen
    }

    #[test]
    fn cursor_col_clamped_into_grid_when_wrap_pending() {
        // Fill a row to its exact width without a newline. With DECAWM (autowrap) on —
        // alacritty's default — the cursor parks one past the last column awaiting the
        // next glyph, so its raw column equals `cols`. The snapshot must clamp it to the
        // last addressable column so the renderer never indexes past its row buffer.
        let cols: u16 = 8;
        let mut grid = TermGrid::new(cols, 3);
        grid.advance(b"ABCDEFGH"); // exactly `cols` chars, no CR/LF
        let snap = grid.snapshot();
        assert!(
            snap.cursor_col < snap.cols,
            "cursor_col {} must be clamped below cols {}",
            snap.cursor_col,
            snap.cols
        );
        assert_eq!(
            snap.cursor_col,
            (cols - 1) as usize,
            "wrap-pending cursor clamps to the last column"
        );
        assert!(snap.cursor_line < snap.rows, "cursor_line stays in-grid");
    }

    #[test]
    fn rowspan_reconstructs_final_snapshot() {
        let mut grid = TermGrid::new(20, 5);
        let gen = drive_and_reconstruct(&mut grid, b"hello");
        // A line of text changes exactly one row; expect one RowSpan, not a ClearAll.
        match gen {
            DamageGen::Frame(f) => {
                assert_eq!(f.ops.len(), 1, "one changed row");
                assert!(
                    matches!(f.ops[0], DamageOp::RowSpan { row: 0, .. }),
                    "expected a RowSpan on row 0, got {:?}",
                    f.ops[0]
                );
                assert!(f.revision.0 > f.base_revision.0, "strictly advancing");
            }
            other => panic!("expected a Frame, got {other:?}"),
        }
    }

    #[test]
    fn multi_row_edit_reconstructs() {
        let mut grid = TermGrid::new(20, 6);
        // Two lines of output across a CRLF — touches two rows.
        let gen = drive_and_reconstruct(&mut grid, b"first\r\nsecond");
        match gen {
            DamageGen::Frame(f) => assert!(!f.ops.is_empty()),
            other => panic!("expected a Frame, got {other:?}"),
        }
    }

    #[test]
    fn color_and_style_rows_survive_equivalence() {
        let mut grid = TermGrid::new(30, 4);
        // Bold red "A", then reset and an underlined "B", plus a default "C".
        // The reconstruction must preserve fg/bg/attrs per cell.
        drive_and_reconstruct(&mut grid, b"\x1b[1;31mA\x1b[0m\x1b[4mB\x1b[0mC");
    }

    #[test]
    fn wide_char_row_survives_equivalence() {
        let mut grid = TermGrid::new(20, 3);
        // A CJK wide char (lead width 2 + width-0 spacer) plus an emoji must round-trip
        // through the RowSpan diff with widths intact.
        drive_and_reconstruct(&mut grid, "中a😀b".as_bytes());
    }

    #[test]
    fn wide_char_at_shrunk_right_boundary_stays_a_valid_wire_pair() {
        let mut grid = TermGrid::new(81, 4);
        let text = format!("{}中", "x".repeat(79));
        grid.advance(text.as_bytes());
        grid.resize(80, 4);

        let snap = grid.snapshot();
        for (row_index, row) in snap.rows_cells.iter().enumerate() {
            for (col, cell) in row.iter().enumerate() {
                match cell.width {
                    2 => assert_eq!(
                        row.get(col + 1).map(|next| next.width),
                        Some(0),
                        "wide lead must keep its spacer after shrink at row={row_index} col={col}",
                    ),
                    0 => assert!(
                        col > 0 && row[col - 1].width == 2,
                        "wide spacer must keep its lead after shrink at row={row_index} col={col}",
                    ),
                    _ => {}
                }
            }
        }
    }

    #[test]
    fn alt_screen_shrink_normalizes_a_wide_lead_truncated_at_the_last_column() {
        let mut grid = TermGrid::new(81, 4);
        grid.advance(b"\x1b[?1049h");
        let text = format!("{}中", "x".repeat(79));
        grid.advance(text.as_bytes());
        grid.resize(80, 4);

        let snap = grid.snapshot();
        assert!(snap.alt_screen);
        assert_eq!(snap.rows_cells[0][79].width, 1);
        assert_eq!(snap.rows_cells[0][79].text, " ");
        assert!(snap.rows_cells.iter().all(|row| {
            row.iter().enumerate().all(|(col, cell)| match cell.width {
                2 => row.get(col + 1).is_some_and(|next| next.width == 0),
                0 => col > 0 && row[col - 1].width == 2,
                _ => true,
            })
        }));
    }

    #[test]
    fn transient_alacritty_wide_boundary_flags_never_escape_as_dangling_wire_cells() {
        let mut grid = TermGrid::new(8, 3);
        {
            let raw = grid.term.grid_mut();
            // Defensive contradictory flags must fail closed. On the wire this cell is a
            // styled blank, never a two-column lead without an in-row spacer.
            raw[Point::new(Line(0), Column(7))]
                .flags
                .insert(Flags::WIDE_CHAR | Flags::LEADING_WIDE_CHAR_SPACER);
            // Also fail closed for either half of a malformed pair at a viewport boundary.
            raw[Point::new(Line(1), Column(7))]
                .flags
                .insert(Flags::WIDE_CHAR);
            raw[Point::new(Line(2), Column(0))]
                .flags
                .insert(Flags::WIDE_CHAR_SPACER);
        }

        let snap = grid.snapshot();
        for (row, col) in [(0, 7), (1, 7), (2, 0)] {
            let cell = &snap.rows_cells[row][col];
            assert_eq!(cell.width, 1, "row={row} col={col}");
            assert_eq!(cell.text, " ", "row={row} col={col}");
        }
    }

    #[test]
    fn full_clear_emits_canonical_clear_all() {
        let mut grid = TermGrid::new(15, 4);
        grid.advance(b"some text on screen\r\nand a second line");
        let before = grid.snapshot();
        // ED (erase display) + cursor home clears the whole screen to blanks.
        grid.advance(b"\x1b[2J\x1b[H");
        let after = grid.snapshot();
        let gen = generate_damage(&before, &after);
        match &gen {
            DamageGen::Frame(f) => {
                assert_eq!(f.ops.len(), 1, "whole-grid clear is one op");
                match &f.ops[0] {
                    DamageOp::ClearAll { cell } => {
                        assert_eq!(cell.text, " ", "canonical blank text");
                        assert_eq!(cell.width, 1, "canonical blank width");
                    }
                    other => panic!("expected ClearAll, got {other:?}"),
                }
                assert_eq!(f.validate(), Ok(()), "clear frame validates");
                // Equivalence: applying the ClearAll reproduces the cleared screen.
                let mut reconstructed = before.clone();
                apply_damage_for_test(&mut reconstructed, f);
                assert_screens_eq(&reconstructed, &after);
            }
            other => panic!("expected a Frame with ClearAll, got {other:?}"),
        }
    }

    #[test]
    fn no_change_emits_no_damage() {
        // Two snapshots of an unchanged grid (same revision, identical cells/cursor/modes)
        // produce NoChange — the generator never emits a no-op frame.
        let grid = TermGrid::new(10, 3);
        let a = grid.snapshot();
        let b = grid.snapshot();
        assert_eq!(generate_damage(&a, &b), DamageGen::NoChange);
    }

    #[test]
    fn geometry_change_forces_resync() {
        // A resize changes the grid geometry; the generator refuses to invent partial
        // damage and signals Resync (the caller ships a full snapshot per the damage contract).
        let mut grid = TermGrid::new(10, 3);
        grid.advance(b"x");
        let before = grid.snapshot();
        grid.resize(20, 5);
        let after = grid.snapshot();
        assert_eq!(generate_damage(&before, &after), DamageGen::Resync);
    }

    #[test]
    fn generation_change_forces_resync() {
        // Different generations cannot be bridged with damage.
        let g1 = TermGrid::new(10, 3);
        let a = g1.snapshot();
        let g2 = TermGrid::new(10, 3); // fresh, different generation
        let b = g2.snapshot();
        assert_ne!(a.generation, b.generation);
        assert_eq!(generate_damage(&a, &b), DamageGen::Resync);
    }

    #[test]
    fn over_ops_cap_forces_resync() {
        // Construct two snapshots that differ on more than MAX_DAMAGE_OPS rows, so the
        // generator gives up on incremental damage and returns Resync (caps still hold).
        let cols = 4usize;
        let rows = MAX_DAMAGE_OPS + 5;
        let blank_row = || vec![blank_cell(); cols];
        let prev = GridSnapshot {
            version: SNAPSHOT_VERSION,
            generation: SessionGeneration::new(),
            revision: Revision(1),
            base_revision: Revision(0),
            cols,
            rows,
            rows_cells: (0..rows).map(|_| blank_row()).collect(),
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
            alt_screen: false,
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_report: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_sgr: false,
            row_stamps: Vec::new(),
        };
        // next: same generation/geometry, but every row has one non-blank cell so every
        // row diffs (rows > MAX_DAMAGE_OPS).
        let mut next = prev.clone();
        next.revision = Revision(2);
        next.base_revision = Revision(1);
        for row in next.rows_cells.iter_mut() {
            let mut c = blank_cell();
            c.text = "x".into();
            row[0] = c;
        }
        assert_eq!(generate_damage(&prev, &next), DamageGen::Resync);
    }

    /// A blank cell (canonical text/width) carrying a specific background color, so we can
    /// build an all-blank grid whose cells differ only in styling.
    fn blank_with_bg(r: u8, g: u8, b: u8) -> Cell {
        let mut c = blank_cell();
        c.bg = Color::Rgb { r, g, b };
        c
    }

    #[test]
    fn mixed_styling_blank_does_not_clear_all() {
        // Every next cell is canonical blank (width 1, text " ") but the cells carry
        // DIFFERENT backgrounds across rows/cols. A single ClearAll cannot reproduce mixed
        // styling, so the generator must fall back to per-row RowSpans — and the
        // reconstruction must STILL be cell-for-cell identical.
        let cols = 3usize;
        let rows = 2usize;
        let gen = SessionGeneration::new();
        // prev: all default-styled blanks.
        let prev = GridSnapshot {
            version: SNAPSHOT_VERSION,
            generation: gen,
            revision: Revision(1),
            base_revision: Revision(0),
            cols,
            rows,
            rows_cells: (0..rows).map(|_| vec![blank_cell(); cols]).collect(),
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
            alt_screen: false,
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_report: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_sgr: false,
            row_stamps: Vec::new(),
        };
        // next: still ALL canonical blank, but each cell has a distinct background.
        let mut next = prev.clone();
        next.revision = Revision(2);
        next.base_revision = Revision(1);
        let mut tint = 0u8;
        for row in next.rows_cells.iter_mut() {
            for cell in row.iter_mut() {
                *cell = blank_with_bg(tint, 0, 0);
                tint = tint.wrapping_add(40);
            }
        }
        // Sanity: every cell really is canonical blank text/width (the OLD, too-broad
        // check would have fired ClearAll here).
        assert!(next
            .rows_cells
            .iter()
            .all(|r| r.iter().all(is_canonical_blank)));

        let result = generate_damage(&prev, &next);
        match &result {
            DamageGen::Frame(f) => {
                // No ClearAll: mixed styling forces the RowSpan path.
                assert!(
                    !f.ops
                        .iter()
                        .any(|op| matches!(op, DamageOp::ClearAll { .. })),
                    "must NOT emit ClearAll for mixed-styling blanks: {:?}",
                    f.ops
                );
                assert_eq!(f.validate(), Ok(()), "frame validates");
                // Equivalence still holds: baseline + frame == next.
                let mut reconstructed = prev.clone();
                apply_damage_for_test(&mut reconstructed, f);
                assert_screens_eq(&reconstructed, &next);
            }
            other => panic!("expected a RowSpan Frame, got {other:?}"),
        }
    }

    #[test]
    fn uniform_blank_still_emits_clear_all() {
        // The tightened condition still emits ClearAll when every next cell is EXACTLY the
        // same canonical-blank fill (the common full-clear case).
        let cols = 4usize;
        let rows = 2usize;
        let gen = SessionGeneration::new();
        let prev = GridSnapshot {
            version: SNAPSHOT_VERSION,
            generation: gen,
            revision: Revision(1),
            base_revision: Revision(0),
            cols,
            rows,
            rows_cells: (0..rows)
                .map(|_| {
                    let mut c = blank_cell();
                    c.text = "z".into();
                    vec![c; cols]
                })
                .collect(),
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
            alt_screen: false,
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_report: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_sgr: false,
            row_stamps: Vec::new(),
        };
        let mut next = prev.clone();
        next.revision = Revision(2);
        next.base_revision = Revision(1);
        next.rows_cells = (0..rows).map(|_| vec![blank_cell(); cols]).collect();

        match generate_damage(&prev, &next) {
            DamageGen::Frame(f) => {
                assert_eq!(f.ops.len(), 1);
                assert!(matches!(f.ops[0], DamageOp::ClearAll { .. }));
                let mut reconstructed = prev.clone();
                apply_damage_for_test(&mut reconstructed, &f);
                assert_screens_eq(&reconstructed, &next);
            }
            other => panic!("expected ClearAll Frame, got {other:?}"),
        }
    }

    #[test]
    fn non_advancing_revision_with_change_forces_resync() {
        // If something changed but the revision did NOT advance, the pure function must
        // refuse (Resync) rather than build a frame `validate()` would reject for
        // non-advancing revision. (The live path always advances on a committed mutation;
        // this guards the function against a malformed input pair.)
        let gen = SessionGeneration::new();
        let prev = GridSnapshot {
            version: SNAPSHOT_VERSION,
            generation: gen,
            revision: Revision(5),
            base_revision: Revision(4),
            cols: 3,
            rows: 1,
            rows_cells: vec![vec![blank_cell(); 3]],
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
            alt_screen: false,
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_report: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_sgr: false,
            row_stamps: Vec::new(),
        };
        // A visible change but SAME revision → Resync.
        let mut same_rev = prev.clone();
        let mut c = blank_cell();
        c.text = "q".into();
        same_rev.rows_cells[0][0] = c;
        assert_eq!(same_rev.revision, prev.revision);
        assert_eq!(generate_damage(&prev, &same_rev), DamageGen::Resync);

        // A header-only change but BACKWARDS revision → Resync.
        let mut back_rev = prev.clone();
        back_rev.revision = Revision(3);
        back_rev.cursor_col = 1;
        assert_eq!(generate_damage(&prev, &back_rev), DamageGen::Resync);

        // No change at all with a non-advancing revision is still just NoChange (the guard
        // only fires when there IS a change to express).
        let mut no_change = prev.clone();
        no_change.revision = Revision(5);
        assert_eq!(generate_damage(&prev, &no_change), DamageGen::NoChange);
    }

    // ---- scroll compression ----

    /// Build a one-cell-per-glyph snapshot from row strings (each char → a canonical-style
    /// cell carrying that glyph; a space is the canonical blank). All rows must be the same
    /// width. Used to construct precise scroll fixtures without driving a real terminal.
    fn grid_from_rows(rows: &[&str], rev: u64) -> GridSnapshot {
        let cols = rows.first().map(|r| r.chars().count()).unwrap_or(0);
        assert!(
            rows.iter().all(|r| r.chars().count() == cols),
            "ragged rows"
        );
        let rows_cells = rows
            .iter()
            .map(|line| {
                line.chars()
                    .map(|ch| {
                        let mut c = blank_cell();
                        c.text = CompactString::from(ch.to_string());
                        c
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        GridSnapshot {
            version: SNAPSHOT_VERSION,
            generation: SessionGeneration::new(),
            revision: Revision(rev),
            base_revision: Revision(rev - 1),
            cols,
            rows: rows.len(),
            rows_cells,
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
            alt_screen: false,
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_report: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_sgr: false,
            row_stamps: Vec::new(),
        }
    }

    /// Same generation as `prev` but a fresh revision and the given rows — the realistic
    /// "next snapshot of the same session" shape (generation must match or it's a Resync).
    fn next_of(prev: &GridSnapshot, rows: &[&str]) -> GridSnapshot {
        let mut n = grid_from_rows(rows, prev.revision.0 + 1);
        n.generation = prev.generation;
        n.base_revision = prev.revision;
        n
    }

    #[test]
    fn scroll_up_one_line_detected_and_reconstructs() {
        let prev = grid_from_rows(&["aaa", "bbb", "ccc", "ddd"], 1);
        // Everything shifts up one row; a new bottom row "eee" is exposed.
        let next = next_of(&prev, &["bbb", "ccc", "ddd", "eee"]);
        match generate_damage(&prev, &next) {
            DamageGen::Frame(f) => {
                assert!(
                    matches!(
                        f.ops.first(),
                        Some(DamageOp::ScrollUp {
                            top: 0,
                            bottom_exclusive: 4,
                            lines: 1
                        })
                    ),
                    "scroll op must come FIRST: {:?}",
                    f.ops
                );
                // Then exactly one RowSpan for the exposed bottom row.
                assert!(
                    f.ops[1..]
                        .iter()
                        .all(|op| matches!(op, DamageOp::RowSpan { row: 3, .. })),
                    "only the exposed row 3 is repainted: {:?}",
                    f.ops
                );
                assert_eq!(f.validate(), Ok(()), "scroll frame validates");
                let mut recon = prev.clone();
                apply_damage_for_test(&mut recon, &f);
                assert_screens_eq(&recon, &next);
            }
            other => panic!("expected a scroll Frame, got {other:?}"),
        }
    }

    #[test]
    fn scroll_up_multiple_lines_detected() {
        let prev = grid_from_rows(&["r0", "r1", "r2", "r3", "r4"], 1);
        // Shift up by two; two new rows exposed at the bottom.
        let next = next_of(&prev, &["r2", "r3", "r4", "n5", "n6"]);
        match generate_damage(&prev, &next) {
            DamageGen::Frame(f) => {
                assert!(
                    matches!(
                        f.ops.first(),
                        Some(DamageOp::ScrollUp {
                            lines: 2,
                            bottom_exclusive: 5,
                            top: 0
                        })
                    ),
                    "expected ScrollUp lines:2: {:?}",
                    f.ops
                );
                let mut recon = prev.clone();
                apply_damage_for_test(&mut recon, &f);
                assert_screens_eq(&recon, &next);
            }
            other => panic!("expected a scroll Frame, got {other:?}"),
        }
    }

    #[test]
    fn scroll_down_detected_and_reconstructs() {
        let prev = grid_from_rows(&["aaa", "bbb", "ccc", "ddd"], 1);
        // Everything shifts DOWN one row; a new top row "zzz" is exposed.
        let next = next_of(&prev, &["zzz", "aaa", "bbb", "ccc"]);
        match generate_damage(&prev, &next) {
            DamageGen::Frame(f) => {
                assert!(
                    matches!(
                        f.ops.first(),
                        Some(DamageOp::ScrollDown {
                            top: 0,
                            bottom_exclusive: 4,
                            lines: 1
                        })
                    ),
                    "expected ScrollDown lines:1 first: {:?}",
                    f.ops
                );
                let mut recon = prev.clone();
                apply_damage_for_test(&mut recon, &f);
                assert_screens_eq(&recon, &next);
            }
            other => panic!("expected a scroll Frame, got {other:?}"),
        }
    }

    #[test]
    fn scroll_plus_exposed_row_repaint_reconstructs() {
        // A scroll up AND a repaint of a row OUTSIDE the exposed set (e.g. a status line at
        // the top redrawn the same instant the body scrolled). The frame carries the scroll,
        // the exposed-row RowSpan, AND the unrelated repaint — and still reconstructs.
        let prev = grid_from_rows(&["top", "bbb", "ccc", "ddd"], 1);
        // Body rows 1..4 shift up by one (bbb,ccc,ddd → ccc,ddd at 0..2 of the body), row 0
        // repaints to "NEW", bottom row exposes "eee". Express the WHOLE-grid shift: shifting
        // the whole grid up by one gives [bbb,ccc,ddd,?]; row0 then differs (NEW vs bbb) and
        // row3 is exposed (eee). Both are RowSpans after the scroll.
        let next = next_of(&prev, &["NEW", "ccc", "ddd", "eee"]);
        match generate_damage(&prev, &next) {
            DamageGen::Frame(f) => {
                // Whichever shape the detector/self-verify chose, equivalence MUST hold.
                assert_eq!(f.validate(), Ok(()), "frame validates");
                let mut recon = prev.clone();
                apply_damage_for_test(&mut recon, &f);
                assert_screens_eq(&recon, &next);
            }
            other => panic!("expected a Frame, got {other:?}"),
        }
    }

    #[test]
    fn non_scroll_falls_back_to_rowspans() {
        // Scattered single-cell edits across rows are NOT a vertical shift; the generator
        // must emit RowSpans (no scroll op) and still reconstruct.
        let prev = grid_from_rows(&["aaaa", "bbbb", "cccc", "dddd"], 1);
        let next = next_of(&prev, &["aXaa", "bbbb", "cYcc", "dddd"]);
        match generate_damage(&prev, &next) {
            DamageGen::Frame(f) => {
                assert!(
                    !f.ops.iter().any(|op| matches!(
                        op,
                        DamageOp::ScrollUp { .. } | DamageOp::ScrollDown { .. }
                    )),
                    "a non-shift diff must NOT emit a scroll op: {:?}",
                    f.ops
                );
                let mut recon = prev.clone();
                apply_damage_for_test(&mut recon, &f);
                assert_screens_eq(&recon, &next);
            }
            other => panic!("expected a RowSpan Frame, got {other:?}"),
        }
    }

    #[test]
    fn live_scroll_via_terminal_reconstructs() {
        // Drive a REAL terminal scroll: fill a 4-row screen, then emit more lines so the
        // viewport scrolls. Whatever shape the generator picks (scroll or RowSpan), the
        // equivalence guarantee must hold — drive_and_reconstruct asserts it.
        let mut grid = TermGrid::new(8, 4);
        grid.advance(b"l1\r\nl2\r\nl3\r\nl4");
        let before = grid.snapshot();
        grid.advance(b"\r\nl5\r\nl6"); // pushes content up past the top
        let after = grid.snapshot();
        let gen = generate_damage(&before, &after);
        if let DamageGen::Frame(f) = &gen {
            assert_eq!(f.validate(), Ok(()), "frame validates");
            let mut recon = before.clone();
            apply_damage_for_test(&mut recon, f);
            assert_screens_eq(&recon, &after);
        } else {
            panic!("expected a Frame from a scroll, got {gen:?}");
        }
    }

    #[test]
    fn apply_scroll_up_parity_fixture() {
        // The canonical apply fixture, mirrored byte-for-byte in the renderer
        // (sync.rs::apply_scroll_up_parity_fixture). A ScrollUp by 1 over [0,3) of a 3-row
        // grid moves rows 1,2 to 0,1 and leaves row 2 unchanged (to be RowSpan'd next).
        let mut rows = vec![
            vec![cell_text("A")],
            vec![cell_text("B")],
            vec![cell_text("C")],
        ];
        apply_scroll(
            &mut rows,
            &DamageOp::ScrollUp {
                top: 0,
                bottom_exclusive: 3,
                lines: 1,
            },
        )
        .unwrap();
        assert_eq!(rows[0][0].text, "B");
        assert_eq!(rows[1][0].text, "C");
        assert_eq!(rows[2][0].text, "C", "vacated row left as-is (not cleared)");
    }

    #[test]
    fn apply_scroll_down_parity_fixture() {
        let mut rows = vec![
            vec![cell_text("A")],
            vec![cell_text("B")],
            vec![cell_text("C")],
        ];
        apply_scroll(
            &mut rows,
            &DamageOp::ScrollDown {
                top: 0,
                bottom_exclusive: 3,
                lines: 1,
            },
        )
        .unwrap();
        assert_eq!(rows[0][0].text, "A", "vacated top row left as-is");
        assert_eq!(rows[1][0].text, "A");
        assert_eq!(rows[2][0].text, "B");
    }

    #[test]
    fn apply_scroll_rejects_out_of_bounds() {
        let mut rows = vec![vec![cell_text("A")], vec![cell_text("B")]];
        // lines > region height.
        assert!(apply_scroll(
            &mut rows,
            &DamageOp::ScrollUp {
                top: 0,
                bottom_exclusive: 2,
                lines: 3,
            },
        )
        .is_err());
        // region past grid.
        assert!(apply_scroll(
            &mut rows,
            &DamageOp::ScrollUp {
                top: 0,
                bottom_exclusive: 5,
                lines: 1,
            },
        )
        .is_err());
    }

    fn cell_text(s: &str) -> Cell {
        let mut c = blank_cell();
        c.text = s.into();
        c
    }

    /// Damage generation stays valid and reconstructs exactly when a cell carries a flood
    /// of combining marks that the per-cell cap truncates: the truncation is applied
    /// uniformly in `line_to_cells`, so both the before- and after-snapshots already carry
    /// the bounded text, the generated frame validates (no over-long cell), and applying it
    /// to the baseline reproduces the after-snapshot cell-for-cell.
    #[test]
    fn damage_valid_after_combining_mark_limit() {
        let mut grid = TermGrid::new(20, 4);
        // Write a base char, then flood the same cell with thousands of combining marks.
        let mut bytes = vec![b'a'];
        bytes.extend_from_slice("\u{0301}".repeat(5000).as_bytes());
        let result = drive_and_reconstruct(&mut grid, &bytes);
        // The edit changed the top-left cell, so it must produce a real damage frame
        // (not NoChange), and `drive_and_reconstruct` already asserted validate()==Ok and
        // exact reconstruction.
        assert!(
            matches!(result, DamageGen::Frame(_)),
            "a combining-mark write produces an incremental damage frame, got {result:?}"
        );
        // And the emitted cell is within the byte cap (so the frame is wire-acceptable).
        let after = grid.snapshot();
        assert!(after.rows_cells[0][0].text.len() <= MAX_CELL_TEXT_BYTES);
    }
}

#[cfg(test)]
mod scrollback_tests {
    use super::*;

    /// Join a row of cells into the visible text (spacers contribute nothing), trimming
    /// trailing blanks so `"line3   "` compares as `"line3"`.
    fn row_text(cells: &[Cell]) -> String {
        let s: String = cells.iter().map(|c| c.text.as_str()).collect();
        s.trim_end().to_string()
    }

    /// Feed `count` numbered lines ("line0\r\nline1\r\n...") so the early ones scroll
    /// above a `rows`-tall screen into history.
    fn grid_with_lines(cols: u16, rows: u16, count: usize) -> TermGrid {
        let mut grid = TermGrid::new(cols, rows);
        let mut bytes = Vec::new();
        for i in 0..count {
            if i > 0 {
                bytes.extend_from_slice(b"\r\n");
            }
            bytes.extend_from_slice(format!("line{i}").as_bytes());
        }
        grid.advance(&bytes);
        grid
    }

    /// FOCUSED verification (the gate the plan demands): historical rows ARE addressable
    /// via NEGATIVE alacritty `Line` indices. `Line(-1)` is the row just above the
    /// visible screen; deeper negatives reach older history. We feed more lines than the
    /// screen holds and read them straight back through `line_to_cells` at negative lines.
    #[test]
    fn negative_line_indices_address_history() {
        // 4-row screen, 8 lines total: line0..3 scroll into history, line4..7 visible.
        let grid = grid_with_lines(20, 4, 8);
        assert!(
            grid.history_len() >= 4,
            "expected >=4 history rows, got {}",
            grid.history_len()
        );
        let alac = grid.term.grid();
        // Line(-1) = row just above screen = "line3".
        assert_eq!(row_text(&line_to_cells(alac, Line(-1), 20)), "line3");
        // Line(-4) = the oldest of our scrolled lines = "line0".
        assert_eq!(row_text(&line_to_cells(alac, Line(-4), 20)), "line0");
        // Line(0) = top visible row = "line4".
        assert_eq!(row_text(&line_to_cells(alac, Line(0), 20)), "line4");
    }

    /// Long output, then a scrollback read returns the EARLIER structured rows that
    /// scrolled off the top — not the live screen.
    #[test]
    fn scrollback_returns_earlier_rows() {
        let grid = grid_with_lines(20, 4, 8);
        // offset_from_top=4 starts at Line(-4)=line0; read 4 rows -> line0..line3.
        let read = grid.scrollback(4, 4);
        assert_eq!(read.offset_from_top, 4);
        let texts: Vec<String> = read.rows.iter().map(|r| row_text(r)).collect();
        assert_eq!(texts, vec!["line0", "line1", "line2", "line3"]);
    }

    /// `ScrollbackRead::rows` carry STRUCTURED `Cell`s with real text — never raw bytes.
    /// Every row is exactly `cols` wide.
    #[test]
    fn scrollback_rows_are_structured_cells() {
        let grid = grid_with_lines(20, 4, 8);
        let read = grid.scrollback(4, 4);
        for row in &read.rows {
            assert_eq!(row.len(), 20, "each row is exactly cols wide");
        }
        // The first cell of the first row is the glyph 'l' of "line0", structured.
        assert_eq!(read.rows[0][0].text, "l");
        assert_eq!(read.rows[0][0].width, 1);
    }

    /// Alt-screen output must NOT contaminate normal scrollback. Entering the alternate
    /// screen, drawing there, and leaving leaves the primary history untouched.
    #[test]
    fn alt_screen_output_absent_from_scrollback() {
        let mut grid = grid_with_lines(20, 4, 8);
        let history_before = grid.history_len();
        // Enter alt screen (1049h), spew lines, leave (1049l). None of this should land
        // in the primary scrollback.
        grid.advance(b"\x1b[?1049h");
        grid.advance(b"ALTSCREEN_SECRET\r\nALT_LINE_2\r\nALT_LINE_3\r\nALT_LINE_4\r\nALT_LINE_5");
        grid.advance(b"\x1b[?1049l");
        // History length unchanged by the alt-screen excursion.
        assert_eq!(grid.history_len(), history_before);
        let read = grid.scrollback(4, 8);
        let joined: String = read
            .rows
            .iter()
            .map(|r| row_text(r))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !joined.contains("ALTSCREEN_SECRET") && !joined.contains("ALT_LINE"),
            "alt-screen text leaked into scrollback: {joined:?}"
        );
    }

    /// History is CAPPED at `HISTORY_LINES`: feeding far more lines evicts the oldest, so
    /// `history_len()` saturates at the cap rather than growing with input. (This is the
    /// behaviour `TermGrid::new` enforces by setting alacritty's `scrolling_history`; left
    /// at the crate default it would grow to 10000.) The oldest surviving line proves the
    /// earliest lines were dropped.
    #[test]
    fn history_is_capped_and_oldest_evicted() {
        let total = HISTORY_LINES + 3000;
        let grid = grid_with_lines(20, 4, total);
        assert_eq!(
            grid.history_len(),
            HISTORY_LINES,
            "history saturates at the cap, not the {total} lines fed"
        );
        // Oldest surviving row: with `total` lines fed and only `HISTORY_LINES` retained,
        // the earliest ~3000 lines were evicted, so the oldest line index is large.
        let read = grid.scrollback(HISTORY_LINES as u32, 1);
        assert_eq!(
            read.offset_from_top, HISTORY_LINES,
            "offset clamps to history_len"
        );
        let oldest = row_text(&read.rows[0]);
        let n: usize = oldest
            .strip_prefix("line")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("oldest row is a real line: {oldest:?}"));
        assert!(
            n > 0,
            "earliest lines were evicted; oldest surviving is line{n}, not line0"
        );
    }

    /// An `offset_from_top` beyond `history_len` clamps DOWN to `history_len` (it never
    /// addresses past the oldest row).
    #[test]
    fn offset_clamps_beyond_history() {
        let grid = grid_with_lines(20, 4, 8);
        let h = grid.history_len();
        let read = grid.scrollback(1_000_000, 4);
        assert_eq!(read.offset_from_top, h, "clamped to history_len");
        assert_eq!(read.history_len, h);
    }

    /// The reply clamps BOTH the requested row count (to `MAX_SCROLLBACK_ROWS_PER_REQUEST`)
    /// AND the cell volume (to `MAX_SNAPSHOT_CELLS / cols`), so a giant request can never
    /// produce an un-shippable reply.
    #[test]
    fn reply_clamps_count_and_cell_volume() {
        // Count cap: request more rows than the per-request cap.
        let grid = grid_with_lines(20, 4, HISTORY_LINES + 10);
        let read = grid.scrollback(HISTORY_LINES as u32, u16::MAX);
        assert!(
            read.rows.len() <= MAX_SCROLLBACK_ROWS_PER_REQUEST as usize,
            "row count capped"
        );
        // Cell-volume cap: with very wide cols, fewer rows than the count cap fit.
        let wide = grid_with_lines(MAX_DIMENSION, 4, HISTORY_LINES + 10);
        let read = wide.scrollback(HISTORY_LINES as u32, MAX_SCROLLBACK_ROWS_PER_REQUEST);
        let cols = MAX_DIMENSION as usize;
        assert!(
            read.rows.len() * cols <= MAX_SNAPSHOT_CELLS,
            "total cells within snapshot budget: {} rows * {} cols",
            read.rows.len(),
            cols
        );
        assert!(
            read.rows.len() < MAX_SCROLLBACK_ROWS_PER_REQUEST as usize,
            "the cell budget, not the count cap, was the binding limit here"
        );
    }

    /// A scrollback window at `offset_from_top == 0` overlaps the live screen top: its
    /// first row equals the live snapshot's top row, cell-for-cell.
    #[test]
    fn offset_zero_matches_live_snapshot_top_row() {
        let grid = grid_with_lines(20, 4, 8);
        let snap = grid.snapshot();
        let read = grid.scrollback(0, 1);
        assert_eq!(read.offset_from_top, 0);
        assert_eq!(
            read.rows[0], snap.rows_cells[0],
            "offset-0 first row == live top row, cell-for-cell"
        );
    }

    /// Smallest possible grid (1 col) reads back cleanly — exercises the narrow path
    /// where the cell-volume cap is huge but rows stay 1 wide. (A real `TermGrid` can
    /// never reach cols==0, since `clamp_dim` floors dimensions at 1; the cols==0 guard
    /// in `scrollback` is defensive and proven by inspection, not reachable here.)
    #[test]
    fn minimum_width_grid_is_safe() {
        let grid = grid_with_lines(1, 4, 8);
        let read = grid.scrollback(4, 4);
        for row in &read.rows {
            assert_eq!(row.len(), 1);
        }
    }

    // ---- total-scrollback cell cap ----

    /// Whatever the grid width, the retained history CELL count never exceeds the cell
    /// cap (`history_budget(cols) * cols <= MAX_SCROLLBACK_CELLS`). The separate
    /// per-cell retained-text test below proves bytes within each cell are bounded too.
    #[test]
    fn retained_history_cells_within_cap() {
        for cols in [1usize, 80, 200, 1000, MAX_DIMENSION as usize] {
            let cells = history_budget(cols) * cols;
            assert!(cells <= MAX_SCROLLBACK_CELLS, "cols={cols}: cell cap held");
        }
    }

    /// Cells whose text carries MANY combining marks do not escape either cap: retained
    /// rows saturate at the cell-count budget and each surviving wire cell stays within
    /// the same byte budget enforced inside the VT engine.
    #[test]
    fn combining_mark_flood_does_not_exceed_row_budget() {
        let cols = MAX_DIMENSION;
        let budget = history_budget(cols as usize);
        assert!(
            budget < HISTORY_LINES,
            "precondition: cell cap binds at {cols} cols"
        );
        // Each fed line is a base glyph followed by a long run of combining acute accents
        // (U+0301), so the first cell of every row accumulates many zero-width chars.
        let combining = "\u{0301}".repeat(64);
        let mut grid = TermGrid::new(cols, 4);
        let mut bytes = Vec::new();
        for i in 0..(budget + 1500) {
            if i > 0 {
                bytes.extend_from_slice(b"\r\n");
            }
            bytes.push(b'a');
            bytes.extend_from_slice(combining.as_bytes());
        }
        grid.advance(&bytes);
        assert_eq!(
            grid.history_len(),
            budget,
            "history row count stays at the budget despite per-cell combining-mark flood"
        );
        // The surviving cells retain a useful prefix of combining marks, while the
        // pathological tail is discarded before it can remain allocated in history.
        let read = grid.scrollback(budget as u32, 1);
        let first = read.rows[0][0].text.as_str();
        assert!(
            first.starts_with('a') && first.chars().filter(|&c| c == '\u{0301}').count() > 1,
            "oldest surviving cell retains its combining marks: {first:?}"
        );
        assert!(first.len() <= MAX_CELL_TEXT_BYTES);
    }

    /// The history-row budget is `MAX_SCROLLBACK_CELLS / cols`, clamped to
    /// `[1, HISTORY_LINES]`: narrow grids cap on rows, wide grids cap on cells, and the
    /// product never exceeds the cell ceiling.
    #[test]
    fn history_budget_caps_cells_not_just_rows() {
        // Narrow grid: cells/cols far exceeds HISTORY_LINES, so the ROW cap binds.
        assert_eq!(history_budget(20), HISTORY_LINES);
        assert_eq!(history_budget(80), HISTORY_LINES);
        // Wide grid: the CELL cap binds, yielding fewer rows than HISTORY_LINES.
        let wide = history_budget(MAX_DIMENSION as usize);
        assert_eq!(wide, MAX_SCROLLBACK_CELLS / MAX_DIMENSION as usize);
        assert!(wide < HISTORY_LINES, "cell cap binds at max width: {wide}");
        // Whatever the width, rows * cols never exceeds the cell ceiling, and there is
        // always at least one history row.
        for cols in [1usize, 20, 80, 200, 1000, MAX_DIMENSION as usize] {
            let rows = history_budget(cols);
            assert!(rows >= 1, "at least one history row at cols={cols}");
            assert!(
                rows * cols <= MAX_SCROLLBACK_CELLS,
                "cols={cols}: {rows} rows * {cols} cols exceeds cell cap"
            );
        }
    }

    /// On a wide grid the total-cell cap evicts the oldest history rows deterministically:
    /// `history_len` saturates at the cell-derived budget (well below `HISTORY_LINES`),
    /// and the oldest surviving line proves the earliest lines were dropped.
    #[test]
    fn wide_grid_cell_cap_evicts_oldest_deterministically() {
        let cols = MAX_DIMENSION;
        let budget = history_budget(cols as usize);
        // Feed comfortably more lines than the budget so eviction must occur.
        let grid = grid_with_lines(cols, 4, budget + 2000);
        assert_eq!(
            grid.history_len(),
            budget,
            "history saturates at the cell-derived budget, not HISTORY_LINES"
        );
        assert!(
            budget < HISTORY_LINES,
            "precondition: cell cap is the binding limit on a {cols}-col grid"
        );
        // Oldest surviving row: the earliest lines were evicted, so its index is large.
        let read = grid.scrollback(budget as u32, 1);
        let oldest = row_text(&read.rows[0]);
        let n: usize = oldest
            .strip_prefix("line")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("oldest row is a real line: {oldest:?}"));
        assert!(
            n > 0,
            "earliest lines evicted; oldest is line{n}, not line0"
        );
    }

    /// The live viewport rows are NEVER evicted by cap pressure: after feeding far more
    /// lines than the budget on a wide grid, the visible screen still shows the most
    /// recent lines intact (cap pressure only sheds HISTORY, never the live screen).
    #[test]
    fn active_viewport_preserved_under_cap_pressure() {
        let cols = MAX_DIMENSION;
        let rows = 4u16;
        let budget = history_budget(cols as usize);
        let total = budget + 5000;
        let grid = grid_with_lines(cols, rows, total);
        // The live snapshot's last row is the most recent line fed.
        let snap = grid.snapshot();
        let last_visible = row_text(&snap.rows_cells[rows as usize - 1]);
        assert_eq!(
            last_visible,
            format!("line{}", total - 1),
            "live bottom row is the newest line, untouched by history eviction"
        );
        // The whole visible screen holds the final `rows` lines in order.
        for (i, row) in snap.rows_cells.iter().enumerate() {
            let expected = format!("line{}", total - rows as usize + i);
            assert_eq!(row_text(row), expected, "visible row {i} preserved");
        }
    }

    /// Wide (width-2) cells are accounted by the same row budget: history of a grid whose
    /// rows are full of double-width graphemes is still capped by the cell budget, and the
    /// wide pairs survive eviction intact (lead width 2 + width-0 spacer).
    #[test]
    fn wide_cell_history_accounting_is_correct() {
        let cols = 1000u16;
        let budget = history_budget(cols as usize);
        assert!(budget < HISTORY_LINES, "cell cap binds at cols={cols}");
        let mut grid = TermGrid::new(cols, 4);
        // Each fed line is a run of CJK (width-2) glyphs, so rows are full of wide pairs.
        let mut bytes = Vec::new();
        for i in 0..(budget + 500) {
            if i > 0 {
                bytes.extend_from_slice(b"\r\n");
            }
            // 3 double-width glyphs then a marker digit so we can identify the row.
            bytes.extend_from_slice("世界河".as_bytes());
        }
        grid.advance(&bytes);
        assert_eq!(
            grid.history_len(),
            budget,
            "wide-cell history capped by the same cell budget"
        );
        // The oldest surviving history row still carries a valid wide pair: a width-2 lead
        // immediately followed by a width-0 spacer.
        let read = grid.scrollback(budget as u32, 1);
        let lead = &read.rows[0][0];
        let spacer = &read.rows[0][1];
        assert_eq!(lead.width, 2, "lead of a wide pair is width 2");
        assert_eq!(spacer.width, 0, "spacer half of a wide pair is width 0");
    }

    /// Repeated output cannot grow history without bound: feeding many separate chunks
    /// (each its own `advance`, the live PTY path) keeps `history_len` pinned at the
    /// budget, never accumulating. This is the per-`advance` enforcement, not just the
    /// one-shot construction cap.
    #[test]
    fn repeated_output_cannot_grow_history_unbounded() {
        let cols = MAX_DIMENSION;
        let budget = history_budget(cols as usize);
        let mut grid = TermGrid::new(cols, 4);
        // Drive well past the budget across MANY advances; check the cap holds each round.
        for round in 0..(budget + 3000) {
            grid.advance(format!("line{round}\r\n").as_bytes());
            assert!(
                grid.history_len() <= budget,
                "history exceeded budget at round {round}: {} > {budget}",
                grid.history_len()
            );
        }
        assert_eq!(
            grid.history_len(),
            budget,
            "history settles exactly at the budget after sustained output"
        );
    }

    /// Dropping a `TermGrid` releases its history capacity. A reaped session drops its
    /// grid, so once cap pressure has bounded a grid's history (proven above), drop frees
    /// it — history capacity cannot outlive the grid. We can't read freed memory directly,
    /// but we assert the grid is `Drop`-able after maximal cap pressure without leaking a
    /// handle, and that a fresh grid starts with empty history (no shared/static history
    /// pool persists across grids).
    #[test]
    fn dropped_grid_releases_history_capacity() {
        let cols = MAX_DIMENSION;
        let budget = history_budget(cols as usize);
        {
            let grid = grid_with_lines(cols, 4, budget + 4000);
            assert_eq!(grid.history_len(), budget, "under cap pressure before drop");
        } // grid dropped here; its history storage is freed with it.
          // A brand-new grid does not inherit any prior history: capacity is per-grid, so a
          // reaped session leaves nothing behind for the next one.
        let fresh = TermGrid::new(cols, 4);
        assert_eq!(
            fresh.history_len(),
            0,
            "a fresh grid starts with empty history; no capacity survives a drop"
        );
    }

    // ---- per-cell zero-width / combining-mark byte cap ----

    /// Build a grid with one base char ('a') in the top-left cell followed by `marks`
    /// combining acute accents (U+0301, zero-width). The daemon trims Alacritty's own
    /// `CellExtra::zerowidth`, then the snapshot path projects the same retained prefix.
    fn grid_with_combining(marks: usize) -> TermGrid {
        let mut grid = TermGrid::new(20, 4);
        let mut bytes = vec![b'a'];
        bytes.extend_from_slice("\u{0301}".repeat(marks).as_bytes());
        grid.advance(&bytes);
        grid
    }

    /// A combining-mark flood aimed at ONE cell cannot grow that cell's emitted text past
    /// `MAX_CELL_TEXT_BYTES`, no matter how many marks are fed. This is the per-cell byte
    /// bound the row/cell scrollback cap does not provide.
    #[test]
    fn combining_mark_flood_cannot_grow_one_cell_unbounded() {
        for marks in [0usize, 1, 30, 100, 5000] {
            let grid = grid_with_combining(marks);
            let snap = grid.snapshot();
            let cell = &snap.rows_cells[0][0];
            assert!(
                cell.text.len() <= MAX_CELL_TEXT_BYTES,
                "marks={marks}: cell text {} bytes exceeds the {MAX_CELL_TEXT_BYTES}-byte cap",
                cell.text.len()
            );
            // The base glyph is always preserved (truncation never empties the cell).
            assert!(
                cell.text.starts_with('a'),
                "marks={marks}: base char preserved, got {:?}",
                cell.text
            );

            let retained = grid.term.grid()[Point::new(Line(0), Column(0))]
                .zerowidth()
                .unwrap_or_default();
            let retained_bytes = 1 + retained.iter().map(|mark| mark.len_utf8()).sum::<usize>();
            assert!(
                retained_bytes <= MAX_CELL_TEXT_BYTES,
                "marks={marks}: VT engine retained {retained_bytes} bytes"
            );
            assert_eq!(
                retained.len(),
                cell.text.chars().count().saturating_sub(1),
                "wire projection matches the engine's bounded retained prefix"
            );
        }
    }

    /// A cell whose marks were truncated still snapshots DETERMINISTICALLY: the same grid
    /// state yields byte-identical cell text every read, and the retained run is the
    /// longest whole-`char` prefix that fits (no partial/garbage char at the boundary).
    #[test]
    fn truncated_cell_snapshots_deterministically() {
        let grid = grid_with_combining(5000);
        let a = grid.snapshot().rows_cells[0][0].text.clone();
        let b = grid.snapshot().rows_cells[0][0].text.clone();
        assert_eq!(a, b, "same grid state -> identical truncated cell text");
        // Valid UTF-8, within cap, and the truncation landed on a char boundary (the byte
        // length is base(1) + k*2 for k acute accents, never a split 2-byte mark).
        assert!(a.len() <= MAX_CELL_TEXT_BYTES);
        assert_eq!(
            (a.len() - 1) % "\u{0301}".len(),
            0,
            "truncated on a char boundary"
        );
        // It would deserialize cleanly on the wire (<= the deserializer's reject limit).
        let json = serde_json::to_string(&grid.snapshot().rows_cells[0][0]).unwrap();
        let back: Cell = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.text, a,
            "round-trips through the wire policy unchanged"
        );
    }

    /// Scrollback reads apply the SAME per-cell text policy as the live snapshot: a cell
    /// pushed into history carries byte-identical text to when it was live (both go through
    /// `line_to_cells`), so a renderer never sees the cell change shape as it scrolls off.
    #[test]
    fn scrollback_cell_text_matches_live_policy() {
        let mut grid = TermGrid::new(20, 4);
        // Put the flooded cell on the live top row, capture it, then scroll it into history.
        let mut bytes = vec![b'a'];
        bytes.extend_from_slice("\u{0301}".repeat(5000).as_bytes());
        grid.advance(&bytes);
        let live_text = grid.snapshot().rows_cells[0][0].text.clone();
        assert!(live_text.len() <= MAX_CELL_TEXT_BYTES && live_text.starts_with('a'));
        // Scroll it above the visible screen (4 rows tall) into history.
        grid.advance(b"\r\nL1\r\nL2\r\nL3\r\nL4\r\nL5");
        let h = grid.history_len();
        assert!(h >= 1, "expected the flooded row in history");
        let read = grid.scrollback(h as u32, 1);
        let hist_text = read.rows[0][0].text.clone();
        assert_eq!(
            hist_text, live_text,
            "history cell text equals the live policy output, byte for byte"
        );
    }
}

// ---- Dirty-row tracking (lives in the damage test module for its helpers) ----
#[cfg(test)]
mod dirty_row_tests {
    use super::*;

    // `generate_damage`'s instrumentation (`last_rows_compared` / `last_detect_scroll_attempted`)
    // is THREAD-LOCAL, so each test reads only the value its OWN `generate_damage` call recorded
    // on its thread. No cross-test lock is needed: a concurrent test on another thread cannot
    // clobber this thread's record. (That is the whole point of the thread-local instrumentation
    // — `cargo test` runs these in parallel by default and they must stay deterministic.)

    fn assert_screens_eq(a: &GridSnapshot, b: &GridSnapshot) {
        assert_eq!(a.cols, b.cols, "cols");
        assert_eq!(a.rows, b.rows, "rows");
        assert_eq!(a.rows_cells, b.rows_cells, "cells");
        assert_eq!(a.cursor_line, b.cursor_line, "cursor_line");
        assert_eq!(a.cursor_col, b.cursor_col, "cursor_col");
        assert_eq!(a.alt_screen, b.alt_screen, "alt_screen");
    }

    /// A single-line text update must cell-compare ONLY the row that
    /// changed, not the whole grid. We drive a 40-row grid, write one line, and assert the
    /// recorded row-compare count is small (`<= 3` — the edited row plus at most the old/new
    /// cursor rows alacritty also damages) and strictly fewer than all 40 rows. We also assert
    /// the single-row edit does NOT enter `detect_scroll`.
    #[test]
    fn single_row_update_compares_only_that_row() {
        let rows = 40u16;
        let mut grid = TermGrid::new(80, rows);
        // Lay down a baseline of distinct lines so the grid is non-trivial (every row has
        // real content, not all-blank — a degenerate all-blank grid would trivially diff to
        // nothing). Use absolute cursor positioning so each line lands on its own row.
        for r in 0..rows {
            grid.advance(format!("\x1b[{};1Hline-{r}", r + 1).as_bytes());
        }
        let before = grid.snapshot();

        // One more write touching a SINGLE row (row index 10, 1-based line 11).
        grid.advance(b"\x1b[11;1HEDITED");
        let after = grid.snapshot();

        let gen = generate_damage(&before, &after);
        // Behavior unchanged: a valid Frame that reconstructs `after` exactly.
        match &gen {
            DamageGen::Frame(f) => {
                assert_eq!(f.validate(), Ok(()));
                let mut recon = before.clone();
                apply_damage_for_test(&mut recon, f);
                assert_screens_eq(&recon, &after);
                // Exactly one row's worth of damage was emitted.
                assert_eq!(
                    f.ops
                        .iter()
                        .filter(|op| matches!(op, DamageOp::RowSpan { .. }))
                        .count(),
                    1,
                    "one row changed → one RowSpan"
                );
            }
            other => panic!("expected a Frame, got {other:?}"),
        }
        // The optimization itself: far fewer than all 40 rows were cell-compared. The hint
        // is a SUPERSET of the truly-changed rows — alacritty also damages the old and new
        // cursor rows on a cursor move — so the candidate set here is the edited row plus at
        // most the two cursor rows. We assert a tight small bound (<= 3) and, crucially,
        // strictly fewer than the full grid: that is the intended row-scan reduction.
        let compared = last_rows_compared();
        assert!(
            compared <= 3,
            "single-line update should compare a handful of rows, compared {compared}"
        );
        assert!(
            compared < rows as usize,
            "must compare strictly fewer than all {rows} rows (compared {compared})"
        );
        // Scroll gate: a single-row edit emits one RowSpan, so `ops.len() > 1` is false and
        // the O(rows²) `detect_scroll` scan is never attempted. A scroll op can't beat one
        // RowSpan, so there is nothing to gain — and we skip the full-grid work.
        assert!(
            !last_detect_scroll_attempted(),
            "single-row edit must NOT enter detect_scroll"
        );
    }

    /// Control: with the dirty-row hint ABSENT (e.g. snapshots decoded from the wire, where
    /// `row_stamps` is empty), the generator falls back to scanning every row — same correct
    /// damage, just no narrowing. This locks in the safe-fallback contract.
    #[test]
    fn absent_stamps_fall_back_to_full_scan() {
        let rows = 12u16;
        let mut grid = TermGrid::new(20, rows);
        for r in 0..rows {
            let line = r + 1;
            grid.advance(format!("\x1b[{line};1Hrow{r}").as_bytes());
        }
        let mut before = grid.snapshot();
        grid.advance(b"\x1b[6;1HX");
        let mut after = grid.snapshot();

        // Simulate wire-decoded snapshots: the off-wire stamps are gone on both sides.
        before.row_stamps.clear();
        after.row_stamps.clear();

        let gen = generate_damage(&before, &after);
        match &gen {
            DamageGen::Frame(f) => {
                let mut recon = before.clone();
                apply_damage_for_test(&mut recon, f);
                assert_screens_eq(&recon, &after);
            }
            other => panic!("expected a Frame, got {other:?}"),
        }
        assert_eq!(
            last_rows_compared(),
            rows as usize,
            "no stamps → scan every row (safe fallback)"
        );
    }

    /// Mismatched stamp length (one side has stamps, the other doesn't, or a stale length)
    /// is also treated as "no hint" → full scan. Guards against indexing a short stamp Vec.
    #[test]
    fn mismatched_stamp_length_falls_back() {
        let rows = 6u16;
        let mut grid = TermGrid::new(10, rows);
        grid.advance(b"\x1b[3;1Hhi");
        let before = grid.snapshot();
        grid.advance(b"\x1b[3;1Hyo");
        let mut after = grid.snapshot();
        // Truncate one side's stamps so the lengths disagree with `rows`.
        after.row_stamps.truncate(2);
        let _ = generate_damage(&before, &after);
        assert_eq!(
            last_rows_compared(),
            rows as usize,
            "mismatched stamp length must disable the hint"
        );
    }

    /// A scroll marks the whole grid dirty in the VT engine, so the stamp hint offers no
    /// narrowing (every row's stamp differs) and the generator still produces correct scroll
    /// damage (or a safe RowSpan fallback). Equivalence must hold either way.
    #[test]
    fn scroll_still_emits_correct_damage() {
        let mut grid = TermGrid::new(8, 4);
        // Fill four lines, then force a scroll by writing a 5th line at the bottom.
        grid.advance(b"AAAA\r\nBBBB\r\nCCCC\r\nDDDD");
        let before = grid.snapshot();
        // Newline at the last row scrolls everything up by one and exposes a fresh bottom.
        grid.advance(b"\r\nEEEE");
        let after = grid.snapshot();

        let gen = generate_damage(&before, &after);
        match &gen {
            DamageGen::Frame(f) => {
                assert_eq!(f.validate(), Ok(()));
                let mut recon = before.clone();
                apply_damage_for_test(&mut recon, f);
                assert_screens_eq(&recon, &after);
            }
            // A safe fallback to Resync would also be acceptable for a complex case; this
            // simple full-grid scroll should produce a Frame, but never wrong pixels.
            other => panic!("expected a Frame for a clean scroll, got {other:?}"),
        }
        // A multi-row scroll produces > 1 plain RowSpan op, so the gate passes and
        // detect_scroll IS attempted — the real-scroll counterpart to the single-row case.
        assert!(
            last_detect_scroll_attempted(),
            "a full-grid scroll must enter detect_scroll"
        );
    }

    /// A full clear (ED + home) marks every row dirty; the generator still recognizes the
    /// uniform-blank grid and emits ONE ClearAll. The stamp hint must not suppress this.
    #[test]
    fn full_clear_marks_all_rows_and_emits_clear_all() {
        let mut grid = TermGrid::new(12, 5);
        grid.advance(b"text\r\nmore text\r\neven more");
        let before = grid.snapshot();
        grid.advance(b"\x1b[2J\x1b[H");
        let after = grid.snapshot();
        match generate_damage(&before, &after) {
            DamageGen::Frame(f) => {
                assert_eq!(f.ops.len(), 1, "whole-grid clear is one op");
                assert!(matches!(f.ops[0], DamageOp::ClearAll { .. }));
                let mut recon = before.clone();
                apply_damage_for_test(&mut recon, &f);
                assert_screens_eq(&recon, &after);
            }
            other => panic!("expected ClearAll Frame, got {other:?}"),
        }
    }

    /// Resize is a geometry change → Resync regardless of stamps, and the post-resize
    /// snapshot's stamps stay aligned to the NEW row count (no stale-length panic on a
    /// later diff). Confirms `row_stamps` remain consistent across resize.
    #[test]
    fn resize_keeps_stamps_aligned_and_resyncs() {
        let mut grid = TermGrid::new(10, 3);
        grid.advance(b"hi");
        let before = grid.snapshot();
        assert_eq!(before.row_stamps.len(), 3, "stamps sized to rows");
        grid.resize(20, 6);
        let after = grid.snapshot();
        assert_eq!(after.row_stamps.len(), 6, "stamps re-sized on resize");
        assert_eq!(generate_damage(&before, &after), DamageGen::Resync);

        // A subsequent normal update on the resized grid still diffs cleanly (no panic from
        // a stale stamp length) and reconstructs.
        let post = grid.snapshot();
        grid.advance(b"\x1b[2;1Hx");
        let post2 = grid.snapshot();
        if let DamageGen::Frame(f) = generate_damage(&post, &post2) {
            let mut recon = post.clone();
            apply_damage_for_test(&mut recon, &f);
            assert_screens_eq(&recon, &post2);
        } else {
            panic!("expected a Frame after the resized-grid edit");
        }
    }

    /// Entering the alternate screen swaps the whole grid; alacritty marks full damage, so
    /// every row's stamp changes and the diff considers all rows. Equivalence must hold.
    #[test]
    fn alt_screen_enter_marks_all_rows() {
        let mut grid = TermGrid::new(10, 4);
        grid.advance(b"primary line\r\nsecond");
        let before = grid.snapshot();
        assert!(!before.alt_screen);
        // Enter the alternate screen and draw something different.
        grid.advance(b"\x1b[?1049h\x1b[2J\x1b[HALT");
        let after = grid.snapshot();
        assert!(after.alt_screen, "now on the alternate screen");
        // All stamps should differ across the swap (full damage), so the hint lists every
        // row as a candidate.
        let cands = candidate_rows(&before, &after).expect("equal-length stamps");
        assert_eq!(cands.len(), after.rows, "alt-screen swap marks all rows");
        if let DamageGen::Frame(f) = generate_damage(&before, &after) {
            let mut recon = before.clone();
            apply_damage_for_test(&mut recon, &f);
            assert_screens_eq(&recon, &after);
        } else {
            panic!("expected a Frame for the alt-screen swap");
        }
    }

    /// DIAGNOSTIC: a one-line scroll on a FULL screen must compress to a ScrollUp (+ the new
    /// bottom row), NOT a RowSpan per moved row. Otherwise a full-screen scroll would ship
    /// `rows` RowSpans and inflate transport frames.
    #[test]
    fn full_screen_one_line_scroll_compresses_to_scroll_op() {
        let mut grid = TermGrid::new(20, 6);
        // fill all 6 rows
        grid.advance(b"r1\r\nr2\r\nr3\r\nr4\r\nr5\r\nr6");
        let before = grid.snapshot();
        // one more line → the viewport scrolls up by 1 (r1 leaves, r7 appears at bottom)
        grid.advance(b"\r\nr7");
        let after = grid.snapshot();
        match generate_damage(&before, &after) {
            DamageGen::Frame(f) => {
                let scrolls = f
                    .ops
                    .iter()
                    .filter(|o| {
                        matches!(o, DamageOp::ScrollUp { .. } | DamageOp::ScrollDown { .. })
                    })
                    .count();
                let rowspans = f
                    .ops
                    .iter()
                    .filter(|o| matches!(o, DamageOp::RowSpan { .. }))
                    .count();
                // reconstruct must be exact regardless
                let mut recon = before.clone();
                apply_damage_for_test(&mut recon, &f);
                assert_screens_eq(&recon, &after);
                assert_eq!(
                    scrolls,
                    1,
                    "expected ONE scroll op, got ops={:?}",
                    f.ops.iter().map(op_name).collect::<Vec<_>>()
                );
                assert!(
                    rowspans <= 2,
                    "expected ≤2 RowSpans (new bottom row), got {rowspans}"
                );
            }
            other => panic!("expected a Frame, got {other:?}"),
        }
    }

    /// DIAGNOSTIC (real-world): streaming output where MANY lines arrive in one advance (like
    /// `seq` / Claude tokens). The viewport scrolls by several lines at once. This must still
    /// compress instead of falling back to a RowSpan per moved row.
    #[test]
    fn multi_line_scroll_in_one_advance_compresses() {
        let mut grid = TermGrid::new(20, 6);
        grid.advance(b"r1\r\nr2\r\nr3\r\nr4\r\nr5\r\nr6");
        let before = grid.snapshot();
        // 4 more lines in ONE advance → viewport scrolls up by 4
        grid.advance(b"\r\nr7\r\nr8\r\nr9\r\nr10");
        let after = grid.snapshot();
        match generate_damage(&before, &after) {
            DamageGen::Frame(f) => {
                let mut recon = before.clone();
                apply_damage_for_test(&mut recon, &f);
                assert_screens_eq(&recon, &after);
                let names: Vec<_> = f.ops.iter().map(op_name).collect();
                let scrolls = names.iter().filter(|n| n.starts_with("scroll")).count();
                assert_eq!(
                    scrolls, 1,
                    "expected ONE scroll op for a multi-line scroll, got {names:?}"
                );
            }
            other => panic!("expected a Frame, got {other:?}"),
        }
    }

    fn op_name(o: &DamageOp) -> &'static str {
        match o {
            DamageOp::RowSpan { .. } => "row_span",
            DamageOp::ClearAll { .. } => "clear_all",
            DamageOp::ScrollUp { .. } => "scroll_up",
            DamageOp::ScrollDown { .. } => "scroll_down",
        }
    }

    /// An unchanged grid still produces NoChange with stamps present — the hint never
    /// invents damage. (Equal stamps everywhere ⇒ zero candidate rows ⇒ no diff.)
    #[test]
    fn no_change_with_stamps_present() {
        let mut grid = TermGrid::new(10, 3);
        grid.advance(b"stable");
        let a = grid.snapshot();
        let b = grid.snapshot();
        assert_eq!(a.row_stamps, b.row_stamps, "identical stamps");
        assert_eq!(candidate_rows(&a, &b).unwrap().len(), 0, "no candidates");
        assert_eq!(generate_damage(&a, &b), DamageGen::NoChange);
    }
}

// ---- Snapshot/cell allocation measurement ----
//
// A repeatable, non-asserting probe for the cost of extracting a full screen of cells. It is
// `#[ignore]` so it never runs in the normal gate (it does real timing, which is noisy in CI);
// run it explicitly to compare before/after a snapshot-allocation change:
//
//     cargo test -p pty-daemon p3_snapshot_extract_cost -- --ignored --nocapture
//
// It fills a realistic 80x50 screen with mostly single-ASCII cells (the dominant case) plus a
// wide CJK cell and a combining mark (the rare multi-byte cases), then times `snapshot()` over
// many iterations and reports cells extracted + ns/cell. The number to watch across a change is
// ns/cell: cutting the per-cell `String` heap allocation should drop it without changing output.
#[cfg(test)]
mod alloc_measurement {
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore = "timing probe; run with --ignored --nocapture to compare snapshot extraction cost"]
    fn p3_snapshot_extract_cost() {
        let cols: u16 = 80;
        let rows: u16 = 50;
        let mut grid = TermGrid::new(cols, rows);
        // Realistic content: each row is ASCII text, with a wide CJK glyph and a combining
        // mark mixed in so the measurement also exercises the multi-byte cell paths.
        for r in 0..rows {
            let line = r + 1;
            grid.advance(format!("\x1b[{line};1H").as_bytes());
            // ~70 ASCII columns of varied text, then a wide char and a combining sequence.
            grid.advance(b"the quick brown fox jumps over the lazy dog 0123456789 ABCDEF ");
            grid.advance("\u{4e16}\u{754c}".as_bytes()); // two wide CJK cells
            grid.advance("e\u{0301}".as_bytes()); // 'e' + combining acute -> one cell
        }

        let iterations = 2000usize;
        // Warm up so allocator/branch state is steady before timing.
        for _ in 0..50 {
            std::hint::black_box(grid.snapshot());
        }

        let start = Instant::now();
        let mut total_cells = 0usize;
        for _ in 0..iterations {
            let snap = std::hint::black_box(grid.snapshot());
            total_cells += snap.rows_cells.iter().map(|r| r.len()).sum::<usize>();
        }
        let elapsed = start.elapsed();

        let cells_per_snapshot = (cols as usize) * (rows as usize);
        let ns_per_cell = elapsed.as_nanos() as f64 / total_cells as f64;
        println!(
            "snapshot extract: {iterations} iters x {cells_per_snapshot} cells = {total_cells} cells \
             in {:?} ({:.2} ns/cell, {:?}/snapshot)",
            elapsed,
            ns_per_cell,
            elapsed / iterations as u32
        );
        // Sanity: we extracted exactly the grid each iteration.
        assert_eq!(total_cells, cells_per_snapshot * iterations);
    }
}
