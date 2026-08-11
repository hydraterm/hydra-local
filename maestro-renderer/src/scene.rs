//! Deterministic, shell-independent test scene. Builds a synthetic `GridSnapshot`
//! that exercises the renderer's full cell vocabulary — RGB / indexed / named
//! colors, wide cells + their width-0 spacers, combining marks, inverse, every
//! underline style, dim, and (via successive frames) all three cursor shapes.
//!
//! This isolates renderer correctness from shell quoting and PTY behavior: the
//! pixels come straight from a hand-built grid, so any misalignment is the
//! renderer's, not the terminal's. Run with `maestro-renderer --demo-scene`.

use crate::wire::{
    Cell, Color, CursorShape, GridSnapshot, NamedColor, Revision, SessionGeneration, UnderlineStyle,
};

const COLS: usize = 48;
const ROWS: usize = 16;

fn rgb(r: u8, g: u8, b: u8) -> Color {
    Color::Rgb { r, g, b }
}
fn named(name: NamedColor) -> Color {
    Color::Named { name }
}
fn indexed(index: u8) -> Color {
    Color::Indexed { index }
}

const DEFAULT_FG: Color = Color::Named {
    name: NamedColor::Foreground,
};
const DEFAULT_BG: Color = Color::Named {
    name: NamedColor::Background,
};

/// A 1-wide cell with default colors and no attributes.
fn cell(text: &str) -> Cell {
    Cell {
        text: text.to_string(),
        fg: DEFAULT_FG,
        bg: DEFAULT_BG,
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

/// A width-0 spacer that trails a wide (width-2) lead cell. Carries no text.
fn spacer() -> Cell {
    Cell {
        text: String::new(),
        width: 0,
        ..cell("")
    }
}

/// Write `text` into `row` starting at `col`, one char per cell, applying `style`
/// to each cell. Returns the next free column. CJK/wide chars are NOT handled
/// here — use `put_wide` for those so the width-2 + spacer pair stays correct.
fn put(row: &mut [Cell], mut col: usize, text: &str, style: &dyn Fn(Cell) -> Cell) -> usize {
    for ch in text.chars() {
        if col >= row.len() {
            break;
        }
        let mut c = cell(&ch.to_string());
        c = style(c);
        row[col] = c;
        col += 1;
    }
    col
}

/// Place a single wide (2-column) grapheme: a width-2 lead carrying the text and
/// a trailing width-0 spacer. Returns the next free column (advanced by 2).
fn put_wide(row: &mut [Cell], col: usize, text: &str, style: &dyn Fn(Cell) -> Cell) -> usize {
    if col + 1 >= row.len() {
        return col;
    }
    let mut lead = cell(text);
    lead.width = 2;
    lead = style(lead);
    row[col] = lead;
    row[col + 1] = spacer();
    col + 2
}

fn blank_row() -> Vec<Cell> {
    (0..COLS).map(|_| cell(" ")).collect()
}

/// Build the fixture grid. `cursor_shape` lets a caller cycle shapes across
/// frames so all three can be eyeballed without rebuilding the rest.
pub fn snapshot(revision: u64, cursor_shape: CursorShape) -> GridSnapshot {
    let mut rows: Vec<Vec<Cell>> = (0..ROWS).map(|_| blank_row()).collect();

    // Row 0: named foreground colors (the 8 base ANSI).
    {
        let r = &mut rows[0];
        let names = [
            ("blk", NamedColor::Black),
            ("red", NamedColor::Red),
            ("grn", NamedColor::Green),
            ("yel", NamedColor::Yellow),
            ("blu", NamedColor::Blue),
            ("mag", NamedColor::Magenta),
            ("cyn", NamedColor::Cyan),
            ("wht", NamedColor::White),
        ];
        let mut col = 0;
        for (label, nc) in names {
            col = put(r, col, label, &|mut c| {
                c.fg = named(nc);
                c
            });
            col += 1;
        }
    }

    // Row 1: bold + bright named colors.
    {
        let r = &mut rows[1];
        let names = [
            ("BLK", NamedColor::BrightBlack),
            ("RED", NamedColor::BrightRed),
            ("GRN", NamedColor::BrightGreen),
            ("YEL", NamedColor::BrightYellow),
            ("BLU", NamedColor::BrightBlue),
            ("MAG", NamedColor::BrightMagenta),
            ("CYN", NamedColor::BrightCyan),
            ("WHT", NamedColor::BrightWhite),
        ];
        let mut col = 0;
        for (label, nc) in names {
            col = put(r, col, label, &|mut c| {
                c.fg = named(nc);
                c.bold = true;
                c
            });
            col += 1;
        }
    }

    // Row 2: indexed 256-color cube samples on colored backgrounds.
    {
        let r = &mut rows[2];
        let mut col = 0;
        for idx in [16u8, 51, 82, 196, 208, 226, 21, 244] {
            col = put(r, col, "##", &|mut c| {
                c.bg = indexed(idx);
                c.fg = named(NamedColor::Black);
                c
            });
            col += 1;
        }
    }

    // Row 3: true-color RGB gradient.
    {
        let r = &mut rows[3];
        for (col, slot) in r.iter_mut().enumerate().take(COLS) {
            let t = col as f32 / (COLS - 1) as f32;
            let cr = (t * 255.0) as u8;
            let cb = ((1.0 - t) * 255.0) as u8;
            let mut c = cell(" ");
            c.bg = rgb(cr, 64, cb);
            *slot = c;
        }
    }

    // Row 4: wide CJK pairs (each is width-2 lead + width-0 spacer). After three
    // wide glyphs (6 cells) the trailing ASCII must start at col 6 exactly.
    {
        let r = &mut rows[4];
        let style = |mut c: Cell| {
            c.fg = named(NamedColor::BrightCyan);
            c
        };
        let mut col = 0;
        col = put_wide(r, col, "界", &style);
        col = put_wide(r, col, "語", &style);
        col = put_wide(r, col, "あ", &style);
        put(r, col, "<-ascii after 3 wide", &|c| c);
    }

    // Row 5: combining marks — base letter + combining diacritic in ONE cell.
    {
        let r = &mut rows[5];
        let mut col = put(r, 0, "combining: ", &|c| c);
        // e + U+0301 (acute), a + U+0308 (diaeresis), n + U+0303 (tilde).
        for g in ["e\u{0301}", "a\u{0308}", "n\u{0303}", "o\u{0302}"] {
            r[col] = cell(g);
            col += 2; // a space between samples
        }
    }

    // Row 6: inverse video (fg/bg swap should be honored by the renderer).
    {
        let r = &mut rows[6];
        put(r, 0, " INVERSE VIDEO ", &|mut c| {
            c.fg = named(NamedColor::White);
            c.bg = named(NamedColor::Blue);
            c.inverse = true;
            c
        });
    }

    // Row 7: dim attribute (fg scaled toward black).
    {
        let r = &mut rows[7];
        let col = put(r, 0, "normal ", &|c| c);
        put(r, col, "dimmed-text", &|mut c| {
            c.dim = true;
            c
        });
    }

    // Rows 8..13: each underline style drawn on a readable sample word, with a plain
    // (undecorated) label naming the style so the eye can compare the DECORATION to its
    // name. The decoration is painted by the renderer (decoration_rects); curly is a
    // documented approximation (dense dotted) until a decoration shader exists.
    {
        let styles = [
            ("single", UnderlineStyle::Single),
            ("double", UnderlineStyle::Double),
            ("curly~", UnderlineStyle::Curly),
            ("dotted", UnderlineStyle::Dotted),
            ("dashed", UnderlineStyle::Dashed),
        ];
        for (i, (label, us)) in styles.into_iter().enumerate() {
            let r = &mut rows[8 + i];
            // Decorated sample: the underline draws under these glyphs.
            let col = put(r, 0, "Sample", &move |mut c| {
                c.underline = us;
                c
            }) + 1;
            // Plain label (no decoration) for comparison.
            put(r, col, label, &|c| c);
        }
    }

    // Row 13: strikethrough drawn on a sample word, plus an italic sample, plus a cell
    // that is BOTH underlined and struck through to prove the two decorations combine.
    {
        let r = &mut rows[13];
        let col = put(r, 0, "Strike", &|mut c| {
            c.strikeout = true;
            c
        }) + 1;
        let col = put(r, col, "italic", &|mut c| {
            c.italic = true;
            c
        }) + 1;
        put(r, col, "both", &|mut c| {
            c.strikeout = true;
            c.underline = UnderlineStyle::Single;
            c
        });
    }

    // Row 14: label.
    {
        let r = &mut rows[14];
        put(r, 0, "-- maestro-renderer demo scene --", &|mut c| {
            c.fg = named(NamedColor::BrightYellow);
            c
        });
    }

    GridSnapshot {
        version: crate::sync::SUPPORTED_VERSION,
        generation: SessionGeneration("00000000-0000-0000-0000-0000scene".to_string()),
        revision: Revision(revision),
        // Self-baselining fixture: each frame is a fresh full snapshot.
        base_revision: Revision(revision),
        cols: COLS,
        rows: ROWS,
        rows_cells: rows,
        // Cursor parked on the label row, first column, so its cell-snap is easy
        // to eyeball against the 'M' below it.
        cursor_line: 15,
        cursor_col: 0,
        cursor_visible: true,
        cursor_shape,
        alt_screen: false,
        app_cursor: false,
        bracketed_paste: false,
        focus_reporting: false,
        mouse_report: false,
        mouse_drag: false,
        mouse_motion: false,
        mouse_sgr: false,
    }
}

/// Reproducible stress grids. Each builds a FIXED full-screen snapshot whose
/// every paintable cell carries text, so the renderer's per-cell glyph cost is exercised
/// at a known, repeatable density (unlike the live shell, where content varies frame to
/// frame). Selected by name on the command line: `maestro-renderer --stress <mode>`.
#[derive(Clone, Copy)]
pub enum StressMode {
    /// A full 80x24 of dense ASCII — the classic terminal size, every cell filled.
    Dense80x24,
    /// A full 160x48 of dense ASCII — 4x the cells; the worst-case throughput probe.
    Dense160x48,
    /// 80x24 where every cell also carries a distinct fg/bg color and bold/italic, so
    /// the per-cell attribute/shape path (and any cache keyed on attrs) is stressed,
    /// not just plain glyphs.
    StyleHeavy,
    /// 80x24 of wide CJK lead+spacer pairs interleaved with base+combining graphemes —
    /// the correctness-sensitive path the optimization must not break.
    WideCombining,
}

impl StressMode {
    /// Parse the CLI mode token; `None` if unrecognized.
    pub fn parse(s: &str) -> Option<StressMode> {
        match s {
            "dense-80x24" => Some(StressMode::Dense80x24),
            "dense-160x48" => Some(StressMode::Dense160x48),
            "styles" => Some(StressMode::StyleHeavy),
            "wide-combining" => Some(StressMode::WideCombining),
            _ => None,
        }
    }

    pub fn names() -> &'static str {
        "dense-80x24 | dense-160x48 | styles | wide-combining"
    }

    fn dims(self) -> (usize, usize) {
        match self {
            StressMode::Dense160x48 => (160, 48),
            _ => (80, 24),
        }
    }
}

/// Build a fixed stress snapshot for `mode` at `revision`. Self-baselining like
/// `snapshot`: each frame is a full snapshot, so the renderer re-shapes every cell every
/// frame — exactly the cost this stress mode measures.
pub fn stress_snapshot(mode: StressMode, revision: u64) -> GridSnapshot {
    let (cols, rows) = mode.dims();
    let mut rows_cells: Vec<Vec<Cell>> = Vec::with_capacity(rows);

    // A small rotating ASCII alphabet keeps cells non-blank and varied without being
    // random (reproducible frame to frame).
    const GLYPHS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    for r in 0..rows {
        let mut row: Vec<Cell> = Vec::with_capacity(cols);
        match mode {
            StressMode::WideCombining => {
                let mut c = 0;
                while c < cols {
                    if c % 4 == 0 && c + 1 < cols {
                        // Wide CJK lead + width-0 spacer.
                        let mut lead = cell("界");
                        lead.width = 2;
                        lead.fg = named(NamedColor::BrightCyan);
                        row.push(lead);
                        row.push(spacer());
                        c += 2;
                    } else {
                        // Base letter + combining diacritic in ONE cell.
                        row.push(cell("e\u{0301}"));
                        c += 1;
                    }
                }
                row.truncate(cols);
                while row.len() < cols {
                    row.push(cell(" "));
                }
            }
            StressMode::StyleHeavy => {
                for col in 0..cols {
                    let g = GLYPHS[(r * cols + col) % GLYPHS.len()] as char;
                    let mut cl = cell(&g.to_string());
                    cl.fg = indexed(((r * 7 + col * 3) % 256) as u8);
                    cl.bg = indexed(((r * 5 + col * 11 + 16) % 256) as u8);
                    cl.bold = (col + r) % 2 == 0;
                    cl.italic = (col + r) % 3 == 0;
                    row.push(cl);
                }
            }
            _ => {
                for col in 0..cols {
                    let g = GLYPHS[(r * cols + col) % GLYPHS.len()] as char;
                    row.push(cell(&g.to_string()));
                }
            }
        }
        rows_cells.push(row);
    }

    GridSnapshot {
        version: crate::sync::SUPPORTED_VERSION,
        generation: SessionGeneration("00000000-0000-0000-0000-00stress".to_string()),
        revision: Revision(revision),
        base_revision: Revision(revision),
        cols,
        rows,
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_is_well_formed() {
        let g = snapshot(7, CursorShape::Block);
        assert_eq!(g.cols, COLS);
        assert_eq!(g.rows, ROWS);
        assert_eq!(g.rows_cells.len(), ROWS);
        for row in &g.rows_cells {
            assert_eq!(row.len(), COLS, "every row is exactly COLS wide");
        }
        assert!(g.cursor_line < g.rows && g.cursor_col < g.cols);
    }

    #[test]
    fn wide_cells_are_lead_plus_spacer() {
        let g = snapshot(1, CursorShape::Block);
        // Row 4 begins with three width-2 leads, each followed by a width-0 spacer.
        let row = &g.rows_cells[4];
        for pair in 0..3 {
            let lead = &row[pair * 2];
            let spacer = &row[pair * 2 + 1];
            assert_eq!(lead.width, 2, "lead of wide pair {pair}");
            assert!(!lead.text.is_empty(), "lead carries the glyph");
            assert_eq!(spacer.width, 0, "spacer of wide pair {pair}");
            assert!(spacer.text.is_empty(), "spacer carries no text");
        }
        // The ASCII tail must begin exactly at column 6 (3 wide glyphs * 2 cells).
        assert_eq!(row[6].text, "<");
    }

    #[test]
    fn combining_mark_occupies_one_cell() {
        let g = snapshot(1, CursorShape::Block);
        let row = &g.rows_cells[5];
        // "combining: " is 11 chars; first sample 'é' (e + U+0301) lands at col 11.
        let cell = &row[11];
        assert_eq!(cell.text.chars().count(), 2, "base + combining in one cell");
        assert_eq!(cell.width, 1, "still a single-width cell");
    }
}
