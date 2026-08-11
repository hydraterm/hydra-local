//! Pure unit-rect pane geometry — the faithful replacement for the lossy flat `split_from` chain.
//!
//! The window layout's geometry is a set of panes, each occupying a `UnitRect` `[x, y, w, h]` in the
//! unit square that tile it exactly. Unlike the old per-pane `split_from { parent, axis }` (which could
//! not distinguish `A/C│B` from `A│B│C/D`), a rect set is an exact,
//! unambiguous description of what the screen shows: the renderer scales each rect by the grid and paints
//! it directly, with dividers derived from shared internal edges. No interpretation, no canonical-layout
//! guessing.
//!
//! Everything here is pure: no IO, no sessions, no pixels beyond the integer grid mapping.

/// A rect in the unit square: `[x, y, w, h]`, all in `[0,1]`, `w,h > 0`.
pub type UnitRect = [f32; 4];

/// One pane's placement on the integer terminal grid: top-left cell `(col,row)` and extent
/// `cols×rows`. Mirrors the renderer's `RendererPaneRegion` so the projection is a trivial field copy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GridRegion {
    pub col: u16,
    pub row: u16,
    pub cols: u16,
    pub rows: u16,
}

/// A divider segment between two panes: a vertical (`vertical = true`) or horizontal line at a grid
/// position, drawn so the user can grab it to resize. Derived from the internal edges shared by adjacent
/// pane rects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GridDivider {
    pub col: u16,
    pub row: u16,
    pub length: u16,
    pub vertical: bool,
}

fn r_right(r: UnitRect) -> f32 {
    r[0] + r[2]
}
fn r_bottom(r: UnitRect) -> f32 {
    r[1] + r[3]
}
fn near(a: f32, b: f32) -> bool {
    (a - b).abs() <= 1e-4
}

/// Map a fraction in `[0,1]` to an integer grid line in `[0, extent]`, rounding to the nearest cell.
fn line(frac: f32, extent: u16) -> u16 {
    let v = (frac * extent as f32).round();
    v.clamp(0.0, extent as f32) as u16
}

/// Convert each pane's unit rect to an integer [`GridRegion`] over a `cols×rows` grid. The mapping floors
/// every rect to the SAME shared grid lines (each internal x/y edge maps to one integer line used by both
/// neighbors), so adjacent panes meet exactly with no overlap or gap. A pane whose rounded extent would
/// be zero is given a minimum of 1 cell so it never vanishes.
pub fn regions(rects: &[(String, UnitRect)], cols: u16, rows: u16) -> Vec<(String, GridRegion)> {
    rects
        .iter()
        .map(|(id, r)| {
            let x0 = line(r[0], cols);
            let y0 = line(r[1], rows);
            let x1 = line(r_right(*r), cols).max(x0 + 1).min(cols);
            let y1 = line(r_bottom(*r), rows).max(y0 + 1).min(rows);
            (
                id.clone(),
                GridRegion {
                    col: x0,
                    row: y0,
                    cols: x1 - x0,
                    rows: y1 - y0,
                },
            )
        })
        .collect()
}

/// Derive the divider segments between adjacent panes from their unit rects. A vertical divider sits on
/// any internal x-line where one pane's right edge meets another's left edge AND their vertical spans
/// overlap; symmetric for horizontal dividers. Coordinates are on the `cols×rows` grid. Deduplicated so
/// one shared edge yields one divider per overlapping span.
pub fn dividers(rects: &[(String, UnitRect)], cols: u16, rows: u16) -> Vec<GridDivider> {
    let mut out: Vec<GridDivider> = Vec::new();
    for (_, a) in rects {
        for (_, b) in rects {
            // vertical divider: a is left of b, a.right == b.left, spans overlap.
            if near(r_right(*a), b[0]) {
                let top = a[1].max(b[1]);
                let bot = r_bottom(*a).min(r_bottom(*b));
                if bot - top > 1e-4 {
                    let col = line(b[0], cols)
                        .saturating_sub(1)
                        .min(cols.saturating_sub(1));
                    let r0 = line(top, rows);
                    let r1 = line(bot, rows);
                    push_unique(
                        &mut out,
                        GridDivider {
                            col,
                            row: r0,
                            length: r1.saturating_sub(r0).max(1),
                            vertical: true,
                        },
                    );
                }
            }
            // horizontal divider: a is above b, a.bottom == b.top, spans overlap.
            if near(r_bottom(*a), b[1]) {
                let left = a[0].max(b[0]);
                let right = r_right(*a).min(r_right(*b));
                if right - left > 1e-4 {
                    let row = line(b[1], rows)
                        .saturating_sub(1)
                        .min(rows.saturating_sub(1));
                    let c0 = line(left, cols);
                    let c1 = line(right, cols);
                    push_unique(
                        &mut out,
                        GridDivider {
                            col: c0,
                            row,
                            length: c1.saturating_sub(c0).max(1),
                            vertical: false,
                        },
                    );
                }
            }
        }
    }
    out
}

fn push_unique(out: &mut Vec<GridDivider>, d: GridDivider) {
    if !out.contains(&d) {
        out.push(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(rs: &[(&str, UnitRect)]) -> Vec<(String, UnitRect)> {
        rs.iter().map(|(id, r)| (id.to_string(), *r)).collect()
    }
    fn region_of<'a>(v: &'a [(String, GridRegion)], id: &str) -> &'a GridRegion {
        &v.iter().find(|(i, _)| i == id).unwrap().1
    }

    #[test]
    fn regions_tile_the_grid_without_overlap_or_gap() {
        // A│(B/C) over a 40×20 grid: A left half full height; B top-right; C bottom-right.
        let rs = ids(&[
            ("A", [0.0, 0.0, 0.5, 1.0]),
            ("B", [0.5, 0.0, 0.5, 0.5]),
            ("C", [0.5, 0.5, 0.5, 0.5]),
        ]);
        let regs = regions(&rs, 40, 20);
        let a = region_of(&regs, "A");
        let b = region_of(&regs, "B");
        let c = region_of(&regs, "C");
        assert_eq!(
            *a,
            GridRegion {
                col: 0,
                row: 0,
                cols: 20,
                rows: 20
            }
        );
        assert_eq!(
            *b,
            GridRegion {
                col: 20,
                row: 0,
                cols: 20,
                rows: 10
            }
        );
        assert_eq!(
            *c,
            GridRegion {
                col: 20,
                row: 10,
                cols: 20,
                rows: 10
            }
        );
        // B and C meet A's right edge; B sits above C with no overlap.
        assert_eq!(a.col + a.cols, b.col);
        assert_eq!(b.row + b.rows, c.row);
    }

    #[test]
    fn the_two_ambiguous_layouts_render_differently_from_rects() {
        // The pair the flat split_from could NOT distinguish — now exact, because rects are exact.
        // A/C│B: A top-left, C bottom-left, B full-height right.
        let acb = ids(&[
            ("A", [0.0, 0.0, 0.5, 0.5]),
            ("C", [0.0, 0.5, 0.5, 0.5]),
            ("B", [0.5, 0.0, 0.5, 1.0]),
        ]);
        let acb_r = regions(&acb, 40, 20);
        assert_eq!(region_of(&acb_r, "B").rows, 20, "B full height in A/C│B");
        assert_eq!(region_of(&acb_r, "A").rows, 10, "A half height in A/C│B");

        // A│B│C / D: A,B,C in the top row, D full-width bottom.
        let abcd = ids(&[
            ("A", [0.0, 0.0, 1.0 / 3.0, 0.5]),
            ("B", [1.0 / 3.0, 0.0, 1.0 / 3.0, 0.5]),
            ("C", [2.0 / 3.0, 0.0, 1.0 / 3.0, 0.5]),
            ("D", [0.0, 0.5, 1.0, 0.5]),
        ]);
        let abcd_r = regions(&abcd, 30, 20);
        assert_eq!(region_of(&abcd_r, "D").cols, 30, "D full width in A│B│C/D");
        assert_eq!(region_of(&abcd_r, "A").rows, 10, "top row is half height");
        // The two layouts differ — exactly what the flat model could not express.
    }

    #[test]
    fn dividers_sit_on_shared_internal_edges() {
        // Two columns: one vertical divider down the middle.
        let two_col = ids(&[("A", [0.0, 0.0, 0.5, 1.0]), ("B", [0.5, 0.0, 0.5, 1.0])]);
        let ds = dividers(&two_col, 40, 20);
        assert_eq!(ds.len(), 1);
        assert!(ds[0].vertical);
        assert_eq!(ds[0].length, 20);

        // Two rows: one horizontal divider across the middle.
        let two_row = ids(&[("A", [0.0, 0.0, 1.0, 0.5]), ("B", [0.0, 0.5, 1.0, 0.5])]);
        let ds = dividers(&two_row, 40, 20);
        assert_eq!(ds.len(), 1);
        assert!(!ds[0].vertical);
        assert_eq!(ds[0].length, 40);
    }

    #[test]
    fn a_local_split_produces_unequal_columns_faithfully() {
        // (A│X)│B — A and X each 1/4 wide, B 1/2 (the confirmed INSERT local-split result).
        let rs = ids(&[
            ("A", [0.0, 0.0, 0.25, 1.0]),
            ("X", [0.25, 0.0, 0.25, 1.0]),
            ("B", [0.5, 0.0, 0.5, 1.0]),
        ]);
        let regs = regions(&rs, 40, 20);
        assert_eq!(region_of(&regs, "A").cols, 10);
        assert_eq!(region_of(&regs, "X").cols, 10);
        assert_eq!(region_of(&regs, "B").cols, 20);
        // adjacency holds: A|X|B meet exactly.
        let a = region_of(&regs, "A");
        let x = region_of(&regs, "X");
        let b = region_of(&regs, "B");
        assert_eq!(a.col + a.cols, x.col);
        assert_eq!(x.col + x.cols, b.col);
        assert_eq!(b.col + b.cols, 40);
    }
}
