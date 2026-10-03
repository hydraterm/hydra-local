//! Selection units use the same authoritative snapshot as terminal painting and copying.

use crate::client::CellPos;
use crate::wire::{Cell, GridSnapshot};
use std::sync::Arc;

/// A bounded, immutable copy source captured at the gesture's press. Offsets only identify rows
/// within one exact daemon revision; neither history depth nor matching text proves identity later.
#[derive(Clone)]
pub(crate) struct ScrolledSelection {
    pub grid: Arc<GridSnapshot>,
    pub served_offset: u32,
    pub origin: CellPos,
    pub live_alt_screen: bool,
}

impl ScrolledSelection {
    fn matches(&self, grid: &GridSnapshot) -> bool {
        self.grid.generation == grid.generation
            && self.grid.revision == grid.revision
            && self.grid.cols == grid.cols
    }

    pub fn local(&self, pos: CellPos) -> Option<CellPos> {
        Some(CellPos {
            col: pos.col.checked_sub(self.origin.col)?,
            row: pos.row.checked_sub(self.origin.row)?,
        })
    }

    /// Project and clip only proven same-revision rows. A selection entirely outside the viewport
    /// has no painted range, but its original source remains available for Copy.
    pub fn project(
        &self,
        a: CellPos,
        b: CellPos,
        grid: &GridSnapshot,
        offset: u32,
    ) -> Option<(CellPos, CellPos)> {
        if !self.matches(grid) || grid.rows == 0 || grid.cols == 0 {
            return None;
        }
        let a = self.local(a)?;
        let b = self.local(b)?;
        let (start, end) = if (a.row, a.col) <= (b.row, b.col) {
            (a, b)
        } else {
            (b, a)
        };
        let shift = i64::from(offset) - i64::from(self.served_offset);
        let start_row = i64::try_from(start.row).ok()?.checked_add(shift)?;
        let end_row = i64::try_from(end.row).ok()?.checked_add(shift)?;
        let last = i64::try_from(grid.rows.checked_sub(1)?).ok()?;
        if end_row < 0 || start_row > last {
            return None;
        }
        Some((
            CellPos {
                col: self.origin.col + if start_row < 0 { 0 } else { start.col },
                row: self.origin.row + start_row.max(0) as usize,
            },
            CellPos {
                col: self.origin.col
                    + if end_row > last {
                        grid.cols - 1
                    } else {
                        end.col
                    },
                row: self.origin.row + end_row.min(last) as usize,
            },
        ))
    }

    /// Extension must fit in the retained source. Missing rows do not turn Shift into a new
    /// selection, invent a join, or initiate uncorrelated history requests.
    pub fn source_position(
        &self,
        pos: CellPos,
        grid: &GridSnapshot,
        offset: u32,
    ) -> Option<CellPos> {
        if !self.matches(grid) {
            return None;
        }
        let pos = self.local(pos)?;
        grid.rows_cells.get(pos.row)?.get(pos.col)?;
        let row = i64::try_from(pos.row).ok()? + i64::from(self.served_offset) - i64::from(offset);
        let row = usize::try_from(row).ok()?;
        self.grid.rows_cells.get(row)?.get(pos.col)?;
        Some(CellPos {
            col: self.origin.col + pos.col,
            row: self.origin.row + row,
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) enum SelectionUnit {
    Word,
    LogicalLine,
}

/// Select a complete logical line only when both boundaries exist in this exact painted snapshot.
/// Unknown, malformed, or off-screen boundaries fall back to the clicked visual row; no history
/// fetch or reconstruction from another revision is permitted here. Endpoints are inclusive.
pub(crate) fn logical_line_range(grid: &GridSnapshot, pos: CellPos) -> Option<(CellPos, CellPos)> {
    let row = grid.rows_cells.get(pos.row)?;
    row.get(pos.col)?;
    let visual = (
        CellPos {
            col: 0,
            row: pos.row,
        },
        CellPos {
            col: row.len() - 1,
            row: pos.row,
        },
    );
    let Some(metadata) = grid.row_copy.as_deref().filter(|metadata| {
        grid.rows == grid.rows_cells.len()
            && grid.rows_cells.iter().all(|row| row.len() == grid.cols)
            && crate::wire::row_copy_cells_valid(&grid.rows_cells, Some(metadata))
    }) else {
        return Some(visual);
    };
    let mut start = pos.row;
    loop {
        match metadata[start].starts_line {
            Some(true) => break,
            Some(false) if start > 0 && metadata[start - 1].soft_wrap => start -= 1,
            _ => return Some(visual),
        }
    }
    let mut end = pos.row;
    while metadata[end].soft_wrap {
        if metadata
            .get(end + 1)
            .is_none_or(|next| next.starts_line != Some(false))
        {
            return Some(visual);
        }
        end += 1;
    }
    Some((
        CellPos { col: 0, row: start },
        CellPos {
            col: grid.cols - 1,
            row: end,
        },
    ))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WordClass {
    Word,
    Space,
    Punctuation,
}

fn word_class(cell: &Cell) -> WordClass {
    match cell.text.chars().next() {
        Some(c) if c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '~') => {
            WordClass::Word
        }
        None => WordClass::Space,
        Some(c) if c.is_whitespace() => WordClass::Space,
        _ => WordClass::Punctuation,
    }
}

/// Select one word/path, a run of whitespace, or one punctuation grapheme. A wide spacer belongs
/// to its preceding lead cell. Without row-wrap metadata, a visual row is the known boundary.
pub(crate) fn word_range(cells: &[Vec<Cell>], pos: CellPos) -> Option<(CellPos, CellPos)> {
    let row = cells.get(pos.row)?;
    let mut col = pos.col;
    let cell = row.get(col)?;
    if cell.width == 0 && col > 0 && row[col - 1].width == 2 {
        col -= 1;
    }
    let class = word_class(&row[col]);
    let mut start = col;
    let mut end = col;
    if class != WordClass::Punctuation {
        while start > 0 {
            let mut previous = start - 1;
            if row[previous].width == 0 && previous > 0 && row[previous - 1].width == 2 {
                previous -= 1;
            }
            if word_class(&row[previous]) != class {
                break;
            }
            start = previous;
        }
        while end + 1 < row.len() {
            let next = end + usize::from(row[end].width.max(1));
            if next >= row.len() || word_class(&row[next]) != class {
                break;
            }
            end = next;
        }
    }
    if row[end].width == 2 && row.get(end + 1).is_some_and(|cell| cell.width == 0) {
        end += 1;
    }
    Some((
        CellPos {
            col: start,
            row: pos.row,
        },
        CellPos {
            col: end,
            row: pos.row,
        },
    ))
}
