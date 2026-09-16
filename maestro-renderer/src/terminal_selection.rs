//! Selection units use the same authoritative snapshot as terminal painting and copying.

use crate::client::CellPos;
use crate::wire::{Cell, GridSnapshot};

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
