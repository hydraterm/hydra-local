//! Word selection uses the same authoritative cells as terminal painting and copying.

use crate::client::CellPos;
use crate::wire::Cell;

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
