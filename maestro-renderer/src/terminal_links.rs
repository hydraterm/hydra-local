//! Bounded terminal-row link detection and hit testing.
//!
//! This module is pure: it never opens a URL.  It projects one authoritative wire
//! row into cell spans, prefers OSC 8 metadata, and falls back to a single-row
//! plain-text HTTP(S) scan.  Native opening remains behind `HostServices`.

use crate::wire::Cell;

/// Maximum link spans considered for one visible frame.  The live caller asks about
/// only the row under the pointer, so this is both the row and frame ceiling.
pub const MAX_LINK_SPANS_PER_FRAME: usize = 128;

/// Maximum reconstructed row bytes considered by the plain-text detector.
const MAX_PLAIN_LINK_SCAN_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkSource {
    Osc8,
    PlainText,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TerminalLinkSpan {
    pub url: String,
    pub start_col: usize,
    pub end_col: usize,
    pub source: LinkSource,
}

/// Resolve `target_col` against one rendered logical row.  OSC 8 spans are checked
/// first, then bounded plain text.  Hidden cells never form a target; a wide lead's
/// hit rectangle includes its spacer column.
pub fn link_at_cell(row: &[Cell], target_col: usize) -> Option<TerminalLinkSpan> {
    if target_col >= row.len() || row[target_col].hidden {
        return None;
    }

    let mut considered = 0usize;
    let mut index = 0usize;
    while index < row.len() && considered < MAX_LINK_SPANS_PER_FRAME {
        // A width-0 cell is only the spacer owned by the preceding width-2 lead.
        // It may extend that lead's hit rectangle, but malformed wire metadata on
        // the spacer must never create an otherwise invisible link target.
        if row[index].width == 0 {
            index += 1;
            continue;
        }
        let Some(url) = safe_cell_hyperlink(&row[index]) else {
            index += 1;
            continue;
        };
        let start = index;
        let mut end = (index + usize::from(row[index].width.max(1))).min(row.len());
        index += 1;
        while index < row.len() && safe_cell_hyperlink(&row[index]).is_some_and(|next| next == url)
        {
            end = end
                .max(index + usize::from(row[index].width.max(1)))
                .min(row.len());
            index += 1;
        }
        considered += 1;
        if (start..end).contains(&target_col) {
            return Some(TerminalLinkSpan {
                url: url.to_owned(),
                start_col: start,
                end_col: end,
                source: LinkSource::Osc8,
            });
        }
    }

    let (text, cells) = reconstructed_row(row);
    for (start, end) in plain_url_ranges(&text, MAX_LINK_SPANS_PER_FRAME - considered) {
        let Some(start_cell) = cells
            .iter()
            .find(|cell| cell.byte_start <= start && start < cell.byte_end)
        else {
            continue;
        };
        let Some(end_cell) = cells
            .iter()
            .find(|cell| cell.byte_start < end && end <= cell.byte_end)
        else {
            continue;
        };
        let end_col = end_cell.end_col.min(row.len());
        if (start_cell.start_col..end_col).contains(&target_col) {
            return Some(TerminalLinkSpan {
                url: text[start..end].to_owned(),
                start_col: start_cell.start_col,
                end_col,
                source: LinkSource::PlainText,
            });
        }
    }
    None
}

fn safe_cell_hyperlink(cell: &Cell) -> Option<&str> {
    if cell.hidden {
        return None;
    }
    cell.hyperlink
        .as_deref()
        .filter(|url| maestro_protocol::is_safe_terminal_http_url(url))
}

#[derive(Clone, Copy)]
struct ReconstructedCell {
    byte_start: usize,
    byte_end: usize,
    start_col: usize,
    end_col: usize,
}

fn reconstructed_row(row: &[Cell]) -> (String, Vec<ReconstructedCell>) {
    let mut text = String::new();
    let mut cells = Vec::with_capacity(row.len());
    for (col, cell) in row.iter().enumerate() {
        if cell.width == 0 {
            continue;
        }
        let fragment = if cell.hidden || cell.text.is_empty() {
            " "
        } else {
            cell.text.as_str()
        };
        if text.len().saturating_add(fragment.len()) > MAX_PLAIN_LINK_SCAN_BYTES {
            break;
        }
        let byte_start = text.len();
        text.push_str(fragment);
        cells.push(ReconstructedCell {
            byte_start,
            byte_end: text.len(),
            start_col: col,
            end_col: (col + usize::from(cell.width.max(1))).min(row.len()),
        });
    }
    (text, cells)
}

fn plain_url_ranges(text: &str, limit: usize) -> Vec<(usize, usize)> {
    let bytes = text.as_bytes();
    let mut ranges = Vec::new();
    let mut index = 0usize;
    while index < bytes.len() && ranges.len() < limit {
        let prefix_len = if starts_ascii_case_insensitive(bytes, index, b"https://") {
            8
        } else if starts_ascii_case_insensitive(bytes, index, b"http://") {
            7
        } else {
            index += 1;
            continue;
        };

        let boundary_ok = text[..index]
            .chars()
            .next_back()
            .is_none_or(|ch| !ch.is_alphanumeric() && !matches!(ch, '_' | '-'));
        if !boundary_ok {
            index += prefix_len;
            continue;
        }

        let mut end = text.len();
        for (offset, ch) in text[index..].char_indices() {
            if offset > 0
                && (ch.is_whitespace()
                    || ch.is_control()
                    || matches!(ch, '<' | '>' | '"' | '\'' | '`' | '|'))
            {
                end = index + offset;
                break;
            }
        }
        end = trim_trailing_punctuation(text, index, end);
        if end > index
            && end - index <= maestro_protocol::MAX_TERMINAL_URL_BYTES
            && maestro_protocol::is_safe_terminal_http_url(&text[index..end])
        {
            ranges.push((index, end));
            index = end;
        } else {
            index += prefix_len;
        }
    }
    ranges
}

fn starts_ascii_case_insensitive(bytes: &[u8], start: usize, prefix: &[u8]) -> bool {
    bytes
        .get(start..start.saturating_add(prefix.len()))
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

fn trim_trailing_punctuation(text: &str, start: usize, mut end: usize) -> usize {
    loop {
        let Some(last) = text[start..end].chars().next_back() else {
            return end;
        };
        let trim = matches!(last, '.' | ',' | ';' | ':' | '!')
            || (last == ')'
                && text[start..end].matches(')').count() > text[start..end].matches('(').count())
            || (last == ']'
                && text[start..end].matches(']').count() > text[start..end].matches('[').count())
            || (last == '}'
                && text[start..end].matches('}').count() > text[start..end].matches('{').count());
        if !trim {
            return end;
        }
        end -= last.len_utf8();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{Color, NamedColor, UnderlineStyle};

    fn cell(text: &str) -> Cell {
        Cell {
            text: text.to_owned(),
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
            hyperlink: None,
            width: 1,
        }
    }

    fn row(text: &str) -> Vec<Cell> {
        text.chars().map(|ch| cell(&ch.to_string())).collect()
    }

    #[test]
    fn plain_http_boundaries_and_punctuation_are_bounded_to_one_row() {
        let cells = row("see (https://example.com/a?q=1), then xhttps://bad.test");
        let hit = link_at_cell(&cells, 8).unwrap();
        assert_eq!(hit.source, LinkSource::PlainText);
        assert_eq!(hit.url, "https://example.com/a?q=1");
        assert_eq!(&cells[hit.start_col].text, "h");
        assert_eq!(&cells[hit.end_col].text, ")");
        assert!(link_at_cell(&cells, cells.len() - 3).is_none());
    }

    #[test]
    fn osc8_wins_over_visible_plain_text_and_invalid_schemes_never_open() {
        let mut cells = row("https://visible.test");
        for cell in &mut cells {
            cell.hyperlink = Some("https://osc.test/target".to_owned());
        }
        let hit = link_at_cell(&cells, 5).unwrap();
        assert_eq!(hit.source, LinkSource::Osc8);
        assert_eq!(hit.url, "https://osc.test/target");

        for cell in &mut cells {
            cell.hyperlink = Some("javascript:alert(1)".to_owned());
        }
        let safe_plain = link_at_cell(&cells, 5).unwrap();
        assert_eq!(safe_plain.source, LinkSource::PlainText);
        assert_eq!(safe_plain.url, "https://visible.test");
    }

    #[test]
    fn wide_spacer_is_in_the_osc_hit_rectangle_but_hidden_cells_break_links() {
        let mut wide = cell("界");
        wide.width = 2;
        wide.hyperlink = Some("https://wide.test".to_owned());
        let mut spacer = cell("");
        spacer.width = 0;
        spacer.hyperlink = wide.hyperlink.clone();
        let cells = vec![wide, spacer, cell(" ")];
        let hit = link_at_cell(&cells, 1).unwrap();
        assert_eq!((hit.start_col, hit.end_col), (0, 2));

        let mut hidden = row("https://hidden.test");
        for cell in &mut hidden {
            cell.hidden = true;
            cell.hyperlink = Some("https://hidden.test".to_owned());
        }
        assert!(link_at_cell(&hidden, 3).is_none());
    }

    #[test]
    fn orphan_spacer_hyperlink_cannot_originate_an_invisible_target() {
        let mut wide = cell("界");
        wide.width = 2;
        let mut spacer = cell("");
        spacer.width = 0;
        spacer.hyperlink = Some("https://orphan-spacer.test".to_owned());

        assert!(link_at_cell(&[wide, spacer], 1).is_none());
    }

    #[test]
    fn selection_overlap_does_not_change_link_projection() {
        let cells = row("https://example.test");
        let before = cells.clone();
        let hit = link_at_cell(&cells, 4).unwrap();
        assert_eq!((hit.start_col, hit.end_col), (0, cells.len()));
        assert_eq!(cells, before, "hit testing is read-only");
    }

    #[test]
    fn malformed_controls_and_non_http_schemes_are_no_target() {
        for value in [
            "file:///tmp/x",
            "javascript:alert(1)",
            "data:text/plain,x",
            "https://bad.test/%zz",
        ] {
            let cells = row(value);
            assert!(link_at_cell(&cells, 1).is_none(), "{value}");
        }
    }
}
