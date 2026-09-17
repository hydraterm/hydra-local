//! Bounded terminal link detection and hit testing.
//!
//! This module is pure: it never opens a URL.  It projects one authoritative wire
//! snapshot into cell spans, prefers OSC 8 metadata, and joins plain-text HTTP(S)
//! links only across proven soft wraps. Native opening remains behind `HostServices`.

use crate::wire::{Cell, GridSnapshot};

/// Maximum link spans considered for one visible frame.  The live caller asks about
/// only the logical line under the pointer.
pub const MAX_LINK_SPANS_PER_FRAME: usize = 128;

/// Maximum reconstructed logical-line bytes considered by the plain-text detector.
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

/// Resolve a visible cell using the same snapshot and clip as terminal painting.
pub(crate) fn link_at_grid_cell(
    grid: &GridSnapshot,
    target_row: usize,
    target_col: usize,
    visible_cols: usize,
    visible_rows: usize,
) -> Option<TerminalLinkSpan> {
    let visible_rows = visible_rows.min(grid.rows).min(grid.rows_cells.len());
    let visible_cols = visible_cols.min(grid.cols);
    if target_row >= visible_rows || target_col >= visible_cols {
        return None;
    }
    let row = grid.rows_cells.get(target_row)?;
    if row.get(target_col)?.hidden {
        return None;
    }
    let (osc8, considered) = osc_link_at(&row[..visible_cols.min(row.len())], target_col);
    if osc8.is_some() {
        return osc8;
    }
    let Some(metadata) = grid.row_copy.as_deref().filter(|metadata| {
        crate::wire::row_copy_cells_valid(&grid.rows_cells, Some(metadata))
            && grid.rows_cells.iter().all(|row| row.len() == grid.cols)
    }) else {
        return link_at_cell(&row[..visible_cols.min(row.len())], target_col);
    };

    // Never join across cells clipped by a pane divider during a pending resize.
    let full_width = visible_cols == grid.cols;
    let mut first = target_row;
    let mut last = target_row;
    if full_width {
        while first > 0
            && metadata[first].starts_line == Some(false)
            && metadata[first - 1].soft_wrap
        {
            first -= 1;
        }
        while last + 1 < visible_rows
            && metadata[last].soft_wrap
            && metadata[last + 1].starts_line == Some(false)
        {
            last += 1;
        }
    }
    let source = (first..=last).flat_map(|row_index| {
        grid.rows_cells[row_index][..visible_cols]
            .iter()
            .enumerate()
            .filter(move |(col, _)| {
                !metadata[row_index]
                    .excluded_columns
                    .iter()
                    .any(|excluded| usize::from(*excluded) == *col)
            })
            .map(move |(col, cell)| (row_index, col, cell))
    });
    let (text, cells, truncated) = reconstructed_cells(source, visible_cols);
    plain_link_at(
        &text,
        &cells,
        (target_row, target_col),
        metadata[first].starts_line != Some(true),
        truncated || !full_width || metadata[last].soft_wrap,
        MAX_LINK_SPANS_PER_FRAME - considered,
    )
}

/// Resolve `target_col` against one rendered logical row.  OSC 8 spans are checked
/// first, then bounded plain text.  Hidden cells never form a target; a wide lead's
/// hit rectangle includes its spacer column.
pub fn link_at_cell(row: &[Cell], target_col: usize) -> Option<TerminalLinkSpan> {
    if target_col >= row.len() || row[target_col].hidden {
        return None;
    }
    let (osc8, considered) = osc_link_at(row, target_col);
    if osc8.is_some() {
        return osc8;
    }
    let (text, cells, truncated) = reconstructed_cells(
        row.iter().enumerate().map(|(col, cell)| (0, col, cell)),
        row.len(),
    );
    plain_link_at(
        &text,
        &cells,
        (0, target_col),
        false,
        truncated,
        MAX_LINK_SPANS_PER_FRAME - considered,
    )
}

fn osc_link_at(row: &[Cell], target_col: usize) -> (Option<TerminalLinkSpan>, usize) {
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
            return (
                Some(TerminalLinkSpan {
                    url: url.to_owned(),
                    start_col: start,
                    end_col: end,
                    source: LinkSource::Osc8,
                }),
                considered,
            );
        }
    }

    (None, considered)
}

fn plain_link_at(
    text: &str,
    cells: &[ReconstructedCell],
    target: (usize, usize),
    unknown_start: bool,
    unknown_end: bool,
    limit: usize,
) -> Option<TerminalLinkSpan> {
    for (start, end) in plain_url_ranges(text, limit) {
        // A visible prefix at the viewport/scan edge is not a complete URL. A real
        // delimiter proves its end, even when trailing punctuation was trimmed.
        if (unknown_start && start == 0)
            || (unknown_end && !text[end..].chars().any(is_url_delimiter))
        {
            continue;
        }
        let mut segment = cells
            .iter()
            .filter(|cell| cell.row == target.0 && cell.byte_start < end && cell.byte_end > start);
        let Some(first) = segment.next() else {
            continue;
        };
        let last = segment.clone().next_back().unwrap_or(first);
        let contains_target = std::iter::once(first)
            .chain(segment)
            .any(|cell| (cell.start_col..cell.end_col).contains(&target.1));
        if contains_target {
            return Some(TerminalLinkSpan {
                url: text[start..end].to_owned(),
                start_col: first.start_col,
                end_col: last.end_col,
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
    row: usize,
    byte_start: usize,
    byte_end: usize,
    start_col: usize,
    end_col: usize,
}

fn reconstructed_cells<'a>(
    source: impl IntoIterator<Item = (usize, usize, &'a Cell)>,
    cols: usize,
) -> (String, Vec<ReconstructedCell>, bool) {
    let mut text = String::new();
    let mut cells = Vec::new();
    for (row, col, cell) in source {
        if cell.width == 0 {
            continue;
        }
        let fragment = if cell.hidden || cell.text.is_empty() {
            " "
        } else {
            cell.text.as_str()
        };
        if text.len().saturating_add(fragment.len()) > MAX_PLAIN_LINK_SCAN_BYTES {
            return (text, cells, true);
        }
        let byte_start = text.len();
        text.push_str(fragment);
        cells.push(ReconstructedCell {
            row,
            byte_start,
            byte_end: text.len(),
            start_col: col,
            end_col: (col + usize::from(cell.width.max(1))).min(cols),
        });
    }
    (text, cells, false)
}

fn is_url_delimiter(ch: char) -> bool {
    ch.is_whitespace() || ch.is_control() || matches!(ch, '<' | '>' | '"' | '\'' | '`' | '|')
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
            if offset > 0 && is_url_delimiter(ch) {
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

    fn grid(lines: &[&str], wraps: &[bool]) -> GridSnapshot {
        let cols = lines.iter().map(|line| line.chars().count()).max().unwrap();
        let rows_cells: Vec<_> = lines
            .iter()
            .map(|line| {
                let mut cells = row(line);
                cells.resize_with(cols, || cell(" "));
                cells
            })
            .collect();
        serde_json::from_value(serde_json::json!({
            "version": 2, "generation": "11111111-1111-1111-1111-111111111111",
            "revision": 1, "cols": cols, "rows": lines.len(), "rows_cells": rows_cells,
            "row_copy": wraps.iter().enumerate().map(|(index, soft_wrap)| {
                serde_json::json!({ "starts_line": index == 0 || !wraps[index - 1],
                    "soft_wrap": soft_wrap, "excluded_columns": [] })
            }).collect::<Vec<_>>(),
            "cursor_line": 0, "cursor_col": 0, "cursor_visible": true,
            "cursor_shape": "block", "alt_screen": false, "app_cursor": false,
            "bracketed_paste": false, "focus_reporting": false
        }))
        .unwrap()
    }

    #[test]
    fn wrapped_plain_urls_open_full_target_from_each_visible_row() {
        let grid = grid(&["see https://exam", "ple.test/a?q=1 "], &[true, false]);
        for (row, col) in [(0, 5), (1, 2)] {
            let hit = link_at_grid_cell(&grid, row, col, grid.cols, grid.rows).unwrap();
            assert_eq!(hit.url, "https://example.test/a?q=1");
            assert!(hit.start_col <= col && col < hit.end_col);
            assert!(hit.end_col <= grid.cols);
        }
    }

    #[test]
    fn wrapped_plain_urls_cross_more_than_two_rows() {
        let grid = grid(
            &["https://ex", "ample.test", "/a?q=1    "],
            &[true, true, false],
        );
        for row in 0..grid.rows {
            let hit = link_at_grid_cell(&grid, row, 2, grid.cols, grid.rows).unwrap();
            assert_eq!(hit.url, "https://example.test/a?q=1");
        }
    }

    #[test]
    fn hard_newline_never_joins_a_plain_url() {
        let grid = grid(&["https://a.test", "/different   "], &[false, false]);
        assert_eq!(
            link_at_grid_cell(&grid, 0, 4, grid.cols, grid.rows)
                .unwrap()
                .url,
            "https://a.test"
        );
        assert!(link_at_grid_cell(&grid, 1, 3, grid.cols, grid.rows).is_none());
    }

    #[test]
    fn scheme_can_start_on_one_row_and_finish_on_the_next() {
        let grid = grid(&["see ht", "tps://", "a.test"], &[true, true, false]);
        for (row, col) in [(0, 4), (1, 1), (2, 2)] {
            assert_eq!(
                link_at_grid_cell(&grid, row, col, 6, 3).unwrap().url,
                "https://a.test"
            );
        }
    }

    #[test]
    fn wide_glyph_and_excluded_wrap_padding_keep_exact_cell_targets() {
        let mut grid = grid(&["https://a.test/ ", "xx/path        "], &[true, false]);
        let pad = grid.cols - 1;
        grid.row_copy.as_mut().unwrap()[0].excluded_columns = vec![pad as u16];
        grid.rows_cells[1][0] = cell("界");
        grid.rows_cells[1][0].width = 2;
        grid.rows_cells[1][1] = cell("");
        grid.rows_cells[1][1].width = 0;
        for (row, col) in [(0, 8), (1, 0), (1, 1), (1, 4)] {
            let hit = link_at_grid_cell(&grid, row, col, grid.cols, 2).unwrap();
            assert_eq!(hit.url, "https://a.test/界/path");
        }
        assert!(link_at_grid_cell(&grid, 0, pad, grid.cols, 2).is_none());
    }

    #[test]
    fn viewport_edges_and_resize_clips_do_not_open_partial_urls() {
        let mut grid = grid(&["https://exam", "ple.test/a "], &[true, false]);
        assert!(link_at_grid_cell(&grid, 0, 4, grid.cols, 1).is_none());
        assert!(link_at_grid_cell(&grid, 0, 4, 10, 2).is_none());
        assert!(link_at_grid_cell(&grid, 1, 2, grid.cols, 1).is_none());
        grid.row_copy.as_mut().unwrap()[0].starts_line = Some(false);
        assert!(link_at_grid_cell(&grid, 0, 4, grid.cols, 2).is_none());

        let grid = self::grid(
            &["https://a.test text", "continues         "],
            &[true, false],
        );
        assert_eq!(
            link_at_grid_cell(&grid, 0, 4, grid.cols, 1).unwrap().url,
            "https://a.test"
        );
    }

    #[test]
    fn missing_or_invalid_wrap_metadata_never_concatenates_rows() {
        let original = grid(&["https://exam", "ple.test/a "], &[true, false]);
        for case in 0..3 {
            let mut grid = original.clone();
            match case {
                0 => grid.row_copy = None,
                1 => grid.row_copy.as_mut().unwrap()[0].excluded_columns = vec![0],
                _ => grid.row_copy.as_mut().unwrap()[1].starts_line = Some(true),
            }
            assert_eq!(
                link_at_grid_cell(&grid, 0, 4, grid.cols, 2).unwrap().url,
                "https://exam"
            );
            assert!(link_at_grid_cell(&grid, 1, 2, grid.cols, 2).is_none());
        }
    }

    #[test]
    fn osc8_metadata_stays_authoritative_across_wraps_and_clips() {
        let mut grid = grid(&["https://exam", "ple.test/a "], &[true, false]);
        for row in &mut grid.rows_cells {
            for cell in row {
                cell.hyperlink = Some("https://actual.test/complete".into());
            }
        }
        for (row, col, cols, rows) in [(0, 4, 10, 1), (1, 2, 11, 2)] {
            let hit = link_at_grid_cell(&grid, row, col, cols, rows).unwrap();
            assert_eq!(hit.url, "https://actual.test/complete");
            assert_eq!(hit.source, LinkSource::Osc8);
        }
        grid.rows_cells[1][2].hidden = true;
        assert!(link_at_grid_cell(&grid, 1, 2, 11, 2).is_none());
    }

    #[test]
    fn scan_budget_does_not_turn_a_long_line_into_a_partial_link() {
        let text = format!(
            "{}https://example.test/path",
            " ".repeat(MAX_PLAIN_LINK_SCAN_BYTES - 12)
        );
        assert!(link_at_cell(&row(&text), MAX_PLAIN_LINK_SCAN_BYTES - 4).is_none());
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
