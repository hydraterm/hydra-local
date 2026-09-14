use super::*;
use maestro_protocol::row_copy::{row_copy_valid, RowCopy};

fn metadata(grid: &TermGrid) -> Vec<RowCopy> {
    let snapshot = grid.snapshot();
    let rows = snapshot.row_copy.unwrap();
    assert!(row_copy_valid(Some(&rows), snapshot.cols, snapshot.rows));
    for (index, row) in rows.iter().enumerate() {
        for &col in &row.excluded_columns {
            assert_eq!(snapshot.rows_cells[index][usize::from(col)].text, " ");
            assert_eq!(snapshot.rows_cells[index][usize::from(col)].width, 1);
        }
    }
    rows
}

#[test]
fn actual_soft_wrap_differs_from_hard_break_with_identical_cells() {
    let mut soft = TermGrid::new(8, 4);
    let mut hard = TermGrid::new(8, 4);
    soft.advance(b"ABCDEFGH12345678xyz");
    hard.advance(b"ABCDEFGH\r\n12345678\r\nxyz");
    assert_eq!(soft.snapshot().rows_cells, hard.snapshot().rows_cells);
    assert_eq!(
        metadata(&soft)
            .iter()
            .map(|row| row.soft_wrap)
            .collect::<Vec<_>>(),
        [true, true, false, false]
    );
    assert!(metadata(&hard).iter().all(|row| !row.soft_wrap));
    assert_eq!(
        metadata(&soft)
            .iter()
            .map(|row| row.starts_line)
            .collect::<Vec<_>>(),
        [None, Some(false), Some(false), Some(true)]
    );
    assert_eq!(
        metadata(&hard)
            .iter()
            .map(|row| row.starts_line)
            .collect::<Vec<_>>(),
        [None, Some(true), Some(true), Some(true)]
    );
}

#[test]
fn exact_width_is_pending_wrap_until_the_next_printable() {
    let mut grid = TermGrid::new(8, 3);
    grid.advance(b"ABCDEFGH");
    assert!(!metadata(&grid)[0].soft_wrap);
    grid.advance(b"X");
    assert!(metadata(&grid)[0].soft_wrap);
    assert_eq!(metadata(&grid)[1].starts_line, Some(false));
}

#[test]
fn page_first_row_uses_predecessor_outside_page_and_lost_origin_is_unknown() {
    let mut grid = TermGrid::new(4, 2);
    grid.advance(b"abcdefghijklmnopq");
    assert!(grid.history_len() >= 3);
    assert_eq!(metadata(&grid)[0].starts_line, Some(false));
    let page = grid.scrollback(2, 1);
    assert_eq!(page.row_copy.unwrap()[0].starts_line, Some(false));
    assert_eq!(page.revision, grid.snapshot().revision);
    assert_eq!(
        grid.scrollback(u32::MAX, 1).row_copy.unwrap()[0].starts_line,
        None
    );
    grid.advance(b"\x1b[3J");
    assert_eq!(grid.history_len(), 0);
    assert_eq!(metadata(&grid)[0].starts_line, None);

    let mut hard = TermGrid::new(4, 2);
    hard.advance(b"abcd\r\nefgh\r\nijkl\r\nmnop");
    assert_eq!(
        hard.scrollback(1, 1).row_copy.unwrap()[0].starts_line,
        Some(true)
    );
    assert_eq!(metadata(&hard)[0].starts_line, Some(true));
    grid.advance(&vec![b'x'; 4 * (history_budget(4) + 10)]);
    assert!(grid.history_len() <= history_budget(4));
    assert_eq!(
        grid.scrollback(u32::MAX, 1).row_copy.unwrap()[0].starts_line,
        None
    );
    assert_eq!(metadata(&grid)[0].starts_line, Some(false));
}

#[test]
fn only_genuine_wide_leading_padding_is_excluded_and_overwrite_recomputes_it() {
    let mut grid = TermGrid::new(4, 3);
    grid.advance("abc界".as_bytes());
    let before = grid.snapshot();
    assert_eq!(metadata(&grid)[0].excluded_columns, [3]);
    assert!(metadata(&grid)[1].excluded_columns.is_empty());
    assert_eq!(before.rows_cells[1][0].width, 2);
    assert_eq!(before.rows_cells[1][1].width, 0);
    grid.advance(b"\x1b[2;1Hx");
    let after = grid.snapshot();
    assert!(metadata(&grid)[0].excluded_columns.is_empty());
    assert_eq!(before.rows_cells[0], after.rows_cells[0]);
    assert_eq!(before.row_stamps[0], after.row_stamps[0]);
    let DamageGen::Frame(frame) = generate_damage(&before, &after) else {
        panic!("overwrite frame")
    };
    assert_eq!(frame.row_copy, after.row_copy);
    let mut ordinary_space = TermGrid::new(4, 3);
    ordinary_space.advance(b"abc ");
    assert!(metadata(&ordinary_space)[0].excluded_columns.is_empty());
}

#[test]
fn metadata_only_terminal_mutation_emits_an_empty_ops_forward_revision() {
    let mut grid = TermGrid::new(4, 3);
    grid.advance(b"abcd\r\nx");
    let before = grid.snapshot();
    grid.advance(b"\x1b[1;4Hdx");
    let after = grid.snapshot();
    assert_eq!(before.rows_cells, after.rows_cells);
    assert!(!before.row_copy.as_ref().unwrap()[0].soft_wrap);
    assert!(after.row_copy.as_ref().unwrap()[0].soft_wrap);
    let DamageGen::Frame(frame) = generate_damage(&before, &after) else {
        panic!("metadata frame")
    };
    assert!(frame.ops.is_empty());
    assert_eq!(frame.base_revision, before.revision);
    assert_eq!(frame.revision, after.revision);
    assert_eq!(frame.row_copy, after.row_copy);
}

#[test]
fn resize_reflow_and_alternate_screen_do_not_inherit_old_metadata() {
    let mut grid = TermGrid::new(8, 6);
    grid.advance(b"ABCDEFGH12345678xyz");
    grid.resize(4, 6);
    // Reflow preserves cursor placement by moving two earlier rows into history;
    // the first live row therefore has a known wrapped predecessor outside the viewport.
    assert!(grid.history_len() > 0);
    assert_eq!(metadata(&grid)[0].starts_line, Some(false));
    let history_and_view = grid.scrollback(u32::MAX, 256).row_copy.unwrap();
    assert_eq!(
        history_and_view
            .iter()
            .take(5)
            .map(|row| row.soft_wrap)
            .collect::<Vec<_>>(),
        [true, true, true, true, false]
    );
    grid.resize(10, 6);
    assert_eq!(
        metadata(&grid)
            .iter()
            .map(|row| row.soft_wrap)
            .collect::<Vec<_>>(),
        [true, false, false, false, false, false]
    );
    let primary = metadata(&grid);
    grid.advance(b"\x1b[?1049hZ");
    assert!(grid.snapshot().alt_screen);
    assert_eq!(metadata(&grid)[0].starts_line, None);
    assert!(metadata(&grid)
        .iter()
        .all(|row| !row.soft_wrap && row.excluded_columns.is_empty()));
    grid.advance(b"\x1b[?1049l");
    assert!(!grid.snapshot().alt_screen);
    assert_eq!(metadata(&grid), primary);
}
