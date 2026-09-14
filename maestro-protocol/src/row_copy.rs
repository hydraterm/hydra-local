//! Optional copy semantics for one complete, generation/revision-bound row payload.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RowCopy {
    /// None means the predecessor/origin is unknown, not a proven line start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starts_line: Option<bool>,
    pub soft_wrap: bool,
    /// Only synthetic wide-glyph placeholder cells, never ordinary trailing spaces.
    pub excluded_columns: Vec<u16>,
}

/// Shape validation shared by both native wire mirrors. Cell validation follows against
/// the resulting snapshot, not a damage frame's pre-apply cells.
pub fn row_copy_valid(metadata: Option<&[RowCopy]>, cols: usize, rows: usize) -> bool {
    let Some(metadata) = metadata else {
        return true;
    };
    metadata.len() == rows
        && metadata.iter().enumerate().all(|(index, row)| {
            row.excluded_columns
                .iter()
                .all(|col| usize::from(*col) < cols)
                && row
                    .excluded_columns
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                && (index == 0
                    || row
                        .starts_line
                        .is_none_or(|starts| starts != metadata[index - 1].soft_wrap))
        })
}

/// Conservative JSON overhead: row object and separators plus every u16 index.
/// This spends existing frame headroom; it does not reduce user dimensions/history.
pub const fn row_copy_max_bytes(rows: usize, cells: usize) -> usize {
    32 + rows * 80 + cells * 6
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_copy_shape_origin_and_absence() {
        let mut rows = vec![
            RowCopy {
                starts_line: None,
                soft_wrap: true,
                excluded_columns: vec![2],
            },
            RowCopy {
                starts_line: Some(false),
                soft_wrap: false,
                excluded_columns: vec![],
            },
        ];
        assert!(row_copy_valid(None, 3, 2));
        assert!(row_copy_valid(Some(&rows), 3, 2));
        assert!(!row_copy_valid(Some(&rows), 3, 1));
        rows[1].starts_line = Some(true);
        assert!(!row_copy_valid(Some(&rows), 3, 2));
        rows[1].starts_line = None;
        for bad in [vec![3], vec![1, 1], vec![2, 1]] {
            rows[0].excluded_columns = bad;
            assert!(!row_copy_valid(Some(&rows), 3, 2));
        }
        for json in [
            "null",
            "12",
            "{}",
            r#"{"soft_wrap":true,"excluded_columns":null}"#,
            r#"{"soft_wrap":true,"excluded_columns":[-1]}"#,
            r#"{"soft_wrap":true,"excluded_columns":[1.5]}"#,
        ] {
            assert!(serde_json::from_str::<RowCopy>(json).is_err());
        }
        for origin in ["", r#""starts_line":null,"#] {
            let row: RowCopy = serde_json::from_str(&format!(
                "{{{origin}\"soft_wrap\":false,\"excluded_columns\":[]}}"
            ))
            .unwrap();
            assert_eq!(row.starts_line, None);
        }
    }

    #[test]
    fn row_copy_serialized_overhead_bound() {
        for (rows, cols) in [(2000, 15), (15, 2000), (175, 175), (256, 119)] {
            let metadata = vec![
                RowCopy {
                    starts_line: Some(true),
                    soft_wrap: false,
                    excluded_columns: (0..cols as u16).collect()
                };
                rows
            ];
            assert!(
                serde_json::to_vec(&metadata).unwrap().len()
                    < row_copy_max_bytes(rows, rows * cols)
            );
        }
    }
}
