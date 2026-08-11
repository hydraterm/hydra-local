//! Bounded, read-only local file preview reader.
//!
//! The sole purpose of this module is to turn a local file path into a SMALL, bounded slice of UTF-8
//! text lines that the renderer can project into a side preview pane. It is deliberately
//! conservative and pure so the side-pane feature stays safe and unit-testable without touching a
//! window or the GPU:
//!
//! - reads at most [`PREVIEW_MAX_BYTES`] from the start of the file (never the whole file), so a
//!   multi-gigabyte file costs one bounded read;
//! - rejects content that looks binary (a NUL byte in the read prefix) rather than spraying control
//!   bytes into the band;
//! - decodes the read prefix as UTF-8 lossily so an invalid tail can never panic;
//! - caps the number of returned lines at [`PREVIEW_MAX_LINES`] and the width of each line at
//!   [`PREVIEW_MAX_LINE_CHARS`] (by char, never mid-codepoint), flagging each kind of truncation so
//!   the projection can show a clear marker.
//!
//! Explicit non-goals (instruction constraints): no editing, saving, file watching, syntax
//! highlighting, website/webview/browser, remote fetch, or command execution. The reader only ever
//! opens and reads a bounded prefix of one already-named local path.

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// Maximum number of bytes read from the start of the file. One bounded read regardless of file
/// size, so a huge file never costs more than this.
pub const PREVIEW_MAX_BYTES: usize = 64 * 1024;

/// Maximum number of text lines returned. Lines beyond this are dropped and flagged.
pub const PREVIEW_MAX_LINES: usize = 500;

/// Maximum number of `char`s kept per line. Longer lines are truncated (by char) and flagged.
pub const PREVIEW_MAX_LINE_CHARS: usize = 1000;

/// Why a preview could not be produced. Kept coarse on purpose — the band shows a short reason, not
/// a stack trace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilePreviewError {
    /// The path could not be opened/read (missing, permission denied, is a directory, …).
    Unreadable(String),
    /// The read prefix contained a NUL byte, so the file is treated as binary and refused.
    Binary,
}

/// A bounded, read-only projection of a local file's leading text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePreview {
    /// The display path exactly as provided (the reader does not canonicalize or resolve symlinks).
    pub path: String,
    /// The bounded, per-line-truncated text lines (at most [`PREVIEW_MAX_LINES`]).
    pub lines: Vec<String>,
    /// True when the file was larger than [`PREVIEW_MAX_BYTES`] so only a prefix was read.
    pub truncated_bytes: bool,
    /// True when more than [`PREVIEW_MAX_LINES`] lines were present and the tail was dropped.
    pub truncated_lines: bool,
    /// True when at least one line was longer than [`PREVIEW_MAX_LINE_CHARS`] and was cut.
    pub truncated_line_width: bool,
}

/// Read a bounded preview of a local file using the module's default limits.
pub fn read_file_preview(path: impl AsRef<Path>) -> Result<FilePreview, FilePreviewError> {
    read_file_preview_with_limits(
        path,
        PREVIEW_MAX_BYTES,
        PREVIEW_MAX_LINES,
        PREVIEW_MAX_LINE_CHARS,
    )
}

/// Read a bounded preview with explicit limits (the limit-free entry point for tests). `max_bytes`
/// bounds the single read; `max_lines` bounds the returned line count; `max_line_chars` bounds each
/// line's char width. Pure aside from the one bounded file read.
pub fn read_file_preview_with_limits(
    path: impl AsRef<Path>,
    max_bytes: usize,
    max_lines: usize,
    max_line_chars: usize,
) -> Result<FilePreview, FilePreviewError> {
    let path_ref = path.as_ref();
    let display_path = path_ref.to_string_lossy().into_owned();

    let file = File::open(path_ref).map_err(|e| FilePreviewError::Unreadable(e.to_string()))?;

    // Read at most max_bytes + 1 so we can tell "exactly max_bytes" from "more than max_bytes".
    let mut buf = Vec::with_capacity(max_bytes.min(PREVIEW_MAX_BYTES) + 1);
    let read_cap = max_bytes.saturating_add(1) as u64;
    file.take(read_cap)
        .read_to_end(&mut buf)
        .map_err(|e| FilePreviewError::Unreadable(e.to_string()))?;

    let truncated_bytes = buf.len() > max_bytes;
    if truncated_bytes {
        buf.truncate(max_bytes);
    }

    if buf.contains(&0) {
        return Err(FilePreviewError::Binary);
    }

    let text = String::from_utf8_lossy(&buf);
    project_preview_text(
        display_path,
        &text,
        truncated_bytes,
        max_lines,
        max_line_chars,
    )
}

/// Shape already-decoded text into the bounded line model. Split out from the IO so the
/// line/width/count truncation logic is unit-testable without a real file.
fn project_preview_text(
    path: String,
    text: &str,
    truncated_bytes: bool,
    max_lines: usize,
    max_line_chars: usize,
) -> Result<FilePreview, FilePreviewError> {
    let mut lines = Vec::new();
    let mut truncated_lines = false;
    let mut truncated_line_width = false;

    for (idx, raw) in text.lines().enumerate() {
        if idx >= max_lines {
            truncated_lines = true;
            break;
        }
        // Strip a trailing CR so CRLF files do not leave a stray carriage return per line.
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if raw.chars().count() > max_line_chars {
            truncated_line_width = true;
            lines.push(raw.chars().take(max_line_chars).collect());
        } else {
            lines.push(raw.to_string());
        }
    }

    Ok(FilePreview {
        path,
        lines,
        truncated_bytes,
        truncated_lines,
        truncated_line_width,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "maestro-file-preview-{}-{}",
            std::process::id(),
            name
        ));
        p
    }

    fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let p = tmp_path(name);
        let mut f = File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        p
    }

    #[test]
    fn small_text_file_reads_all_lines_untruncated() {
        let p = write_tmp("small.txt", b"alpha\nbeta\ngamma\n");
        let preview = read_file_preview(&p).unwrap();
        assert_eq!(preview.lines, vec!["alpha", "beta", "gamma"]);
        assert!(!preview.truncated_bytes);
        assert!(!preview.truncated_lines);
        assert!(!preview.truncated_line_width);
        assert_eq!(preview.path, p.to_string_lossy());
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn crlf_line_endings_lose_the_carriage_return() {
        let p = write_tmp("crlf.txt", b"one\r\ntwo\r\n");
        let preview = read_file_preview(&p).unwrap();
        assert_eq!(preview.lines, vec!["one", "two"]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn binary_content_is_refused() {
        let p = write_tmp("bin", &[0x41, 0x00, 0x42]);
        let err = read_file_preview(&p).unwrap_err();
        assert_eq!(err, FilePreviewError::Binary);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn missing_file_is_unreadable() {
        let p = tmp_path("does-not-exist");
        std::fs::remove_file(&p).ok();
        match read_file_preview(&p) {
            Err(FilePreviewError::Unreadable(_)) => {}
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[test]
    fn oversize_file_truncates_bytes_and_flags() {
        // 10 lines but a 12-byte cap: only the prefix is read, byte truncation flagged.
        let p = write_tmp("oversize.txt", b"aaaa\nbbbb\ncccc\ndddd\n");
        let preview =
            read_file_preview_with_limits(&p, 12, PREVIEW_MAX_LINES, PREVIEW_MAX_LINE_CHARS)
                .unwrap();
        assert!(preview.truncated_bytes);
        // 12 bytes = "aaaa\nbbbb\ncc" -> lines aaaa, bbbb, cc
        assert_eq!(preview.lines, vec!["aaaa", "bbbb", "cc"]);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn too_many_lines_truncates_and_flags() {
        let body = "x\n".repeat(10);
        let p = write_tmp("manylines.txt", body.as_bytes());
        let preview =
            read_file_preview_with_limits(&p, PREVIEW_MAX_BYTES, 4, PREVIEW_MAX_LINE_CHARS)
                .unwrap();
        assert_eq!(preview.lines.len(), 4);
        assert!(preview.truncated_lines);
        assert!(!preview.truncated_bytes);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn long_line_truncates_width_and_flags() {
        let body = format!("{}\nshort\n", "w".repeat(50));
        let p = write_tmp("longline.txt", body.as_bytes());
        let preview =
            read_file_preview_with_limits(&p, PREVIEW_MAX_BYTES, PREVIEW_MAX_LINES, 10).unwrap();
        assert_eq!(preview.lines[0].chars().count(), 10);
        assert_eq!(preview.lines[1], "short");
        assert!(preview.truncated_line_width);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn invalid_utf8_is_lossy_not_fatal() {
        // 0xFF is invalid UTF-8 but not NUL: decoded lossily, not refused.
        let p = write_tmp("badutf8.txt", &[0x68, 0x69, 0xFF, 0x0A]);
        let preview = read_file_preview(&p).unwrap();
        assert_eq!(preview.lines.len(), 1);
        assert!(preview.lines[0].starts_with("hi"));
        std::fs::remove_file(&p).ok();
    }
}
