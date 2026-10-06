//! Safe, platform-neutral file-drop text construction.
//!
//! Native hosts provide paths only. This module never opens, resolves, or executes them; it turns a
//! bounded set of absolute UTF-8 paths into a quoted insertion payload (POSIX on Unix,
//! PowerShell on Windows, matching the native default shell). The caller may
//! then pass that payload through the renderer's existing bracketed-paste encoder.

use std::path::{Path, PathBuf};

/// A single native drop may contribute at most this many paths.
pub(crate) const MAX_DROPPED_PATHS: usize = 32;
/// Maximum unwrapped text inserted for one drop. Paths are admitted whole, never byte-truncated.
pub(crate) const MAX_DROPPED_INSERT_BYTES: usize = 32 * 1024;
/// Bound URI text before a Linux adapter asks GLib to decode it into a local filename.
#[cfg(target_os = "linux")]
pub(crate) const MAX_DROPPED_URI_BYTES: usize = MAX_DROPPED_INSERT_BYTES * 3;

/// Append as many safe, complete quoted paths as fit the remaining count/byte budget.
///
/// Returns the number of paths admitted. Invalid or individually oversized paths are ignored. The
/// output never ends in a newline and never contains an unquoted byte originating from a path.
pub(crate) fn append_quoted_paths(
    payload: &mut String,
    path_count: &mut usize,
    paths: impl IntoIterator<Item = PathBuf>,
) -> usize {
    let mut added = 0;
    for path in paths {
        if *path_count >= MAX_DROPPED_PATHS {
            break;
        }
        let Some(raw) = admissible_path(&path) else {
            continue;
        };
        let quoted = quote_native_path(raw);
        let separator = usize::from(!payload.is_empty());
        let Some(next_len) = payload
            .len()
            .checked_add(separator)
            .and_then(|len| len.checked_add(quoted.len()))
        else {
            break;
        };
        if next_len > MAX_DROPPED_INSERT_BYTES {
            continue;
        }
        if separator != 0 {
            payload.push(' ');
        }
        payload.push_str(&quoted);
        *path_count += 1;
        added += 1;
    }
    added
}

fn admissible_path(path: &Path) -> Option<&str> {
    if !path.is_absolute() {
        return None;
    }
    let raw = path.to_str()?;
    // Reject every control character, including newline. POSIX quoting preserves a newline only
    // when inserted into neutral shell lexical context; an existing unmatched quote can make that
    // byte a command separator. There is no context-independent shell spelling that safely inserts
    // an exact newline-bearing filename, so file drop fails closed for that rare path.
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return None;
    }
    Some(raw)
}

/// Quote one complete path as one POSIX shell word.
///
/// POSIX single quotes make every byte literal except a single quote itself. That byte is represented
/// by ending the single-quoted run, emitting it inside double quotes, then reopening the run:
/// `'a'"'"'b'`. Shell operators, substitutions, backticks, whitespace, and embedded newlines therefore
/// remain data. The function deliberately always quotes, including paths that look simple.
#[cfg(not(windows))]
fn quote_native_path(path: &str) -> String {
    let mut quoted = String::with_capacity(path.len().saturating_add(2));
    quoted.push('\'');
    for ch in path.chars() {
        if ch == '\'' {
            quoted.push_str("'\"'\"'");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

#[cfg(windows)]
fn quote_native_path(path: &str) -> String {
    // PowerShell literal strings escape a quote by doubling it. Backticks, dollar signs,
    // operators and backslashes stay literal. Never append Enter or a call operator.
    format!("'{}'", path.replace('\'', "''"))
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    fn payload(paths: &[&str]) -> String {
        let mut out = String::new();
        let mut count = 0;
        append_quoted_paths(&mut out, &mut count, paths.iter().map(PathBuf::from));
        assert_eq!(count, paths.len());
        out
    }

    #[test]
    fn posix_quotes_spaces_quotes_and_leading_dash_filename() {
        let out = payload(&["/tmp/a b", "/tmp/a'b", "/tmp/a\"b", "/tmp/-leading"]);
        assert_eq!(
            out,
            "'/tmp/a b' '/tmp/a'\"'\"'b' '/tmp/a\"b' '/tmp/-leading'"
        );
        assert!(!out.ends_with('\n'));
    }

    #[test]
    fn shell_operators_and_substitutions_remain_inside_one_quoted_word() {
        let hostile = "/tmp/; && `touch nope` $(touch nope) $HOME >out";
        assert_eq!(payload(&[hostile]), format!("'{hostile}'"));
    }

    #[test]
    fn rejects_relative_non_utf8_and_control_paths_without_damaging_neighbors() {
        let mut paths = vec![
            PathBuf::from("relative"),
            PathBuf::from("/tmp/has\ttab"),
            PathBuf::from("/tmp/has\nnewline"),
            PathBuf::from("/tmp/has\rcarriage-return"),
            PathBuf::from("/tmp/has\u{1b}escape"),
            PathBuf::from("/tmp/good"),
        ];
        #[cfg(unix)]
        {
            use std::ffi::OsString;
            use std::os::unix::ffi::OsStringExt;
            paths.insert(1, PathBuf::from(OsString::from_vec(vec![b'/', 0xff])));
        }
        let mut out = String::new();
        let mut count = 0;
        assert_eq!(append_quoted_paths(&mut out, &mut count, paths), 1);
        assert_eq!(out, "'/tmp/good'");
        assert_eq!(count, 1);
    }

    #[test]
    fn count_and_byte_caps_keep_only_complete_quoted_paths() {
        let many = (0..MAX_DROPPED_PATHS + 4)
            .map(|index| PathBuf::from(format!("/tmp/{index}")))
            .collect::<Vec<_>>();
        let mut out = String::new();
        let mut count = 0;
        assert_eq!(
            append_quoted_paths(&mut out, &mut count, many),
            MAX_DROPPED_PATHS
        );
        assert_eq!(count, MAX_DROPPED_PATHS);

        let oversized = PathBuf::from(format!("/{}", "x".repeat(MAX_DROPPED_INSERT_BYTES)));
        let mut bounded = String::new();
        let mut bounded_count = 0;
        assert_eq!(
            append_quoted_paths(
                &mut bounded,
                &mut bounded_count,
                [oversized, PathBuf::from("/tmp/fits")],
            ),
            1
        );
        assert_eq!(bounded, "'/tmp/fits'");
        assert!(bounded.len() <= MAX_DROPPED_INSERT_BYTES);
        assert!(bounded.ends_with('\''));
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;

    #[test]
    fn powershell_drop_preserves_quotes_unicode_and_metacharacters() {
        let raw = r"C:\QA folder\a'b $HOME `literal`; & 日本語 🦀";
        let mut text = String::new();
        let mut count = 0;
        assert_eq!(
            append_quoted_paths(&mut text, &mut count, [PathBuf::from(raw)]),
            1
        );
        assert_eq!(text, format!("'{}'", raw.replace('\'', "''")));
        assert!(!text.ends_with('\n'));
        assert_eq!(count, 1);
    }

    #[test]
    fn native_powershell_receives_dropped_paths_as_exact_literal_arguments() {
        use std::os::windows::process::CommandExt;
        let inputs = [
            r"C:\QA folder\a'b $HOME `literal`; & 日本語 🦀",
            r"C:\QA\plain",
        ];
        let mut text = String::new();
        let mut count = 0;
        assert_eq!(
            append_quoted_paths(&mut text, &mut count, inputs.iter().map(PathBuf::from)),
            2
        );
        let shell = PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let script=format!("[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); function HydraDropProbe {{ $args | ConvertTo-Json -Compress }}; HydraDropProbe {text}");
        let output = std::process::Command::new(shell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &script,
            ])
            .creation_flags(0x08000000)
            .output()
            .unwrap();
        assert!(output.status.success());
        let received: Vec<String> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(received, inputs);
    }

    #[test]
    fn native_invalid_paths_do_not_damage_neighboring_paths() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;
        let paths = [
            PathBuf::from("relative"),
            PathBuf::from("C:relative"),
            PathBuf::from("C:\\bad\nname"),
            PathBuf::from("C:\\bad\tname"),
            PathBuf::from("C:\\bad\rname"),
            PathBuf::from("C:\\bad\u{1b}name"),
            PathBuf::from(OsString::from_wide(&[67, 58, 92, 0xd800])),
            PathBuf::from(r"C:\QA\good"),
        ];
        let mut text = String::new();
        let mut count = 0;
        assert_eq!(append_quoted_paths(&mut text, &mut count, paths), 1);
        assert_eq!(text, r"'C:\QA\good'");
        assert_eq!(count, 1);
    }

    #[test]
    fn native_count_and_byte_caps_preserve_whole_paths() {
        let mut text = String::new();
        let mut count = 0;
        assert_eq!(
            append_quoted_paths(
                &mut text,
                &mut count,
                (0..MAX_DROPPED_PATHS + 4).map(|n| PathBuf::from(format!(r"C:\QA\{n}")))
            ),
            MAX_DROPPED_PATHS
        );
        assert_eq!(count, MAX_DROPPED_PATHS);
        let mut text = String::new();
        let mut count = 0;
        assert_eq!(
            append_quoted_paths(
                &mut text,
                &mut count,
                [
                    PathBuf::from(format!(r"C:\{}", "x".repeat(MAX_DROPPED_INSERT_BYTES))),
                    PathBuf::from(r"C:\QA\fits")
                ]
            ),
            1
        );
        assert_eq!(text, r"'C:\QA\fits'");
        assert_eq!(count, 1);
    }
}
