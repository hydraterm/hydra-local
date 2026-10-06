//! User-entered commands have native syntax; generated/stored commands retain Hydra's argv grammar.
//! Windows follows Microsoft's C argv rules, including the special executable token:
//! https://learn.microsoft.com/en-us/cpp/c-language/parsing-c-command-line-arguments
//! Unlike CRT startup, an unfinished quote is a form error, never a partially accepted command.

#[cfg(test)]
use crate::launch_preflight::split_command_line;
use crate::launch_preflight::LaunchPreflightError;

/// Custom-only requests save defaults without an initial session. They check syntax but must not
/// require an installed executable, a usable daemon, or a launchable cwd. Generated requests keep
/// the established wire grammar and normal preflight. Actual creates repeat normalization.
pub(crate) fn preflight_custom_or_generated(
    raw: Option<&str>,
    generated: Option<&str>,
    agent: Option<&str>,
    validate: impl FnOnce(Option<&str>) -> Result<(), LaunchPreflightError>,
) -> Result<(), LaunchPreflightError> {
    let custom = normalize_custom_command(raw)?;
    if custom.is_some()
        && agent.is_none_or(|agent| agent.trim().is_empty())
        && generated.is_none_or(|command| command.trim().is_empty())
    {
        return Ok(());
    }
    validate(custom.as_deref().or(generated))
}

/// Convert only explicitly user-entered text. Stored defaults must never pass through this twice.
pub(crate) fn normalize_custom_command(
    raw: Option<&str>,
) -> Result<Option<String>, LaunchPreflightError> {
    let Some(raw) = raw.map(str::trim).filter(|raw| !raw.is_empty()) else {
        return Ok(None);
    };
    #[cfg(windows)]
    {
        Ok(Some(canonical_command(&parse_windows_command(raw)?)))
    }
    #[cfg(not(windows))]
    {
        Ok(Some(raw.to_owned()))
    }
}

#[cfg(any(windows, test))]
fn canonical_command(argv: &[String]) -> String {
    argv.iter()
        .map(|arg| format!("'{}'", arg.replace('\\', "\\\\").replace('\'', "'\\''")))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(any(windows, test))]
fn parse_windows_command(raw: &str) -> Result<Vec<String>, LaunchPreflightError> {
    if raw.contains('\0') {
        return Err(LaunchPreflightError::MalformedCommand);
    }
    let mut chars = raw.trim().chars().peekable();
    let mut argv = Vec::new();
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|ch| matches!(ch, ' ' | '\t')) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut arg = String::new();
        let mut quoted = false;
        while let Some(ch) = chars.peek().copied() {
            if !quoted && matches!(ch, ' ' | '\t') {
                break;
            }
            chars.next();
            // CRT treats argv[0] as a pathname: quotes delimit spaces, backslashes are literal.
            if argv.is_empty() {
                if ch == '"' {
                    quoted = !quoted;
                } else {
                    arg.push(ch);
                }
                continue;
            }
            if ch == '\\' {
                let mut count = 1;
                while chars.peek() == Some(&'\\') {
                    chars.next();
                    count += 1;
                }
                if chars.peek() != Some(&'"') {
                    arg.extend(std::iter::repeat_n('\\', count));
                    continue;
                }
                arg.extend(std::iter::repeat_n('\\', count / 2));
                if count % 2 != 0 {
                    chars.next();
                    arg.push('"');
                }
                // Even counts leave the quote for the next iteration's ordinary quote rule.
            } else if ch == '"' {
                if quoted && chars.peek() == Some(&'"') {
                    chars.next();
                    arg.push('"');
                } else {
                    quoted = !quoted;
                }
            } else {
                arg.push(ch);
            }
        }
        if quoted || (argv.is_empty() && arg.is_empty()) {
            return Err(LaunchPreflightError::MalformedCommand);
        }
        argv.push(arg);
    }
    if argv.is_empty() {
        return Err(LaunchPreflightError::MalformedCommand);
    }
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_paths_are_literal_and_operators_are_not_evaluated() {
        for executable in [
            r"C:\Tools 日本語\claude.cmd",
            r"\\server\tools share\claude.cmd",
        ] {
            let input = format!(r#""{executable}" --version "" "C:\data\""#);
            // A trailing argument backslash must be doubled before its closing quote.
            assert!(parse_windows_command(&input).is_err());
            let input = format!(r#""{executable}" --version "" "C:\data\\" %NAME% & ^ 'literal'"#);
            let argv = parse_windows_command(&input).unwrap();
            assert_eq!(
                argv,
                [
                    executable,
                    "--version",
                    "",
                    "C:\\data\\",
                    "%NAME%",
                    "&",
                    "^",
                    "'literal'"
                ]
            );
            assert_eq!(split_command_line(&canonical_command(&argv)).unwrap(), argv);
        }
    }

    #[test]
    fn microsoft_argument_examples_and_malformed_input() {
        for (raw, expected) in [
            (r#"tool "a b c" d e"#, vec!["tool", "a b c", "d", "e"]),
            (r#"tool "ab\"c" "\\" d"#, vec!["tool", "ab\"c", "\\", "d"]),
            (
                r#"tool a\\\b d"e f"g h"#,
                vec!["tool", r"a\\\b", "de fg", "h"],
            ),
            (r#"tool a\\\"b c d"#, vec!["tool", r#"a\"b"#, "c", "d"]),
            (r#"tool a\\\\"b c" d e"#, vec!["tool", r"a\\b c", "d", "e"]),
            (r#"tool "a""b" tail"#, vec!["tool", "a\"b", "tail"]),
        ] {
            assert_eq!(parse_windows_command(raw).unwrap(), expected);
        }
        for raw in [
            "",
            "   ",
            "\"\" arg",
            "\"unterminated",
            "tool \"unterminated",
            "tool\0arg",
        ] {
            assert!(parse_windows_command(raw).is_err(), "{raw:?}");
        }
    }

    #[test]
    fn stored_generated_and_custom_commands_keep_exact_argv() {
        let argv = vec![
            r"C:\Tools O'Brien 日本語\claude.cmd".into(),
            r"\\server\share\".into(),
            "".into(),
            "a'b \"quoted\"".into(),
            "%NAME% & literal".into(),
        ];
        let stored = canonical_command(&argv);
        assert_eq!(split_command_line(&stored).unwrap(), argv);
        // Historical generated wire still uses its original backslash grammar, not native parsing.
        assert_eq!(
            split_command_line(r"'C:\\Tools\\claude.cmd' --version").unwrap()[0],
            r"C:\Tools\claude.cmd"
        );
        assert!(split_command_line("claude 'unfinished").is_err());
    }

    #[test]
    fn generated_preflight_is_unchanged_and_custom_only_never_probes() {
        let generated = r"'C:\\Tools\\claude.cmd' '\\\\server\\share'";
        preflight_custom_or_generated(None, Some(generated), Some("claude"), |command| {
            assert_eq!(command, Some(generated));
            Ok(())
        })
        .unwrap();
        preflight_custom_or_generated(Some("not-installed --version"), None, None, |_| {
            panic!("saving defaults must not probe a missing executable or daemon")
        })
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_custom_text_is_not_reencoded() {
        let raw = r"claude 'a\\b' 'a'\''b'";
        assert_eq!(
            normalize_custom_command(Some(raw)).unwrap().as_deref(),
            Some(raw)
        );
        assert_eq!(
            normalize_custom_command(Some("claude 'unfinished"))
                .unwrap()
                .as_deref(),
            Some("claude 'unfinished")
        );
    }

    #[cfg(windows)]
    #[test]
    fn native_normalization_matches_preflight_and_preserves_empty_custom() {
        let raw = r#""C:\Tools 日本語\claude.cmd" "\\host\share""#;
        let canonical = normalize_custom_command(Some(raw)).unwrap().unwrap();
        assert_eq!(
            split_command_line(&canonical).unwrap(),
            parse_windows_command(raw).unwrap()
        );
        assert_eq!(normalize_custom_command(Some(" ")).unwrap(), None);
        assert!(
            preflight_custom_or_generated(Some("\"unfinished"), None, None, |_| {
                panic!("malformed custom must never probe or use another command")
            })
            .is_err()
        );
        preflight_custom_or_generated(
            Some(raw),
            Some("different-generated-command"),
            Some("claude"),
            |command| {
                assert_eq!(command, Some(canonical.as_str()));
                Ok(())
            },
        )
        .unwrap();
    }
}
