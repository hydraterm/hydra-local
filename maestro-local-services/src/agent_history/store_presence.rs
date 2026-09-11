//! Metadata-only presence of the stores used by the existing history adapters.
//!
//! Presence is not a session count, folder match, readability promise or resume authority. Never
//! enumerate a directory, open a database or read a transcript to answer this question.

use std::fs;
use std::io;
use std::path::Path;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryStorePresence {
    Present,
    Absent,
    Unavailable,
    Unsupported,
}

#[derive(Clone, Copy)]
enum StoreKind {
    Directory,
    File,
}

/// Inspect only the fixed provider store locations already used by `agent_history`. `home` uses
/// that adapter's HOME policy; a missing HOME is unknown, not proof of an absent store. Providers
/// without a qualified history adapter remain Unsupported even if their executable is launchable.
pub fn provider_history_store_presence(agent: &str, home: Option<&Path>) -> HistoryStorePresence {
    use StoreKind::{Directory, File};
    let candidates: &[(&str, StoreKind)] = match agent {
        "claude" => &[(".claude/projects", Directory)],
        "codex" => &[(".codex/sessions", Directory)],
        "gemini" => &[(".gemini/tmp", Directory)],
        "opencode" => &[(".local/share/opencode/opencode.db", File)],
        "copilot" => &[(".copilot/session-store.db", File)],
        "antigravity" => &[(".gemini/antigravity-cli", Directory)],
        "kimi" => &[
            (".kimi-code/session_index.jsonl", File),
            (".kimi-code/sessions", Directory),
        ],
        "kiro" => &[(".kiro/sessions/cli", Directory)],
        "cursor" => &[
            (".cursor/chats", Directory),
            (".cursor/projects", Directory),
        ],
        // Keep Devin's existing shared path helper rather than a second spelling of its store.
        "devin" => &[],
        _ => return HistoryStorePresence::Unsupported,
    };
    let Some(home) = home.filter(|path| path.is_absolute()) else {
        return HistoryStorePresence::Unavailable;
    };
    if agent == "devin" {
        return classify(fs::metadata(super::devin_store_path(home)), File);
    }
    let mut result = HistoryStorePresence::Absent;
    for (relative, kind) in candidates {
        let path = home.join(relative);
        // Claude's existing adapter requires a real, non-symlink projects root. Other adapters
        // already resolve their store roots through normal filesystem metadata.
        let metadata = if agent == "claude" {
            fs::symlink_metadata(path)
        } else {
            fs::metadata(path)
        };
        match classify(metadata, *kind) {
            HistoryStorePresence::Present => return HistoryStorePresence::Present,
            HistoryStorePresence::Unavailable => result = HistoryStorePresence::Unavailable,
            HistoryStorePresence::Absent | HistoryStorePresence::Unsupported => {}
        }
    }
    result
}

fn classify(metadata: io::Result<fs::Metadata>, kind: StoreKind) -> HistoryStorePresence {
    match metadata {
        Ok(metadata)
            if match kind {
                StoreKind::Directory => metadata.is_dir(),
                StoreKind::File => metadata.is_file(),
            } =>
        {
            HistoryStorePresence::Present
        }
        Ok(_) => HistoryStorePresence::Unavailable,
        Err(error) if error.kind() == io::ErrorKind::NotFound => HistoryStorePresence::Absent,
        Err(_) => HistoryStorePresence::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qualified_store_locations_are_present_without_reading_payloads() {
        let home = tempfile::tempdir().unwrap();
        let cases = [
            ("claude", ".claude/projects", StoreKind::Directory),
            ("codex", ".codex/sessions", StoreKind::Directory),
            ("gemini", ".gemini/tmp", StoreKind::Directory),
            (
                "opencode",
                ".local/share/opencode/opencode.db",
                StoreKind::File,
            ),
            ("copilot", ".copilot/session-store.db", StoreKind::File),
            (
                "antigravity",
                ".gemini/antigravity-cli",
                StoreKind::Directory,
            ),
            ("kimi", ".kimi-code/session_index.jsonl", StoreKind::File),
            ("kiro", ".kiro/sessions/cli", StoreKind::Directory),
            ("cursor", ".cursor/chats", StoreKind::Directory),
            (
                "devin",
                ".local/share/devin/cli/sessions.db",
                StoreKind::File,
            ),
        ];
        for (agent, relative, kind) in cases {
            assert!(super::super::supports_provider_history(agent));
            assert_eq!(
                provider_history_store_presence(agent, Some(home.path())),
                HistoryStorePresence::Absent
            );
            let path = home.path().join(relative);
            match kind {
                StoreKind::Directory => fs::create_dir_all(&path).unwrap(),
                StoreKind::File => {
                    fs::create_dir_all(path.parent().unwrap()).unwrap();
                    // Invalid database/JSON bytes deliberately still prove only store presence.
                    fs::write(&path, b"not a session payload\xff").unwrap();
                }
            }
            assert_eq!(
                provider_history_store_presence(agent, Some(home.path())),
                HistoryStorePresence::Present
            );
            if matches!(kind, StoreKind::File) {
                assert_eq!(fs::read(path).unwrap(), b"not a session payload\xff");
            }
        }
    }

    #[test]
    fn alternate_store_roots_and_unmatched_folder_metadata_do_not_require_sessions() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join(".cursor/projects/another-folder")).unwrap();
        fs::create_dir_all(home.path().join(".kimi-code/sessions")).unwrap();
        for agent in ["cursor", "kimi"] {
            assert_eq!(
                provider_history_store_presence(agent, Some(home.path())),
                HistoryStorePresence::Present
            );
        }
    }

    #[test]
    fn unsupported_missing_home_wrong_type_and_io_failure_are_not_absence() {
        let home = tempfile::tempdir().unwrap();
        assert_eq!(
            provider_history_store_presence("amp", Some(home.path())),
            HistoryStorePresence::Unsupported
        );
        assert_eq!(
            provider_history_store_presence("factory", None),
            HistoryStorePresence::Unsupported
        );
        assert_eq!(
            provider_history_store_presence("codex", None),
            HistoryStorePresence::Unavailable
        );
        assert_eq!(
            provider_history_store_presence("codex", Some(Path::new("relative-home"))),
            HistoryStorePresence::Unavailable
        );
        fs::create_dir_all(home.path().join(".codex")).unwrap();
        fs::write(home.path().join(".codex/sessions"), b"").unwrap();
        assert_eq!(
            provider_history_store_presence("codex", Some(home.path())),
            HistoryStorePresence::Unavailable
        );
        assert_eq!(
            classify(
                Err(io::Error::from(io::ErrorKind::PermissionDenied)),
                StoreKind::Directory
            ),
            HistoryStorePresence::Unavailable
        );
        assert_eq!(
            classify(
                Err(io::Error::from(io::ErrorKind::NotFound)),
                StoreKind::Directory
            ),
            HistoryStorePresence::Absent
        );
    }

    #[cfg(unix)]
    #[test]
    fn claude_symlink_root_is_unavailable_without_following_it() {
        let home = tempfile::tempdir().unwrap();
        fs::create_dir_all(home.path().join(".claude")).unwrap();
        std::os::unix::fs::symlink(
            home.path().join("missing-target"),
            home.path().join(".claude/projects"),
        )
        .unwrap();
        assert_eq!(
            provider_history_store_presence("claude", Some(home.path())),
            HistoryStorePresence::Unavailable
        );
    }
}
