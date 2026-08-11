//! App-support path resolution over an INJECTABLE base directory.
//!
//! Production resolves the base to the platform app-support dir (macOS:
//! `~/Library/Application Support/Maestro`; Linux: `$XDG_DATA_HOME/maestro` or
//! `~/.local/share/maestro`); tests inject a temp dir so they never touch the real
//! app-support path. Everything downstream (the store,
//! policy resolution) takes an `AppPaths` so no code reaches for the real home directory on
//! its own.
//!
//! This module computes and (for storage subdirs) creates directories. It does NOT create any
//! repo metadata, run git, or touch a worktree — `worktree_base`/`scratch_base` here only
//! compute app-support locations for the execution layer.

use std::io;
use std::path::{Path, PathBuf};

use crate::ids::{validate_id, IdError};

/// The kinds of record the store persists, each in its own subdirectory. Centralized so the
/// schema string and the on-disk directory never drift apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    Project,
    Workspace,
    Session,
    AgentTask,
    WindowLayout,
    /// A named, reopenable window arrangement (tab/pane topology), captured by the user so a
    /// working layout can be rebuilt without hand-placing tabs and splits.
    LayoutPreset,
    /// Durable, app-owned marker recording that Maestro prepared a given git worktree.
    /// Read-only provenance: written best-effort at `prepare_worktree`, surfaced informationally
    /// in `worktree-list`. It NEVER drives cleanup eligibility.
    WorktreeProvenance,
    /// The singleton daemon-endpoint record (which Unix socket a running daemon is on).
    /// Unlike the other kinds this is a singleton: it lives at `<base>/daemon/endpoint.json`
    /// (one fixed id), not a per-instance file in a plural directory.
    DaemonEndpoint,
}

impl RecordKind {
    /// The subdirectory under the Maestro base where this kind's records live.
    pub fn dir_name(self) -> &'static str {
        match self {
            RecordKind::Project => "projects",
            RecordKind::Workspace => "workspaces",
            RecordKind::Session => "sessions",
            RecordKind::AgentTask => "agent_tasks",
            RecordKind::WindowLayout => "windows",
            RecordKind::LayoutPreset => "layout_presets",
            RecordKind::WorktreeProvenance => "worktree_provenance",
            // Reuses the existing `daemon` subdir; the singleton lives at `daemon/endpoint.json`.
            RecordKind::DaemonEndpoint => "daemon",
        }
    }

    /// The logical envelope `schema` string for this kind.
    pub fn schema(self) -> &'static str {
        match self {
            RecordKind::Project => "maestro.project",
            RecordKind::Workspace => "maestro.workspace",
            RecordKind::Session => "maestro.session",
            RecordKind::AgentTask => "maestro.agent_task",
            RecordKind::WindowLayout => "maestro.window_layout",
            RecordKind::LayoutPreset => "maestro.layout_preset",
            RecordKind::WorktreeProvenance => "maestro.worktree_provenance",
            RecordKind::DaemonEndpoint => "maestro.daemon_endpoint",
        }
    }
}

/// Resolves all Maestro storage locations beneath one base directory.
#[derive(Clone, Debug)]
pub struct AppPaths {
    base: PathBuf,
}

impl AppPaths {
    /// Build over an explicit base — the form tests use with a temp dir, and the form all
    /// internal code takes so nothing hard-codes the real home path.
    pub fn with_base(base: impl Into<PathBuf>) -> Self {
        AppPaths { base: base.into() }
    }

    /// Production default: the platform app-support convention — macOS
    /// `~/Library/Application Support/Maestro`, elsewhere `$XDG_DATA_HOME/maestro` (falling back
    /// to `~/.local/share/maestro`). Errors if `$HOME` is unset rather than guessing a path.
    ///
    /// Override with `MAESTRO_APP_SUPPORT_DIR` (an absolute base path) when another installed
    /// component must share the exact data directory with the desktop app.
    pub fn production() -> io::Result<Self> {
        if let Some(dir) = std::env::var_os("MAESTRO_APP_SUPPORT_DIR") {
            let base = PathBuf::from(dir);
            if !base.as_os_str().is_empty() {
                return Ok(AppPaths::with_base(base));
            }
        }
        Ok(AppPaths::with_base(Self::platform_default_base()?))
    }

    #[cfg(target_os = "macos")]
    fn platform_default_base() -> io::Result<PathBuf> {
        let home = Self::home_dir()?;
        Ok(home
            .join("Library")
            .join("Application Support")
            .join("Maestro"))
    }

    /// Non-macOS (Linux) default: `$XDG_DATA_HOME/maestro`, or `~/.local/share/maestro` when
    /// `XDG_DATA_HOME` is unset/empty — the XDG base-directory convention.
    #[cfg(not(target_os = "macos"))]
    fn platform_default_base() -> io::Result<PathBuf> {
        if let Some(dir) = std::env::var_os("XDG_DATA_HOME") {
            if !dir.is_empty() {
                let base = PathBuf::from(dir);
                if base.is_absolute() {
                    return Ok(base.join("maestro"));
                }
            }
        }
        let home = Self::home_dir()?;
        Ok(home.join(".local").join("share").join("maestro"))
    }

    fn home_dir() -> io::Result<PathBuf> {
        let home = std::env::var_os("HOME").ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "HOME is not set; cannot resolve app-support",
            )
        })?;
        Ok(PathBuf::from(home))
    }

    /// The Maestro base directory.
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// Directory holding records of `kind`.
    pub fn record_dir(&self, kind: RecordKind) -> PathBuf {
        self.base.join(kind.dir_name())
    }

    /// Full path of one record file (`<base>/<kind-dir>/<id>.json`).
    ///
    /// VALIDATES `id` first: an id with a path separator, `.`/`..`, whitespace, or other
    /// punctuation is rejected (`IdError`) rather than producing a path that escapes the record
    /// directory. Only `[A-Za-z0-9_-]` ids — a superset of UUIDv4 — are accepted.
    pub fn record_path(&self, kind: RecordKind, id: &str) -> Result<PathBuf, IdError> {
        let id = validate_id(id)?;
        Ok(self.record_dir(kind).join(format!("{id}.json")))
    }

    /// Quarantine directory for corrupt records.
    pub fn corrupt_dir(&self) -> PathBuf {
        self.base.join("corrupt")
    }

    /// App-support scratch base. The `ScratchCwd` policy resolves a session's cwd UNDER this,
    /// outside any repo. (Pure path computation — no directory is created here.)
    pub fn scratch_base(&self) -> PathBuf {
        self.base.join("scratch")
    }

    /// App-support worktrees base. The `Worktree` policy resolves a session's checkout path
    /// UNDER this. (Pure path computation — no git, no directory creation.)
    pub fn worktree_base(&self) -> PathBuf {
        self.base.join("worktrees")
    }

    /// The daemon endpoint cache directory (socket path + pid cache). This accessor only computes
    /// the path; it does not open the socket.
    pub fn daemon_dir(&self) -> PathBuf {
        self.base.join("daemon")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> AppPaths {
        AppPaths::with_base("/base/Maestro")
    }

    #[test]
    fn record_path_for_valid_id_stays_under_record_dir() {
        let p = paths()
            .record_path(RecordKind::Project, "550e8400-e29b-41d4-a716-446655440000")
            .unwrap();
        assert!(p.starts_with("/base/Maestro/projects"));
        assert_eq!(
            p,
            PathBuf::from("/base/Maestro/projects/550e8400-e29b-41d4-a716-446655440000.json")
        );
    }

    #[test]
    fn record_path_rejects_traversing_id_and_never_escapes() {
        for bad in ["../escape", "a/b", "..", "/abs", "a/../b", "x y", "x.y"] {
            let r = paths().record_path(RecordKind::Project, bad);
            assert!(
                r.is_err(),
                "record_path for id {bad:?} must error, got {r:?}"
            );
        }
    }
}
