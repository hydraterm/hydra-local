use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use maestro_shell::paths::{AppPaths, RecordKind};
use maestro_shell::records::{LaunchSpec, SessionRecord, WindowLayout};
use maestro_shell::store::{load_all, LoadOutcome};

#[derive(Clone, Debug, Serialize)]
pub struct AgentHistorySession {
    pub id: String,
    pub agent: String,
    pub title: String,
    pub first_message: String,
    pub modified_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_count: Option<usize>,
    pub folder_index: usize,
    pub file_path: String,
    pub in_use: bool,
    pub custom_name: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct AgentPreviewLine {
    pub role: String,
    pub text: String,
}

/// Cooperative cancellation for provider-history discovery and preview work.
///
/// File-backed providers check this token before opening each file and between bounded read chunks.
/// Callers can therefore move discovery off their event loop and make dismissal preempt work without
/// relying on thread termination.
#[derive(Clone, Debug, Default)]
pub struct HistoryCancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl HistoryCancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn check(&self) -> Result<(), HistoryScanCancelled> {
        if self.is_cancelled() {
            Err(HistoryScanCancelled)
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryScanCancelled;

impl std::fmt::Display for HistoryScanCancelled {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("provider history scan cancelled")
    }
}

impl std::error::Error for HistoryScanCancelled {}

/// A single provider-store enumeration partitioned into normal and removed sessions.
#[derive(Clone, Debug, Default)]
pub struct FolderSessionListing {
    pub visible: Vec<AgentHistorySession>,
    pub hidden: Vec<AgentHistorySession>,
}

const HISTORY_METADATA_LINE_MAX_BYTES: usize = 128 * 1024;
const HISTORY_PREVIEW_MAX_BYTES: usize = 2 * 1024 * 1024;
const HISTORY_PREVIEW_LINE_MAX_BYTES: usize = 512 * 1024;
const HISTORY_READ_CHUNK_BYTES: usize = 8 * 1024;
const CLAUDE_CONFIG_MAX_BYTES: u64 = 2 * 1024 * 1024;
const CLAUDE_REPO_PATH_MAX_COUNT: usize = 256;
const CLAUDE_REPO_PATH_MAX_BYTES: usize = 4 * 1024;
/// Provider-owned stores are hostile input. A directory with millions of entries must not keep a
/// picker worker occupied indefinitely, even when every individual metadata read is bounded.
const PROVIDER_HISTORY_ENUMERATION_MAX_ENTRIES: usize = 16_384;
/// Keep the result handed to the dashboard bounded independently from each provider's schema.
const PROVIDER_HISTORY_RESULT_MAX_COUNT: usize = 1_000;
const PROVIDER_HISTORY_LOCK_MAX_ENTRIES: usize = 256;
const PROVIDER_PREVIEW_MAX_SOURCE_LINES: usize = 10_000;
pub const PROVIDER_SESSION_ID_MAX_CHARS: usize = 256;
pub const MAX_HISTORY_SESSION_ID_BYTES: usize = 512;
pub const MAX_HISTORY_CUSTOM_NAME_BYTES: usize = 512;
pub const MAX_HISTORY_OVERRIDES: usize = 4_096;
pub const MAX_HISTORY_PREVIEW_LINES: usize = 500;

#[derive(Clone, Copy, Debug)]
struct HistoryEnumerationBudget {
    remaining: usize,
}

impl HistoryEnumerationBudget {
    fn provider_store() -> Self {
        Self {
            remaining: PROVIDER_HISTORY_ENUMERATION_MAX_ENTRIES,
        }
    }

    fn consume(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }

    fn consume_strict(&mut self) -> Result<(), String> {
        if self.consume() {
            Ok(())
        } else {
            Err(format!(
                "provider history enumeration exceeds {PROVIDER_HISTORY_ENUMERATION_MAX_ENTRIES} entries"
            ))
        }
    }

    fn exhausted(self) -> bool {
        self.remaining == 0
    }
}

fn bound_provider_history_results(sessions: &mut Vec<AgentHistorySession>) {
    sessions.sort_by_key(|row| std::cmp::Reverse(row.modified_at_ms));
    sessions.truncate(PROVIDER_HISTORY_RESULT_MAX_COUNT);
}

fn validate_history_session_id(session_id: &str) -> Result<&str, String> {
    if session_id.is_empty()
        || session_id.len() > MAX_HISTORY_SESSION_ID_BYTES
        || session_id.trim() != session_id
        || session_id.chars().any(char::is_control)
    {
        return Err("agent history session id is invalid or oversized".to_string());
    }
    Ok(session_id)
}

/// Which side of the hidden ("Removed") set a listing wants.
#[derive(Clone, Copy, PartialEq, Eq)]
enum HiddenScope {
    /// Only sessions the user has NOT removed — the normal picker list.
    Visible,
    /// Only sessions the user HAS removed (and that still exist on disk) — the "Removed" view.
    Hidden,
}

/// Provider stores whose folder-scoped history format Hydra has explicitly qualified. Launch support is a
/// separate capability: Amp and Factory are runnable, but stay outside this boundary until real thread fixtures
/// prove their storage, folder scoping, preview, and deletion semantics.
pub fn supports_provider_history(agent: &str) -> bool {
    matches!(
        agent,
        "claude"
            | "codex"
            | "gemini"
            | "opencode"
            | "copilot"
            | "antigravity"
            | "kimi"
            | "kiro"
            | "cursor"
            | "devin"
    )
}

/// Validate one provider-owned resume identity at every history boundary.
///
/// Provider stores are untrusted input. IDs are never truncated or control-stripped because doing so can
/// alias two distinct provider sessions. Providers with a documented UUID shape keep that stronger contract;
/// the remaining providers receive the shared bounded opaque-ID contract.
pub fn normalize_provider_session_id(agent: &str, candidate: &str) -> Option<String> {
    if !supports_provider_history(agent) {
        return None;
    }
    match agent {
        "copilot" | "antigravity" | "kiro" | "cursor" => clean_uuid(candidate),
        "kimi" => clean_kimi_session_id(candidate),
        "claude" | "codex" | "gemini" | "opencode" | "devin" => clean_opaque_session_id(candidate),
        _ => None,
    }
}

fn provider_session_id_is_exact(agent: &str, candidate: &str) -> bool {
    normalize_provider_session_id(agent, candidate).as_deref() == Some(candidate)
}

fn require_exact_provider_session_id(agent: &str, candidate: &str) -> Result<(), String> {
    provider_session_id_is_exact(agent, candidate)
        .then_some(())
        .ok_or_else(|| "provider session id is invalid".to_string())
}

fn list_folder_sessions_scoped(
    paths: &AppPaths,
    agent: &str,
    cwd: &Path,
    scope: HiddenScope,
) -> Vec<AgentHistorySession> {
    let listing = list_folder_sessions_partitioned(paths, agent, cwd);
    match scope {
        HiddenScope::Visible => listing.visible,
        HiddenScope::Hidden => listing.hidden,
    }
}

/// Enumerate a provider store once, then partition the result into visible and removed sessions.
pub fn list_folder_sessions_partitioned(
    paths: &AppPaths,
    agent: &str,
    cwd: &Path,
) -> FolderSessionListing {
    list_folder_sessions_partitioned_with_cancel(
        paths,
        agent,
        cwd,
        &HistoryCancellationToken::new(),
    )
    .unwrap_or_default()
}

/// Cancellation-aware form of [`list_folder_sessions_partitioned`].
pub fn list_folder_sessions_partitioned_with_cancel(
    paths: &AppPaths,
    agent: &str,
    cwd: &Path,
    cancellation: &HistoryCancellationToken,
) -> Result<FolderSessionListing, HistoryScanCancelled> {
    cancellation.check()?;
    if !supports_provider_history(agent) {
        return Ok(FolderSessionListing::default());
    }
    let cwd_candidates = cwd_match_candidates(cwd);
    if cwd_candidates.is_empty() {
        return Ok(FolderSessionListing::default());
    }
    if !cwd_candidates.iter().any(|candidate| candidate.is_dir()) {
        return Ok(FolderSessionListing::default());
    }
    let provider_cwd_candidates = if agent == "claude" {
        claude_repo_path_candidates(&cwd_candidates, cancellation)?
    } else {
        cwd_candidates.clone()
    };
    list_folder_sessions_partitioned_from_candidates(
        paths,
        agent,
        &cwd_candidates,
        &provider_cwd_candidates,
        cancellation,
    )
}

/// Finish one listing from an immutable candidate snapshot. Destructive callers reuse the same
/// snapshot for resolution so a concurrently edited provider registry cannot expand authority
/// between the surfaced row and the filesystem mutation.
fn list_folder_sessions_partitioned_from_candidates(
    paths: &AppPaths,
    agent: &str,
    cwd_candidates: &[PathBuf],
    provider_cwd_candidates: &[PathBuf],
    cancellation: &HistoryCancellationToken,
) -> Result<FolderSessionListing, HistoryScanCancelled> {
    cancellation.check()?;
    let open_provider_sessions = open_provider_session_ids(paths, provider_cwd_candidates);
    cancellation.check()?;
    let names = read_session_names(paths);
    cancellation.check()?;
    let pane_names = pane_session_names(paths, provider_cwd_candidates);
    cancellation.check()?;
    let mut sessions = list_provider_sessions(
        agent,
        cwd_candidates,
        provider_cwd_candidates,
        &open_provider_sessions,
        cancellation,
    )?;
    cancellation.check()?;
    bound_provider_history_results(&mut sessions);
    // Partition by the hidden ("Removed") sidecar. Removing is non-destructive: the file stays on disk,
    // so a hidden session can be surfaced in the Removed view and added back.
    let hidden = read_hidden_sessions(paths);
    cancellation.check()?;
    for session in &mut sessions {
        cancellation.check()?;
        let key = session_name_key(agent, &session.id);
        session.custom_name = names
            .get(&key)
            .cloned()
            .or_else(|| pane_names.get(&key).cloned());
    }
    let (mut hidden_sessions, mut visible_sessions): (Vec<_>, Vec<_>) = sessions
        .into_iter()
        .partition(|session| hidden.contains(&session_name_key(agent, &session.id)));
    assign_folder_index(&mut visible_sessions);
    assign_folder_index(&mut hidden_sessions);
    Ok(FolderSessionListing {
        visible: visible_sessions,
        hidden: hidden_sessions,
    })
}

fn list_provider_sessions(
    agent: &str,
    cwd_candidates: &[PathBuf],
    provider_cwd_candidates: &[PathBuf],
    open_provider_sessions: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentHistorySession>, HistoryScanCancelled> {
    let sessions = match agent {
        "claude" => list_claude_sessions(
            provider_cwd_candidates,
            open_provider_sessions,
            cancellation,
        ),
        "codex" => list_codex_sessions(cwd_candidates, open_provider_sessions, cancellation),
        "gemini" => list_gemini_sessions(cwd_candidates, open_provider_sessions, cancellation),
        "opencode" => list_opencode_sessions(cwd_candidates, open_provider_sessions, cancellation),
        "copilot" => list_copilot_sessions(cwd_candidates, open_provider_sessions, cancellation),
        "antigravity" => {
            list_antigravity_sessions(cwd_candidates, open_provider_sessions, cancellation)
        }
        "kimi" => list_kimi_sessions(cwd_candidates, open_provider_sessions, cancellation),
        "kiro" => list_kiro_sessions(cwd_candidates, open_provider_sessions, cancellation),
        "cursor" => list_cursor_sessions(cwd_candidates, open_provider_sessions, cancellation),
        "devin" => list_devin_sessions(cwd_candidates, open_provider_sessions, cancellation),
        _ => Ok(Vec::new()),
    }?;
    Ok(sessions
        .into_iter()
        .filter(|session| {
            session.agent == agent && provider_session_id_is_exact(agent, &session.id)
        })
        .collect())
}

pub fn list_folder_sessions(paths: &AppPaths, agent: &str, cwd: &Path) -> Vec<AgentHistorySession> {
    list_folder_sessions_scoped(paths, agent, cwd, HiddenScope::Visible)
}

/// List the sessions the user has REMOVED (hidden) for this folder that still exist on disk, so the
/// dashboard can show a "Removed" view from which they can be added back.
pub fn list_hidden_folder_sessions(
    paths: &AppPaths,
    agent: &str,
    cwd: &Path,
) -> Vec<AgentHistorySession> {
    list_folder_sessions_scoped(paths, agent, cwd, HiddenScope::Hidden)
}

/// ADD BACK a previously removed session: drop its `agent:id` from the hidden sidecar so it returns to
/// the normal list. Idempotent.
pub fn unhide_folder_session(
    paths: &AppPaths,
    agent: &str,
    session_id: &str,
) -> Result<(), String> {
    if !supports_provider_history(agent) {
        return Err("agent history provider is not supported".to_string());
    }
    require_exact_provider_session_id(agent, session_id)?;
    let session_id = validate_history_session_id(session_id)?;
    let mut hidden = read_hidden_sessions(paths);
    if hidden.remove(&session_name_key(agent, session_id)) {
        write_hidden_sessions(paths, &hidden)
    } else {
        Ok(())
    }
}

/// REMOVE a folder session from the dashboard list non-destructively: record its `agent:id` in the
/// hidden sidecar so [`list_folder_sessions`] skips it in all future checks. The session FILE on disk is
/// not touched. Idempotent.
pub fn hide_folder_session(paths: &AppPaths, agent: &str, session_id: &str) -> Result<(), String> {
    if !supports_provider_history(agent) {
        return Err("agent history provider is not supported".to_string());
    }
    require_exact_provider_session_id(agent, session_id)?;
    let session_id = validate_history_session_id(session_id)?;
    let mut hidden = read_hidden_sessions(paths);
    let key = session_name_key(agent, session_id);
    if !hidden.contains(&key) && hidden.len() >= MAX_HISTORY_OVERRIDES {
        return Err(format!(
            "hidden agent history entry limit reached ({MAX_HISTORY_OVERRIDES})"
        ));
    }
    hidden.insert(key);
    write_hidden_sessions(paths, &hidden)
}

/// DELETE a folder session COMPLETELY: remove its on-disk provider files. Resolves identity from the
/// current folder listing (so we only ever delete a session we surfaced, never an arbitrary path),
/// deletes it, and clears any custom-name / hidden sidecar entry for it. Codex compaction fragments
/// sharing the surfaced root's `payload.session_id` are one session and are removed together, with the
/// root removed last so a partial filesystem failure leaves a resumable/listable root for retry.
/// Claude's provider-owned `<session-id>/` sidechain directory is removed before its root transcript.
pub fn delete_folder_session(
    paths: &AppPaths,
    agent: &str,
    cwd: &Path,
    session_id: &str,
) -> Result<(), String> {
    delete_folder_session_with_cancel(
        paths,
        agent,
        cwd,
        session_id,
        &HistoryCancellationToken::new(),
    )
}

/// Cancellation-aware form of [`delete_folder_session`].
///
/// The provider scan remains off the UI/listener thread. Cancellation is checked after resolving
/// the surfaced session and immediately before the destructive filesystem operation; once removal
/// begins, sidecar cleanup is completed rather than leaving a half-applied delete.
pub fn delete_folder_session_with_cancel(
    paths: &AppPaths,
    agent: &str,
    cwd: &Path,
    session_id: &str,
    cancellation: &HistoryCancellationToken,
) -> Result<(), String> {
    if !supports_provider_history(agent) {
        return Err("agent history provider is not supported".to_string());
    }
    require_exact_provider_session_id(agent, session_id)?;
    let session_id = validate_history_session_id(session_id)?;
    if agent != "codex" && agent != "claude" {
        return Err(format!(
            "{} session history is managed by the provider; a complete deletion boundary is not proven",
            agent.trim()
        ));
    }
    cancellation.check().map_err(|error| error.to_string())?;
    let cwd_candidates = cwd_match_candidates(cwd);
    if !cwd_candidates.iter().any(|candidate| candidate.is_dir()) {
        return Err("selected folder is unavailable".to_string());
    }
    let provider_cwd_candidates = if agent == "claude" {
        claude_repo_path_candidates(&cwd_candidates, cancellation)
            .map_err(|error| error.to_string())?
    } else {
        cwd_candidates.clone()
    };
    let listing = list_folder_sessions_partitioned_from_candidates(
        paths,
        agent,
        &cwd_candidates,
        &provider_cwd_candidates,
        cancellation,
    )
    .map_err(|error| error.to_string())?;
    let session = listing
        .visible
        .into_iter()
        .chain(listing.hidden)
        .find(|s| s.id == session_id)
        .ok_or_else(|| format!("session {session_id} not found in folder"))?;
    if session.in_use {
        return Err(format!(
            "session {session_id} is open in a Hydra pane; close it before permanent deletion"
        ));
    }
    let path = PathBuf::from(&session.file_path);
    if session.file_path.contains("://") {
        return Err(format!(
            "{} session history is managed by the provider; remove it from Hydra instead",
            agent.trim()
        ));
    }
    cancellation.check().map_err(|error| error.to_string())?;
    let mut files = match agent {
        "codex" => codex_files_for_session(session_id, cancellation)?,
        "claude" => {
            claude_files_for_session(&path, &provider_cwd_candidates, session_id, cancellation)?
        }
        _ => unreachable!("permanent-delete provider allowlist checked above"),
    };
    if !files.iter().any(|candidate| candidate == &path) {
        files.push(path.clone());
    }
    files.sort();
    files.dedup();
    files.sort_by_key(|candidate| candidate == &path);
    cancellation.check().map_err(|error| error.to_string())?;
    let claude_buckets = if agent == "claude" {
        let home = home_dir().ok_or_else(|| "Claude home directory is unavailable".to_string())?;
        let buckets = claude_project_history_buckets(&home, &provider_cwd_candidates);
        if files
            .iter()
            .any(|candidate| claude_root_in_allowed_buckets(candidate, &buckets).is_none())
        {
            return Err(
                "refuse Claude delete outside the immutable project-bucket snapshot".to_string(),
            );
        }
        buckets
    } else {
        Vec::new()
    };
    let claude_sidechains = if agent == "claude" {
        let mut sidechains = Vec::new();
        for candidate in &files {
            let canonical_root = claude_root_in_allowed_buckets(candidate, &claude_buckets)
                .ok_or_else(|| {
                    format!(
                        "refuse Claude root outside the immutable project-bucket snapshot {}",
                        candidate.display()
                    )
                })?;
            let bucket = claude_bucket_for_root(&canonical_root, &claude_buckets)
                .cloned()
                .ok_or_else(|| {
                    format!(
                        "refuse Claude root without an owning project bucket {}",
                        canonical_root.display()
                    )
                })?;
            let sidechain = canonical_root.with_extension("");
            match fs::symlink_metadata(&sidechain) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                    return Err(format!(
                        "refuse unexpected Claude sidechain path {}",
                        sidechain.display()
                    ));
                }
                Ok(_) => {
                    let canonical_sidechain = claude_sidechain_in_bucket(&sidechain, &bucket)
                        .ok_or_else(|| {
                            format!(
                                "refuse Claude sidechain outside its owning project bucket {}",
                                sidechain.display()
                            )
                        })?;
                    sidechains.push((canonical_sidechain, bucket));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "inspect Claude session sidechains {}: {error}",
                        sidechain.display()
                    ));
                }
            }
        }
        sidechains
    } else {
        Vec::new()
    };
    for (sidechain, bucket) in claude_sidechains {
        let revalidated = claude_sidechain_in_bucket(&sidechain, &bucket).ok_or_else(|| {
            format!(
                "refuse changed Claude sidechain before deletion {}",
                sidechain.display()
            )
        })?;
        fs::remove_dir_all(&revalidated).map_err(|error| {
            format!(
                "delete Claude session sidechains {}: {error}",
                revalidated.display()
            )
        })?;
    }
    for candidate in files {
        let target = if agent == "claude" {
            claude_root_in_allowed_buckets(&candidate, &claude_buckets).ok_or_else(|| {
                format!(
                    "refuse changed Claude root before deletion {}",
                    candidate.display()
                )
            })?
        } else {
            candidate
        };
        fs::remove_file(&target)
            .map_err(|e| format!("delete session file {}: {e}", target.display()))?;
    }
    // Clean up sidecar entries for the now-gone session (best-effort).
    let key = session_name_key(agent, session_id);
    let mut names = read_session_names(paths);
    if names.remove(&key).is_some() {
        let _ = write_session_names(paths, &names);
    }
    let mut hidden = read_hidden_sessions(paths);
    if hidden.remove(&key) {
        let _ = write_hidden_sessions(paths, &hidden);
    }
    Ok(())
}

pub fn set_folder_session_name(
    paths: &AppPaths,
    agent: &str,
    session_id: &str,
    name: Option<&str>,
) -> Result<(), String> {
    if !supports_provider_history(agent) {
        return Err("agent history provider is not supported".to_string());
    }
    require_exact_provider_session_id(agent, session_id)?;
    let session_id = validate_history_session_id(session_id)?;
    let mut names = read_session_names(paths);
    let key = session_name_key(agent, session_id);
    let trimmed = name.map(str::trim).unwrap_or_default();
    if trimmed.is_empty() {
        names.remove(&key);
    } else {
        if trimmed.len() > MAX_HISTORY_CUSTOM_NAME_BYTES || trimmed.chars().any(char::is_control) {
            return Err(format!(
                "agent history custom name exceeds {MAX_HISTORY_CUSTOM_NAME_BYTES} bytes or contains control characters"
            ));
        }
        if !names.contains_key(&key) && names.len() >= MAX_HISTORY_OVERRIDES {
            return Err(format!(
                "agent history custom-name limit reached ({MAX_HISTORY_OVERRIDES})"
            ));
        }
        names.insert(key, trimmed.to_string());
    }
    write_session_names(paths, &names)
}

pub fn preview_folder_session(
    paths: &AppPaths,
    agent: &str,
    cwd: &Path,
    session_id: &str,
    max_lines: usize,
) -> Vec<AgentPreviewLine> {
    preview_folder_session_with_cancel(
        paths,
        agent,
        cwd,
        session_id,
        max_lines,
        &HistoryCancellationToken::new(),
    )
    .unwrap_or_default()
}

/// Cancellation-aware form of [`preview_folder_session`].
pub fn preview_folder_session_with_cancel(
    paths: &AppPaths,
    agent: &str,
    cwd: &Path,
    session_id: &str,
    max_lines: usize,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentPreviewLine>, HistoryScanCancelled> {
    cancellation.check()?;
    // Preview is read-only and must remain available after the user moves a transcript into the
    // Removed section. Resolve only from the two folder-scoped listings we already trust; never
    // accept a client-supplied file path. This keeps the same cwd/provider boundary as the visible
    // picker while allowing either side of the non-destructive hidden-session partition.
    if !supports_provider_history(agent) {
        return Ok(Vec::new());
    }
    if require_exact_provider_session_id(agent, session_id).is_err()
        || validate_history_session_id(session_id).is_err()
    {
        return Ok(Vec::new());
    }
    let max_lines = max_lines.min(MAX_HISTORY_PREVIEW_LINES);
    if max_lines == 0 {
        return Ok(Vec::new());
    }
    let cwd_candidates = cwd_match_candidates(cwd);
    if cwd_candidates.is_empty() || !cwd_candidates.iter().any(|candidate| candidate.is_dir()) {
        return Ok(Vec::new());
    }
    let provider_cwd_candidates = if agent == "claude" {
        claude_repo_path_candidates(&cwd_candidates, cancellation)?
    } else {
        cwd_candidates.clone()
    };
    let listing = list_folder_sessions_partitioned_from_candidates(
        paths,
        agent,
        &cwd_candidates,
        &provider_cwd_candidates,
        cancellation,
    )?;
    let session = listing
        .visible
        .into_iter()
        .chain(listing.hidden)
        .find(|session| session.id == session_id);
    let Some(session) = session else {
        return Ok(Vec::new());
    };
    cancellation.check()?;
    if agent == "copilot" {
        return preview_copilot_session(&session.id, max_lines, cancellation);
    }
    if agent == "antigravity" {
        return preview_antigravity_session(&session, max_lines, cancellation);
    }
    if agent == "kimi" {
        return preview_kimi_session(&session.id, max_lines, cancellation);
    }
    if agent == "kiro" {
        return preview_kiro_session(&session.id, max_lines, cancellation);
    }
    if agent == "cursor" {
        return preview_cursor_session(cwd, &session.id, max_lines, cancellation);
    }
    if agent == "devin" {
        return preview_devin_session(&session.id, max_lines, cancellation);
    }
    let preview_path = if agent == "claude" {
        let Some(home) = home_dir() else {
            return Ok(Vec::new());
        };
        let buckets = claude_project_history_buckets(&home, &provider_cwd_candidates);
        let Some(path) = claude_root_in_allowed_buckets(Path::new(&session.file_path), &buckets)
        else {
            return Ok(Vec::new());
        };
        path
    } else {
        PathBuf::from(&session.file_path)
    };
    preview_session_file_with_cancel(agent, &preview_path, max_lines, cancellation)
}

pub fn agent_from_session_record(record: &SessionRecord) -> Option<&'static str> {
    agent_from_launch(&record.launch)
}

pub fn agent_from_launch(launch: &LaunchSpec) -> Option<&'static str> {
    match launch {
        LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } => {
            if launch_spec_id == "agent" {
                return Some("cursor");
            }
            if launch_spec_id == "amp" {
                return Some("amp");
            }
            if launch_spec_id == "devin" {
                return Some("devin");
            }
            if launch_spec_id == "droid" {
                return Some("factory");
            }
            agent_from_tokens(
                std::iter::once(launch_spec_id.as_str()).chain(params.iter().map(String::as_str)),
            )
        }
        LaunchSpec::AdHocRedacted { argv, .. } => {
            agent_from_tokens(argv.iter().map(String::as_str))
        }
        LaunchSpec::OptOut => None,
    }
}

fn agent_from_tokens<'a>(tokens: impl IntoIterator<Item = &'a str>) -> Option<&'static str> {
    for token in tokens {
        let lower = token.to_ascii_lowercase();
        let leaf = lower.rsplit('/').next().unwrap_or(lower.as_str());
        if leaf == "claude" || leaf.starts_with("claude ") || leaf.starts_with("claude-") {
            return Some("claude");
        }
        if leaf == "codex" || leaf.starts_with("codex ") || leaf.starts_with("codex-") {
            return Some("codex");
        }
        if leaf == "gemini" || leaf.starts_with("gemini ") || leaf.starts_with("gemini-") {
            return Some("gemini");
        }
        if leaf == "opencode" || leaf.starts_with("opencode ") || leaf.starts_with("opencode-") {
            return Some("opencode");
        }
        if leaf == "copilot" || leaf.starts_with("copilot ") || leaf.starts_with("copilot-") {
            return Some("copilot");
        }
        if leaf == "agy" || leaf.starts_with("agy ") || leaf.starts_with("agy-") {
            return Some("antigravity");
        }
        if leaf == "kimi" || leaf.starts_with("kimi ") || leaf.starts_with("kimi-") {
            return Some("kimi");
        }
        if leaf == "kiro-cli" || leaf.starts_with("kiro-cli ") || leaf.starts_with("kiro-cli-") {
            return Some("kiro");
        }
    }
    None
}

fn open_provider_session_ids(paths: &AppPaths, cwd_candidates: &[PathBuf]) -> HashSet<String> {
    let normalized_cwds = cwd_candidates
        .iter()
        .map(|cwd| normalize_cwd(cwd))
        .collect::<HashSet<_>>();
    load_all::<SessionRecord>(paths, RecordKind::Session)
        .map(|outcomes| {
            outcomes
                .into_iter()
                .filter_map(|outcome| match outcome {
                    LoadOutcome::Loaded(record) => {
                        if !normalized_cwds
                            .contains(&normalize_cwd(Path::new(&record.cwd_resolved)))
                        {
                            return None;
                        }
                        provider_session_id_from_launch(&record.launch)
                    }
                    LoadOutcome::Quarantined { .. } | LoadOutcome::FutureVersion { .. } => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn pane_session_names(paths: &AppPaths, cwd_candidates: &[PathBuf]) -> SessionNameMap {
    let normalized_cwds = cwd_candidates
        .iter()
        .map(|cwd| normalize_cwd(cwd))
        .collect::<HashSet<_>>();
    let session_provider_ids: HashMap<String, (String, String)> =
        load_all::<SessionRecord>(paths, RecordKind::Session)
            .map(|outcomes| {
                outcomes
                    .into_iter()
                    .filter_map(|outcome| match outcome {
                        LoadOutcome::Loaded(record) => {
                            if !normalized_cwds
                                .contains(&normalize_cwd(Path::new(&record.cwd_resolved)))
                            {
                                return None;
                            }
                            let agent = agent_from_session_record(&record)?;
                            let provider_id = provider_session_id_from_launch(&record.launch)?;
                            Some((record.session_id, (agent.to_string(), provider_id)))
                        }
                        LoadOutcome::Quarantined { .. } | LoadOutcome::FutureVersion { .. } => None,
                    })
                    .collect()
            })
            .unwrap_or_default();
    if session_provider_ids.is_empty() {
        return SessionNameMap::new();
    }

    let mut names = SessionNameMap::new();
    let layouts = load_all::<WindowLayout>(paths, RecordKind::WindowLayout).unwrap_or_default();
    for outcome in layouts {
        let LoadOutcome::Loaded(layout) = outcome else {
            continue;
        };
        for tab in layout.tabs {
            let Some((agent, provider_id)) = session_provider_ids.get(&tab.session_id) else {
                continue;
            };
            let title = tab.title.trim();
            if !is_user_session_name(title) {
                continue;
            }
            names
                .entry(session_name_key(agent, provider_id))
                .or_insert_with(|| title.to_string());
        }
    }
    names
}

fn is_user_session_name(title: &str) -> bool {
    let title = title.trim();
    !title.is_empty()
        && !matches!(
            title.to_ascii_lowercase().as_str(),
            "pane" | "shell" | "terminal" | "new session"
        )
}

fn provider_session_id_from_launch(launch: &LaunchSpec) -> Option<String> {
    match launch {
        LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } => {
            if launch_spec_id == "devin" || launch_spec_id == "droid" {
                return opaque_resume_id_from_params(params);
            }
            provider_session_id_from_tokens(
                std::iter::once(launch_spec_id.as_str()).chain(params.iter().map(String::as_str)),
                true,
            )
        }
        LaunchSpec::AdHocRedacted { argv, .. } => {
            provider_session_id_from_tokens(argv.iter().map(String::as_str), false)
        }
        LaunchSpec::OptOut => None,
    }
}

fn opaque_resume_id_from_params(params: &[String]) -> Option<String> {
    let mut resume_id = None;
    let mut index = 0;
    while index < params.len() {
        if params[index] == "--resume" {
            if resume_id.is_some() {
                return None;
            }
            resume_id = params
                .get(index + 1)
                .and_then(|candidate| clean_opaque_session_id(candidate));
            resume_id.as_ref()?;
            index += 2;
            continue;
        }
        index += 1;
    }
    resume_id
}

fn clean_opaque_session_id(candidate: &str) -> Option<String> {
    let value = candidate.trim();
    (!value.is_empty()
        && value.chars().count() <= PROVIDER_SESSION_ID_MAX_CHARS
        && !value.starts_with('-')
        && !value.chars().any(char::is_control))
    .then(|| value.to_string())
}

fn provider_session_id_from_tokens<'a>(
    tokens: impl IntoIterator<Item = &'a str>,
    allow_cursor: bool,
) -> Option<String> {
    let tokens = tokens.into_iter().collect::<Vec<_>>();
    provider_session_id_from_flat_tokens(&tokens, allow_cursor)
        .or_else(|| provider_session_id_from_shell_fragments(&tokens, allow_cursor))
}

fn provider_session_id_from_shell_fragments(tokens: &[&str], allow_cursor: bool) -> Option<String> {
    tokens.iter().find_map(|token| {
        if !token.contains("--resume")
            && !token.contains("resume ")
            && !token.contains("--session-id")
            && !token.contains("--conversation")
            && !token.contains("--session")
            && !token.contains(" -S ")
            && !token.contains("--resume-id")
        {
            return None;
        }
        let split = token.split_whitespace().collect::<Vec<_>>();
        provider_session_id_from_flat_tokens(&split, allow_cursor)
    })
}

fn provider_session_id_from_flat_tokens(tokens: &[&str], allow_cursor: bool) -> Option<String> {
    for (idx, token) in tokens.iter().enumerate() {
        let leaf = token.rsplit('/').next().unwrap_or(token);
        if leaf == "claude" {
            if tokens.get(idx + 1).copied() == Some("--resume") {
                return clean_session_id(tokens.get(idx + 2).copied());
            }
        } else if leaf == "codex" {
            if tokens.get(idx + 1).copied() == Some("resume") {
                let candidate = tokens.get(idx + 2).copied();
                if candidate != Some("--last") {
                    return clean_session_id(candidate);
                }
            }
        } else if leaf == "gemini" {
            for offset in 1..4 {
                if tokens.get(idx + offset).copied() == Some("--session-file") {
                    return tokens
                        .get(idx + offset + 1)
                        .and_then(|path| Path::new(path).file_stem())
                        .and_then(|stem| stem.to_str())
                        .map(str::to_string);
                }
            }
        } else if leaf == "opencode" {
            for offset in 1..4 {
                if tokens.get(idx + offset).copied() == Some("--session") {
                    return clean_session_id(tokens.get(idx + offset + 1).copied());
                }
            }
        } else if leaf == "copilot" {
            for offset in 1..5 {
                let Some(token) = tokens.get(idx + offset).copied() else {
                    continue;
                };
                if let Some(id) = token
                    .strip_prefix("--resume=")
                    .or_else(|| token.strip_prefix("--session-id="))
                {
                    return clean_uuid(id);
                }
                if token == "--resume" || token == "--session-id" {
                    return tokens.get(idx + offset + 1).and_then(|id| clean_uuid(id));
                }
            }
        } else if leaf == "agy" {
            for offset in 1..5 {
                let Some(token) = tokens.get(idx + offset).copied() else {
                    continue;
                };
                if let Some(id) = token.strip_prefix("--conversation=") {
                    return clean_uuid(id);
                }
                if token == "--conversation" {
                    return tokens.get(idx + offset + 1).and_then(|id| clean_uuid(id));
                }
            }
        } else if leaf == "kimi" {
            for offset in 1..5 {
                let Some(token) = tokens.get(idx + offset).copied() else {
                    continue;
                };
                if let Some(id) = token
                    .strip_prefix("--session=")
                    .or_else(|| token.strip_prefix("-S="))
                {
                    return clean_kimi_session_id(id);
                }
                if token == "--session" || token == "-S" {
                    return tokens
                        .get(idx + offset + 1)
                        .and_then(|id| clean_kimi_session_id(id));
                }
            }
        } else if leaf == "kiro-cli" {
            for offset in 1..6 {
                let Some(token) = tokens.get(idx + offset).copied() else {
                    continue;
                };
                if let Some(id) = token.strip_prefix("--resume-id=") {
                    return clean_uuid(id);
                }
                if token == "--resume-id" {
                    return tokens.get(idx + offset + 1).and_then(|id| clean_uuid(id));
                }
            }
        } else if allow_cursor && idx == 0 && leaf == "agent" {
            for offset in 1..5 {
                let Some(token) = tokens.get(idx + offset).copied() else {
                    continue;
                };
                if let Some(id) = token.strip_prefix("--resume=") {
                    return clean_uuid(id);
                }
                if token == "--resume" {
                    return tokens.get(idx + offset + 1).and_then(|id| clean_uuid(id));
                }
            }
        }
    }
    None
}

fn clean_uuid(candidate: &str) -> Option<String> {
    let value = candidate.trim();
    uuid::Uuid::parse_str(value).ok().map(|id| id.to_string())
}

fn clean_kimi_session_id(candidate: &str) -> Option<String> {
    let value = candidate.trim();
    let uuid = value.strip_prefix("session_")?;
    let parsed = uuid::Uuid::parse_str(uuid).ok()?;
    (parsed.hyphenated().to_string() == uuid).then(|| value.to_string())
}

fn clean_session_id(candidate: Option<&str>) -> Option<String> {
    clean_opaque_session_id(candidate?)
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn antigravity_state(home: &Path) -> PathBuf {
        let state = home.join(".gemini").join("antigravity-cli");
        fs::create_dir_all(state.join("conversations")).unwrap();
        fs::create_dir_all(state.join("cache")).unwrap();
        state
    }

    fn create_antigravity_summary_store(state: &Path) -> rusqlite::Connection {
        let connection =
            rusqlite::Connection::open(state.join("conversation_summaries.db")).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE conversation_summaries (
                  conversation_id TEXT PRIMARY KEY, title TEXT NOT NULL DEFAULT '',
                  preview TEXT NOT NULL DEFAULT '', step_count INTEGER NOT NULL DEFAULT 0,
                  last_modified_time TEXT NOT NULL, workspace_uris TEXT NOT NULL,
                  not_fully_idle INTEGER NOT NULL DEFAULT 0, killed INTEGER NOT NULL DEFAULT 0
                );
                "#,
            )
            .unwrap();
        connection
    }

    fn create_antigravity_modern_summary_store(state: &Path) -> rusqlite::Connection {
        let connection =
            rusqlite::Connection::open(state.join("conversation_summaries.db")).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE conversation_summaries (
                  conversation_id TEXT PRIMARY KEY, title TEXT NOT NULL DEFAULT '',
                  preview TEXT NOT NULL DEFAULT '', step_count INTEGER NOT NULL DEFAULT 0,
                  last_modified_time TEXT NOT NULL, workspace_uris TEXT NOT NULL,
                  parent_conversation_id TEXT NOT NULL DEFAULT '',
                  nesting_depth INTEGER NOT NULL DEFAULT 0,
                  not_fully_idle INTEGER NOT NULL DEFAULT 0, killed INTEGER NOT NULL DEFAULT 0
                );
                "#,
            )
            .unwrap();
        connection
    }

    fn create_antigravity_conversation_db(state: &Path, id: &str) {
        let connection =
            rusqlite::Connection::open(state.join("conversations").join(format!("{id}.db")))
                .unwrap();
        connection
            .execute_batch("CREATE TABLE trajectory_meta (trajectory_id TEXT PRIMARY KEY);")
            .unwrap();
    }

    fn create_devin_test_store(home: &Path) -> rusqlite::Connection {
        let store = devin_store_path(home);
        fs::create_dir_all(store.parent().unwrap()).unwrap();
        let connection = rusqlite::Connection::open(store).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE sessions (
                  id TEXT PRIMARY KEY,
                  working_directory TEXT NOT NULL,
                  backend_type TEXT NOT NULL DEFAULT '',
                  model TEXT NOT NULL DEFAULT '',
                  agent_mode TEXT NOT NULL DEFAULT '',
                  created_at INTEGER,
                  last_activity_at INTEGER,
                  title TEXT,
                  main_chain_id INTEGER,
                  shell_last_seen_index INTEGER,
                  cogs_json TEXT,
                  workspace_dirs TEXT,
                  hidden INTEGER NOT NULL DEFAULT 0,
                  metadata TEXT
                );
                CREATE TABLE message_nodes (
                  row_id INTEGER PRIMARY KEY AUTOINCREMENT,
                  session_id TEXT NOT NULL,
                  node_id INTEGER NOT NULL,
                  parent_node_id INTEGER,
                  chat_message TEXT NOT NULL,
                  created_at INTEGER NOT NULL,
                  metadata TEXT,
                  UNIQUE(session_id, node_id),
                  FOREIGN KEY(session_id) REFERENCES sessions(id)
                );
                "#,
            )
            .unwrap();
        connection
    }

    #[test]
    fn provider_session_id_is_extracted_from_agent_launches() {
        let claude = LaunchSpec::AdHocRedacted {
            argv: vec![
                "claude".into(),
                "--resume".into(),
                "10000000-0000-4000-8000-000000000001".into(),
            ],
            redacted: false,
            restart_requires_user: false,
        };
        assert_eq!(
            provider_session_id_from_launch(&claude).as_deref(),
            Some("10000000-0000-4000-8000-000000000001")
        );

        let shell_wrapped = LaunchSpec::AdHocRedacted {
            argv: vec![
                "/bin/zsh".into(),
                "-lc".into(),
                "claude --resume 10000000-0000-4000-8000-000000000001".into(),
            ],
            redacted: false,
            restart_requires_user: false,
        };
        assert_eq!(
            provider_session_id_from_launch(&shell_wrapped).as_deref(),
            Some("10000000-0000-4000-8000-000000000001")
        );

        let codex = LaunchSpec::AdHocRedacted {
            argv: vec!["codex".into(), "resume".into(), "thread-123".into()],
            redacted: false,
            restart_requires_user: false,
        };
        assert_eq!(
            provider_session_id_from_launch(&codex).as_deref(),
            Some("thread-123")
        );

        let gemini = LaunchSpec::AdHocRedacted {
            argv: vec![
                "gemini".into(),
                "--session-file".into(),
                "/tmp/gemini-session.jsonl".into(),
            ],
            redacted: false,
            restart_requires_user: false,
        };
        assert_eq!(
            provider_session_id_from_launch(&gemini).as_deref(),
            Some("gemini-session")
        );

        let copilot_id = "20000000-0000-4000-8000-000000000001";
        let copilot = LaunchSpec::KnownSafe {
            launch_spec_id: "copilot".into(),
            params: vec![format!("--session-id={copilot_id}")],
        };
        assert_eq!(
            provider_session_id_from_launch(&copilot).as_deref(),
            Some(copilot_id)
        );

        let antigravity_id = "30000000-0000-4000-8000-000000000001";
        let antigravity = LaunchSpec::AdHocRedacted {
            argv: vec![
                "/Users/test/.local/bin/agy".into(),
                "--conversation".into(),
                antigravity_id.into(),
            ],
            redacted: false,
            restart_requires_user: false,
        };
        assert_eq!(
            provider_session_id_from_launch(&antigravity).as_deref(),
            Some(antigravity_id)
        );

        let kimi_id = "session_40000000-0000-4000-8000-000000000001";
        let kimi = LaunchSpec::KnownSafe {
            launch_spec_id: "kimi".into(),
            params: vec!["--session".into(), kimi_id.into()],
        };
        assert_eq!(
            provider_session_id_from_launch(&kimi).as_deref(),
            Some(kimi_id)
        );

        let kiro_id = "40000000-0000-4000-8000-000000000003";
        let kiro = LaunchSpec::KnownSafe {
            launch_spec_id: "kiro-cli".into(),
            params: vec!["chat".into(), "--resume-id".into(), kiro_id.into()],
        };
        assert_eq!(
            provider_session_id_from_launch(&kiro).as_deref(),
            Some(kiro_id)
        );

        let cursor_id = "123e4567-e89b-42d3-a456-426614174000";
        let cursor = LaunchSpec::KnownSafe {
            launch_spec_id: "agent".into(),
            params: vec!["--resume".into(), cursor_id.into()],
        };
        assert_eq!(agent_from_launch(&cursor), Some("cursor"));
        assert_eq!(
            provider_session_id_from_launch(&cursor).as_deref(),
            Some(cursor_id)
        );

        for argv in [
            vec![
                "task-runner".into(),
                "agent".into(),
                "--resume".into(),
                cursor_id.into(),
            ],
            vec!["agent".into(), "--serve".into()],
            vec!["agent".into(), "--resume".into(), cursor_id.into()],
        ] {
            let unrelated = LaunchSpec::AdHocRedacted {
                argv,
                redacted: false,
                restart_requires_user: false,
            };
            assert_eq!(agent_from_launch(&unrelated), None);
            assert_eq!(provider_session_id_from_launch(&unrelated), None);
        }
    }

    #[test]
    fn amp_requires_explicit_known_safe_provenance_and_has_no_inferred_history_id() {
        let known = LaunchSpec::KnownSafe {
            launch_spec_id: "amp".into(),
            params: vec!["threads".into(), "continue".into(), "thread-id".into()],
        };
        assert_eq!(agent_from_launch(&known), Some("amp"));
        assert_eq!(provider_session_id_from_launch(&known), None);

        for argv in [
            vec!["amp".into(), "last".into()],
            vec!["wrapper".into(), "amp".into()],
        ] {
            let unproven = LaunchSpec::AdHocRedacted {
                argv,
                redacted: false,
                restart_requires_user: true,
            };
            assert_eq!(agent_from_launch(&unproven), None);
            assert_eq!(provider_session_id_from_launch(&unproven), None);
        }
    }

    #[test]
    fn amp_history_boundary_is_fail_closed_and_writes_no_sidecars() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("Hydra");
        let paths = AppPaths::with_base(&base);
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        assert!(!supports_provider_history("amp"));
        assert!(list_folder_sessions(&paths, "amp", &cwd).is_empty());
        assert!(list_hidden_folder_sessions(&paths, "amp", &cwd).is_empty());
        assert!(preview_folder_session(&paths, "amp", &cwd, "thread-id", 20).is_empty());
        assert!(hide_folder_session(&paths, "amp", "thread-id").is_err());
        assert!(unhide_folder_session(&paths, "amp", "thread-id").is_err());
        assert!(set_folder_session_name(&paths, "amp", "thread-id", Some("name")).is_err());
        assert!(delete_folder_session(&paths, "amp", &cwd, "thread-id").is_err());
        assert!(
            !base.exists(),
            "unsupported history operations must not create Hydra state"
        );
    }

    #[test]
    fn devin_and_factory_require_explicit_known_safe_provenance() {
        let devin = LaunchSpec::KnownSafe {
            launch_spec_id: "devin".into(),
            params: vec![
                "--resume".into(),
                "synthetic-session".into(),
                "--permission-mode=dangerous".into(),
            ],
        };
        assert_eq!(agent_from_launch(&devin), Some("devin"));
        assert_eq!(
            provider_session_id_from_launch(&devin).as_deref(),
            Some("synthetic-session")
        );

        let factory = LaunchSpec::KnownSafe {
            launch_spec_id: "droid".into(),
            params: vec!["--resume".into(), "synthetic-factory-session".into()],
        };
        assert_eq!(agent_from_launch(&factory), Some("factory"));
        assert_eq!(
            provider_session_id_from_launch(&factory).as_deref(),
            Some("synthetic-factory-session")
        );
        assert!(!supports_provider_history("factory"));

        for argv in [
            vec![
                "devin".into(),
                "--resume".into(),
                "synthetic-session".into(),
            ],
            vec![
                "wrapper".into(),
                "droid".into(),
                "--resume".into(),
                "synthetic-factory-session".into(),
            ],
        ] {
            let unproven = LaunchSpec::AdHocRedacted {
                argv,
                redacted: false,
                restart_requires_user: true,
            };
            assert_eq!(agent_from_launch(&unproven), None);
            assert_eq!(provider_session_id_from_launch(&unproven), None);
        }

        for invalid in [
            String::new(),
            "-flag-like".to_string(),
            "control\ncharacter".to_string(),
            "x".repeat(257),
        ] {
            assert!(clean_opaque_session_id(&invalid).is_none());
            let launch = LaunchSpec::KnownSafe {
                launch_spec_id: "devin".into(),
                params: vec!["--resume".into(), invalid],
            };
            assert_eq!(provider_session_id_from_launch(&launch), None);
        }
        assert!(clean_opaque_session_id(&"é".repeat(256)).is_some());
        let duplicate = LaunchSpec::KnownSafe {
            launch_spec_id: "devin".into(),
            params: vec![
                "--resume".into(),
                "one".into(),
                "--resume".into(),
                "two".into(),
            ],
        };
        assert_eq!(provider_session_id_from_launch(&duplicate), None);
    }

    #[test]
    fn devin_history_is_folder_scoped_main_chain_private_and_provider_managed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let other = normalize_cwd(&{
            let path = tmp.path().join("project-other");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let connection = create_devin_test_store(tmp.path());
        let selected = "synthetic-main-chain";
        connection
            .execute(
                "INSERT INTO sessions
                   (id, working_directory, last_activity_at, title, main_chain_id, hidden)
                 VALUES (?1, ?2, ?3, ?4, 7, 0)",
                rusqlite::params![
                    selected,
                    project.to_string_lossy().as_ref(),
                    1_784_364_247_i64,
                    "Devin renderer review"
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions
                   (id, working_directory, last_activity_at, title, main_chain_id, hidden)
                 VALUES ('synthetic-other-folder', ?1, 1784364250, 'Other', NULL, 0)",
                [other.to_string_lossy().as_ref()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions
                   (id, working_directory, last_activity_at, title, main_chain_id, hidden)
                 VALUES ('synthetic-provider-hidden', ?1, 1784364260, 'Hidden', NULL, 1)",
                [project.to_string_lossy().as_ref()],
            )
            .unwrap();
        for invalid in [
            "".to_string(),
            "-flag-like".to_string(),
            "control\nid".to_string(),
            "x".repeat(257),
        ] {
            connection
                .execute(
                    "INSERT INTO sessions
                       (id, working_directory, last_activity_at, title, main_chain_id, hidden)
                     VALUES (?1, ?2, 1784364270, 'Invalid', NULL, 0)",
                    rusqlite::params![invalid, project.to_string_lossy().as_ref()],
                )
                .unwrap();
        }

        let messages = [
            (
                1_i64,
                None,
                serde_json::json!({"role":"system","content":"PRIVATE SYSTEM"}),
            ),
            (
                2,
                Some(1),
                serde_json::json!({"role":"user","content":"PRIVATE TRANSFORMED","metadata":{"is_user_input":false}}),
            ),
            (
                3,
                Some(2),
                serde_json::json!({"role":"user","content":"inspect the renderer","metadata":{"is_user_input":true,"private":"PRIVATE METADATA"}}),
            ),
            (
                4,
                Some(3),
                serde_json::json!({"role":"assistant","content":[{"type":"thinking","text":"PRIVATE THINK"},{"type":"text","text":"I found the issue"}]}),
            ),
            (
                5,
                Some(4),
                serde_json::json!({"role":"thinking","content":"PRIVATE REASONING"}),
            ),
            (
                6,
                Some(5),
                serde_json::json!({"role":"tool","content":"PRIVATE TOOL"}),
            ),
            (
                7,
                Some(6),
                serde_json::json!({"role":"assistant","content":"Final answer"}),
            ),
            // This valid-looking response descends from the main chain but is not an ancestor of its leaf.
            (
                99,
                Some(3),
                serde_json::json!({"role":"assistant","content":"PRIVATE ABANDONED BRANCH"}),
            ),
        ];
        for (node_id, parent_node_id, chat_message) in messages {
            connection
                .execute(
                    "INSERT INTO message_nodes
                       (session_id, node_id, parent_node_id, chat_message, created_at)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        selected,
                        node_id,
                        parent_node_id,
                        chat_message.to_string(),
                        1_784_364_200_i64 + node_id,
                    ],
                )
                .unwrap();
        }
        drop(connection);

        assert!(supports_provider_history("devin"));
        let sessions = list_folder_sessions(&app_paths, "devin", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, selected);
        assert_eq!(sessions[0].agent, "devin");
        assert_eq!(sessions[0].title, "Devin renderer review");
        assert_eq!(sessions[0].first_message, "Devin renderer review");
        assert_eq!(sessions[0].message_count, None);
        assert_eq!(sessions[0].modified_at_ms, 1_784_364_247_000);
        assert_eq!(sessions[0].file_path, format!("devin://{selected}"));
        let other_sessions = list_folder_sessions(&app_paths, "devin", &other);
        assert_eq!(other_sessions.len(), 1);
        assert_eq!(other_sessions[0].id, "synthetic-other-folder");

        let preview = preview_folder_session(&app_paths, "devin", &project, selected, 20);
        assert_eq!(
            preview
                .iter()
                .map(|line| (line.role.as_str(), line.text.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("user", "inspect the renderer"),
                ("assistant", "I found the issue"),
                ("assistant", "Final answer"),
            ]
        );
        assert_eq!(
            preview_folder_session(&app_paths, "devin", &project, selected, 2).len(),
            2
        );
        let serialized = serde_json::to_string(&preview).unwrap();
        for private in [
            "PRIVATE SYSTEM",
            "PRIVATE TRANSFORMED",
            "PRIVATE METADATA",
            "PRIVATE THINK",
            "PRIVATE REASONING",
            "PRIVATE TOOL",
            "PRIVATE ABANDONED BRANCH",
        ] {
            assert!(!serialized.contains(private));
        }

        set_folder_session_name(&app_paths, "devin", selected, Some("My Devin task")).unwrap();
        assert_eq!(
            list_folder_sessions(&app_paths, "devin", &project)[0]
                .custom_name
                .as_deref(),
            Some("My Devin task")
        );
        hide_folder_session(&app_paths, "devin", selected).unwrap();
        assert!(list_folder_sessions(&app_paths, "devin", &project).is_empty());
        assert_eq!(
            list_hidden_folder_sessions(&app_paths, "devin", &project)[0].id,
            selected
        );
        assert_eq!(
            preview_folder_session(&app_paths, "devin", &project, selected, 20).len(),
            3
        );
        unhide_folder_session(&app_paths, "devin", selected).unwrap();
        assert!(
            delete_folder_session(&app_paths, "devin", &project, selected)
                .unwrap_err()
                .contains("managed by the provider")
        );
        assert!(devin_store_path(tmp.path()).exists());

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn devin_history_rejects_negative_timestamps_and_fails_soft_on_schema_drift() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = tmp.path().join("project");
        fs::create_dir_all(&project).unwrap();

        let connection = create_devin_test_store(tmp.path());
        connection
            .execute(
                "INSERT INTO sessions
                   (id, working_directory, last_activity_at, title, main_chain_id, hidden)
                 VALUES ('negative-time', ?1, -5, 'Clock skew', NULL, 0)",
                [project.to_string_lossy().as_ref()],
            )
            .unwrap();
        drop(connection);
        let sessions = list_folder_sessions(&app_paths, "devin", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].modified_at_ms, 0);

        fs::remove_file(devin_store_path(tmp.path())).unwrap();
        let connection = rusqlite::Connection::open(devin_store_path(tmp.path())).unwrap();
        connection
            .execute("CREATE TABLE unrelated (value TEXT)", [])
            .unwrap();
        drop(connection);
        assert!(list_folder_sessions(&app_paths, "devin", &project).is_empty());
        assert!(
            preview_folder_session(&app_paths, "devin", &project, "negative-time", 20).is_empty()
        );

        fs::remove_file(devin_store_path(tmp.path())).unwrap();
        fs::write(devin_store_path(tmp.path()), b"not a sqlite database").unwrap();
        assert!(list_folder_sessions(&app_paths, "devin", &project).is_empty());

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn devin_listing_never_requires_message_nodes_and_caps_titles_in_sql() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });

        let connection = create_devin_test_store(tmp.path());
        connection.execute("DROP TABLE message_nodes", []).unwrap();
        connection
            .execute(
                "INSERT INTO sessions
                   (id, working_directory, last_activity_at, title, main_chain_id, hidden)
                 VALUES ('metadata-only', ?1, 10, 'Metadata title', 99, 0)",
                [project.to_string_lossy().as_ref()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions
                   (id, working_directory, last_activity_at, title, main_chain_id, hidden)
                 VALUES ('oversized-title', ?1, 9, ?2, 100, 0)",
                rusqlite::params![
                    project.to_string_lossy().as_ref(),
                    "é".repeat(DEVIN_PROVIDER_TITLE_MAX_BYTES),
                ],
            )
            .unwrap();
        drop(connection);

        let sessions = list_folder_sessions(&app_paths, "devin", &project);
        assert_eq!(sessions.len(), 2);
        assert!(sessions
            .iter()
            .all(|session| session.message_count.is_none()));
        let oversized = sessions
            .iter()
            .find(|session| session.id == "oversized-title")
            .unwrap();
        assert_eq!(oversized.title, "Devin session");
        assert!(!serde_json::to_string(&sessions)
            .unwrap()
            .contains(&"é".repeat(64)));

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn folder_session_discovery_uses_provider_store_scoped_to_selected_folder() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = tmp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        let project = normalize_cwd(&project);

        let claude_dir = tmp
            .path()
            .join(".claude")
            .join("projects")
            .join(encode_claude_cwd(&project));
        fs::create_dir_all(&claude_dir).unwrap();
        fs::write(
            claude_dir.join("global-session.jsonl"),
            r#"{"type":"user","userType":"external","message":{"content":"session in selected Documents folder"}}"#,
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "claude", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "global-session");
        assert_eq!(
            sessions[0].first_message,
            "session in selected Documents folder"
        );

        let other_project = tmp.path().join("other-project");
        fs::create_dir_all(&other_project).unwrap();
        assert!(list_folder_sessions(&app_paths, "claude", &other_project).is_empty());

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn claude_listing_is_bounded_and_excludes_nested_sidechain_transcripts() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = normalize_cwd(&{
            let project = tmp.path().join("project");
            fs::create_dir_all(&project).unwrap();
            project
        });
        let claude_dir = tmp
            .path()
            .join(".claude")
            .join("projects")
            .join(encode_claude_cwd(&project));
        fs::create_dir_all(&claude_dir).unwrap();

        let root = claude_dir.join("root-session.jsonl");
        fs::write(
            &root,
            concat!(
                "{\"type\":\"ai-title\",\"sessionId\":\"root-session\",",
                "\"aiTitle\":\"bounded root message\"}\n"
            ),
        )
        .unwrap();
        // A realistic large transcript must not turn listing into an EOF scan.
        fs::OpenOptions::new()
            .write(true)
            .open(&root)
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();

        let nested = claude_dir.join("root-session").join("subagents");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("sidechain.jsonl"),
            concat!(
                "{\"type\":\"user\",\"userType\":\"external\",\"isSidechain\":true,",
                "\"message\":{\"content\":\"must stay hidden\"}}\n"
            ),
        )
        .unwrap();
        let duplicate_root = claude_dir.join("duplicate-root.jsonl");
        fs::write(
            &duplicate_root,
            concat!(
                "{\"type\":\"custom-title\",\"sessionId\":\"root-session\",",
                "\"customTitle\":\"bounded root message\"}\n"
            ),
        )
        .unwrap();
        let duplicate_sidechains = claude_dir.join("duplicate-root").join("subagents");
        fs::create_dir_all(&duplicate_sidechains).unwrap();
        fs::write(
            duplicate_sidechains.join("sidechain.jsonl"),
            "{\"type\":\"user\",\"isSidechain\":true}\n",
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "claude", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "root-session");
        assert_eq!(sessions[0].first_message, "bounded root message");
        assert_eq!(sessions[0].message_count, None);

        fs::write(
            &root,
            concat!(
                "{\"type\":\"ai-title\",\"sessionId\":\"root-session\",",
                "\"aiTitle\":\"updated cached root message\"}\n"
            ),
        )
        .unwrap();
        let refreshed = list_folder_sessions(&app_paths, "claude", &project);
        assert_eq!(refreshed[0].first_message, "updated cached root message");

        let corrupt = claude_dir.join("corrupt.jsonl");
        fs::write(&corrupt, "not-json\n").unwrap();
        assert!(
            delete_folder_session(&app_paths, "claude", &project, "root-session").is_err(),
            "delete must fail closed when complete group ownership cannot be established"
        );
        assert!(root.exists() && duplicate_root.exists());
        fs::remove_file(corrupt).unwrap();
        delete_folder_session(&app_paths, "claude", &project, "root-session").unwrap();
        assert!(!root.exists(), "delete removes the resumable Claude root");
        assert!(
            !nested.parent().unwrap().exists(),
            "delete removes the provider-owned sidechain directory"
        );
        assert!(
            !duplicate_root.exists() && !duplicate_sidechains.parent().unwrap().exists(),
            "delete removes every direct root grouped under the same Claude sessionId"
        );

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn claude_listing_includes_only_registered_paths_from_the_selected_repository() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let project = tmp.path().join("project");
            fs::create_dir_all(&project).unwrap();
            project
        });
        let historical_path = tmp.path().join("project-old-worktree");
        let unrelated_path = tmp.path().join("unrelated-project");
        fs::create_dir_all(&unrelated_path).unwrap();
        let projects = tmp.path().join(".claude").join("projects");
        let current_dir = projects.join(encode_claude_cwd(&project));
        let historical_dir = projects.join(encode_claude_cwd(&historical_path));
        let unrelated_dir = projects.join(encode_claude_cwd(&unrelated_path));
        fs::create_dir_all(&current_dir).unwrap();
        fs::create_dir_all(&historical_dir).unwrap();
        fs::create_dir_all(&unrelated_dir).unwrap();
        for index in 0..17 {
            let id = format!("current-{index:02}");
            fs::write(
                current_dir.join(format!("{id}.jsonl")),
                format!(
                    "{}\n",
                    serde_json::json!({
                        "type": "custom-title",
                        "sessionId": id,
                        "customTitle": format!("Current session {index:02}")
                    })
                ),
            )
            .unwrap();
        }
        fs::write(
            historical_dir.join("historical-session.jsonl"),
            concat!(
                "{\"type\":\"custom-title\",\"sessionId\":\"historical-session\",",
                "\"customTitle\":\"Historical worktree session\"}\n"
            ),
        )
        .unwrap();
        let nested = historical_dir.join("historical-session").join("subagents");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("nested-sidechain.jsonl"),
            concat!(
                "{\"type\":\"user\",\"sessionId\":\"nested-sidechain\",",
                "\"isSidechain\":true}\n"
            ),
        )
        .unwrap();
        fs::write(
            unrelated_dir.join("unrelated-session.jsonl"),
            concat!(
                "{\"type\":\"custom-title\",\"sessionId\":\"unrelated-session\",",
                "\"customTitle\":\"Must stay unrelated\"}\n"
            ),
        )
        .unwrap();
        fs::write(
            tmp.path().join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "githubRepoPaths": {
                    "owner/selected": [
                        project.to_string_lossy(),
                        historical_path.to_string_lossy()
                    ],
                    "owner/unrelated": [unrelated_path.to_string_lossy()]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "claude", &project);
        assert_eq!(sessions.len(), 18, "17 current roots plus one repo alias");
        assert!(sessions
            .iter()
            .any(|session| session.id == "historical-session"));
        assert!(!sessions
            .iter()
            .any(|session| session.id == "nested-sidechain"));
        assert!(!sessions
            .iter()
            .any(|session| session.id == "unrelated-session"));

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn claude_repo_aliases_group_and_delete_duplicate_session_roots() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let project = tmp.path().join("project");
            fs::create_dir_all(&project).unwrap();
            project
        });
        let alias = tmp.path().join("project-old-worktree");
        let projects = tmp.path().join(".claude").join("projects");
        let current_dir = projects.join(encode_claude_cwd(&project));
        let alias_dir = projects.join(encode_claude_cwd(&alias));
        fs::create_dir_all(&current_dir).unwrap();
        fs::create_dir_all(&alias_dir).unwrap();
        let current_root = current_dir.join("current-root.jsonl");
        let alias_root = alias_dir.join("alias-root.jsonl");
        for root in [&current_root, &alias_root] {
            fs::write(
                root,
                concat!(
                    "{\"type\":\"custom-title\",\"sessionId\":\"shared-session\",",
                    "\"customTitle\":\"Shared session\"}\n"
                ),
            )
            .unwrap();
            let sidechains = root.with_extension("").join("subagents");
            fs::create_dir_all(&sidechains).unwrap();
            fs::write(
                sidechains.join("sidechain.jsonl"),
                "{\"type\":\"user\",\"isSidechain\":true}\n",
            )
            .unwrap();
        }
        fs::write(
            tmp.path().join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "githubRepoPaths": {
                    "owner/selected": [project.to_string_lossy(), alias.to_string_lossy()]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "claude", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "shared-session");
        delete_folder_session(&app_paths, "claude", &project, "shared-session").unwrap();
        assert!(!current_root.exists() && !alias_root.exists());
        assert!(!current_root.with_extension("").exists());
        assert!(!alias_root.with_extension("").exists());

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn claude_repo_registry_malformed_or_oversized_falls_back_and_honors_cancellation() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let project = tmp.path().join("project");
            fs::create_dir_all(&project).unwrap();
            project
        });
        let alias = tmp.path().join("project-old-worktree");
        let projects = tmp.path().join(".claude").join("projects");
        let current_dir = projects.join(encode_claude_cwd(&project));
        let alias_dir = projects.join(encode_claude_cwd(&alias));
        fs::create_dir_all(&current_dir).unwrap();
        fs::create_dir_all(&alias_dir).unwrap();
        fs::write(
            current_dir.join("current.jsonl"),
            "{\"type\":\"custom-title\",\"sessionId\":\"current\"}\n",
        )
        .unwrap();
        fs::write(
            alias_dir.join("alias.jsonl"),
            "{\"type\":\"custom-title\",\"sessionId\":\"alias\"}\n",
        )
        .unwrap();
        let config = tmp.path().join(".claude.json");

        fs::write(&config, b"{not valid json").unwrap();
        let malformed = list_folder_sessions(&app_paths, "claude", &project);
        assert_eq!(malformed.len(), 1);
        assert_eq!(malformed[0].id, "current");

        let oversized = fs::File::create(&config).unwrap();
        oversized.set_len(CLAUDE_CONFIG_MAX_BYTES + 1).unwrap();
        drop(oversized);
        let over_limit = list_folder_sessions(&app_paths, "claude", &project);
        assert_eq!(over_limit.len(), 1);
        assert_eq!(over_limit[0].id, "current");

        let cancelled = HistoryCancellationToken::new();
        cancelled.cancel();
        assert!(matches!(
            claude_repo_path_candidates(&[project], &cancelled),
            Err(HistoryScanCancelled)
        ));

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn claude_repo_registry_ignores_malformed_unrelated_groups() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let alias = tmp.path().join("project-old-worktree");
        let projects = tmp.path().join(".claude").join("projects");
        let current_dir = projects.join(encode_claude_cwd(&project));
        let alias_dir = projects.join(encode_claude_cwd(&alias));
        fs::create_dir_all(&current_dir).unwrap();
        fs::create_dir_all(&alias_dir).unwrap();
        fs::write(
            current_dir.join("current.jsonl"),
            "{\"type\":\"custom-title\",\"sessionId\":\"current\"}\n",
        )
        .unwrap();
        fs::write(
            alias_dir.join("alias.jsonl"),
            "{\"type\":\"custom-title\",\"sessionId\":\"alias\"}\n",
        )
        .unwrap();
        let unrelated_oversized = (0..=CLAUDE_REPO_PATH_MAX_COUNT)
            .map(|index| {
                Value::String(
                    tmp.path()
                        .join(format!("other-{index}"))
                        .to_string_lossy()
                        .into_owned(),
                )
            })
            .collect::<Vec<_>>();
        fs::write(
            tmp.path().join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "githubRepoPaths": {
                    "owner/selected": [project.to_string_lossy(), alias.to_string_lossy()],
                    "owner/not-an-array": {"path": "ignored"},
                    "owner/empty": [],
                    "owner/malformed": ["relative/path", 42, "../escape"],
                    "owner/oversized": unrelated_oversized
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let ids = list_folder_sessions(&app_paths, "claude", &project)
            .into_iter()
            .map(|session| session.id)
            .collect::<HashSet<_>>();
        assert_eq!(
            ids,
            HashSet::from(["current".to_string(), "alias".to_string()])
        );

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn claude_repo_registry_fails_closed_for_ambiguous_selected_groups() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let alias_one = tmp.path().join("alias-one");
        let alias_two = tmp.path().join("alias-two");
        let projects = tmp.path().join(".claude").join("projects");
        for (path, id) in [
            (&project, "current"),
            (&alias_one, "alias-one"),
            (&alias_two, "alias-two"),
        ] {
            let bucket = projects.join(encode_claude_cwd(path));
            fs::create_dir_all(&bucket).unwrap();
            fs::write(
                bucket.join(format!("{id}.jsonl")),
                format!("{{\"type\":\"custom-title\",\"sessionId\":\"{id}\"}}\n"),
            )
            .unwrap();
        }
        fs::write(
            tmp.path().join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "githubRepoPaths": {
                    "owner/one": [project.to_string_lossy(), alias_one.to_string_lossy()],
                    "owner/two": [project.to_string_lossy(), alias_two.to_string_lossy()]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "claude", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "current");

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn claude_registered_paths_expand_home_and_reject_relative_or_traversal_paths() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(
            claude_registered_path(tmp.path(), "~/project"),
            Some(tmp.path().join("project"))
        );
        assert_eq!(
            claude_registered_path(tmp.path(), "~"),
            Some(tmp.path().to_path_buf())
        );
        for rejected in [
            "project",
            "../project",
            "~/../project",
            "/tmp/../project",
            "~other/project",
        ] {
            assert_eq!(claude_registered_path(tmp.path(), rejected), None);
        }
    }

    #[test]
    #[cfg(unix)]
    fn claude_symlink_or_non_directory_buckets_never_surface_preview_or_delete_external_history() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let linked_alias = tmp.path().join("linked-alias");
        let file_alias = tmp.path().join("file-alias");
        let projects = tmp.path().join(".claude").join("projects");
        let current_dir = projects.join(encode_claude_cwd(&project));
        fs::create_dir_all(&current_dir).unwrap();
        let current_root = current_dir.join("safe-root.jsonl");
        fs::write(
            &current_root,
            "{\"type\":\"custom-title\",\"sessionId\":\"safe-session\"}\n",
        )
        .unwrap();

        let external = tmp.path().join("external-history");
        fs::create_dir_all(&external).unwrap();
        let external_root = external.join("external-root.jsonl");
        fs::write(
            &external_root,
            concat!(
                "{\"type\":\"custom-title\",\"sessionId\":\"safe-session\"}\n",
                "{\"type\":\"user\",\"message\":{\"content\":\"external secret\"}}\n"
            ),
        )
        .unwrap();
        let external_sidechain = external.join("external-root").join("subagents");
        fs::create_dir_all(&external_sidechain).unwrap();
        fs::write(
            external_sidechain.join("sidechain.jsonl"),
            "{\"type\":\"user\",\"isSidechain\":true}\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&external, projects.join(encode_claude_cwd(&linked_alias)))
            .unwrap();
        fs::write(
            projects.join(encode_claude_cwd(&file_alias)),
            "not a directory",
        )
        .unwrap();
        fs::write(
            tmp.path().join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "githubRepoPaths": {
                    "owner/selected": [
                        project.to_string_lossy(),
                        linked_alias.to_string_lossy(),
                        file_alias.to_string_lossy()
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "claude", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            PathBuf::from(&sessions[0].file_path),
            fs::canonicalize(&current_root).unwrap()
        );
        let preview = preview_folder_session(&app_paths, "claude", &project, "safe-session", 10);
        assert!(preview.iter().all(|line| line.text != "external secret"));
        delete_folder_session(&app_paths, "claude", &project, "safe-session").unwrap();
        assert!(!current_root.exists());
        assert!(external_root.exists());
        assert!(external_sidechain.exists());

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn claude_delete_resolution_does_not_expand_after_registry_changes() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let initial_alias = tmp.path().join("initial-alias");
        let late_alias = tmp.path().join("late-alias");
        let projects = tmp.path().join(".claude").join("projects");
        let current_dir = projects.join(encode_claude_cwd(&project));
        let initial_dir = projects.join(encode_claude_cwd(&initial_alias));
        let late_dir = projects.join(encode_claude_cwd(&late_alias));
        fs::create_dir_all(&current_dir).unwrap();
        fs::create_dir_all(&initial_dir).unwrap();
        fs::create_dir_all(&late_dir).unwrap();
        let current_root = current_dir.join("current.jsonl");
        let initial_root = initial_dir.join("initial.jsonl");
        let late_root = late_dir.join("late.jsonl");
        for root in [&current_root, &initial_root, &late_root] {
            fs::write(
                root,
                "{\"type\":\"custom-title\",\"sessionId\":\"shared-session\"}\n",
            )
            .unwrap();
        }
        let config = tmp.path().join(".claude.json");
        fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "githubRepoPaths": {
                    "owner/selected": [project.to_string_lossy(), initial_alias.to_string_lossy()]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let snapshot = claude_repo_path_candidates(
            std::slice::from_ref(&project),
            &HistoryCancellationToken::new(),
        )
        .unwrap();

        fs::write(
            &config,
            serde_json::to_vec(&serde_json::json!({
                "githubRepoPaths": {
                    "owner/selected": [
                        project.to_string_lossy(),
                        initial_alias.to_string_lossy(),
                        late_alias.to_string_lossy()
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let resolved = claude_files_for_session(
            &current_root,
            &snapshot,
            "shared-session",
            &HistoryCancellationToken::new(),
        )
        .unwrap();
        assert!(resolved.contains(&fs::canonicalize(&current_root).unwrap()));
        assert!(resolved.contains(&fs::canonicalize(&initial_root).unwrap()));
        assert!(!resolved.contains(&fs::canonicalize(&late_root).unwrap()));

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn claude_open_session_state_propagates_across_registered_repo_aliases() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let alias = tmp.path().join("project-old-worktree");
        let alias_dir = tmp
            .path()
            .join(".claude")
            .join("projects")
            .join(encode_claude_cwd(&alias));
        fs::create_dir_all(&alias_dir).unwrap();
        fs::write(
            alias_dir.join("alias-root.jsonl"),
            "{\"type\":\"custom-title\",\"sessionId\":\"alias-session\"}\n",
        )
        .unwrap();
        fs::write(
            tmp.path().join(".claude.json"),
            serde_json::to_vec(&serde_json::json!({
                "githubRepoPaths": {
                    "owner/selected": [project.to_string_lossy(), alias.to_string_lossy()]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let project_record = maestro_shell::records::Project {
            project_id: "project".to_string(),
            name: "Project".to_string(),
            root: project.to_string_lossy().into_owned(),
            default_workspace_policy: maestro_shell::policy::WorkspacePolicy::RepoWrite,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: Vec::new(),
            system: false,
            hidden: false,
        };
        maestro_shell::store::write_record(
            &app_paths,
            RecordKind::Project,
            &project_record.project_id,
            1,
            &project_record,
        )
        .unwrap();
        let workspace_record = maestro_shell::records::Workspace {
            workspace_id: "workspace".to_string(),
            project_id: project_record.project_id.clone(),
            root: alias.to_string_lossy().into_owned(),
            policy: maestro_shell::policy::WorkspacePolicy::RepoWrite,
            consent: maestro_shell::records::WorkspaceConsent::default(),
        };
        maestro_shell::store::write_record(
            &app_paths,
            RecordKind::Workspace,
            &workspace_record.workspace_id,
            1,
            &workspace_record,
        )
        .unwrap();
        let record = SessionRecord {
            session_id: "hydra-alias-session".to_string(),
            workspace_id: "workspace".to_string(),
            kind: maestro_shell::records::SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "claude".to_string(),
                params: vec!["--resume".to_string(), "alias-session".to_string()],
            },
            cwd_resolved: alias.to_string_lossy().into_owned(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: maestro_shell::records::SessionStatus::Live,
        };
        maestro_shell::store::write_record(
            &app_paths,
            RecordKind::Session,
            &record.session_id,
            1,
            &record,
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "claude", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "alias-session");
        assert!(sessions[0].in_use);

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn folder_session_discovery_accepts_raw_and_canonical_selected_folder_spellings() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let real_project = tmp.path().join("real-project");
        let linked_project = tmp.path().join("linked-project");
        fs::create_dir_all(&real_project).unwrap();
        std::os::unix::fs::symlink(&real_project, &linked_project).unwrap();

        let claude_dir = tmp
            .path()
            .join(".claude")
            .join("projects")
            .join(encode_claude_cwd(&linked_project));
        fs::create_dir_all(&claude_dir).unwrap();
        fs::write(
            claude_dir.join("raw-path-session.jsonl"),
            r#"{"type":"user","userType":"external","message":{"content":"raw selected path chat"}}"#,
        )
        .unwrap();

        let codex_dir = tmp.path().join(".codex").join("sessions").join("2026");
        fs::create_dir_all(&codex_dir).unwrap();
        fs::write(
            codex_dir.join("raw-path-codex.jsonl"),
            format!(
                "{}\n{}",
                serde_json::json!({
                    "type": "session_meta",
                    "payload": { "id": "raw-codex", "cwd": linked_project.to_string_lossy() }
                }),
                r#"{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"raw codex cwd chat"}]}}"#,
            ),
        )
        .unwrap();

        let gemini_dir = tmp
            .path()
            .join(".gemini")
            .join("tmp")
            .join("slug")
            .join("chats");
        fs::create_dir_all(&gemini_dir).unwrap();
        fs::write(
            gemini_dir.join("raw-gemini.jsonl"),
            format!(
                "{}\n{}",
                serde_json::json!({
                    "projectHash": gemini_project_hash(&linked_project),
                    "sessionId": "raw-gemini"
                }),
                r#"{"$set":{"messages":[{"type":"user","content":[{"text":"raw gemini cwd chat"}]}]}}"#,
            ),
        )
        .unwrap();

        let claude = list_folder_sessions(&app_paths, "claude", &linked_project);
        assert_eq!(claude.len(), 1);
        assert_eq!(claude[0].id, "raw-path-session");

        let codex = list_folder_sessions(&app_paths, "codex", &linked_project);
        assert_eq!(codex.len(), 1);
        assert_eq!(codex[0].id, "raw-codex");

        let gemini = list_folder_sessions(&app_paths, "gemini", &linked_project);
        assert_eq!(gemini.len(), 1);
        assert_eq!(gemini[0].id, "raw-gemini");

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn codex_session_discovery_filters_global_store_by_cwd_metadata() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = tmp.path().join("project");
        let other_project = tmp.path().join("other-project");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(&other_project).unwrap();
        let project = normalize_cwd(&project);
        let other_project = normalize_cwd(&other_project);
        let codex_dir = tmp.path().join(".codex").join("sessions").join("2026");
        fs::create_dir_all(&codex_dir).unwrap();
        fs::write(
            codex_dir.join("selected.jsonl"),
            format!(
                "{}\n{}",
                serde_json::json!({
                    "type": "session_meta",
                    "payload": { "id": "selected-thread", "cwd": project.to_string_lossy() }
                }),
                r#"{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"selected cwd chat"}]}}"#,
            ),
        )
        .unwrap();
        fs::write(
            codex_dir.join("other.jsonl"),
            format!(
                "{}\n{}",
                serde_json::json!({
                    "type": "session_meta",
                    "payload": { "id": "other-thread", "cwd": other_project.to_string_lossy() }
                }),
                r#"{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"other cwd chat"}]}}"#,
            ),
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "codex", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "selected-thread");
        assert_eq!(sessions[0].first_message, "Codex session selected");

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn gemini_listing_reads_only_bounded_metadata_and_groups_by_session_id() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let chats = tmp.path().join(".gemini/tmp/slug/chats");
        fs::create_dir_all(&chats).unwrap();
        let project_hash = gemini_project_hash(&project);
        let id = "grouped-gemini";
        let older = chats.join("older.jsonl");
        fs::write(
            &older,
            format!(
                "{}\n{}\n",
                serde_json::json!({"projectHash": project_hash, "sessionId": id}),
                r#"{"$set":{"messages":[{"type":"user","content":[{"text":"PRIVATE OLDER BODY"}]}]}}"#,
            ),
        )
        .unwrap();
        std::thread::sleep(Duration::from_millis(20));
        let newer = chats.join("newer.jsonl");
        let mut newer_bytes = format!(
            "{}\n",
            serde_json::json!({"projectHash": project_hash, "sessionId": id})
        )
        .into_bytes();
        newer_bytes.extend(std::iter::repeat_n(b'x', 1024 * 1024));
        fs::write(&newer, newer_bytes).unwrap();
        fs::write(
            chats.join("oversized-meta.jsonl"),
            format!(
                "{{\"projectHash\":\"{project_hash}\",\"sessionId\":\"oversized\",\"padding\":\"{}\"}}\n",
                "x".repeat(GEMINI_SESSION_META_MAX_BYTES)
            ),
        )
        .unwrap();
        #[cfg(unix)]
        {
            let external = tmp.path().join("external-gemini.jsonl");
            fs::write(
                &external,
                format!(
                    "{}\n",
                    serde_json::json!({
                        "projectHash": project_hash,
                        "sessionId": "symlinked-gemini"
                    })
                ),
            )
            .unwrap();
            std::os::unix::fs::symlink(&external, chats.join("symlinked.jsonl")).unwrap();
        }

        let sessions = list_folder_sessions(&app_paths, "gemini", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, id);
        assert_eq!(sessions[0].file_path, newer.to_string_lossy());
        assert_eq!(sessions[0].message_count, None);
        assert_eq!(sessions[0].first_message, "Gemini session grouped-");
        let serialized = serde_json::to_string(&sessions).unwrap();
        assert!(!serialized.contains("PRIVATE OLDER BODY"));
        assert!(!serialized.contains("oversized"));

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn codex_listing_groups_continuations_under_the_interactive_root() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = normalize_cwd(&{
            let project = tmp.path().join("project");
            fs::create_dir_all(&project).unwrap();
            project
        });
        let codex_dir = tmp.path().join(".codex").join("sessions").join("2026");
        fs::create_dir_all(&codex_dir).unwrap();

        let write_session =
            |name: &str, id: &str, session_id: Option<&str>, source: Option<Value>| {
                let mut payload = serde_json::Map::from_iter([
                    ("id".to_string(), Value::String(id.to_string())),
                    (
                        "cwd".to_string(),
                        Value::String(project.to_string_lossy().into_owned()),
                    ),
                ]);
                if let Some(source) = source {
                    payload.insert("source".to_string(), source);
                }
                if let Some(session_id) = session_id {
                    payload.insert(
                        "session_id".to_string(),
                        Value::String(session_id.to_string()),
                    );
                }
                let path = codex_dir.join(name);
                fs::write(
                    &path,
                    format!(
                        "{}\n{}\n",
                        serde_json::json!({"type": "session_meta", "payload": payload}),
                        serde_json::json!({
                            "type": "response_item",
                            "payload": {
                                "type": "message", "role": "user",
                                "content": [{"type": "input_text", "text": format!("message {id}")}]
                            }
                        })
                    ),
                )
                .unwrap();
                path
            };

        write_session("legacy.jsonl", "legacy-root", None, None);
        let large_cli = write_session(
            "cli.jsonl",
            "cli-root",
            Some("cli-root"),
            Some(Value::String("cli".to_string())),
        );
        fs::OpenOptions::new()
            .write(true)
            .open(&large_cli)
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();
        write_session(
            "vscode.jsonl",
            "vscode-root",
            None,
            Some(Value::String("vscode".to_string())),
        );
        write_session(
            "exec.jsonl",
            "exec-thread",
            None,
            Some(Value::String("exec".to_string())),
        );
        std::thread::sleep(Duration::from_millis(10));
        let continuation = write_session(
            "continuation.jsonl",
            "rollout-fragment",
            Some("cli-root"),
            Some(serde_json::json!({
                "subagent": {"thread_spawn": {"parent_thread_id": "cli-root"}}
            })),
        );
        fs::OpenOptions::new()
            .write(true)
            .open(&continuation)
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();
        std::thread::sleep(Duration::from_millis(10));
        let legacy_continuation = write_session(
            "legacy-continuation.jsonl",
            "legacy-rollout-fragment",
            None,
            Some(serde_json::json!({
                "subagent": {"thread_spawn": {"parent_thread_id": "cli-root"}}
            })),
        );
        write_session(
            "orphan-subagent.jsonl",
            "orphan-subagent",
            None,
            Some(serde_json::json!({"subagent": {"thread_spawn": {}}})),
        );

        let sessions = list_folder_sessions(&app_paths, "codex", &project);
        let ids = sessions
            .iter()
            .map(|session| session.id.as_str())
            .collect::<HashSet<_>>();
        assert_eq!(
            ids,
            HashSet::from(["legacy-root", "cli-root", "vscode-root"])
        );
        assert_eq!(sessions.len(), 3, "continuations are not separate rows");
        let cli = sessions
            .iter()
            .find(|session| session.id == "cli-root")
            .unwrap();
        assert_eq!(cli.file_path, large_cli.to_string_lossy());
        assert_eq!(
            cli.modified_at_ms,
            modified_at_ms(&legacy_continuation),
            "root identity is retained while newest continuation supplies recency"
        );
        assert!(sessions
            .iter()
            .all(|session| session.message_count.is_none()));
        let project_record = maestro_shell::records::Project {
            project_id: "project".to_string(),
            name: "Project".to_string(),
            root: project.to_string_lossy().into_owned(),
            default_workspace_policy: maestro_shell::policy::WorkspacePolicy::RepoWrite,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: Vec::new(),
            system: false,
            hidden: false,
        };
        maestro_shell::store::write_record(
            &app_paths,
            RecordKind::Project,
            &project_record.project_id,
            1,
            &project_record,
        )
        .unwrap();
        let workspace_record = maestro_shell::records::Workspace {
            workspace_id: "workspace".to_string(),
            project_id: project_record.project_id.clone(),
            root: project.to_string_lossy().into_owned(),
            policy: maestro_shell::policy::WorkspacePolicy::RepoWrite,
            consent: maestro_shell::records::WorkspaceConsent::default(),
        };
        maestro_shell::store::write_record(
            &app_paths,
            RecordKind::Workspace,
            &workspace_record.workspace_id,
            1,
            &workspace_record,
        )
        .unwrap();
        let open_record = SessionRecord {
            session_id: "hydra-open-codex".to_string(),
            workspace_id: "workspace".to_string(),
            kind: maestro_shell::records::SessionKind::Agent,
            launch: LaunchSpec::AdHocRedacted {
                argv: vec![
                    "codex".to_string(),
                    "resume".to_string(),
                    "cli-root".to_string(),
                ],
                redacted: false,
                restart_requires_user: false,
            },
            cwd_resolved: project.to_string_lossy().into_owned(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: maestro_shell::records::SessionStatus::Live,
        };
        maestro_shell::store::write_record(
            &app_paths,
            RecordKind::Session,
            &open_record.session_id,
            1,
            &open_record,
        )
        .unwrap();
        set_folder_session_name(&app_paths, "codex", "cli-root", Some("Keep while open")).unwrap();
        hide_folder_session(&app_paths, "codex", "cli-root").unwrap();
        let error = delete_folder_session(&app_paths, "codex", &project, "cli-root")
            .expect_err("an in-use provider session must not be deleted");
        assert!(error.contains("open in a Hydra pane"));
        assert!(large_cli.exists() && continuation.exists() && legacy_continuation.exists());
        let still_hidden = list_hidden_folder_sessions(&app_paths, "codex", &project);
        assert_eq!(still_hidden.len(), 1);
        assert_eq!(
            still_hidden[0].custom_name.as_deref(),
            Some("Keep while open")
        );
        maestro_shell::store::delete_record(
            &app_paths,
            RecordKind::Session,
            &open_record.session_id,
        )
        .unwrap();
        let corrupt = codex_dir.join("corrupt.jsonl");
        fs::write(&corrupt, "not-json\n").unwrap();
        assert!(
            delete_folder_session(&app_paths, "codex", &project, "cli-root").is_err(),
            "delete must fail closed before removing a partial Codex group"
        );
        assert!(large_cli.exists() && continuation.exists() && legacy_continuation.exists());
        fs::remove_file(corrupt).unwrap();
        delete_folder_session(&app_paths, "codex", &project, "cli-root").unwrap();
        assert!(!large_cli.exists(), "delete removes the resumable root");
        assert!(
            !continuation.exists(),
            "delete removes every grouped compaction continuation"
        );
        assert!(
            !legacy_continuation.exists(),
            "delete groups the legacy parent_thread_id continuation too"
        );

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn codex_listing_reads_only_the_session_meta_line() {
        let project = PathBuf::from("/tmp/hydra-codex-project");
        let transcript = format!(
            "{}\n\nnot-json\n{}\n{}\n{}\n",
            serde_json::json!({
                "type": "session_meta",
                "payload": { "id": "thread-1", "cwd": project }
            }),
            serde_json::json!({
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{ "type": "input_text", "text": "<environment_context>hidden" }]
                }
            }),
            serde_json::json!({
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{ "type": "input_text", "text": "first visible message" }]
                }
            }),
            serde_json::json!({
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [{ "type": "output_text", "text": "answer" }]
                }
            })
        );
        let mut reader = std::io::Cursor::new(transcript.into_bytes());

        let session = read_codex_session(&mut reader, std::slice::from_ref(&project))
            .unwrap()
            .unwrap();

        assert_eq!(session.id, "thread-1");
        assert_eq!(session.first_message, "Codex session thread-1");
    }

    #[test]
    fn codex_folder_listing_fails_closed_when_root_cwd_is_missing() {
        let project = PathBuf::from("/tmp/hydra-codex-project");
        let transcript = format!(
            "{}\n",
            serde_json::json!({
                "type": "session_meta",
                "payload": { "id": "unscoped-thread", "source": "cli" }
            })
        );
        let mut reader = std::io::Cursor::new(transcript.into_bytes());

        assert!(
            read_codex_session(&mut reader, std::slice::from_ref(&project))
                .unwrap()
                .is_none(),
            "an unscoped root must not appear in every folder"
        );
    }

    #[test]
    fn nonmatching_codex_session_does_not_consume_large_invalid_tail() {
        struct HeaderThenInvalidTail {
            header: Vec<u8>,
            position: usize,
            tail_touched: bool,
            tail_delivered: bool,
        }

        impl Read for HeaderThenInvalidTail {
            fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
                let copied = {
                    let available = self.fill_buf()?;
                    let copied = available.len().min(destination.len());
                    destination[..copied].copy_from_slice(&available[..copied]);
                    copied
                };
                self.consume(copied);
                Ok(copied)
            }
        }

        impl BufRead for HeaderThenInvalidTail {
            fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
                if self.position < self.header.len() {
                    return Ok(&self.header[self.position..]);
                }
                self.tail_touched = true;
                // This represents the start of an arbitrarily large tail. If the folder check reads
                // it, UTF-8 decoding fails; a rejected header must return before asking for it.
                if self.tail_delivered {
                    Ok(&[])
                } else {
                    Ok(&[0xff])
                }
            }

            fn consume(&mut self, amount: usize) {
                if self.position < self.header.len() {
                    self.position = (self.position + amount).min(self.header.len());
                } else if amount > 0 {
                    self.tail_delivered = true;
                }
            }
        }

        let selected = PathBuf::from("/tmp/selected-project");
        let other = PathBuf::from("/tmp/other-project");
        let header = format!(
            "\n{}\n",
            serde_json::json!({
                "type": "session_meta",
                "payload": { "id": "other-thread", "cwd": other }
            })
        )
        .into_bytes();
        let mut reader = HeaderThenInvalidTail {
            header,
            position: 0,
            tail_touched: false,
            tail_delivered: false,
        };

        assert!(read_codex_session(&mut reader, &[selected])
            .unwrap()
            .is_none());
        assert!(!reader.tail_touched);
    }

    #[test]
    fn matching_codex_session_never_reads_its_transcript_body() {
        struct HeaderThenForbiddenTail {
            header: Vec<u8>,
            position: usize,
            tail_touched: bool,
        }

        impl Read for HeaderThenForbiddenTail {
            fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
                let copied = {
                    let available = self.fill_buf()?;
                    let copied = available.len().min(destination.len());
                    destination[..copied].copy_from_slice(&available[..copied]);
                    copied
                };
                self.consume(copied);
                Ok(copied)
            }
        }

        impl BufRead for HeaderThenForbiddenTail {
            fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
                if self.position < self.header.len() {
                    Ok(&self.header[self.position..])
                } else {
                    self.tail_touched = true;
                    Ok(&[0xff])
                }
            }

            fn consume(&mut self, amount: usize) {
                self.position = (self.position + amount).min(self.header.len());
            }
        }

        let project = PathBuf::from("/tmp/hydra-codex-bounded-project");
        let header = format!(
            "{}\n{}\n",
            serde_json::json!({
                "type": "session_meta",
                "payload": {"id": "bounded-thread", "cwd": project, "source": "cli"}
            }),
            serde_json::json!({
                "type": "response_item",
                "payload": {
                    "type": "message", "role": "user",
                    "content": [{"type": "input_text", "text": "first and enough"}]
                }
            })
        )
        .into_bytes();
        let mut reader = HeaderThenForbiddenTail {
            header,
            position: 0,
            tail_touched: false,
        };

        let session = read_codex_session(&mut reader, std::slice::from_ref(&project))
            .unwrap()
            .unwrap();
        assert_eq!(session.first_message, "Codex session bounded-");
        assert!(
            reader.position < reader.header.len(),
            "listing must stop after session_meta"
        );
        assert!(
            !reader.tail_touched,
            "listing must not inspect the remaining body"
        );
    }

    #[test]
    fn bounded_reads_observe_cancellation_between_chunks() {
        struct CancellingChunks {
            chunk: Vec<u8>,
            emitted: bool,
            cancellation: HistoryCancellationToken,
        }

        impl Read for CancellingChunks {
            fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
                let copied = {
                    let available = self.fill_buf()?;
                    let copied = available.len().min(destination.len());
                    destination[..copied].copy_from_slice(&available[..copied]);
                    copied
                };
                self.consume(copied);
                Ok(copied)
            }
        }

        impl BufRead for CancellingChunks {
            fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
                if self.emitted {
                    Ok(&[])
                } else {
                    Ok(&self.chunk)
                }
            }

            fn consume(&mut self, amount: usize) {
                if amount > 0 {
                    self.emitted = true;
                    self.cancellation.cancel();
                }
            }
        }

        let cancellation = HistoryCancellationToken::new();
        let mut reader = CancellingChunks {
            chunk: vec![b'x'; HISTORY_READ_CHUNK_BYTES],
            emitted: false,
            cancellation: cancellation.clone(),
        };
        assert!(matches!(
            read_bounded_line(&mut reader, HISTORY_READ_CHUNK_BYTES * 2, &cancellation),
            Err(BoundedReadFailure::Cancelled)
        ));

        let cancellation = HistoryCancellationToken::new();
        let mut reader = CancellingChunks {
            chunk: vec![b'x'; HISTORY_READ_CHUNK_BYTES],
            emitted: false,
            cancellation: cancellation.clone(),
        };
        assert_eq!(
            read_bytes_with_cancel(&mut reader, None, &cancellation),
            Err(HistoryScanCancelled),
            "the shared file primitive must stop between 8 KiB reads"
        );
    }

    #[test]
    fn sqlite_progress_handler_interrupts_work_before_the_first_row() {
        let connection = rusqlite::Connection::open_in_memory().unwrap();
        let cancellation = HistoryCancellationToken::new();
        install_sqlite_cancellation(&connection, &cancellation);

        let cancel_from_worker = cancellation.clone();
        let worker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            cancel_from_worker.cancel();
        });
        let result = connection.query_row(
            "WITH RECURSIVE count(x) AS (
                 VALUES(0)
                 UNION ALL
                 SELECT x + 1 FROM count WHERE x < 100000000
             )
             SELECT sum(x) FROM count",
            [],
            |row| row.get::<_, i64>(0),
        );
        worker.join().unwrap();

        assert!(cancellation.is_cancelled());
        assert!(result.is_err(), "the long query must be interrupted");
    }

    #[test]
    fn dispatcher_propagates_cancellation_to_every_newly_wired_provider() {
        let cancellation = HistoryCancellationToken::new();
        cancellation.cancel();
        let cwd_candidates = Vec::new();
        let open_provider_sessions = HashSet::new();

        for agent in [
            "antigravity",
            "copilot",
            "cursor",
            "devin",
            "gemini",
            "kimi",
            "kiro",
            "opencode",
        ] {
            assert!(
                matches!(
                    list_provider_sessions(
                        agent,
                        &cwd_candidates,
                        &cwd_candidates,
                        &open_provider_sessions,
                        &cancellation,
                    ),
                    Err(HistoryScanCancelled)
                ),
                "{agent} must receive the dispatcher's cancellation token"
            );
        }
    }

    #[test]
    fn provider_directory_enumeration_has_one_global_budget() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("history");
        fs::create_dir_all(&root).unwrap();
        for index in 0..4 {
            fs::write(root.join(format!("{index}.jsonl")), b"{}\n").unwrap();
        }

        let cancellation = HistoryCancellationToken::new();
        let mut listed = Vec::new();
        let mut list_budget = HistoryEnumerationBudget { remaining: 2 };
        walk_jsonl_with_budget(&root, 0, &mut listed, &cancellation, &mut list_budget).unwrap();
        assert_eq!(listed.len(), 2, "listing must stop at its global budget");
        assert!(list_budget.exhausted());

        let mut delete_candidates = Vec::new();
        let mut delete_budget = HistoryEnumerationBudget { remaining: 2 };
        let error = walk_jsonl_strict_with_budget(
            &root,
            0,
            &mut delete_candidates,
            &cancellation,
            &mut delete_budget,
        )
        .unwrap_err();
        assert!(error.contains("enumeration exceeds"));
        assert_eq!(
            delete_candidates.len(),
            2,
            "destructive discovery must halt before an unbounded traversal"
        );
    }

    #[test]
    fn shared_provider_result_boundary_keeps_only_newest_rows() {
        let mut sessions = (0..=PROVIDER_HISTORY_RESULT_MAX_COUNT)
            .map(|index| AgentHistorySession {
                id: format!("session-{index}"),
                agent: "codex".to_string(),
                title: String::new(),
                first_message: String::new(),
                modified_at_ms: index as u64,
                message_count: None,
                folder_index: 0,
                file_path: String::new(),
                in_use: false,
                custom_name: None,
            })
            .collect::<Vec<_>>();

        bound_provider_history_results(&mut sessions);
        assert_eq!(sessions.len(), PROVIDER_HISTORY_RESULT_MAX_COUNT);
        assert_eq!(
            sessions.first().map(|session| session.modified_at_ms),
            Some(PROVIDER_HISTORY_RESULT_MAX_COUNT as u64)
        );
        assert_eq!(
            sessions.last().map(|session| session.modified_at_ms),
            Some(1)
        );
    }

    #[test]
    fn every_provider_preview_helper_uses_the_callers_token() {
        let cancellation = HistoryCancellationToken::new();
        cancellation.cancel();
        let session = AgentHistorySession {
            id: "cancelled".to_string(),
            agent: "antigravity".to_string(),
            title: String::new(),
            first_message: String::new(),
            modified_at_ms: 0,
            message_count: None,
            folder_index: 0,
            file_path: String::new(),
            in_use: false,
            custom_name: None,
        };

        for (provider, result) in [
            (
                "copilot",
                preview_copilot_session("cancelled", 1, &cancellation),
            ),
            (
                "antigravity",
                preview_antigravity_session(&session, 1, &cancellation),
            ),
            ("kimi", preview_kimi_session("cancelled", 1, &cancellation)),
            ("kiro", preview_kiro_session("cancelled", 1, &cancellation)),
            (
                "cursor",
                preview_cursor_session(Path::new("/tmp"), "cancelled", 1, &cancellation),
            ),
            (
                "devin",
                preview_devin_session("cancelled", 1, &cancellation),
            ),
        ] {
            assert_eq!(
                result.unwrap_err(),
                HistoryScanCancelled,
                "{provider} preview must not replace the caller's cancellation token"
            );
        }
    }

    #[test]
    fn preview_stops_at_requested_lines_in_a_sparse_large_transcript() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("large-codex.jsonl");
        fs::write(
            &path,
            format!(
                "{}\n{}\n",
                serde_json::json!({
                    "type": "session_meta",
                    "payload": {"id": "preview-thread", "cwd": "/tmp", "source": "cli"}
                }),
                serde_json::json!({
                    "type": "response_item",
                    "payload": {
                        "type": "message", "role": "user",
                        "content": [{"type": "input_text", "text": "bounded preview"}]
                    }
                })
            ),
        )
        .unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(1024 * 1024 * 1024)
            .unwrap();

        let preview =
            preview_session_file_with_cancel("codex", &path, 1, &HistoryCancellationToken::new())
                .unwrap();
        assert_eq!(preview.len(), 1);
        assert_eq!(preview[0].text, "bounded preview");
    }

    #[test]
    fn transcript_previews_surface_only_user_and_assistant_visible_text() {
        let tmp = TempDir::new().unwrap();
        let cancellation = HistoryCancellationToken::new();
        let fixtures = [
            (
                "claude",
                vec![
                    serde_json::json!({"type":"system","message":{"content":"PRIVATE CLAUDE SYSTEM"}}),
                    serde_json::json!({"type":"user","userType":"internal","message":{"content":"PRIVATE CLAUDE INTERNAL"}}),
                    serde_json::json!({"type":"user","userType":"external","message":{"role":"user","content":[{"type":"tool_result","text":"PRIVATE CLAUDE TOOL"},{"type":"text","text":"visible claude user"}]}}),
                    serde_json::json!({"type":"assistant","message":{"role":"assistant","content":[{"type":"thinking","text":"PRIVATE CLAUDE THINKING"},{"type":"text","text":"visible claude assistant"},{"type":"tool_use","text":"PRIVATE CLAUDE CALL"}]}}),
                    serde_json::json!({"type":"user","userType":"external","isMeta":true,"message":{"content":"PRIVATE CLAUDE META"}}),
                ],
                vec!["visible claude user", "visible claude assistant"],
            ),
            (
                "codex",
                vec![
                    serde_json::json!({"type":"response_item","payload":{"type":"message","role":"developer","content":[{"type":"input_text","text":"PRIVATE CODEX DEVELOPER"}]}}),
                    serde_json::json!({"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"tool_result","text":"PRIVATE CODEX TOOL"},{"type":"input_text","text":"visible codex user"}]}}),
                    serde_json::json!({"type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"reasoning","text":"PRIVATE CODEX REASONING"},{"type":"output_text","text":"visible codex assistant"}]}}),
                ],
                vec!["visible codex user", "visible codex assistant"],
            ),
            (
                "gemini",
                vec![serde_json::json!({"$set":{"messages":[
                    {"type":"system","content":[{"text":"PRIVATE GEMINI SYSTEM"}]},
                    {"type":"tool","content":[{"text":"PRIVATE GEMINI TOOL"}]},
                    {"type":"user","content":[{"thought":true,"text":"PRIVATE GEMINI THOUGHT"},{"type":"tool_result","text":"PRIVATE GEMINI RESULT"},{"text":"visible gemini user"}]},
                    {"type":"assistant","content":[{"thought":true,"text":"PRIVATE GEMINI REASONING"},{"type":"text","text":"visible gemini assistant"}]}
                ]}})],
                vec!["visible gemini user", "visible gemini assistant"],
            ),
        ];

        for (agent, events, expected) in fixtures {
            let path = tmp.path().join(format!("{agent}.jsonl"));
            let body = events
                .into_iter()
                .map(|event| serde_json::to_string(&event).unwrap())
                .collect::<Vec<_>>()
                .join("\n");
            fs::write(&path, format!("{body}\n")).unwrap();

            let preview =
                preview_session_file_with_cancel(agent, &path, 20, &cancellation).unwrap();
            assert_eq!(
                preview
                    .iter()
                    .map(|line| line.text.as_str())
                    .collect::<Vec<_>>(),
                expected,
                "{agent} preview must expose only interactive visible text"
            );
            let encoded = serde_json::to_string(&preview).unwrap();
            assert!(
                !encoded.contains("PRIVATE"),
                "{agent} preview leaked provider-internal content: {encoded}"
            );
        }
    }

    #[test]
    fn partition_and_preview_share_one_visible_hidden_enumeration_contract() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = normalize_cwd(&{
            let project = tmp.path().join("project");
            fs::create_dir_all(&project).unwrap();
            project
        });
        let codex_dir = tmp.path().join(".codex").join("sessions").join("2026");
        fs::create_dir_all(&codex_dir).unwrap();
        for id in ["visible-thread", "hidden-thread"] {
            fs::write(
                codex_dir.join(format!("{id}.jsonl")),
                format!(
                    "{}\n{}\n",
                    serde_json::json!({
                        "type": "session_meta",
                        "payload": {"id": id, "cwd": project, "source": "cli"}
                    }),
                    serde_json::json!({
                        "type": "response_item",
                        "payload": {
                            "type": "message", "role": "user",
                            "content": [{"type": "input_text", "text": id}]
                        }
                    })
                ),
            )
            .unwrap();
        }
        hide_folder_session(&app_paths, "codex", "hidden-thread").unwrap();

        let partition = list_folder_sessions_partitioned(&app_paths, "codex", &project);
        assert_eq!(partition.visible.len(), 1);
        assert_eq!(partition.visible[0].id, "visible-thread");
        assert_eq!(partition.hidden.len(), 1);
        assert_eq!(partition.hidden[0].id, "hidden-thread");
        let preview = preview_folder_session_with_cancel(
            &app_paths,
            "codex",
            &project,
            "hidden-thread",
            1,
            &HistoryCancellationToken::new(),
        )
        .unwrap();
        assert_eq!(preview.len(), 1);
        assert_eq!(preview[0].text, "hidden-thread");

        let cancelled = HistoryCancellationToken::new();
        cancelled.cancel();
        assert_eq!(
            list_folder_sessions_partitioned_with_cancel(&app_paths, "codex", &project, &cancelled)
                .unwrap_err(),
            HistoryScanCancelled
        );
        let hidden_path = codex_dir.join("hidden-thread.jsonl");
        assert!(delete_folder_session_with_cancel(
            &app_paths,
            "codex",
            &project,
            "hidden-thread",
            &cancelled,
        )
        .unwrap_err()
        .contains("cancelled"));
        assert!(
            hidden_path.exists(),
            "cancellation must win before destructive removal"
        );
        delete_folder_session_with_cancel(
            &app_paths,
            "codex",
            &project,
            "hidden-thread",
            &HistoryCancellationToken::new(),
        )
        .unwrap();
        assert!(
            !hidden_path.exists(),
            "a surfaced hidden session is a valid explicit delete target"
        );

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn permanent_delete_fails_closed_for_unproven_provider_boundaries() {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let cwd = tmp.path().join("project");
        fs::create_dir_all(&cwd).unwrap();

        for (agent, session_id) in [
            ("gemini", "provider-session"),
            ("opencode", "provider-session"),
            ("copilot", "11111111-2222-4333-8444-555555555555"),
            ("antigravity", "11111111-2222-4333-8444-555555555555"),
        ] {
            let error = delete_folder_session(&paths, agent, &cwd, session_id)
                .expect_err("native authority must reject incomplete provider deletion");
            assert!(error.contains("complete deletion boundary is not proven"));
        }
    }

    #[test]
    fn opencode_session_discovery_reads_sqlite_metadata_by_directory() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let p = tmp.path().join("project");
            fs::create_dir_all(&p).unwrap();
            p
        });
        let other_project = normalize_cwd(&{
            let p = tmp.path().join("other-project");
            fs::create_dir_all(&p).unwrap();
            p
        });
        let opencode_dir = tmp.path().join(".local").join("share").join("opencode");
        fs::create_dir_all(&opencode_dir).unwrap();
        let conn = rusqlite::Connection::open(opencode_dir.join("opencode.db")).unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE session (
              id text PRIMARY KEY,
              project_id text NOT NULL,
              slug text NOT NULL,
              directory text NOT NULL,
              title text NOT NULL,
              version text NOT NULL,
              metadata text,
              cost real DEFAULT 0 NOT NULL,
              tokens_input integer DEFAULT 0 NOT NULL,
              tokens_output integer DEFAULT 0 NOT NULL,
              tokens_reasoning integer DEFAULT 0 NOT NULL,
              tokens_cache_read integer DEFAULT 0 NOT NULL,
              tokens_cache_write integer DEFAULT 0 NOT NULL,
              agent text,
              model text,
              time_created integer NOT NULL,
              time_updated integer NOT NULL,
              time_archived integer
            );
            "#,
        )
        .unwrap();
        conn.execute(
            "INSERT INTO session (id, project_id, slug, directory, title, version, agent, model, time_created, time_updated)
             VALUES (?1, 'p', 's', ?2, 'Greeting', '1.17.15', 'build', ?3, 10, 20)",
            (
                "ses_selected",
                project.to_string_lossy().as_ref(),
                r#"{"id":"hy3-free","providerID":"opencode","variant":"high"}"#,
            ),
        )
        .unwrap();
        conn.execute(
            "INSERT INTO session (id, project_id, slug, directory, title, version, agent, model, time_created, time_updated)
             VALUES (?1, 'p', 's', ?2, 'Other', '1.17.15', 'build', ?3, 10, 30)",
            (
                "ses_other",
                other_project.to_string_lossy().as_ref(),
                r#"{"id":"other","providerID":"opencode"}"#,
            ),
        )
        .unwrap();
        drop(conn);

        let sessions = list_folder_sessions(&app_paths, "opencode", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, "ses_selected");
        assert_eq!(sessions[0].agent, "opencode");
        assert!(sessions[0].first_message.contains("opencode/hy3-free:high"));
        assert_eq!(sessions[0].file_path, "opencode://ses_selected");

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn opencode_modern_schema_filters_children_and_caps_selected_strings() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let opencode_dir = tmp.path().join(".local/share/opencode");
        fs::create_dir_all(&opencode_dir).unwrap();
        let connection = rusqlite::Connection::open(opencode_dir.join("opencode.db")).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE session (
                  id TEXT PRIMARY KEY, parent_id TEXT, directory TEXT NOT NULL,
                  title TEXT NOT NULL, agent TEXT, model TEXT,
                  time_updated INTEGER NOT NULL, time_archived INTEGER
                );
                "#,
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO session VALUES ('ses_root',NULL,?1,'Root','build','{}',30,NULL)",
                [project.to_string_lossy().as_ref()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO session VALUES ('ses_child','ses_root',?1,'Child','build','{}',40,NULL)",
                [project.to_string_lossy().as_ref()],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO session VALUES ('ses_oversized',NULL,?1,?2,?3,?4,20,NULL)",
                rusqlite::params![
                    project.to_string_lossy().as_ref(),
                    "é".repeat(OPENCODE_TITLE_MAX_BYTES),
                    "é".repeat(OPENCODE_AGENT_MAX_BYTES),
                    "é".repeat(OPENCODE_MODEL_MAX_BYTES),
                ],
            )
            .unwrap();
        drop(connection);

        let sessions = list_folder_sessions(&app_paths, "opencode", &project);
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().any(|session| session.id == "ses_root"));
        assert!(!sessions.iter().any(|session| session.id == "ses_child"));
        let oversized = sessions
            .iter()
            .find(|session| session.id == "ses_oversized")
            .unwrap();
        assert_eq!(oversized.title, "OpenCode (session)");
        assert_eq!(oversized.first_message, "OpenCode · model unknown");
        assert!(!serde_json::to_string(&sessions)
            .unwrap()
            .contains(&"é".repeat(64)));

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn copilot_history_is_folder_scoped_private_and_provider_managed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project with spaces");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let other = normalize_cwd(&{
            let path = tmp.path().join("other");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let copilot = tmp.path().join(".copilot");
        fs::create_dir_all(&copilot).unwrap();
        let connection = rusqlite::Connection::open(copilot.join("session-store.db")).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE sessions (
                  id TEXT PRIMARY KEY, cwd TEXT, repository TEXT, host_type TEXT, branch TEXT,
                  summary TEXT, created_at TEXT, updated_at TEXT
                );
                CREATE TABLE turns (
                  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL,
                  turn_index INTEGER NOT NULL, user_message TEXT, assistant_response TEXT,
                  timestamp TEXT
                );
                "#,
            )
            .unwrap();
        let selected = "20000000-0000-4000-8000-000000000001";
        let other_id = "20000000-0000-4000-8000-000000000002";
        connection
            .execute(
                "INSERT INTO sessions (id,cwd,summary,created_at,updated_at) VALUES (?1,?2,'Fix dashboard','2026-07-18 08:00:00','2026-07-18 08:01:00')",
                (selected, project.to_string_lossy().as_ref()),
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO sessions (id,cwd,summary,created_at,updated_at) VALUES (?1,?2,'Other','2026-07-18 08:00:00','2026-07-18 08:02:00')",
                (other_id, other.to_string_lossy().as_ref()),
            )
            .unwrap();
        let oversized_id = "20000000-0000-4000-8000-000000000003";
        connection
            .execute(
                "INSERT INTO sessions (id,cwd,summary,created_at,updated_at) VALUES (?1,?2,?3,'2026-07-18 07:00:00','2026-07-18 07:01:00')",
                rusqlite::params![
                    oversized_id,
                    project.to_string_lossy().as_ref(),
                    "é".repeat(COPILOT_SUMMARY_MAX_BYTES),
                ],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO turns (session_id,turn_index,user_message,assistant_response,timestamp) VALUES (?1,0,'inspect the renderer','done','2026-07-18 08:01:00')",
                [selected],
            )
            .unwrap();
        connection.execute("DROP TABLE turns", []).unwrap();
        drop(connection);

        let state = copilot.join("session-state").join(selected);
        fs::create_dir_all(&state).unwrap();
        fs::write(
            state.join("events.jsonl"),
            [
                serde_json::json!({"type":"system.message","data":{"content":"PRIVATE SYSTEM"}}),
                serde_json::json!({"type":"user.message","data":{"content":"inspect the renderer","transformedContent":"PRIVATE TRANSFORM"}}),
                serde_json::json!({"type":"assistant.message","data":{"content":[{"text":"I found the issue"}],"encryptedContent":"PRIVATE ENCRYPTED"}}),
                serde_json::json!({"type":"hook.end","data":{"content":"PRIVATE TOOL"}}),
            ]
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
        )
        .unwrap();
        fs::write(
            state.join(format!("inuse.{}.lock", std::process::id())),
            std::process::id().to_string(),
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "copilot", &project);
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, selected);
        assert_eq!(sessions[0].file_path, format!("copilot://{selected}"));
        assert_eq!(sessions[0].first_message, "Fix dashboard");
        assert_eq!(sessions[0].message_count, None);
        assert!(sessions[0].in_use);
        let oversized = sessions
            .iter()
            .find(|session| session.id == oversized_id)
            .unwrap();
        assert_eq!(oversized.title, "Copilot session");
        assert_eq!(oversized.message_count, None);
        let preview = preview_folder_session(&app_paths, "copilot", &project, selected, 20);
        assert_eq!(preview.len(), 2);
        assert_eq!(preview[0].role, "user");
        assert_eq!(preview[0].text, "inspect the renderer");
        assert_eq!(preview[1].role, "assistant");
        assert_eq!(preview[1].text, "I found the issue");
        let serialized = serde_json::to_string(&preview).unwrap();
        for private in [
            "PRIVATE SYSTEM",
            "PRIVATE TRANSFORM",
            "PRIVATE ENCRYPTED",
            "PRIVATE TOOL",
        ] {
            assert!(!serialized.contains(private));
        }
        assert!(
            delete_folder_session(&app_paths, "copilot", &project, selected)
                .unwrap_err()
                .contains("managed by the provider")
        );
        assert!(state.join("events.jsonl").exists());

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn antigravity_history_uses_summary_index_and_decodes_workspace_uri() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project with spaces");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let state = tmp.path().join(".gemini").join("antigravity-cli");
        fs::create_dir_all(&state).unwrap();
        let connection =
            rusqlite::Connection::open(state.join("conversation_summaries.db")).unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE conversation_summaries (
                  conversation_id TEXT PRIMARY KEY, title TEXT NOT NULL DEFAULT '',
                  preview TEXT NOT NULL DEFAULT '', step_count INTEGER NOT NULL DEFAULT 0,
                  last_modified_time TEXT NOT NULL, workspace_uris TEXT NOT NULL,
                  not_fully_idle INTEGER NOT NULL DEFAULT 0, killed INTEGER NOT NULL DEFAULT 0
                );
                "#,
            )
            .unwrap();
        let id = "30000000-0000-4000-8000-000000000001";
        let uri = format!("file://{}", project.to_string_lossy().replace(' ', "%20"));
        connection
            .execute(
                "INSERT INTO conversation_summaries VALUES (?1,'Renderer review','Check Linux focus',8,'2026-07-18 08:04:59',?2,1,0)",
                (id, serde_json::to_string(&vec![uri]).unwrap()),
            )
            .unwrap();
        drop(connection);

        let sessions = list_folder_sessions(&app_paths, "antigravity", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, id);
        assert_eq!(sessions[0].title, "Renderer review");
        assert_eq!(sessions[0].first_message, "Check Linux focus");
        assert_eq!(sessions[0].file_path, format!("antigravity://{id}"));
        assert!(sessions[0].in_use);
        let preview = preview_folder_session(&app_paths, "antigravity", &project, id, 20);
        assert_eq!(preview.len(), 2);
        assert_eq!(preview[0].role, "system");
        assert_eq!(preview[1].role, "assistant");
        assert!(
            delete_folder_session(&app_paths, "antigravity", &project, id)
                .unwrap_err()
                .contains("managed by the provider")
        );

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn antigravity_history_merges_indexed_and_unindexed_metadata_without_duplicates() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let state = antigravity_state(tmp.path());
        let indexed_id = "30000000-0000-4000-8000-000000000001";
        let unindexed_id = "30000000-0000-4000-8000-000000000002";
        let connection = create_antigravity_summary_store(&state);
        connection
            .execute(
                "INSERT INTO conversation_summaries VALUES (?1,'Indexed title','Indexed preview',8,'2026-07-18 08:04:59',?2,0,0)",
                (
                    indexed_id,
                    serde_json::to_string(&vec![format!(
                        "file://{}",
                        project.to_string_lossy()
                    )])
                    .unwrap(),
                ),
            )
            .unwrap();
        drop(connection);
        create_antigravity_conversation_db(&state, indexed_id);
        create_antigravity_conversation_db(&state, unindexed_id);
        fs::write(
            state.join("history.jsonl"),
            [
                serde_json::json!({
                    "conversationId": indexed_id,
                    "display": "must not replace indexed metadata",
                    "timestamp": 4_000_000_000_001_u64,
                    "workspace": project,
                }),
                serde_json::json!({
                    "conversationId": unindexed_id,
                    "display": "PRIVATE FALLBACK DISPLAY",
                    "timestamp": 4_000_000_000_000_u64,
                    "workspace": project,
                }),
            ]
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
        )
        .unwrap();
        fs::write(
            state.join("cache").join("last_conversations.json"),
            serde_json::to_vec(&HashMap::from([(
                project.to_string_lossy().into_owned(),
                unindexed_id,
            )]))
            .unwrap(),
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "antigravity", &project);
        assert_eq!(sessions.len(), 2);
        assert_eq!(sessions[0].id, unindexed_id);
        assert_eq!(sessions[0].title, "Antigravity conversation");
        assert_eq!(sessions[0].first_message, "(no preview available)");
        assert_eq!(sessions[0].message_count, None);
        assert!(!serde_json::to_string(&sessions)
            .unwrap()
            .contains("PRIVATE FALLBACK DISPLAY"));
        let indexed = sessions
            .iter()
            .find(|session| session.id == indexed_id)
            .unwrap();
        assert_eq!(indexed.title, "Indexed title");
        assert_eq!(indexed.first_message, "Indexed preview");
        assert_eq!(indexed.message_count, Some(8));
        assert_eq!(
            sessions
                .iter()
                .map(|session| session.id.as_str())
                .collect::<HashSet<_>>()
                .len(),
            2,
            "summary/history/latest duplicates must collapse to one row per provider id"
        );

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn antigravity_modern_schema_lists_only_roots_and_caps_sql_metadata() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let state = antigravity_state(tmp.path());
        let connection = create_antigravity_modern_summary_store(&state);
        let root_id = "10000000-0000-4000-8000-000000000001";
        let child_id = "10000000-0000-4000-8000-000000000002";
        let depth_child_id = "10000000-0000-4000-8000-000000000003";
        let oversized_title_id = "10000000-0000-4000-8000-000000000004";
        let oversized_workspace_id = "10000000-0000-4000-8000-000000000005";
        let unindexed_id = "10000000-0000-4000-8000-000000000006";
        let oversized_timestamp_id = "10000000-0000-4000-8000-000000000007";
        let workspace =
            serde_json::to_string(&vec![format!("file://{}", project.to_string_lossy())]).unwrap();
        let oversized_title = "é".repeat(ANTIGRAVITY_TITLE_MAX_BYTES);
        let oversized_workspace =
            serde_json::to_string(&vec!["x".repeat(ANTIGRAVITY_WORKSPACE_MAX_BYTES + 1)]).unwrap();
        for (id, title, parent, depth, workspace_uris) in [
            (root_id, "Root", "", 0_i64, workspace.clone()),
            (child_id, "Child", root_id, 1, workspace.clone()),
            (depth_child_id, "Depth child", "", 1, workspace.clone()),
            (
                oversized_title_id,
                oversized_title.as_str(),
                "",
                0,
                workspace.clone(),
            ),
            (
                oversized_workspace_id,
                "Oversized workspace",
                "",
                0,
                oversized_workspace.clone(),
            ),
        ] {
            connection
                .execute(
                    "INSERT INTO conversation_summaries
                       (conversation_id,title,preview,step_count,last_modified_time,workspace_uris,parent_conversation_id,nesting_depth)
                     VALUES (?1,?2,'metadata preview',1,'2026-08-01 10:00:00',?3,?4,?5)",
                    rusqlite::params![id, title, workspace_uris, parent, depth],
                )
                .unwrap();
        }
        connection
            .execute(
                "INSERT INTO conversation_summaries
                   (conversation_id,title,preview,step_count,last_modified_time,workspace_uris,parent_conversation_id,nesting_depth)
                 VALUES (?1,'Oversized timestamp','metadata preview',1,?2,?3,'',0)",
                rusqlite::params![
                    oversized_timestamp_id,
                    "2".repeat(ANTIGRAVITY_TIMESTAMP_MAX_BYTES + 1),
                    workspace,
                ],
            )
            .unwrap();
        drop(connection);
        create_antigravity_conversation_db(&state, child_id);
        create_antigravity_conversation_db(&state, unindexed_id);
        fs::write(
            state.join("history.jsonl"),
            [child_id, unindexed_id]
                .into_iter()
                .map(|id| {
                    serde_json::json!({
                        "conversationId": id,
                        "timestamp": 4_000_000_000_000_u64,
                        "workspace": project,
                    })
                    .to_string()
                })
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "antigravity", &project);
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().any(|session| session.id == root_id));
        assert!(!sessions.iter().any(|session| session.id == child_id));
        assert!(!sessions.iter().any(|session| session.id == depth_child_id));
        assert!(!sessions.iter().any(|session| session.id == unindexed_id));
        assert!(!sessions
            .iter()
            .any(|session| session.id == oversized_workspace_id));
        assert!(!sessions
            .iter()
            .any(|session| session.id == oversized_timestamp_id));
        let oversized_title = sessions
            .iter()
            .find(|session| session.id == oversized_title_id)
            .unwrap();
        assert_eq!(oversized_title.title, "metadata preview");
        assert!(!serde_json::to_string(&sessions)
            .unwrap()
            .contains(&"é".repeat(64)));

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn antigravity_modern_stale_summary_recovers_only_corroborated_roots() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let other = normalize_cwd(&{
            let path = tmp.path().join("other");
            fs::create_dir_all(&path).unwrap();
            path
        });
        for child in [
            "history-alias",
            "child-alias",
            "killed-alias",
            "selected-alias",
        ] {
            fs::create_dir_all(project.join(child)).unwrap();
        }
        let selected_alias = project.join("selected-alias").join("..");
        let history_alias = project.join("history-alias").join("..");
        let child_alias = project.join("child-alias").join("..");
        let killed_alias = project.join("killed-alias").join("..");

        let state = antigravity_state(tmp.path());
        let recovered_id = "10000000-0000-4000-8000-000000000011";
        let known_child_id = "10000000-0000-4000-8000-000000000012";
        let killed_id = "10000000-0000-4000-8000-000000000013";
        let history_only_id = "10000000-0000-4000-8000-000000000014";
        let stale_id = "10000000-0000-4000-8000-000000000015";
        let connection = create_antigravity_modern_summary_store(&state);
        let other_workspace =
            serde_json::to_string(&vec![format!("file://{}", other.to_string_lossy())]).unwrap();
        let project_workspace =
            serde_json::to_string(&vec![format!("file://{}", project.to_string_lossy())]).unwrap();
        connection
            .execute(
                "INSERT INTO conversation_summaries
                   (conversation_id,title,preview,step_count,last_modified_time,workspace_uris,parent_conversation_id,nesting_depth)
                 VALUES (?1,'Stale root','',1,'2026-08-01 10:00:00',?2,'',0)",
                (stale_id, &other_workspace),
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO conversation_summaries
                   (conversation_id,title,preview,step_count,last_modified_time,workspace_uris,parent_conversation_id,nesting_depth)
                 VALUES (?1,'Known child','',1,'2026-08-01 10:00:00',?2,?3,1)",
                (known_child_id, &project_workspace, stale_id),
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO conversation_summaries
                   (conversation_id,title,preview,step_count,last_modified_time,workspace_uris,parent_conversation_id,nesting_depth,killed)
                 VALUES (?1,'Killed','',1,'2026-08-01 10:00:00',?2,'',0,1)",
                (killed_id, &project_workspace),
            )
            .unwrap();
        drop(connection);

        for id in [recovered_id, known_child_id, killed_id, history_only_id] {
            create_antigravity_conversation_db(&state, id);
        }
        fs::write(
            state.join("history.jsonl"),
            [
                (recovered_id, history_alias.as_path()),
                (known_child_id, project.as_path()),
                (killed_id, project.as_path()),
                (history_only_id, project.as_path()),
            ]
            .into_iter()
            .enumerate()
            .map(|(offset, (id, workspace))| {
                serde_json::json!({
                    "conversationId": id,
                    "timestamp": 4_000_000_000_000_u64 + offset as u64,
                    "workspace": workspace,
                })
                .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n"),
        )
        .unwrap();
        fs::write(
            state.join("cache").join("last_conversations.json"),
            serde_json::to_vec(&HashMap::from([
                (project.to_string_lossy().into_owned(), recovered_id),
                (child_alias.to_string_lossy().into_owned(), known_child_id),
                (killed_alias.to_string_lossy().into_owned(), killed_id),
            ]))
            .unwrap(),
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "antigravity", &selected_alias);
        assert_eq!(
            sessions
                .iter()
                .map(|session| session.id.as_str())
                .collect::<Vec<_>>(),
            vec![recovered_id]
        );
        assert_eq!(sessions[0].title, "Antigravity conversation");
        assert_eq!(sessions[0].first_message, "(no preview available)");
        assert_eq!(sessions[0].message_count, None);

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn antigravity_history_recovers_from_stale_or_missing_summary_store() {
        let _guard = ENV_LOCK.lock().unwrap();
        let old_home = std::env::var_os("HOME");

        for with_stale_summary in [true, false] {
            let tmp = TempDir::new().unwrap();
            let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
            std::env::set_var("HOME", tmp.path());
            let project = normalize_cwd(&{
                let path = tmp.path().join("project");
                fs::create_dir_all(&path).unwrap();
                path
            });
            let other = normalize_cwd(&{
                let path = tmp.path().join("other");
                fs::create_dir_all(&path).unwrap();
                path
            });
            let state = antigravity_state(tmp.path());
            let id = "30000000-0000-4000-8000-000000000002";
            create_antigravity_conversation_db(&state, id);
            fs::write(
                state.join("cache").join("last_conversations.json"),
                serde_json::to_vec(&HashMap::from([(
                    project.to_string_lossy().into_owned(),
                    id,
                )]))
                .unwrap(),
            )
            .unwrap();

            if with_stale_summary {
                let stale_id = "30000000-0000-4000-8000-000000000001";
                let connection = create_antigravity_summary_store(&state);
                connection
                    .execute(
                        "INSERT INTO conversation_summaries VALUES (?1,'Other folder','',1,'2026-07-18 08:04:59',?2,0,0)",
                        (
                            stale_id,
                            serde_json::to_string(&vec![format!(
                                "file://{}",
                                other.to_string_lossy()
                            )])
                            .unwrap(),
                        ),
                    )
                    .unwrap();
            }

            let sessions = list_folder_sessions(&app_paths, "antigravity", &project);
            assert_eq!(
                sessions
                    .iter()
                    .map(|session| session.id.as_str())
                    .collect::<Vec<_>>(),
                vec![id],
                "latest metadata must survive a {} summary cache",
                if with_stale_summary {
                    "stale"
                } else {
                    "missing"
                }
            );
            assert_eq!(sessions[0].file_path, format!("antigravity://{id}"));
        }

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn antigravity_fallback_rejects_corrupt_missing_and_wrong_folder_databases() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let other = normalize_cwd(&{
            let path = tmp.path().join("other");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let state = antigravity_state(tmp.path());
        let corrupt_id = "30000000-0000-4000-8000-000000000001";
        let missing_id = "30000000-0000-4000-8000-000000000003";
        let other_id = "30000000-0000-4000-8000-000000000002";
        fs::write(
            state.join("conversations").join(format!("{corrupt_id}.db")),
            b"not a SQLite database",
        )
        .unwrap();
        create_antigravity_conversation_db(&state, other_id);
        fs::write(
            state.join("history.jsonl"),
            [
                serde_json::json!({
                    "conversationId": corrupt_id,
                    "timestamp": 10,
                    "workspace": project,
                }),
                serde_json::json!({
                    "conversationId": missing_id,
                    "timestamp": 20,
                    "workspace": project,
                }),
                serde_json::json!({
                    "conversationId": other_id,
                    "timestamp": 30,
                    "workspace": other,
                }),
            ]
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
        )
        .unwrap();

        assert!(list_folder_sessions(&app_paths, "antigravity", &project).is_empty());
        let other_sessions = list_folder_sessions(&app_paths, "antigravity", &other);
        assert_eq!(other_sessions.len(), 1);
        assert_eq!(other_sessions[0].id, other_id);

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn antigravity_fallback_reads_the_newest_bounded_history_rows() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let state = antigravity_state(tmp.path());
        let old_id = "30000000-0000-4000-8000-000000000001";
        let newest_id = "30000000-0000-4000-8000-000000000002";
        create_antigravity_conversation_db(&state, newest_id);
        let workspace = project.to_string_lossy().into_owned();
        let mut rows = (0..ANTIGRAVITY_METADATA_MAX_ROWS)
            .map(|timestamp| {
                serde_json::json!({
                    "conversationId": old_id,
                    "timestamp": timestamp,
                    "workspace": workspace,
                })
                .to_string()
            })
            .collect::<Vec<_>>();
        rows.push(
            serde_json::json!({
                "conversationId": newest_id,
                "timestamp": 4_000_000_000_000_u64,
                "workspace": workspace,
            })
            .to_string(),
        );
        fs::write(state.join("history.jsonl"), rows.join("\n")).unwrap();

        let sessions = list_folder_sessions(&app_paths, "antigravity", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, newest_id);

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn antigravity_fallback_does_not_resurrect_killed_rows_beyond_the_summary_display_limit() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let other = normalize_cwd(&{
            let path = tmp.path().join("other");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let state = antigravity_state(tmp.path());
        let killed_id = "30000000-0000-4000-8000-000000000001";
        create_antigravity_conversation_db(&state, killed_id);
        let mut connection = create_antigravity_summary_store(&state);
        let transaction = connection.transaction().unwrap();
        let other_uris =
            serde_json::to_string(&vec![format!("file://{}", other.to_string_lossy())]).unwrap();
        for value in 1_u128..=500 {
            transaction
                .execute(
                    "INSERT INTO conversation_summaries VALUES (?1,'Other folder','',1,'2026-07-18 08:04:59',?2,0,0)",
                    (uuid::Uuid::from_u128(value).to_string(), &other_uris),
                )
                .unwrap();
        }
        transaction
            .execute(
                "INSERT INTO conversation_summaries VALUES (?1,'Killed','',1,'2000-01-01 00:00:00',?2,0,1)",
                (
                    killed_id,
                    serde_json::to_string(&vec![format!(
                        "file://{}",
                        project.to_string_lossy()
                    )])
                    .unwrap(),
                ),
            )
            .unwrap();
        transaction.commit().unwrap();
        drop(connection);
        fs::write(
            state.join("history.jsonl"),
            serde_json::json!({
                "conversationId": killed_id,
                "timestamp": 4_000_000_000_000_u64,
                "workspace": project,
            })
            .to_string(),
        )
        .unwrap();

        assert!(list_folder_sessions(&app_paths, "antigravity", &project).is_empty());

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn kimi_history_is_folder_scoped_private_and_provider_managed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project with spaces");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let other = normalize_cwd(&{
            let path = tmp.path().join("other");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let kimi_root = tmp.path().join(".kimi-code");
        let sessions_root = kimi_root.join("sessions");
        fs::create_dir_all(&sessions_root).unwrap();
        let id = "session_40000000-0000-4000-8000-000000000001";
        let session_dir = sessions_root.join("workspace-safe").join(id);
        fs::create_dir_all(session_dir.join("agents/main")).unwrap();
        fs::write(
            session_dir.join("state.json"),
            serde_json::json!({
                "createdAt": "2026-07-18T08:22:24.872Z",
                "updatedAt": "2026-07-18T08:22:30.206Z",
                "title": "Kimi renderer review",
                "workDir": project,
                "lastPrompt": "inspect the renderer"
            })
            .to_string(),
        )
        .unwrap();
        let wire_path = session_dir.join("agents/main/wire.jsonl");
        fs::write(&wire_path, vec![0xff; 1024 * 1024]).unwrap();
        let outside_id = "session_40000000-0000-4000-8000-000000000002";
        let outside = tmp.path().join(outside_id);
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("state.json"), "{}").unwrap();
        fs::write(
            kimi_root.join("session_index.jsonl"),
            [
                // A malformed duplicate cannot reserve the id and hide the later valid provider row.
                serde_json::json!({
                    "sessionId": id,
                    "sessionDir": outside,
                    "workDir": project,
                }),
                serde_json::json!({
                    "sessionId": id,
                    "sessionDir": session_dir,
                    "workDir": project,
                }),
                serde_json::json!({
                    "sessionId": outside_id,
                    "sessionDir": outside,
                    "workDir": other,
                }),
            ]
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "kimi", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, id);
        assert_eq!(sessions[0].title, "Kimi renderer review");
        assert_eq!(sessions[0].first_message, "inspect the renderer");
        assert_eq!(sessions[0].message_count, None);
        assert_eq!(sessions[0].file_path, format!("kimi://{id}"));
        fs::write(
            &wire_path,
            [
                serde_json::json!({"type":"config.update","systemPrompt":"PRIVATE SYSTEM"}),
                serde_json::json!({"type":"turn.prompt","input":[{"type":"text","text":"inspect the renderer"}],"origin":{"kind":"user"}}),
                serde_json::json!({"type":"context.append_message","message":{"role":"user","content":[{"type":"text","text":"PRIVATE DUPLICATE"}]}}),
                serde_json::json!({"type":"llm.tools_snapshot","tools":[{"description":"PRIVATE TOOL"}]}),
                serde_json::json!({"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"think","think":"PRIVATE THINK"}}}),
                serde_json::json!({"type":"context.append_loop_event","event":{"type":"content.part","part":{"type":"text","text":"I found the issue"}}}),
            ]
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
        )
        .unwrap();
        let preview = preview_folder_session(&app_paths, "kimi", &project, id, 20);
        assert_eq!(preview.len(), 2);
        assert_eq!(preview[0].role, "user");
        assert_eq!(preview[0].text, "inspect the renderer");
        assert_eq!(preview[1].role, "assistant");
        assert_eq!(preview[1].text, "I found the issue");
        let serialized = serde_json::to_string(&preview).unwrap();
        for private in [
            "PRIVATE SYSTEM",
            "PRIVATE DUPLICATE",
            "PRIVATE TOOL",
            "PRIVATE THINK",
        ] {
            assert!(!serialized.contains(private));
        }
        assert!(delete_folder_session(&app_paths, "kimi", &project, id)
            .unwrap_err()
            .contains("managed by the provider"));
        assert!(session_dir.join("state.json").exists());

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn kiro_history_is_folder_scoped_private_live_and_provider_managed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project with spaces");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let other = normalize_cwd(&{
            let path = tmp.path().join("other");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let root = tmp.path().join(".kiro/sessions/cli");
        fs::create_dir_all(&root).unwrap();
        let id = "40000000-0000-4000-8000-000000000003";
        fs::write(
            root.join(format!("{id}.json")),
            serde_json::json!({
                "session_id": id,
                "cwd": project,
                "created_at": "2026-07-18T08:33:33.801469Z",
                "updated_at": "2026-07-18T08:33:40.907Z",
                "title": "Kiro renderer review",
                "session_state": {
                    "permissions": {"trusted_tools": ["PRIVATE TOOL CONFIG"]},
                    "conversation_metadata": {"user_turn_metadatas": [{}]}
                }
            })
            .to_string(),
        )
        .unwrap();
        let transcript_path = root.join(format!("{id}.jsonl"));
        fs::write(&transcript_path, vec![0xff; 1024 * 1024]).unwrap();
        fs::write(
            root.join(format!("{id}.lock")),
            serde_json::json!({"pid": std::process::id(), "started_at": "2026-07-18T08:33:33Z"})
                .to_string(),
        )
        .unwrap();
        let other_id = "40000000-0000-4000-8000-000000000004";
        fs::write(
            root.join(format!("{other_id}.json")),
            serde_json::json!({"session_id":other_id,"cwd":other,"title":"Other"}).to_string(),
        )
        .unwrap();
        fs::write(root.join(format!("{other_id}.jsonl")), "").unwrap();

        let sessions = list_folder_sessions(&app_paths, "kiro", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, id);
        assert_eq!(sessions[0].title, "Kiro renderer review");
        assert_eq!(sessions[0].first_message, "Kiro renderer review");
        assert_eq!(sessions[0].message_count, None);
        assert_eq!(sessions[0].file_path, format!("kiro://{id}"));
        assert!(sessions[0].in_use);

        fs::write(
            &transcript_path,
            [
                serde_json::json!({"version":"1","kind":"Prompt","data":{"content":[{"kind":"text","data":"inspect the renderer"}]}}),
                serde_json::json!({"version":"1","kind":"AssistantMessage","data":{"content":[{"kind":"thinking","data":"PRIVATE THINK"},{"kind":"text","data":"I found the issue"}]}}),
                serde_json::json!({"version":"1","kind":"ToolUse","data":{"content":[{"kind":"text","data":"PRIVATE TOOL"}]}}),
            ]
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
        )
        .unwrap();
        let preview = preview_folder_session(&app_paths, "kiro", &project, id, 20);
        assert_eq!(preview.len(), 2);
        assert_eq!(preview[0].role, "user");
        assert_eq!(preview[0].text, "inspect the renderer");
        assert_eq!(preview[1].role, "assistant");
        assert_eq!(preview[1].text, "I found the issue");
        let serialized = serde_json::to_string(&preview).unwrap();
        for private in ["PRIVATE THINK", "PRIVATE TOOL", "PRIVATE TOOL CONFIG"] {
            assert!(!serialized.contains(private));
        }
        assert!(delete_folder_session(&app_paths, "kiro", &project, id)
            .unwrap_err()
            .contains("managed by the provider"));
        assert!(root.join(format!("{id}.json")).exists());

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn cursor_history_is_folder_scoped_private_and_provider_managed() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let path = tmp.path().join("project with spaces");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let projects = tmp.path().join(".cursor/projects");
        let project_store = projects.join(cursor_project_slug(&project).unwrap());
        fs::create_dir_all(&project_store).unwrap();
        fs::write(
            project_store.join("repo.json"),
            serde_json::json!({"id":"50000000-0000-4000-8000-000000000001"}).to_string(),
        )
        .unwrap();
        let id = "123e4567-e89b-42d3-a456-426614174000";
        let chat_dir = tmp.path().join(".cursor/chats/workspace-hash").join(id);
        fs::create_dir_all(&chat_dir).unwrap();
        fs::write(
            chat_dir.join("meta.json"),
            serde_json::json!({
                "schemaVersion": 1,
                "cwd": project,
                "title": "Cursor renderer review",
                "updatedAtMs": 1_784_364_247_000_u64,
            })
            .to_string(),
        )
        .unwrap();
        let transcript_dir = project_store.join("agent-transcripts").join(id);
        fs::create_dir_all(&transcript_dir).unwrap();
        let transcript = transcript_dir.join(format!("{id}.jsonl"));
        fs::write(&transcript, vec![0xff; 1024 * 1024]).unwrap();

        let other = normalize_cwd(&{
            let path = tmp.path().join("other");
            fs::create_dir_all(&path).unwrap();
            path
        });
        let other_store = projects.join(cursor_project_slug(&other).unwrap());
        fs::create_dir_all(other_store.join("agent-transcripts")).unwrap();
        fs::write(
            other_store.join("repo.json"),
            serde_json::json!({"id":"50000000-0000-4000-8000-000000000002"}).to_string(),
        )
        .unwrap();

        let sessions = list_folder_sessions(&app_paths, "cursor", &project);
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, id);
        assert_eq!(sessions[0].title, "Cursor renderer review");
        assert_eq!(sessions[0].first_message, "Cursor renderer review");
        assert_eq!(sessions[0].message_count, None);
        assert_eq!(sessions[0].file_path, format!("cursor://{id}"));

        fs::write(
            &transcript,
            [
                serde_json::json!({"role":"system","message":{"content":[{"type":"text","text":"PRIVATE SYSTEM"}]}}),
                serde_json::json!({"role":"user","message":{"content":[{"type":"text","text":"inspect the renderer"}]}}),
                serde_json::json!({"role":"assistant","message":{"content":[{"type":"thinking","text":"PRIVATE THINK"},{"type":"text","text":"I found the issue"},{"type":"tool_call","text":"PRIVATE TOOL"}]}}),
                serde_json::json!({"role":"tool","message":{"content":[{"type":"text","text":"PRIVATE RESULT"}]}}),
                serde_json::json!({"type":"turn_ended","status":"completed"}),
            ]
            .into_iter()
            .map(|value| value.to_string())
            .collect::<Vec<_>>()
            .join("\n"),
        )
        .unwrap();
        let preview = preview_folder_session(&app_paths, "cursor", &project, id, 20);
        assert_eq!(preview.len(), 2);
        assert_eq!(preview[0].role, "user");
        assert_eq!(preview[0].text, "inspect the renderer");
        assert_eq!(preview[1].role, "assistant");
        assert_eq!(preview[1].text, "I found the issue");
        let serialized = serde_json::to_string(&preview).unwrap();
        for private in [
            "PRIVATE SYSTEM",
            "PRIVATE THINK",
            "PRIVATE TOOL",
            "PRIVATE RESULT",
        ] {
            assert!(!serialized.contains(private));
        }
        assert!(delete_folder_session(&app_paths, "cursor", &project, id)
            .unwrap_err()
            .contains("managed by the provider"));
        assert!(transcript.exists());

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn unknown_provider_database_schema_fails_soft() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = tmp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        fs::create_dir_all(tmp.path().join(".copilot")).unwrap();
        rusqlite::Connection::open(tmp.path().join(".copilot/session-store.db")).unwrap();
        assert!(list_folder_sessions(&app_paths, "copilot", &project).is_empty());
        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn hide_removes_from_list_but_keeps_file_delete_removes_file() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = normalize_cwd(&{
            let p = tmp.path().join("project");
            fs::create_dir_all(&p).unwrap();
            p
        });
        let codex_dir = tmp.path().join(".codex").join("sessions").join("2026");
        fs::create_dir_all(&codex_dir).unwrap();
        let make = |name: &str, id: &str| {
            let path = codex_dir.join(name);
            fs::write(
                &path,
                format!(
                    "{}\n{}",
                    serde_json::json!({
                        "type": "session_meta",
                        "payload": { "id": id, "cwd": project.to_string_lossy() }
                    }),
                    r#"{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"}]}}"#,
                ),
            )
            .unwrap();
            path
        };
        let keep_path = make("keep.jsonl", "keep-thread");
        let hide_path = make("hide.jsonl", "hide-thread");
        let del_path = make("del.jsonl", "del-thread");

        assert_eq!(list_folder_sessions(&app_paths, "codex", &project).len(), 3);

        // REMOVE: hidden from the list, file still on disk.
        hide_folder_session(&app_paths, "codex", "hide-thread").unwrap();
        let after_hide = list_folder_sessions(&app_paths, "codex", &project);
        assert_eq!(after_hide.len(), 2);
        assert!(after_hide.iter().all(|s| s.id != "hide-thread"));
        assert!(hide_path.exists(), "remove must NOT delete the file");

        // The removed session shows up in the hidden listing, and can be added back.
        let hidden = list_hidden_folder_sessions(&app_paths, "codex", &project);
        assert_eq!(hidden.len(), 1);
        assert_eq!(hidden[0].id, "hide-thread");
        let hidden_preview =
            preview_folder_session(&app_paths, "codex", &project, "hide-thread", 120);
        assert!(
            !hidden_preview.is_empty(),
            "removed sessions remain safely previewable from their original folder"
        );
        let other_folder = tmp.path().join("other-project");
        fs::create_dir_all(&other_folder).unwrap();
        assert!(
            preview_folder_session(&app_paths, "codex", &other_folder, "hide-thread", 120)
                .is_empty(),
            "preview must not escape the requested folder boundary"
        );
        unhide_folder_session(&app_paths, "codex", "hide-thread").unwrap();
        assert_eq!(
            list_hidden_folder_sessions(&app_paths, "codex", &project).len(),
            0
        );
        let back = list_folder_sessions(&app_paths, "codex", &project);
        assert_eq!(back.len(), 3, "add-back restores it to the visible list");
        assert!(back.iter().any(|s| s.id == "hide-thread"));
        // Re-hide so the delete assertions below operate on the original 3-visible state.
        hide_folder_session(&app_paths, "codex", "hide-thread").unwrap();

        // DELETE: file gone from disk and from the list.
        delete_folder_session(&app_paths, "codex", &project, "del-thread").unwrap();
        assert!(!del_path.exists(), "delete must remove the file");
        let after_del = list_folder_sessions(&app_paths, "codex", &project);
        assert_eq!(after_del.len(), 1);
        assert_eq!(after_del[0].id, "keep-thread");
        assert!(keep_path.exists());

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn folder_session_discovery_rejects_non_directory_selection() {
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let missing = tmp.path().join("missing-project");
        assert!(list_folder_sessions(&app_paths, "codex", &missing).is_empty());
    }

    #[test]
    fn public_history_mutations_reject_oversized_ids_names_and_override_growth() {
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let oversized_id = "x".repeat(MAX_HISTORY_SESSION_ID_BYTES + 1);
        assert!(hide_folder_session(&app_paths, "codex", &oversized_id).is_err());
        assert!(unhide_folder_session(&app_paths, "codex", &oversized_id).is_err());
        assert!(set_folder_session_name(&app_paths, "codex", &oversized_id, Some("name")).is_err());
        assert!(set_folder_session_name(
            &app_paths,
            "codex",
            "session-1",
            Some(&"x".repeat(MAX_HISTORY_CUSTOM_NAME_BYTES + 1)),
        )
        .is_err());
        assert!(
            set_folder_session_name(&app_paths, "codex", "session-1", Some("line\nbreak"),)
                .is_err()
        );

        let hidden = (0..MAX_HISTORY_OVERRIDES)
            .map(|index| format!("codex:session-{index}"))
            .collect::<std::collections::BTreeSet<_>>();
        maestro_shell::store::replace_hidden_sessions(&app_paths, &hidden).unwrap();
        assert!(hide_folder_session(&app_paths, "codex", "overflow").is_err());
        assert!(hide_folder_session(&app_paths, "codex", "session-0").is_ok());
        assert!(unhide_folder_session(&app_paths, "codex", "session-0").is_ok());
    }

    #[test]
    fn history_session_id_validation_is_exact_and_accepts_the_byte_boundary() {
        let boundary = "x".repeat(MAX_HISTORY_SESSION_ID_BYTES);
        let validated = validate_history_session_id(&boundary).unwrap();
        assert_eq!(validated, boundary);
        assert_eq!(
            validated.as_ptr(),
            boundary.as_ptr(),
            "validation returns the caller's exact bytes"
        );

        for invalid in [
            format!(" {boundary}"),
            format!("{boundary} "),
            "inside\u{0000}control".to_string(),
            "x".repeat(MAX_HISTORY_SESSION_ID_BYTES + 1),
        ] {
            assert!(
                validate_history_session_id(&invalid).is_err(),
                "non-exact or hostile session id must be rejected"
            );
        }

        let provider_boundary = "x".repeat(PROVIDER_SESSION_ID_MAX_CHARS);
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        hide_folder_session(&app_paths, "codex", &provider_boundary).unwrap();
        set_folder_session_name(&app_paths, "codex", &provider_boundary, Some("boundary")).unwrap();
        assert!(maestro_shell::store::load_hidden_sessions(&app_paths)
            .unwrap()
            .contains(&format!("codex:{provider_boundary}")));
        assert_eq!(
            maestro_shell::store::load_session_names(&app_paths).unwrap()
                [&format!("codex:{provider_boundary}")],
            "boundary"
        );
    }

    #[test]
    fn provider_session_ids_have_one_bounded_non_aliasing_contract() {
        let uuid = "11111111-2222-4333-8444-555555555555";
        for agent in ["claude", "codex", "gemini", "opencode", "devin"] {
            assert_eq!(
                normalize_provider_session_id(agent, "opaque-session").as_deref(),
                Some("opaque-session")
            );
        }
        for agent in ["copilot", "antigravity", "kiro", "cursor"] {
            assert_eq!(
                normalize_provider_session_id(agent, uuid).as_deref(),
                Some(uuid)
            );
            assert!(normalize_provider_session_id(agent, "opaque-session").is_none());
        }
        let kimi = format!("session_{uuid}");
        assert_eq!(
            normalize_provider_session_id("kimi", &kimi).as_deref(),
            Some(kimi.as_str())
        );

        for invalid in [
            String::new(),
            "-flag-like".to_string(),
            "control\ncharacter".to_string(),
            "x".repeat(PROVIDER_SESSION_ID_MAX_CHARS + 1),
        ] {
            for agent in ["claude", "codex", "gemini", "opencode", "devin"] {
                assert!(normalize_provider_session_id(agent, &invalid).is_none());
            }
        }
        let padded = format!(" {uuid}");
        assert_eq!(
            normalize_provider_session_id("claude", &padded).as_deref(),
            Some(uuid)
        );
        assert!(!provider_session_id_is_exact("claude", &padded));
        assert!(normalize_provider_session_id("factory", "opaque-session").is_none());
    }

    #[test]
    fn destructive_history_mutations_reject_aliases_without_touching_files_or_sidecars() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let project = normalize_cwd(&{
            let project = tmp.path().join("project");
            fs::create_dir_all(&project).unwrap();
            project
        });
        let codex_dir = tmp.path().join(".codex/sessions/2026");
        fs::create_dir_all(&codex_dir).unwrap();
        let session_id = "exact-session-id";
        let transcript = codex_dir.join("exact-session.jsonl");
        let transcript_bytes = format!(
            "{}\n{}",
            serde_json::json!({
                "type": "session_meta",
                "payload": { "id": session_id, "cwd": project.to_string_lossy() }
            }),
            r#"{"type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"preserve me"}]}}"#,
        )
        .into_bytes();
        fs::write(&transcript, &transcript_bytes).unwrap();

        let canonical_key = format!("codex:{session_id}");
        let original_names =
            std::collections::BTreeMap::from([(canonical_key, "Canonical name".to_string())]);
        let original_hidden =
            std::collections::BTreeSet::from(["codex:unrelated-hidden-session".to_string()]);
        maestro_shell::store::replace_session_names(&app_paths, &original_names).unwrap();
        maestro_shell::store::replace_hidden_sessions(&app_paths, &original_hidden).unwrap();

        let aliases = [
            format!(" {session_id}"),
            format!("{session_id} "),
            "exact-\u{0000}session-id".to_string(),
            "x".repeat(MAX_HISTORY_SESSION_ID_BYTES + 1),
        ];
        for alias in aliases {
            assert!(hide_folder_session(&app_paths, "codex", &alias).is_err());
            assert!(
                set_folder_session_name(&app_paths, "codex", &alias, Some("Alias name")).is_err()
            );
            assert!(delete_folder_session(&app_paths, "codex", &project, &alias).is_err());

            assert_eq!(fs::read(&transcript).unwrap(), transcript_bytes);
            assert_eq!(
                maestro_shell::store::load_session_names(&app_paths).unwrap(),
                original_names
            );
            assert_eq!(
                maestro_shell::store::load_hidden_sessions(&app_paths).unwrap(),
                original_hidden
            );
        }

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn public_history_preview_clamps_hostile_line_count() {
        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = normalize_cwd(&{
            let project = tmp.path().join("project");
            fs::create_dir_all(&project).unwrap();
            project
        });
        let root = tmp.path().join(".codex/sessions/2026");
        fs::create_dir_all(&root).unwrap();
        let mut lines = vec![serde_json::json!({
            "type": "session_meta",
            "payload": {"id": "bounded-preview", "cwd": project}
        })
        .to_string()];
        lines.extend((0..=MAX_HISTORY_PREVIEW_LINES).map(|index| {
            serde_json::json!({
                "type": "response_item",
                "payload": {"type":"message", "role":"user", "content":[{
                    "type":"input_text", "text": format!("message {index}")
                }]}
            })
            .to_string()
        }));
        fs::write(root.join("preview.jsonl"), lines.join("\n")).unwrap();

        let preview =
            preview_folder_session(&app_paths, "codex", &project, "bounded-preview", usize::MAX);
        assert_eq!(preview.len(), MAX_HISTORY_PREVIEW_LINES);

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn blocked_sidecar_import_keeps_legacy_names_visible_and_rejects_mutation() {
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let sqlite_only = std::collections::BTreeMap::from([(
            "codex:sqlite-only".to_string(),
            "SQLite-only name".to_string(),
        )]);
        maestro_shell::store::replace_session_names(&app_paths, &sqlite_only).unwrap();
        let dashboard = app_paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let names_path = dashboard.join("sessionNames.json");
        let hidden_path = dashboard.join("hiddenSessions.json");
        let legacy_names = std::collections::BTreeMap::from([(
            "codex:thread-1".to_string(),
            "Legacy name".to_string(),
        )]);
        let original_names = serde_json::to_vec(&legacy_names).unwrap();
        fs::write(&names_path, &original_names).unwrap();
        fs::write(&hidden_path, b"not json").unwrap();

        let mut visible = sqlite_only.clone();
        visible.extend(legacy_names.clone());
        assert_eq!(read_session_names(&app_paths), visible);
        let mut replacement = visible;
        replacement.insert("codex:thread-2".into(), "Must not commit".into());
        assert!(write_session_names(&app_paths, &replacement).is_err());
        assert_eq!(fs::read(&names_path).unwrap(), original_names);
        assert_eq!(fs::read(&hidden_path).unwrap(), b"not json");
        assert!(!dashboard.join("sessionNames.json.migrated").exists());
        assert!(!dashboard.join("hiddenSessions.json.migrated").exists());
    }

    #[test]
    #[cfg(unix)]
    fn oversized_and_symlinked_legacy_history_sidecars_fail_soft() {
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let dashboard = app_paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let external = tmp.path().join("external-names.json");
        fs::write(&external, br#"{"codex:external":"must not load"}"#).unwrap();
        std::os::unix::fs::symlink(&external, dashboard.join("sessionNames.json")).unwrap();
        fs::write(
            dashboard.join("hiddenSessions.json"),
            vec![b'x'; LEGACY_HISTORY_SIDECAR_MAX_BYTES as usize + 1],
        )
        .unwrap();

        assert!(read_session_names(&app_paths).is_empty());
        assert!(read_hidden_sessions(&app_paths).is_empty());
        let project = tmp.path().join("project");
        fs::create_dir_all(&project).unwrap();
        assert!(list_folder_sessions(&app_paths, "gemini", &project).is_empty());

        let cancellation = HistoryCancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            list_folder_sessions_partitioned_with_cancel(
                &app_paths,
                "gemini",
                &project,
                &cancellation,
            ),
            Err(HistoryScanCancelled)
        ));
    }

    #[test]
    #[cfg(unix)]
    fn symlinked_dashboard_directory_never_loads_external_legacy_sidecars() {
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        fs::create_dir_all(app_paths.base()).unwrap();
        let external = tmp.path().join("external-dashboard");
        fs::create_dir_all(&external).unwrap();
        fs::write(
            external.join("sessionNames.json"),
            serde_json::to_vec(&SessionNameMap::from([(
                "codex:external".to_string(),
                "Must not load".to_string(),
            )]))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            external.join("hiddenSessions.json"),
            serde_json::to_vec(&HiddenSessionSet::from(["codex:external".to_string()])).unwrap(),
        )
        .unwrap();
        std::os::unix::fs::symlink(&external, app_paths.base().join("dashboard")).unwrap();

        assert!(read_session_names(&app_paths).is_empty());
        assert!(read_hidden_sessions(&app_paths).is_empty());

        let external_base = tmp.path().join("external-base");
        let external_dashboard = external_base.join("dashboard");
        fs::create_dir_all(&external_dashboard).unwrap();
        fs::write(
            external_dashboard.join("sessionNames.json"),
            serde_json::to_vec(&SessionNameMap::from([(
                "codex:external-base".to_string(),
                "Must not load".to_string(),
            )]))
            .unwrap(),
        )
        .unwrap();
        let linked_base = tmp.path().join("linked-base");
        std::os::unix::fs::symlink(&external_base, &linked_base).unwrap();
        let linked_paths = AppPaths::with_base(linked_base);
        assert!(read_session_names(&linked_paths).is_empty());
        assert!(read_hidden_sessions(&linked_paths).is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn fifo_and_symlinked_provider_metadata_never_block_or_surface() {
        use std::os::unix::ffi::OsStrExt;

        fn make_fifo(path: &Path) {
            let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
        }

        let _guard = ENV_LOCK.lock().unwrap();
        let tmp = TempDir::new().unwrap();
        let app_paths = AppPaths::with_base(tmp.path().join("Hydra"));
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());
        let project = tmp.path().join("project");
        fs::create_dir_all(&project).unwrap();

        let kiro_root = tmp.path().join(".kiro/sessions/cli");
        fs::create_dir_all(&kiro_root).unwrap();
        make_fifo(&kiro_root.join("10000000-0000-4000-8000-000000000001.json"));
        let kimi_root = tmp.path().join(".kimi-code");
        fs::create_dir_all(kimi_root.join("sessions")).unwrap();
        make_fifo(&kimi_root.join("session_index.jsonl"));
        let codex_fifo = tmp.path().join("codex-rollout.jsonl");
        make_fifo(&codex_fifo);
        let dashboard = app_paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        make_fifo(&dashboard.join("sessionNames.json"));

        let external_json = tmp.path().join("external.json");
        fs::write(&external_json, br#"{"title":"must not load"}"#).unwrap();
        let linked_json = tmp.path().join("linked.json");
        std::os::unix::fs::symlink(&external_json, &linked_json).unwrap();
        assert!(read_bounded_json_with_cancel(
            &linked_json,
            1024,
            &HistoryCancellationToken::new(),
        )
        .unwrap()
        .is_none());

        let external_jsonl = tmp.path().join("external.jsonl");
        fs::write(&external_jsonl, b"{\"private\":true}\n").unwrap();
        let linked_jsonl = tmp.path().join("linked.jsonl");
        std::os::unix::fs::symlink(&external_jsonl, &linked_jsonl).unwrap();
        let mut visited = false;
        visit_jsonl_file_with_cancel(
            &linked_jsonl,
            Some(1024),
            Some(1),
            &HistoryCancellationToken::new(),
            |_| {
                visited = true;
                true
            },
        )
        .unwrap();
        assert!(!visited);

        let started = std::time::Instant::now();
        assert!(list_folder_sessions(&app_paths, "kiro", &project).is_empty());
        assert!(list_folder_sessions(&app_paths, "kimi", &project).is_empty());
        assert!(open_regular_file_no_follow(&codex_fifo).is_none());
        assert!(preview_session_file_with_cancel(
            "codex",
            &codex_fifo,
            20,
            &HistoryCancellationToken::new(),
        )
        .unwrap()
        .is_empty());
        assert!(read_session_names(&app_paths).is_empty());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "nonblocking metadata opens must reject FIFOs promptly"
        );

        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
    }

    #[test]
    fn in_flight_provider_read_is_cooperatively_cancelled_between_chunks() {
        struct CancelAfterFirstChunk {
            cancellation: HistoryCancellationToken,
            reads: usize,
        }

        impl Read for CancelAfterFirstChunk {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                assert_eq!(
                    self.reads, 0,
                    "a cancelled read must not request another chunk"
                );
                self.reads += 1;
                let count = buffer.len().min(HISTORY_READ_CHUNK_BYTES);
                buffer[..count].fill(b'x');
                self.cancellation.cancel();
                Ok(count)
            }
        }

        let cancellation = HistoryCancellationToken::new();
        let mut reader = CancelAfterFirstChunk {
            cancellation: cancellation.clone(),
            reads: 0,
        };
        assert!(matches!(
            read_bytes_with_cancel(&mut reader, None, &cancellation),
            Err(HistoryScanCancelled)
        ));
        assert_eq!(reader.reads, 1);
    }
}

const LEGACY_HISTORY_SIDECAR_MAX_BYTES: u64 = 4 * 1024 * 1024;

type SessionNameMap = std::collections::BTreeMap<String, String>;

fn session_name_key(agent: &str, session_id: &str) -> String {
    format!("{}:{}", agent.trim(), session_id.trim())
}

fn read_session_names(paths: &AppPaths) -> SessionNameMap {
    match maestro_shell::migrate::migrate_session_sidecars(paths) {
        Ok(()) => maestro_shell::store::load_session_names(paths).unwrap_or_default(),
        Err(error) => {
            eprintln!("agent history: legacy session-name import blocked: {error}");
            // Preserve visibility from BOTH readable authorities while promotion is blocked. DB
            // entries are the base and active legacy values overlay matching keys; neither side is
            // allowed to make unrelated names appear lost.
            let mut merged = if maestro_shell::db::db_path(paths.base()).is_file() {
                maestro_shell::store::load_session_names(paths).unwrap_or_default()
            } else {
                SessionNameMap::new()
            };
            if let Some(legacy) = read_legacy_sidecar::<SessionNameMap>(
                paths.base(),
                &paths.base().join("dashboard").join("sessionNames.json"),
            ) {
                merged.extend(legacy);
            }
            merged
        }
    }
}

fn write_session_names(paths: &AppPaths, names: &SessionNameMap) -> Result<(), String> {
    maestro_shell::migrate::migrate_session_sidecars(paths)?;
    maestro_shell::store::replace_session_names(paths, names)
        .map_err(|e| format!("write session names: {e}"))
}

type HiddenSessionSet = std::collections::BTreeSet<String>;

fn read_hidden_sessions(paths: &AppPaths) -> HiddenSessionSet {
    match maestro_shell::migrate::migrate_session_sidecars(paths) {
        Ok(()) => maestro_shell::store::load_hidden_sessions(paths).unwrap_or_default(),
        Err(error) => {
            eprintln!("agent history: legacy hidden-session import blocked: {error}");
            let mut merged = if maestro_shell::db::db_path(paths.base()).is_file() {
                maestro_shell::store::load_hidden_sessions(paths).unwrap_or_default()
            } else {
                HiddenSessionSet::new()
            };
            if let Some(legacy) = read_legacy_sidecar::<HiddenSessionSet>(
                paths.base(),
                &paths.base().join("dashboard").join("hiddenSessions.json"),
            ) {
                merged.extend(legacy);
            }
            merged
        }
    }
}

fn write_hidden_sessions(paths: &AppPaths, hidden: &HiddenSessionSet) -> Result<(), String> {
    maestro_shell::migrate::migrate_session_sidecars(paths)?;
    maestro_shell::store::replace_hidden_sessions(paths, hidden)
        .map_err(|e| format!("write hidden sessions: {e}"))
}

fn read_legacy_sidecar<T>(base: &Path, path: &Path) -> Option<T>
where
    T: serde::de::DeserializeOwned,
{
    // This fallback runs only when the authoritative migration refuses the legacy pair. Preserve
    // fail-soft visibility without following a redirected dashboard directory/final file or
    // allocating an attacker-sized sidecar.
    let base_metadata = fs::symlink_metadata(base).ok()?;
    if !base_metadata.file_type().is_dir() {
        return None;
    }
    let parent = path.parent()?;
    if parent.parent() != Some(base) {
        return None;
    }
    let parent_metadata = fs::symlink_metadata(parent).ok()?;
    if !parent_metadata.file_type().is_dir() {
        return None;
    }
    let bytes = read_bounded_regular_file_with_cancel(
        path,
        LEGACY_HISTORY_SIDECAR_MAX_BYTES,
        &HistoryCancellationToken::new(),
    )
    .ok()??;
    serde_json::from_slice(&bytes).ok()
}

fn normalize_cwd(cwd: &Path) -> PathBuf {
    cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf())
}

fn cwd_match_candidates(cwd: &Path) -> Vec<PathBuf> {
    let normalized = normalize_cwd(cwd);
    let raw = cwd.to_path_buf();
    let mut candidates = vec![normalized];
    if !candidates.iter().any(|candidate| candidate == &raw) {
        candidates.push(raw);
    }
    candidates
}

fn modified_at_ms(path: &Path) -> u64 {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn truncate(value: &str, max: usize) -> String {
    let trimmed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.chars().count() <= max {
        return trimmed;
    }
    let mut out = trimmed
        .chars()
        .take(max.saturating_sub(1))
        .collect::<String>();
    out.push('…');
    out
}

fn assign_folder_index(sessions: &mut [AgentHistorySession]) {
    let mut ids = sessions.iter().map(|s| s.id.clone()).collect::<Vec<_>>();
    ids.sort();
    for session in sessions {
        session.folder_index = ids
            .iter()
            .position(|id| id == &session.id)
            .map(|idx| idx + 1)
            .unwrap_or(0);
    }
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn push_session(
    out: &mut Vec<AgentHistorySession>,
    agent: &str,
    id: String,
    path: PathBuf,
    first_message: String,
    message_count: Option<usize>,
    in_use: &HashSet<String>,
) {
    let title = truncate(&first_message, 90);
    out.push(AgentHistorySession {
        id: id.clone(),
        agent: agent.to_string(),
        title: if title.is_empty() {
            "(no user message)".to_string()
        } else {
            title
        },
        first_message,
        modified_at_ms: modified_at_ms(&path),
        message_count,
        folder_index: 0,
        file_path: path.to_string_lossy().into_owned(),
        in_use: in_use.contains(&id),
        custom_name: None,
    });
}

fn encode_claude_cwd(cwd: &Path) -> String {
    cwd.to_string_lossy()
        .chars()
        .map(|ch| {
            if ch == '/' || ch.is_whitespace() {
                '-'
            } else {
                ch
            }
        })
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileFingerprint {
    len: u64,
    modified_ns: u128,
}

fn file_fingerprint(path: &Path) -> Option<FileFingerprint> {
    let metadata = fs::metadata(path).ok()?;
    let modified_ns = metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_nanos();
    Some(FileFingerprint {
        len: metadata.len(),
        modified_ns,
    })
}

#[derive(Clone)]
struct CachedClaudeMetadata {
    fingerprint: FileFingerprint,
    metadata: ClaudeRootMetadata,
}

#[derive(Clone)]
struct ClaudeRootMetadata {
    id: String,
    title: String,
}

static CLAUDE_METADATA_CACHE: OnceLock<Mutex<HashMap<PathBuf, CachedClaudeMetadata>>> =
    OnceLock::new();

#[derive(Debug)]
enum BoundedReadFailure {
    Cancelled,
    LimitExceeded,
    Io,
}

impl From<std::io::Error> for BoundedReadFailure {
    fn from(_error: std::io::Error) -> Self {
        Self::Io
    }
}

fn read_bounded_line(
    reader: &mut impl BufRead,
    max_bytes: usize,
    cancellation: &HistoryCancellationToken,
) -> Result<Option<(String, usize)>, BoundedReadFailure> {
    let mut bytes = Vec::new();
    let mut consumed_total = 0;
    loop {
        cancellation
            .check()
            .map_err(|_| BoundedReadFailure::Cancelled)?;
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            break;
        }
        let newline = buffer.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(buffer.len(), |index| index + 1);
        let content_len = newline.unwrap_or(consumed);
        if bytes.len().saturating_add(content_len) > max_bytes {
            return Err(BoundedReadFailure::LimitExceeded);
        }
        bytes.extend_from_slice(&buffer[..content_len]);
        reader.consume(consumed);
        consumed_total += consumed;
        if newline.is_some() {
            break;
        }
    }
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    let line = String::from_utf8(bytes).map_err(|_| BoundedReadFailure::Io)?;
    Ok(Some((line, consumed_total)))
}

fn read_bytes_with_cancel(
    reader: &mut impl Read,
    max_bytes: Option<usize>,
    cancellation: &HistoryCancellationToken,
) -> Result<Option<Vec<u8>>, HistoryScanCancelled> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; HISTORY_READ_CHUNK_BYTES];
    loop {
        cancellation.check()?;
        let read_len = max_bytes
            .map(|limit| limit.saturating_sub(bytes.len()).saturating_add(1))
            .unwrap_or(chunk.len())
            .min(chunk.len());
        let count = match reader.read(&mut chunk[..read_len]) {
            Ok(count) => count,
            Err(_) => return Ok(None),
        };
        if count == 0 {
            break;
        }
        if max_bytes.is_some_and(|limit| bytes.len().saturating_add(count) > limit) {
            return Ok(None);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
    cancellation.check()?;
    Ok(Some(bytes))
}

fn visit_jsonl_file_with_cancel(
    path: &Path,
    max_bytes: Option<usize>,
    max_lines: Option<usize>,
    cancellation: &HistoryCancellationToken,
    mut visit: impl FnMut(&str) -> bool,
) -> Result<(), HistoryScanCancelled> {
    cancellation.check()?;
    let Some(file) = open_regular_file_no_follow(path) else {
        return Ok(());
    };
    let mut reader = BufReader::with_capacity(HISTORY_READ_CHUNK_BYTES, file);
    let mut consumed = 0_usize;
    let mut lines = 0_usize;
    loop {
        cancellation.check()?;
        if max_lines.is_some_and(|limit| lines >= limit)
            || max_bytes.is_some_and(|limit| consumed >= limit)
        {
            break;
        }
        let line_limit = max_bytes
            .map(|limit| limit.saturating_sub(consumed))
            .unwrap_or(usize::MAX);
        let next = match read_bounded_line(&mut reader, line_limit, cancellation) {
            Ok(next) => next,
            Err(BoundedReadFailure::Cancelled) => return Err(HistoryScanCancelled),
            Err(BoundedReadFailure::LimitExceeded | BoundedReadFailure::Io) => break,
        };
        let Some((line, line_bytes)) = next else {
            break;
        };
        consumed = consumed.saturating_add(line_bytes);
        lines = lines.saturating_add(1);
        if !visit(&line) {
            break;
        }
    }
    cancellation.check()
}

fn claude_root_metadata(
    path: &Path,
    fallback_id: &str,
    cancellation: &HistoryCancellationToken,
) -> Result<Option<ClaudeRootMetadata>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(file) = open_regular_file_no_follow(path) else {
        return Ok(None);
    };
    let Some(fingerprint) = file.metadata().ok().and_then(|metadata| {
        let modified_ns = metadata
            .modified()
            .ok()?
            .duration_since(UNIX_EPOCH)
            .ok()?
            .as_nanos();
        Some(FileFingerprint {
            len: metadata.len(),
            modified_ns,
        })
    }) else {
        return Ok(None);
    };
    let cache = CLAUDE_METADATA_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(cached) = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(path)
        .filter(|cached| cached.fingerprint == fingerprint)
        .cloned()
    {
        return Ok(Some(cached.metadata));
    }

    let mut metadata = ClaudeRootMetadata {
        id: fallback_id.to_string(),
        title: format!("Claude session {}", short_session_id(fallback_id)),
    };
    let mut reader = BufReader::with_capacity(HISTORY_READ_CHUNK_BYTES, file);
    let first_line = read_bounded_line(&mut reader, HISTORY_METADATA_LINE_MAX_BYTES, cancellation)
        .map(|line| line.map(|(line, _)| line));
    match first_line {
        Ok(Some(line)) => {
            if let Ok(event) = serde_json::from_str::<Value>(&line) {
                if let Some(session_id) = event
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|id| !id.is_empty())
                {
                    metadata.id = session_id.to_string();
                }
                let title = event
                    .get("aiTitle")
                    .or_else(|| event.get("customTitle"))
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|title| !title.is_empty())
                    .map(str::to_string)
                    .or_else(|| {
                        (event.get("type").and_then(Value::as_str) == Some("user")
                            && event.get("userType").and_then(Value::as_str) == Some("external"))
                        .then(|| {
                            event
                                .get("message")
                                .and_then(|message| message.get("content"))
                                .and_then(extract_claude_visible_text)
                        })
                        .flatten()
                    });
                if let Some(title) = title {
                    metadata.title = truncate(&title, 140);
                }
            }
        }
        Err(BoundedReadFailure::Cancelled) => return Err(HistoryScanCancelled),
        Ok(None) | Err(BoundedReadFailure::LimitExceeded | BoundedReadFailure::Io) => {}
    }
    cancellation.check()?;
    let mut cache = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if cache.len() >= 8_192 {
        cache.clear();
    }
    cache.insert(
        path.to_path_buf(),
        CachedClaudeMetadata {
            fingerprint,
            metadata: metadata.clone(),
        },
    );
    Ok(Some(metadata))
}

fn short_session_id(session_id: &str) -> String {
    session_id.chars().take(8).collect()
}

#[derive(Deserialize)]
struct ClaudeUserConfig {
    #[serde(default, rename = "githubRepoPaths")]
    github_repo_paths: Value,
}

fn read_claude_user_config(
    home: &Path,
    cancellation: &HistoryCancellationToken,
) -> Result<Option<ClaudeUserConfig>, HistoryScanCancelled> {
    cancellation.check()?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let mut file = match options.open(home.join(".claude.json")) {
        Ok(file) => file,
        Err(_) => return Ok(None),
    };
    let metadata = match file.metadata() {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) | Err(_) => return Ok(None),
    };
    if metadata.len() > CLAUDE_CONFIG_MAX_BYTES {
        return Ok(None);
    }

    let max_bytes = CLAUDE_CONFIG_MAX_BYTES as usize;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    let mut chunk = [0_u8; HISTORY_READ_CHUNK_BYTES];
    loop {
        cancellation.check()?;
        let remaining = max_bytes.saturating_add(1).saturating_sub(bytes.len());
        if remaining == 0 {
            return Ok(None);
        }
        let read_len = remaining.min(chunk.len());
        let count = match file.read(&mut chunk[..read_len]) {
            Ok(count) => count,
            Err(_) => return Ok(None),
        };
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..count]);
        if bytes.len() > max_bytes {
            return Ok(None);
        }
    }
    cancellation.check()?;
    Ok(serde_json::from_slice(&bytes).ok())
}

fn claude_registered_path(home: &Path, raw: &str) -> Option<PathBuf> {
    if raw.is_empty() || raw.len() > CLAUDE_REPO_PATH_MAX_BYTES || raw.as_bytes().contains(&0) {
        return None;
    }
    let path = if raw == "~" {
        home.to_path_buf()
    } else if let Some(relative) = raw.strip_prefix("~/") {
        home.join(relative)
    } else {
        PathBuf::from(raw)
    };
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return None;
    }
    Some(path)
}

fn same_normalized_path(left: &Path, right: &Path) -> bool {
    left == right || normalize_cwd(left) == normalize_cwd(right)
}

fn push_cwd_candidate(out: &mut Vec<PathBuf>, seen: &mut HashSet<PathBuf>, path: PathBuf) {
    let normalized = normalize_cwd(&path);
    if seen.insert(normalized.clone()) {
        out.push(normalized);
    }
    if seen.insert(path.clone()) {
        out.push(path);
    }
}

/// Expand Claude history only through the provider's own repository registry.
///
/// A repository group is accepted only when one of its registered paths is the selected folder.
/// This mirrors Claude's worktree-aware resume picker without prefix matching or scanning unrelated
/// project buckets. Historical paths may no longer exist, but their provider-owned transcript bucket
/// can still contain resumable roots. Any malformed, ambiguous, or oversized registry fails closed to
/// the original folder candidates.
fn claude_repo_path_candidates(
    cwd_candidates: &[PathBuf],
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<PathBuf>, HistoryScanCancelled> {
    cancellation.check()?;
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for cwd in cwd_candidates {
        push_cwd_candidate(&mut out, &mut seen, cwd.clone());
    }
    let fallback = out.clone();
    let Some(home) = home_dir() else {
        return Ok(out);
    };
    let Some(config) = read_claude_user_config(&home, cancellation)? else {
        return Ok(out);
    };
    let Some(groups) = config.github_repo_paths.as_object() else {
        return Ok(fallback);
    };

    let mut matched_group: Option<Vec<PathBuf>> = None;
    for (repo, registered) in groups {
        cancellation.check()?;
        let Some(registered) = registered.as_array() else {
            // An unrelated malformed entry cannot authorize a path and must not hide a valid group.
            continue;
        };
        let oversized = registered.len() > CLAUDE_REPO_PATH_MAX_COUNT;
        let mut malformed = false;
        let mut matches_selected = false;
        let mut paths = Vec::new();
        for raw in registered {
            cancellation.check()?;
            let Some(raw) = raw.as_str() else {
                malformed = true;
                continue;
            };
            let Some(path) = claude_registered_path(&home, raw) else {
                malformed = true;
                continue;
            };
            if cwd_candidates
                .iter()
                .any(|cwd| same_normalized_path(&path, cwd))
            {
                matches_selected = true;
            }
            if paths.len() < CLAUDE_REPO_PATH_MAX_COUNT {
                paths.push(path);
            }
        }
        if !matches_selected {
            continue;
        }
        if repo.trim().is_empty()
            || repo.len() > CLAUDE_REPO_PATH_MAX_BYTES
            || registered.is_empty()
            || oversized
            || malformed
        {
            return Ok(fallback);
        }
        if matched_group.is_some() {
            return Ok(fallback);
        }
        matched_group = Some(paths);
    }
    let Some(paths) = matched_group else {
        return Ok(out);
    };
    for path in paths {
        cancellation.check()?;
        push_cwd_candidate(&mut out, &mut seen, path);
    }
    Ok(out)
}

#[derive(Clone, Debug)]
struct ClaudeProjectHistoryBucket {
    canonical_root: PathBuf,
    canonical_dir: PathBuf,
}

fn claude_project_history_buckets(
    home: &Path,
    cwd_candidates: &[PathBuf],
) -> Vec<ClaudeProjectHistoryBucket> {
    let root = home.join(".claude").join("projects");
    let Ok(root_metadata) = fs::symlink_metadata(&root) else {
        return Vec::new();
    };
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Vec::new();
    }
    let Ok(canonical_root) = fs::canonicalize(&root) else {
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut buckets = Vec::new();
    for cwd in cwd_candidates {
        let expected = root.join(encode_claude_cwd(cwd));
        let Ok(metadata) = fs::symlink_metadata(&expected) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let Ok(canonical_dir) = fs::canonicalize(&expected) else {
            continue;
        };
        if canonical_dir.parent() != Some(canonical_root.as_path())
            || !canonical_dir.starts_with(&canonical_root)
            || !seen.insert(canonical_dir.clone())
        {
            continue;
        }
        buckets.push(ClaudeProjectHistoryBucket {
            canonical_root: canonical_root.clone(),
            canonical_dir,
        });
    }
    buckets
}

fn claude_root_in_bucket(path: &Path, bucket: &ClaudeProjectHistoryBucket) -> Option<PathBuf> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || path.extension().and_then(|extension| extension.to_str()) != Some("jsonl")
    {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    (canonical.parent() == Some(bucket.canonical_dir.as_path())
        && canonical.starts_with(&bucket.canonical_root))
    .then_some(canonical)
}

fn claude_root_in_allowed_buckets(
    path: &Path,
    buckets: &[ClaudeProjectHistoryBucket],
) -> Option<PathBuf> {
    buckets
        .iter()
        .find_map(|bucket| claude_root_in_bucket(path, bucket))
}

fn claude_bucket_for_root<'a>(
    path: &Path,
    buckets: &'a [ClaudeProjectHistoryBucket],
) -> Option<&'a ClaudeProjectHistoryBucket> {
    buckets
        .iter()
        .find(|bucket| claude_root_in_bucket(path, bucket).is_some())
}

fn claude_sidechain_in_bucket(path: &Path, bucket: &ClaudeProjectHistoryBucket) -> Option<PathBuf> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    (canonical.parent() == Some(bucket.canonical_dir.as_path())
        && canonical.starts_with(&bucket.canonical_root))
    .then_some(canonical)
}

fn open_regular_file_no_follow(path: &Path) -> Option<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path).ok()?;
    file.metadata()
        .ok()
        .filter(|metadata| metadata.file_type().is_file())?;
    Some(file)
}

fn list_claude_sessions(
    cwd_candidates: &[PathBuf],
    in_use: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentHistorySession>, HistoryScanCancelled> {
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    // Claude stores transcripts globally but buckets them by encoded cwd. We try the selected path
    // and its canonical form because Finder-selected folders, symlinks, and provider CLIs do not
    // always agree on which spelling was used when the transcript was written.
    let mut out = Vec::new();
    let mut seen_paths = HashSet::new();
    let mut budget = HistoryEnumerationBudget::provider_store();
    for bucket in claude_project_history_buckets(&home, cwd_candidates) {
        cancellation.check()?;
        let Ok(entries) = fs::read_dir(&bucket.canonical_dir) else {
            continue;
        };
        for entry in entries {
            cancellation.check()?;
            if !budget.consume() {
                break;
            }
            let Ok(entry) = entry else {
                continue;
            };
            let Some(path) = claude_root_in_bucket(&entry.path(), &bucket) else {
                continue;
            };
            if !seen_paths.insert(path.clone()) {
                continue;
            }
            let id = path
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            if id.is_empty() {
                continue;
            }
            let Some(metadata) = claude_root_metadata(&path, &id, cancellation)? else {
                continue;
            };
            push_session(
                &mut out,
                "claude",
                metadata.id,
                path,
                metadata.title,
                None,
                in_use,
            );
        }
        if budget.exhausted() {
            break;
        }
    }
    out.sort_by_key(|row| std::cmp::Reverse(row.modified_at_ms));
    let mut seen_ids = HashSet::new();
    out.retain(|session| seen_ids.insert(session.id.clone()));
    Ok(out)
}

fn claude_files_for_session(
    surfaced_root: &Path,
    cwd_candidates: &[PathBuf],
    session_id: &str,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<PathBuf>, String> {
    cancellation.check().map_err(|error| error.to_string())?;
    let home = home_dir().ok_or_else(|| "Claude home directory is unavailable".to_string())?;
    let buckets = claude_project_history_buckets(&home, cwd_candidates);
    if claude_root_in_allowed_buckets(surfaced_root, &buckets).is_none() {
        return Err("surfaced Claude root is outside the allowed project buckets".to_string());
    }
    let mut matched = Vec::new();
    let mut budget = HistoryEnumerationBudget::provider_store();
    for bucket in &buckets {
        cancellation.check().map_err(|error| error.to_string())?;
        let entries = match fs::read_dir(&bucket.canonical_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "enumerate Claude project history {}: {error}",
                    bucket.canonical_dir.display()
                ));
            }
        };
        for entry in entries {
            cancellation.check().map_err(|error| error.to_string())?;
            budget.consume_strict()?;
            let entry = entry.map_err(|error| {
                format!(
                    "read Claude project history entry {}: {error}",
                    bucket.canonical_dir.display()
                )
            })?;
            let file_type = entry.file_type().map_err(|error| {
                format!("inspect Claude history {}: {error}", entry.path().display())
            })?;
            if file_type.is_symlink() {
                return Err(format!(
                    "refuse symlink in Claude history delete traversal {}",
                    entry.path().display()
                ));
            }
            if !file_type.is_file() {
                continue;
            }
            if entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("jsonl")
            {
                continue;
            }
            let candidate = claude_root_in_bucket(&entry.path(), bucket).ok_or_else(|| {
                format!(
                    "Claude history root escaped its allowed bucket {}",
                    entry.path().display()
                )
            })?;
            let fallback_id = candidate
                .file_stem()
                .map(|stem| stem.to_string_lossy().into_owned())
                .unwrap_or_default();
            let fallback_id = clean_opaque_session_id(fallback_id.trim()).ok_or_else(|| {
                format!("invalid Claude history filename {}", candidate.display())
            })?;
            let file = open_regular_file_no_follow(&candidate).ok_or_else(|| {
                format!(
                    "open Claude history {} as a regular file",
                    candidate.display()
                )
            })?;
            let mut reader = BufReader::with_capacity(HISTORY_READ_CHUNK_BYTES, file);
            let (line, _) =
                read_bounded_line(&mut reader, HISTORY_METADATA_LINE_MAX_BYTES, cancellation)
                    .map_err(|error| {
                        format!(
                            "read Claude history metadata {}: {error:?}",
                            candidate.display()
                        )
                    })?
                    .ok_or_else(|| {
                        format!("empty Claude history metadata {}", candidate.display())
                    })?;
            let event = serde_json::from_str::<Value>(&line).map_err(|error| {
                format!(
                    "parse Claude history metadata {}: {error}",
                    candidate.display()
                )
            })?;
            let metadata_id = match event.get("sessionId").and_then(Value::as_str) {
                Some(candidate_id) => {
                    clean_opaque_session_id(candidate_id.trim()).ok_or_else(|| {
                        format!("invalid Claude session id in {}", candidate.display())
                    })?
                }
                None => fallback_id,
            };
            if metadata_id == session_id {
                matched.push(candidate);
            }
        }
    }
    Ok(matched)
}

fn extract_claude_visible_text(content: &Value) -> Option<String> {
    if let Some(text) = content.as_str() {
        return Some(text.to_string());
    }
    let blocks = content.as_array()?;
    let text = blocks
        .iter()
        .filter_map(|block| {
            block.as_str().map(str::to_string).or_else(|| {
                (block.get("type").and_then(Value::as_str) == Some("text"))
                    .then(|| block.get("text").and_then(Value::as_str))
                    .flatten()
                    .map(str::to_string)
            })
        })
        .collect::<Vec<_>>()
        .join(" ");
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn preview_session_file_with_cancel(
    agent: &str,
    path: &Path,
    max_lines: usize,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentPreviewLine>, HistoryScanCancelled> {
    cancellation.check()?;
    if max_lines == 0 {
        return Ok(Vec::new());
    }
    let file = open_regular_file_no_follow(path);
    let Some(file) = file else {
        return Ok(Vec::new());
    };
    let mut reader = BufReader::with_capacity(HISTORY_READ_CHUNK_BYTES, file);
    let mut out = Vec::new();
    let mut consumed = 0;
    while consumed < HISTORY_PREVIEW_MAX_BYTES {
        cancellation.check()?;
        if out.len() >= max_lines {
            break;
        }
        let remaining = HISTORY_PREVIEW_MAX_BYTES.saturating_sub(consumed);
        let line_limit = remaining.min(HISTORY_PREVIEW_LINE_MAX_BYTES);
        let line = match read_bounded_line(&mut reader, line_limit, cancellation) {
            Ok(Some((line, line_bytes))) => {
                consumed = consumed.saturating_add(line_bytes);
                line
            }
            Ok(None) | Err(BoundedReadFailure::LimitExceeded) => break,
            Err(BoundedReadFailure::Cancelled) => return Err(HistoryScanCancelled),
            Err(BoundedReadFailure::Io) => return Ok(Vec::new()),
        };
        if line.trim().is_empty() {
            continue;
        }
        let Ok(evt) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        match agent {
            "claude" => {
                let Some(role) = evt.get("type").and_then(Value::as_str) else {
                    continue;
                };
                if role != "user" && role != "assistant" {
                    continue;
                }
                if evt.get("isMeta").and_then(Value::as_bool) == Some(true)
                    || (role == "user"
                        && evt
                            .get("userType")
                            .and_then(Value::as_str)
                            .is_some_and(|user_type| user_type != "external"))
                {
                    continue;
                }
                let message = evt.get("message").unwrap_or(&Value::Null);
                if message
                    .get("role")
                    .and_then(Value::as_str)
                    .is_some_and(|message_role| message_role != role)
                {
                    continue;
                }
                let Some(text) = evt
                    .get("message")
                    .and_then(|message| message.get("content"))
                    .and_then(extract_claude_visible_text)
                else {
                    continue;
                };
                push_preview_line(&mut out, role, &text);
            }
            "codex" => {
                if evt.get("type").and_then(Value::as_str) != Some("response_item") {
                    continue;
                }
                let payload = evt.get("payload").unwrap_or(&Value::Null);
                if payload.get("type").and_then(Value::as_str) != Some("message") {
                    continue;
                }
                let role = match payload.get("role").and_then(Value::as_str) {
                    Some("user") => "user",
                    Some("assistant") => "assistant",
                    _ => continue,
                };
                let visible_item_type = if role == "user" {
                    "input_text"
                } else {
                    "output_text"
                };
                let text = payload
                    .get("content")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter(|item| {
                                item.get("type").and_then(Value::as_str) == Some(visible_item_type)
                            })
                            .filter_map(|item| item.get("text").and_then(Value::as_str))
                            .collect::<Vec<_>>()
                            .join(" ")
                    })
                    .unwrap_or_default();
                if !text.starts_with("<environment_context>") {
                    push_preview_line(&mut out, role, &text);
                }
            }
            "gemini" => {
                let Some(messages) = evt
                    .get("$set")
                    .and_then(|set| set.get("messages"))
                    .and_then(Value::as_array)
                else {
                    continue;
                };
                for message in messages {
                    if out.len() >= max_lines {
                        break;
                    }
                    let role = match message.get("type").and_then(Value::as_str) {
                        Some("user") => "user",
                        Some("assistant") => "assistant",
                        _ => continue,
                    };
                    let text = message
                        .get("content")
                        .and_then(Value::as_array)
                        .map(|items| {
                            items
                                .iter()
                                .filter(|item| {
                                    item.get("thought").and_then(Value::as_bool) != Some(true)
                                        && item
                                            .get("type")
                                            .and_then(Value::as_str)
                                            .is_none_or(|item_type| item_type == "text")
                                })
                                .filter_map(|item| item.get("text").and_then(Value::as_str))
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                        .unwrap_or_default();
                    if !text.starts_with("<session_context>") {
                        push_preview_line(&mut out, role, &text);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

fn push_preview_line(out: &mut Vec<AgentPreviewLine>, role: &str, text: &str) {
    let text = truncate(text, 400);
    if text.is_empty() {
        return;
    }
    out.push(AgentPreviewLine {
        role: role.to_string(),
        text,
    });
}

fn walk_jsonl_with_cancel(
    root: &Path,
    max_depth: usize,
    out: &mut Vec<PathBuf>,
    cancellation: &HistoryCancellationToken,
) -> Result<(), HistoryScanCancelled> {
    let mut budget = HistoryEnumerationBudget::provider_store();
    walk_jsonl_with_budget(root, max_depth, out, cancellation, &mut budget)
}

fn walk_jsonl_with_budget(
    root: &Path,
    max_depth: usize,
    out: &mut Vec<PathBuf>,
    cancellation: &HistoryCancellationToken,
    budget: &mut HistoryEnumerationBudget,
) -> Result<(), HistoryScanCancelled> {
    cancellation.check()?;
    let Ok(entries) = fs::read_dir(root) else {
        return Ok(());
    };
    for entry in entries {
        cancellation.check()?;
        if !budget.consume() {
            break;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() && max_depth > 0 {
            walk_jsonl_with_budget(&path, max_depth - 1, out, cancellation, budget)?;
            if budget.exhausted() {
                break;
            }
        } else if file_type.is_file()
            && path.extension().and_then(|ext| ext.to_str()) == Some("jsonl")
        {
            out.push(path);
        }
    }
    Ok(())
}

fn walk_jsonl_strict_for_delete(
    root: &Path,
    max_depth: usize,
    out: &mut Vec<PathBuf>,
    cancellation: &HistoryCancellationToken,
) -> Result<(), String> {
    let mut budget = HistoryEnumerationBudget::provider_store();
    walk_jsonl_strict_with_budget(root, max_depth, out, cancellation, &mut budget)
}

fn walk_jsonl_strict_with_budget(
    root: &Path,
    max_depth: usize,
    out: &mut Vec<PathBuf>,
    cancellation: &HistoryCancellationToken,
    budget: &mut HistoryEnumerationBudget,
) -> Result<(), String> {
    cancellation.check().map_err(|error| error.to_string())?;
    let entries = fs::read_dir(root)
        .map_err(|error| format!("enumerate provider history {}: {error}", root.display()))?;
    for entry in entries {
        cancellation.check().map_err(|error| error.to_string())?;
        budget.consume_strict()?;
        let entry = entry
            .map_err(|error| format!("read provider history entry {}: {error}", root.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("inspect provider history {}: {error}", path.display()))?;
        if file_type.is_symlink() {
            return Err(format!(
                "refuse symlink in provider history delete traversal {}",
                path.display()
            ));
        }
        if file_type.is_dir() {
            if max_depth == 0 {
                return Err(format!(
                    "refuse unexpected nested provider history directory {}",
                    path.display()
                ));
            }
            walk_jsonl_strict_with_budget(&path, max_depth - 1, out, cancellation, budget)?;
        } else if file_type.is_file()
            && path.extension().and_then(|extension| extension.to_str()) == Some("jsonl")
        {
            out.push(path);
        }
    }
    Ok(())
}

fn list_codex_sessions(
    cwd_candidates: &[PathBuf],
    in_use: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentHistorySession>, HistoryScanCancelled> {
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let mut files = Vec::new();
    walk_jsonl_with_cancel(
        &home.join(".codex").join("sessions"),
        3,
        &mut files,
        cancellation,
    )?;
    let mut roots = Vec::new();
    let mut newest_fragment_ms: HashMap<String, u64> = HashMap::new();
    for path in files {
        cancellation.check()?;
        let Some(fingerprint) = file_fingerprint(&path) else {
            continue;
        };
        let cache_key = CodexCacheKey {
            path: path.clone(),
            cwd_candidates: cwd_candidates.to_vec(),
        };
        let cache = CODEX_SCAN_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
        let cached = cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&cache_key)
            .filter(|cached| cached.fingerprint == fingerprint)
            .cloned();
        let scan = if let Some(cached) = cached {
            cached.scan
        } else {
            cancellation.check()?;
            let Some(file) = open_regular_file_no_follow(&path) else {
                continue;
            };
            let mut reader = BufReader::with_capacity(HISTORY_READ_CHUNK_BYTES, file);
            let scan = match scan_codex_file_with_cancel(&mut reader, cwd_candidates, cancellation)
            {
                Ok(scan) => scan,
                Err(BoundedReadFailure::Cancelled) => return Err(HistoryScanCancelled),
                Err(BoundedReadFailure::LimitExceeded | BoundedReadFailure::Io) => {
                    CodexFileScan::Ignore
                }
            };
            cancellation.check()?;
            let mut cache = cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if cache.len() >= 8_192 {
                cache.clear();
            }
            cache.insert(
                cache_key,
                CachedCodexScan {
                    fingerprint,
                    scan: scan.clone(),
                },
            );
            scan
        };
        let modified_at_ms = u64::try_from(fingerprint.modified_ns / 1_000_000).unwrap_or(u64::MAX);
        let session_id = match &scan {
            CodexFileScan::Root(session) => Some(session.id.as_str()),
            CodexFileScan::Continuation { session_id } => Some(session_id.as_str()),
            CodexFileScan::Ignore => None,
        };
        if let Some(session_id) = session_id {
            newest_fragment_ms
                .entry(session_id.to_string())
                .and_modify(|current| *current = (*current).max(modified_at_ms))
                .or_insert(modified_at_ms);
        }
        if let CodexFileScan::Root(session) = scan {
            roots.push((session, path));
        }
    }

    let mut out = Vec::new();
    for (session, path) in roots {
        let newest_ms = newest_fragment_ms.get(&session.id).copied();
        push_session(
            &mut out,
            "codex",
            session.id,
            path,
            session.first_message,
            None,
            in_use,
        );
        if let (Some(row), Some(newest_ms)) = (out.last_mut(), newest_ms) {
            row.modified_at_ms = newest_ms;
        }
    }
    out.sort_by_key(|row| std::cmp::Reverse(row.modified_at_ms));
    // Modern Codex compaction/subagent rollout files retain the interactive root's
    // `payload.session_id`; only that root is resumable, while every fragment contributes recency.
    // Legacy roots predate `session_id` and remain valid standalone sessions. Defensive deduplication
    // also prevents a malformed store from surfacing two rows for one provider resume identity.
    let mut seen_ids = HashSet::new();
    out.retain(|session| seen_ids.insert(session.id.clone()));
    Ok(out)
}

fn codex_files_for_session(
    session_id: &str,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<PathBuf>, String> {
    let Some(home) = home_dir() else {
        return Err("cannot resolve provider history home directory".to_string());
    };
    let mut files = Vec::new();
    walk_jsonl_strict_for_delete(
        &home.join(".codex").join("sessions"),
        3,
        &mut files,
        cancellation,
    )?;
    let mut matched = Vec::new();
    for path in files {
        cancellation.check().map_err(|error| error.to_string())?;
        let file = open_regular_file_no_follow(&path)
            .ok_or_else(|| format!("open Codex history {} as a regular file", path.display()))?;
        let mut reader = BufReader::with_capacity(HISTORY_READ_CHUNK_BYTES, file);
        let (line, _) =
            read_bounded_line(&mut reader, HISTORY_METADATA_LINE_MAX_BYTES, cancellation)
                .map_err(|error| {
                    format!("read Codex history metadata {}: {error:?}", path.display())
                })?
                .ok_or_else(|| format!("empty Codex history metadata {}", path.display()))?;
        let metadata = serde_json::from_str::<Value>(&line)
            .map_err(|error| format!("parse Codex history metadata {}: {error}", path.display()))?;
        if metadata.get("type").and_then(Value::as_str) != Some("session_meta")
            || metadata
                .get("payload")
                .and_then(|payload| payload.get("id"))
                .and_then(Value::as_str)
                .map(str::trim)
                .and_then(clean_opaque_session_id)
                .is_none()
        {
            return Err(format!(
                "invalid Codex session metadata in {}",
                path.display()
            ));
        }
        let mut metadata_reader = std::io::Cursor::new(line.into_bytes());
        let scan = scan_codex_file_with_cancel(&mut metadata_reader, &[], cancellation)
            .map_err(|error| format!("classify Codex history {}: {error:?}", path.display()))?;
        let belongs = match scan {
            CodexFileScan::Root(root) => root.id == session_id,
            CodexFileScan::Continuation { session_id: parent } => parent == session_id,
            CodexFileScan::Ignore => false,
        };
        if belongs {
            matched.push(path);
        }
    }
    Ok(matched)
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct CodexCacheKey {
    path: PathBuf,
    cwd_candidates: Vec<PathBuf>,
}

#[derive(Clone)]
struct CachedCodexScan {
    fingerprint: FileFingerprint,
    scan: CodexFileScan,
}

static CODEX_SCAN_CACHE: OnceLock<Mutex<HashMap<CodexCacheKey, CachedCodexScan>>> = OnceLock::new();

#[derive(Clone)]
struct CodexSessionSummary {
    id: String,
    first_message: String,
}

#[derive(Clone)]
enum CodexFileScan {
    Root(CodexSessionSummary),
    Continuation { session_id: String },
    Ignore,
}

/// Read just enough of a Codex transcript to establish folder ownership before scanning its body.
/// Codex stores every project's transcripts in one global tree, so consuming non-matching tails here
/// makes an otherwise folder-scoped dashboard request proportional to the user's entire history.
#[cfg(test)]
fn read_codex_session(
    reader: &mut impl BufRead,
    cwd_candidates: &[PathBuf],
) -> std::io::Result<Option<CodexSessionSummary>> {
    match scan_codex_file_with_cancel(reader, cwd_candidates, &HistoryCancellationToken::new()) {
        Ok(CodexFileScan::Root(summary)) => Ok(Some(summary)),
        Ok(CodexFileScan::Continuation { .. } | CodexFileScan::Ignore) => Ok(None),
        Err(BoundedReadFailure::Cancelled) => Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            HistoryScanCancelled,
        )),
        Err(BoundedReadFailure::LimitExceeded) => Ok(None),
        Err(BoundedReadFailure::Io) => Err(std::io::Error::other("bounded transcript read failed")),
    }
}

fn scan_codex_file_with_cancel(
    reader: &mut impl BufRead,
    cwd_candidates: &[PathBuf],
    cancellation: &HistoryCancellationToken,
) -> Result<CodexFileScan, BoundedReadFailure> {
    let Some((line, _)) = read_bounded_line(reader, HISTORY_METADATA_LINE_MAX_BYTES, cancellation)?
    else {
        return Ok(CodexFileScan::Ignore);
    };

    let Ok(meta) = serde_json::from_str::<Value>(&line) else {
        return Ok(CodexFileScan::Ignore);
    };
    if meta.get("type").and_then(Value::as_str) != Some("session_meta") {
        return Ok(CodexFileScan::Ignore);
    }
    let payload = meta.get("payload").unwrap_or(&Value::Null);
    let Some(id) = payload
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .and_then(clean_opaque_session_id)
    else {
        return Ok(CodexFileScan::Ignore);
    };
    let session_id = payload
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|session_id| !session_id.is_empty())
        .and_then(clean_opaque_session_id);
    // Older Codex subagent/compaction rollouts omitted payload.session_id but recorded the same
    // ownership at this exact path. Do not inspect arbitrary source fields: this narrow fallback
    // is the only legacy continuation discriminator observed in the provider store.
    let parent_thread_id = payload
        .get("source")
        .and_then(|source| source.get("subagent"))
        .and_then(|subagent| subagent.get("thread_spawn"))
        .and_then(|spawn| spawn.get("parent_thread_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|session_id| !session_id.is_empty())
        .and_then(clean_opaque_session_id);
    let interactive_source = match payload.get("source") {
        None => true,
        Some(Value::String(source)) => source == "cli" || source == "vscode",
        Some(_) => false,
    };
    let interactive_root = interactive_source
        && session_id
            .as_deref()
            .is_none_or(|session_id| session_id == id);
    if !interactive_root {
        return Ok(match session_id.or(parent_thread_id) {
            Some(session_id) => CodexFileScan::Continuation { session_id },
            None => CodexFileScan::Ignore,
        });
    }
    let session_cwd = payload
        .get("cwd")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !cwd_candidates.is_empty()
        && (session_cwd.is_empty()
            || !cwd_candidates
                .iter()
                .any(|candidate| Path::new(session_cwd) == candidate))
    {
        return Ok(CodexFileScan::Ignore);
    }

    // Listing is deliberately first-line-only. Current Codex session_meta has no human title; a
    // stable short identity is preferable to touching transcript bodies across a multi-gigabyte
    // store. The bounded preview path loads user/assistant text only after explicit selection.
    let first_message = payload
        .get("title")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|title| !title.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("Codex session {}", short_session_id(&id)));
    Ok(CodexFileScan::Root(CodexSessionSummary {
        id: session_id.unwrap_or(id),
        first_message,
    }))
}

fn open_read_only_provider_db(path: &Path) -> Option<rusqlite::Connection> {
    let connection = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    // Provider CLIs keep their catalogs in WAL mode. A short, bounded wait tolerates an overlapping
    // checkpoint without ever making dashboard rendering hang behind the provider process.
    connection.busy_timeout(Duration::from_millis(250)).ok()?;
    Some(connection)
}

const SQLITE_CANCELLATION_PROGRESS_OPS: i32 = 100;

fn install_sqlite_cancellation(
    connection: &rusqlite::Connection,
    cancellation: &HistoryCancellationToken,
) {
    let cancellation = cancellation.clone();
    connection.progress_handler(
        SQLITE_CANCELLATION_PROGRESS_OPS,
        Some(move || cancellation.is_cancelled()),
    );
}

fn sqlite_table_has_column(
    connection: &rusqlite::Connection,
    table: &str,
    column: &str,
    cancellation: &HistoryCancellationToken,
) -> Result<Option<bool>, HistoryScanCancelled> {
    cancellation.check()?;
    let Ok(mut statement) = connection.prepare(
        "SELECT 1
           FROM pragma_table_info(?1)
          WHERE name = ?2
          LIMIT 1",
    ) else {
        cancellation.check()?;
        return Ok(None);
    };
    let result = statement.exists(rusqlite::params![table, column]);
    cancellation.check()?;
    Ok(result.ok())
}

const DEVIN_SESSION_LIST_LIMIT: usize = 500;
const DEVIN_MAIN_CHAIN_LIMIT: usize = 1_024;
const DEVIN_CHAT_MESSAGE_MAX_CHARS: usize = 16 * 1024;
const DEVIN_SESSION_ID_MAX_BYTES: usize = 1_024;
const DEVIN_WORKING_DIRECTORY_MAX_BYTES: usize = 16 * 1024;
const DEVIN_PROVIDER_TITLE_MAX_BYTES: usize = 4 * 1024;
const COPILOT_SESSION_LIST_LIMIT: usize = 500;
const COPILOT_SESSION_ID_MAX_BYTES: usize = 128;
const COPILOT_WORKING_DIRECTORY_MAX_BYTES: usize = 16 * 1024;
const COPILOT_SUMMARY_MAX_BYTES: usize = 16 * 1024;
const COPILOT_TIMESTAMP_MAX_BYTES: usize = 128;
const ANTIGRAVITY_SESSION_LIST_LIMIT: usize = 500;
const ANTIGRAVITY_SESSION_ID_MAX_BYTES: usize = 128;
const ANTIGRAVITY_TITLE_MAX_BYTES: usize = 4 * 1024;
const ANTIGRAVITY_PREVIEW_MAX_BYTES: usize = 16 * 1024;
const ANTIGRAVITY_TIMESTAMP_MAX_BYTES: usize = 128;
const OPENCODE_SESSION_LIST_LIMIT: usize = 200;
const OPENCODE_SESSION_ID_MAX_BYTES: usize = 1_024;
const OPENCODE_DIRECTORY_MAX_BYTES: usize = 16 * 1024;
const OPENCODE_TITLE_MAX_BYTES: usize = 4 * 1024;
const OPENCODE_AGENT_MAX_BYTES: usize = 4 * 1024;
const OPENCODE_MODEL_MAX_BYTES: usize = 16 * 1024;

fn devin_store_path(home: &Path) -> PathBuf {
    home.join(".local")
        .join("share")
        .join("devin")
        .join("cli")
        .join("sessions.db")
}

fn visit_devin_main_chain(
    connection: &rusqlite::Connection,
    session_id: &str,
    main_chain_id: i64,
    cancellation: &HistoryCancellationToken,
    mut visit: impl FnMut(&str) -> bool,
) -> Result<(), HistoryScanCancelled> {
    cancellation.check()?;
    if clean_opaque_session_id(session_id).as_deref() != Some(session_id) {
        return Ok(());
    }
    let Ok(mut statement) = connection.prepare(
        "WITH RECURSIVE main_chain(node_id, parent_node_id, chat_message, depth, seen) AS (
             SELECT node_id,
                    parent_node_id,
                    chat_message,
                    0,
                    ',' || CAST(node_id AS TEXT) || ','
               FROM message_nodes
              WHERE session_id = ?1 AND node_id = ?2
             UNION ALL
             SELECT parent.node_id,
                    parent.parent_node_id,
                    parent.chat_message,
                    chain.depth + 1,
                    chain.seen || CAST(parent.node_id AS TEXT) || ','
               FROM main_chain chain
               JOIN message_nodes parent
                 ON parent.session_id = ?1
                AND parent.node_id = chain.parent_node_id
              WHERE chain.depth + 1 < ?3
                AND instr(
                      chain.seen,
                      ',' || CAST(parent.node_id AS TEXT) || ','
                    ) = 0
         )
         SELECT CASE
                  WHEN length(chat_message) <= ?4 THEN chat_message
                  ELSE ''
                END
           FROM main_chain
          ORDER BY depth DESC
          LIMIT ?3",
    ) else {
        cancellation.check()?;
        return Ok(());
    };
    let Ok(rows) = statement.query_map(
        rusqlite::params![
            session_id,
            main_chain_id,
            DEVIN_MAIN_CHAIN_LIMIT as i64,
            DEVIN_CHAT_MESSAGE_MAX_CHARS as i64,
        ],
        |row| row.get::<_, String>(0),
    ) else {
        cancellation.check()?;
        return Ok(());
    };
    for row in rows {
        cancellation.check()?;
        let Ok(json) = row else {
            cancellation.check()?;
            continue;
        };
        if !json.is_empty() && !visit(&json) {
            break;
        }
    }
    cancellation.check()
}

fn devin_message_content(value: &Value) -> Option<String> {
    let content = value.get("content")?;
    if let Some(text) = content.as_str() {
        let text = truncate(text, 4_000);
        return (!text.is_empty()).then_some(text);
    }
    let blocks = content.as_array()?;
    let text = blocks
        .iter()
        .filter_map(|block| {
            if let Some(text) = block.as_str() {
                return Some(text);
            }
            (block.get("type").and_then(Value::as_str) == Some("text"))
                .then(|| block.get("text").and_then(Value::as_str))
                .flatten()
        })
        .collect::<Vec<_>>()
        .join("\n");
    let text = truncate(&text, 4_000);
    (!text.is_empty()).then_some(text)
}

fn devin_visible_message(chat_message: &str) -> Option<(&'static str, String)> {
    let value = serde_json::from_str::<Value>(chat_message).ok()?;
    let role = match value.get("role").and_then(Value::as_str) {
        Some("user")
            if value
                .get("metadata")
                .and_then(|metadata| metadata.get("is_user_input"))
                .and_then(Value::as_bool)
                == Some(true) =>
        {
            "user"
        }
        Some("assistant") => "assistant",
        // System, tool, thinking, and provider-internal messages are never projected.
        _ => return None,
    };
    Some((role, devin_message_content(&value)?))
}

fn list_devin_sessions(
    cwd_candidates: &[PathBuf],
    recorded_in_use: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentHistorySession>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let Some(connection) = open_read_only_provider_db(&devin_store_path(&home)) else {
        cancellation.check()?;
        return Ok(Vec::new());
    };
    install_sqlite_cancellation(&connection, cancellation);
    cancellation.check()?;
    let Ok(mut statement) = connection.prepare(
        "SELECT id,
                working_directory,
                CASE
                  WHEN length(CAST(COALESCE(title, '') AS BLOB)) <= ?4
                    THEN COALESCE(title, '')
                  ELSE ''
                END,
                COALESCE(last_activity_at, 0)
           FROM sessions
          WHERE hidden = 0
            AND length(CAST(id AS BLOB)) <= ?2
            AND length(CAST(working_directory AS BLOB)) <= ?3
          ORDER BY last_activity_at DESC
          LIMIT ?1",
    ) else {
        cancellation.check()?;
        return Ok(Vec::new());
    };
    let Ok(rows) = statement.query_map(
        rusqlite::params![
            DEVIN_SESSION_LIST_LIMIT as i64,
            DEVIN_SESSION_ID_MAX_BYTES as i64,
            DEVIN_WORKING_DIRECTORY_MAX_BYTES as i64,
            DEVIN_PROVIDER_TITLE_MAX_BYTES as i64,
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3).unwrap_or(0),
            ))
        },
    ) else {
        cancellation.check()?;
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for row in rows {
        cancellation.check()?;
        let Ok((id, working_directory, provider_title, last_activity_at)) = row else {
            cancellation.check()?;
            continue;
        };
        let Some(id) = clean_opaque_session_id(&id) else {
            continue;
        };
        let session_cwd = Path::new(&working_directory);
        if !session_cwd.is_absolute()
            || !cwd_candidates
                .iter()
                .any(|candidate| normalize_cwd(session_cwd) == normalize_cwd(candidate))
        {
            continue;
        }
        let title = if provider_title.trim().is_empty() {
            "Devin session".to_string()
        } else {
            truncate(&provider_title, 90)
        };
        let first_message = if provider_title.trim().is_empty() {
            "(no title available)".to_string()
        } else {
            truncate(&provider_title, 140)
        };
        out.push(AgentHistorySession {
            id: id.clone(),
            agent: "devin".to_string(),
            title,
            first_message,
            modified_at_ms: u64::try_from(last_activity_at)
                .unwrap_or(0)
                .saturating_mul(1_000),
            message_count: None,
            folder_index: 0,
            file_path: format!("devin://{id}"),
            in_use: recorded_in_use.contains(&id),
            custom_name: None,
        });
    }
    out.sort_by_key(|row| std::cmp::Reverse(row.modified_at_ms));
    cancellation.check()?;
    Ok(out)
}

fn preview_devin_session(
    session_id: &str,
    max_lines: usize,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentPreviewLine>, HistoryScanCancelled> {
    cancellation.check()?;
    if max_lines == 0 || clean_opaque_session_id(session_id).as_deref() != Some(session_id) {
        return Ok(Vec::new());
    }
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let Some(connection) = open_read_only_provider_db(&devin_store_path(&home)) else {
        return Ok(Vec::new());
    };
    install_sqlite_cancellation(&connection, cancellation);
    let Ok(main_chain_id) = connection.query_row(
        "SELECT main_chain_id FROM sessions WHERE id = ?1 AND hidden = 0",
        [session_id],
        |row| row.get::<_, Option<i64>>(0),
    ) else {
        cancellation.check()?;
        return Ok(Vec::new());
    };
    let Some(main_chain_id) = main_chain_id else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    visit_devin_main_chain(
        &connection,
        session_id,
        main_chain_id,
        cancellation,
        |chat_message| {
            if out.len() >= max_lines {
                return false;
            }
            let Some((role, content)) = devin_visible_message(chat_message) else {
                return true;
            };
            push_preview_line(&mut out, role, &content);
            out.len() < max_lines
        },
    )?;
    cancellation.check()?;
    Ok(out)
}

fn list_copilot_sessions(
    cwd_candidates: &[PathBuf],
    recorded_in_use: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentHistorySession>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let store = home.join(".copilot").join("session-store.db");
    let Some(connection) = open_read_only_provider_db(&store) else {
        cancellation.check()?;
        return Ok(Vec::new());
    };
    install_sqlite_cancellation(&connection, cancellation);
    cancellation.check()?;
    let Ok(mut statement) = connection.prepare(
        "SELECT s.id,
                COALESCE(s.cwd, ''),
                CASE
                  WHEN length(CAST(COALESCE(s.summary, '') AS BLOB)) <= ?3
                    THEN COALESCE(s.summary, '')
                  ELSE ''
                END,
                COALESCE(CAST(strftime('%s', s.updated_at) AS INTEGER) * 1000, 0)
           FROM sessions s
          WHERE length(CAST(s.id AS BLOB)) <= ?1
            AND length(CAST(COALESCE(s.cwd, '') AS BLOB)) <= ?2
            AND length(CAST(COALESCE(s.updated_at, '') AS BLOB)) <= ?4
          ORDER BY s.updated_at DESC
          LIMIT ?5",
    ) else {
        // Copilot auto-updates and owns this schema. Unknown/new schemas fail soft instead of breaking
        // the dashboard or guessing at private provider files.
        cancellation.check()?;
        return Ok(Vec::new());
    };
    let Ok(rows) = statement.query_map(
        rusqlite::params![
            COPILOT_SESSION_ID_MAX_BYTES as i64,
            COPILOT_WORKING_DIRECTORY_MAX_BYTES as i64,
            COPILOT_SUMMARY_MAX_BYTES as i64,
            COPILOT_TIMESTAMP_MAX_BYTES as i64,
            COPILOT_SESSION_LIST_LIMIT as i64,
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u64>(3).unwrap_or(0),
            ))
        },
    ) else {
        cancellation.check()?;
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for row in rows {
        cancellation.check()?;
        let Ok(row) = row else {
            cancellation.check()?;
            continue;
        };
        let (id, cwd, summary, updated_at_ms) = row;
        let Some(id) = clean_uuid(&id) else {
            continue;
        };
        let session_cwd = Path::new(cwd.trim());
        if !session_cwd.is_absolute()
            || !cwd_candidates
                .iter()
                .any(|candidate| normalize_cwd(session_cwd) == normalize_cwd(candidate))
        {
            continue;
        }
        let first_message = if summary.trim().is_empty() {
            "(no summary available)".to_string()
        } else {
            truncate(&summary, 140)
        };
        out.push(AgentHistorySession {
            id: id.clone(),
            agent: "copilot".to_string(),
            title: if summary.trim().is_empty() {
                "Copilot session".to_string()
            } else {
                truncate(&summary, 90)
            },
            first_message,
            modified_at_ms: updated_at_ms,
            message_count: None,
            folder_index: 0,
            file_path: format!("copilot://{id}"),
            in_use: recorded_in_use.contains(&id)
                || copilot_session_has_live_lock(&home, &id, cancellation)?,
            custom_name: None,
        });
    }
    out.sort_by_key(|row| std::cmp::Reverse(row.modified_at_ms));
    cancellation.check()?;
    Ok(out)
}

fn copilot_session_has_live_lock(
    home: &Path,
    session_id: &str,
    cancellation: &HistoryCancellationToken,
) -> Result<bool, HistoryScanCancelled> {
    cancellation.check()?;
    if clean_uuid(session_id).as_deref() != Some(session_id) {
        return Ok(false);
    }
    let dir = home.join(".copilot").join("session-state").join(session_id);
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(false);
    };
    for entry in entries.take(PROVIDER_HISTORY_LOCK_MAX_ENTRIES).flatten() {
        cancellation.check()?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(pid) = name
            .strip_prefix("inuse.")
            .and_then(|value| value.strip_suffix(".lock"))
            .and_then(|value| value.parse::<libc::pid_t>().ok())
            .filter(|pid| *pid > 0)
        else {
            continue;
        };
        // Signal 0 performs no mutation. EPERM still means a process owns the PID; any other result is
        // a stale lock. This avoids treating a leftover filename as an indefinitely live session.
        let result = unsafe { libc::kill(pid, 0) };
        if result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn preview_copilot_session(
    session_id: &str,
    max_lines: usize,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentPreviewLine>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let Some(session_id) = clean_uuid(session_id) else {
        return Ok(Vec::new());
    };
    let path = home
        .join(".copilot")
        .join("session-state")
        .join(session_id)
        .join("events.jsonl");
    let mut out = Vec::new();
    visit_jsonl_file_with_cancel(
        &path,
        Some(PROVIDER_PREVIEW_MAX_BYTES as usize),
        Some(PROVIDER_PREVIEW_MAX_SOURCE_LINES),
        cancellation,
        |line| {
            let Ok(event) = serde_json::from_str::<Value>(line) else {
                return true;
            };
            let role = match event.get("type").and_then(Value::as_str) {
                Some("user.message") => "user",
                Some("assistant.message") => "assistant",
                // Deliberately ignore system messages, hooks, tool payloads, transformed prompts,
                // encrypted content, rewind snapshots, and logs.
                _ => return true,
            };
            let Some(content) = event
                .get("data")
                .and_then(|data| data.get("content"))
                .and_then(extract_bounded_message_text)
            else {
                return true;
            };
            push_preview_line(&mut out, role, &content);
            out.len() < max_lines
        },
    )?;
    cancellation.check()?;
    Ok(out)
}

fn extract_bounded_message_text(value: &Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(truncate(text, 4_000));
    }
    let items = value.as_array()?;
    let text = items
        .iter()
        .filter_map(|item| {
            item.as_str()
                .map(str::to_string)
                .or_else(|| item.get("text").and_then(Value::as_str).map(str::to_string))
        })
        .collect::<Vec<_>>()
        .join(" ");
    (!text.trim().is_empty()).then(|| truncate(&text, 4_000))
}

fn list_antigravity_sessions(
    cwd_candidates: &[PathBuf],
    recorded_in_use: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentHistorySession>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let state = home.join(".gemini").join("antigravity-cli");

    let mut out = Vec::new();
    // The summary DB is a provider-maintained metadata cache. Modern schemas distinguish root and
    // child conversations; when that hierarchy is present, only proven roots are listed directly.
    // A root missing from that cache may still be recovered below, but only when both independent
    // bounded metadata sidecars agree on its exact folder+UUID mapping. Legacy schemas without
    // hierarchy retain the less restrictive fail-soft fallback used by older `agy` releases.
    let mut indexed_ids = HashSet::new();
    let store = state.join("conversation_summaries.db");
    let mut fallback_authority = match store.try_exists() {
        Ok(false) => AntigravityFallbackAuthority::LegacyMetadata,
        Ok(true) | Err(_) => AntigravityFallbackAuthority::Disabled,
    };
    if let Some(connection) = open_read_only_provider_db(&store) {
        install_sqlite_cancellation(&connection, cancellation);
        cancellation.check()?;
        let hierarchy_columns = (
            sqlite_table_has_column(
                &connection,
                "conversation_summaries",
                "parent_conversation_id",
                cancellation,
            )?,
            sqlite_table_has_column(
                &connection,
                "conversation_summaries",
                "nesting_depth",
                cancellation,
            )?,
        );
        let root_predicate = match hierarchy_columns {
            (Some(has_parent), Some(has_depth)) => {
                fallback_authority = if has_parent || has_depth {
                    AntigravityFallbackAuthority::CorroboratedRootMetadata
                } else {
                    AntigravityFallbackAuthority::LegacyMetadata
                };
                match (has_parent, has_depth) {
                    (true, true) => {
                        "AND COALESCE(parent_conversation_id, '') = ''\n             AND COALESCE(nesting_depth, 0) = 0"
                    }
                    (true, false) => "AND COALESCE(parent_conversation_id, '') = ''",
                    (false, true) => "AND COALESCE(nesting_depth, 0) = 0",
                    (false, false) => "",
                }
            }
            _ => {
                // An unreadable hierarchy shape is not authority to surface possible child runs.
                fallback_authority = AntigravityFallbackAuthority::Disabled;
                "AND 0"
            }
        };
        let query = format!(
            "SELECT conversation_id,
                    CASE
                      WHEN length(CAST(title AS BLOB)) <= ?2 THEN title
                      ELSE ''
                    END,
                    CASE
                      WHEN length(CAST(preview AS BLOB)) <= ?3 THEN preview
                      ELSE ''
                    END,
                    step_count,
                    COALESCE(CAST(strftime('%s', last_modified_time) AS INTEGER) * 1000, 0),
                    workspace_uris,
                    not_fully_idle,
                    killed
               FROM conversation_summaries
              WHERE length(CAST(conversation_id AS BLOB)) <= ?1
                AND length(CAST(workspace_uris AS BLOB)) <= ?4
                AND length(CAST(last_modified_time AS BLOB)) <= ?5
             {root_predicate}
              ORDER BY last_modified_time DESC
              LIMIT ?6"
        );
        if let Ok(mut statement) = connection.prepare(&query) {
            if let Ok(rows) = statement.query_map(
                rusqlite::params![
                    ANTIGRAVITY_SESSION_ID_MAX_BYTES as i64,
                    ANTIGRAVITY_TITLE_MAX_BYTES as i64,
                    ANTIGRAVITY_PREVIEW_MAX_BYTES as i64,
                    ANTIGRAVITY_WORKSPACE_MAX_BYTES as i64,
                    ANTIGRAVITY_TIMESTAMP_MAX_BYTES as i64,
                    ANTIGRAVITY_SESSION_LIST_LIMIT as i64,
                ],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, usize>(3).unwrap_or(0),
                        row.get::<_, u64>(4).unwrap_or(0),
                        row.get::<_, String>(5)?,
                        row.get::<_, bool>(6).unwrap_or(false),
                        row.get::<_, bool>(7).unwrap_or(false),
                    ))
                },
            ) {
                for row in rows {
                    cancellation.check()?;
                    let Ok(row) = row else {
                        cancellation.check()?;
                        continue;
                    };
                    let (
                        id,
                        title,
                        preview,
                        step_count,
                        modified_at_ms,
                        workspace_uris,
                        busy,
                        killed,
                    ) = row;
                    let Some(id) = clean_uuid(&id) else {
                        continue;
                    };
                    // A provider-killed conversation must not be resurrected by a stale auxiliary
                    // mapping that still points at its on-disk DB.
                    indexed_ids.insert(id.clone());
                    if killed || !antigravity_workspace_matches(&workspace_uris, cwd_candidates) {
                        continue;
                    }
                    let first_message = if preview.trim().is_empty() {
                        truncate(&title, 140)
                    } else {
                        truncate(&preview, 140)
                    };
                    let title = if title.trim().is_empty() {
                        if first_message.is_empty() {
                            "Antigravity conversation".to_string()
                        } else {
                            truncate(&first_message, 90)
                        }
                    } else {
                        truncate(&title, 90)
                    };
                    out.push(AgentHistorySession {
                        id: id.clone(),
                        agent: "antigravity".to_string(),
                        title,
                        first_message: if first_message.is_empty() {
                            "(no preview available)".to_string()
                        } else {
                            first_message
                        },
                        modified_at_ms,
                        message_count: Some(step_count),
                        folder_index: 0,
                        file_path: format!("antigravity://{id}"),
                        in_use: busy || recorded_in_use.contains(&id),
                        custom_name: None,
                    });
                }
                cancellation.check()?;
            }
        }
        cancellation.check()?;
    }

    // `agy` updates these bounded metadata files independently of its SQLite summary cache. Accept a
    // fallback only when the metadata's exact folder+UUID mapping is corroborated by a real,
    // provider-named SQLite conversation DB beneath the fixed conversations root. No transcript or
    // provider protobuf BLOB is opened here.
    for (id, modified_at_ms) in antigravity_unindexed_sessions(
        &state,
        cwd_candidates,
        &indexed_ids,
        fallback_authority,
        cancellation,
    )? {
        cancellation.check()?;
        out.push(AgentHistorySession {
            id: id.clone(),
            agent: "antigravity".to_string(),
            title: "Antigravity conversation".to_string(),
            first_message: "(no preview available)".to_string(),
            modified_at_ms,
            message_count: None,
            folder_index: 0,
            file_path: format!("antigravity://{id}"),
            in_use: recorded_in_use.contains(&id),
            custom_name: None,
        });
    }
    out.sort_by(|left, right| {
        right
            .modified_at_ms
            .cmp(&left.modified_at_ms)
            .then_with(|| left.id.cmp(&right.id))
    });
    out.truncate(500);
    cancellation.check()?;
    Ok(out)
}

const ANTIGRAVITY_METADATA_MAX_ROWS: usize = 1_000;
const ANTIGRAVITY_WORKSPACE_MAX_BYTES: usize = 4 * 1024;
const SQLITE_DATABASE_HEADER: &[u8; 16] = b"SQLite format 3\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AntigravityFallbackAuthority {
    Disabled,
    LegacyMetadata,
    CorroboratedRootMetadata,
}

fn antigravity_unindexed_sessions(
    state: &Path,
    cwd_candidates: &[PathBuf],
    indexed_ids: &HashSet<String>,
    fallback_authority: AntigravityFallbackAuthority,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<(String, u64)>, HistoryScanCancelled> {
    cancellation.check()?;
    if fallback_authority == AntigravityFallbackAuthority::Disabled {
        return Ok(Vec::new());
    }
    let mut history_candidates = HashMap::<String, u64>::new();
    let mut latest_candidates = HashSet::<String>::new();

    if let Some(bytes) = read_bounded_regular_file_with_cancel(
        &state.join("history.jsonl"),
        PROVIDER_PREVIEW_MAX_BYTES,
        cancellation,
    )? {
        for line in bytes
            .split(|byte| *byte == b'\n')
            .rev()
            .filter(|line| !line.is_empty())
            .take(ANTIGRAVITY_METADATA_MAX_ROWS)
        {
            cancellation.check()?;
            let Ok(value) = serde_json::from_slice::<Value>(line) else {
                continue;
            };
            let Some(id) = value
                .get("conversationId")
                .and_then(Value::as_str)
                .and_then(clean_uuid)
            else {
                continue;
            };
            let Some(workspace) = value.get("workspace").and_then(Value::as_str) else {
                continue;
            };
            if indexed_ids.contains(&id)
                || workspace.len() > ANTIGRAVITY_WORKSPACE_MAX_BYTES
                || !antigravity_metadata_workspace_matches(workspace, cwd_candidates)
            {
                continue;
            }
            let modified_at_ms = value.get("timestamp").and_then(Value::as_u64).unwrap_or(0);
            history_candidates
                .entry(id)
                .and_modify(|existing| *existing = (*existing).max(modified_at_ms))
                .or_insert(modified_at_ms);
        }
    }

    if let Some(Value::Object(latest)) = read_bounded_regular_json_with_cancel(
        &state.join("cache").join("last_conversations.json"),
        PROVIDER_STATE_MAX_BYTES,
        cancellation,
    )? {
        for (workspace, value) in latest.into_iter().take(ANTIGRAVITY_METADATA_MAX_ROWS) {
            cancellation.check()?;
            let Some(id) = value.as_str().and_then(clean_uuid) else {
                continue;
            };
            if indexed_ids.contains(&id)
                || workspace.len() > ANTIGRAVITY_WORKSPACE_MAX_BYTES
                || !antigravity_metadata_workspace_matches(&workspace, cwd_candidates)
            {
                continue;
            }
            latest_candidates.insert(id);
        }
    }

    let mut candidates =
        if fallback_authority == AntigravityFallbackAuthority::CorroboratedRootMetadata {
            // `history.jsonl` records more than resumable roots, while `last_conversations.json` is the
            // provider's folder-to-root resume map. In a hierarchy-aware install, neither source alone
            // is enough: require their normalized folder mappings to independently yield the same UUID.
            history_candidates
                .into_iter()
                .filter(|(id, _)| latest_candidates.contains(id))
                .collect::<HashMap<_, _>>()
        } else {
            for id in latest_candidates {
                history_candidates.entry(id).or_insert(0);
            }
            history_candidates
        };

    // The rich listing is intentionally capped at 500 rows, but summary membership is not. Check
    // each bounded fallback candidate by primary key so a killed or older indexed conversation
    // outside that display window cannot be resurrected with generic metadata.
    let summary_store = state.join("conversation_summaries.db");
    if let Some(connection) = open_read_only_provider_db(&summary_store) {
        install_sqlite_cancellation(&connection, cancellation);
        cancellation.check()?;
        let Ok(mut statement) = connection
            .prepare("SELECT 1 FROM conversation_summaries WHERE conversation_id = ?1 LIMIT 1")
        else {
            // If a present summary cache cannot answer membership, it cannot prove that a fallback
            // candidate is not a killed conversation or a known child/subagent. Fail closed.
            cancellation.check()?;
            return Ok(Vec::new());
        };
        let mut retained = HashMap::new();
        for (id, modified_at_ms) in candidates {
            cancellation.check()?;
            let exists = statement.exists([id.as_str()]);
            cancellation.check()?;
            if !exists.unwrap_or(true) {
                retained.insert(id, modified_at_ms);
            }
        }
        candidates = retained;
        cancellation.check()?;
    } else if fallback_authority == AntigravityFallbackAuthority::CorroboratedRootMetadata {
        // The modern cache was readable when this scan started, so losing access before the
        // all-row membership check must not weaken child/killed filtering.
        cancellation.check()?;
        return Ok(Vec::new());
    }

    let conversations = state.join("conversations");
    let mut out = Vec::new();
    for (id, metadata_modified_at_ms) in candidates {
        cancellation.check()?;
        let Some(db_modified_at_ms) =
            antigravity_conversation_db_mtime(&conversations, &id, cancellation)?
        else {
            continue;
        };
        out.push((id, metadata_modified_at_ms.max(db_modified_at_ms)));
    }
    out.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    out.truncate(500);
    cancellation.check()?;
    Ok(out)
}

fn antigravity_metadata_workspace_matches(raw: &str, cwd_candidates: &[PathBuf]) -> bool {
    let path = if raw.starts_with("file://") {
        file_uri_path(raw)
    } else {
        let path = PathBuf::from(raw);
        path.is_absolute().then_some(path)
    };
    let Some(path) = path else {
        return false;
    };
    cwd_candidates
        .iter()
        .any(|candidate| normalize_cwd(&path) == normalize_cwd(candidate))
}

fn read_bounded_regular_json_with_cancel(
    path: &Path,
    max_bytes: u64,
    cancellation: &HistoryCancellationToken,
) -> Result<Option<Value>, HistoryScanCancelled> {
    let Some(bytes) = read_bounded_regular_file_with_cancel(path, max_bytes, cancellation)? else {
        return Ok(None);
    };
    Ok(serde_json::from_slice(&bytes).ok())
}

fn read_bounded_regular_file_with_cancel(
    path: &Path,
    max_bytes: u64,
    cancellation: &HistoryCancellationToken,
) -> Result<Option<Vec<u8>>, HistoryScanCancelled> {
    cancellation.check()?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let Ok(mut file) = options.open(path) else {
        return Ok(None);
    };
    let Ok(metadata) = file.metadata() else {
        return Ok(None);
    };
    if !metadata.file_type().is_file() || metadata.len() > max_bytes {
        return Ok(None);
    }
    let max_bytes = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    read_bytes_with_cancel(&mut file, Some(max_bytes), cancellation)
}

fn antigravity_conversation_db_mtime(
    conversations: &Path,
    id: &str,
    cancellation: &HistoryCancellationToken,
) -> Result<Option<u64>, HistoryScanCancelled> {
    cancellation.check()?;
    // Require the canonical UUID spelling before deriving a path from provider metadata.
    if clean_uuid(id).as_deref() != Some(id) {
        return Ok(None);
    }
    let Ok(root_metadata) = fs::symlink_metadata(conversations) else {
        return Ok(None);
    };
    if !root_metadata.file_type().is_dir() {
        return Ok(None);
    }
    let Ok(canonical_root) = fs::canonicalize(conversations) else {
        return Ok(None);
    };
    let path = conversations.join(format!("{id}.db"));
    let Ok(path_metadata) = fs::symlink_metadata(&path) else {
        return Ok(None);
    };
    if !path_metadata.file_type().is_file() {
        return Ok(None);
    }
    let Ok(canonical_path) = fs::canonicalize(&path) else {
        return Ok(None);
    };
    if canonical_path.parent() != Some(canonical_root.as_path()) {
        return Ok(None);
    }

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let Ok(mut file) = options.open(&path) else {
        return Ok(None);
    };
    let Ok(metadata) = file.metadata() else {
        return Ok(None);
    };
    if !metadata.file_type().is_file() {
        return Ok(None);
    }
    cancellation.check()?;
    let mut header = [0_u8; SQLITE_DATABASE_HEADER.len()];
    if file.read_exact(&mut header).is_err() {
        return Ok(None);
    }
    if &header != SQLITE_DATABASE_HEADER {
        return Ok(None);
    }
    cancellation.check()?;
    Ok(metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64))
}

fn antigravity_workspace_matches(raw: &str, cwd_candidates: &[PathBuf]) -> bool {
    let Ok(uris) = serde_json::from_str::<Vec<String>>(raw) else {
        return false;
    };
    uris.into_iter().any(|uri| {
        let Some(path) = file_uri_path(&uri) else {
            return false;
        };
        cwd_candidates
            .iter()
            .any(|candidate| normalize_cwd(&path) == normalize_cwd(candidate))
    })
}

fn file_uri_path(uri: &str) -> Option<PathBuf> {
    let encoded = uri.strip_prefix("file://")?;
    if !encoded.starts_with('/') {
        // Reject remote/hosted file URIs. Provider workspaces are local absolute POSIX paths.
        return None;
    }
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hi = *bytes.get(index + 1)?;
            let lo = *bytes.get(index + 2)?;
            decoded.push((hex_nibble(hi)? << 4) | hex_nibble(lo)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let decoded = String::from_utf8(decoded).ok()?;
    let path = PathBuf::from(decoded);
    path.is_absolute().then_some(path)
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn preview_antigravity_session(
    session: &AgentHistorySession,
    max_lines: usize,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentPreviewLine>, HistoryScanCancelled> {
    cancellation.check()?;
    if max_lines == 0 {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    if !session.title.trim().is_empty() {
        push_preview_line(&mut out, "system", &session.title);
    }
    if out.len() < max_lines
        && !session.first_message.trim().is_empty()
        && session.first_message != session.title
    {
        push_preview_line(&mut out, "assistant", &session.first_message);
    }
    out.truncate(max_lines);
    cancellation.check()?;
    Ok(out)
}

const PROVIDER_PREVIEW_MAX_BYTES: u64 = 4 * 1024 * 1024;
const PROVIDER_STATE_MAX_BYTES: u64 = 256 * 1024;

fn kimi_session_index_rows(
    home: &Path,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<(String, PathBuf, PathBuf)>, HistoryScanCancelled> {
    cancellation.check()?;
    let index_path = home.join(".kimi-code").join("session_index.jsonl");
    let sessions_root = home.join(".kimi-code").join("sessions");
    let canonical_root = fs::canonicalize(&sessions_root).unwrap_or(sessions_root);
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    visit_jsonl_file_with_cancel(
        &index_path,
        Some(PROVIDER_PREVIEW_MAX_BYTES as usize),
        Some(1_000),
        cancellation,
        |line| {
            let Ok(value) = serde_json::from_str::<Value>(line) else {
                return true;
            };
            let Some(id) = value
                .get("sessionId")
                .and_then(Value::as_str)
                .and_then(clean_kimi_session_id)
            else {
                return true;
            };
            if seen.contains(&id) {
                return true;
            }
            let Some(session_dir) = value
                .get("sessionDir")
                .and_then(Value::as_str)
                .map(PathBuf::from)
            else {
                return true;
            };
            let Some(work_dir) = value
                .get("workDir")
                .and_then(Value::as_str)
                .map(PathBuf::from)
            else {
                return true;
            };
            if !work_dir.is_absolute()
                || session_dir.file_name().and_then(|name| name.to_str()) != Some(id.as_str())
            {
                return true;
            }
            // The provider index is metadata, not authority to read an arbitrary path. Resolve symlinks and
            // accept only real session directories beneath ~/.kimi-code/sessions.
            let Ok(session_dir) = fs::canonicalize(session_dir) else {
                return true;
            };
            if !session_dir.starts_with(&canonical_root) {
                return true;
            }
            // Only a fully validated row may reserve the provider id. A malformed duplicate that appears
            // earlier in the append-only index must not hide a later valid entry for the same session.
            seen.insert(id.clone());
            rows.push((id, session_dir, work_dir));
            true
        },
    )?;
    Ok(rows)
}

fn read_bounded_json_with_cancel(
    path: &Path,
    max_bytes: u64,
    cancellation: &HistoryCancellationToken,
) -> Result<Option<Value>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(mut file) = open_regular_file_no_follow(path) else {
        return Ok(None);
    };
    let max_bytes = usize::try_from(max_bytes).unwrap_or(usize::MAX);
    let Some(bytes) = read_bytes_with_cancel(&mut file, Some(max_bytes), cancellation)? else {
        return Ok(None);
    };
    Ok(serde_json::from_slice(&bytes).ok())
}

fn kimi_user_prompt(event: &Value) -> Option<String> {
    if event.get("type").and_then(Value::as_str) != Some("turn.prompt")
        || event
            .get("origin")
            .and_then(|origin| origin.get("kind"))
            .and_then(Value::as_str)
            != Some("user")
    {
        return None;
    }
    let text = event
        .get("input")?
        .as_array()?
        .iter()
        .filter(|part| part.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|part| part.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    (!text.trim().is_empty()).then_some(text)
}

fn kimi_assistant_text(event: &Value) -> Option<String> {
    if event.get("type").and_then(Value::as_str) != Some("context.append_loop_event") {
        return None;
    }
    let event = event.get("event")?;
    if event.get("type").and_then(Value::as_str) != Some("content.part") {
        return None;
    }
    let part = event.get("part")?;
    if part.get("type").and_then(Value::as_str) != Some("text") {
        // Deliberately exclude private chain-of-thought (`part.type == think`) and every tool/event payload.
        return None;
    }
    part.get("text")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .map(str::to_string)
}

fn list_kimi_sessions(
    cwd_candidates: &[PathBuf],
    recorded_in_use: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentHistorySession>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (id, session_dir, work_dir) in kimi_session_index_rows(&home, cancellation)? {
        cancellation.check()?;
        if !cwd_candidates
            .iter()
            .any(|candidate| normalize_cwd(&work_dir) == normalize_cwd(candidate))
        {
            continue;
        }
        let state_path = session_dir.join("state.json");
        let state =
            read_bounded_json_with_cancel(&state_path, PROVIDER_STATE_MAX_BYTES, cancellation)?
                .unwrap_or(Value::Null);
        if let Some(state_work_dir) = state
            .get("workDir")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
        {
            if normalize_cwd(Path::new(state_work_dir)) != normalize_cwd(&work_dir) {
                continue;
            }
        }
        let state_prompt = state
            .get("lastPrompt")
            .and_then(Value::as_str)
            .map(|value| truncate(value, 140))
            .unwrap_or_default();
        let first_message = state_prompt;
        let state_title = state
            .get("title")
            .and_then(Value::as_str)
            .map(|value| truncate(value, 90))
            .unwrap_or_default();
        let title = if !state_title.is_empty() && state_title != "New Session" {
            state_title
        } else if !first_message.is_empty() {
            truncate(&first_message, 90)
        } else {
            "Kimi session".to_string()
        };
        out.push(AgentHistorySession {
            id: id.clone(),
            agent: "kimi".to_string(),
            title,
            first_message: if first_message.is_empty() {
                "(no user message)".to_string()
            } else {
                first_message
            },
            modified_at_ms: modified_at_ms(&state_path),
            message_count: None,
            folder_index: 0,
            file_path: format!("kimi://{id}"),
            in_use: recorded_in_use.contains(&id),
            custom_name: None,
        });
    }
    out.sort_by_key(|row| std::cmp::Reverse(row.modified_at_ms));
    cancellation.check()?;
    Ok(out)
}

fn preview_kimi_session(
    session_id: &str,
    max_lines: usize,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentPreviewLine>, HistoryScanCancelled> {
    cancellation.check()?;
    if max_lines == 0 || clean_kimi_session_id(session_id).as_deref() != Some(session_id) {
        return Ok(Vec::new());
    }
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let Ok(rows) = kimi_session_index_rows(&home, cancellation) else {
        cancellation.check()?;
        return Ok(Vec::new());
    };
    let Some((_, session_dir, _)) = rows.into_iter().find(|(id, _, _)| id == session_id) else {
        return Ok(Vec::new());
    };
    let path = session_dir.join("agents").join("main").join("wire.jsonl");
    let mut out = Vec::new();
    visit_jsonl_file_with_cancel(
        &path,
        Some(PROVIDER_PREVIEW_MAX_BYTES as usize),
        Some(PROVIDER_PREVIEW_MAX_SOURCE_LINES),
        cancellation,
        |line| {
            let Ok(event) = serde_json::from_str::<Value>(line) else {
                return true;
            };
            if let Some(text) = kimi_user_prompt(&event) {
                push_preview_line(&mut out, "user", &text);
            } else if let Some(text) = kimi_assistant_text(&event) {
                push_preview_line(&mut out, "assistant", &text);
            }
            out.len() < max_lines
        },
    )?;
    cancellation.check()?;
    Ok(out)
}

fn kiro_message_text(event: &Value, expected_kind: &str) -> Option<String> {
    if event.get("kind").and_then(Value::as_str) != Some(expected_kind) {
        return None;
    }
    let text = event
        .get("data")?
        .get("content")?
        .as_array()?
        .iter()
        .filter(|part| part.get("kind").and_then(Value::as_str) == Some("text"))
        .filter_map(|part| part.get("data").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join(" ");
    (!text.trim().is_empty()).then_some(text)
}

fn kiro_session_has_live_lock(
    root: &Path,
    session_id: &str,
    cancellation: &HistoryCancellationToken,
) -> Result<bool, HistoryScanCancelled> {
    cancellation.check()?;
    if clean_uuid(session_id).as_deref() != Some(session_id) {
        return Ok(false);
    }
    let lock = root.join(format!("{session_id}.lock"));
    let Some(value) = read_bounded_json_with_cancel(&lock, 8 * 1024, cancellation)? else {
        return Ok(false);
    };
    let Some(pid) = value
        .get("pid")
        .and_then(Value::as_i64)
        .and_then(|pid| libc::pid_t::try_from(pid).ok())
        .filter(|pid| *pid > 0)
    else {
        return Ok(false);
    };
    let result = unsafe { libc::kill(pid, 0) };
    cancellation.check()?;
    Ok(result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM))
}

fn list_kiro_sessions(
    cwd_candidates: &[PathBuf],
    recorded_in_use: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentHistorySession>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let root = home.join(".kiro").join("sessions").join("cli");
    let Ok(entries) = fs::read_dir(&root) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for entry in entries.take(PROVIDER_HISTORY_RESULT_MAX_COUNT).flatten() {
        cancellation.check()?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let Some(id) = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .and_then(clean_uuid)
        else {
            continue;
        };
        let Some(state) =
            read_bounded_json_with_cancel(&path, PROVIDER_STATE_MAX_BYTES, cancellation)?
        else {
            continue;
        };
        if state.get("session_id").and_then(Value::as_str) != Some(id.as_str()) {
            continue;
        }
        let Some(cwd) = state
            .get("cwd")
            .and_then(Value::as_str)
            .filter(|cwd| Path::new(cwd).is_absolute())
        else {
            continue;
        };
        if !cwd_candidates
            .iter()
            .any(|candidate| normalize_cwd(Path::new(cwd)) == normalize_cwd(candidate))
        {
            continue;
        }
        let state_title = state
            .get("title")
            .and_then(Value::as_str)
            .map(|title| truncate(title, 90))
            .unwrap_or_default();
        let title = if !state_title.is_empty() && state_title != "(no title)" {
            state_title.clone()
        } else {
            "Kiro session".to_string()
        };
        let first_message = if !state_title.is_empty() && state_title != "(no title)" {
            truncate(&state_title, 140)
        } else {
            "(no title available)".to_string()
        };
        out.push(AgentHistorySession {
            id: id.clone(),
            agent: "kiro".to_string(),
            title,
            first_message,
            modified_at_ms: modified_at_ms(&path),
            message_count: None,
            folder_index: 0,
            file_path: format!("kiro://{id}"),
            in_use: recorded_in_use.contains(&id)
                || kiro_session_has_live_lock(&root, &id, cancellation)?,
            custom_name: None,
        });
    }
    out.sort_by_key(|row| std::cmp::Reverse(row.modified_at_ms));
    cancellation.check()?;
    Ok(out)
}

fn preview_kiro_session(
    session_id: &str,
    max_lines: usize,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentPreviewLine>, HistoryScanCancelled> {
    cancellation.check()?;
    if max_lines == 0 || clean_uuid(session_id).as_deref() != Some(session_id) {
        return Ok(Vec::new());
    }
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let root = home.join(".kiro").join("sessions").join("cli");
    let state_path = root.join(format!("{session_id}.json"));
    let Some(state) =
        read_bounded_json_with_cancel(&state_path, PROVIDER_STATE_MAX_BYTES, cancellation)?
    else {
        return Ok(Vec::new());
    };
    if state.get("session_id").and_then(Value::as_str) != Some(session_id) {
        return Ok(Vec::new());
    }
    let path = root.join(format!("{session_id}.jsonl"));
    let mut out = Vec::new();
    visit_jsonl_file_with_cancel(
        &path,
        Some(PROVIDER_PREVIEW_MAX_BYTES as usize),
        Some(PROVIDER_PREVIEW_MAX_SOURCE_LINES),
        cancellation,
        |line| {
            let Ok(event) = serde_json::from_str::<Value>(line) else {
                return true;
            };
            if let Some(text) = kiro_message_text(&event, "Prompt") {
                push_preview_line(&mut out, "user", &text);
            } else if let Some(text) = kiro_message_text(&event, "AssistantMessage") {
                push_preview_line(&mut out, "assistant", &text);
            }
            out.len() < max_lines
        },
    )?;
    cancellation.check()?;
    Ok(out)
}

fn cursor_project_slug(cwd: &Path) -> Option<String> {
    if !cwd.is_absolute() {
        return None;
    }
    let mut slug = String::new();
    for ch in cwd.to_string_lossy().trim_matches('/').chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            slug.push(ch);
        } else {
            slug.push('-');
        }
    }
    (!slug.is_empty()).then_some(slug)
}

fn cursor_transcript_roots(
    home: &Path,
    cwd_candidates: &[PathBuf],
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<PathBuf>, HistoryScanCancelled> {
    cancellation.check()?;
    let projects = home.join(".cursor").join("projects");
    let Ok(canonical_projects) = fs::canonicalize(&projects) else {
        return Ok(Vec::new());
    };
    let mut roots = Vec::new();
    let mut seen = HashSet::new();
    for cwd in cwd_candidates {
        cancellation.check()?;
        let Some(slug) = cursor_project_slug(cwd) else {
            continue;
        };
        let Ok(project) = fs::canonicalize(projects.join(slug)) else {
            continue;
        };
        if !project.starts_with(&canonical_projects) || !seen.insert(project.clone()) {
            continue;
        }
        // Cursor writes a UUID-valued repo marker beside CLI transcripts. Requiring it avoids treating an
        // arbitrary lookalike directory as provider state while remaining fail-soft across schema changes.
        let Some(repo) =
            read_bounded_json_with_cancel(&project.join("repo.json"), 8 * 1024, cancellation)?
        else {
            continue;
        };
        if repo
            .get("id")
            .and_then(Value::as_str)
            .and_then(clean_uuid)
            .is_none()
        {
            continue;
        }
        let transcript_root = project.join("agent-transcripts");
        if transcript_root.is_dir() {
            roots.push(transcript_root);
        }
    }
    cancellation.check()?;
    Ok(roots)
}

fn cursor_transcript_file(
    root: &Path,
    session_id: &str,
    cancellation: &HistoryCancellationToken,
) -> Result<Option<PathBuf>, HistoryScanCancelled> {
    cancellation.check()?;
    if clean_uuid(session_id).as_deref() != Some(session_id) {
        return Ok(None);
    }
    let Ok(canonical_root) = fs::canonicalize(root) else {
        return Ok(None);
    };
    let candidate = root.join(session_id).join(format!("{session_id}.jsonl"));
    let Ok(candidate) = fs::canonicalize(candidate) else {
        return Ok(None);
    };
    cancellation.check()?;
    Ok(candidate.starts_with(canonical_root).then_some(candidate))
}

fn cursor_message_text(event: &Value, expected_role: &str) -> Option<String> {
    if event.get("role").and_then(Value::as_str) != Some(expected_role) {
        return None;
    }
    let text = event
        .get("message")?
        .get("content")?
        .as_array()?
        .iter()
        .filter(|part| part.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|part| part.get("text").and_then(Value::as_str))
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("\n");
    (!text.is_empty()).then_some(text)
}

fn cursor_chat_rows(
    home: &Path,
    cwd_candidates: &[PathBuf],
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<(String, String, u64)>, HistoryScanCancelled> {
    cancellation.check()?;
    let root = home.join(".cursor").join("chats");
    let Ok(canonical_root) = fs::canonicalize(&root) else {
        return Ok(Vec::new());
    };
    let Ok(namespaces) = fs::read_dir(&root) else {
        return Ok(Vec::new());
    };
    let mut rows = Vec::new();
    let mut seen = HashSet::new();
    let mut budget = HistoryEnumerationBudget::provider_store();
    for namespace in namespaces {
        cancellation.check()?;
        if !budget.consume() {
            break;
        }
        let Ok(namespace) = namespace else {
            continue;
        };
        let Ok(file_type) = namespace.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let Ok(sessions) = fs::read_dir(namespace.path()) else {
            continue;
        };
        for session in sessions {
            cancellation.check()?;
            if !budget.consume() {
                break;
            }
            let Ok(session) = session else {
                continue;
            };
            let Some(id) = session.file_name().to_str().and_then(clean_uuid) else {
                continue;
            };
            if seen.contains(&id) {
                continue;
            }
            let meta_path = session.path().join("meta.json");
            let Ok(canonical_meta) = fs::canonicalize(&meta_path) else {
                continue;
            };
            if !canonical_meta.starts_with(&canonical_root) {
                continue;
            }
            let Some(meta) = read_bounded_json_with_cancel(
                &canonical_meta,
                PROVIDER_STATE_MAX_BYTES,
                cancellation,
            )?
            else {
                continue;
            };
            let Some(cwd) = meta
                .get("cwd")
                .and_then(Value::as_str)
                .filter(|cwd| Path::new(cwd).is_absolute())
            else {
                continue;
            };
            if !cwd_candidates
                .iter()
                .any(|candidate| normalize_cwd(Path::new(cwd)) == normalize_cwd(candidate))
            {
                continue;
            }
            let title = meta
                .get("title")
                .and_then(Value::as_str)
                .map(|title| truncate(title, 90))
                .unwrap_or_default();
            let modified = meta
                .get("updatedAtMs")
                .and_then(Value::as_u64)
                .unwrap_or_else(|| modified_at_ms(&canonical_meta));
            seen.insert(id.clone());
            rows.push((id, title, modified));
        }
        if budget.exhausted() {
            break;
        }
    }
    cancellation.check()?;
    Ok(rows)
}

fn list_cursor_sessions(
    cwd_candidates: &[PathBuf],
    recorded_in_use: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentHistorySession>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let transcript_roots = cursor_transcript_roots(&home, cwd_candidates, cancellation)?;
    for (id, meta_title, modified) in cursor_chat_rows(&home, cwd_candidates, cancellation)? {
        cancellation.check()?;
        let title = if !meta_title.is_empty() {
            meta_title.clone()
        } else {
            "Cursor session".to_string()
        };
        let first_message = if meta_title.is_empty() {
            "(no title available)".to_string()
        } else {
            truncate(&meta_title, 140)
        };
        seen.insert(id.clone());
        out.push(AgentHistorySession {
            id: id.clone(),
            agent: "cursor".to_string(),
            title,
            first_message,
            modified_at_ms: modified,
            message_count: None,
            folder_index: 0,
            file_path: format!("cursor://{id}"),
            in_use: recorded_in_use.contains(&id),
            custom_name: None,
        });
    }
    // Older/newer Cursor builds may have written the public transcript before (or without) the chat metadata
    // catalog. Preserve a fail-soft transcript-only fallback without ever opening the provider's store.db.
    let mut fallback_budget = HistoryEnumerationBudget::provider_store();
    for root in transcript_roots {
        cancellation.check()?;
        let Ok(entries) = fs::read_dir(&root) else {
            continue;
        };
        for entry in entries {
            cancellation.check()?;
            if !fallback_budget.consume() {
                break;
            }
            let Ok(entry) = entry else {
                continue;
            };
            let Some(id) = entry.file_name().to_str().and_then(clean_uuid) else {
                continue;
            };
            if seen.contains(&id) {
                continue;
            }
            let Some(path) = cursor_transcript_file(&root, &id, cancellation)? else {
                continue;
            };
            seen.insert(id.clone());
            out.push(AgentHistorySession {
                id: id.clone(),
                agent: "cursor".to_string(),
                title: "Cursor session".to_string(),
                first_message: "(metadata unavailable)".to_string(),
                modified_at_ms: modified_at_ms(&path),
                message_count: None,
                folder_index: 0,
                file_path: format!("cursor://{id}"),
                in_use: recorded_in_use.contains(&id),
                custom_name: None,
            });
        }
        if fallback_budget.exhausted() {
            break;
        }
    }
    out.sort_by_key(|row| std::cmp::Reverse(row.modified_at_ms));
    cancellation.check()?;
    Ok(out)
}

fn preview_cursor_session(
    cwd: &Path,
    session_id: &str,
    max_lines: usize,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentPreviewLine>, HistoryScanCancelled> {
    cancellation.check()?;
    if max_lines == 0 || clean_uuid(session_id).as_deref() != Some(session_id) {
        return Ok(Vec::new());
    }
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let candidates = cwd_match_candidates(cwd);
    let Ok(roots) = cursor_transcript_roots(&home, &candidates, cancellation) else {
        cancellation.check()?;
        return Ok(Vec::new());
    };
    let mut path = None;
    for root in roots {
        cancellation.check()?;
        let Ok(candidate) = cursor_transcript_file(&root, session_id, cancellation) else {
            cancellation.check()?;
            return Ok(Vec::new());
        };
        if candidate.is_some() {
            path = candidate;
            break;
        }
    }
    let Some(path) = path else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    visit_jsonl_file_with_cancel(
        &path,
        Some(PROVIDER_PREVIEW_MAX_BYTES as usize),
        Some(PROVIDER_PREVIEW_MAX_SOURCE_LINES),
        cancellation,
        |line| {
            let Ok(event) = serde_json::from_str::<Value>(line) else {
                return true;
            };
            if let Some(text) = cursor_message_text(&event, "user") {
                push_preview_line(&mut out, "user", &text);
            } else if let Some(text) = cursor_message_text(&event, "assistant") {
                push_preview_line(&mut out, "assistant", &text);
            }
            out.len() < max_lines
        },
    )?;
    cancellation.check()?;
    Ok(out)
}

fn gemini_project_hash(cwd: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cwd.to_string_lossy().as_bytes());
    format!("{:x}", hasher.finalize())
}

fn walk_gemini_chat_files(
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<PathBuf>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let tmp_root = home.join(".gemini").join("tmp");
    let Ok(slugs) = fs::read_dir(tmp_root) else {
        return Ok(Vec::new());
    };
    let mut files = Vec::new();
    let mut budget = HistoryEnumerationBudget::provider_store();
    for slug in slugs {
        cancellation.check()?;
        if !budget.consume() {
            break;
        }
        let Ok(slug) = slug else {
            continue;
        };
        let Ok(file_type) = slug.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let chats = slug.path().join("chats");
        let Ok(chats_metadata) = fs::symlink_metadata(&chats) else {
            continue;
        };
        if !chats_metadata.file_type().is_dir() {
            continue;
        }
        let Ok(entries) = fs::read_dir(chats) else {
            continue;
        };
        for entry in entries {
            cancellation.check()?;
            if !budget.consume() {
                break;
            }
            let Ok(entry) = entry else {
                continue;
            };
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("jsonl")
            {
                files.push(path);
            }
        }
        if budget.exhausted() {
            break;
        }
    }
    cancellation.check()?;
    Ok(files)
}

const GEMINI_SESSION_META_MAX_BYTES: usize = 128 * 1024;

fn read_gemini_session_meta(
    path: &Path,
    target_hashes: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Option<(String, u64, u64)>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(file) = open_regular_file_no_follow(path) else {
        return Ok(None);
    };
    let Ok(file_metadata) = file.metadata() else {
        return Ok(None);
    };
    let modified_at_ms = file_metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(0);
    let file_size = file_metadata.len();
    let mut reader = BufReader::with_capacity(HISTORY_READ_CHUNK_BYTES, file);
    let line = match read_bounded_line(&mut reader, GEMINI_SESSION_META_MAX_BYTES, cancellation) {
        Ok(Some((line, _))) => line,
        Ok(None) | Err(BoundedReadFailure::LimitExceeded | BoundedReadFailure::Io) => {
            return Ok(None);
        }
        Err(BoundedReadFailure::Cancelled) => return Err(HistoryScanCancelled),
    };
    let Ok(meta) = serde_json::from_str::<Value>(&line) else {
        return Ok(None);
    };
    if !meta
        .get("projectHash")
        .and_then(Value::as_str)
        .is_some_and(|hash| target_hashes.contains(hash))
    {
        return Ok(None);
    }
    cancellation.check()?;
    Ok(meta
        .get("sessionId")
        .and_then(Value::as_str)
        .and_then(|id| clean_session_id(Some(id)))
        .map(|id| (id, modified_at_ms, file_size)))
}

fn list_gemini_sessions(
    cwd_candidates: &[PathBuf],
    in_use: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentHistorySession>, HistoryScanCancelled> {
    cancellation.check()?;
    let target_hashes = cwd_candidates
        .iter()
        .map(|cwd| gemini_project_hash(cwd))
        .collect::<HashSet<_>>();
    let mut best_by_id = std::collections::HashMap::<String, (PathBuf, u64, u64)>::new();
    for path in walk_gemini_chat_files(cancellation)? {
        cancellation.check()?;
        let Some((id, modified, size)) =
            read_gemini_session_meta(&path, &target_hashes, cancellation)?
        else {
            continue;
        };
        match best_by_id.get(&id) {
            Some((_, existing_modified, existing_size))
                if (*existing_modified, *existing_size) >= (modified, size) => {}
            _ => {
                best_by_id.insert(id, (path, modified, size));
            }
        }
    }

    let mut out = Vec::new();
    for (id, (path, _, _)) in best_by_id {
        cancellation.check()?;
        let generic_title = format!("Gemini session {}", short_session_id(&id));
        push_session(&mut out, "gemini", id, path, generic_title, None, in_use);
    }
    out.sort_by_key(|row| std::cmp::Reverse(row.modified_at_ms));
    cancellation.check()?;
    Ok(out)
}

fn list_opencode_sessions(
    cwd_candidates: &[PathBuf],
    in_use: &HashSet<String>,
    cancellation: &HistoryCancellationToken,
) -> Result<Vec<AgentHistorySession>, HistoryScanCancelled> {
    cancellation.check()?;
    let Some(home) = home_dir() else {
        return Ok(Vec::new());
    };
    let db = home
        .join(".local")
        .join("share")
        .join("opencode")
        .join("opencode.db");
    if !db.exists() {
        return Ok(Vec::new());
    }
    let Ok(conn) = rusqlite::Connection::open_with_flags(
        &db,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        cancellation.check()?;
        return Ok(Vec::new());
    };
    install_sqlite_cancellation(&conn, cancellation);
    cancellation.check()?;
    let Some(has_parent_id) = sqlite_table_has_column(&conn, "session", "parent_id", cancellation)?
    else {
        return Ok(Vec::new());
    };
    let root_predicate = if has_parent_id {
        "AND (parent_id IS NULL OR parent_id = '')"
    } else {
        ""
    };
    let query = format!(
        "SELECT id,
                CASE WHEN length(CAST(title AS BLOB)) <= ?2 THEN title ELSE '' END,
                directory,
                CASE
                  WHEN agent IS NULL THEN NULL
                  WHEN length(CAST(agent AS BLOB)) <= ?4 THEN agent
                  ELSE NULL
                END,
                CASE
                  WHEN model IS NULL THEN NULL
                  WHEN length(CAST(model AS BLOB)) <= ?5 THEN model
                  ELSE NULL
                END,
                time_updated
           FROM session
          WHERE time_archived IS NULL
            AND length(CAST(id AS BLOB)) <= ?1
            AND length(CAST(directory AS BLOB)) <= ?3
            {root_predicate}
          ORDER BY time_updated DESC
          LIMIT ?6"
    );
    let Ok(mut stmt) = conn.prepare(&query) else {
        cancellation.check()?;
        return Ok(Vec::new());
    };
    let Ok(rows) = stmt.query_map(
        rusqlite::params![
            OPENCODE_SESSION_ID_MAX_BYTES as i64,
            OPENCODE_TITLE_MAX_BYTES as i64,
            OPENCODE_DIRECTORY_MAX_BYTES as i64,
            OPENCODE_AGENT_MAX_BYTES as i64,
            OPENCODE_MODEL_MAX_BYTES as i64,
            OPENCODE_SESSION_LIST_LIMIT as i64,
        ],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Option<String>>(3).unwrap_or(None),
                row.get::<_, Option<String>>(4).unwrap_or(None),
                row.get::<_, u64>(5).unwrap_or(0),
            ))
        },
    ) else {
        cancellation.check()?;
        return Ok(Vec::new());
    };

    let mut out = Vec::new();
    for row in rows {
        cancellation.check()?;
        let Ok(row) = row else {
            cancellation.check()?;
            continue;
        };
        let (id, title, directory, opencode_agent, model, time_updated) = row;
        let Some(id) = clean_opaque_session_id(&id) else {
            continue;
        };
        let directory_path = Path::new(&directory);
        if !cwd_candidates
            .iter()
            .any(|candidate| directory_path == candidate)
        {
            continue;
        }
        let model_label = model
            .as_deref()
            .and_then(opencode_model_label)
            .unwrap_or_else(|| "model unknown".to_string());
        let mode = opencode_agent
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or("session");
        let display_title = if title.trim().is_empty() {
            "OpenCode"
        } else {
            title.trim()
        };
        out.push(AgentHistorySession {
            id: id.clone(),
            agent: "opencode".to_string(),
            title: truncate(&format!("{display_title} ({mode})"), 90),
            first_message: truncate(&format!("{display_title} · {model_label}"), 140),
            modified_at_ms: time_updated,
            message_count: None,
            folder_index: 0,
            // OpenCode is SQLite-backed; this virtual path prevents file-based delete from touching opencode.db.
            file_path: format!("opencode://{id}"),
            in_use: in_use.contains(&id),
            custom_name: None,
        });
    }
    out.sort_by_key(|row| std::cmp::Reverse(row.modified_at_ms));
    cancellation.check()?;
    Ok(out)
}

fn opencode_model_label(raw: &str) -> Option<String> {
    let parsed = serde_json::from_str::<Value>(raw).ok()?;
    let id = parsed.get("id").and_then(Value::as_str)?;
    let provider = parsed
        .get("providerID")
        .and_then(Value::as_str)
        .filter(|provider| !provider.is_empty());
    let variant = parsed
        .get("variant")
        .and_then(Value::as_str)
        .filter(|variant| !variant.is_empty());
    Some(match (provider, variant) {
        (Some(provider), Some(variant)) => format!("{provider}/{id}:{variant}"),
        (Some(provider), None) => format!("{provider}/{id}"),
        (None, Some(variant)) => format!("{id}:{variant}"),
        (None, None) => id.to_string(),
    })
}
