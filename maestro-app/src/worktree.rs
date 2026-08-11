//! Worktree cleanup / list / provenance / staleness / orphan inventory surface for `maestro-app`.
//!
//! This module holds the PURE, unit-testable worktree implementation that was extracted from
//! `lib.rs` (the first mechanical `maestro-app` module split). It contains:
//!
//! - the cleanup scan/planner types and [`plan_worktree_cleanup`];
//! - the `worktree-list` candidate/status/count/output types and the
//!   [`build_worktree_list`] / [`build_worktree_list_all`] builders;
//! - the provenance/staleness types, constants, and classifiers;
//! - the orphan inventory types and [`build_orphan_candidates`].
//!
//! All process IO (reading records, inspecting worktrees, removing checkouts) is injected via the
//! callers in `main.rs`; these helpers read no global state and mutate nothing. The CLI argument
//! DTOs (`WorktreeCleanupArgs`, `WorktreeListArgs`) and their parsers deliberately remain in
//! `lib.rs`; the crate root re-exports this module's public items for `maestro_app::<Item>` callers.

/// One session-record file that did NOT load as a current, valid `SessionRecord`. The cleanup
/// planner cannot read `cwd_resolved`/`status` from such a file, so its mere presence makes the
/// reference/liveness scan INCOMPLETE — and an incomplete scan refuses a destructive cleanup. The
/// detail is preserved (not just a count) so reports/tests can show exactly which file blocked it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WorktreeCleanupNonLoadedSession {
    /// A record stamping a schema version newer than this build (`maestro_shell::store::LoadOutcome::FutureVersion`).
    /// Left in place, unread; we cannot decode it, so we cannot prove it does not reference the target.
    FutureVersion { path: String, ours: u32, got: u32 },
    /// A record that failed validation and was quarantined
    /// (`maestro_shell::store::LoadOutcome::Quarantined`). Its original bytes are preserved at
    /// `moved_to`; we cannot decode it, so we cannot prove it does not reference the target.
    Quarantined {
        original: String,
        moved_to: String,
        reason: String,
    },
}

/// The result of scanning the fresh session-record directory for the planner. Splitting loaded from
/// non-loaded outcomes is the whole point of the hardening: a `Removable` verdict requires
/// `non_loaded` to be EMPTY (a complete scan). The previous shape kept only loaded records and
/// silently dropped the rest, which let an undecodable record that referenced the target slip past
/// the reference check.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorktreeCleanupSessionScan {
    /// Session records that loaded as current, valid records — the only ones whose
    /// `status`/`cwd_resolved` the planner can read for liveness/reference checks.
    pub loaded: Vec<maestro_shell::SessionRecord>,
    /// Session record files that loaded as `Quarantined` or `FutureVersion`. ANY entry here makes the
    /// scan incomplete and forces a `session_records_unavailable` refusal.
    pub non_loaded: Vec<WorktreeCleanupNonLoadedSession>,
}

impl WorktreeCleanupSessionScan {
    /// True when every session record decoded cleanly, so the reference/liveness scan is complete and
    /// a `Removable` verdict is even possible.
    pub fn is_complete(&self) -> bool {
        self.non_loaded.is_empty()
    }

    /// How many session-record files failed to load as current valid records.
    pub fn non_loaded_count(&self) -> usize {
        self.non_loaded.len()
    }
}

/// Why a worktree-cleanup plan refused, or that it is safe to remove. Stable, snake_case wire values
/// so the headless JSON `reason` field is testable and scriptable. Every non-`Ok` reason means the
/// caller MUST NOT delete; `Ok` is paired with [`WorktreeCleanupDecision::Removable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeCleanupReason {
    /// The plan is removable: the workspace exists, is `Worktree` policy, has `worktree_create`
    /// consent, and no fresh session record makes the target live or still-referenced.
    Ok,
    /// No workspace with this `workspace_id` exists in the fresh snapshot (also used when the
    /// workspace record is only present as a future-version/quarantined exclusion — never treated
    /// as removable).
    UnknownWorkspace,
    /// The workspace exists but its policy is not exactly `WorkspacePolicy::Worktree`, so it owns no
    /// removable prepared worktree directory (`RepoWrite`/`ScratchCwd` are out of scope).
    NonWorktreePolicy,
    /// The workspace is `Worktree` policy but its `worktree_create` consent is absent — the same
    /// grant that authorized creation is required to remove, and removal must not proceed without it.
    MissingConsent,
    /// A fresh `SessionRecord` with this `session_id` is still `Live`, so the checkout may be in use.
    LiveSession,
    /// A fresh `SessionRecord` (any id) still has `cwd_resolved` equal to the target path, so some
    /// session still references the checkout we would remove.
    ReferencedCwd,
    /// The fresh session scan was INCOMPLETE: at least one session record file loaded as a non-loaded
    /// outcome (`Quarantined` or `FutureVersion`), so we cannot prove no session references the
    /// target checkout. For a destructive command, an unprovable reference check is a refusal, not a
    /// pass — never removable.
    SessionRecordsUnavailable,
}

impl WorktreeCleanupReason {
    /// The stable snake_case wire string for this reason (matches the serde rename).
    pub fn as_str(self) -> &'static str {
        match self {
            WorktreeCleanupReason::Ok => "ok",
            WorktreeCleanupReason::UnknownWorkspace => "unknown_workspace",
            WorktreeCleanupReason::NonWorktreePolicy => "non_worktree_policy",
            WorktreeCleanupReason::MissingConsent => "missing_consent",
            WorktreeCleanupReason::LiveSession => "live_session",
            WorktreeCleanupReason::ReferencedCwd => "referenced_cwd",
            WorktreeCleanupReason::SessionRecordsUnavailable => "session_records_unavailable",
        }
    }
}

/// The pure planner verdict: whether the single target worktree is safe to remove.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeCleanupDecision {
    Removable,
    Refused,
}

impl WorktreeCleanupDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            WorktreeCleanupDecision::Removable => "removable",
            WorktreeCleanupDecision::Refused => "refused",
        }
    }
}

/// The pure plan for reclaiming ONE Maestro-owned worktree checkout. Computed from fresh records
/// only — running NO git, deleting NOTHING, writing NO records. `target_path`/`branch` are the
/// deterministic identifiers the apply path will (only on `Removable` + `--confirm`) hand to
/// [`maestro_shell::remove_worktree_with_consent`], which independently re-verifies them before any
/// git runs.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct WorktreeCleanupPlan {
    pub workspace_id: String,
    pub session_id: String,
    pub decision: WorktreeCleanupDecision,
    pub reason: WorktreeCleanupReason,
    /// `<worktree_base>/<workspace_id>/<session_id>` — the only path this command can ever target.
    pub target_path: String,
    /// `maestro/<workspace_id>/<session_id>` — reported for transparency; never deleted.
    pub branch: String,
}

impl WorktreeCleanupPlan {
    /// True when the planner judged this target safe to remove.
    pub fn is_removable(&self) -> bool {
        self.decision == WorktreeCleanupDecision::Removable
    }
}

/// The deterministic branch name for a Maestro-owned worktree: `maestro/<workspace_id>/<session_id>`.
/// Mirrors `maestro-shell`'s private `worktree_branch` for read-only reporting; the shell primitive
/// recomputes and re-verifies the same branch before any deletion, so this is display-only.
pub fn worktree_cleanup_branch(workspace_id: &str, session_id: &str) -> String {
    format!("maestro/{workspace_id}/{session_id}")
}

/// Plan the cleanup of ONE Maestro-owned worktree checkout from FRESH records — purely.
///
/// This function runs NO git, deletes NOTHING, writes NO records, and creates no directories. It
/// only reads the supplied fresh `snapshot` (for the workspace record: existence, policy, consent)
/// and the fresh session `scan` (for liveness, cwd references, AND scan completeness), and computes
/// the deterministic target path/branch from `paths`.
///
/// ## Why `sessions` is a separate parameter
///
/// [`maestro_shell::DashboardSnapshot`] projects sessions into `DashboardTab` rows that carry a
/// `session_id` and a projected `session_status`, but NOT `cwd_resolved`, and it does not expose the
/// raw `SessionRecord` set. The safety rules here require BOTH a per-session liveness check AND a
/// `cwd_resolved == target_path` reference check, and the latter is impossible from the snapshot
/// alone. Rather than weaken the safety rule, the caller loads the fresh `SessionRecord`s read-only
/// (`maestro_shell::store::load_all`) and passes them in; the planner stays pure (it mutates nothing
/// and performs no I/O), preserving the planner's no-side-effect contract.
///
/// Returns [`WorktreeCleanupDecision::Removable`] ONLY when ALL hold:
/// - a workspace with `workspace_id` exists in the fresh snapshot;
/// - its policy is exactly [`maestro_shell::WorkspacePolicy::Worktree`];
/// - its `worktree_create` consent is present;
/// - the session `scan` is COMPLETE (no `Quarantined`/`FutureVersion` session-record outcomes);
/// - no fresh loaded session with this `session_id` is `Live`;
/// - no fresh loaded session (any id) still has `cwd_resolved` equal to the computed target path.
///
/// Otherwise it returns [`WorktreeCleanupDecision::Refused`] with the first applicable
/// [`WorktreeCleanupReason`], checked in that conservative order (a non-existent or non-`Worktree`
/// or unconsented workspace short-circuits before the scan-completeness gate, since those are
/// stronger refusals; an incomplete scan refuses before liveness/cwd reference checks).
pub fn plan_worktree_cleanup(
    workspace_id: &str,
    session_id: &str,
    snapshot: &maestro_shell::DashboardSnapshot,
    scan: &WorktreeCleanupSessionScan,
    paths: &maestro_shell::AppPaths,
) -> WorktreeCleanupPlan {
    let target_path = paths
        .worktree_base()
        .join(workspace_id)
        .join(session_id)
        .to_string_lossy()
        .into_owned();
    let branch = worktree_cleanup_branch(workspace_id, session_id);

    let refuse = |reason: WorktreeCleanupReason| WorktreeCleanupPlan {
        workspace_id: workspace_id.to_string(),
        session_id: session_id.to_string(),
        decision: WorktreeCleanupDecision::Refused,
        reason,
        target_path: target_path.clone(),
        branch: branch.clone(),
    };

    // The workspace must exist as a current-version record in the fresh snapshot. Workspaces are
    // grouped under their project; a future-version/quarantined workspace is NOT in `projects` and
    // is therefore (correctly) treated as unknown — never removable.
    let Some(workspace) = snapshot
        .projects
        .iter()
        .flat_map(|p| p.workspaces.iter())
        .find(|w| w.workspace_id == workspace_id)
    else {
        return refuse(WorktreeCleanupReason::UnknownWorkspace);
    };

    if workspace.policy != maestro_shell::WorkspacePolicy::Worktree {
        return refuse(WorktreeCleanupReason::NonWorktreePolicy);
    }
    if !workspace.consent.worktree_create {
        return refuse(WorktreeCleanupReason::MissingConsent);
    }

    // Scan completeness gate: once the workspace exists, is `Worktree`, and is consented, deletion is
    // otherwise possible — so an INCOMPLETE session scan must refuse here, BEFORE the liveness/cwd
    // checks. If any session-record file failed to load as a current valid record, we cannot read its
    // `cwd_resolved`/`status` and therefore cannot prove it does not reference the target checkout.
    // For a destructive command, "cannot prove no session references this path" is a refusal, not a
    // pass. (The earlier unknown-workspace / non-worktree / missing-consent refusals already make
    // deletion impossible, so they may still short-circuit first.)
    if !scan.is_complete() {
        return refuse(WorktreeCleanupReason::SessionRecordsUnavailable);
    }

    // Conservative liveness: any fresh record for THIS session that is still Live blocks removal.
    let this_session_live = scan
        .loaded
        .iter()
        .any(|s| s.session_id == session_id && s.status == maestro_shell::SessionStatus::Live);
    if this_session_live {
        return refuse(WorktreeCleanupReason::LiveSession);
    }

    // Conservative reference check: any fresh session (any id, any status — including Unknown) whose
    // resolved cwd still points at the target checkout blocks removal, UNLESS it is the SAME
    // requested session and it is clearly terminal (Exited). An `Unknown`-status record that still
    // references the path is NOT treated as safe.
    let referenced = scan.loaded.iter().any(|s| {
        if s.cwd_resolved != target_path {
            return false;
        }
        let same_requested_terminal =
            s.session_id == session_id && s.status == maestro_shell::SessionStatus::Exited;
        !same_requested_terminal
    });
    if referenced {
        return refuse(WorktreeCleanupReason::ReferencedCwd);
    }

    WorktreeCleanupPlan {
        workspace_id: workspace_id.to_string(),
        session_id: session_id.to_string(),
        decision: WorktreeCleanupDecision::Removable,
        reason: WorktreeCleanupReason::Ok,
        target_path,
        branch,
    }
}

// ===================== worktree-list (read-only inventory) =====================

/// Loaded-vs-missing status of the ONE workspace requested by `worktree-list`. The builder
/// enumerates from record state, so the only outcomes here are a present (`loaded`) workspace
/// record or none (`missing`). The richer `non_worktree`/`future_version`/`quarantined` values are
/// reserved in the vocabulary and are not emitted by the current builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeListWorkspaceStatus {
    Loaded,
    Missing,
    NonWorktree,
    FutureVersion,
    Quarantined,
}

impl WorktreeListWorkspaceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            WorktreeListWorkspaceStatus::Loaded => "loaded",
            WorktreeListWorkspaceStatus::Missing => "missing",
            WorktreeListWorkspaceStatus::NonWorktree => "non_worktree",
            WorktreeListWorkspaceStatus::FutureVersion => "future_version",
            WorktreeListWorkspaceStatus::Quarantined => "quarantined",
        }
    }
}

/// Per-candidate session status. A candidate enumerated from a loaded `SessionRecord` carries one
/// of the `loaded_*` values derived from its `SessionStatus`; the `missing`/`future_version`/
/// `quarantined` values are reserved and are not emitted by the current builder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeListSessionStatus {
    LoadedLive,
    LoadedExited,
    LoadedUnknown,
    Missing,
    FutureVersion,
    Quarantined,
}

impl WorktreeListSessionStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            WorktreeListSessionStatus::LoadedLive => "loaded_live",
            WorktreeListSessionStatus::LoadedExited => "loaded_exited",
            WorktreeListSessionStatus::LoadedUnknown => "loaded_unknown",
            WorktreeListSessionStatus::Missing => "missing",
            WorktreeListSessionStatus::FutureVersion => "future_version",
            WorktreeListSessionStatus::Quarantined => "quarantined",
        }
    }

    /// Map a loaded record's `SessionStatus` into the `loaded_*` wire value.
    pub fn from_loaded(status: maestro_shell::SessionStatus) -> Self {
        match status {
            maestro_shell::SessionStatus::Live => WorktreeListSessionStatus::LoadedLive,
            maestro_shell::SessionStatus::Exited => WorktreeListSessionStatus::LoadedExited,
            maestro_shell::SessionStatus::Unknown => WorktreeListSessionStatus::LoadedUnknown,
        }
    }
}

/// Read-only ownership verdict for a candidate, derived purely from its git inspection. This is the
/// `ownership` output field; it never authorizes deletion (the cleanup planner does that). Path
/// shape is NOT authority: only a git-verified worktree on the expected branch is
/// `verified_maestro_worktree`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeListOwnership {
    VerifiedMaestroWorktree,
    Unknown,
    Conflict,
    Missing,
    Uninspectable,
}

impl WorktreeListOwnership {
    pub fn as_str(self) -> &'static str {
        match self {
            WorktreeListOwnership::VerifiedMaestroWorktree => "verified_maestro_worktree",
            WorktreeListOwnership::Unknown => "unknown",
            WorktreeListOwnership::Conflict => "conflict",
            WorktreeListOwnership::Missing => "missing",
            WorktreeListOwnership::Uninspectable => "uninspectable",
        }
    }

    /// Derive ownership from a git inspection verdict:
    /// - `Verified` -> verified Maestro worktree;
    /// - `PathMissing` -> missing (nothing on disk to own);
    /// - `WrongRepo`/`WrongBranch` -> conflict (registered, but not ours);
    /// - `NotAWorktree` -> unknown (foreign content of indeterminate origin);
    /// - `RootNotARepo`/`GitUnavailable` -> uninspectable (we could not check).
    pub fn from_inspection(inspection: maestro_shell::WorktreeInspection) -> Self {
        use maestro_shell::WorktreeInspection as I;
        match inspection {
            I::Verified => WorktreeListOwnership::VerifiedMaestroWorktree,
            I::PathMissing => WorktreeListOwnership::Missing,
            I::WrongRepo | I::WrongBranch => WorktreeListOwnership::Conflict,
            I::NotAWorktree => WorktreeListOwnership::Unknown,
            I::RootNotARepo | I::GitUnavailable => WorktreeListOwnership::Uninspectable,
        }
    }
}

/// Read-only provenance classification for a worktree row, derived purely by comparing the durable
/// app-owned [`maestro_shell::WorktreeProvenance`] marker (written best-effort at `prepare_worktree`)
/// against the row's expected identity. This is the `provenance` output field. It is INFORMATIONAL
/// ONLY: it never changes `ownership`, `git_status`, `git_reason`, or any cleanup decision, and a
/// `recorded` value never makes a row removable. Path shape alone never produces `recorded` — a
/// marker must exist and every expected field must agree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeProvenanceStatus {
    /// A marker exists and matches the expected workspace_id, session_id, canonical target path,
    /// canonical repo root, and branch.
    Recorded,
    /// A marker exists but at least one expected field disagrees.
    Mismatch,
    /// No marker is present.
    Unrecorded,
    /// A marker exists but is future-version, corrupt/quarantined, or otherwise unreadable.
    Unreadable,
}

impl WorktreeProvenanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            WorktreeProvenanceStatus::Recorded => "recorded",
            WorktreeProvenanceStatus::Mismatch => "mismatch",
            WorktreeProvenanceStatus::Unrecorded => "unrecorded",
            WorktreeProvenanceStatus::Unreadable => "unreadable",
        }
    }
}

/// A pre-resolved provenance-marker load for one session, supplied to the pure worktree-list
/// builders. The apply path performs the actual `load_one`; tests inject a fixed value. Keeping the
/// store read OUT of the classifier keeps it pure and unit-testable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProvenanceMarker {
    /// No marker file present.
    Absent,
    /// A valid marker was loaded.
    Loaded(maestro_shell::WorktreeProvenance),
    /// A marker exists but could not be loaded (future-version or quarantined/corrupt). Treated
    /// conservatively as `unreadable`.
    Unreadable,
}

/// Classify a loaded provenance marker against a row's expected identity. Pure. `recorded` requires
/// the marker to be present AND every expected field — workspace_id, session_id, canonical target
/// path, canonical repo root, and branch — to agree; otherwise `mismatch`. An absent marker is
/// `unrecorded`; an unreadable one is `unreadable`. The caller passes already-canonicalized
/// `expected_target` / `expected_repo_root` (the same canonicalization the writer applied), so a
/// path difference here is a real disagreement, not a formatting artifact.
fn classify_provenance(
    marker: &ProvenanceMarker,
    expected_workspace_id: &str,
    expected_session_id: &str,
    expected_target: &str,
    expected_repo_root: &str,
    expected_branch: &str,
) -> WorktreeProvenanceStatus {
    match marker {
        ProvenanceMarker::Absent => WorktreeProvenanceStatus::Unrecorded,
        ProvenanceMarker::Unreadable => WorktreeProvenanceStatus::Unreadable,
        ProvenanceMarker::Loaded(p) => {
            let matches = p.workspace_id == expected_workspace_id
                && p.session_id == expected_session_id
                && p.target_path == expected_target
                && p.repo_root == expected_repo_root
                && p.branch == expected_branch;
            if matches {
                WorktreeProvenanceStatus::Recorded
            } else {
                WorktreeProvenanceStatus::Mismatch
            }
        }
    }
}

/// Canonicalize a path for provenance comparison, matching the writer's canonicalization. Falls back
/// to the input string when the path cannot be canonicalized (e.g. it no longer exists), so a row for
/// a missing target still compares against the literal expected value rather than silently matching.
fn canonical_for_provenance(path: &str) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.to_string())
}

/// Read-only, DISPLAY-ONLY staleness classification for a record-backed `worktree-list` candidate
/// row. This is the `staleness` output field. It is INFORMATIONAL ONLY: it never changes `ownership`,
/// `git_status`, `git_reason`, `provenance`, or any cleanup decision, and a `stale` value never makes
/// a row removable. The cleanup planner remains the sole removal authority; a row may legitimately be
/// `stale` and still be `Refused` by a live-session, cwd-reference, or incomplete-scan gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorktreeStaleness {
    /// The session is `Live`, or its last-used age is below the idle threshold, or its last-used time
    /// is in the future relative to `now` (clock skew clamped to zero age).
    Active,
    /// `Exited` and last used at least [`STALENESS_IDLE_AFTER_MS`] ago but less than
    /// [`STALENESS_STALE_AFTER_MS`] ago.
    Idle,
    /// `Exited` and last used at least [`STALENESS_STALE_AFTER_MS`] ago.
    Stale,
    /// The record's status is `Unknown`, so its last-used signal cannot be trusted to age the row.
    Unknown,
}

impl WorktreeStaleness {
    pub fn as_str(self) -> &'static str {
        match self {
            WorktreeStaleness::Active => "active",
            WorktreeStaleness::Idle => "idle",
            WorktreeStaleness::Stale => "stale",
            WorktreeStaleness::Unknown => "unknown",
        }
    }
}

/// Fixed, conservative display thresholds for [`classify_worktree_staleness`]. Defined in ONE place so
/// the idle/stale boundaries are auditable and cannot drift between call sites. These are
/// display-only: they age a row's `staleness` label and NEVER gate deletion.
pub const STALENESS_IDLE_AFTER_MS: u64 = 24 * 60 * 60 * 1000; // 24 hours
pub const STALENESS_STALE_AFTER_MS: u64 = 7 * 24 * 60 * 60 * 1000; // 7 days

/// Classify a record-backed row's display-only staleness from its loaded [`SessionRecord`] and an
/// injected `now_ms`. Pure and unit-testable.
///
/// - `Live` => `active`, regardless of age (an attached session is never stale).
/// - `Unknown` => `unknown` (degraded record state; never aged into stale).
/// - `Exited` => aged from its last-used time: `last_attached_at_ms` when non-zero, otherwise
///   `created_at_ms`. If `now_ms < last_used_ms` (clock skew) the age clamps to zero and the row is
///   `active`. Age >= [`STALENESS_STALE_AFTER_MS`] => `stale`; age >= [`STALENESS_IDLE_AFTER_MS`] =>
///   `idle`; below idle => `active`.
///
/// Filesystem mtime/ctime, `WorktreeProvenance.created_at_ms`, and git `prunable`/`locked` metadata
/// are deliberately NOT consulted: only the fresh `SessionRecord` last-use signal ages a row.
pub fn classify_worktree_staleness(
    session: &maestro_shell::SessionRecord,
    now_ms: u64,
) -> WorktreeStaleness {
    match session.status {
        maestro_shell::SessionStatus::Live => WorktreeStaleness::Active,
        maestro_shell::SessionStatus::Unknown => WorktreeStaleness::Unknown,
        maestro_shell::SessionStatus::Exited => {
            let last_used_ms = if session.last_attached_at_ms != 0 {
                session.last_attached_at_ms
            } else {
                session.created_at_ms
            };
            let age_ms = now_ms.saturating_sub(last_used_ms);
            if age_ms >= STALENESS_STALE_AFTER_MS {
                WorktreeStaleness::Stale
            } else if age_ms >= STALENESS_IDLE_AFTER_MS {
                WorktreeStaleness::Idle
            } else {
                WorktreeStaleness::Active
            }
        }
    }
}

/// Map a read-only git inspection verdict to the public `(git_status, git_reason)` pair.
///
/// The top-level `git_status` vocabulary is fixed by contract to
/// `verified`/`path_missing`/`not_a_worktree`/`wrong_repo`/`wrong_branch`/`dirty`/`unavailable`,
/// so the internal `RootNotARepo` variant must NOT leak into `git_status`. It is folded into
/// `git_status:"unavailable"` and distinguished by a stable `git_reason:"root_not_a_repo"`; every
/// other verdict reports `git_reason:"ok"` (the status itself is the reason). Pure.
fn git_status_reason(
    inspection: maestro_shell::WorktreeInspection,
) -> (&'static str, &'static str) {
    use maestro_shell::WorktreeInspection as I;
    match inspection {
        I::RootNotARepo => ("unavailable", "root_not_a_repo"),
        other => (other.as_str(), "ok"),
    }
}

/// One row of the `worktree-list` inventory: a single candidate worktree checkout for the requested
/// workspace, fully classified. Pure serde DTO. `git_status`/`git_reason` come from the read-only
/// inspection; `cleanup_plan_decision`/`cleanup_plan_reason` come from the SHARED
/// [`plan_worktree_cleanup`] planner so listing and cleanup agree on eligibility.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct WorktreeListCandidate {
    pub workspace_id: String,
    pub session_id: String,
    pub target_path: String,
    pub branch: String,
    pub workspace_status: WorktreeListWorkspaceStatus,
    pub workspace_reason: String,
    pub session_status: WorktreeListSessionStatus,
    pub session_reason: String,
    pub git_status: String,
    pub git_reason: String,
    pub ownership: WorktreeListOwnership,
    pub cleanup_plan_decision: WorktreeCleanupDecision,
    pub cleanup_plan_reason: WorktreeCleanupReason,
    /// Read-only durable-marker provenance. INFORMATIONAL ONLY — it never changes `ownership`,
    /// `git_status`, `git_reason`, or any cleanup decision above.
    pub provenance: WorktreeProvenanceStatus,
    /// Read-only, DISPLAY-ONLY staleness derived from the loaded `SessionRecord` last-use time.
    /// INFORMATIONAL ONLY — it never changes `ownership`, `git_status`, `git_reason`, `provenance`,
    /// or any cleanup decision above; a `stale` row can still be `Refused` by the planner.
    pub staleness: WorktreeStaleness,
}

/// Aggregated counts over a `worktree-list` candidate set. `total` is the candidate count; the
/// remaining fields tally the `ownership` and cleanup-plan-decision buckets, so a script can
/// summarize an inventory without re-walking `candidates`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct WorktreeListCounts {
    pub total: usize,
    pub verified_maestro_worktree: usize,
    pub unknown: usize,
    pub conflict: usize,
    pub missing: usize,
    pub uninspectable: usize,
    pub removable: usize,
    pub refused: usize,
}

/// The full read-only `worktree-list` output object. One stable JSON object on stdout.
///
/// `workspace_id` is the top-level SCOPE field: present in single-workspace (`--workspace-id`) mode,
/// and OMITTED entirely in all-workspaces (`--all`) mode (never serialized as `null`). Each candidate
/// row still carries its own `workspace_id` regardless of mode.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct WorktreeListOutput {
    pub command: &'static str,
    pub base: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    pub candidates: Vec<WorktreeListCandidate>,
    pub counts: WorktreeListCounts,
    /// Present ONLY in `--all --include-orphans` mode: a read-only inventory of non-record-backed /
    /// malformed / unknown filesystem entries under `worktree_base`. Omitted entirely otherwise (so
    /// existing scoped and plain `--all` output shapes are byte-for-byte unchanged). Orphan rows are
    /// inventory only — never `removable`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphan_candidates: Option<Vec<WorktreeListOrphanCandidate>>,
    /// Aggregate counts over `orphan_candidates`, kept SEPARATE from record-backed `counts` so a
    /// script cannot confuse orphan inventory rows with eligible cleanup rows. Present iff
    /// `orphan_candidates` is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orphan_counts: Option<WorktreeListOrphanCounts>,
}

/// A pre-computed git inspection for one candidate target path, supplied to the pure
/// [`build_worktree_list`] builder. The apply path runs the real read-only
/// [`maestro_shell::inspect_worktree`]; tests inject a fixed verdict. Keeping the git call OUT of
/// the builder keeps classification pure and unit-testable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorktreeListInspection {
    pub inspection: maestro_shell::WorktreeInspection,
}

/// Build the read-only `worktree-list` inventory for ONE workspace — purely.
///
/// Runs NO git itself: each candidate's git verdict is supplied by `inspect` (the apply path passes
/// a closure wrapping [`maestro_shell::inspect_worktree`]; tests pass a fixed map). Mutates nothing,
/// writes no records.
///
/// Candidate enumeration: if the workspace is present in `snapshot`, every loaded
/// `SessionRecord` whose `workspace_id` matches becomes one candidate (sorted by `session_id` for
/// stable output). For each, the target path/branch and the cleanup decision/reason come from the
/// SHARED [`plan_worktree_cleanup`] planner — so an incomplete session scan surfaces as
/// `session_records_unavailable` here too and is NEVER presented as removable. A
/// syntactically-valid-but-absent workspace yields zero candidates (not an error).
#[allow(clippy::too_many_arguments)]
pub fn build_worktree_list(
    workspace_id: &str,
    base: &str,
    snapshot: &maestro_shell::DashboardSnapshot,
    scan: &WorktreeCleanupSessionScan,
    paths: &maestro_shell::AppPaths,
    mut inspect: impl FnMut(&str, &str, &str) -> maestro_shell::WorktreeInspection,
    mut provenance: impl FnMut(&str) -> ProvenanceMarker,
    now_ms: u64,
) -> WorktreeListOutput {
    let workspace = snapshot
        .projects
        .iter()
        .flat_map(|p| p.workspaces.iter())
        .find(|w| w.workspace_id == workspace_id);

    let mut candidates: Vec<WorktreeListCandidate> = Vec::new();
    if let Some(workspace) = workspace {
        append_workspace_candidates(
            workspace,
            snapshot,
            scan,
            paths,
            &mut inspect,
            &mut provenance,
            now_ms,
            &mut candidates,
        );
    }

    let counts = worktree_list_counts(&candidates);

    WorktreeListOutput {
        command: "worktree-list",
        base: base.to_string(),
        workspace_id: Some(workspace_id.to_string()),
        candidates,
        counts,
        orphan_candidates: None,
        orphan_counts: None,
    }
}

/// Build the read-only `worktree-list` inventory for ALL loaded Worktree-policy workspaces — purely.
///
/// Records-only: enumerates every workspace record in `snapshot` whose policy is exactly
/// `WorkspacePolicy::Worktree` (sorted by `workspace_id` for stable output), and for each emits the
/// same per-session candidates as the single-workspace builder via the SHARED
/// [`append_workspace_candidates`]. Non-Worktree workspaces are excluded entirely (they are never
/// part of `--all`). No filesystem walk, no path-shape inference: a directory under `worktree_base`
/// with no backing record is invisible to this mode. `counts` aggregate across all rows; the
/// top-level `workspace_id` is `None` (omitted in output).
#[allow(clippy::too_many_arguments)]
pub fn build_worktree_list_all(
    base: &str,
    snapshot: &maestro_shell::DashboardSnapshot,
    scan: &WorktreeCleanupSessionScan,
    paths: &maestro_shell::AppPaths,
    mut inspect: impl FnMut(&str, &str, &str) -> maestro_shell::WorktreeInspection,
    mut provenance: impl FnMut(&str) -> ProvenanceMarker,
    now_ms: u64,
) -> WorktreeListOutput {
    let mut workspaces: Vec<&maestro_shell::Workspace> = snapshot
        .projects
        .iter()
        .flat_map(|p| p.workspaces.iter())
        .filter(|w| w.policy == maestro_shell::WorkspacePolicy::Worktree)
        .collect();
    workspaces.sort_by(|a, b| a.workspace_id.cmp(&b.workspace_id));
    workspaces.dedup_by(|a, b| a.workspace_id == b.workspace_id);

    let mut candidates: Vec<WorktreeListCandidate> = Vec::new();
    for workspace in workspaces {
        append_workspace_candidates(
            workspace,
            snapshot,
            scan,
            paths,
            &mut inspect,
            &mut provenance,
            now_ms,
            &mut candidates,
        );
    }

    let counts = worktree_list_counts(&candidates);

    WorktreeListOutput {
        command: "worktree-list",
        base: base.to_string(),
        workspace_id: None,
        candidates,
        counts,
        orphan_candidates: None,
        orphan_counts: None,
    }
}

/// Emit the per-session candidate rows for ONE workspace record into `candidates`. Shared by the
/// single-workspace and all-workspaces builders so classification (the authority boundary, the
/// shared `plan_worktree_cleanup`, the read-only git inspection, and the `RootNotARepo` fold) is
/// identical in both modes. Pure — runs no git itself; `inspect` supplies each git verdict.
#[allow(clippy::too_many_arguments)]
fn append_workspace_candidates(
    workspace: &maestro_shell::Workspace,
    snapshot: &maestro_shell::DashboardSnapshot,
    scan: &WorktreeCleanupSessionScan,
    paths: &maestro_shell::AppPaths,
    inspect: &mut impl FnMut(&str, &str, &str) -> maestro_shell::WorktreeInspection,
    provenance: &mut impl FnMut(&str) -> ProvenanceMarker,
    now_ms: u64,
    candidates: &mut Vec<WorktreeListCandidate>,
) {
    let workspace_id = workspace.workspace_id.as_str();

    // The authority boundary: a matching git worktree can prove a checkout exists, but it must
    // not prove MAESTRO ownership unless the workspace record itself is a loaded Worktree-policy
    // workspace. For a non-Worktree workspace we classify `workspace_status:"non_worktree"` with
    // a stable `non_worktree_policy` reason and SKIP git inspection entirely (the simpler of the
    // two allowed behaviors): ownership is reported `uninspectable` and `git_status:"unavailable"`
    // so a `verified` git verdict can never be surfaced. The shared planner still refuses with
    // `non_worktree_policy`, so listing and cleanup remain in agreement. (`--all` never reaches this
    // branch since it pre-filters to Worktree-policy workspaces; `--workspace-id` still relies on it.)
    let is_worktree = workspace.policy == maestro_shell::WorkspacePolicy::Worktree;
    let (workspace_status, workspace_reason) = if is_worktree {
        (WorktreeListWorkspaceStatus::Loaded, "ok")
    } else {
        (
            WorktreeListWorkspaceStatus::NonWorktree,
            "non_worktree_policy",
        )
    };

    // Loaded session records for THIS workspace, deduped by session_id, sorted for stable output.
    // We carry the full record reference (not just the status) so the display-only staleness
    // classifier can read the fresh last-use timestamps without re-walking the scan.
    let mut sessions: Vec<&maestro_shell::SessionRecord> = scan
        .loaded
        .iter()
        .filter(|s| s.workspace_id == workspace_id)
        .collect();
    sessions.sort_by(|a, b| a.session_id.cmp(&b.session_id));
    sessions.dedup_by(|a, b| a.session_id == b.session_id);

    for session in sessions {
        let session_id = session.session_id.clone();
        let status = session.status;
        let plan = plan_worktree_cleanup(workspace_id, &session_id, snapshot, scan, paths);
        let (git_status, git_reason, ownership) = if is_worktree {
            let inspection = inspect(&workspace.root, &plan.target_path, &plan.branch);
            let (status, reason) = git_status_reason(inspection);
            (
                status.to_string(),
                reason.to_string(),
                WorktreeListOwnership::from_inspection(inspection),
            )
        } else {
            (
                "unavailable".to_string(),
                "non_worktree_policy".to_string(),
                WorktreeListOwnership::Uninspectable,
            )
        };
        // Read-only provenance: compare the loaded marker against this row's canonical identity.
        // Purely informational — it does not touch ownership/git/cleanup above.
        let marker = provenance(&session_id);
        let provenance_status = classify_provenance(
            &marker,
            workspace_id,
            &session_id,
            &canonical_for_provenance(&plan.target_path),
            &canonical_for_provenance(&workspace.root),
            &plan.branch,
        );
        // Read-only, display-only staleness from the loaded record's last-use time. Purely
        // informational — it does not touch ownership/git/provenance/cleanup above.
        let staleness = classify_worktree_staleness(session, now_ms);
        candidates.push(WorktreeListCandidate {
            workspace_id: workspace_id.to_string(),
            session_id,
            target_path: plan.target_path.clone(),
            branch: plan.branch.clone(),
            workspace_status,
            workspace_reason: workspace_reason.to_string(),
            session_status: WorktreeListSessionStatus::from_loaded(status),
            session_reason: "ok".to_string(),
            git_status,
            git_reason,
            ownership,
            cleanup_plan_decision: plan.decision,
            cleanup_plan_reason: plan.reason,
            provenance: provenance_status,
            staleness,
        });
    }
}

/// Tally a candidate set into [`WorktreeListCounts`]. Pure.
fn worktree_list_counts(candidates: &[WorktreeListCandidate]) -> WorktreeListCounts {
    let mut counts = WorktreeListCounts {
        total: candidates.len(),
        ..WorktreeListCounts::default()
    };
    for c in candidates {
        match c.ownership {
            WorktreeListOwnership::VerifiedMaestroWorktree => counts.verified_maestro_worktree += 1,
            WorktreeListOwnership::Unknown => counts.unknown += 1,
            WorktreeListOwnership::Conflict => counts.conflict += 1,
            WorktreeListOwnership::Missing => counts.missing += 1,
            WorktreeListOwnership::Uninspectable => counts.uninspectable += 1,
        }
        match c.cleanup_plan_decision {
            WorktreeCleanupDecision::Removable => counts.removable += 1,
            WorktreeCleanupDecision::Refused => counts.refused += 1,
        }
    }
    counts
}

// ===========================================================================================
// Read-only orphan-directory inventory (`worktree-list --all --include-orphans`).
//
// This is NOT garbage collection. Orphan rows are read-only inventory of what physically exists
// under `worktree_base` that is NOT already represented by a loaded record-backed candidate. No
// orphan row is ever `removable`; path shape alone is never treated as proof of ownership.
// ===========================================================================================

/// What kind of filesystem object an orphan path is, determined WITHOUT following symlinks. A
/// symlink is reported as `symlink` even if it points at a directory (we never traverse it).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanPathStatus {
    Dir,
    File,
    Symlink,
    /// The entry exists but its metadata could not be read (e.g. permission error on the entry).
    Unreadable,
}

impl OrphanPathStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            OrphanPathStatus::Dir => "dir",
            OrphanPathStatus::File => "file",
            OrphanPathStatus::Symlink => "symlink",
            OrphanPathStatus::Unreadable => "unreadable",
        }
    }
}

/// Whether a path segment (workspace or session) is a syntactically valid id, malformed, or sits at
/// the wrong depth. `wrong_depth` is reserved for entries deeper than `<ws>/<session>` that we still
/// surface as a single conservative row without descending.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanSegmentStatus {
    IdShaped,
    Malformed,
    WrongDepth,
}

impl OrphanSegmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            OrphanSegmentStatus::IdShaped => "id_shaped",
            OrphanSegmentStatus::Malformed => "malformed",
            OrphanSegmentStatus::WrongDepth => "wrong_depth",
        }
    }
}

/// Relationship between an id-shaped orphan path and the loaded record set. Conservative: anything
/// other than `backed` means we could not (or did not) prove ownership from records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OrphanRecordStatus {
    /// No loaded workspace record matches the workspace segment.
    WorkspaceRecordMissing,
    /// A loaded workspace record matches, but no loaded session record matches the session segment.
    SessionRecordMissing,
    /// The path is already represented by a loaded record-backed `candidates[]` row (this is used
    /// only internally to suppress duplicates; such paths are never emitted as orphans).
    Backed,
    /// A future-version record shadows this id (surfaced by snapshot/scan data); uninspectable.
    FutureVersion,
    /// A quarantined record shadows this id; uninspectable.
    Quarantined,
    /// We deliberately did not check records (malformed / wrong-depth / non-directory rows).
    NotChecked,
}

impl OrphanRecordStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            OrphanRecordStatus::WorkspaceRecordMissing => "workspace_record_missing",
            OrphanRecordStatus::SessionRecordMissing => "session_record_missing",
            OrphanRecordStatus::Backed => "backed",
            OrphanRecordStatus::FutureVersion => "future_version",
            OrphanRecordStatus::Quarantined => "quarantined",
            OrphanRecordStatus::NotChecked => "not_checked",
        }
    }
}

/// One read-only orphan inventory row. Distinct from [`WorktreeListCandidate`] on purpose so the two
/// row kinds can never be confused. `cleanup_plan_decision` is ALWAYS `Refused` and
/// `cleanup_plan_reason` is informational — an orphan row is never removable.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct WorktreeListOrphanCandidate {
    pub workspace_id_segment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id_segment: Option<String>,
    pub path: String,
    pub path_status: OrphanPathStatus,
    pub segment_status: OrphanSegmentStatus,
    pub record_status: OrphanRecordStatus,
    pub git_status: String,
    pub git_reason: String,
    pub ownership: WorktreeListOwnership,
    /// Always `not_applicable` for orphan rows — they are inventory, never cleanup-eligible.
    pub cleanup_plan_decision: &'static str,
    pub cleanup_plan_reason: String,
    /// Read-only durable-marker provenance for the orphan path. INFORMATIONAL ONLY — it never makes
    /// an orphan row removable and never changes `cleanup_plan_decision` (always `not_applicable`).
    pub provenance: WorktreeProvenanceStatus,
}

/// Aggregate counts over an orphan inventory set. Kept separate from [`WorktreeListCounts`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct WorktreeListOrphanCounts {
    /// Total orphan rows emitted.
    pub total: usize,
    /// Rows whose involved segments are all id-shaped.
    pub id_shaped: usize,
    /// Rows with a malformed or wrong-depth segment.
    pub malformed_or_wrong_depth: usize,
    /// Rows that are not directories (`file`/`symlink`/`unreadable`).
    pub non_directory: usize,
    /// Rows whose ownership is `conflict` (wrong repo/branch from informational git inspection).
    pub conflict: usize,
    /// Rows for which no backing record was found (`workspace_record_missing`/`session_record_missing`).
    pub no_record: usize,
}

/// A single discovered filesystem entry under `worktree_base`, produced by the effectful walk in
/// `main.rs` and handed to the PURE [`build_orphan_candidates`] classifier. Splitting enumeration
/// (I/O) from classification (pure) keeps the orphan logic unit-testable without touching disk.
///
/// `depth` is 1 for an immediate child of `worktree_base` (a workspace-segment entry) and 2 for a
/// child of a workspace segment (a session-segment entry). The walk never descends past depth 2 and
/// never follows symlinks, so `path_status:"symlink"` entries are reported, not traversed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrphanFsEntry {
    /// The immediate workspace-segment name (depth-1 component).
    pub workspace_segment: String,
    /// The session-segment name (depth-2 component), or `None` for a depth-1 entry.
    pub session_segment: Option<String>,
    /// Absolute path of this entry.
    pub path: String,
    /// What kind of object it is (symlink-aware; never followed).
    pub path_status: OrphanPathStatus,
}

/// Build the read-only orphan inventory for `--all --include-orphans` — PURELY.
///
/// Runs no I/O: the caller has already walked `worktree_base` into `entries` (depth 1 and 2,
/// symlink-aware, no recursion). This function classifies each entry against the loaded records and
/// the already-built record-backed `candidates`, suppressing any path that is already a backed
/// candidate, and computing conservative `segment_status`/`record_status`/`ownership` plus an
/// always-`not_applicable` cleanup decision. Optional informational git inspection is supplied by
/// `inspect` (same closure shape as the record-backed builder) ONLY for id-shaped session-segment
/// entries whose workspace record is loaded and `Worktree` policy but whose session record is
/// missing; every other row gets `git_status:"not_checked"` and no git call.
#[allow(clippy::too_many_arguments)]
pub fn build_orphan_candidates(
    entries: &[OrphanFsEntry],
    snapshot: &maestro_shell::DashboardSnapshot,
    scan: &WorktreeCleanupSessionScan,
    record_backed: &[WorktreeListCandidate],
    mut inspect: impl FnMut(&str, &str, &str) -> maestro_shell::WorktreeInspection,
    mut provenance: impl FnMut(&str) -> ProvenanceMarker,
) -> Vec<WorktreeListOrphanCandidate> {
    // Set of target paths already represented by a record-backed candidate row — used to suppress
    // duplicate orphan rows. A path that backs a real candidate is NOT an orphan.
    let backed_paths: std::collections::HashSet<&str> = record_backed
        .iter()
        .map(|c| c.target_path.as_str())
        .collect();

    let mut orphans: Vec<WorktreeListOrphanCandidate> = Vec::new();

    for entry in entries {
        // Skip anything already backed by a real candidate (never duplicate).
        if backed_paths.contains(entry.path.as_str()) {
            continue;
        }

        let ws_id_shaped = maestro_shell::validate_id(&entry.workspace_segment).is_ok();
        let non_directory = entry.path_status != OrphanPathStatus::Dir;

        // Non-directory entries (file/symlink/unreadable) and malformed segments are surfaced
        // conservatively WITHOUT any git inspection. ownership:"unknown", not_applicable.
        if non_directory {
            let segment_status = if ws_id_shaped {
                OrphanSegmentStatus::IdShaped
            } else {
                OrphanSegmentStatus::Malformed
            };
            orphans.push(orphan_row(
                entry,
                segment_status,
                OrphanRecordStatus::NotChecked,
                "not_checked",
                "ok",
                WorktreeListOwnership::Unknown,
                WorktreeProvenanceStatus::Unrecorded,
            ));
            continue;
        }

        // From here on the entry is a real directory.
        match &entry.session_segment {
            // Depth-1 directory: a workspace-segment directory directly under worktree_base.
            None => {
                if !ws_id_shaped {
                    orphans.push(orphan_row(
                        entry,
                        OrphanSegmentStatus::Malformed,
                        OrphanRecordStatus::NotChecked,
                        "not_checked",
                        "ok",
                        WorktreeListOwnership::Unknown,
                        WorktreeProvenanceStatus::Unrecorded,
                    ));
                    continue;
                }
                // id-shaped workspace dir: classify by whether a workspace record is loaded. We do
                // NOT git-inspect a depth-1 dir (the worktree target is always at depth 2).
                let record_status =
                    workspace_record_status(&entry.workspace_segment, snapshot, scan);
                orphans.push(orphan_row(
                    entry,
                    OrphanSegmentStatus::IdShaped,
                    record_status,
                    "not_checked",
                    "ok",
                    WorktreeListOwnership::Unknown,
                    WorktreeProvenanceStatus::Unrecorded,
                ));
            }
            // Depth-2 directory: a session-segment directory under a workspace segment — the shape
            // of an actual worktree target `<worktree_base>/<ws>/<session>`.
            Some(session_segment) => {
                let session_id_shaped = maestro_shell::validate_id(session_segment).is_ok();
                if !ws_id_shaped || !session_id_shaped {
                    orphans.push(orphan_row(
                        entry,
                        OrphanSegmentStatus::Malformed,
                        OrphanRecordStatus::NotChecked,
                        "not_checked",
                        "ok",
                        WorktreeListOwnership::Unknown,
                        WorktreeProvenanceStatus::Unrecorded,
                    ));
                    continue;
                }

                // Both segments id-shaped. Resolve the workspace record to decide record_status and
                // whether an informational git inspection is warranted.
                let workspace = snapshot
                    .projects
                    .iter()
                    .flat_map(|p| p.workspaces.iter())
                    .find(|w| w.workspace_id == *entry.workspace_segment);

                match workspace {
                    None => {
                        // No loaded workspace record: cannot safely resolve a root, so do not
                        // git-inspect. ownership unknown, not removable.
                        orphans.push(orphan_row(
                            entry,
                            OrphanSegmentStatus::IdShaped,
                            OrphanRecordStatus::WorkspaceRecordMissing,
                            "not_checked",
                            "ok",
                            WorktreeListOwnership::Unknown,
                            WorktreeProvenanceStatus::Unrecorded,
                        ));
                    }
                    Some(workspace) => {
                        // Workspace record loaded, both segments id-shaped: an expected worktree
                        // identity is resolvable, so classify the provenance marker (informational
                        // only — it NEVER changes the always-`not_applicable` cleanup decision).
                        let expected_branch =
                            worktree_cleanup_branch(&entry.workspace_segment, session_segment);
                        let marker = provenance(session_segment);
                        let provenance_status = classify_provenance(
                            &marker,
                            &entry.workspace_segment,
                            session_segment,
                            &canonical_for_provenance(&entry.path),
                            &canonical_for_provenance(&workspace.root),
                            &expected_branch,
                        );

                        // Workspace record loaded. Is there a loaded session record for this id?
                        let has_session =
                            scan.loaded.iter().any(|s| s.session_id == *session_segment);
                        if has_session {
                            // This path is backed by a loaded session record. If it was a real
                            // candidate it was already suppressed above; reaching here means the
                            // candidate set excluded it (e.g. workspace not Worktree policy). Treat
                            // as backed/uninspectable inventory, never removable.
                            orphans.push(orphan_row(
                                entry,
                                OrphanSegmentStatus::IdShaped,
                                OrphanRecordStatus::Backed,
                                "not_checked",
                                "ok",
                                WorktreeListOwnership::Uninspectable,
                                provenance_status,
                            ));
                            continue;
                        }

                        // Workspace loaded, session record MISSING. Informational git inspection is
                        // allowed ONLY when the workspace is Worktree policy (so a root + expected
                        // branch can be resolved); the row stays not_applicable regardless.
                        if workspace.policy == maestro_shell::WorkspacePolicy::Worktree {
                            let inspection =
                                inspect(&workspace.root, &entry.path, &expected_branch);
                            let (git_status, git_reason) = git_status_reason(inspection);
                            // Recordless orphan must never be `verified_maestro_worktree`: with no
                            // session record we cannot claim Maestro ownership even if git verifies
                            // the branch. Fold a `Verified` verdict down to `unknown`.
                            let ownership = match WorktreeListOwnership::from_inspection(inspection)
                            {
                                WorktreeListOwnership::VerifiedMaestroWorktree => {
                                    WorktreeListOwnership::Unknown
                                }
                                other => other,
                            };
                            orphans.push(orphan_row(
                                entry,
                                OrphanSegmentStatus::IdShaped,
                                OrphanRecordStatus::SessionRecordMissing,
                                git_status,
                                git_reason,
                                ownership,
                                provenance_status,
                            ));
                        } else {
                            // Non-Worktree workspace: no safe worktree root/branch to inspect.
                            orphans.push(orphan_row(
                                entry,
                                OrphanSegmentStatus::IdShaped,
                                OrphanRecordStatus::SessionRecordMissing,
                                "not_checked",
                                "ok",
                                WorktreeListOwnership::Unknown,
                                provenance_status,
                            ));
                        }
                    }
                }
            }
        }
    }

    // Stable output: sort by (workspace_segment, session_segment, path).
    orphans.sort_by(|a, b| {
        a.workspace_id_segment
            .cmp(&b.workspace_id_segment)
            .then_with(|| a.session_id_segment.cmp(&b.session_id_segment))
            .then_with(|| a.path.cmp(&b.path))
    });
    orphans
}

/// Classify an id-shaped depth-1 workspace segment against loaded records / non-loaded scan
/// outcomes. Pure. A future-version/quarantined session outcome under this workspace is surfaced as
/// `future_version`/`quarantined` (uninspectable, never removable); otherwise the status reflects
/// whether a workspace record is loaded.
fn workspace_record_status(
    workspace_segment: &str,
    snapshot: &maestro_shell::DashboardSnapshot,
    scan: &WorktreeCleanupSessionScan,
) -> OrphanRecordStatus {
    // If the session scan is incomplete (any quarantined/future-version record), we cannot prove the
    // record set for this workspace is authoritative — classify conservatively as uninspectable.
    if !scan.is_complete() {
        // Distinguish the dominant non-loaded kind for a stable, informative status.
        let has_future = scan
            .non_loaded
            .iter()
            .any(|n| matches!(n, WorktreeCleanupNonLoadedSession::FutureVersion { .. }));
        if has_future {
            return OrphanRecordStatus::FutureVersion;
        }
        return OrphanRecordStatus::Quarantined;
    }
    let workspace_loaded = snapshot
        .projects
        .iter()
        .flat_map(|p| p.workspaces.iter())
        .any(|w| w.workspace_id == workspace_segment);
    if workspace_loaded {
        // Workspace dir with a loaded workspace record but no session segment is still inventory —
        // there is no per-session target here. Report it as session-record-missing (no session id).
        OrphanRecordStatus::SessionRecordMissing
    } else {
        OrphanRecordStatus::WorkspaceRecordMissing
    }
}

/// Construct one orphan row with the always-`not_applicable` cleanup decision. Pure helper.
/// `provenance` is informational only and never affects the cleanup decision.
fn orphan_row(
    entry: &OrphanFsEntry,
    segment_status: OrphanSegmentStatus,
    record_status: OrphanRecordStatus,
    git_status: &str,
    git_reason: &str,
    ownership: WorktreeListOwnership,
    provenance: WorktreeProvenanceStatus,
) -> WorktreeListOrphanCandidate {
    WorktreeListOrphanCandidate {
        workspace_id_segment: entry.workspace_segment.clone(),
        session_id_segment: entry.session_segment.clone(),
        path: entry.path.clone(),
        path_status: entry.path_status,
        segment_status,
        record_status,
        git_status: git_status.to_string(),
        git_reason: git_reason.to_string(),
        ownership,
        provenance,
        cleanup_plan_decision: "not_applicable",
        cleanup_plan_reason: "orphan_inventory_read_only".to_string(),
    }
}

/// Tally an orphan inventory set into [`WorktreeListOrphanCounts`]. Pure.
pub fn orphan_counts(orphans: &[WorktreeListOrphanCandidate]) -> WorktreeListOrphanCounts {
    let mut counts = WorktreeListOrphanCounts {
        total: orphans.len(),
        ..WorktreeListOrphanCounts::default()
    };
    for o in orphans {
        match o.segment_status {
            OrphanSegmentStatus::IdShaped => counts.id_shaped += 1,
            OrphanSegmentStatus::Malformed | OrphanSegmentStatus::WrongDepth => {
                counts.malformed_or_wrong_depth += 1
            }
        }
        if o.path_status != OrphanPathStatus::Dir {
            counts.non_directory += 1;
        }
        if o.ownership == WorktreeListOwnership::Conflict {
            counts.conflict += 1;
        }
        if matches!(
            o.record_status,
            OrphanRecordStatus::WorkspaceRecordMissing | OrphanRecordStatus::SessionRecordMissing
        ) {
            counts.no_record += 1;
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- worktree-cleanup: planner -----------------------------------------------------------

    fn wc_consent(worktree_create: bool) -> maestro_shell::WorkspaceConsent {
        maestro_shell::WorkspaceConsent {
            worktree_create,
            repo_write: false,
            granted_at_ms: if worktree_create { Some(1) } else { None },
        }
    }

    fn wc_workspace(
        workspace_id: &str,
        policy: maestro_shell::WorkspacePolicy,
        consent: maestro_shell::WorkspaceConsent,
    ) -> maestro_shell::Workspace {
        maestro_shell::Workspace {
            workspace_id: workspace_id.to_string(),
            project_id: "proj".to_string(),
            root: format!("/repo/{workspace_id}"),
            policy,
            consent,
        }
    }

    fn wc_snapshot(workspaces: Vec<maestro_shell::Workspace>) -> maestro_shell::DashboardSnapshot {
        maestro_shell::DashboardSnapshot {
            projects: vec![maestro_shell::ProjectSnapshot {
                project_id: "proj".to_string(),
                name: "Proj".to_string(),
                root: "/repo".to_string(),
                default_workspace_policy: maestro_shell::WorkspacePolicy::Worktree,
                last_active_at_ms: 0,
                icon: None,
                accent_color: None,
                launch_defaults: None,
                directories: Vec::new(),
                system: false,
                hidden: false,
                workspaces,
                tasks: vec![],
                windows: vec![],
            }],
            ..Default::default()
        }
    }

    fn wc_session(
        session_id: &str,
        cwd_resolved: &str,
        status: maestro_shell::SessionStatus,
    ) -> maestro_shell::SessionRecord {
        maestro_shell::SessionRecord {
            session_id: session_id.to_string(),
            workspace_id: "ws".to_string(),
            kind: maestro_shell::SessionKind::Agent,
            launch: maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "ls".to_string(),
                params: vec![],
            },
            cwd_resolved: cwd_resolved.to_string(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status,
        }
    }

    /// Wrap loaded session records into a COMPLETE scan (no non-loaded outcomes).
    fn wc_scan(loaded: Vec<maestro_shell::SessionRecord>) -> WorktreeCleanupSessionScan {
        WorktreeCleanupSessionScan {
            loaded,
            non_loaded: vec![],
        }
    }

    /// The deterministic target path the planner computes for `ws`/`sess` under `paths`.
    fn wc_target(paths: &maestro_shell::AppPaths, ws: &str, sess: &str) -> String {
        paths
            .worktree_base()
            .join(ws)
            .join(sess)
            .to_string_lossy()
            .into_owned()
    }

    /// Like [`wc_session`] but with explicit last-use timestamps, for staleness classification.
    fn wc_session_aged(
        session_id: &str,
        status: maestro_shell::SessionStatus,
        last_attached_at_ms: u64,
        created_at_ms: u64,
    ) -> maestro_shell::SessionRecord {
        let mut s = wc_session(session_id, "/cwd", status);
        s.last_attached_at_ms = last_attached_at_ms;
        s.created_at_ms = created_at_ms;
        s
    }

    // ---- worktree-list: display-only staleness classifier ------------------------------------

    #[test]
    fn staleness_live_is_active_at_any_age() {
        // Live: never stale even if its timestamps are ancient relative to a far-future `now`.
        let s = wc_session_aged("sess", maestro_shell::SessionStatus::Live, 1, 1);
        let now = STALENESS_STALE_AFTER_MS * 100;
        assert_eq!(
            classify_worktree_staleness(&s, now),
            WorktreeStaleness::Active
        );
    }

    #[test]
    fn staleness_unknown_is_unknown() {
        let s = wc_session_aged("sess", maestro_shell::SessionStatus::Unknown, 1, 1);
        let now = STALENESS_STALE_AFTER_MS * 100;
        assert_eq!(
            classify_worktree_staleness(&s, now),
            WorktreeStaleness::Unknown
        );
    }

    #[test]
    fn staleness_exited_below_idle_is_active() {
        // last used `now - (idle - 1ms)`: just under the idle threshold.
        let last = 1_000_000_000;
        let now = last + STALENESS_IDLE_AFTER_MS - 1;
        let s = wc_session_aged("sess", maestro_shell::SessionStatus::Exited, last, 0);
        assert_eq!(
            classify_worktree_staleness(&s, now),
            WorktreeStaleness::Active
        );
    }

    #[test]
    fn staleness_exited_at_idle_threshold_is_idle() {
        let last = 1_000_000_000;
        let now = last + STALENESS_IDLE_AFTER_MS;
        let s = wc_session_aged("sess", maestro_shell::SessionStatus::Exited, last, 0);
        assert_eq!(
            classify_worktree_staleness(&s, now),
            WorktreeStaleness::Idle
        );
    }

    #[test]
    fn staleness_exited_at_stale_threshold_is_stale() {
        let last = 1_000_000_000;
        let now = last + STALENESS_STALE_AFTER_MS;
        let s = wc_session_aged("sess", maestro_shell::SessionStatus::Exited, last, 0);
        assert_eq!(
            classify_worktree_staleness(&s, now),
            WorktreeStaleness::Stale
        );
    }

    #[test]
    fn staleness_falls_back_to_created_when_last_attached_zero() {
        // last_attached_at_ms == 0 => age from created_at_ms instead.
        let created = 1_000_000_000;
        let now = created + STALENESS_STALE_AFTER_MS;
        let s = wc_session_aged("sess", maestro_shell::SessionStatus::Exited, 0, created);
        assert_eq!(
            classify_worktree_staleness(&s, now),
            WorktreeStaleness::Stale
        );
    }

    #[test]
    fn staleness_clock_skew_clamps_to_active() {
        // now_ms < last_used_ms: a future last-use time must clamp age to zero -> active, never stale.
        let last = 5_000_000_000;
        let now = 1_000;
        let s = wc_session_aged("sess", maestro_shell::SessionStatus::Exited, last, last);
        assert_eq!(
            classify_worktree_staleness(&s, now),
            WorktreeStaleness::Active
        );
    }

    #[test]
    fn planner_removable_for_consented_unreferenced_worktree() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        // An exited session for the SAME requested id, even if it references the target, is allowed.
        let target = wc_target(&paths, "ws", "sess");
        let sessions = vec![wc_session(
            "sess",
            &target,
            maestro_shell::SessionStatus::Exited,
        )];
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &wc_scan(sessions), &paths);
        assert!(plan.is_removable());
        assert_eq!(plan.reason, WorktreeCleanupReason::Ok);
        assert_eq!(plan.target_path, target);
        assert_eq!(plan.branch, "maestro/ws/sess");
    }

    #[test]
    fn planner_refuses_unknown_workspace() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![]);
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &wc_scan(vec![]), &paths);
        assert!(!plan.is_removable());
        assert_eq!(plan.reason, WorktreeCleanupReason::UnknownWorkspace);
    }

    #[test]
    fn planner_refuses_non_worktree_policy() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::RepoWrite,
            wc_consent(true),
        )]);
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &wc_scan(vec![]), &paths);
        assert_eq!(plan.reason, WorktreeCleanupReason::NonWorktreePolicy);
    }

    #[test]
    fn planner_refuses_missing_consent() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(false),
        )]);
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &wc_scan(vec![]), &paths);
        assert_eq!(plan.reason, WorktreeCleanupReason::MissingConsent);
    }

    #[test]
    fn planner_refuses_live_session() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let sessions = vec![wc_session(
            "sess",
            "/somewhere/else",
            maestro_shell::SessionStatus::Live,
        )];
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &wc_scan(sessions), &paths);
        assert_eq!(plan.reason, WorktreeCleanupReason::LiveSession);
    }

    #[test]
    fn planner_refuses_referenced_cwd_from_other_session() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let target = wc_target(&paths, "ws", "sess");
        // A DIFFERENT, exited session still resolving to the target path blocks removal.
        let sessions = vec![wc_session(
            "other-sess",
            &target,
            maestro_shell::SessionStatus::Exited,
        )];
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &wc_scan(sessions), &paths);
        assert_eq!(plan.reason, WorktreeCleanupReason::ReferencedCwd);
    }

    #[test]
    fn planner_refuses_referenced_cwd_when_same_session_unknown_status() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let target = wc_target(&paths, "ws", "sess");
        // SAME requested id, but Unknown status (not clearly terminal) still referencing -> refused.
        let sessions = vec![wc_session(
            "sess",
            &target,
            maestro_shell::SessionStatus::Unknown,
        )];
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &wc_scan(sessions), &paths);
        assert_eq!(plan.reason, WorktreeCleanupReason::ReferencedCwd);
    }

    #[test]
    fn planner_is_pure_does_not_require_git_or_touch_fs() {
        // `/base` does not exist and is not a git repo; the planner must still return a verdict
        // without running git, creating directories, or panicking.
        let paths = maestro_shell::AppPaths::with_base("/nonexistent-base-xyz");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &wc_scan(vec![]), &paths);
        assert!(plan.is_removable());
        // No directory was created as a side effect.
        assert!(!std::path::Path::new("/nonexistent-base-xyz").exists());
    }

    #[test]
    fn planner_refuses_when_scan_has_future_version_session() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        // A consented, otherwise-removable workspace, but the session scan is INCOMPLETE: a
        // future-version session record could not be decoded, so we cannot prove no session
        // references the target. Must refuse — never removable.
        let scan = WorktreeCleanupSessionScan {
            loaded: vec![],
            non_loaded: vec![WorktreeCleanupNonLoadedSession::FutureVersion {
                path: "/sessions/newer.json".to_string(),
                ours: 1,
                got: 2,
            }],
        };
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &scan, &paths);
        assert!(!plan.is_removable());
        assert_eq!(
            plan.reason,
            WorktreeCleanupReason::SessionRecordsUnavailable
        );
    }

    #[test]
    fn planner_refuses_when_scan_has_quarantined_session() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let scan = WorktreeCleanupSessionScan {
            loaded: vec![],
            non_loaded: vec![WorktreeCleanupNonLoadedSession::Quarantined {
                original: "/sessions/bad.json".to_string(),
                moved_to: "/sessions/corrupt/bad.json".to_string(),
                reason: "schema mismatch".to_string(),
            }],
        };
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &scan, &paths);
        assert!(!plan.is_removable());
        assert_eq!(
            plan.reason,
            WorktreeCleanupReason::SessionRecordsUnavailable
        );
    }

    #[test]
    fn planner_scan_incomplete_refuses_before_liveness_and_reference_checks() {
        // Even with loaded sessions present that would otherwise be benign, ANY non-loaded outcome
        // forces the incomplete-scan refusal. The incomplete-scan refusal also wins over a
        // would-be-removable loaded set.
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let scan = WorktreeCleanupSessionScan {
            loaded: vec![wc_session(
                "sess",
                "/somewhere/else",
                maestro_shell::SessionStatus::Exited,
            )],
            non_loaded: vec![WorktreeCleanupNonLoadedSession::Quarantined {
                original: "/sessions/bad.json".to_string(),
                moved_to: "/sessions/corrupt/bad.json".to_string(),
                reason: "bad".to_string(),
            }],
        };
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &scan, &paths);
        assert_eq!(
            plan.reason,
            WorktreeCleanupReason::SessionRecordsUnavailable
        );
    }

    #[test]
    fn planner_unknown_workspace_short_circuits_before_scan_completeness() {
        // The stronger refusals (workspace absent) may still win over the scan gate.
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![]);
        let scan = WorktreeCleanupSessionScan {
            loaded: vec![],
            non_loaded: vec![WorktreeCleanupNonLoadedSession::FutureVersion {
                path: "/sessions/newer.json".to_string(),
                ours: 1,
                got: 2,
            }],
        };
        let plan = plan_worktree_cleanup("ws", "sess", &snap, &scan, &paths);
        assert_eq!(plan.reason, WorktreeCleanupReason::UnknownWorkspace);
    }

    #[test]
    fn worktree_cleanup_branch_is_deterministic() {
        assert_eq!(worktree_cleanup_branch("ws", "sess"), "maestro/ws/sess");
    }

    // ---- worktree-list: pure classifier / builder ---------------------------------------------

    #[test]
    fn ownership_maps_each_inspection_verdict() {
        use maestro_shell::WorktreeInspection as I;
        assert_eq!(
            WorktreeListOwnership::from_inspection(I::Verified),
            WorktreeListOwnership::VerifiedMaestroWorktree
        );
        assert_eq!(
            WorktreeListOwnership::from_inspection(I::PathMissing),
            WorktreeListOwnership::Missing
        );
        assert_eq!(
            WorktreeListOwnership::from_inspection(I::WrongRepo),
            WorktreeListOwnership::Conflict
        );
        assert_eq!(
            WorktreeListOwnership::from_inspection(I::WrongBranch),
            WorktreeListOwnership::Conflict
        );
        assert_eq!(
            WorktreeListOwnership::from_inspection(I::NotAWorktree),
            WorktreeListOwnership::Unknown
        );
        assert_eq!(
            WorktreeListOwnership::from_inspection(I::RootNotARepo),
            WorktreeListOwnership::Uninspectable
        );
        assert_eq!(
            WorktreeListOwnership::from_inspection(I::GitUnavailable),
            WorktreeListOwnership::Uninspectable
        );
    }

    #[test]
    fn build_list_missing_workspace_is_zero_candidates() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![]);
        let out = build_worktree_list(
            "ws",
            "/base",
            &snap,
            &wc_scan(vec![]),
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            0,
        );
        assert_eq!(out.command, "worktree-list");
        assert_eq!(out.workspace_id.as_deref(), Some("ws"));
        assert!(out.candidates.is_empty());
        assert_eq!(out.counts.total, 0);
    }

    #[test]
    fn build_list_verified_removable_candidate_counts() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let target = wc_target(&paths, "ws", "sess");
        let sessions = vec![wc_session(
            "sess",
            &target,
            maestro_shell::SessionStatus::Exited,
        )];
        let out = build_worktree_list(
            "ws",
            "/base",
            &snap,
            &wc_scan(sessions),
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            0,
        );
        assert_eq!(out.candidates.len(), 1);
        let c = &out.candidates[0];
        assert_eq!(c.session_id, "sess");
        assert_eq!(c.target_path, target);
        assert_eq!(c.branch, "maestro/ws/sess");
        assert_eq!(c.git_status, "verified");
        assert_eq!(c.ownership, WorktreeListOwnership::VerifiedMaestroWorktree);
        assert_eq!(c.session_status, WorktreeListSessionStatus::LoadedExited);
        assert_eq!(c.cleanup_plan_decision, WorktreeCleanupDecision::Removable);
        assert_eq!(c.cleanup_plan_reason, WorktreeCleanupReason::Ok);
        assert_eq!(out.counts.total, 1);
        assert_eq!(out.counts.verified_maestro_worktree, 1);
        assert_eq!(out.counts.removable, 1);
        assert_eq!(out.counts.refused, 0);
    }

    #[test]
    fn build_list_scoped_row_carries_staleness() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        // Exited, last used long ago relative to `now` -> stale.
        let last = 1_000_000_000;
        let now = last + STALENESS_STALE_AFTER_MS;
        let sessions = vec![wc_session_aged(
            "sess",
            maestro_shell::SessionStatus::Exited,
            last,
            last,
        )];
        let out = build_worktree_list(
            "ws",
            "/base",
            &snap,
            &wc_scan(sessions),
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            now,
        );
        assert_eq!(out.candidates.len(), 1);
        assert_eq!(out.candidates[0].staleness, WorktreeStaleness::Stale);
    }

    #[test]
    fn build_list_all_rows_carry_staleness() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let last = 1_000_000_000;
        let now = last + STALENESS_IDLE_AFTER_MS; // idle, not yet stale
        let sessions = vec![wc_session_aged(
            "sess",
            maestro_shell::SessionStatus::Exited,
            last,
            last,
        )];
        let out = build_worktree_list_all(
            "/base",
            &snap,
            &wc_scan(sessions),
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            now,
        );
        assert_eq!(out.candidates.len(), 1);
        assert_eq!(out.candidates[0].staleness, WorktreeStaleness::Idle);
    }

    #[test]
    fn build_list_stale_row_can_still_be_refused() {
        // A row may be aged `stale` AND still be Refused by a hard gate: here a DIFFERENT live
        // session references the target cwd, so the planner refuses with `referenced_cwd` even though
        // the requested session is an old exited one. Display never overrides the gate.
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let target = wc_target(&paths, "ws", "sess");
        let last = 1_000_000_000;
        let now = last + STALENESS_STALE_AFTER_MS;
        // The requested exited session, aged into stale.
        let mut requested =
            wc_session_aged("sess", maestro_shell::SessionStatus::Exited, last, last);
        requested.cwd_resolved = "/elsewhere".to_string();
        // A live session whose cwd references the target path -> hard cwd-reference block.
        let blocker = wc_session("other", &target, maestro_shell::SessionStatus::Live);
        let out = build_worktree_list(
            "ws",
            "/base",
            &snap,
            &wc_scan(vec![requested, blocker]),
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            now,
        );
        let c = out
            .candidates
            .iter()
            .find(|c| c.session_id == "sess")
            .expect("requested row present");
        assert_eq!(c.staleness, WorktreeStaleness::Stale);
        assert_eq!(c.cleanup_plan_decision, WorktreeCleanupDecision::Refused);
        assert_eq!(c.cleanup_plan_reason, WorktreeCleanupReason::ReferencedCwd);
    }

    #[test]
    fn build_list_plan_decision_invariant_to_staleness() {
        // The cleanup decision/reason for every row must be byte-identical regardless of the `now_ms`
        // used to classify staleness: staleness is display-only and never feeds the planner.
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let target = wc_target(&paths, "ws", "sess");
        let sessions = vec![wc_session(
            "sess",
            &target,
            maestro_shell::SessionStatus::Exited,
        )];
        let build = |now: u64| {
            build_worktree_list(
                "ws",
                "/base",
                &snap,
                &wc_scan(sessions.clone()),
                &paths,
                |_, _, _| maestro_shell::WorktreeInspection::Verified,
                absent_provenance,
                now,
            )
        };
        let fresh = build(0);
        let aged = build(STALENESS_STALE_AFTER_MS * 1000);
        // Staleness labels differ across the two clocks, but the decision/reason must not.
        assert_eq!(fresh.candidates.len(), aged.candidates.len());
        for (a, b) in fresh.candidates.iter().zip(aged.candidates.iter()) {
            assert_eq!(a.cleanup_plan_decision, b.cleanup_plan_decision);
            assert_eq!(a.cleanup_plan_reason, b.cleanup_plan_reason);
        }
    }

    #[test]
    fn build_list_incomplete_scan_never_removable() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let target = wc_target(&paths, "ws", "sess");
        // One loaded session yields the candidate; a non-loaded outcome makes the scan incomplete.
        let scan = WorktreeCleanupSessionScan {
            loaded: vec![wc_session(
                "sess",
                &target,
                maestro_shell::SessionStatus::Exited,
            )],
            non_loaded: vec![WorktreeCleanupNonLoadedSession::FutureVersion {
                path: "/base/sessions/other.json".to_string(),
                ours: 1,
                got: 2,
            }],
        };
        let out = build_worktree_list(
            "ws",
            "/base",
            &snap,
            &scan,
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            0,
        );
        assert_eq!(out.candidates.len(), 1);
        let c = &out.candidates[0];
        assert_eq!(c.cleanup_plan_decision, WorktreeCleanupDecision::Refused);
        assert_eq!(
            c.cleanup_plan_reason,
            WorktreeCleanupReason::SessionRecordsUnavailable
        );
        assert_eq!(out.counts.removable, 0);
        assert_eq!(out.counts.refused, 1);
    }

    #[test]
    fn build_list_uninspectable_when_git_unavailable() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let target = wc_target(&paths, "ws", "sess");
        let sessions = vec![wc_session(
            "sess",
            &target,
            maestro_shell::SessionStatus::Exited,
        )];
        let out = build_worktree_list(
            "ws",
            "/base",
            &snap,
            &wc_scan(sessions),
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::GitUnavailable,
            absent_provenance,
            0,
        );
        let c = &out.candidates[0];
        assert_eq!(c.git_status, "unavailable");
        assert_eq!(c.ownership, WorktreeListOwnership::Uninspectable);
        assert_eq!(out.counts.uninspectable, 1);
        // A dirty/uninspectable git verdict does not change cleanup eligibility — that comes from
        // the planner, which here still finds it removable.
        assert_eq!(out.counts.removable, 1);
    }

    #[test]
    fn git_status_reason_folds_root_not_a_repo_into_unavailable() {
        use maestro_shell::WorktreeInspection as I;
        // `RootNotARepo` must NOT widen the public `git_status` vocabulary: it folds into
        // `unavailable` and is distinguished only by the stable `git_reason`.
        assert_eq!(
            git_status_reason(I::RootNotARepo),
            ("unavailable", "root_not_a_repo")
        );
        // Every other verdict reports the status as the reason.
        assert_eq!(git_status_reason(I::Verified), ("verified", "ok"));
        assert_eq!(git_status_reason(I::PathMissing), ("path_missing", "ok"));
        assert_eq!(git_status_reason(I::GitUnavailable), ("unavailable", "ok"));
    }

    #[test]
    fn build_list_root_not_a_repo_reports_unavailable_with_reason() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let target = wc_target(&paths, "ws", "sess");
        let sessions = vec![wc_session(
            "sess",
            &target,
            maestro_shell::SessionStatus::Exited,
        )];
        let out = build_worktree_list(
            "ws",
            "/base",
            &snap,
            &wc_scan(sessions),
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::RootNotARepo,
            absent_provenance,
            0,
        );
        let c = &out.candidates[0];
        // Public status stays within the agreed vocabulary; the internal variant surfaces only as a
        // stable reason so callers can still distinguish it.
        assert_eq!(c.git_status, "unavailable");
        assert_eq!(c.git_reason, "root_not_a_repo");
        assert_eq!(c.ownership, WorktreeListOwnership::Uninspectable);
        assert_eq!(out.counts.uninspectable, 1);
    }

    #[test]
    fn build_list_non_worktree_workspace_never_verifies_ownership() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        // A loaded NON-Worktree workspace whose git checkout would otherwise inspect as `Verified`.
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::ScratchCwd,
            wc_consent(true),
        )]);
        let target = wc_target(&paths, "ws", "sess");
        let sessions = vec![wc_session(
            "sess",
            &target,
            maestro_shell::SessionStatus::Exited,
        )];
        let out = build_worktree_list(
            "ws",
            "/base",
            &snap,
            &wc_scan(sessions),
            &paths,
            // Even if git would prove a matching worktree exists, ownership must not be verified.
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            0,
        );
        assert_eq!(out.candidates.len(), 1);
        let c = &out.candidates[0];
        assert_eq!(c.workspace_status, WorktreeListWorkspaceStatus::NonWorktree);
        assert_eq!(c.workspace_reason, "non_worktree_policy");
        // The authority boundary: a non-Worktree workspace can never report Maestro ownership.
        assert_ne!(c.ownership, WorktreeListOwnership::VerifiedMaestroWorktree);
        assert_eq!(c.ownership, WorktreeListOwnership::Uninspectable);
        assert_eq!(c.git_status, "unavailable");
        assert_eq!(c.git_reason, "non_worktree_policy");
        // The shared planner refuses the same non-Worktree workspace for the same reason, so listing
        // and cleanup stay in agreement.
        assert_eq!(c.cleanup_plan_decision, WorktreeCleanupDecision::Refused);
        assert_eq!(
            c.cleanup_plan_reason,
            WorktreeCleanupReason::NonWorktreePolicy
        );
        assert_eq!(out.counts.verified_maestro_worktree, 0);
        assert_eq!(out.counts.removable, 0);
        assert_eq!(out.counts.refused, 1);
    }

    // ---- worktree-list --all: record-backed all-workspaces builder -----------------------------

    /// A loaded session record bound to an explicit `workspace_id` (the shared `wc_session` helper
    /// hardcodes "ws", which the multi-workspace `--all` tests need to vary).
    fn wc_session_for(
        workspace_id: &str,
        session_id: &str,
        cwd_resolved: &str,
        status: maestro_shell::SessionStatus,
    ) -> maestro_shell::SessionRecord {
        let mut rec = wc_session(session_id, cwd_resolved, status);
        rec.workspace_id = workspace_id.to_string();
        rec
    }

    /// A snapshot whose workspaces live across TWO projects, so `--all` is proven to aggregate over
    /// the whole snapshot rather than a single project.
    fn wc_snapshot_two_projects(
        a: Vec<maestro_shell::Workspace>,
        b: Vec<maestro_shell::Workspace>,
    ) -> maestro_shell::DashboardSnapshot {
        maestro_shell::DashboardSnapshot {
            projects: vec![
                maestro_shell::ProjectSnapshot {
                    project_id: "proj-a".to_string(),
                    name: "ProjA".to_string(),
                    root: "/repo-a".to_string(),
                    default_workspace_policy: maestro_shell::WorkspacePolicy::Worktree,
                    last_active_at_ms: 0,
                    icon: None,
                    accent_color: None,
                    launch_defaults: None,
                    directories: Vec::new(),
                    system: false,
                    hidden: false,
                    workspaces: a,
                    tasks: vec![],
                    windows: vec![],
                },
                maestro_shell::ProjectSnapshot {
                    project_id: "proj-b".to_string(),
                    name: "ProjB".to_string(),
                    root: "/repo-b".to_string(),
                    default_workspace_policy: maestro_shell::WorkspacePolicy::Worktree,
                    last_active_at_ms: 0,
                    icon: None,
                    accent_color: None,
                    launch_defaults: None,
                    directories: Vec::new(),
                    system: false,
                    hidden: false,
                    workspaces: b,
                    tasks: vec![],
                    windows: vec![],
                },
            ],
            ..Default::default()
        }
    }

    #[test]
    fn build_all_aggregates_two_worktree_workspaces() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot_two_projects(
            vec![wc_workspace(
                "ws-a",
                maestro_shell::WorkspacePolicy::Worktree,
                wc_consent(true),
            )],
            vec![wc_workspace(
                "ws-b",
                maestro_shell::WorkspacePolicy::Worktree,
                wc_consent(true),
            )],
        );
        let target_a = wc_target(&paths, "ws-a", "sess-a");
        let target_b = wc_target(&paths, "ws-b", "sess-b");
        let scan = wc_scan(vec![
            wc_session_for(
                "ws-a",
                "sess-a",
                &target_a,
                maestro_shell::SessionStatus::Exited,
            ),
            wc_session_for(
                "ws-b",
                "sess-b",
                &target_b,
                maestro_shell::SessionStatus::Exited,
            ),
        ]);
        let out = build_worktree_list_all(
            "/base",
            &snap,
            &scan,
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            0,
        );

        // Top-level workspace_id is omitted in --all mode.
        assert_eq!(out.workspace_id, None);
        // Both workspaces' sessions appear as candidates, each carrying its OWN workspace_id.
        assert_eq!(out.candidates.len(), 2);
        let ids: Vec<&str> = out
            .candidates
            .iter()
            .map(|c| c.workspace_id.as_str())
            .collect();
        assert!(ids.contains(&"ws-a"));
        assert!(ids.contains(&"ws-b"));
        // Counts aggregate across all rows.
        assert_eq!(out.counts.total, 2);
        assert_eq!(out.counts.verified_maestro_worktree, 2);
        assert_eq!(out.counts.removable, 2);
    }

    #[test]
    fn build_all_omits_top_level_workspace_id_in_json() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let out = build_worktree_list_all(
            "/base",
            &snap,
            &wc_scan(vec![]),
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            0,
        );
        let json = serde_json::to_string(&out).expect("serializes");
        // --all omits the key entirely; it must never appear as `null`.
        assert!(!json.contains("\"workspace_id\":null"));
        assert!(!json.contains("\"workspace_id\""));
    }

    #[test]
    fn build_all_excludes_non_worktree_workspaces() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        // One Worktree workspace and one ScratchCwd workspace, each with a loaded session.
        let snap = wc_snapshot(vec![
            wc_workspace(
                "ws-wt",
                maestro_shell::WorkspacePolicy::Worktree,
                wc_consent(true),
            ),
            wc_workspace(
                "ws-scratch",
                maestro_shell::WorkspacePolicy::ScratchCwd,
                wc_consent(true),
            ),
        ]);
        let target_wt = wc_target(&paths, "ws-wt", "sess");
        let target_scratch = wc_target(&paths, "ws-scratch", "sess");
        let scan = wc_scan(vec![
            wc_session_for(
                "ws-wt",
                "sess",
                &target_wt,
                maestro_shell::SessionStatus::Exited,
            ),
            wc_session_for(
                "ws-scratch",
                "sess",
                &target_scratch,
                maestro_shell::SessionStatus::Exited,
            ),
        ]);
        let out = build_worktree_list_all(
            "/base",
            &snap,
            &scan,
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            0,
        );
        // Only the Worktree-policy workspace contributes a candidate; the ScratchCwd one is invisible
        // to --all entirely (NOT merely classified non_worktree).
        assert_eq!(out.candidates.len(), 1);
        assert_eq!(out.candidates[0].workspace_id, "ws-wt");
    }

    #[test]
    fn build_all_incomplete_scan_refuses_removal() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let target = wc_target(&paths, "ws", "sess");
        let scan = WorktreeCleanupSessionScan {
            loaded: vec![wc_session_for(
                "ws",
                "sess",
                &target,
                maestro_shell::SessionStatus::Exited,
            )],
            non_loaded: vec![WorktreeCleanupNonLoadedSession::FutureVersion {
                path: "/base/sessions/other.json".to_string(),
                ours: 1,
                got: 2,
            }],
        };
        let out = build_worktree_list_all(
            "/base",
            &snap,
            &scan,
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            0,
        );
        assert_eq!(out.candidates.len(), 1);
        let c = &out.candidates[0];
        assert_eq!(c.cleanup_plan_decision, WorktreeCleanupDecision::Refused);
        assert_eq!(
            c.cleanup_plan_reason,
            WorktreeCleanupReason::SessionRecordsUnavailable
        );
        assert_eq!(out.counts.removable, 0);
        assert_eq!(out.counts.refused, 1);
    }

    // ---- worktree-list: --include-orphans pure orphan classifier ------------------------------

    /// Build an `OrphanFsEntry` for a depth-1 (workspace-segment) or depth-2 (session-segment) path.
    fn orphan_entry(
        ws: &str,
        sess: Option<&str>,
        path: &str,
        path_status: OrphanPathStatus,
    ) -> OrphanFsEntry {
        OrphanFsEntry {
            workspace_segment: ws.to_string(),
            session_segment: sess.map(str::to_string),
            path: path.to_string(),
            path_status,
        }
    }

    /// A do-nothing inspect closure that asserts it is NEVER called. Used to prove rows that must not
    /// trigger git inspection (malformed/file/symlink/missing-workspace-record) really don't.
    fn never_inspect(
        _root: &str,
        _target: &str,
        _branch: &str,
    ) -> maestro_shell::WorktreeInspection {
        panic!("git inspection must not run for this orphan row");
    }

    /// Test provenance lookup that always reports no marker — the default for rows whose provenance
    /// is irrelevant to the assertion under test.
    fn absent_provenance(_session_id: &str) -> ProvenanceMarker {
        ProvenanceMarker::Absent
    }

    /// Build a fully-matching provenance marker for the canonical expected identity used by the
    /// classifier tests below. Individual tests clone and perturb one field to exercise `mismatch`.
    fn sample_marker() -> maestro_shell::WorktreeProvenance {
        maestro_shell::WorktreeProvenance {
            workspace_id: "ws-1".to_string(),
            session_id: "sess-1".to_string(),
            repo_root: "/repo".to_string(),
            target_path: "/wt/target".to_string(),
            branch: "maestro/ws-1/sess-1".to_string(),
            created_at_ms: 123,
        }
    }

    #[test]
    fn provenance_recorded_when_marker_fully_matches() {
        let status = classify_provenance(
            &ProvenanceMarker::Loaded(sample_marker()),
            "ws-1",
            "sess-1",
            "/wt/target",
            "/repo",
            "maestro/ws-1/sess-1",
        );
        assert_eq!(status, WorktreeProvenanceStatus::Recorded);
        assert_eq!(status.as_str(), "recorded");
    }

    #[test]
    fn provenance_mismatch_when_any_field_disagrees() {
        // Perturb each field in turn; every one must demote a present marker to `mismatch`.
        let perturbations: [(&str, &str, &str, &str, &str); 5] = [
            (
                "ws-OTHER",
                "sess-1",
                "/wt/target",
                "/repo",
                "maestro/ws-1/sess-1",
            ),
            (
                "ws-1",
                "sess-OTHER",
                "/wt/target",
                "/repo",
                "maestro/ws-1/sess-1",
            ),
            (
                "ws-1",
                "sess-1",
                "/wt/OTHER",
                "/repo",
                "maestro/ws-1/sess-1",
            ),
            (
                "ws-1",
                "sess-1",
                "/wt/target",
                "/repo-OTHER",
                "maestro/ws-1/sess-1",
            ),
            (
                "ws-1",
                "sess-1",
                "/wt/target",
                "/repo",
                "maestro/ws-1/OTHER",
            ),
        ];
        for (ws, sess, target, repo, branch) in perturbations {
            let status = classify_provenance(
                &ProvenanceMarker::Loaded(sample_marker()),
                ws,
                sess,
                target,
                repo,
                branch,
            );
            assert_eq!(
                status,
                WorktreeProvenanceStatus::Mismatch,
                "expected mismatch when expected=({ws},{sess},{target},{repo},{branch})"
            );
        }
    }

    #[test]
    fn provenance_unrecorded_when_marker_absent() {
        let status = classify_provenance(
            &ProvenanceMarker::Absent,
            "ws-1",
            "sess-1",
            "/wt/target",
            "/repo",
            "maestro/ws-1/sess-1",
        );
        assert_eq!(status, WorktreeProvenanceStatus::Unrecorded);
        assert_eq!(status.as_str(), "unrecorded");
    }

    #[test]
    fn provenance_unreadable_when_marker_unreadable() {
        let status = classify_provenance(
            &ProvenanceMarker::Unreadable,
            "ws-1",
            "sess-1",
            "/wt/target",
            "/repo",
            "maestro/ws-1/sess-1",
        );
        assert_eq!(status, WorktreeProvenanceStatus::Unreadable);
        assert_eq!(status.as_str(), "unreadable");
    }

    #[test]
    fn orphan_empty_entries_produce_no_rows() {
        let snap = wc_snapshot(vec![]);
        let orphans = build_orphan_candidates(
            &[],
            &snap,
            &wc_scan(vec![]),
            &[],
            never_inspect,
            absent_provenance,
        );
        assert!(orphans.is_empty());
        let counts = orphan_counts(&orphans);
        assert_eq!(counts.total, 0);
    }

    #[test]
    fn orphan_malformed_workspace_segment_not_inspected() {
        let snap = wc_snapshot(vec![]);
        let entries = vec![orphan_entry(
            "../escape",
            None,
            "/base/worktrees/../escape",
            OrphanPathStatus::Dir,
        )];
        let orphans = build_orphan_candidates(
            &entries,
            &snap,
            &wc_scan(vec![]),
            &[],
            never_inspect,
            absent_provenance,
        );
        assert_eq!(orphans.len(), 1);
        let o = &orphans[0];
        assert_eq!(o.segment_status, OrphanSegmentStatus::Malformed);
        assert_eq!(o.git_status, "not_checked");
        assert_eq!(o.ownership, WorktreeListOwnership::Unknown);
        assert_eq!(o.cleanup_plan_decision, "not_applicable");
    }

    #[test]
    fn orphan_malformed_session_segment_not_inspected() {
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let entries = vec![orphan_entry(
            "ws",
            Some("bad/slash"),
            "/base/worktrees/ws/bad/slash",
            OrphanPathStatus::Dir,
        )];
        let orphans = build_orphan_candidates(
            &entries,
            &snap,
            &wc_scan(vec![]),
            &[],
            never_inspect,
            absent_provenance,
        );
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].segment_status, OrphanSegmentStatus::Malformed);
        assert_eq!(orphans[0].cleanup_plan_decision, "not_applicable");
    }

    #[test]
    fn orphan_file_under_workspace_position_not_inspected() {
        let snap = wc_snapshot(vec![]);
        let entries = vec![orphan_entry(
            "loose.txt",
            None,
            "/base/worktrees/loose.txt",
            OrphanPathStatus::File,
        )];
        let orphans = build_orphan_candidates(
            &entries,
            &snap,
            &wc_scan(vec![]),
            &[],
            never_inspect,
            absent_provenance,
        );
        assert_eq!(orphans.len(), 1);
        let o = &orphans[0];
        assert_eq!(o.path_status, OrphanPathStatus::File);
        assert_eq!(o.record_status, OrphanRecordStatus::NotChecked);
        assert_eq!(o.ownership, WorktreeListOwnership::Unknown);
        let counts = orphan_counts(&orphans);
        assert_eq!(counts.non_directory, 1);
    }

    #[test]
    fn orphan_symlink_reported_not_followed() {
        let snap = wc_snapshot(vec![]);
        // A symlink at the session position: reported as a symlink row, never traversed/inspected.
        let entries = vec![orphan_entry(
            "ws",
            Some("link"),
            "/base/worktrees/ws/link",
            OrphanPathStatus::Symlink,
        )];
        let orphans = build_orphan_candidates(
            &entries,
            &snap,
            &wc_scan(vec![]),
            &[],
            never_inspect,
            absent_provenance,
        );
        assert_eq!(orphans.len(), 1);
        assert_eq!(orphans[0].path_status, OrphanPathStatus::Symlink);
        assert_eq!(orphans[0].cleanup_plan_decision, "not_applicable");
        assert_eq!(orphan_counts(&orphans).non_directory, 1);
    }

    #[test]
    fn orphan_id_shaped_dir_missing_workspace_record_not_inspected() {
        // No loaded workspace record for "ghost": cannot resolve a root, so no git inspection.
        let snap = wc_snapshot(vec![]);
        let entries = vec![orphan_entry(
            "ghost",
            Some("sess"),
            "/base/worktrees/ghost/sess",
            OrphanPathStatus::Dir,
        )];
        let orphans = build_orphan_candidates(
            &entries,
            &snap,
            &wc_scan(vec![]),
            &[],
            never_inspect,
            absent_provenance,
        );
        assert_eq!(orphans.len(), 1);
        let o = &orphans[0];
        assert_eq!(o.segment_status, OrphanSegmentStatus::IdShaped);
        assert_eq!(o.record_status, OrphanRecordStatus::WorkspaceRecordMissing);
        assert_eq!(o.git_status, "not_checked");
        assert_eq!(o.ownership, WorktreeListOwnership::Unknown);
        assert_eq!(o.cleanup_plan_decision, "not_applicable");
        assert_eq!(orphan_counts(&orphans).no_record, 1);
    }

    #[test]
    fn orphan_loaded_workspace_missing_session_runs_informational_git() {
        // Workspace record loaded + Worktree policy, but NO loaded session record for "sess":
        // informational git inspection runs, but the row stays not_applicable.
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let entries = vec![orphan_entry(
            "ws",
            Some("sess"),
            "/base/worktrees/ws/sess",
            OrphanPathStatus::Dir,
        )];
        let mut inspected = false;
        let orphans = build_orphan_candidates(
            &entries,
            &snap,
            &wc_scan(vec![]),
            &[],
            |root, target, branch| {
                inspected = true;
                assert_eq!(root, "/repo/ws");
                assert_eq!(target, "/base/worktrees/ws/sess");
                assert_eq!(branch, "maestro/ws/sess");
                maestro_shell::WorktreeInspection::WrongBranch
            },
            absent_provenance,
        );
        assert!(inspected, "informational git inspection should have run");
        assert_eq!(orphans.len(), 1);
        let o = &orphans[0];
        assert_eq!(o.record_status, OrphanRecordStatus::SessionRecordMissing);
        assert_eq!(o.git_status, "wrong_branch");
        // Wrong branch -> conflict ownership, but still NOT removable.
        assert_eq!(o.ownership, WorktreeListOwnership::Conflict);
        assert_eq!(o.cleanup_plan_decision, "not_applicable");
        let counts = orphan_counts(&orphans);
        assert_eq!(counts.conflict, 1);
        assert_eq!(counts.no_record, 1);
    }

    #[test]
    fn orphan_row_carries_provenance_without_changing_cleanup() {
        // A loaded-but-mismatching marker surfaces as `mismatch` on the orphan row, yet the row's
        // cleanup decision and ownership are exactly what they'd be with no marker at all.
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let entries = vec![orphan_entry(
            "ws",
            Some("sess"),
            "/base/worktrees/ws/sess",
            OrphanPathStatus::Dir,
        )];
        let build = |prov: fn(&str) -> ProvenanceMarker| {
            build_orphan_candidates(
                &entries,
                &snap,
                &wc_scan(vec![]),
                &[],
                |_, _, _| maestro_shell::WorktreeInspection::WrongBranch,
                prov,
            )
        };

        // A marker whose fields disagree with the row identity -> `mismatch`.
        let mismatching = |_session: &str| {
            ProvenanceMarker::Loaded(maestro_shell::WorktreeProvenance {
                workspace_id: "OTHER".to_string(),
                session_id: "OTHER".to_string(),
                repo_root: "/other".to_string(),
                target_path: "/other".to_string(),
                branch: "maestro/OTHER/OTHER".to_string(),
                created_at_ms: 1,
            })
        };

        let with_marker = build(mismatching);
        let without_marker = build(absent_provenance);
        assert_eq!(with_marker.len(), 1);
        assert_eq!(without_marker.len(), 1);
        let m = &with_marker[0];
        let n = &without_marker[0];

        // Provenance differs (the whole point), but nothing cleanup-relevant does.
        assert_eq!(m.provenance, WorktreeProvenanceStatus::Mismatch);
        assert_eq!(n.provenance, WorktreeProvenanceStatus::Unrecorded);
        assert_eq!(m.ownership, n.ownership);
        assert_eq!(m.git_status, n.git_status);
        assert_eq!(m.git_reason, n.git_reason);
        assert_eq!(m.cleanup_plan_decision, "not_applicable");
        assert_eq!(m.cleanup_plan_decision, n.cleanup_plan_decision);
        assert_eq!(m.cleanup_plan_reason, n.cleanup_plan_reason);
    }

    #[test]
    fn orphan_recordless_verified_branch_never_verified_maestro() {
        // Even if git VERIFIES the branch, a recordless orphan must never claim Maestro ownership.
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let entries = vec![orphan_entry(
            "ws",
            Some("sess"),
            "/base/worktrees/ws/sess",
            OrphanPathStatus::Dir,
        )];
        let orphans = build_orphan_candidates(
            &entries,
            &snap,
            &wc_scan(vec![]),
            &[],
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
        );
        assert_eq!(orphans.len(), 1);
        // Verified is folded down to Unknown for a recordless path.
        assert_eq!(orphans[0].ownership, WorktreeListOwnership::Unknown);
        assert_ne!(
            orphans[0].ownership,
            WorktreeListOwnership::VerifiedMaestroWorktree
        );
        assert_eq!(orphans[0].cleanup_plan_decision, "not_applicable");
    }

    #[test]
    fn orphan_already_record_backed_target_not_duplicated() {
        let paths = maestro_shell::AppPaths::with_base("/base");
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let target = wc_target(&paths, "ws", "sess");
        let scan = wc_scan(vec![wc_session_for(
            "ws",
            "sess",
            &target,
            maestro_shell::SessionStatus::Exited,
        )]);
        // Build the real record-backed candidate set first; the target IS a candidate.
        let backed = build_worktree_list_all(
            "/base",
            &snap,
            &scan,
            &paths,
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
            0,
        );
        assert_eq!(backed.candidates.len(), 1);
        // The same path appears in the fs walk; it must be suppressed (no duplicate orphan row).
        let entries = vec![orphan_entry(
            "ws",
            Some("sess"),
            &target,
            OrphanPathStatus::Dir,
        )];
        let orphans = build_orphan_candidates(
            &entries,
            &snap,
            &scan,
            &backed.candidates,
            never_inspect,
            absent_provenance,
        );
        assert!(
            orphans.is_empty(),
            "record-backed target must not be duplicated as an orphan row"
        );
    }

    #[test]
    fn orphan_no_row_is_ever_removable() {
        // A mix of every classification path: none may ever be cleanup_plan_decision:"removable".
        let snap = wc_snapshot(vec![wc_workspace(
            "ws",
            maestro_shell::WorkspacePolicy::Worktree,
            wc_consent(true),
        )]);
        let entries = vec![
            orphan_entry(
                "../bad",
                None,
                "/base/worktrees/../bad",
                OrphanPathStatus::Dir,
            ),
            orphan_entry(
                "f.txt",
                None,
                "/base/worktrees/f.txt",
                OrphanPathStatus::File,
            ),
            orphan_entry(
                "ws",
                Some("link"),
                "/base/worktrees/ws/link",
                OrphanPathStatus::Symlink,
            ),
            orphan_entry(
                "ghost",
                Some("sess"),
                "/base/worktrees/ghost/sess",
                OrphanPathStatus::Dir,
            ),
            orphan_entry(
                "ws",
                Some("sess"),
                "/base/worktrees/ws/sess",
                OrphanPathStatus::Dir,
            ),
        ];
        let orphans = build_orphan_candidates(
            &entries,
            &snap,
            &wc_scan(vec![]),
            &[],
            // The only inspect-eligible row is ws/sess (loaded workspace, missing session).
            |_, _, _| maestro_shell::WorktreeInspection::Verified,
            absent_provenance,
        );
        assert_eq!(orphans.len(), 5);
        for o in &orphans {
            assert_eq!(
                o.cleanup_plan_decision, "not_applicable",
                "orphan row {} must never be removable",
                o.path
            );
            assert_ne!(o.cleanup_plan_decision, "removable");
        }
    }
}
