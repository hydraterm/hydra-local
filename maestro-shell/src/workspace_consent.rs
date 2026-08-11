//! Workspace consent gates for repo-affecting policies.
//!
//! `Worktree` (`git worktree add/remove` mutates the source repo's git administrative state) and
//! `RepoWrite` (direct writes into the live checkout) are deliberate, consent-gated operations
//! This module makes that consent model EXECUTABLE: typed consent kinds, pure
//! policy->consent mapping and checking over a [`Workspace`] record, and a store-backed grant
//! that flips exactly one flag on the durable record.
//!
//! It runs NO git and creates NO worktree/repo state — it only reads/writes the workspace
//! record through the shared store. It grants no execution authority by itself; callers must
//! perform a separate consent check before any `Worktree` or `RepoWrite` operation.

use std::path::PathBuf;

use crate::paths::{AppPaths, RecordKind};
use crate::policy::WorkspacePolicy;
use crate::records::Workspace;
use crate::store::{load_one, write_record, LoadOutcome, StoreError};

/// The consent a repo-affecting operation requires. One kind per [`WorkspaceConsent`]
/// (crate::records::WorkspaceConsent) flag, so a grant can never flip more than it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceConsentKind {
    /// Consent to `git worktree add/remove` (mutates `<root>/.git/worktrees/...`).
    WorktreeCreate,
    /// Consent to direct writes into the live checkout.
    RepoWrite,
}

impl std::fmt::Display for WorkspaceConsentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkspaceConsentKind::WorktreeCreate => write!(f, "worktree_create"),
            WorkspaceConsentKind::RepoWrite => write!(f, "repo_write"),
        }
    }
}

/// Why a consent check or grant failed.
#[derive(Debug)]
pub enum WorkspaceConsentError {
    /// The workspace has not granted `kind`; the gated operation must not proceed.
    MissingConsent {
        workspace_id: String,
        kind: WorkspaceConsentKind,
    },
    /// No workspace record exists under this id.
    WorkspaceNotFound { workspace_id: String },
    /// The workspace record was written by a NEWER Maestro. It is left exactly as on disk —
    /// rewriting it could drop fields this build does not model — so consent cannot be granted
    /// from this build.
    FutureVersion { path: PathBuf, ours: u32, got: u32 },
    /// The workspace record was corrupt; the store quarantined it (moved to `corrupt/`,
    /// surfaced here). Nothing was rewritten.
    Corrupt {
        original: PathBuf,
        moved_to: PathBuf,
        reason: String,
    },
    /// Underlying store failure (io / envelope / id).
    Store(StoreError),
}

impl std::fmt::Display for WorkspaceConsentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkspaceConsentError::MissingConsent { workspace_id, kind } => write!(
                f,
                "workspace {workspace_id:?} has not granted {kind} consent"
            ),
            WorkspaceConsentError::WorkspaceNotFound { workspace_id } => {
                write!(f, "no workspace record found for id {workspace_id:?}")
            }
            WorkspaceConsentError::FutureVersion { path, ours, got } => write!(
                f,
                "workspace record {} was written by a newer Maestro (schema version {got} > {ours}); \
                 left in place, consent not granted",
                path.display()
            ),
            WorkspaceConsentError::Corrupt {
                original,
                moved_to,
                reason,
            } => write!(
                f,
                "workspace record {} was corrupt ({reason}); quarantined at {}",
                original.display(),
                moved_to.display()
            ),
            WorkspaceConsentError::Store(e) => write!(f, "workspace consent store error: {e}"),
        }
    }
}

impl std::error::Error for WorkspaceConsentError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WorkspaceConsentError::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreError> for WorkspaceConsentError {
    fn from(e: StoreError) -> Self {
        WorkspaceConsentError::Store(e)
    }
}

/// Which consent `policy` requires. PURE.
///
/// - `ScratchCwd` -> `None` (a shell-owned dir under app-support needs no consent)
/// - `Worktree`   -> `WorktreeCreate`
/// - `RepoWrite`  -> `RepoWrite`
pub fn required_consent_for_policy(policy: WorkspacePolicy) -> Option<WorkspaceConsentKind> {
    match policy {
        WorkspacePolicy::ScratchCwd => None,
        WorkspacePolicy::Worktree => Some(WorkspaceConsentKind::WorktreeCreate),
        WorkspacePolicy::RepoWrite => Some(WorkspaceConsentKind::RepoWrite),
    }
}

/// Has `workspace` granted `kind`? PURE.
pub fn has_consent(workspace: &Workspace, kind: WorkspaceConsentKind) -> bool {
    match kind {
        WorkspaceConsentKind::WorktreeCreate => workspace.consent.worktree_create,
        WorkspaceConsentKind::RepoWrite => workspace.consent.repo_write,
    }
}

/// Require that `workspace` granted `kind`, or fail with [`MissingConsent`]
/// (WorkspaceConsentError::MissingConsent). PURE.
pub fn require_consent(
    workspace: &Workspace,
    kind: WorkspaceConsentKind,
) -> Result<(), WorkspaceConsentError> {
    if has_consent(workspace, kind) {
        Ok(())
    } else {
        Err(WorkspaceConsentError::MissingConsent {
            workspace_id: workspace.workspace_id.clone(),
            kind,
        })
    }
}

/// Check the consent gate for running `policy` in `workspace`: maps the policy to its required
/// consent (if any) and requires it. `ScratchCwd` always passes. PURE.
pub fn check_policy_consent(
    workspace: &Workspace,
    policy: WorkspacePolicy,
) -> Result<(), WorkspaceConsentError> {
    match required_consent_for_policy(policy) {
        None => Ok(()),
        Some(kind) => require_consent(workspace, kind),
    }
}

/// Grant `kind` on the durable workspace record `workspace_id`: load it from the shared store,
/// set ONLY the named consent flag plus `granted_at_ms = now_ms`, and atomically write it back.
/// Returns the updated record.
///
/// Record-safety contract (mirrors the store):
/// - a missing record is a typed [`WorkspaceNotFound`](WorkspaceConsentError::WorkspaceNotFound),
///   never an implicit create — consent can only be granted on a workspace that exists;
/// - a FUTURE-VERSION record is NEVER rewritten (typed
///   [`FutureVersion`](WorkspaceConsentError::FutureVersion); the file is left byte-identical);
/// - a CORRUPT record was already quarantined by the load and is surfaced as
///   [`Corrupt`](WorkspaceConsentError::Corrupt); nothing is rewritten.
pub fn grant_consent(
    paths: &AppPaths,
    workspace_id: &str,
    kind: WorkspaceConsentKind,
    now_ms: u64,
) -> Result<Workspace, WorkspaceConsentError> {
    let outcome = load_one::<Workspace>(paths, RecordKind::Workspace, workspace_id)?;
    let mut workspace = match outcome {
        None => {
            return Err(WorkspaceConsentError::WorkspaceNotFound {
                workspace_id: workspace_id.to_string(),
            })
        }
        Some(LoadOutcome::Loaded(ws)) => ws,
        Some(LoadOutcome::FutureVersion { path, ours, got }) => {
            return Err(WorkspaceConsentError::FutureVersion { path, ours, got })
        }
        Some(LoadOutcome::Quarantined {
            original,
            moved_to,
            reason,
        }) => {
            return Err(WorkspaceConsentError::Corrupt {
                original,
                moved_to,
                reason,
            })
        }
    };

    match kind {
        WorkspaceConsentKind::WorktreeCreate => workspace.consent.worktree_create = true,
        WorkspaceConsentKind::RepoWrite => workspace.consent.repo_write = true,
    }
    workspace.consent.granted_at_ms = Some(now_ms);

    write_record(
        paths,
        RecordKind::Workspace,
        workspace_id,
        now_ms,
        &workspace,
    )?;
    Ok(workspace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::WorkspaceConsent;
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, AppPaths) {
        let tmp = TempDir::new().expect("temp dir");
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        // The relational store enforces workspaces.project_id → projects (FK). Every Workspace these tests store uses
        // project_id "proj-1"; seed that parent so a write doesn't violate the constraint (production creates the
        // project before the workspace).
        seed_project(&paths, "proj-1");
        (tmp, paths)
    }

    /// Persist a minimal parent Project so an FK-bearing Workspace can reference it.
    fn seed_project(paths: &AppPaths, id: &str) {
        crate::project::ProjectService::new(paths)
            .create(id, id, "/r", crate::project::NewProject::default(), 1)
            .ok();
    }

    fn workspace(id: &str) -> Workspace {
        Workspace {
            workspace_id: id.into(),
            project_id: "proj-1".into(),
            root: "/home/u/myrepo".into(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent {
                worktree_create: false,
                repo_write: false,
                granted_at_ms: None,
            },
        }
    }

    fn store_workspace(paths: &AppPaths, ws: &Workspace) {
        write_record(paths, RecordKind::Workspace, &ws.workspace_id, 1, ws).unwrap();
    }

    // ---- pure mapping + checking ----

    #[test]
    fn scratch_cwd_requires_no_consent() {
        assert_eq!(
            required_consent_for_policy(WorkspacePolicy::ScratchCwd),
            None
        );
    }

    #[test]
    fn worktree_maps_to_worktree_create() {
        assert_eq!(
            required_consent_for_policy(WorkspacePolicy::Worktree),
            Some(WorkspaceConsentKind::WorktreeCreate)
        );
    }

    #[test]
    fn repo_write_maps_to_repo_write() {
        assert_eq!(
            required_consent_for_policy(WorkspacePolicy::RepoWrite),
            Some(WorkspaceConsentKind::RepoWrite)
        );
    }

    #[test]
    fn require_consent_passes_and_fails_for_all_three_policies() {
        let mut ws = workspace("ws1");

        // Ungranted: ScratchCwd passes, the repo-affecting two fail with MissingConsent.
        assert!(check_policy_consent(&ws, WorkspacePolicy::ScratchCwd).is_ok());
        for policy in [WorkspacePolicy::Worktree, WorkspacePolicy::RepoWrite] {
            let r = check_policy_consent(&ws, policy);
            assert!(
                matches!(r, Err(WorkspaceConsentError::MissingConsent { .. })),
                "{policy:?} must fail ungranted, got {r:?}"
            );
        }

        // Granting one does not satisfy the other.
        ws.consent.worktree_create = true;
        assert!(check_policy_consent(&ws, WorkspacePolicy::Worktree).is_ok());
        assert!(matches!(
            check_policy_consent(&ws, WorkspacePolicy::RepoWrite),
            Err(WorkspaceConsentError::MissingConsent {
                kind: WorkspaceConsentKind::RepoWrite,
                ..
            })
        ));

        ws.consent.repo_write = true;
        assert!(check_policy_consent(&ws, WorkspacePolicy::RepoWrite).is_ok());
    }

    #[test]
    fn has_consent_reads_exactly_the_named_flag() {
        let mut ws = workspace("ws1");
        assert!(!has_consent(&ws, WorkspaceConsentKind::WorktreeCreate));
        assert!(!has_consent(&ws, WorkspaceConsentKind::RepoWrite));
        ws.consent.repo_write = true;
        assert!(!has_consent(&ws, WorkspaceConsentKind::WorktreeCreate));
        assert!(has_consent(&ws, WorkspaceConsentKind::RepoWrite));
    }

    // ---- store-backed grant ----

    #[test]
    fn granting_worktree_create_sets_only_that_flag_and_timestamp() {
        let (_tmp, paths) = temp_paths();
        store_workspace(&paths, &workspace("ws1"));

        let updated =
            grant_consent(&paths, "ws1", WorkspaceConsentKind::WorktreeCreate, 42).unwrap();
        assert!(updated.consent.worktree_create);
        assert!(!updated.consent.repo_write, "repo_write must stay false");
        assert_eq!(updated.consent.granted_at_ms, Some(42));

        // The durable record agrees with the returned value.
        let on_disk = match load_one::<Workspace>(&paths, RecordKind::Workspace, "ws1") {
            Ok(Some(LoadOutcome::Loaded(ws))) => ws,
            other => panic!("expected Loaded, got {other:?}"),
        };
        assert_eq!(on_disk, updated);
    }

    #[test]
    fn granting_repo_write_sets_only_that_flag_and_timestamp() {
        let (_tmp, paths) = temp_paths();
        store_workspace(&paths, &workspace("ws1"));

        let updated = grant_consent(&paths, "ws1", WorkspaceConsentKind::RepoWrite, 77).unwrap();
        assert!(updated.consent.repo_write);
        assert!(
            !updated.consent.worktree_create,
            "worktree_create must stay false"
        );
        assert_eq!(updated.consent.granted_at_ms, Some(77));
    }

    #[test]
    fn granting_preserves_unrelated_workspace_fields() {
        let (_tmp, paths) = temp_paths();
        let original = workspace("ws1");
        store_workspace(&paths, &original);

        let updated =
            grant_consent(&paths, "ws1", WorkspaceConsentKind::WorktreeCreate, 42).unwrap();
        assert_eq!(updated.workspace_id, original.workspace_id);
        assert_eq!(updated.project_id, original.project_id);
        assert_eq!(updated.root, original.root);
        assert_eq!(updated.policy, original.policy);
    }

    #[test]
    fn missing_workspace_is_a_typed_error() {
        let (_tmp, paths) = temp_paths();
        let r = grant_consent(&paths, "absent", WorkspaceConsentKind::RepoWrite, 1);
        assert!(
            matches!(
                r,
                Err(WorkspaceConsentError::WorkspaceNotFound { ref workspace_id })
                    if workspace_id == "absent"
            ),
            "missing workspace must be WorkspaceNotFound, got {r:?}"
        );
    }

    // NOTE: the old `future_version_workspace_record_is_not_rewritten` and
    // `corrupt_workspace_record_is_quarantined_and_surfaced` tests hand-wrote a raw envelope FILE (a future-version
    // envelope / invalid JSON) and asserted grant_consent surfaced FutureVersion / Corrupt and left the file
    // byte-identical or moved it into `corrupt/`. The SQLite store has no per-record files: future-version is now a
    // DB-LEVEL guard (see store::future_version_db_is_refused_on_open) and a row that won't deserialize surfaces as
    // Quarantined with no file to move (see store::row_that_wont_deserialize_is_quarantined_and_excluded). Both tests
    // were removed because the per-record `LoadOutcome::FutureVersion` / file-quarantine mechanism they exercised is gone.
}
