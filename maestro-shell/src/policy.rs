//! PURE workspace-policy resolution: given a policy and identifiers, compute the `cwd` a
//! session would run in. No directory creation, no git, no daemon/socket/PTY — this is a
//! total function from inputs to a path, unit-testable in isolation. Side-effecting execution
//! (creating the scratch dir, running `git worktree add`, obtaining consent) belongs to the
//! execution and consent modules.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::ids::{validate_id, IdError};
use crate::paths::AppPaths;

/// The three isolation policies. Defaults choose the most isolated policy that fits; `RepoWrite`
/// is never a default. `ScratchCwd` and `Worktree` keep the session OUT of the user's checkout;
/// `RepoWrite` runs in it and requires explicit consent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspacePolicy {
    /// Session cwd is a shell-owned scratch dir under app-support, outside any repo.
    ScratchCwd,
    /// Session cwd is an isolated git worktree under app-support (edits confined to a branch).
    Worktree,
    /// Session cwd is the repo root itself (direct writes to the live checkout).
    RepoWrite,
}

/// The resolved cwd plus which policy produced it, so callers can assert the isolation
/// guarantee (e.g. "this path is under app-support, not the repo") at the type level.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedCwd {
    pub policy: WorkspacePolicy,
    pub cwd: PathBuf,
}

/// Compute the cwd for a session under `policy`. PURE: no IO, no git, no mkdir.
///
/// - `ScratchCwd` -> `<app-support>/scratch/<session_id>/`
/// - `Worktree`   -> `<app-support>/worktrees/<workspace_id>/<session_id>/`
/// - `RepoWrite`  -> `repo_root` verbatim
///
/// The scratch and worktree paths live under app-support BY DESIGN, never beside or inside the
/// repo, so neither can place Maestro state in a repo root. Only `RepoWrite` yields the repo
/// root, and only because the user explicitly asked the agent to work in their tree (the agent
/// may write there; Maestro itself still writes no metadata into the repo).
///
/// The `workspace_id`/`session_id` that become path components under app-support are VALIDATED
/// first (see `ids::validate_id`); a traversing id like `../x` is rejected with `IdError`
/// rather than escaping the scratch/worktree directory. `repo_root` is a full trusted path (the
/// project root), not an id, so it is used verbatim and only matters under `RepoWrite`. Only the
/// ids a given policy actually places in the path are validated.
pub fn resolved_cwd(
    paths: &AppPaths,
    policy: WorkspacePolicy,
    workspace_id: &str,
    session_id: &str,
    repo_root: &str,
) -> Result<ResolvedCwd, IdError> {
    let cwd = match policy {
        WorkspacePolicy::ScratchCwd => {
            let session_id = validate_id(session_id)?;
            paths.scratch_base().join(session_id)
        }
        WorkspacePolicy::Worktree => {
            let workspace_id = validate_id(workspace_id)?;
            let session_id = validate_id(session_id)?;
            paths.worktree_base().join(workspace_id).join(session_id)
        }
        WorkspacePolicy::RepoWrite => PathBuf::from(repo_root),
    };
    Ok(ResolvedCwd { policy, cwd })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> AppPaths {
        AppPaths::with_base("/base/Maestro")
    }

    #[test]
    fn scratch_resolves_under_app_support_not_repo() {
        let r = resolved_cwd(
            &paths(),
            WorkspacePolicy::ScratchCwd,
            "ws1",
            "sess1",
            "/home/u/myrepo",
        )
        .unwrap();
        assert_eq!(r.cwd, PathBuf::from("/base/Maestro/scratch/sess1"));
        assert!(r.cwd.starts_with("/base/Maestro/scratch"));
        // The repo root never appears as a prefix of a scratch cwd.
        assert!(!r.cwd.starts_with("/home/u/myrepo"));
    }

    #[test]
    fn worktree_resolves_under_app_support_not_repo() {
        let r = resolved_cwd(
            &paths(),
            WorkspacePolicy::Worktree,
            "ws1",
            "sess1",
            "/home/u/myrepo",
        )
        .unwrap();
        assert_eq!(r.cwd, PathBuf::from("/base/Maestro/worktrees/ws1/sess1"));
        assert!(r.cwd.starts_with("/base/Maestro/worktrees"));
        assert!(!r.cwd.starts_with("/home/u/myrepo"));
    }

    #[test]
    fn repo_write_resolves_to_repo_root() {
        let r = resolved_cwd(
            &paths(),
            WorkspacePolicy::RepoWrite,
            "ws1",
            "sess1",
            "/home/u/myrepo",
        )
        .unwrap();
        assert_eq!(r.cwd, PathBuf::from("/home/u/myrepo"));
        // RepoWrite is the ONLY policy that returns the repo root, and it never lands under
        // app-support.
        assert!(!r.cwd.starts_with("/base/Maestro"));
    }

    #[test]
    fn scratch_rejects_traversing_session_id_and_cannot_escape() {
        // A traversing session id must be rejected, never resolved into a path that climbs out
        // of the scratch directory.
        for bad in ["../escape", "..", "a/b", "/abs", "a/../b"] {
            let r = resolved_cwd(
                &paths(),
                WorkspacePolicy::ScratchCwd,
                "ws1",
                bad,
                "/home/u/r",
            );
            assert!(
                r.is_err(),
                "scratch session id {bad:?} must be rejected, got {r:?}"
            );
        }
    }

    #[test]
    fn worktree_rejects_traversing_ids_and_cannot_escape() {
        // Either a traversing workspace id or session id must be rejected.
        let bad_ws = resolved_cwd(
            &paths(),
            WorkspacePolicy::Worktree,
            "../../etc",
            "sess1",
            "/home/u/r",
        );
        assert!(bad_ws.is_err(), "traversing workspace id must be rejected");

        let bad_sess = resolved_cwd(
            &paths(),
            WorkspacePolicy::Worktree,
            "ws1",
            "../../etc",
            "/home/u/r",
        );
        assert!(bad_sess.is_err(), "traversing session id must be rejected");
    }

    #[test]
    fn policy_round_trips_through_json() {
        for p in [
            WorkspacePolicy::ScratchCwd,
            WorkspacePolicy::Worktree,
            WorkspacePolicy::RepoWrite,
        ] {
            let s = serde_json::to_string(&p).unwrap();
            let back: WorkspacePolicy = serde_json::from_str(&s).unwrap();
            assert_eq!(p, back);
        }
    }
}
