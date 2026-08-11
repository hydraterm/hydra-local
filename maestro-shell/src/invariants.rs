//! Executable invariant oracle over the shared store.
//!
//! One function, [`check_store_invariants`], that any test (or diagnostic) can call after ANY
//! action to assert the two-writer store is coherent. This is the oracle the interaction-matrix
//! tests assert after every step, and the definition of "healthy" that
//! [`crate::ownership_repair`] must restore.
//!
//! Coverage map for the shared-store consistency contract:
//! - **Attributed writes** — write-trace attribution is asserted by the write_trace tests and
//!   the matrix tests directly (the ring is process-local state, not store state).
//! - **Cross-process convergence and delivery** — timing and transport behavior is outside this
//!   store oracle and is tested at the composition boundary.
//! - **Two-writer integrity** — THIS module: referential integrity plus window-ownership
//!   coherence between the three ownership signals (the `windows.project_id` FK, the project's
//!   `window_order`, and the snapshot's tab-derived association).
//!
//! Checks:
//! 1. `fk`                      — `PRAGMA foreign_key_check` is empty (no dangling references).
//! 2. `window-owner-stamped`    — every window the snapshot places under project P has FK = P.
//! 3. `window-in-order`         — every window the snapshot places under P is in P's window_order.
//! 4. `owned-but-unassigned`    — a window with a valid FK owner must not surface as unassigned
//!    (the FK is authoritative ownership intent; the repair adopts it).
//!
//! Stale `window_order` entries (ids with no window row) are TOLERATED by design — the snapshot
//! ignores them and `reorder_windows` documents that contract — so they are not a violation.

use std::collections::{HashMap, HashSet};

use crate::dashboard_snapshot::DashboardSnapshotService;
use crate::paths::AppPaths;
use crate::project::ProjectService;
use crate::store;

/// One violated invariant: which check + a content-blind detail (ids only, never values).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvariantViolation {
    pub invariant: &'static str,
    pub detail: String,
}

/// Run every store invariant; empty vec = healthy. Read-only.
pub fn check_store_invariants(paths: &AppPaths) -> Result<Vec<InvariantViolation>, String> {
    let mut violations = Vec::new();

    // 1) Referential integrity, straight from SQLite (covers workspaces/sessions/tasks/tabs too).
    {
        let arc = crate::db::conn_for(paths.base()).map_err(|e| format!("db open: {e:?}"))?;
        let conn = arc.lock().map_err(|_| "db lock poisoned".to_string())?;
        let mut stmt = conn
            .prepare("PRAGMA foreign_key_check")
            .map_err(|e| e.to_string())?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(2)?)))
            .map_err(|e| e.to_string())?;
        for row in rows {
            let (table, parent) = row.map_err(|e| e.to_string())?;
            violations.push(InvariantViolation {
                invariant: "fk",
                detail: format!("{table} row references missing {parent}"),
            });
        }
    }

    let snapshot = DashboardSnapshotService::new(paths)
        .snapshot(None)
        .map_err(|e| format!("snapshot: {e:?}"))?;
    let owners: HashMap<String, Option<String>> = store::window_project_owners(paths)
        .map_err(|e| format!("owners: {e:?}"))?
        .into_iter()
        .collect();
    let projects = ProjectService::new(paths)
        .list()
        .map_err(|e| format!("projects: {e:?}"))?;
    let order_by_project: HashMap<&str, &Vec<String>> = projects
        .iter()
        .map(|p| (p.project_id.as_str(), &p.window_order))
        .collect();
    let known_projects: HashSet<&str> = projects.iter().map(|p| p.project_id.as_str()).collect();

    // 2 + 3) Ownership coherence for every snapshot-derived (project, window) pair.
    for project in &snapshot.projects {
        for window in &project.windows {
            let stored = owners.get(&window.window_id).cloned().flatten();
            if stored.as_deref() != Some(project.project_id.as_str()) {
                violations.push(InvariantViolation {
                    invariant: "window-owner-stamped",
                    detail: format!(
                        "window {} derives to {} but FK is {:?}",
                        window.window_id, project.project_id, stored
                    ),
                });
            }
            let in_order = order_by_project
                .get(project.project_id.as_str())
                .is_some_and(|order| order.contains(&window.window_id));
            if !in_order {
                violations.push(InvariantViolation {
                    invariant: "window-in-order",
                    detail: format!(
                        "window {} under {} missing from window_order",
                        window.window_id, project.project_id
                    ),
                });
            }
        }
    }

    // 4) A window whose FK names a live project must not be floating in unassigned.
    for window in &snapshot.unassigned_windows {
        if let Some(Some(pid)) = owners.get(&window.window_id) {
            if known_projects.contains(pid.as_str()) {
                violations.push(InvariantViolation {
                    invariant: "owned-but-unassigned",
                    detail: format!(
                        "window {} has FK owner {pid} but is unassigned",
                        window.window_id
                    ),
                });
            }
        }
    }

    Ok(violations)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The oracle's own behavior is exercised end-to-end by the ownership_repair tests and the
    // interaction-matrix tests (matrix_tests.rs); here we pin only the empty-store baseline.
    #[test]
    fn empty_store_is_healthy() {
        let tmp = tempfile::TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        assert_eq!(check_store_invariants(&paths).unwrap(), Vec::new());
    }
}
