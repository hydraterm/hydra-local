//! Two-writer integrity repair: re-derive and stamp missing window→project ownership (invariant I5).
//!
//! `windows.project_id` is the cascade/ownership FK, but it is stamped SEPARATELY from the window row
//! itself: `WindowLayoutService::create_empty` writes the row, and only a later
//! `ensure_window_in_project_order` / `set_window_project` stamps the owner. A crash or error between
//! the two — in any local writer process — leaves a window with a NULL owner and
//! possibly missing from `project.window_order`: it renders under the wrong place (or as unassigned),
//! and a project delete no longer cascades to it. This is the corruption class behind the
//! "window row lost / main window NULL project_id" incident.
//!
//! [`repair_window_ownership`] fixes what is PROVABLE and touches nothing else:
//! - The owner is re-derived by the dashboard snapshot itself (tab sessions → owning task's project,
//!   else session.workspace → `workspace.project_id`, else a project whose `window_order` already
//!   lists the window) — ONE derivation algorithm, reused, not re-implemented.
//! - A derivable window gets `windows.project_id` stamped and is appended to the owner's
//!   `window_order` when missing.
//! - A window with NO derivable owner is LEFT ALONE — it stays visible in `unassigned_windows`.
//!   Repair never deletes, never guesses.
//!
//! Both mutations ride the normal traced paths (`set_window_project` → "WindowOwner" trace,
//! `reorder_windows` → write_record), so a repair is itself attributable in db-write.jsonl. Callers
//! should wrap the call in a mutation context (e.g. "local:startupOwnershipRepair").

use std::collections::{HashMap, HashSet};

use crate::dashboard_snapshot::DashboardSnapshotService;
use crate::paths::AppPaths;
use crate::project::ProjectService;
use crate::store;

/// What a repair pass did — empty vecs = healthy store, nothing written.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OwnershipRepairReport {
    /// Windows whose `windows.project_id` was stamped (window_id, project_id).
    pub stamped: Vec<(String, String)>,
    /// Windows appended to their owner's `project.window_order` (window_id, project_id).
    pub ordered: Vec<(String, String)>,
    /// Windows with no derivable owner — left untouched, surfaced for visibility.
    pub unassigned: Vec<String>,
}

impl OwnershipRepairReport {
    pub fn changed(&self) -> bool {
        !self.stamped.is_empty() || !self.ordered.is_empty()
    }
}

/// Run one repair pass. Read-mostly: writes happen only for windows whose derived owner disagrees
/// with the stored FK/order state. Safe to run at every startup (idempotent — a healthy store yields
/// an all-empty report and zero writes).
pub fn repair_window_ownership(
    paths: &AppPaths,
    now_ms: u64,
) -> Result<OwnershipRepairReport, String> {
    let snapshot = DashboardSnapshotService::new(paths)
        .snapshot(None)
        .map_err(|e| format!("snapshot failed: {e:?}"))?;
    let owners: HashMap<String, Option<String>> = store::window_project_owners(paths)
        .map_err(|e| format!("owner scan failed: {e:?}"))?
        .into_iter()
        .collect();
    let known_projects: HashSet<&str> = snapshot
        .projects
        .iter()
        .map(|p| p.project_id.as_str())
        .collect();

    let mut report = OwnershipRepairReport::default();
    let projects = ProjectService::new(paths);

    for project in &snapshot.projects {
        if project.windows.is_empty() {
            continue;
        }
        // The snapshot's ProjectSnapshot carries derived windows but not the record's window_order —
        // load the record once per project that actually has windows to check/repair the order.
        let mut order: Vec<String> = projects
            .load(&project.project_id)
            .map_err(|e| format!("load {} failed: {e:?}", project.project_id))?
            .map(|p| p.window_order)
            .unwrap_or_default();
        let mut order_changed = false;
        for window in &project.windows {
            // 1) FK stamp: missing, or dangling (points at a project the snapshot no longer knows).
            let stored = owners.get(&window.window_id).cloned().flatten();
            let fk_ok = stored
                .as_deref()
                .is_some_and(|pid| pid == project.project_id && known_projects.contains(pid));
            if !fk_ok {
                store::set_window_project(paths, &window.window_id, &project.project_id)
                    .map_err(|e| format!("stamp {} failed: {e:?}", window.window_id))?;
                report
                    .stamped
                    .push((window.window_id.clone(), project.project_id.clone()));
            }
            // 2) window_order: the sidebar's ordering signal — append when missing.
            if !order.contains(&window.window_id) {
                order.push(window.window_id.clone());
                order_changed = true;
                report
                    .ordered
                    .push((window.window_id.clone(), project.project_id.clone()));
            }
        }
        if order_changed {
            projects
                .reorder_windows(&project.project_id, &order, now_ms)
                .map_err(|e| format!("order {} failed: {e:?}", project.project_id))?;
        }
    }
    // Adopt FK-owned strays: a window whose FK names a LIVE project but which the snapshot left
    // unassigned (no deriving tabs, missing from window_order). The FK is authoritative ownership
    // intent — one of the writers stamped it — so appending it to the owner's window_order makes it
    // visible under its project again instead of floating (invariant "owned-but-unassigned").
    let mut adopt_by_project: HashMap<String, Vec<String>> = HashMap::new();
    for window in &snapshot.unassigned_windows {
        match owners.get(&window.window_id).cloned().flatten() {
            Some(pid) if known_projects.contains(pid.as_str()) => adopt_by_project
                .entry(pid)
                .or_default()
                .push(window.window_id.clone()),
            _ => report.unassigned.push(window.window_id.clone()),
        }
    }
    for (pid, window_ids) in adopt_by_project {
        let mut order = projects
            .load(&pid)
            .map_err(|e| format!("load {pid} failed: {e:?}"))?
            .map(|p| p.window_order)
            .unwrap_or_default();
        for wid in &window_ids {
            if !order.contains(wid) {
                order.push(wid.clone());
            }
            report.ordered.push((wid.clone(), pid.clone()));
        }
        projects
            .reorder_windows(&pid, &order, now_ms)
            .map_err(|e| format!("adopt into {pid} failed: {e:?}"))?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::RecordKind;
    use crate::policy::WorkspacePolicy;
    use crate::records::{
        Attention, AttentionSource, AttentionState, LaunchSpec, Project, SessionKind,
        SessionRecord, SessionStatus, TabRecord, WindowLayout, Workspace, WorkspaceConsent,
    };
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, AppPaths) {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        (tmp, paths)
    }

    fn seed_project(paths: &AppPaths, id: &str, window_order: Vec<String>) {
        let p = Project {
            project_id: id.into(),
            name: id.into(),
            root: format!("/repos/{id}"),
            default_workspace_policy: WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order,
            system: false,
            hidden: false,
        };
        store::write_record(paths, RecordKind::Project, id, 1, &p).unwrap();
    }

    fn seed_workspace_session(paths: &AppPaths, ws: &str, project: &str, session: &str) {
        let w = Workspace {
            workspace_id: ws.into(),
            project_id: project.into(),
            root: "/repos/x".into(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        };
        store::write_record(paths, RecordKind::Workspace, ws, 1, &w).unwrap();
        let s = SessionRecord {
            session_id: session.into(),
            workspace_id: ws.into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "ls-1".into(),
                params: vec![],
            },
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: SessionStatus::Live,
        };
        store::write_record(paths, RecordKind::Session, session, 1, &s).unwrap();
    }

    fn seed_window(paths: &AppPaths, window_id: &str, session_id: &str) {
        let layout = WindowLayout {
            window_id: window_id.into(),
            name: None,
            tabs: vec![TabRecord {
                tab_id: "pane-1".into(),
                session_id: session_id.into(),
                index: 0,
                title: "Pane 1".into(),
                pinned: false,
                attention: AttentionState {
                    attention: Attention::None,
                    unseen: false,
                    since_ms: 1,
                    source: AttentionSource::Process,
                },
                split_from: None,
                pane_rect: None,
                stashed_from: None,
                stashed: false,
            }],
        };
        store::write_record(paths, RecordKind::WindowLayout, window_id, 1, &layout).unwrap();
    }

    fn owner_of(paths: &AppPaths, window_id: &str) -> Option<String> {
        store::window_project_owners(paths)
            .unwrap()
            .into_iter()
            .find(|(wid, _)| wid == window_id)
            .and_then(|(_, pid)| pid)
    }

    #[test]
    fn stamps_null_fk_and_restores_window_order_then_is_idempotent() {
        let (_tmp, paths) = temp_paths();
        // The corruption class: window exists, its tab's session derives the owner, but the FK stamp
        // and window_order entry are BOTH missing (crash between create_empty and the ownership link).
        seed_project(&paths, "p1", vec![]);
        seed_workspace_session(&paths, "ws1", "p1", "s1");
        seed_window(&paths, "w1", "s1");
        assert_eq!(owner_of(&paths, "w1"), None, "pre: FK unstamped");

        let report = repair_window_ownership(&paths, 100).unwrap();
        assert_eq!(report.stamped, vec![("w1".to_string(), "p1".to_string())]);
        assert_eq!(report.ordered, vec![("w1".to_string(), "p1".to_string())]);
        assert!(report.unassigned.is_empty());
        assert_eq!(owner_of(&paths, "w1"), Some("p1".to_string()));
        let project = ProjectService::new(&paths).load("p1").unwrap().unwrap();
        assert_eq!(project.window_order, vec!["w1".to_string()]);

        // Healthy store → second pass writes nothing (safe to run at every startup).
        let again = repair_window_ownership(&paths, 101).unwrap();
        assert!(!again.changed(), "repair must be idempotent: {again:?}");
        // And the invariant oracle agrees: repaired = healthy.
        assert_eq!(
            crate::invariants::check_store_invariants(&paths).unwrap(),
            Vec::new()
        );
    }

    #[test]
    fn adopts_fk_owned_stray_and_restores_the_oracle() {
        let (_tmp, paths) = temp_paths();
        // FK stamped but missing from window_order: the authoritative owner keeps it under p1,
        // while the invariant oracle requires repair to restore the ordering index.
        seed_project(&paths, "p1", vec![]);
        seed_window(&paths, "w1", "ghost-session");
        store::set_window_project(&paths, "w1", "p1").unwrap();
        let pre = crate::invariants::check_store_invariants(&paths).unwrap();
        assert!(
            pre.iter().any(|v| v.invariant == "window-in-order"),
            "oracle must flag the stray: {pre:?}"
        );

        let report = repair_window_ownership(&paths, 100).unwrap();
        assert_eq!(report.ordered, vec![("w1".to_string(), "p1".to_string())]);
        assert!(report.unassigned.is_empty(), "adopted, not floating");
        assert_eq!(
            crate::invariants::check_store_invariants(&paths).unwrap(),
            Vec::new(),
            "repair must restore the oracle to green"
        );
    }

    #[test]
    fn window_order_fallback_stamps_fk_when_tabs_cannot_derive() {
        let (_tmp, paths) = temp_paths();
        // The order-only ownership shape: window listed in project.window_order but FK NULL and its
        // tab's session record is gone — derivation falls back to the order signal.
        seed_project(&paths, "p1", vec!["w1".into()]);
        seed_window(&paths, "w1", "ghost-session");

        let report = repair_window_ownership(&paths, 100).unwrap();
        assert_eq!(report.stamped, vec![("w1".to_string(), "p1".to_string())]);
        assert!(report.ordered.is_empty(), "already in window_order");
        assert_eq!(owner_of(&paths, "w1"), Some("p1".to_string()));
    }

    #[test]
    fn underivable_windows_are_left_untouched_and_surfaced() {
        let (_tmp, paths) = temp_paths();
        seed_project(&paths, "p1", vec![]);
        // No session record, no order entry → nothing provable. Repair must NOT guess or delete.
        seed_window(&paths, "w-orphan", "ghost-session");

        let report = repair_window_ownership(&paths, 100).unwrap();
        assert!(report.stamped.is_empty() && report.ordered.is_empty());
        assert_eq!(report.unassigned, vec!["w-orphan".to_string()]);
        assert_eq!(owner_of(&paths, "w-orphan"), None);
    }
}
