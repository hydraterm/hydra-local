//! A read-only **dashboard snapshot** over the durable records.
//!
//! [`DashboardSnapshotService`] is the single typed Rust model future native app UI can call
//! without any daemon, socket, git, or record mutation. It loads the current-version
//! `Project` / `Workspace` / `AgentTask` / `SessionRecord` / `WindowLayout` records, reuses the
//! [`AgentTaskReconciler`] to derive per-task attention, projects each window's tabs,
//! and groups everything under its owning project — with anything unassociable surfaced (never
//! dropped) in [`DashboardSnapshot::unassigned_windows`].
//!
//! Hard boundaries (mirroring the other read services, all tested):
//!
//! - NO daemon connect, NO `ShellRuntime`/`SessionService::reconcile`/`DaemonClient`/socket. The
//!   only daemon-derived input is an OPTIONAL [`ReconcileReport`] the caller already produced;
//!   we read it but never call anything that would require a connection.
//! - NO writes: no record is rewritten. The only disk mutation is the store's own corrupt-record
//!   quarantine performed while loading, which is REPORTED in [`DashboardSnapshot::quarantined`].
//! - Future-version records are left byte-identical in place and reported per kind in the
//!   `skipped_future_*` buckets.
//! - Everything is sorted deterministically (see [`DashboardSnapshot`]).
//!
//! ## Session-status override (in-memory only)
//!
//! When the caller supplies a [`ReconcileReport`], its per-session status is NEWER than whatever
//! `SessionRecord.status` is on disk (the report came from an actual daemon reconcile). We prefer
//! it when projecting tab rows and recovered sessions — but ONLY in the returned snapshot. No
//! record is written back; the on-disk bytes are untouched.
//!
//! ## Project association (documented choice)
//!
//! `WindowLayout` has no `project_id`, so a window's owning project is derived from its tabs first.
//! A tab associates to a project if its `session_id` is the `current_session_id` of an `AgentTask`
//! (use that task's `project_id`), or — failing that — if its session's `SessionRecord.workspace_id`
//! maps to a `Workspace` whose `project_id` is known. A window is placed under the project of its
//! FIRST associable tab (tabs scanned in `index` order). If no tab associates, the snapshot falls
//! back to the loaded projects' `window_order`; this keeps newly-created or currently-empty windows
//! under their owning project in the local/browser dashboard tree. Only windows with neither a
//! tab-derived project nor a `window_order` owner go to `unassigned_windows`.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::agent_task_reconcile::{
    AgentTaskReconcileReport, AgentTaskReconciler, QuarantinedRecord,
};
use crate::paths::{AppPaths, RecordKind};
use crate::records::{
    AgentTask, AgentTaskState, AttentionState, Project, SessionRecord, SessionStatus, TabRecord,
    WindowLayout, Workspace,
};
use crate::session_service::{ReconcileReport, RecoveredSession};
use crate::store::{self, LoadOutcome, StoreError};

/// One projected tab row: the persisted [`TabRecord`] fields joined with task-reconciliation
/// data (and, when supplied, an overriding reconciled session status). Purely derived.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DashboardTab {
    pub window_id: String,
    pub tab_id: String,
    pub session_id: String,
    pub index: u32,
    pub title: String,
    pub pinned: bool,
    /// The tab's persisted attention roll-up (survives restarts).
    pub attention: AttentionState,
    /// The joined task's id, if a task currently points at this tab's session.
    pub agent_task_id: Option<String>,
    /// The joined task's state, if any.
    pub agent_task_state: Option<AgentTaskState>,
    /// Status used for projection: the supplied [`ReconcileReport`] status when it has a fresher
    /// entry for this `session_id`, else the joined task's recorded session status, else the
    /// on-disk `SessionRecord.status` when one exists. `None` when nothing is known.
    pub session_status: Option<SessionStatus>,
    /// True when a task links here but its current session record is missing on disk.
    pub session_record_missing: bool,
    /// True if the persisted tab attention is unseen-and-non-`None`, OR the joined task report
    /// says the task needs attention.
    pub needs_attention: bool,
    /// True when the tab is STASHED: hidden from the live pane layout but kept as a dim revive
    /// candidate in the dashboard. Mirrors `TabRecord.stashed`.
    pub stashed: bool,
    /// The tab's session working directory (`SessionRecord.cwd_resolved`), so the UI can default a split's
    /// folder picker to the source pane's/window's folder. Empty when the session record is missing.
    pub cwd: String,
}

/// One window's projected tabs, kept whole so association decisions are transparent.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct DashboardWindow {
    pub window_id: String,
    /// Optional user-facing window title, separate from pane/tab titles.
    #[serde(default)]
    pub name: Option<String>,
    /// Tab rows, sorted by `index` then `tab_id`.
    pub tabs: Vec<DashboardTab>,
}

/// One project with the workspaces, tasks, and windows determinably under it.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct ProjectSnapshot {
    pub project_id: String,
    pub name: String,
    pub root: String,
    /// The project record's default workspace policy, carried through read-only so the picker can
    /// surface it without a second record read.
    pub default_workspace_policy: crate::policy::WorkspacePolicy,
    pub last_active_at_ms: u64,
    /// Project display glyph carried through read-only for dashboard/sidebar branding (`None` = none).
    pub icon: Option<String>,
    /// Project accent color (`#rrggbb`) carried through read-only for the active-project tint
    /// (`None` = neutral chrome).
    pub accent_color: Option<String>,
    /// Default launch settings for new windows/panes in this project.
    pub launch_defaults: Option<crate::records::ProjectLaunchDefaults>,
    /// Extra named folders pinned for window creation.
    pub directories: Vec<crate::records::ProjectDirectory>,
    /// SYSTEM project (built-in "Terminal"): renameable + hideable but never deletable.
    pub system: bool,
    /// User hid this project from the dashboard (still on disk).
    pub hidden: bool,
    /// Workspaces whose `project_id` is this project, sorted by `workspace_id`.
    pub workspaces: Vec<Workspace>,
    /// Tasks whose `project_id` is this project, sorted by `updated_at_ms` desc then `agent_task_id`.
    pub tasks: Vec<AgentTask>,
    /// Windows associated to this project via their tabs, sorted by `window_id`.
    pub windows: Vec<DashboardWindow>,
}

/// The full read-only dashboard view. Deterministic ordering throughout (see field docs).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize)]
pub struct DashboardSnapshot {
    /// Projects sorted by `last_active_at_ms` descending, then `project_id`.
    pub projects: Vec<ProjectSnapshot>,
    /// Windows that could not be associated to any project, sorted by `window_id`. Never dropped.
    pub unassigned_windows: Vec<DashboardWindow>,
    /// Recovered/orphan daemon sessions from a supplied [`ReconcileReport`], sorted by `session_id`.
    pub recovered_sessions: Vec<RecoveredSession>,
    /// Future-version record paths per kind, left byte-identical in place, sorted lexically.
    pub skipped_future_projects: Vec<PathBuf>,
    pub skipped_future_workspaces: Vec<PathBuf>,
    pub skipped_future_windows: Vec<PathBuf>,
    pub skipped_future_tasks: Vec<PathBuf>,
    pub skipped_future_sessions: Vec<PathBuf>,
    /// Corrupt records the store quarantined during the scan, sorted by `original` path.
    pub quarantined: Vec<QuarantinedRecord>,
}

/// Read-only snapshot builder over an injected [`AppPaths`]. Holds no daemon handle, no socket,
/// no services — records (and an optional reconcile report) in, snapshot out.
pub struct DashboardSnapshotService<'a> {
    paths: &'a AppPaths,
}

impl<'a> DashboardSnapshotService<'a> {
    pub fn new(paths: &'a AppPaths) -> Self {
        DashboardSnapshotService { paths }
    }

    /// Build the dashboard snapshot.
    ///
    /// `session_report` is optional:
    /// - `None` — purely local: tab `session_status` falls back to whatever the task report and
    ///   on-disk `SessionRecord.status` say, and `recovered_sessions` is empty.
    /// - `Some(report)` — prefer the report's per-session status when projecting tabs, and include
    ///   its `recovered_sessions`. The override is in-memory only; nothing is written back.
    ///
    /// The only error is the store's own directory IO; per-file problems (future-version, corrupt)
    /// land in the snapshot report instead of aborting the scan.
    pub fn snapshot(
        &self,
        session_report: Option<&ReconcileReport>,
    ) -> Result<DashboardSnapshot, StoreError> {
        let mut snap = DashboardSnapshot::default();

        // --- load each kind, partitioning future/corrupt into the report ---
        let projects: Vec<Project> = self.load_kind(
            RecordKind::Project,
            &mut snap.skipped_future_projects,
            &mut snap.quarantined,
        )?;
        let workspaces: Vec<Workspace> = self.load_kind(
            RecordKind::Workspace,
            &mut snap.skipped_future_workspaces,
            &mut snap.quarantined,
        )?;
        let tasks: Vec<AgentTask> = self.load_kind(
            RecordKind::AgentTask,
            &mut snap.skipped_future_tasks,
            &mut snap.quarantined,
        )?;
        let sessions: Vec<SessionRecord> = self.load_kind(
            RecordKind::Session,
            &mut snap.skipped_future_sessions,
            &mut snap.quarantined,
        )?;
        let windows: Vec<WindowLayout> = self.load_kind(
            RecordKind::WindowLayout,
            &mut snap.skipped_future_windows,
            &mut snap.quarantined,
        )?;

        // Task reconciliation is reused for per-task attention/session linkage. This scan
        // also quarantines corrupt task/session records — but we already loaded (and quarantined)
        // those above, so by now it sees a clean set and reports nothing new. We take its joined
        // task view, not its quarantine buckets, to avoid double-counting.
        let task_report = AgentTaskReconciler::new(self.paths).reconcile()?;

        // --- lookups for association/projection ---
        let workspace_project: HashMap<&str, &str> = workspaces
            .iter()
            .map(|w| (w.workspace_id.as_str(), w.project_id.as_str()))
            .collect();
        let session_by_id: HashMap<&str, &SessionRecord> = sessions
            .iter()
            .map(|s| (s.session_id.as_str(), s))
            .collect();
        // session_id -> project_id via the task that currently owns it.
        let task_session_project: HashMap<&str, &str> = tasks
            .iter()
            .filter_map(|t| {
                t.current_session_id
                    .as_deref()
                    .map(|sid| (sid, t.project_id.as_str()))
            })
            .collect();
        // Fresher reconciled status per session id, if a report was supplied.
        let reconciled_status: HashMap<&str, SessionStatus> = session_report
            .map(|r| {
                r.sessions
                    .iter()
                    .map(|s| (s.session_id.as_str(), s.status))
                    .collect()
            })
            .unwrap_or_default();
        let mut window_project_by_order: HashMap<&str, &str> = HashMap::new();
        for project in &projects {
            for window_id in &project.window_order {
                window_project_by_order
                    .entry(window_id.as_str())
                    .or_insert(project.project_id.as_str());
            }
        }

        // --- project each window's tabs and decide its owning project ---
        let mut windows_by_project: HashMap<String, Vec<DashboardWindow>> = HashMap::new();
        for layout in &windows {
            let dash_window = DashboardWindow {
                window_id: layout.window_id.clone(),
                name: layout.name.clone(),
                tabs: self.project_tabs(
                    &layout.window_id,
                    &layout.tabs,
                    &task_report,
                    &session_by_id,
                    &reconciled_status,
                ),
            };
            match self.window_project(
                &layout.tabs,
                &task_session_project,
                &session_by_id,
                &workspace_project,
                &window_project_by_order,
                &layout.window_id,
            ) {
                Some(project_id) => windows_by_project
                    .entry(project_id)
                    .or_default()
                    .push(dash_window),
                None => snap.unassigned_windows.push(dash_window),
            }
        }

        // --- group workspaces/tasks under projects ---
        let mut workspaces_by_project: HashMap<&str, Vec<Workspace>> = HashMap::new();
        for ws in &workspaces {
            workspaces_by_project
                .entry(ws.project_id.as_str())
                .or_default()
                .push(ws.clone());
        }
        let mut tasks_by_project: HashMap<&str, Vec<AgentTask>> = HashMap::new();
        for t in &tasks {
            tasks_by_project
                .entry(t.project_id.as_str())
                .or_default()
                .push(t.clone());
        }

        for project in &projects {
            let mut workspaces = workspaces_by_project
                .remove(project.project_id.as_str())
                .unwrap_or_default();
            workspaces.sort_by(|a, b| a.workspace_id.cmp(&b.workspace_id));

            let mut tasks = tasks_by_project
                .remove(project.project_id.as_str())
                .unwrap_or_default();
            tasks.sort_by(|a, b| {
                b.updated_at_ms
                    .cmp(&a.updated_at_ms)
                    .then_with(|| a.agent_task_id.cmp(&b.agent_task_id))
            });

            let mut project_windows = windows_by_project
                .remove(&project.project_id)
                .unwrap_or_default();
            let window_order: HashMap<&str, usize> = project
                .window_order
                .iter()
                .enumerate()
                .map(|(idx, id)| (id.as_str(), idx))
                .collect();
            project_windows.sort_by(|a, b| {
                match (
                    window_order.get(a.window_id.as_str()),
                    window_order.get(b.window_id.as_str()),
                ) {
                    (Some(a_idx), Some(b_idx)) => {
                        a_idx.cmp(b_idx).then_with(|| a.window_id.cmp(&b.window_id))
                    }
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => a.window_id.cmp(&b.window_id),
                }
            });

            snap.projects.push(ProjectSnapshot {
                project_id: project.project_id.clone(),
                name: project.name.clone(),
                root: project.root.clone(),
                default_workspace_policy: project.default_workspace_policy,
                last_active_at_ms: project.last_active_at_ms,
                icon: project.icon.clone(),
                accent_color: project.accent_color.clone(),
                launch_defaults: project.launch_defaults.clone(),
                directories: project.directories.clone(),
                system: project.system,
                hidden: project.hidden,
                workspaces,
                tasks,
                windows: project_windows,
            });
        }

        // Windows associated to a project_id that has no loaded Project record cannot be grouped —
        // surface them as unassigned rather than dropping them.
        let mut orphaned: Vec<DashboardWindow> =
            windows_by_project.into_values().flatten().collect();
        snap.unassigned_windows.append(&mut orphaned);

        // --- recovered sessions from the supplied report (reported, never invented) ---
        if let Some(report) = session_report {
            snap.recovered_sessions = report.recovered_sessions.clone();
        }

        self.sort_snapshot(&mut snap);
        Ok(snap)
    }

    /// Load all current-version records of `kind`, draining future-version paths into `future` and
    /// quarantined records into `quarantined`.
    fn load_kind<T>(
        &self,
        kind: RecordKind,
        future: &mut Vec<PathBuf>,
        quarantined: &mut Vec<QuarantinedRecord>,
    ) -> Result<Vec<T>, StoreError>
    where
        T: serde::de::DeserializeOwned,
    {
        let mut out = Vec::new();
        for outcome in store::load_all::<T>(self.paths, kind)? {
            match outcome {
                LoadOutcome::Loaded(record) => out.push(record),
                LoadOutcome::FutureVersion { path, .. } => future.push(path),
                LoadOutcome::Quarantined {
                    original,
                    moved_to,
                    reason,
                } => quarantined.push(QuarantinedRecord {
                    original,
                    moved_to,
                    reason,
                }),
            }
        }
        Ok(out)
    }

    /// Project one window's tabs into [`DashboardTab`] rows, joining the task report and applying
    /// a fresher reconciled session status when available.
    fn project_tabs(
        &self,
        window_id: &str,
        tabs: &[TabRecord],
        task_report: &AgentTaskReconcileReport,
        session_by_id: &HashMap<&str, &SessionRecord>,
        reconciled_status: &HashMap<&str, SessionStatus>,
    ) -> Vec<DashboardTab> {
        let mut rows: Vec<DashboardTab> = tabs
            .iter()
            .map(|tab| {
                let linked = task_report
                    .tasks
                    .iter()
                    .find(|t| t.current_session_id.as_deref() == Some(tab.session_id.as_str()));
                // Status precedence: fresh reconcile report > task-linked recorded status >
                // plain on-disk SessionRecord status.
                let session_status = reconciled_status
                    .get(tab.session_id.as_str())
                    .copied()
                    .or_else(|| linked.and_then(|t| t.current_session_status))
                    .or_else(|| session_by_id.get(tab.session_id.as_str()).map(|s| s.status));
                let needs_attention = tab_needs_attention(
                    &tab.attention,
                    linked.map(|t| t.needs_attention).unwrap_or(false),
                );
                DashboardTab {
                    window_id: window_id.to_string(),
                    tab_id: tab.tab_id.clone(),
                    session_id: tab.session_id.clone(),
                    index: tab.index,
                    title: tab.title.clone(),
                    pinned: tab.pinned,
                    attention: tab.attention,
                    agent_task_id: linked.map(|t| t.agent_task_id.clone()),
                    agent_task_state: linked.map(|t| t.state),
                    session_status,
                    session_record_missing: linked
                        .map(|t| t.session_record_missing)
                        .unwrap_or(false),
                    needs_attention,
                    stashed: tab.stashed,
                    cwd: session_by_id
                        .get(tab.session_id.as_str())
                        .map(|s| s.cwd_resolved.clone())
                        .unwrap_or_default(),
                }
            })
            .collect();
        rows.sort_by(|a, b| a.index.cmp(&b.index).then_with(|| a.tab_id.cmp(&b.tab_id)));
        rows
    }

    /// Decide a window's owning project from its tabs (scanned in `index` order): a tab's session
    /// owned by a task gives that task's project; else the session's workspace gives its project.
    /// First tab match wins. If no tab associates, fall back to the owning project's `window_order`
    /// entry so empty local windows still stay under their project.
    fn window_project(
        &self,
        tabs: &[TabRecord],
        task_session_project: &HashMap<&str, &str>,
        session_by_id: &HashMap<&str, &SessionRecord>,
        workspace_project: &HashMap<&str, &str>,
        window_project_by_order: &HashMap<&str, &str>,
        window_id: &str,
    ) -> Option<String> {
        let mut ordered: Vec<&TabRecord> = tabs.iter().collect();
        ordered.sort_by_key(|t| t.index);
        for tab in ordered {
            let sid = tab.session_id.as_str();
            if let Some(pid) = task_session_project.get(sid) {
                return Some((*pid).to_string());
            }
            if let Some(session) = session_by_id.get(sid) {
                if let Some(pid) = workspace_project.get(session.workspace_id.as_str()) {
                    return Some((*pid).to_string());
                }
            }
        }
        window_project_by_order
            .get(window_id)
            .map(|pid| (*pid).to_string())
    }

    /// Final deterministic ordering of the top-level buckets. Per-project inner vecs are already
    /// sorted at construction; tab rows are sorted in `project_tabs`.
    fn sort_snapshot(&self, snap: &mut DashboardSnapshot) {
        snap.projects.sort_by(|a, b| {
            b.last_active_at_ms
                .cmp(&a.last_active_at_ms)
                .then_with(|| a.project_id.cmp(&b.project_id))
        });
        snap.unassigned_windows
            .sort_by(|a, b| a.window_id.cmp(&b.window_id));
        snap.recovered_sessions
            .sort_by(|a, b| a.session_id.cmp(&b.session_id));
        snap.skipped_future_projects.sort();
        snap.skipped_future_workspaces.sort();
        snap.skipped_future_windows.sort();
        snap.skipped_future_tasks.sort();
        snap.skipped_future_sessions.sort();
        snap.quarantined.sort_by(|a, b| a.original.cmp(&b.original));
    }
}

/// A tab needs attention if its persisted roll-up is an unseen non-`None` signal, OR the joined
/// task says so. Mirrors `WindowLayoutService`'s rule so the two projections agree.
fn tab_needs_attention(attention: &AttentionState, task_needs_attention: bool) -> bool {
    task_needs_attention
        || (attention.unseen && attention.attention != crate::records::Attention::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::WorkspacePolicy;
    use crate::records::{Attention, AttentionSource, LaunchSpec, SessionKind, WorkspaceConsent};
    use crate::session_service::ReconciledSession;
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, AppPaths) {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        (tmp, paths)
    }

    fn project(id: &str, name: &str, last_active_at_ms: u64) -> Project {
        Project {
            project_id: id.into(),
            name: name.into(),
            root: format!("/repos/{id}"),
            default_workspace_policy: WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: Vec::new(),
            system: false,
            hidden: false,
        }
    }

    fn workspace(id: &str, project_id: &str) -> Workspace {
        Workspace {
            workspace_id: id.into(),
            project_id: project_id.into(),
            root: "/repos/x".into(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        }
    }

    fn task(id: &str, project_id: &str, state: AgentTaskState, current: Option<&str>) -> AgentTask {
        AgentTask {
            agent_task_id: id.into(),
            project_id: project_id.into(),
            goal: "goal".into(),
            state,
            current_session_id: current.map(str::to_string),
            session_history: vec![],
            created_at_ms: 1,
            updated_at_ms: 1,
            result_summary: None,
        }
    }

    fn session(id: &str, workspace_id: &str, status: SessionStatus) -> SessionRecord {
        SessionRecord {
            session_id: id.into(),
            workspace_id: workspace_id.into(),
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
            status,
        }
    }

    fn attn(attention: Attention, unseen: bool) -> AttentionState {
        AttentionState {
            attention,
            unseen,
            since_ms: 5,
            source: AttentionSource::Process,
        }
    }

    fn tab(tab_id: &str, session_id: &str, index: u32, attention: AttentionState) -> TabRecord {
        TabRecord {
            tab_id: tab_id.into(),
            session_id: session_id.into(),
            index,
            title: format!("title-{tab_id}"),
            pinned: false,
            attention,
            split_from: None,
            pane_rect: None,
            stashed_from: None,
            stashed: false,
        }
    }

    fn window(window_id: &str, tabs: Vec<TabRecord>) -> WindowLayout {
        WindowLayout {
            window_id: window_id.into(),
            name: None,
            tabs,
        }
    }

    fn write_project(paths: &AppPaths, p: &Project) {
        store::write_record(paths, RecordKind::Project, &p.project_id, 1, p).unwrap();
    }
    /// Persist a minimal parent Project (if absent) so an FK-bearing child can reference it.
    fn seed_project(paths: &AppPaths, id: &str) {
        if store::load_one::<Project>(paths, RecordKind::Project, id)
            .unwrap()
            .is_none()
        {
            write_project(paths, &project(id, id, 1));
        }
    }
    fn write_workspace(paths: &AppPaths, w: &Workspace) {
        // workspaces.project_id → projects: seed the parent first.
        seed_project(paths, &w.project_id);
        store::write_record(paths, RecordKind::Workspace, &w.workspace_id, 1, w).unwrap();
    }
    fn write_task(paths: &AppPaths, t: &AgentTask) {
        // agent_tasks.project_id → projects: seed the parent first.
        seed_project(paths, &t.project_id);
        store::write_record(paths, RecordKind::AgentTask, &t.agent_task_id, 1, t).unwrap();
    }
    fn write_session(paths: &AppPaths, s: &SessionRecord) {
        // sessions.workspace_id → workspaces (→ projects): seed the chain first. The workspace
        // upsert is INSERT OR REPLACE (DELETE+INSERT → cascades to sessions), so only create the
        // workspace if it doesn't already exist, to avoid wiping sessions already written under it.
        if store::load_one::<Workspace>(paths, RecordKind::Workspace, &s.workspace_id)
            .unwrap()
            .is_none()
        {
            write_workspace(paths, &workspace(&s.workspace_id, "p1"));
        }
        store::write_record(paths, RecordKind::Session, &s.session_id, 1, s).unwrap();
    }
    fn write_window(paths: &AppPaths, w: &WindowLayout) {
        store::write_record(paths, RecordKind::WindowLayout, &w.window_id, 1, w).unwrap();
    }

    fn snapshot(paths: &AppPaths, report: Option<&ReconcileReport>) -> DashboardSnapshot {
        DashboardSnapshotService::new(paths)
            .snapshot(report)
            .unwrap()
    }

    /// Every record currently loadable through the store, serialized to JSON, so a test can prove
    /// the snapshot scan mutated nothing. (The file-era byte-for-byte comparison over per-record
    /// files is gone now that records are SQLite rows; loading them back through the API and
    /// comparing values is the behavioral equivalent — same records in, same records out.)
    fn all_records(paths: &AppPaths) -> Vec<(String, serde_json::Value)> {
        fn dump<T: serde::Serialize + serde::de::DeserializeOwned>(
            paths: &AppPaths,
            kind: RecordKind,
            tag: &str,
        ) -> Vec<(String, serde_json::Value)> {
            store::load_all::<T>(paths, kind)
                .unwrap()
                .into_iter()
                .filter_map(|o| match o {
                    LoadOutcome::Loaded(r) => Some(r),
                    _ => None,
                })
                .map(|r| {
                    let v = serde_json::to_value(&r).unwrap();
                    (tag.to_string(), v)
                })
                .collect()
        }
        let mut out = Vec::new();
        out.extend(dump::<Project>(paths, RecordKind::Project, "project"));
        out.extend(dump::<Workspace>(paths, RecordKind::Workspace, "workspace"));
        out.extend(dump::<AgentTask>(
            paths,
            RecordKind::AgentTask,
            "agent_task",
        ));
        out.extend(dump::<SessionRecord>(paths, RecordKind::Session, "session"));
        out.extend(dump::<WindowLayout>(
            paths,
            RecordKind::WindowLayout,
            "window",
        ));
        out.sort_by(|a, b| (a.0.as_str(), a.1.to_string()).cmp(&(b.0.as_str(), b.1.to_string())));
        out
    }

    #[test]
    fn empty_store_yields_empty_snapshot() {
        let (_tmp, paths) = temp_paths();
        let snap = snapshot(&paths, None);
        // No records were seeded, so every bucket is empty. (The DB file existing after a read is
        // expected now — records live in SQLite, not per-record files — so the invariant is "the
        // snapshot is empty", not "no base dir was created".)
        assert_eq!(snap, DashboardSnapshot::default());
    }

    #[test]
    fn projects_sorted_by_recency_then_id() {
        let (_tmp, paths) = temp_paths();
        // Same recency for b & c so the id tiebreak is exercised; a is most recent.
        write_project(&paths, &project("p-a", "A", 300));
        write_project(&paths, &project("p-c", "C", 200));
        write_project(&paths, &project("p-b", "B", 200));

        let snap = snapshot(&paths, None);
        let ids: Vec<&str> = snap
            .projects
            .iter()
            .map(|p| p.project_id.as_str())
            .collect();
        assert_eq!(ids, vec!["p-a", "p-b", "p-c"]);
    }

    #[test]
    fn windows_in_window_order_associate_to_their_project_with_zero_unassigned() {
        // Regression for the "2 local windows, only 1 reached the remote browser" bug: a window whose tabs don't link
        // to a task/workspace still associates to its project via the project's window_order (which the app now appends
        // on every new-window creation). Both windows must land UNDER the project, and unassigned_windows must be empty.
        let (_tmp, paths) = temp_paths();
        let mut p = project("p1", "P1", 100);
        p.window_order = vec!["p1-window-1".into(), "p1-window-2".into()];
        write_project(&paths, &p);
        // Two windows; their tabs' sessions have NO workspace/task link (session records absent) — so ONLY window_order
        // can associate them.
        write_window(
            &paths,
            &window(
                "p1-window-1",
                vec![tab("t1", "s1", 0, AttentionState::default())],
            ),
        );
        write_window(
            &paths,
            &window(
                "p1-window-2",
                vec![tab("t2", "s2", 0, AttentionState::default())],
            ),
        );

        let snap = snapshot(&paths, None);
        assert_eq!(snap.projects.len(), 1);
        let win_ids: Vec<&str> = snap.projects[0]
            .windows
            .iter()
            .map(|w| w.window_id.as_str())
            .collect();
        assert_eq!(win_ids, vec!["p1-window-1", "p1-window-2"]);
        assert!(
            snap.unassigned_windows.is_empty(),
            "both windows associate via window_order → no unassigned; got {:?}",
            snap.unassigned_windows
        );
    }

    #[test]
    fn snapshot_carries_project_default_workspace_policy() {
        let (_tmp, paths) = temp_paths();
        let mut p = project("p1", "One", 100);
        p.default_workspace_policy = WorkspacePolicy::Worktree;
        write_project(&paths, &p);

        let snap = snapshot(&paths, None);
        assert_eq!(
            snap.projects[0].default_workspace_policy,
            WorkspacePolicy::Worktree,
            "the project record's non-default policy must survive onto ProjectSnapshot"
        );
    }

    #[test]
    fn snapshot_carries_project_icon_and_accent_color() {
        let (_tmp, paths) = temp_paths();
        let mut p = project("p1", "One", 100);
        p.icon = Some("🚀".to_string());
        p.accent_color = Some("#4f8cff".to_string());
        write_project(&paths, &p);

        let snap = snapshot(&paths, None);
        assert_eq!(snap.projects[0].icon.as_deref(), Some("🚀"));
        assert_eq!(snap.projects[0].accent_color.as_deref(), Some("#4f8cff"));
    }

    #[test]
    fn snapshot_project_icon_and_accent_default_to_none() {
        let (_tmp, paths) = temp_paths();
        write_project(&paths, &project("p1", "One", 100));

        let snap = snapshot(&paths, None);
        assert_eq!(snap.projects[0].icon, None);
        assert_eq!(snap.projects[0].accent_color, None);
    }

    #[test]
    fn workspaces_and_tasks_grouped_under_right_project() {
        let (_tmp, paths) = temp_paths();
        write_project(&paths, &project("p1", "One", 100));
        write_project(&paths, &project("p2", "Two", 90));
        write_workspace(&paths, &workspace("ws-1", "p1"));
        write_workspace(&paths, &workspace("ws-2", "p2"));
        write_task(&paths, &task("t-1", "p1", AgentTaskState::Running, None));
        write_task(&paths, &task("t-2", "p2", AgentTaskState::Draft, None));

        let snap = snapshot(&paths, None);
        let p1 = &snap.projects[0];
        assert_eq!(p1.project_id, "p1");
        assert_eq!(p1.workspaces.len(), 1);
        assert_eq!(p1.workspaces[0].workspace_id, "ws-1");
        assert_eq!(p1.tasks.len(), 1);
        assert_eq!(p1.tasks[0].agent_task_id, "t-1");
        let p2 = &snap.projects[1];
        assert_eq!(p2.workspaces[0].workspace_id, "ws-2");
        assert_eq!(p2.tasks[0].agent_task_id, "t-2");
    }

    #[test]
    fn window_linked_by_workspace_appears_under_that_project() {
        let (_tmp, paths) = temp_paths();
        write_project(&paths, &project("p1", "One", 100));
        write_workspace(&paths, &workspace("ws-1", "p1"));
        // session in ws-1 -> p1; tab points at it; NO task links the session.
        write_session(&paths, &session("s1", "ws-1", SessionStatus::Live));
        write_window(
            &paths,
            &window(
                "w1",
                vec![tab("tab1", "s1", 0, attn(Attention::None, false))],
            ),
        );

        let snap = snapshot(&paths, None);
        assert!(snap.unassigned_windows.is_empty());
        let p1 = &snap.projects[0];
        assert_eq!(p1.windows.len(), 1);
        assert_eq!(p1.windows[0].window_id, "w1");
        // No task, but the plain on-disk session status is surfaced.
        assert_eq!(
            p1.windows[0].tabs[0].session_status,
            Some(SessionStatus::Live)
        );
        assert!(p1.windows[0].tabs[0].agent_task_id.is_none());
    }

    #[test]
    fn stashed_flag_projects_into_dashboard_tab() {
        let (_tmp, paths) = temp_paths();
        write_project(&paths, &project("p1", "One", 100));
        write_workspace(&paths, &workspace("ws-1", "p1"));
        write_session(&paths, &session("s1", "ws-1", SessionStatus::Live));
        write_session(&paths, &session("s2", "ws-1", SessionStatus::Live));
        let mut live = tab("live", "s1", 0, attn(Attention::None, false));
        live.stashed = false;
        let mut dormant = tab("dormant", "s2", 1, attn(Attention::None, false));
        dormant.stashed = true;
        write_window(&paths, &window("w1", vec![live, dormant]));

        let snap = snapshot(&paths, None);
        let tabs = &snap.projects[0].windows[0].tabs;
        assert_eq!(tabs[0].tab_id, "live");
        assert!(!tabs[0].stashed);
        assert_eq!(tabs[1].tab_id, "dormant");
        assert!(tabs[1].stashed, "stashed flag must survive the projection");
    }

    #[test]
    fn window_linked_by_agent_task_appears_under_that_project() {
        let (_tmp, paths) = temp_paths();
        write_project(&paths, &project("p1", "One", 100));
        // task in p1 currently owns s1; no workspace/session record needed for association.
        write_task(
            &paths,
            &task("t1", "p1", AgentTaskState::Running, Some("s1")),
        );
        write_window(
            &paths,
            &window(
                "w1",
                vec![tab("tab1", "s1", 0, attn(Attention::None, false))],
            ),
        );

        let snap = snapshot(&paths, None);
        assert!(snap.unassigned_windows.is_empty());
        let p1 = &snap.projects[0];
        assert_eq!(p1.windows.len(), 1);
        let row = &p1.windows[0].tabs[0];
        assert_eq!(row.agent_task_id.as_deref(), Some("t1"));
        assert_eq!(row.agent_task_state, Some(AgentTaskState::Running));
        // Running task with a missing session record -> needs attention + missing flag.
        assert!(row.session_record_missing);
        assert!(row.needs_attention);
    }

    #[test]
    fn window_with_no_association_goes_to_unassigned() {
        let (_tmp, paths) = temp_paths();
        write_project(&paths, &project("p1", "One", 100));
        // Tab session links to nothing: no task owns it, no session record (so no workspace).
        write_window(
            &paths,
            &window(
                "w-orphan",
                vec![tab("tab1", "ghost", 0, attn(Attention::None, false))],
            ),
        );

        let snap = snapshot(&paths, None);
        assert!(snap.projects[0].windows.is_empty());
        assert_eq!(snap.unassigned_windows.len(), 1);
        assert_eq!(snap.unassigned_windows[0].window_id, "w-orphan");
    }

    #[test]
    fn empty_window_linked_by_project_window_order_appears_under_that_project() {
        let (_tmp, paths) = temp_paths();
        let mut p = project("p1", "One", 100);
        p.window_order = vec!["w-empty".into()];
        write_project(&paths, &p);
        write_window(&paths, &window("w-empty", vec![]));

        let snap = snapshot(&paths, None);
        assert!(snap.unassigned_windows.is_empty());
        let p1 = &snap.projects[0];
        assert_eq!(p1.windows.len(), 1);
        assert_eq!(p1.windows[0].window_id, "w-empty");
        assert!(p1.windows[0].tabs.is_empty());
    }

    #[test]
    fn window_under_unknown_project_id_is_unassigned_not_dropped() {
        let (_tmp, paths) = temp_paths();
        // Task references project "ghost" which has no LOADED Project record. The FK requires the
        // project row to exist at insert, so we seed it, write the task, then delete the project
        // row with `foreign_keys=OFF` — leaving the task orphaned (a normal cascade would remove
        // the task too, erasing the very state under test). This reproduces a task whose project
        // record is absent/unloadable, which must route its window to `unassigned` not drop it.
        write_task(
            &paths,
            &task("t1", "ghost", AgentTaskState::Running, Some("s1")),
        );
        {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let conn = arc.lock().unwrap();
            conn.pragma_update(None, "foreign_keys", "OFF").unwrap();
            conn.execute("DELETE FROM projects WHERE project_id = 'ghost'", [])
                .unwrap();
            conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        }
        write_window(
            &paths,
            &window(
                "w1",
                vec![tab("tab1", "s1", 0, attn(Attention::None, false))],
            ),
        );

        let snap = snapshot(&paths, None);
        assert!(snap.projects.is_empty());
        assert_eq!(
            snap.unassigned_windows.len(),
            1,
            "window must not be dropped"
        );
        assert_eq!(snap.unassigned_windows[0].window_id, "w1");
    }

    #[test]
    fn tab_rows_carry_persisted_attention_and_task_derived_needs_attention() {
        let (_tmp, paths) = temp_paths();
        write_project(&paths, &project("p1", "One", 100));
        write_task(
            &paths,
            &task("t1", "p1", AgentTaskState::WaitingOnUser, Some("s1")),
        );
        // Persisted unseen Error attention on a SECOND tab whose session has no task.
        write_workspace(&paths, &workspace("ws-1", "p1"));
        write_session(&paths, &session("s2", "ws-1", SessionStatus::Live));
        write_window(
            &paths,
            &window(
                "w1",
                vec![
                    tab("tab1", "s1", 0, attn(Attention::None, false)),
                    tab("tab2", "s2", 1, attn(Attention::Error, true)),
                ],
            ),
        );

        let snap = snapshot(&paths, None);
        let win = &snap.projects[0].windows[0];
        // tab1: task says WaitingOnUser -> needs attention from the task side.
        assert_eq!(win.tabs[0].tab_id, "tab1");
        assert!(win.tabs[0].needs_attention);
        // tab2: no task, but unseen Error persisted -> needs attention from the tab side.
        assert_eq!(win.tabs[1].tab_id, "tab2");
        assert_eq!(win.tabs[1].attention.attention, Attention::Error);
        assert!(win.tabs[1].attention.unseen);
        assert!(win.tabs[1].needs_attention);
    }

    #[test]
    fn supplied_report_recovered_sessions_appear_and_are_sorted() {
        let (_tmp, paths) = temp_paths();
        write_project(&paths, &project("p1", "One", 100));
        let report = ReconcileReport {
            sessions: vec![],
            recovered_sessions: vec![
                RecoveredSession {
                    session_id: "s-z".into(),
                },
                RecoveredSession {
                    session_id: "s-a".into(),
                },
            ],
            skipped_future_version: vec![],
        };

        let snap = snapshot(&paths, Some(&report));
        let ids: Vec<&str> = snap
            .recovered_sessions
            .iter()
            .map(|r| r.session_id.as_str())
            .collect();
        assert_eq!(ids, vec!["s-a", "s-z"]);
    }

    #[test]
    fn supplied_report_status_overrides_stale_on_disk_status_for_projection_only() {
        let (_tmp, paths) = temp_paths();
        write_project(&paths, &project("p1", "One", 100));
        write_workspace(&paths, &workspace("ws-1", "p1"));
        // On disk the session says Live (stale).
        write_session(&paths, &session("s1", "ws-1", SessionStatus::Live));
        write_window(
            &paths,
            &window(
                "w1",
                vec![tab("tab1", "s1", 0, attn(Attention::None, false))],
            ),
        );
        let before = all_records(&paths);

        // The report says it actually Exited.
        let report = ReconcileReport {
            sessions: vec![ReconciledSession {
                session_id: "s1".into(),
                status: SessionStatus::Exited,
                rewritten: false,
            }],
            recovered_sessions: vec![],
            skipped_future_version: vec![],
        };

        let snap = snapshot(&paths, Some(&report));
        let row = &snap.projects[0].windows[0].tabs[0];
        assert_eq!(
            row.session_status,
            Some(SessionStatus::Exited),
            "fresh reconcile status wins over stale on-disk status"
        );
        // Projection only: nothing was written back.
        assert_eq!(all_records(&paths), before, "no record rewritten");
    }

    // The file-era `future_version_records_are_skipped_and_left_byte_identical` and
    // `corrupt_records_are_quarantined_and_reported` tests hand-wrote raw JSON envelope FILES into
    // the records dir (a schema_version=9999 project and a malformed project). That mechanism is
    // gone now that records are SQLite rows: future-version is a DB-LEVEL guard (the whole DB is
    // refused on open — see store.rs::future_version_db_is_refused_on_open), and a row that won't
    // deserialize surfaces as `Quarantined` and is excluded from the loaded set (see
    // store.rs::row_that_wont_deserialize_is_quarantined_and_excluded). The snapshot's
    // `skipped_future_projects` / `quarantined` plumbing still passes through whatever `load_all`
    // reports; there is no longer a per-record file to forge here.

    #[test]
    fn ordering_is_deterministic_across_all_buckets() {
        let (_tmp, paths) = temp_paths();
        write_project(&paths, &project("p1", "One", 100));
        write_workspace(&paths, &workspace("ws-z", "p1"));
        write_workspace(&paths, &workspace("ws-a", "p1"));
        // Two tasks, same updated_at -> id tiebreak.
        write_task(&paths, &task("t-b", "p1", AgentTaskState::Draft, None));
        write_task(&paths, &task("t-a", "p1", AgentTaskState::Draft, None));
        // Two unassigned windows out of id order. Tab ids are globally unique now (tabs share one
        // table with a tab_id primary key), so the two windows' tabs carry distinct ids — the
        // test is about window ORDER, not tab identity.
        write_window(
            &paths,
            &window(
                "w-z",
                vec![tab("t-wz", "ghost", 0, attn(Attention::None, false))],
            ),
        );
        write_window(
            &paths,
            &window(
                "w-a",
                vec![tab("t-wa", "ghost2", 0, attn(Attention::None, false))],
            ),
        );

        let snap = snapshot(&paths, None);
        let p1 = &snap.projects[0];
        let ws_ids: Vec<&str> = p1
            .workspaces
            .iter()
            .map(|w| w.workspace_id.as_str())
            .collect();
        assert_eq!(ws_ids, vec!["ws-a", "ws-z"]);
        let task_ids: Vec<&str> = p1.tasks.iter().map(|t| t.agent_task_id.as_str()).collect();
        assert_eq!(task_ids, vec!["t-a", "t-b"]);
        let win_ids: Vec<&str> = snap
            .unassigned_windows
            .iter()
            .map(|w| w.window_id.as_str())
            .collect();
        assert_eq!(win_ids, vec!["w-a", "w-z"]);
    }

    #[test]
    fn tabs_within_a_window_are_sorted_by_index() {
        let (_tmp, paths) = temp_paths();
        write_project(&paths, &project("p1", "One", 100));
        write_task(
            &paths,
            &task("t1", "p1", AgentTaskState::Running, Some("s-mid")),
        );
        // Tabs written out of index order; projection must sort them.
        write_window(
            &paths,
            &window(
                "w1",
                vec![
                    tab("tab-c", "s-c", 2, attn(Attention::None, false)),
                    tab("tab-a", "s-mid", 0, attn(Attention::None, false)),
                    tab("tab-b", "s-b", 1, attn(Attention::None, false)),
                ],
            ),
        );

        let snap = snapshot(&paths, None);
        let win = &snap.projects[0].windows[0];
        let order: Vec<&str> = win.tabs.iter().map(|t| t.tab_id.as_str()).collect();
        assert_eq!(order, vec!["tab-a", "tab-b", "tab-c"]);
    }
}
