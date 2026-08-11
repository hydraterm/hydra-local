//! Dashboard-domain DTOs, projections, and pure helpers for `maestro-app`.
//!
//! This module holds the PURE, unit-testable dashboard surface. It contains:
//!
//! - the `dashboard` argument DTO ([`DashboardArgs`]);
//! - the compact active-task / terminal-result projections ([`project_active_tasks`],
//!   [`project_task_results`]) and their row/snapshot DTOs;
//! - the app-shell view model ([`build_dashboard_view_model`]) and its state-count DTO;
//! - the bounded, display-ready panel text ([`build_dashboard_panel_lines`]) and its renderer
//!   projection ([`dashboard_panel_to_renderer`]);
//! - the status-strip suffix helpers ([`dashboard_status_suffix`],
//!   [`attach_tab_dashboard_status_label`]);
//! - the `dashboard` success/failure JSON envelopes ([`DashboardSuccess`], [`DashboardFailure`]).
//!
//! These items read no global state and perform no process IO. The argument PARSER (`parse_dashboard`)
//! and the snapshot-building service deliberately remain in `lib.rs`; the crate root re-exports this
//! module's public items for `maestro_app::<Item>` callers.

use std::path::PathBuf;

use serde::Serialize;

use crate::{
    agent_task_state_wire_str, attach_tab_status_label, attention_source_wire_str,
    attention_wire_str, session_status_wire_str, AttentionJson, PRODUCT_RECOVERY_PROJECT_ID,
};

/// App-facing projections preserve the existing semantics of ordinary projects, including hidden
/// projects. Only the product launcher's exact reserved recovery identity is internal-only.
fn dashboard_project_is_projected(project: &maestro_shell::ProjectSnapshot) -> bool {
    project.project_id != PRODUCT_RECOVERY_PROJECT_ID
}

/// Parsed `dashboard` arguments. The default command is local-only and daemon-free (only `--base`).
/// The opt-in `--with-session-reconcile` flag turns on a daemon-aware pass (see `run_dashboard` in
/// `main`); `--socket` overrides the reconcile endpoint and is ONLY valid together with it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DashboardArgs {
    /// `--base <dir>`: app-support/storage base for `maestro-shell` records. When `None`, the
    /// dev-safe default base is used (see [`default_base_dir`]).
    pub base: Option<PathBuf>,
    /// `--with-session-reconcile`: opt in to a daemon-aware pass that runs
    /// `ShellRuntime::reconcile_sessions` and feeds the resulting report into the snapshot. Off by
    /// default, keeping the command local-only and daemon-free.
    pub with_session_reconcile: bool,
    /// `--socket <path>`: explicit reconcile endpoint. Meaningful ONLY with
    /// `--with-session-reconcile`; on its own it is a usage error (the default command never
    /// connects to a daemon).
    pub socket: Option<PathBuf>,
    /// `--active-tasks`: emit the compact active-task projection (see [`project_active_tasks`])
    /// as the success `snapshot` instead of the full [`DashboardSnapshot`]. Off by default, so the
    /// existing full-dashboard output is byte-shape unchanged. Local-only / daemon rules are
    /// identical to the full command; this flag only changes the shape of `snapshot`.
    pub active_tasks: bool,
    /// `--task-results`: emit the compact terminal-task projection (see [`project_task_results`])
    /// as the success `snapshot` instead of the full [`DashboardSnapshot`]. Off by default. Mutually
    /// exclusive with `--active-tasks` (both together is a usage error). Local-only / daemon rules
    /// are identical to the full command; this flag only changes the shape of `snapshot`.
    pub task_results: bool,
    /// `--view-model`: emit the compact app-shell dashboard view model (see
    /// [`build_dashboard_view_model`]) as the success `snapshot` instead of the full
    /// [`DashboardSnapshot`]. Off by default. Mutually exclusive with `--active-tasks` and
    /// `--task-results` (any combination is a usage error). Local-only / daemon rules are identical
    /// to the full command; this flag only changes the shape of `snapshot`.
    pub view_model: bool,
    /// `--panel-lines`: emit the bounded, display-ready dashboard panel text (see
    /// [`build_dashboard_panel_lines`]) as the success `snapshot` instead of the full
    /// [`DashboardSnapshot`]. Off by default. Mutually exclusive with `--active-tasks`,
    /// `--task-results`, and `--view-model` (any combination is a usage error). Local-only / daemon
    /// rules are identical to the full command; this flag only changes the shape of `snapshot`.
    pub panel_lines: bool,
    /// `--picker`: emit the headless read-only project/workspace picker projection (see
    /// [`build_picker_projection`]) as the success `snapshot` instead of the full
    /// [`DashboardSnapshot`]. Off by default. Mutually exclusive with `--active-tasks`,
    /// `--task-results`, `--view-model`, and `--panel-lines` (any combination is a usage error).
    /// Local-only / daemon rules are identical to the full command; this flag only changes the shape
    /// of `snapshot`.
    pub picker: bool,
}

/// Whether an [`maestro_shell::AgentTaskState`] is "active" for the dashboard sidebar: a task the
/// user can still act on. `Running`, `WaitingOnUser`, and `Blocked` are active; the terminal states
/// (`Succeeded`/`Failed`/`Cancelled`) and pure `Draft`s are excluded (a draft has not started, so it
/// is not a live work item, so drafts are omitted). Pure.
fn agent_task_state_is_active(state: maestro_shell::AgentTaskState) -> bool {
    matches!(
        state,
        maestro_shell::AgentTaskState::Running
            | maestro_shell::AgentTaskState::WaitingOnUser
            | maestro_shell::AgentTaskState::Blocked
    )
}

/// One compact active-task row for the future native dashboard sidebar: task identity joined with
/// its current session status and, when a window tab points at that session, the visible placement
/// (`window_id`/`tab_id`/`tab_title`) and persisted tab attention. Pure serde DTO produced by
/// [`project_active_tasks`]; absent joins serialize as JSON `null`. When no visible tab exists, a
/// neutral default [`AttentionJson`] is used and `needs_attention` is `false`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ActiveTaskRow {
    pub agent_task_id: String,
    pub project_id: String,
    pub goal: String,
    /// The active task state string (`running`/`waiting_on_user`/`blocked`).
    pub state: String,
    pub current_session_id: Option<String>,
    /// `live`/`exited`/`unknown` from the joined tab, or null when no visible tab is known.
    pub session_status: Option<String>,
    pub window_id: Option<String>,
    pub tab_id: Option<String>,
    pub tab_title: Option<String>,
    pub needs_attention: bool,
    pub attention: AttentionJson,
    pub updated_at_ms: u64,
}

/// The compact `snapshot` payload emitted by `maestro-app dashboard --active-tasks`: a deterministic
/// list of active task rows for the dashboard sidebar. Replaces the full [`DashboardSnapshot`] in the
/// success `snapshot` field; the surrounding [`DashboardSuccess`] wrapper is unchanged.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ActiveTasksSnapshot {
    pub active_tasks: Vec<ActiveTaskRow>,
}

/// A visible tab that points at a task's current session, kept with its window placement so a
/// deterministic winner can be chosen when multiple tabs share one session.
struct VisibleTabRef<'a> {
    window_id: &'a str,
    tab: &'a maestro_shell::DashboardTab,
}

/// Project the full [`DashboardSnapshot`] into the compact active-task list for the dashboard
/// sidebar. PURE: derived entirely from the already-built snapshot (no store scan, no daemon, no
/// filesystem); future-version/corrupt handling stays owned by the snapshot service that produced
/// `snapshot`.
///
/// Selection: every `AgentTask` across projected projects whose `state` is active (`Running`,
/// `WaitingOnUser`, `Blocked`). The exact reserved recovery project is excluded; ordinary hidden
/// projects remain projected. Terminal and draft tasks are excluded. Tasks under
/// `unassigned_windows` carry no task list, so the task universe is exactly the per-project tasks.
///
/// Join: a task's `current_session_id` is matched against every dashboard tab (project windows AND
/// `unassigned_windows`). When one or more tabs point at the session, the winner is chosen
/// deterministically — lowest `window_id` lexically, then lowest tab `index`, then lowest `tab_id` —
/// and its `session_status`/placement/persisted-attention/`needs_attention` are joined. With no
/// visible tab the row still appears with a null placement, neutral attention, and
/// `needs_attention = false`.
///
/// Sort: attention-needing rows first, then `updated_at_ms` descending, then `agent_task_id`
/// ascending — stable scanning order for the sidebar.
pub fn project_active_tasks(snapshot: &maestro_shell::DashboardSnapshot) -> ActiveTasksSnapshot {
    // All dashboard tabs across project windows and unassigned windows, retaining window placement.
    let all_tabs: Vec<VisibleTabRef> = snapshot
        .projects
        .iter()
        .filter(|project| dashboard_project_is_projected(project))
        .flat_map(|p| p.windows.iter())
        .chain(snapshot.unassigned_windows.iter())
        .flat_map(|w| {
            w.tabs.iter().map(move |tab| VisibleTabRef {
                window_id: &w.window_id,
                tab,
            })
        })
        .collect();

    let mut rows: Vec<ActiveTaskRow> = snapshot
        .projects
        .iter()
        .filter(|project| dashboard_project_is_projected(project))
        .flat_map(|p| p.tasks.iter())
        .filter(|task| agent_task_state_is_active(task.state))
        .map(|task| {
            // Deterministic winner among tabs whose session is this task's current session.
            let winner = task.current_session_id.as_deref().and_then(|sid| {
                all_tabs
                    .iter()
                    .filter(|vt| vt.tab.session_id == sid)
                    .min_by(|a, b| {
                        a.window_id
                            .cmp(b.window_id)
                            .then(a.tab.index.cmp(&b.tab.index))
                            .then_with(|| a.tab.tab_id.cmp(&b.tab.tab_id))
                    })
            });

            let (session_status, window_id, tab_id, tab_title, needs_attention, attention) =
                match winner {
                    Some(vt) => (
                        vt.tab
                            .session_status
                            .map(|s| session_status_wire_str(s).to_string()),
                        Some(vt.window_id.to_string()),
                        Some(vt.tab.tab_id.clone()),
                        Some(vt.tab.title.clone()),
                        vt.tab.needs_attention,
                        AttentionJson {
                            attention: attention_wire_str(vt.tab.attention.attention).to_string(),
                            unseen: vt.tab.attention.unseen,
                            since_ms: vt.tab.attention.since_ms,
                            source: attention_source_wire_str(vt.tab.attention.source).to_string(),
                        },
                    ),
                    None => (
                        None,
                        None,
                        None,
                        None,
                        false,
                        AttentionJson {
                            attention: attention_wire_str(
                                maestro_shell::AttentionState::default().attention,
                            )
                            .to_string(),
                            unseen: maestro_shell::AttentionState::default().unseen,
                            since_ms: maestro_shell::AttentionState::default().since_ms,
                            source: attention_source_wire_str(
                                maestro_shell::AttentionState::default().source,
                            )
                            .to_string(),
                        },
                    ),
                };

            ActiveTaskRow {
                agent_task_id: task.agent_task_id.clone(),
                project_id: task.project_id.clone(),
                goal: task.goal.clone(),
                state: agent_task_state_wire_str(task.state).to_string(),
                current_session_id: task.current_session_id.clone(),
                session_status,
                window_id,
                tab_id,
                tab_title,
                needs_attention,
                attention,
                updated_at_ms: task.updated_at_ms,
            }
        })
        .collect();

    rows.sort_by(|a, b| {
        // attention-needing first (true before false), then updated_at_ms desc, then id asc.
        b.needs_attention
            .cmp(&a.needs_attention)
            .then(b.updated_at_ms.cmp(&a.updated_at_ms))
            .then_with(|| a.agent_task_id.cmp(&b.agent_task_id))
    });

    ActiveTasksSnapshot { active_tasks: rows }
}

/// Whether an [`maestro_shell::AgentTaskState`] is "terminal" for the dashboard results view: a task
/// that has finished. `Succeeded`, `Failed`, and `Cancelled` are terminal; the active states
/// (`Running`/`WaitingOnUser`/`Blocked`) and pure `Draft`s are excluded. Pure.
fn agent_task_state_is_terminal(state: maestro_shell::AgentTaskState) -> bool {
    matches!(
        state,
        maestro_shell::AgentTaskState::Succeeded
            | maestro_shell::AgentTaskState::Failed
            | maestro_shell::AgentTaskState::Cancelled
    )
}

/// One compact terminal-task result row for the future native dashboard results/failure view: task
/// identity plus its terminal `state`, the stored `result_summary`, and `is_failure` for compact
/// failure styling. Pure serde DTO produced by [`project_task_results`]; an absent `result_summary`
/// serializes as JSON `null`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TaskResultRow {
    pub agent_task_id: String,
    pub project_id: String,
    pub goal: String,
    /// The terminal task state string (`succeeded`/`failed`/`cancelled`).
    pub state: String,
    /// The stored `result_summary`, or null when absent.
    pub summary: Option<String>,
    pub current_session_id: Option<String>,
    pub updated_at_ms: u64,
    /// `true` only for `Failed`; `false` for `Succeeded` and `Cancelled`.
    pub is_failure: bool,
}

/// The compact `snapshot` payload emitted by `maestro-app dashboard --task-results`: a deterministic
/// list of terminal task result rows for the dashboard results/failure view. Replaces the full
/// [`DashboardSnapshot`] in the success `snapshot` field; the surrounding [`DashboardSuccess`]
/// wrapper is unchanged.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct TaskResultsSnapshot {
    pub task_results: Vec<TaskResultRow>,
}

/// Project the full [`DashboardSnapshot`] into the compact terminal-task result list. PURE: derived
/// entirely from the already-built snapshot (no store scan, no daemon, no filesystem);
/// future-version/corrupt handling stays owned by the snapshot service that produced `snapshot`.
///
/// Selection: every `AgentTask` across projected projects whose `state` is terminal (`Succeeded`,
/// `Failed`, `Cancelled`). The exact reserved recovery project is excluded; ordinary hidden
/// projects remain projected. Active and draft tasks are excluded. Tasks under
/// `unassigned_windows` carry no task list, so the task universe is exactly the per-project tasks.
///
/// Sort: `updated_at_ms` descending, then `agent_task_id` ascending — most-recently-finished first.
pub fn project_task_results(snapshot: &maestro_shell::DashboardSnapshot) -> TaskResultsSnapshot {
    let mut rows: Vec<TaskResultRow> = snapshot
        .projects
        .iter()
        .filter(|project| dashboard_project_is_projected(project))
        .flat_map(|p| p.tasks.iter())
        .filter(|task| agent_task_state_is_terminal(task.state))
        .map(|task| TaskResultRow {
            agent_task_id: task.agent_task_id.clone(),
            project_id: task.project_id.clone(),
            goal: task.goal.clone(),
            state: agent_task_state_wire_str(task.state).to_string(),
            summary: task.result_summary.clone(),
            current_session_id: task.current_session_id.clone(),
            updated_at_ms: task.updated_at_ms,
            is_failure: task.state == maestro_shell::AgentTaskState::Failed,
        })
        .collect();

    rows.sort_by(|a, b| {
        b.updated_at_ms
            .cmp(&a.updated_at_ms)
            .then_with(|| a.agent_task_id.cmp(&b.agent_task_id))
    });

    TaskResultsSnapshot { task_results: rows }
}

/// One STASHED tab surfaced as a dim revive candidate in the dashboard. Carries just enough identity
/// to revive the tab (its window + tab id) plus its title for display. Pure serde DTO produced by
/// [`project_stashed_tabs`]. Distinct from `ActiveTaskRow`: a stashed tab is dormant layout, not a
/// running task — it may have no task at all.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct StashedTabRow {
    pub window_id: String,
    pub tab_id: String,
    pub title: String,
}

/// The compact stashed-tab list for the dashboard revive view. Pure serde DTO produced by
/// [`project_stashed_tabs`].
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct StashedTabsSnapshot {
    pub stashed_tabs: Vec<StashedTabRow>,
}

/// Project the full [`DashboardSnapshot`] into the compact stashed-tab list for the dashboard revive
/// view. PURE: derived entirely from the already-built snapshot (no store scan, no daemon, no
/// filesystem).
///
/// Selection: every dashboard tab (across projected project windows AND `unassigned_windows`) whose
/// `stashed` flag is set. The exact reserved recovery project is excluded; ordinary hidden projects
/// remain projected. Sort: `window_id` ascending, then tab `index`, then `tab_id` — a stable
/// scanning order matching the rest of the dashboard's deterministic ordering.
pub fn project_stashed_tabs(snapshot: &maestro_shell::DashboardSnapshot) -> StashedTabsSnapshot {
    let mut rows: Vec<(String, u32, StashedTabRow)> = snapshot
        .projects
        .iter()
        .filter(|project| dashboard_project_is_projected(project))
        .flat_map(|p| p.windows.iter())
        .chain(snapshot.unassigned_windows.iter())
        .flat_map(|w| {
            w.tabs.iter().filter(|t| t.stashed).map(move |tab| {
                (
                    w.window_id.clone(),
                    tab.index,
                    StashedTabRow {
                        window_id: w.window_id.clone(),
                        tab_id: tab.tab_id.clone(),
                        title: tab.title.clone(),
                    },
                )
            })
        })
        .collect();

    rows.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(a.1.cmp(&b.1))
            .then_with(|| a.2.tab_id.cmp(&b.2.tab_id))
    });

    StashedTabsSnapshot {
        stashed_tabs: rows.into_iter().map(|(_, _, r)| r).collect(),
    }
}

/// Counts of every project task bucketed by [`maestro_shell::AgentTaskState`], for the dashboard
/// view model. Unlike the active/terminal projections (which each exclude some states), this covers
/// the full projected task population — including `draft` and every terminal state — so the model
/// sees every user-facing task. Pure serde DTO produced by [`build_dashboard_view_model`].
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct DashboardStateCounts {
    pub draft: u32,
    pub running: u32,
    pub waiting_on_user: u32,
    pub blocked: u32,
    pub succeeded: u32,
    pub failed: u32,
    pub cancelled: u32,
}

/// The compact app-shell dashboard view model emitted by `maestro-app dashboard --view-model`: the
/// already-built active-task and terminal-result projections, plus per-state counts and the count of
/// active rows needing attention. This is the stable model seam a later native dashboard chrome will
/// render; it replaces the full [`DashboardSnapshot`] in the success `snapshot` field while the
/// surrounding [`DashboardSuccess`] wrapper is unchanged. Pure serde DTO produced by
/// [`build_dashboard_view_model`].
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DashboardViewModel {
    pub active_tasks: Vec<ActiveTaskRow>,
    pub task_results: Vec<TaskResultRow>,
    /// Dormant tabs the user can revive (kept in the layout but hidden from live panes).
    pub stashed_tabs: Vec<StashedTabRow>,
    pub counts: DashboardStateCounts,
    pub attention_count: u32,
    /// Identity of the most-recently-active projected project (snapshot projects are sorted
    /// `last_active_at_ms` desc), for dashboard/sidebar branding. `None` when there are no projected
    /// projects.
    pub active_project: Option<ActiveProjectIdentity>,
    /// Every projected project in canonical order (`last_active_at_ms` desc, matching the snapshot),
    /// so the renderer can paint a navigable project sidebar/tree. The first row is the active
    /// project (`is_active == true`). Empty when there are no projected projects.
    pub projects: Vec<ProjectListRow>,
}

/// One navigable project row for the dashboard sidebar: identity + branding + default workspace
/// policy, an `is_active` flag (the most-recently-active project), and compact per-project counts
/// (active tasks + windows) so the sidebar can badge each project without a second pass over the
/// snapshot. Pure serde DTO.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ProjectListRow {
    pub project_id: String,
    pub name: String,
    pub icon: Option<String>,
    pub accent_color: Option<String>,
    pub default_workspace_policy: maestro_shell::WorkspacePolicy,
    /// True for the most-recently-active project (the first row); false otherwise.
    pub is_active: bool,
    /// Number of this project's tasks in an active (non-terminal, non-draft) state.
    pub active_task_count: u32,
    /// Number of windows recorded under this project.
    pub window_count: u32,
}

/// Display identity of the active (most-recently-active) project: its name plus optional icon glyph
/// and `#rrggbb` accent color. Carried so the panel can show a branded header and the renderer can
/// apply a subtle accent tint. Pure serde DTO.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ActiveProjectIdentity {
    pub project_id: String,
    pub name: String,
    pub icon: Option<String>,
    pub accent_color: Option<String>,
}

/// Build the [`DashboardViewModel`] from the full [`DashboardSnapshot`]. PURE: derived entirely from
/// the already-built snapshot (no store scan, no daemon, no filesystem).
///
/// `active_tasks` and `task_results` are taken verbatim from [`project_active_tasks`] and
/// [`project_task_results`] (no duplicated row-mapping logic, so the model and the
/// `--active-tasks`/`--task-results` outputs cannot drift). `counts` folds every per-project task by
/// state (including `draft` and the terminal states). `attention_count` is the number of active rows
/// whose `needs_attention` is true.
pub fn build_dashboard_view_model(
    snapshot: &maestro_shell::DashboardSnapshot,
) -> DashboardViewModel {
    let active = project_active_tasks(snapshot);
    let results = project_task_results(snapshot);
    let stashed = project_stashed_tabs(snapshot);

    let mut counts = DashboardStateCounts::default();
    for task in snapshot
        .projects
        .iter()
        .filter(|project| dashboard_project_is_projected(project))
        .flat_map(|p| p.tasks.iter())
    {
        let bucket = match task.state {
            maestro_shell::AgentTaskState::Draft => &mut counts.draft,
            maestro_shell::AgentTaskState::Running => &mut counts.running,
            maestro_shell::AgentTaskState::WaitingOnUser => &mut counts.waiting_on_user,
            maestro_shell::AgentTaskState::Blocked => &mut counts.blocked,
            maestro_shell::AgentTaskState::Succeeded => &mut counts.succeeded,
            maestro_shell::AgentTaskState::Failed => &mut counts.failed,
            maestro_shell::AgentTaskState::Cancelled => &mut counts.cancelled,
        };
        *bucket += 1;
    }

    let attention_count = active
        .active_tasks
        .iter()
        .filter(|row| row.needs_attention)
        .count() as u32;

    // Snapshot projects are sorted `last_active_at_ms` desc, so the first projected project is the
    // active project.
    let active_project = snapshot
        .projects
        .iter()
        .find(|project| dashboard_project_is_projected(project))
        .map(|p| ActiveProjectIdentity {
            project_id: p.project_id.clone(),
            name: p.name.clone(),
            icon: p.icon.clone(),
            accent_color: p.accent_color.clone(),
        });

    // Project sidebar rows in canonical order; the first (most-recently-active) is `is_active`.
    let projects = snapshot
        .projects
        .iter()
        .filter(|project| dashboard_project_is_projected(project))
        .enumerate()
        .map(|(i, p)| ProjectListRow {
            project_id: p.project_id.clone(),
            name: p.name.clone(),
            icon: p.icon.clone(),
            accent_color: p.accent_color.clone(),
            default_workspace_policy: p.default_workspace_policy,
            is_active: i == 0,
            active_task_count: p
                .tasks
                .iter()
                .filter(|t| agent_task_state_is_active(t.state))
                .count() as u32,
            window_count: p.windows.len() as u32,
        })
        .collect();

    DashboardViewModel {
        active_tasks: active.active_tasks,
        task_results: results.task_results,
        stashed_tabs: stashed.stashed_tabs,
        counts,
        attention_count,
        active_project,
        projects,
    }
}

/// Deterministic bounds for [`build_dashboard_panel_lines`]: how many active-task and result rows the
/// compact panel may show, and the per-field character caps used when truncating goals and summaries.
/// Defaults are fixed (not env/record-derived) so the panel-lines output is stable across runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DashboardPanelLimits {
    /// Maximum active-task rows rendered into `lines` (the rest are summarized as a "+N more" hint).
    pub max_active_tasks: usize,
    /// Maximum terminal-result rows rendered into `lines`.
    pub max_task_results: usize,
    /// Maximum stashed-tab (revive candidate) rows rendered into `lines`.
    pub max_stashed_tabs: usize,
    /// Maximum project sidebar rows rendered into `lines` (the rest are summarized as a "+N more").
    pub max_projects: usize,
    /// Goals longer than this (in chars) are truncated with a trailing ellipsis marker.
    pub max_goal_chars: usize,
    /// Result summaries longer than this (in chars) are truncated with a trailing ellipsis marker.
    pub max_summary_chars: usize,
}

impl Default for DashboardPanelLimits {
    fn default() -> Self {
        Self {
            max_active_tasks: 8,
            max_task_results: 8,
            max_stashed_tabs: 8,
            max_projects: 8,
            max_goal_chars: 60,
            max_summary_chars: 80,
        }
    }
}

/// Bounded, display-ready panel text derived from a [`DashboardViewModel`]: a title, a one-line
/// counts summary, and a deterministic list of `lines` (section headers + per-task rows + an explicit
/// empty-state line), plus total-vs-shown bookkeeping. This is the renderer/chrome input contract for
/// the future native dashboard panel — it carries NO records, projects array, or raw snapshot. Pure
/// serde DTO produced by [`build_dashboard_panel_lines`].
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DashboardPanelLines {
    pub title: String,
    pub summary: String,
    pub lines: Vec<String>,
    /// One entry per `lines` entry, in the same order. Carries the structured identity behind each
    /// visible line so a renderer click seam can resolve a row to a focusable tab without re-parsing
    /// the display text. Non-row lines (title, summary, headers, hints, empty-state) carry a
    /// `DashboardPanelRowKind::Static` entry with no tab identity.
    pub rows: Vec<DashboardPanelRow>,
    pub active_tasks_total: usize,
    pub active_tasks_shown: usize,
    pub task_results_total: usize,
    pub task_results_shown: usize,
    pub stashed_tabs_total: usize,
    pub stashed_tabs_shown: usize,
    pub projects_total: usize,
    pub projects_shown: usize,
    pub attention_count: u32,
    /// The active project's `#rrggbb` accent color, carried through for the renderer's subtle
    /// dashboard tint. `None` = neutral chrome (no active project, or it has no accent set).
    pub accent_color: Option<String>,
}

/// What a single dashboard panel line represents. Only `ActiveTask` rows that resolved a visible tab
/// are focusable; everything else is `Static` chrome.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DashboardPanelRowKind {
    /// Title / summary / section header / "+N more" hint / empty-state — never focusable.
    Static,
    /// An active-task row. Focusable only when `tab_id` is present.
    ActiveTask,
    /// A recent-result row. Carries no tab identity and is never focusable.
    TaskResult,
    /// A stashed (dormant) tab offered as a revive candidate. Always carries `window_id`/`tab_id`;
    /// a click REVIVES the tab (clears its stashed flag) rather than focusing it.
    StashedTab,
    /// A project sidebar row. Carries `project_id`; a click SELECTS that project (the app makes it
    /// the active project) rather than focusing or reviving a tab.
    Project,
}

/// Structured identity for one dashboard panel line, aligned 1:1 with [`DashboardPanelLines::lines`].
/// Display-only metadata: it carries no focus/launch authority. `window_id`/`tab_id` are present only
/// when the row's task joined a visible tab (focus/revive target); `project_id` is present only for a
/// `Project` row (the project-selection target).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DashboardPanelRow {
    pub kind: DashboardPanelRowKind,
    pub window_id: Option<String>,
    pub tab_id: Option<String>,
    pub project_id: Option<String>,
}

impl DashboardPanelRow {
    fn stat() -> Self {
        Self {
            kind: DashboardPanelRowKind::Static,
            window_id: None,
            tab_id: None,
            project_id: None,
        }
    }
}

/// Strip control characters (anything `is_control()`, including tabs/newlines/CR) from a display
/// string so a single panel line can never break the layout, then collapse to a single space run.
fn panel_sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Deterministically truncate `s` to at most `max` characters (counting `char`s, not bytes, so
/// multi-byte text never splits mid-codepoint). When truncated, the result is `max` chars total with
/// a trailing `…` marker in the last position. `max == 0` yields an empty string.
fn panel_truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    let keep = max.saturating_sub(1);
    let mut out: String = s.chars().take(keep).collect();
    out.push('…');
    out
}

/// Build the bounded [`DashboardPanelLines`] from a [`DashboardViewModel`]. PURE and deterministic:
/// it only reads the view model's already-ordered `active_tasks`/`task_results`, `counts`, and
/// `attention_count` — it NEVER re-sorts, re-derives task state from raw records, or touches I/O.
///
/// Shape: a fixed title line; a counts summary using the same state buckets as the view model; an
/// `Active` section header followed by up to `max_active_tasks` rows (in view-model order); a
/// `Recent` section header followed by up to `max_task_results` rows; an explicit empty-state line
/// when there are no active tasks AND no results. Goals/summaries are sanitized (control chars
/// removed) and truncated to the configured caps. `*_total` reports the full counts; `*_shown`
/// reports how many rows actually made it into `lines`.
pub fn build_dashboard_panel_lines(
    view_model: &DashboardViewModel,
    limits: DashboardPanelLimits,
) -> DashboardPanelLines {
    let active_total = view_model.active_tasks.len();
    let results_total = view_model.task_results.len();
    let stashed_total = view_model.stashed_tabs.len();
    let projects_total = view_model.projects.len();
    let active_shown = active_total.min(limits.max_active_tasks);
    let results_shown = results_total.min(limits.max_task_results);
    let stashed_shown = stashed_total.min(limits.max_stashed_tabs);
    let projects_shown = projects_total.min(limits.max_projects);

    let mut lines: Vec<String> = Vec::new();
    let mut rows: Vec<DashboardPanelRow> = Vec::new();
    lines.push("Dashboard".to_string());
    rows.push(DashboardPanelRow::stat());

    // Branded project-identity header: `<icon> <name>` for the active (most-recently-active)
    // project. Sanitized + truncated like every other line so it can never break layout. The
    // accent color rides on the DTO (not the text) for the renderer tint.
    let accent_color = view_model
        .active_project
        .as_ref()
        .and_then(|p| p.accent_color.clone());
    if let Some(project) = view_model.active_project.as_ref() {
        let name = panel_truncate(&panel_sanitize(&project.name), limits.max_goal_chars);
        let header = match project
            .icon
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(icon) => format!("{} {name}", panel_sanitize(icon)),
            None => name,
        };
        lines.push(header);
        rows.push(DashboardPanelRow::stat());
    }

    let summary = format!(
        "running={} waiting={} blocked={} succeeded={} failed={} cancelled={} draft={} attn={}",
        view_model.counts.running,
        view_model.counts.waiting_on_user,
        view_model.counts.blocked,
        view_model.counts.succeeded,
        view_model.counts.failed,
        view_model.counts.cancelled,
        view_model.counts.draft,
        view_model.attention_count,
    );
    lines.push(summary.clone());
    rows.push(DashboardPanelRow::stat());

    // Project sidebar section: one selectable row per project (recency order), the active project
    // first and marked. Each row is `<marker> <icon> <name> <active>/<windows>`, using the
    // status-dot/icon/name/running-total layout. Only rendered when projects exist,
    // so a project-less tree keeps the prior shape.
    if projects_total > 0 {
        lines.push(format!("Projects ({projects_shown}/{projects_total})"));
        rows.push(DashboardPanelRow::stat());
        for project in view_model.projects.iter().take(projects_shown) {
            let marker = if project.is_active { "●" } else { "○" };
            let name = panel_truncate(&panel_sanitize(&project.name), limits.max_goal_chars);
            let label = match project
                .icon
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(icon) => format!("{} {name}", panel_sanitize(icon)),
                None => name,
            };
            lines.push(format!(
                "{marker} {label} {}/{}",
                project.active_task_count, project.window_count
            ));
            rows.push(DashboardPanelRow {
                kind: DashboardPanelRowKind::Project,
                window_id: None,
                tab_id: None,
                project_id: Some(project.project_id.clone()),
            });
        }
        if projects_total > projects_shown {
            lines.push(format!(
                "+{} more projects",
                projects_total - projects_shown
            ));
            rows.push(DashboardPanelRow::stat());
        }
    }

    if active_total == 0 && results_total == 0 && stashed_total == 0 {
        lines.push("(no active tasks or recent results)".to_string());
        rows.push(DashboardPanelRow::stat());
        return DashboardPanelLines {
            title: "Dashboard".to_string(),
            summary,
            lines,
            rows,
            active_tasks_total: active_total,
            active_tasks_shown: 0,
            task_results_total: results_total,
            task_results_shown: 0,
            stashed_tabs_total: stashed_total,
            stashed_tabs_shown: 0,
            projects_total,
            projects_shown,
            attention_count: view_model.attention_count,
            accent_color,
        };
    }

    lines.push(format!("Active ({active_shown}/{active_total})"));
    rows.push(DashboardPanelRow::stat());
    for row in view_model.active_tasks.iter().take(active_shown) {
        let attn = if row.needs_attention { "! " } else { "" };
        let goal = panel_truncate(&panel_sanitize(&row.goal), limits.max_goal_chars);
        lines.push(format!("{attn}[{}] {goal}", row.state));
        rows.push(DashboardPanelRow {
            kind: DashboardPanelRowKind::ActiveTask,
            window_id: row.window_id.clone(),
            tab_id: row.tab_id.clone(),
            project_id: None,
        });
    }
    if active_total > active_shown {
        lines.push(format!("+{} more active", active_total - active_shown));
        rows.push(DashboardPanelRow::stat());
    }

    lines.push(format!("Recent ({results_shown}/{results_total})"));
    rows.push(DashboardPanelRow::stat());
    for row in view_model.task_results.iter().take(results_shown) {
        let summary_txt = match row.summary.as_deref() {
            Some(s) => panel_truncate(&panel_sanitize(s), limits.max_summary_chars),
            None => String::new(),
        };
        lines.push(format!("[{}] {summary_txt}", row.state));
        rows.push(DashboardPanelRow {
            kind: DashboardPanelRowKind::TaskResult,
            window_id: None,
            tab_id: None,
            project_id: None,
        });
    }
    if results_total > results_shown {
        lines.push(format!("+{} more results", results_total - results_shown));
        rows.push(DashboardPanelRow::stat());
    }

    // Stashed (revive) section: only rendered when there is at least one dormant tab, so a tree with
    // no stashed tabs keeps the exact prior panel shape.
    if stashed_total > 0 {
        lines.push(format!("Stashed ({stashed_shown}/{stashed_total})"));
        rows.push(DashboardPanelRow::stat());
        for row in view_model.stashed_tabs.iter().take(stashed_shown) {
            let title = panel_truncate(&panel_sanitize(&row.title), limits.max_goal_chars);
            lines.push(format!("⟲ {title}"));
            rows.push(DashboardPanelRow {
                kind: DashboardPanelRowKind::StashedTab,
                window_id: Some(row.window_id.clone()),
                tab_id: Some(row.tab_id.clone()),
                project_id: None,
            });
        }
        if stashed_total > stashed_shown {
            lines.push(format!("+{} more stashed", stashed_total - stashed_shown));
            rows.push(DashboardPanelRow::stat());
        }
    }

    DashboardPanelLines {
        title: "Dashboard".to_string(),
        summary,
        lines,
        rows,
        active_tasks_total: active_total,
        active_tasks_shown: active_shown,
        task_results_total: results_total,
        task_results_shown: results_shown,
        stashed_tabs_total: stashed_total,
        stashed_tabs_shown: stashed_shown,
        projects_total,
        projects_shown,
        attention_count: view_model.attention_count,
        accent_color,
    }
}

/// Project the app-owned [`DashboardPanelLines`] onto the renderer-owned
/// [`maestro_renderer::RendererDashboardPanel`] launch DTO. PURE: clones the already-bounded `lines`
/// in order, dropping nothing. The renderer applies its own row cap/column fit at draw time; this
/// helper only carries the display-ready lines across the crate boundary.
pub fn dashboard_panel_to_renderer(
    panel: &DashboardPanelLines,
) -> maestro_renderer::RendererDashboardPanel {
    let rows: Vec<maestro_renderer::RendererDashboardRow> = panel
        .rows
        .iter()
        .map(|row| {
            // Each actionable kind carries EXACTLY one target so the renderer's click seam routes
            // unambiguously: a focusable tab row (focus_*), a stashed revive candidate (revive_*),
            // or a project sidebar row (select_project_id). Static/result rows carry none.
            let focus = row.kind == DashboardPanelRowKind::ActiveTask;
            let revive = row.kind == DashboardPanelRowKind::StashedTab;
            let select = row.kind == DashboardPanelRowKind::Project;
            maestro_renderer::RendererDashboardRow {
                focus_window_id: if focus { row.window_id.clone() } else { None },
                focus_tab_id: if focus { row.tab_id.clone() } else { None },
                revive_window_id: if revive { row.window_id.clone() } else { None },
                revive_tab_id: if revive { row.tab_id.clone() } else { None },
                select_project_id: if select { row.project_id.clone() } else { None },
            }
        })
        .collect();
    maestro_renderer::RendererDashboardPanel::dashboard_with_rows(panel.lines.clone(), rows)
        .with_accent_color(panel.accent_color.clone())
}

/// Flatten the read-only [`maestro_shell::DashboardSnapshot`] into the renderer's left-dock tree
/// ([`maestro_renderer::RendererDockRow`]s) in draw order. PURE: derived entirely from the snapshot
/// plus the app-owned UI state (`dock_collapsed`, `expanded_projects`); no records/socket/env access.
///
/// Tree shape (document order, projects already sorted `last_active_at_ms` desc):
/// - depth 0 — one **project** row per projected snapshot project. The exact reserved recovery
///   project is excluded while ordinary hidden projects retain their existing semantics. Each row
///   is collapsible (`expanded` is `Some`), carries `select_project_id`, a window-count badge, the
///   project icon/accent, and `active` for the most-recently-active projected project.
/// - depth 1 — one **window** row per `project.windows[*]`, emitted only when the project is expanded.
/// - depth 2 — one **pane** row per `window.tabs[*]` (also expanded-only). A live tab routes to
///   `focus_*`; a stashed tab routes to `revive_*` and is flagged `stashed`. Exactly one target per row.
///
/// When `dock_collapsed`, only depth-0 project rows are emitted (the icon-rail variant) and no project
/// is treated as expanded regardless of `expanded_projects`.
pub fn build_dock_model(
    snapshot: &maestro_shell::DashboardSnapshot,
    dock_collapsed: bool,
    expanded_projects: &std::collections::HashSet<String>,
    dock_width_px: u32,
) -> maestro_renderer::RendererDockModel {
    let mut rows: Vec<maestro_renderer::RendererDockRow> = Vec::new();

    for (i, project) in snapshot
        .projects
        .iter()
        .filter(|project| dashboard_project_is_projected(project))
        .enumerate()
    {
        let expanded = !dock_collapsed && expanded_projects.contains(&project.project_id);
        rows.push(maestro_renderer::RendererDockRow {
            depth: 0,
            kind: maestro_renderer::DockRowKind::Project,
            label: project.name.clone(),
            icon: project.icon.clone().unwrap_or_default(),
            accent_color: project.accent_color.clone(),
            focused: false,
            active: i == 0,
            stashed: false,
            count_badge: Some(project.windows.len() as u32),
            expanded: Some(expanded),
            select_project_id: Some(project.project_id.clone()),
            focus_window_id: None,
            focus_tab_id: None,
            revive_window_id: None,
            revive_tab_id: None,
        });

        if dock_collapsed || !expanded {
            continue;
        }

        for window in project.windows.iter() {
            rows.push(maestro_renderer::RendererDockRow {
                depth: 1,
                kind: maestro_renderer::DockRowKind::Window,
                label: window.window_id.clone(),
                icon: String::new(),
                accent_color: project.accent_color.clone(),
                focused: false,
                active: false,
                stashed: false,
                count_badge: Some(window.tabs.len() as u32),
                expanded: None,
                select_project_id: None,
                focus_window_id: None,
                focus_tab_id: None,
                revive_window_id: None,
                revive_tab_id: None,
            });

            for tab in window.tabs.iter() {
                let live = !tab.stashed;
                rows.push(maestro_renderer::RendererDockRow {
                    depth: 2,
                    kind: maestro_renderer::DockRowKind::Pane,
                    label: tab.title.clone(),
                    icon: String::new(),
                    accent_color: project.accent_color.clone(),
                    focused: false,
                    active: live
                        && matches!(tab.session_status, Some(maestro_shell::SessionStatus::Live)),
                    stashed: tab.stashed,
                    count_badge: None,
                    expanded: None,
                    select_project_id: None,
                    focus_window_id: if live {
                        Some(window.window_id.clone())
                    } else {
                        None
                    },
                    focus_tab_id: if live { Some(tab.tab_id.clone()) } else { None },
                    revive_window_id: if live {
                        None
                    } else {
                        Some(window.window_id.clone())
                    },
                    revive_tab_id: if live { None } else { Some(tab.tab_id.clone()) },
                });
            }
        }
    }

    maestro_renderer::RendererDockModel {
        collapsed: dock_collapsed,
        width_px: dock_width_px,
        rows,
    }
}

/// A compact, deterministic, ASCII-only dashboard summary suffix for the app-owned status strip,
/// derived ENTIRELY from a [`DashboardViewModel`] (no records/socket/env access, no second
/// task-state mapping). Shape: `[active=<n> waiting=<n> blocked=<n> failed=<n> attn=<n>]`.
///
/// - `active` is the number of active task rows (`active_tasks.len()`), i.e. running + waiting + blocked.
/// - `waiting` / `blocked` / `failed` come from the view model's `counts`.
/// - `attn` is the view model's `attention_count`.
///
/// Zero values are always included (never omitted) so the shape is stable across snapshots, and the
/// whole suffix stays short enough for a one-line status strip.
pub fn dashboard_status_suffix(view_model: &DashboardViewModel) -> String {
    format!(
        "[active={} waiting={} blocked={} failed={} attn={}]",
        view_model.active_tasks.len(),
        view_model.counts.waiting_on_user,
        view_model.counts.blocked,
        view_model.counts.failed,
        view_model.attention_count,
    )
}

/// Compose the app-owned attach-tab status identity with an optional dashboard suffix. When `suffix`
/// is `None`, this returns exactly [`attach_tab_status_label`] so default behavior is byte-for-byte
/// unchanged; when `Some`, the suffix is appended after the existing middot separator. Pure.
pub fn attach_tab_dashboard_status_label(
    window_id: &str,
    tab_id: &str,
    session_id: &str,
    suffix: Option<&str>,
) -> String {
    let base = attach_tab_status_label(window_id, tab_id, session_id);
    match suffix {
        Some(s) => format!("{base} · {s}"),
        None => base,
    }
}

/// The success JSON printed to stdout by `maestro-app dashboard`: exactly one structured value
/// wrapping the read-only [`maestro_shell::DashboardSnapshot`]. `base` is the resolved records base
/// that was scanned. Generic over the snapshot type so this stays unit-testable in `lib.rs` (which
/// has no `maestro-shell` dependency) — `main` instantiates it with the real `DashboardSnapshot`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DashboardSuccess<S> {
    pub ok: bool,
    pub command: &'static str,
    pub base: String,
    /// Whether the opt-in `--with-session-reconcile` daemon pass ran. `false` on the default
    /// local-only path.
    pub session_reconcile: bool,
    /// The socket path the reconcile actually used, present only when `session_reconcile` is true.
    pub socket_path: Option<String>,
    pub snapshot: S,
}

impl<S> DashboardSuccess<S> {
    /// The default local-only success: no daemon reconcile ran.
    pub fn new(base: String, snapshot: S) -> Self {
        DashboardSuccess {
            ok: true,
            command: "dashboard",
            base,
            session_reconcile: false,
            socket_path: None,
            snapshot,
        }
    }

    /// A success after the opt-in `--with-session-reconcile` pass, stamping the socket the
    /// reconcile used.
    pub fn reconciled(base: String, socket_path: String, snapshot: S) -> Self {
        DashboardSuccess {
            ok: true,
            command: "dashboard",
            base,
            session_reconcile: true,
            socket_path: Some(socket_path),
            snapshot,
        }
    }
}

/// The failure JSON printed to stderr by `maestro-app dashboard`. Mirrors [`LaunchFailure`]'s shape
/// (`ok:false`, `command`, `error_kind`, `message`) but stamps `command: "dashboard"`. Typical
/// `error_kind`s: `bad_usage` (parse error) and `dashboard_failed` (snapshot/store failure).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct DashboardFailure {
    pub ok: bool,
    pub command: &'static str,
    pub error_kind: String,
    pub message: String,
}

impl DashboardFailure {
    pub fn new(error_kind: impl Into<String>, message: impl Into<String>) -> Self {
        DashboardFailure {
            ok: false,
            command: "dashboard",
            error_kind: error_kind.into(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    // ---- active-task projection -------------------------------------------------------------
    //
    // These tests live here beside `project_active_tasks`, `ActiveTaskRow`, and
    // `ActiveTasksSnapshot`. The `task`/`dash_tab`/`project_with`/`snapshot_of`/`unseen_needs_input`
    // helpers are narrow private copies (they are also retained in `lib.rs::tests`, which still has
    // task-results/view-model/panel-line/status-suffix callers).

    fn task(
        id: &str,
        state: maestro_shell::AgentTaskState,
        session: Option<&str>,
        updated_at_ms: u64,
    ) -> maestro_shell::AgentTask {
        maestro_shell::AgentTask {
            agent_task_id: id.to_string(),
            project_id: "project-1".to_string(),
            goal: format!("goal for {id}"),
            state,
            current_session_id: session.map(str::to_string),
            session_history: vec![],
            created_at_ms: 0,
            updated_at_ms,
            result_summary: None,
        }
    }

    fn dash_tab(
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        index: u32,
        attention: maestro_shell::AttentionState,
        session_status: Option<maestro_shell::SessionStatus>,
        needs_attention: bool,
    ) -> maestro_shell::DashboardTab {
        maestro_shell::DashboardTab {
            window_id: window_id.to_string(),
            tab_id: tab_id.to_string(),
            session_id: session_id.to_string(),
            index,
            title: format!("title {tab_id}"),
            pinned: false,
            attention,
            agent_task_id: None,
            agent_task_state: None,
            session_status,
            session_record_missing: false,
            needs_attention,
            stashed: false,
            cwd: String::new(),
        }
    }

    fn project_with(
        tasks: Vec<maestro_shell::AgentTask>,
        windows: Vec<maestro_shell::DashboardWindow>,
    ) -> maestro_shell::ProjectSnapshot {
        maestro_shell::ProjectSnapshot {
            project_id: "project-1".to_string(),
            name: "Project One".to_string(),
            root: "/p1".to_string(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            last_active_at_ms: 0,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            system: false,
            hidden: false,
            workspaces: vec![],
            tasks,
            windows,
        }
    }

    fn snapshot_of(
        projects: Vec<maestro_shell::ProjectSnapshot>,
    ) -> maestro_shell::DashboardSnapshot {
        maestro_shell::DashboardSnapshot {
            projects,
            ..Default::default()
        }
    }

    fn unseen_needs_input() -> maestro_shell::AttentionState {
        maestro_shell::AttentionState {
            attention: maestro_shell::Attention::NeedsInput,
            unseen: true,
            since_ms: 42,
            source: maestro_shell::AttentionSource::Agent,
        }
    }

    #[test]
    fn active_tasks_filters_terminal_and_draft_states() {
        let projects = vec![project_with(
            vec![
                task("t-run", maestro_shell::AgentTaskState::Running, None, 10),
                task(
                    "t-wait",
                    maestro_shell::AgentTaskState::WaitingOnUser,
                    None,
                    20,
                ),
                task("t-block", maestro_shell::AgentTaskState::Blocked, None, 30),
                task("t-draft", maestro_shell::AgentTaskState::Draft, None, 40),
                task("t-ok", maestro_shell::AgentTaskState::Succeeded, None, 50),
                task("t-fail", maestro_shell::AgentTaskState::Failed, None, 60),
                task(
                    "t-cancel",
                    maestro_shell::AgentTaskState::Cancelled,
                    None,
                    70,
                ),
            ],
            vec![],
        )];
        let out = project_active_tasks(&snapshot_of(projects));
        let ids: Vec<&str> = out
            .active_tasks
            .iter()
            .map(|r| r.agent_task_id.as_str())
            .collect();
        assert_eq!(ids, vec!["t-block", "t-wait", "t-run"]);
        // States carried through as their wire strings.
        assert_eq!(out.active_tasks[0].state, "blocked");
        assert_eq!(out.active_tasks[1].state, "waiting_on_user");
        assert_eq!(out.active_tasks[2].state, "running");
    }

    #[test]
    fn active_tasks_sort_attention_first_then_updated_desc_then_id() {
        // Two attention-needing (sorted by updated desc then id), then non-attention by updated desc.
        let tabs = vec![maestro_shell::DashboardWindow {
            window_id: "w1".to_string(),
            name: None,
            tabs: vec![
                dash_tab("w1", "tab-a", "sess-a", 0, unseen_needs_input(), None, true),
                dash_tab("w1", "tab-b", "sess-b", 1, unseen_needs_input(), None, true),
            ],
        }];
        let projects = vec![project_with(
            vec![
                // attention rows
                task(
                    "a-low",
                    maestro_shell::AgentTaskState::Running,
                    Some("sess-a"),
                    5,
                ),
                task(
                    "a-high",
                    maestro_shell::AgentTaskState::Running,
                    Some("sess-b"),
                    9,
                ),
                // non-attention rows
                task("z-new", maestro_shell::AgentTaskState::Running, None, 100),
                task("z-old", maestro_shell::AgentTaskState::Running, None, 1),
            ],
            tabs,
        )];
        let out = project_active_tasks(&snapshot_of(projects));
        let ids: Vec<&str> = out
            .active_tasks
            .iter()
            .map(|r| r.agent_task_id.as_str())
            .collect();
        // a-high (updated 9) and a-low (updated 5) need attention -> first; then z-new (100), z-old (1).
        assert_eq!(ids, vec!["a-high", "a-low", "z-new", "z-old"]);
        assert!(out.active_tasks[0].needs_attention);
        assert!(out.active_tasks[1].needs_attention);
        assert!(!out.active_tasks[2].needs_attention);
    }

    #[test]
    fn active_task_row_joins_visible_tab_placement_and_attention() {
        let tabs = vec![maestro_shell::DashboardWindow {
            window_id: "w1".to_string(),
            name: None,
            tabs: vec![dash_tab(
                "w1",
                "tab-1",
                "sess-1",
                0,
                unseen_needs_input(),
                Some(maestro_shell::SessionStatus::Live),
                true,
            )],
        }];
        let projects = vec![project_with(
            vec![task(
                "task-1",
                maestro_shell::AgentTaskState::Running,
                Some("sess-1"),
                10,
            )],
            tabs,
        )];
        let out = project_active_tasks(&snapshot_of(projects));
        assert_eq!(out.active_tasks.len(), 1);
        let row = &out.active_tasks[0];
        assert_eq!(row.current_session_id.as_deref(), Some("sess-1"));
        assert_eq!(row.session_status.as_deref(), Some("live"));
        assert_eq!(row.window_id.as_deref(), Some("w1"));
        assert_eq!(row.tab_id.as_deref(), Some("tab-1"));
        assert_eq!(row.tab_title.as_deref(), Some("title tab-1"));
        assert!(row.needs_attention);
        assert_eq!(row.attention.attention, "needs_input");
        assert!(row.attention.unseen);
        assert_eq!(row.attention.since_ms, 42);
        assert_eq!(row.attention.source, "agent");
    }

    #[test]
    fn active_task_without_visible_tab_has_neutral_attention_and_null_placement() {
        let projects = vec![project_with(
            vec![task(
                "task-1",
                maestro_shell::AgentTaskState::Blocked,
                Some("sess-missing"),
                10,
            )],
            vec![],
        )];
        let out = project_active_tasks(&snapshot_of(projects));
        assert_eq!(out.active_tasks.len(), 1);
        let row = &out.active_tasks[0];
        assert_eq!(row.session_status, None);
        assert_eq!(row.window_id, None);
        assert_eq!(row.tab_id, None);
        assert_eq!(row.tab_title, None);
        assert!(!row.needs_attention);
        assert_eq!(row.attention.attention, "none");
        assert!(!row.attention.unseen);
        assert_eq!(row.attention.since_ms, 0);
        assert_eq!(row.attention.source, "process");
    }

    #[test]
    fn active_task_duplicate_tab_placements_choose_deterministically() {
        // Three tabs point at sess-1: across two windows and two indices. Winner is lowest
        // window id, then lowest index, then lowest tab id.
        let win_b = maestro_shell::DashboardWindow {
            window_id: "w-b".to_string(),
            name: None,
            tabs: vec![dash_tab(
                "w-b",
                "tab-x",
                "sess-1",
                0,
                maestro_shell::AttentionState::default(),
                Some(maestro_shell::SessionStatus::Exited),
                false,
            )],
        };
        let win_a = maestro_shell::DashboardWindow {
            window_id: "w-a".to_string(),
            name: None,
            tabs: vec![
                dash_tab(
                    "w-a",
                    "tab-2",
                    "sess-1",
                    1,
                    maestro_shell::AttentionState::default(),
                    Some(maestro_shell::SessionStatus::Unknown),
                    false,
                ),
                dash_tab(
                    "w-a",
                    "tab-1",
                    "sess-1",
                    0,
                    unseen_needs_input(),
                    Some(maestro_shell::SessionStatus::Live),
                    true,
                ),
            ],
        };
        let projects = vec![project_with(
            vec![task(
                "task-1",
                maestro_shell::AgentTaskState::Running,
                Some("sess-1"),
                10,
            )],
            vec![win_b, win_a],
        )];
        let out = project_active_tasks(&snapshot_of(projects));
        let row = &out.active_tasks[0];
        // Lowest window id "w-a", then lowest index 0 -> tab-1.
        assert_eq!(row.window_id.as_deref(), Some("w-a"));
        assert_eq!(row.tab_id.as_deref(), Some("tab-1"));
        assert_eq!(row.session_status.as_deref(), Some("live"));
        assert!(row.needs_attention);
    }

    #[test]
    fn active_task_join_scans_unassigned_windows_too() {
        let snap = maestro_shell::DashboardSnapshot {
            projects: vec![project_with(
                vec![task(
                    "task-1",
                    maestro_shell::AgentTaskState::Running,
                    Some("sess-1"),
                    10,
                )],
                vec![],
            )],
            unassigned_windows: vec![maestro_shell::DashboardWindow {
                window_id: "w-unassigned".to_string(),
                name: None,
                tabs: vec![dash_tab(
                    "w-unassigned",
                    "tab-u",
                    "sess-1",
                    0,
                    maestro_shell::AttentionState::default(),
                    Some(maestro_shell::SessionStatus::Live),
                    false,
                )],
            }],
            ..Default::default()
        };
        let out = project_active_tasks(&snap);
        let row = &out.active_tasks[0];
        assert_eq!(row.window_id.as_deref(), Some("w-unassigned"));
        assert_eq!(row.tab_id.as_deref(), Some("tab-u"));
        assert_eq!(row.session_status.as_deref(), Some("live"));
    }

    #[test]
    fn active_tasks_snapshot_serializes_compact_shape() {
        let projects = vec![project_with(
            vec![task(
                "task-1",
                maestro_shell::AgentTaskState::Running,
                Some("sess-1"),
                123,
            )],
            vec![],
        )];
        let out = project_active_tasks(&snapshot_of(projects));
        let wrapped = DashboardSuccess::new(s("/base"), out);
        let v: serde_json::Value = serde_json::to_value(&wrapped).unwrap();
        assert_eq!(v["command"], serde_json::json!("dashboard"));
        assert_eq!(v["snapshot"]["active_tasks"][0]["agent_task_id"], "task-1");
        assert_eq!(v["snapshot"]["active_tasks"][0]["state"], "running");
        assert_eq!(v["snapshot"]["active_tasks"][0]["updated_at_ms"], 123);
        // Compact shape: no full-dashboard `projects` key in the snapshot.
        assert!(v["snapshot"]["projects"].is_null());
    }

    // ---- task-results projection ------------------------------------------------------------
    //
    // These tests exercise `project_task_results` / `TaskResultRow` / `TaskResultsSnapshot`, all
    // defined in this module. `terminal_task` is copied here (it is also retained in `lib.rs::tests`
    // where many other tests still call it); `task` / `project_with` / `snapshot_of` / `s` are the
    // copies already present in the active-task tests above.

    fn terminal_task(
        id: &str,
        state: maestro_shell::AgentTaskState,
        summary: Option<&str>,
        session: Option<&str>,
        updated_at_ms: u64,
    ) -> maestro_shell::AgentTask {
        maestro_shell::AgentTask {
            result_summary: summary.map(str::to_string),
            ..task(id, state, session, updated_at_ms)
        }
    }

    #[test]
    fn task_results_includes_terminal_only() {
        let projects = vec![project_with(
            vec![
                task("t-run", maestro_shell::AgentTaskState::Running, None, 10),
                task(
                    "t-wait",
                    maestro_shell::AgentTaskState::WaitingOnUser,
                    None,
                    20,
                ),
                task("t-block", maestro_shell::AgentTaskState::Blocked, None, 30),
                task("t-draft", maestro_shell::AgentTaskState::Draft, None, 40),
                task("t-ok", maestro_shell::AgentTaskState::Succeeded, None, 50),
                task("t-fail", maestro_shell::AgentTaskState::Failed, None, 60),
                task(
                    "t-cancel",
                    maestro_shell::AgentTaskState::Cancelled,
                    None,
                    70,
                ),
            ],
            vec![],
        )];
        let out = project_task_results(&snapshot_of(projects));
        let ids: Vec<&str> = out
            .task_results
            .iter()
            .map(|r| r.agent_task_id.as_str())
            .collect();
        // Terminal only, sorted by updated_at_ms desc: t-cancel(70), t-fail(60), t-ok(50).
        assert_eq!(ids, vec!["t-cancel", "t-fail", "t-ok"]);
        assert_eq!(out.task_results[0].state, "cancelled");
        assert_eq!(out.task_results[1].state, "failed");
        assert_eq!(out.task_results[2].state, "succeeded");
    }

    #[test]
    fn task_results_sort_updated_desc_then_id_asc() {
        let projects = vec![project_with(
            vec![
                task("b", maestro_shell::AgentTaskState::Succeeded, None, 100),
                task("a", maestro_shell::AgentTaskState::Failed, None, 100),
                task("c", maestro_shell::AgentTaskState::Cancelled, None, 200),
            ],
            vec![],
        )];
        let out = project_task_results(&snapshot_of(projects));
        let ids: Vec<&str> = out
            .task_results
            .iter()
            .map(|r| r.agent_task_id.as_str())
            .collect();
        // 200 first; the two 100s tie-break by id ascending (a before b).
        assert_eq!(ids, vec!["c", "a", "b"]);
    }

    #[test]
    fn task_results_is_failure_only_for_failed() {
        let projects = vec![project_with(
            vec![
                task("t-fail", maestro_shell::AgentTaskState::Failed, None, 30),
                task("t-ok", maestro_shell::AgentTaskState::Succeeded, None, 20),
                task(
                    "t-cancel",
                    maestro_shell::AgentTaskState::Cancelled,
                    None,
                    10,
                ),
            ],
            vec![],
        )];
        let out = project_task_results(&snapshot_of(projects));
        // Sorted desc: t-fail(30), t-ok(20), t-cancel(10).
        assert!(out.task_results[0].is_failure);
        assert!(!out.task_results[1].is_failure);
        assert!(!out.task_results[2].is_failure);
    }

    #[test]
    fn task_results_summary_present_and_absent() {
        let projects = vec![project_with(
            vec![
                terminal_task(
                    "t-fail",
                    maestro_shell::AgentTaskState::Failed,
                    Some("tests failed"),
                    Some("sess-1"),
                    20,
                ),
                terminal_task(
                    "t-ok",
                    maestro_shell::AgentTaskState::Succeeded,
                    None,
                    None,
                    10,
                ),
            ],
            vec![],
        )];
        let out = project_task_results(&snapshot_of(projects));
        assert_eq!(out.task_results[0].summary.as_deref(), Some("tests failed"));
        assert_eq!(
            out.task_results[0].current_session_id.as_deref(),
            Some("sess-1")
        );
        assert_eq!(out.task_results[1].summary, None);
        assert_eq!(out.task_results[1].current_session_id, None);
    }

    #[test]
    fn task_results_snapshot_serializes_compact_shape() {
        let projects = vec![project_with(
            vec![terminal_task(
                "task-1",
                maestro_shell::AgentTaskState::Failed,
                Some("tests failed"),
                Some("sess-1"),
                123,
            )],
            vec![],
        )];
        let out = project_task_results(&snapshot_of(projects));
        let wrapped = DashboardSuccess::new(s("/base"), out);
        let v: serde_json::Value = serde_json::to_value(&wrapped).unwrap();
        assert_eq!(v["command"], serde_json::json!("dashboard"));
        let row = &v["snapshot"]["task_results"][0];
        assert_eq!(row["agent_task_id"], "task-1");
        assert_eq!(row["project_id"], "project-1");
        assert_eq!(row["goal"], "goal for task-1");
        assert_eq!(row["state"], "failed");
        assert_eq!(row["summary"], "tests failed");
        assert_eq!(row["current_session_id"], "sess-1");
        assert_eq!(row["updated_at_ms"], 123);
        assert_eq!(row["is_failure"], true);
        // Compact shape: no full-dashboard `projects` key in the snapshot.
        assert!(v["snapshot"]["projects"].is_null());
    }

    #[test]
    fn task_results_absent_summary_serializes_null() {
        let projects = vec![project_with(
            vec![terminal_task(
                "task-1",
                maestro_shell::AgentTaskState::Succeeded,
                None,
                None,
                1,
            )],
            vec![],
        )];
        let out = project_task_results(&snapshot_of(projects));
        let v: serde_json::Value = serde_json::to_value(&out).unwrap();
        assert!(v["task_results"][0]["summary"].is_null());
        assert!(v["task_results"][0]["current_session_id"].is_null());
        assert_eq!(v["task_results"][0]["is_failure"], false);
    }

    // ---- dashboard view model ---------------------------------------------------------------
    //
    // These tests exercise `build_dashboard_view_model` / `DashboardViewModel` /
    // `DashboardStateCounts`, all defined in this module. They reuse the
    // `task`/`dash_tab`/`project_with`/`snapshot_of`/`unseen_needs_input`/`terminal_task`/`s`
    // helper copies already present in the dashboard tests above.

    #[test]
    fn view_model_active_rows_match_project_active_tasks() {
        let tabs = vec![maestro_shell::DashboardWindow {
            window_id: "w1".to_string(),
            name: None,
            tabs: vec![dash_tab(
                "w1",
                "tab-1",
                "sess-1",
                0,
                unseen_needs_input(),
                Some(maestro_shell::SessionStatus::Live),
                true,
            )],
        }];
        let projects = vec![project_with(
            vec![
                task(
                    "t-run",
                    maestro_shell::AgentTaskState::Running,
                    Some("sess-1"),
                    10,
                ),
                task("t-block", maestro_shell::AgentTaskState::Blocked, None, 30),
                task("t-draft", maestro_shell::AgentTaskState::Draft, None, 40),
                terminal_task(
                    "t-ok",
                    maestro_shell::AgentTaskState::Succeeded,
                    Some("done"),
                    None,
                    50,
                ),
            ],
            tabs,
        )];
        let snapshot = snapshot_of(projects);
        let vm = build_dashboard_view_model(&snapshot);
        assert_eq!(
            vm.active_tasks,
            project_active_tasks(&snapshot).active_tasks
        );
    }

    #[test]
    fn view_model_result_rows_match_project_task_results() {
        let projects = vec![project_with(
            vec![
                task("t-run", maestro_shell::AgentTaskState::Running, None, 10),
                terminal_task(
                    "t-ok",
                    maestro_shell::AgentTaskState::Succeeded,
                    Some("done"),
                    None,
                    50,
                ),
                terminal_task(
                    "t-fail",
                    maestro_shell::AgentTaskState::Failed,
                    Some("boom"),
                    None,
                    60,
                ),
            ],
            vec![],
        )];
        let snapshot = snapshot_of(projects);
        let vm = build_dashboard_view_model(&snapshot);
        assert_eq!(
            vm.task_results,
            project_task_results(&snapshot).task_results
        );
    }

    #[test]
    fn view_model_counts_all_states_including_draft_and_terminal() {
        let projects = vec![project_with(
            vec![
                task("t-draft", maestro_shell::AgentTaskState::Draft, None, 1),
                task("t-run", maestro_shell::AgentTaskState::Running, None, 2),
                task(
                    "t-wait",
                    maestro_shell::AgentTaskState::WaitingOnUser,
                    None,
                    3,
                ),
                task("t-block", maestro_shell::AgentTaskState::Blocked, None, 4),
                task("t-ok", maestro_shell::AgentTaskState::Succeeded, None, 5),
                task("t-fail", maestro_shell::AgentTaskState::Failed, None, 6),
                task(
                    "t-cancel",
                    maestro_shell::AgentTaskState::Cancelled,
                    None,
                    7,
                ),
            ],
            vec![],
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        assert_eq!(vm.counts.draft, 1);
        assert_eq!(vm.counts.running, 1);
        assert_eq!(vm.counts.waiting_on_user, 1);
        assert_eq!(vm.counts.blocked, 1);
        assert_eq!(vm.counts.succeeded, 1);
        assert_eq!(vm.counts.failed, 1);
        assert_eq!(vm.counts.cancelled, 1);
    }

    #[test]
    fn view_model_empty_snapshot_zero_counts_and_attention() {
        let vm = build_dashboard_view_model(&snapshot_of(vec![]));
        assert_eq!(vm.counts, DashboardStateCounts::default());
        assert_eq!(vm.attention_count, 0);
        assert!(vm.active_tasks.is_empty());
        assert!(vm.task_results.is_empty());
    }

    #[test]
    fn view_model_attention_count_counts_only_active_needs_attention() {
        let tabs = vec![maestro_shell::DashboardWindow {
            window_id: "w1".to_string(),
            name: None,
            tabs: vec![
                dash_tab(
                    "w1",
                    "tab-a",
                    "sess-a",
                    0,
                    unseen_needs_input(),
                    Some(maestro_shell::SessionStatus::Live),
                    true,
                ),
                dash_tab(
                    "w1",
                    "tab-b",
                    "sess-b",
                    1,
                    maestro_shell::AttentionState::default(),
                    Some(maestro_shell::SessionStatus::Live),
                    false,
                ),
            ],
        }];
        let projects = vec![project_with(
            vec![
                task(
                    "a-attn",
                    maestro_shell::AgentTaskState::Running,
                    Some("sess-a"),
                    10,
                ),
                task(
                    "a-calm",
                    maestro_shell::AgentTaskState::Running,
                    Some("sess-b"),
                    20,
                ),
            ],
            tabs,
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        // Two active rows, exactly one needs attention.
        assert_eq!(vm.active_tasks.len(), 2);
        assert_eq!(vm.attention_count, 1);
    }

    #[test]
    fn view_model_serialized_shape_carries_projects_array() {
        let projects = vec![project_with(
            vec![
                task("t-run", maestro_shell::AgentTaskState::Running, None, 10),
                terminal_task(
                    "t-ok",
                    maestro_shell::AgentTaskState::Succeeded,
                    Some("done"),
                    None,
                    50,
                ),
            ],
            vec![],
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let v: serde_json::Value = serde_json::to_value(&vm).unwrap();
        assert!(v["active_tasks"].is_array());
        assert!(v["task_results"].is_array());
        assert!(v["counts"].is_object());
        assert!(v["attention_count"].is_number());
        // The view model carries the project sidebar array (the COMPACT panel does not).
        assert!(v["projects"].is_array());
    }

    #[test]
    fn view_model_nested_optionals_serialize_null() {
        // An active task with no visible tab leaves placement/session-status null; a terminal
        // task with no summary leaves summary/current_session_id null. The view model reuses the
        // row projections verbatim, so those nulls flow through unchanged.
        let projects = vec![project_with(
            vec![
                task(
                    "t-block",
                    maestro_shell::AgentTaskState::Blocked,
                    Some("sess-missing"),
                    10,
                ),
                terminal_task(
                    "t-ok",
                    maestro_shell::AgentTaskState::Succeeded,
                    None,
                    None,
                    50,
                ),
            ],
            vec![],
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let v: serde_json::Value = serde_json::to_value(&vm).unwrap();
        assert!(v["active_tasks"][0]["window_id"].is_null());
        assert!(v["active_tasks"][0]["tab_id"].is_null());
        assert!(v["active_tasks"][0]["session_status"].is_null());
        assert!(v["task_results"][0]["summary"].is_null());
        assert!(v["task_results"][0]["current_session_id"].is_null());
    }

    #[test]
    fn view_model_is_failure_true_only_for_failed_results() {
        let projects = vec![project_with(
            vec![
                terminal_task(
                    "t-ok",
                    maestro_shell::AgentTaskState::Succeeded,
                    Some("done"),
                    None,
                    50,
                ),
                terminal_task(
                    "t-fail",
                    maestro_shell::AgentTaskState::Failed,
                    Some("boom"),
                    None,
                    60,
                ),
                terminal_task(
                    "t-cancel",
                    maestro_shell::AgentTaskState::Cancelled,
                    None,
                    None,
                    70,
                ),
            ],
            vec![],
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let by_id = |id: &str| {
            vm.task_results
                .iter()
                .find(|r| r.agent_task_id == id)
                .unwrap_or_else(|| panic!("missing {id}"))
        };
        assert!(!by_id("t-ok").is_failure);
        assert!(by_id("t-fail").is_failure);
        assert!(!by_id("t-cancel").is_failure);
    }

    // ---- stashed-tab (revive) projection ----------------------------------------------------

    /// A stashed dashboard tab in `window_id` at `index`, otherwise inert.
    fn stashed_dash_tab(window_id: &str, tab_id: &str, index: u32) -> maestro_shell::DashboardTab {
        let mut t = dash_tab(
            window_id,
            tab_id,
            &format!("{tab_id}-sess"),
            index,
            maestro_shell::AttentionState::default(),
            None,
            false,
        );
        t.stashed = true;
        t
    }

    #[test]
    fn project_stashed_tabs_selects_only_stashed_and_sorts_by_window_index_tab() {
        // p1/w1: one live (excluded) + one stashed; an unassigned window with a stashed tab too.
        let live = dash_tab(
            "w1",
            "live",
            "s-live",
            0,
            maestro_shell::AttentionState::default(),
            None,
            false,
        );
        let projects = vec![project_with(
            vec![],
            vec![maestro_shell::DashboardWindow {
                window_id: "w1".to_string(),
                name: None,
                tabs: vec![
                    live,
                    stashed_dash_tab("w1", "z", 2),
                    stashed_dash_tab("w1", "a", 1),
                ],
            }],
        )];
        let mut snap = snapshot_of(projects);
        snap.unassigned_windows = vec![maestro_shell::DashboardWindow {
            window_id: "w0".to_string(),
            name: None,
            tabs: vec![stashed_dash_tab("w0", "u", 0)],
        }];

        let out = project_stashed_tabs(&snap);
        // Sorted by window_id asc (w0 before w1), then index (a@1 before z@2). Live tab excluded.
        let ids: Vec<(&str, &str)> = out
            .stashed_tabs
            .iter()
            .map(|r| (r.window_id.as_str(), r.tab_id.as_str()))
            .collect();
        assert_eq!(ids, vec![("w0", "u"), ("w1", "a"), ("w1", "z")]);
    }

    #[test]
    fn view_model_carries_stashed_tabs() {
        let projects = vec![project_with(
            vec![],
            vec![maestro_shell::DashboardWindow {
                window_id: "w1".to_string(),
                name: None,
                tabs: vec![stashed_dash_tab("w1", "t1", 0)],
            }],
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        assert_eq!(vm.stashed_tabs.len(), 1);
        assert_eq!(vm.stashed_tabs[0].tab_id, "t1");
    }

    #[test]
    fn panel_lines_render_stashed_section_with_revive_row_identity() {
        let projects = vec![project_with(
            vec![],
            vec![maestro_shell::DashboardWindow {
                window_id: "w1".to_string(),
                name: None,
                tabs: vec![stashed_dash_tab("w1", "t1", 0)],
            }],
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        // A Stashed header + one revive row line appear; bookkeeping reflects the single tab.
        assert_eq!(panel.stashed_tabs_total, 1);
        assert_eq!(panel.stashed_tabs_shown, 1);
        assert!(
            panel.lines.iter().any(|l| l.starts_with("Stashed (1/1)")),
            "lines: {:?}",
            panel.lines
        );
        // The revive row carries StashedTab kind + the tab's window/tab identity for the click seam.
        let revive_row = panel
            .rows
            .iter()
            .find(|r| r.kind == DashboardPanelRowKind::StashedTab)
            .expect("a stashed revive row");
        assert_eq!(revive_row.window_id.as_deref(), Some("w1"));
        assert_eq!(revive_row.tab_id.as_deref(), Some("t1"));

        // Projected to the renderer, the row carries the REVIVE target (not a focus target).
        let renderer = dashboard_panel_to_renderer(&panel);
        let rr = renderer
            .dashboard_rows
            .iter()
            .find(|r| r.revive_tab_id.is_some())
            .expect("a renderer revive row");
        assert_eq!(rr.revive_window_id.as_deref(), Some("w1"));
        assert_eq!(rr.revive_tab_id.as_deref(), Some("t1"));
        assert_eq!(rr.focus_tab_id, None);
    }

    #[test]
    fn panel_lines_no_stashed_section_when_no_dormant_tabs() {
        // A tree with an active task but no stashed tabs keeps the prior shape: no Stashed header.
        let projects = vec![project_with(
            vec![task(
                "a-run",
                maestro_shell::AgentTaskState::Running,
                None,
                10,
            )],
            vec![],
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        assert_eq!(panel.stashed_tabs_total, 0);
        assert!(
            !panel.lines.iter().any(|l| l.starts_with("Stashed")),
            "no Stashed section expected, lines: {:?}",
            panel.lines
        );
    }

    // ---- dashboard panel-line rendering -----------------------------------------------------
    //
    // These tests live beside `DashboardPanelLimits` / `DashboardPanelLines` /
    // `build_dashboard_panel_lines`. The pure `--panel-lines` CLI parser tests live in
    // `cli::tests`.

    #[test]
    fn panel_lines_include_title_summary_and_both_sections_for_mixed_data() {
        let projects = vec![project_with(
            vec![
                task("a-run", maestro_shell::AgentTaskState::Running, None, 10),
                terminal_task(
                    "t-ok",
                    maestro_shell::AgentTaskState::Succeeded,
                    Some("done well"),
                    None,
                    50,
                ),
            ],
            vec![],
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        assert_eq!(panel.title, "Dashboard");
        assert!(panel.summary.contains("running=1"));
        assert!(panel.summary.contains("succeeded=1"));
        assert_eq!(panel.lines.first().unwrap(), "Dashboard");
        assert!(panel.lines.iter().any(|l| l.starts_with("Active (")));
        assert!(panel.lines.iter().any(|l| l.starts_with("Recent (")));
        assert!(panel.lines.iter().any(|l| l.contains("[running]")));
        assert!(panel.lines.iter().any(|l| l.contains("done well")));
        assert_eq!(panel.active_tasks_total, 1);
        assert_eq!(panel.active_tasks_shown, 1);
        assert_eq!(panel.task_results_total, 1);
        assert_eq!(panel.task_results_shown, 1);
    }

    #[test]
    fn panel_lines_empty_view_model_has_explicit_empty_state_line() {
        let vm = build_dashboard_view_model(&snapshot_of(vec![]));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        assert!(panel
            .lines
            .iter()
            .any(|l| l == "(no active tasks or recent results)"));
        assert_eq!(panel.active_tasks_total, 0);
        assert_eq!(panel.active_tasks_shown, 0);
        assert_eq!(panel.task_results_total, 0);
        assert_eq!(panel.task_results_shown, 0);
        // No section headers when both are empty.
        assert!(!panel.lines.iter().any(|l| l.starts_with("Active (")));
        assert!(!panel.lines.iter().any(|l| l.starts_with("Recent (")));
    }

    #[test]
    fn panel_lines_limits_truncate_shown_rows_but_keep_totals() {
        let mut tasks = Vec::new();
        for i in 0..5 {
            tasks.push(task(
                &format!("a-{i}"),
                maestro_shell::AgentTaskState::Running,
                None,
                100 - i as u64,
            ));
        }
        for i in 0..5 {
            tasks.push(terminal_task(
                &format!("t-{i}"),
                maestro_shell::AgentTaskState::Succeeded,
                Some("ok"),
                None,
                50 - i as u64,
            ));
        }
        let vm = build_dashboard_view_model(&snapshot_of(vec![project_with(tasks, vec![])]));
        let limits = DashboardPanelLimits {
            max_active_tasks: 2,
            max_task_results: 3,
            ..DashboardPanelLimits::default()
        };
        let panel = build_dashboard_panel_lines(&vm, limits);
        assert_eq!(panel.active_tasks_total, 5);
        assert_eq!(panel.active_tasks_shown, 2);
        assert_eq!(panel.task_results_total, 5);
        assert_eq!(panel.task_results_shown, 3);
        assert!(panel.lines.iter().any(|l| l == "+3 more active"));
        assert!(panel.lines.iter().any(|l| l == "+2 more results"));
    }

    #[test]
    fn panel_lines_preserve_view_model_ordering() {
        // updated_at_ms descending order is decided by the view model; the panel must not re-sort.
        let tasks = vec![
            task("a-old", maestro_shell::AgentTaskState::Running, None, 1),
            task("a-new", maestro_shell::AgentTaskState::Running, None, 99),
            terminal_task(
                "t-old",
                maestro_shell::AgentTaskState::Succeeded,
                Some("old-result"),
                None,
                2,
            ),
            terminal_task(
                "t-new",
                maestro_shell::AgentTaskState::Succeeded,
                Some("new-result"),
                None,
                98,
            ),
        ];
        let vm = build_dashboard_view_model(&snapshot_of(vec![project_with(tasks, vec![])]));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        // Active rows mirror vm.active_tasks order (goal text carries the id).
        let active_goals: Vec<&String> = panel
            .lines
            .iter()
            .filter(|l| l.contains("goal for"))
            .collect();
        let vm_active_goals: Vec<String> = vm.active_tasks.iter().map(|r| r.goal.clone()).collect();
        let panel_active: Vec<String> = active_goals.iter().map(|l| l.to_string()).collect();
        for (g, l) in vm_active_goals.iter().zip(panel_active.iter()) {
            assert!(l.contains(g.as_str()), "{l} should contain {g}");
        }
        // Result rows mirror vm.task_results order (summary carries old/new).
        let result_summaries: Vec<&String> = panel
            .lines
            .iter()
            .filter(|l| l.contains("-result"))
            .collect();
        let vm_result_order: Vec<&str> = vm
            .task_results
            .iter()
            .map(|r| r.summary.as_deref().unwrap_or(""))
            .collect();
        for (s, l) in vm_result_order.iter().zip(result_summaries.iter()) {
            assert!(l.contains(s), "{l} should contain {s}");
        }
    }

    #[test]
    fn panel_lines_truncate_long_goals_and_summaries_deterministically() {
        let long_goal = "G".repeat(200);
        let long_summary = "S".repeat(200);
        let mut t = task("a-long", maestro_shell::AgentTaskState::Running, None, 10);
        t.goal = long_goal.clone();
        let term = maestro_shell::AgentTask {
            result_summary: Some(long_summary.clone()),
            ..terminal_task(
                "t-long",
                maestro_shell::AgentTaskState::Succeeded,
                None,
                None,
                50,
            )
        };
        let vm =
            build_dashboard_view_model(&snapshot_of(vec![project_with(vec![t, term], vec![])]));
        let limits = DashboardPanelLimits {
            max_goal_chars: 10,
            max_summary_chars: 12,
            ..DashboardPanelLimits::default()
        };
        let panel = build_dashboard_panel_lines(&vm, limits);
        let goal_line = panel
            .lines
            .iter()
            .find(|l| l.contains('…') && l.contains('G'))
            .expect("truncated goal line");
        // The truncated goal portion is exactly max_goal_chars chars ending with the marker.
        let goal_part = goal_line.split("] ").nth(1).unwrap();
        assert_eq!(goal_part.chars().count(), 10);
        assert!(goal_part.ends_with('…'));
        let summary_line = panel
            .lines
            .iter()
            .find(|l| l.contains('…') && l.contains('S'))
            .expect("truncated summary line");
        let summary_part = summary_line.split("] ").nth(1).unwrap();
        assert_eq!(summary_part.chars().count(), 12);
        assert!(summary_part.ends_with('…'));
        // Determinism: same inputs produce identical output.
        let again = build_dashboard_panel_lines(&vm, limits);
        assert_eq!(panel, again);
    }

    #[test]
    fn panel_lines_strip_control_characters_from_display_strings() {
        let mut t = task("a-ctrl", maestro_shell::AgentTaskState::Running, None, 10);
        t.goal = "line1\nline2\tend\u{7}bell".to_string();
        let vm = build_dashboard_view_model(&snapshot_of(vec![project_with(vec![t], vec![])]));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        let goal_line = panel
            .lines
            .iter()
            .find(|l| l.contains("line1"))
            .expect("goal line");
        assert!(!goal_line.contains('\n'));
        assert!(!goal_line.contains('\t'));
        assert!(!goal_line.contains('\u{7}'));
        assert!(goal_line.contains("line1 line2 end bell"));
    }

    #[test]
    fn panel_lines_serialized_shape_has_required_fields_without_projects() {
        let projects = vec![project_with(
            vec![
                task("a-run", maestro_shell::AgentTaskState::Running, None, 10),
                terminal_task(
                    "t-ok",
                    maestro_shell::AgentTaskState::Succeeded,
                    Some("done"),
                    None,
                    50,
                ),
            ],
            vec![],
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        let v: serde_json::Value = serde_json::to_value(&panel).unwrap();
        assert!(v["title"].is_string());
        assert!(v["summary"].is_string());
        assert!(v["lines"].is_array());
        assert!(v["active_tasks_total"].is_number());
        assert!(v["active_tasks_shown"].is_number());
        assert!(v["task_results_total"].is_number());
        assert!(v["task_results_shown"].is_number());
        assert!(v["attention_count"].is_number());
        // The compact panel carries no full-dashboard `projects` array.
        assert!(v["projects"].is_null());
    }

    // ---- active-project identity + branded header --------------------------------------------

    fn project_branded(
        id: &str,
        name: &str,
        icon: Option<&str>,
        accent: Option<&str>,
        last_active_at_ms: u64,
    ) -> maestro_shell::ProjectSnapshot {
        maestro_shell::ProjectSnapshot {
            project_id: id.to_string(),
            name: name.to_string(),
            root: format!("/{id}"),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            last_active_at_ms,
            icon: icon.map(str::to_string),
            accent_color: accent.map(str::to_string),
            launch_defaults: None,
            directories: Vec::new(),
            system: false,
            hidden: false,
            workspaces: vec![],
            tasks: vec![],
            windows: vec![],
        }
    }

    #[test]
    fn view_model_active_project_is_first_snapshot_project() {
        // Snapshot projects arrive already sorted last_active desc; the view model takes [0].
        let projects = vec![
            project_branded("p-new", "Newest", Some("🚀"), Some("#4f8cff"), 200),
            project_branded("p-old", "Older", None, None, 100),
        ];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let active = vm.active_project.expect("active project present");
        assert_eq!(active.project_id, "p-new");
        assert_eq!(active.name, "Newest");
        assert_eq!(active.icon.as_deref(), Some("🚀"));
        assert_eq!(active.accent_color.as_deref(), Some("#4f8cff"));
    }

    #[test]
    fn view_model_active_project_none_without_projects() {
        let vm = build_dashboard_view_model(&snapshot_of(vec![]));
        assert!(vm.active_project.is_none());
    }

    #[test]
    fn view_model_projects_list_preserves_order_and_flags_first_active() {
        let projects = vec![
            project_branded("p-new", "Newest", Some("🚀"), Some("#4f8cff"), 200),
            project_branded("p-mid", "Middle", None, None, 150),
            project_branded("p-old", "Older", None, None, 100),
        ];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let ids: Vec<&str> = vm.projects.iter().map(|p| p.project_id.as_str()).collect();
        assert_eq!(ids, ["p-new", "p-mid", "p-old"]);
        assert!(vm.projects[0].is_active);
        assert!(!vm.projects[1].is_active);
        assert!(!vm.projects[2].is_active);
        // Branding + policy pass through verbatim.
        assert_eq!(vm.projects[0].name, "Newest");
        assert_eq!(vm.projects[0].icon.as_deref(), Some("🚀"));
        assert_eq!(vm.projects[0].accent_color.as_deref(), Some("#4f8cff"));
        assert_eq!(
            vm.projects[0].default_workspace_policy,
            maestro_shell::WorkspacePolicy::ScratchCwd
        );
    }

    #[test]
    fn view_model_excludes_recovery_project_but_keeps_ordinary_hidden_project() {
        let mut recovery =
            project_branded(PRODUCT_RECOVERY_PROJECT_ID, "Recovery", None, None, 300);
        recovery.hidden = true;
        let mut recovery_active = task(
            "recovery-running",
            maestro_shell::AgentTaskState::Running,
            None,
            30,
        );
        recovery_active.project_id = PRODUCT_RECOVERY_PROJECT_ID.to_string();
        let mut recovery_failed = terminal_task(
            "recovery-failed",
            maestro_shell::AgentTaskState::Failed,
            Some("internal"),
            None,
            31,
        );
        recovery_failed.project_id = PRODUCT_RECOVERY_PROJECT_ID.to_string();
        let mut recovery_tab = dash_tab(
            "recovery-window",
            "recovery-tab",
            "recovery-session",
            0,
            maestro_shell::AttentionState::default(),
            Some(maestro_shell::SessionStatus::Live),
            false,
        );
        recovery_tab.stashed = true;
        recovery.tasks = vec![recovery_active, recovery_failed];
        recovery.windows = vec![maestro_shell::DashboardWindow {
            window_id: "recovery-window".to_string(),
            name: None,
            tabs: vec![recovery_tab],
        }];

        let mut hidden_user = project_branded("hidden-user", "Hidden User", None, None, 200);
        hidden_user.hidden = true;
        let mut user_active = task(
            "user-running",
            maestro_shell::AgentTaskState::Running,
            None,
            20,
        );
        user_active.project_id = "hidden-user".to_string();
        let mut user_tab = dash_tab(
            "user-window",
            "user-tab",
            "user-session",
            0,
            maestro_shell::AttentionState::default(),
            None,
            false,
        );
        user_tab.stashed = true;
        hidden_user.tasks = vec![user_active];
        hidden_user.windows = vec![maestro_shell::DashboardWindow {
            window_id: "user-window".to_string(),
            name: None,
            tabs: vec![user_tab],
        }];

        let vm = build_dashboard_view_model(&snapshot_of(vec![recovery, hidden_user]));

        assert_eq!(
            vm.projects
                .iter()
                .map(|project| project.project_id.as_str())
                .collect::<Vec<_>>(),
            vec!["hidden-user"]
        );
        assert!(vm.projects[0].is_active);
        assert_eq!(
            vm.active_project
                .as_ref()
                .map(|project| project.project_id.as_str()),
            Some("hidden-user")
        );
        assert_eq!(
            vm.active_tasks
                .iter()
                .map(|task| task.agent_task_id.as_str())
                .collect::<Vec<_>>(),
            vec!["user-running"]
        );
        assert!(vm.task_results.is_empty());
        assert_eq!(
            vm.stashed_tabs
                .iter()
                .map(|tab| tab.tab_id.as_str())
                .collect::<Vec<_>>(),
            vec!["user-tab"]
        );
        assert_eq!(vm.counts.running, 1);
        assert_eq!(vm.counts.failed, 0);
    }

    #[test]
    fn view_model_projects_list_is_empty_without_projects() {
        let vm = build_dashboard_view_model(&snapshot_of(vec![]));
        assert!(vm.projects.is_empty());
    }

    #[test]
    fn view_model_project_row_counts_active_tasks_and_windows() {
        let mut p = project_branded("p1", "Counts", None, None, 100);
        p.tasks = vec![
            task("t-run", maestro_shell::AgentTaskState::Running, None, 1),
            task(
                "t-wait",
                maestro_shell::AgentTaskState::WaitingOnUser,
                None,
                2,
            ),
            task("t-block", maestro_shell::AgentTaskState::Blocked, None, 3),
            // Draft + terminal states do NOT count as active.
            task("t-draft", maestro_shell::AgentTaskState::Draft, None, 4),
            task("t-done", maestro_shell::AgentTaskState::Succeeded, None, 5),
        ];
        p.windows = vec![
            maestro_shell::DashboardWindow {
                window_id: "w1".to_string(),
                name: None,
                tabs: vec![],
            },
            maestro_shell::DashboardWindow {
                window_id: "w2".to_string(),
                name: None,
                tabs: vec![],
            },
        ];
        let vm = build_dashboard_view_model(&snapshot_of(vec![p]));
        assert_eq!(vm.projects[0].active_task_count, 3);
        assert_eq!(vm.projects[0].window_count, 2);
    }

    #[test]
    fn panel_renders_projects_section_with_active_marker_and_select_rows() {
        let projects = vec![
            project_branded("p-new", "Newest", Some("🚀"), None, 200),
            project_branded("p-old", "Older", None, None, 100),
        ];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        assert_eq!(panel.projects_total, 2);
        assert_eq!(panel.projects_shown, 2);
        // A `Projects (n/n)` header line appears, then one row per project.
        assert!(panel.lines.iter().any(|l| l == "Projects (2/2)"));
        // Active project uses the filled marker + icon; inactive uses the hollow marker.
        assert!(panel.lines.iter().any(|l| l == "● 🚀 Newest 0/0"));
        assert!(panel.lines.iter().any(|l| l == "○ Older 0/0"));
        // The aligned rows carry the project-select identity for exactly the two project rows.
        let select_ids: Vec<&str> = panel
            .rows
            .iter()
            .filter(|r| r.kind == DashboardPanelRowKind::Project)
            .filter_map(|r| r.project_id.as_deref())
            .collect();
        assert_eq!(select_ids, ["p-new", "p-old"]);
    }

    #[test]
    fn panel_projects_section_absent_without_projects() {
        let vm = build_dashboard_view_model(&snapshot_of(vec![]));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        assert_eq!(panel.projects_total, 0);
        assert!(!panel.lines.iter().any(|l| l.starts_with("Projects (")));
    }

    #[test]
    fn panel_projects_section_caps_rows_and_reports_more() {
        let projects: Vec<_> = (0..10)
            .map(|i| project_branded(&format!("p{i}"), &format!("P{i}"), None, None, 1000 - i))
            .collect();
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let limits = DashboardPanelLimits {
            max_projects: 3,
            ..DashboardPanelLimits::default()
        };
        let panel = build_dashboard_panel_lines(&vm, limits);
        assert_eq!(panel.projects_total, 10);
        assert_eq!(panel.projects_shown, 3);
        assert!(panel.lines.iter().any(|l| l == "+7 more projects"));
    }

    #[test]
    fn dashboard_panel_to_renderer_carries_select_project_id_only_on_project_rows() {
        let projects = vec![project_branded("p1", "Solo", None, None, 100)];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        let renderer = dashboard_panel_to_renderer(&panel);
        let select_rows: Vec<&str> = renderer
            .dashboard_rows
            .iter()
            .filter_map(|r| r.select_project_id.as_deref())
            .collect();
        assert_eq!(select_rows, ["p1"]);
        // A project row carries no focus/revive target (exactly one actionable target per row).
        for r in &renderer.dashboard_rows {
            if r.select_project_id.is_some() {
                assert!(r.focus_tab_id.is_none());
                assert!(r.revive_tab_id.is_none());
            }
        }
    }

    #[test]
    fn panel_emits_branded_header_with_icon_and_carries_accent() {
        let projects = vec![project_branded(
            "p1",
            "My Project",
            Some("🚀"),
            Some("#4f8cff"),
            10,
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        // Header is row 1 (right after the "Dashboard" title), before the counts summary.
        assert_eq!(panel.lines[0], "Dashboard");
        assert_eq!(panel.lines[1], "🚀 My Project");
        assert_eq!(panel.accent_color.as_deref(), Some("#4f8cff"));
    }

    #[test]
    fn panel_header_omits_icon_when_absent_and_no_accent_stays_none() {
        let projects = vec![project_branded("p1", "Plain", None, None, 10)];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        assert_eq!(panel.lines[1], "Plain");
        assert!(panel.accent_color.is_none());
    }

    #[test]
    fn panel_without_projects_has_no_header_and_keeps_prior_shape() {
        let vm = build_dashboard_view_model(&snapshot_of(vec![]));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        // No project => title is immediately followed by the counts summary (no header line).
        assert_eq!(panel.lines[0], "Dashboard");
        assert!(panel.lines[1].starts_with("running="));
        assert!(panel.accent_color.is_none());
    }

    #[test]
    fn panel_to_renderer_carries_accent_across_boundary() {
        let projects = vec![project_branded(
            "p1",
            "Tinted",
            Some("◆"),
            Some("#abcdef"),
            10,
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));
        let panel = build_dashboard_panel_lines(&vm, DashboardPanelLimits::default());
        let r = dashboard_panel_to_renderer(&panel);
        assert_eq!(r.accent_color.as_deref(), Some("#abcdef"));
    }

    // ---- dashboard status suffix ------------------------------------------------------------
    // These tests live beside `dashboard_status_suffix` (and `build_dashboard_view_model`).

    #[test]
    fn dashboard_status_suffix_includes_stable_fields_with_zeros() {
        // Empty snapshot => every count is zero, but every field is still present (stable shape).
        let vm = build_dashboard_view_model(&snapshot_of(vec![]));
        assert_eq!(
            dashboard_status_suffix(&vm),
            "[active=0 waiting=0 blocked=0 failed=0 attn=0]"
        );
    }

    #[test]
    fn dashboard_status_suffix_is_ascii_only() {
        let vm = build_dashboard_view_model(&snapshot_of(vec![]));
        let suffix = dashboard_status_suffix(&vm);
        assert!(suffix.is_ascii(), "suffix must be ASCII-only: {suffix}");
    }

    #[test]
    fn dashboard_status_suffix_derives_from_view_model_counts_and_attention() {
        // One running + one waiting + one blocked active task (attention on two of them),
        // plus a failed terminal task. The suffix must read directly off the view model:
        //   active = active_tasks.len() (running+waiting+blocked = 3),
        //   waiting = counts.waiting_on_user, blocked = counts.blocked,
        //   failed = counts.failed, attn = attention_count.
        let mut wait = task(
            "t-wait",
            maestro_shell::AgentTaskState::WaitingOnUser,
            Some("sess-wait"),
            20,
        );
        wait.result_summary = None;
        let tabs = vec![maestro_shell::DashboardWindow {
            window_id: "w1".to_string(),
            name: None,
            tabs: vec![
                dash_tab(
                    "w1",
                    "t1",
                    "sess-run",
                    0,
                    unseen_needs_input(),
                    Some(maestro_shell::SessionStatus::Live),
                    true,
                ),
                dash_tab(
                    "w1",
                    "t2",
                    "sess-wait",
                    1,
                    unseen_needs_input(),
                    Some(maestro_shell::SessionStatus::Live),
                    true,
                ),
                dash_tab(
                    "w1",
                    "t3",
                    "sess-block",
                    2,
                    maestro_shell::AttentionState::default(),
                    Some(maestro_shell::SessionStatus::Live),
                    false,
                ),
            ],
        }];
        let projects = vec![project_with(
            vec![
                task(
                    "t-run",
                    maestro_shell::AgentTaskState::Running,
                    Some("sess-run"),
                    10,
                ),
                wait,
                task(
                    "t-block",
                    maestro_shell::AgentTaskState::Blocked,
                    Some("sess-block"),
                    30,
                ),
                task(
                    "t-fail",
                    maestro_shell::AgentTaskState::Failed,
                    Some("sess-fail"),
                    40,
                ),
            ],
            tabs,
        )];
        let vm = build_dashboard_view_model(&snapshot_of(projects));

        // The suffix is a pure projection of the view model — assert it equals a string built
        // from the SAME view-model fields, not a second task-state mapping.
        let expected = format!(
            "[active={} waiting={} blocked={} failed={} attn={}]",
            vm.active_tasks.len(),
            vm.counts.waiting_on_user,
            vm.counts.blocked,
            vm.counts.failed,
            vm.attention_count,
        );
        assert_eq!(dashboard_status_suffix(&vm), expected);

        // And the concrete values for this fixture.
        assert_eq!(vm.active_tasks.len(), 3);
        assert_eq!(vm.counts.waiting_on_user, 1);
        assert_eq!(vm.counts.blocked, 1);
        assert_eq!(vm.counts.failed, 1);
        assert_eq!(vm.attention_count, 2);
        assert_eq!(
            dashboard_status_suffix(&vm),
            "[active=3 waiting=1 blocked=1 failed=1 attn=2]"
        );
    }

    // The dashboard success/failure JSON envelope DTO tests live here beside `DashboardSuccess` and
    // `DashboardFailure`. (The dashboard CLI parser tests live in `cli::tests`; the projection/
    // view-model/panel-line/picker/status-suffix tests stay in their owning modules.)

    #[test]
    fn dashboard_reconciled_success_carries_metadata() {
        let ok = DashboardSuccess::reconciled(
            s("/resolved/base"),
            s("/run/m.sock"),
            serde_json::json!({ "projects": [] }),
        );
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["session_reconcile"], serde_json::json!(true));
        assert_eq!(v["socket_path"], serde_json::json!("/run/m.sock"));
    }

    #[test]
    fn dashboard_default_success_reports_no_reconcile() {
        let ok = DashboardSuccess::new(s("/resolved/base"), serde_json::json!({ "projects": [] }));
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["session_reconcile"], serde_json::json!(false));
        assert_eq!(v["socket_path"], serde_json::Value::Null);
    }

    #[test]
    fn dashboard_success_wrapper_serializes_contract_fields() {
        // A stand-in snapshot value: DashboardSuccess is generic, so we can test the wrapper
        // shape without depending on the real DashboardSnapshot type.
        let ok = DashboardSuccess::new(
            s("/resolved/base"),
            serde_json::json!({ "projects": [], "unassigned_windows": [] }),
        );
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["command"], serde_json::json!("dashboard"));
        assert_eq!(v["base"], serde_json::json!("/resolved/base"));
        assert_eq!(v["snapshot"]["projects"], serde_json::json!([]));
    }

    #[test]
    fn dashboard_failure_stamps_dashboard_command() {
        let f = DashboardFailure::new("dashboard_failed", "store io error");
        let v: serde_json::Value = serde_json::to_value(&f).unwrap();
        assert_eq!(v["ok"], serde_json::json!(false));
        assert_eq!(v["command"], serde_json::json!("dashboard"));
        assert_eq!(v["error_kind"], serde_json::json!("dashboard_failed"));
        assert_eq!(v["message"], serde_json::json!("store io error"));
    }

    #[test]
    fn dashboard_panel_to_renderer_preserves_line_order_and_drops_nothing() {
        let panel = DashboardPanelLines {
            title: "Dashboard".to_string(),
            summary: "running=1".to_string(),
            lines: vec![
                "Dashboard".to_string(),
                "running=1".to_string(),
                "Active (1/1)".to_string(),
                "[running] do the thing".to_string(),
            ],
            rows: vec![
                DashboardPanelRow::stat(),
                DashboardPanelRow::stat(),
                DashboardPanelRow::stat(),
                DashboardPanelRow {
                    kind: DashboardPanelRowKind::ActiveTask,
                    window_id: Some("w1".to_string()),
                    tab_id: Some("t1".to_string()),
                    project_id: None,
                },
            ],
            active_tasks_total: 1,
            active_tasks_shown: 1,
            task_results_total: 0,
            task_results_shown: 0,
            stashed_tabs_total: 0,
            stashed_tabs_shown: 0,
            projects_total: 0,
            projects_shown: 0,
            attention_count: 0,
            accent_color: None,
        };
        let renderer = dashboard_panel_to_renderer(&panel);
        assert_eq!(renderer.lines, panel.lines);
        // The carrier is tagged as a DASHBOARD panel so the settings toggle never clears it.
        assert_eq!(
            renderer.source,
            maestro_renderer::DashboardPanelSource::Dashboard
        );
        // Rows project 1:1 and carry the focus identity only for the focusable active-task row.
        assert_eq!(renderer.dashboard_rows.len(), panel.lines.len());
        assert_eq!(renderer.dashboard_rows[0].focus_tab_id, None);
        assert_eq!(
            renderer.dashboard_rows[3].focus_tab_id,
            Some("t1".to_string())
        );
        assert_eq!(
            renderer.dashboard_rows[3].focus_window_id,
            Some("w1".to_string())
        );
    }

    #[test]
    fn attach_tab_dashboard_status_label_no_suffix_matches_plain_label() {
        // None suffix => byte-for-byte identical to the existing identity label.
        assert_eq!(
            attach_tab_dashboard_status_label("w1", "t1", "sess-1", None),
            attach_tab_status_label("w1", "t1", "sess-1"),
        );
    }

    #[test]
    fn attach_tab_dashboard_status_label_composes_identity_plus_suffix() {
        let suffix = "[active=2 waiting=1 blocked=0 failed=0 attn=1]";
        let composed = attach_tab_dashboard_status_label("w1", "t1", "sess-1", Some(suffix));
        // Preserves the existing identity prefix exactly...
        assert!(
            composed.starts_with(&attach_tab_status_label("w1", "t1", "sess-1")),
            "{composed}"
        );
        // ...and appends the suffix after the existing separator.
        assert_eq!(composed, format!("Hydra · w1/t1 · sess-1 · {suffix}"));
        assert!(composed.ends_with(suffix), "{composed}");
    }

    // --- build_dock_model -----------------------------------------------------------------------

    fn dock_tab(
        window_id: &str,
        tab_id: &str,
        status: Option<maestro_shell::SessionStatus>,
        stashed: bool,
    ) -> maestro_shell::DashboardTab {
        maestro_shell::DashboardTab {
            window_id: window_id.to_string(),
            tab_id: tab_id.to_string(),
            session_id: format!("sess-{tab_id}"),
            index: 0,
            title: format!("title {tab_id}"),
            pinned: false,
            attention: maestro_shell::AttentionState {
                attention: maestro_shell::Attention::None,
                unseen: false,
                since_ms: 0,
                source: maestro_shell::AttentionSource::Agent,
            },
            agent_task_id: None,
            agent_task_state: None,
            session_status: status,
            session_record_missing: false,
            needs_attention: false,
            stashed,
            cwd: String::new(),
        }
    }

    fn dock_project(
        id: &str,
        name: &str,
        last_active_at_ms: u64,
        windows: Vec<maestro_shell::DashboardWindow>,
    ) -> maestro_shell::ProjectSnapshot {
        maestro_shell::ProjectSnapshot {
            project_id: id.to_string(),
            name: name.to_string(),
            root: format!("/{id}"),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            last_active_at_ms,
            icon: Some("●".to_string()),
            accent_color: Some("#ff8800".to_string()),
            launch_defaults: None,
            directories: Vec::new(),
            system: false,
            hidden: false,
            workspaces: vec![],
            tasks: vec![],
            windows,
        }
    }

    /// Exactly one click target is set per row (or none for window/static rows).
    fn one_target(row: &maestro_renderer::RendererDockRow) -> bool {
        let select = row.select_project_id.is_some() as u8;
        let focus = (row.focus_window_id.is_some() && row.focus_tab_id.is_some()) as u8;
        let revive = (row.revive_window_id.is_some() && row.revive_tab_id.is_some()) as u8;
        select + focus + revive <= 1
    }

    #[test]
    fn build_dock_model_collapsed_emits_only_project_rows() {
        let snap = snapshot_of(vec![
            dock_project(
                "p-newer",
                "Newer",
                20,
                vec![maestro_shell::DashboardWindow {
                    window_id: "w1".to_string(),
                    name: None,
                    tabs: vec![dock_tab(
                        "w1",
                        "t1",
                        Some(maestro_shell::SessionStatus::Live),
                        false,
                    )],
                }],
            ),
            dock_project("p-older", "Older", 10, vec![]),
        ]);
        // Even with a project marked expanded, collapsed mode flattens to depth-0 only.
        let mut expanded = std::collections::HashSet::new();
        expanded.insert("p-newer".to_string());

        let dock = build_dock_model(&snap, true, &expanded, 64);

        assert!(dock.collapsed);
        assert_eq!(dock.width_px, 64);
        assert_eq!(dock.rows.len(), 2);
        assert!(dock
            .rows
            .iter()
            .all(|r| r.kind == maestro_renderer::DockRowKind::Project && r.depth == 0));
        // First project (most-recently-active) is `active`; no project is `expanded` when collapsed.
        assert!(dock.rows[0].active);
        assert_eq!(dock.rows[0].expanded, Some(false));
        assert_eq!(dock.rows[0].count_badge, Some(1));
    }

    #[test]
    fn build_dock_model_expands_only_listed_projects_into_windows_and_panes() {
        let snap = snapshot_of(vec![
            dock_project(
                "p-open",
                "Open",
                20,
                vec![maestro_shell::DashboardWindow {
                    window_id: "w1".to_string(),
                    name: None,
                    tabs: vec![
                        dock_tab(
                            "w1",
                            "live",
                            Some(maestro_shell::SessionStatus::Live),
                            false,
                        ),
                        dock_tab("w1", "dead", None, true),
                    ],
                }],
            ),
            dock_project(
                "p-shut",
                "Shut",
                10,
                vec![maestro_shell::DashboardWindow {
                    window_id: "w9".to_string(),
                    name: None,
                    tabs: vec![dock_tab(
                        "w9",
                        "x",
                        Some(maestro_shell::SessionStatus::Live),
                        false,
                    )],
                }],
            ),
        ]);
        let mut expanded = std::collections::HashSet::new();
        expanded.insert("p-open".to_string());

        let dock = build_dock_model(&snap, false, &expanded, 268);

        // p-open: project + window + 2 panes; p-shut: project only (collapsed). = 5 rows.
        assert_eq!(dock.rows.len(), 5);
        let kinds: Vec<_> = dock.rows.iter().map(|r| (r.depth, r.kind)).collect();
        assert_eq!(
            kinds,
            vec![
                (0, maestro_renderer::DockRowKind::Project),
                (1, maestro_renderer::DockRowKind::Window),
                (2, maestro_renderer::DockRowKind::Pane),
                (2, maestro_renderer::DockRowKind::Pane),
                (0, maestro_renderer::DockRowKind::Project),
            ]
        );

        // Live pane routes to focus; stashed pane routes to revive and is flagged.
        let live = &dock.rows[2];
        assert_eq!(live.focus_window_id.as_deref(), Some("w1"));
        assert_eq!(live.focus_tab_id.as_deref(), Some("live"));
        assert!(live.active && !live.stashed);
        let dead = &dock.rows[3];
        assert_eq!(dead.revive_window_id.as_deref(), Some("w1"));
        assert_eq!(dead.revive_tab_id.as_deref(), Some("dead"));
        assert!(dead.stashed && !dead.active && dead.focus_tab_id.is_none());

        // Every row carries at most one click target.
        assert!(dock.rows.iter().all(one_target));
        // Collapsed project still carries its expand flag = false and its window-count badge.
        assert_eq!(dock.rows[4].expanded, Some(false));
        assert_eq!(dock.rows[4].count_badge, Some(1));
    }

    #[test]
    fn build_dock_model_excludes_recovery_tree_but_keeps_ordinary_hidden_project() {
        let mut recovery = dock_project(
            PRODUCT_RECOVERY_PROJECT_ID,
            "Recovery",
            20,
            vec![maestro_shell::DashboardWindow {
                window_id: "recovery-window".to_string(),
                name: None,
                tabs: vec![dock_tab(
                    "recovery-window",
                    "recovery-tab",
                    Some(maestro_shell::SessionStatus::Live),
                    false,
                )],
            }],
        );
        recovery.hidden = true;
        let mut hidden_user = dock_project(
            "hidden-user",
            "Hidden User",
            10,
            vec![maestro_shell::DashboardWindow {
                window_id: "user-window".to_string(),
                name: None,
                tabs: vec![dock_tab(
                    "user-window",
                    "user-tab",
                    Some(maestro_shell::SessionStatus::Live),
                    false,
                )],
            }],
        );
        hidden_user.hidden = true;
        let snap = snapshot_of(vec![recovery, hidden_user]);
        let expanded = [
            PRODUCT_RECOVERY_PROJECT_ID.to_string(),
            "hidden-user".to_string(),
        ]
        .into_iter()
        .collect();

        let dock = build_dock_model(&snap, false, &expanded, 268);

        assert_eq!(dock.rows.len(), 3);
        assert_eq!(
            dock.rows[0].select_project_id.as_deref(),
            Some("hidden-user")
        );
        assert!(dock.rows[0].active);
        assert_eq!(dock.rows[1].label, "user-window");
        assert_eq!(dock.rows[2].focus_tab_id.as_deref(), Some("user-tab"));
        assert!(dock.rows.iter().all(|row| {
            row.select_project_id.as_deref() != Some(PRODUCT_RECOVERY_PROJECT_ID)
                && !row.label.contains("Recovery")
                && !row.label.contains("recovery")
        }));
    }
}
