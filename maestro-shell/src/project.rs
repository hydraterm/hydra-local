//! Durable [`Project`] CRUD — App Shell project management.
//!
//! [`ProjectService`] owns creating, listing, updating, deleting, and reordering `Project`
//! records under app-support through the shared store (atomic envelope writes, corrupt-record
//! quarantine, future-version read-only semantics). Mirrors [`AgentTaskService`] and
//! [`WindowLayoutService`]: STORE/LOCAL-STATE ONLY — no daemon, socket, PTY, git, or renderer. A
//! project is product metadata (name, root, default policy, branding). Deletion reads the complete
//! workspace/session/task/window/tab ownership graph and returns a prepared plan, but this service
//! never opens a daemon socket or mutates a PTY; the app owns that lifecycle boundary.
//!
//! What is strict:
//! - [`create`](ProjectService::create) never overwrites an existing project
//!   ([`ProjectServiceError::ProjectAlreadyExists`]).
//! - mutations never create a missing project ([`ProjectServiceError::ProjectNotFound`]).
//! - field validation: an accent color, when present, must be a `#rrggbb` hex string; an icon,
//!   when present, must be 1..=8 chars (one short glyph/emoji). A violation is a typed
//!   [`ProjectServiceError::InvalidField`] and nothing is written.
//! - future-version records are left byte-identical on disk and never rewritten; corrupt records
//!   are quarantined by the store and surfaced, never trusted or rewritten.
//!
//! Ordering: projects have no stored ordinal; the canonical sort is `last_active_at_ms` desc then
//! `project_id` (matching the dashboard snapshot). [`reorder`](ProjectService::reorder) realizes
//! a caller-supplied order by re-stamping `last_active_at_ms` into a strictly-descending run, so a
//! later load reproduces that exact order without adding a schema field.

use std::collections::BTreeSet;
use std::path::PathBuf;

use crate::paths::{AppPaths, RecordKind};
use crate::records::Project;
use crate::store::{self, load_one, write_record, LoadOutcome, StoreError};
use crate::WorkspacePolicy;
use rusqlite::OptionalExtension;

/// Immutable ownership snapshot for one project deletion.
///
/// The app obtains this before deletion. [`ProjectService::commit_delete`] then recomputes the same
/// snapshot inside an `IMMEDIATE` SQLite transaction and invokes the caller's session-release
/// callback while the writer lock is held. Any workspace/session/task/window/tab ownership change
/// therefore aborts before a PTY is touched, and a conforming concurrent start cannot write its
/// session record between release and cascade.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectDeletionPlan {
    pub project_id: String,
    pub project_exists: bool,
    /// Every window the project owns, including a legacy NULL-FK window named by its
    /// `window_order`. These rows are removed by the same commit as the project.
    pub window_ids: Vec<String>,
    /// Complete session ownership discovered through workspace session rows, project agent-task
    /// current/history references, and tabs in the project's windows.
    pub affected_session_ids: Vec<String>,
    /// Tabs in surviving windows that incorrectly point at a session durably owned only by this
    /// project. They are removed atomically with the project; a misplaced pane is presentation,
    /// not authority to detach a session from its workspace owner.
    pub remove_tab_keys: Vec<(String, String)>,
    /// Affected ids with no surviving durable project/task owner or valid pane owner. A caller must
    /// confirm these ids absent from the daemon before committing the plan.
    pub kill_session_ids: Vec<String>,
    /// Affected ids with a genuine surviving durable owner, or a surviving pane for a session that
    /// was only pane-owned by this project. They are deliberately kept alive.
    pub retained_shared_session_ids: Vec<String>,
}

/// Result of committing a previously prepared [`ProjectDeletionPlan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProjectDeletionResult {
    pub removed: bool,
    pub project_id: String,
    pub window_ids: Vec<String>,
    pub affected_session_ids: Vec<String>,
    pub removed_tab_keys: Vec<(String, String)>,
    pub retained_shared_session_ids: Vec<String>,
}

fn deletion_store_error(error: impl std::fmt::Display) -> ProjectServiceError {
    ProjectServiceError::Store(StoreError::Db(error.to_string()))
}

fn deletion_map_error(error: impl std::fmt::Display) -> ProjectServiceError {
    ProjectServiceError::Store(StoreError::Map(error.to_string()))
}

fn checked_deletion_id(id: &str, what: &str) -> Result<String, ProjectServiceError> {
    crate::ids::validate_id(id)
        .map(|_| id.to_string())
        .map_err(|error| deletion_map_error(format!("invalid {what} id {id:?}: {error}")))
}

fn parse_id_list(json: &str, what: &str) -> Result<Vec<String>, ProjectServiceError> {
    let ids: Vec<String> = serde_json::from_str(json)
        .map_err(|error| deletion_map_error(format!("invalid {what}: {error}")))?;
    let mut seen = BTreeSet::new();
    for id in &ids {
        checked_deletion_id(id, what)?;
        if !seen.insert(id.clone()) {
            return Err(deletion_map_error(format!(
                "invalid {what}: duplicate id {id:?}"
            )));
        }
    }
    Ok(ids)
}

/// Build one complete project-deletion ownership graph from a single SQLite snapshot.
fn project_deletion_plan(
    conn: &rusqlite::Connection,
    project_id: &str,
) -> Result<ProjectDeletionPlan, ProjectServiceError> {
    checked_deletion_id(project_id, "project")?;
    let project_row: Option<(bool, String)> = conn
        .query_row(
            "SELECT system, window_order_json FROM projects WHERE project_id = ?1",
            [project_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(deletion_store_error)?;
    let Some((system, project_window_order_json)) = project_row else {
        return Ok(ProjectDeletionPlan {
            project_id: project_id.to_string(),
            project_exists: false,
            window_ids: Vec::new(),
            affected_session_ids: Vec::new(),
            remove_tab_keys: Vec::new(),
            kill_session_ids: Vec::new(),
            retained_shared_session_ids: Vec::new(),
        });
    };
    if system {
        return Err(ProjectServiceError::SystemProjectCannotBeDeleted {
            project_id: project_id.to_string(),
        });
    }
    let ordered_windows = parse_id_list(
        &project_window_order_json,
        &format!("window_order for project {project_id:?}"),
    )?;

    // Parse every other project's window order before trusting a legacy NULL-FK row. If two
    // projects name it, there is no safe automatic owner choice.
    let mut other_ordered_windows = BTreeSet::new();
    {
        let mut stmt = conn
            .prepare("SELECT project_id, window_order_json FROM projects WHERE project_id <> ?1")
            .map_err(deletion_store_error)?;
        let rows = stmt
            .query_map([project_id], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(deletion_store_error)?;
        for row in rows {
            let (other_project, json) = row.map_err(deletion_store_error)?;
            for window_id in parse_id_list(
                &json,
                &format!("window_order for project {other_project:?}"),
            )? {
                other_ordered_windows.insert(window_id);
            }
        }
    }

    let mut window_ids = BTreeSet::new();
    {
        let mut stmt = conn
            .prepare("SELECT window_id FROM windows WHERE project_id = ?1 ORDER BY window_id")
            .map_err(deletion_store_error)?;
        let rows = stmt
            .query_map([project_id], |row| row.get::<_, String>(0))
            .map_err(deletion_store_error)?;
        for row in rows {
            let window_id = row.map_err(deletion_store_error)?;
            window_ids.insert(checked_deletion_id(&window_id, "window")?);
        }
    }
    for window_id in ordered_windows {
        let owner: Option<Option<String>> = conn
            .query_row(
                "SELECT project_id FROM windows WHERE window_id = ?1",
                [&window_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(deletion_store_error)?;
        match owner {
            None => {} // stale order entry; there is no row to delete
            Some(Some(owner)) if owner == project_id => {
                window_ids.insert(window_id);
            }
            Some(Some(owner)) => {
                return Err(ProjectServiceError::WindowOwnershipConflict {
                    project_id: project_id.to_string(),
                    window_id,
                    detail: format!("the window FK belongs to project {owner:?}"),
                })
            }
            Some(None) if other_ordered_windows.contains(&window_id) => {
                return Err(ProjectServiceError::WindowOwnershipConflict {
                    project_id: project_id.to_string(),
                    window_id,
                    detail: "the NULL-owner window is also named by another project".into(),
                })
            }
            Some(None) => {
                window_ids.insert(window_id);
            }
        }
    }

    let mut session_rows: Vec<(String, String)> = Vec::new();
    {
        let mut stmt = conn
            .prepare(
                "SELECT s.session_id, w.project_id FROM sessions s \
                 JOIN workspaces w ON w.workspace_id = s.workspace_id",
            )
            .map_err(deletion_store_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(deletion_store_error)?;
        for row in rows {
            let (session_id, owner) = row.map_err(deletion_store_error)?;
            session_rows.push((checked_deletion_id(&session_id, "session")?, owner));
        }
    }

    let mut task_refs: Vec<(String, Vec<String>)> = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT project_id, current_session_id, session_history_json FROM agent_tasks")
            .map_err(deletion_store_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(deletion_store_error)?;
        for row in rows {
            let (owner, current, history_json) = row.map_err(deletion_store_error)?;
            let mut refs = parse_id_list(&history_json, "agent task session_history")?;
            if let Some(current) = current {
                refs.push(checked_deletion_id(&current, "agent task current session")?);
            }
            refs.sort();
            refs.dedup();
            task_refs.push((owner, refs));
        }
    }

    let mut tab_refs: Vec<(String, String, String)> = Vec::new();
    {
        let mut stmt = conn
            .prepare("SELECT window_id, tab_id, session_id FROM tabs WHERE session_id IS NOT NULL")
            .map_err(deletion_store_error)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(deletion_store_error)?;
        for row in rows {
            let (window_id, tab_id, session_id) = row.map_err(deletion_store_error)?;
            tab_refs.push((
                checked_deletion_id(&window_id, "tab window")?,
                checked_deletion_id(&tab_id, "tab")?,
                checked_deletion_id(&session_id, "tab session")?,
            ));
        }
    }

    let mut affected = BTreeSet::new();
    for (session_id, owner) in &session_rows {
        if owner == project_id {
            affected.insert(session_id.clone());
        }
    }
    for (owner, refs) in &task_refs {
        if owner == project_id {
            affected.extend(refs.iter().cloned());
        }
    }
    for (window_id, _, session_id) in &tab_refs {
        if window_ids.contains(window_id) {
            affected.insert(session_id.clone());
        }
    }

    let mut target_owned = BTreeSet::new();
    target_owned.extend(
        session_rows
            .iter()
            .filter(|(_, owner)| owner == project_id)
            .map(|(session_id, _)| session_id.clone()),
    );
    for (owner, refs) in &task_refs {
        if owner == project_id {
            target_owned.extend(refs.iter().cloned());
        }
    }

    let mut durable_external = BTreeSet::new();
    for (session_id, owner) in &session_rows {
        if owner != project_id && affected.contains(session_id) {
            durable_external.insert(session_id.clone());
        }
    }
    for (owner, refs) in &task_refs {
        if owner != project_id {
            durable_external.extend(
                refs.iter()
                    .filter(|session_id| affected.contains(*session_id))
                    .cloned(),
            );
        }
    }
    let mut externally_referenced = durable_external.clone();
    let mut remove_tab_keys = BTreeSet::new();
    for (window_id, tab_id, session_id) in &tab_refs {
        if !window_ids.contains(window_id) && affected.contains(session_id) {
            if target_owned.contains(session_id) && !durable_external.contains(session_id) {
                remove_tab_keys.insert((window_id.clone(), tab_id.clone()));
            } else {
                externally_referenced.insert(session_id.clone());
            }
        }
    }

    let kill_session_ids = affected
        .difference(&externally_referenced)
        .cloned()
        .collect();
    let retained_shared_session_ids = affected
        .intersection(&externally_referenced)
        .cloned()
        .collect();
    Ok(ProjectDeletionPlan {
        project_id: project_id.to_string(),
        project_exists: true,
        window_ids: window_ids.into_iter().collect(),
        affected_session_ids: affected.into_iter().collect(),
        remove_tab_keys: remove_tab_keys.into_iter().collect(),
        kill_session_ids,
        retained_shared_session_ids,
    })
}

/// Why a project operation failed.
#[derive(Debug)]
pub enum ProjectServiceError {
    /// No project record exists under this id; mutations never create one implicitly.
    ProjectNotFound { project_id: String },
    /// A project record already exists under this id; `create` refuses to overwrite it.
    ProjectAlreadyExists { project_id: String },
    /// A supplied field failed validation (e.g. a non-`#rrggbb` accent color, an over-long icon,
    /// or an empty name). Nothing was written.
    InvalidField { field: String, reason: String },
    /// `reorder` was given an order that is not an exact permutation of the existing project ids
    /// (missing id, unknown id, or a duplicate). Nothing was rewritten.
    InvalidOrder { reason: String },
    /// `delete` was called on a SYSTEM project (the built-in "Terminal"). System projects can be renamed + hidden
    /// but never deleted. Nothing was removed.
    SystemProjectCannotBeDeleted { project_id: String },
    /// The database ownership graph changed after the daemon cleanup plan was prepared. Nothing
    /// was deleted; the caller must prepare and execute a fresh plan.
    DeletionPlanChanged { project_id: String },
    /// The caller-supplied session-release boundary failed while the deletion transaction held the
    /// ownership graph stable. The transaction was rolled back and every database row remains.
    SessionReleaseFailed { detail: String },
    /// A legacy NULL-FK window is named by more than one project, or a project names a window whose
    /// explicit FK owner is another project. Deletion refuses to guess which owner is authoritative.
    WindowOwnershipConflict {
        project_id: String,
        window_id: String,
        detail: String,
    },
    /// The project record was written by a NEWER Maestro. Left exactly as on disk so no field is
    /// dropped; it cannot be mutated or replaced from this build.
    FutureVersion { path: PathBuf, ours: u32, got: u32 },
    /// The project record was corrupt; the store quarantined it (moved to `corrupt/`, preserved)
    /// and it is surfaced here. Nothing was rewritten.
    Corrupt {
        original: PathBuf,
        moved_to: PathBuf,
        reason: String,
    },
    /// Underlying store failure (io / envelope / id). An unsafe `project_id` surfaces here as
    /// `Store(Id(..))` BEFORE any path is built or file touched.
    Store(StoreError),
}

impl std::fmt::Display for ProjectServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProjectServiceError::ProjectNotFound { project_id } => {
                write!(f, "no project record found for id {project_id:?}")
            }
            ProjectServiceError::ProjectAlreadyExists { project_id } => write!(
                f,
                "a project record already exists for id {project_id:?}; refusing to overwrite it"
            ),
            ProjectServiceError::InvalidField { field, reason } => {
                write!(f, "invalid project {field}: {reason}")
            }
            ProjectServiceError::InvalidOrder { reason } => {
                write!(f, "invalid project order: {reason}")
            }
            ProjectServiceError::SystemProjectCannotBeDeleted { project_id } => write!(
                f,
                "project {project_id:?} is a system project and cannot be deleted (it can be hidden or renamed)"
            ),
            ProjectServiceError::DeletionPlanChanged { project_id } => write!(
                f,
                "project {project_id:?} changed before its sessions could be released; nothing was deleted"
            ),
            ProjectServiceError::SessionReleaseFailed { detail } => write!(
                f,
                "project session release failed; project records were preserved: {detail}"
            ),
            ProjectServiceError::WindowOwnershipConflict {
                project_id,
                window_id,
                detail,
            } => write!(
                f,
                "project {project_id:?} cannot delete window {window_id:?}: {detail}"
            ),
            ProjectServiceError::FutureVersion { path, ours, got } => write!(
                f,
                "project record {} was written by a newer Maestro (schema version {got} > \
                 {ours}); left in place, not modified",
                path.display()
            ),
            ProjectServiceError::Corrupt {
                original,
                moved_to,
                reason,
            } => write!(
                f,
                "project record {} was corrupt ({reason}); quarantined at {}",
                original.display(),
                moved_to.display()
            ),
            ProjectServiceError::Store(e) => write!(f, "project store error: {e}"),
        }
    }
}

impl std::error::Error for ProjectServiceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProjectServiceError::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreError> for ProjectServiceError {
    fn from(e: StoreError) -> Self {
        ProjectServiceError::Store(e)
    }
}

/// Optional fields supplied to [`ProjectService::create`]. `name` and `root` are required
/// positionally; this groups the branding/policy options so the call site stays readable and new
/// optional fields don't churn the signature.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewProject {
    /// Default isolation policy for workspaces spawned in this project. `None` -> `ScratchCwd`
    /// (the most isolated default; `RepoWrite` is never a default).
    pub default_workspace_policy: Option<WorkspacePolicy>,
    /// Optional short display glyph (emoji or 1–2 chars). Validated to 1..=8 chars.
    pub icon: Option<String>,
    /// Optional `#rrggbb` accent color. Validated.
    pub accent_color: Option<String>,
    /// Default launch settings new windows/panes inherit. `None` → no project default.
    pub launch_defaults: Option<super::records::ProjectLaunchDefaults>,
    /// Extra named folders pinned for window creation. Empty when none.
    pub directories: Vec<super::records::ProjectDirectory>,
    /// Mark this a SYSTEM project (the built-in "Terminal"): renameable + hideable but never deletable. Ordinary
    /// user projects leave this false.
    pub system: bool,
}

/// A partial update for [`ProjectService::update`]. Every field is `Option`; `Some(v)` sets the
/// field, `None` leaves it unchanged. To CLEAR an optional field (icon/accent), pass
/// `Some(None)`. `created_at_ms` is never updatable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectUpdate {
    pub name: Option<String>,
    pub root: Option<String>,
    pub default_workspace_policy: Option<WorkspacePolicy>,
    /// `Some(Some(s))` set icon, `Some(None)` clear icon, `None` leave unchanged.
    pub icon: Option<Option<String>>,
    /// `Some(Some(s))` set accent, `Some(None)` clear accent, `None` leave unchanged.
    pub accent_color: Option<Option<String>>,
    /// `Some(Some(defaults))` set launch defaults, `Some(None)` clear them, `None` leave unchanged.
    pub launch_defaults: Option<Option<super::records::ProjectLaunchDefaults>>,
    /// `Some(folders)` replaces the pinned project folders, `None` leaves them unchanged.
    pub directories: Option<Vec<super::records::ProjectDirectory>>,
}

/// Validate a `#rrggbb` hex color: a leading `#` then exactly 6 ASCII hex digits.
fn validate_accent(color: &str) -> Result<(), ProjectServiceError> {
    let ok = color.len() == 7
        && color.starts_with('#')
        && color[1..].bytes().all(|b| b.is_ascii_hexdigit());
    if ok {
        Ok(())
    } else {
        Err(ProjectServiceError::InvalidField {
            field: "accent_color".into(),
            reason: format!("expected #rrggbb hex, got {color:?}"),
        })
    }
}

/// Validate an icon glyph: non-empty and at most 8 chars (one short emoji/glyph, generously
/// bounded for multi-codepoint emoji).
fn validate_icon(icon: &str) -> Result<(), ProjectServiceError> {
    let len = icon.chars().count();
    if (1..=8).contains(&len) {
        Ok(())
    } else {
        Err(ProjectServiceError::InvalidField {
            field: "icon".into(),
            reason: format!("expected 1..=8 chars, got {len}"),
        })
    }
}

/// Validate a non-empty name (trimmed).
fn validate_name(name: &str) -> Result<(), ProjectServiceError> {
    if name.trim().is_empty() {
        Err(ProjectServiceError::InvalidField {
            field: "name".into(),
            reason: "must not be empty".into(),
        })
    } else {
        Ok(())
    }
}

/// Store-backed CRUD service for [`Project`] records. Borrows [`AppPaths`] so the IO boundary
/// stays visible — there is no hidden global store.
pub struct ProjectService<'a> {
    paths: &'a AppPaths,
}

impl<'a> ProjectService<'a> {
    pub fn new(paths: &'a AppPaths) -> Self {
        ProjectService { paths }
    }

    /// Create and persist a brand-new project.
    ///
    /// - `created_at_ms = last_active_at_ms = now_ms`.
    /// - `default_workspace_policy` defaults to `ScratchCwd` when `opts.default_workspace_policy`
    ///   is `None`.
    /// - the `project_id` is validated by the store/id path BEFORE any file is touched; an unsafe
    ///   id fails as `Store(Id(..))` with nothing on disk.
    /// - an existing record under the same id is a typed [`ProjectAlreadyExists`] and never
    ///   overwritten; a future-version or corrupt record under the id surfaces with the usual
    ///   store semantics.
    pub fn create(
        &self,
        project_id: impl Into<String>,
        name: impl Into<String>,
        root: impl Into<String>,
        opts: NewProject,
        now_ms: u64,
    ) -> Result<Project, ProjectServiceError> {
        let project_id = project_id.into();
        let name = name.into();
        let root = root.into();

        validate_name(&name)?;
        if let Some(icon) = opts.icon.as_deref() {
            validate_icon(icon)?;
        }
        if let Some(accent) = opts.accent_color.as_deref() {
            validate_accent(accent)?;
        }

        // load_one validates the id first (StoreError::Id before any path exists), then tells us
        // whether the id is free. Loaded/FutureVersion are refusals; a corrupt record is
        // quarantined by this very load and surfaced.
        match load_one::<Project>(self.paths, RecordKind::Project, &project_id)? {
            None => {}
            Some(LoadOutcome::Loaded(_)) => {
                return Err(ProjectServiceError::ProjectAlreadyExists { project_id });
            }
            Some(LoadOutcome::FutureVersion { path, ours, got }) => {
                return Err(ProjectServiceError::FutureVersion { path, ours, got });
            }
            Some(LoadOutcome::Quarantined {
                original,
                moved_to,
                reason,
            }) => {
                return Err(ProjectServiceError::Corrupt {
                    original,
                    moved_to,
                    reason,
                });
            }
        }

        // Keep project names unique globally (auto-number collisions). The id is brand-new here, so every existing
        // project is a sibling — a same-named project just gets a numbered variant.
        let sibling_names: Vec<String> = self.list()?.into_iter().map(|p| p.name).collect();
        let name = crate::names::unique_name(&name, &sibling_names);

        let project = Project {
            project_id: project_id.clone(),
            name,
            root,
            default_workspace_policy: opts
                .default_workspace_policy
                .unwrap_or(WorkspacePolicy::ScratchCwd),
            created_at_ms: now_ms,
            last_active_at_ms: now_ms,
            icon: opts.icon,
            accent_color: opts.accent_color,
            launch_defaults: opts.launch_defaults,
            directories: opts.directories,
            window_order: Vec::new(),
            system: opts.system,
            hidden: false,
        };
        write_record(
            self.paths,
            RecordKind::Project,
            &project_id,
            now_ms,
            &project,
        )?;
        Ok(project)
    }

    /// Load ONE project by id. `Ok(None)` when no record exists; future/corrupt surface as typed
    /// errors (the latter is quarantined by this load).
    pub fn load(&self, project_id: &str) -> Result<Option<Project>, ProjectServiceError> {
        match load_one::<Project>(self.paths, RecordKind::Project, project_id)? {
            None => Ok(None),
            Some(LoadOutcome::Loaded(p)) => Ok(Some(p)),
            Some(LoadOutcome::FutureVersion { path, ours, got }) => {
                Err(ProjectServiceError::FutureVersion { path, ours, got })
            }
            Some(LoadOutcome::Quarantined {
                original,
                moved_to,
                reason,
            }) => Err(ProjectServiceError::Corrupt {
                original,
                moved_to,
                reason,
            }),
        }
    }

    /// List all loadable projects, sorted `last_active_at_ms` DESC then `project_id` ASC (the
    /// canonical dashboard order). Future-version and corrupt records are SKIPPED (the latter is
    /// quarantined by the load), so a single bad record never fails the whole list — matching the
    /// dashboard snapshot's resilience.
    pub fn list(&self) -> Result<Vec<Project>, ProjectServiceError> {
        let mut projects: Vec<Project> =
            store::load_all::<Project>(self.paths, RecordKind::Project)?
                .into_iter()
                .filter_map(|o| match o {
                    LoadOutcome::Loaded(p) => Some(p),
                    LoadOutcome::FutureVersion { .. } | LoadOutcome::Quarantined { .. } => None,
                })
                .collect();
        projects.sort_by(|a, b| {
            b.last_active_at_ms
                .cmp(&a.last_active_at_ms)
                .then_with(|| a.project_id.cmp(&b.project_id))
        });
        Ok(projects)
    }

    /// Apply a partial [`ProjectUpdate`] to an existing project, preserving every field the update
    /// leaves `None`. Validates any supplied name/icon/accent BEFORE loading, so an invalid update
    /// never touches disk. `created_at_ms` is never changed; `last_active_at_ms` is NOT bumped here
    /// (a metadata edit is not "activity" — use [`touch`](ProjectService::touch) for that).
    pub fn update(
        &self,
        project_id: &str,
        update: ProjectUpdate,
        now_ms: u64,
    ) -> Result<Project, ProjectServiceError> {
        if let Some(name) = update.name.as_deref() {
            validate_name(name)?;
        }
        // `icon`/`accent_color` are `Option<Option<String>>`: only the `Some(Some(_))` case (a SET)
        // is validated; `Some(None)` is a deliberate CLEAR and `None` leaves the field unchanged.
        if let Some(Some(icon)) = &update.icon {
            validate_icon(icon)?;
        }
        if let Some(Some(accent)) = &update.accent_color {
            validate_accent(accent)?;
        }

        // Dedup a renamed name globally, excluding THIS project (so rename-to-self is a no-op). Done before `mutate`
        // because it needs a list() read; the deduped value is applied in the closure below.
        let deduped_name = match update.name {
            Some(name) => {
                let sibling_names: Vec<String> = self
                    .list()?
                    .into_iter()
                    .filter(|p| p.project_id != project_id)
                    .map(|p| p.name)
                    .collect();
                Some(crate::names::unique_name(&name, &sibling_names))
            }
            None => None,
        };

        self.mutate(project_id, now_ms, |p| {
            if let Some(name) = deduped_name {
                p.name = name;
            }
            if let Some(root) = update.root {
                p.root = root;
            }
            if let Some(policy) = update.default_workspace_policy {
                p.default_workspace_policy = policy;
            }
            if let Some(icon) = update.icon {
                p.icon = icon;
            }
            if let Some(accent) = update.accent_color {
                p.accent_color = accent;
            }
            if let Some(launch_defaults) = update.launch_defaults {
                p.launch_defaults = launch_defaults;
            }
            if let Some(directories) = update.directories {
                p.directories = directories;
            }
        })
    }

    /// Stamp `last_active_at_ms = now_ms` (used when a project is opened/focused, so the dashboard
    /// sorts it to the top). Every other field is preserved.
    pub fn touch(&self, project_id: &str, now_ms: u64) -> Result<Project, ProjectServiceError> {
        self.mutate(project_id, now_ms, |p| p.last_active_at_ms = now_ms)
    }

    /// Prepare a complete, read-only project deletion plan.
    ///
    /// Session ownership is the union of:
    /// - durable `sessions → workspaces → project` rows;
    /// - every project `agent_tasks.current_session_id` and `session_history_json` id;
    /// - every tab in a project-owned window (including a legacy NULL-FK window named by the
    ///   project's durable `window_order`).
    ///
    /// The plan also classifies ids referenced by a surviving project/task/tab/session owner as
    /// shared, so callers preserve those live PTYs. Any malformed history/ownership evidence aborts
    /// the plan; an empty set is never inferred from a failed read.
    pub fn plan_delete(
        &self,
        project_id: &str,
    ) -> Result<ProjectDeletionPlan, ProjectServiceError> {
        let _ = self
            .paths
            .record_path(RecordKind::Project, project_id)
            .map_err(|error| ProjectServiceError::Store(StoreError::Id(error)))?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| ProjectServiceError::Store(StoreError::Db(error.to_string())))?;
        let conn = arc.lock().unwrap();
        project_deletion_plan(&conn, project_id)
    }

    /// Atomically commit a previously prepared deletion plan.
    ///
    /// This method intentionally does NOT accept a bare project id. The caller must first obtain
    /// the complete ownership plan. An `IMMEDIATE` transaction recomputes the plan and requires
    /// byte-for-byte equality before invoking `release_sessions`; that callback must confirm every
    /// supplied id absent from the daemon. Keeping the database writer lock through the callback
    /// closes the ordinary record-write/start race: a conforming process cannot publish a new
    /// session owner between release and cascade. A callback error rolls back with all records
    /// intact. Foreign-key cascades remove ordinary children; exact legacy NULL-FK windows proven
    /// solely owned by this project are explicitly removed in the same transaction.
    pub fn commit_delete(
        &self,
        plan: &ProjectDeletionPlan,
        release_sessions: impl FnOnce(&[String]) -> Result<(), String>,
    ) -> Result<ProjectDeletionResult, ProjectServiceError> {
        let _ = self
            .paths
            .record_path(RecordKind::Project, &plan.project_id)
            .map_err(|error| ProjectServiceError::Store(StoreError::Id(error)))?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| ProjectServiceError::Store(StoreError::Db(error.to_string())))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| ProjectServiceError::Store(StoreError::Db(error.to_string())))?;
        let current = project_deletion_plan(&tx, &plan.project_id)?;
        if &current != plan {
            return Err(ProjectServiceError::DeletionPlanChanged {
                project_id: plan.project_id.clone(),
            });
        }

        if !plan.project_exists {
            tx.commit()
                .map_err(|error| ProjectServiceError::Store(StoreError::Db(error.to_string())))?;
            return Ok(ProjectDeletionResult {
                removed: false,
                project_id: plan.project_id.clone(),
                window_ids: Vec::new(),
                affected_session_ids: Vec::new(),
                removed_tab_keys: Vec::new(),
                retained_shared_session_ids: Vec::new(),
            });
        }

        // Remove stale cross-project panes inside the transaction before touching the daemon.
        // Other readers cannot observe these uncommitted deletes; a daemon failure rolls them all
        // back, while a successful release cannot leave a pane pointing at a cascaded session row.
        for (window_id, tab_id) in &plan.remove_tab_keys {
            tx.execute(
                "DELETE FROM tabs WHERE window_id = ?1 AND tab_id = ?2",
                rusqlite::params![window_id, tab_id],
            )
            .map_err(|error| ProjectServiceError::Store(StoreError::Db(error.to_string())))?;
        }

        release_sessions(&plan.kill_session_ids)
            .map_err(|detail| ProjectServiceError::SessionReleaseFailed { detail })?;

        // Delete every exact planned window first. This is redundant for ordinary FK-owned rows,
        // but is what safely closes the documented legacy NULL-owner corruption class.
        for window_id in &plan.window_ids {
            tx.execute(
                "DELETE FROM windows WHERE window_id = ?1 AND (project_id = ?2 OR project_id IS NULL)",
                rusqlite::params![window_id, plan.project_id],
            )
            .map_err(|error| ProjectServiceError::Store(StoreError::Db(error.to_string())))?;
        }
        let removed = tx
            .execute(
                "DELETE FROM projects WHERE project_id = ?1",
                [&plan.project_id],
            )
            .map_err(|error| ProjectServiceError::Store(StoreError::Db(error.to_string())))?
            > 0;
        tx.commit()
            .map_err(|error| ProjectServiceError::Store(StoreError::Db(error.to_string())))?;

        if removed {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_millis() as u64)
                .unwrap_or(0);
            for window_id in &plan.window_ids {
                crate::write_trace::trace_delete(self.paths.base(), "WindowLayout", window_id, ts);
            }
            let surviving_windows: BTreeSet<&str> = plan
                .remove_tab_keys
                .iter()
                .map(|(window_id, _)| window_id.as_str())
                .collect();
            for window_id in surviving_windows {
                crate::write_trace::trace_write(
                    self.paths.base(),
                    "WindowLayout",
                    window_id,
                    &["tabs".into()],
                    ts,
                );
            }
            crate::write_trace::trace_delete(self.paths.base(), "Project", &plan.project_id, ts);
        }

        Ok(ProjectDeletionResult {
            removed,
            project_id: plan.project_id.clone(),
            window_ids: plan.window_ids.clone(),
            affected_session_ids: plan.affected_session_ids.clone(),
            removed_tab_keys: plan.remove_tab_keys.clone(),
            retained_shared_session_ids: plan.retained_shared_session_ids.clone(),
        })
    }

    /// Realize a caller-supplied project order. `ordered_project_ids` MUST be an exact permutation
    /// of the currently-loadable project ids (every id once, no unknowns, no duplicates); on any
    /// violation nothing is written and [`InvalidOrder`] is returned. Since projects carry no
    /// stored ordinal, the order is encoded by re-stamping `last_active_at_ms` into a strictly
    /// DESCENDING run starting at `now_ms` (first id gets the largest stamp), so a subsequent
    /// [`list`](ProjectService::list) reproduces exactly this order.
    pub fn reorder(
        &self,
        ordered_project_ids: &[String],
        now_ms: u64,
    ) -> Result<Vec<Project>, ProjectServiceError> {
        let current = self.list()?;
        let current_ids: std::collections::HashSet<&str> =
            current.iter().map(|p| p.project_id.as_str()).collect();
        let wanted_ids: std::collections::HashSet<&str> =
            ordered_project_ids.iter().map(String::as_str).collect();

        if ordered_project_ids.len() != current.len() {
            return Err(ProjectServiceError::InvalidOrder {
                reason: format!(
                    "expected {} ids, got {}",
                    current.len(),
                    ordered_project_ids.len()
                ),
            });
        }
        if wanted_ids.len() != ordered_project_ids.len() {
            return Err(ProjectServiceError::InvalidOrder {
                reason: "duplicate id in requested order".into(),
            });
        }
        if current_ids != wanted_ids {
            return Err(ProjectServiceError::InvalidOrder {
                reason: "requested order is not a permutation of existing project ids".into(),
            });
        }

        // Re-stamp descending so list() (sort by last_active desc) yields this exact order. Use a
        // gap of 1 ms per slot down from now_ms; the count is bounded by the project population.
        let mut written = Vec::with_capacity(ordered_project_ids.len());
        for (i, id) in ordered_project_ids.iter().enumerate() {
            let stamp = now_ms.saturating_sub(i as u64);
            let p = self.mutate(id, stamp, |p| p.last_active_at_ms = stamp)?;
            written.push(p);
        }
        Ok(written)
    }

    /// Persist the caller's preferred window order for one project. The project service does not own
    /// window records, so this accepts any duplicate-free, non-empty ids and snapshot projection later
    /// ignores stale ids while appending newly discovered windows.
    pub fn reorder_windows(
        &self,
        project_id: &str,
        ordered_window_ids: &[String],
        now_ms: u64,
    ) -> Result<Project, ProjectServiceError> {
        let wanted_ids: std::collections::HashSet<&str> =
            ordered_window_ids.iter().map(String::as_str).collect();
        if wanted_ids.len() != ordered_window_ids.len() {
            return Err(ProjectServiceError::InvalidOrder {
                reason: "duplicate window id in requested order".into(),
            });
        }
        if ordered_window_ids.iter().any(|id| id.trim().is_empty()) {
            return Err(ProjectServiceError::InvalidOrder {
                reason: "empty window id in requested order".into(),
            });
        }
        self.mutate(project_id, now_ms, |p| {
            p.window_order = ordered_window_ids.to_vec();
        })
    }

    /// Load → edit → write a project, preserving all unedited fields. `TabNotFound`-style
    /// `ProjectNotFound` when absent; future/corrupt surface typed (never rewritten).
    fn mutate(
        &self,
        project_id: &str,
        now_ms: u64,
        edit: impl FnOnce(&mut Project),
    ) -> Result<Project, ProjectServiceError> {
        let mut project = match self.load(project_id)? {
            Some(p) => p,
            None => {
                return Err(ProjectServiceError::ProjectNotFound {
                    project_id: project_id.to_string(),
                })
            }
        };
        edit(&mut project);
        write_record(
            self.paths,
            RecordKind::Project,
            project_id,
            now_ms,
            &project,
        )?;
        Ok(project)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, AppPaths) {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        (tmp, paths)
    }

    fn svc(paths: &AppPaths) -> ProjectService<'_> {
        ProjectService::new(paths)
    }

    fn commit_delete(paths: &AppPaths, project_id: &str) -> ProjectDeletionResult {
        let service = svc(paths);
        let plan = service.plan_delete(project_id).unwrap();
        service.commit_delete(&plan, |_| Ok(())).unwrap()
    }

    fn ids(ps: &[Project]) -> Vec<&str> {
        ps.iter().map(|p| p.project_id.as_str()).collect()
    }

    #[test]
    fn create_persists_defaults_and_branding() {
        let (_t, paths) = temp_paths();
        let p = svc(&paths)
            .create(
                "p1",
                "Example",
                "/repo/example",
                NewProject {
                    icon: Some("🐙".into()),
                    accent_color: Some("#4f8cff".into()),
                    ..Default::default()
                },
                100,
            )
            .unwrap();
        assert_eq!(p.name, "Example");
        assert_eq!(p.root, "/repo/example");
        assert_eq!(p.default_workspace_policy, WorkspacePolicy::ScratchCwd);
        assert_eq!(p.created_at_ms, 100);
        assert_eq!(p.last_active_at_ms, 100);
        assert_eq!(p.icon.as_deref(), Some("🐙"));
        assert_eq!(p.accent_color.as_deref(), Some("#4f8cff"));

        // Round-trips through the store.
        let loaded = svc(&paths).load("p1").unwrap().unwrap();
        assert_eq!(loaded, p);
    }

    #[test]
    fn create_refuses_duplicate_and_invalid_fields() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("p1", "A", "/a", NewProject::default(), 1)
            .unwrap();
        assert!(matches!(
            svc(&paths)
                .create("p1", "A2", "/a2", NewProject::default(), 2)
                .unwrap_err(),
            ProjectServiceError::ProjectAlreadyExists { .. }
        ));
        // Empty name.
        assert!(matches!(
            svc(&paths)
                .create("p2", "  ", "/b", NewProject::default(), 2)
                .unwrap_err(),
            ProjectServiceError::InvalidField { .. }
        ));
        // Bad accent.
        assert!(matches!(
            svc(&paths)
                .create(
                    "p3",
                    "C",
                    "/c",
                    NewProject {
                        accent_color: Some("blue".into()),
                        ..Default::default()
                    },
                    2,
                )
                .unwrap_err(),
            ProjectServiceError::InvalidField { .. }
        ));
        // Only p1 was written.
        assert_eq!(ids(&svc(&paths).list().unwrap()), vec!["p1"]);
    }

    #[test]
    fn list_sorts_by_recency_then_id() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("a", "A", "/a", NewProject::default(), 10)
            .unwrap();
        svc(&paths)
            .create("b", "B", "/b", NewProject::default(), 30)
            .unwrap();
        svc(&paths)
            .create("c", "C", "/c", NewProject::default(), 30)
            .unwrap();
        // b and c share recency 30 -> tie broken by id asc; a is older.
        assert_eq!(ids(&svc(&paths).list().unwrap()), vec!["b", "c", "a"]);
    }

    #[test]
    fn update_sets_only_supplied_fields_and_can_clear_optionals() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create(
                "p1",
                "Old",
                "/old",
                NewProject {
                    icon: Some("x".into()),
                    accent_color: Some("#000000".into()),
                    ..Default::default()
                },
                1,
            )
            .unwrap();
        let updated = svc(&paths)
            .update(
                "p1",
                ProjectUpdate {
                    name: Some("New".into()),
                    icon: Some(None), // clear icon
                    ..Default::default()
                },
                5,
            )
            .unwrap();
        assert_eq!(updated.name, "New");
        assert_eq!(updated.root, "/old", "root unchanged");
        assert_eq!(updated.icon, None, "icon cleared");
        assert_eq!(
            updated.accent_color.as_deref(),
            Some("#000000"),
            "accent untouched"
        );
        assert_eq!(updated.created_at_ms, 1, "created_at never changes");
        assert_eq!(
            updated.last_active_at_ms, 1,
            "a metadata edit is not activity"
        );
    }

    #[test]
    fn create_dedups_name_globally() {
        let (_t, paths) = temp_paths();
        let a = svc(&paths)
            .create("p1", "Alpha", "/a", NewProject::default(), 1)
            .unwrap();
        assert_eq!(a.name, "Alpha");
        // A DIFFERENT project (different id) with the same name → auto-numbered.
        let b = svc(&paths)
            .create("p2", "Alpha", "/b", NewProject::default(), 2)
            .unwrap();
        assert_eq!(b.name, "Alpha 2");
        let c = svc(&paths)
            .create("p3", "Alpha", "/c", NewProject::default(), 3)
            .unwrap();
        assert_eq!(c.name, "Alpha 3");
    }

    #[test]
    fn update_dedups_name_against_others_but_self_is_noop() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("p1", "Alpha", "/a", NewProject::default(), 1)
            .unwrap();
        svc(&paths)
            .create("p2", "Beta", "/b", NewProject::default(), 1)
            .unwrap();
        // Rename Beta → "Alpha" collides with p1 → auto-numbered.
        let renamed = svc(&paths)
            .update(
                "p2",
                ProjectUpdate {
                    name: Some("Alpha".into()),
                    ..Default::default()
                },
                2,
            )
            .unwrap();
        assert_eq!(renamed.name, "Alpha 2");
        // Rename p1 to its OWN current name → no-op (self excluded).
        let self_rename = svc(&paths)
            .update(
                "p1",
                ProjectUpdate {
                    name: Some("Alpha".into()),
                    ..Default::default()
                },
                3,
            )
            .unwrap();
        assert_eq!(self_rename.name, "Alpha", "rename-to-self keeps the name");
    }

    #[test]
    fn update_can_set_launch_defaults_and_directories() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("p1", "Project", "/repo", NewProject::default(), 1)
            .unwrap();

        let launch_defaults = super::super::records::ProjectLaunchDefaults {
            agent: Some("codex".into()),
            model: Some("gpt-5".into()),
            resume_mode: Some("resume".into()),
            dangerous_skip_permissions: Some(true),
            custom_command: Some("codex --ask-for-approval never".into()),
        };
        let directories = vec![super::super::records::ProjectDirectory {
            id: "src".into(),
            name: "Source".into(),
            path: "/repo/src".into(),
        }];

        let updated = svc(&paths)
            .update(
                "p1",
                ProjectUpdate {
                    launch_defaults: Some(Some(launch_defaults.clone())),
                    directories: Some(directories.clone()),
                    ..Default::default()
                },
                5,
            )
            .unwrap();

        assert_eq!(updated.launch_defaults, Some(launch_defaults.clone()));
        assert_eq!(updated.directories, directories);
        let loaded = svc(&paths).load("p1").unwrap().unwrap();
        assert_eq!(loaded.launch_defaults, Some(launch_defaults));
        assert_eq!(loaded.directories.len(), 1);
        assert_eq!(loaded.directories[0].path, "/repo/src");
    }

    #[test]
    fn update_can_clear_launch_defaults_without_touching_directories() {
        let (_t, paths) = temp_paths();
        let launch_defaults = super::super::records::ProjectLaunchDefaults {
            agent: Some("claude".into()),
            ..Default::default()
        };
        let directories = vec![super::super::records::ProjectDirectory {
            id: "docs".into(),
            name: "Docs".into(),
            path: "/repo/docs".into(),
        }];
        svc(&paths)
            .create(
                "p1",
                "Project",
                "/repo",
                NewProject {
                    launch_defaults: Some(launch_defaults),
                    directories: directories.clone(),
                    ..Default::default()
                },
                1,
            )
            .unwrap();

        let updated = svc(&paths)
            .update(
                "p1",
                ProjectUpdate {
                    launch_defaults: Some(None),
                    ..Default::default()
                },
                5,
            )
            .unwrap();

        assert_eq!(updated.launch_defaults, None);
        assert_eq!(updated.directories, directories);
    }

    #[test]
    fn update_rejects_invalid_field_without_writing() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("p1", "Ok", "/a", NewProject::default(), 1)
            .unwrap();
        assert!(matches!(
            svc(&paths)
                .update(
                    "p1",
                    ProjectUpdate {
                        accent_color: Some(Some("#zzzzzz".into())),
                        ..Default::default()
                    },
                    5,
                )
                .unwrap_err(),
            ProjectServiceError::InvalidField { .. }
        ));
        assert_eq!(svc(&paths).load("p1").unwrap().unwrap().name, "Ok");
    }

    #[test]
    fn update_missing_project_errors() {
        let (_t, paths) = temp_paths();
        assert!(matches!(
            svc(&paths)
                .update("ghost", ProjectUpdate::default(), 1)
                .unwrap_err(),
            ProjectServiceError::ProjectNotFound { .. }
        ));
    }

    #[test]
    fn touch_bumps_recency_and_resorts() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("a", "A", "/a", NewProject::default(), 10)
            .unwrap();
        svc(&paths)
            .create("b", "B", "/b", NewProject::default(), 20)
            .unwrap();
        assert_eq!(ids(&svc(&paths).list().unwrap()), vec!["b", "a"]);
        svc(&paths).touch("a", 99).unwrap();
        assert_eq!(ids(&svc(&paths).list().unwrap()), vec!["a", "b"]);
    }

    #[test]
    fn delete_is_idempotent_and_removes_only_the_target() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("a", "A", "/a", NewProject::default(), 1)
            .unwrap();
        svc(&paths)
            .create("b", "B", "/b", NewProject::default(), 1)
            .unwrap();
        assert!(commit_delete(&paths, "a").removed, "a removed");
        assert!(
            !commit_delete(&paths, "a").removed,
            "second delete is a no-op"
        );
        assert_eq!(ids(&svc(&paths).list().unwrap()), vec!["b"]);
    }

    #[test]
    fn delete_refuses_a_system_project_but_allows_ordinary_ones() {
        let (_t, paths) = temp_paths();
        // system "Terminal" — must NOT be deletable
        svc(&paths)
            .create(
                "system-terminal",
                "Terminal",
                "/",
                NewProject {
                    system: true,
                    ..Default::default()
                },
                1,
            )
            .unwrap();
        // an ordinary project — deletable
        svc(&paths)
            .create("u1", "User", "/u", NewProject::default(), 1)
            .unwrap();

        let err = svc(&paths).plan_delete("system-terminal").unwrap_err();
        assert!(
            matches!(
                err,
                ProjectServiceError::SystemProjectCannotBeDeleted { .. }
            ),
            "system project delete must be refused, got {err:?}"
        );
        // the record is still there
        assert!(svc(&paths).load("system-terminal").unwrap().is_some());
        // ordinary delete still works
        assert!(commit_delete(&paths, "u1").removed);
        assert!(svc(&paths).load("u1").unwrap().is_none());
    }

    #[test]
    fn delete_cascades_to_all_children() {
        // The payoff: the plan exposes PTY ownership before deleting the project graph.
        use crate::paths::RecordKind;
        use crate::records::{
            AttentionState, LaunchSpec, SessionKind, SessionRecord, SessionStatus, TabRecord,
            WindowLayout, Workspace, WorkspaceConsent,
        };
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("p1", "P", "/r", NewProject::default(), 1)
            .unwrap();
        // workspace → session under p1
        let ws = Workspace {
            workspace_id: "ws1".into(),
            project_id: "p1".into(),
            root: "/r".into(),
            policy: crate::policy::WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        };
        crate::store::write_record(&paths, RecordKind::Workspace, "ws1", 1, &ws).unwrap();
        let sess = SessionRecord {
            session_id: "s1".into(),
            workspace_id: "ws1".into(),
            kind: SessionKind::Shell,
            launch: LaunchSpec::OptOut,
            cwd_resolved: "/r".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: SessionStatus::Live,
        };
        crate::store::write_record(&paths, RecordKind::Session, "s1", 1, &sess).unwrap();
        // window → tab. WindowLayout carries no project_id in the record model; ownership lives in the windows.project_id
        // column (set by the app from window_order). Write the layout, then stamp its owning project for the cascade.
        let win = WindowLayout {
            window_id: "win1".into(),
            name: Some("Window 1".into()),
            tabs: vec![TabRecord {
                tab_id: "t1".into(),
                session_id: "s1".into(),
                index: 0,
                title: "Pane 1".into(),
                pinned: false,
                attention: AttentionState::default(),
                split_from: None,
                pane_rect: None,
                stashed_from: None,
                stashed: false,
            }],
        };
        crate::store::write_record(&paths, RecordKind::WindowLayout, "win1", 1, &win).unwrap();
        {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let conn = arc.lock().unwrap();
            conn.execute(
                "UPDATE windows SET project_id = 'p1' WHERE window_id = 'win1'",
                [],
            )
            .unwrap();
        }

        // Delete the project → everything under it cascades away.
        let plan = svc(&paths).plan_delete("p1").unwrap();
        assert_eq!(plan.affected_session_ids, vec!["s1"]);
        assert_eq!(plan.kill_session_ids, vec!["s1"]);
        assert!(
            svc(&paths)
                .commit_delete(&plan, |_| Ok(()))
                .unwrap()
                .removed
        );
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        for table in ["projects", "workspaces", "sessions", "windows", "tabs"] {
            let n: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                n, 0,
                "{table} must be empty after the project cascade-delete"
            );
        }
    }

    #[test]
    fn delete_plan_finds_tabless_workspace_task_history_and_tab_only_sessions() {
        use crate::paths::RecordKind;
        use crate::records::{
            AgentTask, AgentTaskState, AttentionState, LaunchSpec, SessionKind, SessionRecord,
            SessionStatus, Workspace, WorkspaceConsent,
        };

        let (_t, paths) = temp_paths();
        for project_id in ["target", "other"] {
            svc(&paths)
                .create(project_id, project_id, "/r", NewProject::default(), 1)
                .unwrap();
        }
        let workspace = Workspace {
            workspace_id: "ws-target".into(),
            project_id: "target".into(),
            root: "/r".into(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        };
        crate::store::write_record(&paths, RecordKind::Workspace, "ws-target", 1, &workspace)
            .unwrap();
        let tabless = SessionRecord {
            session_id: "tabless-workspace".into(),
            workspace_id: "ws-target".into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::OptOut,
            cwd_resolved: "/r".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: SessionStatus::Live,
        };
        crate::store::write_record(
            &paths,
            RecordKind::Session,
            "tabless-workspace",
            1,
            &tabless,
        )
        .unwrap();
        let target_task = AgentTask {
            agent_task_id: "task-target".into(),
            project_id: "target".into(),
            goal: "test".into(),
            state: AgentTaskState::Running,
            current_session_id: Some("task-current".into()),
            session_history: vec!["task-history".into(), "shared-history".into()],
            created_at_ms: 1,
            updated_at_ms: 1,
            result_summary: None,
        };
        crate::store::write_record(
            &paths,
            RecordKind::AgentTask,
            "task-target",
            1,
            &target_task,
        )
        .unwrap();
        let other_task = AgentTask {
            agent_task_id: "task-other".into(),
            project_id: "other".into(),
            goal: "test".into(),
            state: AgentTaskState::Running,
            current_session_id: Some("shared-history".into()),
            session_history: vec![],
            created_at_ms: 1,
            updated_at_ms: 1,
            result_summary: None,
        };
        crate::store::write_record(&paths, RecordKind::AgentTask, "task-other", 1, &other_task)
            .unwrap();

        let windows = crate::WindowLayoutService::new(&paths);
        windows.create_empty("target-window", 1).unwrap();
        windows
            .open_tab(
                "target-window",
                "tab-only",
                "tab-only-session",
                "Recovered",
                false,
                AttentionState::default(),
                1,
            )
            .unwrap();
        crate::store::set_window_project(&paths, "target-window", "target").unwrap();

        let plan = svc(&paths).plan_delete("target").unwrap();
        assert_eq!(
            plan.affected_session_ids,
            vec![
                "shared-history",
                "tab-only-session",
                "tabless-workspace",
                "task-current",
                "task-history",
            ]
        );
        assert_eq!(
            plan.kill_session_ids,
            vec![
                "tab-only-session",
                "tabless-workspace",
                "task-current",
                "task-history",
            ]
        );
        assert_eq!(plan.retained_shared_session_ids, vec!["shared-history"]);
    }

    #[test]
    fn delete_commit_refuses_a_stale_session_ownership_plan() {
        use crate::paths::RecordKind;
        use crate::records::{AgentTask, AgentTaskState};

        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("target", "Target", "/r", NewProject::default(), 1)
            .unwrap();
        let stale = svc(&paths).plan_delete("target").unwrap();
        let task = AgentTask {
            agent_task_id: "late-task".into(),
            project_id: "target".into(),
            goal: "late".into(),
            state: AgentTaskState::Running,
            current_session_id: Some("late-session".into()),
            session_history: vec![],
            created_at_ms: 2,
            updated_at_ms: 2,
            result_summary: None,
        };
        crate::store::write_record(&paths, RecordKind::AgentTask, "late-task", 2, &task).unwrap();

        let release_called = std::cell::Cell::new(false);
        assert!(matches!(
            svc(&paths)
                .commit_delete(&stale, |_| {
                    release_called.set(true);
                    Ok(())
                })
                .unwrap_err(),
            ProjectServiceError::DeletionPlanChanged { .. }
        ));
        assert!(
            !release_called.get(),
            "a stale plan must abort before touching the daemon boundary"
        );
        assert!(svc(&paths).load("target").unwrap().is_some());
    }

    #[test]
    fn delete_release_failure_rolls_back_without_losing_ownership_evidence() {
        use crate::records::{LaunchSpec, SessionKind, SessionRecord, SessionStatus};

        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("target", "Target", "/r", NewProject::default(), 1)
            .unwrap();
        let workspace = crate::records::Workspace {
            workspace_id: "target-workspace".into(),
            project_id: "target".into(),
            root: "/r".into(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: crate::records::WorkspaceConsent::default(),
        };
        crate::store::write_record(
            &paths,
            RecordKind::Workspace,
            "target-workspace",
            1,
            &workspace,
        )
        .unwrap();
        let session = SessionRecord {
            session_id: "must-release".into(),
            workspace_id: "target-workspace".into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::OptOut,
            cwd_resolved: "/r".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: SessionStatus::Live,
        };
        crate::store::write_record(&paths, RecordKind::Session, "must-release", 1, &session)
            .unwrap();
        let plan = svc(&paths).plan_delete("target").unwrap();

        assert!(matches!(
            svc(&paths)
                .commit_delete(&plan, |ids| {
                    assert_eq!(ids, ["must-release"]);
                    Err("daemon unavailable".into())
                })
                .unwrap_err(),
            ProjectServiceError::SessionReleaseFailed { .. }
        ));
        assert!(svc(&paths).load("target").unwrap().is_some());
        assert!(crate::store::load_one::<SessionRecord>(
            &paths,
            RecordKind::Session,
            "must-release"
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn delete_removes_a_misplaced_surviving_pane_and_releases_its_owned_session() {
        use crate::records::{
            AttentionState, LaunchSpec, SessionKind, SessionRecord, SessionStatus,
        };

        let (_t, paths) = temp_paths();
        for project_id in ["target", "survivor"] {
            svc(&paths)
                .create(project_id, project_id, "/r", NewProject::default(), 1)
                .unwrap();
        }
        let workspace = crate::records::Workspace {
            workspace_id: "target-workspace".into(),
            project_id: "target".into(),
            root: "/r".into(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: crate::records::WorkspaceConsent::default(),
        };
        crate::store::write_record(
            &paths,
            RecordKind::Workspace,
            "target-workspace",
            1,
            &workspace,
        )
        .unwrap();
        let session = SessionRecord {
            session_id: "shared-pane-session".into(),
            workspace_id: "target-workspace".into(),
            kind: SessionKind::Shell,
            launch: LaunchSpec::OptOut,
            cwd_resolved: "/r".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: SessionStatus::Live,
        };
        crate::store::write_record(
            &paths,
            RecordKind::Session,
            "shared-pane-session",
            1,
            &session,
        )
        .unwrap();
        let windows = crate::WindowLayoutService::new(&paths);
        windows.create_empty("surviving-window", 1).unwrap();
        windows
            .open_tab(
                "surviving-window",
                "surviving-pane",
                "shared-pane-session",
                "Shared",
                false,
                AttentionState::default(),
                1,
            )
            .unwrap();
        crate::store::set_window_project(&paths, "surviving-window", "survivor").unwrap();

        let plan = svc(&paths).plan_delete("target").unwrap();
        assert_eq!(plan.affected_session_ids, vec!["shared-pane-session"]);
        assert_eq!(plan.kill_session_ids, vec!["shared-pane-session"]);
        assert_eq!(
            plan.remove_tab_keys,
            vec![("surviving-window".into(), "surviving-pane".into())]
        );
        assert!(plan.retained_shared_session_ids.is_empty());

        let mut released = Vec::new();
        let result = svc(&paths)
            .commit_delete(&plan, |ids| {
                released.extend_from_slice(ids);
                Ok(())
            })
            .unwrap();
        assert!(result.removed);
        assert_eq!(released, ["shared-pane-session"]);
        assert_eq!(result.removed_tab_keys, plan.remove_tab_keys);
        let surviving = windows.load("surviving-window").unwrap().unwrap();
        assert!(surviving.tabs.is_empty());
    }

    #[test]
    fn delete_plan_never_treats_an_unreadable_ownership_list_as_empty() {
        let (_t, paths) = temp_paths();
        for project_id in ["target", "other"] {
            svc(&paths)
                .create(project_id, project_id, "/r", NewProject::default(), 1)
                .unwrap();
        }
        let arc = crate::db::conn_for(paths.base()).unwrap();
        arc.lock()
            .unwrap()
            .execute(
                "UPDATE projects SET window_order_json = '{not-json' WHERE project_id = 'other'",
                [],
            )
            .unwrap();

        assert!(matches!(
            svc(&paths).plan_delete("target").unwrap_err(),
            ProjectServiceError::Store(StoreError::Map(_))
        ));
        assert!(svc(&paths).load("target").unwrap().is_some());
    }

    #[test]
    fn delete_plan_owns_and_removes_a_legacy_null_fk_window_from_window_order() {
        use crate::records::AttentionState;

        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("target", "Target", "/r", NewProject::default(), 1)
            .unwrap();
        let windows = crate::WindowLayoutService::new(&paths);
        windows.create_empty("legacy-window", 1).unwrap();
        windows
            .open_tab(
                "legacy-window",
                "legacy-tab",
                "legacy-session",
                "Legacy",
                false,
                AttentionState::default(),
                1,
            )
            .unwrap();
        svc(&paths)
            .reorder_windows("target", &["legacy-window".into()], 2)
            .unwrap();

        let plan = svc(&paths).plan_delete("target").unwrap();
        assert_eq!(plan.window_ids, vec!["legacy-window"]);
        assert_eq!(plan.kill_session_ids, vec!["legacy-session"]);
        assert!(
            svc(&paths)
                .commit_delete(&plan, |_| Ok(()))
                .unwrap()
                .removed
        );
        assert!(windows.load("legacy-window").unwrap().is_none());
    }

    #[test]
    fn reorder_realizes_requested_order_via_recency() {
        let (_t, paths) = temp_paths();
        for (id, t) in [("a", 10u64), ("b", 20), ("c", 30)] {
            svc(&paths)
                .create(id, id, "/x", NewProject::default(), t)
                .unwrap();
        }
        // Default order is c, b, a (recency desc). Request a, c, b.
        let want = vec!["a".to_string(), "c".to_string(), "b".to_string()];
        svc(&paths).reorder(&want, 1000).unwrap();
        assert_eq!(ids(&svc(&paths).list().unwrap()), vec!["a", "c", "b"]);
    }

    #[test]
    fn reorder_rejects_non_permutation() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("a", "A", "/a", NewProject::default(), 1)
            .unwrap();
        svc(&paths)
            .create("b", "B", "/b", NewProject::default(), 1)
            .unwrap();
        // Missing one id.
        assert!(matches!(
            svc(&paths).reorder(&["a".into()], 5).unwrap_err(),
            ProjectServiceError::InvalidOrder { .. }
        ));
        // Unknown id.
        assert!(matches!(
            svc(&paths)
                .reorder(&["a".into(), "ghost".into()], 5)
                .unwrap_err(),
            ProjectServiceError::InvalidOrder { .. }
        ));
        // Duplicate.
        assert!(matches!(
            svc(&paths)
                .reorder(&["a".into(), "a".into()], 5)
                .unwrap_err(),
            ProjectServiceError::InvalidOrder { .. }
        ));
    }

    #[test]
    fn reorder_windows_persists_project_window_order() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("p", "P", "/p", NewProject::default(), 1)
            .unwrap();
        let order = vec!["win-b".to_string(), "win-a".to_string()];
        let p = svc(&paths).reorder_windows("p", &order, 5).unwrap();
        assert_eq!(p.window_order, order);
        assert_eq!(
            svc(&paths).load("p").unwrap().unwrap().window_order,
            vec!["win-b".to_string(), "win-a".to_string()]
        );
    }

    #[test]
    fn reorder_windows_rejects_duplicates_or_empty_ids() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("p", "P", "/p", NewProject::default(), 1)
            .unwrap();
        assert!(matches!(
            svc(&paths)
                .reorder_windows("p", &["win-a".into(), "win-a".into()], 5)
                .unwrap_err(),
            ProjectServiceError::InvalidOrder { .. }
        ));
        assert!(matches!(
            svc(&paths)
                .reorder_windows("p", &["win-a".into(), " ".into()], 5)
                .unwrap_err(),
            ProjectServiceError::InvalidOrder { .. }
        ));
    }
}
