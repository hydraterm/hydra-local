//! Durable [`Project`] CRUD — App Shell project management.
//!
//! [`ProjectService`] owns creating, listing, updating, deleting, and reordering `Project`
//! records under app-support through the shared store (atomic envelope writes, corrupt-record
//! quarantine, future-version read-only semantics). Mirrors [`AgentTaskService`] and
//! [`WindowLayoutService`]: STORE/LOCAL-STATE ONLY — no daemon, socket, PTY, git, or renderer. A
//! project is product metadata (name, root, default policy, branding); it never spawns or checks
//! a session, workspace, or task.
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

use std::path::PathBuf;

use crate::paths::{AppPaths, RecordKind};
use crate::records::Project;
use crate::store::{self, load_one, write_record, LoadOutcome, StoreError};
use crate::WorkspacePolicy;

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

    /// Permanently DELETE a project record. Returns `Ok(true)` when a record was removed,
    /// `Ok(false)` when none existed (idempotent). The database foreign keys cascade the deletion
    /// through the project's workspaces, sessions, tasks, windows, tabs, and scoped presets. The id
    /// is validated before any query is built.
    pub fn delete(&self, project_id: &str) -> Result<bool, ProjectServiceError> {
        // A SYSTEM project (the built-in "Terminal") is renameable + hideable but NEVER deletable — refuse before
        // touching disk. A non-existent / non-system project falls through to the idempotent remove below.
        if let Some(project) = self.load(project_id)? {
            if project.system {
                return Err(ProjectServiceError::SystemProjectCannotBeDeleted {
                    project_id: project_id.to_string(),
                });
            }
        }
        // FK ON DELETE CASCADE removes the project's workspaces → sessions, agent_tasks, windows → tabs, and
        // project-scoped presets — closed projects leave NO orphans. Idempotent (missing id → Ok(false)).
        crate::store::delete_record(self.paths, RecordKind::Project, project_id)
            .map_err(ProjectServiceError::Store)
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
        assert!(svc(&paths).delete("a").unwrap(), "a removed");
        assert!(
            !svc(&paths).delete("a").unwrap(),
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

        let err = svc(&paths).delete("system-terminal").unwrap_err();
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
        assert!(svc(&paths).delete("u1").unwrap());
        assert!(svc(&paths).load("u1").unwrap().is_none());
    }

    #[test]
    fn delete_cascades_to_all_children() {
        // The payoff: deleting a project removes its workspaces → sessions, agent_tasks, and windows → tabs. No orphans.
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
        assert!(svc(&paths).delete("p1").unwrap());
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
