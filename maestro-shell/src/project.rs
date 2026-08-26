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
use crate::session_release::{
    insert_pending_releases, resolve_exact_target, PendingReleaseReceipt,
    PreResolvedSessionGenerations, SessionRowPolicy,
};
use crate::store::{self, load_one, LoadOutcome, StoreError};
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
    // Opaque outside maestro-shell: an exact delete/recreate of any Project, Workspace, Session,
    // WindowLayout, or owner/order identity must make a prepared daemon-release plan stale even
    // when every public row field was recreated byte-for-byte.
    window_mutation_epoch: u32,
    /// Complete, strictly parsed target-project order, including stale ids whose window row is
    /// already absent. Deleting the project removes this soft ownership signal, so it participates
    /// in exact plan revalidation and the global window-mutation epoch even when no FK row cascades.
    pub window_order_ids: Vec<String>,
    /// Every window the project owns, including a legacy NULL-FK window named by its
    /// `window_order`. These rows are removed by the same commit as the project.
    pub window_ids: Vec<String>,
    /// Complete session ownership discovered through workspace session rows, project agent-task
    /// current/history references, worktree provenance, and tabs in the project's windows.
    pub affected_session_ids: Vec<String>,
    /// Worktree-provenance markers owned through this project's workspaces. These soft-owner rows
    /// have no SQLite foreign key and must be removed explicitly with the project cascade.
    pub worktree_provenance_session_ids: Vec<String>,
    /// Tabs in surviving windows that incorrectly point at a session durably owned only by this
    /// project. They are removed atomically with the project; a misplaced pane is presentation,
    /// not authority to detach a session from its workspace owner.
    pub remove_tab_keys: Vec<(String, String)>,
    /// Affected ids with no surviving durable project/task owner or valid pane owner. A caller must
    /// confirm these ids absent from the daemon before committing the plan. This remains an ID-only
    /// compatibility cohort; the follow-up conditional-kill protocol should capture each target
    /// SessionRecord generation in this same snapshot and grant no destructive authority for None.
    pub kill_session_ids: Vec<String>,
    /// Exact Session-row generations captured in this plan's ownership snapshot. Missing rows and
    /// NULL generations remain explicit `None`; the destructive commit requires a strictly
    /// pre-resolved daemon generation (or confirmed absence) before it can journal either case.
    kill_session_row_generations: std::collections::BTreeMap<String, SessionRowSnapshot>,
    /// Affected ids with a genuine surviving durable owner, or a surviving pane for a session that
    /// was only pane-owned by this project. They are deliberately kept alive.
    pub retained_shared_session_ids: Vec<String>,
}

impl ProjectDeletionPlan {
    /// Session ids whose exact PTY lifetime was not present in the prepared SQLite snapshot.  A
    /// caller may resolve precisely this opaque cohort from one authoritative daemon Sessions
    /// snapshot before invoking `commit_delete`; ids with an exact row generation need no entry.
    pub fn unresolved_release_session_ids(&self) -> Vec<&str> {
        self.kill_session_row_generations
            .iter()
            .filter_map(|(session_id, snapshot)| match snapshot {
                SessionRowSnapshot::Missing | SessionRowSnapshot::Present(None) => {
                    Some(session_id.as_str())
                }
                SessionRowSnapshot::Present(Some(_)) => None,
            })
            .collect()
    }
}

/// Result of committing a previously prepared [`ProjectDeletionPlan`].
#[derive(Debug)]
pub struct ProjectDeletionResult {
    pub removed: bool,
    pub project_id: String,
    pub window_ids: Vec<String>,
    pub affected_session_ids: Vec<String>,
    pub removed_tab_keys: Vec<(String, String)>,
    pub retained_shared_session_ids: Vec<String>,
    pub release_receipt: Option<PendingReleaseReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SessionRowSnapshot {
    Missing,
    Present(Option<String>),
}

/// One newly inserted Project and opaque authority to remove only that exact, still-empty
/// incarnation if the larger create flow fails before publishing any child records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedProject {
    pub project: Project,
    pub receipt: ProjectCreationReceipt,
}

/// Opaque proof returned by the Project insert transaction.
///
/// The private digest binds the canonical bytes written by that transaction, while the private
/// global identity epoch makes delete/recreate ABA and unrelated owner-namespace mutations stale.
/// Callers cannot manufacture cleanup authority from mutable Project bytes alone.
#[derive(Clone, PartialEq, Eq)]
pub struct ProjectCreationReceipt {
    project_id: String,
    project_fingerprint: [u8; 32],
    window_mutation_epoch: u32,
}

impl std::fmt::Debug for ProjectCreationReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProjectCreationReceipt")
            .field("project_id", &self.project_id)
            .finish_non_exhaustive()
    }
}

/// Result of conditionally removing a newly created Project after a larger create flow failed.
/// Refusal outcomes never mutate the Project, its children, the global identity epoch, or traces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionalCreatedProjectDelete {
    Deleted,
    Missing,
    Changed,
    Referenced,
}

fn project_creation_fingerprint(project: &Project) -> Result<[u8; 32], ProjectServiceError> {
    use sha2::{Digest as _, Sha256};

    let canonical = serde_json::to_vec(project).map_err(|error| {
        deletion_map_error(format!(
            "serialize canonical project creation proof: {error}"
        ))
    })?;
    let digest = Sha256::digest(canonical);
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(&digest);
    Ok(fingerprint)
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

fn validate_project_window_order(
    project_id: &str,
    window_order: &[String],
) -> Result<(), ProjectServiceError> {
    let mut seen = BTreeSet::new();
    for window_id in window_order {
        checked_deletion_id(
            window_id,
            &format!("window_order for project {project_id:?}"),
        )?;
        if !seen.insert(window_id) {
            return Err(deletion_map_error(format!(
                "invalid window_order for project {project_id:?}: duplicate id {window_id:?}"
            )));
        }
    }
    Ok(())
}

/// Parsed project-order rows from one SQLite snapshot. Keeping this parser beside project
/// deletion makes every destructive owner check apply the same duplicate/id/malformed fail-closed
/// rules; fresh-window rollback consumes it as well.
pub(crate) fn project_window_orders(
    conn: &rusqlite::Connection,
) -> Result<Vec<(String, Vec<String>)>, ProjectServiceError> {
    let mut statement = conn
        .prepare("SELECT project_id, window_order_json FROM projects ORDER BY project_id")
        .map_err(deletion_store_error)?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(deletion_store_error)?;
    let mut orders = Vec::new();
    for row in rows {
        let (project_id, json) = row.map_err(deletion_store_error)?;
        checked_deletion_id(&project_id, "project")?;
        let window_ids = parse_id_list(&json, &format!("window_order for project {project_id:?}"))?;
        orders.push((project_id, window_ids));
    }
    Ok(orders)
}

/// All durable session ownership evidence read from one SQLite snapshot.
///
/// This is deliberately shared by project deletion and conditional fresh-window cleanup so a new
/// soft session owner cannot be taught to one destructive path while being forgotten by the
/// other. `worktree_provenance` has no foreign key, so an orphan workspace reference is ambiguous
/// authority and fails closed instead of being treated as absent.
pub(crate) struct SessionOwnershipGraph {
    pub(crate) session_rows: Vec<(String, String, Option<String>)>,
    pub(crate) task_refs: Vec<(String, Vec<String>)>,
    pub(crate) tab_refs: Vec<(String, String, String)>,
    pub(crate) worktree_refs: Vec<(String, String, String)>,
}

pub(crate) fn session_ownership_graph(
    conn: &rusqlite::Connection,
) -> Result<SessionOwnershipGraph, ProjectServiceError> {
    let mut session_rows = Vec::new();
    {
        let mut statement = conn
            .prepare(
                "SELECT s.session_id, w.project_id, s.last_known_generation FROM sessions s \
                 LEFT JOIN workspaces w ON w.workspace_id = s.workspace_id",
            )
            .map_err(deletion_store_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(deletion_store_error)?;
        for row in rows {
            let (session_id, owner, generation) = row.map_err(deletion_store_error)?;
            let session_id = checked_deletion_id(&session_id, "session")?;
            let Some(owner) = owner else {
                return Err(deletion_map_error(format!(
                    "session {session_id:?} names a missing workspace"
                )));
            };
            let owner = checked_deletion_id(&owner, "session workspace project")?;
            if generation
                .as_deref()
                .is_some_and(|generation| generation.is_empty() || generation.len() > 128)
            {
                return Err(deletion_map_error(format!(
                    "session {session_id:?} has an invalid PTY generation"
                )));
            }
            session_rows.push((session_id, owner, generation));
        }
    }

    let mut task_refs = Vec::new();
    {
        let mut statement = conn
            .prepare("SELECT project_id, current_session_id, session_history_json FROM agent_tasks")
            .map_err(deletion_store_error)?;
        let rows = statement
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
            let owner = checked_deletion_id(&owner, "agent task project")?;
            let mut refs = parse_id_list(&history_json, "agent task session_history")?;
            if let Some(current) = current {
                refs.push(checked_deletion_id(&current, "agent task current session")?);
            }
            refs.sort();
            refs.dedup();
            task_refs.push((owner, refs));
        }
    }

    let mut tab_refs = Vec::new();
    {
        let mut statement = conn
            .prepare("SELECT window_id, tab_id, session_id FROM tabs WHERE session_id IS NOT NULL")
            .map_err(deletion_store_error)?;
        let rows = statement
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

    let mut worktree_refs = Vec::new();
    {
        let mut statement = conn
            .prepare(
                "SELECT provenance.session_id, provenance.workspace_id, workspaces.project_id \
                 FROM worktree_provenance provenance \
                 LEFT JOIN workspaces ON workspaces.workspace_id = provenance.workspace_id",
            )
            .map_err(deletion_store_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                ))
            })
            .map_err(deletion_store_error)?;
        for row in rows {
            let (session_id, workspace_id, owner) = row.map_err(deletion_store_error)?;
            let session_id = checked_deletion_id(&session_id, "worktree session")?;
            let workspace_id = checked_deletion_id(&workspace_id, "worktree workspace")?;
            let Some(owner) = owner else {
                return Err(deletion_map_error(format!(
                    "worktree provenance for session {session_id:?} names missing workspace {workspace_id:?}"
                )));
            };
            let owner = checked_deletion_id(&owner, "worktree workspace project")?;
            worktree_refs.push((session_id, workspace_id, owner));
        }
    }

    Ok(SessionOwnershipGraph {
        session_rows,
        task_refs,
        tab_refs,
        worktree_refs,
    })
}

/// Build one complete project-deletion ownership graph from a single SQLite snapshot.
fn project_deletion_plan(
    conn: &rusqlite::Connection,
    project_id: &str,
) -> Result<ProjectDeletionPlan, ProjectServiceError> {
    checked_deletion_id(project_id, "project")?;
    let project_row: Option<bool> = conn
        .query_row(
            "SELECT system FROM projects WHERE project_id = ?1",
            [project_id],
            |row| row.get(0),
        )
        .optional()
        .map_err(deletion_store_error)?;
    // The project SELECT establishes this explicit transaction's read snapshot before the opaque
    // epoch is captured; all ownership graph queries below therefore share that same generation.
    let window_mutation_epoch =
        crate::db::window_mutation_epoch(conn).map_err(deletion_store_error)?;
    let Some(system) = project_row else {
        return Ok(ProjectDeletionPlan {
            project_id: project_id.to_string(),
            project_exists: false,
            window_mutation_epoch,
            window_order_ids: Vec::new(),
            window_ids: Vec::new(),
            affected_session_ids: Vec::new(),
            worktree_provenance_session_ids: Vec::new(),
            remove_tab_keys: Vec::new(),
            kill_session_ids: Vec::new(),
            kill_session_row_generations: std::collections::BTreeMap::new(),
            retained_shared_session_ids: Vec::new(),
        });
    };
    if system {
        return Err(ProjectServiceError::SystemProjectCannotBeDeleted {
            project_id: project_id.to_string(),
        });
    }
    let all_window_orders = project_window_orders(conn)?;
    let ordered_windows = all_window_orders
        .iter()
        .find_map(|(owner, windows)| (owner == project_id).then(|| windows.clone()))
        .ok_or_else(|| {
            deletion_map_error(format!(
                "project {project_id:?} disappeared while reading its window_order"
            ))
        })?;
    let window_order_ids = ordered_windows.clone();

    // Parse every other project's window order before trusting a legacy NULL-FK row. If two
    // projects name it, there is no safe automatic owner choice.
    let other_ordered_windows = all_window_orders
        .iter()
        .filter(|(owner, _)| owner != project_id)
        .flat_map(|(_, windows)| windows.iter().cloned())
        .collect::<BTreeSet<_>>();

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

    let SessionOwnershipGraph {
        session_rows,
        task_refs,
        tab_refs,
        worktree_refs,
    } = session_ownership_graph(conn)?;

    let mut affected = BTreeSet::new();
    for (session_id, owner, _) in &session_rows {
        if owner == project_id {
            affected.insert(session_id.clone());
        }
    }
    for (owner, refs) in &task_refs {
        if owner == project_id {
            affected.extend(refs.iter().cloned());
        }
    }
    for (session_id, _, owner) in &worktree_refs {
        if owner == project_id {
            affected.insert(session_id.clone());
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
            .filter(|(_, owner, _)| owner == project_id)
            .map(|(session_id, _, _)| session_id.clone()),
    );
    for (owner, refs) in &task_refs {
        if owner == project_id {
            target_owned.extend(refs.iter().cloned());
        }
    }
    target_owned.extend(
        worktree_refs
            .iter()
            .filter(|(_, _, owner)| owner == project_id)
            .map(|(session_id, _, _)| session_id.clone()),
    );

    let mut durable_external = BTreeSet::new();
    for (session_id, owner, _) in &session_rows {
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
    durable_external.extend(
        worktree_refs
            .iter()
            .filter(|(session_id, _, owner)| owner != project_id && affected.contains(session_id))
            .map(|(session_id, _, _)| session_id.clone()),
    );
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

    let kill_session_ids: Vec<String> = affected
        .difference(&externally_referenced)
        .cloned()
        .collect();
    let row_generations: std::collections::BTreeMap<&str, Option<String>> = session_rows
        .iter()
        .map(|(session_id, _, generation)| (session_id.as_str(), generation.clone()))
        .collect();
    let kill_session_row_generations = kill_session_ids
        .iter()
        .map(|session_id| {
            (
                session_id.clone(),
                row_generations
                    .get(session_id.as_str())
                    .cloned()
                    .map(SessionRowSnapshot::Present)
                    .unwrap_or(SessionRowSnapshot::Missing),
            )
        })
        .collect();
    let retained_shared_session_ids = affected
        .intersection(&externally_referenced)
        .cloned()
        .collect();
    Ok(ProjectDeletionPlan {
        project_id: project_id.to_string(),
        project_exists: true,
        window_mutation_epoch,
        window_order_ids,
        window_ids: window_ids.into_iter().collect(),
        affected_session_ids: affected.into_iter().collect(),
        worktree_provenance_session_ids: worktree_refs
            .into_iter()
            .filter(|(_, _, owner)| owner == project_id)
            .map(|(session_id, _, _)| session_id)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect(),
        remove_tab_keys: remove_tab_keys.into_iter().collect(),
        kill_session_ids,
        kill_session_row_generations,
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
    /// An exact project snapshot was superseded before its conditional mutation acquired the
    /// SQLite writer fence. Nothing was written.
    ProjectChanged { project_id: String },
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
    /// A user-facing deletion would remove the final visible ordinary-project window. The complete
    /// graph and any staged release journal rows are rolled back together.
    GloballyLastVisibleWindow { project_id: String },
    /// Exact release targets could not be validated or inserted into the durable journal in the
    /// same destructive transaction. The transaction was rolled back and every graph row remains.
    SessionReleaseJournal { detail: String },
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
            ProjectServiceError::ProjectChanged { project_id } => write!(
                f,
                "project {project_id:?} changed before its conditional update; nothing was written"
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
            ProjectServiceError::GloballyLastVisibleWindow { project_id } => write!(
                f,
                "deleting project {project_id:?} would remove the globally last visible window; keep one window open"
            ),
            ProjectServiceError::SessionReleaseJournal { detail } => write!(
                f,
                "project session release could not be journaled; project records were preserved: {detail}"
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

/// Validate and construct one not-yet-persisted Project from the caller's requested fields while
/// holding the transaction that will insert it. Identity absence and sibling-name allocation are
/// intentionally part of this helper so Project-only creation and initial-window graph creation
/// cannot diverge on insert-only or unique-name semantics.
pub(crate) fn build_new_project_in_tx(
    conn: &rusqlite::Connection,
    project_id: String,
    name: String,
    root: String,
    opts: NewProject,
    hidden: bool,
    now_ms: u64,
) -> Result<Project, ProjectServiceError> {
    validate_name(&name)?;
    if let Some(icon) = opts.icon.as_deref() {
        validate_icon(icon)?;
    }
    if let Some(accent) = opts.accent_color.as_deref() {
        validate_accent(accent)?;
    }
    if crate::store_sqlite::load_one(conn, RecordKind::Project, &project_id)
        .map_err(deletion_map_error)?
        .is_some()
    {
        return Err(ProjectServiceError::ProjectAlreadyExists { project_id });
    }

    let sibling_names = crate::store_sqlite::load_all(conn, RecordKind::Project)
        .map_err(deletion_map_error)?
        .into_iter()
        .map(|value| {
            serde_json::from_value::<Project>(value)
                .map(|project| project.name)
                .map_err(|error| deletion_map_error(format!("deserialize project: {error}")))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Project {
        project_id,
        name: crate::names::unique_name(&name, &sibling_names),
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
        hidden,
    })
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
        self.create_with_receipt(project_id, name, root, opts, now_ms)
            .map(|created| created.project)
    }

    /// Create a brand-new project and return opaque authority to conditionally remove only this
    /// exact still-empty incarnation if a larger allocation fails before publishing children.
    /// Ordinary callers should use [`create`](Self::create); this receipt is a narrow rollback
    /// seam, not general delete authority.
    pub fn create_with_receipt(
        &self,
        project_id: impl Into<String>,
        name: impl Into<String>,
        root: impl Into<String>,
        opts: NewProject,
        now_ms: u64,
    ) -> Result<CreatedProject, ProjectServiceError> {
        self.create_with_visibility(project_id, name, root, opts, false, now_ms)
    }

    /// Create the hidden SYSTEM recovery project without a transient visible or unowned project
    /// row. This narrow startup seam has the same insert-only writer transaction as [`create`].
    pub fn create_hidden_system(
        &self,
        project_id: impl Into<String>,
        name: impl Into<String>,
        root: impl Into<String>,
        mut opts: NewProject,
        now_ms: u64,
    ) -> Result<Project, ProjectServiceError> {
        opts.system = true;
        self.create_with_visibility(project_id, name, root, opts, true, now_ms)
            .map(|created| created.project)
    }

    fn create_with_visibility(
        &self,
        project_id: impl Into<String>,
        name: impl Into<String>,
        root: impl Into<String>,
        opts: NewProject,
        hidden: bool,
        now_ms: u64,
    ) -> Result<CreatedProject, ProjectServiceError> {
        let project_id = project_id.into();
        let name = name.into();
        let root = root.into();

        self.paths
            .record_path(RecordKind::Project, &project_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base()).map_err(deletion_store_error)?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(deletion_store_error)?;
        // Name allocation and insert share the writer snapshot, so two creators cannot both pick
        // the same sibling suffix or pass an id preflight and then overwrite one another.
        let project = build_new_project_in_tx(&tx, project_id, name, root, opts, hidden, now_ms)?;
        let project_id = project.project_id.clone();
        let value = serde_json::to_value(&project)
            .map_err(|error| deletion_map_error(format!("serialize project: {error}")))?;
        crate::store_sqlite::upsert(&tx, RecordKind::Project, &project_id, &value)
            .map_err(deletion_map_error)?;
        let receipt = ProjectCreationReceipt {
            project_id: project_id.clone(),
            project_fingerprint: project_creation_fingerprint(&project)?,
            window_mutation_epoch: crate::db::window_mutation_epoch(&tx)
                .map_err(deletion_store_error)?,
        };
        tx.commit().map_err(deletion_store_error)?;
        let fields = value
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        crate::write_trace::trace_write(self.paths.base(), "Project", &project_id, &fields, now_ms);
        Ok(CreatedProject { project, receipt })
    }

    /// Delete a freshly inserted Project only while its private creation receipt still names the
    /// exact current bytes and global identity generation, and only while it remains completely
    /// empty.
    ///
    /// This method reads and validates the Project, every direct FK child cohort, and every strict
    /// project window order after one `BEGIN IMMEDIATE`. Any child, owner/order signal, malformed
    /// order, exact delete/recreate ABA, or unrelated owner-namespace mutation fails closed. The
    /// successful delete and one identity-epoch bump share the same transaction; its trace is
    /// emitted only after commit while preserving the store's DB-mutex → trace lock order.
    pub fn delete_created_if_unchanged(
        &self,
        receipt: &ProjectCreationReceipt,
        now_ms: u64,
    ) -> Result<ConditionalCreatedProjectDelete, ProjectServiceError> {
        self.paths
            .record_path(RecordKind::Project, &receipt.project_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base()).map_err(deletion_store_error)?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(deletion_store_error)?;

        let Some(current_value) =
            crate::store_sqlite::load_one(&tx, RecordKind::Project, &receipt.project_id)
                .map_err(deletion_map_error)?
        else {
            tx.commit().map_err(deletion_store_error)?;
            return Ok(ConditionalCreatedProjectDelete::Missing);
        };
        let current = serde_json::from_value::<Project>(current_value)
            .map_err(|error| deletion_map_error(format!("deserialize project: {error}")))?;
        if current.system {
            return Err(ProjectServiceError::SystemProjectCannotBeDeleted {
                project_id: receipt.project_id.clone(),
            });
        }
        let current_epoch = crate::db::window_mutation_epoch(&tx).map_err(deletion_store_error)?;
        if project_creation_fingerprint(&current)? != receipt.project_fingerprint
            || current_epoch != receipt.window_mutation_epoch
        {
            tx.commit().map_err(deletion_store_error)?;
            return Ok(ConditionalCreatedProjectDelete::Changed);
        }

        // Parse every order, not only the target row. Malformed/duplicate/unsafe foreign evidence
        // is uncertainty and therefore an error, never an inferred empty ownership graph.
        let all_orders = project_window_orders(&tx)?;
        let Some(target_order) = all_orders
            .iter()
            .find_map(|(owner, order)| (owner == &receipt.project_id).then_some(order))
        else {
            return Err(deletion_map_error(format!(
                "project {:?} disappeared while proving fresh-project cleanup",
                receipt.project_id
            )));
        };
        if !target_order.is_empty() {
            tx.commit().map_err(deletion_store_error)?;
            return Ok(ConditionalCreatedProjectDelete::Referenced);
        }

        // These are every schema-v1 durable owner directly rooted at Project. With a strict empty
        // target order and zero target-owned windows, there is no window id for a foreign order to
        // claim; parsing all orders above still fail-closes malformed foreign ownership evidence.
        let references: i64 = tx
            .query_row(
                "SELECT \
                     (SELECT COUNT(*) FROM workspaces WHERE project_id = ?1) + \
                     (SELECT COUNT(*) FROM agent_tasks WHERE project_id = ?1) + \
                     (SELECT COUNT(*) FROM windows WHERE project_id = ?1) + \
                     (SELECT COUNT(*) FROM layout_presets WHERE project_id = ?1)",
                [&receipt.project_id],
                |row| row.get(0),
            )
            .map_err(deletion_store_error)?;
        if references != 0 {
            tx.commit().map_err(deletion_store_error)?;
            return Ok(ConditionalCreatedProjectDelete::Referenced);
        }

        crate::db::preflight_window_mutation_epoch_bump(&tx).map_err(deletion_store_error)?;
        let removed = crate::store_sqlite::delete(&tx, RecordKind::Project, &receipt.project_id)
            .map_err(deletion_map_error)?;
        debug_assert!(
            removed,
            "the transaction-local snapshot observed the Project"
        );
        crate::db::bump_window_mutation_epoch(&tx).map_err(deletion_store_error)?;
        tx.commit().map_err(deletion_store_error)?;
        crate::write_trace::trace_delete(self.paths.base(), "Project", &receipt.project_id, now_ms);
        Ok(ConditionalCreatedProjectDelete::Deleted)
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

    /// Conditionally update the private/system visibility bit while preserving a concurrently
    /// appended window order. Startup recovery uses the exact snapshot it already validated; a
    /// concurrent metadata/ownership change is a typed refusal rather than silently being adopted.
    pub fn set_hidden_if_unchanged(
        &self,
        expected: &Project,
        hidden: bool,
        now_ms: u64,
    ) -> Result<Project, ProjectServiceError> {
        self.mutate_expected(&expected.project_id, Some(expected), now_ms, |project| {
            project.hidden = hidden;
        })
    }

    /// Prepare a complete, read-only project deletion plan.
    ///
    /// Session ownership is the union of:
    /// - durable `sessions → workspaces → project` rows;
    /// - every project `agent_tasks.current_session_id` and `session_history_json` id;
    /// - `worktree_provenance → workspace → project` markers;
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
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(deletion_store_error)?;
        let plan = project_deletion_plan(&tx, project_id)?;
        tx.commit().map_err(deletion_store_error)?;
        Ok(plan)
    }

    /// Atomically commit a previously prepared deletion plan without a global visibility guard.
    ///
    /// This method intentionally does NOT accept a bare project id. The caller must first obtain
    /// the complete ownership plan. An `IMMEDIATE` transaction recomputes the plan and requires
    /// byte-for-byte equality before it writes exact generation-bound release intents into the
    /// durable journal and deletes the graph in that same transaction. No daemon callback runs
    /// under the cached connection mutex. Missing/NULL Session generations require a strictly
    /// pre-resolved daemon observation; unresolved ids abort before any row is removed. Foreign-key
    /// cascades remove ordinary children; exact legacy NULL-FK windows proven solely owned by this
    /// project are explicitly removed in the same transaction. This rollback/internal seam may
    /// remove the final visible window; direct user actions must call
    /// [`commit_delete_preserving_global_last`](Self::commit_delete_preserving_global_last).
    pub fn commit_delete(
        &self,
        plan: &ProjectDeletionPlan,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
    ) -> Result<ProjectDeletionResult, ProjectServiceError> {
        self.commit_delete_internal(plan, pre_resolved, now_ms, false)
    }

    /// User-facing project deletion. In addition to exact ownership and release-journal proofs,
    /// this refuses a commit whose post-state would contain no visible ordinary-project window.
    pub fn commit_delete_preserving_global_last(
        &self,
        plan: &ProjectDeletionPlan,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
    ) -> Result<ProjectDeletionResult, ProjectServiceError> {
        self.commit_delete_internal(plan, pre_resolved, now_ms, true)
    }

    fn commit_delete_internal(
        &self,
        plan: &ProjectDeletionPlan,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
        preserve_global_last: bool,
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
                release_receipt: None,
            });
        }

        let visible_before = if preserve_global_last {
            crate::window_layout::visible_ordinary_project_window_count(&tx)?
        } else {
            0
        };

        let unresolved_ids = plan
            .kill_session_row_generations
            .iter()
            .filter_map(|(session_id, snapshot)| match snapshot {
                SessionRowSnapshot::Missing | SessionRowSnapshot::Present(None) => {
                    Some(session_id.as_str())
                }
                SessionRowSnapshot::Present(Some(_)) => None,
            })
            .collect::<BTreeSet<_>>();
        if let Some(unexpected) = pre_resolved
            .keys()
            .find(|session_id| !unresolved_ids.contains(session_id.as_str()))
        {
            return Err(ProjectServiceError::SessionReleaseJournal {
                detail: format!(
                    "pre-resolved session {unexpected:?} is not an unresolved target in the exact deletion plan"
                ),
            });
        }
        let mut release_targets = Vec::new();
        for session_id in &plan.kill_session_ids {
            let snapshot = plan
                .kill_session_row_generations
                .get(session_id)
                .ok_or_else(|| ProjectServiceError::SessionReleaseJournal {
                    detail: format!(
                        "deletion plan is missing the Session-row snapshot for {session_id:?}"
                    ),
                })?;
            let row_generation = match snapshot {
                SessionRowSnapshot::Missing => None,
                SessionRowSnapshot::Present(generation) => Some(generation.as_deref()),
            };
            if let Some(target) = resolve_exact_target(
                session_id,
                row_generation,
                SessionRowPolicy::RowMustBeAbsent,
                pre_resolved,
            )
            .map_err(|error| ProjectServiceError::SessionReleaseJournal {
                detail: error.to_string(),
            })? {
                release_targets.push(target);
            }
        }

        // Every actual Project identity deletion invalidates outstanding window-restore receipts:
        // even an empty project can be recreated byte-identically under the same caller-supplied
        // id, and an old receipt must not attach its FK owner to that new incarnation. Project
        // creation itself stays epoch-quiet because this preceding delete is the durable ABA
        // fence. Preflight before the irreversible daemon callback so exhaustion cannot release a
        // PTY and then force the SQLite delete to roll back.
        crate::db::preflight_window_mutation_epoch_bump(&tx)
            .map_err(|error| ProjectServiceError::Store(StoreError::Db(error.to_string())))?;

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

        let release_receipt =
            insert_pending_releases(&tx, &release_targets, now_ms).map_err(|error| {
                ProjectServiceError::SessionReleaseJournal {
                    detail: error.to_string(),
                }
            })?;
        crate::store_sqlite::check_window_layout_test_failure(
            "after-project-release-journal",
            &plan.project_id,
        )
        .map_err(deletion_map_error)?;

        // Provenance is intentionally a soft owner with no foreign key: remove only the exact
        // markers that the revalidated ownership plan assigned to this project's workspaces.
        for session_id in &plan.worktree_provenance_session_ids {
            tx.execute(
                "DELETE FROM worktree_provenance WHERE session_id = ?1",
                [session_id],
            )
            .map_err(|error| ProjectServiceError::Store(StoreError::Db(error.to_string())))?;
        }

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
        if preserve_global_last
            && visible_before > 0
            && crate::window_layout::visible_ordinary_project_window_count(&tx)? == 0
        {
            return Err(ProjectServiceError::GloballyLastVisibleWindow {
                project_id: plan.project_id.clone(),
            });
        }
        if removed {
            crate::db::bump_window_mutation_epoch(&tx)
                .map_err(|error| ProjectServiceError::Store(StoreError::Db(error.to_string())))?;
        }
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
            release_receipt,
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

    /// Persist an arbitrary duplicate-free project window-order value.
    ///
    /// This compatibility seam is intentionally unconditional and is retained for migration,
    /// bootstrap, and test fixtures. Ordinary app/agent intent must use
    /// [`reorder_owned_windows`](Self::reorder_owned_windows), which validates the fresh owner graph
    /// and advances the global window-mutation epoch in the same writer transaction.
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

    /// Reorder exactly the windows whose fresh relational owner is `project_id`.
    ///
    /// The project row, every window FK, and every strictly parsed project order are read after one
    /// `BEGIN IMMEDIATE`. The requested ids must be an exact permutation of the current FK-owned
    /// cohort, and none may be named by another project's order. This makes a stale p1 intent fail
    /// closed after a p1→p2 transfer and prevents a p1 request from importing a p2-owned window.
    /// Refusals and no-ops do not advance the global window-mutation epoch or emit a trace.
    pub fn reorder_owned_windows(
        &self,
        project_id: &str,
        ordered_window_ids: &[String],
        now_ms: u64,
    ) -> Result<Project, ProjectServiceError> {
        self.paths
            .record_path(RecordKind::Project, project_id)
            .map_err(StoreError::Id)?;
        let mut wanted_ids = BTreeSet::new();
        for window_id in ordered_window_ids {
            self.paths
                .record_path(RecordKind::WindowLayout, window_id)
                .map_err(StoreError::Id)?;
            if !wanted_ids.insert(window_id.as_str()) {
                return Err(ProjectServiceError::InvalidOrder {
                    reason: format!("duplicate window id {window_id:?} in requested order"),
                });
            }
        }

        let arc = crate::db::conn_for(self.paths.base()).map_err(deletion_store_error)?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(deletion_store_error)?;
        let Some(project_value) =
            crate::store_sqlite::load_one(&tx, RecordKind::Project, project_id)
                .map_err(deletion_map_error)?
        else {
            return Err(ProjectServiceError::ProjectNotFound {
                project_id: project_id.to_string(),
            });
        };
        let mut project = serde_json::from_value::<Project>(project_value)
            .map_err(|error| deletion_map_error(format!("deserialize project: {error}")))?;

        let mut statement = tx
            .prepare("SELECT window_id FROM windows WHERE project_id = ?1 ORDER BY window_id")
            .map_err(deletion_store_error)?;
        let owned_ids = statement
            .query_map([project_id], |row| row.get::<_, String>(0))
            .map_err(deletion_store_error)?
            .collect::<Result<BTreeSet<_>, _>>()
            .map_err(deletion_store_error)?;
        drop(statement);
        let wanted_owned_ids = ordered_window_ids.iter().cloned().collect::<BTreeSet<_>>();
        if wanted_owned_ids != owned_ids {
            return Err(ProjectServiceError::InvalidOrder {
                reason: "requested window order is not a permutation of the fresh FK-owned cohort"
                    .into(),
            });
        }

        let project_orders = project_window_orders(&tx)?;
        let foreign_order_owners = project_orders
            .iter()
            .filter(|(owner, _)| owner != project_id)
            .filter(|(_, order)| order.iter().any(|window_id| owned_ids.contains(window_id)))
            .map(|(owner, _)| owner.clone())
            .collect::<Vec<_>>();
        if !foreign_order_owners.is_empty() {
            return Err(ProjectServiceError::InvalidOrder {
                reason: format!(
                    "FK-owned window is also ordered by foreign projects {foreign_order_owners:?}"
                ),
            });
        }

        if project.window_order == ordered_window_ids {
            tx.commit().map_err(deletion_store_error)?;
            return Ok(project);
        }
        let order_json = serde_json::to_string(ordered_window_ids)
            .map_err(|error| deletion_map_error(format!("serialize project order: {error}")))?;
        let changed = tx
            .execute(
                "UPDATE projects SET window_order_json = ?2 WHERE project_id = ?1",
                rusqlite::params![project_id, order_json],
            )
            .map_err(deletion_store_error)?;
        debug_assert_eq!(changed, 1, "writer-local project order row must exist");
        crate::db::bump_window_mutation_epoch(&tx).map_err(deletion_store_error)?;
        tx.commit().map_err(deletion_store_error)?;

        project.window_order = ordered_window_ids.to_vec();
        crate::write_trace::trace_write(
            self.paths.base(),
            "Project",
            project_id,
            &["window_order".into()],
            now_ms,
        );
        Ok(project)
    }

    /// Fresh transaction-local load → edit → full project upsert, preserving all unedited fields.
    ///
    /// Project rows carry `window_order`, so even metadata-only updates must hold the SQLite writer
    /// fence across their read-modify-write; an autocommit load followed by a full-row write could
    /// otherwise erase a concurrent window-owner append. Old and new orders are strictly validated,
    /// an actual order change advances the global window epoch exactly once, and a true no-op emits
    /// neither a write nor a trace.
    fn mutate(
        &self,
        project_id: &str,
        now_ms: u64,
        edit: impl FnOnce(&mut Project),
    ) -> Result<Project, ProjectServiceError> {
        self.mutate_expected(project_id, None, now_ms, edit)
    }

    fn mutate_expected(
        &self,
        project_id: &str,
        expected: Option<&Project>,
        now_ms: u64,
        edit: impl FnOnce(&mut Project),
    ) -> Result<Project, ProjectServiceError> {
        self.paths
            .record_path(RecordKind::Project, project_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base()).map_err(deletion_store_error)?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(deletion_store_error)?;
        let Some(project_value) =
            crate::store_sqlite::load_one(&tx, RecordKind::Project, project_id)
                .map_err(deletion_map_error)?
        else {
            return Err(ProjectServiceError::ProjectNotFound {
                project_id: project_id.to_string(),
            });
        };
        let mut project = serde_json::from_value::<Project>(project_value)
            .map_err(|error| deletion_map_error(format!("deserialize project: {error}")))?;
        validate_project_window_order(project_id, &project.window_order)?;
        if expected.is_some_and(|expected| &project != expected) {
            return Err(ProjectServiceError::ProjectChanged {
                project_id: project_id.to_string(),
            });
        }
        let previous = project.clone();
        edit(&mut project);
        validate_project_window_order(project_id, &project.window_order)?;
        if project == previous {
            tx.commit().map_err(deletion_store_error)?;
            return Ok(project);
        }

        let window_order_changed = project.window_order != previous.window_order;
        let value = serde_json::to_value(&project)
            .map_err(|error| deletion_map_error(format!("serialize project: {error}")))?;
        crate::store_sqlite::upsert(&tx, RecordKind::Project, project_id, &value)
            .map_err(deletion_map_error)?;
        if window_order_changed {
            crate::db::bump_window_mutation_epoch(&tx).map_err(deletion_store_error)?;
        }
        tx.commit().map_err(deletion_store_error)?;

        let fields = value
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        crate::write_trace::trace_write(self.paths.base(), "Project", project_id, &fields, now_ms);
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
        let pre_resolved = confirmed_absent_resolutions(&plan);
        service.commit_delete(&plan, &pre_resolved, 99).unwrap()
    }

    fn confirmed_absent_resolutions(plan: &ProjectDeletionPlan) -> PreResolvedSessionGenerations {
        plan.kill_session_row_generations
            .iter()
            .filter_map(|(session_id, snapshot)| match snapshot {
                SessionRowSnapshot::Missing | SessionRowSnapshot::Present(None) => Some((
                    session_id.clone(),
                    crate::PreResolvedSessionState::ConfirmedAbsent,
                )),
                SessionRowSnapshot::Present(Some(_)) => None,
            })
            .collect()
    }

    fn ids(ps: &[Project]) -> Vec<&str> {
        ps.iter().map(|p| p.project_id.as_str()).collect()
    }

    fn window_epoch(paths: &AppPaths) -> u32 {
        let connection = crate::db::conn_for(paths.base()).unwrap();
        let epoch = crate::db::window_mutation_epoch(&connection.lock().unwrap()).unwrap();
        epoch
    }

    fn create_assigned_window(paths: &AppPaths, window_id: &str, project_id: &str) {
        let windows = crate::WindowLayoutService::new(paths);
        let created = windows.create_empty_snapshot(window_id, 1).unwrap();
        let outcome = windows
            .assign_project_and_order_if_unchanged(&created, None, project_id, 2)
            .unwrap();
        assert!(matches!(
            outcome,
            crate::ConditionalWindowProjectAssignment::Applied(_)
        ));
    }

    fn create_visible_assigned_window(
        paths: &AppPaths,
        window_id: &str,
        project_id: &str,
        tab_id: &str,
    ) {
        create_assigned_window(paths, window_id, project_id);
        crate::WindowLayoutService::new(paths)
            .open_tab(
                window_id,
                tab_id,
                &format!("{tab_id}-session"),
                tab_id,
                false,
                crate::AttentionState::default(),
                2,
            )
            .unwrap();
    }

    fn pending_release_count(paths: &AppPaths) -> i64 {
        let connection = crate::db::conn_for(paths.base()).unwrap();
        let guard = connection.lock().unwrap();
        guard
            .query_row("SELECT COUNT(*) FROM pending_session_releases", [], |row| {
                row.get(0)
            })
            .unwrap()
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
    fn created_project_receipt_deletes_only_exact_empty_incarnation() {
        let (_t, paths) = temp_paths();
        let created = svc(&paths)
            .create_with_receipt(
                "created-empty",
                "Created empty",
                "/empty",
                NewProject::default(),
                10,
            )
            .unwrap();
        assert_eq!(
            svc(&paths).load("created-empty").unwrap(),
            Some(created.project)
        );
        let epoch_before = window_epoch(&paths);
        let traces_before = crate::write_trace::recent()
            .into_iter()
            .filter(|event| {
                event.op == "delete" && event.kind == "Project" && event.id == "created-empty"
            })
            .count();

        assert_eq!(
            svc(&paths)
                .delete_created_if_unchanged(&created.receipt, 11)
                .unwrap(),
            ConditionalCreatedProjectDelete::Deleted
        );
        assert!(svc(&paths).load("created-empty").unwrap().is_none());
        assert_eq!(window_epoch(&paths), epoch_before + 1);
        assert_eq!(
            crate::write_trace::recent()
                .into_iter()
                .filter(|event| {
                    event.op == "delete" && event.kind == "Project" && event.id == "created-empty"
                })
                .count(),
            traces_before + 1
        );

        let epoch_after = window_epoch(&paths);
        assert_eq!(
            svc(&paths)
                .delete_created_if_unchanged(&created.receipt, 12)
                .unwrap(),
            ConditionalCreatedProjectDelete::Missing
        );
        assert_eq!(window_epoch(&paths), epoch_after);
    }

    #[test]
    fn created_project_receipt_refuses_every_direct_child_and_foreign_owner() {
        let (_t, paths) = temp_paths();
        let mut receipts = Vec::new();
        for project_id in [
            "created-workspace-ref",
            "created-task-ref",
            "created-window-ref",
            "created-preset-ref",
            "created-foreign-order-ref",
        ] {
            receipts.push(
                svc(&paths)
                    .create_with_receipt(project_id, project_id, "/root", NewProject::default(), 20)
                    .unwrap(),
            );
        }
        svc(&paths)
            .create(
                "created-foreign-order-owner",
                "Foreign owner",
                "/root",
                NewProject::default(),
                20,
            )
            .unwrap();

        // A second connection publishes each possible direct Project child after the receipts
        // were captured. These raw fixture writes intentionally leave the epoch unchanged so this
        // test proves the explicit reference queries, not the independent epoch fence.
        let other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        other.pragma_update(None, "foreign_keys", "ON").unwrap();
        other
            .execute(
                "INSERT INTO workspaces \
                 (workspace_id, project_id, root, policy, consent_json) \
                 VALUES ('created-workspace-child', 'created-workspace-ref', '/root', \
                         'scratch_cwd', '{}')",
                [],
            )
            .unwrap();
        other
            .execute(
                "INSERT INTO agent_tasks \
                 (agent_task_id, project_id, goal, state, current_session_id, \
                  session_history_json, created_at_ms, updated_at_ms, result_summary) \
                 VALUES ('created-task-child', 'created-task-ref', 'goal', 'queued', NULL, \
                         '[]', 20, 20, NULL)",
                [],
            )
            .unwrap();
        other
            .execute(
                "INSERT INTO windows (window_id, project_id, name) \
                 VALUES ('created-window-child', 'created-window-ref', NULL)",
                [],
            )
            .unwrap();
        other
            .execute(
                "INSERT INTO layout_presets \
                 (preset_id, project_id, name, created_at_ms, tabs_json) \
                 VALUES ('created-preset-child', 'created-preset-ref', 'Preset', 20, '[]')",
                [],
            )
            .unwrap();
        other
            .execute(
                "INSERT INTO windows (window_id, project_id, name) \
                 VALUES ('created-foreign-ordered-window', 'created-foreign-order-ref', NULL)",
                [],
            )
            .unwrap();
        other
            .execute(
                "UPDATE projects SET window_order_json = \
                 '[\"created-foreign-ordered-window\"]' \
                 WHERE project_id = 'created-foreign-order-owner'",
                [],
            )
            .unwrap();

        let epoch_before = window_epoch(&paths);
        for created in &receipts {
            assert_eq!(
                svc(&paths)
                    .delete_created_if_unchanged(&created.receipt, 21)
                    .unwrap(),
                ConditionalCreatedProjectDelete::Referenced,
                "child/foreign owner must preserve {}",
                created.project.project_id
            );
            assert_eq!(
                svc(&paths).load(&created.project.project_id).unwrap(),
                Some(created.project.clone())
            );
        }
        assert_eq!(window_epoch(&paths), epoch_before);
    }

    #[test]
    fn created_project_receipt_fails_closed_on_changed_or_malformed_orders() {
        let (_t, paths) = temp_paths();
        let changed = svc(&paths)
            .create_with_receipt(
                "created-order-changed",
                "Changed order",
                "/root",
                NewProject::default(),
                30,
            )
            .unwrap();
        let malformed_target = svc(&paths)
            .create_with_receipt(
                "created-malformed-target",
                "Malformed target",
                "/root",
                NewProject::default(),
                30,
            )
            .unwrap();
        svc(&paths)
            .create(
                "created-malformed-foreign",
                "Malformed foreign",
                "/root",
                NewProject::default(),
                30,
            )
            .unwrap();
        let other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        other
            .execute(
                "UPDATE projects SET window_order_json = '[\"new-owner\"]' \
                 WHERE project_id = 'created-order-changed'",
                [],
            )
            .unwrap();

        let epoch_before = window_epoch(&paths);
        assert_eq!(
            svc(&paths)
                .delete_created_if_unchanged(&changed.receipt, 31)
                .unwrap(),
            ConditionalCreatedProjectDelete::Changed
        );
        assert_eq!(window_epoch(&paths), epoch_before);

        other
            .execute(
                "UPDATE projects SET window_order_json = '{not-json' \
                 WHERE project_id = 'created-malformed-foreign'",
                [],
            )
            .unwrap();
        assert!(matches!(
            svc(&paths).delete_created_if_unchanged(&malformed_target.receipt, 32),
            Err(ProjectServiceError::Store(StoreError::Map(ref detail)))
                if detail.contains("invalid window_order")
        ));
        assert_eq!(
            svc(&paths).load("created-malformed-target").unwrap(),
            Some(malformed_target.project)
        );
        assert_eq!(window_epoch(&paths), epoch_before);
    }

    #[test]
    fn created_project_receipt_refuses_unrelated_epoch_and_exact_project_aba() {
        {
            let (_t, paths) = temp_paths();
            let created = svc(&paths)
                .create_with_receipt(
                    "created-unrelated-epoch",
                    "Unrelated epoch",
                    "/root",
                    NewProject::default(),
                    40,
                )
                .unwrap();
            crate::WindowLayoutService::new(&paths)
                .create_empty("unrelated-window", 41)
                .unwrap();
            let epoch_before = window_epoch(&paths);
            assert_eq!(
                svc(&paths)
                    .delete_created_if_unchanged(&created.receipt, 42)
                    .unwrap(),
                ConditionalCreatedProjectDelete::Changed
            );
            assert_eq!(
                svc(&paths).load("created-unrelated-epoch").unwrap(),
                Some(created.project)
            );
            assert_eq!(window_epoch(&paths), epoch_before);
        }

        {
            let (_t, paths) = temp_paths();
            let original = svc(&paths)
                .create_with_receipt(
                    "created-project-aba",
                    "Same bytes",
                    "/same-root",
                    NewProject::default(),
                    43,
                )
                .unwrap();
            assert!(commit_delete(&paths, "created-project-aba").removed);
            let recreated = svc(&paths)
                .create(
                    "created-project-aba",
                    "Same bytes",
                    "/same-root",
                    NewProject::default(),
                    43,
                )
                .unwrap();
            assert_eq!(recreated, original.project);
            let epoch_before = window_epoch(&paths);
            assert_eq!(
                svc(&paths)
                    .delete_created_if_unchanged(&original.receipt, 44)
                    .unwrap(),
                ConditionalCreatedProjectDelete::Changed
            );
            assert_eq!(
                svc(&paths).load("created-project-aba").unwrap(),
                Some(recreated)
            );
            assert_eq!(window_epoch(&paths), epoch_before);
        }
    }

    #[test]
    fn created_project_receipt_epoch_max_rolls_back_without_trace() {
        let (_t, paths) = temp_paths();
        svc(&paths).list().unwrap();
        {
            let connection = crate::db::conn_for(paths.base()).unwrap();
            connection
                .lock()
                .unwrap()
                .pragma_update(None, "user_version", i32::MAX)
                .unwrap();
        }
        let created = svc(&paths)
            .create_with_receipt(
                "created-max-epoch",
                "Max epoch",
                "/root",
                NewProject::default(),
                50,
            )
            .unwrap();
        let traces_before = crate::write_trace::recent()
            .into_iter()
            .filter(|event| {
                event.op == "delete" && event.kind == "Project" && event.id == "created-max-epoch"
            })
            .count();

        let error = svc(&paths)
            .delete_created_if_unchanged(&created.receipt, 51)
            .unwrap_err();
        assert!(matches!(
            error,
            ProjectServiceError::Store(StoreError::Db(ref detail))
                if detail.contains("epoch") && detail.contains("exhausted")
        ));
        assert_eq!(
            svc(&paths).load("created-max-epoch").unwrap(),
            Some(created.project)
        );
        assert_eq!(window_epoch(&paths), i32::MAX as u32);
        assert_eq!(
            crate::write_trace::recent()
                .into_iter()
                .filter(|event| {
                    event.op == "delete"
                        && event.kind == "Project"
                        && event.id == "created-max-epoch"
                })
                .count(),
            traces_before
        );
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
    fn hidden_system_create_is_insert_only_and_exact_hidden_repair_rejects_stale_snapshot() {
        let (_t, paths) = temp_paths();
        let hidden = svc(&paths)
            .create_hidden_system(
                "hidden-system",
                "Recovery",
                "/recovery",
                NewProject::default(),
                1,
            )
            .unwrap();
        assert!(hidden.system && hidden.hidden);
        assert!(matches!(
            svc(&paths)
                .create_hidden_system(
                    "hidden-system",
                    "Replacement",
                    "/replacement",
                    NewProject::default(),
                    2,
                )
                .unwrap_err(),
            ProjectServiceError::ProjectAlreadyExists { .. }
        ));
        assert_eq!(svc(&paths).load("hidden-system").unwrap().unwrap(), hidden);

        svc(&paths)
            .create("repair-system", "Repair", "/p", NewProject::default(), 1)
            .unwrap();
        let stale = svc(&paths).load("repair-system").unwrap().unwrap();
        create_assigned_window(&paths, "repair-window", "repair-system");
        let current = svc(&paths).load("repair-system").unwrap().unwrap();
        let epoch_before = window_epoch(&paths);
        assert!(matches!(
            svc(&paths)
                .set_hidden_if_unchanged(&stale, true, 3)
                .unwrap_err(),
            ProjectServiceError::ProjectChanged { .. }
        ));
        assert_eq!(svc(&paths).load("repair-system").unwrap().unwrap(), current);
        assert!(!current.hidden);
        assert_eq!(current.window_order, vec!["repair-window"]);
        assert_eq!(window_epoch(&paths), epoch_before);
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
    fn guarded_project_delete_refuses_the_global_last_without_writing_or_journaling() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("last", "Last", "/last", NewProject::default(), 1)
            .unwrap();
        create_visible_assigned_window(&paths, "last-window", "last", "last-tab");

        let service = svc(&paths);
        let plan = service.plan_delete("last").unwrap();
        let pre_resolved = confirmed_absent_resolutions(&plan);
        let before_epoch = window_epoch(&paths);
        let before_releases = pending_release_count(&paths);

        assert!(matches!(
            service
                .commit_delete_preserving_global_last(&plan, &pre_resolved, 3)
                .unwrap_err(),
            ProjectServiceError::GloballyLastVisibleWindow { project_id }
                if project_id == "last"
        ));
        assert!(service.load("last").unwrap().is_some());
        assert!(crate::WindowLayoutService::new(&paths)
            .load("last-window")
            .unwrap()
            .is_some());
        assert_eq!(window_epoch(&paths), before_epoch);
        assert_eq!(pending_release_count(&paths), before_releases);
    }

    #[test]
    fn guarded_project_delete_allows_removal_when_another_window_is_visible() {
        let (_t, paths) = temp_paths();
        for project_id in ["target", "survivor"] {
            svc(&paths)
                .create(project_id, project_id, "/root", NewProject::default(), 1)
                .unwrap();
        }
        create_visible_assigned_window(&paths, "target-window", "target", "target-tab");
        create_visible_assigned_window(&paths, "survivor-window", "survivor", "survivor-tab");

        let service = svc(&paths);
        let plan = service.plan_delete("target").unwrap();
        let pre_resolved = confirmed_absent_resolutions(&plan);
        let result = service
            .commit_delete_preserving_global_last(&plan, &pre_resolved, 3)
            .unwrap();

        assert!(result.removed);
        assert!(service.load("target").unwrap().is_none());
        assert!(crate::WindowLayoutService::new(&paths)
            .load("survivor-window")
            .unwrap()
            .unwrap()
            .tabs
            .iter()
            .any(|tab| !tab.stashed));
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
            WindowLayout, Workspace, WorkspaceConsent, WorktreeProvenance,
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
        let provenance = WorktreeProvenance {
            session_id: "s1".into(),
            workspace_id: "ws1".into(),
            repo_root: "/r".into(),
            target_path: "/r/.worktrees/s1".into(),
            branch: "maestro/ws1/s1".into(),
            created_at_ms: 1,
        };
        crate::store::write_record(&paths, RecordKind::WorktreeProvenance, "s1", 1, &provenance)
            .unwrap();
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
        assert_eq!(plan.worktree_provenance_session_ids, vec!["s1"]);
        assert_eq!(plan.kill_session_ids, vec!["s1"]);
        let pre_resolved = confirmed_absent_resolutions(&plan);
        assert!(
            svc(&paths)
                .commit_delete(&plan, &pre_resolved, 3)
                .unwrap()
                .removed
        );
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        for table in [
            "projects",
            "workspaces",
            "sessions",
            "windows",
            "tabs",
            "worktree_provenance",
        ] {
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

        assert!(matches!(
            svc(&paths)
                .commit_delete(&stale, &PreResolvedSessionGenerations::new(), 3)
                .unwrap_err(),
            ProjectServiceError::DeletionPlanChanged { .. }
        ));
        assert!(svc(&paths).load("target").unwrap().is_some());
    }

    #[test]
    fn delete_unresolved_generation_rolls_back_without_losing_ownership_evidence() {
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
        create_assigned_window(&paths, "release-failure-window", "target");
        let plan = svc(&paths).plan_delete("target").unwrap();
        let epoch_before = window_epoch(&paths);

        assert!(matches!(
            svc(&paths)
                .commit_delete(&plan, &PreResolvedSessionGenerations::new(), 3)
                .unwrap_err(),
            ProjectServiceError::SessionReleaseJournal { .. }
        ));
        assert!(svc(&paths).load("target").unwrap().is_some());
        assert!(crate::WindowLayoutService::new(&paths)
            .load("release-failure-window")
            .unwrap()
            .is_some());
        assert_eq!(window_epoch(&paths), epoch_before);
        assert!(crate::store::load_one::<SessionRecord>(
            &paths,
            RecordKind::Session,
            "must-release"
        )
        .unwrap()
        .is_some());
    }

    #[test]
    fn project_failure_after_release_journal_rolls_back_graph_and_intent() {
        use crate::records::{LaunchSpec, SessionKind, SessionRecord, SessionStatus};

        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("journal-target", "Target", "/r", NewProject::default(), 1)
            .unwrap();
        let workspace = crate::records::Workspace {
            workspace_id: "journal-target-workspace".into(),
            project_id: "journal-target".into(),
            root: "/r".into(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: crate::records::WorkspaceConsent::default(),
        };
        crate::store::write_record(
            &paths,
            RecordKind::Workspace,
            &workspace.workspace_id,
            1,
            &workspace,
        )
        .unwrap();
        let session = SessionRecord {
            session_id: "journal-target-session".into(),
            workspace_id: workspace.workspace_id.clone(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::OptOut,
            cwd_resolved: "/r".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: Some("journal-target-generation".into()),
            status: SessionStatus::Live,
        };
        crate::store::write_record(
            &paths,
            RecordKind::Session,
            &session.session_id,
            1,
            &session,
        )
        .unwrap();
        create_assigned_window(&paths, "journal-target-window", "journal-target");
        let plan = svc(&paths).plan_delete("journal-target").unwrap();
        let epoch_before = window_epoch(&paths);
        let _failure = crate::store_sqlite::install_window_layout_test_failure(
            "journal-target",
            "after-project-release-journal",
        );

        assert!(matches!(
            svc(&paths).commit_delete(&plan, &PreResolvedSessionGenerations::new(), 3),
            Err(ProjectServiceError::Store(StoreError::Map(ref detail)))
                if detail.contains("after-project-release-journal")
        ));
        assert!(svc(&paths).load("journal-target").unwrap().is_some());
        assert!(crate::WindowLayoutService::new(&paths)
            .load("journal-target-window")
            .unwrap()
            .is_some());
        assert!(crate::store::load_one::<SessionRecord>(
            &paths,
            RecordKind::Session,
            &session.session_id,
        )
        .unwrap()
        .is_some());
        assert_eq!(window_epoch(&paths), epoch_before);
        let connection = crate::db::conn_for(paths.base()).unwrap();
        let pending: i64 = connection
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM pending_session_releases", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(pending, 0);
    }

    #[test]
    fn project_missing_session_row_uses_pre_resolved_generation_without_store_reentry() {
        use crate::records::AttentionState;
        use std::cell::Cell;

        let (_t, paths) = temp_paths();
        svc(&paths)
            .create(
                "missing-row-project",
                "Target",
                "/r",
                NewProject::default(),
                1,
            )
            .unwrap();
        create_assigned_window(&paths, "missing-row-window", "missing-row-project");
        crate::WindowLayoutService::new(&paths)
            .open_tab(
                "missing-row-window",
                "missing-row-tab",
                "missing-row-session",
                "Missing row",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        let plan = svc(&paths).plan_delete("missing-row-project").unwrap();
        assert_eq!(plan.kill_session_ids, ["missing-row-session"]);
        assert_eq!(
            plan.unresolved_release_session_ids(),
            ["missing-row-session"]
        );
        let pre_resolved = [(
            "missing-row-session".to_string(),
            crate::PreResolvedSessionState::Generation("missing-row-generation".into()),
        )]
        .into_iter()
        .collect();

        let result = svc(&paths).commit_delete(&plan, &pre_resolved, 3).unwrap();
        assert!(result.removed);
        assert!(svc(&paths).load("missing-row-project").unwrap().is_none());
        let cas_calls = Cell::new(0_usize);
        assert!(matches!(
            crate::SessionReleaseService::new(&paths).attempt_owned::<()>(
                result.release_receipt.unwrap(),
                |_| Ok(()),
                |_| {
                    cas_calls.set(cas_calls.get() + 1);
                    crate::CasPublication::Confirmed
                },
            ),
            crate::ReleaseOperationOutcome::Complete {
                confirmed: 1,
                retained: 0,
            }
        ));
        assert_eq!(cas_calls.get(), 1);
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
            last_known_generation: Some("generation-shared-pane".into()),
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

        let before_epoch = window_epoch(&paths);
        let before_releases = pending_release_count(&paths);
        assert!(matches!(
            svc(&paths)
                .commit_delete_preserving_global_last(
                    &plan,
                    &PreResolvedSessionGenerations::new(),
                    2,
                )
                .unwrap_err(),
            ProjectServiceError::GloballyLastVisibleWindow { project_id }
                if project_id == "target"
        ));
        assert!(svc(&paths).load("target").unwrap().is_some());
        assert!(windows
            .load("surviving-window")
            .unwrap()
            .unwrap()
            .tabs
            .iter()
            .any(|tab| tab.tab_id == "surviving-pane"));
        assert_eq!(window_epoch(&paths), before_epoch);
        assert_eq!(pending_release_count(&paths), before_releases);

        let result = svc(&paths)
            .commit_delete(&plan, &PreResolvedSessionGenerations::new(), 3)
            .unwrap();
        assert!(result.removed);
        assert!(result.release_receipt.is_some());
        assert_eq!(result.removed_tab_keys, plan.remove_tab_keys);
        let surviving = windows.load("surviving-window").unwrap().unwrap();
        assert!(surviving.tabs.is_empty());
    }

    #[test]
    fn exhausted_window_epoch_refuses_project_delete_before_daemon_release() {
        let (_tmp, paths) = temp_paths();
        svc(&paths)
            .create("epoch-target", "Target", "/r", NewProject::default(), 1)
            .unwrap();
        let windows = crate::WindowLayoutService::new(&paths);
        windows.create_empty("epoch-owned-window", 1).unwrap();
        crate::store::set_window_project(&paths, "epoch-owned-window", "epoch-target").unwrap();
        {
            let connection = crate::db::conn_for(paths.base()).unwrap();
            let guard = connection.lock().unwrap();
            guard.pragma_update(None, "user_version", i32::MAX).unwrap();
        }
        // Capture the deletion plan at the intentionally exhausted generation. A plan captured
        // before this test-only PRAGMA change is correctly rejected as stale before preflight and
        // therefore would not exercise the no-release-at-capacity contract below.
        let plan = svc(&paths).plan_delete("epoch-target").unwrap();

        let error = svc(&paths)
            .commit_delete(&plan, &PreResolvedSessionGenerations::new(), 3)
            .unwrap_err();
        assert!(matches!(
            error,
            ProjectServiceError::Store(StoreError::Db(ref detail))
                if detail.contains("epoch") && detail.contains("exhausted")
        ));
        assert!(svc(&paths).load("epoch-target").unwrap().is_some());
        assert!(windows.load("epoch-owned-window").unwrap().is_some());
        let connection = crate::db::conn_for(paths.base()).unwrap();
        assert_eq!(
            crate::db::window_mutation_epoch(&connection.lock().unwrap()).unwrap(),
            i32::MAX as u32
        );
    }

    #[test]
    fn exact_project_identity_recreation_invalidates_a_prepared_release_plan() {
        let (_tmp, paths) = temp_paths();
        let original = svc(&paths)
            .create(
                "project-plan-aba",
                "Same bytes",
                "/same-root",
                NewProject::default(),
                41,
            )
            .unwrap();
        let stale_plan = svc(&paths).plan_delete(&original.project_id).unwrap();
        let epoch_before_delete = window_epoch(&paths);

        assert!(
            crate::store::delete_record(&paths, RecordKind::Project, &original.project_id,)
                .unwrap()
        );
        assert_eq!(window_epoch(&paths), epoch_before_delete + 1);
        let recreated = svc(&paths)
            .create(
                "project-plan-aba",
                "Same bytes",
                "/same-root",
                NewProject::default(),
                41,
            )
            .unwrap();
        assert_eq!(recreated, original);
        assert_eq!(window_epoch(&paths), epoch_before_delete + 1);

        assert!(matches!(
            svc(&paths).commit_delete(
                &stale_plan,
                &PreResolvedSessionGenerations::new(),
                43
            ),
            Err(ProjectServiceError::DeletionPlanChanged { ref project_id })
                if project_id == "project-plan-aba"
        ));
        assert_eq!(
            svc(&paths).load("project-plan-aba").unwrap(),
            Some(original)
        );
    }

    #[test]
    fn project_delete_revalidates_and_epochs_stale_window_order_ownership() {
        let (_tmp, paths) = temp_paths();
        svc(&paths)
            .create("order-owner", "Order owner", "/r", NewProject::default(), 1)
            .unwrap();
        svc(&paths)
            .reorder_windows("order-owner", &["already-gone-a".into()], 2)
            .unwrap();
        let stale_plan = svc(&paths).plan_delete("order-owner").unwrap();
        assert_eq!(stale_plan.window_order_ids, ["already-gone-a"]);
        assert!(stale_plan.window_ids.is_empty());

        svc(&paths)
            .reorder_windows("order-owner", &["already-gone-b".into()], 3)
            .unwrap();
        let epoch_before_refusal = window_epoch(&paths);
        assert!(matches!(
            svc(&paths).commit_delete(&stale_plan, &PreResolvedSessionGenerations::new(), 4),
            Err(ProjectServiceError::DeletionPlanChanged { .. })
        ));
        assert_eq!(window_epoch(&paths), epoch_before_refusal);
        assert!(svc(&paths).load("order-owner").unwrap().is_some());

        let fresh_plan = svc(&paths).plan_delete("order-owner").unwrap();
        assert_eq!(fresh_plan.window_order_ids, ["already-gone-b"]);
        assert!(
            svc(&paths)
                .commit_delete(&fresh_plan, &PreResolvedSessionGenerations::new(), 4)
                .unwrap()
                .removed
        );
        assert_eq!(window_epoch(&paths), epoch_before_refusal + 1);
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
        let pre_resolved = confirmed_absent_resolutions(&plan);
        assert!(
            svc(&paths)
                .commit_delete(&plan, &pre_resolved, 3)
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

    #[test]
    fn reorder_owned_windows_uses_the_fresh_fk_cohort_and_noop_is_quiet() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("owned-order", "Owned", "/p", NewProject::default(), 1)
            .unwrap();
        create_assigned_window(&paths, "owned-a", "owned-order");
        create_assigned_window(&paths, "owned-b", "owned-order");

        let epoch_before = window_epoch(&paths);
        let reordered = svc(&paths)
            .reorder_owned_windows("owned-order", &["owned-b".into(), "owned-a".into()], 10)
            .unwrap();
        assert_eq!(
            reordered.window_order,
            vec!["owned-b".to_string(), "owned-a".to_string()]
        );
        assert_eq!(window_epoch(&paths), epoch_before + 1);

        let quiet_epoch = window_epoch(&paths);
        let quiet_trace_count = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "Project" && event.id == "owned-order")
            .count();
        let unchanged = svc(&paths)
            .reorder_owned_windows("owned-order", &["owned-b".into(), "owned-a".into()], 11)
            .unwrap();
        assert_eq!(unchanged, reordered);
        assert_eq!(window_epoch(&paths), quiet_epoch);
        assert_eq!(
            crate::write_trace::recent()
                .into_iter()
                .filter(|event| event.kind == "Project" && event.id == "owned-order")
                .count(),
            quiet_trace_count
        );
    }

    #[test]
    fn reorder_owned_windows_rejects_stale_intent_after_two_connection_transfer() {
        let (_t, paths) = temp_paths();
        for project_id in ["intent-p1", "intent-p2"] {
            svc(&paths)
                .create(project_id, project_id, "/p", NewProject::default(), 1)
                .unwrap();
        }
        create_assigned_window(&paths, "intent-w1", "intent-p1");
        create_assigned_window(&paths, "intent-w2", "intent-p1");
        let stale_p1_intent = vec!["intent-w2".to_string(), "intent-w1".to_string()];

        let mut other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        other.pragma_update(None, "foreign_keys", "ON").unwrap();
        let tx = other
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE windows SET project_id = 'intent-p2' WHERE window_id = 'intent-w2'",
            [],
        )
        .unwrap();
        tx.execute(
            "UPDATE projects SET window_order_json = '[\"intent-w1\"]' \
             WHERE project_id = 'intent-p1'",
            [],
        )
        .unwrap();
        tx.execute(
            "UPDATE projects SET window_order_json = '[\"intent-w2\"]' \
             WHERE project_id = 'intent-p2'",
            [],
        )
        .unwrap();
        crate::db::bump_window_mutation_epoch(&tx).unwrap();
        tx.commit().unwrap();

        let p1_before = svc(&paths).load("intent-p1").unwrap().unwrap();
        let p2_before = svc(&paths).load("intent-p2").unwrap().unwrap();
        let epoch_before = window_epoch(&paths);
        assert!(matches!(
            svc(&paths)
                .reorder_owned_windows("intent-p1", &stale_p1_intent, 10)
                .unwrap_err(),
            ProjectServiceError::InvalidOrder { .. }
        ));
        assert_eq!(svc(&paths).load("intent-p1").unwrap().unwrap(), p1_before);
        assert_eq!(svc(&paths).load("intent-p2").unwrap().unwrap(), p2_before);
        assert_eq!(window_epoch(&paths), epoch_before);

        // A fresh p1 request that directly names p2's w2 is the same forbidden shape.
        assert!(matches!(
            svc(&paths)
                .reorder_owned_windows("intent-p1", &["intent-w1".into(), "intent-w2".into()], 11,)
                .unwrap_err(),
            ProjectServiceError::InvalidOrder { .. }
        ));
        assert_eq!(svc(&paths).load("intent-p1").unwrap().unwrap(), p1_before);
        assert_eq!(window_epoch(&paths), epoch_before);
    }

    #[test]
    fn reorder_owned_windows_rejects_malformed_or_foreign_order_without_write() {
        for (case, foreign_order) in [
            ("malformed", "{not-json"),
            ("foreign", "[\"strict-owned-window\"]"),
        ] {
            let (_t, paths) = temp_paths();
            for project_id in ["strict-owned", "strict-other"] {
                svc(&paths)
                    .create(project_id, project_id, "/p", NewProject::default(), 1)
                    .unwrap();
            }
            create_assigned_window(&paths, "strict-owned-window", "strict-owned");
            let other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
            other
                .execute(
                    "UPDATE projects SET window_order_json = ?2 WHERE project_id = ?1",
                    rusqlite::params!["strict-other", foreign_order],
                )
                .unwrap();
            let target_before = svc(&paths).load("strict-owned").unwrap().unwrap();
            let epoch_before = window_epoch(&paths);

            assert!(
                svc(&paths)
                    .reorder_owned_windows("strict-owned", &["strict-owned-window".into()], 10,)
                    .is_err(),
                "{case} project order must fail closed"
            );
            assert_eq!(
                svc(&paths).load("strict-owned").unwrap().unwrap(),
                target_before
            );
            assert_eq!(window_epoch(&paths), epoch_before);
            let raw: String = other
                .query_row(
                    "SELECT window_order_json FROM projects WHERE project_id = 'strict-other'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(raw, foreign_order);
        }
    }

    #[test]
    fn reorder_owned_windows_epoch_exhaustion_rolls_back_order_and_trace() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("max-order", "Max", "/p", NewProject::default(), 1)
            .unwrap();
        create_assigned_window(&paths, "max-a", "max-order");
        create_assigned_window(&paths, "max-b", "max-order");
        {
            let connection = crate::db::conn_for(paths.base()).unwrap();
            connection
                .lock()
                .unwrap()
                .pragma_update(None, "user_version", i32::MAX)
                .unwrap();
        }
        let before = svc(&paths).load("max-order").unwrap().unwrap();
        let traces_before = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "Project" && event.id == "max-order")
            .count();

        let error = svc(&paths)
            .reorder_owned_windows("max-order", &["max-b".into(), "max-a".into()], 10)
            .unwrap_err();
        assert!(matches!(
            error,
            ProjectServiceError::Store(StoreError::Db(ref detail))
                if detail.contains("epoch") && detail.contains("exhausted")
        ));
        assert_eq!(svc(&paths).load("max-order").unwrap().unwrap(), before);
        assert_eq!(window_epoch(&paths), i32::MAX as u32);
        assert_eq!(
            crate::write_trace::recent()
                .into_iter()
                .filter(|event| event.kind == "Project" && event.id == "max-order")
                .count(),
            traces_before
        );
    }

    #[test]
    fn project_mutation_fence_preserves_concurrent_owner_appends_and_metadata() {
        let (_t, paths) = temp_paths();
        for project_id in ["metadata-p1", "metadata-p2"] {
            svc(&paths)
                .create(project_id, project_id, "/p", NewProject::default(), 1)
                .unwrap();
        }
        create_assigned_window(&paths, "metadata-w1", "metadata-p1");
        let windows = crate::WindowLayoutService::new(&paths);
        let second_window = windows.create_empty_snapshot("metadata-w2", 2).unwrap();

        // Pause conceptually inside the private edit closure: the IMMEDIATE transaction has
        // already loaded the fresh full Project row. A genuinely independent connection cannot
        // enter and publish an owner append until this metadata write commits.
        let mut contender = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        contender.pragma_update(None, "busy_timeout", 0).unwrap();
        let edited = svc(&paths)
            .mutate("metadata-p1", 3, |project| {
                let error = match contender
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                {
                    Ok(transaction) => {
                        transaction.rollback().unwrap();
                        panic!("owner writer entered during project metadata RMW")
                    }
                    Err(error) => error,
                };
                assert!(matches!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
                ));
                project.name = "Metadata updated".into();
            })
            .unwrap();
        assert_eq!(edited.name, "Metadata updated");
        assert_eq!(edited.window_order, vec!["metadata-w1"]);

        let assignment = windows
            .assign_project_and_order_if_unchanged(&second_window, None, "metadata-p1", 4)
            .unwrap();
        assert!(matches!(
            assignment,
            crate::ConditionalWindowProjectAssignment::Applied(_)
        ));
        let epoch_after_append = window_epoch(&paths);

        // Metadata update, touch, and top-level project reorder all reload inside their own writer
        // transactions. None can replay the old one-window order over the committed append.
        svc(&paths)
            .update(
                "metadata-p1",
                ProjectUpdate {
                    root: Some("/new-root".into()),
                    ..ProjectUpdate::default()
                },
                5,
            )
            .unwrap();
        svc(&paths).touch("metadata-p1", 6).unwrap();
        svc(&paths)
            .reorder(&["metadata-p2".into(), "metadata-p1".into()], 10)
            .unwrap();
        let final_project = svc(&paths).load("metadata-p1").unwrap().unwrap();
        assert_eq!(final_project.name, "Metadata updated");
        assert_eq!(final_project.root, "/new-root");
        assert_eq!(
            final_project.window_order,
            vec!["metadata-w1".to_string(), "metadata-w2".to_string()]
        );
        assert_eq!(window_epoch(&paths), epoch_after_append);
    }

    #[test]
    fn project_mutation_noop_has_no_trace_and_metadata_does_not_bump_window_epoch() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("quiet-project", "Quiet", "/p", NewProject::default(), 1)
            .unwrap();
        create_assigned_window(&paths, "quiet-window", "quiet-project");
        let epoch_before = window_epoch(&paths);
        let traces_before = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "Project" && event.id == "quiet-project")
            .count();

        // created_at/last_active both start at 1, so this is a genuine byte-identical no-op.
        svc(&paths).touch("quiet-project", 1).unwrap();
        assert_eq!(window_epoch(&paths), epoch_before);
        assert_eq!(
            crate::write_trace::recent()
                .into_iter()
                .filter(|event| event.kind == "Project" && event.id == "quiet-project")
                .count(),
            traces_before
        );

        svc(&paths).touch("quiet-project", 2).unwrap();
        assert_eq!(window_epoch(&paths), epoch_before);
        assert_eq!(
            crate::write_trace::recent()
                .into_iter()
                .filter(|event| event.kind == "Project" && event.id == "quiet-project")
                .count(),
            traces_before + 1
        );
    }

    #[test]
    fn project_mutation_order_epoch_exhaustion_rolls_back_full_row_and_trace() {
        let (_t, paths) = temp_paths();
        svc(&paths)
            .create("compat-order", "Before", "/p", NewProject::default(), 1)
            .unwrap();
        create_assigned_window(&paths, "compat-a", "compat-order");
        create_assigned_window(&paths, "compat-b", "compat-order");
        {
            let connection = crate::db::conn_for(paths.base()).unwrap();
            connection
                .lock()
                .unwrap()
                .pragma_update(None, "user_version", i32::MAX)
                .unwrap();
        }
        let before = svc(&paths).load("compat-order").unwrap().unwrap();
        let traces_before = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "Project" && event.id == "compat-order")
            .count();

        let error = svc(&paths)
            .reorder_windows("compat-order", &["compat-b".into(), "compat-a".into()], 10)
            .unwrap_err();
        assert!(matches!(
            error,
            ProjectServiceError::Store(StoreError::Db(ref detail))
                if detail.contains("epoch") && detail.contains("exhausted")
        ));
        assert_eq!(svc(&paths).load("compat-order").unwrap().unwrap(), before);
        assert_eq!(window_epoch(&paths), i32::MAX as u32);
        assert_eq!(
            crate::write_trace::recent()
                .into_iter()
                .filter(|event| event.kind == "Project" && event.id == "compat-order")
                .count(),
            traces_before
        );
    }
}
