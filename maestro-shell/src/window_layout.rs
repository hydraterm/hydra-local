//! Durable window/tab layout service.
//!
//! [`WindowLayoutService`] is a thin, store-backed manager over the existing
//! [`WindowLayout`]/[`TabRecord`] records: it creates/loads a window's ordered tab list and
//! applies the small set of layout mutations the app shell needs (open/close/rename/pin/
//! reorder/swap a tab, update a tab's persisted attention roll-up). Every mutation takes one
//! SQLite `BEGIN IMMEDIATE` writer fence, loads the current layout inside it, applies the pure
//! record edit, RENORMALIZES tab indices to a contiguous `0..n` run, and commits the complete
//! window + tab replacement before emitting its diagnostic trace.
//!
//! It also offers a READ-ONLY [`WindowLayoutService::tab_view`] projection that joins the
//! persisted tabs with an [`AgentTaskReconcileReport`], so the UI can show task state /
//! attention alongside each tab without this layer ever talking to the daemon.
//!
//! Hard boundaries (matching the rest of the shell's records layer):
//!
//! - NO daemon/socket/PTY/git/renderer/UI shell. Records in, records out, under an injected
//!   [`AppPaths`].
//! - This layer NEVER creates sessions or tasks and NEVER validates that a tab's `session_id`
//!   names a live (or even existing) session: a layout may legitimately reference a recovered
//!   or future session, and reconciliation — not layout — owns that linkage.
//! - Future-version and corrupt layout records are surfaced as typed errors
//!   ([`WindowLayoutError::FutureVersion`] / [`WindowLayoutError::Corrupt`]); the store leaves a
//!   future record byte-identical in place and quarantines a corrupt one. A mutation never
//!   "repairs" such a record by overwriting it.

// Transaction failures retain exact graph snapshots and consume-once compensation receipts.
#![allow(
    clippy::large_enum_variant,
    clippy::result_large_err,
    clippy::too_many_arguments,
    clippy::type_complexity
)]

use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use maestro_protocol::{DaemonInstanceId, SessionStartOperationToken};
use rusqlite::OptionalExtension as _;

use crate::agent_task_reconcile::AgentTaskReconcileReport;
#[cfg(test)]
use crate::pane_layout::SlotId;
use crate::pane_layout::{
    slot_rects, CanonicalLayout, EdgeDir, PaneLayoutModel, SwallowDir, UnitRect,
};
use crate::paths::{AppPaths, RecordKind};
use crate::records::{
    AgentTask, AgentTaskState, Attention, AttentionState, PaneRect, Project, SessionKind,
    SessionRecord, SessionStatus, SplitAxis, SplitFrom, TabRecord, WindowLayout, Workspace,
    WorktreeProvenance,
};
use crate::session_release::{
    cancel_operation_in_transaction, insert_pending_releases, resolve_exact_target,
    PendingReleaseReceipt, PreResolvedSessionGenerations, ReleaseOperationBinding,
    SessionRowPolicy, UnpublishedCompensationReceipt,
};
use crate::session_service::StartParams;
use crate::store::StoreError;
use crate::workspace_exec::{
    PreparedSessionBinding, PreparedSessionSpec, PreparedWorktreeProvenanceCohort,
    PreparedWorktreeProvenanceSeal,
};

const AGENT_TASK_START_JOURNAL_LEASE_MS: u64 = 120_000;
const _: () = assert!(
    AGENT_TASK_START_JOURNAL_LEASE_MS >= crate::daemon_client::GENERATION_KILL_DEADLINE_MS * 2
);

/// Errors from the window-layout service.
#[derive(Debug)]
pub enum WindowLayoutError {
    /// A mutation/projection targeted a window that has no current-version layout record.
    WindowLayoutNotFound { window_id: String },
    /// `create_empty` was asked to create a layout for a window that already has one. The
    /// existing record is left untouched.
    WindowLayoutAlreadyExists { window_id: String },
    /// A caller carrying an exact snapshot attempted a follow-up mutation after some window
    /// mutation transaction advanced the durable namespace generation. The stale operation is
    /// refused even when the public layout bytes happen to match (delete/recreate ABA).
    WindowLayoutChanged { window_id: String },
    /// A tab operation named a `tab_id` not present in the window's layout.
    TabNotFound { window_id: String, tab_id: String },
    /// `open_tab` was given a `tab_id` already present in the layout. Nothing is rewritten.
    TabAlreadyExists { window_id: String, tab_id: String },
    /// A prepared start requires insert-only Session identity, but the id already has a row.
    SessionAlreadyExists { session_id: String },
    /// An absent Session id already appears in a durable soft-reference namespace.
    SessionIdentityReferenced { session_id: String },
    /// The exact Workspace reviewed by the preparation caller changed or disappeared.
    WorkspaceChanged { workspace_id: String },
    /// A new AgentTask preparation requires insert-only task identity.
    AgentTaskAlreadyExists { agent_task_id: String },
    /// The exact task row reviewed for a resume changed or disappeared.
    AgentTaskChanged { agent_task_id: String },
    /// `reorder_tabs` was given an order that is not an exact permutation of the existing tab
    /// ids (missing id, unknown id, or a duplicate). The layout is left untouched.
    InvalidTabOrder { reason: String },
    /// `stash_pane` was asked to stash the window's only remaining live (non-stashed) pane. Stashing
    /// it would leave the window with an empty live layout, so the request is refused and the layout
    /// is left untouched.
    CannotStashLastPane { window_id: String, tab_id: String },
    /// The on-disk layout was written by a newer schema version than this build understands. It
    /// is left byte-identical in place; surfaced so the caller can tell the user.
    FutureVersion { path: PathBuf, ours: u32, got: u32 },
    /// The on-disk layout failed validation and was quarantined by the store (bytes preserved
    /// at `moved_to`).
    Corrupt {
        original: PathBuf,
        moved_to: PathBuf,
        reason: String,
    },
    /// Underlying store IO / id-validation error (an unsafe `window_id`/`tab_id` is refused here
    /// before any path is built).
    Store(StoreError),
}

impl fmt::Display for WindowLayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WindowLayoutError::WindowLayoutNotFound { window_id } => {
                write!(f, "no window layout for window_id {window_id:?}")
            }
            WindowLayoutError::WindowLayoutAlreadyExists { window_id } => {
                write!(
                    f,
                    "window layout already exists for window_id {window_id:?}"
                )
            }
            WindowLayoutError::WindowLayoutChanged { window_id } => {
                write!(
                    f,
                    "window layout snapshot changed for window_id {window_id:?}"
                )
            }
            WindowLayoutError::TabNotFound { window_id, tab_id } => {
                write!(f, "no tab {tab_id:?} in window {window_id:?}")
            }
            WindowLayoutError::TabAlreadyExists { window_id, tab_id } => {
                write!(f, "tab {tab_id:?} already exists in window {window_id:?}")
            }
            WindowLayoutError::SessionAlreadyExists { session_id } => {
                write!(f, "session {session_id:?} already exists")
            }
            WindowLayoutError::SessionIdentityReferenced { session_id } => {
                write!(f, "session {session_id:?} already has a durable owner")
            }
            WindowLayoutError::WorkspaceChanged { workspace_id } => {
                write!(
                    f,
                    "workspace {workspace_id:?} changed before session preparation"
                )
            }
            WindowLayoutError::AgentTaskAlreadyExists { agent_task_id } => {
                write!(f, "agent task {agent_task_id:?} already exists")
            }
            WindowLayoutError::AgentTaskChanged { agent_task_id } => {
                write!(
                    f,
                    "agent task {agent_task_id:?} changed before session preparation"
                )
            }
            WindowLayoutError::InvalidTabOrder { reason } => {
                write!(f, "invalid tab order: {reason}")
            }
            WindowLayoutError::CannotStashLastPane { window_id, tab_id } => {
                write!(
                    f,
                    "cannot stash the only live pane {tab_id:?} of window {window_id:?}"
                )
            }
            WindowLayoutError::FutureVersion { path, ours, got } => write!(
                f,
                "window layout at {} was written by a newer schema (ours {ours}, got {got})",
                path.display()
            ),
            WindowLayoutError::Corrupt {
                original,
                moved_to,
                reason,
            } => write!(
                f,
                "window layout at {} is corrupt ({reason}); quarantined to {}",
                original.display(),
                moved_to.display()
            ),
            WindowLayoutError::Store(e) => write!(f, "window layout store error: {e}"),
        }
    }
}

impl Error for WindowLayoutError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            WindowLayoutError::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<StoreError> for WindowLayoutError {
    fn from(e: StoreError) -> Self {
        WindowLayoutError::Store(e)
    }
}

/// One projected tab row: the persisted [`TabRecord`] fields joined with whatever the
/// [`AgentTaskReconcileReport`] knows about the task whose `current_session_id` is this tab's
/// `session_id`. Purely derived; producing it mutates nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowTabView {
    pub tab_id: String,
    pub session_id: String,
    pub index: u32,
    pub title: String,
    pub pinned: bool,
    /// The tab's persisted attention roll-up (survives restarts).
    pub attention: AttentionState,
    /// Recorded status of the joined task's current session, if a task currently points at this
    /// tab's session. `None` when no reconciled task links here (the common plain-tab case).
    pub session_status: Option<SessionStatus>,
    /// The joined task's id, if any.
    pub agent_task_id: Option<String>,
    /// The joined task's state, if any.
    pub agent_task_state: Option<AgentTaskState>,
    /// True if the persisted tab attention is unseen-and-non-`None`, OR the joined task report
    /// says the task needs attention. See [`tab_needs_attention`].
    pub needs_attention: bool,
    /// True when a task links here but its current session record is missing on disk.
    pub session_record_missing: bool,
    /// Split provenance copied verbatim from the persisted [`TabRecord::split_from`] (`None` for an
    /// ordinary tab). Carried so the joined window-view strip keeps the same split markers the
    /// persisted-layout strip shows.
    pub split_from: Option<SplitFrom>,
    /// The AUTHORITATIVE live geometry, copied verbatim from [`TabRecord::pane_rect`]. Carried through the
    /// joined window-view strip so the periodic live refresh keeps painting from rects (NOT the legacy
    /// split_from chain) — dropping it here made the layout "snap to another shape" ~750ms after an op.
    pub pane_rect: Option<PaneRect>,
    /// True when the tab is STASHED: its session is kept alive but the renderer hides it from the live
    /// pane layout and the dashboard surfaces it as a revive candidate. Copied verbatim from
    /// [`TabRecord::stashed`] so the joined window-view strip can exclude stashed panes.
    pub stashed: bool,
}

/// One coherent durable window snapshot, including the ownership FK that is stored beside the
/// layout rather than in [`WindowLayout`] itself. Close-window lifecycle code carries this value
/// from daemon-request preparation to the conditional delete/compensation seams below; it must not
/// reconstruct the owner with a second autocommit query.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowLayoutSnapshot {
    pub layout: WindowLayout,
    pub project_id: Option<String>,
    // Opaque outside maestro-shell: callers may carry and update the public state only through
    // snapshot-aware service methods, never forge a revision after delete/recreate ABA.
    revision: WindowLayoutRevision,
}

/// Opaque, read-only authority to validate/revive one pane in an exact layout.
///
/// Construction validates the target and four-pane capacity without writing. The caller may then
/// perform any separately reviewed session work and consume this value in
/// [`WindowLayoutService::commit_prepared_pane_revive`]. That commit compares the complete window
/// snapshot (including its ownership/ABA revision) before writing, so a concurrent topology change
/// is a typed refusal rather than an unconditional late revive.
pub struct PreparedPaneRevive {
    expected: WindowLayoutSnapshot,
    post_layout: WindowLayout,
}

impl std::fmt::Debug for PreparedPaneRevive {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedPaneRevive")
            .field("window_id", &self.expected.layout.window_id)
            .field(
                "changes_layout",
                &(self.expected.layout != self.post_layout),
            )
            .finish()
    }
}

impl PreparedPaneRevive {
    /// Exact layout bytes used to resolve the tab/session binding before any daemon operation.
    pub fn expected_layout(&self) -> &WindowLayout {
        &self.expected.layout
    }
}

/// One visible pane's complete durable Session row and validated PTY lifetime, read beside its
/// WindowLayout under the same SQLite snapshot. Stashed tabs are deliberately absent: they remain
/// durable owners but have no visible renderer role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowViewportPane {
    tab_id: String,
    session: SessionRecord,
    generation: String,
}

impl WindowViewportPane {
    pub fn tab_id(&self) -> &str {
        &self.tab_id
    }

    pub fn session(&self) -> &SessionRecord {
        &self.session
    }

    pub fn session_id(&self) -> &str {
        &self.session.session_id
    }

    pub fn generation(&self) -> &str {
        &self.generation
    }
}

/// All-or-none durable authority for projecting one visible renderer viewport. `window` and every
/// [`WindowViewportPane`] come from one DEFERRED SQLite snapshot; callers must not rebuild this
/// relation from later public record reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowViewportSnapshot {
    window: WindowLayoutSnapshot,
    panes: Vec<WindowViewportPane>,
}

impl WindowViewportSnapshot {
    pub fn window(&self) -> &WindowLayoutSnapshot {
        &self.window
    }

    pub fn panes(&self) -> &[WindowViewportPane] {
        &self.panes
    }

    pub fn pane_for_tab(&self, tab_id: &str) -> Option<&WindowViewportPane> {
        self.panes.iter().find(|pane| pane.tab_id == tab_id)
    }
}

/// A visible layout cannot be partially projected. Any unresolved Session row or lifetime rejects
/// the complete viewport before renderer Attach bytes are authorized; stashed tabs are not read.
#[derive(Debug)]
pub enum WindowViewportSnapshotError {
    Window(WindowLayoutError),
    WindowMissing {
        window_id: String,
    },
    SessionMissing {
        tab_id: String,
        session_id: String,
    },
    SessionMalformed {
        tab_id: String,
        session_id: String,
        reason: String,
    },
    SessionGenerationUnavailable {
        tab_id: String,
        session_id: String,
    },
    ConflictingDuplicateSession {
        session_id: String,
    },
}

impl fmt::Display for WindowViewportSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Window(error) => write!(formatter, "viewport window load failed: {error}"),
            Self::WindowMissing { window_id } => {
                write!(formatter, "viewport window {window_id:?} is missing")
            }
            Self::SessionMissing { tab_id, session_id } => write!(
                formatter,
                "visible tab {tab_id:?} names missing Session {session_id:?}"
            ),
            Self::SessionMalformed {
                tab_id,
                session_id,
                reason,
            } => write!(
                formatter,
                "visible tab {tab_id:?} Session {session_id:?} is malformed: {reason}"
            ),
            Self::SessionGenerationUnavailable { tab_id, session_id } => write!(
                formatter,
                "visible tab {tab_id:?} Session {session_id:?} has no valid generation"
            ),
            Self::ConflictingDuplicateSession { session_id } => write!(
                formatter,
                "visible Session {session_id:?} has conflicting lifetime facts"
            ),
        }
    }
}

impl Error for WindowViewportSnapshotError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Window(error) => Some(error),
            _ => None,
        }
    }
}

impl From<WindowLayoutError> for WindowViewportSnapshotError {
    fn from(error: WindowLayoutError) -> Self {
        Self::Window(error)
    }
}

/// One coherent close preparation: the exact target snapshot plus only target sessions that no
/// other window in that same SQLite read snapshot references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowCloseSnapshot {
    pub window: WindowLayoutSnapshot,
    /// ID-only compatibility cohort. A future conditional-kill wire must bind each id to the
    /// SessionRecord generation read inside this same snapshot; None grants no kill authority.
    pub exclusive_session_ids: Vec<String>,
}

/// One committed tab-removal mutation and the exact row removed by that same writer transaction.
///
/// Daemon cleanup must derive its candidate Session id from `removed_tab`, never from an older UI
/// projection: another process may retarget the tab immediately before the close transaction.
#[derive(Debug)]
pub struct WindowTabClose {
    pub layout: WindowLayout,
    pub removed_tab: TabRecord,
    pub release_receipt: Option<PendingReleaseReceipt>,
    /// Candidates whose transaction-local Session row carried no exact generation and for which
    /// the caller supplied no authoritative daemon resolution.  The tab removal is committed as
    /// a typed safe leak, never downgraded to an id-only daemon mutation.
    pub unresolved_release_session_ids: Vec<String>,
}

/// Result of removing one tab or pane through the user-facing global-window guard. Removing the
/// final live row makes its window invisible, so it must obey the same invariant as whole-window
/// stash and delete: at least one ordinary-project window remains visible across the dashboard.
#[derive(Debug)]
pub enum GuardedWindowTabClose {
    Closed(WindowTabClose),
    GloballyLastVisible,
}

impl GuardedWindowTabClose {
    fn into_unguarded(self) -> WindowTabClose {
        match self {
            Self::Closed(closed) => closed,
            Self::GloballyLastVisible => {
                unreachable!("an unguarded tab/pane close cannot refuse the globally last window")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WindowLayoutRevision {
    window_mutation_epoch: u32,
}

/// Result of deleting a window only when its complete current snapshot still matches the caller's
/// prepared snapshot.
#[derive(Debug)]
pub enum ConditionalWindowDelete {
    Deleted(WindowDeletionReceipt),
    Missing,
    Changed,
}

/// Result of atomically stashing every live pane in one exact window while preserving at least
/// one visible ordinary-project window across the whole dashboard.
///
/// This is deliberately separate from [`WindowLayoutService::set_tab_stashed`] and
/// [`WindowLayoutService::stash_pane`]. Those APIs edit one pane and serve lower-level layout
/// workflows; a user-facing window close must carry an exact [`WindowLayoutSnapshot`] and use the
/// global guard so the App and agent's two SQLite writer paths cannot both hide the final window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConditionalWindowStash {
    /// Every previously-live tab was marked stashed in one writer transaction.
    Stashed(WindowLayoutSnapshot),
    /// The exact target already had no live tabs. No row or mutation epoch was changed.
    AlreadyStashed(WindowLayoutSnapshot),
    /// The expected window no longer exists.
    Missing,
    /// The layout, owner, or global window-mutation revision changed after preparation.
    Changed,
    /// Stashing this visible ordinary-project window would hide the globally last such window.
    GloballyLastVisible,
}

/// Guarded counterpart to [`ConditionalWindowDelete`]. Internal rollback/project-deletion paths
/// retain the existing unguarded enum and API; user-facing window removal uses this type so a
/// globally-last refusal is distinguishable from a stale snapshot or store failure.
#[derive(Debug)]
pub enum GuardedConditionalWindowDelete {
    Deleted(WindowDeletionReceipt),
    Missing,
    Changed,
    GloballyLastVisible,
}

/// Opaque proof of both the exact deleted layout/owner snapshot and the global window-mutation
/// generation committed by a conditional delete. Compensation may use it once; a caller-mutated
/// snapshot or any intervening window mutation makes it stale.
pub struct WindowDeletionReceipt {
    window_id: String,
    deleted_revision: WindowLayoutRevision,
    // Binds compensation to the exact layout + owner bytes that were revalidated and deleted.
    // Keep only the digest here so Debug output cannot expose tab titles/session ids.
    deleted_snapshot_fingerprint: [u8; 32],
    window_mutation_epoch: u32,
    window_only_restore: bool,
    release_binding: Option<ReleaseOperationBinding>,
    release_receipt: Option<PendingReleaseReceipt>,
    unresolved_release_session_ids: Vec<String>,
}

impl std::fmt::Debug for WindowDeletionReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WindowDeletionReceipt")
            .field("window_id", &self.window_id)
            .field("has_pending_release", &self.release_receipt.is_some())
            .field(
                "unresolved_release_count",
                &self.unresolved_release_session_ids.len(),
            )
            .finish_non_exhaustive()
    }
}

impl WindowDeletionReceipt {
    pub fn take_release_receipt(&mut self) -> Option<PendingReleaseReceipt> {
        self.release_receipt.take()
    }

    pub fn unresolved_release_session_ids(&self) -> &[String] {
        &self.unresolved_release_session_ids
    }
}

struct ExactReleaseTargets {
    targets: Vec<crate::SessionReleaseTarget>,
    unresolved_session_ids: Vec<String>,
}

fn has_prior_pending_release_lifetime(
    tx: &rusqlite::Transaction<'_>,
    targets: &[crate::SessionReleaseTarget],
) -> Result<bool, WindowLayoutError> {
    for target in targets {
        let exists: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pending_session_releases \
                 WHERE session_id = ?1 AND expected_generation = ?2)",
                rusqlite::params![target.session_id(), target.expected_generation()],
                |row| row.get(0),
            )
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if exists {
            return Ok(true);
        }
    }
    Ok(false)
}

fn exact_release_targets_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    session_ids: impl IntoIterator<Item = String>,
    row_policy: SessionRowPolicy,
    pre_resolved: &PreResolvedSessionGenerations,
) -> Result<ExactReleaseTargets, WindowLayoutError> {
    let session_ids = session_ids
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>();
    let mut rows = std::collections::BTreeMap::new();
    for session_id in &session_ids {
        crate::validate_id(session_id).map_err(StoreError::Id)?;
        let generation: Option<Option<String>> = tx
            .query_row(
                "SELECT last_known_generation FROM sessions WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        rows.insert(session_id.clone(), generation);
    }
    if let Some(unexpected) = pre_resolved
        .keys()
        .find(|session_id| !rows.contains_key(*session_id))
    {
        return Err(WindowLayoutError::Store(StoreError::Map(format!(
            "pre-resolved session {unexpected:?} is not a transaction-local release candidate"
        ))));
    }

    // A caller commonly obtains one authoritative daemon snapshot for every candidate before it
    // can know which candidates already have transaction-local Session generations.  Extra map
    // entries for exact-row candidates are accepted but still syntax-validated and ignored; keys
    // outside the candidate cohort remain a hard error.
    for state in pre_resolved.values() {
        if let crate::PreResolvedSessionState::Generation(generation) = state {
            if generation.is_empty() || generation.len() > 128 {
                return Err(WindowLayoutError::Store(StoreError::Map(
                    "pre-resolved session generation length must be 1..=128 bytes".into(),
                )));
            }
        }
    }

    let mut targets = Vec::new();
    let mut unresolved_session_ids = Vec::new();
    for (session_id, generation) in rows {
        let effective_row_policy = if generation.is_none() {
            // A missing Session row that is resolved from the daemon is not proof that a later
            // same-id row belongs to that observed lifetime.  Any row published after this
            // destructive transaction is a new/ambiguous durable owner and must veto release.
            SessionRowPolicy::RowMustBeAbsent
        } else {
            row_policy
        };
        let row_generation = generation.as_ref().map(|generation| generation.as_deref());
        if row_generation.flatten().is_none() && !pre_resolved.contains_key(&session_id) {
            unresolved_session_ids.push(session_id);
            continue;
        }
        if let Some(target) = resolve_exact_target(
            &session_id,
            row_generation,
            effective_row_policy,
            pre_resolved,
        )
        .map_err(|error| StoreError::Map(error.to_string()))?
        {
            targets.push(target);
        }
    }
    Ok(ExactReleaseTargets {
        targets,
        unresolved_session_ids,
    })
}

/// Complete caller intent for one freshly allocated window graph. The service validates every
/// cross-record link and constructs the canonical first [`TabRecord`] itself; callers never gain
/// authority by separately writing one of these identities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FreshWindowGraphSpec {
    pub workspace: Workspace,
    pub session: SessionRecord,
    pub window_id: String,
    /// Desired base display name. A unique sibling suffix is chosen inside the writer snapshot.
    pub window_name: String,
    pub tab_id: String,
    pub tab_title: String,
    pub tab_pinned: bool,
    pub tab_attention: AttentionState,
    /// Existing-project desktop creation historically touches project recency; remote creation
    /// does not. When true, that metadata change joins the same order update transaction.
    pub touch_project: bool,
}

/// Project inputs plus an opaque, same-snapshot identity/ownership epoch. Callers may derive launch
/// and root inputs from [`project`](Self::project), but cannot manufacture a proof that survives a
/// Project delete/recreate ABA or an intervening window/owner mutation.
#[derive(Clone, PartialEq, Eq)]
pub struct ProjectWindowGraphSnapshot {
    project: Project,
    window_mutation_epoch: u32,
}

impl ProjectWindowGraphSnapshot {
    pub fn project(&self) -> &Project {
        &self.project
    }
}

impl fmt::Debug for ProjectWindowGraphSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProjectWindowGraphSnapshot")
            .field("project_id", &self.project.project_id)
            .finish_non_exhaustive()
    }
}

/// Which insert-only identity prevented a fresh graph from being created. Even byte-identical
/// rows are conflicts: equality is not creation authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FreshWindowGraphConflict {
    Project {
        project_id: String,
    },
    Workspace {
        workspace_id: String,
    },
    Session {
        session_id: String,
    },
    Window {
        window_id: String,
    },
    ProjectOrder {
        window_id: String,
        project_ids: Vec<String>,
    },
}

/// Canonical records committed by one fresh-graph transaction plus opaque compensation authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatedFreshWindowGraph {
    pub project: Project,
    pub workspace: Workspace,
    pub session: SessionRecord,
    pub window: WindowLayoutSnapshot,
    pub receipt: FreshWindowGraphReceipt,
}

/// Typed result of creating a complete first-window graph. Refusal variants commit no row, epoch,
/// or diagnostic trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FreshWindowGraphCreateOutcome {
    Created(CreatedFreshWindowGraph),
    ProjectMissing { project_id: String },
    ProjectChanged { project_id: String },
    Conflict(FreshWindowGraphConflict),
}

/// Opaque proof of one exact committed Project/order + Workspace + Session + Window/Tab graph.
/// Its canonical digest and post-create global epoch are private so compensation authority cannot
/// be manufactured from caller-mutated public records.
#[derive(Clone, PartialEq, Eq)]
pub struct FreshWindowGraphReceipt {
    project_id: String,
    workspace_id: String,
    session_id: String,
    window_id: String,
    tab_id: String,
    created_project: bool,
    // Existing-project compensation restores this exact canonical row, including metadata the
    // graph transaction touched. Callers cannot inspect or replace these bytes.
    previous_project: Option<Project>,
    graph_fingerprint: [u8; 32],
    window_mutation_epoch: u32,
}

/// Caller inputs for creating a complete first-window graph whose first Session is prepared for
/// one later generation-conditional daemon start.  Unlike [`FreshWindowGraphSpec`], this type does
/// not accept a caller-constructed [`SessionRecord`]: the transaction derives the canonical
/// `Unknown` row from the owned start parameters and seals it into the returned authority.
pub struct PreparedFreshWindowGraphSpec {
    pub workspace: Workspace,
    pub session: PreparedSessionSpec,
    pub window_id: String,
    pub window_name: String,
    pub tab_id: String,
    pub tab_title: String,
    pub tab_pinned: bool,
    pub tab_attention: AttentionState,
    pub touch_project: bool,
}

/// One freshly-created graph whose daemon start authority was minted by the same insert-only
/// transaction.  The canonical `Unknown` Session, live argv, and compensation proof remain owned
/// by [`PreparedNewSessionStart`]; public records cannot be recombined into another authority.
pub struct CreatedPreparedFreshWindowGraph {
    pub project: Project,
    pub window: WindowLayoutSnapshot,
    pub start: PreparedNewSessionStart,
}

impl fmt::Debug for CreatedPreparedFreshWindowGraph {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedPreparedFreshWindowGraph")
            .field("project_id", &self.project.project_id)
            .field("window_id", &self.window.layout.window_id)
            .field("start", &self.start)
            .finish()
    }
}

/// Typed insert-only result for a prepared fresh graph. Refusal variants commit no graph row and
/// mint no daemon or compensation authority.
#[derive(Debug)]
pub enum PreparedFreshWindowGraphCreateOutcome {
    Created(CreatedPreparedFreshWindowGraph),
    ProjectMissing { project_id: String },
    ProjectChanged { project_id: String },
    Conflict(FreshWindowGraphConflict),
}

enum PreparedNewSessionPlacement {
    /// A headless session whose exact Project/Workspace/Session identity is prepared without a
    /// Window/Tab edge. This is deliberately distinct from a caller omitting placement after the
    /// daemon start: the absence of every soft Session owner is checked under the same insert-only
    /// writer fence that creates the canonical `Unknown` row.
    Unplaced { project: Project },
    ExistingWindow {
        project: Project,
        post_layout: WindowLayoutSnapshot,
        tab_id: String,
        /// When a split inherits its Workspace from an existing pane, this seals the exact
        /// source lifetime into every pre-wire and final graph fence.
        split_source: Option<PreparedSplitSource>,
    },
    FreshWindowGraph {
        receipt: FreshWindowGraphReceipt,
        project: Project,
        layout: WindowLayout,
    },
}

struct PreparedSplitSource {
    tab_id: String,
    session: SessionRecord,
}

/// Exact AgentTask transition sealed into one prepared Session start. `before` is either the
/// freshly inserted Draft or the complete caller-reviewed resume row. `after` is derived here and
/// may only be written beside Session Live(G) in the final `BEGIN IMMEDIATE` transaction.
#[derive(Clone)]
struct PreparedAgentTaskTransition {
    before: AgentTask,
    after: AgentTask,
}

pub(crate) enum PreparedAgentTaskPublication {
    NotTaskAware,
    Published(AgentTask),
    Changed,
}

enum PreparedExistingWindowPlacement<'a> {
    Open {
        title: &'a str,
        pinned: bool,
        attention: AttentionState,
        stashed: bool,
    },
    Split {
        from_tab_id: &'a str,
        expected_source_session: Option<&'a SessionRecord>,
        title: &'a str,
        axis: SplitAxis,
    },
}

/// Sealed, consume-once authority for starting one transaction-prepared Session.
///
/// The canonical `Unknown` row, exact Workspace, live argv, and placement proof are private and
/// this type deliberately does not implement `Clone`.  Callers can route it to the consuming
/// Session/Shell runtime APIs, but cannot inspect argv or substitute a caller-built Session row.
pub struct PreparedNewSessionStart {
    unknown: SessionRecord,
    workspace: Workspace,
    params: StartParams,
    publication_launch: crate::LaunchSpec,
    binding: PreparedSessionBinding,
    /// The only Worktree marker allowed to coexist with this prepared Session. This complete
    /// cohort is derived from the consume-once workspace seal and the transaction-reviewed
    /// Workspace row; `None` grants no provenance exception.
    worktree_provenance: Option<PreparedWorktreeProvenanceCohort>,
    placement: PreparedNewSessionPlacement,
    agent_task: Option<PreparedAgentTaskTransition>,
}

/// Consume-once task-aware counterpart to [`PreparedNewSessionStart`]. The inner Session start is
/// intentionally inaccessible: callers cannot strip the exact Task A -> B transition and route the
/// AgentTask FK through a generic prepared or raw start API.
pub struct PreparedAgentTaskSessionStart {
    start: PreparedNewSessionStart,
    journal: PreparedAgentTaskStartJournalReceipt,
}

/// Exact durable journal row inserted after peer proof and before the first conditional Start
/// byte. The token and peer identity stay private and Debug-redacted; this value is not cloneable.
pub(crate) struct PreparedAgentTaskStartJournalReceipt {
    session_id: String,
    agent_task_id: String,
    project_id: String,
    workspace_id: String,
    operation_token: SessionStartOperationToken,
    daemon_instance_id: Option<DaemonInstanceId>,
    server_pid: Option<u32>,
    socket_path: Option<String>,
    session_a_sha256: [u8; 32],
    task_a_sha256: [u8; 32],
    project_sha256: [u8; 32],
    workspace_sha256: [u8; 32],
    publication_launch_json: String,
    publication_now_ms: u64,
    disposition: String,
    applied_generation: Option<String>,
    applied_state: Option<String>,
    created_at_ms: u64,
    lease_token: String,
    lease_until_ms: u64,
}

impl PreparedAgentTaskStartJournalReceipt {
    pub(crate) fn operation_token(&self) -> &SessionStartOperationToken {
        &self.operation_token
    }

    pub(crate) fn daemon_instance_id(&self) -> &DaemonInstanceId {
        self.daemon_instance_id
            .as_ref()
            .expect("bound AgentTask journal owns daemon identity")
    }

    pub(crate) fn is_bound_finalize_applied(&self, generation: &str, state: &str) -> bool {
        self.daemon_instance_id.is_some()
            && self.socket_path.is_some()
            && self.disposition == "finalize"
            && self.applied_generation.as_deref() == Some(generation)
            && self.applied_state.as_deref() == Some(state)
    }

    pub(crate) fn transition_to_release_in_connection_at(
        &self,
        conn: &rusqlite::Connection,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        if self.disposition != "finalize"
            || self.applied_generation.is_none()
            || self.applied_state.is_none()
            || self.lease_until_ms <= now_ms
            || !self.matches_connection(conn)?
        {
            return Ok(false);
        }
        conn.execute(
            "UPDATE pending_agent_task_starts SET disposition = 'release' \
             WHERE session_id = ?1 AND operation_token = ?2 AND lease_token = ?3 \
               AND disposition = 'finalize' AND applied_generation = ?4 \
               AND applied_state = ?5 AND lease_until_ms = ?6 AND lease_until_ms > ?7",
            rusqlite::params![
                self.session_id,
                self.operation_token.as_str(),
                self.lease_token,
                self.applied_generation.as_deref(),
                self.applied_state.as_deref(),
                i64::try_from(self.lease_until_ms)
                    .map_err(|_| StoreError::Map("journal lease exceeds SQLite i64".into()))?,
                i64::try_from(now_ms)
                    .map_err(|_| StoreError::Map("journal clock exceeds SQLite i64".into()))?,
            ],
        )
        .map(|updated| updated == 1)
        .map_err(|error| StoreError::Db(error.to_string()))
    }

    pub(crate) fn matches_release_in_connection(
        &self,
        conn: &rusqlite::Connection,
    ) -> Result<bool, StoreError> {
        prepared_agent_task_start_journal_matches_with_disposition(conn, self, "release")
    }

    pub(crate) fn mark_release_committed(&mut self) {
        debug_assert!(matches!(self.disposition.as_str(), "finalize" | "release"));
        if self.disposition == "finalize" {
            self.disposition = "release".into();
        }
    }

    pub(crate) fn matches_connection(
        &self,
        conn: &rusqlite::Connection,
    ) -> Result<bool, StoreError> {
        prepared_agent_task_start_journal_matches(conn, self)
    }

    pub(crate) fn consume_in_connection_at(
        &self,
        conn: &rusqlite::Connection,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        if !self.matches_connection(conn)? || self.lease_until_ms <= now_ms {
            return Ok(false);
        }
        conn.execute(
            "DELETE FROM pending_agent_task_starts \
             WHERE session_id = ?1 AND operation_token = ?2 AND lease_token = ?3 \
               AND lease_until_ms = ?4 AND lease_until_ms > ?5",
            rusqlite::params![
                self.session_id,
                self.operation_token.as_str(),
                self.lease_token,
                i64::try_from(self.lease_until_ms)
                    .map_err(|_| StoreError::Map("journal lease exceeds SQLite i64".into()))?,
                i64::try_from(now_ms)
                    .map_err(|_| StoreError::Map("journal clock exceeds SQLite i64".into()))?,
            ],
        )
        .map(|removed| removed == 1)
        .map_err(|error| StoreError::Db(error.to_string()))
    }
}

impl fmt::Debug for PreparedAgentTaskStartJournalReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAgentTaskStartJournalReceipt")
            .field("session_id", &self.session_id)
            .field("agent_task_id", &self.agent_task_id)
            .field("peer_bound", &self.daemon_instance_id.is_some())
            .field("server_pid_bound", &self.server_pid.is_some())
            .finish_non_exhaustive()
    }
}

impl PreparedAgentTaskSessionStart {
    pub fn session_id(&self) -> &str {
        self.start.session_id()
    }

    pub fn agent_task_id(&self) -> &str {
        &self
            .start
            .agent_task
            .as_ref()
            .expect("task-aware start owns an exact task transition")
            .before
            .agent_task_id
    }

    pub(crate) fn as_inner(&self) -> &PreparedNewSessionStart {
        &self.start
    }

    pub(crate) fn journal(&self) -> &PreparedAgentTaskStartJournalReceipt {
        &self.journal
    }

    pub(crate) fn journal_mut(&mut self) -> &mut PreparedAgentTaskStartJournalReceipt {
        &mut self.journal
    }

    pub(crate) fn graph_matches_in_snapshot(&self, paths: &AppPaths) -> Result<bool, StoreError> {
        let now_ms = prepared_agent_task_journal_clock_ms()?;
        let arc =
            crate::db::conn_for(paths.base()).map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let matches = self.graph_matches_connection_at(&tx, now_ms)?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        Ok(matches)
    }

    pub(crate) fn graph_matches_connection_at(
        &self,
        conn: &rusqlite::Connection,
        now_ms: u64,
    ) -> Result<bool, StoreError> {
        Ok(self.start.graph_matches_connection(conn)?
            && self.journal.matches_connection(conn)?
            && self.journal.lease_until_ms > now_ms)
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PreparedNewSessionStart,
        PreparedAgentTaskStartJournalReceipt,
    ) {
        (self.start, self.journal)
    }
}

impl fmt::Debug for PreparedAgentTaskSessionStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAgentTaskSessionStart")
            .field("session_id", &self.session_id())
            .field("agent_task_id", &self.agent_task_id())
            .finish_non_exhaustive()
    }
}

impl PreparedNewSessionStart {
    pub fn session_id(&self) -> &str {
        &self.unknown.session_id
    }

    pub fn workspace_id(&self) -> &str {
        &self.workspace.workspace_id
    }

    pub fn window_id(&self) -> Option<&str> {
        match &self.placement {
            PreparedNewSessionPlacement::Unplaced { .. } => None,
            PreparedNewSessionPlacement::ExistingWindow { post_layout, .. } => {
                Some(&post_layout.layout.window_id)
            }
            PreparedNewSessionPlacement::FreshWindowGraph { layout, .. } => Some(&layout.window_id),
        }
    }

    pub fn tab_id(&self) -> Option<&str> {
        match &self.placement {
            PreparedNewSessionPlacement::Unplaced { .. } => None,
            PreparedNewSessionPlacement::ExistingWindow { tab_id, .. } => Some(tab_id),
            PreparedNewSessionPlacement::FreshWindowGraph { receipt, .. } => Some(&receipt.tab_id),
        }
    }

    #[cfg(test)]
    pub(crate) fn trace_scope_id(&self) -> &str {
        self.window_id().unwrap_or_else(|| self.session_id())
    }

    pub(crate) fn params(&self) -> &StartParams {
        &self.params
    }

    pub(crate) fn unknown(&self) -> &SessionRecord {
        &self.unknown
    }

    pub(crate) fn publication_launch(&self) -> &crate::LaunchSpec {
        &self.publication_launch
    }

    pub(crate) fn publication_record_for_generation_and_status(
        &self,
        generation: &str,
        status: SessionStatus,
    ) -> Result<SessionRecord, StoreError> {
        if generation.is_empty() || generation.len() > 128 {
            return Err(StoreError::Map(
                "prepared Session generation length must be 1..=128 bytes".into(),
            ));
        }
        if status == SessionStatus::Unknown {
            return Err(StoreError::Map(
                "an applied prepared Session cannot be published as Unknown".into(),
            ));
        }
        let mut replacement = self.unknown.clone();
        replacement.status = status;
        replacement.last_known_generation = Some(generation.to_string());
        replacement.last_attached_at_ms = self.params.now_ms;
        replacement.launch = self.publication_launch.clone();
        Ok(replacement)
    }

    pub(crate) fn published_agent_task(&self) -> Option<&AgentTask> {
        self.agent_task.as_ref().map(|transition| &transition.after)
    }

    pub(crate) fn workspace(&self) -> &Workspace {
        &self.workspace
    }

    pub(crate) fn graph_matches_in_snapshot(&self, paths: &AppPaths) -> Result<bool, StoreError> {
        let arc =
            crate::db::conn_for(paths.base()).map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let matches = self.graph_matches_connection(&tx)?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        Ok(matches)
    }

    pub(crate) fn graph_matches_connection(
        &self,
        conn: &rusqlite::Connection,
    ) -> Result<bool, StoreError> {
        if !prepared_params_match_unknown(
            &self.params,
            &self.unknown,
            &self.publication_launch,
            self.binding,
            self.agent_task
                .as_ref()
                .map(|transition| transition.before.agent_task_id.as_str()),
        ) || load_graph_record_for_prepared::<SessionRecord>(
            conn,
            RecordKind::Session,
            &self.unknown.session_id,
            "Session",
        )?
        .as_ref()
            != Some(&self.unknown)
            || load_graph_record_for_prepared::<Workspace>(
                conn,
                RecordKind::Workspace,
                &self.workspace.workspace_id,
                "Workspace",
            )?
            .as_ref()
                != Some(&self.workspace)
        {
            return Ok(false);
        }

        if let Some(transition) = &self.agent_task {
            let current_task = load_graph_record_for_prepared::<AgentTask>(
                conn,
                RecordKind::AgentTask,
                &transition.before.agent_task_id,
                "AgentTask",
            )?;
            if current_task.as_ref() != Some(&transition.before)
                || transition.before.project_id != self.workspace.project_id
                || transition.after.agent_task_id != transition.before.agent_task_id
                || transition.after.project_id != transition.before.project_id
                || transition.after.current_session_id.as_deref()
                    != Some(self.unknown.session_id.as_str())
                || !agent_task_pending_session_cohort_matches(
                    conn,
                    &transition.before,
                    &self.unknown.session_id,
                )?
            {
                return Ok(false);
            }
        }

        match &self.placement {
            PreparedNewSessionPlacement::Unplaced { project } => {
                Ok(load_graph_record_for_prepared::<Project>(
                    conn,
                    RecordKind::Project,
                    &project.project_id,
                    "Project",
                )?
                .as_ref()
                    == Some(project)
                    && project.project_id == self.workspace.project_id
                    && prepared_unplaced_session_refs_match(
                        conn,
                        &self.unknown,
                        project,
                        self.worktree_provenance.as_ref(),
                    )?)
            }
            PreparedNewSessionPlacement::ExistingWindow {
                project,
                post_layout,
                tab_id,
                split_source,
            } => prepared_existing_window_placement_matches(
                conn,
                project,
                post_layout,
                tab_id,
                &self.unknown,
                split_source.as_ref(),
                self.worktree_provenance.as_ref(),
            ),
            PreparedNewSessionPlacement::FreshWindowGraph {
                receipt,
                project,
                layout,
            } => prepared_fresh_window_placement_matches(
                conn,
                receipt,
                project,
                &self.workspace,
                &self.unknown,
                layout,
                self.worktree_provenance.as_ref(),
            ),
        }
    }

    /// Audit the exact post-publication graph for idempotent recovery after a lost SQLite commit
    /// result.  This is intentionally narrower than the A/Unknown matcher: task-aware recovery is
    /// currently admitted only for an unplaced headless start, and every durable task soft-ref must
    /// be the one sealed Task B.
    pub(crate) fn published_agent_task_graph_matches_connection(
        &self,
        conn: &rusqlite::Connection,
        replacement: &SessionRecord,
    ) -> Result<bool, StoreError> {
        let Some(transition) = &self.agent_task else {
            return Ok(false);
        };
        if self.publication_record_for_generation_and_status(
            replacement
                .last_known_generation
                .as_deref()
                .unwrap_or_default(),
            replacement.status,
        )? != *replacement
            || load_graph_record_for_prepared::<SessionRecord>(
                conn,
                RecordKind::Session,
                &replacement.session_id,
                "Session",
            )?
            .as_ref()
                != Some(replacement)
            || load_graph_record_for_prepared::<Workspace>(
                conn,
                RecordKind::Workspace,
                &self.workspace.workspace_id,
                "Workspace",
            )?
            .as_ref()
                != Some(&self.workspace)
            || load_graph_record_for_prepared::<AgentTask>(
                conn,
                RecordKind::AgentTask,
                &transition.after.agent_task_id,
                "AgentTask",
            )?
            .as_ref()
                != Some(&transition.after)
            || transition.after.project_id != self.workspace.project_id
            || transition.after.current_session_id.as_deref()
                != Some(replacement.session_id.as_str())
            || !agent_task_session_cohort_matches(conn, &transition.after)?
        {
            return Ok(false);
        }

        let PreparedNewSessionPlacement::Unplaced { project } = &self.placement else {
            // Placement-aware task publication is sealed in a later coordinator; refusing here
            // prevents a graphless recovery authority from adopting a tab/window mutation.
            return Ok(false);
        };
        Ok(load_graph_record_for_prepared::<Project>(
            conn,
            RecordKind::Project,
            &project.project_id,
            "Project",
        )?
        .as_ref()
            == Some(project)
            && project.project_id == self.workspace.project_id
            && prepared_unplaced_published_task_refs_match(
                conn,
                replacement,
                project,
                &transition.after,
                self.worktree_provenance.as_ref(),
            )?)
    }

    pub(crate) fn initial_compensation(self) -> PreparedNewSessionCompensationReceipt {
        let placement = match self.placement {
            PreparedNewSessionPlacement::Unplaced { project } => {
                PreparedNewSessionCompensationPlacement::Unplaced {
                    project,
                    workspace: self.workspace,
                }
            }
            PreparedNewSessionPlacement::ExistingWindow {
                project,
                post_layout,
                tab_id,
                ..
            } => PreparedNewSessionCompensationPlacement::ExistingWindow {
                project,
                workspace: self.workspace,
                post_layout,
                tab_id,
            },
            PreparedNewSessionPlacement::FreshWindowGraph { receipt, .. } => {
                PreparedNewSessionCompensationPlacement::FreshWindowGraph(receipt)
            }
        };
        PreparedNewSessionCompensationReceipt {
            session: self.unknown,
            placement,
            state: PreparedNewSessionCompensationState::UnknownRefused,
            agent_task: self.agent_task,
        }
    }

    /// Construct the successor compensation capability while the caller still holds the final
    /// `BEGIN IMMEDIATE` fence. The value may escape only if that same transaction commits B.
    pub(crate) fn rebased_compensation(
        &self,
        replacement: &SessionRecord,
    ) -> Result<PreparedNewSessionCompensationReceipt, StoreError> {
        if replacement.session_id != self.unknown.session_id
            || replacement.workspace_id != self.unknown.workspace_id
            || replacement.kind != self.unknown.kind
            || replacement.launch != self.publication_launch
            || replacement.cwd_resolved != self.unknown.cwd_resolved
            || replacement.agent_task_id != self.unknown.agent_task_id
            || replacement.created_at_ms != self.unknown.created_at_ms
            || replacement
                .last_known_generation
                .as_deref()
                .is_none_or(|generation| generation.is_empty() || generation.len() > 128)
            || replacement.status == SessionStatus::Unknown
        {
            return Err(StoreError::Map(
                "prepared Session replacement does not match its sealed Unknown row".into(),
            ));
        }

        let placement = match &self.placement {
            PreparedNewSessionPlacement::Unplaced { project } => {
                PreparedNewSessionCompensationPlacement::Unplaced {
                    project: project.clone(),
                    workspace: self.workspace.clone(),
                }
            }
            PreparedNewSessionPlacement::ExistingWindow {
                project,
                post_layout,
                tab_id,
                ..
            } => PreparedNewSessionCompensationPlacement::ExistingWindow {
                project: project.clone(),
                workspace: self.workspace.clone(),
                post_layout: post_layout.clone(),
                tab_id: tab_id.clone(),
            },
            PreparedNewSessionPlacement::FreshWindowGraph {
                receipt,
                project,
                layout,
            } => {
                let mut rebased = receipt.clone();
                rebased.graph_fingerprint = fresh_window_graph_fingerprint(
                    rebased.previous_project.as_ref(),
                    project,
                    &self.workspace,
                    replacement,
                    layout,
                    Some(project.project_id.as_str()),
                    rebased.created_project,
                    rebased.window_mutation_epoch,
                )
                .map_err(|error| StoreError::Map(error.to_string()))?;
                PreparedNewSessionCompensationPlacement::FreshWindowGraph(rebased)
            }
        };
        Ok(PreparedNewSessionCompensationReceipt {
            session: replacement.clone(),
            placement,
            state: PreparedNewSessionCompensationState::PublishedRebased,
            agent_task: self.agent_task.clone(),
        })
    }

    pub(crate) fn publish_agent_task_in_connection(
        &self,
        conn: &rusqlite::Connection,
    ) -> Result<PreparedAgentTaskPublication, StoreError> {
        let Some(transition) = &self.agent_task else {
            return Ok(PreparedAgentTaskPublication::NotTaskAware);
        };
        let current = load_graph_record_for_prepared::<AgentTask>(
            conn,
            RecordKind::AgentTask,
            &transition.before.agent_task_id,
            "AgentTask",
        )?;
        if current.as_ref() != Some(&transition.before) {
            return Ok(PreparedAgentTaskPublication::Changed);
        }
        let value = serde_json::to_value(&transition.after)
            .map_err(|error| StoreError::Map(format!("serialize AgentTask: {error}")))?;
        crate::store_sqlite::upsert(
            conn,
            RecordKind::AgentTask,
            &transition.after.agent_task_id,
            &value,
        )
        .map_err(|error| StoreError::Map(error.to_string()))?;
        Ok(PreparedAgentTaskPublication::Published(
            transition.after.clone(),
        ))
    }
}

impl fmt::Debug for PreparedNewSessionStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedNewSessionStart")
            .field("session_id", &self.unknown.session_id)
            .field("workspace_id", &self.workspace.workspace_id)
            .field("window_id", &self.window_id())
            .field("tab_id", &self.tab_id())
            .finish_non_exhaustive()
    }
}

enum PreparedNewSessionCompensationPlacement {
    Unplaced {
        project: Project,
        workspace: Workspace,
    },
    ExistingWindow {
        project: Project,
        workspace: Workspace,
        post_layout: WindowLayoutSnapshot,
        tab_id: String,
    },
    FreshWindowGraph(FreshWindowGraphReceipt),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PreparedNewSessionCompensationState {
    UnknownRefused,
    PublishedRebased,
}

/// Consume-once exact rollback authority. A typed conditional-start refusal may mint the
/// `UnknownRefused` state; successful final publication mints a distinct `PublishedRebased`
/// successor for either a Live or already-Exited applied generation.
/// It does not implement `Clone` and exposes no durable row or launch bytes.
pub struct PreparedNewSessionCompensationReceipt {
    session: SessionRecord,
    placement: PreparedNewSessionCompensationPlacement,
    state: PreparedNewSessionCompensationState,
    agent_task: Option<PreparedAgentTaskTransition>,
}

/// Task-aware consume-once compensation capability. It cannot be converted into the generic
/// receipt, so exact Task A/B guards cannot be dropped by routing a task start through pane APIs.
pub struct PreparedAgentTaskSessionCompensation {
    receipt: PreparedNewSessionCompensationReceipt,
    journal: PreparedAgentTaskStartJournalReceipt,
}

impl PreparedAgentTaskSessionCompensation {
    pub fn session_id(&self) -> &str {
        self.receipt.session_id()
    }

    pub fn agent_task_id(&self) -> &str {
        &self
            .receipt
            .agent_task
            .as_ref()
            .expect("task compensation owns an exact task transition")
            .before
            .agent_task_id
    }

    pub(crate) fn from_parts(
        receipt: PreparedNewSessionCompensationReceipt,
        journal: PreparedAgentTaskStartJournalReceipt,
    ) -> Result<Self, PreparedNewSessionCompensationReceipt> {
        if receipt.agent_task.is_some() {
            Ok(Self { receipt, journal })
        } else {
            Err(receipt)
        }
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        PreparedNewSessionCompensationReceipt,
        PreparedAgentTaskStartJournalReceipt,
    ) {
        (self.receipt, self.journal)
    }
}

impl fmt::Debug for PreparedAgentTaskSessionCompensation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedAgentTaskSessionCompensation")
            .field("session_id", &self.session_id())
            .field("agent_task_id", &self.agent_task_id())
            .finish_non_exhaustive()
    }
}

impl PreparedNewSessionCompensationReceipt {
    pub fn session_id(&self) -> &str {
        &self.session.session_id
    }
}

impl fmt::Debug for PreparedNewSessionCompensationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (window_id, tab_id, placement) = match &self.placement {
            PreparedNewSessionCompensationPlacement::Unplaced { .. } => {
                ("<unplaced>", "<unplaced>", "unplaced")
            }
            PreparedNewSessionCompensationPlacement::ExistingWindow {
                project: _,
                workspace: _,
                post_layout,
                tab_id,
            } => (
                post_layout.layout.window_id.as_str(),
                tab_id.as_str(),
                "existing-window",
            ),
            PreparedNewSessionCompensationPlacement::FreshWindowGraph(receipt) => (
                receipt.window_id.as_str(),
                receipt.tab_id.as_str(),
                "fresh-window-graph",
            ),
        };
        formatter
            .debug_struct("PreparedNewSessionCompensationReceipt")
            .field("session_id", &self.session.session_id)
            .field("window_id", &window_id)
            .field("tab_id", &tab_id)
            .field("placement", &placement)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Result of consuming a prepared-session compensation receipt.
#[derive(Debug)]
pub enum ConditionalPreparedNewSessionCompensation {
    Unplaced(ConditionalPreparedUnplacedSessionRollback),
    ExistingWindow(ConditionalCreatedTabSessionRollback),
    FreshWindowGraph(ConditionalFreshWindowGraphDelete),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionalPreparedUnplacedSessionRollback {
    RolledBack,
    Missing,
    Changed,
    Referenced,
}

fn canonical_prepared_unknown(
    params: &StartParams,
    publication_launch: &crate::LaunchSpec,
    binding: PreparedSessionBinding,
) -> Result<SessionRecord, WindowLayoutError> {
    canonical_prepared_unknown_with_agent_task(params, publication_launch, binding, None)
}

fn canonical_prepared_unknown_with_agent_task(
    params: &StartParams,
    publication_launch: &crate::LaunchSpec,
    binding: PreparedSessionBinding,
    expected_agent_task_id: Option<&str>,
) -> Result<SessionRecord, WindowLayoutError> {
    crate::validate_id(&params.session_id).map_err(StoreError::Id)?;
    crate::validate_id(&params.workspace_id).map_err(StoreError::Id)?;
    if params.command.trim().is_empty() {
        return Err(WindowLayoutError::Store(StoreError::Map(
            "prepared Session command must not be empty".into(),
        )));
    }
    if params.agent_task_id.as_deref() != expected_agent_task_id {
        return Err(WindowLayoutError::Store(StoreError::Map(
            "prepared pane Session cannot adopt an unsealed AgentTask reference".into(),
        )));
    }
    let mut live_argv = Vec::with_capacity(1 + params.args.len());
    live_argv.push(params.command.clone());
    live_argv.extend(params.args.iter().cloned());
    let launch_is_bound = match binding {
        PreparedSessionBinding::LegacyShellAdHoc => {
            params.kind == SessionKind::Shell
                && publication_launch == &params.launch
                && params.launch == crate::redact::adhoc_launch_spec(&live_argv)
        }
        PreparedSessionBinding::ExactAdHoc => {
            matches!(params.kind, SessionKind::Shell | SessionKind::Agent)
                && publication_launch == &params.launch
                && params.launch
                    == if params.kind == SessionKind::Agent {
                        crate::workspace_exec::noncanonicalizable_agent_launch(&live_argv)
                    } else {
                        crate::redact::adhoc_launch_spec(&live_argv)
                    }
        }
        PreparedSessionBinding::AgentAdHocLoginShell => {
            params.kind == SessionKind::Agent
                && publication_launch == &params.launch
                && matches!(
                    &params.launch,
                    crate::LaunchSpec::AdHocRedacted {
                        redacted: true,
                        restart_requires_user: true,
                        ..
                    }
                )
        }
        PreparedSessionBinding::ProviderExact => {
            params.kind == SessionKind::Agent
                && publication_launch == &params.launch
                && crate::restart_recipe::known_safe_provider_has_exact_resume(publication_launch)
        }
        PreparedSessionBinding::ProviderExplicitNonExact => {
            params.kind == SessionKind::Agent
                && matches!(
                    &params.launch,
                    crate::LaunchSpec::AdHocRedacted {
                        redacted: true,
                        restart_requires_user: true,
                        ..
                    }
                )
                && crate::restart_recipe::strict_known_safe_provider_mode(publication_launch)
                    == Some(crate::restart_recipe::PreparedProviderLaunchMode::ExplicitNonExact)
        }
        PreparedSessionBinding::ProviderTransition => {
            params.kind == SessionKind::Agent
                && matches!(
                    &params.launch,
                    crate::LaunchSpec::AdHocRedacted {
                        redacted: true,
                        restart_requires_user: true,
                        ..
                    }
                )
                && crate::restart_recipe::strict_known_safe_provider_mode(publication_launch)
                    == Some(crate::restart_recipe::PreparedProviderLaunchMode::ExactResume)
        }
    };
    if !launch_is_bound {
        return Err(WindowLayoutError::Store(StoreError::Map(
            "prepared pane launch metadata does not match its sealed source/wire binding".into(),
        )));
    }
    if !std::path::Path::new(&params.cwd).is_dir() {
        return Err(WindowLayoutError::Store(StoreError::Map(
            "prepared Session cwd is not an existing directory".into(),
        )));
    }
    Ok(SessionRecord {
        session_id: params.session_id.clone(),
        workspace_id: params.workspace_id.clone(),
        kind: params.kind,
        launch: params.launch.clone(),
        cwd_resolved: params.cwd.clone(),
        agent_task_id: expected_agent_task_id.map(str::to_string),
        created_at_ms: params.now_ms,
        last_attached_at_ms: params.now_ms,
        last_known_generation: None,
        status: SessionStatus::Unknown,
    })
}

fn prepared_params_match_unknown(
    params: &StartParams,
    unknown: &SessionRecord,
    publication_launch: &crate::LaunchSpec,
    binding: PreparedSessionBinding,
    expected_agent_task_id: Option<&str>,
) -> bool {
    let mut live_argv = Vec::with_capacity(1 + params.args.len());
    live_argv.push(params.command.clone());
    live_argv.extend(params.args.iter().cloned());
    unknown.session_id == params.session_id
        && unknown.workspace_id == params.workspace_id
        && unknown.kind == params.kind
        && unknown.launch == params.launch
        && unknown.cwd_resolved == params.cwd
        && unknown.agent_task_id == params.agent_task_id
        && params.agent_task_id.as_deref() == expected_agent_task_id
        && unknown.created_at_ms == params.now_ms
        && unknown.last_attached_at_ms == params.now_ms
        && unknown.last_known_generation.is_none()
        && unknown.status == SessionStatus::Unknown
        && !params.command.trim().is_empty()
        && match binding {
            PreparedSessionBinding::LegacyShellAdHoc => {
                params.kind == SessionKind::Shell
                    && publication_launch == &params.launch
                    && params.launch == crate::redact::adhoc_launch_spec(&live_argv)
            }
            PreparedSessionBinding::ExactAdHoc => {
                matches!(params.kind, SessionKind::Shell | SessionKind::Agent)
                    && publication_launch == &params.launch
                    && params.launch
                        == if params.kind == SessionKind::Agent {
                            crate::workspace_exec::noncanonicalizable_agent_launch(&live_argv)
                        } else {
                            crate::redact::adhoc_launch_spec(&live_argv)
                        }
            }
            PreparedSessionBinding::AgentAdHocLoginShell => {
                params.kind == SessionKind::Agent
                    && publication_launch == &params.launch
                    && matches!(
                        &params.launch,
                        crate::LaunchSpec::AdHocRedacted {
                            redacted: true,
                            restart_requires_user: true,
                            ..
                        }
                    )
            }
            PreparedSessionBinding::ProviderExact => {
                params.kind == SessionKind::Agent
                    && publication_launch == &params.launch
                    && crate::restart_recipe::known_safe_provider_has_exact_resume(
                        publication_launch,
                    )
            }
            PreparedSessionBinding::ProviderExplicitNonExact => {
                params.kind == SessionKind::Agent
                    && matches!(
                        &params.launch,
                        crate::LaunchSpec::AdHocRedacted {
                            redacted: true,
                            restart_requires_user: true,
                            ..
                        }
                    )
                    && crate::restart_recipe::strict_known_safe_provider_mode(publication_launch)
                        == Some(crate::restart_recipe::PreparedProviderLaunchMode::ExplicitNonExact)
            }
            PreparedSessionBinding::ProviderTransition => {
                params.kind == SessionKind::Agent
                    && matches!(
                        &params.launch,
                        crate::LaunchSpec::AdHocRedacted {
                            redacted: true,
                            restart_requires_user: true,
                            ..
                        }
                    )
                    && crate::restart_recipe::strict_known_safe_provider_mode(publication_launch)
                        == Some(crate::restart_recipe::PreparedProviderLaunchMode::ExactResume)
            }
        }
}

fn load_graph_record_for_prepared<T: serde::de::DeserializeOwned>(
    conn: &rusqlite::Connection,
    kind: RecordKind,
    id: &str,
    what: &str,
) -> Result<Option<T>, StoreError> {
    crate::store_sqlite::load_one(conn, kind, id)
        .map_err(|error| StoreError::Map(error.to_string()))?
        .map(|value| {
            serde_json::from_value(value)
                .map_err(|error| StoreError::Map(format!("deserialize {what} {id:?}: {error}")))
        })
        .transpose()
}

/// Finish the Worktree cohort from an opaque prepared-cwd seal plus the exact Workspace row that
/// the caller will revalidate under its writer transaction. A Worktree Workspace without a seal,
/// or a seal presented for Scratch/RepoWrite, is a closed mismatch rather than a generic marker
/// bypass.
fn complete_prepared_worktree_provenance(
    seal: Option<&PreparedWorktreeProvenanceSeal>,
    workspace: &Workspace,
    session: &SessionRecord,
) -> Result<Option<PreparedWorktreeProvenanceCohort>, StoreError> {
    match (workspace.policy, seal) {
        (crate::WorkspacePolicy::Worktree, Some(seal)) => seal
            .complete(
                workspace,
                &session.session_id,
                &session.workspace_id,
                &session.cwd_resolved,
            )
            .map(Some)
            .ok_or_else(|| {
                StoreError::Map(
                    "prepared Worktree provenance seal does not match the exact Session/Workspace cohort"
                        .into(),
                )
            }),
        (crate::WorkspacePolicy::Worktree, None) => Err(StoreError::Map(
            "prepared Worktree Session has no same-attempt provenance seal".into(),
        )),
        (_, Some(_)) => Err(StoreError::Map(
            "non-Worktree Session cannot consume Worktree provenance authority".into(),
        )),
        (_, None) => Ok(None),
    }
}

/// A best-effort marker may be absent. If it is present, however, every ownership-bearing field
/// must match the one complete cohort sealed for this preparation; malformed rows surface as an
/// error and foreign/mismatched rows return a closed refusal.
fn prepared_worktree_provenance_matches(
    conn: &rusqlite::Connection,
    session_id: &str,
    expected: Option<&PreparedWorktreeProvenanceCohort>,
) -> Result<bool, StoreError> {
    let marker = load_graph_record_for_prepared::<WorktreeProvenance>(
        conn,
        RecordKind::WorktreeProvenance,
        session_id,
        "WorktreeProvenance",
    )?;
    match marker {
        None => Ok(true),
        Some(marker) => Ok(expected.is_some_and(|expected| {
            expected.session_id == session_id && expected.matches(&marker)
        })),
    }
}

fn prepared_session_soft_refs_match(
    conn: &rusqlite::Connection,
    session: &SessionRecord,
    expected_project_id: &str,
    expected_window_id: &str,
    expected_tab_id: &str,
    fresh_workspace: bool,
    allowed_worktree_provenance: Option<&PreparedWorktreeProvenanceCohort>,
) -> Result<bool, StoreError> {
    let ownership = crate::project::session_ownership_graph(conn).map_err(|error| {
        StoreError::Map(format!("prepared Session owner proof failed: {error}"))
    })?;
    let rows = ownership
        .session_rows
        .iter()
        .filter(|(session_id, _, _)| session_id == &session.session_id)
        .collect::<Vec<_>>();
    if rows.len() != 1
        || rows[0].1 != expected_project_id
        || rows[0].2.as_deref() != session.last_known_generation.as_deref()
    {
        return Ok(false);
    }
    let tabs = ownership
        .tab_refs
        .iter()
        .filter(|(_, _, session_id)| session_id == &session.session_id)
        .collect::<Vec<_>>();
    if tabs.len() != 1 || tabs[0].0 != expected_window_id || tabs[0].1 != expected_tab_id {
        return Ok(false);
    }
    if ownership
        .task_refs
        .iter()
        .any(|(_, refs)| refs.iter().any(|id| id == &session.session_id))
        || strict_layout_preset_session_refs(conn)?
            .iter()
            .any(|(_, tabs)| {
                tabs.iter()
                    .any(|tab| tab.session_id.as_deref() == Some(session.session_id.as_str()))
            })
    {
        return Ok(false);
    }
    if !prepared_worktree_provenance_matches(
        conn,
        &session.session_id,
        allowed_worktree_provenance,
    )? {
        return Ok(false);
    }
    if fresh_workspace {
        if ownership
            .worktree_refs
            .iter()
            .any(|(_, workspace_id, _)| workspace_id == &session.workspace_id)
        {
            return Ok(false);
        }
        let child_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE workspace_id = ?1",
                [&session.workspace_id],
                |row| row.get(0),
            )
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if child_count != 1 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn prepared_unplaced_session_refs_match(
    conn: &rusqlite::Connection,
    session: &SessionRecord,
    expected_project: &Project,
    allowed_worktree_provenance: Option<&PreparedWorktreeProvenanceCohort>,
) -> Result<bool, StoreError> {
    let ownership = crate::project::session_ownership_graph(conn).map_err(|error| {
        StoreError::Map(format!(
            "prepared unplaced Session owner proof failed: {error}"
        ))
    })?;
    let rows = ownership
        .session_rows
        .iter()
        .filter(|(session_id, _, _)| session_id == &session.session_id)
        .collect::<Vec<_>>();
    if rows.len() != 1
        || rows[0].1 != expected_project.project_id
        || rows[0].2.as_deref() != session.last_known_generation.as_deref()
    {
        return Ok(false);
    }
    if ownership
        .tab_refs
        .iter()
        .any(|(_, _, session_id)| session_id == &session.session_id)
        || ownership
            .task_refs
            .iter()
            .any(|(_, refs)| refs.iter().any(|id| id == &session.session_id))
        || strict_layout_preset_session_refs(conn)?
            .iter()
            .any(|(_, tabs)| {
                tabs.iter()
                    .any(|tab| tab.session_id.as_deref() == Some(session.session_id.as_str()))
            })
    {
        return Ok(false);
    }
    prepared_worktree_provenance_matches(conn, &session.session_id, allowed_worktree_provenance)
}

fn prepared_unplaced_published_task_refs_match(
    conn: &rusqlite::Connection,
    session: &SessionRecord,
    expected_project: &Project,
    expected_task: &AgentTask,
    allowed_worktree_provenance: Option<&PreparedWorktreeProvenanceCohort>,
) -> Result<bool, StoreError> {
    let ownership = crate::project::session_ownership_graph(conn).map_err(|error| {
        StoreError::Map(format!(
            "prepared published AgentTask Session owner proof failed: {error}"
        ))
    })?;
    let rows = ownership
        .session_rows
        .iter()
        .filter(|(session_id, _, _)| session_id == &session.session_id)
        .collect::<Vec<_>>();
    let task_refs = ownership
        .task_refs
        .iter()
        .filter(|(_, refs)| refs.iter().any(|id| id == &session.session_id))
        .collect::<Vec<_>>();
    if rows.len() != 1
        || rows[0].1 != expected_project.project_id
        || rows[0].2.as_deref() != session.last_known_generation.as_deref()
        || task_refs.len() != 1
        || task_refs[0].0 != expected_task.project_id
        || expected_task.project_id != expected_project.project_id
        || ownership
            .tab_refs
            .iter()
            .any(|(_, _, session_id)| session_id == &session.session_id)
        || strict_layout_preset_session_refs(conn)?
            .iter()
            .any(|(_, tabs)| {
                tabs.iter()
                    .any(|tab| tab.session_id.as_deref() == Some(session.session_id.as_str()))
            })
    {
        return Ok(false);
    }
    prepared_worktree_provenance_matches(conn, &session.session_id, allowed_worktree_provenance)
}

fn agent_task_session_cohort_matches(
    conn: &rusqlite::Connection,
    task: &AgentTask,
) -> Result<bool, StoreError> {
    let mut allowed = task
        .session_history
        .iter()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    if let Some(current) = &task.current_session_id {
        allowed.insert(current.clone());
    }
    if !agent_task_existing_session_refs_match(conn, task, &allowed)? {
        return Ok(false);
    }
    let mut statement = conn
        .prepare("SELECT session_id FROM sessions WHERE agent_task_id = ?1 ORDER BY session_id")
        .map_err(|error| StoreError::Db(error.to_string()))?;
    let rows = statement
        .query_map([&task.agent_task_id], |row| row.get::<_, String>(0))
        .map_err(|error| StoreError::Db(error.to_string()))?;
    for row in rows {
        let session_id = row.map_err(|error| StoreError::Db(error.to_string()))?;
        if !allowed.contains(&session_id) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn agent_task_pending_session_cohort_matches(
    conn: &rusqlite::Connection,
    task: &AgentTask,
    pending_session_id: &str,
) -> Result<bool, StoreError> {
    let mut allowed = task
        .session_history
        .iter()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    if let Some(current) = &task.current_session_id {
        allowed.insert(current.clone());
    }
    if !agent_task_existing_session_refs_match(conn, task, &allowed)? {
        return Ok(false);
    }
    allowed.insert(pending_session_id.to_string());
    let mut saw_pending = false;
    let mut statement = conn
        .prepare("SELECT session_id FROM sessions WHERE agent_task_id = ?1 ORDER BY session_id")
        .map_err(|error| StoreError::Db(error.to_string()))?;
    let rows = statement
        .query_map([&task.agent_task_id], |row| row.get::<_, String>(0))
        .map_err(|error| StoreError::Db(error.to_string()))?;
    for row in rows {
        let session_id = row.map_err(|error| StoreError::Db(error.to_string()))?;
        saw_pending |= session_id == pending_session_id;
        if !allowed.contains(&session_id) {
            return Ok(false);
        }
    }
    Ok(saw_pending)
}

fn agent_task_existing_session_refs_match(
    conn: &rusqlite::Connection,
    task: &AgentTask,
    referenced_ids: &std::collections::HashSet<String>,
) -> Result<bool, StoreError> {
    for session_id in referenced_ids {
        let Some(session) = load_graph_record_for_prepared::<SessionRecord>(
            conn,
            RecordKind::Session,
            session_id,
            "AgentTask Session",
        )?
        else {
            // Historical rows may have been released. Absence is not authority for a different
            // row, while any present row must remain in the exact task/project cohort.
            continue;
        };
        if session.agent_task_id.as_deref() != Some(task.agent_task_id.as_str()) {
            return Ok(false);
        }
        let Some(workspace) = load_graph_record_for_prepared::<Workspace>(
            conn,
            RecordKind::Workspace,
            &session.workspace_id,
            "AgentTask Session Workspace",
        )?
        else {
            return Ok(false);
        };
        if workspace.project_id != task.project_id {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) fn prepared_absent_session_namespace_is_clean(
    conn: &rusqlite::Connection,
    session_id: &str,
) -> Result<bool, StoreError> {
    prepared_absent_session_namespace_matches(conn, session_id, None)
}

fn prepared_absent_session_namespace_matches(
    conn: &rusqlite::Connection,
    session_id: &str,
    allowed_worktree_provenance: Option<&PreparedWorktreeProvenanceCohort>,
) -> Result<bool, StoreError> {
    let ownership = crate::project::session_ownership_graph(conn).map_err(|error| {
        StoreError::Map(format!("prepared Session owner proof failed: {error}"))
    })?;
    let otherwise_clean = !ownership
        .session_rows
        .iter()
        .any(|(id, _, _)| id == session_id)
        && !ownership
            .task_refs
            .iter()
            .any(|(_, refs)| refs.iter().any(|id| id == session_id))
        && !ownership.tab_refs.iter().any(|(_, _, id)| id == session_id)
        && !strict_layout_preset_session_refs(conn)?
            .iter()
            .any(|(_, tabs)| {
                tabs.iter()
                    .any(|tab| tab.session_id.as_deref() == Some(session_id))
            });
    Ok(otherwise_clean
        && prepared_worktree_provenance_matches(conn, session_id, allowed_worktree_provenance)?)
}

fn prepared_project_order_matches(
    conn: &rusqlite::Connection,
    window_id: &str,
    expected_project_id: &str,
) -> Result<bool, StoreError> {
    let orders = crate::project::project_window_orders(conn)
        .map_err(|error| StoreError::Map(format!("prepared window order proof failed: {error}")))?;
    let owners = orders
        .iter()
        .filter(|(_, order)| order.iter().any(|id| id == window_id))
        .map(|(project_id, _)| project_id.as_str())
        .collect::<Vec<_>>();
    Ok(owners == [expected_project_id])
}

fn prepared_existing_window_placement_matches(
    conn: &rusqlite::Connection,
    expected_project: &Project,
    expected_layout: &WindowLayoutSnapshot,
    expected_tab_id: &str,
    expected_session: &SessionRecord,
    expected_split_source: Option<&PreparedSplitSource>,
    allowed_worktree_provenance: Option<&PreparedWorktreeProvenanceCohort>,
) -> Result<bool, StoreError> {
    let current =
        WindowLayoutService::load_snapshot_from_connection(conn, &expected_layout.layout.window_id)
            .map_err(|error| StoreError::Map(error.to_string()))?;
    if current.as_ref() != Some(expected_layout) {
        return Ok(false);
    }
    let Some(project_id) = expected_layout.project_id.as_deref() else {
        return Ok(false);
    };
    if project_id != expected_project.project_id
        || load_graph_record_for_prepared::<Project>(
            conn,
            RecordKind::Project,
            &expected_project.project_id,
            "Project",
        )?
        .as_ref()
            != Some(expected_project)
    {
        return Ok(false);
    }
    let exact_tab = expected_layout
        .layout
        .tabs
        .iter()
        .filter(|tab| tab.tab_id == expected_tab_id)
        .collect::<Vec<_>>();
    if exact_tab.len() != 1 || exact_tab[0].session_id != expected_session.session_id {
        return Ok(false);
    }
    if let Some(source) = expected_split_source {
        let source_tabs = expected_layout
            .layout
            .tabs
            .iter()
            .filter(|tab| tab.tab_id == source.tab_id)
            .collect::<Vec<_>>();
        if source.session.workspace_id != expected_session.workspace_id
            || source_tabs.len() != 1
            || source_tabs[0].stashed
            || source_tabs[0].session_id != source.session.session_id
            || load_graph_record_for_prepared::<SessionRecord>(
                conn,
                RecordKind::Session,
                &source.session.session_id,
                "split source Session",
            )?
            .as_ref()
                != Some(&source.session)
        {
            return Ok(false);
        }
    }
    Ok(
        prepared_project_order_matches(conn, &expected_layout.layout.window_id, project_id)?
            && prepared_session_soft_refs_match(
                conn,
                expected_session,
                project_id,
                &expected_layout.layout.window_id,
                expected_tab_id,
                false,
                allowed_worktree_provenance,
            )?,
    )
}

fn prepared_fresh_window_placement_matches(
    conn: &rusqlite::Connection,
    receipt: &FreshWindowGraphReceipt,
    expected_project: &Project,
    expected_workspace: &Workspace,
    expected_session: &SessionRecord,
    expected_layout: &WindowLayout,
    allowed_worktree_provenance: Option<&PreparedWorktreeProvenanceCohort>,
) -> Result<bool, StoreError> {
    let current_epoch = crate::db::window_mutation_epoch(conn)
        .map_err(|error| StoreError::Db(error.to_string()))?;
    let current_project = load_graph_record_for_prepared::<Project>(
        conn,
        RecordKind::Project,
        &receipt.project_id,
        "Project",
    )?;
    let current_window =
        WindowLayoutService::load_snapshot_from_connection(conn, &receipt.window_id)
            .map_err(|error| StoreError::Map(error.to_string()))?;
    if current_epoch != receipt.window_mutation_epoch
        || current_project.as_ref() != Some(expected_project)
        || current_window
            .as_ref()
            .is_none_or(|window| window.layout != *expected_layout)
        || current_window
            .as_ref()
            .and_then(|window| window.project_id.as_deref())
            != Some(expected_project.project_id.as_str())
        || expected_workspace.workspace_id != receipt.workspace_id
        || expected_session.session_id != receipt.session_id
    {
        return Ok(false);
    }
    let fingerprint = fresh_window_graph_fingerprint(
        receipt.previous_project.as_ref(),
        expected_project,
        expected_workspace,
        expected_session,
        expected_layout,
        Some(expected_project.project_id.as_str()),
        receipt.created_project,
        current_epoch,
    )
    .map_err(|error| StoreError::Map(error.to_string()))?;
    if fingerprint != receipt.graph_fingerprint
        || !prepared_project_order_matches(conn, &receipt.window_id, &receipt.project_id)?
        || !prepared_session_soft_refs_match(
            conn,
            expected_session,
            &receipt.project_id,
            &receipt.window_id,
            &receipt.tab_id,
            true,
            allowed_worktree_provenance,
        )?
    {
        return Ok(false);
    }
    if receipt.created_project {
        let child_count: i64 = conn
            .query_row(
                "SELECT \
                   (SELECT COUNT(*) FROM workspaces WHERE project_id = ?1) + \
                   (SELECT COUNT(*) FROM agent_tasks WHERE project_id = ?1) + \
                   (SELECT COUNT(*) FROM windows WHERE project_id = ?1) + \
                   (SELECT COUNT(*) FROM layout_presets WHERE project_id = ?1)",
                [&receipt.project_id],
                |row| row.get(0),
            )
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if child_count != 2 {
            return Ok(false);
        }
    }
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn apply_prepared_open_tab(
    layout: &mut WindowLayout,
    tab_id: &str,
    session_id: &str,
    title: &str,
    pinned: bool,
    attention: AttentionState,
    stashed: bool,
) -> Result<(), WindowLayoutError> {
    if layout.tabs.iter().any(|tab| tab.tab_id == tab_id) {
        return Err(WindowLayoutError::TabAlreadyExists {
            window_id: layout.window_id.clone(),
            tab_id: tab_id.to_string(),
        });
    }
    let next_index = layout
        .tabs
        .iter()
        .map(|tab| tab.index)
        .max()
        .map_or(0, |max| max + 1);
    let sibling_titles = layout
        .tabs
        .iter()
        .map(|tab| tab.title.clone())
        .collect::<Vec<_>>();
    layout.tabs.push(TabRecord {
        tab_id: tab_id.to_string(),
        session_id: session_id.to_string(),
        index: next_index,
        title: crate::unique_name(title, &sibling_titles),
        pinned,
        attention,
        split_from: None,
        pane_rect: None,
        stashed_from: None,
        stashed,
    });
    Ok(())
}

fn apply_prepared_split_tab(
    layout: &mut WindowLayout,
    from_tab_id: &str,
    tab_id: &str,
    session_id: &str,
    title: &str,
    axis: SplitAxis,
) -> Result<(), WindowLayoutError> {
    if !layout.tabs.iter().any(|tab| tab.tab_id == from_tab_id) {
        return Err(WindowLayoutError::TabNotFound {
            window_id: layout.window_id.clone(),
            tab_id: from_tab_id.to_string(),
        });
    }
    if layout.tabs.iter().any(|tab| tab.tab_id == tab_id) {
        return Err(WindowLayoutError::TabAlreadyExists {
            window_id: layout.window_id.clone(),
            tab_id: tab_id.to_string(),
        });
    }
    let next_index = layout
        .tabs
        .iter()
        .map(|tab| tab.index)
        .max()
        .map_or(0, |max| max + 1);
    let sibling_titles = layout
        .tabs
        .iter()
        .map(|tab| tab.title.clone())
        .collect::<Vec<_>>();
    layout.tabs.push(TabRecord {
        tab_id: tab_id.to_string(),
        session_id: session_id.to_string(),
        index: next_index,
        title: crate::unique_name(title, &sibling_titles),
        pinned: false,
        attention: AttentionState::default(),
        split_from: Some(SplitFrom {
            tab_id: from_tab_id.to_string(),
            axis,
            ratio_per_mille: None,
        }),
        pane_rect: None,
        stashed_from: None,
        stashed: false,
    });

    let edge = match axis {
        SplitAxis::Right => EdgeDir::Right,
        SplitAxis::Down => EdgeDir::Bottom,
    };
    let mut panes = layout
        .tabs
        .iter()
        .filter(|tab| !tab.stashed && tab.tab_id != tab_id)
        .map(|tab| AgentRect {
            agent: tab.tab_id.clone(),
            rect: tab
                .pane_rect
                .map_or([0.0, 0.0, 1.0, 1.0], PaneRect::to_unit),
        })
        .collect::<Vec<_>>();
    let source = panes
        .iter()
        .position(|pane| pane.agent == from_tab_id)
        .or_else(|| {
            panes
                .iter()
                .enumerate()
                .max_by(|(_, left), (_, right)| {
                    (left.rect[2] * left.rect[3])
                        .partial_cmp(&(right.rect[2] * right.rect[3]))
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(index, _)| index)
        });
    match source {
        Some(source) => {
            let (kept, inserted) = split_rect_local(panes[source].rect, edge);
            panes[source].rect = kept;
            panes.push(AgentRect {
                agent: tab_id.to_string(),
                rect: inserted,
            });
        }
        None => panes.push(AgentRect {
            agent: tab_id.to_string(),
            rect: [0.0, 0.0, 1.0, 1.0],
        }),
    }
    for pane in panes {
        if let Some(tab) = layout.tabs.iter_mut().find(|tab| tab.tab_id == pane.agent) {
            tab.pane_rect = Some(PaneRect::from_unit(pane.rect));
        }
    }
    Ok(())
}

impl fmt::Debug for FreshWindowGraphReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FreshWindowGraphReceipt")
            .field("project_id", &self.project_id)
            .field("workspace_id", &self.workspace_id)
            .field("session_id", &self.session_id)
            .field("window_id", &self.window_id)
            .field("tab_id", &self.tab_id)
            .finish_non_exhaustive()
    }
}

/// Result of receipt-only compensation for a freshly created graph.
#[derive(Debug)]
pub enum ConditionalFreshWindowGraphDelete {
    Deleted {
        release_receipt: Option<PendingReleaseReceipt>,
        unresolved_release_session_ids: Vec<String>,
    },
    Missing,
    Changed,
    Referenced,
}

fn fresh_window_graph_fingerprint(
    previous_project: Option<&Project>,
    project: &Project,
    workspace: &Workspace,
    session: &SessionRecord,
    layout: &WindowLayout,
    owner_project_id: Option<&str>,
    created_project: bool,
    window_mutation_epoch: u32,
) -> Result<[u8; 32], WindowLayoutError> {
    use sha2::{Digest as _, Sha256};

    let canonical = serde_json::to_vec(&(
        previous_project,
        project,
        workspace,
        session,
        layout,
        owner_project_id,
        created_project,
        window_mutation_epoch,
    ))
    .map_err(|error| {
        WindowLayoutError::Store(StoreError::Map(format!(
            "serialize fresh window graph proof: {error}"
        )))
    })?;
    let digest = Sha256::digest(canonical);
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(&digest);
    Ok(fingerprint)
}

fn window_layout_snapshot_fingerprint(
    snapshot: &WindowLayoutSnapshot,
) -> Result<[u8; 32], WindowLayoutError> {
    use sha2::{Digest as _, Sha256};

    let canonical = serde_json::to_vec(&(
        &snapshot.layout,
        &snapshot.project_id,
        snapshot.revision.window_mutation_epoch,
    ))
    .map_err(|error| {
        WindowLayoutError::Store(StoreError::Map(format!(
            "serialize window deletion snapshot proof: {error}"
        )))
    })?;
    let digest = Sha256::digest(canonical);
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(&digest);
    Ok(fingerprint)
}

fn prepared_agent_task_journal_fingerprint<T: serde::Serialize>(
    value: &T,
) -> Result<[u8; 32], StoreError> {
    use sha2::{Digest as _, Sha256};

    let canonical = serde_json::to_vec(value).map_err(|error| {
        StoreError::Map(format!(
            "serialize prepared AgentTask journal graph: {error}"
        ))
    })?;
    let digest = Sha256::digest(canonical);
    let mut fingerprint = [0_u8; 32];
    fingerprint.copy_from_slice(&digest);
    Ok(fingerprint)
}

fn prepared_agent_task_journal_clock_ms() -> Result<u64, StoreError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| StoreError::Map("system clock precedes Unix epoch".into()))?
        .as_millis()
        .try_into()
        .map_err(|_| StoreError::Map("system clock exceeds u64 milliseconds".into()))
}

fn prepared_agent_task_start_journal_matches(
    conn: &rusqlite::Connection,
    receipt: &PreparedAgentTaskStartJournalReceipt,
) -> Result<bool, StoreError> {
    prepared_agent_task_start_journal_matches_with_disposition(conn, receipt, &receipt.disposition)
}

fn prepared_agent_task_start_journal_matches_with_disposition(
    conn: &rusqlite::Connection,
    receipt: &PreparedAgentTaskStartJournalReceipt,
    disposition: &str,
) -> Result<bool, StoreError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM pending_agent_task_starts \
         WHERE session_id = ?1 AND agent_task_id = ?2 AND operation_token = ?3 \
           AND project_id = ?4 AND workspace_id = ?5 \
           AND binding_state = ?6 AND daemon_instance_id IS ?7 AND server_pid IS ?8 \
           AND socket_path IS ?9 AND session_a_sha256 = ?10 AND task_a_sha256 = ?11 \
           AND project_sha256 = ?12 AND workspace_sha256 = ?13 \
           AND publication_launch_json = ?14 AND publication_now_ms = ?15 \
           AND disposition = ?16 AND applied_generation IS ?17 AND applied_state IS ?18 \
           AND created_at_ms = ?19 AND lease_token = ?20 AND lease_until_ms = ?21)",
        rusqlite::params![
            receipt.session_id,
            receipt.agent_task_id,
            receipt.operation_token.as_str(),
            receipt.project_id,
            receipt.workspace_id,
            if receipt.daemon_instance_id.is_some() {
                "bound"
            } else {
                "unbound"
            },
            receipt
                .daemon_instance_id
                .as_ref()
                .map(DaemonInstanceId::as_str),
            receipt.server_pid.map(i64::from),
            receipt.socket_path.as_deref(),
            receipt.session_a_sha256.as_slice(),
            receipt.task_a_sha256.as_slice(),
            receipt.project_sha256.as_slice(),
            receipt.workspace_sha256.as_slice(),
            receipt.publication_launch_json,
            i64::try_from(receipt.publication_now_ms)
                .map_err(|_| StoreError::Map("publication timestamp exceeds SQLite i64".into()))?,
            disposition,
            receipt.applied_generation.as_deref(),
            receipt.applied_state.as_deref(),
            i64::try_from(receipt.created_at_ms)
                .map_err(|_| StoreError::Map("journal timestamp exceeds SQLite i64".into()))?,
            receipt.lease_token,
            i64::try_from(receipt.lease_until_ms)
                .map_err(|_| StoreError::Map("journal lease exceeds SQLite i64".into()))?,
        ],
        |row| row.get(0),
    )
    .map_err(|error| StoreError::Db(error.to_string()))
}

/// Current durable meaning of a previously committed deletion receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowDeletionReceiptState {
    CurrentAndAbsent,
    Superseded,
}

/// Result of compensating a previously committed conditional delete. Compensation is deliberately
/// create-only: a concurrent recreation is authoritative and is never overwritten or re-owned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionalWindowRestore {
    Restored,
    AlreadyPresent,
    Changed,
}

/// Result of conditionally removing the durable Session row created for a pane whose tab
/// publication was rolled back. Refusal outcomes retain the row: a caller must never turn them
/// into an unconditional delete, because another window/task/worktree may have acquired the
/// session after it became observable.
#[derive(Debug)]
pub enum ConditionalCreatedSessionDelete {
    Deleted {
        release_receipt: Option<PendingReleaseReceipt>,
        unresolved_release_session_ids: Vec<String>,
    },
    Missing,
    Changed,
    Referenced,
}

/// One atomic rollback of a freshly-published tab and the exact Session row created for it. The
/// layout rewrite, Session delete, and generation-bound journal insert share one `BEGIN IMMEDIATE`
/// transaction, closing the crash gap between the former two-step helpers.
#[derive(Debug)]
pub struct CreatedTabSessionRollback {
    pub layout: WindowLayout,
    pub release_receipt: Option<PendingReleaseReceipt>,
    pub unresolved_release_session_ids: Vec<String>,
}

/// Result of conditionally rolling back a created tab plus Session A. Refusal outcomes perform no
/// write and grant no daemon authority.
#[derive(Debug)]
pub enum ConditionalCreatedTabSessionRollback {
    RolledBack(CreatedTabSessionRollback),
    Missing,
    Changed,
    Referenced,
}

/// One committed owner-FK + project-order assignment. Both ownership signals were read and, when
/// needed, updated under the same SQLite writer transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowProjectAssignment {
    pub window: WindowLayoutSnapshot,
    pub project: Project,
    pub owner_changed: bool,
    pub order_changed: bool,
}

/// Typed result of a conditional window ownership operation. Refusal variants never write either
/// ownership signal and never advance the global window-mutation epoch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConditionalWindowProjectAssignment {
    Applied(WindowProjectAssignment),
    WindowMissing,
    ProjectMissing,
    /// An exact window/project snapshot was superseded before the writer transaction began.
    Changed,
    /// NULL-or-same claiming found a foreign FK/order owner, or an exact retarget found a third
    /// project order it had no authority to rewrite.
    Conflict {
        current_project_id: Option<String>,
        ordered_by_project_ids: Vec<String>,
    },
}

/// Read-only proof that one window's FK and the strictly parsed project-order graph agree on the
/// same project in one SQLite snapshot. The embedded window revision can be fed into an exact
/// snapshot-aware mutation; the proof itself is never authority for an unconditional later write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowProjectAssignmentProof {
    pub window: WindowLayoutSnapshot,
    pub project: Project,
}

/// Typed result of loading a fresh `(window_id, expected_project_id)` ownership proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WindowProjectAssignmentProofOutcome {
    Proven(WindowProjectAssignmentProof),
    WindowMissing,
    ProjectMissing,
    Conflict {
        current_project_id: Option<String>,
        ordered_by_project_ids: Vec<String>,
    },
}

/// Resolve the tab a dock should attach to so the new pane appends at the END of a split chain.
///
/// Starting from `target`, follow the chain of tabs whose `split_from.tab_id` points at the current
/// tab (the next descendant) until a tab with no further child is reached — that tail is the parent
/// the docked source should split from, letting the canonical engine grow the layout one pane wider.
/// `exclude` (the source being docked) is skipped when choosing the next descendant so a tab never
/// docks onto itself. Bounded by the tab count to defend against a corrupt cyclic chain.
fn resolve_chain_tail(layout: &WindowLayout, target: &str, exclude: &str) -> String {
    let mut tail = target.to_string();
    for _ in 0..=layout.tabs.len() {
        let next_child = layout.tabs.iter().find(|t| {
            t.tab_id != exclude && t.split_from.as_ref().is_some_and(|s| s.tab_id == tail)
        });
        match next_child {
            Some(child) => tail = child.tab_id.clone(),
            None => break,
        }
    }
    tail
}

fn live_tab_ids_for_revive(layout: &WindowLayout, reviving_tab_id: &str) -> Vec<String> {
    let mut live: Vec<&TabRecord> = layout
        .tabs
        .iter()
        .filter(|t| !t.stashed && t.tab_id != reviving_tab_id)
        .collect();
    live.sort_by_key(|t| t.index);
    live.into_iter().map(|t| t.tab_id.clone()).collect()
}

fn split_from_parent(parent_id: &str, axis: SplitAxis) -> Option<SplitFrom> {
    Some(SplitFrom {
        tab_id: parent_id.to_string(),
        axis,
        ratio_per_mille: None,
    })
}

fn edge_from_split_axis(axis: SplitAxis) -> EdgeDir {
    match axis {
        SplitAxis::Right => EdgeDir::Right,
        SplitAxis::Down => EdgeDir::Bottom,
    }
}

fn live_tabs_sorted(layout: &WindowLayout) -> Vec<&TabRecord> {
    let mut live: Vec<&TabRecord> = layout.tabs.iter().filter(|t| !t.stashed).collect();
    live.sort_by_key(|t| t.index);
    live
}

/// Every canonical layout, for matching a rect set against each layout's `slot_rects`.
const ALL_CANONICAL_LAYOUTS: [CanonicalLayout; 18] = [
    CanonicalLayout::OneFull,
    CanonicalLayout::TwoColumns,
    CanonicalLayout::TwoRows,
    CanonicalLayout::ThreeColumns,
    CanonicalLayout::ThreeRows,
    CanonicalLayout::ThreeLeftMain,
    CanonicalLayout::ThreeRightMain,
    CanonicalLayout::ThreeTopMain,
    CanonicalLayout::ThreeBottomMain,
    CanonicalLayout::FourGrid,
    CanonicalLayout::FourColumns,
    CanonicalLayout::FourRows,
    CanonicalLayout::FourLeftSplit,
    CanonicalLayout::FourTopSplit,
    CanonicalLayout::FourLeftMain,
    CanonicalLayout::FourRightMain,
    CanonicalLayout::FourTopMain,
    CanonicalLayout::FourBottomMain,
];

/// Classify the live panes' AUTHORITATIVE rects into a canonical [`PaneLayoutModel`]. This reads the
/// real geometry (pane_rect), so it stays correct even after a stash/drag-drop where the legacy
/// split_from chain diverges from what's painted — the cause of swallow silently failing ("no legal
/// swallow") after such an op. Matches a rect set to the canonical layout whose `slot_rects` it equals
/// (within rounding), binding panes in reading order. `None` when no rect, or the shape isn't one of the
/// canonical layouts.
fn canonical_model_from_rects(live: &[&TabRecord]) -> Option<PaneLayoutModel> {
    let n = live.len();
    if !(1..=4).contains(&n) || live.iter().any(|t| t.pane_rect.is_none()) {
        return None;
    }
    // (id, rect) in reading order (y then x).
    let mut panes: Vec<(&str, UnitRect)> = live
        .iter()
        .map(|t| (t.tab_id.as_str(), t.pane_rect.unwrap().to_unit()))
        .collect();
    panes.sort_by(|a, b| {
        a.1[1]
            .partial_cmp(&b.1[1])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                a.1[0]
                    .partial_cmp(&b.1[0])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
    let agents_ro: Vec<String> = panes.iter().map(|(id, _)| id.to_string()).collect();
    let r = |i: usize| panes[i].1;

    // Match the canonical layout whose `slot_rects` have the SAME TOPOLOGY as these rects, ignoring exact
    // proportions (a local split makes unequal panes that still read as e.g. left-main). Two rects share a
    // topology when each canonical slot rect and the corresponding pane rect agree on which edges are
    // flush to 0/1 (full-height / full-width / which corner) — i.e. the sign pattern matches.
    let sig = |rect: UnitRect| -> (bool, bool, bool, bool) {
        (
            nearly_eq(rect[0], 0.0),           // touches left
            nearly_eq(rect[1], 0.0),           // touches top
            nearly_eq(rect_right(rect), 1.0),  // touches right
            nearly_eq(rect_bottom(rect), 1.0), // touches bottom
        )
    };
    for layout in ALL_CANONICAL_LAYOUTS {
        if layout.pane_count() != n {
            continue;
        }
        let slots = slot_rects(layout, &std::collections::BTreeMap::new());
        if slots.len() != n {
            continue;
        }
        // slot_rects come in reading order, as do `panes`. Compare edge-flush signatures slot-by-slot.
        let same_topology = (0..n).all(|i| sig(slots[i]) == sig(r(i)));
        if same_topology {
            return PaneLayoutModel::from_agents(&agents_ro, Some(layout)).ok();
        }
    }
    None
}

fn canonical_model_from_live_tabs(live: &[&TabRecord]) -> Option<PaneLayoutModel> {
    if live.is_empty() || live.len() > 4 {
        return None;
    }
    // PREFER the authoritative rect geometry — it stays correct when the split_from chain diverges.
    if let Some(model) = canonical_model_from_rects(live) {
        return Some(model);
    }
    if live.len() == 4 {
        let ids: Vec<String> = live.iter().map(|tab| tab.tab_id.clone()).collect();
        let [a, b, c, d] = ids.as_slice() else {
            return None;
        };
        let layout = if split_axis_between_records(live, b, a) == Some(SplitAxis::Right)
            && split_axis_between_records(live, c, b) == Some(SplitAxis::Right)
            && split_axis_between_records(live, d, a) == Some(SplitAxis::Down)
        {
            Some(CanonicalLayout::FourBottomMain)
        } else if split_axis_between_records(live, b, a) == Some(SplitAxis::Down)
            && split_axis_between_records(live, c, b) == Some(SplitAxis::Right)
            && split_axis_between_records(live, d, c) == Some(SplitAxis::Right)
        {
            Some(CanonicalLayout::FourTopMain)
        } else if split_axis_between_records(live, b, a) == Some(SplitAxis::Right)
            && split_axis_between_records(live, c, b) == Some(SplitAxis::Down)
            && split_axis_between_records(live, d, c) == Some(SplitAxis::Down)
        {
            Some(CanonicalLayout::FourLeftMain)
        } else if split_axis_between_records(live, b, a) == Some(SplitAxis::Right)
            && split_axis_between_records(live, c, a) == Some(SplitAxis::Down)
            && split_axis_between_records(live, d, c) == Some(SplitAxis::Down)
        {
            Some(CanonicalLayout::FourRightMain)
        } else {
            None
        };
        if let Some(layout) = layout {
            return PaneLayoutModel::from_agents(&ids, Some(layout)).ok();
        }
    }
    let root = live.iter().find(|t| t.split_from.is_none())?;
    if live.iter().filter(|t| t.split_from.is_none()).count() != 1 {
        return None;
    }

    let mut model = PaneLayoutModel::from_agents(std::slice::from_ref(&root.tab_id), None).ok()?;
    for tab in live.iter().filter(|t| t.tab_id != root.tab_id) {
        let split = tab.split_from.as_ref()?;
        let parent_slot = model.slot_of(&split.tab_id)?;
        model = model
            .split_ordered_from_slot(parent_slot, edge_from_split_axis(split.axis), &tab.tab_id)
            .ok()??;
    }
    Some(model)
}

#[derive(Clone, Debug)]
struct AgentRect {
    agent: String,
    rect: UnitRect,
}

const RECT_EPS: f32 = 0.001;

fn rect_right(rect: UnitRect) -> f32 {
    rect[0] + rect[2]
}

/// GLOBAL TILING INVARIANT. The live panes' rects must perfectly TILE the unit square: every rect lies
/// inside [0,1]², no two overlap (more than epsilon), and their areas sum to 1 (no gap, no pane hidden
/// behind another). This is the single guard every geometry write goes through — so NO operation, even
/// an unexplored 4-pane layout, can ever leave panes overlapping or overflowing. Returns `true` when the
/// set is a valid tiling.
fn rects_tile_unit_square(panes: &[AgentRect]) -> bool {
    if panes.is_empty() {
        return false;
    }
    // In-bounds.
    for p in panes {
        let [x, y, w, h] = p.rect;
        if w <= RECT_EPS || h <= RECT_EPS {
            return false;
        }
        if x < -RECT_EPS
            || y < -RECT_EPS
            || rect_right(p.rect) > 1.0 + RECT_EPS
            || rect_bottom(p.rect) > 1.0 + RECT_EPS
        {
            return false;
        }
    }
    // Pairwise non-overlap (positive-area intersection is a violation).
    for (i, p) in panes.iter().enumerate() {
        for q in &panes[i + 1..] {
            let ox =
                p.rect[0].max(q.rect[0]) + RECT_EPS < rect_right(p.rect).min(rect_right(q.rect));
            let oy =
                p.rect[1].max(q.rect[1]) + RECT_EPS < rect_bottom(p.rect).min(rect_bottom(q.rect));
            if ox && oy {
                return false;
            }
        }
    }
    // Areas sum to the whole square (no gap). Combined with non-overlap + in-bounds this proves a tiling.
    let area: f32 = panes.iter().map(|p| p.rect[2] * p.rect[3]).sum();
    (area - 1.0).abs() <= 1e-3
}

fn rect_bottom(rect: UnitRect) -> f32 {
    rect[1] + rect[3]
}

fn nearly_eq(a: f32, b: f32) -> bool {
    (a - b).abs() <= RECT_EPS
}

fn same_height(a: UnitRect, b: UnitRect) -> bool {
    nearly_eq(a[1], b[1]) && nearly_eq(a[3], b[3])
}

/// LOCAL edge-absorb SWALLOW (rect-only). The focused pane `focus` EXTENDS across its `dir` edge,
/// absorbing only the overlapping slice of whatever sits directly across that edge; every neighbor keeps
/// the part that does NOT overlap the focused pane's perpendicular span. Pure geometry, no canonical
/// reshape — so e.g. A/(B│C│D) with B swallowing UP makes B span both rows on the left while A keeps the
/// portion over C and D.
///
/// Mechanics for an Up swallow (others are the four rotations): let `seam = focus.top`. Among the OTHER
/// panes, those whose bottom edge is the seam AND whose x-span overlaps the focus x-span are "across the
/// edge". The focus top moves up to the highest such neighbor's top (the band it can cleanly reclaim
/// without leaving a hole — here a single full row above, so up to 0). Each across neighbor is clipped to
/// the part OUTSIDE the focus x-span; a neighbor fully inside the focus span is wholly absorbed (returned
/// as `None` → caller stashes it). Non-across panes are untouched.
///
/// Returns the new rects (every pane kept alive — focus grown, the across neighbor clipped). Returns
/// `None` when no pane lies across the edge (nothing to swallow), when the absorb would ELIMINATE a
/// neighbor (that is a close, not a resize), or when it would split a neighbor in two.
fn swallow_rect_local(panes: &[AgentRect], focus: &str, dir: SwallowDir) -> Option<Vec<AgentRect>> {
    let f = panes.iter().find(|p| p.agent == focus)?.rect;
    let horizontal = matches!(dir, SwallowDir::Left | SwallowDir::Right);

    // Overlap of two 1-D intervals (strictly, with epsilon tolerance).
    let overlaps =
        |a0: f32, a1: f32, b0: f32, b1: f32| a0.min(a1) < b1 - RECT_EPS && b0 < a1 - RECT_EPS;

    // Identify the panes directly across the swallow edge whose PERPENDICULAR span overlaps the focus.
    let across: Vec<usize> = panes
        .iter()
        .enumerate()
        .filter(|(_, p)| p.agent != focus)
        .filter(|(_, p)| {
            let r = p.rect;
            match dir {
                // neighbor's bottom == focus.top, x-spans overlap.
                SwallowDir::Up => {
                    nearly_eq(rect_bottom(r), f[1])
                        && overlaps(r[0], rect_right(r), f[0], rect_right(f))
                }
                SwallowDir::Down => {
                    nearly_eq(r[1], rect_bottom(f))
                        && overlaps(r[0], rect_right(r), f[0], rect_right(f))
                }
                SwallowDir::Left => {
                    nearly_eq(rect_right(r), f[0])
                        && overlaps(r[1], rect_bottom(r), f[1], rect_bottom(f))
                }
                SwallowDir::Right => {
                    nearly_eq(r[0], rect_right(f))
                        && overlaps(r[1], rect_bottom(r), f[1], rect_bottom(f))
                }
            }
        })
        .map(|(i, _)| i)
        .collect();
    if across.is_empty() {
        return None;
    }

    // How far the focus extends: to the far edge of the across panes (e.g. up to their topmost top).
    let new_f = {
        let mut r = f;
        match dir {
            SwallowDir::Up => {
                let top = across
                    .iter()
                    .map(|&i| panes[i].rect[1])
                    .fold(f[1], f32::min);
                r[3] = rect_bottom(f) - top;
                r[1] = top;
            }
            SwallowDir::Down => {
                let bot = across
                    .iter()
                    .map(|&i| rect_bottom(panes[i].rect))
                    .fold(rect_bottom(f), f32::max);
                r[3] = bot - f[1];
            }
            SwallowDir::Left => {
                let left = across
                    .iter()
                    .map(|&i| panes[i].rect[0])
                    .fold(f[0], f32::min);
                r[2] = rect_right(f) - left;
                r[0] = left;
            }
            SwallowDir::Right => {
                let right = across
                    .iter()
                    .map(|&i| rect_right(panes[i].rect))
                    .fold(rect_right(f), f32::max);
                r[2] = right - f[0];
            }
        }
        r
    };

    let mut out: Vec<AgentRect> = Vec::new();
    for (i, p) in panes.iter().enumerate() {
        if p.agent == focus {
            out.push(AgentRect {
                agent: focus.to_string(),
                rect: new_f,
            });
            continue;
        }
        if !across.contains(&i) {
            out.push(p.clone());
            continue;
        }
        // Clip this across-pane to the part OUTSIDE the focus's perpendicular span.
        let r = p.rect;
        let clipped: Vec<UnitRect> = if horizontal {
            // focus grows L/R: keep the parts of `r` above/below the focus y-span.
            let mut parts = Vec::new();
            if r[1] < f[1] - RECT_EPS {
                parts.push([r[0], r[1], r[2], f[1] - r[1]]);
            }
            if rect_bottom(r) > rect_bottom(f) + RECT_EPS {
                parts.push([r[0], rect_bottom(f), r[2], rect_bottom(r) - rect_bottom(f)]);
            }
            parts
        } else {
            // focus grows U/D: keep the parts of `r` left/right of the focus x-span.
            let mut parts = Vec::new();
            if r[0] < f[0] - RECT_EPS {
                parts.push([r[0], r[1], f[0] - r[0], r[3]]);
            }
            if rect_right(r) > rect_right(f) + RECT_EPS {
                parts.push([rect_right(f), r[1], rect_right(r) - rect_right(f), r[3]]);
            }
            parts
        };
        match clipped.len() {
            // Wholly inside the focus span → the neighbor would be ELIMINATED. Swallow is a resize that
            // keeps every pane alive, so this is NOT a clean swallow: bail and leave the layout unchanged.
            // (Eliminating a pane is "close", a different action.)
            0 => return None,
            1 => out.push(AgentRect {
                agent: p.agent.clone(),
                rect: clipped[0],
            }),
            // A neighbor straddling BOTH sides would split into two — not representable as one pane; treat
            // as not-clean and bail so the caller leaves the layout unchanged.
            _ => return None,
        }
    }
    Some(out)
}

/// Split `rect` in half along `edge` for a local INSERT (drag/drop). Returns `(kept, inserted)` where
/// `inserted` is the half on the dropped edge (taken by the dragged pane) and `kept` is the other half
/// (retained by the target pane). L/R split the width; Top/Bottom split the height. Only this one rect
/// changes — the confirmed drag/drop rule: a drop subdivides the target locally, nothing else moves.
fn split_rect_local(rect: UnitRect, edge: EdgeDir) -> (UnitRect, UnitRect) {
    let [x, y, w, h] = rect;
    match edge {
        EdgeDir::Left => ([x + w / 2.0, y, w / 2.0, h], [x, y, w / 2.0, h]),
        EdgeDir::Right => ([x, y, w / 2.0, h], [x + w / 2.0, y, w / 2.0, h]),
        EdgeDir::Top => ([x, y + h / 2.0, w, h / 2.0], [x, y, w, h / 2.0]),
        EdgeDir::Bottom => ([x, y, w, h / 2.0], [x, y + h / 2.0, w, h / 2.0]),
    }
}

fn split_axis_between_records(
    tabs: &[&TabRecord],
    child_id: &str,
    parent_id: &str,
) -> Option<SplitAxis> {
    tabs.iter()
        .find(|tab| tab.tab_id == child_id)
        .and_then(|tab| tab.split_from.as_ref())
        .filter(|split| split.tab_id == parent_id)
        .map(|split| split.axis)
}

/// The confirmed stash rule, applied to rects. Removing `removed`, the freed cell is reclaimed by:
///   1. a SAME-HEIGHT, column-adjacent neighbor (extends horizontally; row heights untouched), else
///   2. a SAME-COLUMN, row-adjacent neighbor (extends vertically), else
///   3. RE-PACK: the removed pane was a full-span edge band whose neighbors are column/row groups of
///      differing internal structure — the surviving column-GROUPS (or row-groups) re-pack into a fresh
///      equal-width (or equal-height) track one unit smaller, each group keeping its internal split.
///
/// Returns the survivor rects tiling the unit square. See `stash-revive contract`.
/// (75 cases verified to tile with no gap/overlap).
/// The user's general STASH-FILL rule. The freed `removed` rect is reclaimed by the neighbours on ONE
/// of its four sides whose edges EXACTLY TILE that side — they extend into the gap. It can be one OR
/// several neighbours (e.g. a stacked B/C pair both extending left to fill A's column). Try the WIDTH
/// sides first (left, then right — extend horizontally), then the HEIGHT sides (top, then bottom). A side
/// "fits" when the neighbours across that edge together span the freed rect's full perpendicular extent
/// with no gap/overlap (their edge lengths sum to it and they tile it). Returns the updated rects, or
/// `None` if no single side cleanly fits (caller falls back to re-pack).
fn fill_freed_by_neighbors(panes: &[AgentRect], removed: UnitRect) -> Option<Vec<AgentRect>> {
    // Across each side: the neighbours whose touching edge lies on that side AND whose perpendicular span
    // overlaps the freed rect. `extend` rewrites a matching pane to grow into the gap.
    // side = (selector of touching panes, does this set tile the freed perpendicular extent?, extend fn)
    let touches = |p: &AgentRect, side: usize| -> bool {
        let r = p.rect;
        match side {
            0 => nearly_eq(rect_right(r), removed[0]), // left side: pane's right == freed left
            1 => nearly_eq(r[0], rect_right(removed)), // right side
            2 => nearly_eq(rect_bottom(r), removed[1]), // top side
            _ => nearly_eq(r[1], rect_bottom(removed)), // bottom side
        }
    };
    // Try sides in order: left, right (width), top, bottom (height).
    for side in [0usize, 1, 2, 3] {
        let horizontal = side < 2; // left/right grow horizontally; the matching panes share the freed HEIGHT.
        let group: Vec<usize> = panes
            .iter()
            .enumerate()
            .filter(|(_, p)| touches(p, side))
            .filter(|(_, p)| {
                // perpendicular overlap with the freed rect.
                if horizontal {
                    p.rect[1].max(removed[1])
                        < rect_bottom(p.rect).min(rect_bottom(removed)) - RECT_EPS
                } else {
                    p.rect[0].max(removed[0])
                        < rect_right(p.rect).min(rect_right(removed)) - RECT_EPS
                }
            })
            .map(|(i, _)| i)
            .collect();
        if group.is_empty() {
            continue;
        }
        // Do the group's perpendicular spans EXACTLY tile the freed rect's perpendicular extent (cover it
        // fully, no overlap)? If so, each grows across the freed rect.
        let (lo, hi) = if horizontal {
            (removed[1], rect_bottom(removed))
        } else {
            (removed[0], rect_right(removed))
        };
        let mut spans: Vec<(f32, f32)> = group
            .iter()
            .map(|&i| {
                if horizontal {
                    (panes[i].rect[1], rect_bottom(panes[i].rect))
                } else {
                    (panes[i].rect[0], rect_right(panes[i].rect))
                }
            })
            .collect();
        spans.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        // Contiguous coverage of [lo, hi] with no gaps and matching endpoints.
        let mut covered = true;
        if !nearly_eq(spans[0].0, lo) || !nearly_eq(spans[spans.len() - 1].1, hi) {
            covered = false;
        }
        for w in spans.windows(2) {
            if !nearly_eq(w[0].1, w[1].0) {
                covered = false;
            }
        }
        if !covered {
            continue;
        }
        // Fits. Extend each group pane across the freed rect along the grow axis.
        let mut out = panes.to_vec();
        for &i in &group {
            let mut r = out[i].rect;
            if horizontal {
                // extend in x to cover the freed rect's x-extent (merge edge → other side of freed).
                let new_left = r[0].min(removed[0]);
                let new_right = rect_right(r).max(rect_right(removed));
                r[0] = new_left;
                r[2] = new_right - new_left;
            } else {
                let new_top = r[1].min(removed[1]);
                let new_bottom = rect_bottom(r).max(rect_bottom(removed));
                r[1] = new_top;
                r[3] = new_bottom - new_top;
            }
            out[i].rect = r;
        }
        return Some(out);
    }
    None
}

fn reduce_rects_by_spec(mut panes: Vec<AgentRect>, removed: UnitRect) -> Vec<AgentRect> {
    if panes.len() <= 1 {
        // Last survivor (or none): it fills the whole screen.
        for p in &mut panes {
            p.rect = [0.0, 0.0, 1.0, 1.0];
        }
        return panes;
    }

    // PRIMARY: the general edge-fitting fill (one or more neighbours on a side that exactly tiles it).
    if let Some(filled) = fill_freed_by_neighbors(&panes, removed) {
        return filled;
    }

    // 3. Re-pack. Decide whether a full-height column or a full-width row was freed by comparing the
    // removed band against the survivors' bounding span.
    let surv_left = panes
        .iter()
        .map(|p| p.rect[0])
        .fold(f32::INFINITY, f32::min);
    let surv_right = panes
        .iter()
        .map(|p| rect_right(p.rect))
        .fold(f32::NEG_INFINITY, f32::max);
    let freed_column =
        removed[0] < surv_left - RECT_EPS || rect_right(removed) > surv_right + RECT_EPS;

    if freed_column {
        // Distinct surviving column groups, left→right; assign each an equal-width slot of a smaller track.
        let mut spans: Vec<(f32, f32)> = Vec::new();
        for p in &panes {
            let key = (p.rect[0], rect_right(p.rect));
            if !spans
                .iter()
                .any(|s| nearly_eq(s.0, key.0) && nearly_eq(s.1, key.1))
            {
                spans.push(key);
            }
        }
        spans.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let w = 1.0 / spans.len() as f32;
        for p in &mut panes {
            let i = spans
                .iter()
                .position(|s| nearly_eq(s.0, p.rect[0]) && nearly_eq(s.1, rect_right(p.rect)))
                .unwrap_or(0);
            p.rect = [i as f32 * w, p.rect[1], w, p.rect[3]]; // y kept (heights free)
        }
    } else {
        // Full-width row freed: surviving row groups re-pack into equal-height bands; columns kept.
        let mut spans: Vec<(f32, f32)> = Vec::new();
        for p in &panes {
            let key = (p.rect[1], rect_bottom(p.rect));
            if !spans
                .iter()
                .any(|s| nearly_eq(s.0, key.0) && nearly_eq(s.1, key.1))
            {
                spans.push(key);
            }
        }
        spans.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let h = 1.0 / spans.len() as f32;
        for p in &mut panes {
            let i = spans
                .iter()
                .position(|s| nearly_eq(s.0, p.rect[1]) && nearly_eq(s.1, rect_bottom(p.rect)))
                .unwrap_or(0);
            p.rect = [p.rect[0], i as f32 * h, p.rect[2], h];
        }
    }
    panes
}

/// General guillotine recovery: turn a set of rects that tile the unit square into `split_from`
/// topology. Recursively finds a full-span vertical (or horizontal) cut separating the panes into two
/// non-empty groups, emits the right/bottom group as split from the left/top group's first pane, and
/// recurses. Handles any pane count and any of the spec's output shapes — replacing the old per-count
/// match arms. Returns survivors in topology order (root first, `None` split_from).
fn topology_from_rects(panes: &[AgentRect]) -> Vec<(String, Option<SplitFrom>)> {
    fn collect(
        panes: &[AgentRect],
        bounds: UnitRect,
        parent: Option<(&str, SplitAxis)>,
        out: &mut Vec<(String, Option<SplitFrom>)>,
    ) {
        if panes.is_empty() {
            return;
        }
        if panes.len() == 1 {
            let split = parent.and_then(|(pid, axis)| split_from_parent(pid, axis));
            out.push((panes[0].agent.clone(), split));
            return;
        }
        // Try a full-span vertical cut: an x where every pane is entirely left or entirely right of it.
        if let Some((left, right, _cut)) = guillotine(panes, bounds, true) {
            collect(&left, bounds, parent, out);
            // root of the left group is the parent for the right group, split Right.
            let left_root = left_root_agent(&left, bounds, true);
            collect(&right, bounds, Some((&left_root, SplitAxis::Right)), out);
            return;
        }
        // Else a full-span horizontal cut.
        if let Some((top, bottom, _cut)) = guillotine(panes, bounds, false) {
            collect(&top, bounds, parent, out);
            let top_root = left_root_agent(&top, bounds, false);
            collect(&bottom, bounds, Some((&top_root, SplitAxis::Down)), out);
            return;
        }
        // No clean guillotine cut (shouldn't happen for spec-tiled rects): fall back to flat order.
        for (i, p) in panes.iter().enumerate() {
            let split = if i == 0 {
                parent.and_then(|(pid, axis)| split_from_parent(pid, axis))
            } else {
                split_from_parent(&panes[0].agent, SplitAxis::Right)
            };
            out.push((p.agent.clone(), split));
        }
    }

    // Split `panes` at the first full-span cut along the chosen axis (vertical=true → x-cut).
    fn guillotine(
        panes: &[AgentRect],
        _bounds: UnitRect,
        vertical: bool,
    ) -> Option<(Vec<AgentRect>, Vec<AgentRect>, f32)> {
        // candidate cut positions = the trailing edge of each pane along the axis.
        let mut cuts: Vec<f32> = panes
            .iter()
            .map(|p| {
                if vertical {
                    rect_right(p.rect)
                } else {
                    rect_bottom(p.rect)
                }
            })
            .collect();
        cuts.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        for cut in cuts {
            let near_max = panes
                .iter()
                .map(|p| {
                    if vertical {
                        rect_right(p.rect)
                    } else {
                        rect_bottom(p.rect)
                    }
                })
                .fold(f32::NEG_INFINITY, f32::max);
            if nearly_eq(cut, near_max) {
                continue; // the outer edge is not an interior cut
            }
            let mut before = Vec::new();
            let mut after = Vec::new();
            let mut clean = true;
            for p in panes {
                let lo = if vertical { p.rect[0] } else { p.rect[1] };
                let hi = if vertical {
                    rect_right(p.rect)
                } else {
                    rect_bottom(p.rect)
                };
                if hi <= cut + RECT_EPS {
                    before.push(p.clone());
                } else if lo >= cut - RECT_EPS {
                    after.push(p.clone());
                } else {
                    clean = false; // a pane straddles this cut → not full-span here
                    break;
                }
            }
            if clean && !before.is_empty() && !after.is_empty() {
                return Some((before, after, cut));
            }
        }
        None
    }

    // The reading-order root agent of a group (top-left-most pane).
    fn left_root_agent(group: &[AgentRect], _bounds: UnitRect, _vertical: bool) -> String {
        group
            .iter()
            .min_by(|a, b| {
                a.rect[1]
                    .partial_cmp(&b.rect[1])
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| {
                        a.rect[0]
                            .partial_cmp(&b.rect[0])
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
            })
            .map(|p| p.agent.clone())
            .unwrap_or_default()
    }

    let mut out = Vec::new();
    collect(panes, [0.0, 0.0, 1.0, 1.0], None, &mut out);
    out
}

/// Survivor geometry after removing one pane (stash/close), as a RECT set per the confirmed stash rule.
/// `Some(rects)` on success; `None` when the live layout can't be reconstructed (corrupt records) so the
/// caller falls back to a flat survivor chain.
fn reduce_pane_rects(layout: &WindowLayout, removing_tab_id: &str) -> Option<Vec<AgentRect>> {
    let mut panes = live_pane_rects(layout)?;
    let removed_pos = panes.iter().position(|p| p.agent == removing_tab_id)?;
    let removed = panes.remove(removed_pos).rect;
    Some(reduce_rects_by_spec(panes, removed))
}

/// The live panes' AUTHORITATIVE rects, read from each pane's persisted `pane_rect`. Falls back to
/// reconstructing from the legacy `split_from` chain (via the canonical model) for OLD records that
/// predate `pane_rect`. `None` when neither is available (no live panes / unreconstructable).
fn live_pane_rects(layout: &WindowLayout) -> Option<Vec<AgentRect>> {
    let live = live_tabs_sorted(layout);
    if live.is_empty() {
        return None;
    }
    // Preferred: every live pane has a persisted rect — use it verbatim (exact, unambiguous).
    if live.iter().all(|t| t.pane_rect.is_some()) {
        return Some(
            live.iter()
                .map(|t| AgentRect {
                    agent: t.tab_id.clone(),
                    rect: t.pane_rect.unwrap().to_unit(),
                })
                .collect(),
        );
    }
    // Legacy fallback: reconstruct from the split_from chain via the canonical model.
    let model = canonical_model_from_live_tabs(&live)?;
    let rects = slot_rects(model.layout, &model.ratios);
    Some(
        model
            .layout
            .slots()
            .iter()
            .zip(rects)
            .filter_map(|(slot, rect)| {
                model.agent_at(*slot).map(|agent| AgentRect {
                    agent: agent.clone(),
                    rect,
                })
            })
            .collect(),
    )
}

/// Apply a pane-remove (stash/close) to `layout`: write the survivor RECT geometry from
/// [`reduce_pane_rects`], or fall back to a flat survivor chain when geometry can't be reconstructed.
fn apply_reduce(layout: &mut WindowLayout, removing_tab_id: &str) {
    match reduce_pane_rects(layout, removing_tab_id) {
        Some(rects) => apply_pane_geometry(layout, &rects),
        None => {
            // Fallback: flat survivor list (each its own root). Clears rects so the renderer falls back.
            let survivors: Vec<(String, Option<SplitFrom>)> = live_tabs_sorted(layout)
                .iter()
                .filter(|t| t.tab_id != removing_tab_id)
                .map(|t| (t.tab_id.clone(), None))
                .collect();
            for (id, _) in &survivors {
                if let Some(tab) = layout.tabs.iter_mut().find(|t| &t.tab_id == id) {
                    tab.pane_rect = None;
                }
            }
            apply_revive_topology(layout, survivors);
        }
    }
}

/// Click-revive placement, applied to rects. Given the EXISTING live panes' rects (the survivors) and a
/// reviving id, produce the new rect set per the confirmed click-revive rule (see
/// `stash-revive contract`):
///   1:        A            -> A│X                 (new equal-width column on the right)
///   2 cols:   A│B          -> (A/X)│B             (left column splits; X below A)
///   2 rows:   A/B          -> (A│X)/B             (top row splits; X right of A)
///   3 cols:   A│B│C        -> (A/X)│B│C
///   3 rows:   A/B/C        -> (A│X)/B/C
///   left-main A│(B/C)      -> (A│B)/(X│C)         2×2 grid, X bottom-left
///   right-main (A/C)│B     -> (A│B)/(C│X)         2×2 grid, X bottom-right
///   top-main  A/(B│C)      -> (A│X)/(B│C)         2×2 grid, X top-right
///   bottom-main (A│B)/C    -> (A│B)/(C│X)         2×2 grid, X bottom-right
/// The existing panes keep their relative pairing; only the revived pane is new. Returns the survivor +
/// revived rects (tiling the unit square) for `topology_from_rects` to turn into `split_from`.
fn revive_rects_by_spec(existing: &[AgentRect], reviving: &str) -> Vec<AgentRect> {
    let n = existing.len();
    let r = |agent: &str, rect: UnitRect| AgentRect {
        agent: agent.to_string(),
        rect,
    };
    // Reading order (y then x) of the survivors gives A,B,C positions.
    let mut ro: Vec<&AgentRect> = existing.iter().collect();
    ro.sort_by(|a, b| {
        a.rect[1]
            .partial_cmp(&b.rect[1])
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                a.rect[0]
                    .partial_cmp(&b.rect[0])
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
    let id = |i: usize| ro[i].agent.as_str();

    match n {
        0 => vec![r(reviving, [0.0, 0.0, 1.0, 1.0])],
        1 => vec![
            // A│X
            r(id(0), [0.0, 0.0, 0.5, 1.0]),
            r(reviving, [0.5, 0.0, 0.5, 1.0]),
        ],
        2 => {
            // same row (two columns) vs stacked (two rows)
            let same_row = same_height(ro[0].rect, ro[1].rect);
            if same_row {
                // A│B -> (A/X)│B
                vec![
                    r(id(0), [0.0, 0.0, 0.5, 0.5]),
                    r(reviving, [0.0, 0.5, 0.5, 0.5]),
                    r(id(1), [0.5, 0.0, 0.5, 1.0]),
                ]
            } else {
                // A/B -> (A│X)/B
                vec![
                    r(id(0), [0.0, 0.0, 0.5, 0.5]),
                    r(reviving, [0.5, 0.0, 0.5, 0.5]),
                    r(id(1), [0.0, 0.5, 1.0, 0.5]),
                ]
            }
        }
        3 => {
            let full_h =
                |p: &AgentRect| nearly_eq(p.rect[1], 0.0) && nearly_eq(rect_bottom(p.rect), 1.0);
            let full_w =
                |p: &AgentRect| nearly_eq(p.rect[0], 0.0) && nearly_eq(rect_right(p.rect), 1.0);
            let all_cols = existing.iter().all(full_h);
            let all_rows = existing.iter().all(full_w);
            if all_cols {
                // A│B│C -> (A/X)│B│C  (third = 3 equal columns, left one split)
                let t = 1.0 / 3.0;
                vec![
                    r(id(0), [0.0, 0.0, t, 0.5]),
                    r(reviving, [0.0, 0.5, t, 0.5]),
                    r(id(1), [t, 0.0, t, 1.0]),
                    r(id(2), [2.0 * t, 0.0, t, 1.0]),
                ]
            } else if all_rows {
                // A/B/C -> (A│X)/B/C
                let t = 1.0 / 3.0;
                vec![
                    r(id(0), [0.0, 0.0, 0.5, t]),
                    r(reviving, [0.5, 0.0, 0.5, t]),
                    r(id(1), [0.0, t, 1.0, t]),
                    r(id(2), [0.0, 2.0 * t, 1.0, t]),
                ]
            } else if let Some(main) = existing.iter().find(|p| full_h(p)) {
                // left-main (main on left) or right-main (main on right) -> 2×2 grid.
                let a = main.agent.as_str();
                let mut pair: Vec<&AgentRect> = existing.iter().filter(|p| p.agent != a).collect();
                pair.sort_by(|x, y| {
                    x.rect[1]
                        .partial_cmp(&y.rect[1])
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                let (p, q) = (pair[0].agent.as_str(), pair[1].agent.as_str());
                if main.rect[0] < 0.5 {
                    // left-main A│(B/C) -> (A│B)/(X│C): A tl, B tr, X bl, C br
                    vec![
                        r(a, [0.0, 0.0, 0.5, 0.5]),
                        r(p, [0.5, 0.0, 0.5, 0.5]),
                        r(reviving, [0.0, 0.5, 0.5, 0.5]),
                        r(q, [0.5, 0.5, 0.5, 0.5]),
                    ]
                } else {
                    // right-main (A/C)│B -> (A│B)/(C│X): A tl, B tr, C bl, X br
                    vec![
                        r(p, [0.0, 0.0, 0.5, 0.5]),
                        r(a, [0.5, 0.0, 0.5, 0.5]),
                        r(q, [0.0, 0.5, 0.5, 0.5]),
                        r(reviving, [0.5, 0.5, 0.5, 0.5]),
                    ]
                }
            } else {
                // full-width main -> top-main or bottom-main -> 2×2 grid.
                let main = existing.iter().find(|p| full_w(p)).unwrap();
                let a = main.agent.as_str();
                let mut pair: Vec<&AgentRect> = existing.iter().filter(|p| p.agent != a).collect();
                pair.sort_by(|x, y| {
                    x.rect[0]
                        .partial_cmp(&y.rect[0])
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                let (p, q) = (pair[0].agent.as_str(), pair[1].agent.as_str());
                if main.rect[1] < 0.5 {
                    // top-main A/(B│C) -> (A│X)/(B│C): A tl, X tr, B bl, C br
                    vec![
                        r(a, [0.0, 0.0, 0.5, 0.5]),
                        r(reviving, [0.5, 0.0, 0.5, 0.5]),
                        r(p, [0.0, 0.5, 0.5, 0.5]),
                        r(q, [0.5, 0.5, 0.5, 0.5]),
                    ]
                } else {
                    // bottom-main (A│B)/C -> (A│B)/(C│X): A tl, B tr, C bl, X br
                    vec![
                        r(p, [0.0, 0.0, 0.5, 0.5]),
                        r(q, [0.5, 0.0, 0.5, 0.5]),
                        r(a, [0.0, 0.5, 0.5, 0.5]),
                        r(reviving, [0.5, 0.5, 0.5, 0.5]),
                    ]
                }
            }
        }
        _ => existing
            .iter()
            .cloned()
            .chain(std::iter::once(r(reviving, [0.0, 0.0, 0.0, 0.0])))
            .collect(),
    }
}

/// Click-revive geometry: the existing live panes plus the revived pane, as a RECT set per the confirmed
/// click-revive spec. `Some(rects)` on success; `None` when the existing layout can't be reconstructed
/// (corrupt records) so the caller falls back to a flat chain.
fn revive_pane_rects(
    layout: &WindowLayout,
    existing_live_ids: &[String],
    reviving_tab_id: &str,
) -> Option<Vec<AgentRect>> {
    let existing_set: std::collections::HashSet<&str> =
        existing_live_ids.iter().map(|s| s.as_str()).collect();
    // The existing live panes' authoritative rects (excluding the pane being revived).
    let existing: Vec<AgentRect> = live_pane_rects(layout)?
        .into_iter()
        .filter(|p| existing_set.contains(p.agent.as_str()))
        .collect();
    if existing.len() != existing_live_ids.len() {
        return None;
    }
    Some(revive_rects_by_spec(&existing, reviving_tab_id))
}

/// Apply a revive (or repair) to `layout`: write the rect geometry from [`revive_pane_rects`], or fall
/// back to a flat chain (revived appended right of the first existing pane) when geometry can't be built.
fn apply_revive(layout: &mut WindowLayout, existing_live_ids: &[String], reviving_tab_id: &str) {
    match revive_pane_rects(layout, existing_live_ids, reviving_tab_id) {
        Some(rects) => apply_pane_geometry(layout, &rects),
        None => {
            let mut out = Vec::with_capacity(existing_live_ids.len() + 1);
            for (i, id) in existing_live_ids.iter().enumerate() {
                let split = if i == 0 {
                    None
                } else {
                    split_from_parent(&existing_live_ids[0], SplitAxis::Right)
                };
                out.push((id.clone(), split));
            }
            let parent = existing_live_ids.first().cloned();
            out.push((
                reviving_tab_id.to_string(),
                parent.and_then(|p| split_from_parent(&p, SplitAxis::Right)),
            ));
            for (id, _) in &out {
                if let Some(tab) = layout.tabs.iter_mut().find(|t| &t.tab_id == id) {
                    tab.pane_rect = None;
                }
            }
            apply_revive_topology(layout, out);
        }
    }
}

fn apply_revive_topology(layout: &mut WindowLayout, order: Vec<(String, Option<SplitFrom>)>) {
    for (tab_id, split_from) in &order {
        if let Some(tab) = layout.tabs.iter_mut().find(|t| t.tab_id == *tab_id) {
            tab.split_from = split_from.clone();
        }
    }

    let mut ordered = Vec::with_capacity(layout.tabs.len());
    for (tab_id, _) in &order {
        if let Some(pos) = layout.tabs.iter().position(|t| t.tab_id == *tab_id) {
            ordered.push(layout.tabs.remove(pos));
        }
    }
    let mut rest = std::mem::take(&mut layout.tabs);
    rest.sort_by_key(|t| t.index);
    ordered.extend(rest);
    layout.tabs = ordered;
}

/// Write the AUTHORITATIVE pane geometry from a rect set: set each live pane's `pane_rect` from its
/// `AgentRect`, and ALSO refresh the legacy `split_from` topology (so focus-chain navigation and old
/// readers keep working during the transition). Stashed panes are left with `pane_rect = None`. This is
/// the single funnel every rect-producing op (stash/revive/insert/split/close) routes through, so the
/// persisted rect always matches the computed geometry — the renderer paints it directly, no guessing.
fn apply_pane_geometry(layout: &mut WindowLayout, panes: &[AgentRect]) {
    for p in panes {
        if let Some(tab) = layout.tabs.iter_mut().find(|t| t.tab_id == p.agent) {
            tab.pane_rect = Some(PaneRect::from_unit(p.rect));
        }
    }
    // Keep split_from in sync from the same rects (legacy/focus path).
    let order = topology_from_rects(panes);
    apply_revive_topology(layout, order);
}

/// Like [`apply_pane_geometry`] but GUARDED by the [`rects_tile_unit_square`] invariant: if the proposed
/// rects do not perfectly tile (overlap, gap, or out of bounds), it makes NO change and returns an error
/// so the caller leaves the prior valid layout intact. Every interactive geometry op should write
/// through this so a buggy/unexplored case can never paint overlapping panes.
fn apply_pane_geometry_checked(
    layout: &mut WindowLayout,
    panes: &[AgentRect],
) -> Result<(), WindowLayoutError> {
    if !rects_tile_unit_square(panes) {
        return Err(WindowLayoutError::InvalidTabOrder {
            reason: "proposed pane geometry does not tile the window (overlap/gap)".into(),
        });
    }
    apply_pane_geometry(layout, panes);
    Ok(())
}

fn live_topology_needs_repair(layout: &WindowLayout) -> bool {
    let live_ids: Vec<&str> = layout
        .tabs
        .iter()
        .filter(|tab| !tab.stashed)
        .map(|tab| tab.tab_id.as_str())
        .collect();
    if live_ids.len() <= 1 {
        return false;
    }

    let live_set: std::collections::HashSet<&str> = live_ids.iter().copied().collect();
    let root_count = layout
        .tabs
        .iter()
        .filter(|tab| !tab.stashed && tab.split_from.is_none())
        .count();
    if root_count != 1 {
        return true;
    }

    for tab in layout.tabs.iter().filter(|tab| !tab.stashed) {
        let mut seen = std::collections::HashSet::new();
        let mut current = tab;
        while let Some(split) = current.split_from.as_ref() {
            if split.tab_id == current.tab_id || !seen.insert(current.tab_id.as_str()) {
                return true;
            }
            if !live_set.contains(split.tab_id.as_str()) {
                return true;
            }
            let Some(parent) = layout
                .tabs
                .iter()
                .find(|candidate| candidate.tab_id == split.tab_id && !candidate.stashed)
            else {
                return true;
            };
            current = parent;
        }
    }

    false
}

/// Whether pane-op debug tracing (`PANE-DBG …` on stderr) is enabled. OFF by default because the
/// pane-operation regression suite covers the normal path and per-op output is log noise. Opt back
/// in for debugging with `HYDRA_PANE_DEBUG=1`. Checked once and cached.
pub fn pane_debug_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("HYDRA_PANE_DEBUG")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false)
    })
}

/// Emit a `PANE-DBG …` stderr line, but ONLY when `HYDRA_PANE_DEBUG` is set (see `pane_debug_enabled`).
/// Keeps the tracing available for debugging without spamming the log in normal use.
macro_rules! pane_dbg {
    ($($arg:tt)*) => {
        if $crate::window_layout::pane_debug_enabled() {
            eprintln!($($arg)*);
        }
    };
}

/// Compact one-line dump of a window's live panes for debugging pane-op bugs. Each pane shows its state
/// (`S`=stashed, `L`=live+rect, `G`=GHOST: live but no rect), its rect, and its split_from parent/axis.
/// Goes to stderr (the Hydra log). Prefixed `PANE-DBG` for easy grepping. No-op unless `HYDRA_PANE_DEBUG`.
fn dbg_panes(op: &str, layout: &WindowLayout) {
    if !pane_debug_enabled() {
        return;
    }
    let parts: Vec<String> = layout
        .tabs
        .iter()
        .map(|t| {
            let state = if t.stashed {
                "S"
            } else if t.pane_rect.is_some() {
                "L"
            } else {
                "G"
            };
            let r = t
                .pane_rect
                .map(|r| format!("{},{},{},{}", r.x, r.y, r.w, r.h))
                .unwrap_or_else(|| "-".into());
            let sf = t
                .split_from
                .as_ref()
                .map(|s| {
                    format!(
                        "{}{}",
                        &s.tab_id,
                        match s.axis {
                            SplitAxis::Right => "→",
                            SplitAxis::Down => "↓",
                        }
                    )
                })
                .unwrap_or_else(|| "root".into());
            format!("{}:{}[{r}]<{sf}", t.tab_id, state)
        })
        .collect();
    eprintln!("PANE-DBG {op}: {}", parts.join("  ")); // already gated by the early return above
}

fn apply_pane_revive(
    layout: &mut WindowLayout,
    window_id: &str,
    tab_id: &str,
) -> Result<(), WindowLayoutError> {
    pane_dbg!("PANE-DBG REVIVE-ENTER tab={tab_id}");
    dbg_panes("REVIVE-BEFORE", layout);
    let revive_pos = layout
        .tabs
        .iter()
        .position(|tab| tab.tab_id == tab_id)
        .ok_or_else(|| WindowLayoutError::TabNotFound {
            window_id: window_id.to_string(),
            tab_id: tab_id.to_string(),
        })?;
    if !layout.tabs[revive_pos].stashed {
        return Ok(());
    }

    let live_count = layout
        .tabs
        .iter()
        .filter(|tab| !tab.stashed && tab.tab_id != tab_id)
        .count();
    if live_count >= 4 {
        return Err(WindowLayoutError::InvalidTabOrder {
            reason: format!("cannot revive pane {tab_id:?}; four live panes are already active"),
        });
    }

    let existing_live_ids = live_tab_ids_for_revive(layout, tab_id);

    // Compute the revive geometry while the pane is STILL stashed (so live_pane_rects sees only
    // the existing live panes), then unstash and write. apply_revive REORDERS layout.tabs, so the
    // earlier `revive_pos` index is stale and the pane must be found again by id.
    apply_revive(layout, &existing_live_ids, tab_id);
    if let Some(tab) = layout.tabs.iter_mut().find(|tab| tab.tab_id == tab_id) {
        tab.stashed = false;
        tab.stashed_from = None;
    }
    Ok(())
}

/// Store-backed manager for one app's window layouts, over an injected [`AppPaths`].
pub struct WindowLayoutService<'a> {
    paths: &'a AppPaths,
}

enum LayoutTransactionDecision {
    Persist(WindowLayout),
    ReturnWithoutWrite(WindowLayout),
}

fn load_global_visibility_candidate<T: serde::de::DeserializeOwned>(
    conn: &rusqlite::Connection,
    kind: RecordKind,
    id: &str,
) -> Result<T, StoreError> {
    let value = crate::store_sqlite::load_one(conn, kind, id)
        .map_err(|error| StoreError::Map(error.to_string()))?
        .ok_or_else(|| {
            StoreError::Map(format!(
                "global visibility candidate {kind:?} {id:?} disappeared"
            ))
        })?;
    serde_json::from_value(value).map_err(|error| {
        StoreError::Map(format!(
            "global visibility candidate {kind:?} {id:?} is not projectable: {error}"
        ))
    })
}

/// Count fully projectable windows that are part of the user-facing project dashboard and still
/// have at least one non-stashed tab. Ordinary hidden projects intentionally remain in this
/// cohort: the dashboard model projects them and only the exact reserved recovery project is
/// internal-only. Unassigned windows are not "across all projects" and therefore do not authorize
/// hiding a project's final visible window. Any raw-visible candidate whose Project/WindowLayout
/// cannot deserialize fails the mutation closed; a quarantined phantom must never authorize
/// removing the last window the user can actually reach.
pub(crate) fn visible_ordinary_project_window_count(
    conn: &rusqlite::Connection,
) -> Result<usize, StoreError> {
    let candidates = {
        let mut statement = conn
            .prepare(
                "SELECT w.window_id, p.project_id \
                 FROM windows AS w \
                 INNER JOIN projects AS p ON p.project_id = w.project_id \
                 WHERE p.project_id <> ?1 \
                   AND EXISTS ( \
                       SELECT 1 FROM tabs AS t \
                       WHERE t.window_id = w.window_id AND t.stashed = 0 \
                   ) \
                 ORDER BY p.project_id, w.window_id",
            )
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let rows = statement
            .query_map(
                [crate::reserved_product_shell::PRODUCT_RECOVERY_PROJECT_ID],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .map_err(|error| StoreError::Db(error.to_string()))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| StoreError::Db(error.to_string()))?
    };

    let mut validated_projects = std::collections::HashSet::new();
    let mut count = 0usize;
    for (window_id, project_id) in candidates {
        if validated_projects.insert(project_id.clone()) {
            let project: Project =
                load_global_visibility_candidate(conn, RecordKind::Project, &project_id)?;
            if project.project_id != project_id {
                return Err(StoreError::Map(format!(
                    "global visibility Project identity mismatch for {project_id:?}"
                )));
            }
        }
        let layout: WindowLayout =
            load_global_visibility_candidate(conn, RecordKind::WindowLayout, &window_id)?;
        if layout.window_id != window_id {
            return Err(StoreError::Map(format!(
                "global visibility WindowLayout identity mismatch for {window_id:?}"
            )));
        }
        if layout.tabs.iter().any(|tab| !tab.stashed) {
            count = count.checked_add(1).ok_or_else(|| {
                StoreError::Map("visible ordinary-project window count overflow".into())
            })?;
        }
    }
    Ok(count)
}

fn snapshot_is_visible_ordinary_project_window(snapshot: &WindowLayoutSnapshot) -> bool {
    snapshot.project_id.as_deref().is_some_and(|project_id| {
        project_id != crate::reserved_product_shell::PRODUCT_RECOVERY_PROJECT_ID
    }) && snapshot.layout.tabs.iter().any(|tab| !tab.stashed)
}

enum FreshGraphProjectTarget {
    Existing {
        expected: ProjectWindowGraphSnapshot,
    },
    New {
        project_id: String,
        name: String,
        root: String,
        opts: crate::project::NewProject,
    },
}

fn fresh_graph_stage(window_id: &str, stage: &str) -> Result<(), WindowLayoutError> {
    #[cfg(test)]
    crate::store_sqlite::run_window_layout_test_hook(stage, window_id);
    crate::store_sqlite::check_window_layout_test_failure(stage, window_id)
        .map_err(|error| StoreError::Map(error.to_string()))?;
    Ok(())
}

fn decode_graph_record<T: serde::de::DeserializeOwned>(
    conn: &rusqlite::Connection,
    kind: RecordKind,
    id: &str,
    what: &str,
) -> Result<Option<T>, WindowLayoutError> {
    crate::store_sqlite::load_one(conn, kind, id)
        .map_err(|error| StoreError::Map(error.to_string()))?
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                WindowLayoutError::Store(StoreError::Map(format!(
                    "deserialize {what} {id:?}: {error}"
                )))
            })
        })
        .transpose()
}

fn strict_layout_preset_session_refs(
    conn: &rusqlite::Connection,
) -> Result<Vec<(Option<String>, Vec<crate::records::LayoutPresetTab>)>, StoreError> {
    let mut statement = conn
        .prepare("SELECT project_id, tabs_json FROM layout_presets ORDER BY preset_id")
        .map_err(|error| StoreError::Db(error.to_string()))?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|error| StoreError::Db(error.to_string()))?;
    let mut presets = Vec::new();
    for row in rows {
        let (owner, tabs_json) = row.map_err(|error| StoreError::Db(error.to_string()))?;
        let tabs = serde_json::from_str(&tabs_json).map_err(|error| {
            StoreError::Map(format!(
                "fresh graph found malformed layout preset tabs: {error}"
            ))
        })?;
        presets.push((owner, tabs));
    }
    Ok(presets)
}

fn fresh_graph_row_exists(
    conn: &rusqlite::Connection,
    sql: &str,
    id: &str,
) -> Result<bool, StoreError> {
    conn.query_row(sql, [id], |row| row.get::<_, i64>(0))
        .map(|count| count != 0)
        .map_err(|error| StoreError::Db(error.to_string()))
}

fn trace_fields(value: &serde_json::Value) -> Vec<String> {
    value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default()
}

/// Bind caller-derived root/launch/default semantics to the same Project bytes. Epoch-quiet
/// recency changes may be rebased; production order/owner changes advance the private snapshot
/// epoch and are refused before this comparison.
fn fresh_graph_project_inputs_match(expected: &Project, current: &Project) -> bool {
    let mut expected = expected.clone();
    let mut current = current.clone();
    expected.window_order.clear();
    current.window_order.clear();
    expected.last_active_at_ms = 0;
    current.last_active_at_ms = 0;
    expected == current
}

impl<'a> WindowLayoutService<'a> {
    /// Bind the Unbound marker created in the original Task+Session prepare transaction to the
    /// exact reviewed peer immediately before wire publication. The operation token is already
    /// sealed in that marker; callers cannot replace it during this second writer fence.
    pub(crate) fn bind_prepared_agent_task_start(
        &self,
        start: &mut PreparedAgentTaskSessionStart,
        daemon_instance_id: &DaemonInstanceId,
        server_pid: Option<u32>,
        socket_path: &std::path::Path,
    ) -> Result<(), WindowLayoutError> {
        let now_ms = prepared_agent_task_journal_clock_ms()?;
        let lease_until_ms = now_ms
            .checked_add(AGENT_TASK_START_JOURNAL_LEASE_MS)
            .ok_or_else(|| {
                WindowLayoutError::Store(StoreError::Map(
                    "prepared AgentTask journal lease timestamp overflow".into(),
                ))
            })?;
        let lease_token = uuid::Uuid::new_v4().to_string();
        let socket_path = socket_path.to_str().ok_or_else(|| {
            WindowLayoutError::Store(StoreError::Map(
                "daemon socket path is not valid UTF-8".into(),
            ))
        })?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if !start.graph_matches_connection_at(&tx, now_ms)?
            || start.journal().daemon_instance_id.is_some()
            || start.journal().socket_path.is_some()
            || start.journal().server_pid.is_some()
        {
            return Err(WindowLayoutError::AgentTaskChanged {
                agent_task_id: start.agent_task_id().to_string(),
            });
        }
        let updated = tx
            .execute(
                "UPDATE pending_agent_task_starts \
             SET binding_state = 'bound', daemon_instance_id = ?4, server_pid = ?5, \
                 socket_path = ?6, lease_token = ?7, lease_until_ms = ?8 \
             WHERE session_id = ?1 AND operation_token = ?2 AND lease_token = ?3 \
               AND binding_state = 'unbound' AND daemon_instance_id IS NULL \
               AND server_pid IS NULL AND socket_path IS NULL \
               AND disposition = 'finalize' AND applied_generation IS NULL \
               AND applied_state IS NULL AND lease_until_ms > ?9",
                rusqlite::params![
                    start.journal().session_id,
                    start.journal().operation_token.as_str(),
                    start.journal().lease_token,
                    daemon_instance_id.as_str(),
                    server_pid.map(i64::from),
                    socket_path,
                    lease_token,
                    i64::try_from(lease_until_ms)
                        .map_err(|_| StoreError::Map("journal lease exceeds SQLite i64".into()))?,
                    i64::try_from(now_ms)
                        .map_err(|_| StoreError::Map("journal clock exceeds SQLite i64".into()))?,
                ],
            )
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if updated != 1 {
            return Err(WindowLayoutError::AgentTaskChanged {
                agent_task_id: start.agent_task_id().to_string(),
            });
        }
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let journal = start.journal_mut();
        journal.daemon_instance_id = Some(daemon_instance_id.clone());
        journal.server_pid = server_pid;
        journal.socket_path = Some(socket_path.to_string());
        journal.lease_token = lease_token;
        journal.lease_until_ms = lease_until_ms;
        Ok(())
    }

    pub(crate) fn mark_prepared_agent_task_start_applied(
        &self,
        receipt: &mut PreparedAgentTaskStartJournalReceipt,
        generation: &str,
        state: &'static str,
    ) -> Result<bool, WindowLayoutError> {
        if generation.is_empty()
            || generation.len() > 128
            || !matches!(state, "live" | "exited" | "removed")
        {
            return Err(WindowLayoutError::Store(StoreError::Map(
                "invalid task start journal daemon disposition".into(),
            )));
        }
        let transition_allowed = match (
            receipt.applied_generation.as_deref(),
            receipt.applied_state.as_deref(),
        ) {
            (None, None) => true,
            (Some(current_generation), Some("live")) => {
                current_generation == generation && matches!(state, "live" | "exited" | "removed")
            }
            (Some(current_generation), Some("exited")) => {
                current_generation == generation && matches!(state, "exited" | "removed")
            }
            (Some(current_generation), Some("removed")) => {
                current_generation == generation && state == "removed"
            }
            _ => false,
        };
        if !transition_allowed {
            return Ok(false);
        }
        let now_ms = prepared_agent_task_journal_clock_ms()?;
        let lease_until_ms = now_ms
            .checked_add(AGENT_TASK_START_JOURNAL_LEASE_MS)
            .ok_or_else(|| {
                WindowLayoutError::Store(StoreError::Map(
                    "prepared AgentTask journal lease timestamp overflow".into(),
                ))
            })?;
        let lease_token = uuid::Uuid::new_v4().to_string();
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if !prepared_agent_task_start_journal_matches(&tx, receipt)?
            || receipt.lease_until_ms <= now_ms
        {
            return Ok(false);
        }
        let updated = tx
            .execute(
                "UPDATE pending_agent_task_starts \
                 SET applied_generation = ?2, applied_state = ?3, \
                     lease_token = ?6, lease_until_ms = ?7 \
                 WHERE session_id = ?1 AND operation_token = ?4 AND lease_token = ?5 \
                   AND disposition = 'finalize' \
                   AND (applied_generation IS NULL OR applied_generation = ?2) \
                   AND lease_until_ms > ?8",
                rusqlite::params![
                    receipt.session_id,
                    generation,
                    state,
                    receipt.operation_token.as_str(),
                    receipt.lease_token,
                    lease_token,
                    i64::try_from(lease_until_ms)
                        .map_err(|_| StoreError::Map("journal lease exceeds SQLite i64".into()))?,
                    i64::try_from(now_ms)
                        .map_err(|_| StoreError::Map("journal clock exceeds SQLite i64".into()))?,
                ],
            )
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if updated == 1 {
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            receipt.applied_generation = Some(generation.to_string());
            receipt.applied_state = Some(state.to_string());
            receipt.lease_token = lease_token;
            receipt.lease_until_ms = lease_until_ms;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Delete the exact durable operation-release marker only after the caller has received an
    /// exact Applied(G) retirement acknowledgement from the bound daemon. Session B and Task B
    /// are deliberately untouched. A lost DB commit remains recoverable because the row stays in
    /// `release` and the durable worker treats an idempotent `AlreadyRetired` as the same barrier.
    pub(crate) fn delete_prepared_agent_task_release_after_operation_retired(
        &self,
        receipt: &PreparedAgentTaskStartJournalReceipt,
        generation: &str,
    ) -> Result<bool, WindowLayoutError> {
        if receipt.disposition != "release"
            || receipt.applied_generation.as_deref() != Some(generation)
            || receipt.daemon_instance_id.is_none()
        {
            return Ok(false);
        }
        let now_ms = prepared_agent_task_journal_clock_ms()?;
        if receipt.lease_until_ms <= now_ms {
            return Ok(false);
        }
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if !receipt.matches_release_in_connection(&tx)? {
            return Ok(false);
        }
        let removed = tx
            .execute(
                "DELETE FROM pending_agent_task_starts \
                 WHERE session_id = ?1 AND operation_token = ?2 AND lease_token = ?3 \
                   AND lease_until_ms = ?4 AND lease_until_ms > ?5 \
                   AND disposition = 'release' AND daemon_instance_id = ?6 \
                   AND applied_generation = ?7",
                rusqlite::params![
                    receipt.session_id,
                    receipt.operation_token.as_str(),
                    receipt.lease_token,
                    i64::try_from(receipt.lease_until_ms).map_err(|_| {
                        StoreError::Map("journal lease exceeds SQLite i64".into())
                    })?,
                    i64::try_from(now_ms).map_err(|_| {
                        StoreError::Map("journal clock exceeds SQLite i64".into())
                    })?,
                    receipt
                        .daemon_instance_id
                        .as_ref()
                        .expect("release journal remains peer-bound")
                        .as_str(),
                    generation,
                ],
            )
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if removed != 1 {
            return Ok(false);
        }
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        Ok(true)
    }

    pub fn new(paths: &'a AppPaths) -> Self {
        WindowLayoutService { paths }
    }

    /// Load the current-version layout for `window_id`.
    ///
    /// - `Ok(None)` — no record on disk yet.
    /// - `Ok(Some(layout))` — a valid current-version layout.
    /// - `Err(FutureVersion/Corrupt)` — surfaced typed; the store left a future record in place
    ///   and quarantined a corrupt one.
    /// - `Err(Store(Id(_)))` — `window_id` is unsafe for a path (refused before any IO).
    pub fn load(&self, window_id: &str) -> Result<Option<WindowLayout>, WindowLayoutError> {
        Ok(self
            .load_snapshot(window_id)?
            .map(|snapshot| snapshot.layout))
    }

    /// Load a Project and the global identity/ownership epoch from one DEFERRED read snapshot.
    /// This opaque proof is required by fresh existing-Project graph creation; a plain Project row
    /// cannot distinguish delete + byte-identical recreation.
    pub fn load_project_window_graph_snapshot(
        &self,
        project_id: &str,
    ) -> Result<Option<ProjectWindowGraphSnapshot>, WindowLayoutError> {
        self.paths
            .record_path(RecordKind::Project, project_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let load = |conn: &rusqlite::Connection| {
            let Some(project) =
                decode_graph_record::<Project>(conn, RecordKind::Project, project_id, "Project")?
            else {
                return Ok(None);
            };
            let window_mutation_epoch = crate::db::window_mutation_epoch(conn)
                .map_err(|error| StoreError::Db(error.to_string()))?;
            Ok(Some(ProjectWindowGraphSnapshot {
                project,
                window_mutation_epoch,
            }))
        };
        if conn.is_autocommit() {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let snapshot = load(&tx)?;
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            Ok(snapshot)
        } else {
            load(&conn)
        }
    }

    /// Load the layout and its relational project owner from one SQLite read snapshot.
    ///
    /// This is intentionally narrower than a generic store snapshot: the agent's close-window
    /// lifecycle needs the exact owner together with the exact tab cohort so a later conditional
    /// delete and failure compensation cannot act on values observed at different times.
    pub fn load_snapshot(
        &self,
        window_id: &str,
    ) -> Result<Option<WindowLayoutSnapshot>, WindowLayoutError> {
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        if conn.is_autocommit() {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let snapshot = Self::load_snapshot_from_connection(&tx, window_id)?;
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            Ok(snapshot)
        } else {
            // Reuse a caller-owned transaction instead of nesting. This mirrors the store's
            // multi-table read contract and keeps migrations/tests with an outer transaction valid.
            Self::load_snapshot_from_connection(&conn, window_id)
        }
    }

    /// Load one complete visible viewport authority from ONE DEFERRED SQLite snapshot.
    ///
    /// Every non-stashed tab must resolve to a complete current Session row with a valid
    /// `last_known_generation` (`1..=128` bytes). A single refusal returns no partial snapshot.
    /// Stashed tabs remain durable ownership but have no renderer role and are deliberately not
    /// resolved here.
    pub fn load_viewport_snapshot(
        &self,
        window_id: &str,
    ) -> Result<WindowViewportSnapshot, WindowViewportSnapshotError> {
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)
            .map_err(WindowLayoutError::from)?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))
            .map_err(WindowLayoutError::from)?;
        let mut conn = arc.lock().unwrap();
        if conn.is_autocommit() {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
                .map_err(|error| StoreError::Db(error.to_string()))
                .map_err(WindowLayoutError::from)?;
            let snapshot = Self::load_viewport_snapshot_from_connection(&tx, window_id)?;
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))
                .map_err(WindowLayoutError::from)?;
            Ok(snapshot)
        } else {
            Self::load_viewport_snapshot_from_connection(&conn, window_id)
        }
    }

    /// Load the exact target and classify its daemon sessions against every other window under
    /// one DEFERRED read snapshot. Session ids are soft references in this schema and therefore
    /// are not assumed unique: a close must never prepare a kill for an already-shared id.
    pub fn load_close_snapshot(
        &self,
        window_id: &str,
    ) -> Result<Option<WindowCloseSnapshot>, WindowLayoutError> {
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let Some(window) = Self::load_snapshot_from_connection(&tx, window_id)? else {
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            return Ok(None);
        };
        let all = crate::store_sqlite::load_all(&tx, RecordKind::WindowLayout)
            .map_err(|error| StoreError::Map(error.to_string()))?;
        let mut referenced_elsewhere = std::collections::HashSet::new();
        for value in all {
            let layout = serde_json::from_value::<WindowLayout>(value).map_err(|error| {
                WindowLayoutError::Corrupt {
                    original: PathBuf::new(),
                    moved_to: PathBuf::new(),
                    reason: format!("row failed to deserialize during close snapshot: {error}"),
                }
            })?;
            if layout.window_id != window_id {
                referenced_elsewhere.extend(layout.tabs.into_iter().filter_map(|tab| {
                    (!tab.session_id.trim().is_empty()).then_some(tab.session_id)
                }));
            }
        }
        let mut exclusive_session_ids = window
            .layout
            .tabs
            .iter()
            .map(|tab| tab.session_id.clone())
            .filter(|session_id| {
                !session_id.trim().is_empty() && !referenced_elsewhere.contains(session_id)
            })
            .collect::<Vec<_>>();
        exclusive_session_ids.sort();
        exclusive_session_ids.dedup();
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        Ok(Some(WindowCloseSnapshot {
            window,
            exclusive_session_ids,
        }))
    }

    /// Atomically add a fresh Workspace + Session + owned Window + first Tab to an existing
    /// Project. Every identity is insert-only, the window's unique display name and strict project
    /// order are computed from the transaction-local snapshot, and the global ownership epoch is
    /// advanced exactly once with the complete graph.
    pub fn create_fresh_window_graph(
        &self,
        expected: &ProjectWindowGraphSnapshot,
        spec: FreshWindowGraphSpec,
        now_ms: u64,
    ) -> Result<FreshWindowGraphCreateOutcome, WindowLayoutError> {
        self.create_fresh_window_graph_inner(
            FreshGraphProjectTarget::Existing {
                expected: expected.clone(),
            },
            spec,
            now_ms,
        )
    }

    /// Prepared counterpart to [`Self::create_fresh_window_graph`]. The canonical first Session
    /// is derived from `start_params`; the private graph receipt minted by the same insert-only
    /// transaction is moved directly into the consume-once start authority and is never exposed as
    /// a separately cloneable caller value.
    pub fn create_prepared_fresh_window_graph(
        &self,
        expected: &ProjectWindowGraphSnapshot,
        spec: PreparedFreshWindowGraphSpec,
    ) -> Result<PreparedFreshWindowGraphCreateOutcome, WindowLayoutError> {
        self.create_prepared_fresh_window_graph_inner(
            FreshGraphProjectTarget::Existing {
                expected: expected.clone(),
            },
            spec,
        )
    }

    /// Atomically create a brand-new Project and its complete initial Workspace + Session + owned
    /// Window + first Tab. Unlike chaining [`ProjectService::create`](crate::ProjectService::create)
    /// with later writes, no observer can ever see a partial initial graph.
    #[allow(clippy::too_many_arguments)]
    pub fn create_fresh_project_window_graph(
        &self,
        project_id: impl Into<String>,
        name: impl Into<String>,
        root: impl Into<String>,
        opts: crate::project::NewProject,
        spec: FreshWindowGraphSpec,
        now_ms: u64,
    ) -> Result<FreshWindowGraphCreateOutcome, WindowLayoutError> {
        self.create_fresh_window_graph_inner(
            FreshGraphProjectTarget::New {
                project_id: project_id.into(),
                name: name.into(),
                root: root.into(),
                opts,
            },
            spec,
            now_ms,
        )
    }

    /// Prepared counterpart to [`Self::create_fresh_project_window_graph`]. Project, Workspace,
    /// canonical `Unknown` Session, Window/Tab, epoch, compensation proof, and start authority are
    /// all born from one complete fresh-graph transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn create_prepared_fresh_project_window_graph(
        &self,
        project_id: impl Into<String>,
        name: impl Into<String>,
        root: impl Into<String>,
        opts: crate::project::NewProject,
        spec: PreparedFreshWindowGraphSpec,
    ) -> Result<PreparedFreshWindowGraphCreateOutcome, WindowLayoutError> {
        self.create_prepared_fresh_window_graph_inner(
            FreshGraphProjectTarget::New {
                project_id: project_id.into(),
                name: name.into(),
                root: root.into(),
                opts,
            },
            spec,
        )
    }

    fn create_prepared_fresh_window_graph_inner(
        &self,
        target: FreshGraphProjectTarget,
        spec: PreparedFreshWindowGraphSpec,
    ) -> Result<PreparedFreshWindowGraphCreateOutcome, WindowLayoutError> {
        let PreparedFreshWindowGraphSpec {
            workspace,
            session,
            window_id,
            window_name,
            tab_id,
            tab_title,
            tab_pinned,
            tab_attention,
            touch_project,
        } = spec;
        let (start_params, publication_launch, binding, worktree_provenance_seal) =
            session.into_parts();
        let unknown = canonical_prepared_unknown(&start_params, &publication_launch, binding)?;
        if workspace.workspace_id != unknown.workspace_id {
            return Err(WindowLayoutError::WorkspaceChanged {
                workspace_id: workspace.workspace_id,
            });
        }
        // Fresh-graph creation owns a still-absent Workspace identity and therefore cannot
        // transaction-revalidate a Worktree marker that was written before that row existed. Keep
        // this route fail-closed; consented New Tab Worktrees use the existing-Workspace path.
        if worktree_provenance_seal.is_some() {
            return Err(WindowLayoutError::Store(StoreError::Map(
                "prepared Worktree Session requires an existing transaction-reviewed Workspace"
                    .into(),
            )));
        }
        let now_ms = start_params.now_ms;
        let legacy = FreshWindowGraphSpec {
            workspace,
            session: unknown.clone(),
            window_id,
            window_name,
            tab_id,
            tab_title,
            tab_pinned,
            tab_attention,
            touch_project,
        };
        match self.create_fresh_window_graph_inner(target, legacy, now_ms)? {
            FreshWindowGraphCreateOutcome::Created(created) => {
                if created.session != unknown {
                    return Err(WindowLayoutError::Store(StoreError::Map(
                        "fresh graph returned a different canonical prepared Session".into(),
                    )));
                }
                let CreatedFreshWindowGraph {
                    project,
                    workspace,
                    session: _,
                    window,
                    receipt,
                } = created;
                let start = PreparedNewSessionStart {
                    unknown,
                    workspace,
                    params: start_params,
                    publication_launch,
                    binding,
                    worktree_provenance: None,
                    placement: PreparedNewSessionPlacement::FreshWindowGraph {
                        receipt,
                        project: project.clone(),
                        layout: window.layout.clone(),
                    },
                    agent_task: None,
                };
                Ok(PreparedFreshWindowGraphCreateOutcome::Created(
                    CreatedPreparedFreshWindowGraph {
                        project,
                        window,
                        start,
                    },
                ))
            }
            FreshWindowGraphCreateOutcome::ProjectMissing { project_id } => {
                Ok(PreparedFreshWindowGraphCreateOutcome::ProjectMissing { project_id })
            }
            FreshWindowGraphCreateOutcome::ProjectChanged { project_id } => {
                Ok(PreparedFreshWindowGraphCreateOutcome::ProjectChanged { project_id })
            }
            FreshWindowGraphCreateOutcome::Conflict(conflict) => {
                Ok(PreparedFreshWindowGraphCreateOutcome::Conflict(conflict))
            }
        }
    }

    fn create_fresh_window_graph_inner(
        &self,
        target: FreshGraphProjectTarget,
        spec: FreshWindowGraphSpec,
        now_ms: u64,
    ) -> Result<FreshWindowGraphCreateOutcome, WindowLayoutError> {
        let (project_id, creates_project) = match &target {
            FreshGraphProjectTarget::Existing { expected } => {
                (expected.project.project_id.as_str(), false)
            }
            FreshGraphProjectTarget::New { project_id, .. } => (project_id.as_str(), true),
        };
        self.paths
            .record_path(RecordKind::Project, project_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::Workspace, &spec.workspace.workspace_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::Session, &spec.session.session_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::WindowLayout, &spec.window_id)
            .map_err(StoreError::Id)?;
        crate::ids::validate_id(&spec.tab_id).map_err(StoreError::Id)?;

        if spec.workspace.project_id != project_id {
            return Err(WindowLayoutError::Store(StoreError::Map(format!(
                "fresh graph workspace {:?} names project {:?}, expected {project_id:?}",
                spec.workspace.workspace_id, spec.workspace.project_id
            ))));
        }
        if spec.session.workspace_id != spec.workspace.workspace_id {
            return Err(WindowLayoutError::Store(StoreError::Map(format!(
                "fresh graph session {:?} names workspace {:?}, expected {:?}",
                spec.session.session_id, spec.session.workspace_id, spec.workspace.workspace_id
            ))));
        }
        if spec.session.agent_task_id.is_some() {
            return Err(WindowLayoutError::Store(StoreError::Map(
                "fresh first-window graph cannot adopt a pre-existing AgentTask".into(),
            )));
        }

        fresh_graph_stage(&spec.window_id, "before-fresh-graph-transaction")?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        fresh_graph_stage(&spec.window_id, "after-fresh-graph-begin")?;

        let mut project = match target {
            FreshGraphProjectTarget::Existing { expected } => {
                let project_id = expected.project.project_id.clone();
                let Some(project) = decode_graph_record::<Project>(
                    &tx,
                    RecordKind::Project,
                    &project_id,
                    "Project",
                )?
                else {
                    return Ok(FreshWindowGraphCreateOutcome::ProjectMissing { project_id });
                };
                let current_epoch = crate::db::window_mutation_epoch(&tx)
                    .map_err(|error| StoreError::Db(error.to_string()))?;
                if current_epoch != expected.window_mutation_epoch
                    || !fresh_graph_project_inputs_match(&expected.project, &project)
                {
                    return Ok(FreshWindowGraphCreateOutcome::ProjectChanged { project_id });
                }
                project
            }
            FreshGraphProjectTarget::New {
                project_id,
                name,
                root,
                opts,
            } => match crate::project::build_new_project_in_tx(
                &tx,
                project_id.clone(),
                name,
                root,
                opts,
                false,
                now_ms,
            ) {
                Ok(project) => project,
                Err(crate::project::ProjectServiceError::ProjectAlreadyExists { project_id }) => {
                    return Ok(FreshWindowGraphCreateOutcome::Conflict(
                        FreshWindowGraphConflict::Project { project_id },
                    ));
                }
                Err(error) => {
                    return Err(WindowLayoutError::Store(StoreError::Map(format!(
                        "construct fresh Project: {error}"
                    ))));
                }
            },
        };
        let previous_project = (!creates_project).then(|| project.clone());

        // Parse EVERY order before accepting any soft owner evidence. Malformed JSON, invalid ids,
        // or duplicates fail closed rather than being treated as an empty order.
        let project_orders = crate::project::project_window_orders(&tx).map_err(|error| {
            StoreError::Map(format!("fresh graph project-order proof failed: {error}"))
        })?;
        let ordered_by = project_orders
            .iter()
            .filter(|(_, order)| order.iter().any(|id| id == &spec.window_id))
            .map(|(owner, _)| owner.clone())
            .collect::<Vec<_>>();
        if !ordered_by.is_empty() {
            return Ok(FreshWindowGraphCreateOutcome::Conflict(
                FreshWindowGraphConflict::ProjectOrder {
                    window_id: spec.window_id,
                    project_ids: ordered_by,
                },
            ));
        }

        // A missing Project row is not a clean identity namespace by itself: FK-disabled legacy
        // writers may have left children that would otherwise be silently adopted by inserting
        // the same Project id.
        if creates_project {
            let child_count: i64 = tx
                .query_row(
                    "SELECT \
                       (SELECT COUNT(*) FROM workspaces WHERE project_id = ?1) + \
                       (SELECT COUNT(*) FROM agent_tasks WHERE project_id = ?1) + \
                       (SELECT COUNT(*) FROM windows WHERE project_id = ?1) + \
                       (SELECT COUNT(*) FROM layout_presets WHERE project_id = ?1)",
                    [&project.project_id],
                    |row| row.get(0),
                )
                .map_err(|error| StoreError::Db(error.to_string()))?;
            if child_count != 0 {
                return Ok(FreshWindowGraphCreateOutcome::Conflict(
                    FreshWindowGraphConflict::Project {
                        project_id: project.project_id,
                    },
                ));
            }
        }

        if crate::store_sqlite::load_one(&tx, RecordKind::Workspace, &spec.workspace.workspace_id)
            .map_err(|error| StoreError::Map(error.to_string()))?
            .is_some()
        {
            return Ok(FreshWindowGraphCreateOutcome::Conflict(
                FreshWindowGraphConflict::Workspace {
                    workspace_id: spec.workspace.workspace_id,
                },
            ));
        }
        if crate::store_sqlite::load_one(&tx, RecordKind::Session, &spec.session.session_id)
            .map_err(|error| StoreError::Map(error.to_string()))?
            .is_some()
        {
            return Ok(FreshWindowGraphCreateOutcome::Conflict(
                FreshWindowGraphConflict::Session {
                    session_id: spec.session.session_id,
                },
            ));
        }
        if crate::store_sqlite::load_one(&tx, RecordKind::WindowLayout, &spec.window_id)
            .map_err(|error| StoreError::Map(error.to_string()))?
            .is_some()
        {
            return Ok(FreshWindowGraphCreateOutcome::Conflict(
                FreshWindowGraphConflict::Window {
                    window_id: spec.window_id,
                },
            ));
        }

        // Identity absence also requires an empty soft-owner namespace. Reuse the same strict
        // task/tab/provenance and preset parsers as receipt cleanup so creation and compensation
        // cannot drift about what constitutes foreign authority.
        if fresh_graph_row_exists(
            &tx,
            "SELECT COUNT(*) FROM sessions WHERE workspace_id = ?1",
            &spec.workspace.workspace_id,
        )? || fresh_graph_row_exists(
            &tx,
            "SELECT COUNT(*) FROM worktree_provenance WHERE workspace_id = ?1",
            &spec.workspace.workspace_id,
        )? {
            return Ok(FreshWindowGraphCreateOutcome::Conflict(
                FreshWindowGraphConflict::Workspace {
                    workspace_id: spec.workspace.workspace_id,
                },
            ));
        }
        if fresh_graph_row_exists(
            &tx,
            "SELECT COUNT(*) FROM worktree_provenance WHERE session_id = ?1",
            &spec.session.session_id,
        )? {
            return Ok(FreshWindowGraphCreateOutcome::Conflict(
                FreshWindowGraphConflict::Session {
                    session_id: spec.session.session_id,
                },
            ));
        }
        let ownership = crate::project::session_ownership_graph(&tx).map_err(|error| {
            StoreError::Map(format!("fresh graph session-owner proof failed: {error}"))
        })?;
        let preset_refs = strict_layout_preset_session_refs(&tx)?;
        if ownership
            .task_refs
            .iter()
            .any(|(_, refs)| refs.iter().any(|id| id == &spec.session.session_id))
            || ownership
                .tab_refs
                .iter()
                .any(|(_, _, session_id)| session_id == &spec.session.session_id)
            || ownership
                .worktree_refs
                .iter()
                .any(|(session_id, _, _)| session_id == &spec.session.session_id)
            || preset_refs.iter().any(|(_, tabs)| {
                tabs.iter()
                    .any(|tab| tab.session_id.as_deref() == Some(spec.session.session_id.as_str()))
            })
        {
            return Ok(FreshWindowGraphCreateOutcome::Conflict(
                FreshWindowGraphConflict::Session {
                    session_id: spec.session.session_id,
                },
            ));
        }
        if fresh_graph_row_exists(
            &tx,
            "SELECT COUNT(*) FROM tabs WHERE window_id = ?1",
            &spec.window_id,
        )? {
            return Ok(FreshWindowGraphCreateOutcome::Conflict(
                FreshWindowGraphConflict::Window {
                    window_id: spec.window_id,
                },
            ));
        }

        // The order is a presentation hint, but every resolved member must still agree with the
        // authoritative Window FK. Stale missing ids remain tolerated by the Project contract.
        for sibling_window_id in &project.window_order {
            let Some(sibling) = Self::load_snapshot_from_connection(&tx, sibling_window_id)? else {
                continue;
            };
            if sibling.project_id.as_deref() != Some(project.project_id.as_str()) {
                return Err(WindowLayoutError::Store(StoreError::Map(format!(
                    "project {:?} order names window {sibling_window_id:?} owned by {:?}",
                    project.project_id, sibling.project_id
                ))));
            }
        }
        // Window FK ownership, not order membership, defines the complete sibling-name cohort.
        // This catches an owned legacy/orphan window omitted from presentation order and prevents
        // allocating a duplicate title.
        let owned_window_ids = {
            let mut statement = tx
                .prepare("SELECT window_id FROM windows WHERE project_id = ?1 ORDER BY window_id")
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let rows = statement
                .query_map([&project.project_id], |row| row.get::<_, String>(0))
                .map_err(|error| StoreError::Db(error.to_string()))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| StoreError::Db(error.to_string()))?
        };
        let mut sibling_names = Vec::new();
        for sibling_window_id in owned_window_ids {
            let sibling = Self::load_snapshot_from_connection(&tx, &sibling_window_id)?
                .ok_or_else(|| {
                    StoreError::Map(format!(
                        "FK-owned sibling window {sibling_window_id:?} disappeared from writer snapshot"
                    ))
                })?;
            if sibling.project_id.as_deref() != Some(project.project_id.as_str()) {
                return Err(WindowLayoutError::Store(StoreError::Map(format!(
                    "FK-owned sibling window {sibling_window_id:?} decoded owner {:?}",
                    sibling.project_id
                ))));
            }
            if let Some(name) = sibling.layout.name {
                sibling_names.push(name);
            }
        }
        let desired_window_name = spec.window_name.trim();
        let window_name = crate::unique_name(desired_window_name, &sibling_names);
        let layout = WindowLayout {
            window_id: spec.window_id.clone(),
            name: Some(window_name),
            tabs: vec![TabRecord {
                tab_id: spec.tab_id.clone(),
                session_id: spec.session.session_id.clone(),
                index: 0,
                title: spec.tab_title.clone(),
                pinned: spec.tab_pinned,
                attention: spec.tab_attention,
                split_from: None,
                pane_rect: None,
                stashed_from: None,
                stashed: false,
            }],
        };
        project.window_order.push(spec.window_id.clone());
        if spec.touch_project {
            project.last_active_at_ms = now_ms;
        }

        // Exhaustion is checked before the first row changes. Every later error drops this one
        // transaction, restoring every identity/order and the epoch together.
        crate::db::preflight_window_mutation_epoch_bump(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;

        let project_value = serde_json::to_value(&project)
            .map_err(|error| StoreError::Map(format!("serialize Project: {error}")))?;
        if creates_project {
            if !crate::store_sqlite::insert_fresh_project(&tx, &project.project_id, &project_value)
                .map_err(|error| StoreError::Map(error.to_string()))?
            {
                return Ok(FreshWindowGraphCreateOutcome::Conflict(
                    FreshWindowGraphConflict::Project {
                        project_id: project.project_id,
                    },
                ));
            }
        } else {
            let previous_project_value = serde_json::to_value(
                previous_project
                    .as_ref()
                    .expect("existing graph captured its prior Project"),
            )
            .map_err(|error| StoreError::Map(format!("serialize prior Project: {error}")))?;
            if !crate::store_sqlite::update_project_if_exact(
                &tx,
                &project.project_id,
                &previous_project_value,
                &project_value,
            )
            .map_err(|error| StoreError::Map(error.to_string()))?
            {
                return Ok(FreshWindowGraphCreateOutcome::ProjectChanged {
                    project_id: project.project_id,
                });
            }
        }
        fresh_graph_stage(&spec.window_id, "after-project-row")?;

        let workspace_value = serde_json::to_value(&spec.workspace)
            .map_err(|error| StoreError::Map(format!("serialize Workspace: {error}")))?;
        if !crate::store_sqlite::insert_fresh_workspace(
            &tx,
            &spec.workspace.workspace_id,
            &workspace_value,
        )
        .map_err(|error| StoreError::Map(error.to_string()))?
        {
            return Ok(FreshWindowGraphCreateOutcome::Conflict(
                FreshWindowGraphConflict::Workspace {
                    workspace_id: spec.workspace.workspace_id,
                },
            ));
        }
        fresh_graph_stage(&spec.window_id, "after-workspace-row")?;

        let session_value = serde_json::to_value(&spec.session)
            .map_err(|error| StoreError::Map(format!("serialize Session: {error}")))?;
        if !crate::store_sqlite::insert_fresh_session(&tx, &spec.session.session_id, &session_value)
            .map_err(|error| StoreError::Map(error.to_string()))?
        {
            return Ok(FreshWindowGraphCreateOutcome::Conflict(
                FreshWindowGraphConflict::Session {
                    session_id: spec.session.session_id,
                },
            ));
        }
        fresh_graph_stage(&spec.window_id, "after-session-row")?;

        let layout_value = serde_json::to_value(&layout)
            .map_err(|error| StoreError::Map(format!("serialize WindowLayout: {error}")))?;
        if !crate::store_sqlite::insert_fresh_window_with_first_tab(
            &tx,
            &layout.window_id,
            &project.project_id,
            &layout_value,
        )
        .map_err(|error| StoreError::Map(error.to_string()))?
        {
            return Ok(FreshWindowGraphCreateOutcome::Conflict(
                FreshWindowGraphConflict::Window {
                    window_id: layout.window_id,
                },
            ));
        }
        fresh_graph_stage(&spec.window_id, "after-window-layout")?;

        let window_mutation_epoch = crate::db::bump_window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        fresh_graph_stage(&spec.window_id, "after-fresh-graph-epoch")?;

        let graph_fingerprint = fresh_window_graph_fingerprint(
            previous_project.as_ref(),
            &project,
            &spec.workspace,
            &spec.session,
            &layout,
            Some(&project.project_id),
            creates_project,
            window_mutation_epoch,
        )?;
        let receipt = FreshWindowGraphReceipt {
            project_id: project.project_id.clone(),
            workspace_id: spec.workspace.workspace_id.clone(),
            session_id: spec.session.session_id.clone(),
            window_id: layout.window_id.clone(),
            tab_id: spec.tab_id,
            created_project: creates_project,
            previous_project,
            graph_fingerprint,
            window_mutation_epoch,
        };
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;

        // Preserve the established connection-mutex -> trace order. Tracing is content-blind,
        // happens only after COMMIT, and never calls back into the database.
        let project_trace_fields = if creates_project {
            trace_fields(&project_value)
        } else if spec.touch_project {
            vec!["last_active_at_ms".into(), "window_order".into()]
        } else {
            vec!["window_order".into()]
        };
        crate::write_trace::trace_write(
            self.paths.base(),
            "Project",
            &project.project_id,
            &project_trace_fields,
            now_ms,
        );
        crate::write_trace::trace_write(
            self.paths.base(),
            "Workspace",
            &spec.workspace.workspace_id,
            &trace_fields(&workspace_value),
            now_ms,
        );
        crate::write_trace::trace_write(
            self.paths.base(),
            "Session",
            &spec.session.session_id,
            &trace_fields(&session_value),
            now_ms,
        );
        crate::write_trace::trace_write(
            self.paths.base(),
            "WindowLayout",
            &layout.window_id,
            &trace_fields(&layout_value),
            now_ms,
        );
        crate::write_trace::trace_write(
            self.paths.base(),
            "WindowOwner",
            &layout.window_id,
            &["project_id".into()],
            now_ms,
        );

        let window = WindowLayoutSnapshot {
            layout,
            project_id: Some(project.project_id.clone()),
            revision: WindowLayoutRevision {
                window_mutation_epoch,
            },
        };
        Ok(FreshWindowGraphCreateOutcome::Created(
            CreatedFreshWindowGraph {
                project,
                workspace: spec.workspace,
                session: spec.session,
                window,
                receipt,
            },
        ))
    }

    /// Compensate one exact fresh-graph commit after a bounded external launch/focus failure.
    /// Authority comes exclusively from the private receipt returned by creation: a caller cannot
    /// substitute records, and any changed byte, namespace ABA, unrelated window mutation, or new
    /// durable soft owner makes the cleanup fail closed.
    pub fn delete_fresh_window_graph_if_unchanged(
        &self,
        receipt: &FreshWindowGraphReceipt,
        now_ms: u64,
    ) -> Result<ConditionalFreshWindowGraphDelete, WindowLayoutError> {
        self.delete_fresh_window_graph_if_unchanged_with_resolutions(
            receipt,
            &PreResolvedSessionGenerations::new(),
            now_ms,
        )
    }

    /// Consume one exact prepared-session compensation capability. Existing-window receipts
    /// atomically remove the one prepared tab plus its exact Session row; fresh-graph receipts use
    /// the complete Project/Workspace/Session/Window proof. A stale predecessor receipt simply
    /// returns the underlying typed `Changed` result and never adopts replacement bytes.
    pub fn compensate_prepared_new_session(
        &self,
        receipt: PreparedNewSessionCompensationReceipt,
        now_ms: u64,
    ) -> Result<ConditionalPreparedNewSessionCompensation, WindowLayoutError> {
        self.compensate_prepared_new_session_with_journal(receipt, None, now_ms)
    }

    fn compensate_prepared_new_session_with_journal(
        &self,
        receipt: PreparedNewSessionCompensationReceipt,
        journal: Option<PreparedAgentTaskStartJournalReceipt>,
        now_ms: u64,
    ) -> Result<ConditionalPreparedNewSessionCompensation, WindowLayoutError> {
        let PreparedNewSessionCompensationReceipt {
            session,
            placement,
            state,
            agent_task,
        } = receipt;
        match placement {
            PreparedNewSessionCompensationPlacement::Unplaced { project, workspace } => self
                .rollback_prepared_unplaced_session_if_unchanged(
                    &project,
                    &workspace,
                    &session,
                    state,
                    agent_task.as_ref(),
                    journal.as_ref(),
                    now_ms,
                )
                .map(ConditionalPreparedNewSessionCompensation::Unplaced),
            PreparedNewSessionCompensationPlacement::ExistingWindow {
                project,
                workspace,
                post_layout,
                tab_id,
            } => {
                if journal.is_some() {
                    return Err(WindowLayoutError::Store(StoreError::Map(
                        "task journal compensation requires a task-aware placement transaction"
                            .into(),
                    )));
                }
                self.rollback_created_tab_and_session_if_unchanged_with_project_guard(
                    &post_layout,
                    &tab_id,
                    &session,
                    Some(&project),
                    Some(&workspace),
                    &PreResolvedSessionGenerations::new(),
                    now_ms,
                )
                .map(ConditionalPreparedNewSessionCompensation::ExistingWindow)
            }
            PreparedNewSessionCompensationPlacement::FreshWindowGraph(receipt) => {
                if journal.is_some() {
                    return Err(WindowLayoutError::Store(StoreError::Map(
                        "task journal compensation requires a task-aware placement transaction"
                            .into(),
                    )));
                }
                self.delete_fresh_window_graph_if_unchanged(&receipt, now_ms)
                    .map(ConditionalPreparedNewSessionCompensation::FreshWindowGraph)
            }
        }
    }

    fn rollback_prepared_unplaced_session_if_unchanged(
        &self,
        expected_project: &Project,
        expected_workspace: &Workspace,
        expected_session: &SessionRecord,
        state: PreparedNewSessionCompensationState,
        agent_task: Option<&PreparedAgentTaskTransition>,
        journal: Option<&PreparedAgentTaskStartJournalReceipt>,
        now_ms: u64,
    ) -> Result<ConditionalPreparedUnplacedSessionRollback, WindowLayoutError> {
        // A Grid-proven unplaced lifetime needs a daemon-release journal before durable deletion.
        // No current headless caller compensates success; fail closed rather than turn a rebased
        // receipt into an unjournaled PTY leak or delete.
        if state != PreparedNewSessionCompensationState::UnknownRefused {
            return Ok(ConditionalPreparedUnplacedSessionRollback::Referenced);
        }
        let journal_now_ms = journal
            .map(|_| prepared_agent_task_journal_clock_ms())
            .transpose()?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let project = load_graph_record_for_prepared::<Project>(
            &tx,
            RecordKind::Project,
            &expected_project.project_id,
            "Project",
        )?;
        let workspace = load_graph_record_for_prepared::<Workspace>(
            &tx,
            RecordKind::Workspace,
            &expected_workspace.workspace_id,
            "Workspace",
        )?;
        if project.as_ref() != Some(expected_project)
            || workspace.as_ref() != Some(expected_workspace)
            || expected_workspace.project_id != expected_project.project_id
        {
            return Ok(ConditionalPreparedUnplacedSessionRollback::Changed);
        }
        let session = load_graph_record_for_prepared::<SessionRecord>(
            &tx,
            RecordKind::Session,
            &expected_session.session_id,
            "Session",
        )?;
        let Some(session) = session else {
            return Ok(ConditionalPreparedUnplacedSessionRollback::Missing);
        };
        if session != *expected_session
            || session.status != SessionStatus::Unknown
            || session.last_known_generation.is_some()
        {
            return Ok(ConditionalPreparedUnplacedSessionRollback::Changed);
        }
        if let Some(transition) = agent_task {
            let current_task = load_graph_record_for_prepared::<AgentTask>(
                &tx,
                RecordKind::AgentTask,
                &transition.before.agent_task_id,
                "AgentTask",
            )?;
            if current_task.as_ref() != Some(&transition.before) {
                return Ok(ConditionalPreparedUnplacedSessionRollback::Changed);
            }
            if !agent_task_pending_session_cohort_matches(
                &tx,
                &transition.before,
                &expected_session.session_id,
            )? {
                return Ok(ConditionalPreparedUnplacedSessionRollback::Referenced);
            }
        }
        if let Some(journal) = journal {
            let Some(transition) = agent_task else {
                return Ok(ConditionalPreparedUnplacedSessionRollback::Changed);
            };
            if journal.session_id != expected_session.session_id
                || journal.agent_task_id != transition.before.agent_task_id
                || journal.project_id != expected_project.project_id
                || journal.workspace_id != expected_workspace.workspace_id
                || journal.disposition != "finalize"
                || journal.applied_generation.is_some()
                || journal.applied_state.is_some()
                || !prepared_agent_task_start_journal_matches(&tx, journal)?
                || journal.lease_until_ms <= journal_now_ms.expect("journal clock was captured")
            {
                return Ok(ConditionalPreparedUnplacedSessionRollback::Changed);
            }
        }
        if !prepared_unplaced_session_refs_match(&tx, &session, expected_project, None)? {
            return Ok(ConditionalPreparedUnplacedSessionRollback::Referenced);
        }
        if let Some(journal) = journal {
            if !journal.consume_in_connection_at(
                &tx,
                journal_now_ms.expect("journal clock was captured"),
            )? {
                return Ok(ConditionalPreparedUnplacedSessionRollback::Changed);
            }
        }
        if !crate::store_sqlite::delete(&tx, RecordKind::Session, &expected_session.session_id)
            .map_err(|error| StoreError::Map(error.to_string()))?
        {
            return Ok(ConditionalPreparedUnplacedSessionRollback::Missing);
        }
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        crate::write_trace::trace_delete(
            self.paths.base(),
            "Session",
            &expected_session.session_id,
            now_ms,
        );
        Ok(ConditionalPreparedUnplacedSessionRollback::RolledBack)
    }

    /// Abandon one definitely-unpublished prepared start without leaking its durable `Unknown`
    /// placement. This is the only public conversion from retryable Prepared authority into an
    /// exact compensation attempt; ambiguous/applied errors never return a value accepted here.
    pub fn cancel_prepared_new_session(
        &self,
        start: PreparedNewSessionStart,
        now_ms: u64,
    ) -> Result<ConditionalPreparedNewSessionCompensation, WindowLayoutError> {
        self.compensate_prepared_new_session(start.initial_compensation(), now_ms)
    }

    pub fn compensate_prepared_agent_task_session(
        &self,
        receipt: PreparedAgentTaskSessionCompensation,
        now_ms: u64,
    ) -> Result<ConditionalPreparedNewSessionCompensation, WindowLayoutError> {
        let (receipt, journal) = receipt.into_parts();
        self.compensate_prepared_new_session_with_journal(receipt, Some(journal), now_ms)
    }

    pub fn cancel_prepared_agent_task_session(
        &self,
        start: PreparedAgentTaskSessionStart,
        now_ms: u64,
    ) -> Result<ConditionalPreparedNewSessionCompensation, WindowLayoutError> {
        let (start, journal) = start.into_parts();
        self.compensate_prepared_new_session_with_journal(
            start.initial_compensation(),
            Some(journal),
            now_ms,
        )
    }

    pub fn delete_fresh_window_graph_if_unchanged_with_resolutions(
        &self,
        receipt: &FreshWindowGraphReceipt,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
    ) -> Result<ConditionalFreshWindowGraphDelete, WindowLayoutError> {
        self.paths
            .record_path(RecordKind::Project, &receipt.project_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::Workspace, &receipt.workspace_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::Session, &receipt.session_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::WindowLayout, &receipt.window_id)
            .map_err(StoreError::Id)?;

        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;

        let current_epoch = crate::db::window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let project = decode_graph_record::<Project>(
            &tx,
            RecordKind::Project,
            &receipt.project_id,
            "Project",
        )?;
        let workspace = decode_graph_record::<Workspace>(
            &tx,
            RecordKind::Workspace,
            &receipt.workspace_id,
            "Workspace",
        )?;
        let session = decode_graph_record::<SessionRecord>(
            &tx,
            RecordKind::Session,
            &receipt.session_id,
            "Session",
        )?;
        let window = Self::load_snapshot_from_connection(&tx, &receipt.window_id)?;

        let graph_children_absent = workspace.is_none() && session.is_none() && window.is_none();
        if graph_children_absent && (!receipt.created_project || project.is_none()) {
            return Ok(if current_epoch == receipt.window_mutation_epoch {
                ConditionalFreshWindowGraphDelete::Missing
            } else {
                ConditionalFreshWindowGraphDelete::Changed
            });
        }
        let (Some(project), Some(workspace), Some(session), Some(window)) =
            (project, workspace, session, window)
        else {
            return Ok(ConditionalFreshWindowGraphDelete::Changed);
        };
        if current_epoch != receipt.window_mutation_epoch
            || workspace.project_id != receipt.project_id
            || session.workspace_id != receipt.workspace_id
            || window.project_id.as_deref() != Some(receipt.project_id.as_str())
            || window.layout.window_id != receipt.window_id
        {
            return Ok(ConditionalFreshWindowGraphDelete::Changed);
        }
        let current_fingerprint = fresh_window_graph_fingerprint(
            receipt.previous_project.as_ref(),
            &project,
            &workspace,
            &session,
            &window.layout,
            window.project_id.as_deref(),
            receipt.created_project,
            current_epoch,
        )?;
        if current_fingerprint != receipt.graph_fingerprint {
            return Ok(ConditionalFreshWindowGraphDelete::Changed);
        }

        let project_orders = crate::project::project_window_orders(&tx).map_err(|error| {
            StoreError::Map(format!("fresh graph cleanup order proof failed: {error}"))
        })?;
        let ordered_by = project_orders
            .iter()
            .filter(|(_, order)| order.iter().any(|id| id == &receipt.window_id))
            .map(|(owner, _)| owner.clone())
            .collect::<Vec<_>>();
        if ordered_by != [receipt.project_id.clone()] {
            return Ok(ConditionalFreshWindowGraphDelete::Changed);
        }
        if window.layout.tabs.len() != 1
            || window.layout.tabs[0].tab_id != receipt.tab_id
            || window.layout.tabs[0].session_id != receipt.session_id
        {
            return Ok(ConditionalFreshWindowGraphDelete::Changed);
        }

        // A Workspace created by this graph owns exactly the one created Session. Another child
        // is durable ownership acquired after publication and must survive.
        let mut child_sessions = {
            let mut statement = tx
                .prepare(
                    "SELECT session_id FROM sessions WHERE workspace_id = ?1 ORDER BY session_id",
                )
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let rows = statement
                .query_map([&receipt.workspace_id], |row| row.get::<_, String>(0))
                .map_err(|error| StoreError::Db(error.to_string()))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|error| StoreError::Db(error.to_string()))?
        };
        child_sessions.sort();
        if child_sessions != [receipt.session_id.clone()] {
            return Ok(ConditionalFreshWindowGraphDelete::Referenced);
        }

        // Reuse the same complete soft-session-owner parser as project deletion. Any task
        // current/history reference, foreign tab, or worktree provenance blocks cleanup.
        let ownership = crate::project::session_ownership_graph(&tx).map_err(|error| {
            StoreError::Map(format!("fresh graph cleanup session proof failed: {error}"))
        })?;
        let session_rows = ownership
            .session_rows
            .iter()
            .filter(|(session_id, _, _)| session_id == &receipt.session_id)
            .cloned()
            .collect::<Vec<_>>();
        if session_rows.len() != 1
            || session_rows[0].0 != receipt.session_id
            || session_rows[0].1 != receipt.project_id
        {
            return Ok(ConditionalFreshWindowGraphDelete::Referenced);
        }
        if ownership
            .task_refs
            .iter()
            .any(|(_, refs)| refs.iter().any(|id| id == &receipt.session_id))
        {
            return Ok(ConditionalFreshWindowGraphDelete::Referenced);
        }
        let mut tab_refs = ownership
            .tab_refs
            .iter()
            .filter(|(_, _, session_id)| session_id == &receipt.session_id)
            .cloned()
            .collect::<Vec<_>>();
        tab_refs.sort();
        if tab_refs
            != [(
                receipt.window_id.clone(),
                receipt.tab_id.clone(),
                receipt.session_id.clone(),
            )]
        {
            return Ok(ConditionalFreshWindowGraphDelete::Referenced);
        }
        if ownership
            .worktree_refs
            .iter()
            .any(|(session_id, workspace_id, _)| {
                session_id == &receipt.session_id || workspace_id == &receipt.workspace_id
            })
        {
            return Ok(ConditionalFreshWindowGraphDelete::Referenced);
        }

        // Layout-preset session ids are only revive hints, but they are still durable references;
        // preserving the graph is the conservative compensation policy. Malformed JSON is an
        // error, never an inferred empty reference set.
        for (owner, tabs) in strict_layout_preset_session_refs(&tx)? {
            if (receipt.created_project && owner.as_deref() == Some(receipt.project_id.as_str()))
                || tabs
                    .iter()
                    .any(|tab| tab.session_id.as_deref() == Some(receipt.session_id.as_str()))
            {
                return Ok(ConditionalFreshWindowGraphDelete::Referenced);
            }
        }

        if receipt.created_project {
            let project_children: i64 = tx
                .query_row(
                    "SELECT \
                       (SELECT COUNT(*) FROM workspaces WHERE project_id = ?1) + \
                       (SELECT COUNT(*) FROM agent_tasks WHERE project_id = ?1) + \
                       (SELECT COUNT(*) FROM windows WHERE project_id = ?1) + \
                       (SELECT COUNT(*) FROM layout_presets WHERE project_id = ?1)",
                    [&receipt.project_id],
                    |row| row.get(0),
                )
                .map_err(|error| StoreError::Db(error.to_string()))?;
            // Exactly the one Workspace and one Window created here; tasks/presets must be absent.
            if project_children != 2 {
                return Ok(ConditionalFreshWindowGraphDelete::Referenced);
            }
        }

        crate::db::preflight_window_mutation_epoch_bump(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let exact = exact_release_targets_in_transaction(
            &tx,
            [receipt.session_id.clone()],
            SessionRowPolicy::RowMustBeAbsent,
            pre_resolved,
        )?;
        let release_receipt =
            insert_pending_releases(&tx, &exact.targets, now_ms).map_err(|error| {
                StoreError::Map(format!("journal fresh-window receipt release: {error}"))
            })?;
        let mut restored_project_fields = None;
        if receipt.created_project {
            let deleted =
                crate::store_sqlite::delete(&tx, RecordKind::Project, &receipt.project_id)
                    .map_err(|error| StoreError::Map(error.to_string()))?;
            debug_assert!(deleted, "receipt graph Project was just loaded");
        } else {
            let deleted =
                crate::store_sqlite::delete(&tx, RecordKind::WindowLayout, &receipt.window_id)
                    .map_err(|error| StoreError::Map(error.to_string()))?;
            debug_assert!(deleted, "receipt graph Window was just loaded");
            let deleted =
                crate::store_sqlite::delete(&tx, RecordKind::Session, &receipt.session_id)
                    .map_err(|error| StoreError::Map(error.to_string()))?;
            debug_assert!(deleted, "receipt graph Session was just loaded");
            let deleted =
                crate::store_sqlite::delete(&tx, RecordKind::Workspace, &receipt.workspace_id)
                    .map_err(|error| StoreError::Map(error.to_string()))?;
            debug_assert!(deleted, "receipt graph Workspace was just loaded");
            let previous_project = receipt.previous_project.as_ref().ok_or_else(|| {
                StoreError::Map(
                    "existing fresh graph receipt lacks its canonical prior Project".into(),
                )
            })?;
            let current_value = serde_json::to_value(&project)
                .map_err(|error| StoreError::Map(format!("serialize current Project: {error}")))?;
            let value = serde_json::to_value(previous_project)
                .map_err(|error| StoreError::Map(format!("serialize Project: {error}")))?;
            if !crate::store_sqlite::update_project_if_exact(
                &tx,
                &receipt.project_id,
                &current_value,
                &value,
            )
            .map_err(|error| StoreError::Map(error.to_string()))?
            {
                return Ok(ConditionalFreshWindowGraphDelete::Changed);
            }
            restored_project_fields = Some(trace_fields(&value));
        }
        crate::db::bump_window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;

        crate::write_trace::trace_delete(
            self.paths.base(),
            "WindowLayout",
            &receipt.window_id,
            now_ms,
        );
        crate::write_trace::trace_delete(self.paths.base(), "Session", &receipt.session_id, now_ms);
        crate::write_trace::trace_delete(
            self.paths.base(),
            "Workspace",
            &receipt.workspace_id,
            now_ms,
        );
        if receipt.created_project {
            crate::write_trace::trace_delete(
                self.paths.base(),
                "Project",
                &receipt.project_id,
                now_ms,
            );
        } else {
            crate::write_trace::trace_write(
                self.paths.base(),
                "Project",
                &receipt.project_id,
                restored_project_fields.as_deref().unwrap_or_default(),
                now_ms,
            );
        }
        Ok(ConditionalFreshWindowGraphDelete::Deleted {
            release_receipt,
            unresolved_release_session_ids: exact.unresolved_session_ids,
        })
    }

    /// Create and persist an empty layout (`tabs: []`) for `window_id`.
    ///
    /// Refuses to overwrite an existing CURRENT-version layout
    /// ([`WindowLayoutError::WindowLayoutAlreadyExists`]). A future-version or corrupt record is
    /// surfaced as its own typed error rather than silently clobbered.
    pub fn create_empty(
        &self,
        window_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        Ok(self.create_empty_snapshot(window_id, now_ms)?.layout)
    }

    /// Create an empty layout and return the unforgeable generation captured at its commit. Fresh
    /// create flows carry this through snapshot-aware rename/open/owner operations so rollback can
    /// distinguish their incarnation from a byte-identical delete/recreate.
    pub fn create_empty_snapshot(
        &self,
        window_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayoutSnapshot, WindowLayoutError> {
        self.transact_layout_snapshot(window_id, None, now_ms, |current| {
            if current.is_some() {
                return Err(WindowLayoutError::WindowLayoutAlreadyExists {
                    window_id: window_id.to_string(),
                });
            }
            Ok(LayoutTransactionDecision::Persist(WindowLayout {
                window_id: window_id.to_string(),
                name: None,
                tabs: Vec::new(),
            }))
        })
    }

    /// Load the layout for `window_id`, creating an empty one if none exists. A future-version or
    /// corrupt record is surfaced (not replaced).
    pub fn load_or_create(
        &self,
        window_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.transact_layout(window_id, now_ms, |current| match current {
            Some(layout) => Ok(LayoutTransactionDecision::ReturnWithoutWrite(layout)),
            None => Ok(LayoutTransactionDecision::Persist(WindowLayout {
                window_id: window_id.to_string(),
                name: None,
                tabs: Vec::new(),
            })),
        })
    }

    /// Replace the current-version layout for `window_id` with an empty window layout.
    ///
    /// This is intentionally narrower than a general delete: it preserves the window record identity and
    /// refuses future-version/corrupt records exactly like [`load`], so a clean-window launch cannot
    /// silently clobber data this build cannot safely understand.
    pub fn replace_empty(
        &self,
        window_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.transact_layout(window_id, now_ms, |_| {
            Ok(LayoutTransactionDecision::Persist(WindowLayout {
                window_id: window_id.to_string(),
                name: None,
                tabs: Vec::new(),
            }))
        })
    }

    /// Unconditionally remove the current window-layout identity by id. Returns `Ok(true)` when a
    /// record was removed and `Ok(false)` when it was already absent. This compatibility seam does
    /// not grant daemon-kill authority; ordinary close/remove lifecycles must carry a coherent
    /// snapshot through [`delete_if_unchanged`](Self::delete_if_unchanged).
    pub fn delete(&self, window_id: &str) -> Result<bool, WindowLayoutError> {
        // FK ON DELETE CASCADE removes this window's tabs. Idempotent (missing id → Ok(false)).
        crate::store::delete_record(self.paths, RecordKind::WindowLayout, window_id)
            .map_err(WindowLayoutError::Store)
    }

    /// Delete only if the transaction-local layout and owner still exactly equal `expected`.
    ///
    /// The daemon prepares session-kill requests from `expected.layout`. Acquiring a SQLite writer
    /// fence and revalidating the complete snapshot before the delete prevents those prepared
    /// requests from being committed for a concurrently changed window.
    pub fn delete_if_unchanged(
        &self,
        expected: &WindowLayoutSnapshot,
        now_ms: u64,
    ) -> Result<ConditionalWindowDelete, WindowLayoutError> {
        self.delete_if_unchanged_with_resolutions(
            expected,
            &PreResolvedSessionGenerations::new(),
            now_ms,
        )
    }

    /// Generation-aware conditional window deletion. Every exact candidate is journaled inside
    /// the same destructive transaction. Missing/NULL-generation candidates without a supplied
    /// authoritative resolution are surfaced on the opaque deletion receipt as a safe leak.
    pub fn delete_if_unchanged_with_resolutions(
        &self,
        expected: &WindowLayoutSnapshot,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
    ) -> Result<ConditionalWindowDelete, WindowLayoutError> {
        match self.delete_if_unchanged_with_resolutions_internal(
            expected,
            pre_resolved,
            now_ms,
            false,
        )? {
            GuardedConditionalWindowDelete::Deleted(receipt) => {
                Ok(ConditionalWindowDelete::Deleted(receipt))
            }
            GuardedConditionalWindowDelete::Missing => Ok(ConditionalWindowDelete::Missing),
            GuardedConditionalWindowDelete::Changed => Ok(ConditionalWindowDelete::Changed),
            GuardedConditionalWindowDelete::GloballyLastVisible => {
                unreachable!("unguarded conditional delete cannot refuse the globally last window")
            }
        }
    }

    /// Delete an exact window snapshot only when doing so preserves at least one visible window
    /// owned by an ordinary project across the whole dashboard.
    ///
    /// The count, exact-snapshot revalidation, release journaling, and delete all share the same
    /// SQLite writer transaction. This is the user-facing close/remove seam; project teardown and
    /// rollback retain the explicitly unguarded conditional delete APIs above.
    pub fn delete_if_unchanged_preserving_global_last(
        &self,
        expected: &WindowLayoutSnapshot,
        now_ms: u64,
    ) -> Result<GuardedConditionalWindowDelete, WindowLayoutError> {
        self.delete_if_unchanged_with_resolutions_preserving_global_last(
            expected,
            &PreResolvedSessionGenerations::new(),
            now_ms,
        )
    }

    /// Generation-aware variant of
    /// [`delete_if_unchanged_preserving_global_last`](Self::delete_if_unchanged_preserving_global_last).
    pub fn delete_if_unchanged_with_resolutions_preserving_global_last(
        &self,
        expected: &WindowLayoutSnapshot,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
    ) -> Result<GuardedConditionalWindowDelete, WindowLayoutError> {
        self.delete_if_unchanged_with_resolutions_internal(expected, pre_resolved, now_ms, true)
    }

    fn delete_if_unchanged_with_resolutions_internal(
        &self,
        expected: &WindowLayoutSnapshot,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
        preserve_global_last: bool,
    ) -> Result<GuardedConditionalWindowDelete, WindowLayoutError> {
        let window_id = expected.layout.window_id.as_str();
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let current = Self::load_snapshot_from_connection(&tx, window_id)?;
        let outcome = match current {
            None => GuardedConditionalWindowDelete::Missing,
            Some(current) if current != *expected => GuardedConditionalWindowDelete::Changed,
            Some(current)
                if preserve_global_last
                    && snapshot_is_visible_ordinary_project_window(&current)
                    && visible_ordinary_project_window_count(&tx)? <= 1 =>
            {
                GuardedConditionalWindowDelete::GloballyLastVisible
            }
            Some(current) => {
                let deleted_snapshot_fingerprint = window_layout_snapshot_fingerprint(&current)?;
                let exact = exact_release_targets_in_transaction(
                    &tx,
                    current.layout.tabs.iter().map(|tab| tab.session_id.clone()),
                    SessionRowPolicy::MatchingRowIsProof,
                    pre_resolved,
                )?;
                // Destructive operations remain distinct, but only the latest ordinary window
                // receipt can satisfy the global epoch restore guard. If its exact PTY lifetime
                // is already pending in another operation, that earlier operation may publish
                // after this commit; categorically remove restore authority from this receipt.
                let has_prior_release = has_prior_pending_release_lifetime(&tx, &exact.targets)?;
                let release_receipt = insert_pending_releases(&tx, &exact.targets, now_ms)
                    .map_err(|error| {
                        StoreError::Map(format!("journal window session release: {error}"))
                    })?;
                fresh_graph_stage(window_id, "after-release-journal")?;
                let release_binding = release_receipt.as_ref().map(PendingReleaseReceipt::binding);
                let removed = crate::store_sqlite::delete(&tx, RecordKind::WindowLayout, window_id)
                    .map_err(|error| StoreError::Map(error.to_string()))?;
                debug_assert!(
                    removed,
                    "the transaction-local snapshot just observed the row"
                );
                let window_mutation_epoch = crate::db::bump_window_mutation_epoch(&tx)
                    .map_err(|error| StoreError::Db(error.to_string()))?;
                GuardedConditionalWindowDelete::Deleted(WindowDeletionReceipt {
                    window_id: window_id.to_string(),
                    deleted_revision: current.revision,
                    deleted_snapshot_fingerprint,
                    window_mutation_epoch,
                    window_only_restore: !has_prior_release,
                    release_binding,
                    release_receipt,
                    unresolved_release_session_ids: exact.unresolved_session_ids,
                })
            }
        };
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if matches!(outcome, GuardedConditionalWindowDelete::Deleted(_)) {
            // Keep the same connection-mutex -> trace lock order as every other layout mutation.
            crate::write_trace::trace_delete(self.paths.base(), "WindowLayout", window_id, now_ms);
        }
        Ok(outcome)
    }

    /// Revalidate a committed deletion receipt and target absence in one read snapshot. UI code
    /// uses this typed result to authorize cleanup or fallback work derived from the deleted
    /// incarnation. The foreground renderer must already have cleared that incarnation: a same-id
    /// database recreation does not itself bind new renderer ownership. A same-id recreate or any
    /// later window mutation suppresses the old cleanup/fallback authority and is left for fresh
    /// reconciliation.
    pub fn deletion_receipt_state(
        &self,
        receipt: &WindowDeletionReceipt,
    ) -> Result<WindowDeletionReceiptState, WindowLayoutError> {
        self.paths
            .record_path(RecordKind::WindowLayout, &receipt.window_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let current = Self::load_snapshot_from_connection(&tx, &receipt.window_id)?;
        let epoch = crate::db::window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let state = if current.is_none() && epoch == receipt.window_mutation_epoch {
            WindowDeletionReceiptState::CurrentAndAbsent
        } else {
            WindowDeletionReceiptState::Superseded
        };
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        Ok(state)
    }

    /// Remove a freshly-created Session row only after its pane tab has been closed and no other
    /// durable owner has acquired it.
    ///
    /// `expected_layout_without_tab` must be the exact snapshot returned by the conditional close
    /// (or the exact pre-publication snapshot when tab creation itself failed). The global revision
    /// carried by that snapshot is the Session incarnation fence: an intervening Session
    /// delete/recreate, layout mutation, or other owner-namespace change returns `Changed` even if
    /// the public bytes compare equal. Session metadata writes are epoch-quiet, so the complete
    /// expected Session row is compared as well. Tabs, task current/history links, and worktree
    /// provenance are then checked in the same `BEGIN IMMEDIATE` transaction as the delete.
    pub fn delete_created_session_if_unreferenced(
        &self,
        expected_layout_without_tab: &WindowLayoutSnapshot,
        created_tab_id: &str,
        expected_session: &SessionRecord,
        now_ms: u64,
    ) -> Result<ConditionalCreatedSessionDelete, WindowLayoutError> {
        self.delete_created_session_if_unreferenced_with_resolutions(
            expected_layout_without_tab,
            created_tab_id,
            expected_session,
            &PreResolvedSessionGenerations::new(),
            now_ms,
        )
    }

    pub fn delete_created_session_if_unreferenced_with_resolutions(
        &self,
        expected_layout_without_tab: &WindowLayoutSnapshot,
        created_tab_id: &str,
        expected_session: &SessionRecord,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
    ) -> Result<ConditionalCreatedSessionDelete, WindowLayoutError> {
        let window_id = expected_layout_without_tab.layout.window_id.as_str();
        let session_id = expected_session.session_id.as_str();
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::Session, session_id)
            .map_err(StoreError::Id)?;
        crate::validate_id(created_tab_id).map_err(StoreError::Id)?;

        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;

        let current_layout = Self::load_snapshot_from_connection(&tx, window_id)?;
        if current_layout.as_ref() != Some(expected_layout_without_tab) {
            return Ok(ConditionalCreatedSessionDelete::Changed);
        }
        let current_layout = current_layout.expect("matched Some above");
        if current_layout
            .layout
            .tabs
            .iter()
            .any(|tab| tab.tab_id == created_tab_id)
        {
            return Ok(ConditionalCreatedSessionDelete::Referenced);
        }

        let current_session = crate::store_sqlite::load_one(&tx, RecordKind::Session, session_id)
            .map_err(|error| StoreError::Map(error.to_string()))?
            .map(|value| {
                serde_json::from_value::<SessionRecord>(value)
                    .map_err(|error| StoreError::Map(format!("deserialize session: {error}")))
            })
            .transpose()?;
        let Some(current_session) = current_session else {
            return Ok(ConditionalCreatedSessionDelete::Missing);
        };
        if current_session != *expected_session {
            return Ok(ConditionalCreatedSessionDelete::Changed);
        }

        let ownership = crate::project::session_ownership_graph(&tx).map_err(|error| {
            StoreError::Map(format!(
                "created-session cleanup could not prove session ownership: {error}"
            ))
        })?;
        let tab_reference = ownership
            .tab_refs
            .iter()
            .any(|(_, _, referenced_session)| referenced_session == session_id);
        let task_reference = ownership
            .task_refs
            .iter()
            .any(|(_, refs)| refs.iter().any(|reference| reference == session_id));
        let provenance_reference = ownership
            .worktree_refs
            .iter()
            .any(|(reference, _, _)| reference == session_id);
        if tab_reference || task_reference || provenance_reference {
            return Ok(ConditionalCreatedSessionDelete::Referenced);
        }

        let exact = exact_release_targets_in_transaction(
            &tx,
            [session_id.to_string()],
            SessionRowPolicy::RowMustBeAbsent,
            pre_resolved,
        )?;
        let release_receipt =
            insert_pending_releases(&tx, &exact.targets, now_ms).map_err(|error| {
                StoreError::Map(format!("journal created-session release: {error}"))
            })?;
        let removed = crate::store_sqlite::delete(&tx, RecordKind::Session, session_id)
            .map_err(|error| StoreError::Map(error.to_string()))?;
        debug_assert!(
            removed,
            "the transaction-local snapshot just observed the row"
        );
        crate::db::bump_window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        crate::write_trace::trace_delete(self.paths.base(), "Session", session_id, now_ms);
        Ok(ConditionalCreatedSessionDelete::Deleted {
            release_receipt,
            unresolved_release_session_ids: exact.unresolved_session_ids,
        })
    }

    /// Atomically remove one freshly-published tab and its exact created Session row. The complete
    /// post-publication layout incarnation and full Session A bytes are checked before target
    /// resolution, so a delete/recreate B can never inherit stale cleanup authority. Any other tab,
    /// task current/history link, or worktree provenance reference retains both rows.
    pub fn rollback_created_tab_and_session_if_unchanged(
        &self,
        expected_post_layout: &WindowLayoutSnapshot,
        created_tab_id: &str,
        expected_session: &SessionRecord,
        now_ms: u64,
    ) -> Result<ConditionalCreatedTabSessionRollback, WindowLayoutError> {
        self.rollback_created_tab_and_session_if_unchanged_with_resolutions(
            expected_post_layout,
            created_tab_id,
            expected_session,
            &PreResolvedSessionGenerations::new(),
            now_ms,
        )
    }

    pub fn rollback_created_tab_and_session_if_unchanged_with_resolutions(
        &self,
        expected_post_layout: &WindowLayoutSnapshot,
        created_tab_id: &str,
        expected_session: &SessionRecord,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
    ) -> Result<ConditionalCreatedTabSessionRollback, WindowLayoutError> {
        self.rollback_created_tab_and_session_if_unchanged_with_project_guard(
            expected_post_layout,
            created_tab_id,
            expected_session,
            None,
            None,
            pre_resolved,
            now_ms,
        )
    }

    fn rollback_created_tab_and_session_if_unchanged_with_project_guard(
        &self,
        expected_post_layout: &WindowLayoutSnapshot,
        created_tab_id: &str,
        expected_session: &SessionRecord,
        expected_project: Option<&Project>,
        expected_workspace: Option<&Workspace>,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
    ) -> Result<ConditionalCreatedTabSessionRollback, WindowLayoutError> {
        let window_id = expected_post_layout.layout.window_id.as_str();
        let session_id = expected_session.session_id.as_str();
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::Session, session_id)
            .map_err(StoreError::Id)?;
        if let Some(expected_workspace) = expected_workspace {
            self.paths
                .record_path(RecordKind::Workspace, &expected_workspace.workspace_id)
                .map_err(StoreError::Id)?;
        }
        crate::validate_id(created_tab_id).map_err(StoreError::Id)?;

        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;

        let Some(current_layout) = Self::load_snapshot_from_connection(&tx, window_id)? else {
            return Ok(ConditionalCreatedTabSessionRollback::Missing);
        };
        if current_layout != *expected_post_layout {
            return Ok(ConditionalCreatedTabSessionRollback::Changed);
        }
        if let Some(expected_project) = expected_project {
            let current_project = load_graph_record_for_prepared::<Project>(
                &tx,
                RecordKind::Project,
                &expected_project.project_id,
                "Project",
            )?;
            if current_project.as_ref() != Some(expected_project)
                || current_layout.project_id.as_deref()
                    != Some(expected_project.project_id.as_str())
                || !prepared_project_order_matches(&tx, window_id, &expected_project.project_id)?
            {
                return Ok(ConditionalCreatedTabSessionRollback::Changed);
            }
        }
        if let Some(expected_workspace) = expected_workspace {
            let current_workspace = load_graph_record_for_prepared::<Workspace>(
                &tx,
                RecordKind::Workspace,
                &expected_workspace.workspace_id,
                "Workspace",
            )?;
            if current_workspace.as_ref() != Some(expected_workspace)
                || expected_session.workspace_id != expected_workspace.workspace_id
                || expected_project
                    .is_some_and(|project| expected_workspace.project_id != project.project_id)
            {
                return Ok(ConditionalCreatedTabSessionRollback::Changed);
            }
        }
        let Some(created_tab) = current_layout
            .layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == created_tab_id)
        else {
            return Ok(ConditionalCreatedTabSessionRollback::Missing);
        };
        if created_tab.session_id != session_id {
            return Ok(ConditionalCreatedTabSessionRollback::Changed);
        }

        let current_session = crate::store_sqlite::load_one(&tx, RecordKind::Session, session_id)
            .map_err(|error| StoreError::Map(error.to_string()))?
            .map(|value| {
                serde_json::from_value::<SessionRecord>(value)
                    .map_err(|error| StoreError::Map(format!("deserialize session: {error}")))
            })
            .transpose()?;
        let Some(current_session) = current_session else {
            return Ok(ConditionalCreatedTabSessionRollback::Missing);
        };
        // Full equality must precede generation resolution. Otherwise stale A could resolve and
        // journal the transaction-local generation belonging to a replacement Session B.
        if current_session != *expected_session {
            return Ok(ConditionalCreatedTabSessionRollback::Changed);
        }

        let ownership = crate::project::session_ownership_graph(&tx).map_err(|error| {
            StoreError::Map(format!(
                "created-tab rollback could not prove session ownership: {error}"
            ))
        })?;
        let foreign_tab_reference =
            ownership
                .tab_refs
                .iter()
                .any(|(owner_window_id, owner_tab_id, referenced_session)| {
                    referenced_session == session_id
                        && (owner_window_id != window_id || owner_tab_id != created_tab_id)
                });
        let task_reference = ownership
            .task_refs
            .iter()
            .any(|(_, refs)| refs.iter().any(|reference| reference == session_id));
        let provenance_reference = ownership
            .worktree_refs
            .iter()
            .any(|(reference, _, _)| reference == session_id);
        let preset_reference = strict_layout_preset_session_refs(&tx)?
            .iter()
            .any(|(_, tabs)| {
                tabs.iter()
                    .any(|tab| tab.session_id.as_deref() == Some(session_id))
            });
        if foreign_tab_reference || task_reference || provenance_reference || preset_reference {
            return Ok(ConditionalCreatedTabSessionRollback::Referenced);
        }

        let exact = exact_release_targets_in_transaction(
            &tx,
            [session_id.to_string()],
            SessionRowPolicy::RowMustBeAbsent,
            pre_resolved,
        )?;
        let release_receipt =
            insert_pending_releases(&tx, &exact.targets, now_ms).map_err(|error| {
                StoreError::Map(format!("journal created-tab rollback release: {error}"))
            })?;
        fresh_graph_stage(window_id, "after-created-tab-release-journal")?;

        let mut layout = current_layout.layout;
        apply_reduce(&mut layout, created_tab_id);
        layout.tabs.retain(|tab| tab.tab_id != created_tab_id);
        for (index, tab) in layout.tabs.iter_mut().enumerate() {
            tab.index = index as u32;
        }
        let layout_value = serde_json::to_value(&layout)
            .map_err(|error| StoreError::Map(format!("serialize record: {error}")))?;
        crate::store_sqlite::upsert(&tx, RecordKind::WindowLayout, window_id, &layout_value)
            .map_err(|error| StoreError::Map(error.to_string()))?;
        let removed = crate::store_sqlite::delete(&tx, RecordKind::Session, session_id)
            .map_err(|error| StoreError::Map(error.to_string()))?;
        debug_assert!(
            removed,
            "the exact Session row was read in this transaction"
        );
        crate::db::bump_window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;

        let fields = layout_value
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        crate::write_trace::trace_write(
            self.paths.base(),
            "WindowLayout",
            window_id,
            &fields,
            now_ms,
        );
        crate::write_trace::trace_delete(self.paths.base(), "Session", session_id, now_ms);
        Ok(ConditionalCreatedTabSessionRollback::RolledBack(
            CreatedTabSessionRollback {
                layout,
                release_receipt,
                unresolved_release_session_ids: exact.unresolved_session_ids,
            },
        ))
    }

    /// Roll back one freshly-created window allocation as a single conditional graph mutation.
    ///
    /// The exact layout incarnation, workspace row, optional session row, complete session child
    /// set, and project-order membership are all revalidated after one `BEGIN IMMEDIATE`. Only
    /// then are layout/tabs, session/workspace, and this window's one order entry removed before a
    /// single commit. No caller receives a durable "layout deleted" authority that it could use
    /// later to tear down a concurrently recreated child graph.
    #[allow(clippy::too_many_arguments)]
    pub fn cleanup_created_window_graph_if_unchanged(
        &self,
        expected: &WindowLayoutSnapshot,
        expected_workspace: &Workspace,
        expected_session: Option<&SessionRecord>,
        session_id: &str,
        project_id: &str,
        expected_new_project: Option<&Project>,
        expected_order_member: bool,
        now_ms: u64,
    ) -> Result<ConditionalWindowDelete, WindowLayoutError> {
        self.cleanup_created_window_graph_if_unchanged_with_resolutions(
            expected,
            expected_workspace,
            expected_session,
            session_id,
            project_id,
            expected_new_project,
            expected_order_member,
            &PreResolvedSessionGenerations::new(),
            now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cleanup_created_window_graph_if_unchanged_with_resolutions(
        &self,
        expected: &WindowLayoutSnapshot,
        expected_workspace: &Workspace,
        expected_session: Option<&SessionRecord>,
        session_id: &str,
        project_id: &str,
        expected_new_project: Option<&Project>,
        expected_order_member: bool,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
    ) -> Result<ConditionalWindowDelete, WindowLayoutError> {
        let window_id = expected.layout.window_id.as_str();
        let workspace_id = expected_workspace.workspace_id.as_str();
        for (kind, id) in [
            (RecordKind::WindowLayout, window_id),
            (RecordKind::Workspace, workspace_id),
            (RecordKind::Session, session_id),
            (RecordKind::Project, project_id),
        ] {
            self.paths.record_path(kind, id).map_err(StoreError::Id)?;
        }
        if expected_workspace.project_id != project_id
            || expected_new_project.is_some_and(|project| project.project_id.as_str() != project_id)
            || expected_session.is_some_and(|session| {
                session.session_id != session_id || session.workspace_id != workspace_id
            })
        {
            return Err(WindowLayoutError::Store(StoreError::Map(
                "fresh-window cleanup snapshots do not describe one owned graph".into(),
            )));
        }

        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let Some(current_layout) = Self::load_snapshot_from_connection(&tx, window_id)? else {
            return Ok(ConditionalWindowDelete::Missing);
        };
        if current_layout != *expected {
            return Ok(ConditionalWindowDelete::Changed);
        }
        let deleted_snapshot_fingerprint = window_layout_snapshot_fingerprint(&current_layout)?;

        let current_workspace =
            crate::store_sqlite::load_one(&tx, RecordKind::Workspace, workspace_id)
                .map_err(|error| StoreError::Map(error.to_string()))?
                .map(|value| {
                    serde_json::from_value::<Workspace>(value)
                        .map_err(|error| StoreError::Map(format!("deserialize workspace: {error}")))
                })
                .transpose()?;
        if current_workspace.as_ref() != Some(expected_workspace) {
            return Ok(ConditionalWindowDelete::Changed);
        }

        let current_session = crate::store_sqlite::load_one(&tx, RecordKind::Session, session_id)
            .map_err(|error| StoreError::Map(error.to_string()))?
            .map(|value| {
                serde_json::from_value::<SessionRecord>(value)
                    .map_err(|error| StoreError::Map(format!("deserialize session: {error}")))
            })
            .transpose()?;
        if current_session.as_ref() != expected_session {
            return Ok(ConditionalWindowDelete::Changed);
        }

        // Refuse to cascade a workspace if another session was attached after this create flow
        // captured its expected child. Exact row equality alone would not reveal that sibling.
        let mut statement = tx
            .prepare("SELECT session_id FROM sessions WHERE workspace_id = ?1 ORDER BY session_id")
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let actual_session_ids = statement
            .query_map([workspace_id], |row| row.get::<_, String>(0))
            .map_err(|error| StoreError::Db(error.to_string()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        drop(statement);
        let expected_session_ids = expected_session
            .map(|session| vec![session.session_id.clone()])
            .unwrap_or_default();
        if actual_session_ids != expected_session_ids {
            return Ok(ConditionalWindowDelete::Changed);
        }

        // `tabs.session_id`, task current/history ids, and worktree provenance are durable soft
        // owners with no FK back to `sessions`. Reuse the exact graph reader used by project
        // deletion, and require the target session's tab cohort to be precisely the tabs in the
        // expected layout. Fresh-window flows do not create task/provenance owners; their presence
        // (or provenance aimed at the workspace through another session id) therefore proves the
        // graph escaped this rollback authority.
        let ownership = crate::project::session_ownership_graph(&tx).map_err(|error| {
            StoreError::Map(format!(
                "fresh-window cleanup could not prove session ownership: {error}"
            ))
        })?;
        let mut expected_tab_keys = expected
            .layout
            .tabs
            .iter()
            .filter(|tab| tab.session_id == session_id)
            .map(|tab| (window_id.to_string(), tab.tab_id.clone()))
            .collect::<Vec<_>>();
        expected_tab_keys.sort();
        let mut actual_tab_keys = ownership
            .tab_refs
            .iter()
            .filter(|(_, _, referenced_session)| referenced_session == session_id)
            .map(|(referencing_window, tab_id, _)| (referencing_window.clone(), tab_id.clone()))
            .collect::<Vec<_>>();
        actual_tab_keys.sort();
        let task_references_session = ownership
            .task_refs
            .iter()
            .any(|(_, refs)| refs.iter().any(|reference| reference == session_id));
        let provenance_references_graph =
            ownership
                .worktree_refs
                .iter()
                .any(|(reference, provenance_workspace, _)| {
                    reference == session_id || provenance_workspace == workspace_id
                });
        if actual_tab_keys != expected_tab_keys
            || task_references_session
            || provenance_references_graph
            || expected_session.is_some_and(|session| session.agent_task_id.is_some())
        {
            return Ok(ConditionalWindowDelete::Changed);
        }

        if let Some(expected_project) = expected_new_project {
            let current_project =
                crate::store_sqlite::load_one(&tx, RecordKind::Project, project_id)
                    .map_err(|error| StoreError::Map(error.to_string()))?
                    .map(|value| {
                        serde_json::from_value::<Project>(value).map_err(|error| {
                            StoreError::Map(format!("deserialize project: {error}"))
                        })
                    })
                    .transpose()?;
            if current_project.as_ref() != Some(expected_project) {
                return Ok(ConditionalWindowDelete::Changed);
            }

            let mut workspace_statement = tx
                .prepare(
                    "SELECT workspace_id FROM workspaces WHERE project_id = ?1 ORDER BY workspace_id",
                )
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let workspace_ids = workspace_statement
                .query_map([project_id], |row| row.get::<_, String>(0))
                .map_err(|error| StoreError::Db(error.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            drop(workspace_statement);
            if workspace_ids != [workspace_id.to_string()] {
                return Ok(ConditionalWindowDelete::Changed);
            }

            let mut window_statement = tx
                .prepare("SELECT window_id FROM windows WHERE project_id = ?1 ORDER BY window_id")
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let window_ids = window_statement
                .query_map([project_id], |row| row.get::<_, String>(0))
                .map_err(|error| StoreError::Db(error.to_string()))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            drop(window_statement);
            if window_ids != [window_id.to_string()] {
                return Ok(ConditionalWindowDelete::Changed);
            }

            let unexpected_project_children: i64 = tx
                .query_row(
                    "SELECT \
                         (SELECT COUNT(*) FROM agent_tasks WHERE project_id = ?1) + \
                         (SELECT COUNT(*) FROM layout_presets WHERE project_id = ?1)",
                    [project_id],
                    |row| row.get(0),
                )
                .map_err(|error| StoreError::Db(error.to_string()))?;
            if unexpected_project_children != 0 {
                return Ok(ConditionalWindowDelete::Changed);
            }
        }

        // Project orders are another soft owner. Parse every order with the same strict helper as
        // project deletion, then require the one expected target occurrence and no foreign
        // project occurrence. A malformed order anywhere is an error, never an inferred empty set.
        let project_orders = crate::project::project_window_orders(&tx).map_err(|error| {
            StoreError::Map(format!(
                "fresh-window cleanup could not prove window ownership: {error}"
            ))
        })?;
        let Some(mut order) = project_orders
            .iter()
            .find_map(|(owner, order)| (owner == project_id).then(|| order.clone()))
        else {
            return Ok(ConditionalWindowDelete::Changed);
        };
        let occurrences = order.iter().filter(|id| id.as_str() == window_id).count();
        let foreign_occurrences = project_orders
            .iter()
            .filter(|(owner, _)| owner != project_id)
            .flat_map(|(_, order)| order.iter())
            .filter(|id| id.as_str() == window_id)
            .count();
        if occurrences != usize::from(expected_order_member) || foreign_occurrences != 0 {
            return Ok(ConditionalWindowDelete::Changed);
        }

        // This rollback removes the Session identity (directly or by Project cascade), so any
        // exact live daemon lifetime is recorded with RowMustBeAbsent before graph destruction.
        let exact = exact_release_targets_in_transaction(
            &tx,
            [session_id.to_string()],
            SessionRowPolicy::RowMustBeAbsent,
            pre_resolved,
        )?;
        let release_receipt =
            insert_pending_releases(&tx, &exact.targets, now_ms).map_err(|error| {
                StoreError::Map(format!("journal fresh-window graph release: {error}"))
            })?;
        let release_binding = release_receipt.as_ref().map(PendingReleaseReceipt::binding);

        if expected_new_project.is_some() {
            let removed_project = crate::store_sqlite::delete(&tx, RecordKind::Project, project_id)
                .map_err(|error| StoreError::Map(error.to_string()))?;
            debug_assert!(removed_project);
        } else {
            let removed_layout =
                crate::store_sqlite::delete(&tx, RecordKind::WindowLayout, window_id)
                    .map_err(|error| StoreError::Map(error.to_string()))?;
            debug_assert!(removed_layout);
            #[cfg(test)]
            crate::store_sqlite::run_window_layout_test_hook(
                "after-graph-layout-delete-before-child-cleanup",
                window_id,
            );
            if expected_session.is_some() {
                let removed_session =
                    crate::store_sqlite::delete(&tx, RecordKind::Session, session_id)
                        .map_err(|error| StoreError::Map(error.to_string()))?;
                debug_assert!(removed_session);
            }
            let removed_workspace =
                crate::store_sqlite::delete(&tx, RecordKind::Workspace, workspace_id)
                    .map_err(|error| StoreError::Map(error.to_string()))?;
            debug_assert!(removed_workspace);
            if expected_order_member {
                order.retain(|id| id != window_id);
                let order_json = serde_json::to_string(&order).map_err(|error| {
                    StoreError::Map(format!("serialize project order: {error}"))
                })?;
                tx.execute(
                    "UPDATE projects SET window_order_json = ?2 WHERE project_id = ?1",
                    rusqlite::params![project_id, order_json],
                )
                .map_err(|error| StoreError::Db(error.to_string()))?;
            }
        }
        // This graph may delete a Window, Session, Workspace, and (for a failed fresh-project
        // allocation) Project, but it is one logical ownership mutation and advances the shared
        // epoch exactly once. Any error, including exhaustion, rolls the entire transaction back.
        let window_mutation_epoch = crate::db::bump_window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;

        crate::write_trace::trace_delete(self.paths.base(), "WindowLayout", window_id, now_ms);
        if expected_session.is_some() {
            crate::write_trace::trace_delete(self.paths.base(), "Session", session_id, now_ms);
        }
        crate::write_trace::trace_delete(self.paths.base(), "Workspace", workspace_id, now_ms);
        if expected_new_project.is_some() {
            crate::write_trace::trace_delete(self.paths.base(), "Project", project_id, now_ms);
        } else if expected_order_member {
            crate::write_trace::trace_write(
                self.paths.base(),
                "Project",
                project_id,
                &["window_order".into()],
                now_ms,
            );
        }
        Ok(ConditionalWindowDelete::Deleted(WindowDeletionReceipt {
            window_id: window_id.to_string(),
            deleted_revision: current_layout.revision,
            deleted_snapshot_fingerprint,
            window_mutation_epoch,
            window_only_restore: false,
            release_binding,
            release_receipt,
            unresolved_release_session_ids: exact.unresolved_session_ids,
        }))
    }

    /// Restore a snapshot after an external daemon-commit failure, but only when it still matches
    /// the exact private receipt fingerprint, the window id is absent, AND no window mutation has
    /// committed since deletion. Layout and owner are restored in one SQLite transaction. A
    /// caller-mutated snapshot is rejected before DB work; a recreate-then-delete ABA advances the
    /// clock and therefore cannot cause an older incarnation to be resurrected.
    /// Legacy compensation for a deletion that carried no daemon-release operation. A receipt
    /// bound to journal work is categorically forward-only here; only the capability-bearing
    /// method below can atomically cancel that work and restore the window.
    pub fn restore_if_absent(
        &self,
        expected: &WindowLayoutSnapshot,
        receipt: &WindowDeletionReceipt,
        now_ms: u64,
    ) -> Result<ConditionalWindowRestore, WindowLayoutError> {
        if !receipt.window_only_restore || receipt.release_binding.is_some() {
            return Ok(ConditionalWindowRestore::Changed);
        }
        let window_id = expected.layout.window_id.as_str();
        let expected_fingerprint = window_layout_snapshot_fingerprint(expected)?;
        if receipt.window_id != window_id
            || receipt.deleted_revision != expected.revision
            || receipt.deleted_snapshot_fingerprint != expected_fingerprint
            || !receipt.window_only_restore
        {
            return Err(WindowLayoutError::Store(StoreError::Map(
                "window deletion receipt does not match the exact deleted snapshot".into(),
            )));
        }
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if Self::load_snapshot_from_connection(&tx, window_id)?.is_some() {
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            return Ok(ConditionalWindowRestore::AlreadyPresent);
        }
        let current_epoch = crate::db::window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if current_epoch != receipt.window_mutation_epoch {
            return Ok(ConditionalWindowRestore::Changed);
        }
        let value = serde_json::to_value(&expected.layout)
            .map_err(|error| StoreError::Map(format!("serialize record: {error}")))?;
        crate::store_sqlite::upsert(&tx, RecordKind::WindowLayout, window_id, &value)
            .map_err(|error| StoreError::Map(error.to_string()))?;
        if let Some(project_id) = expected.project_id.as_deref() {
            crate::store_sqlite::set_window_project(&tx, window_id, project_id)
                .map_err(|error| StoreError::Map(error.to_string()))?;
        }
        crate::db::bump_window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let fields = value
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        crate::write_trace::trace_write(
            self.paths.base(),
            "WindowLayout",
            window_id,
            &fields,
            now_ms,
        );
        if expected.project_id.is_some() {
            crate::write_trace::trace_write(
                self.paths.base(),
                "WindowOwner",
                window_id,
                &["project_id".into()],
                now_ms,
            );
        }
        Ok(ConditionalWindowRestore::Restored)
    }

    pub fn restore_and_cancel_release_if_absent(
        &self,
        expected: &WindowLayoutSnapshot,
        receipt: &WindowDeletionReceipt,
        compensation: &UnpublishedCompensationReceipt,
        now_ms: u64,
    ) -> Result<ConditionalWindowRestore, WindowLayoutError> {
        let window_id = expected.layout.window_id.as_str();
        let expected_fingerprint = window_layout_snapshot_fingerprint(expected)?;
        if receipt.window_id != window_id
            || receipt.deleted_revision != expected.revision
            || receipt.deleted_snapshot_fingerprint != expected_fingerprint
            || !receipt.window_only_restore
        {
            return Err(WindowLayoutError::Store(StoreError::Map(
                "window deletion receipt does not match the exact deleted snapshot".into(),
            )));
        }
        let Some(release_binding) = receipt.release_binding.as_ref() else {
            return Err(WindowLayoutError::Store(StoreError::Map(
                "window deletion has no pending release operation to compensate".into(),
            )));
        };
        if !compensation.matches(release_binding) {
            return Err(WindowLayoutError::Store(StoreError::Map(
                "window compensation does not match the exact release operation".into(),
            )));
        }
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if Self::load_snapshot_from_connection(&tx, window_id)?.is_some() {
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            return Ok(ConditionalWindowRestore::AlreadyPresent);
        }
        let current_epoch = crate::db::window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if current_epoch != receipt.window_mutation_epoch {
            return Ok(ConditionalWindowRestore::Changed);
        }

        // Cancellation and restore are one atomic writer transaction. A stale, expired, or
        // reclaimed lease cannot delete another drainer's work and therefore cannot resurrect the
        // window either.
        if !cancel_operation_in_transaction(&tx, compensation).map_err(|error| {
            StoreError::Map(format!(
                "cancel compensated window session release: {error}"
            ))
        })? {
            return Ok(ConditionalWindowRestore::Changed);
        }

        let value = serde_json::to_value(&expected.layout)
            .map_err(|error| StoreError::Map(format!("serialize record: {error}")))?;
        crate::store_sqlite::upsert(&tx, RecordKind::WindowLayout, window_id, &value)
            .map_err(|error| StoreError::Map(error.to_string()))?;
        if let Some(project_id) = expected.project_id.as_deref() {
            crate::store_sqlite::set_window_project(&tx, window_id, project_id)
                .map_err(|error| StoreError::Map(error.to_string()))?;
        }
        crate::db::bump_window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;

        // COMMIT precedes diagnostics; the cached connection mutex stays held so trace ordering is
        // consistent with the central mutation seam. write_trace never calls back into the store.
        let fields = value
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        crate::write_trace::trace_write(
            self.paths.base(),
            "WindowLayout",
            window_id,
            &fields,
            now_ms,
        );
        if expected.project_id.is_some() {
            crate::write_trace::trace_write(
                self.paths.base(),
                "WindowOwner",
                window_id,
                &["project_id".into()],
                now_ms,
            );
        }
        Ok(ConditionalWindowRestore::Restored)
    }

    /// Claim an unowned window for `project_id`, or repair its missing project-order entry when the
    /// FK already names that same project. A foreign FK or foreign project-order reference is a
    /// typed conflict and remains byte-identical.
    pub fn ensure_project_assignment(
        &self,
        window_id: &str,
        project_id: &str,
        now_ms: u64,
    ) -> Result<ConditionalWindowProjectAssignment, WindowLayoutError> {
        self.transact_project_assignment(window_id, None, None, project_id, now_ms)
    }

    /// Load an exact FK + project-order ownership proof from one DEFERRED snapshot.
    ///
    /// This is the reusable validation seam for project-scoped window intents: p1 proof rejects a
    /// p2-owned window and a stale proof's [`WindowLayoutSnapshot`] is rejected by snapshot-aware
    /// mutators after any compliant owner/order change advances the global window epoch. A caller
    /// that needs proof and mutation in literally the same transaction must recheck this predicate
    /// inside its writer transaction, not split the proof from an unconditional write.
    pub fn prove_project_assignment(
        &self,
        window_id: &str,
        expected_project_id: &str,
    ) -> Result<WindowProjectAssignmentProofOutcome, WindowLayoutError> {
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::Project, expected_project_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        if conn.is_autocommit() {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let outcome = Self::prove_project_assignment_from_connection(
                &tx,
                window_id,
                expected_project_id,
            )?;
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            Ok(outcome)
        } else {
            Self::prove_project_assignment_from_connection(&conn, window_id, expected_project_id)
        }
    }

    /// Reassign one exact window snapshot and its project-order membership in a single writer
    /// transaction. `expected_target_project` is supplied by fresh-project creation so unrelated
    /// metadata changes are not silently adopted into rollback authority; existing-project callers
    /// pass `None` and preserve the freshly loaded project fields.
    pub fn assign_project_and_order_if_unchanged(
        &self,
        expected: &WindowLayoutSnapshot,
        expected_target_project: Option<&Project>,
        project_id: &str,
        now_ms: u64,
    ) -> Result<ConditionalWindowProjectAssignment, WindowLayoutError> {
        self.transact_project_assignment(
            &expected.layout.window_id,
            Some(expected),
            expected_target_project,
            project_id,
            now_ms,
        )
    }

    fn transact_project_assignment(
        &self,
        window_id: &str,
        expected: Option<&WindowLayoutSnapshot>,
        expected_target_project: Option<&Project>,
        project_id: &str,
        now_ms: u64,
    ) -> Result<ConditionalWindowProjectAssignment, WindowLayoutError> {
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::Project, project_id)
            .map_err(StoreError::Id)?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let Some(current) = Self::load_snapshot_from_connection(&tx, window_id)? else {
            return Ok(ConditionalWindowProjectAssignment::WindowMissing);
        };
        if expected.is_some_and(|expected| &current != expected) {
            return Ok(ConditionalWindowProjectAssignment::Changed);
        }

        let current_project_value =
            crate::store_sqlite::load_one(&tx, RecordKind::Project, project_id)
                .map_err(|error| StoreError::Map(error.to_string()))?;
        let Some(current_project_value) = current_project_value else {
            return Ok(ConditionalWindowProjectAssignment::ProjectMissing);
        };
        let mut target_project = serde_json::from_value::<Project>(current_project_value)
            .map_err(|error| StoreError::Map(format!("deserialize project: {error}")))?;
        if expected_target_project.is_some_and(|expected| &target_project != expected) {
            return Ok(ConditionalWindowProjectAssignment::Changed);
        }

        let project_orders = crate::project::project_window_orders(&tx).map_err(|error| {
            StoreError::Map(format!("window ownership order proof failed: {error}"))
        })?;
        let ordered_by_project_ids = project_orders
            .iter()
            .filter(|(_, order)| order.iter().any(|id| id == window_id))
            .map(|(owner, _)| owner.clone())
            .collect::<Vec<_>>();
        let expected_old_owner = expected.and_then(|snapshot| snapshot.project_id.as_deref());
        let foreign_fk = expected.is_none()
            && current
                .project_id
                .as_deref()
                .is_some_and(|owner| owner != project_id);
        let foreign_order = ordered_by_project_ids
            .iter()
            .any(|owner| owner != project_id && Some(owner.as_str()) != expected_old_owner);
        if foreign_fk || foreign_order {
            return Ok(ConditionalWindowProjectAssignment::Conflict {
                current_project_id: current.project_id,
                ordered_by_project_ids,
            });
        }

        let mut order_updates = Vec::<(String, Vec<String>)>::new();
        let mut target_order = project_orders
            .iter()
            .find_map(|(owner, order)| (owner == project_id).then(|| order.clone()))
            .ok_or_else(|| {
                StoreError::Map(format!(
                    "target project {project_id:?} disappeared from ownership snapshot"
                ))
            })?;
        if !target_order.iter().any(|id| id == window_id) {
            target_order.push(window_id.to_string());
            order_updates.push((project_id.to_string(), target_order.clone()));
        }
        if let Some(old_owner) = expected_old_owner.filter(|owner| *owner != project_id) {
            if let Some(mut old_order) = project_orders
                .iter()
                .find_map(|(owner, order)| (owner == old_owner).then(|| order.clone()))
            {
                let previous_len = old_order.len();
                old_order.retain(|id| id != window_id);
                if old_order.len() != previous_len {
                    order_updates.push((old_owner.to_string(), old_order));
                }
            }
        }

        let owner_changed = current.project_id.as_deref() != Some(project_id);
        if owner_changed {
            let changed = tx
                .execute(
                    "UPDATE windows SET project_id = ?3 \
                     WHERE window_id = ?1 AND project_id IS ?2",
                    rusqlite::params![window_id, current.project_id.as_deref(), project_id],
                )
                .map_err(|error| StoreError::Db(error.to_string()))?;
            debug_assert_eq!(changed, 1, "writer-local owner CAS must match");
        }
        for (owner, order) in &order_updates {
            let order_json = serde_json::to_string(order)
                .map_err(|error| StoreError::Map(format!("serialize project order: {error}")))?;
            let changed = tx
                .execute(
                    "UPDATE projects SET window_order_json = ?2 WHERE project_id = ?1",
                    rusqlite::params![owner, order_json],
                )
                .map_err(|error| StoreError::Db(error.to_string()))?;
            debug_assert_eq!(changed, 1, "writer-local project order must still exist");
        }
        let order_changed = !order_updates.is_empty();
        target_project.window_order = target_order;
        let revision = if owner_changed || order_changed {
            WindowLayoutRevision {
                window_mutation_epoch: crate::db::bump_window_mutation_epoch(&tx)
                    .map_err(|error| StoreError::Db(error.to_string()))?,
            }
        } else {
            current.revision
        };
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if owner_changed {
            crate::write_trace::trace_write(
                self.paths.base(),
                "WindowOwner",
                window_id,
                &["project_id".into()],
                now_ms,
            );
        }
        for (owner, _) in &order_updates {
            crate::write_trace::trace_write(
                self.paths.base(),
                "Project",
                owner,
                &["window_order".into()],
                now_ms,
            );
        }
        Ok(ConditionalWindowProjectAssignment::Applied(
            WindowProjectAssignment {
                window: WindowLayoutSnapshot {
                    layout: current.layout,
                    project_id: Some(project_id.to_string()),
                    revision,
                },
                project: target_project,
                owner_changed,
                order_changed,
            },
        ))
    }

    fn prove_project_assignment_from_connection(
        conn: &rusqlite::Connection,
        window_id: &str,
        expected_project_id: &str,
    ) -> Result<WindowProjectAssignmentProofOutcome, WindowLayoutError> {
        let Some(window) = Self::load_snapshot_from_connection(conn, window_id)? else {
            return Ok(WindowProjectAssignmentProofOutcome::WindowMissing);
        };
        let Some(project_value) =
            crate::store_sqlite::load_one(conn, RecordKind::Project, expected_project_id)
                .map_err(|error| StoreError::Map(error.to_string()))?
        else {
            return Ok(WindowProjectAssignmentProofOutcome::ProjectMissing);
        };
        let project = serde_json::from_value::<Project>(project_value)
            .map_err(|error| StoreError::Map(format!("deserialize project: {error}")))?;
        let project_orders = crate::project::project_window_orders(conn).map_err(|error| {
            StoreError::Map(format!("window ownership order proof failed: {error}"))
        })?;
        let ordered_by_project_ids = project_orders
            .iter()
            .filter(|(_, order)| order.iter().any(|id| id == window_id))
            .map(|(owner, _)| owner.clone())
            .collect::<Vec<_>>();
        let exact_order =
            ordered_by_project_ids.len() == 1 && ordered_by_project_ids[0] == expected_project_id;
        if window.project_id.as_deref() != Some(expected_project_id) || !exact_order {
            return Ok(WindowProjectAssignmentProofOutcome::Conflict {
                current_project_id: window.project_id,
                ordered_by_project_ids,
            });
        }
        Ok(WindowProjectAssignmentProofOutcome::Proven(
            WindowProjectAssignmentProof { window, project },
        ))
    }

    /// Snapshot-aware rename used by fresh-create flows. A replacement incarnation is never
    /// adopted merely because it reused the same public window id.
    pub fn rename_window_if_unchanged(
        &self,
        expected: &WindowLayoutSnapshot,
        name: &str,
        now_ms: u64,
    ) -> Result<WindowLayoutSnapshot, WindowLayoutError> {
        self.mutate_expected_snapshot(expected, now_ms, |layout| {
            layout.name = Some(name.trim().to_string());
            Ok(())
        })
    }

    /// Snapshot-aware first-tab creation used by fresh-create flows.
    #[allow(clippy::too_many_arguments)]
    pub fn open_tab_if_unchanged(
        &self,
        expected: &WindowLayoutSnapshot,
        tab_id: &str,
        session_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
        now_ms: u64,
    ) -> Result<WindowLayoutSnapshot, WindowLayoutError> {
        let window_id = expected.layout.window_id.clone();
        self.mutate_expected_snapshot(expected, now_ms, |layout| {
            if layout.tabs.iter().any(|tab| tab.tab_id == tab_id) {
                return Err(WindowLayoutError::TabAlreadyExists {
                    window_id: window_id.clone(),
                    tab_id: tab_id.to_string(),
                });
            }
            let next_index = layout
                .tabs
                .iter()
                .map(|tab| tab.index)
                .max()
                .map_or(0, |max| max + 1);
            let sibling_titles = layout
                .tabs
                .iter()
                .map(|tab| tab.title.clone())
                .collect::<Vec<_>>();
            layout.tabs.push(TabRecord {
                tab_id: tab_id.to_string(),
                session_id: session_id.to_string(),
                index: next_index,
                title: crate::unique_name(title, &sibling_titles),
                pinned,
                attention,
                split_from: None,
                pane_rect: None,
                stashed_from: None,
                stashed: false,
            });
            Ok(())
        })
    }

    /// Prepare a headless Session for a brand-new AgentTask. The Draft task and canonical Unknown
    /// Session are inserted together under one writer fence; an existing task/session identity or
    /// any pre-existing soft owner is a no-write refusal.
    pub(crate) fn prepare_new_agent_task_unplaced_session(
        &self,
        expected_project: &Project,
        expected_workspace: &Workspace,
        draft: AgentTask,
        session: PreparedSessionSpec,
    ) -> Result<PreparedAgentTaskSessionStart, WindowLayoutError> {
        self.prepare_agent_task_unplaced_session(
            expected_project,
            expected_workspace,
            draft,
            true,
            session,
        )
    }

    /// Prepare a headless Session for one exact existing AgentTask. The task remains byte-equal A
    /// until a Grid-proven final transaction publishes both Session Live(G) and Task Running B.
    pub(crate) fn prepare_resumed_agent_task_unplaced_session(
        &self,
        expected_project: &Project,
        expected_workspace: &Workspace,
        expected_task: AgentTask,
        session: PreparedSessionSpec,
    ) -> Result<PreparedAgentTaskSessionStart, WindowLayoutError> {
        self.prepare_agent_task_unplaced_session(
            expected_project,
            expected_workspace,
            expected_task,
            false,
            session,
        )
    }

    fn prepare_agent_task_unplaced_session(
        &self,
        expected_project: &Project,
        expected_workspace: &Workspace,
        task_before: AgentTask,
        insert_task: bool,
        session: PreparedSessionSpec,
    ) -> Result<PreparedAgentTaskSessionStart, WindowLayoutError> {
        let (mut params, publication_launch, binding, worktree_provenance_seal) =
            session.into_parts();
        if params.kind != SessionKind::Agent
            || task_before.project_id != expected_project.project_id
            || expected_workspace.project_id != expected_project.project_id
        {
            return Err(WindowLayoutError::AgentTaskChanged {
                agent_task_id: task_before.agent_task_id,
            });
        }
        crate::validate_id(&task_before.agent_task_id).map_err(StoreError::Id)?;
        params.agent_task_id = Some(task_before.agent_task_id.clone());
        let unknown = canonical_prepared_unknown_with_agent_task(
            &params,
            &publication_launch,
            binding,
            Some(&task_before.agent_task_id),
        )?;
        if expected_workspace.workspace_id != unknown.workspace_id {
            return Err(WindowLayoutError::WorkspaceChanged {
                workspace_id: expected_workspace.workspace_id.clone(),
            });
        }
        if insert_task
            && (task_before.state != AgentTaskState::Draft
                || task_before.current_session_id.is_some()
                || !task_before.session_history.is_empty()
                || task_before.result_summary.is_some()
                || task_before.created_at_ms != params.now_ms
                || task_before.updated_at_ms != params.now_ms)
        {
            return Err(WindowLayoutError::AgentTaskChanged {
                agent_task_id: task_before.agent_task_id,
            });
        }
        let mut task_after = task_before.clone();
        if let Some(previous) = task_after.current_session_id.take() {
            if previous != unknown.session_id {
                task_after.session_history.push(previous);
            }
        }
        task_after.state = AgentTaskState::Running;
        task_after.current_session_id = Some(unknown.session_id.clone());
        task_after.result_summary = None;
        task_after.updated_at_ms = params.now_ms;

        let created_at_ms = prepared_agent_task_journal_clock_ms()?;
        let lease_until_ms = created_at_ms
            .checked_add(AGENT_TASK_START_JOURNAL_LEASE_MS)
            .ok_or_else(|| {
                WindowLayoutError::Store(StoreError::Map(
                    "prepared AgentTask journal lease timestamp overflow".into(),
                ))
            })?;
        let operation_token: SessionStartOperationToken = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .parse()
            .map_err(|error| {
                WindowLayoutError::Store(StoreError::Map(format!(
                    "construct prepared AgentTask operation token: {error}"
                )))
            })?;
        let journal = PreparedAgentTaskStartJournalReceipt {
            session_id: unknown.session_id.clone(),
            agent_task_id: task_before.agent_task_id.clone(),
            project_id: expected_project.project_id.clone(),
            workspace_id: expected_workspace.workspace_id.clone(),
            operation_token,
            daemon_instance_id: None,
            server_pid: None,
            socket_path: None,
            session_a_sha256: prepared_agent_task_journal_fingerprint(&unknown)?,
            task_a_sha256: prepared_agent_task_journal_fingerprint(&task_before)?,
            project_sha256: prepared_agent_task_journal_fingerprint(expected_project)?,
            workspace_sha256: prepared_agent_task_journal_fingerprint(expected_workspace)?,
            publication_launch_json: serde_json::to_string(&publication_launch).map_err(
                |error| StoreError::Map(format!("serialize publication launch: {error}")),
            )?,
            publication_now_ms: params.now_ms,
            disposition: "finalize".into(),
            applied_generation: None,
            applied_state: None,
            created_at_ms,
            lease_token: uuid::Uuid::new_v4().to_string(),
            lease_until_ms,
        };

        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let project = load_graph_record_for_prepared::<Project>(
            &tx,
            RecordKind::Project,
            &expected_project.project_id,
            "Project",
        )?;
        let workspace = load_graph_record_for_prepared::<Workspace>(
            &tx,
            RecordKind::Workspace,
            &expected_workspace.workspace_id,
            "Workspace",
        )?;
        if project.as_ref() != Some(expected_project)
            || workspace.as_ref() != Some(expected_workspace)
        {
            return Err(WindowLayoutError::WorkspaceChanged {
                workspace_id: expected_workspace.workspace_id.clone(),
            });
        }
        let worktree_provenance = complete_prepared_worktree_provenance(
            worktree_provenance_seal.as_ref(),
            expected_workspace,
            &unknown,
        )?;
        let current_task = load_graph_record_for_prepared::<AgentTask>(
            &tx,
            RecordKind::AgentTask,
            &task_before.agent_task_id,
            "AgentTask",
        )?;
        if insert_task {
            if current_task.is_some() {
                return Err(WindowLayoutError::AgentTaskAlreadyExists {
                    agent_task_id: task_before.agent_task_id,
                });
            }
        } else if current_task.as_ref() != Some(&task_before) {
            return Err(WindowLayoutError::AgentTaskChanged {
                agent_task_id: task_before.agent_task_id,
            });
        }
        if !agent_task_session_cohort_matches(&tx, &task_before)? {
            return Err(WindowLayoutError::AgentTaskChanged {
                agent_task_id: task_before.agent_task_id,
            });
        }
        if crate::store_sqlite::load_one(&tx, RecordKind::Session, &unknown.session_id)
            .map_err(|error| StoreError::Map(error.to_string()))?
            .is_some()
        {
            return Err(WindowLayoutError::SessionAlreadyExists {
                session_id: unknown.session_id,
            });
        }
        if !prepared_absent_session_namespace_matches(
            &tx,
            &unknown.session_id,
            worktree_provenance.as_ref(),
        )? {
            return Err(WindowLayoutError::SessionIdentityReferenced {
                session_id: unknown.session_id,
            });
        }
        let task_value = serde_json::to_value(&task_before)
            .map_err(|error| StoreError::Map(format!("serialize AgentTask: {error}")))?;
        if insert_task {
            crate::store_sqlite::upsert(
                &tx,
                RecordKind::AgentTask,
                &task_before.agent_task_id,
                &task_value,
            )
            .map_err(|error| StoreError::Map(error.to_string()))?;
        }
        let session_value = serde_json::to_value(&unknown)
            .map_err(|error| StoreError::Map(format!("serialize Session: {error}")))?;
        if !crate::store_sqlite::insert_fresh_session(&tx, &unknown.session_id, &session_value)
            .map_err(|error| StoreError::Map(error.to_string()))?
        {
            return Err(WindowLayoutError::SessionAlreadyExists {
                session_id: unknown.session_id,
            });
        }
        tx.execute(
            "INSERT INTO pending_agent_task_starts \
             (session_id, agent_task_id, project_id, workspace_id, operation_token, \
              binding_state, daemon_instance_id, server_pid, socket_path, session_a_sha256, \
              task_a_sha256, project_sha256, workspace_sha256, publication_launch_json, \
              publication_now_ms, disposition, applied_generation, applied_state, created_at_ms, \
              lease_token, lease_until_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, 'unbound', NULL, NULL, NULL, ?6, ?7, ?8, ?9, ?10, \
                     ?11, 'finalize', NULL, NULL, ?12, ?13, ?14)",
            rusqlite::params![
                journal.session_id,
                journal.agent_task_id,
                expected_project.project_id,
                expected_workspace.workspace_id,
                journal.operation_token.as_str(),
                journal.session_a_sha256.as_slice(),
                journal.task_a_sha256.as_slice(),
                journal.project_sha256.as_slice(),
                journal.workspace_sha256.as_slice(),
                journal.publication_launch_json,
                i64::try_from(journal.publication_now_ms).map_err(|_| {
                    StoreError::Map("publication timestamp exceeds SQLite i64".into())
                })?,
                i64::try_from(journal.created_at_ms)
                    .map_err(|_| StoreError::Map("journal timestamp exceeds SQLite i64".into()))?,
                journal.lease_token,
                i64::try_from(journal.lease_until_ms)
                    .map_err(|_| StoreError::Map("journal lease exceeds SQLite i64".into()))?,
            ],
        )
        .map_err(|error| StoreError::Db(error.to_string()))?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if insert_task {
            crate::write_trace::trace_write(
                self.paths.base(),
                "AgentTask",
                &task_before.agent_task_id,
                &trace_fields(&task_value),
                params.now_ms,
            );
        }
        crate::write_trace::trace_write(
            self.paths.base(),
            "Session",
            &unknown.session_id,
            &trace_fields(&session_value),
            params.now_ms,
        );
        Ok(PreparedAgentTaskSessionStart {
            journal,
            start: PreparedNewSessionStart {
                unknown,
                workspace: expected_workspace.clone(),
                params,
                publication_launch,
                binding,
                worktree_provenance,
                placement: PreparedNewSessionPlacement::Unplaced {
                    project: expected_project.clone(),
                },
                agent_task: Some(PreparedAgentTaskTransition {
                    before: task_before,
                    after: task_after,
                }),
            },
        })
    }

    /// Insert one taskless canonical `Unknown` Session without creating layout topology. The exact
    /// Project and Workspace remain sealed in the consume-once start so pre-wire, final publication,
    /// and definitely-unpublished compensation all revalidate the same ownership graph.
    pub fn prepare_unplaced_session_with_spec(
        &self,
        expected_project: &Project,
        expected_workspace: &Workspace,
        session: PreparedSessionSpec,
    ) -> Result<PreparedNewSessionStart, WindowLayoutError> {
        let (params, publication_launch, binding, worktree_provenance_seal) = session.into_parts();
        let unknown = canonical_prepared_unknown(&params, &publication_launch, binding)?;
        if expected_workspace.workspace_id != unknown.workspace_id
            || expected_workspace.project_id != expected_project.project_id
        {
            return Err(WindowLayoutError::WorkspaceChanged {
                workspace_id: expected_workspace.workspace_id.clone(),
            });
        }

        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let project = load_graph_record_for_prepared::<Project>(
            &tx,
            RecordKind::Project,
            &expected_project.project_id,
            "Project",
        )?;
        let workspace = load_graph_record_for_prepared::<Workspace>(
            &tx,
            RecordKind::Workspace,
            &expected_workspace.workspace_id,
            "Workspace",
        )?;
        if project.as_ref() != Some(expected_project)
            || workspace.as_ref() != Some(expected_workspace)
        {
            return Err(WindowLayoutError::WorkspaceChanged {
                workspace_id: expected_workspace.workspace_id.clone(),
            });
        }
        let worktree_provenance = complete_prepared_worktree_provenance(
            worktree_provenance_seal.as_ref(),
            expected_workspace,
            &unknown,
        )?;
        if crate::store_sqlite::load_one(&tx, RecordKind::Session, &unknown.session_id)
            .map_err(|error| StoreError::Map(error.to_string()))?
            .is_some()
        {
            return Err(WindowLayoutError::SessionAlreadyExists {
                session_id: unknown.session_id,
            });
        }
        if !prepared_absent_session_namespace_matches(
            &tx,
            &unknown.session_id,
            worktree_provenance.as_ref(),
        )? {
            return Err(WindowLayoutError::SessionIdentityReferenced {
                session_id: unknown.session_id,
            });
        }
        let session_value = serde_json::to_value(&unknown)
            .map_err(|error| StoreError::Map(format!("serialize Session: {error}")))?;
        if !crate::store_sqlite::insert_fresh_session(&tx, &unknown.session_id, &session_value)
            .map_err(|error| StoreError::Map(error.to_string()))?
        {
            return Err(WindowLayoutError::SessionAlreadyExists {
                session_id: unknown.session_id,
            });
        }
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        crate::write_trace::trace_write(
            self.paths.base(),
            "Session",
            &unknown.session_id,
            &trace_fields(&session_value),
            params.now_ms,
        );
        Ok(PreparedNewSessionStart {
            unknown,
            workspace: expected_workspace.clone(),
            params,
            publication_launch,
            binding,
            worktree_provenance,
            placement: PreparedNewSessionPlacement::Unplaced {
                project: expected_project.clone(),
            },
            agent_task: None,
        })
    }

    /// Insert the canonical `Unknown` Session and its ordinary tab in one writer transaction.
    /// The exact Workspace, complete pre-mutation window snapshot, ownership/order signals, and
    /// absent soft-reference namespace are all checked before either row becomes observable.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_new_tab_session(
        &self,
        expected_window: &WindowLayoutSnapshot,
        expected_project: &Project,
        expected_workspace: &Workspace,
        params: StartParams,
        tab_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
    ) -> Result<PreparedNewSessionStart, WindowLayoutError> {
        self.prepare_new_tab_session_with_spec(
            expected_window,
            expected_project,
            expected_workspace,
            PreparedSessionSpec::from_legacy_shell(params),
            tab_id,
            title,
            pinned,
            attention,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_new_tab_session_with_spec(
        &self,
        expected_window: &WindowLayoutSnapshot,
        expected_project: &Project,
        expected_workspace: &Workspace,
        session: PreparedSessionSpec,
        tab_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
    ) -> Result<PreparedNewSessionStart, WindowLayoutError> {
        self.prepare_new_session_in_existing_window(
            expected_window,
            expected_project,
            expected_workspace,
            session,
            tab_id,
            PreparedExistingWindowPlacement::Open {
                title,
                pinned,
                attention,
                stashed: false,
            },
        )
    }

    /// Insert a browser-owned session as a stashed tab without changing the visible local desktop
    /// split geometry. This shares the exact prepared transaction and compensation authority of an
    /// ordinary tab; only the durable placement bit differs.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_new_stashed_tab_session_with_spec(
        &self,
        expected_window: &WindowLayoutSnapshot,
        expected_project: &Project,
        expected_workspace: &Workspace,
        session: PreparedSessionSpec,
        tab_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
    ) -> Result<PreparedNewSessionStart, WindowLayoutError> {
        self.prepare_new_session_in_existing_window(
            expected_window,
            expected_project,
            expected_workspace,
            session,
            tab_id,
            PreparedExistingWindowPlacement::Open {
                title,
                pinned,
                attention,
                stashed: true,
            },
        )
    }

    /// Split one exact existing pane while inserting the split child's canonical `Unknown`
    /// Session. Layout geometry and the insert-only Session identity commit under one epoch bump.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_new_split_session(
        &self,
        expected_window: &WindowLayoutSnapshot,
        expected_project: &Project,
        expected_workspace: &Workspace,
        params: StartParams,
        from_tab_id: &str,
        tab_id: &str,
        title: &str,
        axis: SplitAxis,
    ) -> Result<PreparedNewSessionStart, WindowLayoutError> {
        self.prepare_new_split_session_with_spec(
            expected_window,
            expected_project,
            expected_workspace,
            PreparedSessionSpec::from_legacy_shell(params),
            from_tab_id,
            tab_id,
            title,
            axis,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_new_split_session_with_spec(
        &self,
        expected_window: &WindowLayoutSnapshot,
        expected_project: &Project,
        expected_workspace: &Workspace,
        session: PreparedSessionSpec,
        from_tab_id: &str,
        tab_id: &str,
        title: &str,
        axis: SplitAxis,
    ) -> Result<PreparedNewSessionStart, WindowLayoutError> {
        self.prepare_new_session_in_existing_window(
            expected_window,
            expected_project,
            expected_workspace,
            session,
            tab_id,
            PreparedExistingWindowPlacement::Split {
                from_tab_id,
                expected_source_session: None,
                title,
                axis,
            },
        )
    }

    /// Split a pane whose exact Session authorizes inheriting the child's Workspace.
    ///
    /// The source tab edge, full source Session row, and Workspace identity are checked in the
    /// same `BEGIN IMMEDIATE` transaction that inserts the child. They remain sealed into the
    /// authority so pre-wire and final publication checks also refuse a later source retarget.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_new_split_session_from_source(
        &self,
        expected_window: &WindowLayoutSnapshot,
        expected_project: &Project,
        expected_workspace: &Workspace,
        expected_source_session: &SessionRecord,
        params: StartParams,
        from_tab_id: &str,
        tab_id: &str,
        title: &str,
        axis: SplitAxis,
    ) -> Result<PreparedNewSessionStart, WindowLayoutError> {
        self.prepare_new_split_session_from_source_with_spec(
            expected_window,
            expected_project,
            expected_workspace,
            expected_source_session,
            PreparedSessionSpec::from_legacy_shell(params),
            from_tab_id,
            tab_id,
            title,
            axis,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn prepare_new_split_session_from_source_with_spec(
        &self,
        expected_window: &WindowLayoutSnapshot,
        expected_project: &Project,
        expected_workspace: &Workspace,
        expected_source_session: &SessionRecord,
        session: PreparedSessionSpec,
        from_tab_id: &str,
        tab_id: &str,
        title: &str,
        axis: SplitAxis,
    ) -> Result<PreparedNewSessionStart, WindowLayoutError> {
        self.prepare_new_session_in_existing_window(
            expected_window,
            expected_project,
            expected_workspace,
            session,
            tab_id,
            PreparedExistingWindowPlacement::Split {
                from_tab_id,
                expected_source_session: Some(expected_source_session),
                title,
                axis,
            },
        )
    }

    fn prepare_new_session_in_existing_window(
        &self,
        expected_window: &WindowLayoutSnapshot,
        expected_project: &Project,
        expected_workspace: &Workspace,
        session: PreparedSessionSpec,
        tab_id: &str,
        placement: PreparedExistingWindowPlacement<'_>,
    ) -> Result<PreparedNewSessionStart, WindowLayoutError> {
        let (params, publication_launch, binding, worktree_provenance_seal) = session.into_parts();
        let unknown = canonical_prepared_unknown(&params, &publication_launch, binding)?;
        let window_id = expected_window.layout.window_id.as_str();
        crate::validate_id(tab_id).map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::Session, &unknown.session_id)
            .map_err(StoreError::Id)?;
        self.paths
            .record_path(RecordKind::Workspace, &expected_workspace.workspace_id)
            .map_err(StoreError::Id)?;
        if expected_workspace.workspace_id != unknown.workspace_id {
            return Err(WindowLayoutError::WorkspaceChanged {
                workspace_id: expected_workspace.workspace_id.clone(),
            });
        }
        if let PreparedExistingWindowPlacement::Split {
            from_tab_id,
            expected_source_session: Some(source),
            ..
        } = &placement
        {
            let source_tabs = expected_window
                .layout
                .tabs
                .iter()
                .filter(|tab| tab.tab_id == *from_tab_id)
                .collect::<Vec<_>>();
            if source.workspace_id != expected_workspace.workspace_id
                || source_tabs.len() != 1
                || source_tabs[0].stashed
                || source_tabs[0].session_id != source.session_id
            {
                return Err(WindowLayoutError::WindowLayoutChanged {
                    window_id: window_id.to_string(),
                });
            }
        }
        let Some(project_id) = expected_window.project_id.as_deref() else {
            return Err(WindowLayoutError::Store(StoreError::Map(format!(
                "prepared window {window_id:?} has no exact Project owner"
            ))));
        };
        if expected_project.project_id != project_id || expected_workspace.project_id != project_id
        {
            return Err(WindowLayoutError::WorkspaceChanged {
                workspace_id: expected_workspace.workspace_id.clone(),
            });
        }

        fresh_graph_stage(window_id, "before-prepared-session-transaction")?;
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        fresh_graph_stage(window_id, "after-prepared-session-begin")?;

        let current_window = Self::load_snapshot_from_connection(&tx, window_id)?;
        if current_window.as_ref() != Some(expected_window) {
            return Err(WindowLayoutError::WindowLayoutChanged {
                window_id: window_id.to_string(),
            });
        }
        let current_workspace = load_graph_record_for_prepared::<Workspace>(
            &tx,
            RecordKind::Workspace,
            &expected_workspace.workspace_id,
            "Workspace",
        )?;
        if current_workspace.as_ref() != Some(expected_workspace) {
            return Err(WindowLayoutError::WorkspaceChanged {
                workspace_id: expected_workspace.workspace_id.clone(),
            });
        }
        let worktree_provenance = complete_prepared_worktree_provenance(
            worktree_provenance_seal.as_ref(),
            expected_workspace,
            &unknown,
        )?;
        let current_project = load_graph_record_for_prepared::<Project>(
            &tx,
            RecordKind::Project,
            &expected_project.project_id,
            "Project",
        )?;
        if current_project.as_ref() != Some(expected_project) {
            return Err(WindowLayoutError::WindowLayoutChanged {
                window_id: window_id.to_string(),
            });
        }
        if let PreparedExistingWindowPlacement::Split {
            expected_source_session: Some(source),
            ..
        } = &placement
        {
            let current_source = load_graph_record_for_prepared::<SessionRecord>(
                &tx,
                RecordKind::Session,
                &source.session_id,
                "split source Session",
            )?;
            if current_source.as_ref() != Some(*source) {
                return Err(WindowLayoutError::WindowLayoutChanged {
                    window_id: window_id.to_string(),
                });
            }
        }
        if !prepared_project_order_matches(&tx, window_id, project_id)? {
            return Err(WindowLayoutError::WindowLayoutChanged {
                window_id: window_id.to_string(),
            });
        }
        if crate::store_sqlite::load_one(&tx, RecordKind::Session, &unknown.session_id)
            .map_err(|error| StoreError::Map(error.to_string()))?
            .is_some()
        {
            return Err(WindowLayoutError::SessionAlreadyExists {
                session_id: unknown.session_id.clone(),
            });
        }
        if !prepared_absent_session_namespace_matches(
            &tx,
            &unknown.session_id,
            worktree_provenance.as_ref(),
        )? {
            return Err(WindowLayoutError::SessionIdentityReferenced {
                session_id: unknown.session_id.clone(),
            });
        }

        let split_source = match &placement {
            PreparedExistingWindowPlacement::Split {
                from_tab_id,
                expected_source_session: Some(source),
                ..
            } => Some(PreparedSplitSource {
                tab_id: (*from_tab_id).to_string(),
                session: (*source).clone(),
            }),
            _ => None,
        };
        let mut layout = current_window
            .expect("exact window equality proved a current row")
            .layout;
        match placement {
            PreparedExistingWindowPlacement::Open {
                title,
                pinned,
                attention,
                stashed,
            } => apply_prepared_open_tab(
                &mut layout,
                tab_id,
                &unknown.session_id,
                title,
                pinned,
                attention,
                stashed,
            )?,
            PreparedExistingWindowPlacement::Split {
                from_tab_id,
                expected_source_session: _,
                title,
                axis,
            } => apply_prepared_split_tab(
                &mut layout,
                from_tab_id,
                tab_id,
                &unknown.session_id,
                title,
                axis,
            )?,
        }
        for (index, tab) in layout.tabs.iter_mut().enumerate() {
            tab.index = index as u32;
        }
        crate::db::preflight_window_mutation_epoch_bump(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let session_value = serde_json::to_value(&unknown)
            .map_err(|error| StoreError::Map(format!("serialize Session: {error}")))?;
        if !crate::store_sqlite::insert_fresh_session(&tx, &unknown.session_id, &session_value)
            .map_err(|error| StoreError::Map(error.to_string()))?
        {
            return Err(WindowLayoutError::SessionAlreadyExists {
                session_id: unknown.session_id.clone(),
            });
        }
        let layout_value = serde_json::to_value(&layout)
            .map_err(|error| StoreError::Map(format!("serialize WindowLayout: {error}")))?;
        crate::store_sqlite::upsert(&tx, RecordKind::WindowLayout, window_id, &layout_value)
            .map_err(|error| StoreError::Map(error.to_string()))?;
        let window_mutation_epoch = crate::db::bump_window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let post_layout = WindowLayoutSnapshot {
            layout,
            project_id: Some(project_id.to_string()),
            revision: WindowLayoutRevision {
                window_mutation_epoch,
            },
        };
        let start = PreparedNewSessionStart {
            unknown,
            workspace: expected_workspace.clone(),
            params,
            publication_launch,
            binding,
            worktree_provenance,
            placement: PreparedNewSessionPlacement::ExistingWindow {
                project: expected_project.clone(),
                post_layout,
                tab_id: tab_id.to_string(),
                split_source,
            },
            agent_task: None,
        };
        fresh_graph_stage(window_id, "before-prepared-session-commit")?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;

        crate::write_trace::trace_write(
            self.paths.base(),
            "Session",
            start.session_id(),
            &trace_fields(&session_value),
            start.params.now_ms,
        );
        crate::write_trace::trace_write(
            self.paths.base(),
            "WindowLayout",
            window_id,
            &trace_fields(&layout_value),
            start.params.now_ms,
        );
        Ok(start)
    }

    /// Rename the window itself. This is intentionally separate from [`rename_tab`]: window chrome
    /// and pane labels are different product concepts.
    pub fn rename_window(
        &self,
        window_id: &str,
        name: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_existing(window_id, now_ms, |layout| {
            layout.name = Some(name.trim().to_string());
            Ok(())
        })
    }

    /// Open a new tab at the END of the window (its pre-normalization index is `max + 1`), then
    /// renormalize. Fails with [`WindowLayoutError::TabAlreadyExists`] (no rewrite) on a
    /// duplicate `tab_id`, and [`WindowLayoutError::WindowLayoutNotFound`] if the window has no
    /// layout. Does NOT verify `session_id` exists.
    #[allow(clippy::too_many_arguments)]
    pub fn open_tab(
        &self,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.open_tab_with_stash_state(
            window_id, tab_id, session_id, title, pinned, attention, false, now_ms,
        )
    }

    /// [`open_tab`](Self::open_tab), returning the exact committed layout incarnation for an
    /// atomic created-tab + Session rollback if a later renderer publication fails.
    #[allow(clippy::too_many_arguments)]
    pub fn open_tab_snapshot(
        &self,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
        now_ms: u64,
    ) -> Result<WindowLayoutSnapshot, WindowLayoutError> {
        self.open_tab_with_stash_state_snapshot(
            window_id, tab_id, session_id, title, pinned, attention, false, now_ms,
        )
    }

    /// Open a new tab that starts stashed. This is for remote/browser existence records: the pane
    /// belongs under the window in the sidebar, but it must not mutate the local desktop split geometry.
    #[allow(clippy::too_many_arguments)]
    pub fn open_stashed_tab(
        &self,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.open_tab_with_stash_state(
            window_id, tab_id, session_id, title, pinned, attention, true, now_ms,
        )
    }

    /// [`open_stashed_tab`](Self::open_stashed_tab), returning the exact committed incarnation so
    /// a failed daemon start can conditionally close this tab without adopting a same-id rewrite.
    #[allow(clippy::too_many_arguments)]
    pub fn open_stashed_tab_snapshot(
        &self,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
        now_ms: u64,
    ) -> Result<WindowLayoutSnapshot, WindowLayoutError> {
        self.open_tab_with_stash_state_snapshot(
            window_id, tab_id, session_id, title, pinned, attention, true, now_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn open_tab_with_stash_state(
        &self,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
        stashed: bool,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        Ok(self
            .open_tab_with_stash_state_snapshot(
                window_id, tab_id, session_id, title, pinned, attention, stashed, now_ms,
            )?
            .layout)
    }

    #[allow(clippy::too_many_arguments)]
    fn open_tab_with_stash_state_snapshot(
        &self,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        pinned: bool,
        attention: AttentionState,
        stashed: bool,
        now_ms: u64,
    ) -> Result<WindowLayoutSnapshot, WindowLayoutError> {
        self.mutate_existing_snapshot(window_id, now_ms, |layout| {
            if layout.tabs.iter().any(|t| t.tab_id == tab_id) {
                return Err(WindowLayoutError::TabAlreadyExists {
                    window_id: window_id.to_string(),
                    tab_id: tab_id.to_string(),
                });
            }
            let next_index = layout
                .tabs
                .iter()
                .map(|t| t.index)
                .max()
                .map_or(0, |m| m + 1);
            // Keep pane titles unique within the window (auto-number collisions). The new tab isn't in `tabs` yet, so all
            // current tabs are siblings.
            let sibling_titles: Vec<String> = layout.tabs.iter().map(|t| t.title.clone()).collect();
            let title = crate::unique_name(title, &sibling_titles);
            layout.tabs.push(TabRecord {
                tab_id: tab_id.to_string(),
                session_id: session_id.to_string(),
                index: next_index,
                title,
                pinned,
                attention,
                split_from: None,
                pane_rect: None,
                stashed_from: None,
                stashed,
            });
            Ok(())
        })
    }

    /// Split an existing tab: add a NEW tab at the end of the window that records it was split
    /// from `from_tab_id` along `axis`. The source tab must exist; the new `tab_id` must not
    /// already exist. Preserves tab order (the new tab lands last, like `open_tab`) and renormalizes
    /// indices. Storage/headless only — no pane geometry, no session spawning, no `session_id`
    /// existence check. Returns the updated layout.
    #[allow(clippy::too_many_arguments)]
    pub fn split_tab(
        &self,
        window_id: &str,
        from_tab_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        axis: SplitAxis,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        Ok(self
            .split_tab_snapshot(
                window_id,
                from_tab_id,
                tab_id,
                session_id,
                title,
                axis,
                now_ms,
            )?
            .layout)
    }

    /// [`split_tab`](Self::split_tab), returning the exact committed layout incarnation for a
    /// conditional rollback if the subsequent daemon start fails.
    #[allow(clippy::too_many_arguments)]
    pub fn split_tab_snapshot(
        &self,
        window_id: &str,
        from_tab_id: &str,
        tab_id: &str,
        session_id: &str,
        title: &str,
        axis: SplitAxis,
        now_ms: u64,
    ) -> Result<WindowLayoutSnapshot, WindowLayoutError> {
        self.mutate_existing_snapshot(window_id, now_ms, |layout| {
            if !layout.tabs.iter().any(|t| t.tab_id == from_tab_id) {
                return Err(WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: from_tab_id.to_string(),
                });
            }
            if layout.tabs.iter().any(|t| t.tab_id == tab_id) {
                return Err(WindowLayoutError::TabAlreadyExists {
                    window_id: window_id.to_string(),
                    tab_id: tab_id.to_string(),
                });
            }
            let next_index = layout
                .tabs
                .iter()
                .map(|t| t.index)
                .max()
                .map_or(0, |m| m + 1);
            // Unique pane title within the window (auto-number collisions). The new tab isn't in `tabs` yet.
            let sibling_titles: Vec<String> = layout.tabs.iter().map(|t| t.title.clone()).collect();
            let title = crate::unique_name(title, &sibling_titles);
            layout.tabs.push(TabRecord {
                tab_id: tab_id.to_string(),
                session_id: session_id.to_string(),
                index: next_index,
                title,
                pinned: false,
                attention: AttentionState::default(),
                split_from: Some(SplitFrom {
                    tab_id: from_tab_id.to_string(),
                    axis,
                    ratio_per_mille: None,
                }),
                pane_rect: None,
                stashed_from: None,
                stashed: false,
            });
            // Persist the AUTHORITATIVE geometry: a split is a LOCAL split of the source pane's rect — the
            // source keeps half, the new pane takes the other half along `axis`. Every other live pane is
            // untouched. Build the live rect set (each pane's existing pane_rect, or the source's full screen
            // on the first split) and write it. This makes split == the same local-split rule as drag/drop.
            let edge = match axis {
                SplitAxis::Right => EdgeDir::Right,
                SplitAxis::Down => EdgeDir::Bottom,
            };
            let mut panes: Vec<AgentRect> = layout
                .tabs
                .iter()
                .filter(|t| !t.stashed && t.tab_id != tab_id)
                .map(|t| AgentRect {
                    agent: t.tab_id.clone(),
                    rect: t.pane_rect.map_or([0.0, 0.0, 1.0, 1.0], PaneRect::to_unit),
                })
                .collect();
            // Pick the pane to split FROM. Normally it's `from_tab_id`. But a split must operate on a real
            // LIVE pane — if the requested source isn't live (stashed/stale), splitting it would leave the
            // new pane with no rect (an invisible "live" pane). In that case fall back to the largest live
            // pane so the new pane always lands somewhere visible. (If there are NO live panes, the new pane
            // takes the full screen.)
            let src = panes
                .iter()
                .position(|p| p.agent == from_tab_id)
                .or_else(|| {
                    // largest-area live pane as the anchor
                    panes
                        .iter()
                        .enumerate()
                        .max_by(|(_, a), (_, b)| {
                            (a.rect[2] * a.rect[3])
                                .partial_cmp(&(b.rect[2] * b.rect[3]))
                                .unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .map(|(i, _)| i)
                });
            match src {
                Some(src) => {
                    let (kept, inserted) = split_rect_local(panes[src].rect, edge);
                    panes[src].rect = kept;
                    panes.push(AgentRect {
                        agent: tab_id.to_string(),
                        rect: inserted,
                    });
                }
                None => {
                    // No live panes at all — the new pane is the whole screen.
                    panes.push(AgentRect {
                        agent: tab_id.to_string(),
                        rect: [0.0, 0.0, 1.0, 1.0],
                    });
                }
            }
            // Write ONLY the rects — keep the direct split_from set at construction (the new pane splits
            // from `from_tab_id` along `axis`). This preserves the canonical split chain that swallow and
            // other split_from readers rely on, while the renderer paints from the authoritative rects.
            for p in &panes {
                if let Some(tab) = layout.tabs.iter_mut().find(|t| t.tab_id == p.agent) {
                    tab.pane_rect = Some(PaneRect::from_unit(p.rect));
                }
            }
            Ok(())
        })
    }

    /// Remove a tab and compact the remaining indices.
    pub fn close_tab(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        Ok(self
            .close_with_removed_transaction(
                window_id,
                now_ms,
                &PreResolvedSessionGenerations::new(),
                false,
                false,
                |layout| {
                    let Some(index) = layout.tabs.iter().position(|tab| tab.tab_id == tab_id)
                    else {
                        return Err(WindowLayoutError::TabNotFound {
                            window_id: window_id.to_string(),
                            tab_id: tab_id.to_string(),
                        });
                    };
                    Ok(layout.tabs.remove(index))
                },
            )?
            .into_unguarded()
            .layout)
    }

    /// Remove a tab and return both the resulting layout and the exact transaction-local tab row
    /// that was removed. Daemon lifecycle callers must use `removed_tab.session_id` and then
    /// revalidate global tab ownership under the SessionService writer fence.
    pub fn close_tab_with_removed(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowTabClose, WindowLayoutError> {
        self.close_tab_with_removed_with_resolutions(
            window_id,
            tab_id,
            &PreResolvedSessionGenerations::new(),
            now_ms,
        )
    }

    pub fn close_tab_with_removed_with_resolutions(
        &self,
        window_id: &str,
        tab_id: &str,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
    ) -> Result<WindowTabClose, WindowLayoutError> {
        Ok(self
            .close_with_removed_transaction(
                window_id,
                now_ms,
                pre_resolved,
                true,
                false,
                |layout| {
                    let Some(index) = layout.tabs.iter().position(|tab| tab.tab_id == tab_id)
                    else {
                        return Err(WindowLayoutError::TabNotFound {
                            window_id: window_id.to_string(),
                            tab_id: tab_id.to_string(),
                        });
                    };
                    Ok(layout.tabs.remove(index))
                },
            )?
            .into_unguarded())
    }

    /// Remove one tab while preserving the single globally-last visible ordinary-project window.
    /// The visibility proof and removal share one SQLite writer fence; lower-level rollback paths
    /// deliberately retain the unguarded `close_tab*` APIs above.
    pub fn close_tab_with_removed_preserving_global_last(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<GuardedWindowTabClose, WindowLayoutError> {
        self.close_with_removed_transaction(
            window_id,
            now_ms,
            &PreResolvedSessionGenerations::new(),
            true,
            true,
            |layout| {
                let Some(index) = layout.tabs.iter().position(|tab| tab.tab_id == tab_id) else {
                    return Err(WindowLayoutError::TabNotFound {
                        window_id: window_id.to_string(),
                        tab_id: tab_id.to_string(),
                    });
                };
                Ok(layout.tabs.remove(index))
            },
        )
    }

    /// Close exactly the newly-published tab carried by `expected`, refusing a concurrent layout
    /// rewrite or a tab that no longer names the Session this create flow owns. The returned
    /// snapshot is the only safe input to [`delete_created_session_if_unreferenced`](Self::delete_created_session_if_unreferenced).
    pub fn close_created_tab_if_unchanged(
        &self,
        expected: &WindowLayoutSnapshot,
        tab_id: &str,
        expected_session_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayoutSnapshot, WindowLayoutError> {
        let window_id = expected.layout.window_id.clone();
        self.mutate_expected_snapshot(expected, now_ms, |layout| {
            let Some(tab) = layout.tabs.iter().find(|tab| tab.tab_id == tab_id) else {
                return Err(WindowLayoutError::TabNotFound {
                    window_id: window_id.clone(),
                    tab_id: tab_id.to_string(),
                });
            };
            if tab.session_id != expected_session_id {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!(
                        "created tab {tab_id:?} no longer names expected session {expected_session_id:?}"
                    ),
                });
            }
            layout.tabs.retain(|tab| tab.tab_id != tab_id);
            Ok(())
        })
    }

    /// Rename a single tab, preserving order.
    pub fn rename_tab(
        &self,
        window_id: &str,
        tab_id: &str,
        title: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        // Load the layout so we can keep the title unique within the window. Siblings EXCLUDE the tab being renamed, so
        // renaming a pane to its OWN current title is a no-op (no collision → returned verbatim).
        self.mutate_existing(window_id, now_ms, |layout| {
            let sibling_titles: Vec<String> = layout
                .tabs
                .iter()
                .filter(|t| t.tab_id != tab_id)
                .map(|t| t.title.clone())
                .collect();
            let unique = crate::unique_name(title, &sibling_titles);
            let tab = layout
                .tabs
                .iter_mut()
                .find(|t| t.tab_id == tab_id)
                .ok_or_else(|| WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: tab_id.to_string(),
                })?;
            tab.title = unique;
            Ok(())
        })
    }

    /// Set a single tab's pinned flag, preserving order.
    pub fn set_pinned(
        &self,
        window_id: &str,
        tab_id: &str,
        pinned: bool,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_tab(window_id, tab_id, now_ms, |tab| tab.pinned = pinned)
    }

    /// Atomically mark every live tab in one exact window snapshot stashed, unless that window is
    /// the globally last visible window owned by an ordinary project.
    ///
    /// Ordinary hidden projects still participate because their windows remain user-owned and
    /// dashboard-addressable. Only the reserved product-recovery project (and unassigned windows)
    /// is outside the global user-window count. A refusal commits no row or mutation-epoch change.
    pub fn stash_if_unchanged_preserving_global_last(
        &self,
        expected: &WindowLayoutSnapshot,
        now_ms: u64,
    ) -> Result<ConditionalWindowStash, WindowLayoutError> {
        let window_id = expected.layout.window_id.as_str();
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        #[cfg(test)]
        crate::store_sqlite::run_window_layout_test_hook(
            "before-window-layout-transaction",
            window_id,
        );
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let current = Self::load_snapshot_from_connection(&tx, window_id)?;
        let mut trace_fields = None;
        let outcome = match current {
            None => ConditionalWindowStash::Missing,
            Some(current) if current != *expected => ConditionalWindowStash::Changed,
            Some(current) if !current.layout.tabs.iter().any(|tab| !tab.stashed) => {
                ConditionalWindowStash::AlreadyStashed(current)
            }
            Some(current)
                if snapshot_is_visible_ordinary_project_window(&current)
                    && visible_ordinary_project_window_count(&tx)? <= 1 =>
            {
                ConditionalWindowStash::GloballyLastVisible
            }
            Some(mut current) => {
                for tab in &mut current.layout.tabs {
                    tab.stashed = true;
                }
                dbg_panes("WRITE", &current.layout);
                let value = serde_json::to_value(&current.layout)
                    .map_err(|error| StoreError::Map(format!("serialize record: {error}")))?;
                crate::store_sqlite::upsert(&tx, RecordKind::WindowLayout, window_id, &value)
                    .map_err(|error| StoreError::Map(error.to_string()))?;
                let revision = WindowLayoutRevision {
                    window_mutation_epoch: crate::db::bump_window_mutation_epoch(&tx)
                        .map_err(|error| StoreError::Db(error.to_string()))?,
                };
                trace_fields = Some(
                    value
                        .as_object()
                        .map(|object| object.keys().cloned().collect::<Vec<_>>())
                        .unwrap_or_default(),
                );
                ConditionalWindowStash::Stashed(WindowLayoutSnapshot {
                    layout: current.layout,
                    project_id: current.project_id,
                    revision,
                })
            }
        };
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        if let Some(fields) = trace_fields {
            // Preserve the connection-mutex -> trace lock order used by the other layout writers.
            crate::write_trace::trace_write(
                self.paths.base(),
                "WindowLayout",
                window_id,
                &fields,
                now_ms,
            );
        }
        Ok(outcome)
    }

    /// Mark a tab STASHED or revive it, preserving order, index, session, and every other field.
    /// Stashing is the soft alternative to [`close_tab`]: the record is kept (so its session can be
    /// relaunched and its place in the layout remembered) but the renderer hides it from the live
    /// pane layout and the dashboard surfaces it as a dim revive candidate. Reviving (`stashed =
    /// false`) simply clears the flag. An unknown window/tab is a typed error; the layout is
    /// otherwise untouched.
    pub fn set_tab_stashed(
        &self,
        window_id: &str,
        tab_id: &str,
        stashed: bool,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_tab(window_id, tab_id, now_ms, |tab| tab.stashed = stashed)
    }

    /// Close a single PANE, removing its tab record while keeping the split chain valid. This is the
    /// record edit behind a per-pane close `x`. Unlike [`close_tab`] (a blind `retain`), it first
    /// RE-PARENTS any children of the closed pane onto the closed pane's own parent — or detaches them
    /// to roots (`split_from = None`) when the closed pane was itself a root — so no surviving tab is
    /// left pointing at a vanished parent (the dangling-`split_from` orphan/scramble class). The
    /// canonical renderer replay then re-snaps the survivors into the right smaller layout. An unknown
    /// window/tab is a typed error; the layout is otherwise untouched.
    pub fn close_pane(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        Ok(self
            .close_with_removed_transaction(
                window_id,
                now_ms,
                &PreResolvedSessionGenerations::new(),
                false,
                false,
                |layout| {
                    pane_dbg!("PANE-DBG CLOSE-ENTER tab={tab_id}");
                    dbg_panes("CLOSE-BEFORE", layout);
                    let Some(closing) = layout.tabs.iter().find(|t| t.tab_id == tab_id).cloned()
                    else {
                        return Err(WindowLayoutError::TabNotFound {
                            window_id: window_id.to_string(),
                            tab_id: tab_id.to_string(),
                        });
                    };
                    apply_reduce(layout, tab_id);
                    layout.tabs.retain(|t| t.tab_id != tab_id);
                    Ok(closing)
                },
            )?
            .into_unguarded()
            .layout)
    }

    /// Geometry-aware pane close with the exact transaction-local removed tab row attached.
    /// Renderer lifecycle code uses this variant before any daemon release decision.
    pub fn close_pane_with_removed(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowTabClose, WindowLayoutError> {
        self.close_pane_with_removed_with_resolutions(
            window_id,
            tab_id,
            &PreResolvedSessionGenerations::new(),
            now_ms,
        )
    }

    pub fn close_pane_with_removed_with_resolutions(
        &self,
        window_id: &str,
        tab_id: &str,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
    ) -> Result<WindowTabClose, WindowLayoutError> {
        Ok(self
            .close_pane_with_removed_with_resolutions_internal(
                window_id,
                tab_id,
                pre_resolved,
                now_ms,
                false,
            )?
            .into_unguarded())
    }

    /// Remove one pane while preserving the single globally-last visible ordinary-project window.
    /// A stashed pane, or a live pane whose window still has another live pane, cannot affect that
    /// invariant and remains removable. The guard and pane removal share one SQLite writer fence.
    pub fn close_pane_with_removed_preserving_global_last(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<GuardedWindowTabClose, WindowLayoutError> {
        self.close_pane_with_removed_with_resolutions_internal(
            window_id,
            tab_id,
            &PreResolvedSessionGenerations::new(),
            now_ms,
            true,
        )
    }

    fn close_pane_with_removed_with_resolutions_internal(
        &self,
        window_id: &str,
        tab_id: &str,
        pre_resolved: &PreResolvedSessionGenerations,
        now_ms: u64,
        preserve_global_last: bool,
    ) -> Result<GuardedWindowTabClose, WindowLayoutError> {
        self.close_with_removed_transaction(
            window_id,
            now_ms,
            pre_resolved,
            true,
            preserve_global_last,
            |layout| {
                pane_dbg!("PANE-DBG CLOSE-ENTER tab={tab_id}");
                dbg_panes("CLOSE-BEFORE", layout);
                let Some(closing) = layout.tabs.iter().find(|t| t.tab_id == tab_id).cloned() else {
                    return Err(WindowLayoutError::TabNotFound {
                        window_id: window_id.to_string(),
                        tab_id: tab_id.to_string(),
                    });
                };
                apply_reduce(layout, tab_id);
                layout.tabs.retain(|t| t.tab_id != tab_id);
                Ok(closing)
            },
        )
    }

    /// STASH a single pane instead of closing it: the soft close behind a per-pane `x`. The record is
    /// KEPT (its `session_id` is preserved so the live daemon session keeps running and can be
    /// relaunched from the dashboard) but `stashed` is set so the joined window-view strip hides it
    /// from the live layout while the dashboard surfaces it as a revive candidate. Like
    /// [`close_pane`], it RE-PARENTS the stashed pane's children onto the stashed pane's own parent
    /// (or detaches them to roots when the stashed pane was a root) so no survivor dangles at a hidden
    /// parent, and the canonical replay re-snaps survivors into the smaller layout. Refuses to stash
    /// the window's only NON-stashed pane (`CannotStashLastPane`) so a window is never left with an
    /// empty live layout. An unknown window/tab is a typed error.
    pub fn stash_pane(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_existing(window_id, now_ms, |layout| {
            pane_dbg!("PANE-DBG STASH-ENTER tab={tab_id}");
            dbg_panes("STASH-BEFORE", layout);
            let Some(closing) = layout.tabs.iter().find(|t| t.tab_id == tab_id) else {
                return Err(WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: tab_id.to_string(),
                });
            };
            // Guard the last live pane: if this is the only pane not already stashed, stashing it would
            // leave the window with nothing to draw. The caller (or dashboard) handles closing the empty
            // window itself; here we refuse rather than create an empty live layout.
            let live_count = layout.tabs.iter().filter(|t| !t.stashed).count();
            if live_count <= 1 && !closing.stashed {
                return Err(WindowLayoutError::CannotStashLastPane {
                    window_id: window_id.to_string(),
                    tab_id: tab_id.to_string(),
                });
            }
            let inherited_parent = closing.split_from.clone();
            apply_reduce(layout, tab_id);
            if let Some(tab) = layout.tabs.iter_mut().find(|t| t.tab_id == tab_id) {
                tab.stashed = true;
                tab.stashed_from = inherited_parent;
                // A stashed pane is no longer part of the live split chain; drop its own provenance and live
                // geometry so live rendering never points through a hidden pane. The original provenance is
                // preserved in `stashed_from` for `revive_pane`.
                tab.split_from = None;
                tab.pane_rect = None;
            }
            Ok(())
        })
    }

    /// REVIVE a stashed pane into the live layout while preserving its session identity.
    ///
    /// This is the layout-aware counterpart to [`set_tab_stashed(false)`]. It first restores the
    /// pane's saved `stashed_from` parent when that parent is still live. If the old parent was closed
    /// or is itself stashed, it falls back to a deterministic four-pane growth rule: the second pane
    /// docks right of the sole survivor, the third docks below the first survivor, and the fourth
    /// docks below a stable right-side/second survivor when available. The transition never revives
    /// beyond four active panes.
    pub fn revive_pane(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_existing(window_id, now_ms, |layout| {
            apply_pane_revive(layout, window_id, tab_id)
        })
    }

    /// Validate one pane revive against an exact read snapshot without changing the layout.
    ///
    /// In particular, the four-live-pane refusal is known before a caller is allowed to attach or
    /// restart the pane's daemon session. The returned opaque plan also seals the exact project
    /// owner and global window-mutation revision for the later conditional commit.
    pub fn prepare_pane_revive(
        &self,
        window_id: &str,
        tab_id: &str,
    ) -> Result<PreparedPaneRevive, WindowLayoutError> {
        let expected = self.load_snapshot(window_id)?.ok_or_else(|| {
            WindowLayoutError::WindowLayoutNotFound {
                window_id: window_id.to_string(),
            }
        })?;
        let mut post_layout = expected.layout.clone();
        apply_pane_revive(&mut post_layout, window_id, tab_id)?;
        Ok(PreparedPaneRevive {
            expected,
            post_layout,
        })
    }

    /// Consume one exact preflight and conditionally publish its layout transition.
    ///
    /// Already-visible panes still perform the exact snapshot comparison but commit no write. This
    /// lets a window-wide Reopen validate each visible Exited pane without advancing the global
    /// epoch between sibling plans.
    pub fn commit_prepared_pane_revive(
        &self,
        prepared: PreparedPaneRevive,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let PreparedPaneRevive {
            expected,
            post_layout,
        } = prepared;
        let window_id = expected.layout.window_id.clone();
        let changed = expected.layout != post_layout;
        Ok(self
            .transact_layout_snapshot(&window_id, Some(&expected), now_ms, |current| {
                let current = current.ok_or_else(|| WindowLayoutError::WindowLayoutNotFound {
                    window_id: window_id.clone(),
                })?;
                if changed {
                    Ok(LayoutTransactionDecision::Persist(post_layout))
                } else {
                    Ok(LayoutTransactionDecision::ReturnWithoutWrite(current))
                }
            })?
            .layout)
    }

    /// Repair a visible multi-pane window whose live tabs no longer form one connected split tree.
    ///
    /// Older/dev builds could leave several live panes as independent roots (`split_from: null` for
    /// every tab). The dashboard still shows those panes as green/live, but the renderer can only
    /// compose a split frame from one root plus child provenance. This repair preserves tab/session
    /// identities and rewrites only live `split_from` topology into the canonical growth order:
    /// 1 pane = root, 2 = right, 3 = below first column, 4 = filled grid.
    pub fn repair_live_topology(
        &self,
        window_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.transact_layout(window_id, now_ms, |current| {
            let mut layout = current.ok_or_else(|| WindowLayoutError::WindowLayoutNotFound {
                window_id: window_id.to_string(),
            })?;
            if !live_topology_needs_repair(&layout) {
                return Ok(LayoutTransactionDecision::ReturnWithoutWrite(layout));
            }

            let live_ids: Vec<String> = layout
                .tabs
                .iter()
                .filter(|tab| !tab.stashed)
                .map(|tab| tab.tab_id.clone())
                .collect();
            if live_ids.len() > 4 {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!(
                        "cannot repair window {window_id:?}; {} live panes exceeds the 4-pane limit",
                        live_ids.len()
                    ),
                });
            }
            let Some((reviving, existing)) = live_ids.split_last() else {
                return Ok(LayoutTransactionDecision::ReturnWithoutWrite(layout));
            };
            apply_revive(&mut layout, existing, reviving);
            Ok(LayoutTransactionDecision::Persist(layout))
        })
    }

    /// Update a single tab's persisted attention roll-up, preserving order.
    pub fn update_attention(
        &self,
        window_id: &str,
        tab_id: &str,
        attention: AttentionState,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_tab(window_id, tab_id, now_ms, |tab| tab.attention = attention)
    }

    /// Persist the divider position for a split-child tab as the first/parent side's PER-MILLE share
    /// (`ratio_per_mille`, clamped to `0..=1000`), preserving order. A no-op on a tab that is not a
    /// split child (`split_from` is `None`): there is no divider to persist, so the record is left
    /// unchanged rather than inventing split provenance. An unknown tab id is `TabNotFound`.
    pub fn set_split_ratio(
        &self,
        window_id: &str,
        tab_id: &str,
        ratio_per_mille: u16,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        let clamped = ratio_per_mille.min(1000);
        self.mutate_tab(window_id, tab_id, now_ms, |tab| {
            if let Some(split) = tab.split_from.as_mut() {
                split.ratio_per_mille = Some(clamped);
            }
        })
    }

    /// Write `pane_rect` VERBATIM for each `(tab_id, PaneRect)` in `rects`, then renormalize+write.
    /// This is the persist target for a settled rect-based divider drag: the renderer hands back the
    /// final rects of every pane whose geometry moved, and we store them as-is (no topology recompute —
    /// a divider drag only resizes existing panes, it doesn't change the split tree). Only LIVE
    /// (non-stashed) tabs that are present in the layout are written; unknown ids are ignored so a
    /// stale drag payload can't error or resurrect a closed pane. A missing window is a typed error.
    pub fn set_pane_rects(
        &self,
        window_id: &str,
        rects: &[(String, PaneRect)],
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_existing(window_id, now_ms, |layout| {
            for (tab_id, rect) in rects {
                if let Some(tab) = layout
                    .tabs
                    .iter_mut()
                    .find(|t| &t.tab_id == tab_id && !t.stashed)
                {
                    tab.pane_rect = Some(*rect);
                }
            }
            // GUARD the resize: the new live geometry MUST still tile. A divider drag that would push a pane
            // over its neighbor (overlap) or leave a gap is refused — panes are separate objects and must
            // never overlap/overflow. The prior valid layout is kept.
            if let Some(live) = live_pane_rects(layout) {
                if !rects_tile_unit_square(&live) {
                    return Err(WindowLayoutError::InvalidTabOrder {
                        reason: "resize would make panes overlap or leave a gap".into(),
                    });
                }
            }
            Ok(())
        })
    }

    /// Point an existing tab at a different `session_id`, preserving every other field (title,
    /// pinned, attention, order, index). Used when a task is resumed: the durable task tab must
    /// follow the task to its newest live session. A missing window/tab is a typed error and the
    /// layout is left unchanged.
    pub fn retarget_tab_session(
        &self,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_tab(window_id, tab_id, now_ms, |tab| {
            tab.session_id = session_id.to_string()
        })
    }

    /// Retarget a task-owned tab only while its fresh current binding is still the requested new
    /// Session or one of `allowed_current_session_ids`. A concurrent retarget to an unrelated
    /// Session is a typed [`WindowLayoutError::WindowLayoutChanged`] refusal and is never
    /// overwritten. An already-current new binding is a true no-op (no epoch or trace).
    pub fn retarget_tab_session_if_current_in(
        &self,
        window_id: &str,
        tab_id: &str,
        allowed_current_session_ids: &[String],
        session_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.transact_layout(window_id, now_ms, |current| {
            let mut layout = current.ok_or_else(|| WindowLayoutError::WindowLayoutNotFound {
                window_id: window_id.to_string(),
            })?;
            let tab = layout
                .tabs
                .iter_mut()
                .find(|tab| tab.tab_id == tab_id)
                .ok_or_else(|| WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: tab_id.to_string(),
                })?;
            if tab.session_id == session_id {
                return Ok(LayoutTransactionDecision::ReturnWithoutWrite(layout));
            }
            if !allowed_current_session_ids
                .iter()
                .any(|allowed| allowed == &tab.session_id)
            {
                return Err(WindowLayoutError::WindowLayoutChanged {
                    window_id: window_id.to_string(),
                });
            }
            tab.session_id = session_id.to_string();
            Ok(LayoutTransactionDecision::Persist(layout))
        })
    }

    /// Reorder the window's tabs to match `ordered_tab_ids`, which MUST be an exact permutation
    /// of the current tab ids (every id once, no unknowns, no duplicates). On any violation the
    /// layout is left untouched and [`WindowLayoutError::InvalidTabOrder`] is returned. Indices
    /// are renormalized to the new order.
    pub fn reorder_tabs(
        &self,
        window_id: &str,
        ordered_tab_ids: &[String],
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_existing(window_id, now_ms, |layout| {
            if ordered_tab_ids.len() != layout.tabs.len() {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!(
                        "expected {} tab ids, got {}",
                        layout.tabs.len(),
                        ordered_tab_ids.len()
                    ),
                });
            }
            // Exact-set check: the requested order must be a permutation of the existing ids. We
            // verify "no duplicates in the request" and "every requested id exists"; with equal
            // lengths those two together imply every existing id appears exactly once.
            let mut seen = std::collections::HashSet::with_capacity(ordered_tab_ids.len());
            for id in ordered_tab_ids {
                if !seen.insert(id.as_str()) {
                    return Err(WindowLayoutError::InvalidTabOrder {
                        reason: format!("duplicate tab id {id:?} in requested order"),
                    });
                }
                if !layout.tabs.iter().any(|t| &t.tab_id == id) {
                    return Err(WindowLayoutError::InvalidTabOrder {
                        reason: format!("unknown tab id {id:?} in requested order"),
                    });
                }
            }

            layout.tabs.sort_by_key(|t| {
                ordered_tab_ids
                    .iter()
                    .position(|id| id == &t.tab_id)
                    .expect("every existing id is present in the validated order")
            });
            Ok(())
        })
    }

    /// Swap the POSITIONS of two existing tabs, leaving every other tab in place. Only the slot
    /// each tab occupies changes; `session_id`, `split_from`, `title`, `pinned`, and `attention`
    /// travel with their tab, so a swap moves layout position without disturbing the running
    /// session, its provenance, or its label. Indices are renormalized to the new order. Both tab
    /// ids must exist and differ; a missing id is [`WindowLayoutError::TabNotFound`] and swapping a
    /// tab with itself is [`WindowLayoutError::InvalidTabOrder`]. On any violation the layout is
    /// left untouched.
    pub fn swap_tab_positions(
        &self,
        window_id: &str,
        tab_id_a: &str,
        tab_id_b: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_existing(window_id, now_ms, |layout| {
            if tab_id_a == tab_id_b {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!("cannot swap tab {tab_id_a:?} with itself"),
                });
            }
            let pos_a = layout
                .tabs
                .iter()
                .position(|t| t.tab_id == tab_id_a)
                .ok_or_else(|| WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: tab_id_a.to_string(),
                })?;
            let pos_b = layout
                .tabs
                .iter()
                .position(|t| t.tab_id == tab_id_b)
                .ok_or_else(|| WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: tab_id_b.to_string(),
                })?;
            layout.tabs.swap(pos_a, pos_b);
            Ok(())
        })
    }

    /// Swap the two panes' OCCUPANTS — which running session sits in each pane — while leaving the split
    /// TOPOLOGY (every tab's `split_from` provenance, `tab_id`, and `index`) completely fixed. This is the
    /// live-model equivalent of the canonical engine's `PaneLayoutModel::swap_agents`, which swaps slot
    /// ASSIGNMENTS within a fixed slot tree rather than rewiring the tree. The pane regions stay exactly
    /// where they are; only the `session_id`, `title`, `pinned`, and `attention` payloads trade places, so
    /// the two terminals visibly swap positions.
    ///
    /// Why occupant-swap and not provenance-rewrite: the renderer derives N-pane geometry by walking the
    /// `split_from` chain to the root. Rewiring provenance for an arbitrary pair (especially a non-adjacent
    /// ancestor/descendant pair in a 4-pane tree) can orphan an intermediate pane from the root chain,
    /// dropping it from the window. Swapping occupants over a fixed topology is correct for EVERY pair
    /// (disjoint, parent/child, ancestor/descendant) and can never drop a pane, because the chain is
    /// untouched. Unlike [`swap_tab_positions`] (a Vec reorder that is a visual no-op when geometry derives
    /// from provenance), this moves the visible occupant, so the swap is always observable.
    ///
    /// Rejections (layout untouched): a missing id is [`WindowLayoutError::TabNotFound`]; swapping a tab
    /// with itself is [`WindowLayoutError::InvalidTabOrder`].
    pub fn swap_tab_panes(
        &self,
        window_id: &str,
        tab_id_a: &str,
        tab_id_b: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_existing(window_id, now_ms, |layout| {
            if tab_id_a == tab_id_b {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!("cannot swap pane {tab_id_a:?} with itself"),
                });
            }
            let pos_a = layout
                .tabs
                .iter()
                .position(|t| t.tab_id == tab_id_a)
                .ok_or_else(|| WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: tab_id_a.to_string(),
                })?;
            let pos_b = layout
                .tabs
                .iter()
                .position(|t| t.tab_id == tab_id_b)
                .ok_or_else(|| WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: tab_id_b.to_string(),
                })?;
            // Exchange only the OCCUPANT payload between the two panes; `tab_id`, `index`, `split_from`,
            // `stashed`, and `stashed_from` stay put so the split topology is byte-stable. The session,
            // its label, pin, and attention roll-up travel to the other pane's fixed slot.
            let (lo, hi) = if pos_a < pos_b {
                (pos_a, pos_b)
            } else {
                (pos_b, pos_a)
            };
            let (left, right) = layout.tabs.split_at_mut(hi);
            let a = &mut left[lo];
            let b = &mut right[0];
            std::mem::swap(&mut a.session_id, &mut b.session_id);
            std::mem::swap(&mut a.title, &mut b.title);
            std::mem::swap(&mut a.pinned, &mut b.pinned);
            std::mem::swap(&mut a.attention, &mut b.attention);
            Ok(())
        })
    }

    /// Swallow the split that `tab_id` belongs to WITHOUT killing any pane's session. Two-pane
    /// splits keep the historical behavior: the divider dissolves and both sessions become ordinary
    /// tabs. Three-pane live layouts use the canonical swallow table ported from the Electron app:
    /// the selected pane re-snaps into the same-pane-count target shape where it becomes the full
    /// row/column main. Sessions, labels, pins, and attention stay attached to their tabs; only
    /// split topology/order changes. Four-pane swallow remains unsupported until the UI exposes an
    /// explicit legal direction.
    ///
    /// `tab_id` must exist ([`WindowLayoutError::TabNotFound`]) and must participate in a split as
    /// either a split child or the parent of one; a tab that is in no split is
    /// [`WindowLayoutError::InvalidTabOrder`] (nothing to swallow). On any violation the layout is
    /// left untouched.
    pub fn swallow_split(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.swallow_split_with_direction(window_id, tab_id, None, now_ms)
    }

    /// Directional variant of [`swallow_split`], used by the per-pane swallow arrows. Three-pane
    /// layouts apply exactly `direction` and reject illegal direction/slot combinations. Two-pane
    /// splits still dissolve because the historical two-pane action has no directional table.
    pub fn swallow_split_direction(
        &self,
        window_id: &str,
        tab_id: &str,
        direction: SwallowDir,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.swallow_split_with_direction(window_id, tab_id, Some(direction), now_ms)
    }

    fn swallow_split_with_direction(
        &self,
        window_id: &str,
        tab_id: &str,
        direction: Option<SwallowDir>,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_existing(window_id, now_ms, |layout| {
            pane_dbg!("PANE-DBG SWALLOW-ENTER tab={tab_id} dir={direction:?}");
            dbg_panes("SWALLOW-BEFORE", layout);
            if !layout.tabs.iter().any(|t| t.tab_id == tab_id) {
                return Err(WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: tab_id.to_string(),
                });
            }

            // Log the canonical model the swallow will read (this is what decides legal directions).
            {
                let live = live_tabs_sorted(layout);
                match canonical_model_from_live_tabs(&live) {
                    Some(m) => pane_dbg!("PANE-DBG SWALLOW-MODEL {:?}", m.layout),
                    None => pane_dbg!("PANE-DBG SWALLOW-MODEL none (cannot classify!)"),
                }
            }

            let live = live_tabs_sorted(layout);
            if live.iter().any(|t| t.tab_id == tab_id) && (live.len() == 3 || live.len() == 4) {
            // LOCAL edge-absorb swallow: the focused pane extends across its edge and eats only the
            // overlapping slice of its neighbor; neighbors keep the rest. Pure rect op — no canonical
            // reshape, so the result is exactly the user's "B grows up, A keeps the part over C and D"
            // model. The arrows pass a direction; a directionless call tries each edge and takes the first
            // clean absorb (stable order: Up, Down, Left, Right).
                let Some(panes) = live_pane_rects(layout) else {
                    return Err(WindowLayoutError::InvalidTabOrder {
                        reason: "live pane geometry unavailable for swallow".into(),
                    });
                };
                let all = [
                    SwallowDir::Up,
                    SwallowDir::Down,
                    SwallowDir::Left,
                    SwallowDir::Right,
                ];
                let candidates: Vec<SwallowDir> = match direction {
                    Some(d) => vec![d],
                    None => all.to_vec(),
                };
                let Some((dir, new_rects)) = candidates
                    .iter()
                    .find_map(|&d| swallow_rect_local(&panes, tab_id, d).map(|r| (d, r)))
                else {
                    eprintln!(
                        "PANE-DBG SWALLOW-REJECT tab={tab_id} dir={direction:?} no clean edge-absorb"
                    );
                    return Err(WindowLayoutError::InvalidTabOrder {
                        reason: format!("tab {tab_id:?} has no legal swallow {direction:?}"),
                    });
                };
                pane_dbg!("PANE-DBG SWALLOW-OK tab={tab_id} dir={dir:?}");
                // GUARD: never write geometry that doesn't tile (no overlap/gap/overflow).
                apply_pane_geometry_checked(layout, &new_rects)?;
                return Ok(());
            }

        // The split child to dissolve: either `tab_id` itself (it is the child) or the child whose
        // `split_from.tab_id` points at `tab_id` (it is the parent). A tab can be the parent of at
        // most one split child in this 2-pane model, so the first match is the frame partner.
            let child_pos = layout.tabs.iter().position(|t| {
                t.tab_id == tab_id && t.split_from.is_some()
                    || t.split_from.as_ref().is_some_and(|s| s.tab_id == tab_id)
            });
            let Some(child_pos) = child_pos else {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!("tab {tab_id:?} is not part of a split; nothing to swallow"),
                });
            };
        // 2-pane dissolve: remove the divider (drop the child's split_from). The two panes become
        // independent full-window tabs, so give each the full-screen rect (the rect path then sees a
        // single-member split per tab and correctly draws no divider).
            layout.tabs[child_pos].split_from = None;
            let full = PaneRect {
                x: 0,
                y: 0,
                w: 1000,
                h: 1000,
            };
            for tab in layout.tabs.iter_mut().filter(|t| !t.stashed) {
                tab.pane_rect = Some(full);
            }
            Ok(())
        })
    }

    /// Dock `source_tab_id` beside `target_tab_id`: re-point the source tab so it becomes the split
    /// child of the target on `axis`, WITHOUT creating or killing any session. This is the record edit
    /// behind an edge drag/drop — the source pane lifts out of wherever it was and re-binds beside the
    /// target. Every field (`session_id`, `title`, `pinned`, `attention`) travels with the source tab;
    /// only its `split_from` provenance changes. The divider ratio resets (`ratio_per_mille: None` =
    /// even) because the split relationship is new. Indices are renormalized.
    ///
    /// When `target_tab_id` already hosts a split child, the dock does NOT reject: it RETARGETS onto
    /// the tail of the target's split chain (the deepest descendant on the `split_from` path) so the
    /// new pane appends as the next canonical growth step (`TwoColumns -> ThreeColumns`, etc.) rather
    /// than forming a forbidden second child of the same parent. This is what lets edge drag/drop grow
    /// a layout past two panes — the canonical engine in `pane_layout.rs` derives the geometry from the
    /// chain, so appending at the tail is exactly the "grow the layout" behavior the old app had.
    ///
    /// Rejections (layout left untouched), matching the "never guess an ambiguous drop" rule:
    /// - either tab id missing -> [`WindowLayoutError::TabNotFound`];
    /// - source == target -> [`WindowLayoutError::InvalidTabOrder`] (a pane cannot dock beside itself);
    /// - docking onto a tab inside the source's OWN split subtree would form a cycle
    ///   -> [`WindowLayoutError::InvalidTabOrder`].
    pub fn dock_tab_beside(
        &self,
        window_id: &str,
        source_tab_id: &str,
        target_tab_id: &str,
        axis: SplitAxis,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_existing(window_id, now_ms, |layout| {
            if source_tab_id == target_tab_id {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!("cannot dock tab {source_tab_id:?} beside itself"),
                });
            }
            if !layout.tabs.iter().any(|t| t.tab_id == source_tab_id) {
                return Err(WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: source_tab_id.to_string(),
                });
            }
            if !layout.tabs.iter().any(|t| t.tab_id == target_tab_id) {
                return Err(WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: target_tab_id.to_string(),
                });
            }
            // Cycle guard: the source must not dock anywhere inside its own split subtree, or the chain
            // would loop (source -> ... -> source). Walk the target's `split_from` ancestry; if it passes
            // through the source, reject. This also covers the direct source-is-target-parent case.
            {
                let mut cursor = Some(target_tab_id.to_string());
                for _ in 0..=layout.tabs.len() {
                    let Some(cur) = cursor else { break };
                    if cur == source_tab_id {
                        return Err(WindowLayoutError::InvalidTabOrder {
                            reason: format!(
                                "cannot dock tab {source_tab_id:?} inside its own split subtree \
                                 (target {target_tab_id:?})"
                            ),
                        });
                    }
                    cursor = layout
                        .tabs
                        .iter()
                        .find(|t| t.tab_id == cur)
                        .and_then(|t| t.split_from.as_ref())
                        .map(|s| s.tab_id.clone());
                }
            }
            // The live 2-pane-per-split model allows one child per parent, but the canonical layout engine
            // grows past two panes by APPENDING to the chain tail. So if the requested target already has a
            // split child, retarget the dock onto the deepest descendant on its chain (skipping the source
            // itself if it happens to be in the way) — the new pane then lands as the next canonical growth
            // step instead of an illegal second child of the same parent.
            let dock_parent = resolve_chain_tail(layout, target_tab_id, source_tab_id);
            let source = layout
                .tabs
                .iter_mut()
                .find(|t| t.tab_id == source_tab_id)
                .expect("source presence checked above");
            source.split_from = Some(SplitFrom {
                tab_id: dock_parent,
                axis,
                ratio_per_mille: None,
            });
            Ok(())
        })
    }

    /// Dock `source_tab_id` against the exact edge of `target_tab_id` using the canonical pane-layout
    /// engine. Unlike [`dock_tab_beside`], this preserves the user's chosen edge instead of collapsing
    /// left/right into one axis and appending to the chain tail. It is intended for stashed-pane
    /// drag/drop from the dashboard.
    pub fn dock_tab_at_edge(
        &self,
        window_id: &str,
        source_tab_id: &str,
        target_tab_id: &str,
        edge: EdgeDir,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.dock_tab_at_edge_guarded(window_id, source_tab_id, None, target_tab_id, edge, now_ms)
    }

    /// Dock a React-originated stashed pane only after revalidating the exact durable source
    /// binding. A drag payload is stale authority: the source must still exist in `window_id`, still
    /// be stashed, and still reference `expected_session_id` in the same `BEGIN IMMEDIATE`
    /// transaction that transforms and writes the layout. Ordinary live-pane edge docking continues
    /// through [`Self::dock_tab_at_edge`].
    pub fn dock_stashed_tab_at_edge(
        &self,
        window_id: &str,
        source_tab_id: &str,
        expected_session_id: &str,
        target_tab_id: &str,
        edge: EdgeDir,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.dock_tab_at_edge_guarded(
            window_id,
            source_tab_id,
            Some(expected_session_id),
            target_tab_id,
            edge,
            now_ms,
        )
    }

    fn dock_tab_at_edge_guarded(
        &self,
        window_id: &str,
        source_tab_id: &str,
        expected_stashed_session_id: Option<&str>,
        target_tab_id: &str,
        edge: EdgeDir,
        now_ms: u64,
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_existing(window_id, now_ms, |layout| {
            if let Some(expected_session_id) = expected_stashed_session_id {
                let source_matches = layout.tabs.iter().filter(|tab| {
                    tab.tab_id == source_tab_id
                        && tab.session_id == expected_session_id
                        && tab.stashed
                });
                if source_matches.count() != 1 {
                    return Err(WindowLayoutError::InvalidTabOrder {
                        reason: format!(
                            "stashed dock source {source_tab_id:?} no longer has the expected session binding"
                        ),
                    });
                }
            }
            pane_dbg!(
                "PANE-DBG DOCK-ENTER src={source_tab_id} target={target_tab_id} edge={edge:?}"
            );
            dbg_panes("DOCK-BEFORE", layout);
            if source_tab_id == target_tab_id {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!("cannot dock tab {source_tab_id:?} beside itself"),
                });
            }
            if !layout.tabs.iter().any(|t| t.tab_id == source_tab_id) {
                return Err(WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: source_tab_id.to_string(),
                });
            }
            if !layout.tabs.iter().any(|t| t.tab_id == target_tab_id) {
                return Err(WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: target_tab_id.to_string(),
                });
            }

            let source_is_live = layout
                .tabs
                .iter()
                .find(|tab| tab.tab_id == source_tab_id)
                .is_some_and(|tab| !tab.stashed);
            let mut projected = layout.clone();
            if source_is_live {
                apply_reduce(&mut projected, source_tab_id);
            }

            let live: Vec<&TabRecord> = projected
                .tabs
                .iter()
                .filter(|tab| !tab.stashed && tab.tab_id != source_tab_id)
                .collect();
            if live.is_empty() || live.len() >= 4 {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!(
                        "cannot dock tab {source_tab_id:?}: live target set has {} panes",
                        live.len()
                    ),
                });
            }

            // INSERT = a LOCAL split of the TARGET pane's own rectangle (confirmed drag/drop spec,
            // stash-revive contract). Read the target set's AUTHORITATIVE rects (source already
            // removed by apply_reduce above), split the target rect in half along the dropped edge — source
            // takes the dropped side, target keeps the other. Only the target pane subdivides; every other
            // pane is untouched.
            let mut panes =
                live_pane_rects(&projected).ok_or_else(|| WindowLayoutError::InvalidTabOrder {
                    reason: "current live pane geometry is unavailable".into(),
                })?;
            panes.retain(|p| p.agent != source_tab_id);
            let Some(target) = panes.iter().position(|p| p.agent == target_tab_id) else {
                return Err(WindowLayoutError::InvalidTabOrder {
                    reason: format!("target tab {target_tab_id:?} is not live"),
                });
            };
            let t = panes[target].rect;
            let (kept, inserted) = split_rect_local(t, edge);
            panes[target].rect = kept;
            panes.push(AgentRect {
                agent: source_tab_id.to_string(),
                rect: inserted,
            });

            if let Some(source) = layout
                .tabs
                .iter_mut()
                .find(|tab| tab.tab_id == source_tab_id)
            {
                source.stashed = false;
                source.stashed_from = None;
            }
            // GUARD: a dock must produce a clean tiling (no overlap/gap).
            apply_pane_geometry_checked(layout, &panes)?;
            Ok(())
        })
    }

    /// Read-only projection: the window's tabs (sorted by index), each joined with the Phase 3D
    /// task report. A tab is linked to a task when some reconciled task's `current_session_id`
    /// equals the tab's `session_id`; that task contributes `agent_task_id`, `agent_task_state`,
    /// `session_status`, `session_record_missing`, and its `needs_attention`.
    ///
    /// Limitation (documented, intentional): the Phase 3D report is task-centric, so a tab whose
    /// session is NOT the current session of any task gets no `session_status` here even if a
    /// `SessionRecord` exists on disk. Broadening Phase 3D to expose all sessions is out of scope
    /// for Phase 4A; this projection joins the subset the existing report already provides.
    pub fn tab_view(
        &self,
        window_id: &str,
        task_report: &AgentTaskReconcileReport,
    ) -> Result<Vec<WindowTabView>, WindowLayoutError> {
        let layout = self.require(window_id)?;
        let mut tabs = layout.tabs;
        tabs.sort_by_key(|t| t.index);

        let views = tabs
            .into_iter()
            .map(|tab| {
                let linked = task_report
                    .tasks
                    .iter()
                    .find(|t| t.current_session_id.as_deref() == Some(tab.session_id.as_str()));
                let needs_attention = tab_needs_attention(
                    &tab.attention,
                    linked.map(|t| t.needs_attention).unwrap_or(false),
                );
                WindowTabView {
                    tab_id: tab.tab_id,
                    session_id: tab.session_id,
                    index: tab.index,
                    title: tab.title,
                    pinned: tab.pinned,
                    attention: tab.attention,
                    session_status: linked.and_then(|t| t.current_session_status),
                    agent_task_id: linked.map(|t| t.agent_task_id.clone()),
                    agent_task_state: linked.map(|t| t.state),
                    needs_attention,
                    session_record_missing: linked
                        .map(|t| t.session_record_missing)
                        .unwrap_or(false),
                    split_from: tab.split_from,
                    pane_rect: tab.pane_rect,
                    stashed: tab.stashed,
                }
            })
            .collect();
        Ok(views)
    }

    // --- internals ---

    fn load_snapshot_from_connection(
        conn: &rusqlite::Connection,
        window_id: &str,
    ) -> Result<Option<WindowLayoutSnapshot>, WindowLayoutError> {
        let raw = crate::store_sqlite::load_one(conn, RecordKind::WindowLayout, window_id)
            .map_err(|error| StoreError::Map(error.to_string()))?;
        let decoded = raw
            .map(|value| {
                let project_id = match value.get("project_id") {
                    None | Some(serde_json::Value::Null) => None,
                    Some(serde_json::Value::String(project_id)) => Some(project_id.clone()),
                    Some(other) => {
                        return Err(WindowLayoutError::Corrupt {
                            original: PathBuf::new(),
                            moved_to: PathBuf::new(),
                            reason: format!("row has non-string project_id: {other}"),
                        });
                    }
                };
                let layout = serde_json::from_value::<WindowLayout>(value).map_err(|error| {
                    WindowLayoutError::Corrupt {
                        original: PathBuf::new(),
                        moved_to: PathBuf::new(),
                        reason: format!("row failed to deserialize: {error}"),
                    }
                })?;
                Ok((layout, project_id))
            })
            .transpose()?;
        let revision = WindowLayoutRevision {
            window_mutation_epoch: crate::db::window_mutation_epoch(conn)
                .map_err(|error| StoreError::Db(error.to_string()))?,
        };
        Ok(decoded.map(|(layout, project_id)| WindowLayoutSnapshot {
            layout,
            project_id,
            revision,
        }))
    }

    fn load_viewport_snapshot_from_connection(
        conn: &rusqlite::Connection,
        window_id: &str,
    ) -> Result<WindowViewportSnapshot, WindowViewportSnapshotError> {
        let window = Self::load_snapshot_from_connection(conn, window_id)?.ok_or_else(|| {
            WindowViewportSnapshotError::WindowMissing {
                window_id: window_id.to_string(),
            }
        })?;
        let mut panes = Vec::new();
        let mut unique_sessions = std::collections::BTreeMap::<String, SessionRecord>::new();
        for tab in window.layout.tabs.iter().filter(|tab| !tab.stashed) {
            let session_id = tab.session_id.clone();
            let raw = match crate::store_sqlite::load_one(conn, RecordKind::Session, &session_id) {
                Ok(raw) => raw,
                Err(crate::store_sqlite::MapError::Shape(reason)) => {
                    return Err(WindowViewportSnapshotError::SessionMalformed {
                        tab_id: tab.tab_id.clone(),
                        session_id,
                        reason,
                    })
                }
                Err(crate::store_sqlite::MapError::Sqlite(error)) => {
                    return Err(WindowViewportSnapshotError::Window(
                        WindowLayoutError::Store(StoreError::Db(error.to_string())),
                    ))
                }
            };
            let value = raw.ok_or_else(|| WindowViewportSnapshotError::SessionMissing {
                tab_id: tab.tab_id.clone(),
                session_id: session_id.clone(),
            })?;
            let session = serde_json::from_value::<SessionRecord>(value).map_err(|error| {
                WindowViewportSnapshotError::SessionMalformed {
                    tab_id: tab.tab_id.clone(),
                    session_id: session_id.clone(),
                    reason: error.to_string(),
                }
            })?;
            if session.session_id != session_id {
                return Err(WindowViewportSnapshotError::SessionMalformed {
                    tab_id: tab.tab_id.clone(),
                    session_id,
                    reason: "loaded Session identity does not match the visible tab".into(),
                });
            }
            let generation = session
                .last_known_generation
                .as_ref()
                .filter(|generation| !generation.is_empty() && generation.len() <= 128)
                .cloned()
                .ok_or_else(
                    || WindowViewportSnapshotError::SessionGenerationUnavailable {
                        tab_id: tab.tab_id.clone(),
                        session_id: session.session_id.clone(),
                    },
                )?;
            if unique_sessions
                .get(&session.session_id)
                .is_some_and(|prior| prior != &session)
            {
                return Err(WindowViewportSnapshotError::ConflictingDuplicateSession {
                    session_id: session.session_id.clone(),
                });
            }
            unique_sessions
                .entry(session.session_id.clone())
                .or_insert_with(|| session.clone());
            panes.push(WindowViewportPane {
                tab_id: tab.tab_id.clone(),
                session,
                generation,
            });
        }
        Ok(WindowViewportSnapshot { window, panes })
    }

    /// Load the layout or fail with `WindowLayoutNotFound` (future/corrupt propagate as typed).
    fn require(&self, window_id: &str) -> Result<WindowLayout, WindowLayoutError> {
        self.load(window_id)?
            .ok_or_else(|| WindowLayoutError::WindowLayoutNotFound {
                window_id: window_id.to_string(),
            })
    }

    /// Execute one complete layout read-modify-write under SQLite's writer fence. The closure sees
    /// only the transaction-local fresh value; it must perform domain validation and pure record
    /// mutation, while this seam alone owns normalization, the full window+tabs upsert, commit, and
    /// post-commit trace. Keeping all service mutators here prevents `require()` followed by a later
    /// whole-layout write from erasing another app/agent writer's committed fields.
    fn transact_layout(
        &self,
        window_id: &str,
        now_ms: u64,
        mutate: impl FnOnce(
            Option<WindowLayout>,
        ) -> Result<LayoutTransactionDecision, WindowLayoutError>,
    ) -> Result<WindowLayout, WindowLayoutError> {
        Ok(self
            .transact_layout_snapshot(window_id, None, now_ms, mutate)?
            .layout)
    }

    fn transact_layout_snapshot(
        &self,
        window_id: &str,
        expected: Option<&WindowLayoutSnapshot>,
        now_ms: u64,
        mutate: impl FnOnce(
            Option<WindowLayout>,
        ) -> Result<LayoutTransactionDecision, WindowLayoutError>,
    ) -> Result<WindowLayoutSnapshot, WindowLayoutError> {
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        #[cfg(test)]
        crate::store_sqlite::run_window_layout_test_hook(
            "before-window-layout-transaction",
            window_id,
        );
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let current_snapshot = Self::load_snapshot_from_connection(&tx, window_id)?;
        if expected.is_some_and(|expected| current_snapshot.as_ref() != Some(expected)) {
            return Err(WindowLayoutError::WindowLayoutChanged {
                window_id: window_id.to_string(),
            });
        }
        let current_project_id = current_snapshot
            .as_ref()
            .and_then(|snapshot| snapshot.project_id.clone());
        let current_revision = WindowLayoutRevision {
            window_mutation_epoch: crate::db::window_mutation_epoch(&tx)
                .map_err(|error| StoreError::Db(error.to_string()))?,
        };
        let current = current_snapshot.map(|snapshot| snapshot.layout);

        let decision = mutate(current)?;
        let mut layout = match decision {
            LayoutTransactionDecision::ReturnWithoutWrite(layout) => {
                tx.commit()
                    .map_err(|error| StoreError::Db(error.to_string()))?;
                return Ok(WindowLayoutSnapshot {
                    layout,
                    project_id: current_project_id,
                    revision: current_revision,
                });
            }
            LayoutTransactionDecision::Persist(layout) => layout,
        };
        if layout.window_id != window_id {
            return Err(WindowLayoutError::Store(StoreError::Map(format!(
                "window layout mutation changed id from {window_id:?} to {:?}",
                layout.window_id
            ))));
        }
        for (index, tab) in layout.tabs.iter_mut().enumerate() {
            tab.index = index as u32;
        }
        dbg_panes("WRITE", &layout);

        let value = serde_json::to_value(&layout)
            .map_err(|error| StoreError::Map(format!("serialize record: {error}")))?;
        crate::store_sqlite::upsert(&tx, RecordKind::WindowLayout, window_id, &value)
            .map_err(|error| StoreError::Map(error.to_string()))?;
        let revision = WindowLayoutRevision {
            window_mutation_epoch: crate::db::bump_window_mutation_epoch(&tx)
                .map_err(|error| StoreError::Db(error.to_string()))?,
        };
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;

        // Keep the established store lock order (connection mutex, then trace ring/file) so a
        // second in-process writer cannot commit between this commit and its diagnostic event.
        // The connection mutex intentionally remains held through even the opt-in trace file IO;
        // `write_trace` drops its ring lock before that IO and never calls back into the store, so
        // there is no trace -> connection reverse edge.
        let fields = value
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        crate::write_trace::trace_write(
            self.paths.base(),
            "WindowLayout",
            window_id,
            &fields,
            now_ms,
        );
        Ok(WindowLayoutSnapshot {
            layout,
            project_id: current_project_id,
            revision,
        })
    }

    fn mutate_expected_snapshot(
        &self,
        expected: &WindowLayoutSnapshot,
        now_ms: u64,
        mutate: impl FnOnce(&mut WindowLayout) -> Result<(), WindowLayoutError>,
    ) -> Result<WindowLayoutSnapshot, WindowLayoutError> {
        let window_id = expected.layout.window_id.as_str();
        self.transact_layout_snapshot(window_id, Some(expected), now_ms, |current| {
            let mut layout = current.ok_or_else(|| WindowLayoutError::WindowLayoutNotFound {
                window_id: window_id.to_string(),
            })?;
            mutate(&mut layout)?;
            Ok(LayoutTransactionDecision::Persist(layout))
        })
    }

    fn mutate_existing(
        &self,
        window_id: &str,
        now_ms: u64,
        mutate: impl FnOnce(&mut WindowLayout) -> Result<(), WindowLayoutError>,
    ) -> Result<WindowLayout, WindowLayoutError> {
        Ok(self
            .mutate_existing_snapshot(window_id, now_ms, mutate)?
            .layout)
    }

    fn mutate_existing_snapshot(
        &self,
        window_id: &str,
        now_ms: u64,
        mutate: impl FnOnce(&mut WindowLayout) -> Result<(), WindowLayoutError>,
    ) -> Result<WindowLayoutSnapshot, WindowLayoutError> {
        self.transact_layout_snapshot(window_id, None, now_ms, |current| {
            let mut layout = current.ok_or_else(|| WindowLayoutError::WindowLayoutNotFound {
                window_id: window_id.to_string(),
            })?;
            mutate(&mut layout)?;
            Ok(LayoutTransactionDecision::Persist(layout))
        })
    }

    /// Close one exact transaction-local tab row, persist the resulting layout, and bind any
    /// generation-proven daemon lifetime to the same commit. `allow_unresolved` is false for the
    /// layout-only compatibility APIs (which must abort rather than hide a leak) and true only for
    /// the typed `WindowTabClose` APIs that surface the unresolved cohort to their caller.
    fn close_with_removed_transaction(
        &self,
        window_id: &str,
        now_ms: u64,
        pre_resolved: &PreResolvedSessionGenerations,
        allow_unresolved: bool,
        preserve_global_last: bool,
        remove: impl FnOnce(&mut WindowLayout) -> Result<TabRecord, WindowLayoutError>,
    ) -> Result<GuardedWindowTabClose, WindowLayoutError> {
        self.paths
            .record_path(RecordKind::WindowLayout, window_id)
            .map_err(StoreError::Id)?;
        #[cfg(test)]
        crate::store_sqlite::run_window_layout_test_hook(
            "before-window-layout-transaction",
            window_id,
        );
        let arc = crate::db::conn_for(self.paths.base())
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let current = Self::load_snapshot_from_connection(&tx, window_id)?.ok_or_else(|| {
            WindowLayoutError::WindowLayoutNotFound {
                window_id: window_id.to_string(),
            }
        })?;
        let was_visible_ordinary = snapshot_is_visible_ordinary_project_window(&current);
        let mut layout = current.layout;
        let removed_tab = remove(&mut layout)?;
        if preserve_global_last
            && was_visible_ordinary
            && !removed_tab.stashed
            && !layout.tabs.iter().any(|tab| !tab.stashed)
            && visible_ordinary_project_window_count(&tx)? <= 1
        {
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            return Ok(GuardedWindowTabClose::GloballyLastVisible);
        }
        for (index, tab) in layout.tabs.iter_mut().enumerate() {
            tab.index = index as u32;
        }
        let exact = exact_release_targets_in_transaction(
            &tx,
            [removed_tab.session_id.clone()],
            SessionRowPolicy::MatchingRowIsProof,
            pre_resolved,
        )?;
        if !allow_unresolved && !exact.unresolved_session_ids.is_empty() {
            return Err(WindowLayoutError::Store(StoreError::Map(format!(
                "tab close has no exact generation for session {:?}",
                exact.unresolved_session_ids[0]
            ))));
        }
        let release_receipt =
            insert_pending_releases(&tx, &exact.targets, now_ms).map_err(|error| {
                StoreError::Map(format!("journal closed-tab session release: {error}"))
            })?;

        dbg_panes("WRITE", &layout);
        let value = serde_json::to_value(&layout)
            .map_err(|error| StoreError::Map(format!("serialize record: {error}")))?;
        crate::store_sqlite::upsert(&tx, RecordKind::WindowLayout, window_id, &value)
            .map_err(|error| StoreError::Map(error.to_string()))?;
        crate::db::bump_window_mutation_epoch(&tx)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;

        let fields = value
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        crate::write_trace::trace_write(
            self.paths.base(),
            "WindowLayout",
            window_id,
            &fields,
            now_ms,
        );
        Ok(GuardedWindowTabClose::Closed(WindowTabClose {
            layout,
            removed_tab,
            release_receipt,
            unresolved_release_session_ids: exact.unresolved_session_ids,
        }))
    }

    /// Find a tab by id, apply `edit`, then renormalize+write. Order is preserved (only the named
    /// tab is touched); indices are renormalized for consistency even though a field edit cannot
    /// change order.
    fn mutate_tab(
        &self,
        window_id: &str,
        tab_id: &str,
        now_ms: u64,
        edit: impl FnOnce(&mut TabRecord),
    ) -> Result<WindowLayout, WindowLayoutError> {
        self.mutate_existing(window_id, now_ms, |layout| {
            let tab = layout
                .tabs
                .iter_mut()
                .find(|t| t.tab_id == tab_id)
                .ok_or_else(|| WindowLayoutError::TabNotFound {
                    window_id: window_id.to_string(),
                    tab_id: tab_id.to_string(),
                })?;
            edit(tab);
            Ok(())
        })
    }
}

/// The projected `needs_attention`: true if the persisted tab attention is a real (non-`None`)
/// unseen signal, OR the joined task report flagged the task. Pure.
fn tab_needs_attention(persisted: &AttentionState, task_needs_attention: bool) -> bool {
    task_needs_attention || (persisted.unseen && persisted.attention != Attention::None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_task_reconcile::ReconciledAgentTask;
    use crate::records::AttentionSource;
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, AppPaths) {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        (tmp, paths)
    }

    fn svc(paths: &AppPaths) -> WindowLayoutService<'_> {
        WindowLayoutService::new(paths)
    }

    fn attn(attention: Attention, unseen: bool) -> AttentionState {
        AttentionState {
            attention,
            unseen,
            since_ms: 0,
            source: AttentionSource::Process,
        }
    }

    /// Regression: reviving a stashed pane into a 3-pane layout must leave the revived pane LIVE (not
    /// stashed) AND placed per the click-revive spec. A stale tab index after the geometry reorder used
    /// to leave the revived pane stashed → invisible (it had a rect but never un-stashed).
    #[test]
    fn revive_into_three_pane_layouts_makes_revived_pane_live_and_placed() {
        type Split = (&'static str, &'static str, SplitAxis);
        type ReviveCase = (&'static str, &'static [Split], (u16, u16, u16, u16));
        let cases: &[ReviveCase] = &[
            // (label, splits building the 3-pane layout, expected X rect after revive)
            // A│(B/C) left-main → (A│B)/(X│C): X bottom-LEFT.
            (
                "leftMain",
                &[("a", "b", SplitAxis::Right), ("b", "c", SplitAxis::Down)],
                (0, 500, 500, 500),
            ),
            // A/(B│C) top-main → (A│X)/(B│C): X top-RIGHT.
            (
                "topMain",
                &[("a", "b", SplitAxis::Down), ("b", "c", SplitAxis::Right)],
                (500, 0, 500, 500),
            ),
        ];
        for (label, splits, want_x) in cases {
            let (_tmp, paths) = temp_paths();
            let s = svc(&paths);
            s.create_empty("w1", 1).unwrap();
            s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
                .unwrap();
            for (idx, (from, new, axis)) in splits.iter().enumerate() {
                s.split_tab(
                    "w1",
                    from,
                    new,
                    &format!("s{new}"),
                    new,
                    *axis,
                    3 + idx as u64,
                )
                .unwrap();
            }
            s.open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 9)
                .unwrap();
            s.set_tab_stashed("w1", "x", true, 10).unwrap();
            let l = s.revive_pane("w1", "x", 11).unwrap();
            let x = l.tabs.iter().find(|t| t.tab_id == "x").unwrap();
            assert!(!x.stashed, "{label}: revived X must be LIVE, not stashed");
            assert_eq!(
                x.pane_rect.map(|r| (r.x, r.y, r.w, r.h)),
                Some(*want_x),
                "{label}: revived X placed per spec"
            );
            let live = l.tabs.iter().filter(|t| !t.stashed).count();
            assert_eq!(live, 4, "{label}: all four panes live after revive");
        }
    }

    fn tab_ids(layout: &WindowLayout) -> Vec<String> {
        layout.tabs.iter().map(|t| t.tab_id.clone()).collect()
    }

    fn indices(layout: &WindowLayout) -> Vec<u32> {
        layout.tabs.iter().map(|t| t.index).collect()
    }

    /// The window's CURRENT stored layout value, loaded through the service. Used by the
    /// "rejects X without rewrite" tests to compare the persisted `WindowLayout` before/after a
    /// refused op — the SQLite-store analog of the old byte-for-byte `fs::read(layout_path(..))`
    /// comparison (records are DB rows now, not JSON files, so we compare the loaded value).
    fn stored(paths: &AppPaths, window_id: &str) -> WindowLayout {
        svc(paths).load(window_id).unwrap().unwrap()
    }

    fn window_epoch(paths: &AppPaths) -> u32 {
        let connection = crate::db::conn_for(paths.base()).unwrap();
        let guard = connection.lock().unwrap();
        crate::db::window_mutation_epoch(&guard).unwrap()
    }

    fn create_test_project(paths: &AppPaths, project_id: &str) -> Project {
        crate::ProjectService::new(paths)
            .create(project_id, project_id, ".", crate::NewProject::default(), 1)
            .unwrap()
    }

    fn create_owned_visible_test_window(
        paths: &AppPaths,
        project_id: &str,
        window_id: &str,
        tab_id: &str,
    ) -> WindowLayoutSnapshot {
        let service = svc(paths);
        service.create_empty(window_id, 1).unwrap();
        service
            .open_tab(
                window_id,
                tab_id,
                &format!("session-{tab_id}"),
                tab_id,
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        crate::store::set_window_project(paths, window_id, project_id).unwrap();
        service.load_snapshot(window_id).unwrap().unwrap()
    }

    #[test]
    fn global_last_visible_stash_is_exact_atomic_and_noop_on_refusal() {
        let (_tmp, paths) = temp_paths();
        create_test_project(&paths, "stash-project-a");
        create_test_project(&paths, "stash-project-b");
        create_owned_visible_test_window(&paths, "stash-project-a", "stash-window-a", "pane-a");
        svc(&paths)
            .open_tab(
                "stash-window-a",
                "pane-a-2",
                "session-pane-a-2",
                "pane-a-2",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        create_owned_visible_test_window(&paths, "stash-project-b", "stash-window-b", "pane-b");

        let service = svc(&paths);
        let first = service.load_snapshot("stash-window-a").unwrap().unwrap();
        let stale_last = service.load_snapshot("stash-window-b").unwrap().unwrap();
        let before_stash_epoch = window_epoch(&paths);
        let stashed = match service
            .stash_if_unchanged_preserving_global_last(&first, 3)
            .unwrap()
        {
            ConditionalWindowStash::Stashed(snapshot) => snapshot,
            outcome => panic!("expected atomic stash, got {outcome:?}"),
        };
        assert!(stashed.layout.tabs.iter().all(|tab| tab.stashed));
        assert_eq!(stashed.project_id.as_deref(), Some("stash-project-a"));
        assert_eq!(window_epoch(&paths), before_stash_epoch + 1);
        assert!(stored(&paths, "stash-window-a")
            .tabs
            .iter()
            .all(|tab| tab.stashed));

        let after_stash_epoch = window_epoch(&paths);
        match service
            .stash_if_unchanged_preserving_global_last(&stashed, 4)
            .unwrap()
        {
            ConditionalWindowStash::AlreadyStashed(snapshot) => {
                assert_eq!(snapshot, stashed)
            }
            outcome => panic!("expected already-stashed no-op, got {outcome:?}"),
        }
        assert_eq!(window_epoch(&paths), after_stash_epoch);

        assert!(matches!(
            service
                .stash_if_unchanged_preserving_global_last(&stale_last, 5)
                .unwrap(),
            ConditionalWindowStash::Changed
        ));
        let last = service.load_snapshot("stash-window-b").unwrap().unwrap();
        let last_before = last.layout.clone();
        let refusal_epoch = window_epoch(&paths);
        assert!(matches!(
            service
                .stash_if_unchanged_preserving_global_last(&last, 6)
                .unwrap(),
            ConditionalWindowStash::GloballyLastVisible
        ));
        assert_eq!(stored(&paths, "stash-window-b"), last_before);
        assert_eq!(window_epoch(&paths), refusal_epoch);
    }

    #[test]
    fn global_last_visible_count_includes_hidden_projects_but_excludes_recovery() {
        let (_tmp, paths) = temp_paths();
        let hidden = create_test_project(&paths, "hidden-project");
        crate::ProjectService::new(&paths)
            .set_hidden_if_unchanged(&hidden, true, 2)
            .unwrap();
        create_test_project(&paths, "ordinary-project");
        create_owned_visible_test_window(&paths, "hidden-project", "hidden-window", "hidden-pane");
        create_owned_visible_test_window(
            &paths,
            "ordinary-project",
            "ordinary-window",
            "ordinary-pane",
        );

        let service = svc(&paths);
        let ordinary = service.load_snapshot("ordinary-window").unwrap().unwrap();
        assert!(matches!(
            service
                .stash_if_unchanged_preserving_global_last(&ordinary, 3)
                .unwrap(),
            ConditionalWindowStash::Stashed(_)
        ));

        crate::ProjectService::new(&paths)
            .create_hidden_system(
                crate::reserved_product_shell::PRODUCT_RECOVERY_PROJECT_ID,
                "Recovery",
                ".",
                crate::NewProject::default(),
                4,
            )
            .unwrap();
        create_owned_visible_test_window(
            &paths,
            crate::reserved_product_shell::PRODUCT_RECOVERY_PROJECT_ID,
            "recovery-window",
            "recovery-pane",
        );

        let hidden = service.load_snapshot("hidden-window").unwrap().unwrap();
        let before = hidden.layout.clone();
        let before_epoch = window_epoch(&paths);
        assert!(matches!(
            service
                .stash_if_unchanged_preserving_global_last(&hidden, 5)
                .unwrap(),
            ConditionalWindowStash::GloballyLastVisible
        ));
        assert_eq!(stored(&paths, "hidden-window"), before);
        assert_eq!(window_epoch(&paths), before_epoch);

        let recovery = service.load_snapshot("recovery-window").unwrap().unwrap();
        assert!(matches!(
            service
                .stash_if_unchanged_preserving_global_last(&recovery, 6)
                .unwrap(),
            ConditionalWindowStash::Stashed(_)
        ));
    }

    #[test]
    fn global_last_guard_fails_closed_for_unprojectable_visible_candidates() {
        for corrupt_project in [true, false] {
            let (_tmp, paths) = temp_paths();
            create_test_project(&paths, "valid-project");
            create_test_project(&paths, "phantom-project");
            create_owned_visible_test_window(&paths, "valid-project", "valid-window", "valid-pane");
            create_owned_visible_test_window(
                &paths,
                "phantom-project",
                "phantom-window",
                "phantom-pane",
            );
            let target = svc(&paths).load_snapshot("valid-window").unwrap().unwrap();

            let connection = crate::db::conn_for(paths.base()).unwrap();
            {
                let guard = connection.lock().unwrap();
                if corrupt_project {
                    // Valid JSON but an invalid enum: DashboardSnapshot quarantines this Project,
                    // so its raw window must not authorize hiding the only projectable window.
                    guard
                        .execute(
                            "UPDATE projects SET default_workspace_policy = '\"not_a_policy\"' \
                             WHERE project_id = 'phantom-project'",
                            [],
                        )
                        .unwrap();
                } else {
                    // Same shape at the WindowLayout layer: the raw non-stashed tab exists, but
                    // the typed window is unprojectable because its attention enum is invalid.
                    guard
                        .execute(
                            "UPDATE tabs SET attention_json = \
                             '{\"attention\":\"not_attention\",\"unseen\":false,\"since_ms\":0,\"source\":\"process\"}' \
                             WHERE tab_id = 'phantom-pane'",
                            [],
                        )
                        .unwrap();
                }
            }

            let before = stored(&paths, "valid-window");
            let before_epoch = window_epoch(&paths);
            let error = svc(&paths)
                .stash_if_unchanged_preserving_global_last(&target, 3)
                .unwrap_err();
            assert!(matches!(
                error,
                WindowLayoutError::Store(StoreError::Map(ref reason))
                    if reason.contains("global visibility candidate")
                        && reason.contains("not projectable")
            ));
            assert_eq!(stored(&paths, "valid-window"), before);
            assert_eq!(window_epoch(&paths), before_epoch);
        }
    }

    #[test]
    fn guarded_conditional_delete_preserves_global_last_but_allows_invisible_delete() {
        let (_tmp, paths) = temp_paths();
        for project_id in ["delete-project-a", "delete-project-b", "delete-project-c"] {
            create_test_project(&paths, project_id);
        }
        create_owned_visible_test_window(
            &paths,
            "delete-project-a",
            "delete-window-a",
            "delete-pane-a",
        );
        create_owned_visible_test_window(
            &paths,
            "delete-project-b",
            "delete-window-b",
            "delete-pane-b",
        );

        let service = svc(&paths);
        let first = service.load_snapshot("delete-window-a").unwrap().unwrap();
        assert!(matches!(
            service
                .delete_if_unchanged_preserving_global_last(&first, 3)
                .unwrap(),
            GuardedConditionalWindowDelete::Deleted(_)
        ));
        assert!(service.load("delete-window-a").unwrap().is_none());

        let last = service.load_snapshot("delete-window-b").unwrap().unwrap();
        let before = last.layout.clone();
        let refusal_epoch = window_epoch(&paths);
        assert!(matches!(
            service
                .delete_if_unchanged_preserving_global_last(&last, 4)
                .unwrap(),
            GuardedConditionalWindowDelete::GloballyLastVisible
        ));
        assert_eq!(stored(&paths, "delete-window-b"), before);
        assert_eq!(window_epoch(&paths), refusal_epoch);

        let third = create_owned_visible_test_window(
            &paths,
            "delete-project-c",
            "delete-window-c",
            "delete-pane-c",
        );
        let third = match service
            .stash_if_unchanged_preserving_global_last(&third, 5)
            .unwrap()
        {
            ConditionalWindowStash::Stashed(snapshot) => snapshot,
            outcome => panic!("expected third window stash, got {outcome:?}"),
        };
        assert!(matches!(
            service
                .delete_if_unchanged_preserving_global_last(&third, 6)
                .unwrap(),
            GuardedConditionalWindowDelete::Deleted(_)
        ));
        assert!(service.load("delete-window-c").unwrap().is_none());
        assert!(service
            .load("delete-window-b")
            .unwrap()
            .unwrap()
            .tabs
            .iter()
            .any(|tab| !tab.stashed));
    }

    #[test]
    fn guarded_pane_close_preserves_global_last_without_writing_or_journaling() {
        let (_tmp, paths) = temp_paths();
        create_test_project(&paths, "pane-close-project");
        seed_viewport_session(
            &paths,
            "session-pane-close-live",
            Some("generation-pane-close-live"),
        );
        create_owned_visible_test_window(
            &paths,
            "pane-close-project",
            "pane-close-window",
            "pane-close-live",
        );
        let before = stored(&paths, "pane-close-window");
        let before_epoch = window_epoch(&paths);
        let before_releases = pending_release_count(&paths);

        assert!(matches!(
            svc(&paths)
                .close_pane_with_removed_preserving_global_last(
                    "pane-close-window",
                    "pane-close-live",
                    3,
                )
                .unwrap(),
            GuardedWindowTabClose::GloballyLastVisible
        ));
        assert_eq!(stored(&paths, "pane-close-window"), before);
        assert_eq!(window_epoch(&paths), before_epoch);
        assert_eq!(pending_release_count(&paths), before_releases);
    }

    #[test]
    fn guarded_tab_close_preserves_global_last_without_writing_or_journaling() {
        let (_tmp, paths) = temp_paths();
        create_test_project(&paths, "tab-close-project");
        seed_viewport_session(
            &paths,
            "session-tab-close-live",
            Some("generation-tab-close-live"),
        );
        create_owned_visible_test_window(
            &paths,
            "tab-close-project",
            "tab-close-window",
            "tab-close-live",
        );
        let before = stored(&paths, "tab-close-window");
        let before_epoch = window_epoch(&paths);
        let before_releases = pending_release_count(&paths);

        assert!(matches!(
            svc(&paths)
                .close_tab_with_removed_preserving_global_last(
                    "tab-close-window",
                    "tab-close-live",
                    3,
                )
                .unwrap(),
            GuardedWindowTabClose::GloballyLastVisible
        ));
        assert_eq!(stored(&paths, "tab-close-window"), before);
        assert_eq!(window_epoch(&paths), before_epoch);
        assert_eq!(pending_release_count(&paths), before_releases);
    }

    #[test]
    fn guarded_tab_close_allows_another_visible_window() {
        let (_tmp, paths) = temp_paths();
        create_test_project(&paths, "tab-project-a");
        create_test_project(&paths, "tab-project-b");
        create_owned_visible_test_window(&paths, "tab-project-a", "tab-window-a", "tab-a");
        create_owned_visible_test_window(&paths, "tab-project-b", "tab-window-b", "tab-b");

        assert!(matches!(
            svc(&paths)
                .close_tab_with_removed_preserving_global_last("tab-window-a", "tab-a", 3)
                .unwrap(),
            GuardedWindowTabClose::Closed(_)
        ));
        assert!(!stored(&paths, "tab-window-a")
            .tabs
            .iter()
            .any(|tab| !tab.stashed));
        assert!(stored(&paths, "tab-window-b")
            .tabs
            .iter()
            .any(|tab| !tab.stashed));
    }

    #[test]
    fn guarded_pane_close_allows_another_visible_window_and_stashed_targets() {
        let (_tmp, paths) = temp_paths();
        create_test_project(&paths, "pane-project-a");
        create_test_project(&paths, "pane-project-b");
        create_owned_visible_test_window(&paths, "pane-project-a", "pane-window-a", "pane-a");
        create_owned_visible_test_window(&paths, "pane-project-b", "pane-window-b", "pane-b");
        svc(&paths)
            .open_tab(
                "pane-window-b",
                "pane-b-stashed",
                "session-pane-b-stashed",
                "pane-b-stashed",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        svc(&paths)
            .set_tab_stashed("pane-window-b", "pane-b-stashed", true, 3)
            .unwrap();

        assert!(matches!(
            svc(&paths)
                .close_pane_with_removed_preserving_global_last("pane-window-a", "pane-a", 4,)
                .unwrap(),
            GuardedWindowTabClose::Closed(_)
        ));
        assert!(!stored(&paths, "pane-window-a")
            .tabs
            .iter()
            .any(|tab| !tab.stashed));

        assert!(matches!(
            svc(&paths)
                .close_pane_with_removed_preserving_global_last(
                    "pane-window-b",
                    "pane-b-stashed",
                    5,
                )
                .unwrap(),
            GuardedWindowTabClose::Closed(_)
        ));
        assert!(stored(&paths, "pane-window-b")
            .tabs
            .iter()
            .any(|tab| !tab.stashed));
    }

    #[test]
    fn concurrent_leaf_stash_and_close_cannot_hide_the_global_last_window() {
        let (_tmp, paths) = temp_paths();
        create_test_project(&paths, "pane-race-project");
        create_owned_visible_test_window(
            &paths,
            "pane-race-project",
            "pane-race-window",
            "pane-race-a",
        );
        svc(&paths)
            .open_tab(
                "pane-race-window",
                "pane-race-b",
                "session-pane-race-b",
                "pane-race-b",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let stash_paths = paths.clone();
        let stash_barrier = barrier.clone();
        let stash = std::thread::spawn(move || {
            stash_barrier.wait();
            svc(&stash_paths).stash_pane("pane-race-window", "pane-race-a", 3)
        });
        let close_paths = paths.clone();
        let close = std::thread::spawn(move || {
            barrier.wait();
            svc(&close_paths).close_pane_with_removed_preserving_global_last(
                "pane-race-window",
                "pane-race-b",
                3,
            )
        });
        let _ = stash.join().unwrap();
        let _ = close.join().unwrap();

        assert!(stored(&paths, "pane-race-window")
            .tabs
            .iter()
            .any(|tab| !tab.stashed));
    }

    #[test]
    fn concurrent_global_last_visible_stashes_cannot_hide_both_projects() {
        let (_tmp, paths) = temp_paths();
        create_test_project(&paths, "race-project-a");
        create_test_project(&paths, "race-project-b");
        create_owned_visible_test_window(&paths, "race-project-a", "race-window-a", "race-pane-a");
        create_owned_visible_test_window(&paths, "race-project-b", "race-window-b", "race-pane-b");
        let first = svc(&paths).load_snapshot("race-window-a").unwrap().unwrap();
        let second = svc(&paths).load_snapshot("race-window-b").unwrap().unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

        let run = |paths: AppPaths,
                   expected: WindowLayoutSnapshot,
                   barrier: std::sync::Arc<std::sync::Barrier>| {
            std::thread::spawn(move || {
                barrier.wait();
                svc(&paths)
                    .stash_if_unchanged_preserving_global_last(&expected, 3)
                    .unwrap()
            })
        };
        let first_result = run(paths.clone(), first, barrier.clone());
        let second_result = run(paths.clone(), second, barrier);
        let outcomes = [first_result.join().unwrap(), second_result.join().unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ConditionalWindowStash::Stashed(_)))
                .count(),
            1
        );
        assert_eq!(
            ["race-window-a", "race-window-b"]
                .into_iter()
                .filter(|window_id| {
                    stored(&paths, window_id)
                        .tabs
                        .iter()
                        .any(|tab| !tab.stashed)
                })
                .count(),
            1
        );
    }

    fn seed_viewport_session(paths: &AppPaths, session_id: &str, generation: Option<&str>) {
        let project_id = "viewport-project";
        let workspace_id = "viewport-workspace";
        crate::ProjectService::new(paths)
            .create(
                project_id,
                "Viewport",
                "/tmp",
                crate::NewProject::default(),
                1,
            )
            .ok();
        if loaded_record::<Workspace>(paths, RecordKind::Workspace, workspace_id).is_none() {
            crate::write_record(
                paths,
                RecordKind::Workspace,
                workspace_id,
                1,
                &Workspace {
                    workspace_id: workspace_id.into(),
                    project_id: project_id.into(),
                    root: "/tmp".into(),
                    policy: crate::WorkspacePolicy::ScratchCwd,
                    consent: crate::WorkspaceConsent::default(),
                },
            )
            .unwrap();
        }
        crate::write_record(
            paths,
            RecordKind::Session,
            session_id,
            1,
            &SessionRecord {
                session_id: session_id.into(),
                workspace_id: workspace_id.into(),
                kind: crate::SessionKind::Shell,
                launch: crate::LaunchSpec::OptOut,
                cwd_resolved: "/tmp".into(),
                agent_task_id: None,
                created_at_ms: 1,
                last_attached_at_ms: 1,
                last_known_generation: generation.map(str::to_string),
                status: SessionStatus::Live,
            },
        )
        .unwrap();
    }

    #[test]
    fn viewport_snapshot_is_one_all_or_none_layout_and_visible_session_authority() {
        let (_tmp, paths) = temp_paths();
        seed_viewport_session(&paths, "viewport-a", Some("generation-a"));
        seed_viewport_session(&paths, "viewport-b", Some("generation-b"));
        let service = svc(&paths);
        service.create_empty("viewport-window", 1).unwrap();
        service
            .open_tab(
                "viewport-window",
                "tab-a",
                "viewport-a",
                "A",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        service
            .split_tab(
                "viewport-window",
                "tab-a",
                "tab-b",
                "viewport-b",
                "B",
                SplitAxis::Right,
                3,
            )
            .unwrap();
        // A stashed unresolved id remains durable ownership but is not a renderer role.
        service
            .open_tab(
                "viewport-window",
                "tab-stashed",
                "unresolved-stashed-session",
                "Stashed",
                false,
                AttentionState::default(),
                4,
            )
            .unwrap();
        service
            .set_tab_stashed("viewport-window", "tab-stashed", true, 5)
            .unwrap();

        let snapshot = service.load_viewport_snapshot("viewport-window").unwrap();
        assert_eq!(snapshot.window().layout.tabs.len(), 3);
        assert_eq!(snapshot.panes().len(), 2);
        assert_eq!(
            snapshot
                .pane_for_tab("tab-a")
                .map(WindowViewportPane::generation),
            Some("generation-a")
        );
        assert_eq!(
            snapshot
                .pane_for_tab("tab-b")
                .map(WindowViewportPane::generation),
            Some("generation-b")
        );
        assert!(snapshot.pane_for_tab("tab-stashed").is_none());
    }

    #[test]
    fn viewport_snapshot_rejects_any_visible_missing_or_unproven_session() {
        let (_tmp, paths) = temp_paths();
        seed_viewport_session(&paths, "viewport-a", Some("generation-a"));
        let service = svc(&paths);
        service.create_empty("viewport-window", 1).unwrap();
        service
            .open_tab(
                "viewport-window",
                "tab-a",
                "viewport-a",
                "A",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        service
            .split_tab(
                "viewport-window",
                "tab-a",
                "tab-missing",
                "viewport-missing",
                "Missing",
                SplitAxis::Right,
                3,
            )
            .unwrap();
        assert!(matches!(
            service.load_viewport_snapshot("viewport-window"),
            Err(WindowViewportSnapshotError::SessionMissing {
                tab_id,
                session_id
            }) if tab_id == "tab-missing" && session_id == "viewport-missing"
        ));

        seed_viewport_session(&paths, "viewport-missing", None);
        assert!(matches!(
            service.load_viewport_snapshot("viewport-window"),
            Err(WindowViewportSnapshotError::SessionGenerationUnavailable {
                tab_id,
                session_id
            }) if tab_id == "tab-missing" && session_id == "viewport-missing"
        ));

        for invalid in [String::new(), "x".repeat(129)] {
            seed_viewport_session(&paths, "viewport-missing", Some(&invalid));
            assert!(matches!(
                service.load_viewport_snapshot("viewport-window"),
                Err(WindowViewportSnapshotError::SessionGenerationUnavailable {
                    tab_id,
                    session_id
                }) if tab_id == "tab-missing" && session_id == "viewport-missing"
            ));
        }
    }

    #[test]
    fn viewport_snapshot_allows_duplicate_session_roles_only_with_one_coherent_lifetime() {
        let (_tmp, paths) = temp_paths();
        seed_viewport_session(&paths, "viewport-shared", Some("generation-shared"));
        let service = svc(&paths);
        service.create_empty("viewport-window", 1).unwrap();
        service
            .open_tab(
                "viewport-window",
                "tab-a",
                "viewport-shared",
                "A",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        service
            .split_tab(
                "viewport-window",
                "tab-a",
                "tab-b",
                "viewport-shared",
                "B",
                SplitAxis::Right,
                3,
            )
            .unwrap();
        let snapshot = service.load_viewport_snapshot("viewport-window").unwrap();
        assert_eq!(snapshot.panes().len(), 2);
        assert!(snapshot.panes().iter().all(|pane| {
            pane.session_id() == "viewport-shared" && pane.generation() == "generation-shared"
        }));
    }

    #[test]
    fn viewport_snapshot_layout_and_sessions_share_one_deferred_database_version() {
        let (_tmp, paths) = temp_paths();
        let window_id = "viewport-window-deferred-database-version";
        seed_viewport_session(&paths, "viewport-a", Some("generation-a"));
        let service = svc(&paths);
        service.create_empty(window_id, 1).unwrap();
        service
            .open_tab(
                window_id,
                "tab-a",
                "viewport-a",
                "A",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();

        let db_path = crate::db::db_path(paths.base());
        let mut replacement =
            loaded_record::<SessionRecord>(&paths, RecordKind::Session, "viewport-a").unwrap();
        replacement.last_known_generation = Some("generation-b".into());
        let replacement_for_hook = replacement.clone();
        let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let fired_worker = std::sync::Arc::clone(&fired);
        let _hook =
            crate::store_sqlite::install_window_layout_test_hook(window_id, move |stage, _| {
                if stage != "after-window-before-tabs"
                    || fired_worker.swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    return;
                }
                let mut other = rusqlite::Connection::open(&db_path).unwrap();
                other.pragma_update(None, "foreign_keys", "ON").unwrap();
                other.pragma_update(None, "busy_timeout", 5000).unwrap();
                let tx = other
                    .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                    .unwrap();
                crate::store_sqlite::upsert(
                    &tx,
                    RecordKind::Session,
                    &replacement_for_hook.session_id,
                    &serde_json::to_value(&replacement_for_hook).unwrap(),
                )
                .unwrap();
                tx.commit().unwrap();
            });

        let snapshot = service.load_viewport_snapshot(window_id).unwrap();
        assert!(fired.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            snapshot.pane_for_tab("tab-a").unwrap().generation(),
            "generation-a",
            "the Session read must stay on the layout's DEFERRED snapshot"
        );
        assert_eq!(
            loaded_record::<SessionRecord>(&paths, RecordKind::Session, "viewport-a")
                .unwrap()
                .last_known_generation
                .as_deref(),
            Some("generation-b")
        );
    }

    fn fresh_graph_spec(project_id: &str, suffix: &str) -> FreshWindowGraphSpec {
        let workspace_id = format!("fresh-workspace-{suffix}");
        FreshWindowGraphSpec {
            workspace: Workspace {
                workspace_id: workspace_id.clone(),
                project_id: project_id.to_string(),
                root: format!("/fresh/{suffix}"),
                policy: crate::WorkspacePolicy::ScratchCwd,
                consent: crate::WorkspaceConsent::default(),
            },
            session: SessionRecord {
                session_id: format!("fresh-session-{suffix}"),
                workspace_id,
                kind: crate::SessionKind::Shell,
                launch: crate::LaunchSpec::OptOut,
                cwd_resolved: format!("/fresh/{suffix}"),
                agent_task_id: None,
                created_at_ms: 10,
                last_attached_at_ms: 10,
                last_known_generation: None,
                status: SessionStatus::Unknown,
            },
            window_id: format!("fresh-window-{suffix}"),
            window_name: "Fresh Window".into(),
            tab_id: format!("fresh-tab-{suffix}"),
            tab_title: "shell".into(),
            tab_pinned: false,
            tab_attention: AttentionState::default(),
            touch_project: false,
        }
    }

    fn is_fresh_graph_trace(
        trace: &crate::write_trace::WriteTrace,
        project_id: &str,
        spec: &FreshWindowGraphSpec,
        ts_ms: u64,
    ) -> bool {
        trace.ts_ms == ts_ms
            && match trace.kind.as_str() {
                "Project" => trace.id == project_id,
                "Workspace" => trace.id == spec.workspace.workspace_id,
                "Session" => trace.id == spec.session.session_id,
                "WindowLayout" | "WindowOwner" => trace.id == spec.window_id,
                _ => false,
            }
    }

    fn loaded_record<T: serde::de::DeserializeOwned>(
        paths: &AppPaths,
        kind: RecordKind,
        id: &str,
    ) -> Option<T> {
        match crate::store::load_one(paths, kind, id).unwrap() {
            Some(crate::store::LoadOutcome::Loaded(record)) => Some(record),
            Some(crate::store::LoadOutcome::FutureVersion { .. })
            | Some(crate::store::LoadOutcome::Quarantined { .. }) => {
                panic!("test fixture record did not load")
            }
            None => None,
        }
    }

    fn raw_record_value(paths: &AppPaths, kind: RecordKind, id: &str) -> Option<serde_json::Value> {
        let connection = crate::db::conn_for(paths.base()).unwrap();
        let guard = connection.lock().unwrap();
        crate::store_sqlite::load_one(&guard, kind, id).unwrap()
    }

    fn created_graph(outcome: FreshWindowGraphCreateOutcome) -> CreatedFreshWindowGraph {
        match outcome {
            FreshWindowGraphCreateOutcome::Created(created) => created,
            other => panic!("expected fresh graph creation, got {other:?}"),
        }
    }

    fn create_fixture_project(paths: &AppPaths, project_id: &str) -> Project {
        crate::ProjectService::new(paths)
            .create(
                project_id,
                "Fresh Project",
                "/fresh",
                crate::NewProject::default(),
                1,
            )
            .unwrap()
    }

    fn stored_project(paths: &AppPaths, project_id: &str) -> Project {
        loaded_record(paths, RecordKind::Project, project_id).expect("fixture Project exists")
    }

    fn stored_graph_project_snapshot(
        paths: &AppPaths,
        project_id: &str,
    ) -> ProjectWindowGraphSnapshot {
        svc(paths)
            .load_project_window_graph_snapshot(project_id)
            .unwrap()
            .expect("fixture Project graph snapshot exists")
    }

    fn prepared_params(workspace_id: &str, session_id: &str, cwd: &std::path::Path) -> StartParams {
        StartParams::adhoc(
            session_id,
            workspace_id,
            crate::SessionKind::Shell,
            cwd.to_string_lossy(),
            &[
                "secret-command-must-not-appear".into(),
                "secret-argument-must-not-appear".into(),
            ],
            80,
            24,
            50,
        )
    }

    #[test]
    fn prepared_generic_start_refuses_unbound_launch_metadata_and_agent_kind() {
        let (_tmp, paths) = temp_paths();
        let cwd = TempDir::new().unwrap();
        let (project, workspace, window) =
            prepared_existing_target(&paths, cwd.path(), "launch-binding");
        let before = svc(&paths).load_snapshot(&window.layout.window_id).unwrap();

        let mut known_safe =
            prepared_params(&workspace.workspace_id, "prepared-known-safe", cwd.path());
        known_safe.launch = crate::LaunchSpec::KnownSafe {
            launch_spec_id: "provider".into(),
            params: Vec::new(),
        };
        assert!(svc(&paths)
            .prepare_new_tab_session(
                &window,
                &project,
                &workspace,
                known_safe,
                "prepared-known-safe-tab",
                "Known safe",
                false,
                AttentionState::default(),
            )
            .is_err());

        let mut retargeted =
            prepared_params(&workspace.workspace_id, "prepared-retargeted", cwd.path());
        retargeted.command = "foreign-command".into();
        assert!(svc(&paths)
            .prepare_new_tab_session(
                &window,
                &project,
                &workspace,
                retargeted,
                "prepared-retargeted-tab",
                "Retargeted",
                false,
                AttentionState::default(),
            )
            .is_err());

        let mut agent = prepared_params(&workspace.workspace_id, "prepared-agent", cwd.path());
        agent.kind = crate::SessionKind::Agent;
        assert!(svc(&paths)
            .prepare_new_tab_session(
                &window,
                &project,
                &workspace,
                agent,
                "prepared-agent-tab",
                "Agent",
                false,
                AttentionState::default(),
            )
            .is_err());

        assert_eq!(
            svc(&paths).load_snapshot(&window.layout.window_id).unwrap(),
            before
        );
        for session_id in [
            "prepared-known-safe",
            "prepared-retargeted",
            "prepared-agent",
        ] {
            assert!(
                loaded_record::<SessionRecord>(&paths, RecordKind::Session, session_id).is_none()
            );
        }
    }

    #[test]
    fn prepared_taskless_unplaced_start_seals_graph_and_compensates_exact_unknown() {
        let (_tmp, paths) = temp_paths();
        let cwd = TempDir::new().unwrap();
        let (project, workspace, _window) =
            prepared_existing_target(&paths, cwd.path(), "taskless-unplaced");
        let session_id = "prepared-taskless-unplaced-session";
        let spec = crate::PreparedWorkspace::unsealed(
            workspace.policy,
            workspace.workspace_id.clone(),
            session_id,
            cwd.path(),
        )
        .adhoc_session_spec(crate::SessionKind::Shell, &["/bin/sh".into()], 80, 24, 50)
        .unwrap();

        let start = svc(&paths)
            .prepare_unplaced_session_with_spec(&project, &workspace, spec)
            .unwrap();
        assert_eq!(start.session_id(), session_id);
        assert_eq!(start.window_id(), None);
        assert_eq!(start.tab_id(), None);
        assert!(start.graph_matches_in_snapshot(&paths).unwrap());
        assert_eq!(
            loaded_record::<SessionRecord>(&paths, RecordKind::Session, session_id)
                .unwrap()
                .status,
            SessionStatus::Unknown
        );

        assert!(matches!(
            svc(&paths).cancel_prepared_new_session(start, 51).unwrap(),
            ConditionalPreparedNewSessionCompensation::Unplaced(
                ConditionalPreparedUnplacedSessionRollback::RolledBack
            )
        ));
        assert!(loaded_record::<SessionRecord>(&paths, RecordKind::Session, session_id).is_none());
    }

    #[test]
    fn prepared_agent_task_journal_and_diagnostics_omit_live_secrets() {
        let (_tmp, paths) = temp_paths();
        let root = TempDir::new().unwrap();
        let cwd = root.path().join("private-cwd-secret-marker");
        std::fs::create_dir(&cwd).unwrap();
        let (project, workspace, _window) =
            prepared_existing_target(&paths, &cwd, "journal-privacy");
        let task_id = "prepared-journal-privacy-task";
        let session_id = "prepared-journal-privacy-session";
        let task = AgentTask {
            agent_task_id: task_id.into(),
            project_id: project.project_id.clone(),
            goal: "private-goal-secret-marker".into(),
            state: AgentTaskState::Draft,
            current_session_id: None,
            session_history: Vec::new(),
            created_at_ms: 50,
            updated_at_ms: 50,
            result_summary: None,
        };
        let spec = crate::PreparedWorkspace::unsealed(
            workspace.policy,
            workspace.workspace_id.clone(),
            session_id,
            cwd,
        )
        .adhoc_session_spec(
            crate::SessionKind::Agent,
            &[
                "custom-agent".into(),
                "--api-key=raw-live-secret-marker".into(),
            ],
            80,
            24,
            50,
        )
        .unwrap();

        let start = svc(&paths)
            .prepare_new_agent_task_unplaced_session(&project, &workspace, task, spec)
            .unwrap();
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        let journal_text: String = conn
            .query_row(
                "SELECT session_id || '|' || agent_task_id || '|' || project_id || '|' || \
                        workspace_id || '|' || operation_token || '|' || binding_state || '|' || \
                        COALESCE(daemon_instance_id, '') || '|' || COALESCE(socket_path, '') || '|' || \
                        publication_launch_json || '|' || disposition || '|' || \
                        COALESCE(applied_generation, '') || '|' || COALESCE(applied_state, '') || '|' || \
                        lease_token \
                 FROM pending_agent_task_starts WHERE session_id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .unwrap();
        drop(conn);
        for secret in [
            "raw-live-secret-marker",
            "private-cwd-secret-marker",
            "private-goal-secret-marker",
        ] {
            assert!(!journal_text.contains(secret));
            assert!(!format!("{start:?}").contains(secret));
            assert!(!format!("{:?}", start.journal()).contains(secret));
            let matching_traces = crate::write_trace::recent()
                .into_iter()
                .filter(|trace| trace.id == task_id || trace.id == session_id)
                .collect::<Vec<_>>();
            assert!(!serde_json::to_string(&matching_traces)
                .unwrap()
                .contains(secret));
        }

        assert!(matches!(
            svc(&paths)
                .cancel_prepared_agent_task_session(start, 51)
                .unwrap(),
            ConditionalPreparedNewSessionCompensation::Unplaced(
                ConditionalPreparedUnplacedSessionRollback::RolledBack
            )
        ));
    }

    fn prepared_existing_target(
        paths: &AppPaths,
        cwd: &std::path::Path,
        suffix: &str,
    ) -> (Project, Workspace, WindowLayoutSnapshot) {
        let project_id = format!("prepared-project-{suffix}");
        create_fixture_project(paths, &project_id);
        let mut spec = fresh_graph_spec(&project_id, suffix);
        spec.workspace.root = cwd.to_string_lossy().into_owned();
        spec.session.cwd_resolved = spec.workspace.root.clone();
        let created = created_graph(
            svc(paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(paths, &project_id),
                    spec,
                    10,
                )
                .unwrap(),
        );
        (created.project, created.workspace, created.window)
    }

    fn init_prepared_worktree_repo() -> TempDir {
        let repo = TempDir::new().unwrap();
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "prepared@example.invalid"]);
        git(&["config", "user.name", "Prepared Test"]);
        git(&["commit", "-q", "--allow-empty", "-m", "base"]);
        repo
    }

    fn prepared_worktree_existing_target(
        paths: &AppPaths,
        repo: &std::path::Path,
        suffix: &str,
    ) -> (Project, Workspace, WindowLayoutSnapshot) {
        let project_id = format!("prepared-worktree-project-{suffix}");
        create_fixture_project(paths, &project_id);
        let mut spec = fresh_graph_spec(&project_id, suffix);
        spec.workspace.root = repo.to_string_lossy().into_owned();
        spec.workspace.policy = crate::WorkspacePolicy::Worktree;
        spec.workspace.consent = crate::WorkspaceConsent {
            worktree_create: true,
            repo_write: false,
            granted_at_ms: Some(1),
        };
        spec.session.cwd_resolved = spec.workspace.root.clone();
        let created = created_graph(
            svc(paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(paths, &project_id),
                    spec,
                    10,
                )
                .unwrap(),
        );
        (created.project, created.workspace, created.window)
    }

    fn prepared_worktree_session_spec(
        paths: &AppPaths,
        workspace: &Workspace,
        session_id: &str,
    ) -> PreparedSessionSpec {
        crate::prepare_workspace_with_consent(
            paths,
            crate::WorkspacePolicy::Worktree,
            workspace,
            session_id,
        )
        .unwrap()
        .adhoc_session_spec(crate::SessionKind::Shell, &["/bin/sh".into()], 80, 24, 50)
        .unwrap()
    }

    #[test]
    fn prepared_worktree_exact_marker_or_best_effort_absence_is_admitted() {
        for marker_present in [true, false] {
            let (_tmp, paths) = temp_paths();
            let repo = init_prepared_worktree_repo();
            let suffix = if marker_present { "exact" } else { "absent" };
            let (project, workspace, window) =
                prepared_worktree_existing_target(&paths, repo.path(), suffix);
            let session_id = format!("prepared-worktree-session-{suffix}");
            let spec = prepared_worktree_session_spec(&paths, &workspace, &session_id);
            if !marker_present {
                let connection = crate::db::conn_for(paths.base()).unwrap();
                connection
                    .lock()
                    .unwrap()
                    .execute(
                        "DELETE FROM worktree_provenance WHERE session_id = ?1",
                        [&session_id],
                    )
                    .unwrap();
            }

            let start = svc(&paths)
                .prepare_new_tab_session_with_spec(
                    &window,
                    &project,
                    &workspace,
                    spec,
                    &format!("prepared-worktree-tab-{suffix}"),
                    "Worktree",
                    false,
                    AttentionState::default(),
                )
                .unwrap();
            assert!(start.graph_matches_in_snapshot(&paths).unwrap());
            assert_eq!(start.session_id(), session_id);
        }
    }

    #[test]
    fn prepared_worktree_mismatched_marker_cohort_is_refused_without_graph_write() {
        for mismatch in ["workspace", "repo_root", "target_path", "branch"] {
            let (_tmp, paths) = temp_paths();
            let repo = init_prepared_worktree_repo();
            let (project, workspace, window) =
                prepared_worktree_existing_target(&paths, repo.path(), mismatch);
            let session_id = format!("prepared-worktree-session-{mismatch}");
            let tab_id = format!("prepared-worktree-tab-{mismatch}");
            let spec = prepared_worktree_session_spec(&paths, &workspace, &session_id);

            let connection = crate::db::conn_for(paths.base()).unwrap();
            let guard = connection.lock().unwrap();
            match mismatch {
                "workspace" => {
                    let foreign = Workspace {
                        workspace_id: "prepared-worktree-foreign-workspace".into(),
                        project_id: project.project_id.clone(),
                        root: repo.path().to_string_lossy().into_owned(),
                        policy: crate::WorkspacePolicy::ScratchCwd,
                        consent: crate::WorkspaceConsent::default(),
                    };
                    crate::store_sqlite::upsert(
                        &guard,
                        RecordKind::Workspace,
                        &foreign.workspace_id,
                        &serde_json::to_value(&foreign).unwrap(),
                    )
                    .unwrap();
                    guard
                        .execute(
                            "UPDATE worktree_provenance SET workspace_id = ?1 WHERE session_id = ?2",
                            rusqlite::params![foreign.workspace_id, session_id],
                        )
                        .unwrap();
                }
                "repo_root" => {
                    guard
                        .execute(
                            "UPDATE worktree_provenance SET repo_root = '/foreign/repo' WHERE session_id = ?1",
                            [&session_id],
                        )
                        .unwrap();
                }
                "target_path" => {
                    guard
                        .execute(
                            "UPDATE worktree_provenance SET target_path = '/foreign/worktree' WHERE session_id = ?1",
                            [&session_id],
                        )
                        .unwrap();
                }
                "branch" => {
                    guard
                        .execute(
                            "UPDATE worktree_provenance SET branch = 'maestro/foreign/branch' WHERE session_id = ?1",
                            [&session_id],
                        )
                        .unwrap();
                }
                _ => unreachable!(),
            }
            drop(guard);

            assert!(matches!(
                svc(&paths).prepare_new_tab_session_with_spec(
                    &window,
                    &project,
                    &workspace,
                    spec,
                    &tab_id,
                    "Worktree",
                    false,
                    AttentionState::default(),
                ),
                Err(WindowLayoutError::SessionIdentityReferenced { session_id: refused })
                    if refused == session_id
            ));
            assert!(
                loaded_record::<SessionRecord>(&paths, RecordKind::Session, &session_id).is_none()
            );
            assert_eq!(
                svc(&paths).load_snapshot(&window.layout.window_id).unwrap(),
                Some(window)
            );
        }
    }

    #[test]
    fn caller_constructed_unsealed_worktree_cannot_admit_present_marker() {
        let (_tmp, paths) = temp_paths();
        let repo = init_prepared_worktree_repo();
        let (project, workspace, window) =
            prepared_worktree_existing_target(&paths, repo.path(), "unsealed");
        let session_id = "prepared-worktree-session-unsealed";
        let prepared = crate::prepare_workspace_with_consent(
            &paths,
            crate::WorkspacePolicy::Worktree,
            &workspace,
            session_id,
        )
        .unwrap();
        let forged = crate::PreparedWorkspace::unsealed(
            crate::WorkspacePolicy::Worktree,
            workspace.workspace_id.clone(),
            session_id,
            prepared.cwd.clone(),
        )
        .adhoc_session_spec(crate::SessionKind::Shell, &["/bin/sh".into()], 80, 24, 50)
        .unwrap();

        assert!(matches!(
            svc(&paths).prepare_new_tab_session_with_spec(
                &window,
                &project,
                &workspace,
                forged,
                "prepared-worktree-tab-unsealed",
                "Worktree",
                false,
                AttentionState::default(),
            ),
            Err(WindowLayoutError::Store(_))
        ));
        assert!(loaded_record::<SessionRecord>(&paths, RecordKind::Session, session_id).is_none());
        assert_eq!(
            svc(&paths).load_snapshot(&window.layout.window_id).unwrap(),
            Some(window)
        );
    }

    fn prepared_source_session(paths: &AppPaths, window: &WindowLayoutSnapshot) -> SessionRecord {
        let session_id = &window.layout.tabs[0].session_id;
        loaded_record(paths, RecordKind::Session, session_id)
            .expect("prepared fixture source Session exists")
    }

    #[test]
    fn prepared_stashed_tab_preserves_visible_geometry_and_inserts_unknown_atomically() {
        let (_tmp, paths) = temp_paths();
        let cwd = TempDir::new().unwrap();
        let (project, workspace, window) =
            prepared_existing_target(&paths, cwd.path(), "stashed-tab");
        let visible_before = window.layout.tabs[0].clone();
        let session_id = "prepared-stashed-session";
        let tab_id = "prepared-stashed-tab";

        let start = svc(&paths)
            .prepare_new_stashed_tab_session_with_spec(
                &window,
                &project,
                &workspace,
                PreparedSessionSpec::from_legacy_shell(prepared_params(
                    &workspace.workspace_id,
                    session_id,
                    cwd.path(),
                )),
                tab_id,
                "Remote",
                false,
                AttentionState::default(),
            )
            .unwrap();

        let after = svc(&paths)
            .load_snapshot(&window.layout.window_id)
            .unwrap()
            .unwrap();
        let visible_after = after
            .layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == visible_before.tab_id)
            .unwrap();
        assert_eq!(visible_after.pane_rect, visible_before.pane_rect);
        let stashed = after
            .layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == tab_id)
            .unwrap();
        assert!(stashed.stashed);
        assert!(stashed.pane_rect.is_none());
        let unknown: SessionRecord =
            loaded_record(&paths, RecordKind::Session, session_id).unwrap();
        assert_eq!(unknown.status, SessionStatus::Unknown);
        assert_eq!(start.session_id(), session_id);
    }

    #[test]
    fn prepared_source_bound_split_refuses_source_replacement_and_tab_retarget() {
        {
            let (_tmp, paths) = temp_paths();
            let cwd = TempDir::new().unwrap();
            let (project, workspace, window) =
                prepared_existing_target(&paths, cwd.path(), "source-replacement");
            let source = prepared_source_session(&paths, &window);
            let mut replacement = source.clone();
            replacement.last_attached_at_ms += 1;
            crate::store::write_record(
                &paths,
                RecordKind::Session,
                &replacement.session_id,
                20,
                &replacement,
            )
            .unwrap();

            assert!(matches!(
                svc(&paths).prepare_new_split_session_from_source(
                    &window,
                    &project,
                    &workspace,
                    &source,
                    prepared_params(
                        &workspace.workspace_id,
                        "source-replacement-child",
                        cwd.path()
                    ),
                    &window.layout.tabs[0].tab_id,
                    "source-replacement-child-tab",
                    "Child",
                    SplitAxis::Right,
                ),
                Err(WindowLayoutError::WindowLayoutChanged { .. })
            ));
            assert!(loaded_record::<SessionRecord>(
                &paths,
                RecordKind::Session,
                "source-replacement-child"
            )
            .is_none());
        }

        {
            let (_tmp, paths) = temp_paths();
            let cwd = TempDir::new().unwrap();
            let (project, workspace, window) =
                prepared_existing_target(&paths, cwd.path(), "source-retarget");
            let source = prepared_source_session(&paths, &window);
            let foreign = SessionRecord {
                session_id: "source-retarget-foreign".into(),
                workspace_id: workspace.workspace_id.clone(),
                kind: crate::SessionKind::Shell,
                launch: crate::LaunchSpec::OptOut,
                cwd_resolved: workspace.root.clone(),
                agent_task_id: None,
                created_at_ms: 20,
                last_attached_at_ms: 20,
                last_known_generation: Some("foreign-generation".into()),
                status: SessionStatus::Live,
            };
            crate::store::write_record(
                &paths,
                RecordKind::Session,
                &foreign.session_id,
                20,
                &foreign,
            )
            .unwrap();
            svc(&paths)
                .retarget_tab_session(
                    &window.layout.window_id,
                    &window.layout.tabs[0].tab_id,
                    &foreign.session_id,
                    21,
                )
                .unwrap();

            assert!(matches!(
                svc(&paths).prepare_new_split_session_from_source(
                    &window,
                    &project,
                    &workspace,
                    &source,
                    prepared_params(&workspace.workspace_id, "source-retarget-child", cwd.path()),
                    &window.layout.tabs[0].tab_id,
                    "source-retarget-child-tab",
                    "Child",
                    SplitAxis::Right,
                ),
                Err(WindowLayoutError::WindowLayoutChanged { .. })
            ));
            assert!(loaded_record::<SessionRecord>(
                &paths,
                RecordKind::Session,
                "source-retarget-child"
            )
            .is_none());
        }
    }

    #[test]
    fn prepared_source_bound_split_keeps_source_in_pre_wire_and_final_fence() {
        let (_tmp, paths) = temp_paths();
        let cwd = TempDir::new().unwrap();
        let (project, workspace, window) =
            prepared_existing_target(&paths, cwd.path(), "source-fence");
        let source = prepared_source_session(&paths, &window);
        let start = svc(&paths)
            .prepare_new_split_session_from_source(
                &window,
                &project,
                &workspace,
                &source,
                prepared_params(&workspace.workspace_id, "source-fence-child", cwd.path()),
                &window.layout.tabs[0].tab_id,
                "source-fence-child-tab",
                "Child",
                SplitAxis::Down,
            )
            .unwrap();
        assert!(start.graph_matches_in_snapshot(&paths).unwrap());

        let mut replacement = source;
        replacement.last_attached_at_ms += 1;
        crate::store::write_record(
            &paths,
            RecordKind::Session,
            &replacement.session_id,
            22,
            &replacement,
        )
        .unwrap();
        assert!(!start.graph_matches_in_snapshot(&paths).unwrap());
        assert!(matches!(
            svc(&paths).cancel_prepared_new_session(start, 23).unwrap(),
            ConditionalPreparedNewSessionCompensation::ExistingWindow(
                ConditionalCreatedTabSessionRollback::RolledBack(_)
            )
        ));
    }

    #[test]
    fn prepared_existing_start_is_non_clone_redacted_and_cancelable() {
        trait AmbiguousIfClone<Marker> {
            fn assert_not_clone() {}
        }
        impl<T> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}
        let _ = <PreparedNewSessionStart as AmbiguousIfClone<_>>::assert_not_clone;
        let _ = <PreparedNewSessionCompensationReceipt as AmbiguousIfClone<_>>::assert_not_clone;

        let (_tmp, paths) = temp_paths();
        let cwd = TempDir::new().unwrap();
        let (project, workspace, window) = prepared_existing_target(&paths, cwd.path(), "redacted");
        let start = svc(&paths)
            .prepare_new_tab_session(
                &window,
                &project,
                &workspace,
                prepared_params(&workspace.workspace_id, "prepared-redacted", cwd.path()),
                "prepared-redacted-tab",
                "Prepared",
                false,
                AttentionState::default(),
            )
            .unwrap();
        let debug = format!("{start:?}");
        assert!(!debug.contains("secret-command"));
        assert!(!debug.contains("secret-argument"));
        assert!(!debug.contains(cwd.path().to_string_lossy().as_ref()));

        let cancelled = svc(&paths).cancel_prepared_new_session(start, 60).unwrap();
        assert!(matches!(
            cancelled,
            ConditionalPreparedNewSessionCompensation::ExistingWindow(
                ConditionalCreatedTabSessionRollback::RolledBack(_)
            )
        ));
        assert!(
            loaded_record::<SessionRecord>(&paths, RecordKind::Session, "prepared-redacted")
                .is_none()
        );
    }

    #[test]
    fn prepared_existing_compensation_refuses_workspace_and_preset_owner_races() {
        {
            let (_tmp, paths) = temp_paths();
            let cwd = TempDir::new().unwrap();
            let (project, workspace, window) =
                prepared_existing_target(&paths, cwd.path(), "comp-workspace");
            let session_id = "prepared-comp-workspace";
            let tab_id = "prepared-comp-workspace-tab";
            let start = svc(&paths)
                .prepare_new_tab_session(
                    &window,
                    &project,
                    &workspace,
                    prepared_params(&workspace.workspace_id, session_id, cwd.path()),
                    tab_id,
                    "Prepared",
                    false,
                    AttentionState::default(),
                )
                .unwrap();
            let receipt = start.initial_compensation();
            let mut changed_workspace = workspace.clone();
            changed_workspace.root.push_str("-foreign");
            crate::store::write_record(
                &paths,
                RecordKind::Workspace,
                &changed_workspace.workspace_id,
                60,
                &changed_workspace,
            )
            .unwrap();

            assert!(matches!(
                svc(&paths)
                    .compensate_prepared_new_session(receipt, 61)
                    .unwrap(),
                ConditionalPreparedNewSessionCompensation::ExistingWindow(
                    ConditionalCreatedTabSessionRollback::Changed
                )
            ));
            assert!(
                loaded_record::<SessionRecord>(&paths, RecordKind::Session, session_id).is_some()
            );
            assert!(svc(&paths)
                .load_snapshot(&window.layout.window_id)
                .unwrap()
                .unwrap()
                .layout
                .tabs
                .iter()
                .any(|tab| tab.tab_id == tab_id));
        }

        {
            let (_tmp, paths) = temp_paths();
            let cwd = TempDir::new().unwrap();
            let (project, workspace, window) =
                prepared_existing_target(&paths, cwd.path(), "comp-preset");
            let session_id = "prepared-comp-preset";
            let tab_id = "prepared-comp-preset-tab";
            let start = svc(&paths)
                .prepare_new_tab_session(
                    &window,
                    &project,
                    &workspace,
                    prepared_params(&workspace.workspace_id, session_id, cwd.path()),
                    tab_id,
                    "Prepared",
                    false,
                    AttentionState::default(),
                )
                .unwrap();
            let receipt = start.initial_compensation();
            let preset = crate::records::LayoutPreset {
                preset_id: "prepared-comp-preset-owner".into(),
                name: "Owner".into(),
                project_id: Some(project.project_id.clone()),
                created_at_ms: 60,
                tabs: vec![crate::records::LayoutPresetTab {
                    index: 0,
                    title: "Owner".into(),
                    pinned: false,
                    split_from: None,
                    session_id: Some(session_id.into()),
                    source_tab_id: "owner-source".into(),
                }],
            };
            crate::store::write_record(
                &paths,
                RecordKind::LayoutPreset,
                &preset.preset_id,
                60,
                &preset,
            )
            .unwrap();

            assert!(matches!(
                svc(&paths)
                    .compensate_prepared_new_session(receipt, 61)
                    .unwrap(),
                ConditionalPreparedNewSessionCompensation::ExistingWindow(
                    ConditionalCreatedTabSessionRollback::Referenced
                )
            ));
            assert!(
                loaded_record::<SessionRecord>(&paths, RecordKind::Session, session_id).is_some()
            );
            assert!(svc(&paths)
                .load_snapshot(&window.layout.window_id)
                .unwrap()
                .unwrap()
                .layout
                .tabs
                .iter()
                .any(|tab| tab.tab_id == tab_id));
        }
    }

    #[test]
    fn prepared_existing_start_refuses_session_workspace_and_project_races_without_layout_write() {
        let (_tmp, paths) = temp_paths();
        let cwd = TempDir::new().unwrap();
        let (project, workspace, window) = prepared_existing_target(&paths, cwd.path(), "races");
        let before = svc(&paths).load_snapshot(&window.layout.window_id).unwrap();

        let colliding = SessionRecord {
            session_id: "prepared-collision".into(),
            workspace_id: workspace.workspace_id.clone(),
            kind: crate::SessionKind::Shell,
            launch: crate::LaunchSpec::OptOut,
            cwd_resolved: workspace.root.clone(),
            agent_task_id: None,
            created_at_ms: 20,
            last_attached_at_ms: 20,
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        crate::store::write_record(
            &paths,
            RecordKind::Session,
            &colliding.session_id,
            20,
            &colliding,
        )
        .unwrap();
        assert!(matches!(
            svc(&paths).prepare_new_tab_session(
                &window,
                &project,
                &workspace,
                prepared_params(&workspace.workspace_id, &colliding.session_id, cwd.path()),
                "prepared-collision-tab",
                "Collision",
                false,
                AttentionState::default(),
            ),
            Err(WindowLayoutError::SessionAlreadyExists { .. })
        ));
        assert_eq!(
            svc(&paths).load_snapshot(&window.layout.window_id).unwrap(),
            before
        );

        let mut changed_workspace = workspace.clone();
        changed_workspace.root.push_str("-changed");
        crate::store::write_record(
            &paths,
            RecordKind::Workspace,
            &changed_workspace.workspace_id,
            21,
            &changed_workspace,
        )
        .unwrap();
        assert!(matches!(
            svc(&paths).prepare_new_tab_session(
                &window,
                &project,
                &workspace,
                prepared_params(&workspace.workspace_id, "prepared-w-race", cwd.path()),
                "prepared-w-race-tab",
                "Workspace race",
                false,
                AttentionState::default(),
            ),
            Err(WindowLayoutError::WorkspaceChanged { .. })
        ));
        assert!(
            loaded_record::<SessionRecord>(&paths, RecordKind::Session, "prepared-w-race")
                .is_none()
        );

        crate::store::write_record(
            &paths,
            RecordKind::Workspace,
            &workspace.workspace_id,
            22,
            &workspace,
        )
        .unwrap();
        let mut changed_project = project.clone();
        changed_project.name.push_str(" changed");
        crate::store::write_record(
            &paths,
            RecordKind::Project,
            &changed_project.project_id,
            23,
            &changed_project,
        )
        .unwrap();
        assert!(matches!(
            svc(&paths).prepare_new_tab_session(
                &window,
                &project,
                &workspace,
                prepared_params(&workspace.workspace_id, "prepared-p-race", cwd.path()),
                "prepared-p-race-tab",
                "Project race",
                false,
                AttentionState::default(),
            ),
            Err(WindowLayoutError::WindowLayoutChanged { .. })
        ));
        assert!(
            loaded_record::<SessionRecord>(&paths, RecordKind::Session, "prepared-p-race")
                .is_none()
        );
    }

    #[test]
    fn prepared_invalid_cwd_error_is_content_blind_and_writes_no_graph() {
        let (_tmp, paths) = temp_paths();
        let cwd = TempDir::new().unwrap();
        let cwd_path = cwd.path().to_path_buf();
        let (project, workspace, window) =
            prepared_existing_target(&paths, &cwd_path, "invalid-cwd-redaction");
        let before = svc(&paths).load_snapshot(&window.layout.window_id).unwrap();
        drop(cwd);

        let error = svc(&paths)
            .prepare_new_tab_session(
                &window,
                &project,
                &workspace,
                prepared_params(&workspace.workspace_id, "invalid-cwd-session", &cwd_path),
                "invalid-cwd-tab",
                "Invalid cwd",
                false,
                AttentionState::default(),
            )
            .expect_err("missing prepared cwd is refused before graph write");
        let rendered = error.to_string();
        assert!(!rendered.contains(&cwd_path.to_string_lossy().to_string()));
        assert!(cwd_path
            .file_name()
            .and_then(|name| name.to_str())
            .is_none_or(|name| !rendered.contains(name)));
        assert_eq!(
            svc(&paths).load_snapshot(&window.layout.window_id).unwrap(),
            before
        );
        assert!(
            loaded_record::<SessionRecord>(&paths, RecordKind::Session, "invalid-cwd-session")
                .is_none()
        );
    }

    #[test]
    fn prepared_existing_start_has_one_insert_only_winner() {
        let (_tmp, paths) = temp_paths();
        let cwd = TempDir::new().unwrap();
        let (project, workspace, window) = prepared_existing_target(&paths, cwd.path(), "winner");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut joins = Vec::new();
        for _ in 0..2 {
            let paths = paths.clone();
            let project = project.clone();
            let workspace = workspace.clone();
            let window = window.clone();
            let cwd = cwd.path().to_path_buf();
            let barrier = barrier.clone();
            joins.push(std::thread::spawn(move || {
                barrier.wait();
                svc(&paths).prepare_new_split_session(
                    &window,
                    &project,
                    &workspace,
                    prepared_params(&workspace.workspace_id, "prepared-winner", &cwd),
                    &window.layout.tabs[0].tab_id,
                    "prepared-winner-tab",
                    "Winner",
                    SplitAxis::Right,
                )
            }));
        }
        barrier.wait();
        let outcomes = joins
            .into_iter()
            .map(|join| join.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        let layout = svc(&paths)
            .load_snapshot(&window.layout.window_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            layout
                .layout
                .tabs
                .iter()
                .filter(|tab| tab.tab_id == "prepared-winner-tab")
                .count(),
            1
        );
        assert!(
            loaded_record::<SessionRecord>(&paths, RecordKind::Session, "prepared-winner")
                .is_some()
        );
    }

    fn assert_graph_children_absent(paths: &AppPaths, spec: &FreshWindowGraphSpec) {
        assert!(loaded_record::<Workspace>(
            paths,
            RecordKind::Workspace,
            &spec.workspace.workspace_id
        )
        .is_none());
        assert!(loaded_record::<SessionRecord>(
            paths,
            RecordKind::Session,
            &spec.session.session_id
        )
        .is_none());
        assert!(svc(paths).load(&spec.window_id).unwrap().is_none());
    }

    #[test]
    fn fresh_graph_existing_project_commits_exact_graph_once_and_receipt_deletes_it() {
        let (_tmp, paths) = temp_paths();
        let project_id = "fresh-existing-project";
        let original_project = create_fixture_project(&paths, project_id);
        let mut spec = fresh_graph_spec(project_id, "existing-success");
        spec.touch_project = true;
        let epoch_before = window_epoch(&paths);

        let created = created_graph(
            svc(&paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(&paths, project_id),
                    spec.clone(),
                    20,
                )
                .unwrap(),
        );
        assert_eq!(window_epoch(&paths), epoch_before + 1);
        assert_eq!(
            created.project.window_order,
            std::slice::from_ref(&spec.window_id)
        );
        assert_eq!(created.project.last_active_at_ms, 20);
        assert_eq!(created.workspace, spec.workspace);
        assert_eq!(created.session, spec.session);
        assert_eq!(created.window.project_id.as_deref(), Some(project_id));
        assert_eq!(created.window.layout.name.as_deref(), Some("Fresh Window"));
        assert_eq!(created.window.layout.tabs.len(), 1);
        assert_eq!(created.window.layout.tabs[0].tab_id, spec.tab_id);
        assert_eq!(
            created.window.layout.tabs[0].session_id,
            spec.session.session_id
        );
        assert_eq!(
            loaded_record::<Project>(&paths, RecordKind::Project, project_id),
            Some(created.project.clone())
        );
        assert_eq!(
            loaded_record::<Workspace>(
                &paths,
                RecordKind::Workspace,
                &created.workspace.workspace_id
            ),
            Some(created.workspace.clone())
        );
        assert_eq!(
            loaded_record::<SessionRecord>(
                &paths,
                RecordKind::Session,
                &created.session.session_id
            ),
            Some(created.session.clone())
        );
        let trace_kinds = crate::write_trace::recent()
            .into_iter()
            .filter(|trace| is_fresh_graph_trace(trace, project_id, &spec, 20))
            .map(|trace| trace.kind)
            .collect::<Vec<_>>();
        assert_eq!(
            trace_kinds,
            [
                "Project",
                "Workspace",
                "Session",
                "WindowLayout",
                "WindowOwner"
            ]
        );

        assert!(matches!(
            svc(&paths)
                .delete_fresh_window_graph_if_unchanged(&created.receipt, 21)
                .unwrap(),
            ConditionalFreshWindowGraphDelete::Deleted { .. }
        ));
        assert_eq!(window_epoch(&paths), epoch_before + 2);
        assert_graph_children_absent(&paths, &spec);
        let remaining = loaded_record::<Project>(&paths, RecordKind::Project, project_id).unwrap();
        assert_eq!(
            remaining, original_project,
            "receipt cleanup must restore every pre-create Project byte, including touch metadata"
        );
    }

    #[test]
    fn fresh_graph_new_project_is_never_partial_and_receipt_cascades_exact_graph() {
        let (_tmp, paths) = temp_paths();
        let project_id = "fresh-new-project";
        let spec = fresh_graph_spec(project_id, "new-success");
        let created = created_graph(
            svc(&paths)
                .create_fresh_project_window_graph(
                    project_id,
                    "New Project",
                    "/fresh/new",
                    crate::NewProject::default(),
                    spec.clone(),
                    30,
                )
                .unwrap(),
        );
        assert_eq!(window_epoch(&paths), 1);
        assert_eq!(
            created.project.window_order,
            std::slice::from_ref(&spec.window_id)
        );
        assert!(matches!(
            svc(&paths)
                .delete_fresh_window_graph_if_unchanged(&created.receipt, 31)
                .unwrap(),
            ConditionalFreshWindowGraphDelete::Deleted { .. }
        ));
        assert_eq!(window_epoch(&paths), 2);
        assert_graph_children_absent(&paths, &spec);
        assert!(loaded_record::<Project>(&paths, RecordKind::Project, project_id).is_none());
    }

    #[test]
    fn fresh_graph_every_sql_stage_failure_rolls_back_rows_epoch_and_traces() {
        let stages = [
            "after-project-row",
            "after-workspace-row",
            "after-session-row",
            "after-window-row",
            "after-window-before-tabs",
            "after-tab-row",
            "after-window-layout",
            "after-fresh-graph-epoch",
        ];
        for (index, stage) in stages.into_iter().enumerate() {
            let (_tmp, paths) = temp_paths();
            let project_id = format!("fresh-fail-project-{index}");
            let spec = fresh_graph_spec(&project_id, &format!("fail-{index}"));
            let now_ms = 1_000 + index as u64;
            let _failure = crate::store_sqlite::install_window_layout_test_failure(
                spec.window_id.clone(),
                stage,
            );
            let error = svc(&paths)
                .create_fresh_project_window_graph(
                    &project_id,
                    "Failure Project",
                    "/fresh/failure",
                    crate::NewProject::default(),
                    spec.clone(),
                    now_ms,
                )
                .unwrap_err();
            assert!(
                matches!(error, WindowLayoutError::Store(StoreError::Map(_))),
                "stage {stage}: {error:?}"
            );
            assert_eq!(window_epoch(&paths), 0, "stage {stage}");
            assert_graph_children_absent(&paths, &spec);
            assert!(loaded_record::<Project>(&paths, RecordKind::Project, &project_id).is_none());
            assert!(
                crate::write_trace::recent()
                    .into_iter()
                    .all(|trace| !is_fresh_graph_trace(&trace, &project_id, &spec, now_ms)),
                "stage {stage} emitted a pre-commit trace"
            );
        }
    }

    #[test]
    fn fresh_graph_two_connection_workspace_winner_is_never_adopted_or_overwritten() {
        for identical in [true, false] {
            let (_tmp, paths) = temp_paths();
            let project_id = if identical {
                "fresh-race-identical"
            } else {
                "fresh-race-different"
            };
            let original_project = create_fixture_project(&paths, project_id);
            let spec = fresh_graph_spec(project_id, project_id);
            let mut winner = spec.workspace.clone();
            if !identical {
                winner.root = "/second-writer-wins".into();
            }
            let winner_for_hook = winner.clone();
            let db_path = crate::db::db_path(paths.base());
            let _hook = crate::store_sqlite::install_window_layout_test_hook(
                spec.window_id.clone(),
                move |stage, _| {
                    if stage != "before-fresh-graph-transaction" {
                        return;
                    }
                    let mut second = rusqlite::Connection::open(&db_path).unwrap();
                    second.pragma_update(None, "foreign_keys", "ON").unwrap();
                    let tx = second
                        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                        .unwrap();
                    crate::store_sqlite::upsert(
                        &tx,
                        RecordKind::Workspace,
                        &winner_for_hook.workspace_id,
                        &serde_json::to_value(&winner_for_hook).unwrap(),
                    )
                    .unwrap();
                    tx.commit().unwrap();
                },
            );

            let outcome = svc(&paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(&paths, project_id),
                    spec.clone(),
                    50,
                )
                .unwrap();
            assert_eq!(
                outcome,
                FreshWindowGraphCreateOutcome::Conflict(FreshWindowGraphConflict::Workspace {
                    workspace_id: spec.workspace.workspace_id.clone()
                })
            );
            assert_eq!(
                loaded_record::<Workspace>(
                    &paths,
                    RecordKind::Workspace,
                    &spec.workspace.workspace_id
                ),
                Some(winner)
            );
            assert_eq!(
                loaded_record::<Project>(&paths, RecordKind::Project, project_id),
                Some(original_project)
            );
            assert!(loaded_record::<SessionRecord>(
                &paths,
                RecordKind::Session,
                &spec.session.session_id
            )
            .is_none());
            assert!(svc(&paths).load(&spec.window_id).unwrap().is_none());
            assert_eq!(window_epoch(&paths), 0);
        }
    }

    #[test]
    fn fresh_graph_two_production_callers_serialize_to_one_complete_winner() {
        for identical in [true, false] {
            let (_tmp, paths) = temp_paths();
            let project_id = if identical {
                "fresh-service-race-identical"
            } else {
                "fresh-service-race-different"
            };
            create_fixture_project(&paths, project_id);
            let expected_project = stored_graph_project_snapshot(&paths, project_id);
            let winner_ts = if identical { 70_120 } else { 70_220 };
            let loser_ts = winner_ts + 1;
            let mut loser_spec = fresh_graph_spec(project_id, project_id);
            let mut winner_spec = loser_spec.clone();
            if !identical {
                loser_spec.workspace.root = "/loser-must-not-overwrite".into();
                loser_spec.session.cwd_resolved = "/loser-must-not-overwrite".into();
                winner_spec.workspace.root = "/winner".into();
                winner_spec.session.cwd_resolved = "/winner".into();
            }
            let entered_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let release =
                std::sync::Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new()));
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let entered_count_for_hook = std::sync::Arc::clone(&entered_count);
            let release_for_hook = std::sync::Arc::clone(&release);
            let _hook = crate::store_sqlite::install_window_layout_test_hook(
                loser_spec.window_id.clone(),
                move |stage, _| {
                    if stage != "before-fresh-graph-transaction"
                        || entered_count_for_hook.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                            != 0
                    {
                        return;
                    }
                    entered_tx.send(()).unwrap();
                    let (lock, ready) = &*release_for_hook;
                    let mut released = lock.lock().unwrap();
                    while !*released {
                        released = ready.wait(released).unwrap();
                    }
                },
            );
            let loser_paths = paths.clone();
            let loser_project = expected_project.clone();
            let loser = std::thread::spawn(move || {
                svc(&loser_paths).create_fresh_window_graph(&loser_project, loser_spec, loser_ts)
            });
            entered_rx.recv().unwrap();

            let winner = created_graph(
                svc(&paths)
                    .create_fresh_window_graph(&expected_project, winner_spec.clone(), winner_ts)
                    .unwrap(),
            );
            let (lock, ready) = &*release;
            *lock.lock().unwrap() = true;
            ready.notify_all();
            let loser = loser.join().unwrap().unwrap();
            assert_eq!(
                loser,
                FreshWindowGraphCreateOutcome::ProjectChanged {
                    project_id: project_id.into()
                }
            );
            assert_eq!(window_epoch(&paths), 1);
            assert_eq!(winner.workspace, winner_spec.workspace);
            assert_eq!(winner.session, winner_spec.session);
            assert_eq!(winner.project.window_order, [winner_spec.window_id.clone()]);
            assert_eq!(
                loaded_record::<Workspace>(
                    &paths,
                    RecordKind::Workspace,
                    &winner.workspace.workspace_id
                ),
                Some(winner.workspace)
            );
            assert_eq!(
                crate::write_trace::recent()
                    .into_iter()
                    .filter(|trace| {
                        is_fresh_graph_trace(trace, project_id, &winner_spec, winner_ts)
                    })
                    .count(),
                5
            );
            assert!(
                crate::write_trace::recent().into_iter().all(|trace| {
                    !is_fresh_graph_trace(&trace, project_id, &winner_spec, loser_ts)
                }),
                "losing production caller must emit no trace"
            );
        }
    }

    #[test]
    fn fresh_graph_entrypoint_distinguishes_missing_semantic_change_and_recency_rebase() {
        // A semantic caller input is an exact precondition; a fresh root change refuses without
        // publishing any candidate row or epoch/trace.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-project-changed";
            create_fixture_project(&paths, project_id);
            let expected = stored_graph_project_snapshot(&paths, project_id);
            let spec = fresh_graph_spec(project_id, "project-changed");
            let db_path = crate::db::db_path(paths.base());
            let _hook = crate::store_sqlite::install_window_layout_test_hook(
                spec.window_id.clone(),
                move |stage, _| {
                    if stage == "before-fresh-graph-transaction" {
                        rusqlite::Connection::open(&db_path)
                            .unwrap()
                            .execute(
                                "UPDATE projects SET root = '/fresh/concurrent-root' \
                                 WHERE project_id = 'fresh-project-changed'",
                                [],
                            )
                            .unwrap();
                    }
                },
            );
            assert_eq!(
                svc(&paths)
                    .create_fresh_window_graph(&expected, spec.clone(), 70_300)
                    .unwrap(),
                FreshWindowGraphCreateOutcome::ProjectChanged {
                    project_id: project_id.into()
                }
            );
            assert_graph_children_absent(&paths, &spec);
            assert_eq!(window_epoch(&paths), 0);
            assert!(crate::write_trace::recent()
                .into_iter()
                .all(|trace| { !is_fresh_graph_trace(&trace, project_id, &spec, 70_300) }));
        }

        // Absence is a distinct terminal result. Raw test SQL isolates the entrypoint branch from
        // the production Project-delete epoch contract.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-project-missing";
            create_fixture_project(&paths, project_id);
            let expected = stored_graph_project_snapshot(&paths, project_id);
            let spec = fresh_graph_spec(project_id, "project-missing");
            let db_path = crate::db::db_path(paths.base());
            let _hook = crate::store_sqlite::install_window_layout_test_hook(
                spec.window_id.clone(),
                move |stage, _| {
                    if stage == "before-fresh-graph-transaction" {
                        rusqlite::Connection::open(&db_path)
                            .unwrap()
                            .execute(
                                "DELETE FROM projects WHERE project_id = 'fresh-project-missing'",
                                [],
                            )
                            .unwrap();
                    }
                },
            );
            assert_eq!(
                svc(&paths)
                    .create_fresh_window_graph(&expected, spec.clone(), 70_310)
                    .unwrap(),
                FreshWindowGraphCreateOutcome::ProjectMissing {
                    project_id: project_id.into()
                }
            );
            assert_graph_children_absent(&paths, &spec);
            assert_eq!(window_epoch(&paths), 0);
            assert!(crate::write_trace::recent()
                .into_iter()
                .all(|trace| { !is_fresh_graph_trace(&trace, project_id, &spec, 70_310) }));
        }

        // Epoch-quiet recency is deliberately rebased from the writer snapshot. Production order
        // changes advance the epoch and therefore refuse a stale proof.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-project-recency-rebase";
            create_fixture_project(&paths, project_id);
            let expected = stored_graph_project_snapshot(&paths, project_id);
            let epoch_before = window_epoch(&paths);
            let spec = fresh_graph_spec(project_id, "recency-rebase");
            let db_path = crate::db::db_path(paths.base());
            let _hook = crate::store_sqlite::install_window_layout_test_hook(
                spec.window_id.clone(),
                move |stage, _| {
                    if stage == "before-fresh-graph-transaction" {
                        rusqlite::Connection::open(&db_path)
                            .unwrap()
                            .execute(
                                "UPDATE projects SET last_active_at_ms = 777 \
                                 WHERE project_id = 'fresh-project-recency-rebase'",
                                [],
                            )
                            .unwrap();
                    }
                },
            );
            let created = created_graph(
                svc(&paths)
                    .create_fresh_window_graph(&expected, spec.clone(), 70_320)
                    .unwrap(),
            );
            assert_eq!(
                created.project.window_order,
                std::slice::from_ref(&spec.window_id)
            );
            assert_eq!(created.project.last_active_at_ms, 777);
            assert_eq!(window_epoch(&paths), epoch_before + 1);
        }
    }

    #[test]
    fn fresh_graph_project_snapshot_rejects_identity_aba_and_unrelated_epoch() {
        // The public Project view can be cloned and edited, but that never mutates or retargets
        // the opaque proof carried by the snapshot.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-proof-immutable";
            create_fixture_project(&paths, project_id);
            let proof = stored_graph_project_snapshot(&paths, project_id);
            let mut caller_copy = proof.project().clone();
            caller_copy.project_id = "retarget-attempt".into();
            assert_eq!(proof.project().project_id, project_id);
        }

        // Delete + byte-identical recreation crosses the global identity epoch even though the
        // visible Project bytes match exactly.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-project-proof-aba";
            let exact_project = create_fixture_project(&paths, project_id);
            let proof = stored_graph_project_snapshot(&paths, project_id);
            let epoch_before = window_epoch(&paths);
            let spec = fresh_graph_spec(project_id, "project-proof-aba");
            let hook_paths = paths.clone();
            let exact_for_hook = exact_project.clone();
            let _hook = crate::store_sqlite::install_window_layout_test_hook(
                spec.window_id.clone(),
                move |stage, _| {
                    if stage != "before-fresh-graph-transaction" {
                        return;
                    }
                    let projects = crate::ProjectService::new(&hook_paths);
                    let plan = projects.plan_delete(project_id).unwrap();
                    let removed = projects
                        .commit_delete(&plan, &crate::PreResolvedSessionGenerations::new(), 42)
                        .unwrap();
                    assert!(removed.removed);
                    let recreated = projects
                        .create(
                            project_id,
                            exact_for_hook.name.clone(),
                            exact_for_hook.root.clone(),
                            crate::NewProject {
                                default_workspace_policy: Some(
                                    exact_for_hook.default_workspace_policy,
                                ),
                                icon: exact_for_hook.icon.clone(),
                                accent_color: exact_for_hook.accent_color.clone(),
                                launch_defaults: exact_for_hook.launch_defaults.clone(),
                                directories: exact_for_hook.directories.clone(),
                                system: exact_for_hook.system,
                            },
                            exact_for_hook.created_at_ms,
                        )
                        .unwrap();
                    assert_eq!(recreated, exact_for_hook);
                },
            );
            assert_eq!(
                svc(&paths)
                    .create_fresh_window_graph(&proof, spec.clone(), 70_330)
                    .unwrap(),
                FreshWindowGraphCreateOutcome::ProjectChanged {
                    project_id: project_id.into()
                }
            );
            assert_eq!(stored_project(&paths, project_id), exact_project);
            assert_graph_children_absent(&paths, &spec);
            assert_eq!(window_epoch(&paths), epoch_before + 1);
            assert!(crate::write_trace::recent()
                .into_iter()
                .all(|trace| { !is_fresh_graph_trace(&trace, project_id, &spec, 70_330) }));
        }

        // An unrelated window/owner mutation conservatively invalidates the same global proof.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-project-proof-unrelated";
            create_fixture_project(&paths, project_id);
            let proof = stored_graph_project_snapshot(&paths, project_id);
            let epoch_before = window_epoch(&paths);
            let spec = fresh_graph_spec(project_id, "project-proof-unrelated");
            let hook_paths = paths.clone();
            let _hook = crate::store_sqlite::install_window_layout_test_hook(
                spec.window_id.clone(),
                move |stage, _| {
                    if stage == "before-fresh-graph-transaction" {
                        svc(&hook_paths)
                            .create_empty("fresh-proof-unrelated-window", 1)
                            .unwrap();
                    }
                },
            );
            assert_eq!(
                svc(&paths)
                    .create_fresh_window_graph(&proof, spec.clone(), 70_340)
                    .unwrap(),
                FreshWindowGraphCreateOutcome::ProjectChanged {
                    project_id: project_id.into()
                }
            );
            assert_graph_children_absent(&paths, &spec);
            assert_eq!(window_epoch(&paths), epoch_before + 1);
            assert!(crate::write_trace::recent()
                .into_iter()
                .all(|trace| { !is_fresh_graph_trace(&trace, project_id, &spec, 70_340) }));
        }
    }

    #[test]
    fn fresh_graph_session_window_and_foreign_order_conflicts_publish_nothing() {
        // Session identity owned by another Workspace wins unchanged.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-session-conflict";
            create_fixture_project(&paths, project_id);
            let spec = fresh_graph_spec(project_id, "session-conflict");
            let other_workspace = Workspace {
                workspace_id: "fresh-other-workspace".into(),
                project_id: project_id.into(),
                root: "/other".into(),
                policy: crate::WorkspacePolicy::ScratchCwd,
                consent: crate::WorkspaceConsent::default(),
            };
            crate::write_record(
                &paths,
                RecordKind::Workspace,
                &other_workspace.workspace_id,
                1,
                &other_workspace,
            )
            .unwrap();
            let mut winner = spec.session.clone();
            winner.workspace_id = other_workspace.workspace_id;
            assert_eq!(
                crate::create_session_record_if_absent(&paths, &winner, 1).unwrap(),
                crate::CreateSessionRecordOutcome::Created
            );
            let outcome = svc(&paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(&paths, project_id),
                    spec.clone(),
                    60,
                )
                .unwrap();
            assert_eq!(
                outcome,
                FreshWindowGraphCreateOutcome::Conflict(FreshWindowGraphConflict::Session {
                    session_id: spec.session.session_id.clone()
                })
            );
            assert_eq!(
                loaded_record::<SessionRecord>(
                    &paths,
                    RecordKind::Session,
                    &spec.session.session_id
                ),
                Some(winner)
            );
            assert!(loaded_record::<Workspace>(
                &paths,
                RecordKind::Workspace,
                &spec.workspace.workspace_id
            )
            .is_none());
            assert!(svc(&paths).load(&spec.window_id).unwrap().is_none());
        }

        // An existing Window identity wins; preflight Workspace/Session rows never appear.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-window-conflict";
            create_fixture_project(&paths, project_id);
            let spec = fresh_graph_spec(project_id, "window-conflict");
            let winner = svc(&paths).create_empty(&spec.window_id, 1).unwrap();
            let epoch = window_epoch(&paths);
            let outcome = svc(&paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(&paths, project_id),
                    spec.clone(),
                    61,
                )
                .unwrap();
            assert_eq!(
                outcome,
                FreshWindowGraphCreateOutcome::Conflict(FreshWindowGraphConflict::Window {
                    window_id: spec.window_id.clone()
                })
            );
            assert_eq!(svc(&paths).load(&spec.window_id).unwrap(), Some(winner));
            assert!(loaded_record::<Workspace>(
                &paths,
                RecordKind::Workspace,
                &spec.workspace.workspace_id
            )
            .is_none());
            assert!(loaded_record::<SessionRecord>(
                &paths,
                RecordKind::Session,
                &spec.session.session_id
            )
            .is_none());
            assert_eq!(window_epoch(&paths), epoch);
        }

        // A soft owner in another strictly parsed Project order is a conflict even while the
        // Window row is absent.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-order-target";
            let foreign_project_id = "fresh-order-foreign";
            create_fixture_project(&paths, project_id);
            create_fixture_project(&paths, foreign_project_id);
            let spec = fresh_graph_spec(project_id, "order-conflict");
            let connection = crate::db::conn_for(paths.base()).unwrap();
            let guard = connection.lock().unwrap();
            guard
                .execute(
                    "UPDATE projects SET window_order_json = ?2 WHERE project_id = ?1",
                    rusqlite::params![
                        foreign_project_id,
                        serde_json::to_string(std::slice::from_ref(&spec.window_id)).unwrap()
                    ],
                )
                .unwrap();
            drop(guard);
            let outcome = svc(&paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(&paths, project_id),
                    spec.clone(),
                    62,
                )
                .unwrap();
            assert_eq!(
                outcome,
                FreshWindowGraphCreateOutcome::Conflict(FreshWindowGraphConflict::ProjectOrder {
                    window_id: spec.window_id.clone(),
                    project_ids: vec![foreign_project_id.into()]
                })
            );
            assert_graph_children_absent(&paths, &spec);
            assert_eq!(window_epoch(&paths), 0);
        }
    }

    #[test]
    fn fresh_graph_new_project_refuses_every_orphan_direct_child_namespace() {
        #[derive(Clone, Copy, Debug)]
        enum ChildKind {
            Workspace,
            AgentTask,
            Window,
            LayoutPreset,
        }

        for (index, child) in [
            ChildKind::Workspace,
            ChildKind::AgentTask,
            ChildKind::Window,
            ChildKind::LayoutPreset,
        ]
        .into_iter()
        .enumerate()
        {
            let (_tmp, paths) = temp_paths();
            let project_id = format!("fresh-orphan-project-{index}");
            let spec = fresh_graph_spec(&project_id, &format!("orphan-project-{index}"));
            assert_eq!(window_epoch(&paths), 0);
            let raw = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
            raw.pragma_update(None, "foreign_keys", "OFF").unwrap();
            let (kind, child_id, value) = match child {
                ChildKind::Workspace => {
                    let row = Workspace {
                        workspace_id: format!("fresh-orphan-workspace-{index}"),
                        project_id: project_id.clone(),
                        root: "/foreign/workspace".into(),
                        policy: crate::WorkspacePolicy::ScratchCwd,
                        consent: crate::WorkspaceConsent::default(),
                    };
                    (
                        RecordKind::Workspace,
                        row.workspace_id.clone(),
                        serde_json::to_value(row).unwrap(),
                    )
                }
                ChildKind::AgentTask => {
                    let row = crate::records::AgentTask {
                        agent_task_id: format!("fresh-orphan-task-{index}"),
                        project_id: project_id.clone(),
                        goal: "foreign authority".into(),
                        state: crate::AgentTaskState::Draft,
                        current_session_id: None,
                        session_history: Vec::new(),
                        created_at_ms: 1,
                        updated_at_ms: 1,
                        result_summary: None,
                    };
                    (
                        RecordKind::AgentTask,
                        row.agent_task_id.clone(),
                        serde_json::to_value(row).unwrap(),
                    )
                }
                ChildKind::Window => {
                    let row = WindowLayout {
                        window_id: format!("fresh-orphan-owned-window-{index}"),
                        name: Some("foreign".into()),
                        tabs: Vec::new(),
                    };
                    (
                        RecordKind::WindowLayout,
                        row.window_id.clone(),
                        serde_json::to_value(row).unwrap(),
                    )
                }
                ChildKind::LayoutPreset => {
                    let row = crate::records::LayoutPreset {
                        preset_id: format!("fresh-orphan-preset-{index}"),
                        name: "foreign".into(),
                        project_id: Some(project_id.clone()),
                        created_at_ms: 1,
                        tabs: Vec::new(),
                    };
                    (
                        RecordKind::LayoutPreset,
                        row.preset_id.clone(),
                        serde_json::to_value(row).unwrap(),
                    )
                }
            };
            crate::store_sqlite::upsert(&raw, kind, &child_id, &value).unwrap();
            if matches!(child, ChildKind::Window) {
                assert!(
                    crate::store_sqlite::set_window_project(&raw, &child_id, &project_id).unwrap()
                );
            }
            drop(raw);
            let child_before = raw_record_value(&paths, kind, &child_id).unwrap();

            let now_ms = 71_000 + index as u64;
            assert_eq!(
                svc(&paths)
                    .create_fresh_project_window_graph(
                        &project_id,
                        "Must not adopt",
                        "/fresh",
                        crate::NewProject::default(),
                        spec.clone(),
                        now_ms,
                    )
                    .unwrap(),
                FreshWindowGraphCreateOutcome::Conflict(FreshWindowGraphConflict::Project {
                    project_id: project_id.clone()
                }),
                "{child:?}"
            );
            assert!(loaded_record::<Project>(&paths, RecordKind::Project, &project_id).is_none());
            assert_graph_children_absent(&paths, &spec);
            assert_eq!(
                raw_record_value(&paths, kind, &child_id),
                Some(child_before)
            );
            if matches!(child, ChildKind::Window) {
                assert_eq!(
                    svc(&paths)
                        .load_snapshot(&child_id)
                        .unwrap()
                        .unwrap()
                        .project_id
                        .as_deref(),
                    Some(project_id.as_str())
                );
            }
            assert_eq!(window_epoch(&paths), 0);
            assert!(crate::write_trace::recent()
                .into_iter()
                .all(|trace| { !is_fresh_graph_trace(&trace, &project_id, &spec, now_ms) }));
        }
    }

    #[test]
    fn fresh_graph_refuses_every_candidate_identity_soft_owner_namespace() {
        #[derive(Clone, Copy, Debug)]
        enum OwnerKind {
            WorkspaceSession,
            WorkspaceProvenance,
            SessionTaskCurrent,
            SessionTaskHistory,
            SessionTab,
            SessionProvenance,
            SessionPreset,
            WindowSessionTab,
            WindowNullSessionTab,
        }

        for (index, owner) in [
            OwnerKind::WorkspaceSession,
            OwnerKind::WorkspaceProvenance,
            OwnerKind::SessionTaskCurrent,
            OwnerKind::SessionTaskHistory,
            OwnerKind::SessionTab,
            OwnerKind::SessionProvenance,
            OwnerKind::SessionPreset,
            OwnerKind::WindowSessionTab,
            OwnerKind::WindowNullSessionTab,
        ]
        .into_iter()
        .enumerate()
        {
            let (_tmp, paths) = temp_paths();
            let project_id = format!("fresh-owner-project-{index}");
            let project_before = create_fixture_project(&paths, &project_id);
            let spec = fresh_graph_spec(&project_id, &format!("owner-{index}"));
            let raw = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
            raw.pragma_update(None, "foreign_keys", "OFF").unwrap();
            let mut protected_record: Option<(RecordKind, String, serde_json::Value)> = None;
            let expected_conflict = match owner {
                OwnerKind::WorkspaceSession => {
                    let mut row = spec.session.clone();
                    row.session_id = format!("fresh-foreign-workspace-session-{index}");
                    let value = serde_json::to_value(&row).unwrap();
                    crate::store_sqlite::upsert(&raw, RecordKind::Session, &row.session_id, &value)
                        .unwrap();
                    protected_record = Some((RecordKind::Session, row.session_id, value));
                    FreshWindowGraphConflict::Workspace {
                        workspace_id: spec.workspace.workspace_id.clone(),
                    }
                }
                OwnerKind::WorkspaceProvenance => {
                    let row = crate::records::WorktreeProvenance {
                        session_id: format!("fresh-workspace-provenance-{index}"),
                        workspace_id: spec.workspace.workspace_id.clone(),
                        repo_root: "/foreign".into(),
                        target_path: format!("/tmp/foreign-workspace-{index}"),
                        branch: format!("maestro/foreign-workspace-{index}"),
                        created_at_ms: 1,
                    };
                    let value = serde_json::to_value(&row).unwrap();
                    crate::store_sqlite::upsert(
                        &raw,
                        RecordKind::WorktreeProvenance,
                        &row.session_id,
                        &value,
                    )
                    .unwrap();
                    protected_record =
                        Some((RecordKind::WorktreeProvenance, row.session_id, value));
                    FreshWindowGraphConflict::Workspace {
                        workspace_id: spec.workspace.workspace_id.clone(),
                    }
                }
                OwnerKind::SessionTaskCurrent | OwnerKind::SessionTaskHistory => {
                    let current = matches!(owner, OwnerKind::SessionTaskCurrent);
                    let row = crate::records::AgentTask {
                        agent_task_id: format!("fresh-session-task-{index}"),
                        project_id: project_id.clone(),
                        goal: "foreign session owner".into(),
                        state: crate::AgentTaskState::Running,
                        current_session_id: current.then(|| spec.session.session_id.clone()),
                        session_history: if current {
                            Vec::new()
                        } else {
                            vec![spec.session.session_id.clone()]
                        },
                        created_at_ms: 1,
                        updated_at_ms: 1,
                        result_summary: None,
                    };
                    let value = serde_json::to_value(&row).unwrap();
                    crate::store_sqlite::upsert(
                        &raw,
                        RecordKind::AgentTask,
                        &row.agent_task_id,
                        &value,
                    )
                    .unwrap();
                    protected_record = Some((RecordKind::AgentTask, row.agent_task_id, value));
                    FreshWindowGraphConflict::Session {
                        session_id: spec.session.session_id.clone(),
                    }
                }
                OwnerKind::SessionTab => {
                    let row = WindowLayout {
                        window_id: format!("fresh-session-owner-window-{index}"),
                        name: Some("foreign".into()),
                        tabs: vec![TabRecord {
                            tab_id: "foreign-tab".into(),
                            session_id: spec.session.session_id.clone(),
                            index: 0,
                            title: "foreign".into(),
                            pinned: false,
                            attention: AttentionState::default(),
                            split_from: None,
                            pane_rect: None,
                            stashed_from: None,
                            stashed: false,
                        }],
                    };
                    let value = serde_json::to_value(&row).unwrap();
                    crate::store_sqlite::upsert(
                        &raw,
                        RecordKind::WindowLayout,
                        &row.window_id,
                        &value,
                    )
                    .unwrap();
                    protected_record = Some((RecordKind::WindowLayout, row.window_id, value));
                    FreshWindowGraphConflict::Session {
                        session_id: spec.session.session_id.clone(),
                    }
                }
                OwnerKind::SessionProvenance => {
                    let workspace = Workspace {
                        workspace_id: format!("fresh-session-provenance-workspace-{index}"),
                        project_id: project_id.clone(),
                        root: "/foreign".into(),
                        policy: crate::WorkspacePolicy::ScratchCwd,
                        consent: crate::WorkspaceConsent::default(),
                    };
                    crate::store_sqlite::upsert(
                        &raw,
                        RecordKind::Workspace,
                        &workspace.workspace_id,
                        &serde_json::to_value(&workspace).unwrap(),
                    )
                    .unwrap();
                    let row = crate::records::WorktreeProvenance {
                        session_id: spec.session.session_id.clone(),
                        workspace_id: workspace.workspace_id,
                        repo_root: "/foreign".into(),
                        target_path: format!("/tmp/foreign-session-{index}"),
                        branch: format!("maestro/foreign-session-{index}"),
                        created_at_ms: 1,
                    };
                    let value = serde_json::to_value(&row).unwrap();
                    crate::store_sqlite::upsert(
                        &raw,
                        RecordKind::WorktreeProvenance,
                        &row.session_id,
                        &value,
                    )
                    .unwrap();
                    protected_record =
                        Some((RecordKind::WorktreeProvenance, row.session_id, value));
                    FreshWindowGraphConflict::Session {
                        session_id: spec.session.session_id.clone(),
                    }
                }
                OwnerKind::SessionPreset => {
                    let row = crate::records::LayoutPreset {
                        preset_id: format!("fresh-session-preset-{index}"),
                        name: "foreign".into(),
                        project_id: Some(project_id.clone()),
                        created_at_ms: 1,
                        tabs: vec![crate::records::LayoutPresetTab {
                            index: 0,
                            title: "foreign".into(),
                            pinned: false,
                            split_from: None,
                            session_id: Some(spec.session.session_id.clone()),
                            source_tab_id: "foreign-source".into(),
                        }],
                    };
                    let value = serde_json::to_value(&row).unwrap();
                    crate::store_sqlite::upsert(
                        &raw,
                        RecordKind::LayoutPreset,
                        &row.preset_id,
                        &value,
                    )
                    .unwrap();
                    protected_record = Some((RecordKind::LayoutPreset, row.preset_id, value));
                    FreshWindowGraphConflict::Session {
                        session_id: spec.session.session_id.clone(),
                    }
                }
                OwnerKind::WindowSessionTab | OwnerKind::WindowNullSessionTab => {
                    let foreign_session = matches!(owner, OwnerKind::WindowSessionTab)
                        .then(|| format!("fresh-window-tab-session-{index}"));
                    raw.execute(
                        "INSERT INTO tabs (window_id, tab_id, session_id, idx, title, pinned, \
                         stashed, attention_json, pane_rect_json, split_from_json, stashed_from_json) \
                         VALUES (?1, 'orphan-tab', ?2, 0, 'foreign-tab', 0, 0, ?3, NULL, NULL, NULL)",
                        rusqlite::params![
                            spec.window_id,
                            foreign_session,
                            serde_json::to_string(&AttentionState::default()).unwrap()
                        ],
                    )
                    .unwrap();
                    FreshWindowGraphConflict::Window {
                        window_id: spec.window_id.clone(),
                    }
                }
            };
            drop(raw);
            let protected_before = protected_record
                .as_ref()
                .map(|(kind, id, _)| raw_record_value(&paths, *kind, id).unwrap());
            let proof = stored_graph_project_snapshot(&paths, &project_id);
            let epoch_before = window_epoch(&paths);
            let now_ms = 72_000 + index as u64;

            assert_eq!(
                svc(&paths)
                    .create_fresh_window_graph(&proof, spec.clone(), now_ms)
                    .unwrap(),
                FreshWindowGraphCreateOutcome::Conflict(expected_conflict),
                "{owner:?}"
            );
            assert_eq!(stored_project(&paths, &project_id), project_before);
            assert_graph_children_absent(&paths, &spec);
            if let (Some((kind, id, _)), Some(before)) =
                (protected_record.as_ref(), protected_before)
            {
                assert_eq!(raw_record_value(&paths, *kind, id), Some(before));
            } else {
                let connection = crate::db::conn_for(paths.base()).unwrap();
                let guard = connection.lock().unwrap();
                let row = guard
                    .query_row(
                        "SELECT session_id, title FROM tabs \
                         WHERE window_id = ?1 AND tab_id = 'orphan-tab'",
                        [&spec.window_id],
                        |row| Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?)),
                    )
                    .unwrap();
                let expected_session = matches!(owner, OwnerKind::WindowSessionTab)
                    .then(|| format!("fresh-window-tab-session-{index}"));
                assert_eq!(row, (expected_session, "foreign-tab".into()));
            }
            assert_eq!(window_epoch(&paths), epoch_before);
            assert!(crate::write_trace::recent()
                .into_iter()
                .all(|trace| { !is_fresh_graph_trace(&trace, &project_id, &spec, now_ms) }));
        }
    }

    #[test]
    fn fresh_graph_epoch_max_and_busy_fail_before_any_row_or_trace() {
        // MAX preflight is before the first upsert.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-max-project";
            let spec = fresh_graph_spec(project_id, "max");
            let connection = crate::db::conn_for(paths.base()).unwrap();
            connection
                .lock()
                .unwrap()
                .pragma_update(None, "user_version", i32::MAX)
                .unwrap();
            let error = svc(&paths)
                .create_fresh_project_window_graph(
                    project_id,
                    "Max Project",
                    "/max",
                    crate::NewProject::default(),
                    spec.clone(),
                    70,
                )
                .unwrap_err();
            assert!(matches!(error, WindowLayoutError::Store(StoreError::Db(_))));
            assert_eq!(window_epoch(&paths), i32::MAX as u32);
            assert!(loaded_record::<Project>(&paths, RecordKind::Project, project_id).is_none());
            assert_graph_children_absent(&paths, &spec);
            assert!(crate::write_trace::recent()
                .into_iter()
                .all(|trace| !is_fresh_graph_trace(&trace, project_id, &spec, 70)));
        }

        // A second connection's writer fence produces a bounded busy error and no partial rows.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-busy-project";
            let original = create_fixture_project(&paths, project_id);
            let spec = fresh_graph_spec(project_id, "busy");
            let cached = crate::db::conn_for(paths.base()).unwrap();
            cached
                .lock()
                .unwrap()
                .pragma_update(None, "busy_timeout", 0)
                .unwrap();
            let mut blocker = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
            blocker.pragma_update(None, "foreign_keys", "ON").unwrap();
            let blocker_tx = blocker
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            let error = svc(&paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(&paths, project_id),
                    spec.clone(),
                    71,
                )
                .unwrap_err();
            assert!(matches!(error, WindowLayoutError::Store(StoreError::Db(_))));
            blocker_tx.rollback().unwrap();
            cached
                .lock()
                .unwrap()
                .pragma_update(None, "busy_timeout", 5_000)
                .unwrap();
            assert_eq!(
                loaded_record::<Project>(&paths, RecordKind::Project, project_id),
                Some(original)
            );
            assert_graph_children_absent(&paths, &spec);
            assert_eq!(window_epoch(&paths), 0);
            assert!(crate::write_trace::recent()
                .into_iter()
                .all(|trace| !is_fresh_graph_trace(&trace, project_id, &spec, 71)));
        }
    }

    #[test]
    fn fresh_graph_receipt_rejects_metadata_change_aba_and_unrelated_epoch() {
        // Target Project/order metadata is part of the canonical receipt even though an ordinary
        // metadata edit does not advance the window epoch.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-receipt-metadata";
            create_fixture_project(&paths, project_id);
            let spec = fresh_graph_spec(project_id, "receipt-metadata");
            let created = created_graph(
                svc(&paths)
                    .create_fresh_window_graph(
                        &stored_graph_project_snapshot(&paths, project_id),
                        spec.clone(),
                        80,
                    )
                    .unwrap(),
            );
            let epoch = window_epoch(&paths);
            crate::ProjectService::new(&paths)
                .update(
                    project_id,
                    crate::ProjectUpdate {
                        icon: Some(Some("M".into())),
                        ..crate::ProjectUpdate::default()
                    },
                    81,
                )
                .unwrap();
            assert_eq!(window_epoch(&paths), epoch);
            assert!(matches!(
                svc(&paths)
                    .delete_fresh_window_graph_if_unchanged(&created.receipt, 82)
                    .unwrap(),
                ConditionalFreshWindowGraphDelete::Changed
            ));
            assert_eq!(
                svc(&paths).load(&spec.window_id).unwrap(),
                Some(created.window.layout)
            );
        }

        // Exact graph delete -> byte-identical recreate -> delete advances the epoch twice; the
        // first receipt cannot classify the final absence as its own creation.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-receipt-aba";
            create_fixture_project(&paths, project_id);
            let spec = fresh_graph_spec(project_id, "receipt-aba");
            let first = created_graph(
                svc(&paths)
                    .create_fresh_window_graph(
                        &stored_graph_project_snapshot(&paths, project_id),
                        spec.clone(),
                        83,
                    )
                    .unwrap(),
            );
            assert!(matches!(
                svc(&paths)
                    .delete_fresh_window_graph_if_unchanged(&first.receipt, 84)
                    .unwrap(),
                ConditionalFreshWindowGraphDelete::Deleted { .. }
            ));
            let second = created_graph(
                svc(&paths)
                    .create_fresh_window_graph(
                        &stored_graph_project_snapshot(&paths, project_id),
                        spec,
                        85,
                    )
                    .unwrap(),
            );
            assert!(matches!(
                svc(&paths)
                    .delete_fresh_window_graph_if_unchanged(&second.receipt, 86)
                    .unwrap(),
                ConditionalFreshWindowGraphDelete::Deleted { .. }
            ));
            assert!(matches!(
                svc(&paths)
                    .delete_fresh_window_graph_if_unchanged(&first.receipt, 87)
                    .unwrap(),
                ConditionalFreshWindowGraphDelete::Changed
            ));
        }

        // A mutation to another window conservatively invalidates the global receipt.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-receipt-unrelated";
            create_fixture_project(&paths, project_id);
            let spec = fresh_graph_spec(project_id, "receipt-unrelated");
            let created = created_graph(
                svc(&paths)
                    .create_fresh_window_graph(
                        &stored_graph_project_snapshot(&paths, project_id),
                        spec.clone(),
                        88,
                    )
                    .unwrap(),
            );
            svc(&paths)
                .create_empty("fresh-unrelated-window", 89)
                .unwrap();
            assert!(matches!(
                svc(&paths)
                    .delete_fresh_window_graph_if_unchanged(&created.receipt, 90)
                    .unwrap(),
                ConditionalFreshWindowGraphDelete::Changed
            ));
            assert_eq!(
                svc(&paths).load(&spec.window_id).unwrap(),
                Some(created.window.layout)
            );
        }
    }

    #[test]
    fn fresh_graph_receipt_refuses_new_soft_owners_and_created_project_children() {
        // AgentTask current/history is a durable Session owner and creation is epoch-quiet.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-receipt-task-ref";
            create_fixture_project(&paths, project_id);
            let spec = fresh_graph_spec(project_id, "receipt-task-ref");
            let created = created_graph(
                svc(&paths)
                    .create_fresh_window_graph(
                        &stored_graph_project_snapshot(&paths, project_id),
                        spec.clone(),
                        91,
                    )
                    .unwrap(),
            );
            let epoch = window_epoch(&paths);
            let task = crate::records::AgentTask {
                agent_task_id: "fresh-receipt-task".into(),
                project_id: project_id.into(),
                goal: "retain session".into(),
                state: crate::AgentTaskState::Running,
                current_session_id: Some(spec.session.session_id.clone()),
                session_history: Vec::new(),
                created_at_ms: 92,
                updated_at_ms: 92,
                result_summary: None,
            };
            crate::write_record(
                &paths,
                RecordKind::AgentTask,
                &task.agent_task_id,
                92,
                &task,
            )
            .unwrap();
            assert_eq!(window_epoch(&paths), epoch);
            assert!(matches!(
                svc(&paths)
                    .delete_fresh_window_graph_if_unchanged(&created.receipt, 93)
                    .unwrap(),
                ConditionalFreshWindowGraphDelete::Referenced
            ));
            assert_eq!(
                svc(&paths).load(&spec.window_id).unwrap(),
                Some(created.window.layout)
            );
        }

        // A newly published Project graph may be cascaded only while its direct children remain
        // exactly the one Workspace + one Window from the receipt.
        {
            let (_tmp, paths) = temp_paths();
            let project_id = "fresh-receipt-project-child";
            let spec = fresh_graph_spec(project_id, "receipt-project-child");
            let created = created_graph(
                svc(&paths)
                    .create_fresh_project_window_graph(
                        project_id,
                        "Receipt Project",
                        "/fresh/receipt",
                        crate::NewProject::default(),
                        spec.clone(),
                        94,
                    )
                    .unwrap(),
            );
            let extra_task = crate::records::AgentTask {
                agent_task_id: "fresh-receipt-extra-task".into(),
                project_id: project_id.into(),
                goal: "foreign child".into(),
                state: crate::AgentTaskState::Draft,
                current_session_id: None,
                session_history: Vec::new(),
                created_at_ms: 95,
                updated_at_ms: 95,
                result_summary: None,
            };
            crate::write_record(
                &paths,
                RecordKind::AgentTask,
                &extra_task.agent_task_id,
                95,
                &extra_task,
            )
            .unwrap();
            assert!(matches!(
                svc(&paths)
                    .delete_fresh_window_graph_if_unchanged(&created.receipt, 96)
                    .unwrap(),
                ConditionalFreshWindowGraphDelete::Referenced
            ));
            assert!(loaded_record::<Project>(&paths, RecordKind::Project, project_id).is_some());
            assert_eq!(
                svc(&paths).load(&spec.window_id).unwrap(),
                Some(created.window.layout)
            );
        }
    }

    #[test]
    fn fresh_graph_receipt_refuses_each_durable_soft_owner_without_mutation() {
        #[derive(Clone, Copy, Debug)]
        enum RefKind {
            ExtraWorkspaceSession,
            TaskHistory,
            ForeignTab,
            ProvenanceSession,
            ProvenanceWorkspace,
            LayoutPresetHint,
        }

        for (index, reference) in [
            RefKind::ExtraWorkspaceSession,
            RefKind::TaskHistory,
            RefKind::ForeignTab,
            RefKind::ProvenanceSession,
            RefKind::ProvenanceWorkspace,
            RefKind::LayoutPresetHint,
        ]
        .into_iter()
        .enumerate()
        {
            let (_tmp, paths) = temp_paths();
            let project_id = format!("fresh-receipt-owner-{index}");
            create_fixture_project(&paths, &project_id);
            let spec = fresh_graph_spec(&project_id, &format!("receipt-owner-{index}"));
            let created = created_graph(
                svc(&paths)
                    .create_fresh_window_graph(
                        &stored_graph_project_snapshot(&paths, &project_id),
                        spec.clone(),
                        10_000 + index as u64,
                    )
                    .unwrap(),
            );

            match reference {
                RefKind::ExtraWorkspaceSession => {
                    let mut extra = spec.session.clone();
                    extra.session_id = format!("fresh-extra-child-{index}");
                    assert_eq!(
                        crate::create_session_record_if_absent(&paths, &extra, 20_000).unwrap(),
                        crate::CreateSessionRecordOutcome::Created
                    );
                }
                RefKind::TaskHistory => {
                    let task = crate::records::AgentTask {
                        agent_task_id: format!("fresh-history-owner-{index}"),
                        project_id: project_id.clone(),
                        goal: "retain historical session".into(),
                        state: crate::AgentTaskState::Running,
                        current_session_id: None,
                        session_history: vec![spec.session.session_id.clone()],
                        created_at_ms: 20_000,
                        updated_at_ms: 20_000,
                        result_summary: None,
                    };
                    crate::write_record(
                        &paths,
                        RecordKind::AgentTask,
                        &task.agent_task_id,
                        20_000,
                        &task,
                    )
                    .unwrap();
                }
                RefKind::ForeignTab => {
                    let connection = crate::db::conn_for(paths.base()).unwrap();
                    let guard = connection.lock().unwrap();
                    guard
                        .execute(
                            "INSERT INTO windows (window_id, project_id, name) \
                             VALUES (?1, NULL, 'foreign')",
                            [format!("fresh-foreign-window-{index}")],
                        )
                        .unwrap();
                    guard
                        .execute(
                            "INSERT INTO tabs (window_id, tab_id, session_id, idx, title, pinned, \
                             stashed, attention_json, pane_rect_json, split_from_json, stashed_from_json) \
                             VALUES (?1, 'foreign-tab', ?2, 0, 'foreign', 0, 0, ?3, NULL, NULL, NULL)",
                            rusqlite::params![
                                format!("fresh-foreign-window-{index}"),
                                spec.session.session_id,
                                serde_json::to_string(&AttentionState::default()).unwrap()
                            ],
                        )
                        .unwrap();
                }
                RefKind::ProvenanceSession | RefKind::ProvenanceWorkspace => {
                    let workspace_id = if matches!(reference, RefKind::ProvenanceWorkspace) {
                        spec.workspace.workspace_id.clone()
                    } else {
                        let foreign_project_id = format!("fresh-provenance-project-{index}");
                        create_fixture_project(&paths, &foreign_project_id);
                        let foreign_workspace = Workspace {
                            workspace_id: format!("fresh-provenance-workspace-{index}"),
                            project_id: foreign_project_id,
                            root: "/fresh/foreign".into(),
                            policy: crate::WorkspacePolicy::ScratchCwd,
                            consent: crate::WorkspaceConsent::default(),
                        };
                        crate::write_record(
                            &paths,
                            RecordKind::Workspace,
                            &foreign_workspace.workspace_id,
                            20_000,
                            &foreign_workspace,
                        )
                        .unwrap();
                        foreign_workspace.workspace_id
                    };
                    let provenance = crate::records::WorktreeProvenance {
                        session_id: if matches!(reference, RefKind::ProvenanceSession) {
                            spec.session.session_id.clone()
                        } else {
                            format!("fresh-foreign-provenance-session-{index}")
                        },
                        workspace_id,
                        repo_root: "/fresh".into(),
                        target_path: format!("/tmp/fresh-owner-{index}"),
                        branch: format!("maestro/fresh-owner-{index}"),
                        created_at_ms: 20_000,
                    };
                    crate::write_record(
                        &paths,
                        RecordKind::WorktreeProvenance,
                        &provenance.session_id,
                        20_000,
                        &provenance,
                    )
                    .unwrap();
                }
                RefKind::LayoutPresetHint => {
                    let preset = crate::records::LayoutPreset {
                        preset_id: format!("fresh-preset-owner-{index}"),
                        name: "retain fresh session".into(),
                        project_id: None,
                        created_at_ms: 20_000,
                        tabs: vec![crate::records::LayoutPresetTab {
                            index: 0,
                            title: "fresh".into(),
                            pinned: false,
                            split_from: None,
                            session_id: Some(spec.session.session_id.clone()),
                            source_tab_id: "preset-source".into(),
                        }],
                    };
                    crate::write_record(
                        &paths,
                        RecordKind::LayoutPreset,
                        &preset.preset_id,
                        20_000,
                        &preset,
                    )
                    .unwrap();
                }
            }

            let epoch_before = window_epoch(&paths);
            let project_before = stored_project(&paths, &project_id);
            let workspace_before = loaded_record::<Workspace>(
                &paths,
                RecordKind::Workspace,
                &spec.workspace.workspace_id,
            );
            let session_before = loaded_record::<SessionRecord>(
                &paths,
                RecordKind::Session,
                &spec.session.session_id,
            );
            let window_before = svc(&paths).load_snapshot(&spec.window_id).unwrap();
            let cleanup_ts = 50_000 + index as u64;
            assert!(
                matches!(
                    svc(&paths)
                        .delete_fresh_window_graph_if_unchanged(&created.receipt, cleanup_ts)
                        .unwrap(),
                    ConditionalFreshWindowGraphDelete::Referenced
                ),
                "{reference:?}"
            );
            assert_eq!(window_epoch(&paths), epoch_before, "{reference:?}");
            assert_eq!(stored_project(&paths, &project_id), project_before);
            assert_eq!(
                loaded_record::<Workspace>(
                    &paths,
                    RecordKind::Workspace,
                    &spec.workspace.workspace_id
                ),
                workspace_before
            );
            assert_eq!(
                loaded_record::<SessionRecord>(
                    &paths,
                    RecordKind::Session,
                    &spec.session.session_id
                ),
                session_before
            );
            assert_eq!(
                svc(&paths).load_snapshot(&spec.window_id).unwrap(),
                window_before
            );
            assert!(
                crate::write_trace::recent()
                    .into_iter()
                    .all(|trace| { !is_fresh_graph_trace(&trace, &project_id, &spec, cleanup_ts) }),
                "{reference:?} emitted a cleanup trace"
            );
        }
    }

    #[test]
    fn fresh_graph_receipt_malformed_preset_is_error_not_empty_reference_set() {
        let (_tmp, paths) = temp_paths();
        let project_id = "fresh-receipt-malformed-preset";
        create_fixture_project(&paths, project_id);
        let spec = fresh_graph_spec(project_id, "receipt-malformed-preset");
        let created = created_graph(
            svc(&paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(&paths, project_id),
                    spec.clone(),
                    97,
                )
                .unwrap(),
        );
        let connection = crate::db::conn_for(paths.base()).unwrap();
        connection
            .lock()
            .unwrap()
            .execute(
                "INSERT INTO layout_presets \
                 (preset_id, project_id, name, created_at_ms, tabs_json) \
                 VALUES ('fresh-bad-preset', ?1, 'bad', 1, '{')",
                [project_id],
            )
            .unwrap();
        let error = svc(&paths)
            .delete_fresh_window_graph_if_unchanged(&created.receipt, 98)
            .unwrap_err();
        assert!(matches!(
            error,
            WindowLayoutError::Store(StoreError::Map(_))
        ));
        assert_eq!(
            svc(&paths).load(&spec.window_id).unwrap(),
            Some(created.window.layout)
        );
    }

    #[test]
    fn fresh_graph_window_title_is_allocated_from_writer_snapshot() {
        let (_tmp, paths) = temp_paths();
        let project_id = "fresh-title-project";
        create_fixture_project(&paths, project_id);
        let first_spec = fresh_graph_spec(project_id, "title-one");
        let first = created_graph(
            svc(&paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(&paths, project_id),
                    first_spec,
                    99,
                )
                .unwrap(),
        );
        let second_spec = fresh_graph_spec(project_id, "title-two");
        let second = created_graph(
            svc(&paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(&paths, project_id),
                    second_spec,
                    100,
                )
                .unwrap(),
        );
        assert_eq!(first.window.layout.name.as_deref(), Some("Fresh Window"));
        assert_eq!(second.window.layout.name.as_deref(), Some("Fresh Window 2"));
        assert_eq!(
            second.project.window_order,
            [
                first.window.layout.window_id,
                second.window.layout.window_id
            ]
        );
    }

    #[test]
    fn fresh_graph_title_includes_fk_owned_sibling_omitted_from_project_order() {
        let (_tmp, paths) = temp_paths();
        let project_id = "fresh-title-fk-project";
        create_fixture_project(&paths, project_id);
        let layouts = svc(&paths);
        layouts.create_empty("fresh-title-owned-orphan", 1).unwrap();
        layouts
            .rename_window("fresh-title-owned-orphan", "Fresh Window", 2)
            .unwrap();
        let connection = crate::db::conn_for(paths.base()).unwrap();
        let mut guard = connection.lock().unwrap();
        let tx = guard
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE windows SET project_id = ?2 WHERE window_id = ?1",
            rusqlite::params!["fresh-title-owned-orphan", project_id],
        )
        .unwrap();
        crate::db::bump_window_mutation_epoch(&tx).unwrap();
        tx.commit().unwrap();
        drop(guard);

        let spec = fresh_graph_spec(project_id, "title-fk-owned");
        let created = created_graph(
            layouts
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(&paths, project_id),
                    spec,
                    3,
                )
                .unwrap(),
        );
        assert_eq!(
            created.window.layout.name.as_deref(),
            Some("Fresh Window 2")
        );
        assert_eq!(
            created.project.window_order,
            std::slice::from_ref(&created.window.layout.window_id),
            "fresh creation appends only its new window; it does not rewrite legacy presentation hints"
        );
        assert_eq!(
            layouts
                .load_snapshot("fresh-title-owned-orphan")
                .unwrap()
                .unwrap()
                .project_id
                .as_deref(),
            Some(project_id)
        );
    }

    /// Simulate an independent process retargeting one durable tab. The raw test writer mirrors
    /// the production mutation contract by changing the full layout and global window epoch in
    /// one IMMEDIATE transaction.
    fn retarget_tab_from_second_connection(
        paths: &AppPaths,
        window_id: &str,
        tab_id: &str,
        session_id: &str,
    ) {
        let mut connection = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        let tx = connection
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let raw = crate::store_sqlite::load_one(&tx, RecordKind::WindowLayout, window_id)
            .unwrap()
            .expect("race fixture window exists");
        let mut layout: WindowLayout = serde_json::from_value(raw).unwrap();
        layout
            .tabs
            .iter_mut()
            .find(|tab| tab.tab_id == tab_id)
            .expect("race fixture tab exists")
            .session_id = session_id.to_string();
        crate::store_sqlite::upsert(
            &tx,
            RecordKind::WindowLayout,
            window_id,
            &serde_json::to_value(&layout).unwrap(),
        )
        .unwrap();
        crate::db::bump_window_mutation_epoch(&tx).unwrap();
        tx.commit().unwrap();
    }

    struct ChildIdentityRestoreFixture {
        _tmp: TempDir,
        paths: AppPaths,
        workspace: Workspace,
        session: SessionRecord,
        expected: WindowLayoutSnapshot,
        receipt: WindowDeletionReceipt,
        epoch_after_window_delete: u32,
    }

    fn child_identity_restore_fixture(suffix: &str) -> ChildIdentityRestoreFixture {
        let (tmp, paths) = temp_paths();
        let project_id = format!("restore-child-project-{suffix}");
        crate::ProjectService::new(&paths)
            .create(
                &project_id,
                "Same parent",
                "/same-root",
                crate::NewProject::default(),
                41,
            )
            .unwrap();
        let workspace = Workspace {
            workspace_id: format!("restore-workspace-{suffix}"),
            project_id,
            root: "/same-root".into(),
            policy: crate::WorkspacePolicy::ScratchCwd,
            consent: crate::WorkspaceConsent::default(),
        };
        let session = SessionRecord {
            session_id: format!("restore-session-{suffix}"),
            workspace_id: workspace.workspace_id.clone(),
            kind: crate::SessionKind::Shell,
            launch: crate::LaunchSpec::OptOut,
            cwd_resolved: "/same-root".into(),
            agent_task_id: None,
            created_at_ms: 41,
            last_attached_at_ms: 41,
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        crate::write_record(
            &paths,
            RecordKind::Workspace,
            &workspace.workspace_id,
            41,
            &workspace,
        )
        .unwrap();
        crate::write_record(
            &paths,
            RecordKind::Session,
            &session.session_id,
            41,
            &session,
        )
        .unwrap();
        let service = svc(&paths);
        let window_id = format!("restore-child-window-{suffix}");
        service.create_empty(&window_id, 1).unwrap();
        service
            .open_tab(
                &window_id,
                "same-tab",
                &session.session_id,
                "Same tab",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        let expected = service.load_snapshot(&window_id).unwrap().unwrap();
        let receipt = match service.delete_if_unchanged(&expected, 3).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            outcome => panic!("expected conditional delete, got {outcome:?}"),
        };
        let epoch_after_window_delete = window_epoch(&paths);
        ChildIdentityRestoreFixture {
            _tmp: tmp,
            paths,
            workspace,
            session,
            expected,
            receipt,
            epoch_after_window_delete,
        }
    }

    fn assignment_trace_count(window_id: &str, project_ids: &[&str]) -> usize {
        crate::write_trace::recent()
            .into_iter()
            .filter(|event| {
                (event.kind == "WindowOwner" && event.id == window_id)
                    || (event.kind == "Project"
                        && project_ids.iter().any(|project_id| event.id == *project_id))
            })
            .count()
    }

    struct CreatedGraphFixture {
        _tmp: TempDir,
        paths: AppPaths,
        project: Project,
        workspace: Workspace,
        session: SessionRecord,
        expected: WindowLayoutSnapshot,
    }

    fn created_graph_fixture_with_suffix(suffix: &str) -> CreatedGraphFixture {
        let (tmp, paths) = temp_paths();
        let id = |base: &str| {
            if suffix.is_empty() {
                base.to_string()
            } else {
                format!("{base}-{suffix}")
            }
        };
        let fresh_project = id("fresh-project");
        let foreign_project = id("foreign-project");
        let foreign_window = id("foreign-window");
        let projects = crate::ProjectService::new(&paths);
        projects
            .create(
                &fresh_project,
                "Fresh",
                ".",
                crate::NewProject::default(),
                1,
            )
            .unwrap();
        projects
            .create(
                &foreign_project,
                "Foreign",
                ".",
                crate::NewProject::default(),
                1,
            )
            .unwrap();

        // Publish the possible foreign tab owner before capturing the target's final generation.
        // Individual tests then add only a legacy/raw soft reference, without an epoch bump, so a
        // refusal proves the ownership query rather than merely the global-generation guard.
        let service = svc(&paths);
        service.create_empty(&foreign_window, 1).unwrap();
        crate::store::set_window_project(&paths, &foreign_window, &foreign_project).unwrap();

        let workspace = Workspace {
            workspace_id: id("fresh-workspace"),
            project_id: fresh_project.clone(),
            root: ".".into(),
            policy: crate::WorkspacePolicy::ScratchCwd,
            consent: crate::WorkspaceConsent::default(),
        };
        let session = SessionRecord {
            session_id: id("fresh-session"),
            workspace_id: workspace.workspace_id.clone(),
            kind: crate::SessionKind::Shell,
            launch: crate::LaunchSpec::OptOut,
            cwd_resolved: ".".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        crate::write_record(
            &paths,
            RecordKind::Workspace,
            &workspace.workspace_id,
            1,
            &workspace,
        )
        .unwrap();
        crate::write_record(
            &paths,
            RecordKind::Session,
            &session.session_id,
            1,
            &session,
        )
        .unwrap();
        let mut expected = service
            .create_empty_snapshot(&id("fresh-window"), 2)
            .unwrap();
        expected = service
            .open_tab_if_unchanged(
                &expected,
                &id("fresh-pane"),
                &session.session_id,
                "Fresh",
                false,
                AttentionState::default(),
                3,
            )
            .unwrap();
        let assignment = service
            .assign_project_and_order_if_unchanged(&expected, None, &fresh_project, 4)
            .unwrap();
        let ConditionalWindowProjectAssignment::Applied(assignment) = assignment else {
            panic!("fresh graph owner assignment was refused")
        };
        expected = assignment.window;
        let project = assignment.project;
        CreatedGraphFixture {
            _tmp: tmp,
            paths,
            project,
            workspace,
            session,
            expected,
        }
    }

    fn created_graph_fixture() -> CreatedGraphFixture {
        created_graph_fixture_with_suffix("")
    }

    #[derive(Clone, Copy, Debug)]
    enum EscapedFreshGraphOwner {
        ForeignTab,
        TaskCurrent,
        TaskHistory,
        ProvenanceSession,
        ProvenanceWorkspace,
        ForeignProjectOrder,
    }

    fn inject_escaped_fresh_graph_owner(paths: &AppPaths, owner: EscapedFreshGraphOwner) {
        let connection = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        match owner {
            EscapedFreshGraphOwner::ForeignTab => {
                connection
                    .execute(
                        "INSERT INTO tabs (
                             window_id, tab_id, session_id, idx, title, pinned, stashed,
                             attention_json, pane_rect_json, split_from_json, stashed_from_json
                         ) VALUES (?1, ?2, ?3, 0, 'Foreign', 0, 0, ?4, NULL, NULL, NULL)",
                        rusqlite::params![
                            "foreign-window",
                            "foreign-pane",
                            "fresh-session",
                            serde_json::to_string(&AttentionState::default()).unwrap()
                        ],
                    )
                    .unwrap();
            }
            EscapedFreshGraphOwner::TaskCurrent => {
                connection
                    .execute(
                        "INSERT INTO agent_tasks (
                             agent_task_id, project_id, goal, state, current_session_id,
                             session_history_json, created_at_ms, updated_at_ms, result_summary
                         ) VALUES ('foreign-current-task', 'foreign-project', '', 'running',
                                   'fresh-session', '[]', 1, 1, NULL)",
                        [],
                    )
                    .unwrap();
            }
            EscapedFreshGraphOwner::TaskHistory => {
                connection
                    .execute(
                        "INSERT INTO agent_tasks (
                             agent_task_id, project_id, goal, state, current_session_id,
                             session_history_json, created_at_ms, updated_at_ms, result_summary
                         ) VALUES ('foreign-history-task', 'foreign-project', '', 'running',
                                   NULL, '[\"fresh-session\"]', 1, 1, NULL)",
                        [],
                    )
                    .unwrap();
            }
            EscapedFreshGraphOwner::ProvenanceSession => {
                connection
                    .execute(
                        "INSERT INTO worktree_provenance (
                             session_id, workspace_id, repo_root, target_path, branch, created_at_ms
                         ) VALUES ('fresh-session', 'fresh-workspace', '.', '/tmp/fresh',
                                   'maestro/fresh', 1)",
                        [],
                    )
                    .unwrap();
            }
            EscapedFreshGraphOwner::ProvenanceWorkspace => {
                connection
                    .execute(
                        "INSERT INTO worktree_provenance (
                             session_id, workspace_id, repo_root, target_path, branch, created_at_ms
                         ) VALUES ('foreign-provenance-session', 'fresh-workspace', '.',
                                   '/tmp/foreign', 'maestro/foreign', 1)",
                        [],
                    )
                    .unwrap();
            }
            EscapedFreshGraphOwner::ForeignProjectOrder => {
                connection
                    .execute(
                        "UPDATE projects SET window_order_json = '[\"fresh-window\"]'
                         WHERE project_id = 'foreign-project'",
                        [],
                    )
                    .unwrap();
            }
        }
    }

    #[test]
    fn exact_created_pane_session_cleanup_deletes_only_unreferenced_and_advances_epoch() {
        let fixture = created_graph_fixture_with_suffix("exact-pane-cleanup");
        let tab_id = fixture.expected.layout.tabs[0].tab_id.clone();
        let service = svc(&fixture.paths);
        let closed = service
            .close_created_tab_if_unchanged(
                &fixture.expected,
                &tab_id,
                &fixture.session.session_id,
                5,
            )
            .unwrap();
        assert!(closed.layout.tabs.iter().all(|tab| tab.tab_id != tab_id));
        let epoch_after_close = window_epoch(&fixture.paths);
        let traces_before = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "Session" && event.id == fixture.session.session_id)
            .count();

        assert!(matches!(
            service
                .delete_created_session_if_unreferenced(&closed, &tab_id, &fixture.session, 6,)
                .unwrap(),
            ConditionalCreatedSessionDelete::Deleted {
                release_receipt: None,
                unresolved_release_session_ids,
            } if unresolved_release_session_ids == [fixture.session.session_id.clone()]
        ));
        assert!(crate::load_one::<SessionRecord>(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session.session_id,
        )
        .unwrap()
        .is_none());
        assert_eq!(window_epoch(&fixture.paths), epoch_after_close + 1);
        assert_eq!(
            crate::write_trace::recent()
                .into_iter()
                .filter(|event| {
                    event.kind == "Session" && event.id == fixture.session.session_id
                })
                .count(),
            traces_before + 1
        );
        let after = service
            .load_snapshot(&fixture.expected.layout.window_id)
            .unwrap()
            .unwrap();
        assert_eq!(after.layout, closed.layout);
        assert_eq!(after.project_id, closed.project_id);
    }

    #[test]
    fn second_writer_owner_between_created_tab_close_and_session_cleanup_is_retained() {
        for owner in [
            EscapedFreshGraphOwner::ForeignTab,
            EscapedFreshGraphOwner::TaskCurrent,
            EscapedFreshGraphOwner::TaskHistory,
            EscapedFreshGraphOwner::ProvenanceSession,
        ] {
            let fixture = created_graph_fixture();
            let service = svc(&fixture.paths);
            let closed = service
                .close_created_tab_if_unchanged(
                    &fixture.expected,
                    "fresh-pane",
                    &fixture.session.session_id,
                    5,
                )
                .unwrap();

            // A separate SQLite connection deterministically publishes the escaped soft owner
            // after the tab close committed and before conditional Session cleanup begins.
            inject_escaped_fresh_graph_owner(&fixture.paths, owner);
            let epoch_before_cleanup = window_epoch(&fixture.paths);
            assert!(
                matches!(
                    service
                        .delete_created_session_if_unreferenced(
                            &closed,
                            "fresh-pane",
                            &fixture.session,
                            6,
                        )
                        .unwrap(),
                    ConditionalCreatedSessionDelete::Referenced
                ),
                "owner {owner:?} must retain the published Session"
            );
            assert_eq!(window_epoch(&fixture.paths), epoch_before_cleanup);
            let current = crate::load_one::<SessionRecord>(
                &fixture.paths,
                RecordKind::Session,
                &fixture.session.session_id,
            )
            .unwrap()
            .unwrap();
            assert!(matches!(
                current,
                crate::LoadOutcome::Loaded(session) if session == fixture.session
            ));
        }
    }

    #[test]
    fn created_session_cleanup_rejects_changed_bytes_and_exact_delete_recreate() {
        let changed = created_graph_fixture();
        let changed_service = svc(&changed.paths);
        let changed_closed = changed_service
            .close_created_tab_if_unchanged(
                &changed.expected,
                "fresh-pane",
                &changed.session.session_id,
                5,
            )
            .unwrap();
        let mut edited_session = changed.session.clone();
        edited_session.last_attached_at_ms += 1;
        crate::write_record(
            &changed.paths,
            RecordKind::Session,
            &edited_session.session_id,
            6,
            &edited_session,
        )
        .unwrap();
        let epoch_after_metadata = window_epoch(&changed.paths);
        assert!(matches!(
            changed_service
                .delete_created_session_if_unreferenced(
                    &changed_closed,
                    "fresh-pane",
                    &changed.session,
                    7,
                )
                .unwrap(),
            ConditionalCreatedSessionDelete::Changed
        ));
        assert_eq!(window_epoch(&changed.paths), epoch_after_metadata);

        let recreated = created_graph_fixture();
        let recreated_service = svc(&recreated.paths);
        let recreated_closed = recreated_service
            .close_created_tab_if_unchanged(
                &recreated.expected,
                "fresh-pane",
                &recreated.session.session_id,
                5,
            )
            .unwrap();
        assert!(crate::store::delete_record(
            &recreated.paths,
            RecordKind::Session,
            &recreated.session.session_id,
        )
        .unwrap());
        crate::write_record(
            &recreated.paths,
            RecordKind::Session,
            &recreated.session.session_id,
            6,
            &recreated.session,
        )
        .unwrap();
        let epoch_after_recreate = window_epoch(&recreated.paths);
        assert!(matches!(
            recreated_service
                .delete_created_session_if_unreferenced(
                    &recreated_closed,
                    "fresh-pane",
                    &recreated.session,
                    7,
                )
                .unwrap(),
            ConditionalCreatedSessionDelete::Changed
        ));
        assert_eq!(window_epoch(&recreated.paths), epoch_after_recreate);
        assert!(crate::load_one::<SessionRecord>(
            &recreated.paths,
            RecordKind::Session,
            &recreated.session.session_id,
        )
        .unwrap()
        .is_some());
    }

    fn reconciled(
        agent_task_id: &str,
        state: AgentTaskState,
        current_session_id: Option<&str>,
        current_session_status: Option<SessionStatus>,
        session_record_missing: bool,
        needs_attention: bool,
    ) -> ReconciledAgentTask {
        ReconciledAgentTask {
            agent_task_id: agent_task_id.into(),
            state,
            current_session_id: current_session_id.map(str::to_string),
            current_session_status,
            session_record_missing,
            needs_attention,
        }
    }

    #[test]
    fn create_empty_writes_expected_layout() {
        let (_tmp, paths) = temp_paths();
        let layout = svc(&paths).create_empty("w1", 5).unwrap();
        assert_eq!(layout.window_id, "w1");
        assert!(layout.tabs.is_empty());

        // Round-trips from disk.
        let reloaded = svc(&paths).load("w1").unwrap().unwrap();
        assert_eq!(reloaded, layout);
    }

    #[test]
    fn create_refuses_overwrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        let err = svc(&paths).create_empty("w1", 2).unwrap_err();
        assert!(matches!(
            err,
            WindowLayoutError::WindowLayoutAlreadyExists { .. }
        ));
    }

    #[test]
    fn concurrent_layout_mutations_preserve_both_committed_edits() {
        use rusqlite::{ErrorCode, TransactionBehavior};
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{mpsc, Arc, Mutex};
        use std::time::Duration;

        #[derive(Debug)]
        enum WriterEvent {
            Contended,
            Committed,
        }

        fn pin_from_fresh_layout(
            conn: &mut rusqlite::Connection,
            window_id: &str,
        ) -> Result<(), rusqlite::Error> {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let raw = crate::store_sqlite::load_one(&tx, RecordKind::WindowLayout, window_id)
                .map_err(|error| match error {
                    crate::store_sqlite::MapError::Sqlite(error) => error,
                    crate::store_sqlite::MapError::Shape(error) => {
                        panic!("test fixture window maps cleanly: {error}")
                    }
                })?
                .expect("test fixture window exists");
            let mut layout: WindowLayout = serde_json::from_value(raw).unwrap();
            layout.tabs[0].pinned = true;
            crate::store_sqlite::upsert(
                &tx,
                RecordKind::WindowLayout,
                window_id,
                &serde_json::to_value(layout).unwrap(),
            )
            .map_err(|error| match error {
                crate::store_sqlite::MapError::Sqlite(error) => error,
                crate::store_sqlite::MapError::Shape(error) => {
                    panic!("test fixture mutation maps cleanly: {error}")
                }
            })?;
            tx.commit()
        }

        let (_tmp, paths) = temp_paths();
        let window_id = "lost-update-window";
        svc(&paths).create_empty(window_id, 1).unwrap();
        svc(&paths)
            .open_tab(
                window_id,
                "tab-a",
                "session-a",
                "A",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();

        let mut second_conn = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        second_conn
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        second_conn.pragma_update(None, "busy_timeout", 0).unwrap();

        let (paused_tx, paused_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let paused_once = Arc::new(AtomicBool::new(false));
        let _hook = crate::store_sqlite::install_window_layout_test_hook(window_id, {
            let release_rx = Arc::clone(&release_rx);
            let paused_once = Arc::clone(&paused_once);
            move |stage, _| {
                if stage == "after-window-load" && !paused_once.swap(true, Ordering::SeqCst) {
                    paused_tx.send(()).unwrap();
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .expect("test releases the first mutation");
                }
            }
        });

        let first_paths = paths.clone();
        let first =
            std::thread::spawn(move || svc(&first_paths).rename_window(window_id, "renamed", 10));
        paused_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("first mutation pauses after its fresh layout load");

        let (event_tx, event_rx) = mpsc::channel();
        let (retry_tx, retry_rx) = mpsc::channel();
        let second =
            std::thread::spawn(
                move || match pin_from_fresh_layout(&mut second_conn, window_id) {
                    Ok(()) => event_tx.send(WriterEvent::Committed).unwrap(),
                    Err(error)
                        if matches!(
                            error.sqlite_error_code(),
                            Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked)
                        ) =>
                    {
                        event_tx.send(WriterEvent::Contended).unwrap();
                        retry_rx
                            .recv_timeout(Duration::from_secs(5))
                            .expect("test retries after the first mutation commits");
                        pin_from_fresh_layout(&mut second_conn, window_id).unwrap();
                        event_tx.send(WriterEvent::Committed).unwrap();
                    }
                    Err(error) => panic!("unexpected second-writer failure: {error}"),
                },
            );

        match event_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("second connection either commits or observes the writer fence")
        {
            WriterEvent::Committed => release_tx.send(()).unwrap(),
            WriterEvent::Contended => {
                release_tx.send(()).unwrap();
                first.join().unwrap().unwrap();
                retry_tx.send(()).unwrap();
                assert!(matches!(
                    event_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
                    WriterEvent::Committed
                ));
                second.join().unwrap();
                let final_layout = stored(&paths, window_id);
                assert_eq!(final_layout.name.as_deref(), Some("renamed"));
                assert!(final_layout.tabs[0].pinned);
                return;
            }
        }

        first.join().unwrap().unwrap();
        second.join().unwrap();
        let final_layout = stored(&paths, window_id);
        assert_eq!(final_layout.name.as_deref(), Some("renamed"));
        assert!(
            final_layout.tabs[0].pinned,
            "a delayed stale full-layout write must not erase the second connection's committed pin"
        );
    }

    #[test]
    fn created_tab_and_exact_session_rollback_is_one_journaled_commit() {
        let mut fixture = created_graph_fixture();
        fixture.session.last_known_generation = Some("created-tab-generation".into());
        crate::write_record(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session.session_id,
            5,
            &fixture.session,
        )
        .unwrap();
        let epoch_before = window_epoch(&fixture.paths);
        let rolled_back = svc(&fixture.paths)
            .rollback_created_tab_and_session_if_unchanged(
                &fixture.expected,
                "fresh-pane",
                &fixture.session,
                6,
            )
            .unwrap();
        let ConditionalCreatedTabSessionRollback::RolledBack(rolled_back) = rolled_back else {
            panic!("expected exact created-tab rollback")
        };
        assert!(rolled_back.layout.tabs.is_empty());
        assert!(rolled_back.unresolved_release_session_ids.is_empty());
        assert!(rolled_back.release_receipt.is_some());
        assert_eq!(window_epoch(&fixture.paths), epoch_before + 1);
        assert!(loaded_record::<SessionRecord>(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session.session_id,
        )
        .is_none());
        assert_eq!(pending_release_count(&fixture.paths), 1);
    }

    #[test]
    fn created_tab_rollback_rejects_replacement_session_before_generation_resolution() {
        let mut fixture = created_graph_fixture();
        fixture.session.last_known_generation = Some("created-session-a".into());
        crate::write_record(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session.session_id,
            5,
            &fixture.session,
        )
        .unwrap();
        let mut replacement = fixture.session.clone();
        replacement.last_known_generation = Some("created-session-b".into());
        replacement.last_attached_at_ms += 1;
        crate::write_record(
            &fixture.paths,
            RecordKind::Session,
            &replacement.session_id,
            6,
            &replacement,
        )
        .unwrap();
        assert!(matches!(
            svc(&fixture.paths)
                .rollback_created_tab_and_session_if_unchanged(
                    &fixture.expected,
                    "fresh-pane",
                    &fixture.session,
                    7,
                )
                .unwrap(),
            ConditionalCreatedTabSessionRollback::Changed
        ));
        assert_eq!(
            loaded_record::<SessionRecord>(
                &fixture.paths,
                RecordKind::Session,
                &replacement.session_id,
            ),
            Some(replacement)
        );
        assert_eq!(pending_release_count(&fixture.paths), 0);
    }

    #[test]
    fn created_tab_rollback_retains_a_session_with_an_external_tab_owner() {
        let mut fixture = created_graph_fixture();
        fixture.session.last_known_generation = Some("created-owned-generation".into());
        crate::write_record(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session.session_id,
            5,
            &fixture.session,
        )
        .unwrap();
        inject_escaped_fresh_graph_owner(&fixture.paths, EscapedFreshGraphOwner::ForeignTab);
        assert!(matches!(
            svc(&fixture.paths)
                .rollback_created_tab_and_session_if_unchanged(
                    &fixture.expected,
                    "fresh-pane",
                    &fixture.session,
                    6,
                )
                .unwrap(),
            ConditionalCreatedTabSessionRollback::Referenced
        ));
        assert!(loaded_record::<SessionRecord>(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session.session_id,
        )
        .is_some());
        assert_eq!(pending_release_count(&fixture.paths), 0);
    }

    #[test]
    fn created_tab_rollback_failure_after_journal_restores_tab_session_and_journal() {
        let mut fixture = created_graph_fixture_with_suffix("rollback-failure-after-journal");
        let tab_id = fixture.expected.layout.tabs[0].tab_id.clone();
        fixture.session.last_known_generation = Some("created-rollback-generation".into());
        crate::write_record(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session.session_id,
            5,
            &fixture.session,
        )
        .unwrap();
        let _failure = crate::store_sqlite::install_window_layout_test_failure(
            fixture.expected.layout.window_id.clone(),
            "after-created-tab-release-journal",
        );
        assert!(svc(&fixture.paths)
            .rollback_created_tab_and_session_if_unchanged(
                &fixture.expected,
                &tab_id,
                &fixture.session,
                6,
            )
            .is_err());
        assert_eq!(
            svc(&fixture.paths)
                .load_snapshot(&fixture.expected.layout.window_id)
                .unwrap(),
            Some(fixture.expected)
        );
        assert_eq!(
            loaded_record::<SessionRecord>(
                &fixture.paths,
                RecordKind::Session,
                &fixture.session.session_id,
            ),
            Some(fixture.session)
        );
        assert_eq!(pending_release_count(&fixture.paths), 0);
    }

    #[test]
    fn conditional_delete_revalidates_layout_and_owner_on_the_writer_connection() {
        let (_tmp, paths) = temp_paths();
        let projects = crate::ProjectService::new(&paths);
        for project_id in ["delete-owner-a", "delete-owner-b"] {
            projects
                .create(project_id, project_id, ".", crate::NewProject::default(), 1)
                .unwrap();
        }
        let window_id = "conditional-delete-window";
        let service = svc(&paths);
        service.create_empty(window_id, 1).unwrap();
        service
            .open_tab(
                window_id,
                "tab-a",
                "session-a",
                "A",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        crate::store::set_window_project(&paths, window_id, "delete-owner-a").unwrap();
        let expected = service.load_snapshot(window_id).unwrap().unwrap();

        // Simulate the other process with an independent connection and commit both a layout and
        // owner edit after the close caller captured its preparation snapshot.
        let mut other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        other.pragma_update(None, "foreign_keys", "ON").unwrap();
        let tx = other
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE windows SET name = ?2, project_id = ?3 WHERE window_id = ?1",
            rusqlite::params![window_id, "other writer", "delete-owner-b"],
        )
        .unwrap();
        tx.commit().unwrap();

        assert!(matches!(
            service.delete_if_unchanged(&expected, 3).unwrap(),
            ConditionalWindowDelete::Changed
        ));
        let current = service.load_snapshot(window_id).unwrap().unwrap();
        assert_eq!(current.layout.name.as_deref(), Some("other writer"));
        assert_eq!(current.project_id.as_deref(), Some("delete-owner-b"));
    }

    #[test]
    fn conditional_delete_rejects_byte_identical_delete_recreate_aba() {
        let (_tmp, paths) = temp_paths();
        crate::ProjectService::new(&paths)
            .create(
                "aba-owner",
                "ABA owner",
                ".",
                crate::NewProject::default(),
                1,
            )
            .unwrap();
        let service = svc(&paths);
        let mut expected = service.create_empty_snapshot("aba-window", 1).unwrap();
        expected = service
            .open_tab_if_unchanged(
                &expected,
                "pane-a",
                "session-a",
                "A",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        let assignment = service
            .assign_project_and_order_if_unchanged(&expected, None, "aba-owner", 3)
            .unwrap();
        let ConditionalWindowProjectAssignment::Applied(assignment) = assignment else {
            panic!("initial ABA owner assignment was refused")
        };
        expected = assignment.window;

        // One independent writer transaction removes and reinserts the exact same public bytes.
        // The global WindowLayout epoch is the only observable difference and must fail closed.
        let mut other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        other.pragma_update(None, "foreign_keys", "ON").unwrap();
        let tx = other
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        assert!(crate::store_sqlite::delete(&tx, RecordKind::WindowLayout, "aba-window").unwrap());
        let mut value = serde_json::to_value(&expected.layout).unwrap();
        value.as_object_mut().unwrap().insert(
            "project_id".into(),
            serde_json::Value::String("aba-owner".into()),
        );
        crate::store_sqlite::upsert(&tx, RecordKind::WindowLayout, "aba-window", &value).unwrap();
        crate::db::bump_window_mutation_epoch(&tx).unwrap();
        tx.commit().unwrap();

        let current = service.load_snapshot("aba-window").unwrap().unwrap();
        assert_eq!(current.layout, expected.layout);
        assert_eq!(current.project_id, expected.project_id);
        assert_ne!(current.revision, expected.revision);
        assert!(matches!(
            service.delete_if_unchanged(&expected, 4).unwrap(),
            ConditionalWindowDelete::Changed
        ));
        assert!(service.load("aba-window").unwrap().is_some());
    }

    #[test]
    fn window_project_assignment_rejects_a_two_connection_foreign_owner_race() {
        let (_tmp, paths) = temp_paths();
        let projects = crate::ProjectService::new(&paths);
        for project_id in ["owner-target", "owner-foreign"] {
            projects
                .create(project_id, project_id, ".", crate::NewProject::default(), 1)
                .unwrap();
        }
        let service = svc(&paths);
        let stale_unowned = service
            .create_empty_snapshot("owner-race-window", 1)
            .unwrap();

        // A genuinely independent SQLite connection publishes both foreign ownership signals
        // after the first writer captured an unowned snapshot.
        let mut other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        other.pragma_update(None, "foreign_keys", "ON").unwrap();
        let tx = other
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE windows SET project_id = 'owner-foreign' WHERE window_id = 'owner-race-window'",
            [],
        )
        .unwrap();
        tx.execute(
            "UPDATE projects SET window_order_json = '[\"owner-race-window\"]' \
             WHERE project_id = 'owner-foreign'",
            [],
        )
        .unwrap();
        crate::db::bump_window_mutation_epoch(&tx).unwrap();
        tx.commit().unwrap();

        let before = service.load_snapshot("owner-race-window").unwrap().unwrap();
        let target_before = projects.load("owner-target").unwrap().unwrap();
        let foreign_before = projects.load("owner-foreign").unwrap().unwrap();
        let epoch_before = window_epoch(&paths);
        let traces_before =
            assignment_trace_count("owner-race-window", &["owner-target", "owner-foreign"]);

        assert_eq!(
            service
                .assign_project_and_order_if_unchanged(&stale_unowned, None, "owner-target", 2,)
                .unwrap(),
            ConditionalWindowProjectAssignment::Changed,
            "the stale exact snapshot must not retarget the foreign incarnation"
        );
        assert_eq!(
            service
                .ensure_project_assignment("owner-race-window", "owner-target", 3)
                .unwrap(),
            ConditionalWindowProjectAssignment::Conflict {
                current_project_id: Some("owner-foreign".into()),
                ordered_by_project_ids: vec!["owner-foreign".into()],
            },
            "NULL-or-same repair must read the foreign owner inside its writer transaction"
        );
        assert_eq!(
            service.load_snapshot("owner-race-window").unwrap().unwrap(),
            before
        );
        assert_eq!(
            projects.load("owner-target").unwrap().unwrap(),
            target_before
        );
        assert_eq!(
            projects.load("owner-foreign").unwrap().unwrap(),
            foreign_before
        );
        assert_eq!(window_epoch(&paths), epoch_before);
        assert_eq!(
            assignment_trace_count("owner-race-window", &["owner-target", "owner-foreign"],),
            traces_before
        );
    }

    #[test]
    fn window_project_assignment_rejects_a_foreign_order_without_stamping_null_fk() {
        let (_tmp, paths) = temp_paths();
        let projects = crate::ProjectService::new(&paths);
        for project_id in ["order-target", "order-foreign"] {
            projects
                .create(project_id, project_id, ".", crate::NewProject::default(), 1)
                .unwrap();
        }
        let service = svc(&paths);
        service.create_empty("foreign-order-window", 1).unwrap();
        let other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        other
            .execute(
                "UPDATE projects SET window_order_json = '[\"foreign-order-window\"]' \
                 WHERE project_id = 'order-foreign'",
                [],
            )
            .unwrap();

        let epoch_before = window_epoch(&paths);
        let traces_before =
            assignment_trace_count("foreign-order-window", &["order-target", "order-foreign"]);
        assert_eq!(
            service
                .ensure_project_assignment("foreign-order-window", "order-target", 2)
                .unwrap(),
            ConditionalWindowProjectAssignment::Conflict {
                current_project_id: None,
                ordered_by_project_ids: vec!["order-foreign".into()],
            }
        );
        assert_eq!(
            service
                .load_snapshot("foreign-order-window")
                .unwrap()
                .unwrap()
                .project_id,
            None
        );
        assert!(projects
            .load("order-target")
            .unwrap()
            .unwrap()
            .window_order
            .is_empty());
        assert_eq!(
            projects
                .load("order-foreign")
                .unwrap()
                .unwrap()
                .window_order,
            vec!["foreign-order-window"]
        );
        assert_eq!(window_epoch(&paths), epoch_before);
        assert_eq!(
            assignment_trace_count("foreign-order-window", &["order-target", "order-foreign"],),
            traces_before
        );
    }

    #[test]
    fn window_project_assignment_fails_closed_on_malformed_or_duplicate_order() {
        for (case, invalid_order) in [
            ("malformed", "{not-json"),
            ("duplicate", "[\"strict-window\",\"strict-window\"]"),
        ] {
            let (_tmp, paths) = temp_paths();
            let projects = crate::ProjectService::new(&paths);
            projects
                .create(
                    "strict-target",
                    "Strict",
                    ".",
                    crate::NewProject::default(),
                    1,
                )
                .unwrap();
            let service = svc(&paths);
            service.create_empty("strict-window", 1).unwrap();
            let other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
            other
                .execute(
                    "UPDATE projects SET window_order_json = ?2 WHERE project_id = ?1",
                    rusqlite::params!["strict-target", invalid_order],
                )
                .unwrap();
            let epoch_before = window_epoch(&paths);
            let traces_before = assignment_trace_count("strict-window", &["strict-target"]);

            assert!(
                service
                    .ensure_project_assignment("strict-window", "strict-target", 2)
                    .is_err(),
                "{case} order must fail closed"
            );
            assert_eq!(
                service
                    .load_snapshot("strict-window")
                    .unwrap()
                    .unwrap()
                    .project_id,
                None,
                "{case} refusal must not stamp the FK"
            );
            let raw_order: String = other
                .query_row(
                    "SELECT window_order_json FROM projects WHERE project_id = 'strict-target'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(raw_order, invalid_order, "{case} refusal must not rewrite");
            assert_eq!(window_epoch(&paths), epoch_before);
            assert_eq!(
                assignment_trace_count("strict-window", &["strict-target"]),
                traces_before
            );
        }
    }

    #[test]
    fn window_project_assignment_exact_retarget_is_atomic_and_noop_is_quiet() {
        let (_tmp, paths) = temp_paths();
        let projects = crate::ProjectService::new(&paths);
        for project_id in ["retarget-old", "retarget-new", "retarget-third"] {
            projects
                .create(project_id, project_id, ".", crate::NewProject::default(), 1)
                .unwrap();
        }
        let service = svc(&paths);
        let created = service.create_empty_snapshot("retarget-window", 1).unwrap();
        let initial = service
            .assign_project_and_order_if_unchanged(&created, None, "retarget-old", 2)
            .unwrap();
        let ConditionalWindowProjectAssignment::Applied(initial) = initial else {
            panic!("initial owner assignment was refused")
        };
        let proof = service
            .prove_project_assignment("retarget-window", "retarget-old")
            .unwrap();
        let WindowProjectAssignmentProofOutcome::Proven(proof) = proof else {
            panic!("exact owner/order proof was refused")
        };
        assert_eq!(proof.window, initial.window);
        assert_eq!(proof.project, initial.project);
        assert!(matches!(
            service
                .prove_project_assignment("retarget-window", "retarget-new")
                .unwrap(),
            WindowProjectAssignmentProofOutcome::Conflict { .. }
        ));

        let noop_epoch = window_epoch(&paths);
        let noop_traces = assignment_trace_count(
            "retarget-window",
            &["retarget-old", "retarget-new", "retarget-third"],
        );
        let noop = service
            .ensure_project_assignment("retarget-window", "retarget-old", 3)
            .unwrap();
        let ConditionalWindowProjectAssignment::Applied(noop) = noop else {
            panic!("same-owner no-op was refused")
        };
        assert!(!noop.owner_changed && !noop.order_changed);
        assert_eq!(noop.window, initial.window);
        assert_eq!(window_epoch(&paths), noop_epoch);
        assert_eq!(
            assignment_trace_count(
                "retarget-window",
                &["retarget-old", "retarget-new", "retarget-third"],
            ),
            noop_traces
        );

        let before_retarget_epoch = window_epoch(&paths);
        let retargeted = service
            .assign_project_and_order_if_unchanged(&initial.window, None, "retarget-new", 4)
            .unwrap();
        let ConditionalWindowProjectAssignment::Applied(retargeted) = retargeted else {
            panic!("exact retarget was refused")
        };
        assert!(retargeted.owner_changed && retargeted.order_changed);
        assert_eq!(
            retargeted.window.project_id.as_deref(),
            Some("retarget-new")
        );
        assert_eq!(window_epoch(&paths), before_retarget_epoch + 1);
        assert!(projects
            .load("retarget-old")
            .unwrap()
            .unwrap()
            .window_order
            .is_empty());
        assert_eq!(
            projects.load("retarget-new").unwrap().unwrap().window_order,
            vec!["retarget-window"]
        );

        // A legacy writer adds a third project-order owner without advancing the epoch. The exact
        // layout snapshot still matches, so the conflict result proves the strict order predicate.
        let mut other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        other
            .execute(
                "UPDATE projects SET window_order_json = '[\"retarget-window\"]' \
                 WHERE project_id = 'retarget-third'",
                [],
            )
            .unwrap();
        let conflict_epoch = window_epoch(&paths);
        let conflict = service
            .assign_project_and_order_if_unchanged(&retargeted.window, None, "retarget-old", 5)
            .unwrap();
        assert!(matches!(
            conflict,
            ConditionalWindowProjectAssignment::Conflict {
                current_project_id: Some(ref owner),
                ref ordered_by_project_ids,
            } if owner == "retarget-new"
                && ordered_by_project_ids
                    == &vec!["retarget-new".to_string(), "retarget-third".to_string()]
        ));
        assert_eq!(window_epoch(&paths), conflict_epoch);

        // Then the independent writer publishes an actual FK/order transfer. The previously exact
        // snapshot is stale and must not overwrite the new owner.
        let tx = other
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE windows SET project_id = 'retarget-third' WHERE window_id = 'retarget-window'",
            [],
        )
        .unwrap();
        tx.execute(
            "UPDATE projects SET window_order_json = '[]' WHERE project_id = 'retarget-new'",
            [],
        )
        .unwrap();
        crate::db::bump_window_mutation_epoch(&tx).unwrap();
        tx.commit().unwrap();
        let final_epoch = window_epoch(&paths);
        assert_eq!(
            service
                .assign_project_and_order_if_unchanged(&retargeted.window, None, "retarget-old", 6,)
                .unwrap(),
            ConditionalWindowProjectAssignment::Changed
        );
        assert_eq!(
            service
                .load_snapshot("retarget-window")
                .unwrap()
                .unwrap()
                .project_id
                .as_deref(),
            Some("retarget-third")
        );
        assert_eq!(window_epoch(&paths), final_epoch);
    }

    #[test]
    fn window_epoch_ignores_non_window_commits_but_conservatively_tracks_other_windows() {
        let (_tmp, paths) = temp_paths();
        let projects = crate::ProjectService::new(&paths);
        projects
            .create(
                "epoch-project",
                "Before",
                ".",
                crate::NewProject::default(),
                1,
            )
            .unwrap();
        let service = svc(&paths);
        service.create_empty("epoch-target", 1).unwrap();
        let before_non_window = service.load_snapshot("epoch-target").unwrap().unwrap();
        let epoch_before = window_epoch(&paths);

        let mut other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        let tx = other
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        tx.execute(
            "UPDATE projects SET name = 'After' WHERE project_id = 'epoch-project'",
            [],
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(window_epoch(&paths), epoch_before);
        assert!(matches!(
            service.delete_if_unchanged(&before_non_window, 2).unwrap(),
            ConditionalWindowDelete::Deleted(_)
        ));

        service.create_empty("epoch-target", 3).unwrap();
        let before_other_window = service.load_snapshot("epoch-target").unwrap().unwrap();
        service.create_empty("epoch-unrelated-window", 4).unwrap();
        assert!(
            matches!(
                service
                    .delete_if_unchanged(&before_other_window, 5)
                    .unwrap(),
                ConditionalWindowDelete::Changed
            ),
            "the no-schema global clock intentionally refuses after any other window mutation"
        );
    }

    #[test]
    fn deletion_receipt_state_detects_same_id_recreation_before_old_cleanup() {
        let (_tmp, paths) = temp_paths();
        let service = svc(&paths);
        let expected = service.create_empty_snapshot("receipt-window", 1).unwrap();
        let receipt = match service.delete_if_unchanged(&expected, 2).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            outcome => panic!("expected delete, got {outcome:?}"),
        };
        assert_eq!(
            service.deletion_receipt_state(&receipt).unwrap(),
            WindowDeletionReceiptState::CurrentAndAbsent
        );
        service.create_empty("receipt-window", 3).unwrap();
        assert_eq!(
            service.deletion_receipt_state(&receipt).unwrap(),
            WindowDeletionReceiptState::Superseded
        );
    }

    #[test]
    fn exhausted_window_epoch_rolls_back_layout_write_without_wrap() {
        let (_tmp, paths) = temp_paths();
        crate::ProjectService::new(&paths)
            .create(
                "epoch-max-project",
                "Max",
                ".",
                crate::NewProject::default(),
                1,
            )
            .unwrap();
        let service = svc(&paths);
        service.create_empty("epoch-max-window", 1).unwrap();
        {
            let connection = crate::db::conn_for(paths.base()).unwrap();
            let guard = connection.lock().unwrap();
            guard.pragma_update(None, "user_version", i32::MAX).unwrap();
        }
        let before = service.load("epoch-max-window").unwrap().unwrap();
        let error = service
            .rename_window("epoch-max-window", "must roll back", 2)
            .unwrap_err();
        assert!(matches!(
            error,
            WindowLayoutError::Store(StoreError::Db(ref detail))
                if detail.contains("epoch") && detail.contains("exhausted")
        ));
        assert_eq!(service.load("epoch-max-window").unwrap(), Some(before));
        let expected = service.load_snapshot("epoch-max-window").unwrap().unwrap();
        assert!(service
            .assign_project_and_order_if_unchanged(&expected, None, "epoch-max-project", 3,)
            .is_err());
        assert!(service
            .load_snapshot("epoch-max-window")
            .unwrap()
            .unwrap()
            .project_id
            .is_none());
        assert!(crate::ProjectService::new(&paths)
            .load("epoch-max-project")
            .unwrap()
            .unwrap()
            .window_order
            .is_empty());
        assert!(service.create_empty("epoch-max-new-window", 4).is_err());
        assert!(service.load("epoch-max-new-window").unwrap().is_none());
        assert_eq!(window_epoch(&paths), i32::MAX as u32);
    }

    #[test]
    fn created_graph_cleanup_holds_writer_fence_through_child_and_order_delete() {
        use std::sync::{mpsc, Arc, Mutex};
        use std::time::Duration;

        let (_tmp, paths) = temp_paths();
        let project_id = "graph-project";
        let workspace = Workspace {
            workspace_id: "graph-workspace".into(),
            project_id: project_id.into(),
            root: ".".into(),
            policy: crate::WorkspacePolicy::ScratchCwd,
            consent: crate::WorkspaceConsent::default(),
        };
        let session = SessionRecord {
            session_id: "graph-session".into(),
            workspace_id: workspace.workspace_id.clone(),
            kind: crate::SessionKind::Shell,
            launch: crate::LaunchSpec::OptOut,
            cwd_resolved: ".".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        let projects = crate::ProjectService::new(&paths);
        projects
            .create(project_id, "Graph", ".", crate::NewProject::default(), 1)
            .unwrap();
        crate::write_record(
            &paths,
            RecordKind::Workspace,
            &workspace.workspace_id,
            1,
            &workspace,
        )
        .unwrap();
        crate::write_record(
            &paths,
            RecordKind::Session,
            &session.session_id,
            1,
            &session,
        )
        .unwrap();
        let service = svc(&paths);
        let mut expected = service.create_empty_snapshot("graph-window", 1).unwrap();
        expected = service
            .open_tab_if_unchanged(
                &expected,
                "pane-1",
                &session.session_id,
                "Pane",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        let assignment = service
            .assign_project_and_order_if_unchanged(&expected, None, project_id, 3)
            .unwrap();
        let ConditionalWindowProjectAssignment::Applied(_) = assignment else {
            panic!("graph owner assignment was refused")
        };
        projects
            .reorder_windows(
                project_id,
                &["graph-window".into(), "concurrent-sibling".into()],
                4,
            )
            .unwrap();
        // The order seed is itself a compliant ownership mutation and therefore advances the
        // global revision. Capture the exact unchanged layout/owner at that generation so this
        // test reaches the intended pause inside the later cleanup transaction.
        expected = service.load_snapshot("graph-window").unwrap().unwrap();

        let (paused_tx, paused_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let _hook = crate::store_sqlite::install_window_layout_test_hook("graph-window", {
            let release_rx = Arc::clone(&release_rx);
            move |stage, _| {
                if stage == "after-graph-layout-delete-before-child-cleanup" {
                    paused_tx.send(()).unwrap();
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .expect("test releases atomic graph cleanup");
                }
            }
        });
        let cleanup_paths = paths.clone();
        let cleanup_workspace = workspace.clone();
        let cleanup_session = session.clone();
        let cleanup_expected = expected.clone();
        let cleanup = std::thread::spawn(move || {
            svc(&cleanup_paths).cleanup_created_window_graph_if_unchanged(
                &cleanup_expected,
                &cleanup_workspace,
                Some(&cleanup_session),
                &cleanup_session.session_id,
                project_id,
                None,
                true,
                5,
            )
        });
        paused_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("cleanup pauses after its uncommitted layout delete");

        let mut contender = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        contender.pragma_update(None, "foreign_keys", "ON").unwrap();
        contender.pragma_update(None, "busy_timeout", 0).unwrap();
        let error =
            match contender.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate) {
                Ok(transaction) => {
                    transaction.rollback().unwrap();
                    panic!("a recreate writer entered during atomic child cleanup");
                }
                Err(error) => error,
            };
        assert!(matches!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        ));
        release_tx.send(()).unwrap();
        assert!(matches!(
            cleanup.join().unwrap().unwrap(),
            ConditionalWindowDelete::Deleted(_)
        ));

        assert!(service.load("graph-window").unwrap().is_none());
        assert!(crate::load_one::<Workspace>(
            &paths,
            RecordKind::Workspace,
            &workspace.workspace_id
        )
        .unwrap()
        .is_none());
        assert!(
            crate::load_one::<SessionRecord>(&paths, RecordKind::Session, &session.session_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            projects.load(project_id).unwrap().unwrap().window_order,
            ["concurrent-sibling"]
        );
    }

    #[test]
    fn created_graph_cleanup_refuses_an_unexpected_workspace_child() {
        let (_tmp, paths) = temp_paths();
        let project_id = "graph-child-project";
        let workspace = Workspace {
            workspace_id: "graph-child-workspace".into(),
            project_id: project_id.into(),
            root: ".".into(),
            policy: crate::WorkspacePolicy::ScratchCwd,
            consent: crate::WorkspaceConsent::default(),
        };
        let session = SessionRecord {
            session_id: "graph-child-session".into(),
            workspace_id: workspace.workspace_id.clone(),
            kind: crate::SessionKind::Shell,
            launch: crate::LaunchSpec::OptOut,
            cwd_resolved: ".".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        crate::ProjectService::new(&paths)
            .create(project_id, "Graph", ".", crate::NewProject::default(), 1)
            .unwrap();
        crate::write_record(
            &paths,
            RecordKind::Workspace,
            &workspace.workspace_id,
            1,
            &workspace,
        )
        .unwrap();
        crate::write_record(
            &paths,
            RecordKind::Session,
            &session.session_id,
            1,
            &session,
        )
        .unwrap();
        let service = svc(&paths);
        let expected = service
            .create_empty_snapshot("graph-child-window", 1)
            .unwrap();

        let mut sibling = session.clone();
        sibling.session_id = "concurrent-sibling".into();
        crate::write_record(
            &paths,
            RecordKind::Session,
            &sibling.session_id,
            2,
            &sibling,
        )
        .unwrap();
        assert!(matches!(
            service
                .cleanup_created_window_graph_if_unchanged(
                    &expected,
                    &workspace,
                    Some(&session),
                    &session.session_id,
                    project_id,
                    None,
                    false,
                    3,
                )
                .unwrap(),
            ConditionalWindowDelete::Changed
        ));
        assert!(service.load("graph-child-window").unwrap().is_some());
        assert!(
            crate::load_one::<SessionRecord>(&paths, RecordKind::Session, &sibling.session_id)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn created_graph_cleanup_refuses_every_escaped_soft_owner_for_existing_project() {
        for escaped_owner in [
            EscapedFreshGraphOwner::ForeignTab,
            EscapedFreshGraphOwner::TaskCurrent,
            EscapedFreshGraphOwner::TaskHistory,
            EscapedFreshGraphOwner::ProvenanceSession,
            EscapedFreshGraphOwner::ProvenanceWorkspace,
            EscapedFreshGraphOwner::ForeignProjectOrder,
        ] {
            let fixture = created_graph_fixture();
            inject_escaped_fresh_graph_owner(&fixture.paths, escaped_owner);

            assert!(
                matches!(
                    svc(&fixture.paths)
                        .cleanup_created_window_graph_if_unchanged(
                            &fixture.expected,
                            &fixture.workspace,
                            Some(&fixture.session),
                            &fixture.session.session_id,
                            &fixture.project.project_id,
                            None,
                            true,
                            6,
                        )
                        .unwrap(),
                    ConditionalWindowDelete::Changed
                ),
                "legacy/raw {escaped_owner:?} must escape conditional rollback authority"
            );
            assert_eq!(
                svc(&fixture.paths).load_snapshot("fresh-window").unwrap(),
                Some(fixture.expected.clone())
            );
            assert!(crate::load_one::<SessionRecord>(
                &fixture.paths,
                RecordKind::Session,
                &fixture.session.session_id
            )
            .unwrap()
            .is_some());
        }
    }

    #[test]
    fn created_new_project_cleanup_refuses_every_escaped_soft_owner() {
        for escaped_owner in [
            EscapedFreshGraphOwner::ForeignTab,
            EscapedFreshGraphOwner::TaskCurrent,
            EscapedFreshGraphOwner::TaskHistory,
            EscapedFreshGraphOwner::ProvenanceSession,
            EscapedFreshGraphOwner::ProvenanceWorkspace,
            EscapedFreshGraphOwner::ForeignProjectOrder,
        ] {
            let fixture = created_graph_fixture();
            inject_escaped_fresh_graph_owner(&fixture.paths, escaped_owner);

            assert!(
                matches!(
                    svc(&fixture.paths)
                        .cleanup_created_window_graph_if_unchanged(
                            &fixture.expected,
                            &fixture.workspace,
                            Some(&fixture.session),
                            &fixture.session.session_id,
                            &fixture.project.project_id,
                            Some(&fixture.project),
                            true,
                            6,
                        )
                        .unwrap(),
                    ConditionalWindowDelete::Changed
                ),
                "new-project rollback must preserve a graph with {escaped_owner:?}"
            );
            assert!(crate::ProjectService::new(&fixture.paths)
                .load(&fixture.project.project_id)
                .unwrap()
                .is_some());
            assert!(svc(&fixture.paths).load("fresh-window").unwrap().is_some());
        }
    }

    #[test]
    fn created_graph_cleanup_fails_closed_on_any_malformed_project_order() {
        let fixture = created_graph_fixture();
        let connection =
            rusqlite::Connection::open(crate::db::db_path(fixture.paths.base())).unwrap();
        connection
            .execute(
                "UPDATE projects SET window_order_json = '{not-json'
                 WHERE project_id = 'foreign-project'",
                [],
            )
            .unwrap();

        let error = svc(&fixture.paths)
            .cleanup_created_window_graph_if_unchanged(
                &fixture.expected,
                &fixture.workspace,
                Some(&fixture.session),
                &fixture.session.session_id,
                &fixture.project.project_id,
                None,
                true,
                6,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            WindowLayoutError::Store(StoreError::Map(ref detail))
                if detail.contains("window_order") && detail.contains("foreign-project")
        ));
        assert!(svc(&fixture.paths).load("fresh-window").unwrap().is_some());
    }

    #[test]
    fn created_graph_cleanup_epoch_exhaustion_rolls_back_the_complete_graph_without_trace() {
        let mut fixture = created_graph_fixture_with_suffix("epoch-exhaustion");
        fixture.session.last_known_generation = Some("fresh-generation-at-epoch-cap".into());
        crate::write_record(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session.session_id,
            5,
            &fixture.session,
        )
        .unwrap();
        let project_before = crate::ProjectService::new(&fixture.paths)
            .load(&fixture.project.project_id)
            .unwrap()
            .unwrap();
        let trace_count = |kind: &str, id: &str| {
            crate::write_trace::recent()
                .into_iter()
                .filter(|event| event.kind == kind && event.id == id)
                .count()
        };
        let trace_counts_before = [
            (
                "WindowLayout",
                trace_count("WindowLayout", &fixture.expected.layout.window_id),
            ),
            (
                "Session",
                trace_count("Session", &fixture.session.session_id),
            ),
            (
                "Workspace",
                trace_count("Workspace", &fixture.workspace.workspace_id),
            ),
            (
                "Project",
                trace_count("Project", &fixture.project.project_id),
            ),
        ];
        {
            let connection = crate::db::conn_for(fixture.paths.base()).unwrap();
            connection
                .lock()
                .unwrap()
                .pragma_update(None, "user_version", i32::MAX)
                .unwrap();
        }
        // Model a caller that captured this exact unchanged graph at the terminal generation. The
        // cleanup must pass its freshness guard, attempt the one required bump, and roll every
        // preceding delete back when that bump cannot advance.
        fixture.expected.revision.window_mutation_epoch = i32::MAX as u32;

        let error = svc(&fixture.paths)
            .cleanup_created_window_graph_if_unchanged(
                &fixture.expected,
                &fixture.workspace,
                Some(&fixture.session),
                &fixture.session.session_id,
                &fixture.project.project_id,
                None,
                true,
                6,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            WindowLayoutError::Store(StoreError::Db(ref detail))
                if detail.contains("epoch") && detail.contains("exhausted")
        ));
        assert_eq!(window_epoch(&fixture.paths), i32::MAX as u32);
        let window_after = svc(&fixture.paths)
            .load_snapshot(&fixture.expected.layout.window_id)
            .unwrap()
            .unwrap();
        assert_eq!(window_after.layout, fixture.expected.layout);
        assert_eq!(window_after.project_id, fixture.expected.project_id);
        assert!(matches!(
            crate::load_one::<Workspace>(
                &fixture.paths,
                RecordKind::Workspace,
                &fixture.workspace.workspace_id,
            )
            .unwrap(),
            Some(crate::LoadOutcome::Loaded(ref workspace)) if workspace == &fixture.workspace
        ));
        assert!(matches!(
            crate::load_one::<SessionRecord>(
                &fixture.paths,
                RecordKind::Session,
                &fixture.session.session_id,
            )
            .unwrap(),
            Some(crate::LoadOutcome::Loaded(ref session)) if session == &fixture.session
        ));
        assert_eq!(
            crate::ProjectService::new(&fixture.paths)
                .load(&fixture.project.project_id)
                .unwrap(),
            Some(project_before)
        );
        assert_eq!(
            pending_release_count(&fixture.paths),
            0,
            "the exact release row inserted before the failed epoch bump rolls back with the graph"
        );
        for (kind, before) in trace_counts_before {
            let id = match kind {
                "WindowLayout" => &fixture.expected.layout.window_id,
                "Session" => &fixture.session.session_id,
                "Workspace" => &fixture.workspace.workspace_id,
                "Project" => &fixture.project.project_id,
                _ => unreachable!(),
            };
            assert_eq!(trace_count(kind, id), before);
        }
    }

    #[test]
    fn fresh_graph_cleanup_receipt_cannot_restore_a_partial_graph() {
        let mut fixture = created_graph_fixture();
        fixture.session.last_known_generation = Some("fresh-non-restorable-generation".into());
        crate::write_record(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session.session_id,
            5,
            &fixture.session,
        )
        .unwrap();
        let service = svc(&fixture.paths);
        let mut deletion = match service
            .cleanup_created_window_graph_if_unchanged(
                &fixture.expected,
                &fixture.workspace,
                Some(&fixture.session),
                &fixture.session.session_id,
                &fixture.project.project_id,
                None,
                true,
                6,
            )
            .unwrap()
        {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            other => panic!("expected journaled graph cleanup, got {other:?}"),
        };
        let release = deletion
            .take_release_receipt()
            .expect("exact graph Session generation is journaled");
        let compensation = match crate::SessionReleaseService::new(&fixture.paths).attempt_owned(
            release,
            |_| Ok::<(), &'static str>(()),
            |_| crate::CasPublication::NotPublished("offline"),
        ) {
            crate::ReleaseOperationOutcome::UnpublishedFailure { compensation, .. } => compensation,
            other => panic!("expected zero-publication compensation, got {other:?}"),
        };
        assert_eq!(pending_release_count(&fixture.paths), 1);
        assert_eq!(
            service
                .restore_if_absent(&fixture.expected, &deletion, 7)
                .unwrap(),
            ConditionalWindowRestore::Changed,
            "legacy window-only restore must refuse a graph-cleanup receipt"
        );
        assert!(
            service
                .restore_and_cancel_release_if_absent(
                    &fixture.expected,
                    &deletion,
                    &compensation,
                    8,
                )
                .is_err(),
            "capability restore must refuse to restore only the Window after graph cleanup"
        );
        assert_eq!(pending_release_count(&fixture.paths), 1);
        assert!(service
            .load(&fixture.expected.layout.window_id)
            .unwrap()
            .is_none());
        assert!(crate::load_one::<SessionRecord>(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session.session_id,
        )
        .unwrap()
        .is_none());
        assert!(crate::load_one::<Workspace>(
            &fixture.paths,
            RecordKind::Workspace,
            &fixture.workspace.workspace_id,
        )
        .unwrap()
        .is_none());
    }

    #[test]
    fn conditional_restore_is_create_only_and_restores_owner_atomically() {
        let (_tmp, paths) = temp_paths();
        let projects = crate::ProjectService::new(&paths);
        for project_id in ["restore-owner-old", "restore-owner-new"] {
            projects
                .create(project_id, project_id, ".", crate::NewProject::default(), 1)
                .unwrap();
        }
        let window_id = "conditional-restore-window";
        let service = svc(&paths);
        service.create_empty(window_id, 1).unwrap();
        service
            .open_tab(
                window_id,
                "old-tab",
                "old-session",
                "Old",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        crate::store::set_window_project(&paths, window_id, "restore-owner-old").unwrap();
        let deleted = service.load_snapshot(window_id).unwrap().unwrap();
        let deleted_receipt = match service.delete_if_unchanged(&deleted, 3).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            outcome => panic!("expected delete, got {outcome:?}"),
        };

        // The second connection recreates the same id before compensation, with different bytes
        // and a different owner. restore_if_absent must not rewrite either table.
        let mut recreated_layout = deleted.layout.clone();
        recreated_layout.name = Some("concurrent recreation".into());
        recreated_layout.tabs[0].session_id = "new-session".into();
        recreated_layout.tabs[0].title = "New".into();
        recreated_layout.tabs[0].pinned = true;
        let mut recreated_value = serde_json::to_value(&recreated_layout).unwrap();
        recreated_value.as_object_mut().unwrap().insert(
            "project_id".into(),
            serde_json::Value::String("restore-owner-new".into()),
        );
        let mut other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        other.pragma_update(None, "foreign_keys", "ON").unwrap();
        let tx = other
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        crate::store_sqlite::upsert(&tx, RecordKind::WindowLayout, window_id, &recreated_value)
            .unwrap();
        crate::db::bump_window_mutation_epoch(&tx).unwrap();
        tx.commit().unwrap();
        let before_compensation =
            crate::store_sqlite::load_one(&other, RecordKind::WindowLayout, window_id)
                .unwrap()
                .unwrap();

        assert_eq!(
            service
                .restore_if_absent(&deleted, &deleted_receipt, 4)
                .unwrap(),
            ConditionalWindowRestore::AlreadyPresent
        );
        let after_compensation =
            crate::store_sqlite::load_one(&other, RecordKind::WindowLayout, window_id)
                .unwrap()
                .unwrap();
        assert_eq!(
            serde_json::to_vec(&after_compensation).unwrap(),
            serde_json::to_vec(&before_compensation).unwrap(),
            "a concurrent recreation and owner must remain byte-identical"
        );

        // If the id is genuinely still absent, one compensation transaction restores both the
        // exact old layout and its old owner FK.
        let recreated = service.load_snapshot(window_id).unwrap().unwrap();
        let recreated_receipt = match service.delete_if_unchanged(&recreated, 5).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            outcome => panic!("expected delete, got {outcome:?}"),
        };
        assert_eq!(
            service
                .restore_if_absent(&deleted, &deleted_receipt, 6)
                .unwrap(),
            ConditionalWindowRestore::Changed,
            "recreate then delete must not resurrect the older incarnation"
        );
        assert_eq!(
            service
                .restore_if_absent(&recreated, &recreated_receipt, 7)
                .unwrap(),
            ConditionalWindowRestore::Restored
        );
        let restored = service.load_snapshot(window_id).unwrap().unwrap();
        assert_eq!(restored.layout, recreated.layout);
        assert_eq!(restored.project_id, recreated.project_id);
    }

    #[test]
    fn deletion_receipt_rejects_a_caller_mutated_snapshot_before_restore() {
        let (_tmp, paths) = temp_paths();
        let window_id = "restore-proof-window";
        let service = svc(&paths);
        service.create_empty(window_id, 1).unwrap();
        service
            .open_tab(
                window_id,
                "restore-proof-tab",
                "restore-proof-session",
                "Original title",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        let expected = service.load_snapshot(window_id).unwrap().unwrap();
        let receipt = match service.delete_if_unchanged(&expected, 3).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            outcome => panic!("expected delete, got {outcome:?}"),
        };
        let epoch_after_delete = window_epoch(&paths);
        let trace_count = || {
            crate::write_trace::recent()
                .into_iter()
                .filter(|event| event.kind == "WindowLayout" && event.id == window_id)
                .count()
        };
        let trace_count_after_delete = trace_count();

        let mut changed_layout = expected.clone();
        changed_layout.layout.name = Some("caller-mutated bytes".into());
        let layout_error = service
            .restore_if_absent(&changed_layout, &receipt, 4)
            .unwrap_err();
        assert!(matches!(
            layout_error,
            WindowLayoutError::Store(StoreError::Map(ref detail))
                if detail.contains("exact deleted snapshot")
        ));

        let mut changed_owner = expected.clone();
        changed_owner.project_id = Some("caller-mutated-owner".into());
        let owner_error = service
            .restore_if_absent(&changed_owner, &receipt, 5)
            .unwrap_err();
        assert!(matches!(
            owner_error,
            WindowLayoutError::Store(StoreError::Map(ref detail))
                if detail.contains("exact deleted snapshot")
        ));

        assert!(service.load(window_id).unwrap().is_none());
        assert_eq!(window_epoch(&paths), epoch_after_delete);
        assert_eq!(trace_count(), trace_count_after_delete);

        // Refusing a forged input does not consume the receipt: the exact deleted snapshot can
        // still be restored while the target remains absent and the global epoch is unchanged.
        assert_eq!(
            service.restore_if_absent(&expected, &receipt, 6).unwrap(),
            ConditionalWindowRestore::Restored
        );
    }

    #[test]
    fn exact_project_identity_recreation_invalidates_an_old_owner_restore_receipt() {
        let (_tmp, paths) = temp_paths();
        let projects = crate::ProjectService::new(&paths);
        let original_project = projects
            .create(
                "restore-project-aba",
                "Same bytes",
                "/same-root",
                crate::NewProject::default(),
                41,
            )
            .unwrap();
        let service = svc(&paths);
        service.create_empty("restore-project-window", 1).unwrap();
        // Deliberately leave window_order empty: Project identity deletion itself, not a cascade
        // or order-row side effect, must be the generation fence.
        crate::store::set_window_project(
            &paths,
            "restore-project-window",
            &original_project.project_id,
        )
        .unwrap();
        let expected = service
            .load_snapshot("restore-project-window")
            .unwrap()
            .unwrap();
        let receipt = match service.delete_if_unchanged(&expected, 2).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            outcome => panic!("expected conditional delete, got {outcome:?}"),
        };
        let epoch_after_window_delete = window_epoch(&paths);

        let plan = projects.plan_delete(&original_project.project_id).unwrap();
        assert!(plan.window_order_ids.is_empty());
        assert!(plan.window_ids.is_empty());
        assert!(
            projects
                .commit_delete(&plan, &crate::PreResolvedSessionGenerations::new(), 42)
                .unwrap()
                .removed
        );
        assert_eq!(window_epoch(&paths), epoch_after_window_delete + 1);

        let recreated_project = projects
            .create(
                "restore-project-aba",
                "Same bytes",
                "/same-root",
                crate::NewProject::default(),
                41,
            )
            .unwrap();
        assert_eq!(recreated_project, original_project);
        assert_eq!(window_epoch(&paths), epoch_after_window_delete + 1);
        assert_eq!(
            service.restore_if_absent(&expected, &receipt, 3).unwrap(),
            ConditionalWindowRestore::Changed
        );
        assert!(service.load("restore-project-window").unwrap().is_none());
    }

    #[test]
    fn exact_none_generation_session_recreation_invalidates_an_old_window_restore_receipt() {
        let fixture = child_identity_restore_fixture("session-aba");
        assert_eq!(fixture.session.last_known_generation, None);
        assert!(crate::store::delete_record(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session.session_id,
        )
        .unwrap());
        assert_eq!(
            window_epoch(&fixture.paths),
            fixture.epoch_after_window_delete + 1
        );

        let other = rusqlite::Connection::open(crate::db::db_path(fixture.paths.base())).unwrap();
        other.pragma_update(None, "foreign_keys", "ON").unwrap();
        crate::store_sqlite::upsert(
            &other,
            RecordKind::Session,
            &fixture.session.session_id,
            &serde_json::to_value(&fixture.session).unwrap(),
        )
        .unwrap();
        assert_eq!(
            window_epoch(&fixture.paths),
            fixture.epoch_after_window_delete + 1,
            "same-id creation is quiet because the preceding deletion is the ABA fence"
        );
        assert!(matches!(
            crate::load_one::<SessionRecord>(
                &fixture.paths,
                RecordKind::Session,
                &fixture.session.session_id,
            )
            .unwrap(),
            Some(crate::LoadOutcome::Loaded(ref session)) if session == &fixture.session
        ));
        assert_eq!(
            svc(&fixture.paths)
                .restore_if_absent(&fixture.expected, &fixture.receipt, 42)
                .unwrap(),
            ConditionalWindowRestore::Changed
        );
        assert!(svc(&fixture.paths)
            .load(&fixture.expected.layout.window_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn exact_none_generation_workspace_recreation_invalidates_an_old_window_restore_receipt() {
        let fixture = child_identity_restore_fixture("workspace-aba");
        assert_eq!(fixture.session.last_known_generation, None);
        assert!(crate::store::delete_record(
            &fixture.paths,
            RecordKind::Workspace,
            &fixture.workspace.workspace_id,
        )
        .unwrap());
        assert_eq!(
            window_epoch(&fixture.paths),
            fixture.epoch_after_window_delete + 1,
            "one workspace delete fences its cascaded session identity exactly once"
        );

        let other = rusqlite::Connection::open(crate::db::db_path(fixture.paths.base())).unwrap();
        other.pragma_update(None, "foreign_keys", "ON").unwrap();
        crate::store_sqlite::upsert(
            &other,
            RecordKind::Workspace,
            &fixture.workspace.workspace_id,
            &serde_json::to_value(&fixture.workspace).unwrap(),
        )
        .unwrap();
        crate::store_sqlite::upsert(
            &other,
            RecordKind::Session,
            &fixture.session.session_id,
            &serde_json::to_value(&fixture.session).unwrap(),
        )
        .unwrap();
        assert_eq!(
            window_epoch(&fixture.paths),
            fixture.epoch_after_window_delete + 1
        );
        assert!(matches!(
            crate::load_one::<Workspace>(
                &fixture.paths,
                RecordKind::Workspace,
                &fixture.workspace.workspace_id,
            )
            .unwrap(),
            Some(crate::LoadOutcome::Loaded(ref workspace)) if workspace == &fixture.workspace
        ));
        assert!(matches!(
            crate::load_one::<SessionRecord>(
                &fixture.paths,
                RecordKind::Session,
                &fixture.session.session_id,
            )
            .unwrap(),
            Some(crate::LoadOutcome::Loaded(ref session)) if session == &fixture.session
        ));
        assert_eq!(
            svc(&fixture.paths)
                .restore_if_absent(&fixture.expected, &fixture.receipt, 42)
                .unwrap(),
            ConditionalWindowRestore::Changed
        );
        assert!(svc(&fixture.paths)
            .load(&fixture.expected.layout.window_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn failed_full_layout_upsert_rolls_back_and_emits_no_trace() {
        let (_tmp, paths) = temp_paths();
        let window_id = "service-rollback-window";
        let service = svc(&paths);
        service.create_empty(window_id, 1).unwrap();
        service
            .open_tab(
                window_id,
                "tab-a",
                "session-a",
                "A",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        let before = stored(&paths, window_id);
        let epoch_before = window_epoch(&paths);
        let traces_before = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "WindowLayout" && event.id == window_id)
            .collect::<Vec<_>>();

        let error = service
            .mutate_existing(window_id, 3, |layout| {
                layout.name = Some("must-roll-back".into());
                layout.tabs.push(layout.tabs[0].clone());
                Ok(())
            })
            .unwrap_err();
        assert!(matches!(
            error,
            WindowLayoutError::Store(StoreError::Map(_))
        ));
        assert_eq!(stored(&paths, window_id), before);
        assert_eq!(window_epoch(&paths), epoch_before);
        let traces_after = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "WindowLayout" && event.id == window_id)
            .collect::<Vec<_>>();
        assert_eq!(traces_after, traces_before);
    }

    #[test]
    fn immediate_mutation_honors_bounded_busy_timeout_without_partial_write() {
        use std::time::{Duration, Instant};

        let (_tmp, paths) = temp_paths();
        let window_id = "service-busy-window";
        let service = svc(&paths);
        service.create_empty(window_id, 1).unwrap();
        service
            .open_tab(
                window_id,
                "tab-a",
                "session-a",
                "A",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        let before = stored(&paths, window_id);
        let epoch_before = window_epoch(&paths);
        let traces_before = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "WindowLayout" && event.id == window_id)
            .collect::<Vec<_>>();

        let cached = crate::db::conn_for(paths.base()).unwrap();
        cached
            .lock()
            .unwrap()
            .pragma_update(None, "busy_timeout", 25)
            .unwrap();
        let mut blocker = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        blocker.pragma_update(None, "foreign_keys", "ON").unwrap();
        let blocking_tx = blocker
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();

        let started = Instant::now();
        let error = service
            .rename_window(window_id, "must-not-commit", 3)
            .unwrap_err();
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(matches!(error, WindowLayoutError::Store(StoreError::Db(_))));
        blocking_tx.rollback().unwrap();
        assert_eq!(stored(&paths, window_id), before);
        assert_eq!(window_epoch(&paths), epoch_before);
        let traces_after = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "WindowLayout" && event.id == window_id)
            .collect::<Vec<_>>();
        assert_eq!(traces_after, traces_before);
    }

    #[test]
    fn transaction_local_dock_guard_rejects_a_retargeted_stashed_source() {
        let (_tmp, paths) = temp_paths();
        let window_id = "dock-revalidate-window";
        let service = svc(&paths);
        service.create_empty(window_id, 1).unwrap();
        service
            .open_tab(
                window_id,
                "target",
                "target-session",
                "Target",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();
        service
            .open_stashed_tab(
                window_id,
                "source",
                "expected-session",
                "Source",
                false,
                AttentionState::default(),
                3,
            )
            .unwrap();

        let stale = service.load(window_id).unwrap().unwrap();
        assert!(stale.tabs.iter().any(|tab| {
            tab.tab_id == "source" && tab.session_id == "expected-session" && tab.stashed
        }));
        let mut other = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        let tx = other
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let raw = crate::store_sqlite::load_one(&tx, RecordKind::WindowLayout, window_id)
            .unwrap()
            .unwrap();
        let mut retargeted: WindowLayout = serde_json::from_value(raw).unwrap();
        retargeted
            .tabs
            .iter_mut()
            .find(|tab| tab.tab_id == "source")
            .unwrap()
            .session_id = "replacement-session".into();
        crate::store_sqlite::upsert(
            &tx,
            RecordKind::WindowLayout,
            window_id,
            &serde_json::to_value(&retargeted).unwrap(),
        )
        .unwrap();
        tx.commit().unwrap();

        let error = service
            .dock_stashed_tab_at_edge(
                window_id,
                "source",
                "expected-session",
                "target",
                EdgeDir::Right,
                4,
            )
            .unwrap_err();
        assert!(matches!(error, WindowLayoutError::InvalidTabOrder { .. }));
        assert_eq!(stored(&paths, window_id), retargeted);
    }

    #[test]
    fn load_or_create_creates_then_loads() {
        let (_tmp, paths) = temp_paths();
        let created = svc(&paths).load_or_create("w1", 1).unwrap();
        assert!(created.tabs.is_empty());
        // Second call loads the same one (does not error on already-exists).
        let loaded = svc(&paths).load_or_create("w1", 2).unwrap();
        assert_eq!(loaded, created);
    }

    #[test]
    fn replace_empty_overwrites_current_window_with_no_tabs() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t1",
                "s1",
                "one",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();

        let replaced = svc(&paths).replace_empty("w1", 3).unwrap();
        assert_eq!(replaced.window_id, "w1");
        assert!(replaced.tabs.is_empty());
        assert_eq!(svc(&paths).load("w1").unwrap().unwrap(), replaced);
    }

    #[test]
    fn unsafe_window_id_is_rejected_before_write() {
        let (_tmp, paths) = temp_paths();
        for bad in ["../escape", "a/b", "..", "/abs", "x y"] {
            let r = svc(&paths).create_empty(bad, 1);
            assert!(
                matches!(r, Err(WindowLayoutError::Store(StoreError::Id(_)))),
                "create_empty({bad:?}) must be refused, got {r:?}"
            );
        }
        // Nothing escaped the base.
        assert!(!_tmp.path().join("escape").exists());
    }

    #[test]
    fn unsafe_tab_id_does_not_corrupt_layout() {
        // A tab_id is stored INSIDE the layout (it is not a path component), so it is not a path
        // escape; but an open with an existing/duplicate guard still applies. This documents that
        // tab ids are free-form and never reach the filesystem.
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        let layout = svc(&paths)
            .open_tab(
                "w1",
                "tab/with/slashes",
                "s1",
                "t",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        assert_eq!(tab_ids(&layout), vec!["tab/with/slashes"]);
    }

    #[test]
    fn open_tab_appends_and_normalizes_indices() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "b", "sb", "B", true, attn(Attention::None, false), 3)
            .unwrap();
        let layout = svc(&paths)
            .open_tab("w1", "c", "sc", "C", false, attn(Attention::None, false), 4)
            .unwrap();
        assert_eq!(tab_ids(&layout), vec!["a", "b", "c"]);
        assert_eq!(indices(&layout), vec![0, 1, 2]);
    }

    #[test]
    fn duplicate_tab_open_fails_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        let before = stored(&paths, "w1");
        let err = svc(&paths)
            .open_tab(
                "w1",
                "a",
                "sa2",
                "A2",
                true,
                attn(Attention::Error, true),
                3,
            )
            .unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabAlreadyExists { .. }));
        // Byte-identical: the failed open rewrote nothing.
        assert_eq!(stored(&paths, "w1"), before);
    }

    #[test]
    fn close_tab_compacts_indices() {
        let (_tmp, paths) = temp_paths();
        seed_viewport_session(&paths, "sb", Some("generation-b"));
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let layout = svc(&paths).close_tab("w1", "b", 5).unwrap();
        assert_eq!(tab_ids(&layout), vec!["a", "c"]);
        assert_eq!(indices(&layout), vec![0, 1]);
    }

    #[test]
    fn close_returns_the_fresh_removed_tab_after_a_concurrent_retarget() {
        use std::sync::{mpsc, Arc, Mutex};
        use std::time::Duration;

        let (_tmp, paths) = temp_paths();
        let window_id = "close-fresh-removed-tab";
        let service = svc(&paths);
        service.create_empty(window_id, 1).unwrap();
        service
            .open_tab(
                window_id,
                "tab-a",
                "historical-session",
                "A",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();

        let (paused_tx, paused_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let _hook = crate::store_sqlite::install_window_layout_test_hook(window_id, {
            let release_rx = Arc::clone(&release_rx);
            move |stage, _| {
                if stage == "before-window-layout-transaction" {
                    paused_tx.send(()).unwrap();
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .expect("test releases close after the concurrent retarget");
                }
            }
        });

        let close_paths = paths.clone();
        let close = std::thread::spawn(move || {
            svc(&close_paths).close_tab_with_removed(window_id, "tab-a", 4)
        });
        paused_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("close pauses before acquiring its writer transaction");
        retarget_tab_from_second_connection(&paths, window_id, "tab-a", "concurrent-session");
        release_tx.send(()).unwrap();

        let closed = close.join().unwrap().unwrap();
        assert_eq!(closed.removed_tab.tab_id, "tab-a");
        assert_eq!(closed.removed_tab.session_id, "concurrent-session");
        assert!(closed.layout.tabs.is_empty());
        assert!(service.load(window_id).unwrap().unwrap().tabs.is_empty());
    }

    #[test]
    fn close_missing_tab_errors_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        let before = stored(&paths, "w1");
        let err = svc(&paths).close_tab("w1", "nope", 3).unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabNotFound { .. }));
        assert_eq!(stored(&paths, "w1"), before);
    }

    #[test]
    fn rename_pin_attention_update_only_intended_tab_and_preserve_order() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        svc(&paths).rename_tab("w1", "b", "Renamed B", 3).unwrap();
        svc(&paths).set_pinned("w1", "b", true, 4).unwrap();
        let layout = svc(&paths)
            .update_attention("w1", "b", attn(Attention::NeedsInput, true), 5)
            .unwrap();

        assert_eq!(tab_ids(&layout), vec!["a", "b", "c"], "order preserved");
        assert_eq!(indices(&layout), vec![0, 1, 2]);
        let a = &layout.tabs[0];
        let b = &layout.tabs[1];
        let c = &layout.tabs[2];
        assert_eq!(b.title, "Renamed B");
        assert!(b.pinned);
        assert_eq!(b.attention.attention, Attention::NeedsInput);
        assert!(b.attention.unseen);
        // Siblings untouched.
        assert_eq!(a.title, "a");
        assert!(!a.pinned);
        assert_eq!(a.attention.attention, Attention::None);
        assert_eq!(c.title, "c");
        assert!(!c.pinned);
    }

    #[test]
    fn close_deletes_the_tab_row_but_stash_keeps_it() {
        // The DB payoff for panes: closing a pane DELETES its tab row (gone for good); stashing KEEPS the row with
        // stashed=1 (revivable). "Closed things gone, stashed things kept."
        let (_tmp, paths) = temp_paths();
        seed_viewport_session(&paths, "sb", Some("generation-b"));
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        for (id, sess) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            s.open_tab("w1", id, sess, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let row_count = |window: &str| -> i64 {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let conn = arc.lock().unwrap();
            conn.query_row(
                "SELECT COUNT(*) FROM tabs WHERE window_id = ?1",
                [window],
                |r| r.get(0),
            )
            .unwrap()
        };
        let stashed_flag = |tab: &str| -> bool {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let conn = arc.lock().unwrap();
            conn.query_row("SELECT stashed FROM tabs WHERE tab_id = ?1", [tab], |r| {
                r.get::<_, i64>(0)
            })
            .unwrap()
                != 0
        };
        assert_eq!(row_count("w1"), 3);
        // Stash 'a' → its row survives with stashed=1.
        s.stash_pane("w1", "a", 3).unwrap();
        assert_eq!(row_count("w1"), 3, "stash keeps the row");
        assert!(stashed_flag("a"), "stashed pane row has stashed=1");
        // Close 'b' → its row is deleted.
        s.close_tab("w1", "b", 4).unwrap();
        assert_eq!(row_count("w1"), 2, "close deletes the tab row");
        let after = s.load("w1").unwrap().unwrap();
        assert!(
            after.tabs.iter().all(|t| t.tab_id != "b"),
            "closed pane is gone"
        );
        assert!(
            after.tabs.iter().any(|t| t.tab_id == "a" && t.stashed),
            "stashed pane persists"
        );
    }

    #[test]
    fn set_tab_stashed_marks_and_revives_only_intended_tab_preserving_order() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        // Fresh tabs are never stashed.
        let opened = svc(&paths).load("w1").unwrap().unwrap();
        assert!(opened.tabs.iter().all(|t| !t.stashed));

        // Stash "b": flag flips, nothing else moves, sibling tabs stay live.
        let stashed = svc(&paths).set_tab_stashed("w1", "b", true, 3).unwrap();
        assert_eq!(tab_ids(&stashed), vec!["a", "b", "c"], "order preserved");
        assert_eq!(indices(&stashed), vec![0, 1, 2]);
        assert!(stashed.tabs[1].stashed);
        assert!(!stashed.tabs[0].stashed);
        assert!(!stashed.tabs[2].stashed);
        // The session id is preserved so the stashed tab can be relaunched.
        assert_eq!(stashed.tabs[1].session_id, "sb");

        // Revive "b": flag clears.
        let revived = svc(&paths).set_tab_stashed("w1", "b", false, 4).unwrap();
        assert!(!revived.tabs[1].stashed);
        assert_eq!(tab_ids(&revived), vec!["a", "b", "c"]);
    }

    #[test]
    fn set_tab_stashed_missing_tab_errors() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        let err = svc(&paths)
            .set_tab_stashed("w1", "ghost", true, 2)
            .unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabNotFound { .. }));
    }

    #[test]
    fn mutate_missing_tab_errors() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        let err = svc(&paths).rename_tab("w1", "ghost", "x", 2).unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabNotFound { .. }));
    }

    #[test]
    fn retarget_tab_session_changes_only_session_id_and_preserves_everything_else() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        // Give "b" a distinctive title/pinned/attention to prove they survive the retarget.
        svc(&paths).rename_tab("w1", "b", "Renamed B", 3).unwrap();
        svc(&paths).set_pinned("w1", "b", true, 4).unwrap();
        svc(&paths)
            .update_attention("w1", "b", attn(Attention::NeedsInput, true), 5)
            .unwrap();

        let layout = svc(&paths)
            .retarget_tab_session("w1", "b", "sb-new", 6)
            .unwrap();

        assert_eq!(tab_ids(&layout), vec!["a", "b", "c"], "order preserved");
        assert_eq!(indices(&layout), vec![0, 1, 2]);
        let b = &layout.tabs[1];
        assert_eq!(b.session_id, "sb-new", "session retargeted");
        // Everything else preserved.
        assert_eq!(b.title, "Renamed B");
        assert!(b.pinned);
        assert_eq!(b.attention.attention, Attention::NeedsInput);
        assert!(b.attention.unseen);
        // Siblings untouched (including their session ids).
        assert_eq!(layout.tabs[0].session_id, "sa");
        assert_eq!(layout.tabs[2].session_id, "sc");
    }

    #[test]
    fn guarded_retarget_refuses_a_concurrent_unrelated_binding() {
        use std::sync::{mpsc, Arc, Mutex};
        use std::time::Duration;

        let (_tmp, paths) = temp_paths();
        let window_id = "guarded-retarget-race";
        let service = svc(&paths);
        service.create_empty(window_id, 1).unwrap();
        service
            .open_tab(
                window_id,
                "task-tab",
                "historical-session",
                "Task",
                false,
                AttentionState::default(),
                2,
            )
            .unwrap();

        let (paused_tx, paused_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let _hook = crate::store_sqlite::install_window_layout_test_hook(window_id, {
            let release_rx = Arc::clone(&release_rx);
            move |stage, _| {
                if stage == "before-window-layout-transaction" {
                    paused_tx.send(()).unwrap();
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .expect("test releases resume retarget after the concurrent writer");
                }
            }
        });

        let retarget_paths = paths.clone();
        let retarget = std::thread::spawn(move || {
            svc(&retarget_paths).retarget_tab_session_if_current_in(
                window_id,
                "task-tab",
                &["historical-session".to_string()],
                "resumed-session",
                4,
            )
        });
        paused_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("resume retarget pauses before acquiring its writer transaction");
        retarget_tab_from_second_connection(&paths, window_id, "task-tab", "unrelated-session");
        release_tx.send(()).unwrap();

        assert!(matches!(
            retarget.join().unwrap().unwrap_err(),
            WindowLayoutError::WindowLayoutChanged { .. }
        ));
        let final_layout = service.load(window_id).unwrap().unwrap();
        assert_eq!(final_layout.tabs[0].session_id, "unrelated-session");
    }

    #[test]
    fn retarget_missing_window_or_tab_errors_typed_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        // Missing window.
        let err = svc(&paths)
            .retarget_tab_session("nope", "a", "s", 1)
            .unwrap_err();
        assert!(matches!(
            err,
            WindowLayoutError::WindowLayoutNotFound { .. }
        ));

        // Missing tab leaves the layout byte-identical.
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        let before = stored(&paths, "w1");
        let err = svc(&paths)
            .retarget_tab_session("w1", "ghost", "s", 3)
            .unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabNotFound { .. }));
        assert_eq!(stored(&paths, "w1"), before);
    }

    #[test]
    fn reorder_exact_set_succeeds_and_normalizes() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let order = vec!["c".to_string(), "a".to_string(), "b".to_string()];
        let layout = svc(&paths).reorder_tabs("w1", &order, 5).unwrap();
        assert_eq!(tab_ids(&layout), vec!["c", "a", "b"]);
        assert_eq!(indices(&layout), vec![0, 1, 2]);
    }

    #[test]
    fn reorder_missing_unknown_or_duplicate_fails_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let before = stored(&paths, "w1");

        // Wrong length (missing an id).
        let missing = vec!["a".to_string(), "b".to_string()];
        assert!(matches!(
            svc(&paths).reorder_tabs("w1", &missing, 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        // Unknown id (same length).
        let unknown = vec!["a".to_string(), "b".to_string(), "z".to_string()];
        assert!(matches!(
            svc(&paths).reorder_tabs("w1", &unknown, 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        // Duplicate id (same length).
        let dup = vec!["a".to_string(), "a".to_string(), "b".to_string()];
        assert!(matches!(
            svc(&paths).reorder_tabs("w1", &dup, 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));

        assert_eq!(
            stored(&paths, "w1"),
            before,
            "no failed reorder rewrote the layout"
        );
    }

    #[test]
    fn swap_tab_positions_swaps_slots_and_preserves_identity() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        // Give "c" split provenance so we can prove it travels with the tab through a swap.
        svc(&paths)
            .split_tab("w1", "a", "d", "sd", "D", SplitAxis::Right, 2)
            .unwrap();

        let layout = svc(&paths).swap_tab_positions("w1", "a", "c", 5).unwrap();
        // Positions swap; the rest stay put. Indices renormalize to the new vec order.
        assert_eq!(tab_ids(&layout), vec!["c", "b", "a", "d"]);
        assert_eq!(indices(&layout), vec![0, 1, 2, 3]);

        // session_id travels with each tab (a swap moves position, not the running session).
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("a").session_id, "sa");
        assert_eq!(by_id("c").session_id, "sc");
        // split provenance is untouched by a position swap of unrelated tabs.
        assert!(by_id("d").split_from.is_some());
    }

    #[test]
    fn swap_tab_panes_swaps_occupants_and_leaves_topology_fixed() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        // Build: root "a" with child "b" (a|b). Then a separate root "c" with child "d" (c|d).
        svc(&paths)
            .open_tab("w1", "a", "sa", "a", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "b", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "c", "sc", "c", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "c", "d", "sd", "d", SplitAxis::Down, 2)
            .unwrap();
        let before = svc(&paths).require("w1").unwrap();

        // Swap occupants of panes b and c. The pane TOPOLOGY (every split_from) must be byte-identical;
        // only the occupant session/title trades between the two fixed slots.
        let layout = svc(&paths).swap_tab_panes("w1", "b", "c", 5).unwrap();
        let from = |l: &WindowLayout, id: &str| {
            l.tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .split_from
                .clone()
        };
        for id in ["a", "b", "c", "d"] {
            assert_eq!(
                from(&layout, id),
                from(&before, id),
                "topology of {id} must be unchanged by an occupant swap"
            );
        }
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // The sessions traded slots: pane "b" now hosts c's session and vice versa.
        assert_eq!(by_id("b").session_id, "sc");
        assert_eq!(by_id("c").session_id, "sb");
        // The other two panes are untouched.
        assert_eq!(by_id("a").session_id, "sa");
        assert_eq!(by_id("d").session_id, "sd");
    }

    #[test]
    fn swap_tab_panes_parent_child_swaps_occupants() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        // root "a", child "b" split Right (a is outer/parent, b is inner/child).
        svc(&paths)
            .open_tab("w1", "a", "sa", "a", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "b", SplitAxis::Right, 2)
            .unwrap();
        let before = svc(&paths).require("w1").unwrap();

        let layout = svc(&paths).swap_tab_panes("w1", "a", "b", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // Topology fixed: "a" stays root, "b" stays its child; only the occupants trade.
        let from = |l: &WindowLayout, id: &str| {
            l.tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .split_from
                .clone()
        };
        assert_eq!(from(&layout, "a"), from(&before, "a"));
        assert_eq!(from(&layout, "b"), from(&before, "b"));
        assert_eq!(by_id("a").session_id, "sb");
        assert_eq!(by_id("b").session_id, "sa");
    }

    #[test]
    fn swap_tab_panes_is_observable_in_the_three_pane_regression_case() {
        // The exact case the directional arrows hit and `swap_tab_positions` left a no-op:
        // left | (rt / rb). Swapping left <-> rb must MOVE the visible occupant while keeping topology.
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "left",
                "sl",
                "left",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "left", "rt", "srt", "rt", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "rt", "rb", "srb", "rb", SplitAxis::Down, 2)
            .unwrap();
        let before = svc(&paths).require("w1").unwrap();
        let sess = |l: &WindowLayout, id: &str| {
            l.tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .session_id
                .clone()
        };
        let layout = svc(&paths).swap_tab_panes("w1", "left", "rb", 5).unwrap();
        // Observable: the two panes' occupants traded (the old position-swap left this byte-identical).
        assert_ne!(
            sess(&before, "left"),
            sess(&layout, "left"),
            "left pane's occupant must change"
        );
        assert_eq!(sess(&layout, "left"), "srb");
        assert_eq!(sess(&layout, "rb"), "sl");
        // Topology untouched.
        let from = |l: &WindowLayout, id: &str| {
            l.tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .split_from
                .clone()
        };
        for id in ["left", "rt", "rb"] {
            assert_eq!(from(&layout, id), from(&before, id));
        }
    }

    #[test]
    fn canonical_live_replay_matches_ordered_renderer_splits() {
        // Renderer split replay inserts a new pane next to the active source, not at the
        // append/end slot. Shell mutation paths must read records the same way or pane header
        // arrows can swallow/swap the wrong visual slot.
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();

        let layout = svc(&paths).require("w1").unwrap();
        let live = live_tabs_sorted(&layout);
        let model = canonical_model_from_live_tabs(&live).expect("canonical topology");
        assert_eq!(model.layout, CanonicalLayout::ThreeColumns);
        assert_eq!(model.agent_at(SlotId::S0), Some(&"a".to_string()));
        assert_eq!(model.agent_at(SlotId::S1), Some(&"c".to_string()));
        assert_eq!(model.agent_at(SlotId::S2), Some(&"b".to_string()));
    }

    #[test]
    fn repro_four_pane_second_row_swap_keeps_all_panes_in_chain() {
        // 2x2 grid built the way the app does: root tl; tr=split-right(tl); bl=split-down(tl);
        // br=split-down(tr). Chain: tl(root) <- tr(tl,Right), bl(tl,Down), br(tr,Down).
        // Second row = bl, br. Swapping them must keep ALL FOUR reachable from the root.
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "tl",
                "stl",
                "tl",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "tl", "tr", "str", "tr", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "tl", "bl", "sbl", "bl", SplitAxis::Down, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "tr", "br", "sbr", "br", SplitAxis::Down, 2)
            .unwrap();

        let layout = svc(&paths).swap_tab_panes("w1", "bl", "br", 5).unwrap();
        // Reachability: every tab must walk split_from up to the root "tl".
        let reaches_root = |id: &str| {
            let mut cur = id.to_string();
            for _ in 0..layout.tabs.len() + 1 {
                if cur == "tl" {
                    return true;
                }
                match layout
                    .tabs
                    .iter()
                    .find(|t| t.tab_id == cur)
                    .and_then(|t| t.split_from.as_ref())
                {
                    Some(s) => cur = s.tab_id.clone(),
                    None => return cur == "tl",
                }
            }
            false
        };
        for id in ["tl", "tr", "bl", "br"] {
            assert!(
                reaches_root(id),
                "pane {id} dropped out of the root chain after swap"
            );
        }
    }

    #[test]
    fn repro_four_pane_grandparent_swap_keeps_all_panes_in_chain() {
        // Linear chain (split-right, then split-down on the new pane, etc.):
        // tl(root) <- a(tl,Right) <- b(a,Down) <- c(b,Right). Swap a NON-adjacent ancestor/descendant
        // pair (tl <-> b: tl is b's grandparent via a) and an arbitrary pair (a <-> c).
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "tl",
                "stl",
                "tl",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "tl", "a", "sa", "a", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "b", SplitAxis::Down, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "c", SplitAxis::Right, 2)
            .unwrap();

        let reaches_root = |layout: &WindowLayout, id: &str| {
            let mut cur = id.to_string();
            for _ in 0..layout.tabs.len() + 1 {
                if cur == "tl" {
                    return true;
                }
                match layout
                    .tabs
                    .iter()
                    .find(|t| t.tab_id == cur)
                    .and_then(|t| t.split_from.as_ref())
                {
                    Some(s) => cur = s.tab_id.clone(),
                    None => return cur == "tl",
                }
            }
            false
        };

        let layout = svc(&paths).swap_tab_panes("w1", "tl", "b", 5).unwrap();
        for id in ["tl", "a", "b", "c"] {
            assert!(
                reaches_root(&layout, id),
                "pane {id} dropped after grandparent swap tl<->b"
            );
        }
    }

    #[test]
    fn swap_tab_panes_rejects_missing_or_self_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "a", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "b", "sb", "b", false, attn(Attention::None, false), 2)
            .unwrap();
        let before = stored(&paths, "w1");
        match svc(&paths)
            .swap_tab_panes("w1", "a", "ghost", 5)
            .unwrap_err()
        {
            WindowLayoutError::TabNotFound { tab_id, .. } => assert_eq!(tab_id, "ghost"),
            other => panic!("expected TabNotFound, got {other:?}"),
        }
        assert!(matches!(
            svc(&paths).swap_tab_panes("w1", "a", "a", 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "a rejected swap leaves the layout byte-identical"
        );
    }

    #[test]
    fn swap_tab_positions_rejects_missing_or_self_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let before = stored(&paths, "w1");

        // Unknown tab id -> TabNotFound naming the missing id.
        match svc(&paths)
            .swap_tab_positions("w1", "a", "ghost", 5)
            .unwrap_err()
        {
            WindowLayoutError::TabNotFound { tab_id, .. } => assert_eq!(tab_id, "ghost"),
            other => panic!("expected TabNotFound for the missing target, got {other:?}"),
        }
        // Swapping a tab with itself -> InvalidTabOrder.
        assert!(matches!(
            svc(&paths)
                .swap_tab_positions("w1", "a", "a", 5)
                .unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));

        assert_eq!(
            stored(&paths, "w1"),
            before,
            "no failed swap rewrote the layout"
        );
    }

    #[test]
    fn swallow_split_named_by_child_dissolves_divider_keeping_both_sessions() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // Split "a" -> child "b". The frame is parent "a" + child "b".
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();

        // Swallow naming the CHILD: the child reclaims the full frame; its split binding is gone.
        let layout = svc(&paths).swallow_split("w1", "b", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("b").split_from, None, "the divider is dissolved");
        // Neither session is killed; both tabs remain with their sessions and labels.
        assert_eq!(tab_ids(&layout), vec!["a", "b"]);
        assert_eq!(by_id("a").session_id, "sa");
        assert_eq!(by_id("b").session_id, "sb");
        assert_eq!(by_id("a").split_from, None);
    }

    #[test]
    fn swallow_split_named_by_parent_dissolves_the_child_binding() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();

        // Swallow naming the PARENT "a": the same frame dissolves (the child "b" loses split_from).
        let layout = svc(&paths).swallow_split("w1", "a", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("b").split_from, None, "the divider is dissolved");
        assert_eq!(tab_ids(&layout), vec!["a", "b"]);
        assert_eq!(by_id("a").session_id, "sa");
        assert_eq!(by_id("b").session_id, "sb");
    }

    #[test]
    fn swallow_split_three_left_main_bottom_reclaims_full_bottom_band() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A | B/C: a is the full-height left pane, b/c are stacked on the right.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();

        // C (bottom-right) swallow LEFT: absorbs A's slice across C's left edge → C becomes the full-width
        // bottom band, A keeps the top-left, B the top-right = (A│B)/C. All three stay alive.
        let layout = svc(&paths)
            .swallow_split_direction("w1", "c", SwallowDir::Left, 5)
            .unwrap();
        let r = |id: &str| {
            let p = layout
                .tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .pane_rect
                .unwrap();
            (p.x, p.y, p.w, p.h)
        };
        assert_eq!(layout.tabs.iter().filter(|t| !t.stashed).count(), 3);
        let c = r("c");
        assert_eq!(
            (c.0, c.2),
            (0, 1000),
            "C spans the full width along the bottom"
        );
        let a = r("a");
        assert_eq!((a.0, a.1), (0, 0), "A keeps the top-left");
        assert!(r("b").0 > a.0, "B remains to the right of A on the top row");
    }

    #[test]
    fn swallow_split_direction_rejects_wrong_axis_instead_of_guessing() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();
        let before = stored(&paths, "w1");

        assert!(matches!(
            svc(&paths)
                .swallow_split_direction("w1", "c", SwallowDir::Down, 5)
                .unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "wrong-axis directional swallow leaves records untouched"
        );

        // C swallow LEFT absorbs A's slice across C's left edge → C becomes the full-width bottom band.
        let layout = svc(&paths)
            .swallow_split_direction("w1", "c", SwallowDir::Left, 6)
            .unwrap();
        let cr = layout
            .tabs
            .iter()
            .find(|t| t.tab_id == "c")
            .unwrap()
            .pane_rect
            .unwrap();
        assert_eq!(
            (cr.x, cr.w),
            (0, 1000),
            "C now spans the full width along the bottom"
        );
        assert_eq!(layout.tabs.iter().filter(|t| !t.stashed).count(), 3);
    }

    #[test]
    fn swallow_split_three_top_main_bottom_left_becomes_left_main() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A/(B|C): a is full-width top; b/c share the bottom row.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Down, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 2)
            .unwrap();

        // Swallow UP on B: B becomes the full-height left pane, A/C stack to its right.
        let layout = svc(&paths)
            .swallow_split_direction("w1", "b", SwallowDir::Up, 5)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(tab_ids(&layout), vec!["b", "a", "c"]);
        assert_eq!(by_id("b").split_from, None);
        assert_eq!(
            by_id("a").split_from,
            split_from_parent("b", SplitAxis::Right)
        );
        assert_eq!(
            by_id("c").split_from,
            split_from_parent("a", SplitAxis::Down)
        );
    }

    #[test]
    fn swallow_split_three_left_main_top_right_becomes_top_main() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A|(B/C): a is full-height left; b/c stack on the right.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();

        // Swallow LEFT on B: B becomes the full-width top pane, A/C share the bottom row.
        let layout = svc(&paths)
            .swallow_split_direction("w1", "b", SwallowDir::Left, 5)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(tab_ids(&layout), vec!["b", "a", "c"]);
        assert_eq!(by_id("b").split_from, None);
        assert_eq!(
            by_id("a").split_from,
            split_from_parent("b", SplitAxis::Down)
        );
        assert_eq!(
            by_id("c").split_from,
            split_from_parent("a", SplitAxis::Right)
        );
    }

    #[test]
    fn swallow_split_three_bottom_main_top_left_round_trips_to_left_main() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // (A|B)/C: c is full-width bottom, a/b share the top row.
        svc(&paths)
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();

        // Inverse of the anchor case: swallowing A vertically returns to A | B/C.
        let layout = svc(&paths).swallow_split("w1", "a", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(tab_ids(&layout), vec!["a", "b", "c"]);
        assert_eq!(by_id("a").split_from, None);
        assert_eq!(
            by_id("b").split_from,
            split_from_parent("a", SplitAxis::Right)
        );
        assert_eq!(
            by_id("c").split_from,
            split_from_parent("b", SplitAxis::Down)
        );
    }

    #[test]
    fn swallow_split_rejects_illegal_three_pane_main_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();
        let before = stored(&paths, "w1");

        assert!(matches!(
            svc(&paths).swallow_split("w1", "a", 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "illegal three-pane swallow leaves records untouched"
        );
    }

    /// Build a window whose live panes hold the canonical `layout`'s slot rects, agents a,b,c,d in slot
    /// order.
    fn build_four_pane(paths: &AppPaths, layout: CanonicalLayout) {
        let s = svc(paths);
        s.create_empty("w1", 1).unwrap();
        for (id, sid, title, t) in [
            ("a", "sa", "A", 2),
            ("b", "sb", "B", 3),
            ("c", "sc", "C", 4),
            ("d", "sd", "D", 5),
        ] {
            s.open_tab("w1", id, sid, title, false, attn(Attention::None, false), t)
                .unwrap();
        }
        let rects = slot_rects(layout, &std::collections::BTreeMap::new());
        let agents: Vec<AgentRect> = ["a", "b", "c", "d"]
            .iter()
            .zip(rects)
            .map(|(id, rect)| AgentRect {
                agent: id.to_string(),
                rect,
            })
            .collect();
        s.mutate_existing("w1", 6, |layout| {
            apply_pane_geometry(layout, &agents);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn stash_fill_nested_a_filled_by_bc_pair() {
        // (A│(B/C))/D, stash A: A's right side has B+C whose heights tile A's full height → B and C
        // extend LEFT to fill A. Every survivor tiles, no gap.
        let panes = vec![
            AgentRect {
                agent: "b".into(),
                rect: [0.5, 0.0, 0.5, 0.275],
            },
            AgentRect {
                agent: "c".into(),
                rect: [0.5, 0.275, 0.5, 0.275],
            },
            AgentRect {
                agent: "d".into(),
                rect: [0.0, 0.55, 1.0, 0.45],
            },
        ];
        let removed = [0.0, 0.0, 0.5, 0.55]; // A.
        let out = reduce_rects_by_spec(panes, removed);
        let r = |id: &str| out.iter().find(|p| p.agent == id).unwrap().rect;
        // B and C now span the full top-left+right (x from 0), keeping their own heights.
        assert!(
            (r("b")[0] - 0.0).abs() < 1e-3 && (r("b")[2] - 1.0).abs() < 1e-3,
            "B fills width"
        );
        assert!(
            (r("c")[0] - 0.0).abs() < 1e-3 && (r("c")[2] - 1.0).abs() < 1e-3,
            "C fills width"
        );
        assert_eq!(r("d"), [0.0, 0.55, 1.0, 0.45], "D untouched");
        assert!(
            rects_tile_unit_square(&out),
            "survivors tile with no gap/overlap"
        );
    }

    #[test]
    fn tiling_invariant_accepts_valid_and_rejects_overlap_gap_and_overflow() {
        // A clean 2×2 grid tiles.
        let grid = vec![
            AgentRect {
                agent: "a".into(),
                rect: [0.0, 0.0, 0.5, 0.5],
            },
            AgentRect {
                agent: "b".into(),
                rect: [0.5, 0.0, 0.5, 0.5],
            },
            AgentRect {
                agent: "c".into(),
                rect: [0.0, 0.5, 0.5, 0.5],
            },
            AgentRect {
                agent: "d".into(),
                rect: [0.5, 0.5, 0.5, 0.5],
            },
        ];
        assert!(rects_tile_unit_square(&grid));
        // Overlap: B sits over A.
        let overlap = vec![
            AgentRect {
                agent: "a".into(),
                rect: [0.0, 0.0, 0.6, 1.0],
            },
            AgentRect {
                agent: "b".into(),
                rect: [0.4, 0.0, 0.6, 1.0],
            },
        ];
        assert!(
            !rects_tile_unit_square(&overlap),
            "overlap must be rejected"
        );
        // Gap: only covers the left half.
        let gap = vec![AgentRect {
            agent: "a".into(),
            rect: [0.0, 0.0, 0.5, 1.0],
        }];
        assert!(!rects_tile_unit_square(&gap), "gap must be rejected");
        // Overflow: extends past the right edge.
        let overflow = vec![AgentRect {
            agent: "a".into(),
            rect: [0.0, 0.0, 1.4, 1.0],
        }];
        assert!(
            !rects_tile_unit_square(&overflow),
            "overflow must be rejected"
        );
    }

    /// The user's report: in a nested layout a swallow could leave a pane behind/over another. The
    /// edge-absorb refuses the un-tileable case, and even if it didn't the geometry GUARD would. Here
    /// (A│(B/C))/D, D swallow-up cannot cleanly absorb (it would split A) → rejected, layout unchanged.
    #[test]
    fn nested_swallow_that_would_overlap_is_refused() {
        let panes = vec![
            AgentRect {
                agent: "a".into(),
                rect: [0.0, 0.0, 0.5, 0.55],
            },
            AgentRect {
                agent: "b".into(),
                rect: [0.5, 0.0, 0.5, 0.275],
            },
            AgentRect {
                agent: "c".into(),
                rect: [0.5, 0.275, 0.5, 0.275],
            },
            AgentRect {
                agent: "d".into(),
                rect: [0.0, 0.55, 1.0, 0.45],
            },
        ];
        assert!(
            swallow_rect_local(&panes, "d", SwallowDir::Up).is_none(),
            "a swallow that can't cleanly tile must be refused, not painted as overlap"
        );
    }

    /// The user's headline case: A/(B│C│D), B swallows UP → B spans both rows on the left (its own width),
    /// A keeps only the slice over C and D. Local edge-absorb, NOT a canonical reshape.
    #[test]
    fn swallow_up_absorbs_only_the_overlapping_slice_of_the_neighbor() {
        let (_tmp, paths) = temp_paths();
        build_four_pane(&paths, CanonicalLayout::FourTopMain);
        let after = svc(&paths)
            .swallow_split_direction("w1", "b", SwallowDir::Up, 7)
            .unwrap();
        let r = |id: &str| {
            let t = after.tabs.iter().find(|t| t.tab_id == id).unwrap();
            let p = t.pane_rect.unwrap();
            (p.x, p.y, p.w, p.h)
        };
        assert_eq!(
            r("b"),
            (0, 0, 330, 1000),
            "B is full-height on the left at its own width"
        );
        assert_eq!(
            r("a"),
            (330, 0, 670, 550),
            "A keeps only the part over C and D"
        );
        assert_eq!(r("c"), (330, 550, 340, 450), "C untouched");
        assert_eq!(r("d"), (670, 550, 330, 450), "D untouched");
        // No pane was wholly absorbed (all four still live).
        assert_eq!(after.tabs.iter().filter(|t| !t.stashed).count(), 4);
    }

    /// FourBottomMain (A│B│C)/D: A (top-left corner) swallows DOWN → A absorbs only the slice of the
    /// bottom main D directly below it (A's width); D keeps the rest under B and C. A becomes full-height
    /// on the left; B,C,D all stay alive.
    #[test]
    fn swallow_down_four_bottom_main_corner_absorbs_only_its_slice_of_the_main() {
        let (_tmp, paths) = temp_paths();
        build_four_pane(&paths, CanonicalLayout::FourBottomMain);
        let after = svc(&paths)
            .swallow_split_direction("w1", "a", SwallowDir::Down, 8)
            .expect("edge-absorb swallow succeeds");
        let r = |id: &str| {
            let p = after
                .tabs
                .iter()
                .find(|t| t.tab_id == id)
                .unwrap()
                .pane_rect
                .unwrap();
            (p.x, p.y, p.w, p.h)
        };
        assert_eq!(after.tabs.iter().filter(|t| !t.stashed).count(), 4);
        // A full-height left at its own width (≈333); D keeps the part to the right of A.
        let a = r("a");
        assert_eq!(
            (a.0, a.1, a.3),
            (0, 0, 1000),
            "A spans full height on the left"
        );
        let d = r("d");
        assert_eq!(
            d.0, a.2,
            "D now starts where A's column ends (its left slice was absorbed)"
        );
        assert_eq!(d.0 + d.2, 1000, "D still reaches the right edge");
    }

    #[test]
    fn swallow_split_rejects_missing_or_non_split_tab_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        let before = stored(&paths, "w1");

        // Unknown tab id -> TabNotFound.
        match svc(&paths).swallow_split("w1", "ghost", 5).unwrap_err() {
            WindowLayoutError::TabNotFound { tab_id, .. } => assert_eq!(tab_id, "ghost"),
            other => panic!("expected TabNotFound, got {other:?}"),
        }
        // A tab that is in no split -> InvalidTabOrder (nothing to swallow).
        assert!(matches!(
            svc(&paths).swallow_split("w1", "a", 5).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));

        assert_eq!(
            stored(&paths, "w1"),
            before,
            "no failed swallow rewrote the layout"
        );
    }

    #[test]
    fn dock_tab_beside_repoints_source_split_from_to_target() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        for (id, s) in [("a", "sa"), ("b", "sb")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        // Dock "b" beside "a" on the Right edge -> b becomes a's split child on the vertical axis.
        let layout = svc(&paths)
            .dock_tab_beside("w1", "b", "a", SplitAxis::Right, 5)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        let split = by_id("b").split_from.expect("b now docked beside a");
        assert_eq!(split.tab_id, "a");
        assert_eq!(split.axis, SplitAxis::Right);
        assert_eq!(by_id("a").split_from, None);
    }

    #[test]
    fn dock_tab_beside_retargets_to_chain_tail_when_target_already_has_a_child() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // a -> child b (a now has a split child).
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        // A third standalone pane c to dock onto a's chain.
        svc(&paths)
            .open_tab("w1", "c", "sc", "C", false, attn(Attention::None, false), 2)
            .unwrap();

        // Dock c beside a. a already has child b, so the dock must RETARGET to the chain tail (b),
        // appending c as the next canonical growth step rather than rejecting.
        let layout = svc(&paths)
            .dock_tab_beside("w1", "c", "a", SplitAxis::Right, 5)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        let c_split = by_id("c").split_from.expect("c is docked");
        assert_eq!(
            c_split.tab_id, "b",
            "c appends to the chain tail (b), not a (which is full)"
        );
        // b's binding to a is untouched; the chain is a -> b -> c.
        assert_eq!(by_id("b").split_from.unwrap().tab_id, "a");
    }

    #[test]
    fn dock_tab_beside_rejects_a_dock_into_the_sources_own_subtree() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // a -> child b: b's parent is a.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        let before = stored(&paths, "w1");

        // Docking a (the parent) onto b (its own child) would loop the chain -> reject, no rewrite.
        assert!(matches!(
            svc(&paths)
                .dock_tab_beside("w1", "a", "b", SplitAxis::Right, 5)
                .unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "a rejected dock left the layout untouched"
        );
    }

    #[test]
    fn dock_tab_beside_rejects_docking_a_tab_beside_itself() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        assert!(matches!(
            svc(&paths)
                .dock_tab_beside("w1", "a", "a", SplitAxis::Right, 5)
                .unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
    }

    #[test]
    fn dock_tab_at_edge_moves_visible_pane_into_requested_edge_layout() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();

        // Move A below C: after removing A, B | C is split at C's bottom edge, yielding
        // B full-height left and C/A stacked on the right.
        let layout = svc(&paths)
            .dock_tab_at_edge("w1", "a", "c", EdgeDir::Bottom, 5)
            .unwrap();
        let live = live_tabs_sorted(&layout);
        let model = canonical_model_from_live_tabs(&live).expect("canonical topology");
        assert_eq!(model.layout, CanonicalLayout::ThreeLeftMain);
        assert_eq!(tab_ids(&layout), vec!["b", "c", "a"]);
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("b").split_from, None);
        assert_eq!(
            by_id("c").split_from,
            split_from_parent("b", SplitAxis::Right)
        );
        assert_eq!(
            by_id("a").split_from,
            split_from_parent("c", SplitAxis::Down)
        );
    }

    #[test]
    fn dock_tab_at_edge_from_four_grid_keeps_three_side_plus_one_main_shape() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "one",
                "s1",
                "One",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "one", "two", "s2", "Two", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "one", "three", "s3", "Three", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "two", "four", "s4", "Four", SplitAxis::Down, 5)
            .unwrap();

        // 2x2: one|two / three|four. Drag pane THREE onto the RIGHT edge of pane TWO (confirmed
        // local-split INSERT). three is removed (four expands to the full-width bottom row), then two's
        // OWN cell splits in half — two keeps its left, three takes the right. Result geometry:
        // one|two|three over a full-width four. The split tree below is one valid decomposition of that
        // grid; three docks directly off two (the local split), four off one (the absorbed bottom).
        let layout = svc(&paths)
            .dock_tab_at_edge("w1", "three", "two", EdgeDir::Right, 6)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("one").split_from, None);
        assert_eq!(
            by_id("two").split_from,
            split_from_parent("one", SplitAxis::Right)
        );
        assert_eq!(
            by_id("three").split_from,
            split_from_parent("two", SplitAxis::Right)
        );
        assert_eq!(
            by_id("four").split_from,
            split_from_parent("one", SplitAxis::Down)
        );
    }

    #[test]
    fn dock_tab_at_edge_from_four_grid_bottom_left_to_top_row_expands_bottom_neighbor() {
        for target in ["one", "two"] {
            let (_tmp, paths) = temp_paths();
            svc(&paths).create_empty("w1", 1).unwrap();
            svc(&paths)
                .open_tab(
                    "w1",
                    "one",
                    "s1",
                    "One",
                    false,
                    attn(Attention::None, false),
                    2,
                )
                .unwrap();
            svc(&paths)
                .split_tab("w1", "one", "two", "s2", "Two", SplitAxis::Right, 3)
                .unwrap();
            svc(&paths)
                .split_tab("w1", "one", "three", "s3", "Three", SplitAxis::Down, 4)
                .unwrap();
            svc(&paths)
                .split_tab("w1", "two", "four", "s4", "Four", SplitAxis::Down, 5)
                .unwrap();

            // Confirmed local-split INSERT: dragging three onto the TOP edge of `target` removes three
            // from its cell (the survivors re-tile), then splits `target`'s OWN cell so three takes the
            // top half. All four panes stay live and the layout stays a valid single-rooted tree.
            let layout = svc(&paths)
                .dock_tab_at_edge("w1", "three", target, EdgeDir::Top, 6)
                .unwrap_or_else(|err| panic!("dock three to {target} top failed: {err}"));
            let live = live_tabs_sorted(&layout);
            assert_eq!(live.len(), 4, "all four panes stay live (target {target})");
            // exactly one root, every non-root splits from another LIVE pane (no orphans).
            let live_ids: std::collections::HashSet<&str> =
                live.iter().map(|t| t.tab_id.as_str()).collect();
            let roots = live.iter().filter(|t| t.split_from.is_none()).count();
            assert_eq!(roots, 1, "exactly one root after dock (target {target})");
            for t in &live {
                if let Some(sf) = &t.split_from {
                    assert!(
                        live_ids.contains(sf.tab_id.as_str()),
                        "pane {} splits from a live pane (target {target})",
                        t.tab_id
                    );
                }
            }
            // three is adjacent to the target it was dropped onto (its parent or the target's parent).
            let three = live.iter().find(|t| t.tab_id == "three").unwrap();
            assert!(
                three
                    .split_from
                    .as_ref()
                    .is_some_and(|sf| sf.tab_id == target)
                    || live.iter().any(|t| {
                        t.tab_id == target
                            && t.split_from.as_ref().is_some_and(|sf| sf.tab_id == "three")
                    }),
                "three docks locally next to {target}"
            );
        }
    }

    #[test]
    fn dock_stashed_tab_at_edge_extends_right_side_stack() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "d", "sd", "D", false, attn(Attention::None, false), 5)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "d", true, 6).unwrap();

        let layout = svc(&paths)
            .dock_tab_at_edge("w1", "d", "c", EdgeDir::Bottom, 7)
            .unwrap();
        let live = live_tabs_sorted(&layout);
        let model = canonical_model_from_live_tabs(&live).expect("canonical topology");
        assert_eq!(model.layout, CanonicalLayout::FourLeftMain);
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(
            tab_ids(&layout),
            vec!["a", "b", "c", "d"],
            "drag/drop revive should honor the drop edge and produce A|B/C/D"
        );
        assert_eq!(by_id("a").split_from, None);
        assert_eq!(
            by_id("b").split_from,
            split_from_parent("a", SplitAxis::Right)
        );
        assert_eq!(
            by_id("c").split_from,
            split_from_parent("b", SplitAxis::Down)
        );
        assert_eq!(
            by_id("d").split_from,
            split_from_parent("c", SplitAxis::Down),
            "D must be below C for the requested side-stack drop"
        );
    }

    /// Regression: swallow must keep working after a drag-drop/stash that routes split_from through
    /// topology_from_rects. The split_from chain there can diverge from the painted rects, and swallow
    /// used to classify the layout from the (wrong) chain → "no legal swallow" → it silently stopped
    /// working until the project was reopened. The rect-based classifier reads the authoritative geometry.
    #[test]
    fn swallow_works_after_a_drag_drop_op() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        s.split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        s.open_tab("w1", "c", "sc", "C", false, attn(Attention::None, false), 4)
            .unwrap();
        s.set_tab_stashed("w1", "c", true, 5).unwrap();
        // Drag-drop C below A — produces (A/C)│B; split_from chain reads c-Down-from-a, b-Right-from-a
        // (which the old chain-classifier mistook for ThreeBottomMain).
        s.dock_tab_at_edge("w1", "c", "a", EdgeDir::Bottom, 6)
            .unwrap();

        // The canonical model must come from the RECTS: (A/C)│B is right-main (B is the full-height side).
        let layout = s.require("w1").unwrap();
        let live = live_tabs_sorted(&layout);
        let model = canonical_model_from_live_tabs(&live).expect("model reconstructs from rects");
        assert_eq!(
            model.layout,
            CanonicalLayout::ThreeRightMain,
            "classified from rects, not the divergent split_from chain"
        );
        // And swallow on a side pane must SUCCEED (it had a legal direction all along).
        s.swallow_split("w1", "c", 7)
            .expect("swallow must work after a drag-drop op");
    }

    /// Drag-revive (from the dashboard) must produce the SAME final shape as a normal pane-to-pane drop
    /// for the same gesture: both end with A over the dropped pane on the left, B full-height right.
    /// (The bug: drag-revive used to run click-revive placement first, giving a different shape.)
    #[test]
    fn drag_revive_matches_normal_drop_shape() {
        type IdRect = (String, (u16, u16, u16, u16));
        let drop_result = |stashed_source: bool| -> Vec<IdRect> {
            let (_tmp, paths) = temp_paths();
            let s = svc(&paths);
            s.create_empty("w1", 1).unwrap();
            s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
                .unwrap();
            s.split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
                .unwrap();
            // The dropped source pane is "src" — live (normal drop) or stashed (drag-revive).
            if stashed_source {
                s.open_tab(
                    "w1",
                    "src",
                    "ss",
                    "S",
                    false,
                    attn(Attention::None, false),
                    4,
                )
                .unwrap();
                s.set_tab_stashed("w1", "src", true, 5).unwrap();
            } else {
                // a live src: split it off B so a normal drop has something to vacate.
                s.split_tab("w1", "b", "src", "ss", "S", SplitAxis::Down, 4)
                    .unwrap();
            }
            let l = s
                .dock_tab_at_edge("w1", "src", "a", EdgeDir::Bottom, 6)
                .unwrap();
            let mut out: Vec<(String, (u16, u16, u16, u16))> = l
                .tabs
                .iter()
                .filter(|t| !t.stashed)
                .map(|t| {
                    let r = t.pane_rect.unwrap();
                    (t.tab_id.clone(), (r.x, r.y, r.w, r.h))
                })
                .collect();
            out.sort();
            out
        };
        // A and the dropped src share A's column (A top, src bottom); B full-height right — identical
        // in both paths for the panes they share (A, B, src).
        let revive = drop_result(true);
        let pick = |v: &[IdRect], id: &str| v.iter().find(|(i, _)| i == id).map(|(_, r)| *r);
        assert_eq!(pick(&revive, "a"), Some((0, 0, 500, 500)), "A top-left");
        assert_eq!(
            pick(&revive, "src"),
            Some((0, 500, 500, 500)),
            "src below A"
        );
        assert_eq!(
            pick(&revive, "b"),
            Some((500, 0, 500, 1000)),
            "B full-height right"
        );
        // A normal drop of a live pane onto A.bottom yields the same A/src/B placement.
        let normal = drop_result(false);
        assert_eq!(pick(&normal, "a"), pick(&revive, "a"), "A identical");
        assert_eq!(pick(&normal, "src"), pick(&revive, "src"), "src identical");
        assert_eq!(pick(&normal, "b"), pick(&revive, "b"), "B identical");
    }

    /// Drag-revive a stashed pane onto A's BOTTOM edge: the source must land BELOW A (A keeps the top
    /// half). Regression for the inverted drop — A was ending up below the new pane. dock_tab_at_edge is
    /// the ONLY operation (the app no longer calls revive_pane first).
    #[test]
    fn drag_revive_onto_bottom_edge_places_source_below_target() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A│B so A is a real column; stash X.
        s.split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        s.open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 4)
            .unwrap();
        s.set_tab_stashed("w1", "x", true, 5).unwrap();

        // Drop X on A's BOTTOM edge (the single drag-revive operation).
        let layout = s
            .dock_tab_at_edge("w1", "x", "a", EdgeDir::Bottom, 6)
            .unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        let a = by_id("a").pane_rect.unwrap();
        let x = by_id("x").pane_rect.unwrap();
        assert!(!by_id("x").stashed, "X is revived (live)");
        // A and X share A's column; A is the TOP half, X the BOTTOM half.
        assert_eq!(a.x, x.x, "A and X in the same column");
        assert_eq!(a.w, x.w);
        assert!(a.y < x.y, "A stays on TOP, X goes BELOW (not inverted)");
        assert_eq!(a.h + x.h, 1000, "A/X split A's height");
    }

    #[test]
    fn stashed_edge_drop_revalidates_the_exact_source_session_before_mutation() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        s.split_tab("w1", "a", "x", "sx", "X", SplitAxis::Right, 3)
            .unwrap();
        let before = s.stash_pane("w1", "x", 4).unwrap();

        let err = s
            .dock_stashed_tab_at_edge("w1", "x", "stale-session", "a", EdgeDir::Bottom, 5)
            .expect_err("stale drag identity grants no dock authority");
        assert!(matches!(err, WindowLayoutError::InvalidTabOrder { .. }));
        assert_eq!(
            s.require("w1").unwrap(),
            before,
            "rejection is mutation-free"
        );
    }

    #[test]
    fn dock_tab_at_edge_from_four_grid_bottom_pane_to_top_row_keeps_four_visible_panes() {
        for (source, target, edge) in [
            ("three", "one", EdgeDir::Left),
            ("three", "one", EdgeDir::Top),
            ("three", "two", EdgeDir::Right),
            ("three", "two", EdgeDir::Top),
            ("four", "one", EdgeDir::Left),
            ("four", "one", EdgeDir::Top),
            ("four", "two", EdgeDir::Right),
            ("four", "two", EdgeDir::Top),
        ] {
            let (_tmp, paths) = temp_paths();
            svc(&paths).create_empty("w1", 1).unwrap();
            svc(&paths)
                .open_tab(
                    "w1",
                    "one",
                    "s1",
                    "One",
                    false,
                    attn(Attention::None, false),
                    2,
                )
                .unwrap();
            svc(&paths)
                .split_tab("w1", "one", "two", "s2", "Two", SplitAxis::Right, 3)
                .unwrap();
            svc(&paths)
                .split_tab("w1", "one", "three", "s3", "Three", SplitAxis::Down, 4)
                .unwrap();
            svc(&paths)
                .split_tab("w1", "two", "four", "s4", "Four", SplitAxis::Down, 5)
                .unwrap();

            // Local-split INSERT must keep ALL FOUR panes live and form a valid single-rooted tree (no
            // orphan, no hidden pane) regardless of which pane/edge is dropped. The exact shape varies by
            // drop; the invariant is "nothing disappears" — the bug this guards against is the dropped
            // pane (or a displaced neighbor) vanishing.
            let layout = svc(&paths)
                .dock_tab_at_edge("w1", source, target, edge, 6)
                .unwrap_or_else(|err| panic!("dock {source} to {target} {edge:?} failed: {err}"));
            let live = live_tabs_sorted(&layout);
            let live_ids: std::collections::HashSet<&str> =
                live.iter().map(|t| t.tab_id.as_str()).collect();
            for id in ["one", "two", "three", "four"] {
                assert!(
                    live_ids.contains(id),
                    "dock {source} to {target} {edge:?} hid pane {id}"
                );
            }
            assert_eq!(
                live.len(),
                4,
                "dock {source} to {target} {edge:?} must keep all panes live"
            );
            let roots = live.iter().filter(|t| t.split_from.is_none()).count();
            assert_eq!(
                roots, 1,
                "dock {source} to {target} {edge:?}: exactly one root"
            );
            for t in &live {
                if let Some(sf) = &t.split_from {
                    assert!(
                        live_ids.contains(sf.tab_id.as_str()),
                        "dock {source} to {target} {edge:?}: {} splits from a live pane",
                        t.tab_id
                    );
                }
            }
        }
    }

    #[test]
    fn close_pane_reparents_children_onto_the_closed_panes_parent() {
        let (_tmp, paths) = temp_paths();
        seed_viewport_session(&paths, "sb", Some("generation-b"));
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // Chain a -> b -> c (`A | B/C`). Closing b lets c expand upward into b's right-column space,
        // so the surviving layout is `A | C`.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();

        let layout = svc(&paths).close_pane("w1", "b", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(
            tab_ids(&layout),
            vec!["a", "c"],
            "b removed, a and c survive"
        );
        let c_split = by_id("c").split_from.expect("c keeps a split parent");
        assert_eq!(
            c_split.tab_id, "a",
            "c expands into b's column and remains beside a"
        );
        assert_eq!(c_split.axis, SplitAxis::Right);
        assert_eq!(by_id("a").split_from, None);
    }

    #[test]
    fn close_pane_detaches_children_to_roots_when_closing_a_root() {
        let (_tmp, paths) = temp_paths();
        seed_viewport_session(&paths, "sa", Some("generation-a"));
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // a is the root; b is its child. Closing the root a must detach b to a root (no parent).
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();

        let layout = svc(&paths).close_pane("w1", "a", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(tab_ids(&layout), vec!["b"], "a removed, b survives");
        assert_eq!(
            by_id("b").split_from,
            None,
            "b detached to a root, not pointing at the vanished a"
        );
    }

    #[test]
    fn close_pane_rejects_unknown_tab_without_rewrite() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        let before = stored(&paths, "w1");
        assert!(matches!(
            svc(&paths).close_pane("w1", "ghost", 5).unwrap_err(),
            WindowLayoutError::TabNotFound { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "a rejected close left the layout untouched"
        );
    }

    #[test]
    fn stash_pane_keeps_the_record_flags_it_and_reparents_children() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // Chain a -> b -> c (`A | B/C`). Stashing b must KEEP b (flagged stashed, session preserved)
        // and let c expand upward into b's right-column space.
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 2)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "b", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(
            tab_ids(&layout),
            vec!["a", "c", "b"],
            "live panes stay first; b is kept as a stashed revive candidate"
        );
        let b = by_id("b");
        assert!(b.stashed, "b is flagged stashed");
        assert_eq!(b.session_id, "sb", "b's session is preserved for revive");
        assert_eq!(
            b.split_from, None,
            "stashed b is hidden from the live split chain"
        );
        let b_stashed_from = b.stashed_from.expect("b keeps revive provenance");
        assert_eq!(b_stashed_from.tab_id, "a");
        assert_eq!(b_stashed_from.axis, SplitAxis::Right);
        assert!(
            !by_id("a").stashed && !by_id("c").stashed,
            "siblings stay live"
        );
        assert_eq!(
            by_id("c").split_from.expect("c keeps a parent").tab_id,
            "a",
            "c expands into b's column and remains beside a"
        );
        assert_eq!(by_id("c").split_from.unwrap().axis, SplitAxis::Right);
    }

    #[test]
    fn revive_pane_restores_stashed_leaf_to_original_live_parent() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths).stash_pane("w1", "b", 4).unwrap();

        let layout = svc(&paths).revive_pane("w1", "b", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        let b = by_id("b");
        assert!(!b.stashed);
        assert_eq!(
            b.session_id, "sb",
            "revive preserves the running-session identity"
        );
        assert_eq!(b.stashed_from, None, "revive consumes saved provenance");
        let split = b.split_from.expect("b restored beside a");
        assert_eq!(split.tab_id, "a");
        assert_eq!(split.axis, SplitAxis::Right);
    }

    #[test]
    fn revive_pane_of_stashed_middle_appends_to_live_parent_chain_tail() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // a -> b -> c. Stashing b re-parents c onto a, so revive must not create a second direct
        // child of a; it appends b at the current chain tail (c).
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths).stash_pane("w1", "b", 5).unwrap();

        let layout = svc(&paths).revive_pane("w1", "b", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert_eq!(by_id("c").split_from.unwrap().tab_id, "a");
        let b_split = by_id("b").split_from.expect("b revived into live chain");
        assert_eq!(
            b_split.tab_id, "a",
            "b revives into the current visible 2-column layout by filling below the first column"
        );
        assert_eq!(b_split.axis, SplitAxis::Down);
    }

    #[test]
    fn revive_pane_falls_back_to_deterministic_growth_when_original_parent_is_gone() {
        let (_tmp, paths) = temp_paths();
        seed_viewport_session(&paths, "sa", Some("generation-a"));
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths).stash_pane("w1", "b", 4).unwrap();
        svc(&paths).close_pane("w1", "a", 5).unwrap();

        // With no live panes left after closing the old parent, revive becomes a root.
        let layout = svc(&paths).revive_pane("w1", "b", 6).unwrap();
        let b = layout.tabs.iter().find(|t| t.tab_id == "b").unwrap();
        assert!(!b.stashed);
        assert_eq!(b.split_from, None);

        // Add a second stashed pane with a missing parent: it revives to the right of the sole live
        // pane, matching the fixed 1 -> 2 growth rule.
        svc(&paths)
            .open_tab("w1", "c", "sc", "C", false, attn(Attention::None, false), 7)
            .unwrap();
        svc(&paths).stash_pane("w1", "c", 8).unwrap();
        let layout = svc(&paths).revive_pane("w1", "c", 9).unwrap();
        let c_split = layout
            .tabs
            .iter()
            .find(|t| t.tab_id == "c")
            .unwrap()
            .split_from
            .clone()
            .expect("c revived beside b");
        assert_eq!(c_split.tab_id, "b");
        assert_eq!(c_split.axis, SplitAxis::Right);
    }

    #[test]
    fn revive_pane_uses_current_visible_topology_for_third_pane() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Down, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();
        svc(&paths).stash_pane("w1", "c", 5).unwrap();
        svc(&paths).stash_pane("w1", "b", 6).unwrap();

        let layout = svc(&paths).revive_pane("w1", "b", 7).unwrap();
        let b = layout.tabs.iter().find(|t| t.tab_id == "b").unwrap();
        assert_eq!(
            b.split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "the second live pane always comes back to the right of the first"
        );

        let layout = svc(&paths).revive_pane("w1", "c", 8).unwrap();
        let c = layout.tabs.iter().find(|t| t.tab_id == "c").unwrap();
        assert_eq!(
            c.split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "with two live columns, the third pane fills below the first column"
        );
    }

    #[test]
    fn repair_live_topology_connects_multiple_live_roots() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "b", "sb", "B", false, attn(Attention::None, false), 3)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "c", "sc", "C", false, attn(Attention::None, false), 4)
            .unwrap();

        let broken = svc(&paths).load("w1").unwrap().unwrap();
        assert!(
            broken
                .tabs
                .iter()
                .filter(|tab| !tab.stashed)
                .all(|tab| tab.split_from.is_none()),
            "regression setup must match old bad records: three green roots"
        );

        // Repair reconnects three orphaned roots into a valid single-rooted tree. With no surviving
        // split geometry to reconstruct, the reviving rule falls back to a uniform chain off the first
        // root (A│B│C) — any valid single-root tree is acceptable here; the invariant is one root + no
        // orphans, which the assertions below pin down.
        let repaired = svc(&paths).repair_live_topology("w1", 5).unwrap();
        let by_id = |id: &str| repaired.tabs.iter().find(|t| t.tab_id == id).unwrap();
        assert_eq!(by_id("a").split_from, None, "exactly one root after repair");
        assert_eq!(
            by_id("b").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            })
        );
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "C reattaches under the single root (uniform fallback chain)"
        );
        assert!(
            repaired.tabs.iter().all(|tab| !tab.stashed),
            "repair must not stash or kill any live pane"
        );
    }

    #[test]
    fn revive_fourth_pane_restores_bottom_row_after_stash_neighbor_expansion() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "d", "sd", "D", SplitAxis::Down, 5)
            .unwrap();
        svc(&paths).stash_pane("w1", "d", 6).unwrap();

        // After stashing D, the live layout is bottom-main (A│B)/C (C is the full-width bottom row).
        // Per the confirmed click-revive spec, reviving D yields the 2×2 grid (A│B)/(C│X): A tl, B tr,
        // C bl, D br. So D lands in the bottom-right corner (below B in this grid decomposition).
        let layout = svc(&paths).revive_pane("w1", "d", 7).unwrap();
        let d = layout.tabs.iter().find(|t| t.tab_id == "d").unwrap();
        assert_eq!(
            d.split_from,
            Some(SplitFrom {
                tab_id: "b".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "revived D is the bottom-right of the (A│B)/(C│D) grid"
        );
    }

    #[test]
    fn revive_fourth_pane_splits_the_single_full_width_row_to_the_right() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Down, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "d", "sd", "D", false, attn(Attention::None, false), 5)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "d", true, 6).unwrap();

        // Source is top-main A/(B│C): A full-width top, B│C bottom row. Per the confirmed click-revive
        // spec, reviving the fourth pane (D) yields the 2×2 grid (A│D)/(B│C): A tl, D tr, B bl, C br.
        let layout = svc(&paths).revive_pane("w1", "d", 7).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // Verify the GEOMETRY is the (A│D)/(B│C) grid via the resulting split tree (one valid
        // decomposition of that grid): A root; B below A; D right of A; C completes the bottom-right.
        assert_eq!(by_id("a").split_from, None);
        assert_eq!(
            by_id("b").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "B is the bottom-left of the grid (below A)"
        );
        assert_eq!(
            by_id("d").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "revived D is the top-right of the grid (right of A)"
        );
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "d".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "C is the bottom-right of the grid (below D in this decomposition)"
        );
    }

    #[test]
    fn stash_from_four_grid_expands_the_full_edge_neighbor() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "d", "sd", "D", SplitAxis::Down, 5)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "b", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert!(by_id("b").stashed);
        assert_eq!(tab_ids(&layout), vec!["a", "c", "d", "b"]);
        assert_eq!(by_id("a").split_from, None);
        assert_eq!(
            by_id("d").split_from,
            Some(SplitFrom {
                tab_id: "c".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "same-height side neighbor a consumes b's top-right space, leaving c|d in the lower row"
        );
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "lower-left neighbor c remains below expanded a"
        );
    }

    #[test]
    fn stash_from_four_grid_bottom_left_expands_bottom_row_neighbor() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "d", "sd", "D", SplitAxis::Down, 5)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "c", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // Reading order (y then x): top row A,B then full-width bottom D; stashed c trails.
        assert_eq!(tab_ids(&layout), vec!["a", "b", "d", "c"]);
        assert!(by_id("c").stashed, "c is flagged stashed for the dashboard");
        assert_eq!(
            by_id("c").split_from,
            None,
            "stashed c must not stay in the live split chain"
        );
        assert!(
            !by_id("a").stashed && !by_id("b").stashed && !by_id("d").stashed,
            "the remaining panes stay live"
        );
        assert_eq!(by_id("a").split_from, None);
        assert_eq!(
            by_id("b").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "top row remains A|B"
        );
        assert_eq!(
            by_id("d").split_from,
            Some(SplitFrom {
                tab_id: "a".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "d expands across the bottom row instead of moving into the upper group"
        );
    }

    /// Three columns A│B│C, revive X → (A/X)│B│C — STAYS three columns, the LEFT column splits into
    /// A over X. Does NOT become a 2×2 grid. (This pins the user's fixed rule for the columnar case.)
    #[test]
    fn click_revive_three_columns_splits_left_column_not_grid() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 5)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "x", true, 6).unwrap();

        let layout = svc(&paths).revive_pane("w1", "x", 7).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // Sequential right-splits make a LOCAL split each time, so the live layout before revive is
        // A(left half) │ B(quarter) │ C(quarter) — not equal thirds. Click-revive splits the LEFT column
        // (A's column) into A over X; B and C remain FULL-HEIGHT columns (the key: NOT a grid).
        let a = by_id("a").pane_rect.unwrap();
        let x = by_id("x").pane_rect.unwrap();
        let b = by_id("b").pane_rect.unwrap();
        let c = by_id("c").pane_rect.unwrap();
        // A and X share A's column (same x and width), A on top, X below.
        assert_eq!(a.x, x.x);
        assert_eq!(a.w, x.w);
        assert!(a.y < x.y, "A above X in the left column");
        assert_eq!(a.h + x.h, 1000, "A and X split the column height");
        // B and C stay full-height columns — NOT split into a grid.
        assert_eq!(b.y, 0);
        assert_eq!(b.h, 1000, "B is a full-height column");
        assert_eq!(c.y, 0);
        assert_eq!(c.h, 1000, "C is a full-height column — not a grid");
    }

    // ---- click-revive specification coverage ----

    /// Single pane A, revive X → A│X (new equal-width column on the right).
    #[test]
    fn click_revive_one_pane_adds_right_column() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 3)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "x", true, 4).unwrap();

        let layout = svc(&paths).revive_pane("w1", "x", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // AUTHORITATIVE A│X — equal halves.
        assert_eq!(
            by_id("a").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 0,
                w: 500,
                h: 1000
            })
        );
        assert_eq!(
            by_id("x").pane_rect,
            Some(PaneRect {
                x: 500,
                y: 0,
                w: 500,
                h: 1000
            })
        );
    }

    /// Two columns A│B, revive X → (A/X)│B (the LEFT column splits; X below A).
    #[test]
    fn click_revive_two_columns_splits_left_column() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 4)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "x", true, 5).unwrap();

        let layout = svc(&paths).revive_pane("w1", "x", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // AUTHORITATIVE (A/X)│B: A top-left, X bottom-left, B full-height right.
        assert_eq!(
            by_id("a").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 0,
                w: 500,
                h: 500
            })
        );
        assert_eq!(
            by_id("x").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 500,
                w: 500,
                h: 500
            })
        );
        assert_eq!(
            by_id("b").pane_rect,
            Some(PaneRect {
                x: 500,
                y: 0,
                w: 500,
                h: 1000
            })
        );
    }

    /// Two rows A/B, revive X → (A│X)/B (the TOP row splits; X right of A).
    #[test]
    fn click_revive_two_rows_splits_top_row() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Down, 3)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "x", "sx", "X", false, attn(Attention::None, false), 4)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "x", true, 5).unwrap();

        let layout = svc(&paths).revive_pane("w1", "x", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // AUTHORITATIVE (A│X)/B: A top-left, X top-right, B full-width bottom.
        assert_eq!(
            by_id("a").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 0,
                w: 500,
                h: 500
            })
        );
        assert_eq!(
            by_id("x").pane_rect,
            Some(PaneRect {
                x: 500,
                y: 0,
                w: 500,
                h: 500
            })
        );
        assert_eq!(
            by_id("b").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 500,
                w: 1000,
                h: 500
            })
        );
    }

    // ---- spec-coverage: the cases that diverged before the single-rule rewrite ----

    /// `A│(B/C/D)` (left main + right 3-stack). Stashing the BOTTOM of the right stack (D) leaves the
    /// surviving panes as `A│(B/C)` — A as the left half (root), the B/C stack as the right half, in
    /// reading order A,B,C. Verifies the same-column absorb plus reading-order topology.
    #[test]
    fn stash_bottom_of_right_stack_leaves_left_main_with_pair() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "d", "sd", "D", SplitAxis::Right, 5)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "d", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert!(by_id("d").stashed);
        assert_eq!(
            by_id("d").pane_rect,
            None,
            "stashed pane has no live geometry"
        );
        // AUTHORITATIVE geometry A│(B/C): A left half full-height, B top-right, C bottom-right.
        assert_eq!(
            by_id("a").pane_rect,
            Some(PaneRect {
                x: 0,
                y: 0,
                w: 500,
                h: 1000
            })
        );
        assert_eq!(
            by_id("b").pane_rect,
            Some(PaneRect {
                x: 500,
                y: 0,
                w: 500,
                h: 500
            })
        );
        assert_eq!(
            by_id("c").pane_rect,
            Some(PaneRect {
                x: 500,
                y: 500,
                w: 500,
                h: 500
            })
        );
    }

    /// `A│(B/C/D)` (left main + right column split into a 3-stack). Stashing the full-height main A must
    /// leave the surviving 3-stack as a single full-width column B/C/D — NOT split them into two columns.
    #[test]
    fn stash_full_height_main_leaves_survivor_stack_as_full_width_column() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "c", "d", "sd", "D", SplitAxis::Down, 5)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "a", 6).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        // B/C/D become a single full-width column, each stacked below the previous.
        assert_eq!(by_id("b").split_from, None);
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "b".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "C below B in the full-width column"
        );
        assert_eq!(
            by_id("d").split_from,
            Some(SplitFrom {
                tab_id: "c".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "D below C — the 3-stack stays one full-width column, not split into two"
        );
    }

    #[test]
    fn stash_full_height_column_lets_split_neighbor_column_expand() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "a", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert!(by_id("a").stashed);
        assert_eq!(tab_ids(&layout), vec!["b", "c", "a"]);
        assert_eq!(
            by_id("b").split_from,
            None,
            "top-right pane becomes the full-width top row"
        );
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "b".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            }),
            "bottom-right pane keeps its row relationship and expands with b into the old full column"
        );
    }

    #[test]
    fn stash_full_width_row_lets_split_neighbor_row_expand() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Down, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Right, 4)
            .unwrap();

        let layout = svc(&paths).stash_pane("w1", "a", 5).unwrap();
        let by_id = |id: &str| layout.tabs.iter().find(|t| t.tab_id == id).unwrap().clone();
        assert!(by_id("a").stashed);
        assert_eq!(tab_ids(&layout), vec!["b", "c", "a"]);
        assert_eq!(
            by_id("b").split_from,
            None,
            "bottom-left pane becomes the full-height left column"
        );
        assert_eq!(
            by_id("c").split_from,
            Some(SplitFrom {
                tab_id: "b".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            }),
            "bottom-right pane keeps its column relationship and expands with b into the old full row"
        );
    }

    #[test]
    fn revive_pane_refuses_more_than_four_live_panes() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "b", "c", "sc", "C", SplitAxis::Down, 4)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "c", "d", "sd", "D", SplitAxis::Right, 5)
            .unwrap();
        svc(&paths)
            .open_tab("w1", "e", "se", "E", false, attn(Attention::None, false), 6)
            .unwrap();
        svc(&paths).set_tab_stashed("w1", "e", true, 7).unwrap();
        let before = stored(&paths, "w1");
        assert!(matches!(
            svc(&paths).revive_pane("w1", "e", 8).unwrap_err(),
            WindowLayoutError::InvalidTabOrder { .. }
        ));
        assert_eq!(stored(&paths, "w1"), before);
    }

    #[test]
    fn stash_pane_refuses_the_only_live_pane() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        svc(&paths)
            .split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 2)
            .unwrap();
        // Stash a -> only b live. Stashing b too would empty the window's live layout -> refused.
        svc(&paths).stash_pane("w1", "a", 5).unwrap();
        let before = stored(&paths, "w1");
        assert!(matches!(
            svc(&paths).stash_pane("w1", "b", 6).unwrap_err(),
            WindowLayoutError::CannotStashLastPane { .. }
        ));
        assert_eq!(
            stored(&paths, "w1"),
            before,
            "a refused last-pane stash left the layout untouched"
        );
    }

    #[test]
    fn stash_pane_rejects_unknown_tab() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        assert!(matches!(
            svc(&paths).stash_pane("w1", "ghost", 5).unwrap_err(),
            WindowLayoutError::TabNotFound { .. }
        ));
    }

    #[test]
    fn mutations_on_missing_window_error() {
        let (_tmp, paths) = temp_paths();
        let err = svc(&paths)
            .open_tab(
                "nope",
                "a",
                "s",
                "A",
                false,
                attn(Attention::None, false),
                1,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            WindowLayoutError::WindowLayoutNotFound { .. }
        ));
    }

    // NOTE: the old per-record `future_version_layout_is_left_byte_identical_and_surfaced` test wrote a raw JSON
    // envelope FILE with a future `schema_version` to assert it was surfaced and left byte-identical. That
    // per-record file mechanism is GONE in the SQLite store: future-version is now a DB-LEVEL guard, tested in
    // store::future_version_db_is_refused_on_open.

    #[test]
    fn old_window_record_without_split_metadata_still_loads() {
        // A tab persisted without split metadata must load back with `split_from` defaulting to None. In the
        // file era this was verified by writing a raw envelope whose tab lacked a `split_from` field (serde
        // `#[serde(default)]`); in the SQLite store `split_from` is a nullable JSON column, so we exercise the
        // same invariant behaviorally: open an ordinary (un-split) tab, reload, and assert its split_from is None.
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w-old", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w-old",
                "t0",
                "s0",
                "Legacy",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();

        let layout = svc(&paths)
            .load("w-old")
            .expect("old record loads")
            .expect("record present");
        assert_eq!(tab_ids(&layout), vec!["t0"]);
        assert_eq!(
            layout.tabs[0].split_from, None,
            "a tab with no split metadata loads with split_from None"
        );
    }

    #[test]
    fn split_tab_appends_new_tab_with_split_metadata() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Source",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();

        let layout = svc(&paths)
            .split_tab("w1", "t0", "t1", "s1", "Split", SplitAxis::Right, 3)
            .unwrap();

        // The new tab lands LAST, preserving the source order, with contiguous indices.
        assert_eq!(tab_ids(&layout), vec!["t0", "t1"]);
        assert_eq!(indices(&layout), vec![0, 1]);
        let new_tab = layout.tabs.iter().find(|t| t.tab_id == "t1").unwrap();
        assert_eq!(
            new_tab.split_from,
            Some(SplitFrom {
                tab_id: "t0".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            })
        );
        // The source tab is untouched (no split metadata back-written onto it).
        let src = layout.tabs.iter().find(|t| t.tab_id == "t0").unwrap();
        assert_eq!(src.split_from, None);

        // Persisted: round-trips from disk including the split metadata.
        let reloaded = svc(&paths).load("w1").unwrap().unwrap();
        assert_eq!(reloaded, layout);
    }

    #[test]
    fn split_tab_refuses_missing_source_tab() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        let err = svc(&paths)
            .split_tab("w1", "ghost", "t1", "s1", "Split", SplitAxis::Down, 2)
            .unwrap_err();
        match err {
            WindowLayoutError::TabNotFound { tab_id, .. } => assert_eq!(tab_id, "ghost"),
            other => panic!("expected TabNotFound for the source, got {other:?}"),
        }
        // Nothing was written.
        assert!(svc(&paths).load("w1").unwrap().unwrap().tabs.is_empty());
    }

    #[test]
    fn set_split_ratio_persists_only_the_dragged_child_and_round_trips() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Source",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "t0", "t1", "s1", "Split", SplitAxis::Right, 3)
            .unwrap();

        let layout = svc(&paths).set_split_ratio("w1", "t1", 333, 4).unwrap();

        // ONLY the dragged child carries the persisted per-mille ratio; the source tab is untouched.
        let child = layout.tabs.iter().find(|t| t.tab_id == "t1").unwrap();
        assert_eq!(
            child.split_from,
            Some(SplitFrom {
                tab_id: "t0".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: Some(333),
            })
        );
        let src = layout.tabs.iter().find(|t| t.tab_id == "t0").unwrap();
        assert_eq!(src.split_from, None);

        // Persisted: the ratio survives a reload from disk.
        let reloaded = svc(&paths).load("w1").unwrap().unwrap();
        assert_eq!(reloaded, layout);
    }

    #[test]
    fn set_split_ratio_clamps_above_one_thousand_and_no_ops_on_a_non_split_tab() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Plain",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "t0", "t1", "s1", "Split", SplitAxis::Down, 3)
            .unwrap();

        // Over-range input clamps to 1000 on the child.
        let layout = svc(&paths).set_split_ratio("w1", "t1", 5000, 4).unwrap();
        let child = layout.tabs.iter().find(|t| t.tab_id == "t1").unwrap();
        assert_eq!(
            child.split_from.as_ref().unwrap().ratio_per_mille,
            Some(1000)
        );

        // A plain (non-split) tab has no divider to persist: the call succeeds but leaves it `None`.
        let layout = svc(&paths).set_split_ratio("w1", "t0", 600, 5).unwrap();
        let src = layout.tabs.iter().find(|t| t.tab_id == "t0").unwrap();
        assert_eq!(src.split_from, None);

        // An unknown tab id is a typed error.
        let err = svc(&paths)
            .set_split_ratio("w1", "ghost", 500, 6)
            .unwrap_err();
        assert!(matches!(err, WindowLayoutError::TabNotFound { tab_id, .. } if tab_id == "ghost"));
    }

    #[test]
    fn set_pane_rects_writes_verbatim_ignores_unknown_and_round_trips() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Source",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "t0", "t1", "s1", "Split", SplitAxis::Right, 3)
            .unwrap();

        // Move the shared vertical edge to 40%: left pane 0..400, right pane 400..1000.
        let left = PaneRect {
            x: 0,
            y: 0,
            w: 400,
            h: 1000,
        };
        let right = PaneRect {
            x: 400,
            y: 0,
            w: 600,
            h: 1000,
        };
        let layout = svc(&paths)
            .set_pane_rects(
                "w1",
                &[
                    ("t0".into(), left),
                    ("t1".into(), right),
                    // An unknown id is silently ignored (no error, no resurrection).
                    ("ghost".into(), left),
                ],
                4,
            )
            .unwrap();

        assert_eq!(
            layout
                .tabs
                .iter()
                .find(|t| t.tab_id == "t0")
                .unwrap()
                .pane_rect,
            Some(left)
        );
        assert_eq!(
            layout
                .tabs
                .iter()
                .find(|t| t.tab_id == "t1")
                .unwrap()
                .pane_rect,
            Some(right)
        );
        assert!(!layout.tabs.iter().any(|t| t.tab_id == "ghost"));

        // Persisted: the verbatim rects survive a reload from disk.
        let reloaded = svc(&paths).load("w1").unwrap().unwrap();
        assert_eq!(reloaded, layout);

        // A missing window is a typed error.
        let err = svc(&paths)
            .set_pane_rects("nope", &[("t0".into(), left)], 5)
            .unwrap_err();
        assert!(
            matches!(err, WindowLayoutError::WindowLayoutNotFound { window_id } if window_id == "nope")
        );
    }

    #[test]
    fn old_split_record_without_ratio_field_loads_and_defaults_to_none() {
        // A V-current record JSON whose `split_from` predates the ratio field must still load, with
        // the missing field defaulting to `None` (an even split for the renderer).
        let json = r#"{"tab_id":"t1","session_id":"s1","index":0,"title":"Split","pinned":false,"attention":{"attention":"none","unseen":false,"since_ms":0,"source":"process"},"split_from":{"tab_id":"t0","axis":"right"}}"#;
        let rec: TabRecord = serde_json::from_str(json).unwrap();
        assert_eq!(
            rec.split_from,
            Some(SplitFrom {
                tab_id: "t0".into(),
                axis: SplitAxis::Right,
                ratio_per_mille: None,
            })
        );
    }

    #[test]
    fn split_tab_refuses_duplicate_new_tab_id() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Source",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        let err = svc(&paths)
            .split_tab("w1", "t0", "t0", "s1", "Split", SplitAxis::Right, 3)
            .unwrap_err();
        match err {
            WindowLayoutError::TabAlreadyExists { tab_id, .. } => assert_eq!(tab_id, "t0"),
            other => panic!("expected TabAlreadyExists, got {other:?}"),
        }
        // Layout unchanged: still just the source tab, no split metadata.
        let layout = svc(&paths).load("w1").unwrap().unwrap();
        assert_eq!(tab_ids(&layout), vec!["t0"]);
        assert_eq!(layout.tabs[0].split_from, None);
    }

    // NOTE: the old per-record `corrupt_layout_is_quarantined_and_surfaced` test wrote a malformed raw envelope
    // FILE and asserted the store quarantined it (moved to `corrupt/`). That per-file quarantine mechanism is GONE
    // in the SQLite store; a stored row that won't deserialize into the requested type now surfaces as
    // Quarantined, tested in store::row_that_wont_deserialize_is_quarantined_and_excluded.

    #[test]
    fn tab_view_sorts_by_index_and_joins_task_report() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        // Open in one order...
        for (id, s) in [("a", "sa"), ("b", "sb"), ("c", "sc")] {
            svc(&paths)
                .open_tab("w1", id, s, id, false, attn(Attention::None, false), 2)
                .unwrap();
        }
        // ...then reorder so index order differs from insertion order.
        let order = vec!["c".to_string(), "a".to_string(), "b".to_string()];
        svc(&paths).reorder_tabs("w1", &order, 3).unwrap();

        // Task report: a Running task whose current session is tab "a"'s session, exited -> needs
        // attention; nothing for b/c.
        let report = AgentTaskReconcileReport {
            tasks: vec![reconciled(
                "task-a",
                AgentTaskState::Running,
                Some("sa"),
                Some(SessionStatus::Exited),
                false,
                true,
            )],
            ..Default::default()
        };

        let views = svc(&paths).tab_view("w1", &report).unwrap();
        let view_ids: Vec<&str> = views.iter().map(|v| v.tab_id.as_str()).collect();
        assert_eq!(view_ids, vec!["c", "a", "b"], "sorted by index");
        assert_eq!(
            views.iter().map(|v| v.index).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );

        let a = views.iter().find(|v| v.tab_id == "a").unwrap();
        assert_eq!(a.agent_task_id.as_deref(), Some("task-a"));
        assert_eq!(a.agent_task_state, Some(AgentTaskState::Running));
        assert_eq!(a.session_status, Some(SessionStatus::Exited));
        assert!(a.needs_attention, "joined task needs attention");

        let b = views.iter().find(|v| v.tab_id == "b").unwrap();
        assert_eq!(b.agent_task_id, None, "no task links to b");
        assert_eq!(b.agent_task_state, None);
        assert_eq!(b.session_status, None);
        assert!(!b.needs_attention);
    }

    #[test]
    fn tab_view_uses_persisted_attention_when_no_task_links() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        // Persisted unseen Error attention, but NO linking task in the report.
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::Error, true), 2)
            .unwrap();
        // A non-unseen signal must NOT flag attention.
        svc(&paths)
            .open_tab(
                "w1",
                "b",
                "sb",
                "B",
                false,
                attn(Attention::Error, false),
                3,
            )
            .unwrap();
        // unseen but None attention must NOT flag.
        svc(&paths)
            .open_tab("w1", "c", "sc", "C", false, attn(Attention::None, true), 4)
            .unwrap();

        let views = svc(&paths)
            .tab_view("w1", &AgentTaskReconcileReport::default())
            .unwrap();
        let a = views.iter().find(|v| v.tab_id == "a").unwrap();
        let b = views.iter().find(|v| v.tab_id == "b").unwrap();
        let c = views.iter().find(|v| v.tab_id == "c").unwrap();
        assert!(
            a.needs_attention,
            "unseen non-None persisted attention flags"
        );
        assert!(!b.needs_attention, "seen attention does not flag");
        assert!(!c.needs_attention, "unseen None does not flag");
    }

    #[test]
    fn tab_view_carries_split_from_for_split_tabs() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab(
                "w1",
                "t0",
                "s0",
                "Source",
                false,
                attn(Attention::None, false),
                2,
            )
            .unwrap();
        svc(&paths)
            .split_tab("w1", "t0", "t1", "s1", "Split", SplitAxis::Down, 3)
            .unwrap();

        let views = svc(&paths)
            .tab_view("w1", &AgentTaskReconcileReport::default())
            .unwrap();
        let src = views.iter().find(|v| v.tab_id == "t0").unwrap();
        let split = views.iter().find(|v| v.tab_id == "t1").unwrap();
        // The ordinary source tab carries no split provenance.
        assert_eq!(src.split_from, None);
        // The split tab's view carries the persisted source id + axis verbatim.
        assert_eq!(
            split.split_from,
            Some(SplitFrom {
                tab_id: "t0".into(),
                axis: SplitAxis::Down,
                ratio_per_mille: None,
            })
        );
        // CRITICAL: tab_view (the path the 750ms periodic strip refresh uses) must carry the
        // AUTHORITATIVE pane_rect — dropping it here made the periodic rebuild repaint from the
        // split_from chain, snapping the layout to another shape ~750ms after every op.
        // split a down -> b: A│B as a row split = A top half, t1 bottom half.
        assert_eq!(
            src.pane_rect,
            Some(PaneRect {
                x: 0,
                y: 0,
                w: 1000,
                h: 500
            })
        );
        assert_eq!(
            split.pane_rect,
            Some(PaneRect {
                x: 0,
                y: 500,
                w: 1000,
                h: 500
            })
        );
    }

    #[test]
    fn tab_view_handles_missing_task_session_linkage_without_error() {
        let (_tmp, paths) = temp_paths();
        svc(&paths).create_empty("w1", 1).unwrap();
        svc(&paths)
            .open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A task whose current_session_id is None (no linkage) and one pointing elsewhere.
        let report = AgentTaskReconcileReport {
            tasks: vec![
                reconciled("t-none", AgentTaskState::Draft, None, None, false, false),
                reconciled(
                    "t-other",
                    AgentTaskState::Running,
                    Some("s-elsewhere"),
                    Some(SessionStatus::Live),
                    false,
                    false,
                ),
            ],
            ..Default::default()
        };
        let views = svc(&paths).tab_view("w1", &report).unwrap();
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].agent_task_id, None);
        assert!(!views[0].needs_attention);
    }

    #[test]
    fn tab_view_on_missing_window_errors() {
        let (_tmp, paths) = temp_paths();
        let err = svc(&paths)
            .tab_view("nope", &AgentTaskReconcileReport::default())
            .unwrap_err();
        assert!(matches!(
            err,
            WindowLayoutError::WindowLayoutNotFound { .. }
        ));
    }

    /// REGRESSION (user report: "no live pane may be hidden by layout math"). Splitting FROM a pane that
    /// isn't in the live set (e.g. a stashed source) used to push the new tab LIVE but with no rect — an
    /// invisible green pane. The split must always operate from a real live pane (the active one) and
    /// every resulting live pane must have a rect that tiles the screen.
    #[test]
    fn split_from_stashed_source_never_leaves_a_live_pane_without_a_rect() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // A│B, then stash A (stash_pane fills A's space with B, so the live set tiles: B = full screen).
        s.split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 3)
            .unwrap();
        s.stash_pane("w1", "a", 4).unwrap();

        // Split FROM the now-stashed pane "a" (a stale/non-live source). The new pane must still land as a
        // real live pane with a rect — never a hidden, rect-less live tab — and the result must tile.
        let l = s
            .split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 5)
            .unwrap();

        // INVARIANT: every live (non-stashed) pane has a rect (nothing hidden).
        let live: Vec<_> = l.tabs.iter().filter(|t| !t.stashed).collect();
        for t in &live {
            assert!(
                t.pane_rect.is_some(),
                "live pane {:?} has no rect — it would be invisible",
                t.tab_id
            );
        }
        // INVARIANT: the live rects perfectly tile the screen (no overlap/gap/overflow).
        let rects: Vec<AgentRect> = live
            .iter()
            .map(|t| AgentRect {
                agent: t.tab_id.clone(),
                rect: t.pane_rect.unwrap().to_unit(),
            })
            .collect();
        assert!(
            rects_tile_unit_square(&rects),
            "live panes must tile the unit square; got {rects:?}"
        );
    }

    /// REGRESSION (user case: "A|B/C|D, drag C to the first row"). In the 2×2 grid (A│B)/(C│D), dragging
    /// the bottom-left pane C up beside A must: land C visibly in the top row, expand D to fill the freed
    /// bottom row, hide nothing, and keep the live rects tiling the window.
    #[test]
    fn drag_c_to_first_row_keeps_all_panes_visible_and_tiling() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab("w1", "a", "sa", "A", false, attn(Attention::None, false), 2)
            .unwrap();
        // Build (A│B)/(C│D): A/C, then A│B (top), then C│D (bottom).
        s.split_tab("w1", "a", "c", "sc", "C", SplitAxis::Down, 3)
            .unwrap();
        s.split_tab("w1", "a", "b", "sb", "B", SplitAxis::Right, 4)
            .unwrap();
        s.split_tab("w1", "c", "d", "sd", "D", SplitAxis::Right, 5)
            .unwrap();

        // Sanity: 4 live panes before the drag.
        let pre = s
            .require("w1")
            .unwrap()
            .tabs
            .iter()
            .filter(|t| !t.stashed)
            .count();
        assert_eq!(pre, 4, "precondition: 4 live panes");

        // Drag C up beside A — i.e. dock C onto A's TOP edge. (Source C is live; D should fill C's freed
        // bottom-left space, then C inserts into A's row.)
        let l = s.dock_tab_at_edge("w1", "c", "a", EdgeDir::Top, 6).unwrap();

        let live: Vec<_> = l.tabs.iter().filter(|t| !t.stashed).collect();
        // Nothing hidden: every live pane has a rect.
        for t in &live {
            assert!(
                t.pane_rect.is_some(),
                "live pane {:?} has no rect after the drag — it would be invisible",
                t.tab_id
            );
        }
        // All four still live (C wasn't lost, D wasn't replaced).
        assert_eq!(
            live.len(),
            4,
            "all four panes stay live after dragging C to the first row"
        );
        // Live rects tile the window — no gap/overlap.
        let rects: Vec<AgentRect> = live
            .iter()
            .map(|t| AgentRect {
                agent: t.tab_id.clone(),
                rect: t.pane_rect.unwrap().to_unit(),
            })
            .collect();
        assert!(
            rects_tile_unit_square(&rects),
            "live panes must tile after the drag; got {rects:?}"
        );
    }

    #[test]
    fn open_tab_dedups_title_within_window() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab(
            "w1",
            "a",
            "sa",
            "shell",
            false,
            attn(Attention::None, false),
            2,
        )
        .unwrap();
        let layout = s
            .open_tab(
                "w1",
                "b",
                "sb",
                "shell",
                false,
                attn(Attention::None, false),
                3,
            )
            .unwrap();
        let titles: Vec<&str> = layout.tabs.iter().map(|t| t.title.as_str()).collect();
        assert_eq!(
            titles,
            vec!["shell", "shell 2"],
            "duplicate pane title auto-numbers"
        );
    }

    #[test]
    fn rename_tab_dedups_against_siblings_but_self_is_noop() {
        let (_tmp, paths) = temp_paths();
        let s = svc(&paths);
        s.create_empty("w1", 1).unwrap();
        s.open_tab(
            "w1",
            "a",
            "sa",
            "Pane 1",
            false,
            attn(Attention::None, false),
            2,
        )
        .unwrap();
        s.open_tab(
            "w1",
            "b",
            "sb",
            "Pane 2",
            false,
            attn(Attention::None, false),
            3,
        )
        .unwrap();
        // rename b to a's title → collides → auto-numbers.
        let layout = s.rename_tab("w1", "b", "Pane 1", 4).unwrap();
        let b = layout.tabs.iter().find(|t| t.tab_id == "b").unwrap();
        assert_eq!(
            b.title, "Pane 2",
            "rename to an existing title bumps the counter"
        );
        // rename a to its OWN current title → no-op (self excluded).
        let layout = s.rename_tab("w1", "a", "Pane 1", 5).unwrap();
        let a = layout.tabs.iter().find(|t| t.tab_id == "a").unwrap();
        assert_eq!(a.title, "Pane 1", "rename-to-self keeps the name");
    }

    fn create_exact_release_window(paths: &AppPaths, suffix: &str) -> WindowLayoutSnapshot {
        let project_id = format!("release-project-{suffix}");
        let workspace_id = format!("release-workspace-{suffix}");
        let session_id = format!("release-session-{suffix}");
        let window_id = format!("release-window-{suffix}");
        crate::ProjectService::new(paths)
            .create(
                &project_id,
                &project_id,
                ".",
                crate::NewProject::default(),
                1,
            )
            .unwrap();
        crate::write_record(
            paths,
            RecordKind::Workspace,
            &workspace_id,
            1,
            &Workspace {
                workspace_id: workspace_id.clone(),
                project_id,
                root: ".".into(),
                policy: crate::WorkspacePolicy::ScratchCwd,
                consent: crate::WorkspaceConsent::default(),
            },
        )
        .unwrap();
        crate::write_record(
            paths,
            RecordKind::Session,
            &session_id,
            1,
            &SessionRecord {
                session_id: session_id.clone(),
                workspace_id,
                kind: crate::SessionKind::Shell,
                launch: crate::LaunchSpec::OptOut,
                cwd_resolved: ".".into(),
                agent_task_id: None,
                created_at_ms: 1,
                last_attached_at_ms: 1,
                last_known_generation: Some(format!("generation-{suffix}")),
                status: SessionStatus::Live,
            },
        )
        .unwrap();
        let service = svc(paths);
        service.create_empty(&window_id, 2).unwrap();
        service
            .open_tab(
                &window_id,
                &format!("release-tab-{suffix}"),
                &session_id,
                "Release",
                false,
                AttentionState::default(),
                3,
            )
            .unwrap();
        service.load_snapshot(&window_id).unwrap().unwrap()
    }

    fn pending_release_count(paths: &AppPaths) -> i64 {
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM pending_session_releases", [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    #[test]
    fn window_not_published_compensation_cancels_journal_and_restores_atomically() {
        let (_tmp, paths) = temp_paths();
        let expected = create_exact_release_window(&paths, "atomic-comp");
        let service = svc(&paths);
        let mut deletion = match service.delete_if_unchanged(&expected, 10).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            other => panic!("expected journaled delete, got {other:?}"),
        };
        assert!(deletion.unresolved_release_session_ids().is_empty());
        let release = deletion
            .take_release_receipt()
            .expect("exact Session generation is journaled");
        let compensation = match crate::SessionReleaseService::new(&paths).attempt_owned(
            release,
            |_| Ok::<(), &'static str>(()),
            |_| crate::CasPublication::NotPublished("offline"),
        ) {
            crate::ReleaseOperationOutcome::UnpublishedFailure { compensation, .. } => compensation,
            other => panic!("expected zero-publication compensation, got {other:?}"),
        };
        assert_eq!(pending_release_count(&paths), 1);
        assert_eq!(
            service.restore_if_absent(&expected, &deletion, 11).unwrap(),
            ConditionalWindowRestore::Changed,
            "legacy restore cannot erase a journal-bound publication decision"
        );
        assert_eq!(
            service
                .restore_and_cancel_release_if_absent(&expected, &deletion, &compensation, 12)
                .unwrap(),
            ConditionalWindowRestore::Restored
        );
        assert_eq!(pending_release_count(&paths), 0);
        let restored = service
            .load_snapshot(&expected.layout.window_id)
            .unwrap()
            .expect("compensated window is restored");
        assert_eq!(restored.layout, expected.layout);
        assert_eq!(restored.project_id, expected.project_id);
        assert!(
            restored.revision.window_mutation_epoch > expected.revision.window_mutation_epoch,
            "restoration is a new durable window mutation, not a resurrection of the old epoch"
        );
    }

    #[test]
    fn exact_session_readoption_revokes_stale_window_compensation() {
        let (_tmp, paths) = temp_paths();
        let expected_window = create_exact_release_window(&paths, "readopted-comp");
        let session_id = expected_window.layout.tabs[0].session_id.clone();
        let service = svc(&paths);
        let mut deletion = match service.delete_if_unchanged(&expected_window, 10).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            other => panic!("expected journaled delete, got {other:?}"),
        };
        let compensation = match crate::SessionReleaseService::new(&paths).attempt_owned(
            deletion.take_release_receipt().unwrap(),
            |_| Ok::<(), &'static str>(()),
            |_| crate::CasPublication::NotPublished("offline"),
        ) {
            crate::ReleaseOperationOutcome::UnpublishedFailure { compensation, .. } => compensation,
            other => panic!("expected zero-publication compensation, got {other:?}"),
        };

        let current =
            match crate::store::load_one::<SessionRecord>(&paths, RecordKind::Session, &session_id)
                .unwrap()
            {
                Some(crate::store::LoadOutcome::Loaded(record)) => record,
                other => panic!("expected exact Session row, got {other:?}"),
            };
        let generation = current.last_known_generation.clone().unwrap();
        let mut readopted = current.clone();
        readopted.last_attached_at_ms = 11;
        assert_eq!(
            crate::store::finalize_session_attach_if_unchanged(
                &paths,
                &current,
                &readopted,
                &generation,
                11,
            )
            .unwrap(),
            crate::store::ConditionalSessionAttachFinalize::Finalized {
                consumed_release_targets: 1,
            }
        );

        assert_eq!(pending_release_count(&paths), 0);
        assert_eq!(
            service
                .restore_and_cancel_release_if_absent(
                    &expected_window,
                    &deletion,
                    &compensation,
                    12,
                )
                .unwrap(),
            ConditionalWindowRestore::Changed,
        );
        assert!(service
            .load(&expected_window.layout.window_id)
            .unwrap()
            .is_none());
    }

    #[test]
    fn wrong_or_reclaimed_window_compensation_never_restores_or_cancels() {
        let (_tmp, paths) = temp_paths();
        let mut expected_a = create_exact_release_window(&paths, "wrong-a");
        let mut expected_b = create_exact_release_window(&paths, "wrong-b");
        let service = svc(&paths);
        expected_a = service
            .load_snapshot(&expected_a.layout.window_id)
            .unwrap()
            .unwrap();
        let mut deletion_a = match service.delete_if_unchanged(&expected_a, 10).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            other => panic!("expected delete A, got {other:?}"),
        };
        expected_b = service
            .load_snapshot(&expected_b.layout.window_id)
            .unwrap()
            .unwrap();
        let mut deletion_b = match service.delete_if_unchanged(&expected_b, 20).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            other => panic!("expected delete B, got {other:?}"),
        };
        let compensation_a = match crate::SessionReleaseService::new(&paths).attempt_owned(
            deletion_a.take_release_receipt().unwrap(),
            |_| Ok::<(), &'static str>(()),
            |_| crate::CasPublication::NotPublished("offline-a"),
        ) {
            crate::ReleaseOperationOutcome::UnpublishedFailure { compensation, .. } => compensation,
            other => panic!("expected compensation A, got {other:?}"),
        };
        let compensation_b = match crate::SessionReleaseService::new(&paths).attempt_owned(
            deletion_b.take_release_receipt().unwrap(),
            |_| Ok::<(), &'static str>(()),
            |_| crate::CasPublication::NotPublished("offline-b"),
        ) {
            crate::ReleaseOperationOutcome::UnpublishedFailure { compensation, .. } => compensation,
            other => panic!("expected compensation B, got {other:?}"),
        };
        assert!(service
            .restore_and_cancel_release_if_absent(&expected_a, &deletion_a, &compensation_b, 21,)
            .is_err());
        assert!(service
            .load(&expected_a.layout.window_id)
            .unwrap()
            .is_none());
        assert_eq!(pending_release_count(&paths), 2);

        let arc = crate::db::conn_for(paths.base()).unwrap();
        arc.lock()
            .unwrap()
            .execute(
                "UPDATE session_release_operations SET lease_until_ms = 0 \
                 WHERE operation_id = (
                   SELECT operation_id FROM pending_session_releases WHERE session_id = ?1
                 )",
                [&expected_a.layout.tabs[0].session_id],
            )
            .unwrap();
        let claim = crate::SessionReleaseService::new(&paths)
            .claim_next()
            .unwrap()
            .expect("expired A operation is reclaimed");
        assert!(matches!(
            service
                .restore_and_cancel_release_if_absent(
                    &expected_a,
                    &deletion_a,
                    &compensation_a,
                    22,
                )
                .unwrap(),
            ConditionalWindowRestore::Changed
        ));
        assert!(service
            .load(&expected_a.layout.window_id)
            .unwrap()
            .is_none());
        assert_eq!(
            crate::SessionReleaseService::new(&paths)
                .list_claimed(&claim)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn prepared_fresh_live_finalize_rebases_receipt_and_retires_release_atomically() {
        let (_tmp, paths) = temp_paths();
        let cwd = TempDir::new().unwrap();
        let project_id = "prepared-fresh-rebase-project";
        create_fixture_project(&paths, project_id);
        let workspace = Workspace {
            workspace_id: "prepared-fresh-rebase-workspace".into(),
            project_id: project_id.into(),
            root: cwd.path().to_string_lossy().into_owned(),
            policy: crate::WorkspacePolicy::ScratchCwd,
            consent: crate::WorkspaceConsent::default(),
        };
        let session = crate::PreparedWorkspace::unsealed(
            workspace.policy,
            workspace.workspace_id.clone(),
            "prepared-fresh-rebase-session",
            cwd.path(),
        )
        .provider_session_spec(
            "claude",
            &[
                "claude".into(),
                "--model".into(),
                "opus".into(),
                "--session-id".into(),
                "30000000-0000-4000-8000-000000000001".into(),
            ],
            &crate::ProcessLaunchEnv,
            80,
            24,
            50,
        )
        .unwrap();
        let created = match svc(&paths)
            .create_prepared_fresh_window_graph(
                &stored_graph_project_snapshot(&paths, project_id),
                PreparedFreshWindowGraphSpec {
                    session,
                    workspace,
                    window_id: "prepared-fresh-rebase-window".into(),
                    window_name: "Prepared".into(),
                    tab_id: "prepared-fresh-rebase-tab".into(),
                    tab_title: "Prepared".into(),
                    tab_pinned: false,
                    tab_attention: AttentionState::default(),
                    touch_project: false,
                },
            )
            .unwrap()
        {
            PreparedFreshWindowGraphCreateOutcome::Created(created) => created,
            other => panic!("expected prepared fresh graph, got {other:?}"),
        };
        let start = created.start;
        assert_ne!(start.unknown().launch, *start.publication_launch());
        let old_receipt = match &start.placement {
            PreparedNewSessionPlacement::FreshWindowGraph { receipt, .. } => receipt.clone(),
            PreparedNewSessionPlacement::ExistingWindow { .. } => {
                panic!("expected fresh-graph placement")
            }
            PreparedNewSessionPlacement::Unplaced { .. } => {
                panic!("expected fresh-graph placement")
            }
        };
        let generation = "prepared-fresh-rebase-generation";
        let target = crate::SessionReleaseTarget::new_recovered(
            start.session_id().to_string(),
            generation,
            crate::SessionRowPolicy::MatchingRowIsProof,
        )
        .unwrap();
        {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let mut conn = arc.lock().unwrap();
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            assert!(
                crate::session_release::insert_pending_releases(&tx, &[target], 51)
                    .unwrap()
                    .is_some()
            );
            tx.commit().unwrap();
        }

        let mut replacement = start.unknown().clone();
        replacement.status = SessionStatus::Live;
        replacement.last_known_generation = Some(generation.into());
        replacement.last_attached_at_ms = 52;
        replacement.launch = start.publication_launch().clone();
        let mut rebased = None;
        let finalized =
            crate::store::finalize_session_attach_if_unchanged_with_workspace_and_guard(
                &paths,
                start.unknown(),
                &replacement,
                Some(start.workspace()),
                generation,
                52,
                |transaction| {
                    if !start.graph_matches_connection(transaction)? {
                        return Ok(false);
                    }
                    rebased = Some(start.rebased_compensation(&replacement)?);
                    Ok(true)
                },
            )
            .unwrap();
        assert!(matches!(
            finalized,
            crate::store::ConditionalSessionAttachFinalize::Finalized {
                consumed_release_targets: 1
            }
        ));
        let connection = crate::db::conn_for(paths.base()).unwrap();
        let guard = connection.lock().unwrap();
        assert_eq!(
            guard
                .query_row("SELECT COUNT(*) FROM pending_session_releases", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            guard
                .query_row(
                    "SELECT COUNT(*) FROM session_release_operations",
                    [],
                    |row| { row.get::<_, i64>(0) }
                )
                .unwrap(),
            0
        );
        drop(guard);

        assert!(matches!(
            svc(&paths)
                .delete_fresh_window_graph_if_unchanged(&old_receipt, 53)
                .unwrap(),
            ConditionalFreshWindowGraphDelete::Changed
        ));
        assert_eq!(
            loaded_record::<SessionRecord>(
                &paths,
                RecordKind::Session,
                "prepared-fresh-rebase-session"
            ),
            Some(replacement)
        );
        assert!(matches!(
            svc(&paths)
                .compensate_prepared_new_session(rebased.unwrap(), 54)
                .unwrap(),
            ConditionalPreparedNewSessionCompensation::FreshWindowGraph(
                ConditionalFreshWindowGraphDelete::Deleted { .. }
            )
        ));
        assert!(loaded_record::<SessionRecord>(
            &paths,
            RecordKind::Session,
            "prepared-fresh-rebase-session"
        )
        .is_none());
    }

    #[test]
    fn later_shared_lifetime_window_receipt_cannot_restore_after_earlier_publication() {
        let (_tmp, paths) = temp_paths();
        let mut expected_a = create_exact_release_window(&paths, "shared-release-a");
        let session_id = expected_a.layout.tabs[0].session_id.clone();
        let service = svc(&paths);
        service.create_empty("shared-release-window-b", 4).unwrap();
        service
            .open_tab(
                "shared-release-window-b",
                "shared-release-tab-b",
                &session_id,
                "Shared B",
                false,
                AttentionState::default(),
                5,
            )
            .unwrap();
        expected_a = service
            .load_snapshot(&expected_a.layout.window_id)
            .unwrap()
            .unwrap();
        let mut deletion_a = match service.delete_if_unchanged(&expected_a, 10).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            other => panic!("expected first shared delete, got {other:?}"),
        };
        let expected_b = service
            .load_snapshot("shared-release-window-b")
            .unwrap()
            .unwrap();
        let mut deletion_b = match service.delete_if_unchanged(&expected_b, 11).unwrap() {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            other => panic!("expected second shared delete, got {other:?}"),
        };

        let compensation_b = match crate::SessionReleaseService::new(&paths).attempt_owned(
            deletion_b.take_release_receipt().unwrap(),
            |_| Ok::<(), &'static str>(()),
            |_| crate::CasPublication::NotPublished("offline-b"),
        ) {
            crate::ReleaseOperationOutcome::UnpublishedFailure { compensation, .. } => compensation,
            other => panic!("expected B zero-publication result, got {other:?}"),
        };
        assert!(matches!(
            crate::SessionReleaseService::new(&paths).attempt_owned::<()>(
                deletion_a.take_release_receipt().unwrap(),
                |_| Ok(()),
                |_| crate::CasPublication::Confirmed,
            ),
            crate::ReleaseOperationOutcome::Complete {
                confirmed: 1,
                retained: 0,
            }
        ));
        assert_eq!(pending_release_count(&paths), 1);
        assert_eq!(
            service
                .restore_if_absent(&expected_b, &deletion_b, 12)
                .unwrap(),
            ConditionalWindowRestore::Changed
        );
        assert!(service
            .restore_and_cancel_release_if_absent(&expected_b, &deletion_b, &compensation_b, 13,)
            .is_err());
        assert_eq!(pending_release_count(&paths), 1);
        assert!(service.load("shared-release-window-b").unwrap().is_none());
    }

    #[test]
    fn failure_after_window_journal_insert_rolls_back_graph_and_journal() {
        let (_tmp, paths) = temp_paths();
        let expected = create_exact_release_window(&paths, "journal-rollback");
        let _failure = crate::store_sqlite::install_window_layout_test_failure(
            expected.layout.window_id.clone(),
            "after-release-journal",
        );
        assert!(svc(&paths).delete_if_unchanged(&expected, 10).is_err());
        assert_eq!(
            svc(&paths)
                .load_snapshot(&expected.layout.window_id)
                .unwrap(),
            Some(expected)
        );
        assert_eq!(pending_release_count(&paths), 0);
    }

    #[test]
    fn tab_and_fresh_graph_cleanup_commit_exact_journal_with_destruction() {
        let (_tmp, paths) = temp_paths();
        let expected = create_exact_release_window(&paths, "tab-close");
        let closed = svc(&paths)
            .close_tab_with_removed(
                &expected.layout.window_id,
                &expected.layout.tabs[0].tab_id,
                10,
            )
            .unwrap();
        assert!(closed.layout.tabs.is_empty());
        assert!(closed.release_receipt.is_some());
        assert!(closed.unresolved_release_session_ids.is_empty());
        assert_eq!(pending_release_count(&paths), 1);

        let project_id = "fresh-journal-project";
        create_fixture_project(&paths, project_id);
        let mut spec = fresh_graph_spec(project_id, "journal-cleanup");
        spec.session.last_known_generation = Some("fresh-journal-generation".into());
        let created = created_graph(
            svc(&paths)
                .create_fresh_window_graph(
                    &stored_graph_project_snapshot(&paths, project_id),
                    spec.clone(),
                    20,
                )
                .unwrap(),
        );
        let outcome = svc(&paths)
            .delete_fresh_window_graph_if_unchanged(&created.receipt, 21)
            .unwrap();
        assert!(matches!(
            outcome,
            ConditionalFreshWindowGraphDelete::Deleted {
                release_receipt: Some(_),
                unresolved_release_session_ids,
            } if unresolved_release_session_ids.is_empty()
        ));
        assert_graph_children_absent(&paths, &spec);
        assert_eq!(pending_release_count(&paths), 2);
    }

    #[test]
    fn pre_resolved_missing_window_session_requires_the_row_to_stay_absent() {
        use std::cell::Cell;

        let (_tmp, paths) = temp_paths();
        let service = svc(&paths);

        let initial = create_exact_release_window(&paths, "missing-row-recreated");
        let session_id = initial.layout.tabs[0].session_id.clone();
        let session =
            match crate::store::load_one::<SessionRecord>(&paths, RecordKind::Session, &session_id)
                .unwrap()
            {
                Some(crate::LoadOutcome::Loaded(session)) => session,
                other => panic!("expected exact Session fixture, got {other:?}"),
            };
        assert!(crate::store::delete_record(&paths, RecordKind::Session, &session_id,).unwrap());
        let expected = service
            .load_snapshot(&initial.layout.window_id)
            .unwrap()
            .unwrap();
        let pre_resolved = [(
            session_id.clone(),
            crate::PreResolvedSessionState::Generation(
                session.last_known_generation.clone().unwrap(),
            ),
        )]
        .into_iter()
        .collect();
        let mut deletion = match service
            .delete_if_unchanged_with_resolutions(&expected, &pre_resolved, 10)
            .unwrap()
        {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            other => panic!("expected journaled missing-row delete, got {other:?}"),
        };
        crate::store::write_record(&paths, RecordKind::Session, &session_id, 11, &session).unwrap();
        let release = deletion.take_release_receipt().unwrap();
        let recreated_calls = Cell::new(0_usize);
        assert!(matches!(
            crate::SessionReleaseService::new(&paths).attempt_owned::<()>(
                release,
                |_| Ok(()),
                |_| {
                    recreated_calls.set(recreated_calls.get() + 1);
                    crate::CasPublication::Confirmed
                },
            ),
            crate::ReleaseOperationOutcome::Complete {
                confirmed: 0,
                retained: 1,
            }
        ));
        assert_eq!(recreated_calls.get(), 0);

        let initial = create_exact_release_window(&paths, "missing-row-absent");
        let session_id = initial.layout.tabs[0].session_id.clone();
        let generation =
            match crate::store::load_one::<SessionRecord>(&paths, RecordKind::Session, &session_id)
                .unwrap()
            {
                Some(crate::LoadOutcome::Loaded(session)) => session.last_known_generation.unwrap(),
                other => panic!("expected second exact Session fixture, got {other:?}"),
            };
        assert!(crate::store::delete_record(&paths, RecordKind::Session, &session_id,).unwrap());
        let expected = service
            .load_snapshot(&initial.layout.window_id)
            .unwrap()
            .unwrap();
        let pre_resolved = [(
            session_id,
            crate::PreResolvedSessionState::Generation(generation),
        )]
        .into_iter()
        .collect();
        let mut deletion = match service
            .delete_if_unchanged_with_resolutions(&expected, &pre_resolved, 20)
            .unwrap()
        {
            ConditionalWindowDelete::Deleted(receipt) => receipt,
            other => panic!("expected second journaled missing-row delete, got {other:?}"),
        };
        let absent_calls = Cell::new(0_usize);
        assert!(matches!(
            crate::SessionReleaseService::new(&paths).attempt_owned::<()>(
                deletion.take_release_receipt().unwrap(),
                |_| Ok(()),
                |_| {
                    absent_calls.set(absent_calls.get() + 1);
                    crate::CasPublication::Confirmed
                },
            ),
            crate::ReleaseOperationOutcome::Complete {
                confirmed: 1,
                retained: 0,
            }
        ));
        assert_eq!(absent_calls.get(), 1);
    }
}
