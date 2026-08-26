//! SIDE-EFFECTING workspace execution — `ScratchCwd`, consent-gated `Worktree` creation and
//! removal, and consent-gated `RepoWrite`.
//!
//! [`policy::resolved_cwd`](crate::policy::resolved_cwd) is pure: it computes the cwd a policy
//! WOULD use. This module is the execution step on top of it: create the shell-owned scratch
//! directory under app-support (owner-only `0700`), or — behind an explicit recorded consent
//! gate — run `git worktree add` into `<app-support>/worktrees/<workspace_id>/<session_id>` on
//! a new deterministic branch `maestro/<workspace_id>/<session_id>`.
//!
//! Capability boundaries, deliberately:
//!
//! - `Worktree` is reachable ONLY through [`prepare_workspace_with_consent`] with
//!   `consent.worktree_create` already granted on the supplied [`Workspace`] record. The
//!   non-consent-aware [`prepare_workspace`] stays conservative and keeps rejecting it with
//!   [`WorkspaceExecError::UnsupportedPolicy`]; the worktree executor is not exported.
//! - `RepoWrite` is likewise reachable ONLY through
//!   [`prepare_workspace_with_consent`] with `consent.repo_write` granted. It is the one policy
//!   whose cwd IS the live repo root — but the executor itself only VERIFIES (ids valid, root
//!   is an existing directory) and returns the path: it runs no git and creates, deletes, or
//!   chmods nothing, under the repo root or anywhere else. Any writing that follows is done by
//!   the session the user explicitly consented to run there.
//! - The only repo mutation is git's own administrative bookkeeping from `git worktree add` /
//!   `git worktree remove` (e.g. `<root>/.git/worktrees/...`) — consent-gated, deliberate
//!   operations under the explicit workspace-consent boundary. Maestro itself writes no metadata,
//!   scratch, or worktree content into the repo root.
//! - The ONLY deletion anywhere in this module is [`remove_worktree_with_consent`],
//!   and it deletes nothing unless the destination is VERIFIED as the matching Maestro worktree
//!   of the matching repo on the deterministic branch — and even then only via
//!   `git worktree remove` WITHOUT `--force`, so git itself refuses dirty checkouts. Foreign or
//!   non-matching content is never touched; preparation still never deletes anything.
//!
//! Path safety: workspace/session ids are validated (via `resolved_cwd` -> `ids::validate_id`)
//! BEFORE any directory is created or any git command runs, so a traversing id fails with
//! nothing on disk. Created cwds are under `scratch_base()` / `worktree_base()` by construction,
//! and a supplied repo root is never written into: if the resolved scratch cwd would fall under
//! the repo root (only possible when the repo root contains the app-support tree), preparation
//! is REFUSED — unless the repo root itself lies inside the scratch base, the one unusual
//! containment where "under the repo root" and "under scratch" coincide.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::ids::{validate_id, IdError};
use crate::launch_environment::LaunchEnvLookup;
use crate::paths::{AppPaths, RecordKind};
use crate::policy::{resolved_cwd, WorkspacePolicy};
use crate::records::{LaunchSpec, SessionKind, Workspace, WorktreeProvenance};
use crate::session_service::StartParams;
use crate::store::{write_record, StoreError};
use crate::workspace_consent::{
    check_policy_consent, require_consent, WorkspaceConsentError, WorkspaceConsentKind,
};

/// Owner-only mode for every directory this module creates (matches the record store).
const DIR_MODE: u32 = 0o700;

/// Why a workspace could not be prepared.
#[derive(Debug)]
pub enum WorkspaceExecError {
    /// The session/workspace id was unsafe as a path component; nothing was created.
    Id(IdError),
    /// The policy is not supported for the attempted operation (e.g. a repo-affecting policy
    /// via the non-consent-aware entrypoint, or worktree removal on a non-`Worktree` record).
    UnsupportedPolicy { policy: WorkspacePolicy },
    /// `workspace.root` is missing or a regular file, so a `RepoWrite` session has no directory
    /// to run in. Nothing was created — `RepoWrite` preparation never creates the root (or
    /// anything else); the live checkout must already exist.
    RepoRootNotDirectory { root: PathBuf },
    /// The workspace has not granted the consent the policy requires. Checked
    /// BEFORE the unsupported-policy rejection, so a consent failure is never masked.
    Consent(WorkspaceConsentError),
    /// The resolved scratch cwd would sit under the supplied repo root (the repo root contains
    /// the app-support tree) — refused so Maestro never creates state "inside" a repo, even
    /// nominally. Nothing was created.
    ScratchUnderRepoRoot { cwd: PathBuf, repo_root: PathBuf },
    /// The fresh-session-only scratch preparer found that its exact session directory already
    /// exists. It must not adopt that directory: another attempt or a live lifetime may own it.
    FreshScratchCwdAlreadyExists { cwd: PathBuf },
    /// A consume-once fresh scratch cleanup receipt was presented with different AppPaths than
    /// the paths that minted it. Nothing was removed.
    FreshScratchCwdReceiptMismatch,
    /// A prepared-session constructor could not bind a nonempty live argv to one of the sealed
    /// Shell/Agent launch modes. No daemon or durable graph mutation was attempted.
    InvalidPreparedSessionSpec,
    /// The git executable could not be spawned at all (not installed / not on PATH).
    GitSpawn { command: String, source: io::Error },
    /// A git command ran but exited non-zero; `stderr` carries git's own diagnostic.
    GitCommand {
        command: String,
        status: Option<i32>,
        stderr: String,
    },
    /// `workspace.root` is not a usable git repository (missing, not a repo, or unreadable).
    /// Nothing was created.
    NotAGitRepo { root: PathBuf, stderr: String },
    /// The resolved worktree destination already exists but is not a worktree of this repo on
    /// the expected branch (or is a file / foreign content). Nothing was deleted.
    WorktreeConflict { path: PathBuf, reason: String },
    /// The resolved worktree destination does not exist, so there is nothing to remove. Nothing
    /// was deleted and no stale git metadata was touched.
    WorktreeMissing { path: PathBuf },
    /// Directory creation or permission setting failed.
    Io(io::Error),
    /// The durable namespace fence needed by fresh scratch cleanup could not be evaluated.
    Store(StoreError),
}

impl std::fmt::Display for WorkspaceExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WorkspaceExecError::Id(e) => write!(f, "workspace exec id error: {e}"),
            WorkspaceExecError::UnsupportedPolicy { policy } => write!(
                f,
                "workspace policy {policy:?} is not supported for this operation"
            ),
            WorkspaceExecError::ScratchUnderRepoRoot { cwd, repo_root } => write!(
                f,
                "refusing to create scratch cwd {} under the supplied repo root {}",
                cwd.display(),
                repo_root.display()
            ),
            WorkspaceExecError::FreshScratchCwdAlreadyExists { cwd } => write!(
                f,
                "fresh scratch cwd {} already exists; refusing to adopt it",
                cwd.display()
            ),
            WorkspaceExecError::FreshScratchCwdReceiptMismatch => write!(
                f,
                "fresh scratch cleanup receipt does not belong to these app paths"
            ),
            WorkspaceExecError::InvalidPreparedSessionSpec => write!(
                f,
                "prepared session launch is empty, mismatched, or outside the sealed launch set"
            ),
            WorkspaceExecError::Consent(e) => write!(f, "workspace consent gate: {e}"),
            WorkspaceExecError::RepoRootNotDirectory { root } => write!(
                f,
                "repo-write workspace root {} is not an existing directory",
                root.display()
            ),
            WorkspaceExecError::GitSpawn { command, source } => {
                write!(f, "failed to spawn `{command}`: {source}")
            }
            WorkspaceExecError::GitCommand {
                command,
                status,
                stderr,
            } => match status {
                Some(code) => write!(f, "`{command}` exited with status {code}: {stderr}"),
                None => write!(f, "`{command}` was terminated by a signal: {stderr}"),
            },
            WorkspaceExecError::NotAGitRepo { root, stderr } => write!(
                f,
                "workspace root {} is not a usable git repository: {stderr}",
                root.display()
            ),
            WorkspaceExecError::WorktreeConflict { path, reason } => write!(
                f,
                "worktree destination {} exists but is not safe to reuse or remove ({reason}); \
                 refusing to touch it",
                path.display()
            ),
            WorkspaceExecError::WorktreeMissing { path } => write!(
                f,
                "worktree destination {} does not exist; nothing to remove",
                path.display()
            ),
            WorkspaceExecError::Io(e) => write!(f, "workspace exec io error: {e}"),
            WorkspaceExecError::Store(e) => write!(f, "workspace exec store error: {e}"),
        }
    }
}

impl std::error::Error for WorkspaceExecError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            WorkspaceExecError::Id(e) => Some(e),
            WorkspaceExecError::Consent(e) => Some(e),
            WorkspaceExecError::GitSpawn { source, .. } => Some(source),
            WorkspaceExecError::Io(e) => Some(e),
            WorkspaceExecError::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<IdError> for WorkspaceExecError {
    fn from(e: IdError) -> Self {
        WorkspaceExecError::Id(e)
    }
}

impl From<io::Error> for WorkspaceExecError {
    fn from(e: io::Error) -> Self {
        WorkspaceExecError::Io(e)
    }
}

impl From<WorkspaceConsentError> for WorkspaceExecError {
    fn from(e: WorkspaceConsentError) -> Self {
        WorkspaceExecError::Consent(e)
    }
}

impl From<StoreError> for WorkspaceExecError {
    fn from(error: StoreError) -> Self {
        WorkspaceExecError::Store(error)
    }
}

/// A workspace cwd that has actually been PREPARED on disk (directory exists, `0700`), as
/// opposed to the pure [`ResolvedCwd`](crate::policy::ResolvedCwd) which is only computed.
/// Carries the ids it was prepared for so [`PreparedWorkspace::adhoc_start_params`] cannot pair
/// the cwd with the wrong session.
#[derive(Clone)]
pub struct PreparedWorkspace {
    pub policy: WorkspacePolicy,
    pub workspace_id: String,
    pub session_id: String,
    /// The existing, owner-only directory the session should run in.
    pub cwd: PathBuf,
    /// Unforgeable outside this module: only a successful/reused `prepare_worktree` attempt mints
    /// it. Public callers may describe an existing cwd through [`PreparedWorkspace::unsealed`],
    /// but that value can never authorize a durable provenance marker.
    worktree_provenance:
        Option<std::sync::Arc<std::sync::Mutex<Option<PreparedWorktreeProvenanceSeal>>>>,
}

impl std::fmt::Debug for PreparedWorkspace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedWorkspace")
            .field("policy", &self.policy)
            .field("workspace_id", &self.workspace_id)
            .field("session_id", &self.session_id)
            .field("cwd", &self.cwd)
            .finish_non_exhaustive()
    }
}

impl PartialEq for PreparedWorkspace {
    fn eq(&self, other: &Self) -> bool {
        self.policy == other.policy
            && self.workspace_id == other.workspace_id
            && self.session_id == other.session_id
            && self.cwd == other.cwd
    }
}

impl Eq for PreparedWorkspace {}

/// Opaque, non-clone launch authority for transaction-prepared sessions. The live daemon argv,
/// pre-Grid non-replayable metadata, and optional post-Grid successor are derived together by
/// Shell-owned constructors; graph callers cannot substitute a `StartParams` or publication row.
pub struct PreparedSessionSpec {
    params: StartParams,
    publication_launch: LaunchSpec,
    binding: PreparedSessionBinding,
    /// Exact Worktree preparation evidence carried only by specs derived from a prepared
    /// `WorkspacePolicy::Worktree` cwd. The spec itself is consume-once, so callers cannot reuse
    /// this allowance for a second Session preparation.
    worktree_provenance: Option<PreparedWorktreeProvenanceSeal>,
}

/// Partial Worktree provenance sealed at the filesystem-preparation boundary. The exact repo root
/// is deliberately completed later from the transaction-revalidated [`Workspace`] row; everything
/// that comes from the prepared cwd itself is fixed here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedWorktreeProvenanceSeal {
    session_id: String,
    workspace_id: String,
    repo_root: String,
    target_path: String,
    branch: String,
}

/// Complete marker cohort admitted beside one prepared Session. `created_at_ms` is intentionally
/// absent: the provenance writer is best-effort and its wall-clock stamp is informational, while
/// every ownership-bearing identity/path field must match exactly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PreparedWorktreeProvenanceCohort {
    pub(crate) session_id: String,
    pub(crate) workspace_id: String,
    pub(crate) repo_root: String,
    pub(crate) target_path: String,
    pub(crate) branch: String,
}

fn canonicalized_or_lexical(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .into_owned()
}

impl PreparedWorktreeProvenanceSeal {
    fn mint(workspace: &Workspace, session_id: &str, target: &Path, branch: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
            workspace_id: workspace.workspace_id.clone(),
            repo_root: canonicalized_or_lexical(Path::new(&workspace.root)),
            target_path: canonicalized_or_lexical(target),
            branch: branch.to_string(),
        }
    }

    /// Complete the exact cohort only when the transaction-reviewed Workspace and canonical
    /// Session inputs still describe the same Worktree preparation. `None` is a closed refusal,
    /// never permission to ignore a marker.
    pub(crate) fn complete(
        &self,
        workspace: &Workspace,
        session_id: &str,
        workspace_id: &str,
        cwd: &str,
    ) -> Option<PreparedWorktreeProvenanceCohort> {
        if workspace.policy != WorkspacePolicy::Worktree
            || workspace.workspace_id != self.workspace_id
            || workspace_id != self.workspace_id
            || session_id != self.session_id
        {
            return None;
        }
        let target_path = canonicalized_or_lexical(Path::new(cwd));
        let branch = worktree_branch(workspace_id, session_id);
        if target_path != self.target_path || branch != self.branch {
            return None;
        }
        let repo_root = canonicalized_or_lexical(Path::new(&workspace.root));
        if repo_root != self.repo_root {
            return None;
        }
        Some(PreparedWorktreeProvenanceCohort {
            session_id: self.session_id.clone(),
            workspace_id: self.workspace_id.clone(),
            repo_root,
            target_path,
            branch,
        })
    }
}

impl PreparedWorktreeProvenanceCohort {
    pub(crate) fn matches(&self, marker: &WorktreeProvenance) -> bool {
        marker.session_id == self.session_id
            && marker.workspace_id == self.workspace_id
            && marker.repo_root == self.repo_root
            && marker.target_path == self.target_path
            && marker.branch == self.branch
    }
}

pub(crate) fn noncanonicalizable_agent_launch(argv: &[String]) -> LaunchSpec {
    let mut launch = crate::redact::adhoc_launch_spec(argv);
    if let LaunchSpec::AdHocRedacted { redacted, .. } = &mut launch {
        // `true` means either a secret was redacted OR these bytes are intentionally untrusted for
        // automatic recipe promotion. Prepared Agent A rows must survive startup canonicalizers
        // byte-for-byte until their own final publication transaction writes B.
        *redacted = true;
    }
    launch
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedSessionBinding {
    /// Compatibility surface for public raw `StartParams` APIs. It never grants Agent authority.
    LegacyShellAdHoc,
    /// Shell-minted exact source argv; Shell or custom Agent, with no AgentTask association.
    ExactAdHoc,
    /// A custom Agent command whose exact first token is a provider executable. Source metadata is
    /// token-redacted, while live bytes are derived through the user's login shell; A and B remain
    /// the same non-replayable AdHoc recipe.
    AgentAdHocLoginShell,
    /// An exact reviewed provider conversation. A and B use the same canonical KnownSafe recipe.
    ProviderExact,
    /// A provider launch explicitly selecting latest/import/search/index. A is token-redacted and
    /// non-replayable; B retains the bounded non-exact recipe only after Grid. It is never automatic
    /// recovery authority, but an explicit user Reopen may replay what the user selected.
    ProviderExplicitNonExact,
    /// A caller-assigned fresh provider identity. A is token-redacted and non-replayable; B is the
    /// exact canonical resume successor written only after Grid under the final writer fence.
    ProviderTransition,
}

impl std::fmt::Debug for PreparedSessionSpec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSessionSpec")
            .field("session_id", &self.params.session_id)
            .field("kind", &self.params.kind)
            .field("publication_launch", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl PreparedSessionSpec {
    pub(crate) fn into_parts(
        self,
    ) -> (
        StartParams,
        LaunchSpec,
        PreparedSessionBinding,
        Option<PreparedWorktreeProvenanceSeal>,
    ) {
        (
            self.params,
            self.publication_launch,
            self.binding,
            self.worktree_provenance,
        )
    }

    pub(crate) fn from_legacy_shell(params: StartParams) -> Self {
        Self {
            publication_launch: params.launch.clone(),
            params,
            binding: PreparedSessionBinding::LegacyShellAdHoc,
            worktree_provenance: None,
        }
    }
}

/// Consume-once authority to remove a scratch session directory that this exact preparation
/// created with an exclusive final-component `create_dir`.
///
/// The fields are private, the type is not `Clone`, and its `Debug` output is redacted. A
/// pre-existing directory can never produce this receipt.
pub struct FreshScratchCwdReceipt {
    scratch_base: PathBuf,
    cwd: PathBuf,
    session_id: String,
}

impl std::fmt::Debug for FreshScratchCwdReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FreshScratchCwdReceipt")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

/// A fresh ScratchCwd plus its sole cleanup authority. This bundle is not `Clone`; callers must
/// explicitly split ownership before they can launch the session.
pub struct FreshScratchCwdPreparation {
    prepared: PreparedWorkspace,
    cleanup: FreshScratchCwdReceipt,
}

impl FreshScratchCwdPreparation {
    pub fn into_parts(self) -> (PreparedWorkspace, FreshScratchCwdReceipt) {
        (self.prepared, self.cleanup)
    }
}

impl std::fmt::Debug for FreshScratchCwdPreparation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FreshScratchCwdPreparation")
            .field("workspace_id", &self.prepared.workspace_id)
            .field("session_id", &self.prepared.session_id)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreshScratchCwdCleanupOutcome {
    Removed,
    AlreadyMissing,
    /// The exclusively-created directory is no longer empty, so another actor may own its
    /// contents. Cleanup consumed the receipt but retained the directory byte-for-byte.
    RetainedNotEmpty,
    /// The exact Session id or one of its durable soft-owner references existed under an
    /// IMMEDIATE writer fence. Cleanup consumed the receipt and retained the directory.
    RetainedNamespaceInUse,
}

impl PreparedWorkspace {
    /// Describe an already-existing cwd without claiming that this call created or revalidated a
    /// git worktree. This keeps compatibility adapters explicit: even with `policy = Worktree`, a
    /// value made here cannot admit a present `WorktreeProvenance` row during Session preparation.
    pub fn unsealed(
        policy: WorkspacePolicy,
        workspace_id: impl Into<String>,
        session_id: impl Into<String>,
        cwd: impl Into<PathBuf>,
    ) -> Self {
        Self {
            policy,
            workspace_id: workspace_id.into(),
            session_id: session_id.into(),
            cwd: cwd.into(),
            worktree_provenance: None,
        }
    }

    fn take_worktree_provenance(
        &self,
    ) -> Result<Option<PreparedWorktreeProvenanceSeal>, WorkspaceExecError> {
        let Some(authority) = &self.worktree_provenance else {
            return Ok(None);
        };
        authority
            .lock()
            .map_err(|_| WorkspaceExecError::InvalidPreparedSessionSpec)?
            .take()
            .map(Some)
            .ok_or(WorkspaceExecError::InvalidPreparedSessionSpec)
    }

    /// Build ad-hoc (redaction-safe) [`StartParams`] running in this prepared cwd. Pure
    /// convenience — it does NOT talk to the daemon; hand the result to
    /// [`ShellRuntime::start_session`](crate::shell_runtime::ShellRuntime::start_session).
    pub fn adhoc_start_params(
        &self,
        kind: SessionKind,
        argv: &[String],
        cols: u16,
        rows: u16,
        now_ms: u64,
    ) -> StartParams {
        StartParams::adhoc(
            self.session_id.clone(),
            self.workspace_id.clone(),
            kind,
            self.cwd.to_string_lossy(),
            argv,
            cols,
            rows,
            now_ms,
        )
    }

    /// Seal an exact ad-hoc Shell or Agent launch. Metadata is recomputed from the same live argv;
    /// AgentTask association is intentionally impossible in this generic pane constructor.
    pub fn adhoc_session_spec(
        &self,
        kind: SessionKind,
        argv: &[String],
        cols: u16,
        rows: u16,
        now_ms: u64,
    ) -> Result<PreparedSessionSpec, WorkspaceExecError> {
        self.adhoc_session_spec_with_env(kind, argv, &crate::ProcessLaunchEnv, cols, rows, now_ms)
    }

    pub fn adhoc_session_spec_with_env(
        &self,
        kind: SessionKind,
        argv: &[String],
        env: &impl LaunchEnvLookup,
        cols: u16,
        rows: u16,
        now_ms: u64,
    ) -> Result<PreparedSessionSpec, WorkspaceExecError> {
        if !matches!(kind, SessionKind::Shell | SessionKind::Agent)
            || argv.first().is_none_or(|command| command.trim().is_empty())
        {
            return Err(WorkspaceExecError::InvalidPreparedSessionSpec);
        }
        let source_launch = if kind == SessionKind::Agent {
            noncanonicalizable_agent_launch(argv)
        } else {
            crate::redact::adhoc_launch_spec(argv)
        };
        let login_shell_agent = kind == SessionKind::Agent
            && argv
                .first()
                .is_some_and(|command| crate::restart_recipe::is_known_provider_id(command));
        let wire_argv = if login_shell_agent {
            crate::launch_environment::login_shell_argv(argv, env)
        } else {
            argv.to_vec()
        };
        let (command, args) = wire_argv
            .split_first()
            .filter(|(command, _)| !command.trim().is_empty())
            .ok_or(WorkspaceExecError::InvalidPreparedSessionSpec)?;
        let params = StartParams {
            session_id: self.session_id.clone(),
            workspace_id: self.workspace_id.clone(),
            kind,
            launch: source_launch,
            cwd: self.cwd.to_string_lossy().into_owned(),
            command: command.clone(),
            args: args.to_vec(),
            cols,
            rows,
            agent_task_id: None,
            now_ms,
        };
        Ok(PreparedSessionSpec {
            publication_launch: params.launch.clone(),
            params,
            binding: if login_shell_agent {
                PreparedSessionBinding::AgentAdHocLoginShell
            } else {
                PreparedSessionBinding::ExactAdHoc
            },
            worktree_provenance: self.take_worktree_provenance()?,
        })
    }

    /// Seal one Hydra-selected provider launch.
    ///
    /// The selected provider id must be the exact first source token and every remaining source
    /// byte must belong to that provider's closed fresh/latest/exact grammar. Shell derives the
    /// login-shell wire argv privately. It never accepts caller-built KnownSafe metadata and never
    /// redacts the packed login-shell script (which could hide a nested secret flag).
    pub fn provider_session_spec(
        &self,
        selected_provider: &str,
        source_argv: &[String],
        env: &impl LaunchEnvLookup,
        cols: u16,
        rows: u16,
        now_ms: u64,
    ) -> Result<PreparedSessionSpec, WorkspaceExecError> {
        let (mode, canonical_publication) =
            crate::restart_recipe::strict_prepared_provider_launch(selected_provider, source_argv)
                .ok_or(WorkspaceExecError::InvalidPreparedSessionSpec)?;
        let wire_argv = crate::launch_environment::login_shell_argv(source_argv, env);
        let (command, args) = wire_argv
            .split_first()
            .filter(|(command, _)| !command.trim().is_empty())
            .ok_or(WorkspaceExecError::InvalidPreparedSessionSpec)?;
        let source_launch = noncanonicalizable_agent_launch(source_argv);
        let (launch, publication_launch, binding) = match mode {
            crate::restart_recipe::PreparedProviderLaunchMode::ExactResume => (
                canonical_publication.clone(),
                canonical_publication,
                PreparedSessionBinding::ProviderExact,
            ),
            crate::restart_recipe::PreparedProviderLaunchMode::FreshUnassigned => (
                source_launch.clone(),
                source_launch,
                PreparedSessionBinding::AgentAdHocLoginShell,
            ),
            crate::restart_recipe::PreparedProviderLaunchMode::ExplicitNonExact => (
                source_launch,
                canonical_publication,
                PreparedSessionBinding::ProviderExplicitNonExact,
            ),
            crate::restart_recipe::PreparedProviderLaunchMode::FreshWithAssignedIdentity => (
                source_launch,
                canonical_publication,
                PreparedSessionBinding::ProviderTransition,
            ),
        };
        let params = StartParams {
            session_id: self.session_id.clone(),
            workspace_id: self.workspace_id.clone(),
            kind: SessionKind::Agent,
            launch,
            cwd: self.cwd.to_string_lossy().into_owned(),
            command: command.clone(),
            args: args.to_vec(),
            cols,
            rows,
            agent_task_id: None,
            now_ms,
        };
        Ok(PreparedSessionSpec {
            params,
            publication_launch,
            binding,
            worktree_provenance: self.take_worktree_provenance()?,
        })
    }

    /// Seal an explicit custom command whose first token happens to be a known provider word.
    /// Selector-shaped invalid input is never downgraded through this path: it must pass the
    /// strict provider constructor or fail. Other custom subcommands remain A=B AdHoc and execute
    /// through the login shell without gaining KnownSafe restart authority.
    pub fn provider_custom_adhoc_session_spec(
        &self,
        selected_provider: &str,
        source_argv: &[String],
        env: &impl LaunchEnvLookup,
        cols: u16,
        rows: u16,
        now_ms: u64,
    ) -> Result<PreparedSessionSpec, WorkspaceExecError> {
        if !crate::restart_recipe::is_valid_prepared_provider_custom_adhoc(
            selected_provider,
            source_argv,
        ) {
            return Err(WorkspaceExecError::InvalidPreparedSessionSpec);
        }
        self.adhoc_session_spec_with_env(SessionKind::Agent, source_argv, env, cols, rows, now_ms)
    }
}

/// Prepare the `ScratchCwd` workspace for one new session: validate ids, compute
/// `<app-support>/scratch/<session_id>` via the pure resolver, exclusively create it (and the
/// scratch parents) with `0700`, and return it.
///
/// `repo_root` is the project root the session is associated with. `ScratchCwd` never resolves
/// into it; it is used here only for the refusal check documented on
/// [`WorkspaceExecError::ScratchUnderRepoRoot`]. Pass `""` when there is no associated repo.
///
/// Failure order: id validation and the repo-root check both happen BEFORE any directory is
/// created, so an error means nothing was written.
pub fn prepare_scratch_cwd(
    paths: &AppPaths,
    workspace_id: &str,
    session_id: &str,
    repo_root: &str,
) -> Result<PreparedWorkspace, WorkspaceExecError> {
    // Drop the cleanup authority deliberately: this compatibility signature cannot return it,
    // so its successful directory is retained. It still shares the exclusive/non-adopting leaf
    // claim with every other production Scratch preparer.
    prepare_fresh_scratch_cwd(paths, workspace_id, session_id, repo_root)
        .map(FreshScratchCwdPreparation::into_parts)
        .map(|(prepared, _cleanup)| prepared)
}

/// Prepare a ScratchCwd for a brand-new session attempt and mint cleanup authority only when this
/// call exclusively created the final session directory.
///
/// If the exact session directory already exists it returns
/// [`WorkspaceExecError::FreshScratchCwdAlreadyExists`] without chmodding, deleting, or adopting
/// that directory. This prevents a losing same-id retry from using a directory while the winning
/// preparer still owns its cleanup receipt.
pub fn prepare_fresh_scratch_cwd(
    paths: &AppPaths,
    workspace_id: &str,
    session_id: &str,
    repo_root: &str,
) -> Result<FreshScratchCwdPreparation, WorkspaceExecError> {
    // Resolve and reject before creating any directory, matching `prepare_scratch_cwd`.
    let resolved = resolved_cwd(
        paths,
        WorkspacePolicy::ScratchCwd,
        workspace_id,
        session_id,
        repo_root,
    )?;
    let scratch_base = paths.scratch_base();
    debug_assert!(resolved.cwd.starts_with(&scratch_base));

    let repo_root_path = Path::new(repo_root);
    if !repo_root.is_empty()
        && resolved.cwd.starts_with(repo_root_path)
        && !repo_root_path.starts_with(&scratch_base)
    {
        return Err(WorkspaceExecError::ScratchUnderRepoRoot {
            cwd: resolved.cwd,
            repo_root: repo_root_path.to_path_buf(),
        });
    }

    // Only the parent hierarchy is idempotent. The session leaf is an atomic ownership claim.
    fs::create_dir_all(&scratch_base)?;
    for dir in [paths.base(), scratch_base.as_path()] {
        set_dir_mode(dir)?;
    }
    match fs::create_dir(&resolved.cwd) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(WorkspaceExecError::FreshScratchCwdAlreadyExists { cwd: resolved.cwd });
        }
        Err(error) => return Err(WorkspaceExecError::Io(error)),
    }
    if let Err(error) = set_dir_mode(&resolved.cwd) {
        // The leaf is still empty and no authority has escaped. Best effort avoids leaving an
        // unusable directory that all later fresh attempts must correctly refuse to adopt.
        let _ = fs::remove_dir(&resolved.cwd);
        return Err(WorkspaceExecError::Io(error));
    }

    Ok(FreshScratchCwdPreparation {
        prepared: PreparedWorkspace {
            policy: WorkspacePolicy::ScratchCwd,
            workspace_id: workspace_id.to_string(),
            session_id: session_id.to_string(),
            cwd: resolved.cwd.clone(),
            worktree_provenance: None,
        },
        cleanup: FreshScratchCwdReceipt {
            scratch_base,
            cwd: resolved.cwd,
            session_id: session_id.to_string(),
        },
    })
}

/// Consume a fresh-directory receipt and remove exactly the directory it created.
///
/// Passing different [`AppPaths`] fails closed and still consumes the receipt. A directory that
/// was already removed is reported as an idempotent outcome rather than an IO failure.
pub fn cleanup_fresh_scratch_cwd(
    paths: &AppPaths,
    receipt: FreshScratchCwdReceipt,
) -> Result<FreshScratchCwdCleanupOutcome, WorkspaceExecError> {
    let expected_base = paths.scratch_base();
    let expected_cwd = expected_base.join(&receipt.session_id);
    if receipt.scratch_base != expected_base || receipt.cwd != expected_cwd {
        return Err(WorkspaceExecError::FreshScratchCwdReceiptMismatch);
    }

    // A legacy same-id writer does not participate in the filesystem leaf claim. Fence that
    // compatibility path at the durable namespace: raw legacy start records Unknown before it
    // can launch, and every soft owner is checked too. Keep the IMMEDIATE transaction alive
    // through the filesystem operation so no cross-process writer can claim the id between the
    // absence proof and `remove_dir`.
    let arc = crate::db::conn_for(paths.base())
        .map_err(|error| WorkspaceExecError::Store(StoreError::Db(error.to_string())))?;
    let mut conn = arc.lock().unwrap();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| WorkspaceExecError::Store(StoreError::Db(error.to_string())))?;
    if !crate::window_layout::prepared_absent_session_namespace_is_clean(&tx, &receipt.session_id)?
    {
        return Ok(FreshScratchCwdCleanupOutcome::RetainedNamespaceInUse);
    }

    // Pre-wire / definitely-unpublished cleanup should only ever see the empty leaf that prepare
    // created. Never recursively delete: unexpected content is evidence of another owner.
    let outcome = match fs::remove_dir(&receipt.cwd) {
        Ok(()) => Ok(FreshScratchCwdCleanupOutcome::Removed),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            Ok(FreshScratchCwdCleanupOutcome::AlreadyMissing)
        }
        Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {
            Ok(FreshScratchCwdCleanupOutcome::RetainedNotEmpty)
        }
        Err(error) => Err(WorkspaceExecError::Io(error)),
    };
    drop(tx);
    outcome
}

/// Generic NON-consent-aware entrypoint, deliberately conservative: only `ScratchCwd` is
/// executable here. `Worktree` and `RepoWrite` return
/// [`WorkspaceExecError::UnsupportedPolicy`] and create nothing — repo-affecting policies are
/// reachable ONLY through [`prepare_workspace_with_consent`], which proves recorded consent on
/// an explicit [`Workspace`] record first. There is no consent record in this signature, so
/// there is no consent to prove, so there is no repo-affecting capability.
pub fn prepare_workspace(
    paths: &AppPaths,
    policy: WorkspacePolicy,
    workspace_id: &str,
    session_id: &str,
    repo_root: &str,
) -> Result<PreparedWorkspace, WorkspaceExecError> {
    match policy {
        WorkspacePolicy::ScratchCwd => {
            prepare_scratch_cwd(paths, workspace_id, session_id, repo_root)
        }
        WorkspacePolicy::Worktree | WorkspacePolicy::RepoWrite => {
            Err(WorkspaceExecError::UnsupportedPolicy { policy })
        }
    }
}

/// Consent-gated entrypoint: prove the consent state on an
/// EXPLICITLY supplied in-memory [`Workspace`] record before any execution. This function does
/// NOT look the workspace up in the store — the caller chooses where the record came from
/// (typically `store::load_one`), keeping the IO boundary visible.
///
/// Gate order, deliberately: **consent first, then capability.**
///
/// 1. [`check_policy_consent`] — `ScratchCwd` needs none; `Worktree` requires `worktree_create`;
///    `RepoWrite` requires `repo_write`. A missing grant fails with
///    [`WorkspaceExecError::Consent`] and nothing is created, no git runs.
/// 2. Then the policy capability:
///    - `ScratchCwd` executes exactly like [`prepare_scratch_cwd`].
///    - `Worktree` creates a real git worktree of `workspace.root` under
///      `<app-support>/worktrees/<workspace_id>/<session_id>` on branch
///      `maestro/<workspace_id>/<session_id>` — see the module docs for the exact git behavior
///      and idempotency rules.
///    - `RepoWrite` verifies the ids and that `workspace.root` is an existing
///      directory, then returns that root verbatim as the session cwd. It runs no git and
///      mutates nothing — see [`prepare_repo_write`] (private) for the exact contract.
///
/// The workspace's own `workspace_id` and `root` are used (the record is the authority on what
/// repo it governs), so a caller cannot pair consent from one workspace with another's repo.
pub fn prepare_workspace_with_consent(
    paths: &AppPaths,
    policy: WorkspacePolicy,
    workspace: &Workspace,
    session_id: &str,
) -> Result<PreparedWorkspace, WorkspaceExecError> {
    check_policy_consent(workspace, policy)?;
    match policy {
        WorkspacePolicy::ScratchCwd => {
            prepare_scratch_cwd(paths, &workspace.workspace_id, session_id, &workspace.root)
        }
        WorkspacePolicy::Worktree => prepare_worktree(paths, workspace, session_id),
        WorkspacePolicy::RepoWrite => prepare_repo_write(workspace, session_id),
    }
}

/// Execute `WorkspacePolicy::RepoWrite` for one session. PRIVATE on purpose: the only
/// route here is [`prepare_workspace_with_consent`], so the live repo root can never become a
/// session cwd without a [`Workspace`] record whose `repo_write` consent already passed the gate.
///
/// This executor VERIFIES and returns — it has no side effects at all:
///
/// - both ids are validated first (same `ids::validate_id` discipline as the other policies; the
///   ids do not become path components here, but they flow into records and `StartParams`, so an
///   unsafe id still fails before anything is reported as prepared)
/// - `workspace.root` must already be a directory; a missing path or regular file is
///   [`WorkspaceExecError::RepoRootNotDirectory`] and nothing is created
/// - NO git runs, and nothing under the repo root (or anywhere else) is created, deleted, or
///   chmodded — unlike scratch/worktree preparation there is no Maestro-owned directory to set
///   up, and the root is the user's own checkout, not ours to touch
///
/// The returned cwd is `workspace.root` verbatim.
fn prepare_repo_write(
    workspace: &Workspace,
    session_id: &str,
) -> Result<PreparedWorkspace, WorkspaceExecError> {
    validate_id(&workspace.workspace_id)?;
    validate_id(session_id)?;

    let root = Path::new(&workspace.root);
    if !root.is_dir() {
        return Err(WorkspaceExecError::RepoRootNotDirectory {
            root: root.to_path_buf(),
        });
    }

    Ok(PreparedWorkspace {
        policy: WorkspacePolicy::RepoWrite,
        workspace_id: workspace.workspace_id.clone(),
        session_id: session_id.to_string(),
        cwd: root.to_path_buf(),
        worktree_provenance: None,
    })
}

/// Deterministic branch a session's worktree is created on. Both ids are already validated to
/// `[A-Za-z0-9_-]` (see `ids::validate_id`) before this is used, which is also a safe subset
/// for git refname components.
pub(crate) fn worktree_branch(workspace_id: &str, session_id: &str) -> String {
    format!("maestro/{workspace_id}/{session_id}")
}

/// Local wall-clock millis for stamping a provenance marker. Used only for the best-effort
/// marker write; a clock that is before the epoch (impossible in practice) folds to 0 rather
/// than failing preparation.
fn wall_clock_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Write the durable, app-owned [`WorktreeProvenance`] marker for a prepared worktree.
/// BEST-EFFORT: any failure is swallowed (returned as `Err` for the caller to ignore) — a marker
/// write must NEVER abort or roll back an already-successful worktree preparation. The marker is
/// keyed by `session_id` (a `workspace_id` mismatch is caught at read time because the record
/// also stores `workspace_id`).
///
/// All path fields are canonicalized so a later canonical listing compares exactly; if a path
/// cannot be canonicalized (it should exist by now) the lexical form is stored as a fallback so
/// the marker is still written rather than skipped.
fn write_worktree_provenance(
    paths: &AppPaths,
    seal: &PreparedWorktreeProvenanceSeal,
) -> Result<(), StoreError> {
    let record = WorktreeProvenance {
        workspace_id: seal.workspace_id.clone(),
        session_id: seal.session_id.clone(),
        repo_root: seal.repo_root.clone(),
        target_path: seal.target_path.clone(),
        branch: seal.branch.clone(),
        created_at_ms: wall_clock_ms(),
    };
    write_record(
        paths,
        RecordKind::WorktreeProvenance,
        &seal.session_id,
        record.created_at_ms,
        &record,
    )
}

/// Execute `WorkspacePolicy::Worktree` for one session. PRIVATE on purpose: the only route here
/// is [`prepare_workspace_with_consent`], so a worktree can never be created without a
/// [`Workspace`] record whose `worktree_create` consent already passed the gate.
///
/// Exact git behavior:
///
/// - source repo root: `workspace.root` (must already be a git repository — verified with
///   `git -C <root> rev-parse --absolute-git-dir` BEFORE any side effect; failure is
///   [`WorkspaceExecError::NotAGitRepo`])
/// - worktree path: `<app-support>/worktrees/<workspace_id>/<session_id>` from the pure resolver
/// - branch: `maestro/<workspace_id>/<session_id>` (new branch via `-b`)
/// - command: `git -C <root> worktree add <path> -b <branch>`
///
/// Idempotency / existing destinations (nothing is EVER deleted here):
///
/// - destination is already a worktree of the SAME repo on the SAME branch -> reused as-is
/// - destination is an existing EMPTY directory -> `git worktree add` populates it
/// - anything else at the destination -> [`WorkspaceExecError::WorktreeConflict`]
fn prepare_worktree(
    paths: &AppPaths,
    workspace: &Workspace,
    session_id: &str,
) -> Result<PreparedWorkspace, WorkspaceExecError> {
    // Pure resolution first: validates BOTH ids, computes the path, creates nothing. An unsafe
    // id therefore fails before any git command runs.
    let resolved = resolved_cwd(
        paths,
        WorkspacePolicy::Worktree,
        &workspace.workspace_id,
        session_id,
        &workspace.root,
    )?;
    let worktree_base = paths.worktree_base();
    debug_assert!(resolved.cwd.starts_with(&worktree_base));

    let root = Path::new(&workspace.root);
    // Prove the root is a usable git repo BEFORE creating anything or mutating git state.
    let git_dir = match run_git(&[
        OsStr::new("-C"),
        root.as_os_str(),
        OsStr::new("rev-parse"),
        OsStr::new("--absolute-git-dir"),
    ]) {
        Ok(out) => PathBuf::from(out),
        Err(WorkspaceExecError::GitCommand { stderr, .. }) => {
            return Err(WorkspaceExecError::NotAGitRepo {
                root: root.to_path_buf(),
                stderr,
            })
        }
        Err(e) => return Err(e),
    };

    let branch = worktree_branch(&workspace.workspace_id, session_id);

    if resolved.cwd.symlink_metadata().is_ok() {
        if matching_worktree(&resolved.cwd, &git_dir, &branch) {
            // Same repo, same branch: prepare is idempotent. Refresh the provenance marker
            // best-effort — a write failure here must NOT abort the (already successful) reuse.
            set_dir_mode(&resolved.cwd)?;
            let worktree_provenance =
                PreparedWorktreeProvenanceSeal::mint(workspace, session_id, &resolved.cwd, &branch);
            let _ = write_worktree_provenance(paths, &worktree_provenance);
            return Ok(PreparedWorkspace {
                policy: WorkspacePolicy::Worktree,
                workspace_id: workspace.workspace_id.clone(),
                session_id: session_id.to_string(),
                cwd: resolved.cwd,
                worktree_provenance: Some(std::sync::Arc::new(std::sync::Mutex::new(Some(
                    worktree_provenance,
                )))),
            });
        }
        // Only a pre-existing EMPTY directory may be handed to `git worktree add`; any other
        // content (file, symlink, foreign/non-matching checkout) is refused untouched.
        let is_empty_dir = resolved.cwd.is_dir()
            && fs::read_dir(&resolved.cwd)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false);
        if !is_empty_dir {
            return Err(WorkspaceExecError::WorktreeConflict {
                path: resolved.cwd,
                reason: format!(
                    "not an empty directory and not a worktree of {} on branch {branch}",
                    root.display()
                ),
            });
        }
    }

    // Create base -> worktrees base -> per-workspace dir, each owner-only, so the worktree
    // inherits a 0700 ancestry like the record store and scratch dirs.
    let workspace_dir = worktree_base.join(workspace.workspace_id.as_str());
    fs::create_dir_all(&workspace_dir)?;
    for dir in [
        paths.base(),
        worktree_base.as_path(),
        workspace_dir.as_path(),
    ] {
        set_dir_mode(dir)?;
    }

    run_git(&[
        OsStr::new("-C"),
        root.as_os_str(),
        OsStr::new("worktree"),
        OsStr::new("add"),
        resolved.cwd.as_os_str(),
        OsStr::new("-b"),
        OsStr::new(&branch),
    ])?;
    set_dir_mode(&resolved.cwd)?;

    // Worktree created: write the provenance marker best-effort. A marker failure must NOT roll
    // back or fail the already-created worktree, so the result is deliberately ignored.
    let worktree_provenance =
        PreparedWorktreeProvenanceSeal::mint(workspace, session_id, &resolved.cwd, &branch);
    let _ = write_worktree_provenance(paths, &worktree_provenance);

    Ok(PreparedWorkspace {
        policy: WorkspacePolicy::Worktree,
        workspace_id: workspace.workspace_id.clone(),
        session_id: session_id.to_string(),
        cwd: resolved.cwd,
        worktree_provenance: Some(std::sync::Arc::new(std::sync::Mutex::new(Some(
            worktree_provenance,
        )))),
    })
}

/// Proof that a Maestro-owned worktree checkout was actually removed. Every `Ok`
/// from [`remove_worktree_with_consent`] means `git worktree remove` ran and succeeded — there
/// is no "nothing happened" success, so no boolean is needed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemovedWorkspace {
    pub workspace_id: String,
    pub session_id: String,
    /// The app-support worktree path that was removed.
    pub path: PathBuf,
    /// The deterministic branch the worktree was on (`maestro/<workspace_id>/<session_id>`).
    /// The branch itself is NOT deleted — this operation removes only the checkout.
    pub branch: String,
}

/// Safely remove the Maestro-owned worktree checkout for one session.
///
/// Gate order, deliberately: **consent first, then capability, then verification, then git.**
///
/// 1. [`require_consent`] for `worktree_create` — the same grant that allowed creation governs
///    removal of what it created. A missing grant fails with [`WorkspaceExecError::Consent`]
///    and nothing runs.
/// 2. `workspace.policy` must be [`WorkspacePolicy::Worktree`]; anything else is
///    [`WorkspaceExecError::UnsupportedPolicy`] (`RepoWrite` has no removal path).
/// 3. Pure resolution validates BOTH ids before any git command, then the path is verified to
///    sit under `worktree_base()` — this function can only ever target
///    `<app-support>/worktrees/<workspace_id>/<session_id>`, never an arbitrary path.
/// 4. `workspace.root` must be a usable git repo
///    ([`WorkspaceExecError::NotAGitRepo`] otherwise), and the destination must be VERIFIED as
///    a worktree of THAT repo on the deterministic branch
///    `maestro/<workspace_id>/<session_id>`:
///    - destination missing -> [`WorkspaceExecError::WorktreeMissing`] (no stale-metadata
///      this operation does not invent stale-metadata cleanup);
///    - destination exists but is foreign content, a worktree of another repo, or on another
///      branch -> [`WorkspaceExecError::WorktreeConflict`] and NOTHING is deleted.
/// 5. Removal is `git -C <root> worktree remove <path>` — NO `--force`, ever. If git refuses
///    (e.g. the worktree is dirty), the error surfaces as [`WorkspaceExecError::GitCommand`]
///    and every file is left intact.
///
/// The branch is NOT deleted; removing the checkout is the whole capability.
pub fn remove_worktree_with_consent(
    paths: &AppPaths,
    workspace: &Workspace,
    session_id: &str,
) -> Result<RemovedWorkspace, WorkspaceExecError> {
    // Consent first — a missing grant is never masked by a capability or verification error.
    require_consent(workspace, WorkspaceConsentKind::WorktreeCreate)?;
    if workspace.policy != WorkspacePolicy::Worktree {
        return Err(WorkspaceExecError::UnsupportedPolicy {
            policy: workspace.policy,
        });
    }

    // Pure resolution: validates BOTH ids, computes the only removable path, runs no git.
    let resolved = resolved_cwd(
        paths,
        WorkspacePolicy::Worktree,
        &workspace.workspace_id,
        session_id,
        &workspace.root,
    )?;
    let worktree_base = paths.worktree_base();
    // Runtime (not debug) containment check: we are about to delete, so over-checking is cheap
    // and under-checking is unacceptable.
    if !resolved.cwd.starts_with(&worktree_base) {
        return Err(WorkspaceExecError::WorktreeConflict {
            path: resolved.cwd,
            reason: "resolved path is not under the app-support worktree base".to_string(),
        });
    }

    let root = Path::new(&workspace.root);
    let git_dir = match run_git(&[
        OsStr::new("-C"),
        root.as_os_str(),
        OsStr::new("rev-parse"),
        OsStr::new("--absolute-git-dir"),
    ]) {
        Ok(out) => PathBuf::from(out),
        Err(WorkspaceExecError::GitCommand { stderr, .. }) => {
            return Err(WorkspaceExecError::NotAGitRepo {
                root: root.to_path_buf(),
                stderr,
            })
        }
        Err(e) => return Err(e),
    };

    let branch = worktree_branch(&workspace.workspace_id, session_id);

    if resolved.cwd.symlink_metadata().is_err() {
        return Err(WorkspaceExecError::WorktreeMissing { path: resolved.cwd });
    }
    if !matching_worktree(&resolved.cwd, &git_dir, &branch) {
        return Err(WorkspaceExecError::WorktreeConflict {
            path: resolved.cwd,
            reason: format!("not a worktree of {} on branch {branch}", root.display()),
        });
    }

    // Verified: this is OUR worktree of OUR repo on OUR branch. Still no --force — git itself
    // refuses dirty/locked checkouts and that refusal surfaces untouched as GitCommand.
    run_git(&[
        OsStr::new("-C"),
        root.as_os_str(),
        OsStr::new("worktree"),
        OsStr::new("remove"),
        resolved.cwd.as_os_str(),
    ])?;

    Ok(RemovedWorkspace {
        workspace_id: workspace.workspace_id.clone(),
        session_id: session_id.to_string(),
        path: resolved.cwd,
        branch,
    })
}

/// True iff `path` is a git worktree whose common (main) git dir is `git_dir` and whose checked
/// out branch is `branch`. Any git failure inside `path` simply means "not a matching worktree";
/// the caller then refuses the destination rather than reusing it.
fn matching_worktree(path: &Path, git_dir: &Path, branch: &str) -> bool {
    let common = match run_git(&[
        OsStr::new("-C"),
        path.as_os_str(),
        OsStr::new("rev-parse"),
        OsStr::new("--git-common-dir"),
    ]) {
        Ok(out) => out,
        Err(_) => return false,
    };
    // `--git-common-dir` may print a path relative to the worktree; resolve both sides through
    // the filesystem so symlinked temp dirs (e.g. macOS /var -> /private/var) compare equal.
    let common_path = Path::new(&common);
    let common_abs = if common_path.is_absolute() {
        common_path.to_path_buf()
    } else {
        path.join(common_path)
    };
    let same_repo = match (fs::canonicalize(&common_abs), fs::canonicalize(git_dir)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    };
    if !same_repo {
        return false;
    }

    matches!(
        run_git(&[
            OsStr::new("-C"),
            path.as_os_str(),
            OsStr::new("symbolic-ref"),
            OsStr::new("--short"),
            OsStr::new("HEAD"),
        ]),
        Ok(head) if head == branch
    )
}

/// Read-only classification of one resolved worktree destination relative to a repo root and
/// the expected Maestro branch. Computed WITHOUT mutating anything: at most read-only
/// `git worktree list --porcelain` / `rev-parse` / `symbolic-ref` queries plus a path stat.
///
/// This is the listing/inspection counterpart of [`matching_worktree`] (which is destructive
/// removal's gate): it never deletes, never runs a mutating git subcommand, and treats every
/// git failure as a classification, not an error to propagate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorktreeInspection {
    /// `target` is a worktree of `root`'s repo, checked out on the expected `branch`. Dirty or
    /// clean — dirtiness is informational only and does not change this verdict.
    Verified,
    /// `target` does not exist on disk.
    PathMissing,
    /// `target` exists but is not registered as a git worktree (foreign dir / file / stale).
    NotAWorktree,
    /// `target` is a worktree, but of a different repo (not visible from `root`).
    WrongRepo,
    /// `target` is a worktree of this repo, but on a branch other than the expected one.
    WrongBranch,
    /// `root` is missing or is not a git repository, so nothing under it can be inspected.
    RootNotARepo,
    /// The git executable could not be spawned at all.
    GitUnavailable,
}

impl WorktreeInspection {
    /// Stable snake_case wire string for the `git_status` output field.
    pub fn as_str(self) -> &'static str {
        match self {
            WorktreeInspection::Verified => "verified",
            WorktreeInspection::PathMissing => "path_missing",
            WorktreeInspection::NotAWorktree => "not_a_worktree",
            WorktreeInspection::WrongRepo => "wrong_repo",
            WorktreeInspection::WrongBranch => "wrong_branch",
            WorktreeInspection::RootNotARepo => "root_not_a_repo",
            WorktreeInspection::GitUnavailable => "unavailable",
        }
    }
}

/// One entry parsed from `git worktree list --porcelain`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PorcelainWorktree {
    /// Absolute path of the worktree checkout (the `worktree` line).
    pub path: PathBuf,
    /// Short branch name if the `branch refs/heads/<name>` line is present; `None` for a
    /// detached HEAD (`detached`) or bare entry.
    pub branch: Option<String>,
    /// Whether a `locked` annotation was present.
    pub locked: bool,
    /// Whether a `prunable` annotation was present.
    pub prunable: bool,
}

/// Parse `git worktree list --porcelain` output into per-worktree records. Records are separated
/// by blank lines; each begins with a `worktree <path>` line. `branch refs/heads/<name>` yields
/// the short name; `detached` / bare entries leave `branch` as `None`. Unknown lines are ignored
/// so future git annotations do not break parsing.
pub fn parse_worktree_porcelain(output: &str) -> Vec<PorcelainWorktree> {
    let mut out = Vec::new();
    let mut current: Option<PorcelainWorktree> = None;
    for line in output.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            if let Some(done) = current.take() {
                out.push(done);
            }
            current = Some(PorcelainWorktree {
                path: PathBuf::from(path),
                branch: None,
                locked: false,
                prunable: false,
            });
        } else if let Some(entry) = current.as_mut() {
            if let Some(refname) = line.strip_prefix("branch ") {
                entry.branch = refname
                    .strip_prefix("refs/heads/")
                    .map(str::to_string)
                    .or_else(|| Some(refname.to_string()));
            } else if line == "locked" || line.starts_with("locked ") {
                entry.locked = true;
            } else if line == "prunable" || line.starts_with("prunable ") {
                entry.prunable = true;
            }
            // `detached`, `bare`, `HEAD <sha>`, blank, and unknown lines are ignored.
        }
    }
    if let Some(done) = current.take() {
        out.push(done);
    }
    out
}

/// Read-only inspection of a single resolved worktree `target` against the repo at `root` and the
/// expected Maestro `branch`. Runs ONLY read-only git queries; mutates nothing. See
/// [`WorktreeInspection`] for the verdicts.
pub fn inspect_worktree(root: &Path, target: &Path, branch: &str) -> WorktreeInspection {
    // Enumerate the repo's worktrees read-only. A spawn failure means git is unavailable; any
    // other failure (root missing / not a repo) is classified as `RootNotARepo`.
    let listing = match run_git(&[
        OsStr::new("-C"),
        root.as_os_str(),
        OsStr::new("worktree"),
        OsStr::new("list"),
        OsStr::new("--porcelain"),
    ]) {
        Ok(out) => out,
        Err(WorkspaceExecError::GitSpawn { .. }) => return WorktreeInspection::GitUnavailable,
        Err(_) => return WorktreeInspection::RootNotARepo,
    };

    let target_abs = fs::canonicalize(target).ok();
    let registered = parse_worktree_porcelain(&listing).into_iter().find(|wt| {
        match (&target_abs, fs::canonicalize(&wt.path).ok()) {
            (Some(a), Some(b)) => a == &b,
            _ => wt.path == target,
        }
    });

    match registered {
        Some(wt) => match wt.branch.as_deref() {
            Some(b) if b == branch => WorktreeInspection::Verified,
            _ => WorktreeInspection::WrongBranch,
        },
        None => {
            if !target.exists() {
                return WorktreeInspection::PathMissing;
            }
            // The path exists but is not registered for THIS root. Distinguish "registered for
            // another repo" from "not a worktree at all" by asking the path itself, read-only.
            match run_git(&[
                OsStr::new("-C"),
                target.as_os_str(),
                OsStr::new("rev-parse"),
                OsStr::new("--is-inside-work-tree"),
            ]) {
                Ok(out) if out == "true" => WorktreeInspection::WrongRepo,
                Ok(_) => WorktreeInspection::NotAWorktree,
                Err(WorkspaceExecError::GitSpawn { .. }) => WorktreeInspection::GitUnavailable,
                Err(_) => WorktreeInspection::NotAWorktree,
            }
        }
    }
}

/// Run one git command, capturing output. Non-zero exit becomes
/// [`WorkspaceExecError::GitCommand`] with trimmed stderr; a spawn failure (git missing)
/// becomes [`WorkspaceExecError::GitSpawn`]. Returns trimmed stdout.
fn run_git(args: &[&OsStr]) -> Result<String, WorkspaceExecError> {
    let command = std::iter::once("git".to_string())
        .chain(args.iter().map(|a| a.to_string_lossy().into_owned()))
        .collect::<Vec<_>>()
        .join(" ");
    let output =
        Command::new("git")
            .args(args)
            .output()
            .map_err(|source| WorkspaceExecError::GitSpawn {
                command: command.clone(),
                source,
            })?;
    if !output.status.success() {
        return Err(WorkspaceExecError::GitCommand {
            command,
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

#[cfg(unix)]
fn set_dir_mode(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
}

#[cfg(not(unix))]
fn set_dir_mode(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, AppPaths) {
        let tmp = TempDir::new().expect("temp dir");
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        (tmp, paths)
    }

    #[cfg(unix)]
    fn mode_of(p: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn prepare_creates_scratch_session_dir_with_0700() {
        let (_tmp, paths) = temp_paths();
        let prepared = prepare_scratch_cwd(&paths, "ws1", "sess1", "/home/u/myrepo").unwrap();

        assert_eq!(prepared.cwd, paths.scratch_base().join("sess1"));
        assert!(prepared.cwd.is_dir(), "scratch cwd must exist");
        assert_eq!(prepared.policy, WorkspacePolicy::ScratchCwd);
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&prepared.cwd), 0o700, "session dir must be 0700");
            assert_eq!(
                mode_of(&paths.scratch_base()),
                0o700,
                "scratch base must be 0700"
            );
            assert_eq!(mode_of(paths.base()), 0o700, "app base must be 0700");
        }
    }

    #[test]
    fn repeated_prepare_refuses_to_adopt_existing_session_directory() {
        let (_tmp, paths) = temp_paths();
        let first = prepare_scratch_cwd(&paths, "ws1", "sess1", "").unwrap();
        let again = prepare_scratch_cwd(&paths, "ws1", "sess1", "");
        assert!(matches!(
            again,
            Err(WorkspaceExecError::FreshScratchCwdAlreadyExists { cwd })
                if cwd == first.cwd
        ));
        assert!(first.cwd.is_dir());
        #[cfg(unix)]
        assert_eq!(mode_of(&first.cwd), 0o700);
    }

    #[test]
    fn fresh_prepare_is_exclusive_and_receipt_is_non_clone_redacted() {
        trait AmbiguousIfClone<Marker> {
            fn assert_not_clone() {}
        }
        impl<T> AmbiguousIfClone<()> for T {}
        impl<T: Clone> AmbiguousIfClone<u8> for T {}
        let _ = <FreshScratchCwdReceipt as AmbiguousIfClone<_>>::assert_not_clone;
        let _ = <FreshScratchCwdPreparation as AmbiguousIfClone<_>>::assert_not_clone;
        let _ = <PreparedSessionSpec as AmbiguousIfClone<_>>::assert_not_clone;

        let (_tmp, paths) = temp_paths();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let paths = paths.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                prepare_fresh_scratch_cwd(&paths, "ws1", "sess1", "")
            }));
        }
        barrier.wait();

        let mut winner = None;
        let mut conflict_count = 0;
        for handle in handles {
            match handle.join().expect("fresh prepare thread") {
                Ok(preparation) => {
                    assert!(winner.replace(preparation).is_none(), "only one winner");
                }
                Err(WorkspaceExecError::FreshScratchCwdAlreadyExists { cwd }) => {
                    assert_eq!(cwd, paths.scratch_base().join("sess1"));
                    conflict_count += 1;
                }
                Err(other) => panic!("unexpected fresh prepare result: {other:?}"),
            }
        }
        assert_eq!(conflict_count, 1);
        let (prepared, receipt) = winner.expect("one exclusive winner").into_parts();
        let debug = format!("{receipt:?}");
        assert!(debug.contains("sess1"));
        assert!(!debug.contains(prepared.cwd.to_string_lossy().as_ref()));
        assert_eq!(
            cleanup_fresh_scratch_cwd(&paths, receipt).unwrap(),
            FreshScratchCwdCleanupOutcome::Removed
        );
        assert!(!prepared.cwd.exists());
    }

    struct PreparedLaunchEnv;

    impl LaunchEnvLookup for PreparedLaunchEnv {
        fn shell_utf8(&self) -> Option<String> {
            Some("/bin/prepared-shell".into())
        }

        fn home_os(&self) -> Option<std::ffi::OsString> {
            None
        }
    }

    #[test]
    fn provider_session_spec_keeps_source_metadata_separate_from_private_wire_bytes() {
        let cwd = TempDir::new().unwrap();
        let prepared = PreparedWorkspace::unsealed(
            WorkspacePolicy::ScratchCwd,
            "provider-ws",
            "provider-session",
            cwd.path(),
        );
        let source = vec!["claude".into(), "--model".into(), "opus".into()];
        let spec = prepared
            .provider_session_spec("claude", &source, &PreparedLaunchEnv, 80, 24, 10)
            .unwrap();
        assert_eq!(spec.params.kind, SessionKind::Agent);
        assert_eq!(spec.params.command, "/bin/prepared-shell");
        assert_eq!(spec.params.args.first().map(String::as_str), Some("-lic"));
        assert!(matches!(
            &spec.params.launch,
            LaunchSpec::AdHocRedacted {
                argv,
                redacted: true,
                restart_requires_user: true,
            } if argv == &source
        ));
        assert_eq!(spec.binding, PreparedSessionBinding::AgentAdHocLoginShell);
        assert_eq!(spec.publication_launch, spec.params.launch);
        assert!(!crate::known_safe_provider_has_exact_resume(
            &spec.publication_launch
        ));
        let debug = format!("{spec:?}");
        assert!(!debug.contains("opus"));
        assert!(!debug.contains("prepared-shell"));

        assert!(matches!(
            prepared.provider_session_spec(
                "claude",
                &[
                    "claude".into(),
                    "--resume=bad".into(),
                    "--api-key".into(),
                    "secret-value".into(),
                ],
                &PreparedLaunchEnv,
                80,
                24,
                10,
            ),
            Err(WorkspaceExecError::InvalidPreparedSessionSpec)
        ));
    }

    #[test]
    fn explicit_nonexact_provider_selector_publishes_only_user_restart_authority() {
        let cwd = TempDir::new().unwrap();
        let prepared = PreparedWorkspace::unsealed(
            WorkspacePolicy::ScratchCwd,
            "provider-latest-ws",
            "provider-latest-session",
            cwd.path(),
        );
        let source = vec![
            "claude".into(),
            "--continue".into(),
            "--model".into(),
            "opus".into(),
        ];
        let spec = prepared
            .provider_session_spec("claude", &source, &PreparedLaunchEnv, 80, 24, 10)
            .expect("explicit latest selector must retain bounded user restart authority");
        assert_eq!(
            spec.binding,
            PreparedSessionBinding::ProviderExplicitNonExact
        );
        assert_eq!(
            spec.publication_launch,
            LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: vec!["--continue".into(), "--model".into(), "opus".into()],
            }
        );
        assert!(!crate::known_safe_provider_has_exact_resume(
            &spec.publication_launch
        ));
        assert_ne!(spec.params.launch, spec.publication_launch);
    }

    #[test]
    fn claude_assigned_identity_transitions_create_argv_to_exact_resume_publication() {
        const UUID: &str = "01234567-89ab-4def-8123-456789abcdef";
        let cwd = TempDir::new().unwrap();
        let prepared = PreparedWorkspace::unsealed(
            WorkspacePolicy::ScratchCwd,
            "claude-assigned-ws",
            "claude-assigned-session",
            cwd.path(),
        );
        let source = vec![
            "claude".into(),
            "--model".into(),
            "opus".into(),
            "--dangerously-skip-permissions".into(),
            "--session-id".into(),
            UUID.into(),
        ];
        let spec = prepared
            .provider_session_spec("claude", &source, &PreparedLaunchEnv, 80, 24, 10)
            .expect("Hydra-assigned Claude identity must seal as a provider transition");

        assert_eq!(spec.binding, PreparedSessionBinding::ProviderTransition);
        assert!(matches!(
            &spec.params.launch,
            LaunchSpec::AdHocRedacted {
                argv,
                redacted: true,
                restart_requires_user: true,
            } if argv == &[
                "claude".to_string(),
                "--model".to_string(),
                "opus".to_string(),
                "--dangerously-skip-permissions".to_string(),
                "--session-id".to_string(),
                "<redacted>".to_string(),
            ]
        ));
        assert!(spec.params.args.iter().any(|arg| arg.contains(UUID)));
        assert_eq!(
            spec.publication_launch,
            LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: vec![
                    "--model".into(),
                    "opus".into(),
                    "--dangerously-skip-permissions".into(),
                    "--resume".into(),
                    UUID.into(),
                ],
            }
        );
        assert!(crate::known_safe_provider_has_exact_resume(
            &spec.publication_launch
        ));
        assert_ne!(spec.params.launch, spec.publication_launch);
    }

    #[test]
    fn gemini_assigned_identity_transitions_create_argv_to_exact_resume_publication() {
        const UUID: &str = "01234567-89ab-4def-8123-456789abcdef";
        let cwd = TempDir::new().unwrap();
        let prepared = PreparedWorkspace::unsealed(
            WorkspacePolicy::ScratchCwd,
            "gemini-assigned-ws",
            "gemini-assigned-session",
            cwd.path(),
        );
        let source = vec![
            "gemini".into(),
            "--model".into(),
            "pro".into(),
            "--yolo".into(),
            "--session-id".into(),
            UUID.into(),
        ];
        let spec = prepared
            .provider_session_spec("gemini", &source, &PreparedLaunchEnv, 80, 24, 10)
            .expect("Hydra-assigned Gemini identity must seal as a provider transition");

        assert_eq!(spec.binding, PreparedSessionBinding::ProviderTransition);
        assert!(spec.params.args.iter().any(|arg| arg.contains(UUID)));
        assert_eq!(
            spec.publication_launch,
            LaunchSpec::KnownSafe {
                launch_spec_id: "gemini".into(),
                params: vec![
                    "--model".into(),
                    "pro".into(),
                    "--yolo".into(),
                    "--resume".into(),
                    UUID.into(),
                ],
            }
        );
        assert!(crate::known_safe_provider_has_exact_resume(
            &spec.publication_launch
        ));
        assert_ne!(spec.params.launch, spec.publication_launch);
    }

    #[test]
    fn exact_provider_spec_uses_one_canonical_known_safe_recipe_for_a_and_b() {
        const UUID: &str = "01234567-89ab-4def-8123-456789abcdef";
        let cwd = TempDir::new().unwrap();
        let prepared = PreparedWorkspace::unsealed(
            WorkspacePolicy::ScratchCwd,
            "provider-exact-ws",
            "provider-exact-session",
            cwd.path(),
        );
        let spec = prepared
            .provider_session_spec(
                "claude",
                &["claude".into(), "--resume".into(), UUID.into()],
                &PreparedLaunchEnv,
                80,
                24,
                10,
            )
            .unwrap();
        assert_eq!(spec.binding, PreparedSessionBinding::ProviderExact);
        assert_eq!(spec.params.launch, spec.publication_launch);
        assert!(crate::known_safe_provider_has_exact_resume(
            &spec.publication_launch
        ));
    }

    #[test]
    fn custom_provider_word_agent_stays_redacted_adhoc_across_startup_canonicalization() {
        let cwd = TempDir::new().unwrap();
        let prepared = PreparedWorkspace::unsealed(
            WorkspacePolicy::ScratchCwd,
            "provider-custom-ws",
            "provider-custom-session",
            cwd.path(),
        );
        let source = vec![
            "claude".into(),
            "mcp".into(),
            "--api-key".into(),
            "secret-value-123456789".into(),
        ];
        let spec = prepared
            .provider_custom_adhoc_session_spec("claude", &source, &PreparedLaunchEnv, 80, 24, 10)
            .unwrap();
        assert_eq!(spec.binding, PreparedSessionBinding::AgentAdHocLoginShell);
        assert_eq!(spec.params.command, "/bin/prepared-shell");
        assert_eq!(spec.params.args.first().map(String::as_str), Some("-lic"));
        assert_eq!(spec.params.launch, spec.publication_launch);
        let LaunchSpec::AdHocRedacted {
            argv,
            redacted,
            restart_requires_user,
        } = &spec.params.launch
        else {
            panic!("custom provider-word launch must remain AdHoc")
        };
        assert!(*redacted && *restart_requires_user);
        assert_eq!(argv[0], "claude");
        assert!(argv.iter().any(|value| value == "<redacted>"));
        assert!(!format!("{argv:?}").contains("secret-value"));
        assert_eq!(
            crate::canonical_launch_for_restart(&spec.params.launch),
            spec.params.launch
        );
        let debug = format!("{spec:?}");
        assert!(!debug.contains("secret-value"));
        assert!(!debug.contains("prepared-shell"));
    }

    #[test]
    fn malformed_provider_selector_shapes_never_downgrade_to_custom_adhoc() {
        let cwd = TempDir::new().unwrap();
        let prepared = PreparedWorkspace::unsealed(
            WorkspacePolicy::ScratchCwd,
            "provider-selector-ws",
            "provider-selector-session",
            cwd.path(),
        );
        for (provider, malformed) in [
            ("claude", "--continue=foreign"),
            ("claude", "--session-id=foreign"),
            ("codex", "resume=foreign"),
            ("codex", "--continue=foreign"),
            ("opencode", "--continue=foreign"),
            ("copilot", "--continue=foreign"),
            ("copilot", "-r=foreign"),
            ("copilot", "--connect=foreign"),
            ("agy", "--continue=foreign"),
            ("kimi", "--continue=foreign"),
            ("kiro-cli", "--resume=foreign"),
            ("agent", "--continue=foreign"),
            ("devin", "--continue=foreign"),
            ("amp", "threads=foreign"),
        ] {
            let source = vec![provider.to_string(), malformed.to_string()];
            assert!(
                prepared
                    .provider_custom_adhoc_session_spec(
                        provider,
                        &source,
                        &PreparedLaunchEnv,
                        80,
                        24,
                        10,
                    )
                    .is_err(),
                "selector-shaped malformed source must not downgrade: {source:?}"
            );
        }
    }

    #[test]
    fn fresh_prepare_never_adopts_or_deletes_preexisting_content() {
        let (_tmp, paths) = temp_paths();
        let cwd = paths.scratch_base().join("sess1");
        fs::create_dir_all(&cwd).unwrap();
        let sentinel = cwd.join("keep.txt");
        fs::write(&sentinel, b"owned by an earlier lifetime").unwrap();

        let result = prepare_fresh_scratch_cwd(&paths, "ws1", "sess1", "");
        assert!(matches!(
            result,
            Err(WorkspaceExecError::FreshScratchCwdAlreadyExists { cwd: found })
                if found == cwd
        ));
        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"owned by an earlier lifetime"
        );
    }

    #[test]
    fn fresh_cleanup_is_exact_non_recursive_and_consumes_wrong_paths() {
        let (_tmp, paths) = temp_paths();
        let preparation = prepare_fresh_scratch_cwd(&paths, "ws1", "sess1", "").unwrap();
        let (prepared, receipt) = preparation.into_parts();
        let sentinel = prepared.cwd.join("keep.txt");
        fs::write(&sentinel, b"unexpected owner").unwrap();
        assert_eq!(
            cleanup_fresh_scratch_cwd(&paths, receipt).unwrap(),
            FreshScratchCwdCleanupOutcome::RetainedNotEmpty
        );
        assert_eq!(fs::read(&sentinel).unwrap(), b"unexpected owner");

        let other = AppPaths::with_base(paths.base().with_extension("other"));
        let (_, wrong_paths_receipt) = prepare_fresh_scratch_cwd(&paths, "ws1", "sess2", "")
            .unwrap()
            .into_parts();
        assert!(matches!(
            cleanup_fresh_scratch_cwd(&other, wrong_paths_receipt),
            Err(WorkspaceExecError::FreshScratchCwdReceiptMismatch)
        ));
        assert!(paths.scratch_base().join("sess2").is_dir());
    }

    #[test]
    fn fresh_cleanup_retains_directory_when_same_id_durable_namespace_is_in_use() {
        let (_tmp, paths) = temp_paths();
        let (prepared, receipt) = prepare_fresh_scratch_cwd(&paths, "ws1", "sess1", "")
            .unwrap()
            .into_parts();
        {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let conn = arc.lock().unwrap();
            conn.execute(
                "INSERT INTO projects (
                     project_id, name, root, default_workspace_policy, created_at_ms,
                     last_active_at_ms, directories_json, window_order_json, system, hidden
                 ) VALUES ('p1','P','/tmp','scratch_cwd',1,1,'[]','[]',0,0)",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO workspaces (workspace_id, project_id, root, policy, consent_json)
                 VALUES ('ws1','p1','/tmp','scratch_cwd','{}')",
                [],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO sessions (
                     session_id, workspace_id, kind, launch_json, cwd_resolved, agent_task_id,
                     created_at_ms, last_attached_at_ms, last_known_generation, status
                 ) VALUES ('sess1','ws1','shell','\"opt_out\"',?1,NULL,1,1,NULL,'unknown')",
                [prepared.cwd.to_string_lossy().as_ref()],
            )
            .unwrap();
        }

        assert_eq!(
            cleanup_fresh_scratch_cwd(&paths, receipt).unwrap(),
            FreshScratchCwdCleanupOutcome::RetainedNamespaceInUse
        );
        assert!(prepared.cwd.is_dir());
    }

    #[test]
    fn unsafe_session_id_fails_before_creating_anything() {
        let (_tmp, paths) = temp_paths();
        for bad in ["../escape", "..", "a/b", "/abs", "a b", ""] {
            let r = prepare_scratch_cwd(&paths, "ws1", bad, "/home/u/r");
            assert!(
                matches!(r, Err(WorkspaceExecError::Id(_))),
                "id {bad:?} must fail with Id error, got {r:?}"
            );
        }
        // NOTHING was created — not even the base or scratch base.
        assert!(
            !paths.base().exists(),
            "no directory may exist after rejected ids"
        );
    }

    #[test]
    fn prepared_cwd_stays_under_scratch_base() {
        let (_tmp, paths) = temp_paths();
        let prepared = prepare_scratch_cwd(&paths, "ws1", "sess-1_A", "/home/u/r").unwrap();
        assert!(prepared.cwd.starts_with(paths.scratch_base()));
        // Exactly one component below the scratch base (the validated session id).
        assert_eq!(
            prepared.cwd.parent().unwrap(),
            paths.scratch_base().as_path()
        );
    }

    #[test]
    fn creates_nothing_under_supplied_repo_root() {
        let (_tmp, paths) = temp_paths();
        let repo = TempDir::new().expect("repo dir");
        let prepared = prepare_scratch_cwd(
            &paths,
            "ws1",
            "sess1",
            repo.path().to_str().expect("utf8 temp path"),
        )
        .unwrap();
        assert!(!prepared.cwd.starts_with(repo.path()));
        // The repo root stays completely empty.
        let entries: Vec<_> = fs::read_dir(repo.path()).unwrap().collect();
        assert!(
            entries.is_empty(),
            "repo root must remain empty, found {entries:?}"
        );
    }

    #[test]
    fn repo_root_containing_app_support_is_refused_and_creates_nothing() {
        // UNUSUAL: the supplied repo root is an ancestor of the app-support tree, so the
        // scratch cwd would lexically sit "under the repo root". Refused, nothing created.
        let (tmp, paths) = temp_paths();
        let repo_root = tmp.path().to_str().expect("utf8 temp path");
        let r = prepare_scratch_cwd(&paths, "ws1", "sess1", repo_root);
        assert!(
            matches!(r, Err(WorkspaceExecError::ScratchUnderRepoRoot { .. })),
            "ancestor repo root must be refused, got {r:?}"
        );
        assert!(!paths.base().exists(), "nothing may be created on refusal");
    }

    #[test]
    fn repo_root_inside_scratch_base_is_the_allowed_unusual_containment() {
        // UNUSUAL but allowed: a repo root INSIDE the scratch base. "Under the repo root" then
        // coincides with "under scratch", which is shell-owned territory; prepare proceeds and
        // the result is still under the scratch base.
        let (_tmp, paths) = temp_paths();
        let repo_root = paths.scratch_base();
        let prepared = prepare_scratch_cwd(
            &paths,
            "ws1",
            "sess1",
            repo_root.to_str().expect("utf8 path"),
        )
        .unwrap();
        assert!(prepared.cwd.starts_with(paths.scratch_base()));
    }

    #[test]
    fn worktree_and_repo_write_are_rejected_by_generic_api() {
        let (_tmp, paths) = temp_paths();
        for policy in [WorkspacePolicy::Worktree, WorkspacePolicy::RepoWrite] {
            let r = prepare_workspace(&paths, policy, "ws1", "sess1", "/home/u/r");
            assert!(
                matches!(r, Err(WorkspaceExecError::UnsupportedPolicy { policy: p }) if p == policy),
                "{policy:?} must be UnsupportedPolicy, got {r:?}"
            );
        }
        // Rejection creates nothing — no worktree base, no scratch, no app base.
        assert!(!paths.worktree_base().exists());
        assert!(!paths.base().exists());
    }

    #[test]
    fn generic_api_executes_scratch_cwd() {
        let (_tmp, paths) = temp_paths();
        let prepared = prepare_workspace(
            &paths,
            WorkspacePolicy::ScratchCwd,
            "ws1",
            "sess1",
            "/home/u/r",
        )
        .unwrap();
        assert!(prepared.cwd.is_dir());
        assert!(prepared.cwd.starts_with(paths.scratch_base()));
    }

    fn test_workspace(consent: crate::records::WorkspaceConsent) -> Workspace {
        Workspace {
            workspace_id: "ws1".into(),
            project_id: "proj-1".into(),
            root: "/home/u/myrepo".into(),
            policy: WorkspacePolicy::ScratchCwd,
            consent,
        }
    }

    fn no_consent() -> crate::records::WorkspaceConsent {
        crate::records::WorkspaceConsent {
            worktree_create: false,
            repo_write: false,
            granted_at_ms: None,
        }
    }

    fn full_consent() -> crate::records::WorkspaceConsent {
        crate::records::WorkspaceConsent {
            worktree_create: true,
            repo_write: true,
            granted_at_ms: Some(1),
        }
    }

    #[test]
    fn with_consent_scratch_cwd_executes_without_any_grant() {
        let (_tmp, paths) = temp_paths();
        let ws = test_workspace(no_consent());
        let prepared =
            prepare_workspace_with_consent(&paths, WorkspacePolicy::ScratchCwd, &ws, "sess1")
                .unwrap();
        assert!(prepared.cwd.is_dir());
        assert!(prepared.cwd.starts_with(paths.scratch_base()));
        assert_eq!(prepared.workspace_id, "ws1");
    }

    #[test]
    fn with_consent_repo_affecting_policies_fail_consent_first_when_ungranted() {
        let (_tmp, paths) = temp_paths();
        let ws = test_workspace(no_consent());
        for policy in [WorkspacePolicy::Worktree, WorkspacePolicy::RepoWrite] {
            let r = prepare_workspace_with_consent(&paths, policy, &ws, "sess1");
            assert!(
                matches!(r, Err(WorkspaceExecError::Consent(_))),
                "{policy:?} ungranted must fail at the consent gate, got {r:?}"
            );
        }
        assert!(
            !paths.base().exists(),
            "consent failure must create nothing"
        );
    }

    // ---- RepoWrite execution — verification only, NO git, temp dirs only ----

    fn repo_write_consent() -> crate::records::WorkspaceConsent {
        crate::records::WorkspaceConsent {
            worktree_create: false,
            repo_write: true,
            granted_at_ms: Some(1),
        }
    }

    fn repo_write_workspace(root: &str, consent: crate::records::WorkspaceConsent) -> Workspace {
        Workspace {
            workspace_id: "ws1".into(),
            project_id: "proj-1".into(),
            root: root.into(),
            policy: WorkspacePolicy::RepoWrite,
            consent,
        }
    }

    #[test]
    fn with_consent_granted_repo_write_returns_repo_root_verbatim_and_mutates_nothing() {
        let (_tmp, paths) = temp_paths();
        // A PLAIN directory, deliberately not a git repo: RepoWrite preparation must not need
        // (or run) git, so a non-repo root succeeds — a NotAGitRepo error here would prove git
        // ran.
        let root = TempDir::new().expect("root dir");
        let root_str = root.path().to_str().expect("utf8 temp path");
        let ws = repo_write_workspace(root_str, repo_write_consent());

        let prepared =
            prepare_workspace_with_consent(&paths, WorkspacePolicy::RepoWrite, &ws, "sess1")
                .unwrap();

        assert_eq!(prepared.policy, WorkspacePolicy::RepoWrite);
        assert_eq!(prepared.workspace_id, "ws1");
        assert_eq!(prepared.session_id, "sess1");
        assert_eq!(
            prepared.cwd,
            PathBuf::from(root_str),
            "cwd must be exactly the repo root"
        );
        // NOTHING was created, deleted, or chmodded: the root stays empty with its original
        // mode, and no app-support tree appears.
        assert!(top_level_names(root.path()).is_empty());
        assert!(!paths.base().exists());
        assert!(!paths.scratch_base().exists());
        assert!(!paths.worktree_base().exists());
        #[cfg(unix)]
        {
            let before = mode_of(root.path());
            // Prepare again; the mode is untouched both times (no set_dir_mode on user dirs).
            prepare_workspace_with_consent(&paths, WorkspacePolicy::RepoWrite, &ws, "sess1")
                .unwrap();
            assert_eq!(mode_of(root.path()), before, "root mode must not change");
        }
    }

    #[test]
    fn repo_write_missing_root_is_typed_error_and_creates_nothing() {
        let (_tmp, paths) = temp_paths();
        let gone = TempDir::new().expect("dir");
        let missing = gone.path().join("does-not-exist");
        let ws = repo_write_workspace(missing.to_str().unwrap(), repo_write_consent());

        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::RepoWrite, &ws, "sess1");
        match r {
            Err(WorkspaceExecError::RepoRootNotDirectory { root }) => assert_eq!(root, missing),
            other => panic!("missing root must be RepoRootNotDirectory, got {other:?}"),
        }
        assert!(!missing.exists(), "the missing root must NOT be created");
        assert!(!paths.base().exists(), "nothing may be created");
    }

    #[test]
    fn repo_write_file_root_is_typed_error_and_leaves_the_file_intact() {
        let (_tmp, paths) = temp_paths();
        let dir = TempDir::new().expect("dir");
        let file_root = dir.path().join("not-a-dir.txt");
        fs::write(&file_root, "plain file\n").unwrap();
        let ws = repo_write_workspace(file_root.to_str().unwrap(), repo_write_consent());

        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::RepoWrite, &ws, "sess1");
        match r {
            Err(WorkspaceExecError::RepoRootNotDirectory { root }) => assert_eq!(root, file_root),
            other => panic!("file root must be RepoRootNotDirectory, got {other:?}"),
        }
        assert_eq!(fs::read_to_string(&file_root).unwrap(), "plain file\n");
        assert!(!paths.base().exists(), "nothing may be created");
    }

    #[test]
    fn repo_write_ungranted_fails_consent_first_even_with_a_valid_root() {
        // Root EXISTS and is valid: only the missing grant can fail, and it must do so before
        // any filesystem check (a RepoRootNotDirectory here would mean the order is wrong —
        // covered by the missing-root variant below).
        let (_tmp, paths) = temp_paths();
        let root = TempDir::new().expect("root dir");
        let ws = repo_write_workspace(root.path().to_str().unwrap(), no_consent());
        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::RepoWrite, &ws, "sess1");
        assert!(
            matches!(r, Err(WorkspaceExecError::Consent(_))),
            "ungranted RepoWrite must fail at the consent gate, got {r:?}"
        );
        assert!(
            !paths.base().exists(),
            "consent failure must create nothing"
        );

        // And with a MISSING root: consent still wins, proving it runs before the root check.
        let missing = root.path().join("nope");
        let ws = repo_write_workspace(missing.to_str().unwrap(), no_consent());
        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::RepoWrite, &ws, "sess1");
        assert!(
            matches!(r, Err(WorkspaceExecError::Consent(_))),
            "consent must be checked before the filesystem, got {r:?}"
        );
    }

    #[test]
    fn repo_write_unsafe_ids_fail_before_the_root_check() {
        let (_tmp, paths) = temp_paths();
        // Root is MISSING: if ids were checked after the root, we'd see RepoRootNotDirectory
        // instead of Id — so an Id error proves validation happened first.
        let dir = TempDir::new().expect("dir");
        let missing = dir.path().join("nope");

        let ws = repo_write_workspace(missing.to_str().unwrap(), repo_write_consent());
        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::RepoWrite, &ws, "../esc");
        assert!(
            matches!(r, Err(WorkspaceExecError::Id(_))),
            "unsafe session id must fail with Id error first, got {r:?}"
        );

        let mut bad_ws = repo_write_workspace(missing.to_str().unwrap(), repo_write_consent());
        bad_ws.workspace_id = "../escape".into();
        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::RepoWrite, &bad_ws, "s1");
        assert!(
            matches!(r, Err(WorkspaceExecError::Id(_))),
            "unsafe workspace id must fail with Id error first, got {r:?}"
        );
        assert!(!paths.base().exists(), "nothing may be created");
    }

    #[test]
    fn repo_write_prepared_cwd_flows_into_start_params() {
        let (_tmp, paths) = temp_paths();
        let root = TempDir::new().expect("root dir");
        let ws = repo_write_workspace(root.path().to_str().unwrap(), repo_write_consent());
        let prepared =
            prepare_workspace_with_consent(&paths, WorkspacePolicy::RepoWrite, &ws, "sess1")
                .unwrap();

        let argv = vec!["/bin/sh".to_string()];
        let params = prepared.adhoc_start_params(SessionKind::Shell, &argv, 80, 24, 7);
        assert_eq!(params.cwd, root.path().to_string_lossy());
        assert_eq!(params.session_id, "sess1");
        assert_eq!(params.workspace_id, "ws1");
        // The cwd really exists, so the daemon-side is_dir check would pass.
        assert!(PathBuf::from(&params.cwd).is_dir());
    }

    // ---- Worktree execution — git runs ONLY inside temp repositories ----

    /// Run git in a TEST temp repo, asserting success. Never pointed at the real repo.
    fn git(args: &[&str]) -> String {
        let out = Command::new("git").args(args).output().expect("spawn git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    /// A fresh throwaway repo with one commit (worktree add needs a HEAD). Identity is
    /// configured INSIDE the temp repo only — global git config is never touched.
    fn init_temp_repo() -> TempDir {
        let repo = TempDir::new().expect("repo dir");
        let r = repo.path().to_str().expect("utf8 temp path");
        git(&["-C", r, "init", "-q"]);
        git(&["-C", r, "config", "user.email", "maestro-test@example.com"]);
        git(&["-C", r, "config", "user.name", "Maestro Test"]);
        fs::write(repo.path().join("seed.txt"), "seed\n").expect("seed file");
        git(&["-C", r, "add", "seed.txt"]);
        git(&["-C", r, "commit", "-q", "-m", "seed"]);
        repo
    }

    fn worktree_consent() -> crate::records::WorkspaceConsent {
        crate::records::WorkspaceConsent {
            worktree_create: true,
            repo_write: false,
            granted_at_ms: Some(1),
        }
    }

    fn worktree_workspace(root: &Path, consent: crate::records::WorkspaceConsent) -> Workspace {
        Workspace {
            workspace_id: "ws1".into(),
            project_id: "proj-1".into(),
            root: root.to_str().expect("utf8 temp path").into(),
            policy: WorkspacePolicy::Worktree,
            consent,
        }
    }

    fn top_level_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn with_consent_granted_worktree_creates_real_git_worktree_under_app_support() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());

        let prepared =
            prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1")
                .unwrap();

        assert_eq!(prepared.policy, WorkspacePolicy::Worktree);
        assert_eq!(
            prepared.cwd,
            paths.worktree_base().join("ws1").join("sess1"),
            "cwd must equal the pure-resolved worktree path"
        );
        assert!(prepared.cwd.starts_with(paths.worktree_base()));
        assert!(prepared.cwd.is_dir());
        // It is a REAL linked worktree: the checkout is there and git agrees.
        assert!(prepared.cwd.join("seed.txt").is_file());
        let cwd = prepared.cwd.to_str().unwrap();
        assert_eq!(
            git(&["-C", cwd, "rev-parse", "--is-inside-work-tree"]),
            "true"
        );
        assert_eq!(
            git(&["-C", cwd, "symbolic-ref", "--short", "HEAD"]),
            "maestro/ws1/sess1"
        );
        // The user's checkout is untouched and Maestro wrote NO metadata into the repo root:
        // only git's own .git plus the original file remain.
        assert_eq!(top_level_names(repo.path()), vec![".git", "seed.txt"]);
        // The source repo's own HEAD was not switched to the maestro branch.
        assert_ne!(
            git(&[
                "-C",
                repo.path().to_str().unwrap(),
                "symbolic-ref",
                "--short",
                "HEAD"
            ]),
            "maestro/ws1/sess1"
        );
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&prepared.cwd), 0o700);
            assert_eq!(mode_of(&paths.worktree_base()), 0o700);
            assert_eq!(mode_of(paths.base()), 0o700);
        }
    }

    #[test]
    fn worktree_branch_is_deterministic_and_safe() {
        assert_eq!(worktree_branch("ws1", "sess1"), "maestro/ws1/sess1");
        assert_eq!(worktree_branch("ws-2_A", "s-3_B"), "maestro/ws-2_A/s-3_B");

        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());
        prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1").unwrap();
        // The deterministic ref really exists in the source repo.
        git(&[
            "-C",
            repo.path().to_str().unwrap(),
            "rev-parse",
            "--verify",
            "refs/heads/maestro/ws1/sess1",
        ]);
    }

    #[test]
    fn with_consent_worktree_prepare_is_idempotent_for_matching_worktree() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());

        let first = prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1")
            .unwrap();
        let again = prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1")
            .unwrap();
        assert_eq!(first, again, "matching worktree must be reused as-is");
        assert!(again.cwd.join("seed.txt").is_file());
    }

    fn load_provenance(
        paths: &AppPaths,
        session_id: &str,
    ) -> Option<crate::store::LoadOutcome<WorktreeProvenance>> {
        crate::store::load_one(paths, RecordKind::WorktreeProvenance, session_id).unwrap()
    }

    #[test]
    fn provenance_record_path_and_schema_are_distinct_and_stable() {
        assert_eq!(
            RecordKind::WorktreeProvenance.dir_name(),
            "worktree_provenance"
        );
        assert_eq!(
            RecordKind::WorktreeProvenance.schema(),
            "maestro.worktree_provenance"
        );
        let p = AppPaths::with_base("/base/Maestro")
            .record_path(RecordKind::WorktreeProvenance, "sess1")
            .unwrap();
        assert_eq!(
            p,
            std::path::PathBuf::from("/base/Maestro/worktree_provenance/sess1.json")
        );
    }

    #[test]
    fn provenance_write_load_round_trips() {
        let (_tmp, paths) = temp_paths();
        let record = WorktreeProvenance {
            workspace_id: "ws1".into(),
            session_id: "sess1".into(),
            repo_root: "/repo".into(),
            target_path: "/wt/ws1/sess1".into(),
            branch: "maestro/ws1/sess1".into(),
            created_at_ms: 42,
        };
        write_record(&paths, RecordKind::WorktreeProvenance, "sess1", 42, &record).unwrap();
        match load_provenance(&paths, "sess1") {
            Some(crate::store::LoadOutcome::Loaded(got)) => assert_eq!(got, record),
            other => panic!("expected Loaded provenance, got {other:?}"),
        }
    }

    #[test]
    fn prepare_worktree_writes_matching_provenance_marker_on_create() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());

        let prepared =
            prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1")
                .unwrap();

        let marker = match load_provenance(&paths, "sess1") {
            Some(crate::store::LoadOutcome::Loaded(m)) => m,
            other => panic!("expected a provenance marker after create, got {other:?}"),
        };
        assert_eq!(marker.workspace_id, "ws1");
        assert_eq!(marker.session_id, "sess1");
        assert_eq!(marker.branch, "maestro/ws1/sess1");
        // Canonical target path equals the canonicalized prepared cwd.
        assert_eq!(
            marker.target_path,
            fs::canonicalize(&prepared.cwd)
                .unwrap()
                .to_string_lossy()
                .into_owned()
        );
        assert_eq!(
            marker.repo_root,
            fs::canonicalize(repo.path())
                .unwrap()
                .to_string_lossy()
                .into_owned()
        );
    }

    #[test]
    fn only_actual_worktree_preparation_mints_session_provenance_authority() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());
        let prepared =
            prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1")
                .unwrap();
        let cwd = prepared.cwd.clone();
        let cloned_attempt = prepared.clone();
        let (_, _, _, actual_seal) = prepared
            .adhoc_session_spec(SessionKind::Shell, &["/bin/sh".into()], 80, 24, 1)
            .unwrap()
            .into_parts();
        assert!(actual_seal.is_some());
        assert!(matches!(
            cloned_attempt.adhoc_session_spec(SessionKind::Shell, &["/bin/sh".into()], 80, 24, 1,),
            Err(WorkspaceExecError::InvalidPreparedSessionSpec)
        ));

        let (_, _, _, unsealed) = PreparedWorkspace::unsealed(
            WorkspacePolicy::Worktree,
            ws.workspace_id.clone(),
            "sess1",
            cwd,
        )
        .adhoc_session_spec(SessionKind::Shell, &["/bin/sh".into()], 80, 24, 1)
        .unwrap()
        .into_parts();
        assert!(unsealed.is_none());
    }

    #[test]
    fn prepare_worktree_idempotent_reuse_leaves_matching_marker() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());

        prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1").unwrap();
        // Second prepare reuses the existing worktree; the marker must still be present + matching.
        prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1").unwrap();

        match load_provenance(&paths, "sess1") {
            Some(crate::store::LoadOutcome::Loaded(m)) => {
                assert_eq!(m.workspace_id, "ws1");
                assert_eq!(m.session_id, "sess1");
                assert_eq!(m.branch, "maestro/ws1/sess1");
            }
            other => panic!("expected a marker after idempotent reuse, got {other:?}"),
        }
    }

    #[test]
    fn with_consent_ungranted_worktree_on_real_repo_fails_consent_first_and_runs_no_git() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), no_consent());

        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1");
        assert!(
            matches!(r, Err(WorkspaceExecError::Consent(_))),
            "ungranted Worktree must fail at the consent gate, got {r:?}"
        );
        assert!(
            !paths.base().exists(),
            "consent failure must create nothing"
        );
        // No git ran: no maestro branch, no worktree registered.
        let branches = git(&[
            "-C",
            repo.path().to_str().unwrap(),
            "branch",
            "--list",
            "maestro/*",
        ]);
        assert!(branches.is_empty(), "no branch may exist, got {branches:?}");
    }

    #[test]
    fn worktree_unsafe_ids_fail_before_git_runs() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();

        // Unsafe session id.
        let ws = worktree_workspace(repo.path(), worktree_consent());
        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "../esc");
        assert!(
            matches!(r, Err(WorkspaceExecError::Id(_))),
            "unsafe session id must fail with Id error, got {r:?}"
        );

        // Unsafe workspace id (from the record itself).
        let mut bad_ws = worktree_workspace(repo.path(), worktree_consent());
        bad_ws.workspace_id = "../escape".into();
        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &bad_ws, "s1");
        assert!(
            matches!(r, Err(WorkspaceExecError::Id(_))),
            "unsafe workspace id must fail with Id error, got {r:?}"
        );

        // Nothing on disk, and no git mutation in the repo.
        assert!(!paths.base().exists());
        let branches = git(&[
            "-C",
            repo.path().to_str().unwrap(),
            "branch",
            "--list",
            "maestro/*",
        ]);
        assert!(branches.is_empty(), "no branch may exist, got {branches:?}");
    }

    #[test]
    fn with_consent_worktree_non_git_root_is_typed_error_and_creates_nothing() {
        let (_tmp, paths) = temp_paths();
        let not_a_repo = TempDir::new().expect("plain dir");
        let ws = worktree_workspace(not_a_repo.path(), worktree_consent());

        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1");
        assert!(
            matches!(r, Err(WorkspaceExecError::NotAGitRepo { .. })),
            "non-repo root must be NotAGitRepo, got {r:?}"
        );
        assert!(!paths.base().exists(), "nothing may be created");
        // The plain directory was not touched either.
        assert!(top_level_names(not_a_repo.path()).is_empty());
    }

    #[test]
    fn with_consent_worktree_nonempty_destination_is_typed_conflict_and_deletes_nothing() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());

        // Pre-existing foreign content at the resolved destination.
        let dest = paths.worktree_base().join("ws1").join("sess1");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("precious.txt"), "user data\n").unwrap();

        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1");
        assert!(
            matches!(r, Err(WorkspaceExecError::WorktreeConflict { .. })),
            "non-empty non-worktree destination must be WorktreeConflict, got {r:?}"
        );
        // NOTHING was deleted or overwritten.
        assert_eq!(
            fs::read_to_string(dest.join("precious.txt")).unwrap(),
            "user data\n"
        );
        assert_eq!(top_level_names(&dest), vec!["precious.txt"]);
    }

    #[test]
    fn with_consent_worktree_existing_empty_destination_is_populated() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());

        let dest = paths.worktree_base().join("ws1").join("sess1");
        fs::create_dir_all(&dest).unwrap();

        let prepared =
            prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1")
                .unwrap();
        assert_eq!(prepared.cwd, dest);
        assert!(prepared.cwd.join("seed.txt").is_file());
    }

    // ---- Worktree removal — git runs ONLY inside temp repositories ----

    /// Create the standard `ws1`/`sess1` worktree via the real consent-gated path.
    fn prepared_worktree(paths: &AppPaths, ws: &Workspace) -> PreparedWorkspace {
        prepare_workspace_with_consent(paths, WorkspacePolicy::Worktree, ws, "sess1").unwrap()
    }

    /// Worktree paths registered in `root` (`git worktree list --porcelain` lines).
    fn worktree_list(root: &Path) -> String {
        git(&[
            "-C",
            root.to_str().unwrap(),
            "worktree",
            "list",
            "--porcelain",
        ])
    }

    #[test]
    fn remove_ungranted_worktree_fails_consent_first_and_removes_nothing() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let granted = worktree_workspace(repo.path(), worktree_consent());
        let prepared = prepared_worktree(&paths, &granted);

        // Same workspace but WITHOUT the grant: removal must fail at the consent gate, before
        // policy/path/git, and the existing worktree must be fully intact.
        let ungranted = worktree_workspace(repo.path(), no_consent());
        let r = remove_worktree_with_consent(&paths, &ungranted, "sess1");
        assert!(
            matches!(r, Err(WorkspaceExecError::Consent(_))),
            "ungranted removal must fail consent-first, got {r:?}"
        );
        assert!(prepared.cwd.is_dir(), "worktree must still exist");
        assert!(prepared.cwd.join("seed.txt").is_file());
        assert!(worktree_list(repo.path()).contains("maestro/ws1/sess1"));
    }

    #[test]
    fn remove_clean_matching_worktree_removes_checkout_and_reports_path_and_branch() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());
        let prepared = prepared_worktree(&paths, &ws);
        assert!(prepared.cwd.is_dir());

        let removed = remove_worktree_with_consent(&paths, &ws, "sess1").unwrap();

        assert_eq!(
            removed.path, prepared.cwd,
            "result must carry the removed path"
        );
        assert_eq!(removed.branch, "maestro/ws1/sess1");
        assert_eq!(removed.workspace_id, "ws1");
        assert_eq!(removed.session_id, "sess1");
        assert!(!prepared.cwd.exists(), "checkout must be gone");
        // Git agrees the worktree is unregistered.
        assert!(!worktree_list(repo.path()).contains("sess1"));
        // The source repo's own checkout is untouched.
        assert_eq!(top_level_names(repo.path()), vec![".git", "seed.txt"]);
        // The BRANCH is NOT deleted — only the checkout was removed.
        git(&[
            "-C",
            repo.path().to_str().unwrap(),
            "rev-parse",
            "--verify",
            "refs/heads/maestro/ws1/sess1",
        ]);
    }

    #[test]
    fn remove_dirty_worktree_is_git_command_error_and_leaves_files_intact() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());
        let prepared = prepared_worktree(&paths, &ws);

        // Make the worktree dirty: an untracked file makes `git worktree remove` (no --force)
        // refuse.
        let dirty = prepared.cwd.join("unsaved-work.txt");
        fs::write(&dirty, "do not lose me\n").unwrap();

        let r = remove_worktree_with_consent(&paths, &ws, "sess1");
        assert!(
            matches!(r, Err(WorkspaceExecError::GitCommand { .. })),
            "dirty worktree must surface git's refusal, got {r:?}"
        );
        assert!(prepared.cwd.is_dir(), "worktree must still exist");
        assert_eq!(
            fs::read_to_string(&dirty).unwrap(),
            "do not lose me\n",
            "dirty file must be intact"
        );
        assert!(prepared.cwd.join("seed.txt").is_file());
    }

    #[test]
    fn remove_foreign_content_destination_is_conflict_and_deletes_nothing() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());

        // Foreign (non-worktree) content at the exact resolved destination.
        let dest = paths.worktree_base().join("ws1").join("sess1");
        fs::create_dir_all(&dest).unwrap();
        fs::write(dest.join("precious.txt"), "user data\n").unwrap();

        let r = remove_worktree_with_consent(&paths, &ws, "sess1");
        assert!(
            matches!(r, Err(WorkspaceExecError::WorktreeConflict { .. })),
            "foreign content must be WorktreeConflict, got {r:?}"
        );
        assert_eq!(
            fs::read_to_string(dest.join("precious.txt")).unwrap(),
            "user data\n"
        );
        assert_eq!(top_level_names(&dest), vec!["precious.txt"]);
    }

    #[test]
    fn remove_worktree_of_another_repo_is_conflict_and_deletes_nothing() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let other_repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());

        // A worktree at the EXPECTED path with the EXPECTED branch name — but of ANOTHER repo.
        let dest = paths.worktree_base().join("ws1").join("sess1");
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        git(&[
            "-C",
            other_repo.path().to_str().unwrap(),
            "worktree",
            "add",
            dest.to_str().unwrap(),
            "-b",
            "maestro/ws1/sess1",
        ]);

        let r = remove_worktree_with_consent(&paths, &ws, "sess1");
        assert!(
            matches!(r, Err(WorkspaceExecError::WorktreeConflict { .. })),
            "another repo's worktree must be WorktreeConflict, got {r:?}"
        );
        assert!(dest.is_dir(), "foreign worktree must still exist");
        assert!(dest.join("seed.txt").is_file());
        assert!(worktree_list(other_repo.path()).contains("maestro/ws1/sess1"));
    }

    #[test]
    fn remove_worktree_on_another_branch_is_conflict_and_deletes_nothing() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());

        // A worktree of the RIGHT repo at the RIGHT path — but on the WRONG branch.
        let dest = paths.worktree_base().join("ws1").join("sess1");
        fs::create_dir_all(dest.parent().unwrap()).unwrap();
        git(&[
            "-C",
            repo.path().to_str().unwrap(),
            "worktree",
            "add",
            dest.to_str().unwrap(),
            "-b",
            "not-maestro-branch",
        ]);

        let r = remove_worktree_with_consent(&paths, &ws, "sess1");
        assert!(
            matches!(r, Err(WorkspaceExecError::WorktreeConflict { .. })),
            "wrong-branch worktree must be WorktreeConflict, got {r:?}"
        );
        assert!(dest.is_dir(), "wrong-branch worktree must still exist");
        assert!(dest.join("seed.txt").is_file());
        assert!(worktree_list(repo.path()).contains("not-maestro-branch"));
    }

    #[test]
    fn remove_missing_destination_is_typed_missing_error_and_deletes_nothing() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());

        let r = remove_worktree_with_consent(&paths, &ws, "sess1");
        let expected = paths.worktree_base().join("ws1").join("sess1");
        match r {
            Err(WorkspaceExecError::WorktreeMissing { path }) => assert_eq!(path, expected),
            other => panic!("missing destination must be WorktreeMissing, got {other:?}"),
        }
        // Nothing created, repo untouched.
        assert!(!paths.base().exists());
        assert_eq!(top_level_names(repo.path()), vec![".git", "seed.txt"]);
    }

    #[test]
    fn remove_unsafe_ids_fail_before_git_runs() {
        let (_tmp, paths) = temp_paths();
        // Root is NOT a repo: if ids failed AFTER the repo check, we'd see NotAGitRepo instead
        // of Id — so an Id error proves validation happened before any git command.
        let not_a_repo = TempDir::new().expect("plain dir");

        let ws = worktree_workspace(not_a_repo.path(), worktree_consent());
        let r = remove_worktree_with_consent(&paths, &ws, "../esc");
        assert!(
            matches!(r, Err(WorkspaceExecError::Id(_))),
            "unsafe session id must fail with Id error before git, got {r:?}"
        );

        let mut bad_ws = worktree_workspace(not_a_repo.path(), worktree_consent());
        bad_ws.workspace_id = "../escape".into();
        let r = remove_worktree_with_consent(&paths, &bad_ws, "s1");
        assert!(
            matches!(r, Err(WorkspaceExecError::Id(_))),
            "unsafe workspace id must fail with Id error before git, got {r:?}"
        );

        assert!(!paths.base().exists(), "nothing may be created");
        assert!(top_level_names(not_a_repo.path()).is_empty());
    }

    #[test]
    fn remove_non_worktree_policy_is_unsupported_even_with_consent_and_deletes_nothing() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();

        // Create a real worktree first so there IS something a buggy implementation could
        // delete.
        let good = worktree_workspace(repo.path(), worktree_consent());
        let prepared = prepared_worktree(&paths, &good);

        // ScratchCwd and RepoWrite records — even with FULL consent — have no removal path.
        for policy in [WorkspacePolicy::ScratchCwd, WorkspacePolicy::RepoWrite] {
            let mut ws = worktree_workspace(repo.path(), full_consent());
            ws.policy = policy;
            let r = remove_worktree_with_consent(&paths, &ws, "sess1");
            assert!(
                matches!(r, Err(WorkspaceExecError::UnsupportedPolicy { policy: p }) if p == policy),
                "{policy:?} must be UnsupportedPolicy, got {r:?}"
            );
        }
        assert!(prepared.cwd.is_dir(), "worktree must still exist");
        assert!(prepared.cwd.join("seed.txt").is_file());
    }

    #[test]
    fn remove_then_prepare_recreates_worktree_on_existing_branch() {
        // Lifecycle round-trip: create -> remove -> create again. The branch survives removal,
        // and the second prepare must still work (git reuses the surviving branch via -b only
        // when absent — here `worktree add -b` would fail on the existing branch, so this test
        // documents the CURRENT contract: re-prepare after remove surfaces git's own error
        // rather than silently force-recreating).
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());

        let first = prepared_worktree(&paths, &ws);
        remove_worktree_with_consent(&paths, &ws, "sess1").unwrap();
        assert!(!first.cwd.exists());

        let r = prepare_workspace_with_consent(&paths, WorkspacePolicy::Worktree, &ws, "sess1");
        assert!(
            matches!(r, Err(WorkspaceExecError::GitCommand { .. })),
            "re-prepare on a surviving branch surfaces git's -b refusal, got {r:?}"
        );
    }

    #[test]
    fn adhoc_start_params_pairs_prepared_cwd_with_its_ids() {
        let (_tmp, paths) = temp_paths();
        let prepared = prepare_scratch_cwd(&paths, "ws-9", "sess-9", "").unwrap();
        let argv = vec!["/bin/zsh".to_string(), "-l".to_string()];
        let params = prepared.adhoc_start_params(SessionKind::Shell, &argv, 120, 32, 42);

        assert_eq!(params.session_id, "sess-9");
        assert_eq!(params.workspace_id, "ws-9");
        assert_eq!(params.cwd, prepared.cwd.to_string_lossy());
        assert_eq!(params.command, "/bin/zsh");
        assert_eq!(params.args, vec!["-l".to_string()]);
        assert_eq!((params.cols, params.rows, params.now_ms), (120, 32, 42));
        // The prepared cwd really exists, so the daemon-side is_dir check would pass.
        assert!(PathBuf::from(&params.cwd).is_dir());
    }

    // ---- Read-only porcelain parser (pure) ----

    #[test]
    fn porcelain_parses_multiple_worktrees_with_branch_lines() {
        let out = "worktree /repo\nHEAD abc123\nbranch refs/heads/main\n\nworktree /repo/wt-a\nHEAD def456\nbranch refs/heads/maestro/ws1/sess1\n";
        let parsed = parse_worktree_porcelain(out);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].path, PathBuf::from("/repo"));
        assert_eq!(parsed[0].branch.as_deref(), Some("main"));
        assert_eq!(parsed[1].path, PathBuf::from("/repo/wt-a"));
        assert_eq!(parsed[1].branch.as_deref(), Some("maestro/ws1/sess1"));
        assert!(!parsed[1].locked && !parsed[1].prunable);
    }

    #[test]
    fn porcelain_detached_and_bare_have_no_branch() {
        let out = "worktree /repo\nbare\n\nworktree /repo/wt-d\nHEAD abc123\ndetached\n";
        let parsed = parse_worktree_porcelain(out);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].branch, None);
        assert_eq!(parsed[1].branch, None);
    }

    #[test]
    fn porcelain_captures_locked_and_prunable_annotations() {
        let out = "worktree /repo/wt-l\nHEAD abc\nbranch refs/heads/x\nlocked sleeping\n\nworktree /repo/wt-p\nHEAD def\nbranch refs/heads/y\nprunable gitdir gone\n";
        let parsed = parse_worktree_porcelain(out);
        assert!(parsed[0].locked && !parsed[0].prunable);
        assert!(parsed[1].prunable && !parsed[1].locked);
    }

    #[test]
    fn porcelain_empty_output_is_empty() {
        assert!(parse_worktree_porcelain("").is_empty());
    }

    // ---- Read-only inspector — git runs ONLY inside temp repositories ----

    #[test]
    fn inspect_verified_worktree_on_expected_branch() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());
        let prepared = prepared_worktree(&paths, &ws);

        let verdict = inspect_worktree(repo.path(), &prepared.cwd, "maestro/ws1/sess1");
        assert_eq!(verdict, WorktreeInspection::Verified, "got {verdict:?}");
        assert_eq!(verdict.as_str(), "verified");
    }

    #[test]
    fn inspect_wrong_branch_when_registered_on_other_branch() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());
        let prepared = prepared_worktree(&paths, &ws);

        let verdict = inspect_worktree(repo.path(), &prepared.cwd, "maestro/ws1/OTHER");
        assert_eq!(verdict, WorktreeInspection::WrongBranch, "got {verdict:?}");
    }

    #[test]
    fn inspect_path_missing_when_target_absent() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let target = paths.worktree_base().join("ws1").join("ghost");

        let verdict = inspect_worktree(repo.path(), &target, "maestro/ws1/ghost");
        assert_eq!(verdict, WorktreeInspection::PathMissing, "got {verdict:?}");
    }

    #[test]
    fn inspect_not_a_worktree_for_plain_directory() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let target = paths.worktree_base().join("ws1").join("plain");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("file.txt"), "x").unwrap();

        let verdict = inspect_worktree(repo.path(), &target, "maestro/ws1/plain");
        assert_eq!(verdict, WorktreeInspection::NotAWorktree, "got {verdict:?}");
    }

    #[test]
    fn inspect_wrong_repo_when_target_is_foreign_worktree() {
        let (_tmp, paths) = temp_paths();
        let repo_a = init_temp_repo();
        let ws = worktree_workspace(repo_a.path(), worktree_consent());
        // A real maestro worktree of repo A.
        let prepared = prepared_worktree(&paths, &ws);

        // A second, unrelated repo. Inspecting A's worktree from B's root must NOT find it
        // registered, but the path IS inside a work tree -> wrong_repo, never verified.
        let repo_b = init_temp_repo();
        let verdict = inspect_worktree(repo_b.path(), &prepared.cwd, "maestro/ws1/sess1");
        assert_eq!(verdict, WorktreeInspection::WrongRepo, "got {verdict:?}");
    }

    #[test]
    fn inspect_root_not_a_repo_for_non_repo_root() {
        let (_tmp, paths) = temp_paths();
        let not_a_repo = TempDir::new().unwrap();
        let target = paths.worktree_base().join("ws1").join("sess1");

        let verdict = inspect_worktree(not_a_repo.path(), &target, "maestro/ws1/sess1");
        assert_eq!(verdict, WorktreeInspection::RootNotARepo, "got {verdict:?}");
    }

    #[test]
    fn inspect_dirty_verified_worktree_is_still_verified() {
        let (_tmp, paths) = temp_paths();
        let repo = init_temp_repo();
        let ws = worktree_workspace(repo.path(), worktree_consent());
        let prepared = prepared_worktree(&paths, &ws);
        // Dirty the checkout: a verified worktree stays verified (dirtiness is informational).
        fs::write(prepared.cwd.join("seed.txt"), "modified\n").unwrap();

        let verdict = inspect_worktree(repo.path(), &prepared.cwd, "maestro/ws1/sess1");
        assert_eq!(verdict, WorktreeInspection::Verified, "got {verdict:?}");
    }
}
