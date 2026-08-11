//! Picker-domain DTOs, projections, resolvers, and pure helpers for `maestro-app`.
//!
//! This module holds the PURE, unit-testable picker surface. It contains:
//!
//! - the headless read-only picker projection ([`build_picker_projection`]) and its DTOs
//!   ([`PickerProjection`], [`PickerProject`], [`PickerWorkspace`], [`PickerActiveTask`]) plus the
//!   renderer overlay model builder ([`build_picker_overlay_model`]);
//! - the pure picker-activation resolver ([`resolve_picker_activation`]) and its typed outcomes
//!   ([`PickerActivationResolution`], [`PickerActivationDeclineReason`]);
//! - the missing-consent grant request/confirm resolvers ([`resolve_picker_consent_request`],
//!   [`resolve_picker_consent_confirm`]) and their typed outcomes ([`PickerConsentRequestResolution`],
//!   [`PickerConsentConfirmResolution`], [`PickerConsentConfirmFields`]);
//! - the display-only hint helpers ([`project_header_hint_text`], [`picker_stale_decline_hint_text`])
//!   and the stable wire-string helper ([`workspace_policy_wire_str`]).
//!
//! These items read no global state and perform no process IO. The argument PARSER (`parse_dashboard
//! --picker`) and the snapshot-building service deliberately remain in `lib.rs`; the crate root
//! re-exports this module's public items for `maestro_app::<Item>` callers.
//! The picker launch-policy helpers REFERENCE the `NewTab*` types via `use crate::{...}`; they do not
//! own them.

use std::path::PathBuf;

use serde::Serialize;

use crate::{NewTabCwdBasis, NewTabLaunchPolicy, NewTabLaunchSource, PRODUCT_RECOVERY_PROJECT_ID};

/// Whether a durable project identity may cross the picker boundary. The product recovery project
/// is an internal startup fallback, not user-selectable state; exact-id denial here protects both
/// projections and raw fresh-snapshot resolution paths without changing ordinary hidden projects.
fn picker_project_id_is_exposed(project_id: &str) -> bool {
    project_id != PRODUCT_RECOVERY_PROJECT_ID
}

/// Why a picker-row activation was declined (no mutation). Typed so the listener can log the exact
/// authoritative reason instead of a generic message. These are NOT errors: declining is the safe,
/// expected outcome for targets outside the supported workspace activation path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PickerActivationDeclineReason {
    /// A project header row was activated (`workspace_id == None`). A project has no single
    /// unambiguous launch target, so activation does nothing.
    ProjectHeader,
    /// No project with the activated `project_id` exists in the fresh records.
    UnknownProject,
    /// No workspace with the activated `workspace_id` exists in the fresh records.
    UnknownWorkspace,
    /// The workspace exists but its fresh `project_id` does not match the activated project.
    WorkspaceProjectMismatch,
    /// The fresh workspace policy is `Worktree`, which this activation path does not launch
    /// (and never silently escalates).
    WorktreeConsentDeferred,
    /// The fresh workspace policy is `RepoWrite`, which this activation path does not launch
    /// against the live repository.
    RepoWriteLiveCheckoutDeferred,
}

impl PickerActivationDeclineReason {
    /// A stable, secret-free human-readable label for logging.
    pub fn label(&self) -> &'static str {
        match self {
            PickerActivationDeclineReason::ProjectHeader => {
                "project-header activation has no single launch target"
            }
            PickerActivationDeclineReason::UnknownProject => {
                "project id not found in fresh records"
            }
            PickerActivationDeclineReason::UnknownWorkspace => {
                "workspace id not found in fresh records"
            }
            PickerActivationDeclineReason::WorkspaceProjectMismatch => {
                "workspace does not belong to the activated project"
            }
            PickerActivationDeclineReason::WorktreeConsentDeferred => {
                "worktree workspace requires consent; launch deferred"
            }
            PickerActivationDeclineReason::RepoWriteLiveCheckoutDeferred => {
                "repo_write workspace is a live checkout; launch deferred"
            }
        }
    }
}

/// The pure resolution of a `RendererEvent::PickerRowActivated` against FRESH authoritative records.
/// Either launch one new scratch-cwd tab/session, or decline with a typed reason — never anything in
/// between, and never a mutation by itself (the caller executes the launch).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PickerActivationResolution {
    /// The activated row is a freshly-revalidated launchable workspace under the activated project:
    /// open one new tab through the existing foreground new-tab pipeline using this policy.
    ///
    /// `workspace` carries the FRESH authoritative [`maestro_shell::Workspace`] record ONLY for
    /// `Worktree` launches, where the later execution path must prepare the worktree through the
    /// consent-gated executor (`prepare_workspace_with_consent`) and therefore needs the record's
    /// `root`/`policy`/`consent`. For `ScratchCwd` it is `None`: the policy already carries everything
    /// scratch preparation needs, so no record is threaded. This is in-process app data only — it adds
    /// no wire/protocol/schema/record type. The record is boxed so the common `None` (scratch)
    /// resolution stays small.
    Launch {
        policy: NewTabLaunchPolicy,
        workspace: Option<Box<maestro_shell::Workspace>>,
    },
    /// Do nothing (leave the overlay open). The reason is for logging only.
    Decline {
        reason: PickerActivationDeclineReason,
    },
}

/// Pure resolver for the first MUTATING picker activation. It reads ONLY fresh authoritative records
/// (`projects` from a freshly-built [`maestro_shell::DashboardSnapshot`]) plus the activation ids; it
/// deliberately ignores the renderer's `RendererPickerModel`, `selectable`, and render-time consent
/// strings, which may be stale by click time.
///
/// Decision table (in order):
/// - reserved product-recovery project id -> decline `UnknownProject`;
/// - `workspace_id == None` (project header) -> decline `ProjectHeader`;
/// - project id absent from fresh records -> decline `UnknownProject`;
/// - workspace id absent from fresh records -> decline `UnknownWorkspace`;
/// - workspace's fresh `project_id` != activated project -> decline `WorkspaceProjectMismatch`;
/// - fresh `WorkspacePolicy::ScratchCwd` -> launch (consent-free, lowest risk; `workspace == None`);
/// - fresh `WorkspacePolicy::Worktree` WITH `worktree_create` consent already granted -> launch,
///   carrying the fresh `Workspace` record so the executor can prepare the worktree under the
///   consent gate (this resolver NEVER grants consent);
/// - fresh `WorkspacePolicy::Worktree` WITHOUT consent -> decline `WorktreeConsentDeferred`;
/// - fresh `WorkspacePolicy::RepoWrite` -> decline `RepoWriteLiveCheckoutDeferred`.
///
/// The launch policy is secret-free: `DefaultShellDev` source, the fresh workspace mode/id,
/// `WorkspaceDerived` cwd, and a presentation-only title derived from identity.
pub fn resolve_picker_activation(
    project_id: &str,
    workspace_id: Option<&str>,
    projects: &[maestro_shell::ProjectSnapshot],
) -> PickerActivationResolution {
    if !picker_project_id_is_exposed(project_id) {
        return PickerActivationResolution::Decline {
            reason: PickerActivationDeclineReason::UnknownProject,
        };
    }
    let Some(workspace_id) = workspace_id else {
        return PickerActivationResolution::Decline {
            reason: PickerActivationDeclineReason::ProjectHeader,
        };
    };
    let Some(project) = projects.iter().find(|p| p.project_id == project_id) else {
        return PickerActivationResolution::Decline {
            reason: PickerActivationDeclineReason::UnknownProject,
        };
    };
    let Some(workspace) = project
        .workspaces
        .iter()
        .find(|w| w.workspace_id == workspace_id)
    else {
        // The workspace might exist under a DIFFERENT project; distinguish "unknown" from
        // "mismatch" by scanning every project so the logged reason is exact.
        let exists_elsewhere = projects
            .iter()
            .any(|p| p.workspaces.iter().any(|w| w.workspace_id == workspace_id));
        let reason = if exists_elsewhere {
            PickerActivationDeclineReason::WorkspaceProjectMismatch
        } else {
            PickerActivationDeclineReason::UnknownWorkspace
        };
        return PickerActivationResolution::Decline { reason };
    };
    // `find` above already scoped to `project.workspaces`, whose `project_id` is this project by
    // snapshot construction; assert the invariant defensively rather than trust it blindly.
    if workspace.project_id != project_id {
        return PickerActivationResolution::Decline {
            reason: PickerActivationDeclineReason::WorkspaceProjectMismatch,
        };
    }
    match workspace.policy {
        maestro_shell::WorkspacePolicy::ScratchCwd => PickerActivationResolution::Launch {
            policy: NewTabLaunchPolicy {
                source: NewTabLaunchSource::DefaultShellDev,
                workspace: maestro_shell::WorkspacePolicy::ScratchCwd,
                workspace_id: workspace.workspace_id.clone(),
                cwd_basis: NewTabCwdBasis::WorkspaceDerived,
                title: picker_activation_tab_title(&project.name, &workspace.workspace_id),
            },
            workspace: None,
        },
        maestro_shell::WorkspacePolicy::Worktree => {
            // Consent is read from the FRESH record only; the resolver never grants it. Missing
            // consent declines (overlay stays open); present consent launches and threads the record
            // so the executor can re-verify consent at the defense-in-depth gate before any git.
            if maestro_shell::has_consent(
                workspace,
                maestro_shell::WorkspaceConsentKind::WorktreeCreate,
            ) {
                PickerActivationResolution::Launch {
                    policy: NewTabLaunchPolicy {
                        source: NewTabLaunchSource::DefaultShellDev,
                        workspace: maestro_shell::WorkspacePolicy::Worktree,
                        workspace_id: workspace.workspace_id.clone(),
                        cwd_basis: NewTabCwdBasis::WorkspaceDerived,
                        title: picker_activation_tab_title(&project.name, &workspace.workspace_id),
                    },
                    workspace: Some(Box::new(workspace.clone())),
                }
            } else {
                PickerActivationResolution::Decline {
                    reason: PickerActivationDeclineReason::WorktreeConsentDeferred,
                }
            }
        }
        maestro_shell::WorkspacePolicy::RepoWrite => {
            // `RepoWrite` is the live-checkout policy: the session cwd is the user's repo root with
            // NO worktree isolation. Consent is read from the FRESH record only; the resolver never
            // grants it. Missing consent declines (overlay stays open; the row exposes a separate
            // explicit grant affordance instead); present consent launches and threads the record so
            // the executor re-verifies `repo_write` at the defense-in-depth gate before any open.
            if maestro_shell::has_consent(workspace, maestro_shell::WorkspaceConsentKind::RepoWrite)
            {
                PickerActivationResolution::Launch {
                    policy: repo_write_launch_policy(&project.name, workspace),
                    workspace: Some(Box::new(workspace.clone())),
                }
            } else {
                PickerActivationResolution::Decline {
                    reason: PickerActivationDeclineReason::RepoWriteLiveCheckoutDeferred,
                }
            }
        }
    }
}

/// Deterministic, presentation-only tab title for a picker-launched scratch session. Never parsed
/// back as identity (the policy carries the real `workspace_id`). Prefers the project name for a
/// readable label, falling back to the workspace id when the name is blank.
fn picker_activation_tab_title(project_name: &str, workspace_id: &str) -> String {
    let trimmed = project_name.trim();
    if trimmed.is_empty() {
        format!("shell · {workspace_id}")
    } else {
        format!("shell · {trimmed}")
    }
}

/// Build the secret-free `Worktree` launch policy for a picker-driven worktree open. Shared by the
/// already-consented activation resolver and the missing-consent grant-and-launch path so all worktree
/// launches produce an identical policy. The launch is always routed through the consent-gated
/// executor (`prepare_workspace_with_consent(Worktree)`), which re-verifies consent before any git.
fn worktree_launch_policy(
    project_name: &str,
    workspace: &maestro_shell::Workspace,
) -> NewTabLaunchPolicy {
    NewTabLaunchPolicy {
        source: NewTabLaunchSource::DefaultShellDev,
        workspace: maestro_shell::WorkspacePolicy::Worktree,
        workspace_id: workspace.workspace_id.clone(),
        cwd_basis: NewTabCwdBasis::WorkspaceDerived,
        title: picker_activation_tab_title(project_name, &workspace.workspace_id),
    }
}

/// Build the secret-free `RepoWrite` launch policy for a picker-driven live-checkout open. Shared by
/// the already-consented activation resolver and the missing-consent grant-and-launch path so every
/// repo-write launch produces an identical policy. The launch is always routed through the
/// consent-gated executor (`prepare_workspace_with_consent(RepoWrite)`), which re-verifies `repo_write`
/// consent and that `root` is an existing directory before returning the live checkout root as cwd.
/// Unlike the worktree preparer it performs no git/mkdir — the session opens directly on the user's
/// working tree, so the confirm copy and this policy keep that direct-write risk explicit.
fn repo_write_launch_policy(
    project_name: &str,
    workspace: &maestro_shell::Workspace,
) -> NewTabLaunchPolicy {
    NewTabLaunchPolicy {
        source: NewTabLaunchSource::DefaultShellDev,
        workspace: maestro_shell::WorkspacePolicy::RepoWrite,
        workspace_id: workspace.workspace_id.clone(),
        cwd_basis: NewTabCwdBasis::WorkspaceDerived,
        title: picker_activation_tab_title(project_name, &workspace.workspace_id),
    }
}

/// Display-only fields for the consent-confirm prompt, projected from FRESH authoritative records.
/// Carries no record and no authority — only the safe identity fields the renderer draws. Mirrors
/// `maestro_renderer::RendererPickerConsentConfirm` but kept app-side so the resolver has no renderer
/// dependency; `main.rs` maps it 1:1 into the renderer type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PickerConsentConfirmFields {
    pub project_id: String,
    pub project_name: String,
    pub workspace_id: String,
    pub root: String,
    pub policy: String,
    pub consent_kind: String,
}

/// Outcome of the missing-consent worktree GRANT-REQUEST resolver. Re-derived from fresh records only;
/// it NEVER grants consent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PickerConsentRequestResolution {
    /// Fresh records confirm a missing-consent `Worktree` under the activated project: show the
    /// confirm prompt populated from these fresh fields. No consent written, nothing launched.
    ShowConfirm { confirm: PickerConsentConfirmFields },
    /// Consent was already granted by another process between browse and request: do NOT re-grant.
    /// Route straight to the existing already-consented launch path with the fresh record + policy.
    AlreadyConsentedLaunch {
        policy: NewTabLaunchPolicy,
        workspace: Box<maestro_shell::Workspace>,
    },
    /// Do nothing (leave the overlay open). The reason is for logging only.
    Decline {
        reason: PickerActivationDeclineReason,
    },
}

/// Outcome of the missing-consent worktree GRANT-CONFIRM resolver. Re-derived from fresh records only
/// (the confirm prompt is a hint, not authority). It NEVER grants consent itself — it only decides
/// whether the caller may call `grant_consent` (`Grant`), should skip straight to launch because
/// consent already landed (`AlreadyConsentedLaunch`), or must decline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PickerConsentConfirmResolution {
    /// Fresh records still show a missing-consent consent-bearing workspace under the activated
    /// project: the caller may call `grant_consent(consent_kind)` exactly once, then launch with this
    /// policy. `consent_kind` is derived from the FRESH policy (`WorktreeCreate` for `Worktree`,
    /// `RepoWrite` for `RepoWrite`) so the caller never hardcodes the kind.
    Grant {
        policy: NewTabLaunchPolicy,
        consent_kind: maestro_shell::WorkspaceConsentKind,
        workspace: Box<maestro_shell::Workspace>,
    },
    /// Consent already landed (another process granted it): do NOT re-grant; launch directly.
    AlreadyConsentedLaunch {
        policy: NewTabLaunchPolicy,
        workspace: Box<maestro_shell::Workspace>,
    },
    /// Do nothing (leave the overlay open). The reason is for logging only.
    Decline {
        reason: PickerActivationDeclineReason,
    },
}

/// Shared fresh-record lookup for both consent resolvers: resolve the activated ids to a fresh
/// `Workspace` under the activated project, applying the same identity/project/mismatch checks as
/// [`resolve_picker_activation`]. Returns the project name + the workspace on success, or a typed
/// decline reason. Pure; reads only fresh records.
fn lookup_fresh_picker_workspace<'a>(
    project_id: &str,
    workspace_id: &str,
    projects: &'a [maestro_shell::ProjectSnapshot],
) -> Result<(&'a str, &'a maestro_shell::Workspace), PickerActivationDeclineReason> {
    if !picker_project_id_is_exposed(project_id) {
        return Err(PickerActivationDeclineReason::UnknownProject);
    }
    let Some(project) = projects.iter().find(|p| p.project_id == project_id) else {
        return Err(PickerActivationDeclineReason::UnknownProject);
    };
    let Some(workspace) = project
        .workspaces
        .iter()
        .find(|w| w.workspace_id == workspace_id)
    else {
        let exists_elsewhere = projects
            .iter()
            .any(|p| p.workspaces.iter().any(|w| w.workspace_id == workspace_id));
        return Err(if exists_elsewhere {
            PickerActivationDeclineReason::WorkspaceProjectMismatch
        } else {
            PickerActivationDeclineReason::UnknownWorkspace
        });
    };
    if workspace.project_id != project_id {
        return Err(PickerActivationDeclineReason::WorkspaceProjectMismatch);
    }
    Ok((project.name.as_str(), workspace))
}

/// Map a fresh `Workspace`'s policy/consent into the consent-resolver decision shared by request and
/// confirm. It must still be a consent-bearing policy:
///
/// - `Worktree` -> open the worktree grant path; consent kind is `WorktreeCreate`.
/// - `RepoWrite` -> open the live-checkout grant path; consent kind is `RepoWrite` (no worktree
///   isolation — the session can modify the checkout directly, which the confirm copy makes explicit).
///
/// In both cases, if consent already landed the caller launches directly; otherwise the grant/confirm
/// path is open. A `ScratchCwd` workspace declines `WorktreeConsentDeferred` (there is nothing to
/// grant — scratch needs no consent). The returned tuple carries the launch policy, the
/// `WorkspaceConsentKind` the caller must grant, and the `already_consented` bool that distinguishes
/// the launch-directly case. Pure; reads only the fresh record.
fn classify_grant_consent_target(
    project_name: &str,
    workspace: &maestro_shell::Workspace,
) -> Result<
    (
        NewTabLaunchPolicy,
        maestro_shell::WorkspaceConsentKind,
        bool,
    ),
    PickerActivationDeclineReason,
> {
    match workspace.policy {
        maestro_shell::WorkspacePolicy::Worktree => {
            let kind = maestro_shell::WorkspaceConsentKind::WorktreeCreate;
            let already_consented = maestro_shell::has_consent(workspace, kind);
            Ok((
                worktree_launch_policy(project_name, workspace),
                kind,
                already_consented,
            ))
        }
        maestro_shell::WorkspacePolicy::RepoWrite => {
            let kind = maestro_shell::WorkspaceConsentKind::RepoWrite;
            let already_consented = maestro_shell::has_consent(workspace, kind);
            Ok((
                repo_write_launch_policy(project_name, workspace),
                kind,
                already_consented,
            ))
        }
        // Policy changed out from under the row. There is nothing to GRANT for scratch (it needs no
        // consent); decline the grant path. `ScratchCwd` re-activation is a separate concern.
        maestro_shell::WorkspacePolicy::ScratchCwd => {
            Err(PickerActivationDeclineReason::WorktreeConsentDeferred)
        }
    }
}

/// Pure resolver for the missing-consent GRANT-REQUEST intent (the "grant worktree access & open" /
/// "grant repo-write access & open" affordance). Reads ONLY fresh authoritative records plus the
/// activation ids — it ignores the renderer model, which may be stale. It NEVER grants consent and
/// NEVER launches; it only decides what the listener should display. The consent kind is derived from
/// the fresh policy, so a `RepoWrite` row yields a `repo_write` confirm and a `Worktree` row a
/// `worktree_create` confirm:
///
/// - missing-consent `Worktree`/`RepoWrite` under the activated project -> `ShowConfirm` (display
///   fields only, including the policy-derived `consent_kind`);
/// - consent already granted by another process -> `AlreadyConsentedLaunch` (do not re-grant);
/// - unknown/stale project or workspace, cross-project workspace, or policy now `ScratchCwd` (nothing
///   to grant) -> `Decline` with the typed reason.
pub fn resolve_picker_consent_request(
    project_id: &str,
    workspace_id: &str,
    projects: &[maestro_shell::ProjectSnapshot],
) -> PickerConsentRequestResolution {
    let (project_name, workspace) =
        match lookup_fresh_picker_workspace(project_id, workspace_id, projects) {
            Ok(found) => found,
            Err(reason) => return PickerConsentRequestResolution::Decline { reason },
        };
    match classify_grant_consent_target(project_name, workspace) {
        Ok((policy, consent_kind, already_consented)) => {
            if already_consented {
                PickerConsentRequestResolution::AlreadyConsentedLaunch {
                    policy,
                    workspace: Box::new(workspace.clone()),
                }
            } else {
                PickerConsentRequestResolution::ShowConfirm {
                    confirm: PickerConsentConfirmFields {
                        project_id: project_id.to_string(),
                        project_name: project_name.to_string(),
                        workspace_id: workspace.workspace_id.clone(),
                        root: workspace.root.clone(),
                        policy: workspace_policy_wire_str(workspace.policy).to_string(),
                        consent_kind: consent_kind.to_string(),
                    },
                }
            }
        }
        Err(reason) => PickerConsentRequestResolution::Decline { reason },
    }
}

/// Pure resolver for the missing-consent GRANT-CONFIRM intent. Re-derives the decision from fresh
/// records (the confirm prompt is only a hint). It NEVER grants consent itself — the caller does that
/// exactly once on a `Grant` outcome using the carried `consent_kind`, then launches:
///
/// - missing-consent `Worktree`/`RepoWrite` under the activated project -> `Grant` (caller may
///   `grant_consent(consent_kind)`);
/// - consent already granted -> `AlreadyConsentedLaunch` (launch without re-granting);
/// - unknown/stale/cross-project or policy now `ScratchCwd` -> `Decline`.
pub fn resolve_picker_consent_confirm(
    project_id: &str,
    workspace_id: &str,
    projects: &[maestro_shell::ProjectSnapshot],
) -> PickerConsentConfirmResolution {
    let (project_name, workspace) =
        match lookup_fresh_picker_workspace(project_id, workspace_id, projects) {
            Ok(found) => found,
            Err(reason) => return PickerConsentConfirmResolution::Decline { reason },
        };
    match classify_grant_consent_target(project_name, workspace) {
        Ok((policy, consent_kind, already_consented)) => {
            let workspace = Box::new(workspace.clone());
            if already_consented {
                PickerConsentConfirmResolution::AlreadyConsentedLaunch { policy, workspace }
            } else {
                PickerConsentConfirmResolution::Grant {
                    policy,
                    consent_kind,
                    workspace,
                }
            }
        }
        Err(reason) => PickerConsentConfirmResolution::Decline { reason },
    }
}

/// Stable snake_case wire string for a [`maestro_shell::WorkspacePolicy`], mirroring
/// [`crate::agent_task_state_wire_str`]. Matches the policy's own serde `rename_all = "snake_case"` so
/// the picker projection and the raw record serialize the policy identically.
pub fn workspace_policy_wire_str(policy: maestro_shell::WorkspacePolicy) -> &'static str {
    match policy {
        maestro_shell::WorkspacePolicy::ScratchCwd => "scratch_cwd",
        maestro_shell::WorkspacePolicy::Worktree => "worktree",
        maestro_shell::WorkspacePolicy::RepoWrite => "repo_write",
    }
}

/// One workspace row in the headless picker projection: the selectable workspace plus its RESOLVED
/// safety state (consent + escalation), so a future picker UI consumes ready-made flags instead of
/// re-deriving consent logic. Pure serde DTO produced by [`build_picker_projection`].
///
/// `requires_consent_kind` is the consent a session under `policy` would need
/// ([`maestro_shell::required_consent_for_policy`], rendered `worktree_create` / `repo_write`), or
/// `null` for `ScratchCwd`. `consent_status` is `not_required` when no consent is needed, else
/// `granted` / `missing` per [`maestro_shell::has_consent`]. `selectable` is `false` ONLY when consent
/// is `missing` (advisory; the row is always listed). `live_checkout` is true only for `RepoWrite`
/// (the policy that writes the user's live checkout).
///
/// `active_task` is intentionally always `None` and `recovered_session_ids` always empty: an
/// [`maestro_shell::AgentTask`] carries only `project_id` (never a `workspace_id`), and a
/// [`maestro_shell::RecoveredSession`] carries only `session_id`, so neither can be attributed to a
/// specific workspace without new shell support. Both are surfaced at the projection top level instead
/// (project tasks via the existing dashboard projections; recovered sessions via
/// `PickerProjection.recovered_sessions`). See the dashboard-picker-projection report.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PickerWorkspace {
    pub workspace_id: String,
    pub root: String,
    pub policy: String,
    pub requires_consent_kind: Option<String>,
    pub consent_status: String,
    pub selectable: bool,
    pub live_checkout: bool,
    pub active_task: Option<PickerActiveTask>,
    pub recovered_session_ids: Vec<String>,
}

/// Reserved compact active-task context for a future per-workspace join. Not currently populated
/// (workspaces are not attributable from task records); defined so the wire shape is forward-stable.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PickerActiveTask {
    pub agent_task_id: String,
    pub state: String,
}

/// One project row in the picker projection: the selectable project plus its workspaces.
/// Pure serde DTO produced by [`build_picker_projection`].
///
/// `default_workspace_policy` is the project record's default policy as a stable wire string
/// (`scratch_cwd` / `worktree` / `repo_write`), carried through [`maestro_shell::ProjectSnapshot`].
/// Each workspace's own `policy` IS exact and may differ from this project-level default.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PickerProject {
    pub project_id: String,
    pub name: String,
    pub root: String,
    pub default_workspace_policy: Option<String>,
    pub last_active_at_ms: u64,
    pub workspaces: Vec<PickerWorkspace>,
}

/// The headless read-only project/workspace picker projection emitted by
/// `maestro-app dashboard --picker`: the project -> workspace tree with each workspace's policy and
/// resolved consent/safety state, plus the snapshot's future-version / quarantined / recovered-session
/// bookkeeping passed through unchanged. It replaces the full [`maestro_shell::DashboardSnapshot`] in
/// the success `snapshot` field while the surrounding [`crate::DashboardSuccess`] wrapper is unchanged.
///
/// Strictly READ-ONLY and local: produced from an already-built snapshot, it grants no consent, runs
/// no `workspace_exec`, opens no daemon connection, and carries no raw daemon socket handle. Pure serde
/// DTO produced by [`build_picker_projection`].
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PickerProjection {
    pub projects: Vec<PickerProject>,
    pub recovered_sessions: Vec<maestro_shell::RecoveredSession>,
    pub skipped_future_projects: Vec<PathBuf>,
    pub skipped_future_workspaces: Vec<PathBuf>,
    pub skipped_future_windows: Vec<PathBuf>,
    pub skipped_future_tasks: Vec<PathBuf>,
    pub skipped_future_sessions: Vec<PathBuf>,
    pub quarantined: Vec<maestro_shell::QuarantinedRecord>,
}

/// Build the headless [`PickerProjection`] from the full [`maestro_shell::DashboardSnapshot`]. PURE:
/// derived entirely from the already-built snapshot (no store scan, no daemon, no filesystem, no
/// mutation). Future-version / quarantined / recovered-session bookkeeping is passed through verbatim
/// so the picker inherits the snapshot service's existing skip/quarantine semantics rather than
/// re-deriving them. The exact reserved product-recovery project id is excluded because it is an
/// internal startup fallback; ordinary hidden projects retain the picker's existing inclusion
/// semantics.
///
/// Per workspace, the consent gate is resolved via [`maestro_shell::required_consent_for_policy`] +
/// [`maestro_shell::has_consent`]: `ScratchCwd` -> `not_required` / selectable; a policy needing a
/// consent the workspace lacks -> `missing` / not selectable; granted -> `granted` / selectable.
/// `RepoWrite` is additionally flagged `live_checkout: true`. No per-workspace task/recovered-session
/// join is attempted (see [`PickerWorkspace`]).
pub fn build_picker_projection(snapshot: &maestro_shell::DashboardSnapshot) -> PickerProjection {
    let projects = snapshot
        .projects
        .iter()
        .filter(|project| picker_project_id_is_exposed(&project.project_id))
        .map(|project| {
            let workspaces = project
                .workspaces
                .iter()
                .map(|ws| {
                    let required = maestro_shell::required_consent_for_policy(ws.policy);
                    let consent_status = match required {
                        None => "not_required",
                        Some(kind) if maestro_shell::has_consent(ws, kind) => "granted",
                        Some(_) => "missing",
                    };
                    PickerWorkspace {
                        workspace_id: ws.workspace_id.clone(),
                        root: ws.root.clone(),
                        policy: workspace_policy_wire_str(ws.policy).to_string(),
                        requires_consent_kind: required.map(|kind| kind.to_string()),
                        selectable: consent_status != "missing",
                        consent_status: consent_status.to_string(),
                        live_checkout: ws.policy == maestro_shell::WorkspacePolicy::RepoWrite,
                        active_task: None,
                        recovered_session_ids: Vec::new(),
                    }
                })
                .collect();
            PickerProject {
                project_id: project.project_id.clone(),
                name: project.name.clone(),
                root: project.root.clone(),
                default_workspace_policy: Some(
                    workspace_policy_wire_str(project.default_workspace_policy).to_string(),
                ),
                last_active_at_ms: project.last_active_at_ms,
                workspaces,
            }
        })
        .collect();

    PickerProjection {
        projects,
        recovered_sessions: snapshot.recovered_sessions.clone(),
        skipped_future_projects: snapshot.skipped_future_projects.clone(),
        skipped_future_workspaces: snapshot.skipped_future_workspaces.clone(),
        skipped_future_windows: snapshot.skipped_future_windows.clone(),
        skipped_future_tasks: snapshot.skipped_future_tasks.clone(),
        skipped_future_sessions: snapshot.skipped_future_sessions.clone(),
        quarantined: snapshot.quarantined.clone(),
    }
}

/// Convert the headless [`PickerProjection`] into the renderer-owned [`maestro_renderer::RendererPickerModel`]
/// for the read-only foreground picker overlay. Pure field pass-through in deterministic projection order;
/// the renderer never re-sorts. Carries no records, daemon handles, or mutating capability — selecting a
/// row in the overlay only emits an intent event the app observes.
pub fn build_picker_overlay_model(
    projection: &PickerProjection,
) -> maestro_renderer::RendererPickerModel {
    let projects = projection
        .projects
        .iter()
        .map(|project| {
            let workspaces = project
                .workspaces
                .iter()
                .map(|ws| maestro_renderer::RendererPickerWorkspace {
                    workspace_id: ws.workspace_id.clone(),
                    root: ws.root.clone(),
                    policy: ws.policy.clone(),
                    requires_consent_kind: ws.requires_consent_kind.clone(),
                    consent_status: ws.consent_status.clone(),
                    selectable: ws.selectable,
                    live_checkout: ws.live_checkout,
                })
                .collect();
            maestro_renderer::RendererPickerProject {
                project_id: project.project_id.clone(),
                name: project.name.clone(),
                root: project.root.clone(),
                default_workspace_policy: project.default_workspace_policy.clone(),
                workspaces,
            }
        })
        .collect();

    maestro_renderer::RendererPickerModel {
        projects,
        confirm: None,
        hint: None,
    }
}

/// Build the project-header no-launch hint text from FRESH authoritative records. Pure and
/// secret-free. A project-header activation never launches; this is the single display-only line the
/// app attaches to a freshly-rebuilt browse overlay so the "headers do nothing" outcome is honest and
/// visible instead of only logged.
///
/// Prefers the fresh project's name; falls back to the `project_id` when the name is blank. When the
/// project is missing from the fresh records (stale/removed between render and click), returns the
/// stale-project message. It selects/creates no workspace and reads no consent.
pub fn project_header_hint_text(
    project_id: &str,
    projects: &[maestro_shell::ProjectSnapshot],
) -> String {
    match projects.iter().find(|p| p.project_id == project_id) {
        Some(project) => {
            let label = if project.name.trim().is_empty() {
                project_id
            } else {
                project.name.as_str()
            };
            format!("Select a workspace under {label} to open a session.")
        }
        None => "Project is no longer available.".to_string(),
    }
}

/// The single generic, secret-free hint shown when a clicked picker row resolves to a stale/race
/// decline. It deliberately echoes NO `project_id`/`workspace_id`, so one string covers all three
/// stale/race reasons and nothing internal leaks into the overlay. The refreshed browse rows beneath
/// the hint are the real correction; the stale row is simply gone.
pub const PICKER_STALE_DECLINE_HINT: &str =
    "That item is no longer available; the list has been refreshed.";

/// Pure mapping from a decline reason to the optional generic stale/race hint. Returns the generic
/// hint ONLY for the three stale/race reasons — `UnknownProject`, `UnknownWorkspace`,
/// `WorkspaceProjectMismatch` — because a fresh overlay row cannot point at records the fresh
/// snapshot lacks or cross-links, so these only occur when the model is stale by click time.
///
/// Returns `None` for:
/// - `ProjectHeader`, which keeps its own distinct project-specific hint
///   ([`project_header_hint_text`]);
/// - `WorktreeConsentDeferred` / `RepoWriteLiveCheckoutDeferred`, which stay log-only because the
///   missing-consent rows already carry their own explicit grant affordance; a second hint would
///   duplicate it.
///
/// This helper performs no I/O, reads no records, and mutates nothing — it only classifies a typed
/// reason into display text.
pub fn picker_stale_decline_hint_text(reason: &PickerActivationDeclineReason) -> Option<String> {
    match reason {
        PickerActivationDeclineReason::UnknownProject
        | PickerActivationDeclineReason::UnknownWorkspace
        | PickerActivationDeclineReason::WorkspaceProjectMismatch => {
            Some(PICKER_STALE_DECLINE_HINT.to_string())
        }
        PickerActivationDeclineReason::ProjectHeader
        | PickerActivationDeclineReason::WorktreeConsentDeferred
        | PickerActivationDeclineReason::RepoWriteLiveCheckoutDeferred => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_decline_hint_text_for_the_three_stale_race_reasons() {
        // The three stale/race reasons all map to the same single generic hint string.
        for reason in [
            PickerActivationDeclineReason::UnknownProject,
            PickerActivationDeclineReason::UnknownWorkspace,
            PickerActivationDeclineReason::WorkspaceProjectMismatch,
        ] {
            assert_eq!(
                picker_stale_decline_hint_text(&reason).as_deref(),
                Some(PICKER_STALE_DECLINE_HINT),
                "stale/race reason {reason:?} must yield the generic hint"
            );
        }
    }

    #[test]
    fn stale_decline_hint_text_is_none_for_header_and_deferred_reasons() {
        // ProjectHeader keeps its OWN distinct hint; the two *Deferred reasons stay log-only because
        // missing-consent rows already carry their explicit grant affordance.
        for reason in [
            PickerActivationDeclineReason::ProjectHeader,
            PickerActivationDeclineReason::WorktreeConsentDeferred,
            PickerActivationDeclineReason::RepoWriteLiveCheckoutDeferred,
        ] {
            assert_eq!(
                picker_stale_decline_hint_text(&reason),
                None,
                "reason {reason:?} must produce no generic stale hint"
            );
        }
    }

    #[test]
    fn stale_decline_hint_echoes_no_ids() {
        // The hint is one fixed string that never embeds a project_id or workspace_id.
        let hint = picker_stale_decline_hint_text(&PickerActivationDeclineReason::UnknownWorkspace)
            .expect("stale/race reason yields a hint");
        assert!(!hint.contains("proj"), "hint must not leak a project id");
        assert!(!hint.contains("ws"), "hint must not leak a workspace id");
    }

    // ---- picker projection / overlay-model (localized here from lib.rs) ------------------------
    //
    // These narrow private builders mirror the lib.rs picker fixtures but are kept local so the
    // Projection and overlay tests live next to the production code they exercise. `snapshot_of` is a
    // narrow private copy (lib.rs keeps its own copy for the many retained tests there).

    fn workspace_with(
        workspace_id: &str,
        policy: maestro_shell::WorkspacePolicy,
        consent: maestro_shell::WorkspaceConsent,
    ) -> maestro_shell::Workspace {
        maestro_shell::Workspace {
            workspace_id: workspace_id.to_string(),
            project_id: "project-1".to_string(),
            root: format!("/p1/{workspace_id}"),
            policy,
            consent,
        }
    }

    fn project_with_workspaces(
        workspaces: Vec<maestro_shell::Workspace>,
    ) -> maestro_shell::ProjectSnapshot {
        maestro_shell::ProjectSnapshot {
            project_id: "project-1".to_string(),
            name: "Project One".to_string(),
            root: "/p1".to_string(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::Worktree,
            last_active_at_ms: 1234,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            system: false,
            hidden: false,
            workspaces,
            tasks: vec![],
            windows: vec![],
        }
    }

    fn worktree_granted() -> maestro_shell::WorkspaceConsent {
        maestro_shell::WorkspaceConsent {
            worktree_create: true,
            repo_write: false,
            granted_at_ms: Some(99),
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

    #[test]
    fn picker_excludes_exact_recovery_project_but_retains_ordinary_hidden_projects() {
        let mut ordinary_hidden = project_with_workspaces(vec![workspace_with(
            "ws-hidden",
            maestro_shell::WorkspacePolicy::ScratchCwd,
            maestro_shell::WorkspaceConsent::default(),
        )]);
        ordinary_hidden.project_id = "ordinary-hidden-project".to_string();
        ordinary_hidden.hidden = true;
        ordinary_hidden.workspaces[0].project_id = ordinary_hidden.project_id.clone();

        let mut recovery = project_with_workspaces(vec![workspace_with(
            "ws-recovery",
            maestro_shell::WorkspacePolicy::ScratchCwd,
            maestro_shell::WorkspaceConsent::default(),
        )]);
        recovery.project_id = PRODUCT_RECOVERY_PROJECT_ID.to_string();
        // Exact identity, rather than the hidden bit, owns the exclusion. A malformed/raw visible
        // recovery snapshot must therefore remain unavailable too.
        recovery.hidden = false;
        recovery.workspaces[0].project_id = recovery.project_id.clone();

        let out = build_picker_projection(&snapshot_of(vec![recovery, ordinary_hidden]));
        assert_eq!(out.projects.len(), 1);
        assert_eq!(out.projects[0].project_id, "ordinary-hidden-project");
        assert_eq!(out.projects[0].workspaces[0].workspace_id, "ws-hidden");
    }

    #[test]
    fn picker_scratch_cwd_is_not_required_and_selectable() {
        let projects = vec![project_with_workspaces(vec![workspace_with(
            "ws-scratch",
            maestro_shell::WorkspacePolicy::ScratchCwd,
            maestro_shell::WorkspaceConsent::default(),
        )])];
        let out = build_picker_projection(&snapshot_of(projects));
        let ws = &out.projects[0].workspaces[0];
        assert_eq!(ws.policy, "scratch_cwd");
        assert_eq!(ws.requires_consent_kind, None);
        assert_eq!(ws.consent_status, "not_required");
        assert!(ws.selectable);
        assert!(!ws.live_checkout);
    }

    #[test]
    fn picker_worktree_without_consent_is_missing_and_not_selectable() {
        let projects = vec![project_with_workspaces(vec![workspace_with(
            "ws-wt",
            maestro_shell::WorkspacePolicy::Worktree,
            maestro_shell::WorkspaceConsent::default(),
        )])];
        let out = build_picker_projection(&snapshot_of(projects));
        let ws = &out.projects[0].workspaces[0];
        assert_eq!(ws.policy, "worktree");
        assert_eq!(ws.requires_consent_kind.as_deref(), Some("worktree_create"));
        assert_eq!(ws.consent_status, "missing");
        assert!(!ws.selectable);
        assert!(!ws.live_checkout);
    }

    #[test]
    fn picker_worktree_with_consent_is_granted_and_selectable() {
        let projects = vec![project_with_workspaces(vec![workspace_with(
            "ws-wt",
            maestro_shell::WorkspacePolicy::Worktree,
            worktree_granted(),
        )])];
        let out = build_picker_projection(&snapshot_of(projects));
        let ws = &out.projects[0].workspaces[0];
        assert_eq!(ws.requires_consent_kind.as_deref(), Some("worktree_create"));
        assert_eq!(ws.consent_status, "granted");
        assert!(ws.selectable);
        assert!(!ws.live_checkout);
    }

    #[test]
    fn picker_repo_write_flags_live_checkout() {
        let consent = maestro_shell::WorkspaceConsent {
            worktree_create: false,
            repo_write: true,
            granted_at_ms: Some(7),
        };
        let projects = vec![project_with_workspaces(vec![workspace_with(
            "ws-rw",
            maestro_shell::WorkspacePolicy::RepoWrite,
            consent,
        )])];
        let out = build_picker_projection(&snapshot_of(projects));
        let ws = &out.projects[0].workspaces[0];
        assert_eq!(ws.policy, "repo_write");
        assert_eq!(ws.requires_consent_kind.as_deref(), Some("repo_write"));
        assert_eq!(ws.consent_status, "granted");
        assert!(ws.selectable);
        assert!(ws.live_checkout);
    }

    #[test]
    fn overlay_model_maps_project_and_workspace_fields_through_exactly() {
        // RepoWrite workspace exercises the consent/selectable/live_checkout fields all at once.
        let consent = maestro_shell::WorkspaceConsent {
            worktree_create: false,
            repo_write: true,
            granted_at_ms: Some(7),
        };
        let projects = vec![project_with_workspaces(vec![workspace_with(
            "ws-rw",
            maestro_shell::WorkspacePolicy::RepoWrite,
            consent,
        )])];
        let projection = build_picker_projection(&snapshot_of(projects));
        let model = build_picker_overlay_model(&projection);

        assert_eq!(model.projects.len(), 1);
        let p = &model.projects[0];
        let pp = &projection.projects[0];
        // Project fields pass through unchanged, in projection order.
        assert_eq!(p.project_id, pp.project_id);
        assert_eq!(p.name, pp.name);
        assert_eq!(p.root, pp.root);
        assert_eq!(p.default_workspace_policy, pp.default_workspace_policy);
        assert_eq!(p.default_workspace_policy.as_deref(), Some("worktree"));

        assert_eq!(p.workspaces.len(), 1);
        let w = &p.workspaces[0];
        let pw = &pp.workspaces[0];
        assert_eq!(w.workspace_id, pw.workspace_id);
        assert_eq!(w.root, pw.root);
        assert_eq!(w.policy, pw.policy);
        assert_eq!(w.policy, "repo_write");
        assert_eq!(w.requires_consent_kind, pw.requires_consent_kind);
        assert_eq!(w.requires_consent_kind.as_deref(), Some("repo_write"));
        assert_eq!(w.consent_status, pw.consent_status);
        assert_eq!(w.consent_status, "granted");
        assert_eq!(w.selectable, pw.selectable);
        assert!(w.selectable);
        assert_eq!(w.live_checkout, pw.live_checkout);
        assert!(w.live_checkout);
    }

    #[test]
    fn overlay_model_empty_projection_maps_to_empty_renderable_model() {
        let projection = build_picker_projection(&snapshot_of(vec![]));
        let model = build_picker_overlay_model(&projection);
        // The model is empty (the empty-state line is composed renderer-side, not here).
        assert!(model.projects.is_empty());
    }

    #[test]
    fn picker_project_passthrough_fields_and_documented_omissions() {
        let projects = vec![project_with_workspaces(vec![workspace_with(
            "ws-scratch",
            maestro_shell::WorkspacePolicy::ScratchCwd,
            maestro_shell::WorkspaceConsent::default(),
        )])];
        let out = build_picker_projection(&snapshot_of(projects));
        let project = &out.projects[0];
        assert_eq!(project.project_id, "project-1");
        assert_eq!(project.name, "Project One");
        assert_eq!(project.root, "/p1");
        assert_eq!(project.last_active_at_ms, 1234);
        // The project's default workspace policy is now carried through the snapshot.
        assert_eq!(
            project.default_workspace_policy.as_deref(),
            Some("worktree")
        );
        // Remaining documented omissions: per-workspace task/recovered joins are not safely derivable
        // from the snapshot, so they are null/empty by design.
        let ws = &project.workspaces[0];
        assert_eq!(ws.active_task, None);
        assert!(ws.recovered_session_ids.is_empty());
    }

    #[test]
    fn picker_carries_project_default_workspace_policy_from_snapshot() {
        for (policy, wire) in [
            (maestro_shell::WorkspacePolicy::ScratchCwd, "scratch_cwd"),
            (maestro_shell::WorkspacePolicy::Worktree, "worktree"),
            (maestro_shell::WorkspacePolicy::RepoWrite, "repo_write"),
        ] {
            let mut project = project_with_workspaces(vec![]);
            project.default_workspace_policy = policy;
            let out = build_picker_projection(&snapshot_of(vec![project]));
            assert_eq!(
                out.projects[0].default_workspace_policy.as_deref(),
                Some(wire),
                "policy {policy:?} should serialize as {wire}"
            );
        }
    }

    #[test]
    fn picker_preserves_future_and_quarantine_and_recovered_buckets() {
        use std::path::PathBuf;
        let snapshot = maestro_shell::DashboardSnapshot {
            projects: vec![],
            recovered_sessions: vec![maestro_shell::RecoveredSession {
                session_id: "sess-recovered".to_string(),
            }],
            skipped_future_projects: vec![PathBuf::from("/store/proj.future")],
            skipped_future_workspaces: vec![PathBuf::from("/store/ws.future")],
            skipped_future_windows: vec![PathBuf::from("/store/win.future")],
            skipped_future_tasks: vec![PathBuf::from("/store/task.future")],
            skipped_future_sessions: vec![PathBuf::from("/store/sess.future")],
            quarantined: vec![maestro_shell::QuarantinedRecord {
                original: PathBuf::from("/store/bad.json"),
                moved_to: PathBuf::from("/store/quarantine/bad.json"),
                reason: "corrupt".to_string(),
            }],
            ..Default::default()
        };
        let out = build_picker_projection(&snapshot);
        assert_eq!(out.recovered_sessions.len(), 1);
        assert_eq!(out.recovered_sessions[0].session_id, "sess-recovered");
        assert_eq!(
            out.skipped_future_projects,
            vec![PathBuf::from("/store/proj.future")]
        );
        assert_eq!(
            out.skipped_future_workspaces,
            vec![PathBuf::from("/store/ws.future")]
        );
        assert_eq!(
            out.skipped_future_windows,
            vec![PathBuf::from("/store/win.future")]
        );
        assert_eq!(
            out.skipped_future_tasks,
            vec![PathBuf::from("/store/task.future")]
        );
        assert_eq!(
            out.skipped_future_sessions,
            vec![PathBuf::from("/store/sess.future")]
        );
        assert_eq!(out.quarantined.len(), 1);
        assert_eq!(out.quarantined[0].reason, "corrupt");
    }

    #[test]
    fn picker_serialized_shape_is_stable_without_raw_socket_handles() {
        let projects = vec![project_with_workspaces(vec![workspace_with(
            "ws-wt",
            maestro_shell::WorkspacePolicy::Worktree,
            maestro_shell::WorkspaceConsent::default(),
        )])];
        let out = build_picker_projection(&snapshot_of(projects));
        let v: serde_json::Value = serde_json::to_value(&out).unwrap();
        assert!(v["projects"].is_array());
        assert!(v["recovered_sessions"].is_array());
        assert!(v["quarantined"].is_array());
        let ws = &v["projects"][0]["workspaces"][0];
        assert_eq!(ws["workspace_id"], "ws-wt");
        assert_eq!(ws["policy"], "worktree");
        assert_eq!(ws["requires_consent_kind"], "worktree_create");
        assert_eq!(ws["consent_status"], "missing");
        assert_eq!(ws["selectable"], false);
        assert_eq!(ws["live_checkout"], false);
        assert!(ws["active_task"].is_null());
        // No daemon socket path / handle leaks into the picker payload.
        let serialized = serde_json::to_string(&out).unwrap();
        assert!(
            !serialized.contains("socket") && !serialized.contains(".sock"),
            "picker payload must not carry raw socket handles: {serialized}"
        );
    }

    // ---- picker activation / project-header hint (localized here from lib.rs) -----------------
    // Narrow module-private fixtures for the activation and hint tests. `lib.rs` keeps its own copies of
    // these builders for the retained listener-composition and consent request/confirm tests.

    fn ws(
        workspace_id: &str,
        project_id: &str,
        policy: maestro_shell::WorkspacePolicy,
    ) -> maestro_shell::Workspace {
        maestro_shell::Workspace {
            workspace_id: workspace_id.to_string(),
            project_id: project_id.to_string(),
            root: format!("/{project_id}/{workspace_id}"),
            policy,
            consent: maestro_shell::WorkspaceConsent::default(),
        }
    }

    fn ws_with_consent(
        workspace_id: &str,
        project_id: &str,
        policy: maestro_shell::WorkspacePolicy,
        consent: maestro_shell::WorkspaceConsent,
    ) -> maestro_shell::Workspace {
        maestro_shell::Workspace {
            workspace_id: workspace_id.to_string(),
            project_id: project_id.to_string(),
            root: format!("/{project_id}/{workspace_id}"),
            policy,
            consent,
        }
    }

    fn worktree_create_consent() -> maestro_shell::WorkspaceConsent {
        maestro_shell::WorkspaceConsent {
            worktree_create: true,
            ..Default::default()
        }
    }

    fn repo_write_consent() -> maestro_shell::WorkspaceConsent {
        maestro_shell::WorkspaceConsent {
            repo_write: true,
            ..Default::default()
        }
    }

    fn project(
        project_id: &str,
        name: &str,
        workspaces: Vec<maestro_shell::Workspace>,
    ) -> maestro_shell::ProjectSnapshot {
        maestro_shell::ProjectSnapshot {
            project_id: project_id.to_string(),
            name: name.to_string(),
            root: format!("/{project_id}"),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            last_active_at_ms: 7,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            system: false,
            hidden: false,
            workspaces,
            tasks: vec![],
            windows: vec![],
        }
    }

    #[test]
    fn resolver_launches_fresh_scratch_cwd_under_activated_project() {
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-scratch",
                "proj-a",
                maestro_shell::WorkspacePolicy::ScratchCwd,
            )],
        )];
        let res = resolve_picker_activation("proj-a", Some("ws-scratch"), &projects);
        let PickerActivationResolution::Launch { policy, workspace } = res else {
            panic!("expected launch, got {res:?}");
        };
        assert!(
            workspace.is_none(),
            "scratch launch must not thread a workspace record"
        );
        assert_eq!(policy.source, NewTabLaunchSource::DefaultShellDev);
        assert_eq!(policy.workspace, maestro_shell::WorkspacePolicy::ScratchCwd);
        assert_eq!(policy.workspace_id, "ws-scratch");
        assert_eq!(policy.cwd_basis, NewTabCwdBasis::WorkspaceDerived);
        // Title is presentation-only; just assert it is non-empty and secret-free.
        assert!(!policy.title.is_empty());
        assert!(!policy.title.contains(".sock"));
    }

    #[test]
    fn resolver_declines_recovery_project_even_when_raw_snapshot_contains_it() {
        let projects = vec![project(
            PRODUCT_RECOVERY_PROJECT_ID,
            "Recovery",
            vec![ws(
                "ws-recovery",
                PRODUCT_RECOVERY_PROJECT_ID,
                maestro_shell::WorkspacePolicy::ScratchCwd,
            )],
        )];

        assert_eq!(
            resolve_picker_activation(PRODUCT_RECOVERY_PROJECT_ID, Some("ws-recovery"), &projects,),
            PickerActivationResolution::Decline {
                reason: PickerActivationDeclineReason::UnknownProject,
            }
        );
        // Check identity before header handling so a forged direct header activation cannot expose
        // the reserved project through the project-specific hint route.
        assert_eq!(
            resolve_picker_activation(PRODUCT_RECOVERY_PROJECT_ID, None, &projects),
            PickerActivationResolution::Decline {
                reason: PickerActivationDeclineReason::UnknownProject,
            }
        );
    }

    #[test]
    fn resolver_declines_project_header_when_workspace_id_is_none() {
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-scratch",
                "proj-a",
                maestro_shell::WorkspacePolicy::ScratchCwd,
            )],
        )];
        assert_eq!(
            resolve_picker_activation("proj-a", None, &projects),
            PickerActivationResolution::Decline {
                reason: PickerActivationDeclineReason::ProjectHeader,
            }
        );
    }

    #[test]
    fn project_header_hint_prefers_fresh_project_name() {
        let projects = vec![project("proj-a", "Alpha", vec![])];
        assert_eq!(
            project_header_hint_text("proj-a", &projects),
            "Select a workspace under Alpha to open a session."
        );
    }

    #[test]
    fn project_header_hint_falls_back_to_project_id_when_name_blank() {
        let projects = vec![project("proj-a", "   ", vec![])];
        assert_eq!(
            project_header_hint_text("proj-a", &projects),
            "Select a workspace under proj-a to open a session."
        );
    }

    #[test]
    fn project_header_hint_reports_stale_project_when_missing() {
        let projects = vec![project("proj-a", "Alpha", vec![])];
        assert_eq!(
            project_header_hint_text("proj-gone", &projects),
            "Project is no longer available."
        );
    }

    #[test]
    fn project_header_hint_does_not_depend_on_workspace_count() {
        // Zero workspaces: still the same "select a workspace" hint (no synthesis, no auto-pick).
        let zero = vec![project("proj-a", "Alpha", vec![])];
        // Many workspaces: identical hint (the header never picks a row).
        let many = vec![project(
            "proj-a",
            "Alpha",
            vec![
                ws("w1", "proj-a", maestro_shell::WorkspacePolicy::ScratchCwd),
                ws("w2", "proj-a", maestro_shell::WorkspacePolicy::ScratchCwd),
            ],
        )];
        assert_eq!(
            project_header_hint_text("proj-a", &zero),
            project_header_hint_text("proj-a", &many)
        );
    }

    #[test]
    fn resolver_project_header_is_never_launch() {
        // The header activation outcome must never be `Launch` regardless of children: it is the
        // typed non-launch `ProjectHeader` decline, and the listener surfaces the hint.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-scratch",
                "proj-a",
                maestro_shell::WorkspacePolicy::ScratchCwd,
            )],
        )];
        let res = resolve_picker_activation("proj-a", None, &projects);
        assert!(
            !matches!(res, PickerActivationResolution::Launch { .. }),
            "project-header activation must never launch, got {res:?}"
        );
    }

    #[test]
    fn resolver_declines_unknown_project() {
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-scratch",
                "proj-a",
                maestro_shell::WorkspacePolicy::ScratchCwd,
            )],
        )];
        assert_eq!(
            resolve_picker_activation("proj-missing", Some("ws-scratch"), &projects),
            PickerActivationResolution::Decline {
                reason: PickerActivationDeclineReason::UnknownProject,
            }
        );
    }

    #[test]
    fn resolver_declines_unknown_workspace() {
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-scratch",
                "proj-a",
                maestro_shell::WorkspacePolicy::ScratchCwd,
            )],
        )];
        assert_eq!(
            resolve_picker_activation("proj-a", Some("ws-nope"), &projects),
            PickerActivationResolution::Decline {
                reason: PickerActivationDeclineReason::UnknownWorkspace,
            }
        );
    }

    #[test]
    fn resolver_declines_workspace_belonging_to_a_different_project() {
        let projects = vec![
            project(
                "proj-a",
                "Alpha",
                vec![ws(
                    "ws-a",
                    "proj-a",
                    maestro_shell::WorkspacePolicy::ScratchCwd,
                )],
            ),
            project(
                "proj-b",
                "Beta",
                vec![ws(
                    "ws-b",
                    "proj-b",
                    maestro_shell::WorkspacePolicy::ScratchCwd,
                )],
            ),
        ];
        // ws-b is real but lives under proj-b; activating it under proj-a is a mismatch, not unknown.
        assert_eq!(
            resolve_picker_activation("proj-a", Some("ws-b"), &projects),
            PickerActivationResolution::Decline {
                reason: PickerActivationDeclineReason::WorkspaceProjectMismatch,
            }
        );
    }

    #[test]
    fn resolver_declines_fresh_worktree_without_consent_even_if_overlay_claimed_selectable() {
        // The renderer model is irrelevant here: only the FRESH record decides. A stale overlay that
        // showed this row as selectable cannot promote a worktree launch when consent is missing.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-wt",
                "proj-a",
                maestro_shell::WorkspacePolicy::Worktree,
            )],
        )];
        assert_eq!(
            resolve_picker_activation("proj-a", Some("ws-wt"), &projects),
            PickerActivationResolution::Decline {
                reason: PickerActivationDeclineReason::WorktreeConsentDeferred,
            }
        );
    }

    #[test]
    fn resolver_launches_fresh_worktree_only_when_consent_granted() {
        // With `worktree_create` consent already granted on the FRESH record, the worktree row
        // launches and threads the authoritative `Workspace` so the executor can re-verify consent.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws_with_consent(
                "ws-wt",
                "proj-a",
                maestro_shell::WorkspacePolicy::Worktree,
                worktree_create_consent(),
            )],
        )];
        let res = resolve_picker_activation("proj-a", Some("ws-wt"), &projects);
        let PickerActivationResolution::Launch { policy, workspace } = res else {
            panic!("expected launch, got {res:?}");
        };
        // The launch policy carries the worktree workspace mode, the activated id, derived cwd, and a
        // presentation-only secret-free title.
        assert_eq!(policy.source, NewTabLaunchSource::DefaultShellDev);
        assert_eq!(policy.workspace, maestro_shell::WorkspacePolicy::Worktree);
        assert_eq!(policy.workspace_id, "ws-wt");
        assert_eq!(policy.cwd_basis, NewTabCwdBasis::WorkspaceDerived);
        assert!(!policy.title.is_empty());
        assert!(!policy.title.contains(".sock"));
        // The fresh authoritative record is threaded for the consent-gated preparation path.
        let workspace = workspace.expect("worktree launch must thread the fresh Workspace record");
        assert_eq!(workspace.workspace_id, "ws-wt");
        assert_eq!(workspace.project_id, "proj-a");
        assert_eq!(workspace.policy, maestro_shell::WorkspacePolicy::Worktree);
        assert!(
            maestro_shell::has_consent(
                &workspace,
                maestro_shell::WorkspaceConsentKind::WorktreeCreate
            ),
            "threaded record must still carry the granted consent"
        );
    }

    #[test]
    fn resolver_declines_missing_consent_repo_write_naming_live_checkout_deferral() {
        // A bare `PickerRowActivated` on a MISSING-consent RepoWrite row never grants and never
        // launches: it declines to the live-checkout deferral so the explicit grant affordance is the
        // only path to consent. (Consent comes only from the request/confirm/grant flow.)
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-rw",
                "proj-a",
                maestro_shell::WorkspacePolicy::RepoWrite,
            )],
        )];
        let res = resolve_picker_activation("proj-a", Some("ws-rw"), &projects);
        assert_eq!(
            res,
            PickerActivationResolution::Decline {
                reason: PickerActivationDeclineReason::RepoWriteLiveCheckoutDeferred,
            }
        );
        let PickerActivationResolution::Decline { reason } = res else {
            unreachable!()
        };
        assert!(
            reason.label().contains("live checkout"),
            "repo_write decline must name the live-checkout deferral: {}",
            reason.label()
        );
    }

    #[test]
    fn resolver_launches_fresh_repo_write_only_when_consent_granted() {
        // With `repo_write` consent already granted on the FRESH record, the live-checkout row launches
        // and threads the authoritative `Workspace` so the executor re-verifies `repo_write` before any
        // open. The launch policy is the live-checkout policy (NOT worktree).
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws_with_consent(
                "ws-rw",
                "proj-a",
                maestro_shell::WorkspacePolicy::RepoWrite,
                repo_write_consent(),
            )],
        )];
        let res = resolve_picker_activation("proj-a", Some("ws-rw"), &projects);
        let PickerActivationResolution::Launch { policy, workspace } = res else {
            panic!("expected launch, got {res:?}");
        };
        assert_eq!(policy.source, NewTabLaunchSource::DefaultShellDev);
        assert_eq!(policy.workspace, maestro_shell::WorkspacePolicy::RepoWrite);
        assert_eq!(policy.workspace_id, "ws-rw");
        assert_eq!(policy.cwd_basis, NewTabCwdBasis::WorkspaceDerived);
        assert!(!policy.title.is_empty());
        assert!(!policy.title.contains(".sock"));
        let workspace =
            workspace.expect("repo_write launch must thread the fresh Workspace record");
        assert_eq!(workspace.workspace_id, "ws-rw");
        assert_eq!(workspace.project_id, "proj-a");
        assert_eq!(workspace.policy, maestro_shell::WorkspacePolicy::RepoWrite);
        assert!(
            maestro_shell::has_consent(&workspace, maestro_shell::WorkspaceConsentKind::RepoWrite),
            "threaded record must still carry the granted repo_write consent"
        );
    }

    #[test]
    fn resolver_launch_builds_expected_new_tab_launch_policy() {
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-scratch",
                "proj-a",
                maestro_shell::WorkspacePolicy::ScratchCwd,
            )],
        )];
        let PickerActivationResolution::Launch { policy, .. } =
            resolve_picker_activation("proj-a", Some("ws-scratch"), &projects)
        else {
            panic!("expected launch");
        };
        // The launch policy is exactly the secret-free scratch policy the pipeline expects, carrying
        // the activated workspace id verbatim.
        assert_eq!(
            policy,
            NewTabLaunchPolicy {
                source: NewTabLaunchSource::DefaultShellDev,
                workspace: maestro_shell::WorkspacePolicy::ScratchCwd,
                workspace_id: "ws-scratch".to_string(),
                cwd_basis: NewTabCwdBasis::WorkspaceDerived,
                title: policy.title.clone(),
            }
        );
    }

    #[test]
    fn resolver_title_falls_back_to_workspace_id_when_name_blank() {
        let projects = vec![project(
            "proj-a",
            "   ",
            vec![ws(
                "ws-scratch",
                "proj-a",
                maestro_shell::WorkspacePolicy::ScratchCwd,
            )],
        )];
        let PickerActivationResolution::Launch { policy, .. } =
            resolve_picker_activation("proj-a", Some("ws-scratch"), &projects)
        else {
            panic!("expected launch");
        };
        assert!(
            policy.title.contains("ws-scratch"),
            "blank project name should fall back to the workspace id: {}",
            policy.title
        );
    }

    #[test]
    fn plain_activation_never_grants_for_missing_consent_repo_write() {
        // Defense-in-depth: the bare `PickerRowActivated` resolver declines a missing-consent RepoWrite
        // (no grant, no launch) — only the explicit request/confirm path can grant repo-write access.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-rw",
                "proj-a",
                maestro_shell::WorkspacePolicy::RepoWrite,
            )],
        )];
        assert_eq!(
            resolve_picker_activation("proj-a", Some("ws-rw"), &projects),
            PickerActivationResolution::Decline {
                reason: PickerActivationDeclineReason::RepoWriteLiveCheckoutDeferred,
            }
        );
    }

    #[test]
    fn plain_activation_never_grants_for_missing_consent_worktree() {
        // Defense-in-depth: the bare `PickerRowActivated` resolver still declines a missing-consent
        // worktree (no grant, no launch) — only the explicit request/confirm path can grant.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-wt",
                "proj-a",
                maestro_shell::WorkspacePolicy::Worktree,
            )],
        )];
        assert_eq!(
            resolve_picker_activation("proj-a", Some("ws-wt"), &projects),
            PickerActivationResolution::Decline {
                reason: PickerActivationDeclineReason::WorktreeConsentDeferred,
            }
        );
    }

    // ---- picker stale/header listener composition (localized here from lib.rs) ----
    // These exercise picker projection / activation / hint behavior together with
    // `maestro_renderer::compose_picker_rows`, but they are still picker-domain tests.

    #[test]
    fn header_listener_composition_yields_one_hint_row_plus_browse_rows() {
        // Mirror exactly what the foreground listener does on a project-header activation:
        // resolve (non-launch), then build a FRESH browse model from the same snapshot and attach
        // the header hint. Compose the rows and assert exactly one hint row sits above the normal
        // project/workspace rows, and that the resolution never launches.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-scratch",
                "proj-a",
                maestro_shell::WorkspacePolicy::ScratchCwd,
            )],
        )];
        let snapshot = maestro_shell::DashboardSnapshot {
            projects: projects.clone(),
            ..Default::default()
        };

        // (a) Resolver never launches a header.
        assert!(matches!(
            resolve_picker_activation("proj-a", None, &snapshot.projects),
            PickerActivationResolution::Decline {
                reason: PickerActivationDeclineReason::ProjectHeader
            }
        ));

        // (b) The listener rebuilds the browse model from the SAME fresh snapshot and attaches the
        // hint — exactly one model, hint set.
        let projection = build_picker_projection(&snapshot);
        let mut model = build_picker_overlay_model(&projection);
        model.hint = Some(project_header_hint_text("proj-a", &snapshot.projects));

        // (c) Composing that model yields one disabled hint row, then the header + workspace rows.
        let rows = maestro_renderer::compose_picker_rows(&model);
        let hint_rows: Vec<_> = rows
            .iter()
            .filter(|r| r.text.starts_with("Select a workspace under Alpha"))
            .collect();
        assert_eq!(hint_rows.len(), 1, "exactly one hint row");
        assert_eq!(
            hint_rows[0].target,
            maestro_renderer::PickerRowTarget::Disabled
        );
        assert!(rows
            .iter()
            .any(|r| matches!(&r.target, maestro_renderer::PickerRowTarget::Project { project_id } if project_id == "proj-a")));
        assert!(rows.iter().any(|r| matches!(
            &r.target,
            maestro_renderer::PickerRowTarget::Workspace { workspace_id, .. } if workspace_id == "ws-scratch"
        )));
    }

    #[test]
    fn header_listener_stale_project_composes_unavailable_hint() {
        // If the activated project vanished from the fresh records, the listener attaches the
        // stale-project hint and the overlay still composes (no panic, no launch).
        let snapshot = maestro_shell::DashboardSnapshot {
            projects: vec![project("proj-a", "Alpha", vec![])],
            ..Default::default()
        };
        let projection = build_picker_projection(&snapshot);
        let mut model = build_picker_overlay_model(&projection);
        model.hint = Some(project_header_hint_text("proj-gone", &snapshot.projects));
        let rows = maestro_renderer::compose_picker_rows(&model);
        assert_eq!(rows[0].target, maestro_renderer::PickerRowTarget::Disabled);
        assert_eq!(rows[0].text, "Project is no longer available.");
    }

    #[test]
    fn stale_decline_listener_composition_yields_one_hint_row_plus_refreshed_browse_rows() {
        // Mirror exactly what the foreground listener does on a stale/race decline: resolve
        // (non-launch), then rebuild a FRESH browse model from the SAME snapshot and attach the
        // generic stale hint. Compose the rows and assert exactly one disabled hint row sits above
        // the refreshed project/workspace rows, for each of the three stale/race reasons.
        let snapshot = maestro_shell::DashboardSnapshot {
            projects: vec![project(
                "proj-a",
                "Alpha",
                vec![ws(
                    "ws-scratch",
                    "proj-a",
                    maestro_shell::WorkspacePolicy::ScratchCwd,
                )],
            )],
            ..Default::default()
        };

        // A row that resolves to each stale/race reason against this fresh snapshot.
        let stale_activations = [
            // UnknownProject: activated project absent from fresh records.
            ("proj-gone", "ws-scratch"),
            // UnknownWorkspace: project exists, workspace absent.
            ("proj-a", "ws-gone"),
        ];
        for (project_id, workspace_id) in stale_activations {
            let resolution =
                resolve_picker_activation(project_id, Some(workspace_id), &snapshot.projects);
            let reason = match resolution {
                PickerActivationResolution::Decline { reason } => reason,
                other => panic!("expected a decline, got {other:?}"),
            };
            let hint =
                picker_stale_decline_hint_text(&reason).expect("stale/race reason yields a hint");

            // Rebuild the browse model from the SAME fresh snapshot and attach the generic hint.
            let projection = build_picker_projection(&snapshot);
            let mut model = build_picker_overlay_model(&projection);
            model.hint = Some(hint);

            let rows = maestro_renderer::compose_picker_rows(&model);
            // Exactly one disabled hint row carrying the generic text, sitting first.
            assert_eq!(rows[0].target, maestro_renderer::PickerRowTarget::Disabled);
            assert_eq!(rows[0].text, PICKER_STALE_DECLINE_HINT);
            let hint_rows: Vec<_> = rows
                .iter()
                .filter(|r| r.text == PICKER_STALE_DECLINE_HINT)
                .collect();
            assert_eq!(hint_rows.len(), 1, "exactly one generic stale hint row");
            // The refreshed browse rows are present beneath the hint (the stale row is simply gone).
            assert!(rows.iter().any(|r| matches!(
                &r.target,
                maestro_renderer::PickerRowTarget::Workspace { workspace_id, .. } if workspace_id == "ws-scratch"
            )));
        }
    }

    #[test]
    fn consent_deferred_reasons_produce_no_hint_in_composition_path() {
        // The same listener-composition path must attach NO generic hint for the *Deferred reasons:
        // the helper returns None, so the model carries no stale hint row.
        let snapshot = maestro_shell::DashboardSnapshot {
            projects: vec![project("proj-a", "Alpha", vec![])],
            ..Default::default()
        };
        for reason in [
            PickerActivationDeclineReason::WorktreeConsentDeferred,
            PickerActivationDeclineReason::RepoWriteLiveCheckoutDeferred,
        ] {
            let projection = build_picker_projection(&snapshot);
            let mut model = build_picker_overlay_model(&projection);
            model.hint = picker_stale_decline_hint_text(&reason);
            assert!(
                model.hint.is_none(),
                "reason {reason:?} must not attach a generic stale hint"
            );
            let rows = maestro_renderer::compose_picker_rows(&model);
            assert!(
                rows.iter().all(|r| r.text != PICKER_STALE_DECLINE_HINT),
                "no generic stale hint row may appear for {reason:?}"
            );
        }
    }

    // ---- picker consent request/confirm resolvers (localized here from lib.rs) ----

    #[test]
    fn consent_request_shows_confirm_for_missing_consent_worktree() {
        // A fresh missing-consent worktree under the activated project resolves to ShowConfirm with
        // safe display fields ONLY. It never grants and never launches.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-wt",
                "proj-a",
                maestro_shell::WorkspacePolicy::Worktree,
            )],
        )];
        let res = resolve_picker_consent_request("proj-a", "ws-wt", &projects);
        let PickerConsentRequestResolution::ShowConfirm { confirm } = res else {
            panic!("expected ShowConfirm, got {res:?}");
        };
        assert_eq!(confirm.project_id, "proj-a");
        assert_eq!(confirm.project_name, "Alpha");
        assert_eq!(confirm.workspace_id, "ws-wt");
        assert_eq!(confirm.root, "/proj-a/ws-wt");
        assert_eq!(confirm.policy, "worktree");
        assert_eq!(confirm.consent_kind, "worktree_create");
    }

    #[test]
    fn consent_resolvers_decline_recovery_project_from_raw_snapshot() {
        let projects = vec![project(
            PRODUCT_RECOVERY_PROJECT_ID,
            "Recovery",
            vec![ws(
                "ws-recovery",
                PRODUCT_RECOVERY_PROJECT_ID,
                maestro_shell::WorkspacePolicy::Worktree,
            )],
        )];

        assert_eq!(
            resolve_picker_consent_request(PRODUCT_RECOVERY_PROJECT_ID, "ws-recovery", &projects,),
            PickerConsentRequestResolution::Decline {
                reason: PickerActivationDeclineReason::UnknownProject,
            }
        );
        assert_eq!(
            resolve_picker_consent_confirm(PRODUCT_RECOVERY_PROJECT_ID, "ws-recovery", &projects,),
            PickerConsentConfirmResolution::Decline {
                reason: PickerActivationDeclineReason::UnknownProject,
            }
        );
    }

    #[test]
    fn consent_request_routes_already_consented_to_launch_without_granting() {
        // Consent already landed (another process granted it): the request resolves straight to the
        // already-consented launch path, never re-showing a confirm prompt.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws_with_consent(
                "ws-wt",
                "proj-a",
                maestro_shell::WorkspacePolicy::Worktree,
                worktree_create_consent(),
            )],
        )];
        let res = resolve_picker_consent_request("proj-a", "ws-wt", &projects);
        let PickerConsentRequestResolution::AlreadyConsentedLaunch { policy, workspace } = res
        else {
            panic!("expected AlreadyConsentedLaunch, got {res:?}");
        };
        assert_eq!(policy.workspace, maestro_shell::WorkspacePolicy::Worktree);
        assert!(maestro_shell::has_consent(
            &workspace,
            maestro_shell::WorkspaceConsentKind::WorktreeCreate
        ));
    }

    #[test]
    fn consent_request_revalidation_rejects_stale_and_wrong_policy() {
        let proj_a = project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-wt",
                "proj-a",
                maestro_shell::WorkspacePolicy::Worktree,
            )],
        );
        let proj_b = project(
            "proj-b",
            "Beta",
            vec![ws(
                "ws-b",
                "proj-b",
                maestro_shell::WorkspacePolicy::Worktree,
            )],
        );
        let projects = vec![proj_a, proj_b];

        // Unknown project / unknown workspace.
        assert_eq!(
            resolve_picker_consent_request("proj-missing", "ws-wt", &projects),
            PickerConsentRequestResolution::Decline {
                reason: PickerActivationDeclineReason::UnknownProject,
            }
        );
        assert_eq!(
            resolve_picker_consent_request("proj-a", "ws-nope", &projects),
            PickerConsentRequestResolution::Decline {
                reason: PickerActivationDeclineReason::UnknownWorkspace,
            }
        );
        // Cross-project workspace.
        assert_eq!(
            resolve_picker_consent_request("proj-a", "ws-b", &projects),
            PickerConsentRequestResolution::Decline {
                reason: PickerActivationDeclineReason::WorkspaceProjectMismatch,
            }
        );

        // Policy changed to ScratchCwd: there is nothing to grant for the worktree path.
        let scratch = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-x",
                "proj-a",
                maestro_shell::WorkspacePolicy::ScratchCwd,
            )],
        )];
        assert_eq!(
            resolve_picker_consent_request("proj-a", "ws-x", &scratch),
            PickerConsentRequestResolution::Decline {
                reason: PickerActivationDeclineReason::WorktreeConsentDeferred,
            }
        );

        // A missing-consent RepoWrite row now drives the unified grant path: the request resolves to
        // ShowConfirm with `repo_write` fields (it still NEVER grants or launches). This mirrors the
        // worktree branch but carries the live-checkout consent kind.
        let repo = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-x",
                "proj-a",
                maestro_shell::WorkspacePolicy::RepoWrite,
            )],
        )];
        let res = resolve_picker_consent_request("proj-a", "ws-x", &repo);
        let PickerConsentRequestResolution::ShowConfirm { confirm } = res else {
            panic!("missing-consent RepoWrite request must ShowConfirm, got {res:?}");
        };
        assert_eq!(confirm.policy, "repo_write");
        assert_eq!(confirm.consent_kind, "repo_write");
    }

    #[test]
    fn consent_confirm_grants_and_launches_for_still_missing_consent_worktree() {
        // Fresh records STILL show a missing-consent worktree: the confirm resolves to Grant (the
        // caller may `grant_consent` exactly once, then launch). The resolver itself never grants.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-wt",
                "proj-a",
                maestro_shell::WorkspacePolicy::Worktree,
            )],
        )];
        let res = resolve_picker_consent_confirm("proj-a", "ws-wt", &projects);
        let PickerConsentConfirmResolution::Grant {
            policy,
            consent_kind,
            workspace,
        } = res
        else {
            panic!("expected Grant, got {res:?}");
        };
        assert_eq!(policy.workspace, maestro_shell::WorkspacePolicy::Worktree);
        assert_eq!(policy.workspace_id, "ws-wt");
        assert_eq!(
            consent_kind,
            maestro_shell::WorkspaceConsentKind::WorktreeCreate
        );
        // The resolver returns the PRE-grant record (consent still missing); the caller grants.
        assert!(!maestro_shell::has_consent(
            &workspace,
            maestro_shell::WorkspaceConsentKind::WorktreeCreate
        ));
    }

    #[test]
    fn consent_confirm_already_consented_launches_without_regrant() {
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws_with_consent(
                "ws-wt",
                "proj-a",
                maestro_shell::WorkspacePolicy::Worktree,
                worktree_create_consent(),
            )],
        )];
        let res = resolve_picker_consent_confirm("proj-a", "ws-wt", &projects);
        let PickerConsentConfirmResolution::AlreadyConsentedLaunch { workspace, .. } = res else {
            panic!("expected AlreadyConsentedLaunch, got {res:?}");
        };
        assert!(maestro_shell::has_consent(
            &workspace,
            maestro_shell::WorkspaceConsentKind::WorktreeCreate
        ));
    }

    #[test]
    fn consent_request_shows_repo_write_confirm_for_missing_consent_live_checkout() {
        // A fresh missing-consent RepoWrite under the activated project resolves to ShowConfirm with
        // the `repo_write` consent kind and live-checkout policy — display fields ONLY. It never grants
        // and never launches.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-rw",
                "proj-a",
                maestro_shell::WorkspacePolicy::RepoWrite,
            )],
        )];
        let res = resolve_picker_consent_request("proj-a", "ws-rw", &projects);
        let PickerConsentRequestResolution::ShowConfirm { confirm } = res else {
            panic!("expected ShowConfirm, got {res:?}");
        };
        assert_eq!(confirm.project_id, "proj-a");
        assert_eq!(confirm.project_name, "Alpha");
        assert_eq!(confirm.workspace_id, "ws-rw");
        assert_eq!(confirm.root, "/proj-a/ws-rw");
        assert_eq!(confirm.policy, "repo_write");
        assert_eq!(confirm.consent_kind, "repo_write");
    }

    #[test]
    fn consent_request_routes_already_consented_repo_write_to_launch_without_granting() {
        // RepoWrite consent already landed: the request resolves straight to the already-consented
        // launch path with the live-checkout policy, never re-showing a confirm.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws_with_consent(
                "ws-rw",
                "proj-a",
                maestro_shell::WorkspacePolicy::RepoWrite,
                repo_write_consent(),
            )],
        )];
        let res = resolve_picker_consent_request("proj-a", "ws-rw", &projects);
        let PickerConsentRequestResolution::AlreadyConsentedLaunch { policy, workspace } = res
        else {
            panic!("expected AlreadyConsentedLaunch, got {res:?}");
        };
        assert_eq!(policy.workspace, maestro_shell::WorkspacePolicy::RepoWrite);
        assert!(maestro_shell::has_consent(
            &workspace,
            maestro_shell::WorkspaceConsentKind::RepoWrite
        ));
    }

    #[test]
    fn consent_confirm_grants_repo_write_and_launches_for_still_missing_consent() {
        // Fresh records STILL show a missing-consent RepoWrite: the confirm resolves to Grant carrying
        // the `RepoWrite` kind (the caller may `grant_consent` exactly once, then launch). The resolver
        // itself never grants.
        let projects = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-rw",
                "proj-a",
                maestro_shell::WorkspacePolicy::RepoWrite,
            )],
        )];
        let res = resolve_picker_consent_confirm("proj-a", "ws-rw", &projects);
        let PickerConsentConfirmResolution::Grant {
            policy,
            consent_kind,
            workspace,
        } = res
        else {
            panic!("expected Grant, got {res:?}");
        };
        assert_eq!(policy.workspace, maestro_shell::WorkspacePolicy::RepoWrite);
        assert_eq!(policy.workspace_id, "ws-rw");
        assert_eq!(consent_kind, maestro_shell::WorkspaceConsentKind::RepoWrite);
        // The resolver returns the PRE-grant record (consent still missing); the caller grants.
        assert!(!maestro_shell::has_consent(
            &workspace,
            maestro_shell::WorkspaceConsentKind::RepoWrite
        ));
    }

    #[test]
    fn consent_confirm_revalidation_rejects_stale_cross_project_and_wrong_policy() {
        let projects = vec![
            project(
                "proj-a",
                "Alpha",
                vec![ws(
                    "ws-wt",
                    "proj-a",
                    maestro_shell::WorkspacePolicy::Worktree,
                )],
            ),
            project(
                "proj-b",
                "Beta",
                vec![ws(
                    "ws-b",
                    "proj-b",
                    maestro_shell::WorkspacePolicy::Worktree,
                )],
            ),
        ];
        assert_eq!(
            resolve_picker_consent_confirm("proj-a", "ws-b", &projects),
            PickerConsentConfirmResolution::Decline {
                reason: PickerActivationDeclineReason::WorkspaceProjectMismatch,
            }
        );

        let scratch = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-x",
                "proj-a",
                maestro_shell::WorkspacePolicy::ScratchCwd,
            )],
        )];
        assert_eq!(
            resolve_picker_consent_confirm("proj-a", "ws-x", &scratch),
            PickerConsentConfirmResolution::Decline {
                reason: PickerActivationDeclineReason::WorktreeConsentDeferred,
            }
        );

        // A missing-consent RepoWrite confirm now authorizes a `RepoWrite` grant (unified grant path);
        // the resolver still never grants itself.
        let repo = vec![project(
            "proj-a",
            "Alpha",
            vec![ws(
                "ws-x",
                "proj-a",
                maestro_shell::WorkspacePolicy::RepoWrite,
            )],
        )];
        let res = resolve_picker_consent_confirm("proj-a", "ws-x", &repo);
        let PickerConsentConfirmResolution::Grant { consent_kind, .. } = res else {
            panic!("missing-consent RepoWrite confirm must Grant, got {res:?}");
        };
        assert_eq!(consent_kind, maestro_shell::WorkspaceConsentKind::RepoWrite);
    }
}
