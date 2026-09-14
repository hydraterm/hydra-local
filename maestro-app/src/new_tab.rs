//! The extracted NewTab production cluster: the new-tab planning surface, the prepared-start /
//! workspace-preparation / session-start / layout-record / strip-projection / renderer-send runtime
//! pipeline, and the foreground failure classification + recovery (plan / resolve / execute / effects)
//! machinery. Moved verbatim out of `lib.rs`; every item keeps the visibility it had there and is
//! re-exported from the crate root so existing `maestro_app::<Item>` paths keep working.

// Foreground failures deliberately retain consume-once handoff, rollback, and recovery receipts.
#![allow(clippy::large_enum_variant, clippy::result_large_err)]

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::{
    build_tab_strip_model, live_tab_records_json, renderer_tab_strip, RendererTabRuntime,
    TabSelection, TabStripModel, TabStripModelError, TabSwitchError, WindowTabJson,
    ID_MINT_ATTEMPTS,
};

/// Where a new tab's launch command/argv is re-resolved from. Carries NO raw argv and NO secrets:
/// command/argv is re-resolved at start time from a non-secret launch-spec id (or, for
/// an explicit dev/test policy only, a default-shell marker), never read back out of a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewTabLaunchSource {
    /// Re-resolve argv from a known-safe, non-secret launch-spec id at start time.
    KnownSafeSpec { launch_spec_id: String },
    /// Start a default shell. Only valid for an explicit, pre-declared dev/test launch policy — it
    /// is never selected by the `+` glyph alone (the final product routes `+` through the launcher).
    DefaultShellDev,
    /// A reviewed explicit custom Agent launch. The raw source argv remains live-only and is sealed
    /// as non-replayable AdHoc metadata after the exact workspace/cwd is prepared.
    PreparedAgentAdHoc,
}

/// How a new tab's cwd is derived. A `Worktree`/`RepoWrite` cwd is never blindly
/// inherited; only a `ScratchCwd` (or already-consented) basis may reuse the current tab's cwd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewTabCwdBasis {
    /// Reuse the current tab's already-resolved `cwd_resolved` (non-secret). Only safe under a
    /// scratch/already-consented workspace mode.
    InheritCurrent,
    /// An explicit cwd the caller already resolved (e.g. a launcher selection).
    Explicit { cwd: String },
    /// Derive the cwd from the chosen workspace policy at preparation time.
    WorkspaceDerived,
}

/// A resolved, secret-free new-tab launch policy: the app-owned inputs a `NewTabRequested`
/// handler needs BEFORE any session starts. It is deliberately free of raw argv, env secrets,
/// tokens, and daemon socket details — those flow live to the daemon at start time, never here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTabLaunchPolicy {
    /// Where command/argv is re-resolved from.
    pub source: NewTabLaunchSource,
    /// The workspace isolation mode (reuses the shell's policy enum). `+`-alone may only carry
    /// `ScratchCwd`; a write-capable mode must come from an explicit, consent-backed selection.
    pub workspace: maestro_shell::WorkspacePolicy,
    /// The workspace IDENTITY stamped into new `SessionRecord`s and scratch/worktree paths.
    /// Distinct from `workspace` (the mode/capability): session startup needs this to
    /// build `StartParams` / `PreparedWorkspace::adhoc_start_params(...)`. Secret-free.
    pub workspace_id: String,
    /// How the cwd is derived.
    pub cwd_basis: NewTabCwdBasis,
    /// Presentation-only tab title (e.g. `"shell"`). Never parsed as identity.
    pub title: String,
}

/// The no-I/O state a [`plan_new_tab`] call reads to plan a new tab. The planner NEVER reads records
/// or mutates anything; the caller projects this from its in-memory window state before calling.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewTabSnapshot {
    /// Tab ids already present in the target window layout (uniqueness is enforced against these).
    pub existing_tab_ids: Vec<String>,
    /// Session ids already present (uniqueness is enforced against these).
    pub existing_session_ids: Vec<String>,
    /// The currently active tab id, if any. Unused by the decline/abort/create policy in this
    /// operation; retained so callers may clone the active tab's launch spec.
    pub active_tab_id: Option<String>,
}

/// An injectable seam for minting `tab_id`/`session_id` values, so tests can drive deterministic ids
/// and exercise the collision/exhaustion paths. Object-safe (`&mut dyn IdGen`). The production
/// implementation is [`UuidIdGen`]; tests use a deterministic scripted generator.
pub trait IdGen {
    /// Mint a candidate tab id. May be called more than once per plan if a candidate collides.
    fn next_tab_id(&mut self) -> String;
    /// Mint a candidate session id. Independent of [`IdGen::next_tab_id`].
    fn next_session_id(&mut self) -> String;
}

/// Production [`IdGen`] that mints fresh random UUIDv4 strings. Each call to `next_tab_id` /
/// `next_session_id` is an independent `Uuid::new_v4()` mint, so the two identities are never derived
/// from each other (the tab/session identity-independence invariant). Plain hyphenated UUID strings —
/// no prefixes — so the planner/tests treat them as ordinary product ids. The
/// [`plan_new_tab`] re-mint/abort guard still applies on the (astronomically unlikely) collision.
#[derive(Debug, Default, Clone, Copy)]
pub struct UuidIdGen;

impl IdGen for UuidIdGen {
    fn next_tab_id(&mut self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
    fn next_session_id(&mut self) -> String {
        uuid::Uuid::new_v4().to_string()
    }
}

/// Why [`plan_new_tab`] could not produce a `Create`. Typed so the caller logs a precise reason
/// rather than guessing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewTabAbortReason {
    /// A unique `tab_id` could not be minted within [`ID_MINT_ATTEMPTS`] attempts.
    TabIdMintExhausted,
    /// A unique `session_id` could not be minted within [`ID_MINT_ATTEMPTS`] attempts.
    SessionIdMintExhausted,
}

/// The pure outcome of planning a new tab. The caller turns a `Create` into the durable/daemon/
/// renderer sequence; `Decline`/`Abort` produce no side effect at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewTabPlan {
    /// No launch policy was available: do nothing (the safe intent-only fallback). NOT an error.
    Decline,
    /// Planning failed for a typed reason (e.g. id-mint exhaustion). No ids are returned.
    Abort { reason: NewTabAbortReason },
    /// Planning succeeded: the caller may proceed to start a session and open a tab with these
    /// independent, snapshot-unique ids and the policy-derived presentation/launch fields.
    Create {
        tab_id: String,
        session_id: String,
        source: NewTabLaunchSource,
        workspace: maestro_shell::WorkspacePolicy,
        workspace_id: String,
        cwd_basis: NewTabCwdBasis,
        title: String,
    },
}

/// Mint an id (via `mint`) that is unique against both `existing` and `reserved`, re-minting on
/// collision up to [`ID_MINT_ATTEMPTS`] times. `reserved` carries ids that are not in the snapshot
/// but must still be treated as taken — e.g. an already-accepted `tab_id` that the `session_id` must
/// not equal, enforcing the tab/session identity-independence invariant. Returns `None` if every
/// attempt collided (only possible with a deterministic/test generator; a real UUIDv4 source never
/// collides). PURE.
fn mint_unique_id(
    existing: &[String],
    reserved: &[&str],
    mut mint: impl FnMut() -> String,
) -> Option<String> {
    for _ in 0..ID_MINT_ATTEMPTS {
        let candidate = mint();
        let collides =
            existing.iter().any(|e| e == &candidate) || reserved.iter().any(|r| *r == candidate);
        if !collides {
            return Some(candidate);
        }
    }
    None
}

/// Pure planner for a `RendererEvent::NewTabRequested`. Decides between decline / abort / create
/// WITHOUT any side effect: no filesystem, daemon, renderer command, record store, or workspace
/// preparation, and it does not mutate `snapshot`.
///
/// Rules:
/// - no policy -> [`NewTabPlan::Decline`] (the safe intent-only fallback), and `id_gen` is NOT
///   called;
/// - mint INDEPENDENT `tab_id` and `session_id`, each unique against `snapshot`, re-minting on
///   collision up to [`ID_MINT_ATTEMPTS`]; the `session_id` additionally may never equal the
///   accepted `tab_id` (the identity-independence invariant), so an equal candidate re-mints;
/// - if uniqueness cannot be reached within the bound -> [`NewTabPlan::Abort`] with a typed reason;
/// - otherwise [`NewTabPlan::Create`] carrying the ids plus the policy-derived launch/presentation
///   fields (the policy is cloned, never argv/secrets).
pub fn plan_new_tab(
    policy: Option<&NewTabLaunchPolicy>,
    snapshot: &NewTabSnapshot,
    id_gen: &mut dyn IdGen,
) -> NewTabPlan {
    let Some(policy) = policy else {
        return NewTabPlan::Decline;
    };
    let Some(tab_id) = mint_unique_id(&snapshot.existing_tab_ids, &[], || id_gen.next_tab_id())
    else {
        return NewTabPlan::Abort {
            reason: NewTabAbortReason::TabIdMintExhausted,
        };
    };
    // The session id must be unique against the snapshot AND must never equal the accepted tab id:
    // Tab and session are independent identities, so an equal candidate is a collision.
    let Some(session_id) =
        mint_unique_id(&snapshot.existing_session_ids, &[tab_id.as_str()], || {
            id_gen.next_session_id()
        })
    else {
        return NewTabPlan::Abort {
            reason: NewTabAbortReason::SessionIdMintExhausted,
        };
    };
    NewTabPlan::Create {
        tab_id,
        session_id,
        source: policy.source.clone(),
        workspace: policy.workspace,
        workspace_id: policy.workspace_id.clone(),
        cwd_basis: policy.cwd_basis.clone(),
        title: policy.title.clone(),
    }
}

/// The ASCII suffix appended to the live status label when a `+` new-tab click is declined for
/// lack of a launch policy. Deterministic and message-stable so tests can assert it exactly.
pub const NEW_TAB_DECLINE_HINT: &str = "new tab needs launch policy";

/// Compose the visible decline status label shown when a no-policy `+` click is declined: the base
/// status label (what the dashboard suffix already produced) with the decline hint appended after a
/// ` · ` separator. Pure and ASCII-only; never mutates records or mints ids.
pub fn new_tab_decline_status_label(base: &str) -> String {
    format!("{base} · {NEW_TAB_DECLINE_HINT}")
}

/// The planned new-tab identity plus the [`maestro_shell::StartParams`] a daemon session
/// start needs. Produced by [`new_tab_prepared_start_params`] from a [`NewTabPlan::Create`] and an
/// already-[`maestro_shell::PreparedWorkspace`]. Carries no daemon handle and no socket: it is the
/// pure hand-off value fed to
/// [`maestro_shell::ShellRuntime::start_session`].
pub struct NewTabPreparedStart {
    /// The planned tab id (from the `Create`).
    pub tab_id: String,
    /// The planned presentation title (from the `Create`).
    pub title: String,
    /// The ad-hoc start params bound to the prepared cwd and the planned ids.
    pub params: maestro_shell::StartParams,
}

/// Launch input owned by one foreground new-tab/split attempt. The ordinary shell arm is sealed as
/// exact ad-hoc metadata at the prepared cwd. Provider/custom Agent callers use the consume-once
/// source arm so no caller-built `StartParams` or repeatable prepared spec crosses the transaction
/// boundary.
pub struct NewTabForegroundLaunch {
    kind: NewTabForegroundLaunchKind,
    provider_executable: Option<maestro_shell::ProviderExecutable>,
}

enum NewTabForegroundLaunchKind {
    ShellAdHoc {
        argv: Vec<String>,
    },
    AgentAdHoc {
        source_argv: Vec<String>,
        selected_agent: Option<String>,
    },
    Provider {
        provider_id: String,
        source_argv: Vec<String>,
        selected_agent: String,
    },
    ProviderCustomAdHoc {
        provider_id: String,
        source_argv: Vec<String>,
        selected_agent: String,
    },
}

impl NewTabForegroundLaunch {
    pub fn with_provider_executable(
        mut self,
        executable: Option<maestro_shell::ProviderExecutable>,
    ) -> Self {
        self.provider_executable = executable;
        self
    }

    pub fn shell_adhoc(argv: &[String]) -> Self {
        Self {
            provider_executable: None,
            kind: NewTabForegroundLaunchKind::ShellAdHoc {
                argv: argv.to_vec(),
            },
        }
    }

    pub fn agent_adhoc(source_argv: Vec<String>, selected_agent: Option<String>) -> Option<Self> {
        let command = source_argv.first()?;
        (!command.trim().is_empty()).then_some(Self {
            provider_executable: None,
            kind: NewTabForegroundLaunchKind::AgentAdHoc {
                source_argv,
                selected_agent,
            },
        })
    }

    pub fn provider(
        provider_id: String,
        source_argv: Vec<String>,
        selected_agent: String,
    ) -> Option<Self> {
        maestro_shell::is_strict_prepared_provider_launch(&provider_id, &source_argv).then_some(
            Self {
                provider_executable: None,
                kind: NewTabForegroundLaunchKind::Provider {
                    provider_id,
                    source_argv,
                    selected_agent,
                },
            },
        )
    }

    pub fn provider_custom_adhoc(
        provider_id: String,
        source_argv: Vec<String>,
        selected_agent: String,
    ) -> Option<Self> {
        maestro_shell::is_valid_prepared_provider_custom_adhoc(&provider_id, &source_argv)
            .then_some(Self {
                provider_executable: None,
                kind: NewTabForegroundLaunchKind::ProviderCustomAdHoc {
                    provider_id,
                    source_argv,
                    selected_agent,
                },
            })
    }

    fn matches_plan_source(&self, source: &NewTabLaunchSource) -> bool {
        match (&self.kind, source) {
            (
                NewTabForegroundLaunchKind::ShellAdHoc { .. },
                NewTabLaunchSource::DefaultShellDev,
            ) => true,
            (
                NewTabForegroundLaunchKind::AgentAdHoc { .. },
                NewTabLaunchSource::PreparedAgentAdHoc,
            ) => true,
            (
                NewTabForegroundLaunchKind::ProviderCustomAdHoc { .. },
                NewTabLaunchSource::PreparedAgentAdHoc,
            ) => true,
            (
                NewTabForegroundLaunchKind::Provider { provider_id, .. },
                NewTabLaunchSource::KnownSafeSpec { launch_spec_id },
            ) => provider_id == launch_spec_id,
            _ => false,
        }
    }

    fn is_valid_for_preparation(&self) -> bool {
        match &self.kind {
            NewTabForegroundLaunchKind::ShellAdHoc { argv }
            | NewTabForegroundLaunchKind::AgentAdHoc {
                source_argv: argv, ..
            } => argv
                .first()
                .is_some_and(|command| !command.trim().is_empty()),
            NewTabForegroundLaunchKind::Provider {
                provider_id,
                source_argv,
                ..
            } => maestro_shell::is_strict_prepared_provider_launch(provider_id, source_argv),
            NewTabForegroundLaunchKind::ProviderCustomAdHoc {
                provider_id,
                source_argv,
                ..
            } => maestro_shell::is_valid_prepared_provider_custom_adhoc(provider_id, source_argv),
        }
    }

    fn into_session_spec_with_reprobe<R>(
        self,
        prepared: &maestro_shell::PreparedWorkspace,
        cols: u16,
        rows: u16,
        now_ms: u64,
        mut reprobe: R,
    ) -> Result<maestro_shell::PreparedSessionSpec, NewTabStartParamsError>
    where
        R: FnMut(&[String], Option<&str>, &Path) -> Result<(), NewTabStartParamsError>,
    {
        let env = maestro_shell::SelectedProviderLaunchEnv {
            env: &maestro_shell::ProcessLaunchEnv,
            selected: self.provider_executable.as_ref(),
        };
        let mut check = |argv: &[String], agent: Option<&str>| {
            if let Some(selected) = env.selected {
                crate::launch_preflight::reprobe_selected_provider(argv, selected)
                    .map_err(|_| NewTabStartParamsError::PreparedLaunch)
            } else {
                reprobe(argv, agent, &prepared.cwd)
            }
        };
        match self.kind {
            NewTabForegroundLaunchKind::ShellAdHoc { argv } => {
                if env.selected.is_some() {
                    check(&argv, None)?;
                }
                prepared
                    .adhoc_session_spec_with_env(
                        maestro_shell::SessionKind::Shell,
                        &argv,
                        &env,
                        cols,
                        rows,
                        now_ms,
                    )
                    .map_err(|_| NewTabStartParamsError::PreparedLaunch)
            }
            NewTabForegroundLaunchKind::AgentAdHoc {
                source_argv,
                selected_agent,
            } => {
                check(&source_argv, selected_agent.as_deref())?;
                prepared
                    .adhoc_session_spec_with_env(
                        maestro_shell::SessionKind::Agent,
                        &source_argv,
                        &env,
                        cols,
                        rows,
                        now_ms,
                    )
                    .map_err(|_| NewTabStartParamsError::PreparedLaunch)
            }
            NewTabForegroundLaunchKind::Provider {
                provider_id,
                source_argv,
                selected_agent,
            } => {
                check(&source_argv, Some(&selected_agent))?;
                prepared
                    .provider_session_spec(&provider_id, &source_argv, &env, cols, rows, now_ms)
                    .map_err(|_| NewTabStartParamsError::PreparedLaunch)
            }
            NewTabForegroundLaunchKind::ProviderCustomAdHoc {
                provider_id,
                source_argv,
                selected_agent,
            } => {
                check(&source_argv, Some(&selected_agent))?;
                prepared
                    .provider_custom_adhoc_session_spec(
                        &provider_id,
                        &source_argv,
                        &env,
                        cols,
                        rows,
                        now_ms,
                    )
                    .map_err(|_| NewTabStartParamsError::PreparedLaunch)
            }
        }
    }
}

/// Why [`new_tab_prepared_start_params`] could not build start params. Typed so the caller can log a
/// precise reason rather than guessing, and so a prepared/planned mismatch fails loudly instead of
/// silently pairing a cwd with the wrong session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewTabStartParamsError {
    /// The plan was `Decline` or `Abort`, not `Create`: there is nothing to start.
    NotCreate,
    /// The launch source is not startable through this adapter. `KnownSafeSpec` requires argv
    /// re-resolution, so this adapter refuses to fake it with the supplied ad-hoc argv.
    UnsupportedLaunchSource { source: NewTabLaunchSource },
    /// The prepared workspace was prepared under a different isolation policy than the plan chose.
    PreparedWorkspacePolicyMismatch {
        expected: maestro_shell::WorkspacePolicy,
        actual: maestro_shell::WorkspacePolicy,
    },
    /// The prepared workspace carries a different workspace identity than the plan.
    PreparedWorkspaceWorkspaceIdMismatch { expected: String, actual: String },
    /// The prepared workspace was prepared for a different session id than the plan minted.
    PreparedWorkspaceSessionIdMismatch { expected: String, actual: String },
    /// A reviewed provider/custom launch could not be reprobed or sealed at the actual prepared
    /// cwd. This occurs before the Unknown+placement transaction and before any daemon byte.
    PreparedLaunch,
    /// The launch carrier and secret-free plan source disagree. Refused before graph/wire.
    PreparedLaunchSourceMismatch,
}

fn validate_new_tab_prepared_identity(
    plan: &NewTabPlan,
    prepared: &maestro_shell::PreparedWorkspace,
    launch: Option<&NewTabForegroundLaunch>,
) -> Result<(String, String), NewTabStartParamsError> {
    let NewTabPlan::Create {
        tab_id,
        session_id,
        source,
        workspace,
        workspace_id,
        cwd_basis: _,
        title,
    } = plan
    else {
        return Err(NewTabStartParamsError::NotCreate);
    };

    if let Some(launch) = launch {
        if !launch.matches_plan_source(source) {
            return Err(NewTabStartParamsError::PreparedLaunchSourceMismatch);
        }
    } else if !matches!(source, NewTabLaunchSource::DefaultShellDev) {
        return Err(NewTabStartParamsError::UnsupportedLaunchSource {
            source: source.clone(),
        });
    }
    if prepared.policy != *workspace {
        return Err(NewTabStartParamsError::PreparedWorkspacePolicyMismatch {
            expected: *workspace,
            actual: prepared.policy,
        });
    }
    if prepared.workspace_id != *workspace_id {
        return Err(
            NewTabStartParamsError::PreparedWorkspaceWorkspaceIdMismatch {
                expected: workspace_id.clone(),
                actual: prepared.workspace_id.clone(),
            },
        );
    }
    if prepared.session_id != *session_id {
        return Err(NewTabStartParamsError::PreparedWorkspaceSessionIdMismatch {
            expected: session_id.clone(),
            actual: prepared.session_id.clone(),
        });
    }
    Ok((tab_id.clone(), title.clone()))
}

fn validate_new_tab_launch_source(
    plan: &NewTabPlan,
    launch: &NewTabForegroundLaunch,
) -> Result<(), NewTabStartParamsError> {
    let NewTabPlan::Create { source, .. } = plan else {
        return Err(NewTabStartParamsError::NotCreate);
    };
    if !launch.is_valid_for_preparation() {
        Err(NewTabStartParamsError::PreparedLaunch)
    } else if launch.matches_plan_source(source) {
        Ok(())
    } else {
        Err(NewTabStartParamsError::PreparedLaunchSourceMismatch)
    }
}

/// Turn a planned new-tab [`NewTabPlan::Create`] plus an already-prepared workspace into the
/// [`maestro_shell::StartParams`] a future daemon session start needs. PURE: no filesystem, no
/// daemon connect, no `ShellRuntime::start_session`, no workspace preparation, no window-layout
/// mutation, no renderer command. It only RESHAPES already-decided inputs.
///
/// The matching guards (`policy`, `workspace_id`, `session_id`) ensure the cwd the workspace was
/// prepared for is paired only with the session the plan minted — never the wrong one.
///
/// `argv` is the real launch argv (first token the command, rest the args). For now only
/// [`NewTabLaunchSource::DefaultShellDev`] is startable; [`NewTabLaunchSource::KnownSafeSpec`] is
/// rejected rather than replayed as ad-hoc argv.
pub fn new_tab_prepared_start_params(
    plan: &NewTabPlan,
    prepared: &maestro_shell::PreparedWorkspace,
    argv: &[String],
    cols: u16,
    rows: u16,
    now_ms: u64,
) -> Result<NewTabPreparedStart, NewTabStartParamsError> {
    let (tab_id, title) = validate_new_tab_prepared_identity(plan, prepared, None)?;

    let params =
        prepared.adhoc_start_params(maestro_shell::SessionKind::Shell, argv, cols, rows, now_ms);
    Ok(NewTabPreparedStart {
        tab_id,
        title,
        params,
    })
}

/// Why [`prepare_new_tab_scratch_workspace`] could not prepare a workspace. Typed so the caller can
/// distinguish "nothing to prepare" (`NotCreate`) from "this helper does not support the isolation
/// policy" (`UnsupportedWorkspacePolicy`) from a real shell preparation failure
/// (`WorkspaceExec`).
#[derive(Debug)]
pub enum NewTabWorkspacePrepareError {
    /// A previous renderer handoff has not produced its correlated terminal disposition. No
    /// workspace/session/layout side effect has begun.
    RendererHandoffPending,
    /// The plan was `Decline` or `Abort`, not `Create`: there is no workspace to prepare. No
    /// filesystem effect.
    NotCreate,
    /// The planned isolation policy is not `ScratchCwd`. This helper rejects `Worktree` and
    /// `RepoWrite` BEFORE any filesystem effect rather than faking preparation.
    UnsupportedWorkspacePolicy {
        policy: maestro_shell::WorkspacePolicy,
    },
    /// `maestro-shell` workspace preparation failed (e.g. an unsafe id, or a scratch path that would
    /// sit under the repo root). The shell error is propagated verbatim; nothing partial is left for
    /// the caller to clean up beyond what `maestro-shell` itself guarantees.
    WorkspaceExec(maestro_shell::WorkspaceExecError),
}

impl std::fmt::Display for NewTabWorkspacePrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NewTabWorkspacePrepareError::RendererHandoffPending => {
                write!(
                    f,
                    "renderer handoff is still pending; new-tab creation is busy"
                )
            }
            NewTabWorkspacePrepareError::NotCreate => {
                write!(f, "new-tab plan was not Create: nothing to prepare")
            }
            NewTabWorkspacePrepareError::UnsupportedWorkspacePolicy { policy } => write!(
                f,
                "new-tab workspace policy {policy:?} is not supported by the scratch preparer"
            ),
            NewTabWorkspacePrepareError::WorkspaceExec(e) => {
                write!(f, "new-tab scratch workspace preparation failed: {e}")
            }
        }
    }
}

impl std::error::Error for NewTabWorkspacePrepareError {}

/// Prepare the `ScratchCwd` workspace a planned new-tab [`NewTabPlan::Create`] needs, producing the
/// [`maestro_shell::PreparedWorkspace`] that [`new_tab_prepared_start_params`] consumes. This is the
/// missing bridge between the pure planner and the pure prepared-start adapter:
///
/// ```text
/// plan_new_tab -> prepare_new_tab_scratch_workspace -> new_tab_prepared_start_params -> (future start)
/// ```
///
/// SIDE EFFECT (the only one): creation of the app-support base, the scratch base, and the per-session
/// scratch cwd (each owner-only), all under `paths`, delegated to [`maestro_shell::prepare_scratch_cwd`].
/// It does NOT connect to the daemon, call `ShellRuntime::start_session`, mutate a window layout, write
/// session records, send renderer commands, touch git, or prepare worktree/repo-write workspaces.
///
/// Only `NewTabPlan::Create { workspace: WorkspacePolicy::ScratchCwd, .. }` is supported here;
/// `Worktree` / `RepoWrite` return [`NewTabWorkspacePrepareError::UnsupportedWorkspacePolicy`] before
/// any filesystem effect. All path resolution, id validation, chmod, and repo-root safety are inherited
/// from `maestro-shell` (not re-implemented), so the returned workspace's policy, workspace id, session
/// id, and cwd are exactly what the shell produced.
pub fn prepare_new_tab_scratch_workspace(
    paths: &maestro_shell::AppPaths,
    plan: &NewTabPlan,
    repo_root: &str,
) -> Result<maestro_shell::PreparedWorkspace, NewTabWorkspacePrepareError> {
    let NewTabPlan::Create {
        workspace,
        workspace_id,
        session_id,
        ..
    } = plan
    else {
        return Err(NewTabWorkspacePrepareError::NotCreate);
    };

    if *workspace != maestro_shell::WorkspacePolicy::ScratchCwd {
        return Err(NewTabWorkspacePrepareError::UnsupportedWorkspacePolicy { policy: *workspace });
    }

    maestro_shell::prepare_scratch_cwd(paths, workspace_id, session_id, repo_root)
        .map_err(NewTabWorkspacePrepareError::WorkspaceExec)
}

/// Fresh-session variant used by the production PreparedNew pipeline. Unlike the public
/// preparation adapter above, it retains the Shell-minted consume-once cleanup receipt.
fn prepare_fresh_new_tab_scratch_workspace(
    paths: &maestro_shell::AppPaths,
    plan: &NewTabPlan,
    repo_root: &str,
) -> Result<
    (
        maestro_shell::PreparedWorkspace,
        NewTabScratchRemovalAuthority,
    ),
    NewTabWorkspacePrepareError,
> {
    let NewTabPlan::Create {
        workspace,
        workspace_id,
        session_id,
        ..
    } = plan
    else {
        return Err(NewTabWorkspacePrepareError::NotCreate);
    };
    if *workspace != maestro_shell::WorkspacePolicy::ScratchCwd {
        return Err(NewTabWorkspacePrepareError::UnsupportedWorkspacePolicy { policy: *workspace });
    }
    let (prepared, receipt) =
        maestro_shell::prepare_fresh_scratch_cwd(paths, workspace_id, session_id, repo_root)
            .map_err(NewTabWorkspacePrepareError::WorkspaceExec)?
            .into_parts();
    Ok((
        prepared,
        NewTabScratchRemovalAuthority::from_fresh_receipt(receipt),
    ))
}

/// The result of starting a planned new tab's daemon session: the planned tab identity carried
/// alongside the [`maestro_shell::StartSessionOutcome`] (socket path + durable session record) that
/// `maestro-shell` produced. The planned `tab_id`/`title` come from the original
/// [`NewTabPlan::Create`] (threaded through [`NewTabPreparedStart`]); the `outcome` is whatever
/// `ShellRuntime::start_session` returned. No window layout, tab record, or renderer state is
/// produced here — that is later GUI wiring.
#[derive(Debug)]
pub struct NewTabSessionStart {
    /// The planned tab id (from the `Create`, threaded through the prepared start).
    pub tab_id: String,
    /// The planned presentation title (from the `Create`).
    pub title: String,
    /// The shell-runtime start outcome: the socket actually used and the durable session record.
    pub outcome: maestro_shell::StartSessionOutcome,
}

/// Why [`start_new_tab_prepared_session`] could not start the session. The shell runtime owns all of
/// connect / endpoint-persist / session-start / record-persist; its typed
/// [`maestro_shell::ShellRuntimeError`] is propagated verbatim so the caller can still tell a
/// resolution/persist failure from an unreachable daemon from a daemon refusal.
#[derive(Debug)]
pub enum NewTabSessionStartError {
    /// The shell runtime failed to resolve/connect/persist/start. Propagated unchanged.
    Shell(maestro_shell::ShellRuntimeError),
    /// The production recovery state machine already consumed the owned error authority. A second
    /// execution is intentionally inert.
    AuthorityHandled,
}

impl std::fmt::Display for NewTabSessionStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NewTabSessionStartError::Shell(e) => {
                write!(f, "new-tab session start failed: {e}")
            }
            NewTabSessionStartError::AuthorityHandled => {
                f.write_str("new-tab session start authority was already handled")
            }
        }
    }
}

impl std::error::Error for NewTabSessionStartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NewTabSessionStartError::Shell(e) => Some(e),
            NewTabSessionStartError::AuthorityHandled => None,
        }
    }
}

impl NewTabSessionStartError {
    fn take_shell_error(&mut self) -> Option<maestro_shell::ShellRuntimeError> {
        match std::mem::replace(self, Self::AuthorityHandled) {
            Self::Shell(error) => Some(error),
            Self::AuthorityHandled => None,
        }
    }
}

/// Start the daemon session for a planned new tab, the first consumer after
/// [`new_tab_prepared_start_params`]. It takes the [`NewTabPreparedStart`] that adapter produced
/// (which already carries the validated [`maestro_shell::StartParams`] bound to the prepared cwd and
/// the planned ids) and hands the start params straight to
/// [`maestro_shell::ShellRuntime::start_session_for_renderer`]:
///
/// ```text
/// plan_new_tab -> prepare_new_tab_scratch_workspace -> new_tab_prepared_start_params
///   -> start_new_tab_prepared_session -> (separate layout mutation / renderer attach)
/// ```
///
/// This helper touches the daemon/session runtime but is NOT GUI wiring. It does NOT spawn or
/// ensure a daemon (it expects an already-reachable socket, via
/// `explicit_socket` or the shell runtime's existing resolution rules), prepare a workspace, mutate
/// a window layout, write an app-owned tab record, send a renderer command, or apply any
/// cleanup/kill policy.
///
/// SIDE EFFECTS are exactly what `ShellRuntime::start_session_for_renderer` performs: connect to
/// the daemon; persist/update the daemon endpoint only AFTER a successful connect; start/attach the
/// session; atomically publish its durable Grid generation; and reserve one opaque one-shot
/// attachment handoff for the renderer. App code reimplements none of that. On failure the typed
/// [`maestro_shell::ShellRuntimeError`] is propagated through
/// [`NewTabSessionStartError::Shell`].
#[cfg(test)]
fn start_new_tab_prepared_session(
    paths: &maestro_shell::AppPaths,
    explicit_socket: Option<std::path::PathBuf>,
    env: &impl maestro_shell::EnvLookup,
    prepared: &NewTabPreparedStart,
) -> Result<NewTabSessionStart, NewTabSessionStartError> {
    let outcome = maestro_shell::ShellRuntime::new(paths)
        .start_session_for_renderer(explicit_socket, env, &prepared.params)
        .map_err(NewTabSessionStartError::Shell)?;
    Ok(NewTabSessionStart {
        tab_id: prepared.tab_id.clone(),
        title: prepared.title.clone(),
        outcome,
    })
}

/// The updated layout plus the tab/session identity recorded by [`record_new_tab_in_window_layout`].
pub struct NewTabLayoutRecord {
    /// The tab id that was appended (the planned tab id from the started session).
    pub tab_id: String,
    /// The session id bound to that tab (the started session's durable record id).
    pub session_id: String,
    /// The window layout after the tab was appended (post-normalize, as the service returns it).
    pub layout: maestro_shell::WindowLayout,
}

impl std::fmt::Debug for NewTabLayoutRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewTabLayoutRecord")
            .field("tab_id", &self.tab_id)
            .field("session_id", &self.session_id)
            .field("tab_count", &self.layout.tabs.len())
            .finish_non_exhaustive()
    }
}

/// Why [`record_new_tab_in_window_layout`] could not record the tab. The
/// [`maestro_shell::WindowLayoutService`] owns missing-window detection (`WindowLayoutNotFound`),
/// duplicate-tab detection (`TabAlreadyExists`), id validation, future-version/corrupt handling,
/// index normalization, and the atomic write; its typed
/// [`maestro_shell::window_layout::WindowLayoutError`] is propagated verbatim.
#[derive(Debug)]
pub enum NewTabLayoutRecordError {
    /// The window-layout service rejected or failed the `open_tab` mutation. Propagated unchanged.
    WindowLayout(maestro_shell::window_layout::WindowLayoutError),
}

impl std::fmt::Display for NewTabLayoutRecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NewTabLayoutRecordError::WindowLayout(e) => {
                write!(f, "recording new tab in window layout failed: {e}")
            }
        }
    }
}

impl std::error::Error for NewTabLayoutRecordError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NewTabLayoutRecordError::WindowLayout(e) => Some(e),
        }
    }
}

/// Record an already-started new-tab session into an EXISTING window layout, the durable-state
/// consumer after [`start_new_tab_prepared_session`]:
///
/// ```text
/// ... -> start_new_tab_prepared_session -> record_new_tab_in_window_layout
///   -> (future renderer attach / tab-strip update)
/// ```
///
/// It appends one tab to the window `window_id` via
/// [`maestro_shell::WindowLayoutService::open_tab`], binding `started.tab_id` to the started
/// session's durable id (`started.outcome.record.session_id`) with `started.title`, `pinned = false`,
/// and the default no-attention state ([`maestro_shell::AttentionState::default`], i.e.
/// `Attention::None`). The caller supplies `now_ms`.
///
/// This requires an existing layout: it does NOT create a window. If the window is unknown the
/// service surfaces `WindowLayoutNotFound`, propagated through
/// [`NewTabLayoutRecordError::WindowLayout`]; likewise duplicate-tab, id-validation,
/// future-version/corrupt, and store failures stay owned by the service (this helper reimplements
/// none of them).
///
/// The ONLY side effect is the single `open_tab` layout mutation and its atomic store write. It does
/// NOT connect to or start a daemon/session, prepare a workspace, send a renderer `AttachSession` /
/// `SetTabStrip`, mutate a `RendererTabRuntime`, or apply any cleanup/kill policy. It consumes an
/// already-started [`NewTabSessionStart`]; it does not start the session itself.
#[cfg(test)]
fn record_new_tab_in_window_layout(
    paths: &maestro_shell::AppPaths,
    window_id: &str,
    started: &NewTabSessionStart,
    split_from: Option<&NewTabSplitFrom>,
    now_ms: u64,
) -> Result<NewTabLayoutRecord, NewTabLayoutRecordError> {
    let session_id = started.outcome.record.session_id.clone();
    let service = maestro_shell::WindowLayoutService::new(paths);
    let rollback_snapshot = match split_from {
        Some(split) => service.split_tab_snapshot(
            window_id,
            &split.from_tab_id,
            &started.tab_id,
            &session_id,
            &started.title,
            split.axis,
            now_ms,
        ),
        None => service.open_tab_snapshot(
            window_id,
            &started.tab_id,
            &session_id,
            &started.title,
            false,
            maestro_shell::AttentionState::default(),
            now_ms,
        ),
    }
    .map_err(NewTabLayoutRecordError::WindowLayout)?;
    let layout = rollback_snapshot.layout.clone();
    Ok(NewTabLayoutRecord {
        tab_id: started.tab_id.clone(),
        session_id,
        layout,
    })
}

/// The no-I/O projection of a just-recorded new tab: the recorded tab/session identity plus both
/// strip projections — the app-side [`TabStripModel`] and the renderer-side
/// [`maestro_renderer::RendererTabStrip`] — with the newly recorded tab marked active.
#[derive(Debug)]
pub struct NewTabStripProjection {
    pub tab_id: String,
    pub session_id: String,
    pub model: TabStripModel,
    pub renderer_strip: maestro_renderer::RendererTabStrip,
}

/// Why [`new_tab_strip_projection`] could not project a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewTabStripProjectionError {
    /// The recorded `tab_id` was not present in `record.layout.tabs`. We refuse to silently produce a
    /// strip with no active tab when the layout should already contain the recorded tab.
    ActiveTabNotFound {
        tab_id: String,
    },
    /// The committed layout could not be reloaded as one all-pane exact lifetime cohort. No partial
    /// renderer membership is sent.
    ExactViewport(crate::RendererViewportProjectionError),
    ExactViewportSnapshot(String),
}

impl std::fmt::Display for NewTabStripProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NewTabStripProjectionError::ActiveTabNotFound { tab_id } => {
                write!(
                    f,
                    "recorded tab id {tab_id:?} is not in the recorded layout"
                )
            }
            NewTabStripProjectionError::ExactViewport(error) => error.fmt(f),
            NewTabStripProjectionError::ExactViewportSnapshot(error) => f.write_str(error),
        }
    }
}

impl std::error::Error for NewTabStripProjectionError {}

/// Project a just-recorded [`NewTabLayoutRecord`] into the app tab-strip model and the renderer
/// tab-strip payload, with the newly recorded tab active. This is the PURE, no-I/O bridge between
/// durable layout recording ([`record_new_tab_in_window_layout`]) and a future renderer command
/// send: it converts only the updated layout's LIVE rows into [`WindowTabJson`] via
/// [`live_tab_records_json`], builds a [`TabStripModel`] with `record.tab_id` active via
/// [`build_tab_strip_model`], and converts that to a [`maestro_renderer::RendererTabStrip`] via
/// [`renderer_tab_strip`]. Durable parked rows remain in `record.layout` for inspection and identity
/// reservation but never re-enter the native renderer projection.
///
/// It performs NO filesystem, daemon connect, session start, workspace preparation, window-layout
/// mutation, renderer command send, `RendererTabRuntime` mutation, event-loop wiring, or git. If the
/// recorded `tab_id` is not present in the recorded layout it returns
/// [`NewTabStripProjectionError::ActiveTabNotFound`] rather than producing a strip with no active tab.
pub fn new_tab_strip_projection(
    window_id: &str,
    record: &NewTabLayoutRecord,
) -> Result<NewTabStripProjection, NewTabStripProjectionError> {
    let tabs = live_tab_records_json(&record.layout.tabs);
    let model =
        build_tab_strip_model(window_id, &tabs, Some(&record.tab_id)).map_err(|e| match e {
            TabStripModelError::ActiveTabNotFound { tab_id } => {
                NewTabStripProjectionError::ActiveTabNotFound { tab_id }
            }
        })?;
    let renderer_strip = renderer_tab_strip(&model);
    Ok(NewTabStripProjection {
        tab_id: record.tab_id.clone(),
        session_id: record.session_id.clone(),
        model,
        renderer_strip,
    })
}

/// The recorded tab/session identity returned after the new tab's strip update was delivered to the
/// renderer. Carries `tab_id`/`session_id` through so the caller can attach the correct started
/// session WITHOUT re-reading the layout.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTabSetTabStrip {
    pub tab_id: String,
    pub session_id: String,
}

/// Why [`send_new_tab_set_tab_strip`] could not deliver the strip update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewTabSetTabStripError {
    /// The renderer command receiver is closed (event loop gone); the `SetTabStrip` was not
    /// delivered. Mapped from [`TabSwitchError::RendererControlClosed`]; never swallowed or retried.
    RendererControlClosed,
    HandoffPending,
}

impl std::fmt::Display for NewTabSetTabStripError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NewTabSetTabStripError::RendererControlClosed => {
                write!(
                    f,
                    "renderer command channel is closed; tab strip not updated"
                )
            }
            NewTabSetTabStripError::HandoffPending => {
                write!(
                    f,
                    "renderer handoff is still pending; tab strip not updated"
                )
            }
        }
    }
}

impl std::error::Error for NewTabSetTabStripError {}

/// Send exactly one renderer `SetTabStrip` command for a just-projected new tab, returning the
/// recorded `tab_id`/`session_id`. This is the first I/O-bearing consumer after the pure
/// [`new_tab_strip_projection`]: it updates ONLY the read-only tab-strip overlay, leaving session
/// session attach to its caller.
///
/// It delegates to [`RendererTabRuntime::set_tab_strip`]`(Some(&projection.model))`, so the wire
/// payload is the same `renderer_tab_strip(&projection.model)` (== `projection.renderer_strip`) the
/// existing display path produces. It does NOT alter active-tab state, send `AttachSession`, call
/// `switch_to`/`on_tab_activated`, start sessions, prepare workspaces, mutate layouts, connect to a
/// daemon, touch the filesystem, wire foreground `RendererEvent::NewTabRequested`, or touch git. A
/// closed receiver surfaces [`NewTabSetTabStripError::RendererControlClosed`] (mapped from
/// [`TabSwitchError::RendererControlClosed`]); the error is neither swallowed nor retried.
pub fn send_new_tab_set_tab_strip(
    runtime: &mut RendererTabRuntime,
    projection: &NewTabStripProjection,
) -> Result<NewTabSetTabStrip, NewTabSetTabStripError> {
    runtime
        .set_tab_strip(Some(&projection.model))
        .map_err(|e| match e {
            TabSwitchError::RendererControlClosed => NewTabSetTabStripError::RendererControlClosed,
            TabSwitchError::HandoffPending => NewTabSetTabStripError::HandoffPending,
            // `set_tab_strip` performs no tab lookup, so it can only fail on a closed channel; the
            // lookup-based variants are unreachable for this send path.
            TabSwitchError::TabNotFound { .. } | TabSwitchError::AmbiguousTab { .. } => {
                NewTabSetTabStripError::RendererControlClosed
            }
            TabSwitchError::RendererEventChannelUnavailable
            | TabSwitchError::ViewportAuthorityRequired
            | TabSwitchError::ViewportProjection(_) => NewTabSetTabStripError::HandoffPending,
        })?;
    Ok(NewTabSetTabStrip {
        tab_id: projection.tab_id.clone(),
        session_id: projection.session_id.clone(),
    })
}

/// The result of attaching a just-projected new tab's session to the renderer viewport.
/// Carries the recorded `tab_id`/`session_id` plus whether a command was actually sent
/// (`attached`): `true` when `switch_to` delivered an `AttachSession`, `false` when the same
/// `(window_id, tab_id)` was already the active tab (a no-op, nothing sent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTabAttachSession {
    pub tab_id: String,
    pub session_id: String,
    pub attached: bool,
}

/// Why [`send_new_tab_attach_session`] could not attach the new tab's session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewTabAttachSessionError {
    /// The renderer command receiver is closed (event loop gone); the `AttachSession` was not
    /// delivered and active-tab state is left unchanged. Mapped from
    /// [`TabSwitchError::RendererControlClosed`]; never swallowed or retried.
    RendererControlClosed,
    /// A different renderer handoff is still awaiting its correlated disposition. This refusal is
    /// observable before any new create pipeline side effect begins.
    HandoffPending,
    /// A legacy textual projection cannot authorize a renderer Attach. Production callers must
    /// supply one coherent Shell snapshot projection and (for new sessions) the owned handoff.
    ViewportAuthorityRequired,
    /// The projected `tab_id` was not found in the single-item selection. Unreachable for the
    /// one-element selection this helper builds, but mapped rather than panicked to keep the
    /// helper honest.
    ActiveTabNotFound { tab_id: String },
    /// The projected `tab_id` resolved ambiguously. Also unreachable for the one-element
    /// selection, mapped for honesty.
    AmbiguousTab { tab_id: String },
    /// Renderer command delivery succeeded, but its correlated terminal disposition was not
    /// `Claimed`. The renderer is neutral; the newly-created graph requires forward recovery.
    HandoffNotClaimed {
        outcome: maestro_renderer::RendererAttachmentHandoffOutcome,
        request_id: maestro_renderer::RendererAttachmentHandoffRequestId,
    },
}

impl std::fmt::Display for NewTabAttachSessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NewTabAttachSessionError::RendererControlClosed => {
                write!(
                    f,
                    "renderer command channel is closed; session not attached"
                )
            }
            NewTabAttachSessionError::HandoffPending => {
                write!(
                    f,
                    "renderer handoff is still pending; session attach refused"
                )
            }
            NewTabAttachSessionError::ViewportAuthorityRequired => {
                write!(f, "renderer attach requires an exact viewport authority")
            }
            NewTabAttachSessionError::ActiveTabNotFound { tab_id } => {
                write!(f, "projected tab {tab_id:?} not found in its own selection")
            }
            NewTabAttachSessionError::AmbiguousTab { tab_id } => {
                write!(f, "projected tab {tab_id:?} resolved ambiguously")
            }
            NewTabAttachSessionError::HandoffNotClaimed { outcome, .. } => {
                write!(f, "renderer handoff completed without Claim: {outcome:?}")
            }
        }
    }
}

impl std::error::Error for NewTabAttachSessionError {}

/// Attach a just-projected new tab's session to the renderer viewport, sending at most one
/// `maestro_renderer::RendererCommand::AttachSession` through the existing
/// [`RendererTabRuntime::switch_to`] path. The production handoff variant below instead sends one
/// atomic `AttachSessionWithHandoff` carrying the exact full strip projection plus the opaque
/// Claim; no two-command partial state is exposed.
///
/// It builds the minimal one-item [`TabSelection`] from the projection identity
/// (`tab_id`/`session_id`), uses `projection.model.window_id` as the window, and switches to
/// `projection.tab_id`. Because it goes through `switch_to`, active-tab state advances ONLY after
/// a successful send: `Ok(true)` -> `attached: true`; `Ok(false)` (the same `(window_id, tab_id)`
/// already active) -> `attached: false` with nothing sent; a closed receiver ->
/// [`NewTabAttachSessionError::RendererControlClosed`] with active-tab state unchanged. The
/// unreachable lookup errors are mapped to typed variants rather than panicking.
///
/// It does NOT call `set_tab_strip` / `send_new_tab_set_tab_strip`, send `SetTabStrip`, call
/// `on_tab_activated`, start sessions, prepare workspaces, mutate layouts, connect/spawn a daemon,
/// touch the filesystem, wire foreground `RendererEvent::NewTabRequested`, or touch git.
pub fn send_new_tab_attach_session(
    _runtime: &mut RendererTabRuntime,
    _projection: &NewTabStripProjection,
) -> Result<NewTabAttachSession, NewTabAttachSessionError> {
    Err(NewTabAttachSessionError::ViewportAuthorityRequired)
}

fn send_new_tab_attach_session_with_handoff(
    runtime: &mut RendererTabRuntime,
    projection: &crate::RendererViewportProjection,
    handoff: maestro_renderer::RendererAttachmentHandoff,
) -> Result<NewTabAttachSession, NewTabAttachSessionError> {
    let attached = runtime
        .switch_to_with_handoff(projection.clone(), handoff)
        .map_err(|error| match error {
            TabSwitchError::RendererControlClosed => {
                NewTabAttachSessionError::RendererControlClosed
            }
            TabSwitchError::HandoffPending => NewTabAttachSessionError::HandoffPending,
            TabSwitchError::TabNotFound { tab_id, .. } => {
                NewTabAttachSessionError::ActiveTabNotFound { tab_id }
            }
            TabSwitchError::AmbiguousTab { tab_id, .. } => {
                NewTabAttachSessionError::AmbiguousTab { tab_id }
            }
            TabSwitchError::RendererEventChannelUnavailable
            | TabSwitchError::ViewportAuthorityRequired
            | TabSwitchError::ViewportProjection(_) => {
                NewTabAttachSessionError::ViewportAuthorityRequired
            }
        })?;
    Ok(NewTabAttachSession {
        tab_id: projection.target().tab_id.clone(),
        session_id: projection.target().session_id.clone(),
        attached,
    })
}

const MAX_RETAINED_NEW_TAB_AUTHORITIES: usize = 4096;
static RETAINED_NEW_TAB_HANDOFFS: OnceLock<Mutex<Vec<maestro_shell::AttachmentHandoffAuthority>>> =
    OnceLock::new();
static RETAINED_NEW_TAB_CONDITIONAL_STARTS: OnceLock<
    Mutex<Vec<maestro_shell::ConditionalStartRecoveryAuthority>>,
> = OnceLock::new();

fn retain_new_tab_handoff(authority: maestro_shell::AttachmentHandoffAuthority) {
    let retained = RETAINED_NEW_TAB_HANDOFFS.get_or_init(|| Mutex::new(Vec::new()));
    let mut retained = retained
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if retained.len() < MAX_RETAINED_NEW_TAB_AUTHORITIES {
        retained.push(authority);
    }
}

fn retain_new_tab_conditional_start(authority: maestro_shell::ConditionalStartRecoveryAuthority) {
    let retained = RETAINED_NEW_TAB_CONDITIONAL_STARTS.get_or_init(|| Mutex::new(Vec::new()));
    let mut retained = retained
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if retained.len() < MAX_RETAINED_NEW_TAB_AUTHORITIES {
        retained.push(authority);
    }
}

fn cancel_new_tab_attachment_handoff(authority: maestro_shell::AttachmentHandoffAuthority) {
    if authority.cancel().is_err() {
        retain_new_tab_handoff(authority);
    }
}

fn settle_new_tab_shell_runtime_error(error: maestro_shell::ShellRuntimeError) {
    match error {
        maestro_shell::ShellRuntimeError::Session(
            maestro_shell::SessionServiceError::ConditionalStartPossiblyApplied {
                authority, ..
            },
        ) => {
            let _ = authority.cancel_pending_handoff();
            retain_new_tab_conditional_start(authority);
        }
        maestro_shell::ShellRuntimeError::Session(
            maestro_shell::SessionServiceError::AttachmentHandoffPossiblyPending {
                authority, ..
            },
        ) => cancel_new_tab_attachment_handoff(authority),
        maestro_shell::ShellRuntimeError::Store(_)
        | maestro_shell::ShellRuntimeError::Daemon(_)
        | maestro_shell::ShellRuntimeError::Session(_) => {}
    }
}

/// The post-success foreground listener state for a created new tab. The foreground event loop
/// adopts these projections only after the atomic renderer projection + handoff command has been
/// delivered successfully.
pub struct NewTabForegroundSuccess {
    pub tab_id: String,
    pub session_id: String,
    pub strip_tabs: Vec<WindowTabJson>,
    pub selection: Vec<TabSelection>,
    pub pending_handoff: NewTabForegroundPendingHandoff,
}

impl std::fmt::Debug for NewTabForegroundSuccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewTabForegroundSuccess")
            .field("tab_id", &self.tab_id)
            .field("session_id", &self.session_id)
            .field("strip_tabs", &self.strip_tabs)
            .field("selection", &self.selection)
            .field("pending_handoff", &"<redacted>")
            .finish()
    }
}

pub struct NewTabForegroundPendingHandoff {
    handoff: maestro_renderer::RendererAttachmentHandoff,
    expected_generation: String,
    rollback_authority: Option<NewTabPreparedRollbackAuthority>,
}

impl NewTabForegroundPendingHandoff {
    pub fn request_id(&self) -> maestro_renderer::RendererAttachmentHandoffRequestId {
        self.handoff.request_id()
    }

    pub fn expected_generation(&self) -> &str {
        &self.expected_generation
    }

    pub fn expected_daemon_instance(&self) -> &maestro_shell::DaemonInstanceId {
        self.handoff.authority().expected_daemon_instance()
    }

    pub fn session_id(&self) -> &str {
        self.handoff.authority().session_id().0.as_str()
    }
}

impl std::fmt::Debug for NewTabForegroundPendingHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NewTabForegroundPendingHandoff(<redacted>)")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTabForegroundAdoption {
    pub tab_id: String,
    pub session_id: String,
    pub strip_tabs: Vec<WindowTabJson>,
    pub selection: Vec<TabSelection>,
}

pub enum NewTabForegroundHandoffResolution {
    Claimed(NewTabForegroundAdoption),
    Recover(NewTabForegroundError),
    /// A correlated `Claimed` event whose instance/generation proof contradicts the shell
    /// authority. Preserve the durable graph and leave App neutral; never compensate.
    Contradicted {
        reason: String,
    },
}

impl NewTabForegroundSuccess {
    pub fn resolve_handoff(
        mut self,
        disposition: maestro_renderer::RendererAttachmentHandoffDisposition,
    ) -> Result<
        NewTabForegroundHandoffResolution,
        (Self, maestro_renderer::RendererAttachmentHandoffDisposition),
    > {
        if disposition.request_id() != self.pending_handoff.request_id()
            || disposition.session_id() != self.session_id
        {
            return Err((self, disposition));
        }
        let outcome = disposition.outcome();
        let request_id = disposition.request_id();
        if outcome == maestro_renderer::RendererAttachmentHandoffOutcome::Claimed {
            let exact_instance = disposition.daemon_instance_id()
                == Some(self.pending_handoff.expected_daemon_instance());
            let exact_generation =
                disposition.generation() == Some(self.pending_handoff.expected_generation());
            if !exact_instance || !exact_generation {
                return Ok(NewTabForegroundHandoffResolution::Contradicted {
                    reason:
                        "renderer Claimed disposition contradicted exact daemon/generation proof"
                            .to_string(),
                });
            }
            return Ok(NewTabForegroundHandoffResolution::Claimed(
                NewTabForegroundAdoption {
                    tab_id: self.tab_id,
                    session_id: self.session_id,
                    strip_tabs: self.strip_tabs,
                    selection: self.selection,
                },
            ));
        }

        if let Some(authority) = disposition.into_retry_authority() {
            retain_new_tab_handoff(authority);
        }
        Ok(NewTabForegroundHandoffResolution::Recover(
            NewTabForegroundError::PreparedGenerationBoundAttachSession {
                session_id: self.session_id,
                session_generation: self.pending_handoff.expected_generation,
                rollback_authority: self.pending_handoff.rollback_authority.take(),
                error: NewTabAttachSessionError::HandoffNotClaimed {
                    outcome,
                    request_id,
                },
            },
        ))
    }

    /// Convert renderer teardown without a correlated disposition into the only safe runtime
    /// classification. Command admission may have crossed the writer FIFO, so recovery is
    /// forward-only and the original reviewed authority is retained for exact retry/cancellation.
    pub fn into_renderer_exit_recovery(mut self) -> NewTabForegroundError {
        let request_id = self.pending_handoff.request_id();
        let expected_generation = self.pending_handoff.expected_generation.clone();
        retain_new_tab_handoff(self.pending_handoff.handoff.authority().clone());
        NewTabForegroundError::PreparedGenerationBoundAttachSession {
            session_id: self.session_id,
            session_generation: expected_generation,
            rollback_authority: self.pending_handoff.rollback_authority.take(),
            error: NewTabAttachSessionError::HandoffNotClaimed {
                outcome: maestro_renderer::RendererAttachmentHandoffOutcome::ClaimPossiblyApplied,
                request_id,
            },
        }
    }
}

/// Why the foreground `NewTabRequested` create pipeline failed. The caller logs the error and keeps
/// the foreground renderer listener alive; rollback/cleanup is deliberately not part of this slice.
pub struct NewTabSessionRollbackAuthority {
    expected_layout_without_tab: maestro_shell::WindowLayoutSnapshot,
    expected_session: maestro_shell::SessionRecord,
    expected_generation: String,
    created_tab_id: String,
    scratch_cwd: Option<PathBuf>,
    attachment_handoff: Option<maestro_shell::AttachmentHandoffAuthority>,
}

impl std::fmt::Debug for NewTabSessionRollbackAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewTabSessionRollbackAuthority")
            .field("has_scratch", &self.scratch_cwd.is_some())
            .finish_non_exhaustive()
    }
}

pub struct NewTabCreatedTabRollbackAuthority {
    expected_post_layout: maestro_shell::WindowLayoutSnapshot,
    expected_session: maestro_shell::SessionRecord,
    expected_generation: String,
    created_tab_id: String,
    scratch_cwd: Option<PathBuf>,
    attachment_handoff: Option<maestro_shell::AttachmentHandoffAuthority>,
}

/// Exact, consume-once compensation authority for the transaction-prepared production path.
///
/// The Shell receipt binds the canonical prepared placement and the finalized Live lifetime.  The
/// App carries only the renderer-recovery facts it must order around compensation; it cannot
/// inspect or rebuild the Session/Workspace/layout proof.  This type deliberately does not
/// implement `Clone`.
pub struct NewTabPreparedRollbackAuthority {
    compensation: maestro_shell::PreparedNewSessionCompensationReceipt,
    session_id: String,
    expected_generation: String,
    tab_id: String,
    window_id: String,
    attachment_handoff: Option<maestro_shell::AttachmentHandoffAuthority>,
}

impl std::fmt::Debug for NewTabPreparedRollbackAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewTabPreparedRollbackAuthority")
            .field("has_attachment_handoff", &self.attachment_handoff.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewTabPreparedCompensationStatus {
    RolledBack,
    Missing,
    Changed,
    Referenced,
    Failed { detail: String },
}

/// Typed certainty for failures while consuming a transaction-prepared new-session authority.
/// `DefinitelyUnpublished` and `Refused` have already consumed their exact compensation authority;
/// `PossiblyApplied` intentionally exposes no retry or rollback capability.
#[derive(Debug)]
pub enum NewTabPreparedSessionError {
    GraphAuthority {
        detail: String,
    },
    DefinitelyUnpublished {
        error: maestro_shell::ShellRuntimeError,
        compensation: NewTabPreparedCompensationStatus,
    },
    Refused {
        error: maestro_shell::ShellRuntimeError,
        compensation: NewTabPreparedCompensationStatus,
    },
    PossiblyApplied {
        detail: String,
    },
    FinalizedInvariant {
        detail: String,
        compensation: NewTabPreparedCompensationStatus,
    },
}

impl std::fmt::Display for NewTabPreparedSessionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GraphAuthority { detail } => formatter.write_str(detail),
            Self::DefinitelyUnpublished {
                error,
                compensation,
            } => write!(
                formatter,
                "prepared new-session start was definitely unpublished ({error}); compensation={compensation:?}"
            ),
            Self::Refused {
                error,
                compensation,
            } => write!(
                formatter,
                "prepared new-session start was refused ({error}); compensation={compensation:?}"
            ),
            Self::PossiblyApplied { detail } => write!(
                formatter,
                "prepared new-session start may have applied; graph retained for forward recovery: {detail}"
            ),
            Self::FinalizedInvariant {
                detail,
                compensation,
            } => write!(
                formatter,
                "prepared new-session finalization invariant failed ({detail}); compensation={compensation:?}"
            ),
        }
    }
}

impl std::error::Error for NewTabPreparedSessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DefinitelyUnpublished { error, .. } | Self::Refused { error, .. } => Some(error),
            Self::GraphAuthority { .. }
            | Self::PossiblyApplied { .. }
            | Self::FinalizedInvariant { .. } => None,
        }
    }
}

impl NewTabPreparedSessionError {
    fn permits_scratch_removal(&self) -> bool {
        match self {
            Self::GraphAuthority { .. } => true,
            Self::DefinitelyUnpublished { compensation, .. } => {
                *compensation == NewTabPreparedCompensationStatus::RolledBack
            }
            // Absent refusal may mean a same-id daemon lifetime already owns this per-session cwd.
            Self::Refused { .. } | Self::PossiblyApplied { .. } => false,
            // This branch is post-Grid/post-Live-rebase. Durable graph compensation may have
            // queued a forward daemon release, so even `RolledBack` is not process-unpublished.
            Self::FinalizedInvariant { .. } => false,
        }
    }
}

impl std::fmt::Debug for NewTabCreatedTabRollbackAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewTabCreatedTabRollbackAuthority")
            .field("has_scratch", &self.scratch_cwd.is_some())
            .finish_non_exhaustive()
    }
}

/// Opaque cleanup capability minted only for the exact per-session ScratchCwd prepared by the
/// shell layer. Diagnostic cwd strings and consented checkout roots cannot be converted into this
/// type, and it deliberately does not implement `Clone`.
pub struct NewTabScratchRemovalAuthority {
    receipt: maestro_shell::FreshScratchCwdReceipt,
}

impl NewTabScratchRemovalAuthority {
    fn from_fresh_receipt(receipt: maestro_shell::FreshScratchCwdReceipt) -> Self {
        Self { receipt }
    }

    fn cleanup(
        self,
        paths: &maestro_shell::AppPaths,
    ) -> Result<maestro_shell::FreshScratchCwdCleanupOutcome, maestro_shell::WorkspaceExecError>
    {
        maestro_shell::cleanup_fresh_scratch_cwd(paths, self.receipt)
    }
}

impl std::fmt::Debug for NewTabScratchRemovalAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NewTabScratchRemovalAuthority")
            .finish_non_exhaustive()
    }
}

pub enum NewTabForegroundError {
    WorkspacePrepare(NewTabWorkspacePrepareError),
    StartParams {
        cwd: PathBuf,
        /// Cleanup authority minted only for a shell-prepared ScratchCwd. Generic worktree and
        /// RepoWrite roots are diagnostic cwd values, never recursive-delete authority.
        scratch: Option<NewTabScratchRemovalAuthority>,
        error: NewTabStartParamsError,
    },
    SessionStart {
        cwd: PathBuf,
        error: NewTabSessionStartError,
    },
    LayoutRecord {
        cwd: PathBuf,
        error: NewTabLayoutRecordError,
    },
    Projection(NewTabStripProjectionError),
    SetTabStrip(NewTabSetTabStripError),
    AttachSession(NewTabAttachSessionError),
    PreparedSessionStart {
        cwd: PathBuf,
        scratch: Option<NewTabScratchRemovalAuthority>,
        error: NewTabPreparedSessionError,
    },
    PreparedGenerationBoundProjection {
        session_id: String,
        session_generation: String,
        rollback_authority: Option<NewTabPreparedRollbackAuthority>,
        error: NewTabStripProjectionError,
    },
    PreparedGenerationBoundAttachSession {
        session_id: String,
        session_generation: String,
        rollback_authority: Option<NewTabPreparedRollbackAuthority>,
        error: NewTabAttachSessionError,
    },
    PreparedStartedHandoffMissing {
        session_id: String,
        session_generation: String,
        rollback_authority: Option<NewTabPreparedRollbackAuthority>,
    },
    /// Generation-bearing production variants for failures after a successful Grid-proven start.
    /// Legacy tuple variants above remain accepted by the pure diagnostic API, but grant no kill
    /// authority because they carry no PTY lifetime.
    GenerationBoundLayoutRecord {
        cwd: PathBuf,
        session_id: String,
        session_generation: String,
        rollback_authority: Option<NewTabSessionRollbackAuthority>,
        error: NewTabLayoutRecordError,
    },
    GenerationBoundProjection {
        session_id: String,
        session_generation: String,
        rollback_authority: Option<NewTabCreatedTabRollbackAuthority>,
        error: NewTabStripProjectionError,
    },
    GenerationBoundSetTabStrip {
        session_id: String,
        session_generation: String,
        rollback_authority: Option<NewTabCreatedTabRollbackAuthority>,
        error: NewTabSetTabStripError,
    },
    GenerationBoundAttachSession {
        session_id: String,
        session_generation: String,
        rollback_authority: Option<NewTabCreatedTabRollbackAuthority>,
        error: NewTabAttachSessionError,
    },
    StartedSessionGenerationMissing {
        session_id: String,
    },
    StartedSessionHandoffMissing {
        session_id: String,
        session_generation: String,
        rollback_authority: Option<NewTabSessionRollbackAuthority>,
    },
}

impl std::fmt::Debug for NewTabForegroundError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let variant = match self {
            Self::WorkspacePrepare(_) => "WorkspacePrepare",
            Self::StartParams { .. } => "StartParams",
            Self::SessionStart { .. } => "SessionStart",
            Self::LayoutRecord { .. } => "LayoutRecord",
            Self::Projection(_) => "Projection",
            Self::SetTabStrip(_) => "SetTabStrip",
            Self::AttachSession(_) => "AttachSession",
            Self::PreparedSessionStart { .. } => "PreparedSessionStart",
            Self::PreparedGenerationBoundProjection { .. } => "PreparedGenerationBoundProjection",
            Self::PreparedGenerationBoundAttachSession { .. } => {
                "PreparedGenerationBoundAttachSession"
            }
            Self::PreparedStartedHandoffMissing { .. } => "PreparedStartedHandoffMissing",
            Self::GenerationBoundLayoutRecord { .. } => "GenerationBoundLayoutRecord",
            Self::GenerationBoundProjection { .. } => "GenerationBoundProjection",
            Self::GenerationBoundSetTabStrip { .. } => "GenerationBoundSetTabStrip",
            Self::GenerationBoundAttachSession { .. } => "GenerationBoundAttachSession",
            Self::StartedSessionGenerationMissing { .. } => "StartedSessionGenerationMissing",
            Self::StartedSessionHandoffMissing { .. } => "StartedSessionHandoffMissing",
        };
        formatter
            .debug_struct("NewTabForegroundError")
            .field("variant", &variant)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum NewTabRendererRecoveryKind {
    None,
    RevertStrip,
    ReconcileState,
}

enum NewTabRollbackAuthority {
    StartedSession(NewTabSessionRollbackAuthority),
    CreatedTab {
        authority: NewTabCreatedTabRollbackAuthority,
        renderer: NewTabRendererRecoveryKind,
    },
    Prepared {
        authority: NewTabPreparedRollbackAuthority,
        renderer: NewTabRendererRecoveryKind,
    },
}

impl NewTabForegroundError {
    fn take_rollback_authority(&mut self) -> Option<NewTabRollbackAuthority> {
        match self {
            Self::GenerationBoundLayoutRecord {
                rollback_authority, ..
            } => rollback_authority
                .take()
                .map(NewTabRollbackAuthority::StartedSession),
            Self::GenerationBoundProjection {
                rollback_authority, ..
            } => rollback_authority
                .take()
                .map(|authority| NewTabRollbackAuthority::CreatedTab {
                    authority,
                    renderer: NewTabRendererRecoveryKind::None,
                }),
            Self::GenerationBoundSetTabStrip {
                rollback_authority, ..
            } => rollback_authority
                .take()
                .map(|authority| NewTabRollbackAuthority::CreatedTab {
                    authority,
                    renderer: NewTabRendererRecoveryKind::RevertStrip,
                }),
            Self::GenerationBoundAttachSession {
                rollback_authority, ..
            } => rollback_authority
                .take()
                .map(|authority| NewTabRollbackAuthority::CreatedTab {
                    authority,
                    renderer: NewTabRendererRecoveryKind::ReconcileState,
                }),
            Self::StartedSessionHandoffMissing {
                rollback_authority, ..
            } => rollback_authority
                .take()
                .map(NewTabRollbackAuthority::StartedSession),
            Self::PreparedGenerationBoundProjection {
                rollback_authority, ..
            } => rollback_authority
                .take()
                .map(|authority| NewTabRollbackAuthority::Prepared {
                    authority,
                    renderer: NewTabRendererRecoveryKind::None,
                }),
            Self::PreparedGenerationBoundAttachSession {
                rollback_authority, ..
            } => rollback_authority
                .take()
                .map(|authority| NewTabRollbackAuthority::Prepared {
                    authority,
                    renderer: NewTabRendererRecoveryKind::ReconcileState,
                }),
            Self::PreparedStartedHandoffMissing {
                rollback_authority, ..
            } => rollback_authority
                .take()
                .map(|authority| NewTabRollbackAuthority::Prepared {
                    authority,
                    renderer: NewTabRendererRecoveryKind::None,
                }),
            _ => None,
        }
    }
}

impl std::fmt::Display for NewTabForegroundError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NewTabForegroundError::WorkspacePrepare(e) => write!(f, "{e}"),
            NewTabForegroundError::StartParams { error, .. } => {
                write!(f, "new-tab start params failed: {error:?}")
            }
            NewTabForegroundError::SessionStart { error, .. } => write!(f, "{error}"),
            NewTabForegroundError::LayoutRecord { error, .. } => write!(f, "{error}"),
            NewTabForegroundError::Projection(e) => write!(f, "{e}"),
            NewTabForegroundError::SetTabStrip(e) => write!(f, "{e}"),
            NewTabForegroundError::AttachSession(e) => write!(f, "{e}"),
            NewTabForegroundError::PreparedSessionStart { error, .. } => write!(f, "{error}"),
            NewTabForegroundError::PreparedGenerationBoundProjection { error, .. } => {
                write!(f, "{error}")
            }
            NewTabForegroundError::PreparedGenerationBoundAttachSession { error, .. } => {
                write!(f, "{error}")
            }
            NewTabForegroundError::PreparedStartedHandoffMissing { session_id, .. } => write!(
                f,
                "prepared new-tab session {session_id:?} supplied no renderer handoff"
            ),
            NewTabForegroundError::GenerationBoundLayoutRecord { error, .. } => {
                write!(f, "{error}")
            }
            NewTabForegroundError::GenerationBoundProjection { error, .. } => write!(f, "{error}"),
            NewTabForegroundError::GenerationBoundSetTabStrip { error, .. } => write!(f, "{error}"),
            NewTabForegroundError::GenerationBoundAttachSession { error, .. } => {
                write!(f, "{error}")
            }
            NewTabForegroundError::StartedSessionGenerationMissing { session_id } => write!(
                f,
                "started new-tab session {session_id:?} supplied no PTY generation"
            ),
            NewTabForegroundError::StartedSessionHandoffMissing { session_id, .. } => write!(
                f,
                "started new-tab session {session_id:?} supplied no renderer handoff"
            ),
        }
    }
}

impl std::error::Error for NewTabForegroundError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            NewTabForegroundError::WorkspacePrepare(e) => Some(e),
            NewTabForegroundError::StartParams { .. } => None,
            NewTabForegroundError::SessionStart { error, .. } => Some(error),
            NewTabForegroundError::LayoutRecord { error, .. } => Some(error),
            NewTabForegroundError::Projection(e) => Some(e),
            NewTabForegroundError::SetTabStrip(e) => Some(e),
            NewTabForegroundError::AttachSession(e) => Some(e),
            NewTabForegroundError::PreparedSessionStart { error, .. } => Some(error),
            NewTabForegroundError::PreparedGenerationBoundProjection { error, .. } => Some(error),
            NewTabForegroundError::PreparedGenerationBoundAttachSession { error, .. } => {
                Some(error)
            }
            NewTabForegroundError::PreparedStartedHandoffMissing { .. } => None,
            NewTabForegroundError::GenerationBoundLayoutRecord { error, .. } => Some(error),
            NewTabForegroundError::GenerationBoundProjection { error, .. } => Some(error),
            NewTabForegroundError::GenerationBoundSetTabStrip { error, .. } => Some(error),
            NewTabForegroundError::GenerationBoundAttachSession { error, .. } => Some(error),
            NewTabForegroundError::StartedSessionGenerationMissing { .. } => None,
            NewTabForegroundError::StartedSessionHandoffMissing { .. } => None,
        }
    }
}

/// The foreground new-tab pipeline stage that failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewTabFailureStage {
    WorkspacePrepare,
    StartParams,
    SessionStart,
    LayoutRecord,
    Projection,
    SetTabStrip,
    AttachSession,
}

/// A pure description of how far a foreground new-tab create attempt got before failing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTabFailureDiagnostic {
    pub stage: NewTabFailureStage,
    pub layout_record_persisted: bool,
    pub session_started: bool,
    pub deferred_cleanup: &'static str,
}

impl std::fmt::Display for NewTabFailureDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "stage={:?}; session_started={}; layout_record_persisted={}; {}",
            self.stage, self.session_started, self.layout_record_persisted, self.deferred_cleanup
        )
    }
}

/// Classify a foreground new-tab failure by the real [`run_new_tab_foreground_pipeline`] order.
///
/// `SessionStart` is conservative: the start helper failed after start params succeeded, and a
/// daemon/PTY session may have been partly spawned, so `session_started = true`; no layout append
/// has run yet. `LayoutRecord` is after a successful start but during the durable append itself, so
/// the started session is residue while the tab record is not treated as cleanly persisted. For
/// `Projection`, `SetTabStrip`, and `AttachSession`, the layout append already succeeded, so both
/// the started session and tab record are residue that the recovery planner must consider.
pub fn classify_new_tab_foreground_failure(err: &NewTabForegroundError) -> NewTabFailureDiagnostic {
    match err {
        NewTabForegroundError::WorkspacePrepare(_) => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::WorkspacePrepare,
            session_started: false,
            layout_record_persisted: false,
            deferred_cleanup: "nothing durable persisted; cleanup deferred",
        },
        NewTabForegroundError::StartParams { .. } => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::StartParams,
            session_started: false,
            layout_record_persisted: false,
            deferred_cleanup: "prepared scratch dir may be removed; no session or TabRecord persisted",
        },
        NewTabForegroundError::SessionStart { .. } => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::SessionStart,
            session_started: true,
            layout_record_persisted: false,
            deferred_cleanup: "prepared scratch dir may be removed; possible started session cleanup deferred",
        },
        NewTabForegroundError::LayoutRecord { .. } => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::LayoutRecord,
            session_started: true,
            layout_record_persisted: false,
            deferred_cleanup: "prepared scratch dir may be removed; started session cleanup deferred; no clean TabRecord persisted",
        },
        NewTabForegroundError::Projection(_) => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::Projection,
            session_started: true,
            layout_record_persisted: true,
            deferred_cleanup: "scratch dir, started session, and persisted TabRecord left in place; cleanup deferred",
        },
        NewTabForegroundError::SetTabStrip(_) => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::SetTabStrip,
            session_started: true,
            layout_record_persisted: true,
            deferred_cleanup: "scratch dir, started session, and persisted TabRecord left in place; cleanup deferred",
        },
        NewTabForegroundError::AttachSession(_) => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::AttachSession,
            session_started: true,
            layout_record_persisted: true,
            deferred_cleanup: "scratch dir, started session, and persisted TabRecord left in place; cleanup deferred",
        },
        NewTabForegroundError::PreparedSessionStart { error, .. } => {
            let possibly_applied = matches!(
                error,
                NewTabPreparedSessionError::PossiblyApplied { .. }
            );
            NewTabFailureDiagnostic {
                stage: NewTabFailureStage::SessionStart,
                session_started: possibly_applied,
                layout_record_persisted: possibly_applied,
                deferred_cleanup: if possibly_applied {
                    "conditional start may have applied; prepared graph retained for forward recovery"
                } else {
                    "prepared graph was conditionally compensated before returning"
                },
            }
        }
        NewTabForegroundError::PreparedGenerationBoundProjection { .. } => {
            NewTabFailureDiagnostic {
                stage: NewTabFailureStage::Projection,
                session_started: true,
                layout_record_persisted: true,
                deferred_cleanup:
                    "prepared Live session and tab await exact compensation/release recovery",
            }
        }
        NewTabForegroundError::PreparedGenerationBoundAttachSession { .. } => {
            NewTabFailureDiagnostic {
                stage: NewTabFailureStage::AttachSession,
                session_started: true,
                layout_record_persisted: true,
                deferred_cleanup:
                    "prepared Live session and tab await exact compensation/release recovery",
            }
        }
        NewTabForegroundError::PreparedStartedHandoffMissing { .. } => {
            NewTabFailureDiagnostic {
                stage: NewTabFailureStage::AttachSession,
                session_started: true,
                layout_record_persisted: true,
                deferred_cleanup:
                    "prepared Live session lacked renderer handoff; exact compensation deferred",
            }
        }
        NewTabForegroundError::GenerationBoundLayoutRecord { .. } => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::LayoutRecord,
            session_started: true,
            layout_record_persisted: false,
            deferred_cleanup: "prepared scratch dir may be removed; generation-bound started session cleanup deferred; no clean TabRecord persisted",
        },
        NewTabForegroundError::GenerationBoundProjection { .. } => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::Projection,
            session_started: true,
            layout_record_persisted: true,
            deferred_cleanup: "generation-bound started session and persisted TabRecord left in place; cleanup deferred",
        },
        NewTabForegroundError::GenerationBoundSetTabStrip { .. } => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::SetTabStrip,
            session_started: true,
            layout_record_persisted: true,
            deferred_cleanup: "generation-bound started session and persisted TabRecord left in place; cleanup deferred",
        },
        NewTabForegroundError::GenerationBoundAttachSession { .. } => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::AttachSession,
            session_started: true,
            layout_record_persisted: true,
            deferred_cleanup: "generation-bound started session and persisted TabRecord left in place; cleanup deferred",
        },
        NewTabForegroundError::StartedSessionGenerationMissing { .. } => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::SessionStart,
            session_started: true,
            layout_record_persisted: false,
            deferred_cleanup: "started session lacked a PTY generation; mutation cleanup refused",
        },
        NewTabForegroundError::StartedSessionHandoffMissing { .. } => NewTabFailureDiagnostic {
            stage: NewTabFailureStage::LayoutRecord,
            session_started: true,
            layout_record_persisted: false,
            deferred_cleanup:
                "generation-bound started session lacked renderer handoff; exact cleanup deferred",
        },
    }
}

/// Return the prepared scratch cwd that is safe to remove for pre-record foreground new-tab
/// failures. Pure: this decides only, and never touches the filesystem.
pub fn new_tab_failure_scratch_to_remove(err: &NewTabForegroundError) -> Option<&Path> {
    match err {
        NewTabForegroundError::StartParams { cwd, scratch, .. } if scratch.is_some() => {
            Some(cwd.as_path())
        }
        NewTabForegroundError::PreparedSessionStart {
            cwd,
            scratch: Some(_),
            error,
        } if error.permits_scratch_removal() => Some(cwd.as_path()),
        _ => None,
    }
}

fn take_new_tab_failure_scratch_authority(
    err: &mut NewTabForegroundError,
) -> Option<NewTabScratchRemovalAuthority> {
    match err {
        NewTabForegroundError::StartParams { scratch, .. } => scratch.take(),
        NewTabForegroundError::PreparedSessionStart { scratch, error, .. }
            if error.permits_scratch_removal() =>
        {
            scratch.take()
        }
        _ => None,
    }
}

/// Pure action intents for a future foreground new-tab recovery executor.
///
/// The current [`NewTabForegroundError`] value carries a concrete scratch cwd for eligible cleanup
/// stages, but it does not carry the started session id or persisted tab id. Those are therefore
/// represented as context-resolved intents instead of invented identifiers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NewTabRecoveryAction {
    RemoveScratch(PathBuf),
    KillStartedSession,
    RollbackTabRecord,
    RevertRendererStrip,
    ReconcileRendererState,
}

/// A pure, deterministic recovery plan for a foreground new-tab failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTabRecoveryPlan {
    pub diagnostic: NewTabFailureDiagnostic,
    pub actions: Vec<NewTabRecoveryAction>,
}

/// Concrete state captured by a foreground new-tab caller for later recovery resolution.
///
/// Fields are optional because each failure stage occurs at a different point in the creation
/// pipeline. This type is pure state only; it does not execute recovery.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewTabRecoveryContext {
    pub window_id: Option<String>,
    pub tab_id: Option<String>,
    pub session_id: Option<String>,
    pub session_generation: Option<String>,
    pub previous_strip_tabs: Option<Vec<WindowTabJson>>,
    pub previous_selection: Option<Vec<TabSelection>>,
    pub scratch_cwd: Option<PathBuf>,
}

fn foreground_error_session_generation(err: &NewTabForegroundError) -> Option<&str> {
    match err {
        NewTabForegroundError::GenerationBoundLayoutRecord {
            session_generation, ..
        }
        | NewTabForegroundError::GenerationBoundProjection {
            session_generation, ..
        }
        | NewTabForegroundError::GenerationBoundSetTabStrip {
            session_generation, ..
        }
        | NewTabForegroundError::GenerationBoundAttachSession {
            session_generation, ..
        }
        | NewTabForegroundError::StartedSessionHandoffMissing {
            session_generation, ..
        }
        | NewTabForegroundError::PreparedGenerationBoundProjection {
            session_generation, ..
        }
        | NewTabForegroundError::PreparedGenerationBoundAttachSession {
            session_generation, ..
        }
        | NewTabForegroundError::PreparedStartedHandoffMissing {
            session_generation, ..
        } => Some(session_generation),
        _ => None,
    }
}

/// Build the recovery context available to the foreground new-tab listener on failure.
///
/// The foreground path already knows the planned tab/session ids and has a pre-attempt snapshot of
/// the renderer/listener strip state. This helper packages that state for pure recovery reporting
/// without executing any recovery action.
pub fn foreground_new_tab_recovery_context(
    window_id: &str,
    planned_tab_id: &str,
    planned_session_id: &str,
    previous_strip_tabs: &[WindowTabJson],
    previous_selection: &[TabSelection],
    err: &NewTabForegroundError,
) -> NewTabRecoveryContext {
    NewTabRecoveryContext {
        window_id: Some(window_id.to_string()),
        tab_id: Some(planned_tab_id.to_string()),
        session_id: Some(planned_session_id.to_string()),
        session_generation: foreground_error_session_generation(err).map(str::to_owned),
        previous_strip_tabs: Some(previous_strip_tabs.to_vec()),
        previous_selection: Some(previous_selection.to_vec()),
        scratch_cwd: new_tab_failure_scratch_to_remove(err).map(Path::to_path_buf),
    }
}

/// A recovery action after pure resolution against [`NewTabRecoveryContext`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedNewTabRecoveryAction {
    RemoveScratch(PathBuf),
    KillSessionIfGeneration {
        session_id: String,
        expected_generation: String,
    },
    MissingSessionForKill,
    RollbackTabRecord {
        window_id: String,
        tab_id: String,
    },
    MissingTabRecordTarget,
    RevertRendererStrip {
        strip_tabs: Vec<WindowTabJson>,
        selection: Vec<TabSelection>,
    },
    MissingRendererStripState,
    ReconcileRendererState {
        strip_tabs: Vec<WindowTabJson>,
        selection: Vec<TabSelection>,
    },
    MissingRendererReconcileState,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedNewTabRecoveryPlan {
    pub diagnostic: NewTabFailureDiagnostic,
    pub actions: Vec<ResolvedNewTabRecoveryAction>,
}

/// Plan foreground new-tab recovery without touching the daemon, renderer, records, or filesystem.
pub fn plan_new_tab_failure_recovery(err: &NewTabForegroundError) -> NewTabRecoveryPlan {
    let diagnostic = classify_new_tab_foreground_failure(err);
    let scratch_cleanup = new_tab_failure_scratch_to_remove(err)
        .map(|cwd| NewTabRecoveryAction::RemoveScratch(cwd.to_path_buf()));
    let actions = match diagnostic.stage {
        NewTabFailureStage::WorkspacePrepare => Vec::new(),
        NewTabFailureStage::StartParams => scratch_cleanup.into_iter().collect(),
        // A failed start produced no accepted Grid and therefore no PTY generation proof. Scratch
        // cleanup is safe, but an id-only Kill is forbidden even if the daemon may have partially
        // started a process.
        NewTabFailureStage::SessionStart => scratch_cleanup.into_iter().collect(),
        NewTabFailureStage::LayoutRecord => {
            let mut actions = vec![NewTabRecoveryAction::KillStartedSession];
            actions.extend(scratch_cleanup);
            actions
        }
        NewTabFailureStage::Projection => {
            vec![
                NewTabRecoveryAction::RollbackTabRecord,
                NewTabRecoveryAction::KillStartedSession,
            ]
        }
        NewTabFailureStage::SetTabStrip => {
            vec![
                NewTabRecoveryAction::RollbackTabRecord,
                NewTabRecoveryAction::RevertRendererStrip,
                NewTabRecoveryAction::KillStartedSession,
            ]
        }
        NewTabFailureStage::AttachSession => {
            vec![
                NewTabRecoveryAction::RollbackTabRecord,
                NewTabRecoveryAction::ReconcileRendererState,
                NewTabRecoveryAction::KillStartedSession,
            ]
        }
    };
    NewTabRecoveryPlan {
        diagnostic,
        actions,
    }
}

/// Resolve a pure recovery plan against captured context, without executing any recovery action.
pub fn resolve_new_tab_recovery_plan(
    plan: &NewTabRecoveryPlan,
    context: &NewTabRecoveryContext,
) -> ResolvedNewTabRecoveryPlan {
    let actions = plan
        .actions
        .iter()
        .map(|action| match action {
            NewTabRecoveryAction::RemoveScratch(cwd) => {
                ResolvedNewTabRecoveryAction::RemoveScratch(cwd.clone())
            }
            NewTabRecoveryAction::KillStartedSession => context
                .session_id
                .as_ref()
                .zip(context.session_generation.as_ref())
                .map(|(session_id, expected_generation)| {
                    ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                        session_id: session_id.clone(),
                        expected_generation: expected_generation.clone(),
                    }
                })
                .unwrap_or(ResolvedNewTabRecoveryAction::MissingSessionForKill),
            NewTabRecoveryAction::RollbackTabRecord => {
                match (&context.window_id, &context.tab_id) {
                    (Some(window_id), Some(tab_id)) => {
                        ResolvedNewTabRecoveryAction::RollbackTabRecord {
                            window_id: window_id.clone(),
                            tab_id: tab_id.clone(),
                        }
                    }
                    (None, _) | (_, None) => ResolvedNewTabRecoveryAction::MissingTabRecordTarget,
                }
            }
            NewTabRecoveryAction::RevertRendererStrip => {
                match (&context.previous_strip_tabs, &context.previous_selection) {
                    (Some(strip_tabs), Some(selection)) => {
                        ResolvedNewTabRecoveryAction::RevertRendererStrip {
                            strip_tabs: strip_tabs.clone(),
                            selection: selection.clone(),
                        }
                    }
                    (None, _) | (_, None) => {
                        ResolvedNewTabRecoveryAction::MissingRendererStripState
                    }
                }
            }
            NewTabRecoveryAction::ReconcileRendererState => {
                match (&context.previous_strip_tabs, &context.previous_selection) {
                    (Some(strip_tabs), Some(selection)) => {
                        ResolvedNewTabRecoveryAction::ReconcileRendererState {
                            strip_tabs: strip_tabs.clone(),
                            selection: selection.clone(),
                        }
                    }
                    (None, _) | (_, None) => {
                        ResolvedNewTabRecoveryAction::MissingRendererReconcileState
                    }
                }
            }
        })
        .collect();
    ResolvedNewTabRecoveryPlan {
        diagnostic: plan.diagnostic.clone(),
        actions,
    }
}

/// Plan and resolve foreground new-tab recovery in one pure call.
///
/// Equivalent to `resolve_new_tab_recovery_plan(&plan_new_tab_failure_recovery(err), context)`:
/// it delegates to both, executing nothing. Provided so a caller does not have to thread the
/// intermediate [`NewTabRecoveryPlan`] when it only wants the resolved plan.
pub fn resolve_new_tab_recovery(
    err: &NewTabForegroundError,
    context: &NewTabRecoveryContext,
) -> ResolvedNewTabRecoveryPlan {
    let plan = plan_new_tab_failure_recovery(err);
    resolve_new_tab_recovery_plan(&plan, context)
}

/// Render a [`ResolvedNewTabRecoveryPlan`] as one deterministic single-line diagnostic summary.
///
/// Pure: returns the line and never logs or touches any side-effecting surface. Each resolved
/// action becomes a short stable token in plan order; every `Missing*` variant renders a distinct
/// `missing_*` token so an unresolved intent is never confused with a concrete one. The result
/// contains no newlines.
fn resolved_recovery_action_label(action: &ResolvedNewTabRecoveryAction) -> String {
    match action {
        ResolvedNewTabRecoveryAction::RemoveScratch(cwd) => {
            format!("remove_scratch({})", cwd.display())
        }
        ResolvedNewTabRecoveryAction::KillSessionIfGeneration { session_id, .. } => {
            format!("kill_session({session_id})")
        }
        ResolvedNewTabRecoveryAction::MissingSessionForKill => {
            "missing_session_for_kill".to_string()
        }
        ResolvedNewTabRecoveryAction::RollbackTabRecord { window_id, tab_id } => {
            format!("rollback_tab_record({window_id},{tab_id})")
        }
        ResolvedNewTabRecoveryAction::MissingTabRecordTarget => {
            "missing_tab_record_target".to_string()
        }
        ResolvedNewTabRecoveryAction::RevertRendererStrip {
            strip_tabs,
            selection,
        } => format!(
            "revert_renderer_strip(tabs={},selection={})",
            strip_tabs.len(),
            selection.len()
        ),
        ResolvedNewTabRecoveryAction::MissingRendererStripState => {
            "missing_renderer_strip_state".to_string()
        }
        ResolvedNewTabRecoveryAction::ReconcileRendererState {
            strip_tabs,
            selection,
        } => format!(
            "reconcile_renderer_state(tabs={},selection={})",
            strip_tabs.len(),
            selection.len()
        ),
        ResolvedNewTabRecoveryAction::MissingRendererReconcileState => {
            "missing_renderer_reconcile_state".to_string()
        }
    }
}

pub fn render_resolved_recovery_log_line(plan: &ResolvedNewTabRecoveryPlan) -> String {
    let actions = plan
        .actions
        .iter()
        .map(resolved_recovery_action_label)
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "new-tab recovery: {}; actions=[{}]",
        plan.diagnostic, actions
    )
}

/// Render a single-line summary of an executed recovery plan for live diagnostics.
///
/// Pure and headless: it formats an already-produced [`ResolvedNewTabRecoveryExecutionReport`] into
/// one stable, greppable line (diagnostic + succeeded/skipped/failed counts + ordered
/// `label=status` outcomes). It executes nothing; the live failure branches call it after the
/// recovery executor returns.
pub fn render_resolved_recovery_execution_log_line(
    report: &ResolvedNewTabRecoveryExecutionReport,
) -> String {
    let outcomes = report
        .outcomes
        .iter()
        .map(|outcome| {
            let status = match &outcome.status {
                ResolvedNewTabRecoveryActionStatus::Succeeded => "ok".to_string(),
                ResolvedNewTabRecoveryActionStatus::Skipped { reason } => format!("skip({reason})"),
                ResolvedNewTabRecoveryActionStatus::Failed { error } => format!("fail({error})"),
            };
            format!(
                "{}={}",
                resolved_recovery_action_label(&outcome.action),
                status
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "new-tab recovery executed: {}; succeeded={} skipped={} failed={}; outcomes=[{}]",
        report.diagnostic,
        report.succeeded_count(),
        report.skipped_count(),
        report.failed_count(),
        outcomes
    )
}

/// Injected effect surface for executing a resolved foreground new-tab recovery plan.
///
/// Implementations own all side effects. Returning [`ResolvedNewTabRecoveryEffectResult::Skipped`]
/// records an idempotent no-op such as an already-gone session or already-restored renderer state.
/// The executor below never calls these methods for `Missing*` resolved actions; those are reported
/// as skipped directly.
#[cfg(test)]
pub trait ResolvedNewTabRecoveryEffects {
    type Error: std::fmt::Display;

    fn remove_scratch(
        &mut self,
        cwd: &Path,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error>;
    fn kill_session(
        &mut self,
        session_id: &str,
        expected_generation: &str,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error>;
    fn rollback_tab_record(
        &mut self,
        window_id: &str,
        tab_id: &str,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error>;
    fn revert_renderer_strip(
        &mut self,
        strip_tabs: &[WindowTabJson],
        selection: &[TabSelection],
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error>;
    fn reconcile_renderer_state(
        &mut self,
        strip_tabs: &[WindowTabJson],
        selection: &[TabSelection],
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedNewTabRecoveryEffectResult {
    Succeeded,
    Skipped { reason: String },
}

impl ResolvedNewTabRecoveryEffectResult {
    pub fn skipped(reason: impl Into<String>) -> Self {
        Self::Skipped {
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedNewTabRecoveryActionStatus {
    Succeeded,
    Skipped { reason: String },
    Failed { error: String },
}

impl ResolvedNewTabRecoveryActionStatus {
    pub fn is_succeeded(&self) -> bool {
        matches!(self, Self::Succeeded)
    }

    pub fn is_skipped(&self) -> bool {
        matches!(self, Self::Skipped { .. })
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, Self::Failed { .. })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedNewTabRecoveryActionOutcome {
    pub action: ResolvedNewTabRecoveryAction,
    pub status: ResolvedNewTabRecoveryActionStatus,
}

impl ResolvedNewTabRecoveryActionOutcome {
    pub fn succeeded(action: ResolvedNewTabRecoveryAction) -> Self {
        Self {
            action,
            status: ResolvedNewTabRecoveryActionStatus::Succeeded,
        }
    }

    pub fn skipped(action: ResolvedNewTabRecoveryAction, reason: impl Into<String>) -> Self {
        Self {
            action,
            status: ResolvedNewTabRecoveryActionStatus::Skipped {
                reason: reason.into(),
            },
        }
    }

    pub fn failed(action: ResolvedNewTabRecoveryAction, error: impl Into<String>) -> Self {
        Self {
            action,
            status: ResolvedNewTabRecoveryActionStatus::Failed {
                error: error.into(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedNewTabRecoveryExecutionReport {
    pub diagnostic: NewTabFailureDiagnostic,
    pub outcomes: Vec<ResolvedNewTabRecoveryActionOutcome>,
}

impl ResolvedNewTabRecoveryExecutionReport {
    pub fn succeeded_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.status.is_succeeded())
            .count()
    }

    pub fn skipped_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.status.is_skipped())
            .count()
    }

    pub fn failed_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| outcome.status.is_failed())
            .count()
    }
}

/// Execute a resolved recovery plan through injected effects, preserving order.
///
/// This is a seam only: callers provide the concrete effects. Missing-target resolved actions are
/// treated as skipped/idempotent outcomes. Effect failures are recorded and later actions continue.
#[cfg(test)]
pub fn execute_resolved_new_tab_recovery_plan<E: ResolvedNewTabRecoveryEffects>(
    plan: &ResolvedNewTabRecoveryPlan,
    effects: &mut E,
) -> ResolvedNewTabRecoveryExecutionReport {
    let mut outcomes = Vec::with_capacity(plan.actions.len());
    for action in &plan.actions {
        let outcome = match action {
            ResolvedNewTabRecoveryAction::RemoveScratch(cwd) => {
                resolved_recovery_effect_outcome(action, effects.remove_scratch(cwd.as_path()))
            }
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id,
                expected_generation,
            } => resolved_recovery_effect_outcome(
                action,
                effects.kill_session(session_id, expected_generation),
            ),
            ResolvedNewTabRecoveryAction::RollbackTabRecord { window_id, tab_id } => {
                resolved_recovery_effect_outcome(
                    action,
                    effects.rollback_tab_record(window_id, tab_id),
                )
            }
            ResolvedNewTabRecoveryAction::RevertRendererStrip {
                strip_tabs,
                selection,
            } => resolved_recovery_effect_outcome(
                action,
                effects.revert_renderer_strip(strip_tabs, selection),
            ),
            ResolvedNewTabRecoveryAction::ReconcileRendererState {
                strip_tabs,
                selection,
            } => resolved_recovery_effect_outcome(
                action,
                effects.reconcile_renderer_state(strip_tabs, selection),
            ),
            ResolvedNewTabRecoveryAction::MissingSessionForKill => {
                ResolvedNewTabRecoveryActionOutcome::skipped(
                    action.clone(),
                    "missing_session_for_kill",
                )
            }
            ResolvedNewTabRecoveryAction::MissingTabRecordTarget => {
                ResolvedNewTabRecoveryActionOutcome::skipped(
                    action.clone(),
                    "missing_tab_record_target",
                )
            }
            ResolvedNewTabRecoveryAction::MissingRendererStripState => {
                ResolvedNewTabRecoveryActionOutcome::skipped(
                    action.clone(),
                    "missing_renderer_strip_state",
                )
            }
            ResolvedNewTabRecoveryAction::MissingRendererReconcileState => {
                ResolvedNewTabRecoveryActionOutcome::skipped(
                    action.clone(),
                    "missing_renderer_reconcile_state",
                )
            }
        };
        outcomes.push(outcome);
    }
    ResolvedNewTabRecoveryExecutionReport {
        diagnostic: plan.diagnostic.clone(),
        outcomes,
    }
}

fn resolved_recovery_effect_outcome<E: std::fmt::Display>(
    action: &ResolvedNewTabRecoveryAction,
    result: Result<ResolvedNewTabRecoveryEffectResult, E>,
) -> ResolvedNewTabRecoveryActionOutcome {
    match result {
        Ok(ResolvedNewTabRecoveryEffectResult::Succeeded) => {
            ResolvedNewTabRecoveryActionOutcome::succeeded(action.clone())
        }
        Ok(ResolvedNewTabRecoveryEffectResult::Skipped { reason }) => {
            ResolvedNewTabRecoveryActionOutcome::skipped(action.clone(), reason)
        }
        Err(error) => {
            ResolvedNewTabRecoveryActionOutcome::failed(action.clone(), error.to_string())
        }
    }
}

/// Injected effect surface for executing a foreground new-tab recovery plan.
///
/// Implementations own all side effects. The executor below only dispatches these callbacks in the
/// plan's order and records callback outcomes.
#[cfg(test)]
pub trait NewTabRecoveryEffects {
    type Error: std::fmt::Display;

    fn remove_scratch(&mut self, cwd: &Path) -> Result<(), Self::Error>;
    fn kill_started_session(&mut self) -> Result<(), Self::Error>;
    fn rollback_tab_record(&mut self) -> Result<(), Self::Error>;
    fn revert_renderer_strip(&mut self) -> Result<(), Self::Error>;
    fn reconcile_renderer_state(&mut self) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTabRecoveryActionOutcome {
    pub action: NewTabRecoveryAction,
    pub error: Option<String>,
}

impl NewTabRecoveryActionOutcome {
    pub fn ok(action: NewTabRecoveryAction) -> Self {
        Self {
            action,
            error: None,
        }
    }

    pub fn failed(action: NewTabRecoveryAction, error: impl Into<String>) -> Self {
        Self {
            action,
            error: Some(error.into()),
        }
    }

    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTabRecoveryExecutionReport {
    pub diagnostic: NewTabFailureDiagnostic,
    pub outcomes: Vec<NewTabRecoveryActionOutcome>,
}

impl NewTabRecoveryExecutionReport {
    pub fn failed_count(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|outcome| !outcome.is_ok())
            .count()
    }
}

/// Execute a recovery plan through injected effects, preserving order and treating failures as
/// non-fatal.
#[cfg(test)]
pub fn execute_new_tab_recovery_plan<E: NewTabRecoveryEffects>(
    plan: &NewTabRecoveryPlan,
    effects: &mut E,
) -> NewTabRecoveryExecutionReport {
    let mut outcomes = Vec::with_capacity(plan.actions.len());
    for action in &plan.actions {
        let result = match action {
            NewTabRecoveryAction::RemoveScratch(cwd) => effects.remove_scratch(cwd.as_path()),
            NewTabRecoveryAction::KillStartedSession => effects.kill_started_session(),
            NewTabRecoveryAction::RollbackTabRecord => effects.rollback_tab_record(),
            NewTabRecoveryAction::RevertRendererStrip => effects.revert_renderer_strip(),
            NewTabRecoveryAction::ReconcileRendererState => effects.reconcile_renderer_state(),
        };
        outcomes.push(match result {
            Ok(()) => NewTabRecoveryActionOutcome::ok(action.clone()),
            Err(error) => NewTabRecoveryActionOutcome::failed(action.clone(), error.to_string()),
        });
    }
    NewTabRecoveryExecutionReport {
        diagnostic: plan.diagnostic.clone(),
        outcomes,
    }
}

/// Consume the Shell-minted fresh-directory receipt. Unexpected content or a durable same-id
/// namespace is retained and reported as a safe skip.
fn cleanup_new_tab_scratch(
    paths: &maestro_shell::AppPaths,
    authority: NewTabScratchRemovalAuthority,
) -> Result<ResolvedNewTabRecoveryEffectResult, maestro_shell::WorkspaceExecError> {
    authority.cleanup(paths).map(|outcome| match outcome {
        maestro_shell::FreshScratchCwdCleanupOutcome::Removed => {
            ResolvedNewTabRecoveryEffectResult::Succeeded
        }
        maestro_shell::FreshScratchCwdCleanupOutcome::AlreadyMissing => {
            ResolvedNewTabRecoveryEffectResult::skipped("fresh scratch dir is already absent")
        }
        maestro_shell::FreshScratchCwdCleanupOutcome::RetainedNotEmpty => {
            ResolvedNewTabRecoveryEffectResult::skipped(
                "fresh scratch dir acquired content; retained byte-for-byte",
            )
        }
        maestro_shell::FreshScratchCwdCleanupOutcome::RetainedNamespaceInUse => {
            ResolvedNewTabRecoveryEffectResult::skipped(
                "exact Session namespace is in use; fresh scratch dir retained",
            )
        }
    })
}

/// Test-only legacy effect for recovery-plan fixtures that predate opaque cleanup receipts.
#[cfg(test)]
fn remove_new_tab_scratch(cwd: &Path) -> std::io::Result<()> {
    std::fs::remove_dir_all(cwd)
}

/// Concrete `RemoveScratch` adapter translating a resolved scratch-removal target into the resolved
/// recovery seam's [`ResolvedNewTabRecoveryEffectResult`] vocabulary. An already-absent directory is
/// an idempotent no-op (`Skipped`), not a failure; any other IO error is propagated so the caller's
/// effects implementation decides fatality. The complete live recovery adapter below uses this
/// helper for its `RemoveScratch` action.
#[cfg(test)]
fn remove_scratch_recovery_effect(
    cwd: &Path,
) -> std::io::Result<ResolvedNewTabRecoveryEffectResult> {
    match remove_new_tab_scratch(cwd) {
        Ok(()) => Ok(ResolvedNewTabRecoveryEffectResult::Succeeded),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(
            ResolvedNewTabRecoveryEffectResult::skipped("missing scratch dir (already gone)"),
        ),
        Err(e) => Err(e),
    }
}

/// Result vocabulary for an injected session-kill capability.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KillSessionRecoveryEffectResult {
    Killed,
    AlreadyGone,
    Represented,
    #[allow(dead_code)]
    GenerationChanged,
}

/// Injected session-kill capability for resolved new-tab recovery.
///
/// Tests can fake this trait without a live daemon. Production adapters can wrap the existing
/// `maestro-shell` daemon client.
#[cfg(test)]
pub trait NewTabRecoverySessionKiller {
    type Error: std::fmt::Display;

    fn kill_session(
        &mut self,
        session_id: &str,
        expected_generation: &str,
    ) -> Result<KillSessionRecoveryEffectResult, Self::Error>;
}

/// Translate an injected session-kill result into the resolved recovery seam vocabulary.
///
/// This helper does not connect to a daemon by itself; all side effects are owned by `killer`.
#[cfg(test)]
pub fn kill_session_recovery_effect<K: NewTabRecoverySessionKiller>(
    session_id: &str,
    expected_generation: &str,
    killer: &mut K,
) -> Result<ResolvedNewTabRecoveryEffectResult, K::Error> {
    match killer.kill_session(session_id, expected_generation)? {
        KillSessionRecoveryEffectResult::Killed => {
            Ok(ResolvedNewTabRecoveryEffectResult::Succeeded)
        }
        KillSessionRecoveryEffectResult::AlreadyGone => Ok(
            ResolvedNewTabRecoveryEffectResult::skipped("session already gone"),
        ),
        KillSessionRecoveryEffectResult::Represented => Ok(
            ResolvedNewTabRecoveryEffectResult::skipped("session is represented by a durable pane"),
        ),
        KillSessionRecoveryEffectResult::GenerationChanged => Ok(
            ResolvedNewTabRecoveryEffectResult::skipped("session generation changed"),
        ),
    }
}

/// Concrete `RollbackTabRecord` adapter translating a resolved window/tab target into the resolved
/// recovery seam's [`ResolvedNewTabRecoveryEffectResult`] vocabulary.
///
/// This removes only the durable app-owned tab record through
/// [`maestro_shell::WindowLayoutService::close_tab`]. Already-absent targets are idempotent skips;
/// storage/future-version/corrupt/id errors are propagated for the executor to record as failures.
/// The complete live recovery adapter below uses this helper for its `RollbackTabRecord` action.
#[cfg(test)]
pub fn rollback_tab_record_recovery_effect(
    paths: &maestro_shell::AppPaths,
    window_id: &str,
    tab_id: &str,
    now_ms: u64,
) -> Result<ResolvedNewTabRecoveryEffectResult, maestro_shell::window_layout::WindowLayoutError> {
    match maestro_shell::WindowLayoutService::new(paths).close_tab(window_id, tab_id, now_ms) {
        Ok(_) => Ok(ResolvedNewTabRecoveryEffectResult::Succeeded),
        Err(maestro_shell::window_layout::WindowLayoutError::TabNotFound { .. }) => Ok(
            ResolvedNewTabRecoveryEffectResult::skipped("tab record already absent"),
        ),
        Err(maestro_shell::window_layout::WindowLayoutError::WindowLayoutNotFound { .. }) => Ok(
            ResolvedNewTabRecoveryEffectResult::skipped("window layout already absent"),
        ),
        Err(e) => Err(e),
    }
}

/// Renderer-state recovery result before translation into the resolved recovery seam vocabulary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RendererStateRecoveryEffectResult {
    Restored,
    AlreadyCurrent,
    /// The prior lifetime could not be reacquired from a fresh exact snapshot in this adapter. The
    /// failed target is neutral and no id-only Attach was attempted.
    Neutralized,
}

/// Injected renderer-state recovery capability.
///
/// The resolved action payload carries the previous strip tabs plus the tab/session selection map,
/// but not every piece of live renderer state a production adapter needs (for example, the window id
/// and current active renderer session). Implementations own those live details. These helpers only
/// translate the implementation's result into the executor's common status vocabulary.
pub trait NewTabRecoveryRendererStateController {
    type Error: std::fmt::Display;

    fn revert_renderer_strip(
        &mut self,
        strip_tabs: &[WindowTabJson],
        selection: &[TabSelection],
    ) -> Result<RendererStateRecoveryEffectResult, Self::Error>;

    fn reconcile_renderer_state(
        &mut self,
        strip_tabs: &[WindowTabJson],
        selection: &[TabSelection],
    ) -> Result<RendererStateRecoveryEffectResult, Self::Error>;
}

/// Translate an injected renderer-strip revert into the resolved recovery seam vocabulary.
pub fn revert_renderer_strip_recovery_effect<C: NewTabRecoveryRendererStateController>(
    strip_tabs: &[WindowTabJson],
    selection: &[TabSelection],
    controller: &mut C,
) -> Result<ResolvedNewTabRecoveryEffectResult, C::Error> {
    match controller.revert_renderer_strip(strip_tabs, selection)? {
        RendererStateRecoveryEffectResult::Restored => {
            Ok(ResolvedNewTabRecoveryEffectResult::Succeeded)
        }
        RendererStateRecoveryEffectResult::AlreadyCurrent => Ok(
            ResolvedNewTabRecoveryEffectResult::skipped("renderer strip already current"),
        ),
        RendererStateRecoveryEffectResult::Neutralized => {
            Ok(ResolvedNewTabRecoveryEffectResult::skipped(
                "renderer remained neutral; exact prior lifetime was not reacquired",
            ))
        }
    }
}

/// Translate an injected renderer-state reconciliation into the resolved recovery seam vocabulary.
pub fn reconcile_renderer_state_recovery_effect<C: NewTabRecoveryRendererStateController>(
    strip_tabs: &[WindowTabJson],
    selection: &[TabSelection],
    controller: &mut C,
) -> Result<ResolvedNewTabRecoveryEffectResult, C::Error> {
    match controller.reconcile_renderer_state(strip_tabs, selection)? {
        RendererStateRecoveryEffectResult::Restored => {
            Ok(ResolvedNewTabRecoveryEffectResult::Succeeded)
        }
        RendererStateRecoveryEffectResult::AlreadyCurrent => Ok(
            ResolvedNewTabRecoveryEffectResult::skipped("renderer state already reconciled"),
        ),
        RendererStateRecoveryEffectResult::Neutralized => {
            Ok(ResolvedNewTabRecoveryEffectResult::skipped(
                "renderer remained neutral; exact prior lifetime was not reacquired",
            ))
        }
    }
}

/// Live renderer-state recovery controller backed by the foreground listener's
/// [`RendererTabRuntime`].
///
/// It owns the mutable runtime plus the listener window id — the live details the resolved action
/// payload deliberately does not carry. Both `revert` and `reconcile` rebuild the read-only tab
/// strip from the pre-attempt projection and send it over the renderer command channel BEFORE the
/// caller adopts any listener projection, exactly mirroring the reviewed
/// `ContractRendererStateController::restore_renderer_projection` adoption boundary:
///
/// - a closed renderer command channel surfaces [`TabSwitchError::RendererControlClosed`], which the
///   executor records as a failed outcome and the listener must NOT treat as projection adoption;
/// - the strip model's active marker is sourced from the live `active_tab_id()` (which a failed
///   foreground attempt never advanced), not recomputed — and only when that id still exists in the
///   pre-attempt strip, so a benign active/strip mismatch degrades to an unmarked strip rather than a
///   hard error.
///
/// The live controller deliberately has NO derived already-current / ambiguous skip. Legacy and
/// diagnostic error variants may still describe a renderer projection that needs repair, while the
/// production handoff command now admits strip+Claim atomically. `RendererTabRuntime` tracks active
/// session/window ownership, NOT the last-delivered strip payload, so its active coordinate alone
/// is not a sound "strip already current" signal. The production controller therefore always
/// restores the pre-attempt strip when recovery requests it; the idempotent-skip
/// ([`RendererStateRecoveryEffectResult::AlreadyCurrent`]) contract is proven separately by
/// `ContractRendererStateController`, whose skip modes are driven by an explicit reviewed signal.
pub struct ForegroundRendererStateController<'a> {
    runtime: &'a mut RendererTabRuntime,
    window_id: String,
    expected_handoff: Option<(maestro_renderer::RendererAttachmentHandoffRequestId, String)>,
}

impl<'a> ForegroundRendererStateController<'a> {
    pub fn new(runtime: &'a mut RendererTabRuntime, window_id: impl Into<String>) -> Self {
        Self {
            runtime,
            window_id: window_id.into(),
            expected_handoff: None,
        }
    }

    fn for_handoff(
        runtime: &'a mut RendererTabRuntime,
        window_id: impl Into<String>,
        request_id: maestro_renderer::RendererAttachmentHandoffRequestId,
        session_id: impl Into<String>,
    ) -> Self {
        Self {
            runtime,
            window_id: window_id.into(),
            expected_handoff: Some((request_id, session_id.into())),
        }
    }

    fn restore_renderer_projection(
        &mut self,
        strip_tabs: &[WindowTabJson],
    ) -> Result<RendererStateRecoveryEffectResult, TabSwitchError> {
        let pending = self.runtime.pending_handoff().cloned();
        match (&self.expected_handoff, &pending) {
            (Some((request_id, session_id)), Some(pending))
                if pending.handoff_request_id() == Some(*request_id)
                    && pending.target().target().session_id == *session_id => {}
            (Some(_), _) | (None, Some(_)) => return Err(TabSwitchError::HandoffPending),
            (None, None) => {}
        }
        if let Some(pending) = pending {
            let request_id = pending
                .handoff_request_id()
                .expect("pending_handoff contains only handoff requests");
            let session_id = pending.target().target().session_id.clone();
            let _ = self
                .runtime
                .take_nonclaimed_handoff(request_id, &session_id);
            self.runtime.clear_viewport()?;
            return Ok(RendererStateRecoveryEffectResult::Neutralized);
        }
        let active_tab_id = self
            .runtime
            .active_tab_id()
            .filter(|id| strip_tabs.iter().any(|t| t.tab_id == *id))
            .map(str::to_string);
        let model = build_tab_strip_model(&self.window_id, strip_tabs, active_tab_id.as_deref())
            .map_err(|e| {
                let TabStripModelError::ActiveTabNotFound { tab_id } = e;
                TabSwitchError::TabNotFound {
                    window_id: self.window_id.clone(),
                    tab_id,
                }
            })?;
        match self.runtime.set_tab_strip(Some(&model)) {
            Ok(()) => Ok(RendererStateRecoveryEffectResult::Restored),
            // The legacy recovery payload carries presentation only. When no already-proven exact
            // cohort is active, it cannot authorize a replacement Attach or strip publication.
            // Staying neutral is a successful fail-closed recovery state; the caller may continue
            // its generation-bound forward release without resurrecting a textual prior lifetime.
            Err(TabSwitchError::ViewportAuthorityRequired) => {
                Ok(RendererStateRecoveryEffectResult::Neutralized)
            }
            Err(error) => Err(error),
        }
    }
}

impl NewTabRecoveryRendererStateController for ForegroundRendererStateController<'_> {
    type Error = TabSwitchError;

    fn revert_renderer_strip(
        &mut self,
        strip_tabs: &[WindowTabJson],
        _selection: &[TabSelection],
    ) -> Result<RendererStateRecoveryEffectResult, Self::Error> {
        self.restore_renderer_projection(strip_tabs)
    }

    fn reconcile_renderer_state(
        &mut self,
        strip_tabs: &[WindowTabJson],
        _selection: &[TabSelection],
    ) -> Result<RendererStateRecoveryEffectResult, Self::Error> {
        self.restore_renderer_projection(strip_tabs)
    }
}

struct CommittedNewTabRollback {
    release_receipt: Option<maestro_shell::PendingReleaseReceipt>,
    unresolved_release_session_ids: Vec<String>,
    session_id: String,
    expected_generation: String,
    scratch_cwd: Option<PathBuf>,
    window_id: String,
    renderer: NewTabRendererRecoveryKind,
    handoff_cancel: NewTabHandoffCancelGuard,
}

struct NewTabHandoffCancelGuard {
    authority: Option<maestro_shell::AttachmentHandoffAuthority>,
}

impl NewTabHandoffCancelGuard {
    fn new(authority: Option<maestro_shell::AttachmentHandoffAuthority>) -> Self {
        Self { authority }
    }

    fn cancel_now(&mut self) {
        if let Some(authority) = self.authority.take() {
            cancel_new_tab_attachment_handoff(authority);
        }
    }
}

impl Drop for NewTabHandoffCancelGuard {
    fn drop(&mut self) {
        self.cancel_now();
    }
}

fn new_tab_release_action(
    session_id: &str,
    expected_generation: &str,
) -> ResolvedNewTabRecoveryAction {
    ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
        session_id: session_id.to_string(),
        expected_generation: expected_generation.to_string(),
    }
}

fn compensate_prepared_new_tab_status(
    paths: &maestro_shell::AppPaths,
    receipt: maestro_shell::PreparedNewSessionCompensationReceipt,
    now_ms: u64,
) -> NewTabPreparedCompensationStatus {
    match maestro_shell::WindowLayoutService::new(paths)
        .compensate_prepared_new_session(receipt, now_ms)
    {
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
            maestro_shell::ConditionalCreatedTabSessionRollback::RolledBack(_),
        )) => NewTabPreparedCompensationStatus::RolledBack,
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
            maestro_shell::ConditionalCreatedTabSessionRollback::Missing,
        )) => NewTabPreparedCompensationStatus::Missing,
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
            maestro_shell::ConditionalCreatedTabSessionRollback::Changed,
        )) => NewTabPreparedCompensationStatus::Changed,
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
            maestro_shell::ConditionalCreatedTabSessionRollback::Referenced,
        )) => NewTabPreparedCompensationStatus::Referenced,
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::FreshWindowGraph(_)) => {
            NewTabPreparedCompensationStatus::Failed {
                detail: "existing-window new-tab compensation returned a fresh-graph receipt"
                    .into(),
            }
        }
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::Unplaced(_)) => {
            NewTabPreparedCompensationStatus::Failed {
                detail: "existing-window new-tab compensation returned an unplaced receipt".into(),
            }
        }
        Err(error) => NewTabPreparedCompensationStatus::Failed {
            detail: error.to_string(),
        },
    }
}

fn cancel_prepared_new_tab_status(
    paths: &maestro_shell::AppPaths,
    start: maestro_shell::PreparedNewSessionStart,
    now_ms: u64,
) -> NewTabPreparedCompensationStatus {
    match maestro_shell::WindowLayoutService::new(paths).cancel_prepared_new_session(start, now_ms)
    {
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
            maestro_shell::ConditionalCreatedTabSessionRollback::RolledBack(_),
        )) => NewTabPreparedCompensationStatus::RolledBack,
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
            maestro_shell::ConditionalCreatedTabSessionRollback::Missing,
        )) => NewTabPreparedCompensationStatus::Missing,
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
            maestro_shell::ConditionalCreatedTabSessionRollback::Changed,
        )) => NewTabPreparedCompensationStatus::Changed,
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
            maestro_shell::ConditionalCreatedTabSessionRollback::Referenced,
        )) => NewTabPreparedCompensationStatus::Referenced,
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::FreshWindowGraph(_)) => {
            NewTabPreparedCompensationStatus::Failed {
                detail: "existing-window new-tab cancellation returned a fresh-graph receipt"
                    .into(),
            }
        }
        Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::Unplaced(_)) => {
            NewTabPreparedCompensationStatus::Failed {
                detail: "existing-window new-tab cancellation returned an unplaced receipt".into(),
            }
        }
        Err(error) => NewTabPreparedCompensationStatus::Failed {
            detail: error.to_string(),
        },
    }
}

fn drain_committed_new_tab_release(
    paths: &maestro_shell::AppPaths,
    socket_path: &Path,
    release_receipt: maestro_shell::PendingReleaseReceipt,
    renderer_ready: bool,
) -> ResolvedNewTabRecoveryActionStatus {
    let service = maestro_shell::SessionReleaseService::new(paths);
    let attempt = if renderer_ready {
        match maestro_shell::DaemonClient::connect(socket_path) {
            Ok(mut client) => service.attempt_owned_with_daemon(release_receipt, &mut client),
            Err(error) => service.attempt_owned_with_daemon_unavailable(release_receipt, error),
        }
    } else {
        service.attempt_owned_with_daemon_unavailable(
            release_receipt,
            maestro_shell::DaemonClientError::Protocol {
                detail: "renderer recovery was not confirmed before new-tab release".into(),
            },
        )
    };
    let (outcome, _confirmed_lifetimes) = attempt.into_parts();
    match outcome {
        maestro_shell::ReleaseOperationOutcome::Complete {
            confirmed,
            retained: _,
        } if confirmed > 0 => ResolvedNewTabRecoveryActionStatus::Succeeded,
        maestro_shell::ReleaseOperationOutcome::Complete { retained, .. } => {
            ResolvedNewTabRecoveryActionStatus::Skipped {
                reason: format!("durable ownership retained {retained} release target(s)"),
            }
        }
        maestro_shell::ReleaseOperationOutcome::UnpublishedFailure { compensation, .. } => {
            // This does not restore the deleted graph or compensate an unpublished renderer Claim.
            // It surrenders only the zero-publication lease so the durable RowMustBeAbsent forward
            // journal is immediately claimable by the next release worker.
            match service.release_unpublished_for_retry(compensation) {
                Ok(()) => ResolvedNewTabRecoveryActionStatus::Skipped {
                    reason: "release queued for forward retry before any daemon publication".into(),
                },
                Err(_) => ResolvedNewTabRecoveryActionStatus::Failed {
                    error: "release retry scheduling failed; durable lease will expire safely"
                        .into(),
                },
            }
        }
        maestro_shell::ReleaseOperationOutcome::ForwardOnly {
            confirmed,
            possibly_published,
            pending,
            ..
        } => ResolvedNewTabRecoveryActionStatus::Skipped {
            reason: format!(
                "release remains forward-only (confirmed={confirmed}, possibly_published={possibly_published}, pending={pending})"
            ),
        },
    }
}

/// Execute the generation-bound production recovery state machine.
///
/// Durable rollback/journaling always runs before renderer repair. Daemon connection/CAS is lazy
/// and occurs only after renderer state is known neutralized; a renderer or connection failure
/// surrenders zero-publication authority for durable forward retry. Refused/changed rollback
/// authority suppresses renderer, daemon, and scratch effects entirely.
pub fn execute_production_new_tab_recovery(
    paths: &maestro_shell::AppPaths,
    socket_path: &Path,
    now_ms: u64,
    error: &mut NewTabForegroundError,
    previous_strip_tabs: &[WindowTabJson],
    previous_selection: &[TabSelection],
    runtime: &mut RendererTabRuntime,
) -> ResolvedNewTabRecoveryExecutionReport {
    let disposition_handoff = match error {
        NewTabForegroundError::GenerationBoundAttachSession {
            session_id,
            error: NewTabAttachSessionError::HandoffNotClaimed { request_id, .. },
            ..
        }
        | NewTabForegroundError::PreparedGenerationBoundAttachSession {
            session_id,
            error: NewTabAttachSessionError::HandoffNotClaimed { request_id, .. },
            ..
        } => Some((*request_id, session_id.clone())),
        _ => None,
    };
    let diagnostic = classify_new_tab_foreground_failure(error);
    if let NewTabForegroundError::SessionStart { error, .. } = error {
        if let Some(shell_error) = error.take_shell_error() {
            settle_new_tab_shell_runtime_error(shell_error);
        }
    }
    let Some(authority) = error.take_rollback_authority() else {
        let mut outcomes = Vec::new();
        // The opaque capability already encodes both ScratchCwd provenance and mutation
        // certainty. Prepared GraphAuthority and D.U.+RolledBack failures may therefore clean up
        // even though their diagnostic stage is SessionStart; Refused never does.
        let scratch_cwd = new_tab_failure_scratch_to_remove(error).map(Path::to_path_buf);
        if let Some(authority) = take_new_tab_failure_scratch_authority(error) {
            let cwd = scratch_cwd.unwrap_or_else(|| paths.scratch_base().join("redacted"));
            let action = ResolvedNewTabRecoveryAction::RemoveScratch(cwd.clone());
            outcomes.push(resolved_recovery_effect_outcome(
                &action,
                cleanup_new_tab_scratch(paths, authority),
            ));
        }
        return ResolvedNewTabRecoveryExecutionReport {
            diagnostic,
            outcomes,
        };
    };

    let service = maestro_shell::WindowLayoutService::new(paths);
    let mut outcomes = Vec::new();
    let mut committed = match authority {
        NewTabRollbackAuthority::StartedSession(mut authority) => {
            let session_id = authority.expected_session.session_id.clone();
            let expected_generation = authority.expected_generation.clone();
            let handoff_cancel = NewTabHandoffCancelGuard::new(authority.attachment_handoff.take());
            let release_action = new_tab_release_action(&session_id, &expected_generation);
            match service.delete_created_session_if_unreferenced(
                &authority.expected_layout_without_tab,
                &authority.created_tab_id,
                &authority.expected_session,
                now_ms,
            ) {
                Ok(maestro_shell::ConditionalCreatedSessionDelete::Deleted {
                    release_receipt,
                    unresolved_release_session_ids,
                }) => CommittedNewTabRollback {
                    release_receipt,
                    unresolved_release_session_ids,
                    session_id,
                    expected_generation,
                    scratch_cwd: authority.scratch_cwd,
                    window_id: authority.expected_layout_without_tab.layout.window_id,
                    renderer: NewTabRendererRecoveryKind::None,
                    handoff_cancel,
                },
                Ok(maestro_shell::ConditionalCreatedSessionDelete::Missing) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::skipped(
                        release_action,
                        "exact created Session is already missing; recovery authority consumed",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
                Ok(maestro_shell::ConditionalCreatedSessionDelete::Changed) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::skipped(
                        release_action,
                        "created Session/layout authority changed; no recovery effects published",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
                Ok(maestro_shell::ConditionalCreatedSessionDelete::Referenced) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::skipped(
                        release_action,
                        "created Session acquired a durable owner; no recovery effects published",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
                Err(_) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::failed(
                        release_action,
                        "atomic created-Session rollback failed",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
            }
        }
        NewTabRollbackAuthority::CreatedTab {
            mut authority,
            renderer,
        } => {
            let session_id = authority.expected_session.session_id.clone();
            let expected_generation = authority.expected_generation.clone();
            let handoff_cancel = NewTabHandoffCancelGuard::new(authority.attachment_handoff.take());
            let rollback_action = ResolvedNewTabRecoveryAction::RollbackTabRecord {
                window_id: authority.expected_post_layout.layout.window_id.clone(),
                tab_id: authority.created_tab_id.clone(),
            };
            match service.rollback_created_tab_and_session_if_unchanged(
                &authority.expected_post_layout,
                &authority.created_tab_id,
                &authority.expected_session,
                now_ms,
            ) {
                Ok(maestro_shell::ConditionalCreatedTabSessionRollback::RolledBack(rollback)) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::succeeded(
                        rollback_action,
                    ));
                    CommittedNewTabRollback {
                        release_receipt: rollback.release_receipt,
                        unresolved_release_session_ids: rollback.unresolved_release_session_ids,
                        session_id,
                        expected_generation,
                        scratch_cwd: authority.scratch_cwd,
                        window_id: authority.expected_post_layout.layout.window_id,
                        renderer,
                        handoff_cancel,
                    }
                }
                Ok(maestro_shell::ConditionalCreatedTabSessionRollback::Missing) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::skipped(
                        rollback_action,
                        "created tab or Session is already missing; no recovery effects published",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
                Ok(maestro_shell::ConditionalCreatedTabSessionRollback::Changed) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::skipped(
                        rollback_action,
                        "created tab/Session authority changed; no recovery effects published",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
                Ok(maestro_shell::ConditionalCreatedTabSessionRollback::Referenced) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::skipped(
                        rollback_action,
                        "created Session acquired another durable owner; no recovery effects published",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
                Err(_) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::failed(
                        rollback_action,
                        "atomic created-tab rollback failed",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
            }
        }
        NewTabRollbackAuthority::Prepared {
            mut authority,
            renderer,
        } => {
            let handoff_cancel = NewTabHandoffCancelGuard::new(authority.attachment_handoff.take());
            let rollback_action = ResolvedNewTabRecoveryAction::RollbackTabRecord {
                window_id: authority.window_id.clone(),
                tab_id: authority.tab_id.clone(),
            };
            match service.compensate_prepared_new_session(authority.compensation, now_ms) {
                Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
                    maestro_shell::ConditionalCreatedTabSessionRollback::RolledBack(rollback),
                )) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::succeeded(
                        rollback_action,
                    ));
                    CommittedNewTabRollback {
                        release_receipt: rollback.release_receipt,
                        unresolved_release_session_ids: rollback.unresolved_release_session_ids,
                        session_id: authority.session_id,
                        expected_generation: authority.expected_generation,
                        scratch_cwd: None,
                        window_id: authority.window_id,
                        renderer,
                        handoff_cancel,
                    }
                }
                Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
                    maestro_shell::ConditionalCreatedTabSessionRollback::Missing,
                )) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::skipped(
                        rollback_action,
                        "prepared tab or Session is already missing; compensation consumed",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
                Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
                    maestro_shell::ConditionalCreatedTabSessionRollback::Changed,
                )) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::skipped(
                        rollback_action,
                        "prepared graph authority changed; no recovery effects published",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
                Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::ExistingWindow(
                    maestro_shell::ConditionalCreatedTabSessionRollback::Referenced,
                )) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::skipped(
                        rollback_action,
                        "prepared Session acquired a durable owner; no recovery effects published",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
                Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::FreshWindowGraph(
                    _,
                )) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::failed(
                        rollback_action,
                        "existing-window recovery received a fresh-graph compensation outcome",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
                Ok(maestro_shell::ConditionalPreparedNewSessionCompensation::Unplaced(_)) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::failed(
                        rollback_action,
                        "existing-window recovery received an unplaced compensation outcome",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
                Err(_) => {
                    outcomes.push(ResolvedNewTabRecoveryActionOutcome::failed(
                        rollback_action,
                        "atomic prepared-session compensation failed",
                    ));
                    return ResolvedNewTabRecoveryExecutionReport {
                        diagnostic,
                        outcomes,
                    };
                }
            }
        }
    };

    let renderer_ready = match committed.renderer {
        NewTabRendererRecoveryKind::None => true,
        NewTabRendererRecoveryKind::RevertStrip => {
            let action = ResolvedNewTabRecoveryAction::RevertRendererStrip {
                strip_tabs: previous_strip_tabs.to_vec(),
                selection: previous_selection.to_vec(),
            };
            let mut controller = match &disposition_handoff {
                Some((request_id, session_id)) => ForegroundRendererStateController::for_handoff(
                    runtime,
                    committed.window_id.clone(),
                    *request_id,
                    session_id.clone(),
                ),
                None => {
                    ForegroundRendererStateController::new(runtime, committed.window_id.clone())
                }
            };
            let outcome = resolved_recovery_effect_outcome(
                &action,
                revert_renderer_strip_recovery_effect(
                    previous_strip_tabs,
                    previous_selection,
                    &mut controller,
                ),
            );
            let ready = !outcome.status.is_failed();
            outcomes.push(outcome);
            ready
        }
        NewTabRendererRecoveryKind::ReconcileState => {
            let action = ResolvedNewTabRecoveryAction::ReconcileRendererState {
                strip_tabs: previous_strip_tabs.to_vec(),
                selection: previous_selection.to_vec(),
            };
            let mut controller = match &disposition_handoff {
                Some((request_id, session_id)) => ForegroundRendererStateController::for_handoff(
                    runtime,
                    committed.window_id.clone(),
                    *request_id,
                    session_id.clone(),
                ),
                None => {
                    ForegroundRendererStateController::new(runtime, committed.window_id.clone())
                }
            };
            let outcome = resolved_recovery_effect_outcome(
                &action,
                reconcile_renderer_state_recovery_effect(
                    previous_strip_tabs,
                    previous_selection,
                    &mut controller,
                ),
            );
            let ready = !outcome.status.is_failed();
            outcomes.push(outcome);
            ready
        }
    };

    // Retire any still-owned pre-command handoff before the forward-only release attempt. A
    // post-disposition failure has already transferred that authority out of the rollback guard,
    // so this remains a no-op for a possibly-applied Claim.
    committed.handoff_cancel.cancel_now();

    let release_action =
        new_tab_release_action(&committed.session_id, &committed.expected_generation);
    let release_status = match committed.release_receipt {
        Some(receipt) => {
            drain_committed_new_tab_release(paths, socket_path, receipt, renderer_ready)
        }
        None if committed.unresolved_release_session_ids.is_empty() => {
            ResolvedNewTabRecoveryActionStatus::Skipped {
                reason: "no daemon lifetime remained after exact durable rollback".into(),
            }
        }
        None => ResolvedNewTabRecoveryActionStatus::Skipped {
            reason:
                "exact daemon generation was unavailable; durable cleanup committed as a safe leak"
                    .into(),
        },
    };
    outcomes.push(ResolvedNewTabRecoveryActionOutcome {
        action: release_action,
        status: release_status,
    });

    if let Some(cwd) = committed.scratch_cwd {
        outcomes.push(ResolvedNewTabRecoveryActionOutcome::skipped(
            ResolvedNewTabRecoveryAction::RemoveScratch(cwd),
            "scratch is retained after Session start because a replacement lifetime may share it",
        ));
    }

    ResolvedNewTabRecoveryExecutionReport {
        diagnostic,
        outcomes,
    }
}

/// Concrete filesystem-backed resolved recovery effects.
///
/// This first implementation only supports `RemoveScratch`. The remaining effects are explicit
/// skipped no-ops so wiring this into the resolved executor cannot accidentally kill sessions,
/// mutate records, or send renderer commands.
#[cfg(test)]
#[derive(Clone, Debug, Default)]
pub struct ResolvedNewTabRecoveryFilesystemEffects;

#[cfg(test)]
impl ResolvedNewTabRecoveryEffects for ResolvedNewTabRecoveryFilesystemEffects {
    type Error = std::io::Error;

    fn remove_scratch(
        &mut self,
        cwd: &Path,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        remove_scratch_recovery_effect(cwd)
    }

    fn kill_session(
        &mut self,
        _session_id: &str,
        _expected_generation: &str,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        Ok(ResolvedNewTabRecoveryEffectResult::skipped(
            "kill_session unsupported by filesystem effects",
        ))
    }

    fn rollback_tab_record(
        &mut self,
        _window_id: &str,
        _tab_id: &str,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        Ok(ResolvedNewTabRecoveryEffectResult::skipped(
            "rollback_tab_record unsupported by filesystem effects",
        ))
    }

    fn revert_renderer_strip(
        &mut self,
        _strip_tabs: &[WindowTabJson],
        _selection: &[TabSelection],
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        Ok(ResolvedNewTabRecoveryEffectResult::skipped(
            "revert_renderer_strip unsupported by filesystem effects",
        ))
    }

    fn reconcile_renderer_state(
        &mut self,
        _strip_tabs: &[WindowTabJson],
        _selection: &[TabSelection],
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        Ok(ResolvedNewTabRecoveryEffectResult::skipped(
            "reconcile_renderer_state unsupported by filesystem effects",
        ))
    }
}

/// Error vocabulary for concrete local resolved new-tab recovery effects.
#[cfg(test)]
#[derive(Debug)]
pub enum ResolvedNewTabRecoveryLocalEffectError<KillError> {
    Io(std::io::Error),
    Kill(KillError),
    WindowLayout(maestro_shell::window_layout::WindowLayoutError),
}

#[cfg(test)]
impl<KillError: std::fmt::Display> std::fmt::Display
    for ResolvedNewTabRecoveryLocalEffectError<KillError>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolvedNewTabRecoveryLocalEffectError::Io(error) => write!(f, "{error}"),
            ResolvedNewTabRecoveryLocalEffectError::Kill(error) => write!(f, "{error}"),
            ResolvedNewTabRecoveryLocalEffectError::WindowLayout(error) => write!(f, "{error}"),
        }
    }
}

#[cfg(test)]
impl<KillError> std::error::Error for ResolvedNewTabRecoveryLocalEffectError<KillError>
where
    KillError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ResolvedNewTabRecoveryLocalEffectError::Io(error) => Some(error),
            ResolvedNewTabRecoveryLocalEffectError::Kill(error) => Some(error),
            ResolvedNewTabRecoveryLocalEffectError::WindowLayout(error) => Some(error),
        }
    }
}

/// Partial local resolved recovery effects for `RemoveScratch` and `KillSession`.
///
/// This adapter can remove orphan scratch directories and kill a resolved session through an
/// injected capability. Post-record rollback and renderer reconciliation are explicit skipped
/// no-ops here; the complete live adapter below implements all five actions.
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct ResolvedNewTabRecoveryLocalEffects<K> {
    session_killer: K,
}

#[cfg(test)]
impl<K> ResolvedNewTabRecoveryLocalEffects<K> {
    pub fn new(session_killer: K) -> Self {
        Self { session_killer }
    }

    pub fn session_killer(&self) -> &K {
        &self.session_killer
    }
}

#[cfg(test)]
impl<K> ResolvedNewTabRecoveryEffects for ResolvedNewTabRecoveryLocalEffects<K>
where
    K: NewTabRecoverySessionKiller,
{
    type Error = ResolvedNewTabRecoveryLocalEffectError<K::Error>;

    fn remove_scratch(
        &mut self,
        cwd: &Path,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        remove_scratch_recovery_effect(cwd).map_err(ResolvedNewTabRecoveryLocalEffectError::Io)
    }

    fn kill_session(
        &mut self,
        session_id: &str,
        expected_generation: &str,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        kill_session_recovery_effect(session_id, expected_generation, &mut self.session_killer)
            .map_err(ResolvedNewTabRecoveryLocalEffectError::Kill)
    }

    fn rollback_tab_record(
        &mut self,
        _window_id: &str,
        _tab_id: &str,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        Ok(ResolvedNewTabRecoveryEffectResult::skipped(
            "rollback_tab_record unsupported by local recovery effects",
        ))
    }

    fn revert_renderer_strip(
        &mut self,
        _strip_tabs: &[WindowTabJson],
        _selection: &[TabSelection],
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        Ok(ResolvedNewTabRecoveryEffectResult::skipped(
            "revert_renderer_strip unsupported by local recovery effects",
        ))
    }

    fn reconcile_renderer_state(
        &mut self,
        _strip_tabs: &[WindowTabJson],
        _selection: &[TabSelection],
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        Ok(ResolvedNewTabRecoveryEffectResult::skipped(
            "reconcile_renderer_state unsupported by local recovery effects",
        ))
    }
}

/// Concrete local resolved recovery effects including durable tab-record rollback.
///
/// This extends the local scratch/session effects with an app-support-backed `RollbackTabRecord`
/// implementation. Renderer actions remain explicit skipped no-ops here; the complete live adapter
/// below supplies them.
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct ResolvedNewTabRecoveryRecordLocalEffects<K> {
    paths: maestro_shell::AppPaths,
    now_ms: u64,
    session_killer: K,
}

#[cfg(test)]
impl<K> ResolvedNewTabRecoveryRecordLocalEffects<K> {
    pub fn new(paths: maestro_shell::AppPaths, now_ms: u64, session_killer: K) -> Self {
        Self {
            paths,
            now_ms,
            session_killer,
        }
    }

    pub fn session_killer(&self) -> &K {
        &self.session_killer
    }
}

#[cfg(test)]
impl<K> ResolvedNewTabRecoveryEffects for ResolvedNewTabRecoveryRecordLocalEffects<K>
where
    K: NewTabRecoverySessionKiller,
{
    type Error = ResolvedNewTabRecoveryLocalEffectError<K::Error>;

    fn remove_scratch(
        &mut self,
        cwd: &Path,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        remove_scratch_recovery_effect(cwd).map_err(ResolvedNewTabRecoveryLocalEffectError::Io)
    }

    fn kill_session(
        &mut self,
        session_id: &str,
        expected_generation: &str,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        kill_session_recovery_effect(session_id, expected_generation, &mut self.session_killer)
            .map_err(ResolvedNewTabRecoveryLocalEffectError::Kill)
    }

    fn rollback_tab_record(
        &mut self,
        window_id: &str,
        tab_id: &str,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        rollback_tab_record_recovery_effect(&self.paths, window_id, tab_id, self.now_ms)
            .map_err(ResolvedNewTabRecoveryLocalEffectError::WindowLayout)
    }

    fn revert_renderer_strip(
        &mut self,
        _strip_tabs: &[WindowTabJson],
        _selection: &[TabSelection],
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        Ok(ResolvedNewTabRecoveryEffectResult::skipped(
            "revert_renderer_strip unsupported by record-local recovery effects",
        ))
    }

    fn reconcile_renderer_state(
        &mut self,
        _strip_tabs: &[WindowTabJson],
        _selection: &[TabSelection],
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        Ok(ResolvedNewTabRecoveryEffectResult::skipped(
            "reconcile_renderer_state unsupported by record-local recovery effects",
        ))
    }
}

/// Error vocabulary for the complete headless resolved new-tab recovery effects object.
#[cfg(test)]
#[derive(Debug)]
pub enum ResolvedNewTabRecoveryCompleteEffectError<KillError, RendererError> {
    Io(std::io::Error),
    Kill(KillError),
    WindowLayout(maestro_shell::window_layout::WindowLayoutError),
    Renderer(RendererError),
}

#[cfg(test)]
impl<KillError: std::fmt::Display, RendererError: std::fmt::Display> std::fmt::Display
    for ResolvedNewTabRecoveryCompleteEffectError<KillError, RendererError>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolvedNewTabRecoveryCompleteEffectError::Io(error) => write!(f, "{error}"),
            ResolvedNewTabRecoveryCompleteEffectError::Kill(error) => write!(f, "{error}"),
            ResolvedNewTabRecoveryCompleteEffectError::WindowLayout(error) => write!(f, "{error}"),
            ResolvedNewTabRecoveryCompleteEffectError::Renderer(error) => write!(f, "{error}"),
        }
    }
}

#[cfg(test)]
impl<KillError, RendererError> std::error::Error
    for ResolvedNewTabRecoveryCompleteEffectError<KillError, RendererError>
where
    KillError: std::error::Error + 'static,
    RendererError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ResolvedNewTabRecoveryCompleteEffectError::Io(error) => Some(error),
            ResolvedNewTabRecoveryCompleteEffectError::Kill(error) => Some(error),
            ResolvedNewTabRecoveryCompleteEffectError::WindowLayout(error) => Some(error),
            ResolvedNewTabRecoveryCompleteEffectError::Renderer(error) => Some(error),
        }
    }
}

/// Complete headless resolved recovery effects for all five concrete action types.
///
/// This composes the record-local filesystem/session/layout effects with an injected renderer-state
/// controller. Foreground failure branches construct it as the complete live recovery adapter;
/// renderer restore/reconcile details remain owned by the injected controller.
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct ResolvedNewTabRecoveryCompleteEffects<K, C> {
    paths: maestro_shell::AppPaths,
    now_ms: u64,
    session_killer: K,
    renderer_controller: C,
}

#[cfg(test)]
impl<K, C> ResolvedNewTabRecoveryCompleteEffects<K, C> {
    pub fn new(
        paths: maestro_shell::AppPaths,
        now_ms: u64,
        session_killer: K,
        renderer_controller: C,
    ) -> Self {
        Self {
            paths,
            now_ms,
            session_killer,
            renderer_controller,
        }
    }

    pub fn session_killer(&self) -> &K {
        &self.session_killer
    }

    pub fn renderer_controller(&self) -> &C {
        &self.renderer_controller
    }
}

#[cfg(test)]
impl<K, C> ResolvedNewTabRecoveryEffects for ResolvedNewTabRecoveryCompleteEffects<K, C>
where
    K: NewTabRecoverySessionKiller,
    C: NewTabRecoveryRendererStateController,
{
    type Error = ResolvedNewTabRecoveryCompleteEffectError<K::Error, C::Error>;

    fn remove_scratch(
        &mut self,
        cwd: &Path,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        remove_scratch_recovery_effect(cwd).map_err(ResolvedNewTabRecoveryCompleteEffectError::Io)
    }

    fn kill_session(
        &mut self,
        session_id: &str,
        expected_generation: &str,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        kill_session_recovery_effect(session_id, expected_generation, &mut self.session_killer)
            .map_err(ResolvedNewTabRecoveryCompleteEffectError::Kill)
    }

    fn rollback_tab_record(
        &mut self,
        window_id: &str,
        tab_id: &str,
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        rollback_tab_record_recovery_effect(&self.paths, window_id, tab_id, self.now_ms)
            .map_err(ResolvedNewTabRecoveryCompleteEffectError::WindowLayout)
    }

    fn revert_renderer_strip(
        &mut self,
        strip_tabs: &[WindowTabJson],
        selection: &[TabSelection],
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        revert_renderer_strip_recovery_effect(strip_tabs, selection, &mut self.renderer_controller)
            .map_err(ResolvedNewTabRecoveryCompleteEffectError::Renderer)
    }

    fn reconcile_renderer_state(
        &mut self,
        strip_tabs: &[WindowTabJson],
        selection: &[TabSelection],
    ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
        reconcile_renderer_state_recovery_effect(
            strip_tabs,
            selection,
            &mut self.renderer_controller,
        )
        .map_err(ResolvedNewTabRecoveryCompleteEffectError::Renderer)
    }
}

/// Immutable inputs for [`run_new_tab_foreground_pipeline`].
pub struct NewTabForegroundRequest<'a> {
    pub paths: &'a maestro_shell::AppPaths,
    pub socket_path: std::path::PathBuf,
    pub window_id: &'a str,
    pub plan: &'a NewTabPlan,
    /// Consume-once launch description. It is converted into a Shell-owned opaque prepared spec
    /// only after this attempt's exact workspace/cwd has been prepared.
    pub launch: NewTabForegroundLaunch,
    pub cols: u16,
    pub rows: u16,
    pub now_ms: u64,
    /// When `Some`, the new tab is recorded as a SPLIT of `from_tab_id` along `axis` (via
    /// [`maestro_shell::WindowLayoutService::split_tab`]) instead of an ordinary appended tab. The
    /// rest of the foreground pipeline (session start, strip projection, attach) is identical — only
    /// the layout-record step differs — so a GUI split reuses the whole new-tab launch path. `None`
    /// is the existing plain new-tab behavior, byte-identical.
    pub split_from: Option<NewTabSplitFrom>,
    /// Exact source lifetime when a split inherits its Workspace from that pane. The shell core
    /// revalidates this row and the source tab edge in the same transaction that prepares the
    /// child; ordinary new tabs and splits with independently selected Workspaces leave it empty.
    pub split_source_session: Option<&'a maestro_shell::SessionRecord>,
    /// Optional caller-reviewed Project owner (used by React intents carrying an explicit
    /// project id). A later window reassignment is a refusal, never authority to adopt the new
    /// owner by window id alone.
    pub expected_project_id: Option<&'a str>,
}

/// Names the source tab and axis for a split-tab record on [`NewTabForegroundRequest`]. The new tab
/// is appended as a split child of `from_tab_id` (the active tab when the split shortcut fired).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewTabSplitFrom {
    pub from_tab_id: String,
    pub axis: maestro_shell::SplitAxis,
}

/// Compose the reviewed new-tab helpers for the foreground `RendererEvent::NewTabRequested` create
/// path. This function intentionally starts at an already-planned [`NewTabPlan::Create`]; callers
/// must still run [`plan_new_tab`] so the explicit `--new-tab-default-shell` gate can decline before
/// any id minting or side effect.
///
/// This is the `ScratchCwd` entry point: it prepares the scratch workspace and then runs the shared
/// post-preparation flow. The `NewTabRequested` scratch behavior is byte-identical to before — only
/// the worktree path ([`run_new_tab_foreground_pipeline_with_consent`]) was added alongside it.
///
/// Side effects occur in this exact order:
///
/// ```text
/// prepare_fresh_scratch_cwd (exclusive leaf + opaque cleanup receipt)
///   -> new_tab_prepared_start_params
///   -> prepare_new_{tab|split}_session (one IMMEDIATE Unknown + placement transaction)
///   -> start_prepared_new_session_for_renderer (one conditional Absent(None))
///   -> same-IMMEDIATE Live(G) finalization + rebased compensation receipt
///   -> load_viewport_snapshot
///   -> send_new_tab_attach_session_with_handoff (atomic exact viewport + strip + Claim)
/// ```
///
/// The returned [`NewTabForegroundSuccess`] remains pending until the correlated renderer
/// disposition claims the exact viewport. Typed error paths either consume their exact prepared
/// compensation/cleanup authority or retain ambiguous state for forward recovery; no id-based
/// rollback or unconditional scratch deletion is permitted.
pub fn run_new_tab_foreground_pipeline(
    request: NewTabForegroundRequest<'_>,
    env: &impl maestro_shell::EnvLookup,
    runtime: &mut RendererTabRuntime,
) -> Result<NewTabForegroundSuccess, NewTabForegroundError> {
    if runtime.handoff_is_pending() {
        return Err(NewTabForegroundError::WorkspacePrepare(
            NewTabWorkspacePrepareError::RendererHandoffPending,
        ));
    }
    validate_new_tab_launch_source(request.plan, &request.launch).map_err(|error| {
        NewTabForegroundError::StartParams {
            cwd: PathBuf::new(),
            scratch: None,
            error,
        }
    })?;
    let (prepared, scratch) =
        prepare_fresh_new_tab_scratch_workspace(request.paths, request.plan, "")
            .map_err(NewTabForegroundError::WorkspacePrepare)?;
    run_new_tab_foreground_pipeline_from_prepared(
        request,
        prepared,
        Some(scratch),
        None,
        env,
        runtime,
    )
}

/// The already-consented consent-gated foreground new-tab entry point for `Worktree` AND `RepoWrite`
/// rows. Identical to [`run_new_tab_foreground_pipeline`] except the workspace is prepared through the
/// consent-gated shell executor [`maestro_shell::prepare_workspace_with_consent`] (the defense-in-depth
/// gate that re-verifies consent before any side effect) instead of the scratch preparer. The
/// preparation policy is taken from the FRESH record's `policy` field, NOT hardcoded: a `Worktree`
/// record re-verifies `worktree_create` before any `git worktree add`; a `RepoWrite` record re-verifies
/// `repo_write` and (per the verify-only repo-write preparer) returns the live checkout root as cwd with
/// no git/mkdir side effects. The caller MUST have already resolved this row as launchable via the
/// picker resolvers (which read consent from the fresh record and never grant it); `fresh_workspace` is
/// that same fresh authoritative record.
///
/// The post-preparation transaction/start/disposition order is shared with the scratch path (see
/// [`run_new_tab_foreground_pipeline`]). Worktree/RepoWrite paths never mint scratch-removal
/// authority; typed PreparedNew compensation owns any safe durable rollback.
pub fn run_new_tab_foreground_pipeline_with_consent(
    request: NewTabForegroundRequest<'_>,
    fresh_workspace: &maestro_shell::Workspace,
    env: &impl maestro_shell::EnvLookup,
    runtime: &mut RendererTabRuntime,
) -> Result<NewTabForegroundSuccess, NewTabForegroundError> {
    if runtime.handoff_is_pending() {
        return Err(NewTabForegroundError::WorkspacePrepare(
            NewTabWorkspacePrepareError::RendererHandoffPending,
        ));
    }
    validate_new_tab_launch_source(request.plan, &request.launch).map_err(|error| {
        NewTabForegroundError::StartParams {
            cwd: PathBuf::new(),
            scratch: None,
            error,
        }
    })?;
    let session_id = new_tab_plan_session_id(request.plan).ok_or(
        NewTabForegroundError::WorkspacePrepare(NewTabWorkspacePrepareError::NotCreate),
    )?;
    let (prepared, scratch) = if fresh_workspace.policy
        == maestro_shell::WorkspacePolicy::ScratchCwd
    {
        maestro_shell::check_policy_consent(fresh_workspace, fresh_workspace.policy).map_err(
            |error| {
                NewTabForegroundError::WorkspacePrepare(NewTabWorkspacePrepareError::WorkspaceExec(
                    maestro_shell::WorkspaceExecError::Consent(error),
                ))
            },
        )?;
        let (prepared, receipt) = maestro_shell::prepare_fresh_scratch_cwd(
            request.paths,
            &fresh_workspace.workspace_id,
            session_id,
            &fresh_workspace.root,
        )
        .map_err(|error| {
            NewTabForegroundError::WorkspacePrepare(NewTabWorkspacePrepareError::WorkspaceExec(
                error,
            ))
        })?
        .into_parts();
        (
            prepared,
            Some(NewTabScratchRemovalAuthority::from_fresh_receipt(receipt)),
        )
    } else {
        (
            maestro_shell::prepare_workspace_with_consent(
                request.paths,
                fresh_workspace.policy,
                fresh_workspace,
                session_id,
            )
            .map_err(|error| {
                NewTabForegroundError::WorkspacePrepare(NewTabWorkspacePrepareError::WorkspaceExec(
                    error,
                ))
            })?,
            None,
        )
    };
    run_new_tab_foreground_pipeline_from_prepared(
        request,
        prepared,
        scratch,
        Some(fresh_workspace.clone()),
        env,
        runtime,
    )
}

/// Shared post-preparation foreground new-tab flow. Scratch, Worktree, and RepoWrite entry points
/// converge here once a [`maestro_shell::PreparedWorkspace`] exists. The exact graph is prepared
/// before the single daemon request, then finalized Live before renderer projection:
///
/// ```text
/// new_tab_prepared_start_params
///   -> exact Window/Project/Workspace/source proof
///   -> prepare_new_{tab|split}_session (Unknown + placement, atomic)
///   -> start_prepared_new_session_for_renderer
///   -> Live(G) + release-journal finalization (atomic)
///   -> exact viewport snapshot/projection
///   -> send_new_tab_attach_session_with_handoff
/// ```
fn prepared_new_tab_failure(
    prepared: &maestro_shell::PreparedWorkspace,
    scratch: &mut Option<NewTabScratchRemovalAuthority>,
    error: NewTabPreparedSessionError,
) -> NewTabForegroundError {
    NewTabForegroundError::PreparedSessionStart {
        cwd: prepared.cwd.clone(),
        scratch: scratch.take(),
        error,
    }
}

fn run_new_tab_foreground_pipeline_from_prepared(
    request: NewTabForegroundRequest<'_>,
    prepared: maestro_shell::PreparedWorkspace,
    scratch: Option<NewTabScratchRemovalAuthority>,
    reviewed_workspace: Option<maestro_shell::Workspace>,
    env: &impl maestro_shell::EnvLookup,
    runtime: &mut RendererTabRuntime,
) -> Result<NewTabForegroundSuccess, NewTabForegroundError> {
    run_new_tab_foreground_pipeline_from_prepared_with_reprobe(
        request,
        prepared,
        scratch,
        reviewed_workspace,
        env,
        runtime,
        |source_argv, selected_agent, cwd| {
            crate::launch_preflight::reprobe_prepared_argv(source_argv, selected_agent, cwd)
                .map_err(|_| NewTabStartParamsError::PreparedLaunch)
        },
    )
}

fn run_new_tab_foreground_pipeline_from_prepared_with_reprobe<R>(
    request: NewTabForegroundRequest<'_>,
    prepared: maestro_shell::PreparedWorkspace,
    mut scratch: Option<NewTabScratchRemovalAuthority>,
    reviewed_workspace: Option<maestro_shell::Workspace>,
    env: &impl maestro_shell::EnvLookup,
    runtime: &mut RendererTabRuntime,
    mut reprobe: R,
) -> Result<NewTabForegroundSuccess, NewTabForegroundError>
where
    R: FnMut(&[String], Option<&str>, &Path) -> Result<(), NewTabStartParamsError>,
{
    let (tab_id, title) =
        validate_new_tab_prepared_identity(request.plan, &prepared, Some(&request.launch))
            .map_err(|error| NewTabForegroundError::StartParams {
                cwd: prepared.cwd.clone(),
                scratch: scratch.take(),
                error,
            })?;
    let session_spec = request
        .launch
        .into_session_spec_with_reprobe(
            &prepared,
            request.cols,
            request.rows,
            request.now_ms,
            &mut reprobe,
        )
        .map_err(|error| NewTabForegroundError::StartParams {
            cwd: prepared.cwd.clone(),
            scratch: scratch.take(),
            error,
        })?;
    let windows = maestro_shell::WindowLayoutService::new(request.paths);
    let expected_window = windows
        .load_snapshot(request.window_id)
        .map_err(|error| {
            prepared_new_tab_failure(
                &prepared,
                &mut scratch,
                NewTabPreparedSessionError::GraphAuthority {
                    detail: error.to_string(),
                },
            )
        })?
        .ok_or_else(|| {
            prepared_new_tab_failure(
                &prepared,
                &mut scratch,
                NewTabPreparedSessionError::GraphAuthority {
                    detail: format!("new-tab target window {:?} is missing", request.window_id),
                },
            )
        })?;
    let project_id = expected_window.project_id.clone().ok_or_else(|| {
        prepared_new_tab_failure(
            &prepared,
            &mut scratch,
            NewTabPreparedSessionError::GraphAuthority {
                detail: format!(
                    "new-tab target window {:?} has no exact Project owner",
                    request.window_id
                ),
            },
        )
    })?;
    let proof = match windows
        .prove_project_assignment(request.window_id, &project_id)
        .map_err(|error| {
            prepared_new_tab_failure(
                &prepared,
                &mut scratch,
                NewTabPreparedSessionError::GraphAuthority {
                    detail: error.to_string(),
                },
            )
        })? {
        maestro_shell::WindowProjectAssignmentProofOutcome::Proven(proof) => proof,
        outcome => {
            return Err(prepared_new_tab_failure(
                &prepared,
                &mut scratch,
                NewTabPreparedSessionError::GraphAuthority {
                    detail: format!(
                        "new-tab target window/project authority is unavailable: {outcome:?}"
                    ),
                },
            ))
        }
    };
    if request
        .expected_project_id
        .is_some_and(|expected| expected != proof.project.project_id)
    {
        return Err(prepared_new_tab_failure(
            &prepared,
            &mut scratch,
            NewTabPreparedSessionError::GraphAuthority {
                detail: format!(
                    "new-tab target Project changed (expected {:?}, got {:?})",
                    request.expected_project_id, proof.project.project_id
                ),
            },
        ));
    }
    let workspace = match reviewed_workspace {
        Some(workspace) => workspace,
        None => match maestro_shell::load_one::<maestro_shell::Workspace>(
            request.paths,
            maestro_shell::RecordKind::Workspace,
            &prepared.workspace_id,
        )
        .map_err(|error| {
            prepared_new_tab_failure(
                &prepared,
                &mut scratch,
                NewTabPreparedSessionError::GraphAuthority {
                    detail: error.to_string(),
                },
            )
        })? {
            Some(maestro_shell::LoadOutcome::Loaded(workspace)) => workspace,
            Some(outcome) => {
                return Err(prepared_new_tab_failure(
                    &prepared,
                    &mut scratch,
                    NewTabPreparedSessionError::GraphAuthority {
                        detail: format!(
                            "new-tab Workspace {:?} is not current/loadable: {outcome:?}",
                            prepared.workspace_id
                        ),
                    },
                ))
            }
            None => {
                return Err(prepared_new_tab_failure(
                    &prepared,
                    &mut scratch,
                    NewTabPreparedSessionError::GraphAuthority {
                        detail: format!(
                        "new-tab Workspace {:?} is missing; implicit workspace creation is refused",
                        prepared.workspace_id
                    ),
                    },
                ))
            }
        },
    };
    if workspace.workspace_id != prepared.workspace_id || workspace.policy != prepared.policy {
        return Err(prepared_new_tab_failure(
            &prepared,
            &mut scratch,
            NewTabPreparedSessionError::GraphAuthority {
                detail: "prepared cwd and exact Workspace authority disagree".into(),
            },
        ));
    }
    let sealed_start = match request.split_from.as_ref() {
        Some(split) => match request.split_source_session {
            Some(source) => windows.prepare_new_split_session_from_source_with_spec(
                &proof.window,
                &proof.project,
                &workspace,
                source,
                session_spec,
                &split.from_tab_id,
                &tab_id,
                &title,
                split.axis,
            ),
            None => windows.prepare_new_split_session_with_spec(
                &proof.window,
                &proof.project,
                &workspace,
                session_spec,
                &split.from_tab_id,
                &tab_id,
                &title,
                split.axis,
            ),
        },
        None => windows.prepare_new_tab_session_with_spec(
            &proof.window,
            &proof.project,
            &workspace,
            session_spec,
            &tab_id,
            &title,
            false,
            maestro_shell::AttentionState::default(),
        ),
    }
    .map_err(|error| {
        prepared_new_tab_failure(
            &prepared,
            &mut scratch,
            NewTabPreparedSessionError::GraphAuthority {
                detail: error.to_string(),
            },
        )
    })?;

    let runtime_start = maestro_shell::ShellRuntime::new(request.paths)
        .start_prepared_new_session_for_renderer(Some(request.socket_path), env, sealed_start);
    let started = match runtime_start {
        Ok(started) => started,
        Err(maestro_shell::PreparedNewSessionRuntimeError::DefinitelyUnpublished {
            error,
            start,
        }) => {
            let compensation = cancel_prepared_new_tab_status(request.paths, start, request.now_ms);
            return Err(prepared_new_tab_failure(
                &prepared,
                &mut scratch,
                NewTabPreparedSessionError::DefinitelyUnpublished {
                    error,
                    compensation,
                },
            ));
        }
        Err(maestro_shell::PreparedNewSessionRuntimeError::Refused {
            error,
            compensation,
        }) => {
            let compensation =
                compensate_prepared_new_tab_status(request.paths, compensation, request.now_ms);
            return Err(NewTabForegroundError::PreparedSessionStart {
                cwd: prepared.cwd.clone(),
                scratch: None,
                error: NewTabPreparedSessionError::Refused {
                    error,
                    compensation,
                },
            });
        }
        Err(maestro_shell::PreparedNewSessionRuntimeError::PossiblyApplied { error }) => {
            let detail = error.to_string();
            settle_new_tab_shell_runtime_error(error);
            return Err(NewTabForegroundError::PreparedSessionStart {
                cwd: prepared.cwd.clone(),
                scratch: None,
                error: NewTabPreparedSessionError::PossiblyApplied { detail },
            });
        }
    };
    // A daemon request succeeded. Fresh-directory cleanup authority is now permanently burned;
    // all later recovery is durable/generation-bound and never removes the cwd.
    drop(scratch.take());
    let (_socket_path, expected_session, compensation, attachment_handoff) = started.into_parts();
    let started_session_id = expected_session.session_id.clone();
    let started_session_generation = match expected_session.last_known_generation.clone() {
        Some(generation) => generation,
        None => {
            if let Some(authority) = attachment_handoff {
                cancel_new_tab_attachment_handoff(authority);
            }
            let compensation =
                compensate_prepared_new_tab_status(request.paths, compensation, request.now_ms);
            return Err(NewTabForegroundError::PreparedSessionStart {
                cwd: prepared.cwd.clone(),
                scratch: None,
                error: NewTabPreparedSessionError::FinalizedInvariant {
                    detail: "finalized prepared Session supplied no PTY generation".into(),
                    compensation,
                },
            });
        }
    };
    let Some(attachment_handoff) = attachment_handoff else {
        return Err(NewTabForegroundError::PreparedStartedHandoffMissing {
            session_id: started_session_id.clone(),
            session_generation: started_session_generation.clone(),
            rollback_authority: Some(NewTabPreparedRollbackAuthority {
                compensation,
                session_id: started_session_id,
                expected_generation: started_session_generation,
                tab_id,
                window_id: request.window_id.to_string(),
                attachment_handoff: None,
            }),
        });
    };
    let renderer_handoff =
        maestro_renderer::RendererAttachmentHandoff::new(attachment_handoff.clone());
    let exact_snapshot = match maestro_shell::WindowLayoutService::new(request.paths)
        .load_viewport_snapshot(request.window_id)
    {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Err(NewTabForegroundError::PreparedGenerationBoundProjection {
                session_id: started_session_id.clone(),
                session_generation: started_session_generation.clone(),
                rollback_authority: Some(NewTabPreparedRollbackAuthority {
                    compensation,
                    session_id: started_session_id,
                    expected_generation: started_session_generation,
                    tab_id,
                    window_id: request.window_id.to_string(),
                    attachment_handoff: Some(attachment_handoff),
                }),
                error: NewTabStripProjectionError::ExactViewportSnapshot(error.to_string()),
            });
        }
    };
    let exact_projection =
        match crate::renderer_viewport_projection_from_snapshot(&exact_snapshot, &tab_id) {
            Ok(projection) => projection,
            Err(error) => {
                return Err(NewTabForegroundError::PreparedGenerationBoundProjection {
                    session_id: started_session_id.clone(),
                    session_generation: started_session_generation.clone(),
                    rollback_authority: Some(NewTabPreparedRollbackAuthority {
                        compensation,
                        session_id: started_session_id,
                        expected_generation: started_session_generation,
                        tab_id,
                        window_id: request.window_id.to_string(),
                        attachment_handoff: Some(attachment_handoff),
                    }),
                    error: NewTabStripProjectionError::ExactViewport(error),
                });
            }
        };

    if let Err(error) = send_new_tab_attach_session_with_handoff(
        runtime,
        &exact_projection,
        renderer_handoff.clone(),
    ) {
        return Err(
            NewTabForegroundError::PreparedGenerationBoundAttachSession {
                session_id: started_session_id.clone(),
                session_generation: started_session_generation.clone(),
                rollback_authority: Some(NewTabPreparedRollbackAuthority {
                    compensation,
                    session_id: started_session_id,
                    expected_generation: started_session_generation,
                    tab_id,
                    window_id: request.window_id.to_string(),
                    attachment_handoff: Some(attachment_handoff),
                }),
                error,
            },
        );
    }

    let strip_tabs = exact_projection.strip_tabs().to_vec();
    let selection = exact_projection.selection().to_vec();
    Ok(NewTabForegroundSuccess {
        tab_id: exact_projection.target().tab_id.clone(),
        session_id: exact_projection.target().session_id.clone(),
        strip_tabs,
        selection,
        pending_handoff: NewTabForegroundPendingHandoff {
            handoff: renderer_handoff,
            expected_generation: started_session_generation.clone(),
            rollback_authority: Some(NewTabPreparedRollbackAuthority {
                compensation,
                session_id: started_session_id,
                expected_generation: started_session_generation,
                tab_id,
                window_id: request.window_id.to_string(),
                // Renderer owns cancellation after command delivery; a non-Claimed disposition
                // has already settled it and returns any retry authority explicitly.
                attachment_handoff: None,
            }),
        },
    })
}

/// The planned `session_id` of a [`NewTabPlan::Create`], used by the worktree foreground path to
/// drive `prepare_workspace_with_consent`. Returns `None` for `Decline`/`Abort`.
fn new_tab_plan_session_id(plan: &NewTabPlan) -> Option<&str> {
    match plan {
        NewTabPlan::Create { session_id, .. } => Some(session_id.as_str()),
        _ => None,
    }
}

/// How one preset slot will be reported once exact asynchronous preset restore is implemented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresetRestoreSlotKind {
    /// A fresh session was launched through the ordinary new-tab foreground pipeline.
    Launched,
    /// The slot's hinted session was live, so the tab was recorded against it WITHOUT relaunching.
    Reattached,
}

/// The outcome of restoring ONE preset slot: the freshly-minted tab id, the session backing it
/// (newly launched or reattached), and the parent tab id when the slot was placed as a split child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresetRestoreSlotOutcome {
    /// Preset-local slot index (mirrors [`maestro_shell::PresetRestoreSlot::index`]).
    pub index: u32,
    /// The fresh tab id minted for this slot. Never reuses the capture-time id.
    pub tab_id: String,
    /// The session id now backing this slot.
    pub session_id: String,
    /// How the slot was backed (launch vs. reattach).
    pub kind: PresetRestoreSlotKind,
    /// When this slot was recorded as a split CHILD, the freshly-minted tab id of its parent slot;
    /// `None` for a top-level tab (including a split whose source could not be resolved, which is
    /// recorded unsplit as the safe fallback).
    pub split_parent_tab_id: Option<String>,
}

/// Why preset restore cannot begin. The current availability gate refuses every non-empty plan
/// before id minting, layout creation, renderer publication, or daemon work.
#[derive(Debug)]
pub enum PresetRestoreError {
    /// Another renderer handoff is unresolved. Refuse the whole preset before any id mint,
    /// session start, or layout mutation.
    RendererHandoffPending,
    /// Multi-slot restore has no asynchronous per-slot disposition state machine yet. Refuse every
    /// LaunchFresh plan before id minting, daemon startup, or durable layout mutation.
    LaunchFreshRequiresAsyncHandoff { index: u32 },
    /// Reattach currently carries only a textual session id. Refuse before id mint/layout mutation
    /// until an exact generation + renderer publication receipt can join the topology transaction.
    ReattachRequiresExactViewport { index: u32 },
    /// A LaunchFresh slot's new-tab foreground pipeline failed (carrying the slot index).
    Launch {
        index: u32,
        error: NewTabForegroundError,
    },
    /// A Reattach slot's window-layout record/mutation failed (carrying the slot index).
    Reattach {
        index: u32,
        error: maestro_shell::WindowLayoutError,
    },
    /// Minting a unique tab id for a slot exhausted the bound (only reachable with a deterministic
    /// test id generator; a real UUID source never collides).
    TabIdMintExhausted { index: u32 },
}

impl std::fmt::Display for PresetRestoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PresetRestoreError::RendererHandoffPending => {
                write!(
                    f,
                    "renderer handoff is still pending; preset restore refused"
                )
            }
            PresetRestoreError::LaunchFreshRequiresAsyncHandoff { index } => write!(
                f,
                "restore slot {index} requires asynchronous renderer handoff settlement"
            ),
            PresetRestoreError::ReattachRequiresExactViewport { index } => write!(
                f,
                "restore slot {index} requires exact Session/renderer viewport authority"
            ),
            PresetRestoreError::Launch { index, error } => {
                write!(f, "restore slot {index} launch failed: {error}")
            }
            PresetRestoreError::Reattach { index, error } => {
                write!(f, "restore slot {index} reattach failed: {error}")
            }
            PresetRestoreError::TabIdMintExhausted { index } => {
                write!(f, "restore slot {index} could not mint a unique tab id")
            }
        }
    }
}

impl std::error::Error for PresetRestoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PresetRestoreError::RendererHandoffPending => None,
            PresetRestoreError::LaunchFreshRequiresAsyncHandoff { .. } => None,
            PresetRestoreError::ReattachRequiresExactViewport { .. } => None,
            PresetRestoreError::Launch { error, .. } => Some(error),
            PresetRestoreError::Reattach { error, .. } => Some(error),
            PresetRestoreError::TabIdMintExhausted { .. } => None,
        }
    }
}

/// Immutable inputs for [`execute_preset_restore`].
pub struct PresetRestoreRequest<'a> {
    pub paths: &'a maestro_shell::AppPaths,
    pub socket_path: std::path::PathBuf,
    /// The window the preset is restored INTO. Its layout record must already exist (the caller
    /// `load_or_create`s it); restored tabs are appended in slot order.
    pub window_id: &'a str,
    /// The ordered restore plan from [`maestro_shell::plan_preset_restore`].
    pub plan: &'a [maestro_shell::PresetRestoreSlot],
    /// The preset's slots, used ONLY to resolve `split_from` by `source_tab_id`. Parallel to `plan`
    /// (same order, same length); each carries the capture-time `source_tab_id` the plan omits.
    pub source_tabs: &'a [maestro_shell::records::LayoutPresetTab],
    /// The launch policy applied to every LaunchFresh slot. Reattach slots ignore it.
    pub policy: &'a NewTabLaunchPolicy,
    pub argv: &'a [String],
    pub cols: u16,
    pub rows: u16,
    pub now_ms: u64,
}

/// Pure, effect-free availability preflight shared by every preset-restore entry point.
///
/// Empty plans are legal no-ops. Every non-empty plan is refused at its first slot until the exact
/// topology coordinator can atomically combine layout placement with a correlated renderer proof.
/// Keeping the renderer-pending bit explicit lets callers run this check before creating a target
/// window, preparing logs, resolving/spawning a daemon, or minting an id.
pub fn preflight_preset_restore(
    plan: &[maestro_shell::PresetRestoreSlot],
    renderer_handoff_pending: bool,
) -> Result<(), PresetRestoreError> {
    let Some(slot) = plan.first() else {
        return Ok(());
    };
    if renderer_handoff_pending {
        return Err(PresetRestoreError::RendererHandoffPending);
    }
    match &slot.action {
        maestro_shell::PresetRestoreAction::LaunchFresh => {
            Err(PresetRestoreError::LaunchFreshRequiresAsyncHandoff { index: slot.index })
        }
        maestro_shell::PresetRestoreAction::Reattach { .. } => {
            Err(PresetRestoreError::ReattachRequiresExactViewport { index: slot.index })
        }
    }
}

/// Recheck the pure availability gate at the executor boundary. Callers must invoke
/// [`preflight_preset_restore`] immediately after deriving the plan and before any side effect; this
/// second check prevents a direct caller from bypassing the invariant.
pub fn execute_preset_restore(
    request: PresetRestoreRequest<'_>,
    _env: &impl maestro_shell::EnvLookup,
    _id_gen: &mut dyn IdGen,
    runtime: &mut RendererTabRuntime,
) -> Result<Vec<PresetRestoreSlotOutcome>, PresetRestoreError> {
    preflight_preset_restore(request.plan, runtime.handoff_is_pending())?;
    debug_assert!(request.plan.is_empty());
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    /// A deterministic `IdGen` that hands out ids from fixed queues, recording how many times each
    /// mint method was called so tests can assert decline never touches the generator.
    struct ScriptedIdGen {
        tab_ids: std::collections::VecDeque<String>,
        session_ids: std::collections::VecDeque<String>,
        tab_calls: u32,
        session_calls: u32,
    }

    impl ScriptedIdGen {
        fn new(tab_ids: &[&str], session_ids: &[&str]) -> Self {
            Self {
                tab_ids: tab_ids.iter().map(|s| s.to_string()).collect(),
                session_ids: session_ids.iter().map(|s| s.to_string()).collect(),
                tab_calls: 0,
                session_calls: 0,
            }
        }
    }

    impl IdGen for ScriptedIdGen {
        fn next_tab_id(&mut self) -> String {
            self.tab_calls += 1;
            self.tab_ids
                .pop_front()
                .unwrap_or_else(|| panic!("ScriptedIdGen ran out of tab ids"))
        }
        fn next_session_id(&mut self) -> String {
            self.session_calls += 1;
            self.session_ids
                .pop_front()
                .unwrap_or_else(|| panic!("ScriptedIdGen ran out of session ids"))
        }
    }

    fn scratch_policy() -> NewTabLaunchPolicy {
        NewTabLaunchPolicy {
            source: NewTabLaunchSource::DefaultShellDev,
            workspace: maestro_shell::WorkspacePolicy::ScratchCwd,
            workspace_id: s("maestro-app-dev"),
            cwd_basis: NewTabCwdBasis::InheritCurrent,
            title: s("shell"),
        }
    }

    /// Seed the project → workspace FK parents that a started session's `SessionRecord` needs.
    ///
    /// The scratch new-tab pipeline prepares (but never persists) its workspace, then starts a
    /// session whose `SessionRecord.workspace_id` references it. Under the SQLite store's
    /// `foreign_keys=ON`, that session INSERT fails unless the workspace (and its project) already
    /// exist. Tests that drive a real session start must seed the parent chain first; the pipeline's
    /// own behaviour is unchanged.
    ///
    /// Mirrors the proven `seed_workspace` pattern from `maestro-shell`.
    fn seed_scratch_workspace_parents(paths: &maestro_shell::AppPaths, workspace_id: &str) {
        let project_id = "maestro-app-dev-project";
        maestro_shell::project::ProjectService::new(paths)
            .create(
                project_id,
                project_id,
                "/r",
                maestro_shell::project::NewProject::default(),
                1,
            )
            .ok();
        let workspace = maestro_shell::records::Workspace {
            workspace_id: workspace_id.to_string(),
            project_id: project_id.to_string(),
            root: "/tmp".into(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: Default::default(),
        };
        maestro_shell::store::write_record(
            paths,
            maestro_shell::RecordKind::Workspace,
            workspace_id,
            1,
            &workspace,
        )
        .ok();
    }

    /// Seed the FK parents for the scratch workspace id that `scratch_policy()` (and thus every
    /// `create_plan*` / `prepared_start_for` / `started_session_for` helper) uses.
    fn seed_default_scratch_workspace_parents(paths: &maestro_shell::AppPaths) {
        seed_scratch_workspace_parents(paths, "maestro-app-dev");
    }

    fn seed_exact_test_session(
        paths: &maestro_shell::AppPaths,
        session_id: &str,
        generation: &str,
    ) {
        seed_default_scratch_workspace_parents(paths);
        maestro_shell::store::write_record(
            paths,
            maestro_shell::RecordKind::Session,
            session_id,
            1,
            &maestro_shell::SessionRecord {
                session_id: session_id.into(),
                workspace_id: "maestro-app-dev".into(),
                kind: maestro_shell::SessionKind::Shell,
                launch: maestro_shell::LaunchSpec::OptOut,
                cwd_resolved: "/tmp".into(),
                agent_task_id: None,
                created_at_ms: 1,
                last_attached_at_ms: 1,
                last_known_generation: Some(generation.into()),
                status: maestro_shell::SessionStatus::Live,
            },
        )
        .expect("seed exact test Session");
    }

    fn snapshot_with(tab_ids: &[&str], session_ids: &[&str]) -> NewTabSnapshot {
        NewTabSnapshot {
            existing_tab_ids: tab_ids.iter().map(|s| s.to_string()).collect(),
            existing_session_ids: session_ids.iter().map(|s| s.to_string()).collect(),
            active_tab_id: None,
        }
    }

    #[test]
    fn new_tab_no_policy_declines_without_touching_id_gen() {
        let mut id_gen = ScriptedIdGen::new(&[], &[]);
        let snapshot = snapshot_with(&[], &[]);
        let plan = plan_new_tab(None, &snapshot, &mut id_gen);
        assert_eq!(plan, NewTabPlan::Decline);
        assert_eq!(id_gen.tab_calls, 0, "decline must not mint a tab id");
        assert_eq!(
            id_gen.session_calls, 0,
            "decline must not mint a session id"
        );
    }

    #[test]
    fn new_tab_valid_policy_creates() {
        let mut id_gen = ScriptedIdGen::new(&["tab-1"], &["sess-1"]);
        let snapshot = snapshot_with(&[], &[]);
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        match plan {
            NewTabPlan::Create {
                tab_id,
                session_id,
                source,
                workspace,
                workspace_id,
                cwd_basis,
                title,
            } => {
                assert_eq!(tab_id, "tab-1");
                assert_eq!(session_id, "sess-1");
                assert_eq!(source, NewTabLaunchSource::DefaultShellDev);
                assert_eq!(workspace, maestro_shell::WorkspacePolicy::ScratchCwd);
                assert_eq!(workspace_id, "maestro-app-dev");
                assert_eq!(cwd_basis, NewTabCwdBasis::InheritCurrent);
                assert_eq!(title, "shell");
            }
            other => panic!("expected Create, got {other:?}"),
        }
    }

    #[test]
    fn new_tab_create_carries_policy_workspace_id() {
        // The planner must thread the POLICY's own workspace id into Create, not a hardcoded
        // constant. Use a distinctive id so a constant default could not accidentally pass.
        let mut id_gen = ScriptedIdGen::new(&["tab-1"], &["sess-1"]);
        let snapshot = snapshot_with(&[], &[]);
        let mut policy = scratch_policy();
        policy.workspace_id = s("ws-custom-42");
        let plan = plan_new_tab(Some(&policy), &snapshot, &mut id_gen);
        if let NewTabPlan::Create { workspace_id, .. } = plan {
            assert_eq!(workspace_id, "ws-custom-42");
        } else {
            panic!("expected Create");
        }
    }

    #[test]
    fn new_tab_created_ids_are_independent() {
        let mut id_gen = ScriptedIdGen::new(&["tab-1"], &["sess-1"]);
        let snapshot = snapshot_with(&[], &[]);
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        if let NewTabPlan::Create {
            tab_id, session_id, ..
        } = plan
        {
            assert_ne!(tab_id, session_id, "tab_id and session_id must be distinct");
        } else {
            panic!("expected Create");
        }
    }

    #[test]
    fn new_tab_created_ids_are_unique_against_snapshot() {
        let mut id_gen = ScriptedIdGen::new(&["tab-new"], &["sess-new"]);
        let snapshot = snapshot_with(&["tab-old"], &["sess-old"]);
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        if let NewTabPlan::Create {
            tab_id, session_id, ..
        } = plan
        {
            assert!(!snapshot.existing_tab_ids.contains(&tab_id));
            assert!(!snapshot.existing_session_ids.contains(&session_id));
        } else {
            panic!("expected Create");
        }
    }

    /// A `Create` plan with the given ids/source under the `scratch_policy` defaults, minted
    /// deterministically through the planner so the test exercises the real `Create` shape.
    fn create_plan(tab_id: &str, session_id: &str, source: NewTabLaunchSource) -> NewTabPlan {
        let mut id_gen = ScriptedIdGen::new(&[tab_id], &[session_id]);
        let snapshot = snapshot_with(&[], &[]);
        let mut policy = scratch_policy();
        policy.source = source;
        let plan = plan_new_tab(Some(&policy), &snapshot, &mut id_gen);
        assert!(matches!(plan, NewTabPlan::Create { .. }), "expected Create");
        plan
    }

    /// Unwrap the `Err` of a `new_tab_prepared_start_params` result without requiring `T: Debug`
    /// (the `Ok` variant holds `StartParams`, which has no `Debug`, so `Result::unwrap_err` is
    /// unavailable).
    fn start_params_err(
        result: Result<NewTabPreparedStart, NewTabStartParamsError>,
    ) -> NewTabStartParamsError {
        match result {
            Ok(_) => panic!("expected an error, got start params"),
            Err(e) => e,
        }
    }

    /// A prepared workspace matching the `scratch_policy` defaults for the given ids.
    fn prepared_for(session_id: &str) -> maestro_shell::PreparedWorkspace {
        maestro_shell::PreparedWorkspace::unsealed(
            maestro_shell::WorkspacePolicy::ScratchCwd,
            "maestro-app-dev",
            session_id,
            "/tmp/maestro-scratch/sess",
        )
    }

    #[test]
    fn selected_provider_carrier_seals_without_repeating_path_lookup() {
        use std::os::unix::fs::PermissionsExt;
        struct OwnedEnv(PathBuf);
        impl maestro_shell::LaunchEnvLookup for OwnedEnv {
            fn shell_utf8(&self) -> Option<String> {
                Some(self.0.join("shell").to_str().unwrap().into())
            }
            fn home_os(&self) -> Option<std::ffi::OsString> {
                Some(self.0.as_os_str().to_owned())
            }
            fn path_os(&self) -> Option<std::ffi::OsString> {
                Some("/usr/bin:/bin".into())
            }
        }
        let root = tempfile::tempdir().unwrap();
        let env = OwnedEnv(root.path().to_owned());
        let executable = root.path().join(".local/bin/claude");
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        for (path, text) in [
            (&executable, "#!/bin/sh\nexit 0\n"),
            (
                &root.path().join("shell"),
                "#!/bin/sh\nexec /bin/sh -c \"$2\"\n",
            ),
        ] {
            std::fs::write(path, text).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let Some(maestro_shell::ProviderResolution::Executable(selected)) =
            maestro_shell::resolve_provider_executable("claude", root.path(), &env).unwrap()
        else {
            panic!("owned selection")
        };
        let prepared = maestro_shell::PreparedWorkspace::unsealed(
            maestro_shell::WorkspacePolicy::ScratchCwd,
            "owned-workspace",
            "owned-session",
            root.path(),
        );
        for params in [
            vec![],
            vec!["--resume".to_owned(), "owned-conversation".to_owned()],
        ] {
            let mut source = vec!["claude".to_owned()];
            source.extend(params);
            let launch = NewTabForegroundLaunch::provider("claude".into(), source, "claude".into())
                .unwrap()
                .with_provider_executable(Some(selected.clone()));
            assert!(launch
                .into_session_spec_with_reprobe(&prepared, 80, 24, 1, |_, _, _| panic!(
                    "must not rediscover a selected executable"
                ))
                .is_ok());
        }
        std::fs::remove_file(executable).unwrap();
        let launch = NewTabForegroundLaunch::provider(
            "claude".into(),
            vec!["claude".into()],
            "claude".into(),
        )
        .unwrap()
        .with_provider_executable(Some(selected));
        assert!(matches!(
            launch.into_session_spec_with_reprobe(&prepared, 80, 24, 1, |_, _, _| panic!(
                "missing selected executable must not fall back"
            )),
            Err(NewTabStartParamsError::PreparedLaunch)
        ));
    }

    #[test]
    fn new_tab_prepared_start_params_success_populates_start_params() {
        let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
        let prepared = prepared_for("sess-1");
        let argv = vec![s("/bin/zsh"), s("-l")];
        let out = new_tab_prepared_start_params(&plan, &prepared, &argv, 120, 40, 1_700_000_000)
            .expect("matching create + prepared must produce start params");
        assert_eq!(out.tab_id, "tab-1");
        assert_eq!(out.title, "shell");
        assert_eq!(out.params.session_id, "sess-1");
        assert_eq!(out.params.workspace_id, "maestro-app-dev");
        assert_eq!(out.params.kind, maestro_shell::SessionKind::Shell);
        assert_eq!(out.params.cwd, "/tmp/maestro-scratch/sess");
        assert_eq!(out.params.command, "/bin/zsh");
        assert_eq!(out.params.args, vec![s("-l")]);
        assert_eq!(out.params.cols, 120);
        assert_eq!(out.params.rows, 40);
        assert_eq!(out.params.now_ms, 1_700_000_000);
        assert_eq!(out.params.agent_task_id, None);
    }

    #[test]
    fn new_tab_prepared_start_params_decline_is_not_create() {
        let prepared = prepared_for("sess-1");
        let err = start_params_err(new_tab_prepared_start_params(
            &NewTabPlan::Decline,
            &prepared,
            &[s("/bin/sh")],
            80,
            24,
            0,
        ));
        assert_eq!(err, NewTabStartParamsError::NotCreate);
    }

    #[test]
    fn new_tab_prepared_start_params_abort_is_not_create() {
        let prepared = prepared_for("sess-1");
        let plan = NewTabPlan::Abort {
            reason: NewTabAbortReason::TabIdMintExhausted,
        };
        let err = start_params_err(new_tab_prepared_start_params(
            &plan,
            &prepared,
            &[s("/bin/sh")],
            80,
            24,
            0,
        ));
        assert_eq!(err, NewTabStartParamsError::NotCreate);
    }

    #[test]
    fn new_tab_prepared_start_params_known_safe_spec_unsupported() {
        let source = NewTabLaunchSource::KnownSafeSpec {
            launch_spec_id: s("spec-7"),
        };
        let plan = create_plan("tab-1", "sess-1", source.clone());
        let prepared = prepared_for("sess-1");
        let err = start_params_err(new_tab_prepared_start_params(
            &plan,
            &prepared,
            &[s("/bin/sh")],
            80,
            24,
            0,
        ));
        assert_eq!(
            err,
            NewTabStartParamsError::UnsupportedLaunchSource { source }
        );
    }

    #[test]
    fn new_tab_prepared_start_params_policy_mismatch() {
        let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
        let mut prepared = prepared_for("sess-1");
        prepared.policy = maestro_shell::WorkspacePolicy::Worktree;
        let err = start_params_err(new_tab_prepared_start_params(
            &plan,
            &prepared,
            &[s("/bin/sh")],
            80,
            24,
            0,
        ));
        assert_eq!(
            err,
            NewTabStartParamsError::PreparedWorkspacePolicyMismatch {
                expected: maestro_shell::WorkspacePolicy::ScratchCwd,
                actual: maestro_shell::WorkspacePolicy::Worktree,
            }
        );
    }

    #[test]
    fn new_tab_prepared_start_params_workspace_id_mismatch() {
        let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
        let mut prepared = prepared_for("sess-1");
        prepared.workspace_id = s("other-ws");
        let err = start_params_err(new_tab_prepared_start_params(
            &plan,
            &prepared,
            &[s("/bin/sh")],
            80,
            24,
            0,
        ));
        assert_eq!(
            err,
            NewTabStartParamsError::PreparedWorkspaceWorkspaceIdMismatch {
                expected: s("maestro-app-dev"),
                actual: s("other-ws"),
            }
        );
    }

    #[test]
    fn new_tab_prepared_start_params_session_id_mismatch() {
        let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
        let prepared = prepared_for("sess-different");
        let err = start_params_err(new_tab_prepared_start_params(
            &plan,
            &prepared,
            &[s("/bin/sh")],
            80,
            24,
            0,
        ));
        assert_eq!(
            err,
            NewTabStartParamsError::PreparedWorkspaceSessionIdMismatch {
                expected: s("sess-1"),
                actual: s("sess-different"),
            }
        );
    }

    /// A `Create` plan with the given ids minted through the real planner, but with the launch
    /// policy's `workspace` isolation policy overridden — so tests can exercise non-`ScratchCwd`
    /// rejection without hand-constructing the `Create`.
    fn create_plan_with_workspace(
        tab_id: &str,
        session_id: &str,
        workspace: maestro_shell::WorkspacePolicy,
    ) -> NewTabPlan {
        let mut id_gen = ScriptedIdGen::new(&[tab_id], &[session_id]);
        let snapshot = snapshot_with(&[], &[]);
        let mut policy = scratch_policy();
        policy.workspace = workspace;
        let plan = plan_new_tab(Some(&policy), &snapshot, &mut id_gen);
        assert!(matches!(plan, NewTabPlan::Create { .. }), "expected Create");
        plan
    }

    /// Map a prepare error to a stable tag for assertions without leaning on `PartialEq` (the inner
    /// `WorkspaceExecError` does not implement it).
    fn prepare_err_tag(err: &NewTabWorkspacePrepareError) -> &'static str {
        match err {
            NewTabWorkspacePrepareError::RendererHandoffPending => "renderer_handoff_pending",
            NewTabWorkspacePrepareError::NotCreate => "not_create",
            NewTabWorkspacePrepareError::UnsupportedWorkspacePolicy { .. } => "unsupported_policy",
            NewTabWorkspacePrepareError::WorkspaceExec(_) => "workspace_exec",
        }
    }

    #[test]
    fn prepare_new_tab_scratch_workspace_creates_cwd_and_preserves_identity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        // Real planner output: ScratchCwd policy, workspace id "maestro-app-dev", session id "sess-1".
        let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
        let prepared = prepare_new_tab_scratch_workspace(&paths, &plan, "")
            .expect("ScratchCwd create must prepare a workspace");

        assert_eq!(prepared.policy, maestro_shell::WorkspacePolicy::ScratchCwd);
        assert_eq!(prepared.workspace_id, "maestro-app-dev");
        assert_eq!(prepared.session_id, "sess-1");
        assert!(
            prepared.cwd.starts_with(paths.scratch_base()),
            "prepared cwd {:?} must be under the scratch base {:?}",
            prepared.cwd,
            paths.scratch_base()
        );
        assert!(
            prepared.cwd.is_dir(),
            "the scratch cwd must exist after prepare"
        );
    }

    #[test]
    fn prepare_new_tab_scratch_workspace_round_trips_into_start_params() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
        let prepared = prepare_new_tab_scratch_workspace(&paths, &plan, "")
            .expect("ScratchCwd create must prepare a workspace");

        // The preparer's output feeds the prepared-start adapter and passes its
        // policy/workspace-id/session-id agreement guards.
        let argv = vec![s("/bin/zsh"), s("-l")];
        let out = new_tab_prepared_start_params(&plan, &prepared, &argv, 100, 30, 42)
            .expect("preparer output must satisfy the prepared-start adapter guards");
        assert_eq!(
            out.params.cwd,
            prepared.cwd.to_string_lossy(),
            "start params cwd must equal the prepared scratch cwd"
        );
        assert_eq!(out.params.session_id, "sess-1");
        assert_eq!(out.params.workspace_id, "maestro-app-dev");
    }

    #[test]
    fn prepare_new_tab_scratch_workspace_decline_is_not_create_and_creates_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let err = prepare_new_tab_scratch_workspace(&paths, &NewTabPlan::Decline, "")
            .expect_err("Decline has no workspace to prepare");
        assert_eq!(prepare_err_tag(&err), "not_create");
        assert!(
            !paths.scratch_base().exists(),
            "Decline must not create the scratch base"
        );
    }

    #[test]
    fn prepare_new_tab_scratch_workspace_abort_is_not_create_and_creates_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let plan = NewTabPlan::Abort {
            reason: NewTabAbortReason::TabIdMintExhausted,
        };
        let err = prepare_new_tab_scratch_workspace(&paths, &plan, "")
            .expect_err("Abort has no workspace to prepare");
        assert_eq!(prepare_err_tag(&err), "not_create");
        assert!(
            !paths.scratch_base().exists(),
            "Abort must not create the scratch base"
        );
    }

    #[test]
    fn prepare_new_tab_scratch_workspace_worktree_unsupported_before_any_effect() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let plan =
            create_plan_with_workspace("tab-1", "sess-1", maestro_shell::WorkspacePolicy::Worktree);
        let err = prepare_new_tab_scratch_workspace(&paths, &plan, "")
            .expect_err("Worktree is not supported by the scratch preparer");
        assert_eq!(prepare_err_tag(&err), "unsupported_policy");
        assert!(
            !paths.scratch_base().exists(),
            "an unsupported policy must create nothing"
        );
    }

    #[test]
    fn prepare_new_tab_scratch_workspace_repo_write_unsupported_before_any_effect() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let plan = create_plan_with_workspace(
            "tab-1",
            "sess-1",
            maestro_shell::WorkspacePolicy::RepoWrite,
        );
        let err = prepare_new_tab_scratch_workspace(&paths, &plan, "")
            .expect_err("RepoWrite is not supported by the scratch preparer");
        assert_eq!(prepare_err_tag(&err), "unsupported_policy");
        assert!(
            !paths.scratch_base().exists(),
            "an unsupported policy must create nothing"
        );
    }

    #[test]
    fn prepare_new_tab_scratch_workspace_unsafe_id_propagates_shell_error_and_creates_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        // An unsafe session id (path traversal) must be rejected by maestro-shell's id validation,
        // surfacing as a WorkspaceExec error with no filesystem effect — we do NOT re-validate ids
        // in maestro-app.
        let mut id_gen = ScriptedIdGen::new(&["tab-1"], &["../escape"]);
        let snapshot = snapshot_with(&[], &[]);
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        assert!(matches!(plan, NewTabPlan::Create { .. }), "expected Create");
        let err = prepare_new_tab_scratch_workspace(&paths, &plan, "")
            .expect_err("an unsafe session id must be rejected by the shell preparer");
        assert_eq!(prepare_err_tag(&err), "workspace_exec");
        assert!(
            !paths.scratch_base().join("../escape").exists(),
            "an unsafe id must not create a scratch cwd"
        );
    }

    // ---- new-tab session start (start_new_tab_prepared_session) -----------------------------
    //
    // These tests exercise new-tab startup through the daemon/session runtime. A
    // loopback stub daemon (a `UnixListener` on a temp socket) stands in for a real `pty-daemon`:
    // no PTY, GUI, renderer, network, git, or child process. The whole planner -> preparer ->
    // prepared-start -> start chain is driven end to end so the helper's success path is the real
    // one a GUI caller takes.

    /// A minimal [`maestro_shell::EnvLookup`] backed by a map, so socket resolution is deterministic
    /// (no real process environment is read).
    struct MapEnv(std::collections::HashMap<String, String>);
    impl MapEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            MapEnv(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        }
    }
    impl maestro_shell::EnvLookup for MapEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    /// A loopback stub daemon on a caller-chosen socket path. The accept thread runs the supplied
    /// serve closure against the single accepted connection, then drops it. The caller owns the
    /// socket path and its temp dir.
    struct StubDaemon {
        handle: Option<std::thread::JoinHandle<()>>,
        socket_path: std::path::PathBuf,
        stopping: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl StubDaemon {
        fn spawn_at<F>(path: std::path::PathBuf, serve: F) -> StubDaemon
        where
            F: FnOnce(&mut std::os::unix::net::UnixStream) + Send + 'static,
        {
            let listener = std::os::unix::net::UnixListener::bind(&path).expect("bind stub socket");
            let stopping = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let worker_stopping = std::sync::Arc::clone(&stopping);
            let handle = std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    if worker_stopping.load(std::sync::atomic::Ordering::Acquire) {
                        return;
                    }
                    serve(&mut stream);
                    drop(stream);
                }
            });
            StubDaemon {
                handle: Some(handle),
                socket_path: path,
                stopping,
            }
        }
    }

    impl Drop for StubDaemon {
        fn drop(&mut self) {
            if let Some(h) = self.handle.take() {
                self.stopping
                    .store(true, std::sync::atomic::Ordering::Release);
                let _ = std::os::unix::net::UnixStream::connect(&self.socket_path);
                let _ = h.join();
            }
        }
    }

    /// Read one newline-terminated request line; `None` at EOF.
    fn stub_read_line(reader: &mut impl std::io::BufRead) -> Option<String> {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read request line");
        if n == 0 {
            return None;
        }
        Some(line.trim().to_string())
    }

    /// A serve script that accepts the protocol-v3/capability mutation probe, then answers the StartSession +
    /// Attach handshake with a grid for `id` at `generation` (a successful start) — mirrors the
    /// shell-runtime test stub.
    fn serve_grid(
        id: String,
        generation: String,
    ) -> impl FnOnce(&mut std::os::unix::net::UnixStream) + Send + 'static {
        serve_grid_with_start_observer(id, generation, |_| {})
    }

    fn serve_grid_with_start_observer<F>(
        id: String,
        generation: String,
        observe_start: F,
    ) -> impl FnOnce(&mut std::os::unix::net::UnixStream) + Send + 'static
    where
        F: FnOnce(&maestro_protocol::ClientRequest) + Send + 'static,
    {
        move |stream| {
            use std::io::Write;
            let mut reader = std::io::BufReader::new(stream.try_clone().expect("clone stream"));
            assert_eq!(
                stub_read_line(&mut reader).as_deref(),
                Some(r#"{"op":"daemon_info"}"#)
            );
            writeln!(
                stream,
                "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"test\",\"daemon_instance_id\":\"22222222222242228222222222222222\",\"output_generation_echo\":true,\"child_environment\":true,\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":true,\"generation_conditional_start\":true,\"start_operation_ledger\":true,\"generation_conditional_attach\":true}}",
                maestro_protocol::DAEMON_PROTOCOL_VERSION
            )
            .expect("write daemon_info");
            stream.flush().expect("flush daemon_info");

            let reserve = stub_read_line(&mut reader).expect("ReserveStartOperation");
            let (reserved_id, reserved_token) =
                match serde_json::from_str::<maestro_protocol::ClientRequest>(&reserve)
                    .expect("decode ReserveStartOperation")
                {
                    maestro_protocol::ClientRequest::ReserveStartOperation {
                        id,
                        operation_token,
                    } => (id, operation_token),
                    other => panic!("expected ReserveStartOperation, got {other:?}"),
                };
            assert_eq!(reserved_id.0, id);
            writeln!(
                stream,
                "{{\"ev\":\"start_operation_reserved\",\"id\":\"{id}\",\"operation_token\":\"{}\",\"daemon_instance_id\":\"22222222222242228222222222222222\",\"outcome\":{{\"status\":\"reserved\"}}}}",
                reserved_token.as_str()
            )
            .expect("write start operation reservation acknowledgement");
            stream
                .flush()
                .expect("flush start operation reservation acknowledgement");

            let start = stub_read_line(&mut reader).expect("StartSession");
            let request = serde_json::from_str::<maestro_protocol::ClientRequest>(&start)
                .expect("decode StartSession");
            observe_start(&request);
            let operation_token = match request {
                maestro_protocol::ClientRequest::StartSession {
                    ref id,
                    conditional_start: Some(conditional),
                    ..
                } if id == &reserved_id && conditional.operation_token == reserved_token => {
                    conditional.operation_token
                }
                other => panic!("expected conditional StartSession, got {other:?}"),
            };
            writeln!(
                stream,
                "{{\"ev\":\"conditional_session_start\",\"id\":\"{id}\",\"operation_token\":\"{}\",\"daemon_instance_id\":\"22222222222242228222222222222222\",\"outcome\":{{\"status\":\"applied\",\"generation\":\"{generation}\"}}}}",
                operation_token.as_str()
            )
            .expect("write conditional start acknowledgement");
            stream
                .flush()
                .expect("flush conditional start acknowledgement");
            let attach = stub_read_line(&mut reader).expect("Attach offer");
            let output_generation =
                match serde_json::from_str::<maestro_protocol::ClientRequest>(&attach)
                    .expect("decode Attach")
                {
                    maestro_protocol::ClientRequest::Attach {
                        handoff: Some(maestro_protocol::AttachmentHandoff::Offer { .. }),
                        output_generation,
                        ..
                    } => output_generation,
                    other => panic!("expected Attach offer, got {other:?}"),
                };
            let grid = format!(
                r#"{{"ev":"grid","id":"{id}","output_generation":{},"grid":{{"generation":"{generation}","revision":1}}}}"#,
                output_generation
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "null".to_string())
            );
            stream
                .write_all(format!("{grid}\n").as_bytes())
                .expect("write grid");
            stream.flush().expect("flush grid");
            // The production daemon keeps the Offer connection alive. Give the client time to
            // restore its bounded socket options before this minimal one-shot stub closes; closing
            // immediately can make that required post-Offer check observe EINVAL on macOS.
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
    }

    fn expect_single_handoff_command(
        rx: &std::sync::mpsc::Receiver<maestro_renderer::RendererCommand>,
        expected_session_id: &str,
        expected_tab_count: usize,
    ) -> maestro_renderer::RendererTabStrip {
        let strip = match rx.try_recv().expect("one atomic renderer handoff") {
            maestro_renderer::RendererCommand::AttachSessionWithHandoff {
                session_id,
                handoff,
                tab_strip,
                ..
            } => {
                assert_eq!(session_id, expected_session_id);
                assert!(
                    format!("{handoff:?}").contains("redacted"),
                    "handoff Debug must remain opaque"
                );
                tab_strip
            }
            other => panic!("expected atomic AttachSessionWithHandoff, got {other:?}"),
        };
        assert_eq!(strip.tabs.len(), expected_tab_count);
        assert!(rx.try_recv().is_err(), "exactly one renderer command");
        strip
    }

    /// Build the `NewTabPreparedStart` for `session_id` by running the real planner -> preparer ->
    /// prepared-start chain against a temp app-support base, so the start params carry a prepared
    /// scratch cwd that actually exists (the daemon-side is_dir check would pass).
    fn prepared_start_for(
        paths: &maestro_shell::AppPaths,
        tab_id: &str,
        session_id: &str,
    ) -> NewTabPreparedStart {
        let plan = create_plan(tab_id, session_id, NewTabLaunchSource::DefaultShellDev);
        let prepared = prepare_new_tab_scratch_workspace(paths, &plan, "")
            .expect("ScratchCwd create must prepare a workspace");
        let argv = vec![s("/bin/zsh"), s("-l")];
        new_tab_prepared_start_params(&plan, &prepared, &argv, 80, 24, 1_700_000_000)
            .expect("preparer output must satisfy the prepared-start adapter guards")
    }

    /// Is there a persisted `WindowLayout` record anywhere under the app-support base? The helper must
    /// never write one — session start is not GUI wiring.
    fn any_window_layout_file_exists(paths: &maestro_shell::AppPaths) -> bool {
        let dir = paths.record_dir(maestro_shell::RecordKind::WindowLayout);
        match std::fs::read_dir(&dir) {
            Ok(entries) => entries.filter_map(|e| e.ok()).any(|_| true),
            Err(_) => false,
        }
    }

    #[test]
    fn start_new_tab_prepared_session_success_returns_identity_and_live_record() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        // The started session's SessionRecord references the scratch workspace; seed its FK parents.
        seed_default_scratch_workspace_parents(&paths);
        let prepared = prepared_start_for(&paths, "tab-1", "sess-1");

        let sock_dir = tempfile::tempdir().expect("sock dir");
        let sock_path = sock_dir.path().join("stub.sock");
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid(s("sess-1"), s("gen-1")));

        let env = MapEnv::new(&[]);
        let started =
            start_new_tab_prepared_session(&paths, Some(sock_path.clone()), &env, &prepared)
                .expect("a reachable stub daemon must start the session");

        // Planned identity is threaded through unchanged.
        assert_eq!(started.tab_id, "tab-1");
        assert_eq!(started.title, "shell");
        // The socket actually used + a Live record for the planned session.
        assert_eq!(started.outcome.socket_path, sock_path);
        let record = &started.outcome.record;
        assert_eq!(record.session_id, "sess-1");
        assert_eq!(record.status, maestro_shell::SessionStatus::Live);
        // The record's identity/cwd match the start params / grid proof.
        assert_eq!(record.workspace_id, prepared.params.workspace_id);
        assert_eq!(record.kind, prepared.params.kind);
        assert_eq!(record.cwd_resolved, prepared.params.cwd);
        assert_eq!(record.last_known_generation.as_deref(), Some("gen-1"));
        // No app-owned window layout was written.
        assert!(
            !any_window_layout_file_exists(&paths),
            "session start must not create a window layout"
        );
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn start_new_tab_prepared_session_connect_failure_is_typed_shell_error_no_layout() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let prepared = prepared_start_for(&paths, "tab-1", "sess-1");

        // An explicit socket path with no daemon listening: connect must fail before any session or
        // endpoint record is written.
        let missing = tmp.path().join("nope.sock");
        let env = MapEnv::new(&[]);
        let err = start_new_tab_prepared_session(&paths, Some(missing), &env, &prepared)
            .expect_err("an unreachable daemon must fail the start");

        match err {
            NewTabSessionStartError::Shell(maestro_shell::ShellRuntimeError::Daemon(_)) => {}
            other => panic!("expected a Shell(Daemon) error, got {other:?}"),
        }
        // No session record was persisted, and no window layout was created.
        assert!(
            maestro_shell::store::load_one::<maestro_shell::SessionRecord>(
                &paths,
                maestro_shell::RecordKind::Session,
                "sess-1",
            )
            .expect("load session record")
            .is_none(),
            "a connect failure must not persist a session record"
        );
        assert!(
            !any_window_layout_file_exists(&paths),
            "a failed start must not create a window layout"
        );
    }

    /// Run the real planner -> preparer -> prepared-start -> session-start chain against a stub
    /// daemon to obtain a genuine `NewTabSessionStart` (its `outcome.record.session_id`, `tab_id`,
    /// and `title` are what `record_new_tab_in_window_layout` reads). The stub + its socket are kept
    /// alive only for the duration of the start, then dropped.
    fn started_session_for(
        paths: &maestro_shell::AppPaths,
        tab_id: &str,
        session_id: &str,
    ) -> NewTabSessionStart {
        // The started session's SessionRecord references the scratch workspace; seed its FK parents.
        seed_default_scratch_workspace_parents(paths);
        let prepared = prepared_start_for(paths, tab_id, session_id);
        let sock_dir = tempfile::tempdir().expect("sock dir");
        let sock_path = sock_dir.path().join("stub.sock");
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid(s(session_id), s("gen-1")));
        let env = MapEnv::new(&[]);
        let started = start_new_tab_prepared_session(paths, Some(sock_path), &env, &prepared)
            .expect("a reachable stub daemon must start the session");
        drop(stub);
        drop(sock_dir);
        started
    }

    #[test]
    fn record_new_tab_appends_started_session_to_existing_layout() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());

        // An existing window with one prior tab. The helper must require this layout, not create it.
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create window");
        service
            .open_tab(
                "w1",
                "t0",
                "sess-t0",
                "shell",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed prior tab");

        let started = started_session_for(&paths, "tab-1", "sess-1");
        let recorded = record_new_tab_in_window_layout(&paths, "w1", &started, None, 1_700_000_000)
            .expect("recording into an existing layout must succeed");

        // The returned identity is the started session's, threaded through unchanged.
        assert_eq!(recorded.tab_id, "tab-1");
        assert_eq!(recorded.session_id, "sess-1");

        // The new tab is appended AFTER the existing one, with contiguous indices, the started
        // session's title, pinned=false, and a no-attention state.
        let tabs = &recorded.layout.tabs;
        assert_eq!(tabs.len(), 2, "existing tab is preserved");
        assert_eq!(tabs[0].tab_id, "t0");
        assert_eq!(tabs[0].index, 0);
        let new_tab = &tabs[1];
        assert_eq!(new_tab.tab_id, "tab-1");
        assert_eq!(new_tab.session_id, "sess-1");
        assert_eq!(new_tab.index, 1);
        // The prior tab "t0" is titled "shell"; the new tab's title collides, so pane-name uniqueness auto-numbers it.
        let expected_title = if started.title == "shell" {
            "shell 2".to_string()
        } else {
            started.title.clone()
        };
        assert_eq!(new_tab.title, expected_title);
        assert!(!new_tab.pinned);
        assert_eq!(
            new_tab.attention.attention,
            maestro_shell::Attention::None,
            "a freshly recorded tab carries no attention"
        );

        // The mutation was persisted: reloading the layout shows both tabs.
        let reloaded = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load layout")
            .expect("layout exists");
        assert_eq!(reloaded.tabs.len(), 2);
        assert_eq!(reloaded.tabs[1].tab_id, "tab-1");
    }

    #[test]
    fn record_new_tab_with_split_from_records_a_split_tab_from_the_active_tab() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());

        // An existing window with one prior tab to split FROM.
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create window");
        service
            .open_tab(
                "w1",
                "t0",
                "sess-t0",
                "shell",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed prior tab");

        let started = started_session_for(&paths, "tab-1", "sess-1");
        let split = NewTabSplitFrom {
            from_tab_id: "t0".to_string(),
            axis: maestro_shell::SplitAxis::Down,
        };
        let recorded =
            record_new_tab_in_window_layout(&paths, "w1", &started, Some(&split), 1_700_000_000)
                .expect("recording a split into an existing layout must succeed");

        // Identity is the started session's, threaded through unchanged.
        assert_eq!(recorded.tab_id, "tab-1");
        assert_eq!(recorded.session_id, "sess-1");

        // The new tab is recorded with split provenance pointing at the active tab + axis, NOT as a
        // plain top-level open_tab.
        let new_tab = recorded
            .layout
            .tabs
            .iter()
            .find(|t| t.tab_id == "tab-1")
            .expect("the split tab is present");
        let split_from = new_tab
            .split_from
            .as_ref()
            .expect("a split-recorded tab carries split provenance");
        assert_eq!(split_from.tab_id, "t0");
        assert_eq!(split_from.axis, maestro_shell::SplitAxis::Down);

        // The mutation persists: reloading shows the split provenance.
        let reloaded = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load layout")
            .expect("layout exists")
            .tabs
            .into_iter()
            .find(|t| t.tab_id == "tab-1")
            .expect("split tab persisted");
        let reloaded_split = reloaded
            .split_from
            .expect("persisted split provenance survives reload");
        assert_eq!(reloaded_split.tab_id, "t0");
        assert_eq!(reloaded_split.axis, maestro_shell::SplitAxis::Down);
    }

    #[test]
    fn record_new_tab_splits_from_the_focused_source_tab_not_the_active_one() {
        // Models the nested right-then-down case: the down split must branch from the FOCUSED right
        // pane (`t-right`) even though another tab (`t-root`) is the active one. The split source is
        // whatever `from_tab_id` the renderer resolved from pane focus — not the active tab.
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());

        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create window");
        service
            .open_tab(
                "w1",
                "t-root",
                "sess-root",
                "root",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed root tab");
        // The right pane already exists as a Right split child of root; it is the FOCUSED pane.
        service
            .split_tab(
                "w1",
                "t-root",
                "t-right",
                "sess-right",
                "right",
                maestro_shell::SplitAxis::Right,
                1,
            )
            .expect("seed right split child");

        let started = started_session_for(&paths, "t-bottom", "sess-bottom");
        let split = NewTabSplitFrom {
            from_tab_id: "t-right".to_string(),
            axis: maestro_shell::SplitAxis::Down,
        };
        let recorded =
            record_new_tab_in_window_layout(&paths, "w1", &started, Some(&split), 1_700_000_000)
                .expect("recording a nested split must succeed");

        // The new down pane branches from the focused right pane, producing a 3-tab chain, NOT a
        // sibling of root (which would have built a 2x2 off the active tab).
        let new_tab = recorded
            .layout
            .tabs
            .iter()
            .find(|t| t.tab_id == "t-bottom")
            .expect("the nested split tab is present");
        let split_from = new_tab
            .split_from
            .as_ref()
            .expect("a split-recorded tab carries split provenance");
        assert_eq!(split_from.tab_id, "t-right");
        assert_eq!(split_from.axis, maestro_shell::SplitAxis::Down);
    }

    #[test]
    fn closing_a_focused_split_leaf_removes_only_that_record_and_keeps_the_root() {
        // Seed a root tab plus one split-child leaf off it. Closing the leaf via the same
        // `WindowLayoutService::close_tab` the close-focused-pane handler uses must remove ONLY the
        // leaf's record and leave the root tab/header in place.
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_exact_test_session(&paths, "sess-root", "gen-root");
        seed_exact_test_session(&paths, "sess-leaf", "gen-leaf");

        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create window");
        service
            .open_tab(
                "w1",
                "t-root",
                "sess-root",
                "root",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed root tab");
        service
            .split_tab(
                "w1",
                "t-root",
                "t-leaf",
                "sess-leaf",
                "leaf",
                maestro_shell::SplitAxis::Right,
                1,
            )
            .expect("seed split-child leaf");

        let updated = service
            .close_tab("w1", "t-leaf", 1_700_000_000)
            .expect("closing the leaf record succeeds");

        // Only the leaf record is gone; the root header survives.
        assert!(
            updated.tabs.iter().any(|t| t.tab_id == "t-root"),
            "the root tab/header must remain visible after closing a split child"
        );
        assert!(
            !updated.tabs.iter().any(|t| t.tab_id == "t-leaf"),
            "the closed leaf record must be removed"
        );
        assert_eq!(updated.tabs.len(), 1, "exactly one (root) tab remains");
    }

    #[test]
    fn record_new_tab_missing_layout_is_typed_error_and_creates_nothing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());

        // No window layout exists; the helper must NOT create one.
        let started = started_session_for(&paths, "tab-1", "sess-1");
        let err = record_new_tab_in_window_layout(&paths, "missing-window", &started, None, 1)
            .expect_err("recording into a missing layout must fail");

        match err {
            NewTabLayoutRecordError::WindowLayout(
                maestro_shell::window_layout::WindowLayoutError::WindowLayoutNotFound { window_id },
            ) => assert_eq!(window_id, "missing-window"),
            other => panic!("expected WindowLayoutNotFound, got {other:?}"),
        }
        assert!(
            !any_window_layout_file_exists(&paths),
            "a missing-layout record must not create a layout"
        );
    }

    #[test]
    fn record_new_tab_duplicate_id_is_typed_error_and_layout_unchanged() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());

        // An existing layout already containing the tab id we will try to record.
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create window");
        service
            .open_tab(
                "w1",
                "tab-1",
                "sess-existing",
                "shell",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed the duplicate tab id");

        let started = started_session_for(&paths, "tab-1", "sess-1");
        let err = record_new_tab_in_window_layout(&paths, "w1", &started, None, 1)
            .expect_err("a duplicate tab id must be rejected by the service");

        match err {
            NewTabLayoutRecordError::WindowLayout(
                maestro_shell::window_layout::WindowLayoutError::TabAlreadyExists {
                    window_id,
                    tab_id,
                },
            ) => {
                assert_eq!(window_id, "w1");
                assert_eq!(tab_id, "tab-1");
            }
            other => panic!("expected TabAlreadyExists, got {other:?}"),
        }

        // The pre-existing tab/session binding is untouched.
        let reloaded = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load layout")
            .expect("layout exists");
        assert_eq!(reloaded.tabs.len(), 1);
        assert_eq!(reloaded.tabs[0].tab_id, "tab-1");
        assert_eq!(
            reloaded.tabs[0].session_id, "sess-existing",
            "the duplicate-rejected record must not overwrite the existing binding"
        );
    }

    // ---- new-tab strip projection + renderer send/attach -------------------------------
    // `ActiveTab` is re-exported at the crate root from `window`; `new_tab.rs`'s module imports do
    // not bring it in, so the moved cohort reaches it by its crate path.
    #[test]
    fn new_tab_strip_projection_marks_recorded_tab_active_in_both_strips() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());

        // Existing window with a prior pinned tab carrying unseen attention, then record a new tab.
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create window");
        service
            .open_tab(
                "w1",
                "t0",
                "sess-t0",
                "shell",
                true,
                maestro_shell::AttentionState {
                    attention: maestro_shell::Attention::NeedsInput,
                    unseen: true,
                    since_ms: 5,
                    source: maestro_shell::AttentionSource::Agent,
                },
                0,
            )
            .expect("seed prior tab");

        let started = started_session_for(&paths, "tab-1", "sess-1");
        let recorded = record_new_tab_in_window_layout(&paths, "w1", &started, None, 1_700_000_000)
            .expect("record into existing layout");

        let projection =
            new_tab_strip_projection("w1", &recorded).expect("projection must succeed");

        // Identity is the recorded tab/session.
        assert_eq!(projection.tab_id, "tab-1");
        assert_eq!(projection.session_id, "sess-1");

        // App model: ordered tabs, new tab active.
        let model = &projection.model;
        assert_eq!(model.active_tab_id.as_deref(), Some("tab-1"));
        assert_eq!(model.tabs.len(), 2);
        assert_eq!(model.tabs[0].tab_id, "t0");
        assert!(!model.tabs[0].active);
        assert!(model.tabs[0].pinned, "prior pinned tab stays pinned");
        assert!(
            model.tabs[0].needs_attention,
            "prior tab's unseen non-none attention surfaces"
        );
        assert_eq!(model.tabs[1].tab_id, "tab-1");
        assert!(model.tabs[1].active, "the recorded tab is active");
        assert!(!model.tabs[1].pinned);
        assert!(
            !model.tabs[1].needs_attention,
            "a freshly recorded tab needs no attention"
        );

        // Renderer strip: same ordered tabs, new tab active, flags carried.
        let strip = &projection.renderer_strip;
        assert_eq!(strip.window_id, "w1");
        assert_eq!(strip.tabs.len(), 2);
        assert_eq!(strip.tabs[0].tab_id, "t0");
        assert!(!strip.tabs[0].active);
        assert!(strip.tabs[0].pinned);
        assert!(strip.tabs[0].needs_attention);
        assert_eq!(strip.tabs[1].tab_id, "tab-1");
        assert!(strip.tabs[1].active);
        assert!(!strip.tabs[1].pinned);
        assert!(!strip.tabs[1].needs_attention);
    }

    #[test]
    fn new_tab_strip_projection_missing_recorded_tab_is_typed_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let windows = maestro_shell::WindowLayoutService::new(&paths);
        windows.create_empty("w1", 0).expect("create window");
        let rollback_snapshot = windows
            .open_tab_snapshot(
                "w1",
                "real",
                "sess-real",
                "Real",
                false,
                maestro_shell::AttentionState::default(),
                1,
            )
            .expect("record exact layout incarnation");
        // The exact recorded layout does NOT contain the claimed active tab_id.
        let record = NewTabLayoutRecord {
            tab_id: s("ghost"),
            session_id: s("sess-ghost"),
            layout: rollback_snapshot.layout.clone(),
        };
        let err = new_tab_strip_projection("w1", &record)
            .expect_err("a recorded tab id missing from the layout must be a typed error");
        assert_eq!(
            err,
            NewTabStripProjectionError::ActiveTabNotFound { tab_id: s("ghost") }
        );
    }

    #[test]
    fn new_tab_strip_projection_never_resurrects_existing_stashed_rows() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let windows = maestro_shell::WindowLayoutService::new(&paths);
        windows.create_empty("w1", 0).expect("create window");
        windows
            .open_stashed_tab(
                "w1",
                "parked",
                "sess-parked",
                "Parked",
                false,
                maestro_shell::AttentionState::default(),
                1,
            )
            .expect("record stashed tab");
        let rollback_snapshot = windows
            .open_tab_snapshot(
                "w1",
                "new-live",
                "sess-new",
                "New live",
                false,
                maestro_shell::AttentionState::default(),
                2,
            )
            .expect("record live tab");
        let record = NewTabLayoutRecord {
            tab_id: s("new-live"),
            session_id: s("sess-new"),
            layout: rollback_snapshot.layout.clone(),
        };

        let projection =
            new_tab_strip_projection("w1", &record).expect("the new live tab projects");
        assert_eq!(
            projection
                .model
                .tabs
                .iter()
                .map(|tab| tab.tab_id.as_str())
                .collect::<Vec<_>>(),
            vec!["new-live"],
            "durable stashed rows stay inspectable but never enter RendererTabRuntime"
        );
        assert_eq!(projection.renderer_strip.tabs.len(), 1);
    }

    /// Build a `NewTabStripProjection` for `tab_id`/`session_id` without any daemon/filesystem: a
    /// single-tab in-memory `NewTabLayoutRecord` run through the real `new_tab_strip_projection`.
    fn strip_projection_fixture(
        window_id: &str,
        tab_id: &str,
        session_id: &str,
    ) -> NewTabStripProjection {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let windows = maestro_shell::WindowLayoutService::new(&paths);
        windows
            .create_empty(window_id, 0)
            .expect("create projection window");
        let rollback_snapshot = windows
            .open_tab_snapshot(
                window_id,
                tab_id,
                session_id,
                &format!("Title {tab_id}"),
                false,
                maestro_shell::AttentionState::default(),
                1,
            )
            .expect("record projection tab");
        let record = NewTabLayoutRecord {
            tab_id: s(tab_id),
            session_id: s(session_id),
            layout: rollback_snapshot.layout.clone(),
        };
        new_tab_strip_projection(window_id, &record).expect("projection must succeed")
    }

    #[test]
    fn legacy_new_tab_strip_without_exact_active_is_refused_and_sends_nothing() {
        let projection = strip_projection_fixture("w1", "tab-1", "sess-1");
        let (mut rt, rx) = RendererTabRuntime::new();

        assert_eq!(
            send_new_tab_set_tab_strip(&mut rt, &projection),
            Err(NewTabSetTabStripError::HandoffPending)
        );
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn textual_seed_cannot_authorize_new_tab_strip() {
        let projection = strip_projection_fixture("w1", "tab-1", "sess-1");
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w0", "t0", "sess-t0");

        assert_eq!(
            send_new_tab_set_tab_strip(&mut rt, &projection),
            Err(NewTabSetTabStripError::HandoffPending)
        );
        assert!(rt.active_tab_key().is_none());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn legacy_new_tab_strip_refuses_before_observing_a_closed_receiver() {
        let projection = strip_projection_fixture("w1", "tab-1", "sess-1");
        let (mut rt, rx) = RendererTabRuntime::new();
        drop(rx);
        assert_eq!(
            send_new_tab_set_tab_strip(&mut rt, &projection),
            Err(NewTabSetTabStripError::HandoffPending)
        );
    }

    #[test]
    fn legacy_new_tab_attach_requires_exact_viewport_and_sends_nothing() {
        let projection = strip_projection_fixture("w1", "tab-1", "sess-1");
        let (mut rt, rx) = RendererTabRuntime::new();

        assert_eq!(
            send_new_tab_attach_session(&mut rt, &projection),
            Err(NewTabAttachSessionError::ViewportAuthorityRequired)
        );
        assert!(rt.active_tab_key().is_none());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn textual_seed_does_not_make_legacy_new_tab_attach_a_noop() {
        let projection = strip_projection_fixture("w1", "tab-1", "sess-1");
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w1", "tab-1", "sess-1");

        assert_eq!(
            send_new_tab_attach_session(&mut rt, &projection),
            Err(NewTabAttachSessionError::ViewportAuthorityRequired)
        );
        assert!(rt.active_tab_key().is_none());
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn legacy_new_tab_attach_refuses_before_observing_a_closed_receiver() {
        let projection = strip_projection_fixture("w1", "tab-1", "sess-1");
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w0", "t0", "sess-t0");
        drop(rx);

        assert_eq!(
            send_new_tab_attach_session(&mut rt, &projection),
            Err(NewTabAttachSessionError::ViewportAuthorityRequired)
        );
        assert!(rt.active_tab_key().is_none());
    }

    // ---- new-tab foreground scratch/worktree pipeline ----
    // `new_tab_snapshot_from_strip_tabs` is re-exported at the crate root from `window`; reach it by
    // crate path. `one_existing_tab_window`, `snapshot_tab`, and `fresh_worktree_workspace` are
    // private test helpers for this module.
    use crate::new_tab_snapshot_from_strip_tabs;

    fn one_existing_tab_window(paths: &maestro_shell::AppPaths, project_id: &str) {
        if maestro_shell::store::load_one::<maestro_shell::Workspace>(
            paths,
            maestro_shell::RecordKind::Workspace,
            "maestro-app-dev",
        )
        .expect("load fixture Workspace")
        .is_none()
        {
            seed_default_scratch_workspace_parents(paths);
        }
        maestro_shell::store::write_record(
            paths,
            maestro_shell::RecordKind::Session,
            "sess-t0",
            1,
            &maestro_shell::SessionRecord {
                session_id: "sess-t0".into(),
                workspace_id: "maestro-app-dev".into(),
                kind: maestro_shell::SessionKind::Shell,
                launch: maestro_shell::LaunchSpec::OptOut,
                cwd_resolved: "/tmp".into(),
                agent_task_id: None,
                created_at_ms: 1,
                last_attached_at_ms: 1,
                last_known_generation: Some("existing-generation".into()),
                status: maestro_shell::SessionStatus::Live,
            },
        )
        .expect("seed exact existing Session");
        let service = maestro_shell::WindowLayoutService::new(paths);
        service.create_empty("w1", 0).expect("create window");
        service
            .open_tab(
                "w1",
                "t0",
                "sess-t0",
                "shell",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed prior tab");
        service
            .ensure_project_assignment("w1", project_id, 2)
            .expect("assign exact Project/order owner to fixture window");
    }

    fn snapshot_tab(tab_id: &str, session_id: &str, index: u32) -> WindowTabJson {
        WindowTabJson {
            tab_id: s(tab_id),
            session_id: s(session_id),
            index,
            title: format!("Title {tab_id}"),
            pinned: false,
            attention: crate::AttentionJson {
                attention: s("none"),
                unseen: false,
                since_ms: 0,
                source: s("process"),
            },
            split_from: None,
            pane_rect: None,
        }
    }

    fn fresh_worktree_workspace(
        workspace_id: &str,
        root: &std::path::Path,
        worktree_create: bool,
    ) -> maestro_shell::Workspace {
        maestro_shell::Workspace {
            workspace_id: workspace_id.to_string(),
            project_id: "proj-wt".to_string(),
            root: root.to_string_lossy().into_owned(),
            policy: maestro_shell::WorkspacePolicy::Worktree,
            consent: maestro_shell::WorkspaceConsent {
                worktree_create,
                ..Default::default()
            },
        }
    }

    // Picker-consent grant-and-launch tests. The picker consent resolver
    // types/functions live in `crate::picker` and are re-exported at the crate root; reach them by
    // crate path. `one_existing_tab_window`, `MapEnv`, `StubDaemon`, `serve_grid`, `snapshot_with`,
    // `s`, and `ScriptedIdGen` are reused from helpers already present in this module. The four
    // seed/consent helpers below are private to these tests.
    use crate::{
        resolve_picker_consent_confirm, resolve_picker_consent_request,
        PickerConsentConfirmResolution, PickerConsentRequestResolution,
    };

    /// Seed a fresh project + a missing-consent `Worktree` workspace on disk so the consent
    /// resolvers read them through `DashboardSnapshotService::snapshot(None)`, exactly as the
    /// `attach-tab --picker-overlay` listener does. `root` is the (real, throwaway) git repo the
    /// worktree is cut from. Returns nothing — callers read the records back through the snapshot.
    fn seed_missing_consent_worktree_project(
        paths: &maestro_shell::AppPaths,
        project_id: &str,
        workspace_id: &str,
        root: &std::path::Path,
    ) {
        let project = maestro_shell::Project {
            project_id: project_id.to_string(),
            name: format!("Project {project_id}"),
            root: root.to_string_lossy().into_owned(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::Worktree,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            system: false,
            hidden: false,
            window_order: Vec::new(),
        };
        maestro_shell::store::write_record(
            paths,
            maestro_shell::RecordKind::Project,
            project_id,
            1,
            &project,
        )
        .expect("write project");
        let workspace = maestro_shell::Workspace {
            workspace_id: workspace_id.to_string(),
            project_id: project_id.to_string(),
            root: root.to_string_lossy().into_owned(),
            policy: maestro_shell::WorkspacePolicy::Worktree,
            consent: maestro_shell::WorkspaceConsent::default(),
        };
        maestro_shell::store::write_record(
            paths,
            maestro_shell::RecordKind::Workspace,
            workspace_id,
            1,
            &workspace,
        )
        .expect("write workspace");
    }

    /// Read the current on-disk `worktree_create` consent for a workspace through the public store,
    /// so assertions observe what `grant_consent` actually persisted (not an in-memory copy).
    fn on_disk_worktree_consent(paths: &maestro_shell::AppPaths, workspace_id: &str) -> bool {
        match maestro_shell::store::load_one::<maestro_shell::Workspace>(
            paths,
            maestro_shell::RecordKind::Workspace,
            workspace_id,
        )
        .expect("load workspace")
        .expect("workspace exists")
        {
            maestro_shell::store::LoadOutcome::Loaded(ws) => ws.consent.worktree_create,
            other => panic!("workspace must load cleanly, got {other:?}"),
        }
    }

    /// Seed a fresh project + a missing-consent `RepoWrite` workspace on disk. `root` is the (real,
    /// throwaway) directory that stands in for the live checkout the session would open directly. A
    /// plain directory is sufficient: the RepoWrite preparer is verify-only (no git, no mkdir).
    fn seed_missing_consent_repo_write_project(
        paths: &maestro_shell::AppPaths,
        project_id: &str,
        workspace_id: &str,
        root: &std::path::Path,
    ) {
        let project = maestro_shell::Project {
            project_id: project_id.to_string(),
            name: format!("Project {project_id}"),
            root: root.to_string_lossy().into_owned(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::RepoWrite,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            system: false,
            hidden: false,
            window_order: Vec::new(),
        };
        maestro_shell::store::write_record(
            paths,
            maestro_shell::RecordKind::Project,
            project_id,
            1,
            &project,
        )
        .expect("write project");
        let workspace = maestro_shell::Workspace {
            workspace_id: workspace_id.to_string(),
            project_id: project_id.to_string(),
            root: root.to_string_lossy().into_owned(),
            policy: maestro_shell::WorkspacePolicy::RepoWrite,
            consent: maestro_shell::WorkspaceConsent::default(),
        };
        maestro_shell::store::write_record(
            paths,
            maestro_shell::RecordKind::Workspace,
            workspace_id,
            1,
            &workspace,
        )
        .expect("write workspace");
    }

    /// Read the current on-disk `repo_write` consent for a workspace through the public store.
    fn on_disk_repo_write_consent(paths: &maestro_shell::AppPaths, workspace_id: &str) -> bool {
        match maestro_shell::store::load_one::<maestro_shell::Workspace>(
            paths,
            maestro_shell::RecordKind::Workspace,
            workspace_id,
        )
        .expect("load workspace")
        .expect("workspace exists")
        {
            maestro_shell::store::LoadOutcome::Loaded(ws) => ws.consent.repo_write,
            other => panic!("workspace must load cleanly, got {other:?}"),
        }
    }

    #[test]
    fn picker_consent_request_then_confirm_grants_once_and_launches_one_tab() {
        // The one allowed temp-dir/temp-git-repo integration test for the app-side grant-and-launch
        // seam. It drives the SAME resolver + grant + consent-gated launch helpers the listener uses,
        // against real on-disk records, a throwaway git repo, and a stub daemon. It proves:
        //   1. the request resolver shows the confirm prompt WITHOUT flipping on-disk consent;
        //   2. the confirm resolver authorizes a grant, `grant_consent` flips `worktree_create` to
        //      true EXACTLY once, and the consent-gated launch opens one tab/session.
        // No real user repo, network, GUI, RepoWrite, live checkout, or worktree removal.
        let repo = tempfile::tempdir().expect("repo dir");
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("git runs");
            assert!(status.success(), "git {args:?} succeeded");
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        git(&["commit", "-q", "--allow-empty", "-m", "base"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_missing_consent_worktree_project(&paths, "proj-wt", "ws-wt", repo.path());
        one_existing_tab_window(&paths, "proj-wt");

        // --- Request phase: fresh snapshot -> ShowConfirm, no consent write. ---
        let snapshot = maestro_shell::DashboardSnapshotService::new(&paths)
            .snapshot(None)
            .expect("request snapshot");
        match resolve_picker_consent_request("proj-wt", "ws-wt", &snapshot.projects) {
            PickerConsentRequestResolution::ShowConfirm { confirm } => {
                assert_eq!(confirm.project_id, "proj-wt");
                assert_eq!(confirm.workspace_id, "ws-wt");
                assert_eq!(confirm.policy, "worktree");
                assert_eq!(confirm.consent_kind, "worktree_create");
                assert_eq!(confirm.root, repo.path().to_string_lossy());
            }
            other => {
                panic!("request must show confirm for missing-consent worktree, got {other:?}")
            }
        }
        assert!(
            !on_disk_worktree_consent(&paths, "ws-wt"),
            "the request phase must NOT write consent"
        );

        // --- Confirm phase: re-snapshot -> Grant; the resolver itself still never writes. ---
        let snapshot = maestro_shell::DashboardSnapshotService::new(&paths)
            .snapshot(None)
            .expect("confirm snapshot");
        let policy = match resolve_picker_consent_confirm("proj-wt", "ws-wt", &snapshot.projects) {
            PickerConsentConfirmResolution::Grant { policy, .. } => policy,
            other => panic!("confirm must authorize a grant, got {other:?}"),
        };
        assert!(
            !on_disk_worktree_consent(&paths, "ws-wt"),
            "the confirm resolver must NOT write consent either"
        );

        // --- Grant phase: the app calls grant_consent EXACTLY once (as the listener does). ---
        let granted = maestro_shell::grant_consent(
            &paths,
            "ws-wt",
            maestro_shell::WorkspaceConsentKind::WorktreeCreate,
            1_700_000_000,
        )
        .expect("grant_consent succeeds");
        assert!(
            granted.consent.worktree_create,
            "grant_consent returns a workspace with consent set"
        );
        assert!(
            on_disk_worktree_consent(&paths, "ws-wt"),
            "grant_consent flips on-disk worktree_create to true exactly once"
        );

        // --- Launch phase: consent-gated worktree pipeline opens ONE tab/session. ---
        let sock_dir = tempfile::tempdir().expect("sock dir");
        let sock_path = sock_dir.path().join("stub.sock");
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid(s("sess-1"), s("gen-1")));
        let env = MapEnv::new(&[]);
        let mut id_gen = ScriptedIdGen::new(&["tab-1"], &["sess-1"]);
        let snapshot_for_plan = snapshot_with(&[], &[]);
        let plan = plan_new_tab(Some(&policy), &snapshot_for_plan, &mut id_gen);
        let NewTabPlan::Create { workspace_id, .. } = &plan else {
            panic!("expected Create from the granted worktree policy");
        };
        assert_eq!(
            workspace_id, "ws-wt",
            "the launch plan threads the fresh workspace id from the resolved policy"
        );
        let argv = vec![s("/bin/zsh"), s("-l")];
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w1", "t0", "sess-t0");

        let out = run_new_tab_foreground_pipeline_with_consent(
            NewTabForegroundRequest {
                paths: &paths,
                socket_path: sock_path,
                window_id: "w1",
                plan: &plan,
                launch: NewTabForegroundLaunch::shell_adhoc(&argv),
                cols: 80,
                rows: 24,
                now_ms: 1_700_000_000,
                split_from: None,
                split_source_session: None,
                expected_project_id: None,
            },
            &granted,
            &env,
            &mut rt,
        )
        .unwrap_or_else(|error| panic!("granted worktree launch succeeds: {error}"));

        assert_eq!(out.tab_id, "tab-1");
        assert_eq!(out.session_id, "sess-1");
        assert_eq!(rt.active_tab_id(), None, "send is not renderer adoption");
        assert_eq!(
            rt.pending_handoff()
                .map(|pending| pending.target().target().tab_id.as_str()),
            Some("tab-1")
        );
        let strip = expect_single_handoff_command(&rx, "sess-1", 2);
        assert!(strip.tabs[1].active);

        let persisted = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load")
            .expect("window exists");
        assert_eq!(persisted.tabs.len(), 2, "exactly one tab was adopted");
        assert_eq!(persisted.tabs[1].session_id, "sess-1");
        // Re-granting is idempotent: a second grant does not toggle or duplicate consent state.
        assert!(
            on_disk_worktree_consent(&paths, "ws-wt"),
            "consent remains granted after launch"
        );
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn picker_repo_write_request_then_confirm_grants_once_and_launches_one_tab_in_live_checkout() {
        // The one allowed temp-dir integration test for the RepoWrite grant-and-launch seam. It
        // drives the SAME resolver + grant + consent-gated launch helpers the listener uses, against
        // real on-disk records and a stub daemon, and proves the higher-risk direct-write path:
        //   1. the request resolver shows the confirm prompt WITHOUT flipping on-disk repo_write;
        //   2. the confirm resolver authorizes a grant carrying WorkspaceConsentKind::RepoWrite;
        //   3. grant_consent flips `repo_write` to true EXACTLY once;
        //   4. the consent-gated launch opens ONE tab/session whose cwd is the live checkout root
        //      verbatim (RepoWrite is verify-only: no worktree directory is cut).
        // A plain temp dir stands in for the live checkout — no git, no real user repo, no network,
        // no GUI, and no writes outside the temp dir.
        let checkout = tempfile::tempdir().expect("checkout dir");

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_missing_consent_repo_write_project(&paths, "proj-rw", "ws-rw", checkout.path());
        one_existing_tab_window(&paths, "proj-rw");

        // --- Request phase: fresh snapshot -> ShowConfirm, no consent write. ---
        let snapshot = maestro_shell::DashboardSnapshotService::new(&paths)
            .snapshot(None)
            .expect("request snapshot");
        match resolve_picker_consent_request("proj-rw", "ws-rw", &snapshot.projects) {
            PickerConsentRequestResolution::ShowConfirm { confirm } => {
                assert_eq!(confirm.project_id, "proj-rw");
                assert_eq!(confirm.workspace_id, "ws-rw");
                assert_eq!(confirm.policy, "repo_write");
                assert_eq!(confirm.consent_kind, "repo_write");
                assert_eq!(confirm.root, checkout.path().to_string_lossy());
            }
            other => {
                panic!("request must show confirm for missing-consent repo_write, got {other:?}")
            }
        }
        assert!(
            !on_disk_repo_write_consent(&paths, "ws-rw"),
            "the request phase must NOT write repo_write consent"
        );

        // --- Confirm phase: re-snapshot -> Grant carrying RepoWrite; resolver still never writes. ---
        let snapshot = maestro_shell::DashboardSnapshotService::new(&paths)
            .snapshot(None)
            .expect("confirm snapshot");
        let (policy, consent_kind) =
            match resolve_picker_consent_confirm("proj-rw", "ws-rw", &snapshot.projects) {
                PickerConsentConfirmResolution::Grant {
                    policy,
                    consent_kind,
                    ..
                } => (policy, consent_kind),
                other => panic!("confirm must authorize a repo_write grant, got {other:?}"),
            };
        assert_eq!(
            consent_kind,
            maestro_shell::WorkspaceConsentKind::RepoWrite,
            "the confirm resolution derives RepoWrite consent from the fresh policy"
        );
        assert!(
            !on_disk_repo_write_consent(&paths, "ws-rw"),
            "the confirm resolver must NOT write consent either"
        );

        // --- Grant phase: the app calls grant_consent EXACTLY once with the derived kind. ---
        let granted = maestro_shell::grant_consent(&paths, "ws-rw", consent_kind, 1_700_000_000)
            .expect("grant_consent succeeds");
        assert!(
            granted.consent.repo_write,
            "grant_consent returns a workspace with repo_write consent set"
        );
        assert!(
            on_disk_repo_write_consent(&paths, "ws-rw"),
            "grant_consent flips on-disk repo_write to true exactly once"
        );

        // --- Launch phase: consent-gated pipeline opens ONE tab/session in the live checkout. ---
        let sock_dir = tempfile::tempdir().expect("sock dir");
        let sock_path = sock_dir.path().join("stub.sock");
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid(s("sess-1"), s("gen-1")));
        let env = MapEnv::new(&[]);
        let mut id_gen = ScriptedIdGen::new(&["tab-1"], &["sess-1"]);
        let snapshot_for_plan = snapshot_with(&[], &[]);
        let plan = plan_new_tab(Some(&policy), &snapshot_for_plan, &mut id_gen);
        let NewTabPlan::Create { workspace_id, .. } = &plan else {
            panic!("expected Create from the granted repo_write policy");
        };
        assert_eq!(
            workspace_id, "ws-rw",
            "the launch plan threads the fresh workspace id from the resolved policy"
        );
        let argv = vec![s("/bin/zsh"), s("-l")];
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w1", "t0", "sess-t0");

        let out = run_new_tab_foreground_pipeline_with_consent(
            NewTabForegroundRequest {
                paths: &paths,
                socket_path: sock_path,
                window_id: "w1",
                plan: &plan,
                launch: NewTabForegroundLaunch::shell_adhoc(&argv),
                cols: 80,
                rows: 24,
                now_ms: 1_700_000_000,
                split_from: None,
                split_source_session: None,
                expected_project_id: None,
            },
            &granted,
            &env,
            &mut rt,
        )
        .expect("granted repo_write launch succeeds");

        assert_eq!(out.tab_id, "tab-1");
        assert_eq!(out.session_id, "sess-1");
        assert_eq!(rt.active_tab_id(), None, "send is not renderer adoption");
        assert_eq!(
            rt.pending_handoff()
                .map(|pending| pending.target().target().tab_id.as_str()),
            Some("tab-1")
        );
        let strip = expect_single_handoff_command(&rx, "sess-1", 2);
        assert!(strip.tabs[1].active);

        let persisted = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load")
            .expect("window exists");
        assert_eq!(persisted.tabs.len(), 2, "exactly one tab was adopted");
        assert_eq!(persisted.tabs[1].session_id, "sess-1");
        // RepoWrite is verify-only: the live checkout root is reused directly, never copied into a
        // per-session worktree directory.
        assert!(
            checkout.path().is_dir(),
            "the live checkout root remains the session cwd, unmodified by preparation"
        );
        assert!(
            on_disk_repo_write_consent(&paths, "ws-rw"),
            "repo_write consent remains granted after launch"
        );
        drop(stub);
        drop(sock_dir);
    }

    // Picker-to-NewTab planning seam tests. These two tests prove a picker-built
    // launch policy feeds the SAME `plan_new_tab` seam the foreground pipeline uses and produces a
    // `NewTabPlan::Create` without any `--new-tab-default-shell` flag. `resolve_picker_activation` +
    // `PickerActivationResolution` live in `crate::picker` and are re-exported at the crate root; reach
    // them by crate path. `ScriptedIdGen` and `snapshot_with` are reused from helpers already in
    // this module; the four in-memory picker builders below are narrow private helpers
    // (the on-disk grant-and-launch tests above seed via `store::write_record` instead, so they do
    // not share these).
    use crate::{resolve_picker_activation, PickerActivationResolution};

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
    fn resolver_worktree_launch_policy_plans_via_plan_new_tab_without_default_shell_flag() {
        // The consent-granted worktree policy feeds the SAME `plan_new_tab` seam as scratch and
        // produces a Create with no `--new-tab-default-shell` flag.
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
        let PickerActivationResolution::Launch { policy, .. } =
            resolve_picker_activation("proj-a", Some("ws-wt"), &projects)
        else {
            panic!("expected launch");
        };
        let snapshot = snapshot_with(&["tab-existing"], &["sess-existing"]);
        let plan = plan_new_tab(
            Some(&policy),
            &snapshot,
            &mut ScriptedIdGen::new(&["tab-new"], &["sess-new"]),
        );
        let NewTabPlan::Create { workspace, .. } = &plan else {
            panic!("worktree picker policy should plan a Create, got {plan:?}");
        };
        assert_eq!(*workspace, maestro_shell::WorkspacePolicy::Worktree);
    }

    #[test]
    fn resolver_launch_policy_plans_via_plan_new_tab_without_default_shell_flag() {
        // Picker activation is itself the launch intent: the resolver-built policy feeds the SAME
        // `plan_new_tab` seam the foreground pipeline uses, and produces a Create with no extra flag.
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
        let snapshot = snapshot_with(&["tab-existing"], &["sess-existing"]);
        let plan = plan_new_tab(
            Some(&policy),
            &snapshot,
            &mut ScriptedIdGen::new(&["tab-new"], &["sess-new"]),
        );
        assert!(
            matches!(plan, NewTabPlan::Create { .. }),
            "scratch picker policy should plan a Create, got {plan:?}"
        );
    }

    #[test]
    fn new_tab_foreground_no_policy_declines_and_sends_no_renderer_command() {
        let tabs = vec![snapshot_tab("t0", "sess-t0", 0)];
        let snapshot = new_tab_snapshot_from_strip_tabs(&tabs, Some("t0"));
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w1", "t0", "sess-t0");
        let mut id_gen = ScriptedIdGen::new(&["unused-tab"], &["unused-sess"]);

        assert_eq!(
            plan_new_tab(None, &snapshot, &mut id_gen),
            NewTabPlan::Decline
        );
        assert_eq!(id_gen.tab_calls, 0);
        assert_eq!(id_gen.session_calls, 0);
        assert!(
            rx.try_recv().is_err(),
            "decline path must not send SetTabStrip or AttachSession"
        );
        assert_eq!(
            rt.active_tab_id(),
            None,
            "textual seed facts cannot invent a proven renderer lifetime"
        );
    }

    #[test]
    fn new_tab_foreground_pipeline_sends_strip_then_attach_and_returns_adoptable_projections() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        // The pipeline starts a session whose SessionRecord references the scratch workspace; seed
        // its FK parents so the SQLite session INSERT does not fail the foreign-key constraint.
        seed_default_scratch_workspace_parents(&paths);
        one_existing_tab_window(&paths, "maestro-app-dev-project");

        let sock_dir = tempfile::tempdir().expect("sock dir");
        let sock_path = sock_dir.path().join("stub.sock");
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid(s("sess-1"), s("gen-1")));
        let env = MapEnv::new(&[]);
        let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
        let argv = vec![s("/bin/zsh"), s("-l")];
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w1", "t0", "sess-t0");

        let out = run_new_tab_foreground_pipeline(
            NewTabForegroundRequest {
                paths: &paths,
                socket_path: sock_path,
                window_id: "w1",
                plan: &plan,
                launch: NewTabForegroundLaunch::shell_adhoc(&argv),
                cols: 80,
                rows: 24,
                now_ms: 1_700_000_000,
                split_from: None,
                split_source_session: None,
                expected_project_id: None,
            },
            &env,
            &mut rt,
        )
        .expect("foreground create pipeline succeeds");

        assert_eq!(out.tab_id, "tab-1");
        assert_eq!(out.session_id, "sess-1");
        assert_eq!(
            out.strip_tabs
                .iter()
                .map(|t| t.tab_id.as_str())
                .collect::<Vec<_>>(),
            vec!["t0", "tab-1"]
        );
        assert_eq!(
            out.selection
                .iter()
                .map(|t| (t.tab_id.as_str(), t.session_id.as_str()))
                .collect::<Vec<_>>(),
            vec![("t0", "sess-t0"), ("tab-1", "sess-1")]
        );
        assert_eq!(rt.active_tab_id(), None, "send is not renderer adoption");
        assert_eq!(
            rt.pending_handoff()
                .map(|pending| pending.target().target().tab_id.as_str()),
            Some("tab-1")
        );

        let strip = expect_single_handoff_command(&rx, "sess-1", 2);
        assert_eq!(strip.window_id, "w1");
        assert!(!strip.tabs[0].active);
        assert!(strip.tabs[1].active);
        assert_eq!(strip.tabs[1].tab_id, "tab-1");

        let persisted = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load")
            .expect("window exists");
        assert_eq!(persisted.tabs.len(), 2);
        assert_eq!(persisted.tabs[1].tab_id, "tab-1");
        assert_eq!(persisted.tabs[1].session_id, "sess-1");
        assert!(
            paths.scratch_base().join("sess-1").is_dir(),
            "success leaves the scratch cwd in place because the TabRecord owns it"
        );
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn custom_agent_split_seals_after_scratch_and_keeps_exact_source_fence() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_default_scratch_workspace_parents(&paths);
        one_existing_tab_window(&paths, "maestro-app-dev-project");
        let source_session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "sess-t0",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("source Session must be current: {other:?}"),
        };

        let sock_dir = tempfile::tempdir().expect("sock dir");
        let sock_path = sock_dir.path().join("stub.sock");
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid(s("sess-agent"), s("gen-1")));
        let env = MapEnv::new(&[]);
        let plan = create_plan(
            "tab-agent",
            "sess-agent",
            NewTabLaunchSource::PreparedAgentAdHoc,
        );
        let launch = NewTabForegroundLaunch::agent_adhoc(vec![s("/bin/sh"), s("-l")], None)
            .expect("absolute custom Agent source is valid");
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w1", "t0", "sess-t0");

        let out = run_new_tab_foreground_pipeline(
            NewTabForegroundRequest {
                paths: &paths,
                socket_path: sock_path,
                window_id: "w1",
                plan: &plan,
                launch,
                cols: 80,
                rows: 24,
                now_ms: 1_700_000_000,
                split_from: Some(NewTabSplitFrom {
                    from_tab_id: s("t0"),
                    axis: maestro_shell::SplitAxis::Right,
                }),
                split_source_session: Some(&source_session),
                expected_project_id: Some("maestro-app-dev-project"),
            },
            &env,
            &mut rt,
        )
        .expect("custom Agent split succeeds through PreparedNew");

        assert_eq!(out.session_id, "sess-agent");
        let strip = expect_single_handoff_command(&rx, "sess-agent", 2);
        assert_eq!(strip.tabs[1].tab_id, "tab-agent");
        let stored = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "sess-agent",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("new Session must be current: {other:?}"),
        };
        assert_eq!(stored.kind, maestro_shell::SessionKind::Agent);
        assert_eq!(stored.status, maestro_shell::SessionStatus::Live);
        assert_eq!(stored.last_known_generation.as_deref(), Some("gen-1"));
        assert!(matches!(
            stored.launch,
            maestro_shell::LaunchSpec::AdHocRedacted {
                redacted: true,
                restart_requires_user: true,
                ..
            }
        ));
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .unwrap()
            .unwrap();
        let child = layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == "tab-agent")
            .expect("split child is durable");
        assert_eq!(
            child.split_from.as_ref().map(|split| split.tab_id.as_str()),
            Some("t0")
        );
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn assigned_provider_split_uses_redacted_unknown_a_then_publishes_exact_b() {
        const PROVIDER_ID: &str = "70000000-0000-4000-8000-000000000001";
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_default_scratch_workspace_parents(&paths);
        one_existing_tab_window(&paths, "maestro-app-dev-project");
        let source_session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "sess-t0",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("source Session must be current: {other:?}"),
        };
        let plan = create_plan(
            "tab-provider",
            "sess-provider",
            NewTabLaunchSource::KnownSafeSpec {
                launch_spec_id: s("claude"),
            },
        );
        let launch = NewTabForegroundLaunch::provider(
            s("claude"),
            vec![s("claude"), s("--session-id"), s(PROVIDER_ID)],
            s("claude"),
        )
        .expect("assigned Claude identity is a strict fresh provider source");
        let (prepared, scratch) =
            prepare_fresh_new_tab_scratch_workspace(&paths, &plan, "").unwrap();

        let sock_dir = tempfile::tempdir().expect("sock dir");
        let sock_path = sock_dir.path().join("stub.sock");
        let paths_at_wire = paths.clone();
        let serve =
            serve_grid_with_start_observer(s("sess-provider"), s("gen-provider"), |request| {
                match request {
                    maestro_protocol::ClientRequest::StartSession { args, .. } => {
                        let packed = args.last().expect("login-shell provider command");
                        assert!(packed.contains("--session-id") && packed.contains(PROVIDER_ID));
                        assert!(!packed.contains("--resume"));
                    }
                    other => panic!("expected StartSession, got {other:?}"),
                }
            });
        let stub = StubDaemon::spawn_at(sock_path.clone(), move |stream| {
            let unknown = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
                &paths_at_wire,
                maestro_shell::RecordKind::Session,
                "sess-provider",
            )
            .unwrap()
            .unwrap()
            {
                maestro_shell::LoadOutcome::Loaded(session) => session,
                other => panic!("provider A must be durable before daemon wire: {other:?}"),
            };
            assert_eq!(unknown.status, maestro_shell::SessionStatus::Unknown);
            assert_eq!(unknown.last_known_generation, None);
            assert!(matches!(
                unknown.launch,
                maestro_shell::LaunchSpec::AdHocRedacted {
                    ref argv,
                    redacted: true,
                    restart_requires_user: true,
                } if argv == &[s("claude"), s("--session-id"), s("<redacted>")]
            ));
            serve(stream);
        });
        let env = MapEnv::new(&[]);
        let (mut runtime, rx) = RendererTabRuntime::new();
        runtime.seed_active_tab("w1", "t0", "sess-t0");
        let request = NewTabForegroundRequest {
            paths: &paths,
            socket_path: sock_path,
            window_id: "w1",
            plan: &plan,
            launch,
            cols: 80,
            rows: 24,
            now_ms: 1_700_000_000,
            split_from: Some(NewTabSplitFrom {
                from_tab_id: s("t0"),
                axis: maestro_shell::SplitAxis::Right,
            }),
            split_source_session: Some(&source_session),
            expected_project_id: Some("maestro-app-dev-project"),
        };
        let out = run_new_tab_foreground_pipeline_from_prepared_with_reprobe(
            request,
            prepared,
            Some(scratch),
            None,
            &env,
            &mut runtime,
            |_source_argv, _selected_agent, _cwd| Ok(()),
        )
        .expect("strict provider split succeeds through the shared production pipeline");

        assert_eq!(out.session_id, "sess-provider");
        let strip = expect_single_handoff_command(&rx, "sess-provider", 2);
        assert_eq!(strip.tabs[1].tab_id, "tab-provider");
        let live = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "sess-provider",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("provider B must be current after Grid: {other:?}"),
        };
        assert_eq!(live.status, maestro_shell::SessionStatus::Live);
        assert_eq!(live.last_known_generation.as_deref(), Some("gen-provider"));
        assert_eq!(
            live.launch,
            maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: s("claude"),
                params: vec![s("--resume"), s(PROVIDER_ID)],
            }
        );
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .unwrap()
            .unwrap();
        let child = layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == "tab-provider")
            .expect("provider split child is durable");
        assert_eq!(
            child.split_from.as_ref().map(|split| split.tab_id.as_str()),
            Some("t0")
        );
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn provider_word_custom_split_keeps_redacted_adhoc_a_and_b() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_default_scratch_workspace_parents(&paths);
        one_existing_tab_window(&paths, "maestro-app-dev-project");
        let source_session = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "sess-t0",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("source Session must be current: {other:?}"),
        };
        let plan = create_plan(
            "tab-provider-custom",
            "sess-provider-custom",
            NewTabLaunchSource::PreparedAgentAdHoc,
        );
        let source_argv = vec![s("claude"), s("mcp"), s("--serve")];
        let launch = NewTabForegroundLaunch::provider_custom_adhoc(
            s("claude"),
            source_argv.clone(),
            s("claude"),
        )
        .expect("non-selector provider-word command is valid opaque custom Agent input");
        let (prepared, scratch) =
            prepare_fresh_new_tab_scratch_workspace(&paths, &plan, "").unwrap();

        let sock_dir = tempfile::tempdir().expect("sock dir");
        let sock_path = sock_dir.path().join("stub.sock");
        let paths_at_wire = paths.clone();
        let serve = serve_grid_with_start_observer(
            s("sess-provider-custom"),
            s("gen-provider-custom"),
            |request| match request {
                maestro_protocol::ClientRequest::StartSession { command, args, .. } => {
                    assert_ne!(
                        command, "claude",
                        "provider-word source uses private shell wire"
                    );
                    assert_eq!(args.first().map(String::as_str), Some("-lic"));
                    assert!(
                        args.iter().any(|arg| arg.contains("claude")),
                        "private login-shell wire retains the reviewed source command"
                    );
                }
                other => panic!("expected StartSession, got {other:?}"),
            },
        );
        let source_for_wire = source_argv.clone();
        let stub = StubDaemon::spawn_at(sock_path.clone(), move |stream| {
            let unknown = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
                &paths_at_wire,
                maestro_shell::RecordKind::Session,
                "sess-provider-custom",
            )
            .unwrap()
            .unwrap()
            {
                maestro_shell::LoadOutcome::Loaded(session) => session,
                other => panic!("custom provider A must precede daemon wire: {other:?}"),
            };
            assert_eq!(unknown.status, maestro_shell::SessionStatus::Unknown);
            assert!(matches!(
                unknown.launch,
                maestro_shell::LaunchSpec::AdHocRedacted {
                    ref argv,
                    redacted: true,
                    restart_requires_user: true,
                } if argv == &source_for_wire
            ));
            serve(stream);
        });
        let env = MapEnv::new(&[]);
        let (mut runtime, rx) = RendererTabRuntime::new();
        runtime.seed_active_tab("w1", "t0", "sess-t0");
        let request = NewTabForegroundRequest {
            paths: &paths,
            socket_path: sock_path,
            window_id: "w1",
            plan: &plan,
            launch,
            cols: 80,
            rows: 24,
            now_ms: 1_700_000_000,
            split_from: Some(NewTabSplitFrom {
                from_tab_id: s("t0"),
                axis: maestro_shell::SplitAxis::Right,
            }),
            split_source_session: Some(&source_session),
            expected_project_id: Some("maestro-app-dev-project"),
        };
        let out = run_new_tab_foreground_pipeline_from_prepared_with_reprobe(
            request,
            prepared,
            Some(scratch),
            None,
            &env,
            &mut runtime,
            |_source_argv, _selected_agent, _cwd| Ok(()),
        )
        .expect("provider-word custom split succeeds through the shared production pipeline");

        assert_eq!(out.session_id, "sess-provider-custom");
        let strip = expect_single_handoff_command(&rx, "sess-provider-custom", 2);
        assert_eq!(strip.tabs[1].tab_id, "tab-provider-custom");
        let live = match maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "sess-provider-custom",
        )
        .unwrap()
        .unwrap()
        {
            maestro_shell::LoadOutcome::Loaded(session) => session,
            other => panic!("custom provider B must be current after Grid: {other:?}"),
        };
        assert_eq!(live.status, maestro_shell::SessionStatus::Live);
        assert_eq!(
            live.launch,
            maestro_shell::LaunchSpec::AdHocRedacted {
                argv: source_argv,
                redacted: true,
                restart_requires_user: true,
            }
        );
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .unwrap()
            .unwrap();
        let child = layout
            .tabs
            .iter()
            .find(|tab| tab.tab_id == "tab-provider-custom")
            .expect("custom provider split child is durable");
        assert_eq!(
            child.split_from.as_ref().map(|split| split.tab_id.as_str()),
            Some("t0")
        );
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn custom_agent_carrier_preserves_opaque_cross_provider_commands() {
        assert!(NewTabForegroundLaunch::agent_adhoc(
            vec![s("claude"), s("mcp"), s("--serve")],
            Some(s("claude")),
        )
        .is_some());
        assert!(NewTabForegroundLaunch::agent_adhoc(
            vec![s("claude"), s("--continue=foreign")],
            Some(s("codex")),
        )
        .is_some());
        assert!(NewTabForegroundLaunch::agent_adhoc(
            vec![s("/opt/custom/claude"), s("--continue=foreign")],
            Some(s("claude")),
        )
        .is_some());
        assert!(NewTabForegroundLaunch::provider_custom_adhoc(
            s("copilot"),
            vec![s("copilot"), s("-r=foreign")],
            s("copilot"),
        )
        .is_none());
    }

    #[test]
    fn worktree_foreground_pipeline_missing_consent_fails_at_gate_before_any_side_effect() {
        // Defense-in-depth: even if the caller routed a worktree here, a record WITHOUT
        // `worktree_create` consent must fail at `prepare_workspace_with_consent`'s consent gate
        // BEFORE any git runs, any daemon connect, or any renderer command is sent.
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        one_existing_tab_window(&paths, "maestro-app-dev-project");

        let env = MapEnv::new(&[]);
        let plan =
            create_plan_with_workspace("tab-1", "sess-1", maestro_shell::WorkspacePolicy::Worktree);
        let NewTabPlan::Create { workspace_id, .. } = &plan else {
            panic!("expected Create");
        };
        // The root does not even need to be a git repo: the consent gate runs first.
        let fresh = fresh_worktree_workspace(workspace_id, tmp.path(), false);
        let argv = vec![s("/bin/zsh"), s("-l")];
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w1", "t0", "sess-t0");

        let err = run_new_tab_foreground_pipeline_with_consent(
            NewTabForegroundRequest {
                paths: &paths,
                socket_path: tmp.path().join("unused.sock"),
                window_id: "w1",
                plan: &plan,
                launch: NewTabForegroundLaunch::shell_adhoc(&argv),
                cols: 80,
                rows: 24,
                now_ms: 1_700_000_000,
                split_from: None,
                split_source_session: None,
                expected_project_id: None,
            },
            &fresh,
            &env,
            &mut rt,
        )
        .expect_err("missing consent must fail at the gate");

        assert!(
            matches!(
                err,
                NewTabForegroundError::WorkspacePrepare(
                    NewTabWorkspacePrepareError::WorkspaceExec(
                        maestro_shell::WorkspaceExecError::Consent(_)
                    )
                )
            ),
            "missing-consent worktree must surface a consent-gate error, got {err:?}"
        );
        assert!(
            rx.try_recv().is_err(),
            "consent-gate failure sends no renderer commands"
        );
        assert_eq!(
            rt.active_tab_id(),
            None,
            "consent-gate failure cannot upgrade the textual seed into authority"
        );
        let persisted = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load")
            .expect("window exists");
        assert_eq!(
            persisted.tabs.len(),
            1,
            "consent-gate failure appends no TabRecord"
        );
    }

    #[test]
    fn worktree_foreground_pipeline_consented_prepares_real_worktree_and_runs_shared_flow() {
        // End-to-end through the app-side consent seam against a THROWAWAY temp git repo and a stub
        // daemon: a consented worktree prepares via `prepare_workspace_with_consent(Worktree)` and
        // then runs the SAME post-preparation foreground flow as scratch (strip then attach, one
        // adopted TabRecord). No real user repo, network, GUI, RepoWrite, or worktree removal.
        let repo = tempfile::tempdir().expect("repo dir");
        // Minimal real git repo with one commit so `git worktree add` has a base.
        let git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(repo.path())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .expect("git runs");
            assert!(status.success(), "git {args:?} succeeded");
        };
        git(&["init", "-q"]);
        git(&["config", "user.email", "t@t"]);
        git(&["config", "user.name", "t"]);
        git(&["commit", "-q", "--allow-empty", "-m", "base"]);

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_missing_consent_worktree_project(&paths, "proj-wt", "maestro-app-dev", repo.path());
        let fresh = maestro_shell::grant_consent(
            &paths,
            "maestro-app-dev",
            maestro_shell::WorkspaceConsentKind::WorktreeCreate,
            2,
        )
        .expect("grant fixture worktree consent");
        one_existing_tab_window(&paths, "proj-wt");

        let sock_dir = tempfile::tempdir().expect("sock dir");
        let sock_path = sock_dir.path().join("stub.sock");
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid(s("sess-1"), s("gen-1")));
        let env = MapEnv::new(&[]);
        let plan =
            create_plan_with_workspace("tab-1", "sess-1", maestro_shell::WorkspacePolicy::Worktree);
        let NewTabPlan::Create { workspace_id, .. } = &plan else {
            panic!("expected Create");
        };
        assert_eq!(workspace_id, &fresh.workspace_id);
        let argv = vec![s("/bin/zsh"), s("-l")];
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w1", "t0", "sess-t0");

        let out = run_new_tab_foreground_pipeline_with_consent(
            NewTabForegroundRequest {
                paths: &paths,
                socket_path: sock_path,
                window_id: "w1",
                plan: &plan,
                launch: NewTabForegroundLaunch::shell_adhoc(&argv),
                cols: 80,
                rows: 24,
                now_ms: 1_700_000_000,
                split_from: None,
                split_source_session: None,
                expected_project_id: None,
            },
            &fresh,
            &env,
            &mut rt,
        )
        .unwrap_or_else(|error| panic!("consented worktree foreground pipeline succeeds: {error}"));

        assert_eq!(out.tab_id, "tab-1");
        assert_eq!(out.session_id, "sess-1");
        assert_eq!(rt.active_tab_id(), None, "send is not renderer adoption");
        assert_eq!(
            rt.pending_handoff()
                .map(|pending| pending.target().target().tab_id.as_str()),
            Some("tab-1")
        );
        let strip = expect_single_handoff_command(&rx, "sess-1", 2);
        assert!(strip.tabs[1].active);

        let persisted = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load")
            .expect("window exists");
        assert_eq!(persisted.tabs.len(), 2);
        assert_eq!(persisted.tabs[1].session_id, "sess-1");
        // The worktree was actually prepared under the app-support worktrees base; this pipeline
        // permits idempotent reuse and never removes the checkout.
        assert!(
            paths
                .worktree_base()
                .join(workspace_id)
                .join("sess-1")
                .is_dir(),
            "consented worktree preparation created the per-session worktree directory"
        );
        drop(stub);
        drop(sock_dir);
    }

    // ---- new-tab foreground failure / scratch-cleanup classification (moved from lib.rs).
    // These tests own the production items they exercise (`run_new_tab_foreground_pipeline`,
    // `classify_new_tab_foreground_failure`, `new_tab_failure_scratch_to_remove`,
    // `remove_new_tab_scratch`, the `NewTabForegroundError`/`NewTabFailureStage` surface), all
    // reached via `use super::*;`. `session_start_foreground_error` below is an INDEPENDENT private
    // copy: the original stays in `lib.rs` because the later retained recovery-planning tests still
    // call it there. The broad fixtures (`one_existing_tab_window`/`MapEnv`/`StubDaemon`/`serve_grid`/
    // `create_plan`/`s`) reuse the existing private copies above.

    fn session_start_foreground_error(cwd: PathBuf) -> NewTabForegroundError {
        NewTabForegroundError::SessionStart {
            cwd,
            error: NewTabSessionStartError::Shell(maestro_shell::ShellRuntimeError::Daemon(
                maestro_shell::DaemonClientError::Timeout { during: "test" },
            )),
        }
    }

    fn layout_record_foreground_error(cwd: PathBuf) -> NewTabForegroundError {
        NewTabForegroundError::LayoutRecord {
            cwd,
            error: NewTabLayoutRecordError::WindowLayout(
                maestro_shell::window_layout::WindowLayoutError::WindowLayoutNotFound {
                    window_id: s("w-missing"),
                },
            ),
        }
    }

    #[test]
    fn plan_new_tab_failure_recovery_maps_every_stage_to_action_intents() {
        let cwd = PathBuf::from("/tmp/maestro-recovery-plan");
        let cases = vec![
            (
                NewTabForegroundError::WorkspacePrepare(NewTabWorkspacePrepareError::NotCreate),
                NewTabFailureStage::WorkspacePrepare,
                vec![],
            ),
            (
                NewTabForegroundError::StartParams {
                    cwd: cwd.join("start-params"),
                    scratch: None,
                    error: NewTabStartParamsError::NotCreate,
                },
                NewTabFailureStage::StartParams,
                vec![],
            ),
            (
                session_start_foreground_error(cwd.join("session-start")),
                NewTabFailureStage::SessionStart,
                vec![],
            ),
            (
                layout_record_foreground_error(cwd.join("layout-record")),
                NewTabFailureStage::LayoutRecord,
                vec![NewTabRecoveryAction::KillStartedSession],
            ),
            (
                NewTabForegroundError::Projection(NewTabStripProjectionError::ActiveTabNotFound {
                    tab_id: s("tab-missing"),
                }),
                NewTabFailureStage::Projection,
                vec![
                    NewTabRecoveryAction::RollbackTabRecord,
                    NewTabRecoveryAction::KillStartedSession,
                ],
            ),
            (
                NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed),
                NewTabFailureStage::SetTabStrip,
                vec![
                    NewTabRecoveryAction::RollbackTabRecord,
                    NewTabRecoveryAction::RevertRendererStrip,
                    NewTabRecoveryAction::KillStartedSession,
                ],
            ),
            (
                NewTabForegroundError::AttachSession(
                    NewTabAttachSessionError::RendererControlClosed,
                ),
                NewTabFailureStage::AttachSession,
                vec![
                    NewTabRecoveryAction::RollbackTabRecord,
                    NewTabRecoveryAction::ReconcileRendererState,
                    NewTabRecoveryAction::KillStartedSession,
                ],
            ),
        ];

        for (err, stage, actions) in cases {
            let plan = plan_new_tab_failure_recovery(&err);
            assert_eq!(plan.diagnostic.stage, stage);
            assert_eq!(plan.actions, actions);
        }
    }

    #[test]
    fn plan_new_tab_failure_recovery_reuses_scratch_cleanup_decision() {
        let cwd = PathBuf::from("/tmp/maestro-recovery-scratch");
        let cases = vec![
            NewTabForegroundError::WorkspacePrepare(NewTabWorkspacePrepareError::NotCreate),
            NewTabForegroundError::StartParams {
                cwd: cwd.join("start-params"),
                scratch: None,
                error: NewTabStartParamsError::NotCreate,
            },
            session_start_foreground_error(cwd.join("session-start")),
            layout_record_foreground_error(cwd.join("layout-record")),
            NewTabForegroundError::Projection(NewTabStripProjectionError::ActiveTabNotFound {
                tab_id: s("tab-missing"),
            }),
            NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed),
            NewTabForegroundError::AttachSession(NewTabAttachSessionError::RendererControlClosed),
        ];

        for err in cases {
            let expected = new_tab_failure_scratch_to_remove(&err).map(Path::to_path_buf);
            let planned = plan_new_tab_failure_recovery(&err)
                .actions
                .into_iter()
                .find_map(|action| match action {
                    NewTabRecoveryAction::RemoveScratch(cwd) => Some(cwd),
                    NewTabRecoveryAction::KillStartedSession
                    | NewTabRecoveryAction::RollbackTabRecord
                    | NewTabRecoveryAction::RevertRendererStrip
                    | NewTabRecoveryAction::ReconcileRendererState => None,
                });
            assert_eq!(planned, expected);
        }
    }

    #[test]
    fn plan_new_tab_failure_recovery_orders_post_record_recovery_before_any_scratch_handling() {
        let err = NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed);
        let plan = plan_new_tab_failure_recovery(&err);

        assert_eq!(
            plan.actions.first(),
            Some(&NewTabRecoveryAction::RollbackTabRecord),
            "post-record recovery starts with durable rollback intent"
        );
        assert_eq!(
            plan.actions.get(1),
            Some(&NewTabRecoveryAction::RevertRendererStrip),
            "renderer strip restoration follows the rollback intent"
        );
        assert!(
            !plan
                .actions
                .iter()
                .any(|action| matches!(action, NewTabRecoveryAction::RemoveScratch(_))),
            "post-record recovery never plans scratch deletion while a TabRecord may reference it"
        );
    }

    fn recovery_context_with_saved_strip() -> NewTabRecoveryContext {
        NewTabRecoveryContext {
            window_id: Some(s("w1")),
            tab_id: Some(s("tab-new")),
            session_id: Some(s("sess-new")),
            session_generation: Some(s("gen-new")),
            previous_strip_tabs: Some(vec![snapshot_tab("tab-old", "sess-old", 0)]),
            previous_selection: Some(vec![TabSelection {
                tab_id: s("tab-old"),
                session_id: s("sess-old"),
            }]),
            scratch_cwd: Some(PathBuf::from("/tmp/maestro-recovery-context")),
        }
    }

    #[test]
    fn resolve_new_tab_recovery_plan_preserves_order_and_attaches_context() {
        let err = NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed);
        let plan = plan_new_tab_failure_recovery(&err);
        let context = recovery_context_with_saved_strip();
        let strip_tabs = context.previous_strip_tabs.clone().expect("strip");
        let selection = context.previous_selection.clone().expect("selection");

        let resolved = resolve_new_tab_recovery_plan(&plan, &context);

        assert_eq!(resolved.diagnostic, plan.diagnostic);
        assert_eq!(
            resolved.actions,
            vec![
                ResolvedNewTabRecoveryAction::RollbackTabRecord {
                    window_id: s("w1"),
                    tab_id: s("tab-new"),
                },
                ResolvedNewTabRecoveryAction::RevertRendererStrip {
                    strip_tabs,
                    selection,
                },
                ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                    session_id: s("sess-new"),
                    expected_generation: s("gen-new"),
                },
            ],
            "resolved actions preserve planner order while attaching concrete state"
        );
    }

    #[test]
    fn resolve_new_tab_recovery_plan_missing_session_does_not_invent_kill_target() {
        let err = layout_record_foreground_error(PathBuf::from("/tmp/maestro-no-session"));
        let plan = plan_new_tab_failure_recovery(&err);
        let context = NewTabRecoveryContext {
            scratch_cwd: Some(PathBuf::from("/tmp/maestro-no-session")),
            ..Default::default()
        };

        let resolved = resolve_new_tab_recovery_plan(&plan, &context);

        assert_eq!(
            resolved.actions,
            vec![ResolvedNewTabRecoveryAction::MissingSessionForKill],
            "missing session context is explicit, while a path-only cwd grants no scratch cleanup authority"
        );
    }

    #[test]
    fn resolve_new_tab_recovery_plan_requires_window_and_tab_for_record_rollback() {
        let err =
            NewTabForegroundError::Projection(NewTabStripProjectionError::ActiveTabNotFound {
                tab_id: s("tab-missing"),
            });
        let plan = plan_new_tab_failure_recovery(&err);
        let context = NewTabRecoveryContext {
            session_id: Some(s("sess-new")),
            session_generation: Some(s("gen-new")),
            ..Default::default()
        };

        let resolved = resolve_new_tab_recovery_plan(&plan, &context);

        assert_eq!(
            resolved.actions,
            vec![
                ResolvedNewTabRecoveryAction::MissingTabRecordTarget,
                ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                    session_id: s("sess-new"),
                    expected_generation: s("gen-new"),
                },
            ]
        );
    }

    #[test]
    fn resolve_new_tab_recovery_plan_carries_reconcile_state_when_present() {
        let err =
            NewTabForegroundError::AttachSession(NewTabAttachSessionError::RendererControlClosed);
        let plan = plan_new_tab_failure_recovery(&err);
        let context = recovery_context_with_saved_strip();
        let strip_tabs = context.previous_strip_tabs.clone().expect("strip");
        let selection = context.previous_selection.clone().expect("selection");

        let resolved = resolve_new_tab_recovery_plan(&plan, &context);

        assert_eq!(
            resolved.actions,
            vec![
                ResolvedNewTabRecoveryAction::RollbackTabRecord {
                    window_id: s("w1"),
                    tab_id: s("tab-new"),
                },
                ResolvedNewTabRecoveryAction::ReconcileRendererState {
                    strip_tabs,
                    selection,
                },
                ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                    session_id: s("sess-new"),
                    expected_generation: s("gen-new"),
                },
            ]
        );
    }

    #[test]
    fn resolve_new_tab_recovery_plan_does_not_enable_post_record_scratch_from_context() {
        let err =
            NewTabForegroundError::Projection(NewTabStripProjectionError::ActiveTabNotFound {
                tab_id: s("tab-missing"),
            });
        let plan = plan_new_tab_failure_recovery(&err);
        let context = NewTabRecoveryContext {
            window_id: Some(s("w1")),
            tab_id: Some(s("tab-new")),
            session_id: Some(s("sess-new")),
            session_generation: Some(s("gen-new")),
            scratch_cwd: Some(PathBuf::from("/tmp/must-not-remove")),
            ..Default::default()
        };

        let resolved = resolve_new_tab_recovery_plan(&plan, &context);

        assert!(
            !resolved
                .actions
                .iter()
                .any(|action| matches!(action, ResolvedNewTabRecoveryAction::RemoveScratch(_))),
            "post-record stages remain no-scratch even when context has a scratch cwd"
        );
    }

    #[test]
    fn resolve_new_tab_recovery_matches_plan_then_resolve_for_pre_and_post_record_stages() {
        let context = recovery_context_with_saved_strip();

        let pre_record = layout_record_foreground_error(PathBuf::from("/tmp/maestro-one-call-pre"));
        assert_eq!(
            resolve_new_tab_recovery(&pre_record, &context),
            resolve_new_tab_recovery_plan(&plan_new_tab_failure_recovery(&pre_record), &context),
            "one-call resolve equals plan-then-resolve for a pre-record stage"
        );

        let post_record =
            NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed);
        assert_eq!(
            resolve_new_tab_recovery(&post_record, &context),
            resolve_new_tab_recovery_plan(&plan_new_tab_failure_recovery(&post_record), &context),
            "one-call resolve equals plan-then-resolve for a post-record stage"
        );
    }

    // NewTab recovery EXECUTOR tests (`execute_new_tab_recovery_plan_*`,
    // `execute_resolved_new_tab_recovery_plan_*`) and the resolved-plan log-render tests
    // (`render_resolved_recovery_log_line_*`) now live here beside `execute_new_tab_recovery_plan`,
    // `execute_resolved_new_tab_recovery_plan`, and `render_resolved_recovery_log_line` (reached via
    // `use super::*;`). Effects, live, and end-to-end tests use the crate-level
    // `resolved_recovery_plan`; the helper below is private to `new_tab::tests`.

    #[derive(Default)]
    struct FakeNewTabRecoveryEffects {
        calls: Vec<String>,
        fail_on: Option<&'static str>,
    }

    impl FakeNewTabRecoveryEffects {
        fn finish(&mut self, name: &'static str) -> Result<(), String> {
            self.calls.push(name.to_string());
            if self.fail_on == Some(name) {
                Err(format!("{name} failed"))
            } else {
                Ok(())
            }
        }
    }

    impl NewTabRecoveryEffects for FakeNewTabRecoveryEffects {
        type Error = String;

        fn remove_scratch(&mut self, cwd: &Path) -> Result<(), Self::Error> {
            self.calls.push(format!("remove_scratch:{}", cwd.display()));
            if self.fail_on == Some("remove_scratch") {
                Err("remove_scratch failed".to_string())
            } else {
                Ok(())
            }
        }

        fn kill_started_session(&mut self) -> Result<(), Self::Error> {
            self.finish("kill_started_session")
        }

        fn rollback_tab_record(&mut self) -> Result<(), Self::Error> {
            self.finish("rollback_tab_record")
        }

        fn revert_renderer_strip(&mut self) -> Result<(), Self::Error> {
            self.finish("revert_renderer_strip")
        }

        fn reconcile_renderer_state(&mut self) -> Result<(), Self::Error> {
            self.finish("reconcile_renderer_state")
        }
    }

    #[test]
    fn execute_new_tab_recovery_plan_invokes_actions_in_plan_order() {
        let err = NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed);
        let plan = plan_new_tab_failure_recovery(&err);
        let mut effects = FakeNewTabRecoveryEffects::default();

        let report = execute_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(
            effects.calls,
            vec![
                "rollback_tab_record",
                "revert_renderer_strip",
                "kill_started_session"
            ]
        );
        assert_eq!(report.diagnostic, plan.diagnostic);
        assert_eq!(
            report
                .outcomes
                .iter()
                .map(|outcome| outcome.action.clone())
                .collect::<Vec<_>>(),
            plan.actions
        );
        assert_eq!(report.failed_count(), 0);
        assert!(report
            .outcomes
            .iter()
            .all(NewTabRecoveryActionOutcome::is_ok));
    }

    #[test]
    fn execute_new_tab_recovery_plan_reports_failure_and_continues() {
        let err = NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed);
        let plan = plan_new_tab_failure_recovery(&err);
        let mut effects = FakeNewTabRecoveryEffects {
            fail_on: Some("rollback_tab_record"),
            ..Default::default()
        };

        let report = execute_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(
            effects.calls,
            vec![
                "rollback_tab_record",
                "revert_renderer_strip",
                "kill_started_session",
            ],
            "renderer recovery and generation-bound cleanup still run after rollback failure"
        );
        assert_eq!(report.outcomes.len(), 3);
        assert_eq!(
            report.outcomes[0],
            NewTabRecoveryActionOutcome::failed(
                NewTabRecoveryAction::RollbackTabRecord,
                "rollback_tab_record failed"
            )
        );
        assert_eq!(
            report.outcomes[1],
            NewTabRecoveryActionOutcome::ok(NewTabRecoveryAction::RevertRendererStrip)
        );
        assert_eq!(
            report.outcomes[2],
            NewTabRecoveryActionOutcome::ok(NewTabRecoveryAction::KillStartedSession)
        );
        assert_eq!(report.failed_count(), 1);
    }

    #[test]
    fn execute_new_tab_recovery_plan_empty_plan_dispatches_nothing() {
        let err = NewTabForegroundError::WorkspacePrepare(NewTabWorkspacePrepareError::NotCreate);
        let plan = plan_new_tab_failure_recovery(&err);
        let mut effects = FakeNewTabRecoveryEffects::default();

        let report = execute_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(plan.actions, Vec::<NewTabRecoveryAction>::new());
        assert!(effects.calls.is_empty());
        assert!(report.outcomes.is_empty());
        assert_eq!(report.failed_count(), 0);
        assert_eq!(
            report.diagnostic.stage,
            NewTabFailureStage::WorkspacePrepare
        );
    }

    #[derive(Default)]
    struct FakeResolvedNewTabRecoveryEffects {
        calls: Vec<String>,
        fail_on: Option<&'static str>,
        skip_on: Vec<(&'static str, &'static str)>,
    }

    impl FakeResolvedNewTabRecoveryEffects {
        fn finish(
            &mut self,
            name: &'static str,
        ) -> Result<ResolvedNewTabRecoveryEffectResult, String> {
            if self.fail_on == Some(name) {
                Err(format!("{name} failed"))
            } else if let Some((_, reason)) = self
                .skip_on
                .iter()
                .find(|(skip_name, _)| *skip_name == name)
            {
                Ok(ResolvedNewTabRecoveryEffectResult::skipped(*reason))
            } else {
                Ok(ResolvedNewTabRecoveryEffectResult::Succeeded)
            }
        }
    }

    impl ResolvedNewTabRecoveryEffects for FakeResolvedNewTabRecoveryEffects {
        type Error = String;

        fn remove_scratch(
            &mut self,
            cwd: &Path,
        ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
            self.calls.push(format!("remove_scratch:{}", cwd.display()));
            self.finish("remove_scratch")
        }

        fn kill_session(
            &mut self,
            session_id: &str,
            _expected_generation: &str,
        ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
            self.calls.push(format!("kill_session:{session_id}"));
            self.finish("kill_session")
        }

        fn rollback_tab_record(
            &mut self,
            window_id: &str,
            tab_id: &str,
        ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
            self.calls
                .push(format!("rollback_tab_record:{window_id}:{tab_id}"));
            self.finish("rollback_tab_record")
        }

        fn revert_renderer_strip(
            &mut self,
            strip_tabs: &[WindowTabJson],
            selection: &[TabSelection],
        ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
            self.calls.push(format!(
                "revert_renderer_strip:{}:{}",
                strip_tabs.len(),
                selection.len()
            ));
            self.finish("revert_renderer_strip")
        }

        fn reconcile_renderer_state(
            &mut self,
            strip_tabs: &[WindowTabJson],
            selection: &[TabSelection],
        ) -> Result<ResolvedNewTabRecoveryEffectResult, Self::Error> {
            self.calls.push(format!(
                "reconcile_renderer_state:{}:{}",
                strip_tabs.len(),
                selection.len()
            ));
            self.finish("reconcile_renderer_state")
        }
    }

    fn resolved_recovery_plan(
        actions: Vec<ResolvedNewTabRecoveryAction>,
    ) -> ResolvedNewTabRecoveryPlan {
        let err = NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed);
        ResolvedNewTabRecoveryPlan {
            diagnostic: classify_new_tab_foreground_failure(&err),
            actions,
        }
    }

    #[test]
    fn execute_resolved_new_tab_recovery_plan_invokes_actions_in_plan_order() {
        let saved_tabs = vec![snapshot_tab("tab-old", "sess-old", 0)];
        let saved_selection = vec![TabSelection {
            tab_id: s("tab-old"),
            session_id: s("sess-old"),
        }];
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::RollbackTabRecord {
                window_id: s("w1"),
                tab_id: s("tab-new"),
            },
            ResolvedNewTabRecoveryAction::RevertRendererStrip {
                strip_tabs: saved_tabs,
                selection: saved_selection,
            },
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id: s("sess-new"),
                expected_generation: s("gen-new"),
            },
        ]);
        let mut effects = FakeResolvedNewTabRecoveryEffects::default();

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(
            effects.calls,
            vec![
                "rollback_tab_record:w1:tab-new",
                "revert_renderer_strip:1:1",
                "kill_session:sess-new",
            ]
        );
        assert_eq!(
            report
                .outcomes
                .iter()
                .map(|outcome| outcome.action.clone())
                .collect::<Vec<_>>(),
            plan.actions
        );
        assert_eq!(report.succeeded_count(), 3);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 0);
    }

    #[test]
    fn execute_resolved_new_tab_recovery_plan_reports_missing_and_idempotent_skips() {
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::MissingSessionForKill,
            ResolvedNewTabRecoveryAction::MissingTabRecordTarget,
            ResolvedNewTabRecoveryAction::RemoveScratch(PathBuf::from("/tmp/missing-scratch")),
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id: s("sess-already-gone"),
                expected_generation: s("gen-already-gone"),
            },
        ]);
        let mut effects = FakeResolvedNewTabRecoveryEffects {
            skip_on: vec![
                ("remove_scratch", "scratch_missing"),
                ("kill_session", "session_already_gone"),
            ],
            ..Default::default()
        };

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(
            effects.calls,
            vec![
                "remove_scratch:/tmp/missing-scratch",
                "kill_session:sess-already-gone"
            ],
            "missing-target actions are reported directly and do not dispatch effects"
        );
        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 4);
        assert_eq!(report.failed_count(), 0);
        assert_eq!(
            report.outcomes[0],
            ResolvedNewTabRecoveryActionOutcome::skipped(
                ResolvedNewTabRecoveryAction::MissingSessionForKill,
                "missing_session_for_kill"
            )
        );
        assert_eq!(
            report.outcomes[1],
            ResolvedNewTabRecoveryActionOutcome::skipped(
                ResolvedNewTabRecoveryAction::MissingTabRecordTarget,
                "missing_tab_record_target"
            )
        );
        assert_eq!(
            report.outcomes[2].status,
            ResolvedNewTabRecoveryActionStatus::Skipped {
                reason: s("scratch_missing")
            }
        );
        assert_eq!(
            report.outcomes[3].status,
            ResolvedNewTabRecoveryActionStatus::Skipped {
                reason: s("session_already_gone")
            }
        );
    }

    #[test]
    fn execute_resolved_new_tab_recovery_plan_reports_failure_and_continues() {
        let saved_tabs = vec![snapshot_tab("tab-old", "sess-old", 0)];
        let saved_selection = vec![TabSelection {
            tab_id: s("tab-old"),
            session_id: s("sess-old"),
        }];
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::RollbackTabRecord {
                window_id: s("w1"),
                tab_id: s("tab-new"),
            },
            ResolvedNewTabRecoveryAction::ReconcileRendererState {
                strip_tabs: saved_tabs,
                selection: saved_selection,
            },
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id: s("sess-new"),
                expected_generation: s("gen-new"),
            },
        ]);
        let mut effects = FakeResolvedNewTabRecoveryEffects {
            fail_on: Some("rollback_tab_record"),
            ..Default::default()
        };

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(
            effects.calls,
            vec![
                "rollback_tab_record:w1:tab-new",
                "reconcile_renderer_state:1:1",
                "kill_session:sess-new",
            ],
            "later actions still dispatch after a failed rollback"
        );
        assert_eq!(report.succeeded_count(), 2);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 1);
        assert_eq!(
            report.outcomes[0],
            ResolvedNewTabRecoveryActionOutcome::failed(
                ResolvedNewTabRecoveryAction::RollbackTabRecord {
                    window_id: s("w1"),
                    tab_id: s("tab-new"),
                },
                "rollback_tab_record failed"
            )
        );
        assert!(report.outcomes[1].status.is_succeeded());
        assert!(report.outcomes[2].status.is_succeeded());
    }

    #[test]
    fn render_resolved_recovery_log_line_is_single_line_with_stage_and_ordered_concrete_tokens() {
        let err = NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed);
        let context = recovery_context_with_saved_strip();
        let resolved = resolve_new_tab_recovery(&err, &context);

        let line = render_resolved_recovery_log_line(&resolved);

        assert!(!line.contains('\n'), "log line must be single-line");
        assert!(
            line.contains("stage=SetTabStrip"),
            "diagnostic stage stays visible in the report line: {line}"
        );

        let rollback = line
            .find("rollback_tab_record(w1,tab-new)")
            .expect("rollback");
        let revert = line.find("revert_renderer_strip(").expect("revert");
        let kill = line.find("kill_session(sess-new)").expect("kill");
        assert!(
            rollback < revert && revert < kill,
            "resolved action order is preserved in the rendered line: {line}"
        );
        assert!(
            !line.contains("missing"),
            "a fully-populated context renders no missing marker: {line}"
        );
    }

    #[test]
    fn render_resolved_recovery_log_line_marks_missing_post_record_context_distinctly() {
        let err = NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed);
        let resolved = resolve_new_tab_recovery(&err, &NewTabRecoveryContext::default());

        let line = render_resolved_recovery_log_line(&resolved);

        assert!(!line.contains('\n'), "log line must be single-line");
        assert!(line.contains("missing_tab_record_target"), "{line}");
        assert!(line.contains("missing_renderer_strip_state"), "{line}");
        assert!(line.contains("missing_session_for_kill"), "{line}");
        assert!(
            !line.contains("kill_session("),
            "an empty context must not invent a concrete kill id: {line}"
        );
    }

    #[test]
    fn foreground_new_tab_recovery_context_reports_concrete_post_record_targets() {
        let err = generation_bound_set_tab_strip_failure();
        let previous_strip_tabs = vec![snapshot_tab("tab-old", "sess-old", 0)];
        let previous_selection = vec![TabSelection {
            tab_id: s("tab-old"),
            session_id: s("sess-old"),
        }];

        let context = foreground_new_tab_recovery_context(
            "w-live",
            "tab-new",
            "sess-new",
            &previous_strip_tabs,
            &previous_selection,
            &err,
        );

        assert_eq!(context.window_id.as_deref(), Some("w-live"));
        assert_eq!(context.tab_id.as_deref(), Some("tab-new"));
        assert_eq!(context.session_id.as_deref(), Some("sess-new"));
        assert_eq!(context.previous_strip_tabs, Some(previous_strip_tabs));
        assert_eq!(context.previous_selection, Some(previous_selection));
        assert_eq!(context.scratch_cwd, None);

        let line = render_resolved_recovery_log_line(&resolve_new_tab_recovery(&err, &context));
        assert!(line.contains("stage=SetTabStrip"), "{line}");
        assert!(
            line.contains("rollback_tab_record(w-live,tab-new)"),
            "{line}"
        );
        assert!(
            line.contains("revert_renderer_strip(tabs=1,selection=1)"),
            "{line}"
        );
        assert!(line.contains("kill_session(sess-new)"), "{line}");
        assert!(
            !line.contains("missing"),
            "populated foreground context should resolve concrete report targets: {line}"
        );
    }

    #[test]
    fn foreground_new_tab_recovery_context_carries_pre_record_scratch_cleanup() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let (prepared, receipt) =
            maestro_shell::prepare_fresh_scratch_cwd(&paths, "ws-report", "sess-new", "")
                .expect("prepare fresh scratch")
                .into_parts();
        let cwd = prepared.cwd;
        let err = NewTabForegroundError::StartParams {
            cwd: cwd.clone(),
            scratch: Some(NewTabScratchRemovalAuthority::from_fresh_receipt(receipt)),
            error: NewTabStartParamsError::NotCreate,
        };

        let context =
            foreground_new_tab_recovery_context("w-live", "tab-new", "sess-new", &[], &[], &err);

        assert_eq!(context.scratch_cwd.as_deref(), Some(cwd.as_path()));

        let line = render_resolved_recovery_log_line(&resolve_new_tab_recovery(&err, &context));
        assert!(line.contains("stage=StartParams"), "{line}");
        assert!(
            !line.contains("kill_session(") && !line.contains("missing_session_for_kill"),
            "pre-start failure has no session cleanup action: {line}"
        );
        assert!(
            line.contains(&format!("remove_scratch({})", cwd.display())),
            "{line}"
        );
    }

    #[test]
    fn remove_new_tab_scratch_removes_existing_dir_and_missing_dir_errors() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scratch = tmp.path().join("scratch-cwd");
        std::fs::create_dir_all(scratch.join("nested")).expect("create scratch");
        std::fs::write(scratch.join("nested").join("marker"), b"orphan").expect("write marker");

        remove_new_tab_scratch(&scratch).expect("existing scratch dir is removed");
        assert!(!scratch.exists(), "scratch dir must be gone");

        let err = remove_new_tab_scratch(&scratch).expect_err("missing dir surfaces io error");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn remove_scratch_recovery_effect_succeeds_for_existing_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scratch = tmp.path().join("scratch-cwd");
        std::fs::create_dir_all(scratch.join("nested")).expect("create scratch");
        std::fs::write(scratch.join("nested").join("marker"), b"orphan").expect("write marker");

        let result =
            remove_scratch_recovery_effect(&scratch).expect("existing dir removes cleanly");
        assert_eq!(result, ResolvedNewTabRecoveryEffectResult::Succeeded);
        assert!(!scratch.exists(), "scratch dir must be gone");
    }

    #[test]
    fn remove_scratch_recovery_effect_skips_missing_dir_idempotently() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scratch = tmp.path().join("never-created");

        let result =
            remove_scratch_recovery_effect(&scratch).expect("missing dir is an idempotent skip");
        match result {
            ResolvedNewTabRecoveryEffectResult::Skipped { reason } => {
                assert!(
                    reason.contains("missing scratch dir"),
                    "skip reason must carry the stable marker, got: {reason}"
                );
            }
            ResolvedNewTabRecoveryEffectResult::Succeeded => {
                panic!("absent dir must report Skipped, not Succeeded")
            }
        }
    }

    #[test]
    fn render_resolved_recovery_execution_log_line_is_single_line_with_counts_and_ordered_outcomes()
    {
        let err = layout_record_foreground_error(PathBuf::from("/tmp/scratch-x"));
        let report = ResolvedNewTabRecoveryExecutionReport {
            diagnostic: classify_new_tab_foreground_failure(&err),
            outcomes: vec![
                ResolvedNewTabRecoveryActionOutcome::succeeded(
                    ResolvedNewTabRecoveryAction::RemoveScratch(PathBuf::from("/tmp/scratch-x")),
                ),
                ResolvedNewTabRecoveryActionOutcome::skipped(
                    ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                        session_id: s("sess-gone"),
                        expected_generation: s("gen-gone"),
                    },
                    "session already gone",
                ),
            ],
        };

        let line = render_resolved_recovery_execution_log_line(&report);

        assert!(
            !line.contains('\n'),
            "execution log line must be single-line"
        );
        assert!(line.contains("stage=LayoutRecord"), "{line}");
        assert!(line.contains("succeeded=1 skipped=1 failed=0"), "{line}");
        let scratch_at = line
            .find("remove_scratch(/tmp/scratch-x)=ok")
            .expect("scratch outcome rendered");
        let kill_at = line
            .find("kill_session(sess-gone)=skip(session already gone)")
            .expect("kill outcome rendered with reason");
        assert!(
            scratch_at < kill_at,
            "outcomes must preserve plan order: {line}"
        );
    }

    #[test]
    fn render_resolved_recovery_execution_log_line_renders_failed_outcome_with_error() {
        let err = generation_bound_set_tab_strip_failure();
        let report = ResolvedNewTabRecoveryExecutionReport {
            diagnostic: classify_new_tab_foreground_failure(&err),
            outcomes: vec![ResolvedNewTabRecoveryActionOutcome::failed(
                ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                    session_id: s("sess-new"),
                    expected_generation: s("gen-new"),
                },
                "daemon unavailable",
            )],
        };

        let line = render_resolved_recovery_execution_log_line(&report);

        assert!(line.contains("succeeded=0 skipped=0 failed=1"), "{line}");
        assert!(
            line.contains("kill_session(sess-new)=fail(daemon unavailable)"),
            "{line}"
        );
    }

    #[test]
    fn render_resolved_recovery_execution_log_line_for_effects_unavailable_is_single_line_with_no_actions(
    ) {
        // Effects-construction failure: the production effects object could not be built, so the
        // executor never ran and no per-action outcome exists. The live path must still emit ONE
        // deterministic diagnostic carrying the failure stage, never an ad-hoc fallback. A synthetic
        // zero-outcome report built straight from the resolved plan's diagnostic renders exactly that.
        let err = generation_bound_set_tab_strip_failure();
        let report = ResolvedNewTabRecoveryExecutionReport {
            diagnostic: classify_new_tab_foreground_failure(&err),
            outcomes: Vec::new(),
        };

        let line = render_resolved_recovery_execution_log_line(&report);

        assert!(
            !line.contains('\n'),
            "effects-unavailable diagnostic must be single-line: {line}"
        );
        assert!(line.contains("stage=SetTabStrip"), "{line}");
        assert!(line.contains("succeeded=0 skipped=0 failed=0"), "{line}");
        assert!(line.contains("outcomes=[]"), "{line}");
        assert!(
            !line.contains("=ok") && !line.contains("=skip(") && !line.contains("=fail("),
            "no recovery action ran, so no per-action outcome token may appear: {line}"
        );
    }

    #[test]
    fn render_resolved_recovery_execution_log_line_matches_real_executor_report() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scratch = tmp.path().join("scratch-cwd");
        std::fs::create_dir_all(&scratch).expect("create scratch");
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::RemoveScratch(scratch.clone()),
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id: s("sess-new"),
                expected_generation: s("gen-new"),
            },
        ]);
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let mut effects = ResolvedNewTabRecoveryLocalEffects::new(killer);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);
        let line = render_resolved_recovery_execution_log_line(&report);

        assert!(line.contains("succeeded=2 skipped=0 failed=0"), "{line}");
        assert!(
            line.contains(&format!("remove_scratch({})=ok", scratch.display())),
            "{line}"
        );
        assert!(line.contains("kill_session(sess-new)=ok"), "{line}");
    }

    struct FakeRecoverySessionKiller {
        result: Result<KillSessionRecoveryEffectResult, String>,
        calls: Vec<String>,
    }

    impl NewTabRecoverySessionKiller for FakeRecoverySessionKiller {
        type Error = String;

        fn kill_session(
            &mut self,
            session_id: &str,
            expected_generation: &str,
        ) -> Result<KillSessionRecoveryEffectResult, Self::Error> {
            self.calls
                .push(format!("{session_id}@{expected_generation}"));
            self.result.clone()
        }
    }

    #[test]
    fn new_tab_kill_session_recovery_effect_succeeds_for_killed_session() {
        let mut killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };

        let result = kill_session_recovery_effect("sess-new", "gen-new", &mut killer)
            .expect("kill succeeds");

        assert_eq!(killer.calls, vec![s("sess-new@gen-new")]);
        assert_eq!(result, ResolvedNewTabRecoveryEffectResult::Succeeded);
    }

    #[test]
    fn new_tab_kill_session_recovery_effect_skips_already_gone_session() {
        let mut killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::AlreadyGone),
            calls: Vec::new(),
        };

        let result = kill_session_recovery_effect("sess-gone", "gen-gone", &mut killer)
            .expect("already-gone session is idempotent");

        assert_eq!(killer.calls, vec![s("sess-gone@gen-gone")]);
        assert_eq!(
            result,
            ResolvedNewTabRecoveryEffectResult::Skipped {
                reason: s("session already gone")
            }
        );
    }

    #[test]
    fn new_tab_kill_session_recovery_effect_propagates_failure() {
        let mut killer = FakeRecoverySessionKiller {
            result: Err(s("daemon unavailable")),
            calls: Vec::new(),
        };

        let err = kill_session_recovery_effect("sess-new", "gen-new", &mut killer)
            .expect_err("genuine kill failure is propagated");

        assert_eq!(killer.calls, vec![s("sess-new@gen-new")]);
        assert_eq!(err, "daemon unavailable");
    }

    #[test]
    fn new_tab_rollback_tab_record_recovery_effect_removes_existing_tab_record() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_exact_test_session(&paths, "sess-t0", "gen-t0");
        seed_exact_test_session(&paths, "sess-new", "gen-new");
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create layout");
        service
            .open_tab(
                "w1",
                "t0",
                "sess-t0",
                "old",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed old tab");
        service
            .open_tab(
                "w1",
                "tab-new",
                "sess-new",
                "new",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed new tab");

        let result = rollback_tab_record_recovery_effect(&paths, "w1", "tab-new", 42)
            .expect("rollback succeeds");

        assert_eq!(result, ResolvedNewTabRecoveryEffectResult::Succeeded);
        let reloaded = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load layout")
            .expect("layout exists");
        assert_eq!(reloaded.tabs.len(), 1);
        assert_eq!(reloaded.tabs[0].tab_id, "t0");
        assert_eq!(
            reloaded.tabs[0].index, 0,
            "remaining tab index is compacted"
        );
    }

    #[test]
    fn new_tab_rollback_tab_record_recovery_effect_skips_missing_targets() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create layout");
        service
            .open_tab(
                "w1",
                "t0",
                "sess-t0",
                "old",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed old tab");

        let missing_tab = rollback_tab_record_recovery_effect(&paths, "w1", "tab-new", 1)
            .expect("missing tab is idempotent");
        let missing_window =
            rollback_tab_record_recovery_effect(&paths, "missing-window", "tab-new", 1)
                .expect("missing window is idempotent");

        assert_eq!(
            missing_tab,
            ResolvedNewTabRecoveryEffectResult::Skipped {
                reason: s("tab record already absent")
            }
        );
        assert_eq!(
            missing_window,
            ResolvedNewTabRecoveryEffectResult::Skipped {
                reason: s("window layout already absent")
            }
        );
        let reloaded = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load layout")
            .expect("layout exists");
        assert_eq!(
            reloaded.tabs.len(),
            1,
            "idempotent skips must leave existing layout untouched"
        );
        assert_eq!(reloaded.tabs[0].tab_id, "t0");
    }

    #[test]
    fn new_tab_rollback_tab_record_recovery_effect_propagates_store_error() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());

        let err = rollback_tab_record_recovery_effect(&paths, "../escape", "tab-new", 1)
            .expect_err("unsafe window id must propagate as a failure");

        match err {
            maestro_shell::window_layout::WindowLayoutError::Store(_) => {}
            other => panic!("expected Store error, got {other:?}"),
        }
    }

    // ---- NewTab renderer-state recovery effects ----
    //
    // These exercise `revert_renderer_strip_recovery_effect`,
    // `reconcile_renderer_state_recovery_effect`, and the
    // `NewTabRecoveryRendererStateController` contract. `FakeRendererStateController`
    // and `renderer_state_payload` are private copies here; `lib.rs` retains its own
    // copies because local/complete/end-to-end recovery tests still call them.

    #[derive(Clone, Debug)]
    struct FakeRendererStateController {
        revert_result: Result<RendererStateRecoveryEffectResult, String>,
        reconcile_result: Result<RendererStateRecoveryEffectResult, String>,
        calls: Vec<String>,
    }

    impl NewTabRecoveryRendererStateController for FakeRendererStateController {
        type Error = String;

        fn revert_renderer_strip(
            &mut self,
            strip_tabs: &[WindowTabJson],
            selection: &[TabSelection],
        ) -> Result<RendererStateRecoveryEffectResult, Self::Error> {
            self.calls.push(format!(
                "revert:{}:{}:{}",
                strip_tabs.len(),
                selection.len(),
                strip_tabs
                    .iter()
                    .map(|tab| tab.tab_id.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            self.revert_result.clone()
        }

        fn reconcile_renderer_state(
            &mut self,
            strip_tabs: &[WindowTabJson],
            selection: &[TabSelection],
        ) -> Result<RendererStateRecoveryEffectResult, Self::Error> {
            self.calls.push(format!(
                "reconcile:{}:{}:{}",
                strip_tabs.len(),
                selection.len(),
                selection
                    .iter()
                    .map(|sel| sel.session_id.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            ));
            self.reconcile_result.clone()
        }
    }

    fn renderer_state_payload() -> (Vec<WindowTabJson>, Vec<TabSelection>) {
        (
            vec![
                snapshot_tab("tab-old", "sess-old", 0),
                snapshot_tab("tab-other", "sess-other", 1),
            ],
            vec![
                TabSelection {
                    tab_id: s("tab-old"),
                    session_id: s("sess-old"),
                },
                TabSelection {
                    tab_id: s("tab-other"),
                    session_id: s("sess-other"),
                },
            ],
        )
    }

    #[test]
    fn new_tab_revert_renderer_strip_recovery_effect_succeeds_through_injected_controller() {
        let (strip_tabs, selection) = renderer_state_payload();
        let mut controller = FakeRendererStateController {
            revert_result: Ok(RendererStateRecoveryEffectResult::Restored),
            reconcile_result: Ok(RendererStateRecoveryEffectResult::AlreadyCurrent),
            calls: Vec::new(),
        };

        let result =
            revert_renderer_strip_recovery_effect(&strip_tabs, &selection, &mut controller)
                .expect("revert succeeds");

        assert_eq!(result, ResolvedNewTabRecoveryEffectResult::Succeeded);
        assert_eq!(controller.calls, vec![s("revert:2:2:tab-old,tab-other")]);
    }

    #[test]
    fn new_tab_renderer_state_recovery_effects_report_idempotent_skips() {
        let (strip_tabs, selection) = renderer_state_payload();
        let mut controller = FakeRendererStateController {
            revert_result: Ok(RendererStateRecoveryEffectResult::AlreadyCurrent),
            reconcile_result: Ok(RendererStateRecoveryEffectResult::AlreadyCurrent),
            calls: Vec::new(),
        };

        let revert =
            revert_renderer_strip_recovery_effect(&strip_tabs, &selection, &mut controller)
                .expect("already-current revert is idempotent");
        let reconcile =
            reconcile_renderer_state_recovery_effect(&strip_tabs, &selection, &mut controller)
                .expect("already-reconciled state is idempotent");

        assert_eq!(
            revert,
            ResolvedNewTabRecoveryEffectResult::Skipped {
                reason: s("renderer strip already current")
            }
        );
        assert_eq!(
            reconcile,
            ResolvedNewTabRecoveryEffectResult::Skipped {
                reason: s("renderer state already reconciled")
            }
        );
        assert_eq!(
            controller.calls,
            vec![
                s("revert:2:2:tab-old,tab-other"),
                s("reconcile:2:2:sess-old,sess-other")
            ]
        );
    }

    #[test]
    fn new_tab_renderer_state_recovery_effects_propagate_failures() {
        let (strip_tabs, selection) = renderer_state_payload();
        let mut controller = FakeRendererStateController {
            revert_result: Err(s("renderer control closed")),
            reconcile_result: Err(s("ambiguous active state")),
            calls: Vec::new(),
        };

        let revert_err =
            revert_renderer_strip_recovery_effect(&strip_tabs, &selection, &mut controller)
                .expect_err("revert failure must propagate");
        let reconcile_err =
            reconcile_renderer_state_recovery_effect(&strip_tabs, &selection, &mut controller)
                .expect_err("reconcile failure must propagate");

        assert_eq!(revert_err, "renderer control closed");
        assert_eq!(reconcile_err, "ambiguous active state");
        assert_eq!(
            controller.calls,
            vec![
                s("revert:2:2:tab-old,tab-other"),
                s("reconcile:2:2:sess-old,sess-other")
            ]
        );
    }

    enum ContractRendererStateMode {
        AdoptAfterRendererCommand,
        AlreadyCorrect,
        AmbiguousActiveState,
    }

    struct ContractRendererStateController {
        runtime: RendererTabRuntime,
        window_id: String,
        active_tab_id: Option<String>,
        mode: ContractRendererStateMode,
        adopted_strip_tabs: Option<Vec<WindowTabJson>>,
        adopted_selection: Option<Vec<TabSelection>>,
    }

    impl ContractRendererStateController {
        fn restore_renderer_projection(
            &mut self,
            strip_tabs: &[WindowTabJson],
            selection: &[TabSelection],
        ) -> Result<RendererStateRecoveryEffectResult, TabSwitchError> {
            let model =
                build_tab_strip_model(&self.window_id, strip_tabs, self.active_tab_id.as_deref())
                    .expect("contract test payload builds a valid strip model");
            self.runtime.set_tab_strip(Some(&model))?;
            self.adopted_strip_tabs = Some(strip_tabs.to_vec());
            self.adopted_selection = Some(selection.to_vec());
            Ok(RendererStateRecoveryEffectResult::Restored)
        }
    }

    impl NewTabRecoveryRendererStateController for ContractRendererStateController {
        type Error = TabSwitchError;

        fn revert_renderer_strip(
            &mut self,
            strip_tabs: &[WindowTabJson],
            selection: &[TabSelection],
        ) -> Result<RendererStateRecoveryEffectResult, Self::Error> {
            match self.mode {
                ContractRendererStateMode::AdoptAfterRendererCommand => {
                    self.restore_renderer_projection(strip_tabs, selection)
                }
                ContractRendererStateMode::AlreadyCorrect => {
                    // This mode represents an independently reviewed exact-current signal. It is
                    // deliberately not derived from the runtime's textual compatibility getters.
                    Ok(RendererStateRecoveryEffectResult::AlreadyCurrent)
                }
                ContractRendererStateMode::AmbiguousActiveState => {
                    let duplicate_active_count = self
                        .active_tab_id
                        .as_deref()
                        .map(|active| {
                            selection
                                .iter()
                                .filter(|candidate| candidate.tab_id == active)
                                .count()
                        })
                        .unwrap_or_default();
                    assert!(
                        duplicate_active_count > 1,
                        "ambiguous-active contract test must carry duplicate active selections"
                    );
                    Ok(RendererStateRecoveryEffectResult::AlreadyCurrent)
                }
            }
        }

        fn reconcile_renderer_state(
            &mut self,
            strip_tabs: &[WindowTabJson],
            selection: &[TabSelection],
        ) -> Result<RendererStateRecoveryEffectResult, Self::Error> {
            match self.mode {
                ContractRendererStateMode::AdoptAfterRendererCommand => {
                    self.restore_renderer_projection(strip_tabs, selection)
                }
                ContractRendererStateMode::AlreadyCorrect => {
                    // See the matching `revert` arm: the test injects the proof classification.
                    Ok(RendererStateRecoveryEffectResult::AlreadyCurrent)
                }
                ContractRendererStateMode::AmbiguousActiveState => {
                    let duplicate_active_count = self
                        .active_tab_id
                        .as_deref()
                        .map(|active| {
                            selection
                                .iter()
                                .filter(|candidate| candidate.tab_id == active)
                                .count()
                        })
                        .unwrap_or_default();
                    assert!(
                        duplicate_active_count > 1,
                        "ambiguous-active contract test must carry duplicate active selections"
                    );
                    Ok(RendererStateRecoveryEffectResult::AlreadyCurrent)
                }
            }
        }
    }

    #[test]
    fn new_tab_renderer_state_controller_contract_preserves_failure_and_adoption_boundaries() {
        let (strip_tabs, selection) = renderer_state_payload();

        let (runtime, rx) = RendererTabRuntime::new();
        let mut controller = ContractRendererStateController {
            runtime,
            window_id: s("w-live"),
            active_tab_id: Some(s("tab-old")),
            mode: ContractRendererStateMode::AdoptAfterRendererCommand,
            adopted_strip_tabs: None,
            adopted_selection: None,
        };

        let refused =
            revert_renderer_strip_recovery_effect(&strip_tabs, &selection, &mut controller)
                .expect_err("presentation-only restore has no exact viewport authority");
        assert_eq!(refused, TabSwitchError::ViewportAuthorityRequired);
        assert!(controller.adopted_strip_tabs.is_none());
        assert!(controller.adopted_selection.is_none());
        assert!(
            matches!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "authority refusal sends no renderer command"
        );

        let (runtime, closed_rx) = RendererTabRuntime::new();
        drop(closed_rx);
        let closed_controller = ContractRendererStateController {
            runtime,
            window_id: s("w-live"),
            active_tab_id: Some(s("tab-old")),
            mode: ContractRendererStateMode::AdoptAfterRendererCommand,
            adopted_strip_tabs: None,
            adopted_selection: None,
        };
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let mut effects =
            ResolvedNewTabRecoveryCompleteEffects::new(paths, 1, killer, closed_controller);
        let failed_plan =
            resolved_recovery_plan(vec![ResolvedNewTabRecoveryAction::RevertRendererStrip {
                strip_tabs: strip_tabs.clone(),
                selection: selection.clone(),
            }]);

        let failed_report = execute_resolved_new_tab_recovery_plan(&failed_plan, &mut effects);

        assert_eq!(failed_report.succeeded_count(), 0);
        assert_eq!(failed_report.skipped_count(), 0);
        assert_eq!(failed_report.failed_count(), 1);
        let failed_line = render_resolved_recovery_execution_log_line(&failed_report);
        assert!(
            failed_line.contains(
                "revert_renderer_strip(tabs=2,selection=2)=fail(renderer switch requires an exact viewport authority)"
            ),
            "{failed_line}"
        );
        assert!(
            effects.renderer_controller().adopted_strip_tabs.is_none(),
            "listener projection must not be adopted when renderer command delivery fails"
        );
        assert!(
            effects.renderer_controller().adopted_selection.is_none(),
            "listener selection must not be adopted when renderer command delivery fails"
        );

        let (runtime, _rx) = RendererTabRuntime::new();
        let mut already_correct = ContractRendererStateController {
            runtime,
            window_id: s("w-live"),
            active_tab_id: Some(s("tab-old")),
            mode: ContractRendererStateMode::AlreadyCorrect,
            adopted_strip_tabs: None,
            adopted_selection: None,
        };

        let already_reconciled =
            reconcile_renderer_state_recovery_effect(&strip_tabs, &selection, &mut already_correct)
                .expect("already-correct state is a stable skip");

        assert_eq!(
            already_reconciled,
            ResolvedNewTabRecoveryEffectResult::Skipped {
                reason: s("renderer state already reconciled")
            }
        );
        assert!(
            already_correct.adopted_strip_tabs.is_none(),
            "idempotent skip must not rewrite listener projections"
        );

        let ambiguous_selection = vec![
            TabSelection {
                tab_id: s("tab-old"),
                session_id: s("sess-old"),
            },
            TabSelection {
                tab_id: s("tab-old"),
                session_id: s("sess-duplicate"),
            },
        ];
        let (runtime, _rx) = RendererTabRuntime::new();
        let mut ambiguous = ContractRendererStateController {
            runtime,
            window_id: s("w-live"),
            active_tab_id: Some(s("tab-old")),
            mode: ContractRendererStateMode::AmbiguousActiveState,
            adopted_strip_tabs: None,
            adopted_selection: None,
        };

        let ambiguous_skip = reconcile_renderer_state_recovery_effect(
            &strip_tabs,
            &ambiguous_selection,
            &mut ambiguous,
        )
        .expect("ambiguous active state is represented as an idempotent skip");

        assert_eq!(
            ambiguous_skip,
            ResolvedNewTabRecoveryEffectResult::Skipped {
                reason: s("renderer state already reconciled")
            }
        );
        assert!(
            ambiguous.adopted_strip_tabs.is_none(),
            "ambiguous/idempotent skip must not rewrite listener projections"
        );
    }

    // ---- NewTab filesystem + local recovery effects ----
    // Reach owning items (`ResolvedNewTabRecoveryFilesystemEffects` /
    // `ResolvedNewTabRecoveryLocalEffects` / `execute_resolved_new_tab_recovery_plan` /
    // `ResolvedNewTabRecoveryActionOutcome` / `ResolvedNewTabRecoveryActionStatus` /
    // `KillSessionRecoveryEffectResult`) via `use super::*;` and use the existing private
    // `new_tab::tests` copies of `resolved_recovery_plan` / `snapshot_tab` /
    // `FakeRecoverySessionKiller` / `s`. Complete / live / end-to-end recovery tests stay in
    // `lib.rs`.

    #[test]
    fn new_tab_filesystem_recovery_effects_remove_scratch_plan_removes_existing_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scratch = tmp.path().join("scratch-cwd");
        std::fs::create_dir_all(scratch.join("nested")).expect("create scratch");
        std::fs::write(scratch.join("nested").join("marker"), b"orphan").expect("write marker");
        let plan = resolved_recovery_plan(vec![ResolvedNewTabRecoveryAction::RemoveScratch(
            scratch.clone(),
        )]);
        let mut effects = ResolvedNewTabRecoveryFilesystemEffects;

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert!(!scratch.exists(), "scratch dir must be removed");
        assert_eq!(report.succeeded_count(), 1);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 0);
        assert_eq!(
            report.outcomes,
            vec![ResolvedNewTabRecoveryActionOutcome::succeeded(
                ResolvedNewTabRecoveryAction::RemoveScratch(scratch)
            )]
        );
    }

    #[test]
    fn new_tab_filesystem_recovery_effects_remove_scratch_plan_skips_missing_dir() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scratch = tmp.path().join("never-created");
        let plan = resolved_recovery_plan(vec![ResolvedNewTabRecoveryAction::RemoveScratch(
            scratch.clone(),
        )]);
        let mut effects = ResolvedNewTabRecoveryFilesystemEffects;

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 1);
        assert_eq!(report.failed_count(), 0);
        assert_eq!(
            report.outcomes[0],
            ResolvedNewTabRecoveryActionOutcome::skipped(
                ResolvedNewTabRecoveryAction::RemoveScratch(scratch),
                "missing scratch dir (already gone)"
            )
        );
    }

    #[test]
    fn new_tab_filesystem_recovery_effects_report_unsupported_effects_as_skipped() {
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id: s("sess-new"),
                expected_generation: s("gen-new"),
            },
            ResolvedNewTabRecoveryAction::RollbackTabRecord {
                window_id: s("w1"),
                tab_id: s("tab-new"),
            },
            ResolvedNewTabRecoveryAction::RevertRendererStrip {
                strip_tabs: vec![snapshot_tab("tab-old", "sess-old", 0)],
                selection: vec![TabSelection {
                    tab_id: s("tab-old"),
                    session_id: s("sess-old"),
                }],
            },
            ResolvedNewTabRecoveryAction::ReconcileRendererState {
                strip_tabs: vec![snapshot_tab("tab-old", "sess-old", 0)],
                selection: vec![TabSelection {
                    tab_id: s("tab-old"),
                    session_id: s("sess-old"),
                }],
            },
        ]);
        let mut effects = ResolvedNewTabRecoveryFilesystemEffects;

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 4);
        assert_eq!(report.failed_count(), 0);
        let reasons = report
            .outcomes
            .iter()
            .map(|outcome| match &outcome.status {
                ResolvedNewTabRecoveryActionStatus::Skipped { reason } => reason.as_str(),
                other => panic!("expected skipped status, got {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            reasons,
            vec![
                "kill_session unsupported by filesystem effects",
                "rollback_tab_record unsupported by filesystem effects",
                "revert_renderer_strip unsupported by filesystem effects",
                "reconcile_renderer_state unsupported by filesystem effects",
            ]
        );
    }

    #[test]
    fn new_tab_local_recovery_effects_remove_scratch_and_kill_session_succeed_in_plan_order() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scratch = tmp.path().join("scratch-cwd");
        std::fs::create_dir_all(scratch.join("nested")).expect("create scratch");
        std::fs::write(scratch.join("nested").join("marker"), b"orphan").expect("write marker");
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::RemoveScratch(scratch.clone()),
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id: s("sess-new"),
                expected_generation: s("gen-new"),
            },
        ]);
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let mut effects = ResolvedNewTabRecoveryLocalEffects::new(killer);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert!(!scratch.exists(), "scratch dir must be removed");
        assert_eq!(effects.session_killer().calls, vec![s("sess-new@gen-new")]);
        assert_eq!(
            report
                .outcomes
                .iter()
                .map(|outcome| outcome.action.clone())
                .collect::<Vec<_>>(),
            plan.actions,
            "local effects preserve resolved plan order"
        );
        assert_eq!(report.succeeded_count(), 2);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 0);
    }

    #[test]
    fn new_tab_local_recovery_effects_skip_missing_scratch_and_already_gone_session() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let scratch = tmp.path().join("never-created");
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::RemoveScratch(scratch.clone()),
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id: s("sess-gone"),
                expected_generation: s("gen-gone"),
            },
        ]);
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::AlreadyGone),
            calls: Vec::new(),
        };
        let mut effects = ResolvedNewTabRecoveryLocalEffects::new(killer);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(
            effects.session_killer().calls,
            vec![s("sess-gone@gen-gone")]
        );
        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 2);
        assert_eq!(report.failed_count(), 0);
        assert_eq!(
            report.outcomes,
            vec![
                ResolvedNewTabRecoveryActionOutcome::skipped(
                    ResolvedNewTabRecoveryAction::RemoveScratch(scratch),
                    "missing scratch dir (already gone)",
                ),
                ResolvedNewTabRecoveryActionOutcome::skipped(
                    ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                        session_id: s("sess-gone"),
                        expected_generation: s("gen-gone"),
                    },
                    "session already gone",
                ),
            ]
        );
    }

    #[test]
    fn new_tab_local_recovery_effects_report_unsupported_effects_as_skipped() {
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::RollbackTabRecord {
                window_id: s("w1"),
                tab_id: s("tab-new"),
            },
            ResolvedNewTabRecoveryAction::RevertRendererStrip {
                strip_tabs: vec![snapshot_tab("tab-old", "sess-old", 0)],
                selection: vec![TabSelection {
                    tab_id: s("tab-old"),
                    session_id: s("sess-old"),
                }],
            },
            ResolvedNewTabRecoveryAction::ReconcileRendererState {
                strip_tabs: vec![snapshot_tab("tab-old", "sess-old", 0)],
                selection: vec![TabSelection {
                    tab_id: s("tab-old"),
                    session_id: s("sess-old"),
                }],
            },
        ]);
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let mut effects = ResolvedNewTabRecoveryLocalEffects::new(killer);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert!(
            effects.session_killer().calls.is_empty(),
            "unsupported non-kill actions must not call the injected killer"
        );
        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 3);
        assert_eq!(report.failed_count(), 0);
        let reasons = report
            .outcomes
            .iter()
            .map(|outcome| match &outcome.status {
                ResolvedNewTabRecoveryActionStatus::Skipped { reason } => reason.as_str(),
                other => panic!("expected skipped status, got {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            reasons,
            vec![
                "rollback_tab_record unsupported by local recovery effects",
                "revert_renderer_strip unsupported by local recovery effects",
                "reconcile_renderer_state unsupported by local recovery effects",
            ]
        );
    }
    // ---- NewTab record-local + complete recovery effects ----
    // Moved from `lib.rs` beside their owning `ResolvedNewTabRecoveryRecordLocalEffects` /
    // `ResolvedNewTabRecoveryCompleteEffects` impls and the `execute_resolved_new_tab_recovery_plan`
    // executor. Reached via `use super::*;`; they reuse the existing private `new_tab::tests`
    // copies of `resolved_recovery_plan`, `snapshot_tab`, `FakeRecoverySessionKiller`,
    // `FakeRendererStateController`, and `renderer_state_payload`.

    #[test]
    fn new_tab_record_local_recovery_effects_remove_rollback_and_kill_in_plan_order() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_exact_test_session(&paths, "sess-t0", "gen-t0");
        seed_exact_test_session(&paths, "sess-new", "gen-new");
        let scratch = tmp.path().join("scratch-cwd");
        std::fs::create_dir_all(scratch.join("nested")).expect("create scratch");
        std::fs::write(scratch.join("nested").join("marker"), b"orphan").expect("write marker");
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create layout");
        service
            .open_tab(
                "w1",
                "t0",
                "sess-t0",
                "old",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed old tab");
        service
            .open_tab(
                "w1",
                "tab-new",
                "sess-new",
                "new",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed new tab");
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::RemoveScratch(scratch.clone()),
            ResolvedNewTabRecoveryAction::RollbackTabRecord {
                window_id: s("w1"),
                tab_id: s("tab-new"),
            },
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id: s("sess-new"),
                expected_generation: s("gen-new"),
            },
        ]);
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let mut effects = ResolvedNewTabRecoveryRecordLocalEffects::new(paths.clone(), 42, killer);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert!(!scratch.exists(), "scratch dir must be removed");
        assert_eq!(effects.session_killer().calls, vec![s("sess-new@gen-new")]);
        let reloaded = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load layout")
            .expect("layout exists");
        assert_eq!(reloaded.tabs.len(), 1);
        assert_eq!(reloaded.tabs[0].tab_id, "t0");
        assert_eq!(reloaded.tabs[0].index, 0);
        assert_eq!(
            report
                .outcomes
                .iter()
                .map(|outcome| outcome.action.clone())
                .collect::<Vec<_>>(),
            plan.actions,
            "record-local effects preserve resolved plan order"
        );
        assert_eq!(report.succeeded_count(), 3);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 0);
    }

    #[test]
    fn new_tab_record_local_recovery_effects_skip_missing_tab_and_renderer_actions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create layout");
        service
            .open_tab(
                "w1",
                "t0",
                "sess-t0",
                "old",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed old tab");
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::RollbackTabRecord {
                window_id: s("w1"),
                tab_id: s("tab-new"),
            },
            ResolvedNewTabRecoveryAction::RevertRendererStrip {
                strip_tabs: vec![snapshot_tab("tab-old", "sess-old", 0)],
                selection: vec![TabSelection {
                    tab_id: s("tab-old"),
                    session_id: s("sess-old"),
                }],
            },
            ResolvedNewTabRecoveryAction::ReconcileRendererState {
                strip_tabs: vec![snapshot_tab("tab-old", "sess-old", 0)],
                selection: vec![TabSelection {
                    tab_id: s("tab-old"),
                    session_id: s("sess-old"),
                }],
            },
        ]);
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let mut effects = ResolvedNewTabRecoveryRecordLocalEffects::new(paths.clone(), 42, killer);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert!(
            effects.session_killer().calls.is_empty(),
            "non-kill actions must not call the injected killer"
        );
        let reloaded = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load layout")
            .expect("layout exists");
        assert_eq!(reloaded.tabs.len(), 1);
        assert_eq!(reloaded.tabs[0].tab_id, "t0");
        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 3);
        assert_eq!(report.failed_count(), 0);
        let reasons = report
            .outcomes
            .iter()
            .map(|outcome| match &outcome.status {
                ResolvedNewTabRecoveryActionStatus::Skipped { reason } => reason.as_str(),
                other => panic!("expected skipped status, got {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            reasons,
            vec![
                "tab record already absent",
                "revert_renderer_strip unsupported by record-local recovery effects",
                "reconcile_renderer_state unsupported by record-local recovery effects",
            ]
        );
    }

    #[test]
    fn new_tab_record_local_recovery_effects_record_store_error_is_failed_outcome() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let plan = resolved_recovery_plan(vec![ResolvedNewTabRecoveryAction::RollbackTabRecord {
            window_id: s("../escape"),
            tab_id: s("tab-new"),
        }]);
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let mut effects = ResolvedNewTabRecoveryRecordLocalEffects::new(paths, 42, killer);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert!(
            effects.session_killer().calls.is_empty(),
            "failed record rollback must not call the injected killer"
        );
        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 1);
        assert!(matches!(
            &report.outcomes[0].status,
            ResolvedNewTabRecoveryActionStatus::Failed { .. }
        ));
    }

    #[test]
    fn new_tab_complete_recovery_effects_execute_all_five_actions_in_plan_order() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_exact_test_session(&paths, "sess-t0", "gen-t0");
        seed_exact_test_session(&paths, "sess-new", "gen-new");
        let scratch = tmp.path().join("scratch-cwd");
        std::fs::create_dir_all(scratch.join("nested")).expect("create scratch");
        std::fs::write(scratch.join("nested").join("marker"), b"orphan").expect("write marker");
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create layout");
        service
            .open_tab(
                "w1",
                "t0",
                "sess-t0",
                "old",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed old tab");
        service
            .open_tab(
                "w1",
                "tab-new",
                "sess-new",
                "new",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed new tab");
        let (strip_tabs, selection) = renderer_state_payload();
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::RemoveScratch(scratch.clone()),
            ResolvedNewTabRecoveryAction::RollbackTabRecord {
                window_id: s("w1"),
                tab_id: s("tab-new"),
            },
            ResolvedNewTabRecoveryAction::RevertRendererStrip {
                strip_tabs: strip_tabs.clone(),
                selection: selection.clone(),
            },
            ResolvedNewTabRecoveryAction::ReconcileRendererState {
                strip_tabs: strip_tabs.clone(),
                selection: selection.clone(),
            },
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id: s("sess-new"),
                expected_generation: s("gen-new"),
            },
        ]);
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let controller = FakeRendererStateController {
            revert_result: Ok(RendererStateRecoveryEffectResult::Restored),
            reconcile_result: Ok(RendererStateRecoveryEffectResult::Restored),
            calls: Vec::new(),
        };
        let mut effects =
            ResolvedNewTabRecoveryCompleteEffects::new(paths.clone(), 42, killer, controller);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert!(!scratch.exists(), "scratch dir must be removed");
        assert_eq!(effects.session_killer().calls, vec![s("sess-new@gen-new")]);
        assert_eq!(
            effects.renderer_controller().calls,
            vec![
                s("revert:2:2:tab-old,tab-other"),
                s("reconcile:2:2:sess-old,sess-other")
            ]
        );
        let reloaded = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load layout")
            .expect("layout exists");
        assert_eq!(reloaded.tabs.len(), 1);
        assert_eq!(reloaded.tabs[0].tab_id, "t0");
        assert_eq!(
            report
                .outcomes
                .iter()
                .map(|outcome| outcome.action.clone())
                .collect::<Vec<_>>(),
            plan.actions,
            "complete effects preserve resolved plan order"
        );
        assert_eq!(report.succeeded_count(), 5);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 0);
    }

    #[test]
    fn new_tab_complete_recovery_effects_report_idempotent_skips_for_all_actions() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let scratch = tmp.path().join("never-created");
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w1", 0).expect("create layout");
        service
            .open_tab(
                "w1",
                "t0",
                "sess-t0",
                "old",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed old tab");
        let (strip_tabs, selection) = renderer_state_payload();
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::RemoveScratch(scratch),
            ResolvedNewTabRecoveryAction::RollbackTabRecord {
                window_id: s("w1"),
                tab_id: s("tab-new"),
            },
            ResolvedNewTabRecoveryAction::RevertRendererStrip {
                strip_tabs: strip_tabs.clone(),
                selection: selection.clone(),
            },
            ResolvedNewTabRecoveryAction::ReconcileRendererState {
                strip_tabs,
                selection,
            },
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id: s("sess-gone"),
                expected_generation: s("gen-gone"),
            },
        ]);
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::AlreadyGone),
            calls: Vec::new(),
        };
        let controller = FakeRendererStateController {
            revert_result: Ok(RendererStateRecoveryEffectResult::AlreadyCurrent),
            reconcile_result: Ok(RendererStateRecoveryEffectResult::AlreadyCurrent),
            calls: Vec::new(),
        };
        let mut effects =
            ResolvedNewTabRecoveryCompleteEffects::new(paths.clone(), 42, killer, controller);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(
            effects.session_killer().calls,
            vec![s("sess-gone@gen-gone")]
        );
        let reloaded = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load layout")
            .expect("layout exists");
        assert_eq!(reloaded.tabs.len(), 1);
        assert_eq!(reloaded.tabs[0].tab_id, "t0");
        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 5);
        assert_eq!(report.failed_count(), 0);
        let reasons = report
            .outcomes
            .iter()
            .map(|outcome| match &outcome.status {
                ResolvedNewTabRecoveryActionStatus::Skipped { reason } => reason.as_str(),
                other => panic!("expected skipped status, got {other:?}"),
            })
            .collect::<Vec<_>>();
        assert_eq!(
            reasons,
            vec![
                "missing scratch dir (already gone)",
                "tab record already absent",
                "renderer strip already current",
                "renderer state already reconciled",
                "session already gone",
            ]
        );
    }

    #[test]
    fn new_tab_complete_recovery_effects_record_failures_and_continue() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let (strip_tabs, selection) = renderer_state_payload();
        let plan = resolved_recovery_plan(vec![
            ResolvedNewTabRecoveryAction::RollbackTabRecord {
                window_id: s("../escape"),
                tab_id: s("tab-new"),
            },
            ResolvedNewTabRecoveryAction::RevertRendererStrip {
                strip_tabs: strip_tabs.clone(),
                selection: selection.clone(),
            },
            ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                session_id: s("sess-new"),
                expected_generation: s("gen-new"),
            },
            ResolvedNewTabRecoveryAction::ReconcileRendererState {
                strip_tabs,
                selection,
            },
        ]);
        let killer = FakeRecoverySessionKiller {
            result: Err(s("daemon unavailable")),
            calls: Vec::new(),
        };
        let controller = FakeRendererStateController {
            revert_result: Err(s("renderer control closed")),
            reconcile_result: Err(s("ambiguous active state")),
            calls: Vec::new(),
        };
        let mut effects = ResolvedNewTabRecoveryCompleteEffects::new(paths, 42, killer, controller);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(effects.session_killer().calls, vec![s("sess-new@gen-new")]);
        assert_eq!(
            effects.renderer_controller().calls,
            vec![
                s("revert:2:2:tab-old,tab-other"),
                s("reconcile:2:2:sess-old,sess-other")
            ]
        );
        assert_eq!(
            report
                .outcomes
                .iter()
                .map(|outcome| outcome.action.clone())
                .collect::<Vec<_>>(),
            plan.actions,
            "executor must continue through failures in plan order"
        );
        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 4);
        let errors = report
            .outcomes
            .iter()
            .map(|outcome| match &outcome.status {
                ResolvedNewTabRecoveryActionStatus::Failed { error } => error.as_str(),
                other => panic!("expected failed status, got {other:?}"),
            })
            .collect::<Vec<_>>();
        assert!(
            !errors[0].is_empty(),
            "window-layout failure must preserve a diagnostic"
        );
        assert_eq!(errors[1], "renderer control closed");
        assert_eq!(errors[2], "daemon unavailable");
        assert_eq!(errors[3], "ambiguous active state");
    }

    #[test]
    fn new_tab_foreground_pipeline_closed_renderer_receiver_is_typed_nonpanic_failure() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        // The pipeline starts a session whose SessionRecord references the scratch workspace; seed
        // its FK parents so the SQLite session INSERT does not fail the foreign-key constraint.
        seed_default_scratch_workspace_parents(&paths);
        one_existing_tab_window(&paths, "maestro-app-dev-project");

        let sock_dir = tempfile::tempdir().expect("sock dir");
        let sock_path = sock_dir.path().join("stub.sock");
        let stub = StubDaemon::spawn_at(sock_path.clone(), serve_grid(s("sess-1"), s("gen-1")));
        let env = MapEnv::new(&[]);
        let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
        let argv = vec![s("/bin/zsh"), s("-l")];
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w1", "t0", "sess-t0");
        drop(rx);

        let err = run_new_tab_foreground_pipeline(
            NewTabForegroundRequest {
                paths: &paths,
                socket_path: sock_path,
                window_id: "w1",
                plan: &plan,
                launch: NewTabForegroundLaunch::shell_adhoc(&argv),
                cols: 80,
                rows: 24,
                now_ms: 1_700_000_000,
                split_from: None,
                split_source_session: None,
                expected_project_id: None,
            },
            &env,
            &mut rt,
        )
        .expect_err("closed renderer receiver surfaces a typed error");

        assert!(matches!(
            err,
            NewTabForegroundError::PreparedGenerationBoundAttachSession {
                ref session_id,
                ref session_generation,
                error: NewTabAttachSessionError::RendererControlClosed,
                ..
            } if session_id == "sess-1" && session_generation == "gen-1"
        ));
        assert_eq!(
            rt.active_tab_id(),
            None,
            "a textual seed never authorizes an active renderer lifetime"
        );
        let persisted = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load")
            .expect("window exists");
        assert_eq!(
            persisted.tabs.len(),
            2,
            "record mutation is deliberately not rolled back after post-record failure"
        );
        assert_eq!(new_tab_failure_scratch_to_remove(&err), None);
        assert!(
            paths.scratch_base().join("sess-1").is_dir(),
            "post-record failure leaves scratch cwd in place because a TabRecord references it"
        );
        drop(stub);
        drop(sock_dir);
    }

    #[test]
    fn new_tab_smoke_pre_record_failure_removes_orphan_scratch_and_leaves_layout_unchanged() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        one_existing_tab_window(&paths, "maestro-app-dev-project");

        let env = MapEnv::new(&[]);
        let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
        let argv = vec![s("/bin/zsh"), s("-l")];
        let (mut rt, rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w1", "t0", "sess-t0");
        let missing_socket = tmp.path().join("missing.sock");

        let mut err = run_new_tab_foreground_pipeline(
            NewTabForegroundRequest {
                paths: &paths,
                socket_path: missing_socket,
                window_id: "w1",
                plan: &plan,
                launch: NewTabForegroundLaunch::shell_adhoc(&argv),
                cols: 80,
                rows: 24,
                now_ms: 1_700_000_000,
                split_from: None,
                split_source_session: None,
                expected_project_id: None,
            },
            &env,
            &mut rt,
        )
        .expect_err("missing socket fails before any layout record append");

        let cleanup = new_tab_failure_scratch_to_remove(&err)
            .expect("session-start failure after prepare is scratch-cleanup eligible")
            .to_path_buf();
        assert_eq!(cleanup, paths.scratch_base().join("sess-1"));
        assert!(cleanup.is_dir(), "scratch exists before cleanup");

        let report = execute_production_new_tab_recovery(
            &paths,
            &tmp.path().join("missing-again.sock"),
            1_700_000_001,
            &mut err,
            &[],
            &[],
            &mut rt,
        );
        assert_eq!(report.succeeded_count(), 1);
        assert!(
            !cleanup.exists(),
            "orphan scratch cwd is gone after cleanup"
        );
        assert!(
            rx.try_recv().is_err(),
            "pre-record failure sends no renderer commands"
        );
        assert_eq!(
            rt.active_tab_id(),
            None,
            "pre-record failure cannot upgrade the textual seed into authority"
        );

        let persisted = maestro_shell::WindowLayoutService::new(&paths)
            .load("w1")
            .expect("load")
            .expect("window exists");
        assert_eq!(
            persisted
                .tabs
                .iter()
                .map(|tab| tab.tab_id.as_str())
                .collect::<Vec<_>>(),
            vec!["t0"],
            "no TabRecord was appended before cleanup"
        );
    }

    #[test]
    fn classify_new_tab_foreground_failure_maps_every_stage_and_residue() {
        let cwd = PathBuf::from("/tmp/maestro-scratch-test");
        let cases = vec![
            (
                NewTabForegroundError::WorkspacePrepare(NewTabWorkspacePrepareError::NotCreate),
                NewTabFailureStage::WorkspacePrepare,
                false,
                false,
            ),
            (
                NewTabForegroundError::StartParams {
                    cwd: cwd.join("start-params"),
                    scratch: None,
                    error: NewTabStartParamsError::NotCreate,
                },
                NewTabFailureStage::StartParams,
                false,
                false,
            ),
            (
                session_start_foreground_error(cwd.join("session-start")),
                NewTabFailureStage::SessionStart,
                true,
                false,
            ),
            (
                NewTabForegroundError::LayoutRecord {
                    cwd: cwd.join("layout-record"),
                    error: NewTabLayoutRecordError::WindowLayout(
                        maestro_shell::window_layout::WindowLayoutError::WindowLayoutNotFound {
                            window_id: s("w-missing"),
                        },
                    ),
                },
                NewTabFailureStage::LayoutRecord,
                true,
                false,
            ),
            (
                NewTabForegroundError::Projection(NewTabStripProjectionError::ActiveTabNotFound {
                    tab_id: s("tab-missing"),
                }),
                NewTabFailureStage::Projection,
                true,
                true,
            ),
            (
                NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed),
                NewTabFailureStage::SetTabStrip,
                true,
                true,
            ),
            (
                NewTabForegroundError::AttachSession(
                    NewTabAttachSessionError::RendererControlClosed,
                ),
                NewTabFailureStage::AttachSession,
                true,
                true,
            ),
        ];

        for (err, stage, session_started, layout_record_persisted) in cases {
            let got = classify_new_tab_foreground_failure(&err);
            assert_eq!(got.stage, stage);
            assert_eq!(got.session_started, session_started);
            assert_eq!(got.layout_record_persisted, layout_record_persisted);
            assert!(
                got.deferred_cleanup.contains("cleanup")
                    || got.deferred_cleanup.contains("removed"),
                "cleanup/removal text stays explicit for {got:?}"
            );
        }
    }

    #[test]
    fn new_tab_failure_diagnostic_display_is_single_line_and_names_residue() {
        let diagnostic = classify_new_tab_foreground_failure(
            &NewTabForegroundError::AttachSession(NewTabAttachSessionError::RendererControlClosed),
        );
        let rendered = diagnostic.to_string();

        assert!(
            !rendered.contains('\n'),
            "diagnostic display must stay one line"
        );
        assert!(rendered.contains("AttachSession"));
        assert!(rendered.contains("session_started=true"));
        assert!(rendered.contains("layout_record_persisted=true"));
        assert!(rendered.contains("persisted TabRecord"));
    }

    #[test]
    fn new_tab_failure_scratch_to_remove_matches_pre_record_residue_contract() {
        let cwd = PathBuf::from("/tmp/maestro-pre-record-scratch");
        let cases: Vec<(NewTabForegroundError, Option<PathBuf>)> = vec![
            (
                NewTabForegroundError::WorkspacePrepare(NewTabWorkspacePrepareError::NotCreate),
                None,
            ),
            (
                NewTabForegroundError::StartParams {
                    cwd: cwd.join("start-params"),
                    scratch: None,
                    error: NewTabStartParamsError::NotCreate,
                },
                None,
            ),
            (
                session_start_foreground_error(cwd.join("session-start")),
                None,
            ),
            (
                NewTabForegroundError::LayoutRecord {
                    cwd: cwd.join("layout-record"),
                    error: NewTabLayoutRecordError::WindowLayout(
                        maestro_shell::window_layout::WindowLayoutError::WindowLayoutNotFound {
                            window_id: s("w-missing"),
                        },
                    ),
                },
                None,
            ),
            (
                NewTabForegroundError::Projection(NewTabStripProjectionError::ActiveTabNotFound {
                    tab_id: s("tab-missing"),
                }),
                None,
            ),
            (
                NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed),
                None,
            ),
            (
                NewTabForegroundError::AttachSession(
                    NewTabAttachSessionError::RendererControlClosed,
                ),
                None,
            ),
        ];

        for (err, expected) in cases {
            assert_eq!(new_tab_failure_scratch_to_remove(&err), expected.as_deref());
        }
    }

    // ---- NewTab live-recovery + end-to-end recovery-log tests (localized 2026-06-13) ----
    // Moved from `lib.rs` beside the owning recovery resolver/executor/effects items.
    // Reached via `use super::*;`; they reuse the existing private `new_tab::tests` copies of
    // `resolved_recovery_plan`, `snapshot_tab`, `FakeRecoverySessionKiller`,
    // `FakeRendererStateController`, `renderer_state_payload`, and `session_start_foreground_error`.
    // The live-test helper `post_record_set_tab_strip_failure` moved with this cohort (it had no
    // retained `lib.rs` callers).
    // ---- Live `attach-tab` recovery wiring (instruction 2026-06-11) ----
    //
    // The foreground `attach-tab` `NewTabRequested` listener only constructs a
    // `ResolvedNewTabRecoveryPlan` and runs the executor on the `Err(e)` arm of
    // `run_new_tab_foreground_pipeline`. These tests pin the seam the live `main.rs` branch drives:
    // who produces a plan (only a real failure), what the production controller + executor do on
    // that plan, that scratch cleanup has one owner, that a closed renderer channel is a failed
    // outcome with no projection adoption, and the effects-unavailable empty-outcome diagnostic.

    fn post_record_set_tab_strip_failure() -> NewTabForegroundError {
        NewTabForegroundError::SetTabStrip(NewTabSetTabStripError::RendererControlClosed)
    }

    fn generation_bound_set_tab_strip_failure() -> NewTabForegroundError {
        NewTabForegroundError::GenerationBoundSetTabStrip {
            session_id: s("sess-new"),
            session_generation: s("gen-new"),
            rollback_authority: None,
            error: NewTabSetTabStripError::RendererControlClosed,
        }
    }

    fn seed_production_new_tab_recovery_graph(
        paths: &maestro_shell::AppPaths,
        cwd: &Path,
        generation: Option<&str>,
        include_created_tab: bool,
    ) -> (
        maestro_shell::SessionRecord,
        maestro_shell::WindowLayoutSnapshot,
    ) {
        let project = maestro_shell::Project {
            project_id: s("project-recovery"),
            name: s("Recovery project"),
            root: cwd.to_string_lossy().into_owned(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: Vec::new(),
            system: false,
            hidden: false,
        };
        maestro_shell::write_record(
            paths,
            maestro_shell::RecordKind::Project,
            &project.project_id,
            1,
            &project,
        )
        .expect("seed project");
        let workspace = maestro_shell::Workspace {
            workspace_id: s("workspace-recovery"),
            project_id: project.project_id,
            root: cwd.to_string_lossy().into_owned(),
            policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            consent: maestro_shell::WorkspaceConsent::default(),
        };
        maestro_shell::write_record(
            paths,
            maestro_shell::RecordKind::Workspace,
            &workspace.workspace_id,
            1,
            &workspace,
        )
        .expect("seed workspace");
        let session = maestro_shell::SessionRecord {
            session_id: s("session-recovery"),
            workspace_id: workspace.workspace_id,
            kind: maestro_shell::SessionKind::Shell,
            launch: maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: s("secret-launch-spec"),
                params: vec![s("secret-argv")],
            },
            cwd_resolved: cwd.to_string_lossy().into_owned(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: generation.map(str::to_string),
            status: maestro_shell::SessionStatus::Live,
        };
        maestro_shell::write_record(
            paths,
            maestro_shell::RecordKind::Session,
            &session.session_id,
            1,
            &session,
        )
        .expect("seed session");
        let windows = maestro_shell::WindowLayoutService::new(paths);
        let empty = windows
            .create_empty_snapshot("window-recovery", 1)
            .expect("seed recovery window");
        let snapshot = if include_created_tab {
            windows
                .open_tab_snapshot(
                    "window-recovery",
                    "tab-recovery",
                    &session.session_id,
                    "secret-tab-title",
                    false,
                    maestro_shell::AttentionState::default(),
                    2,
                )
                .expect("seed created tab")
        } else {
            empty
        };
        (session, snapshot)
    }

    fn created_tab_recovery_error(
        snapshot: maestro_shell::WindowLayoutSnapshot,
        session: maestro_shell::SessionRecord,
        generation: &str,
        scratch_cwd: Option<PathBuf>,
    ) -> NewTabForegroundError {
        NewTabForegroundError::GenerationBoundSetTabStrip {
            session_id: session.session_id.clone(),
            session_generation: generation.to_string(),
            rollback_authority: Some(NewTabCreatedTabRollbackAuthority {
                expected_post_layout: snapshot,
                expected_session: session,
                expected_generation: generation.to_string(),
                created_tab_id: s("tab-recovery"),
                scratch_cwd,
                attachment_handoff: None,
            }),
            error: NewTabSetTabStripError::RendererControlClosed,
        }
    }

    fn assert_no_socket_connection(listener: &std::os::unix::net::UnixListener) {
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("recovery unexpectedly connected to the daemon socket"),
            Err(error) => panic!("checking daemon socket: {error}"),
        }
    }

    #[test]
    fn production_new_tab_recovery_rolls_back_offline_repairs_renderer_and_parks_release() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        let scratch = tmp.path().join("secret-scratch");
        std::fs::create_dir_all(&scratch).expect("create scratch");
        let (session, snapshot) =
            seed_production_new_tab_recovery_graph(&paths, &scratch, Some("generation-a"), true);
        let mut error = created_tab_recovery_error(
            snapshot,
            session.clone(),
            "generation-a",
            Some(scratch.clone()),
        );
        if let NewTabForegroundError::GenerationBoundSetTabStrip {
            session_generation, ..
        } = &mut error
        {
            *session_generation = s("tampered-diagnostic-generation");
        }
        let socket = tmp.path().join("offline.sock");
        let (mut runtime, commands) = RendererTabRuntime::new();
        runtime.seed_active_tab("window-recovery", "tab-old", "session-old");
        let previous_strip_tabs = vec![snapshot_tab("tab-old", "session-old", 0)];
        let previous_selection = vec![TabSelection {
            tab_id: s("tab-old"),
            session_id: s("session-old"),
        }];

        let report = execute_production_new_tab_recovery(
            &paths,
            &socket,
            3,
            &mut error,
            &previous_strip_tabs,
            &previous_selection,
            &mut runtime,
        );

        assert!(
            maestro_shell::load_one::<maestro_shell::SessionRecord>(
                &paths,
                maestro_shell::RecordKind::Session,
                &session.session_id,
            )
            .unwrap()
            .is_none(),
            "the exact Session row is removed before daemon connection"
        );
        assert!(
            maestro_shell::WindowLayoutService::new(&paths)
                .load("window-recovery")
                .unwrap()
                .unwrap()
                .tabs
                .is_empty(),
            "the created tab is removed in the same commit"
        );
        assert!(
            matches!(
                commands.try_recv(),
                Err(std::sync::mpsc::TryRecvError::Empty)
            ),
            "recovery has no fresh exact prior-lifetime authority, so it stays renderer-neutral"
        );
        assert!(
            maestro_shell::SessionReleaseService::new(&paths)
                .claim_next()
                .expect("claim parked release")
                .is_some(),
            "offline Unpublished authority is surrendered for forward retry"
        );
        assert!(scratch.exists(), "post-start scratch is always retained");
        assert_eq!(report.failed_count(), 0);
        assert!(
            report.outcomes.iter().any(|outcome| matches!(
                &outcome.action,
                ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                    expected_generation,
                    ..
                } if expected_generation == "generation-a"
            )),
            "private authority, not mutable diagnostic fields, binds the release generation"
        );

        let second = execute_production_new_tab_recovery(
            &paths,
            &socket,
            4,
            &mut error,
            &previous_strip_tabs,
            &previous_selection,
            &mut runtime,
        );
        assert!(
            second.outcomes.is_empty(),
            "opaque rollback authority is consumed by the first execution"
        );
        assert!(
            commands.try_recv().is_err(),
            "second execution sends nothing"
        );
    }

    #[test]
    fn production_new_tab_recovery_neutral_renderer_parks_release_without_raw_restore() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        let scratch = tmp.path().join("scratch-renderer-failure");
        std::fs::create_dir_all(&scratch).expect("create scratch");
        let (session, snapshot) =
            seed_production_new_tab_recovery_graph(&paths, &scratch, Some("generation-a"), true);
        let mut error =
            created_tab_recovery_error(snapshot, session, "generation-a", Some(scratch.clone()));
        let socket = tmp.path().join("offline.sock");
        let (mut runtime, commands) = RendererTabRuntime::new();

        let report = execute_production_new_tab_recovery(
            &paths,
            &socket,
            3,
            &mut error,
            &[],
            &[],
            &mut runtime,
        );

        assert!(report.outcomes.iter().any(|outcome| {
            matches!(
                outcome.action,
                ResolvedNewTabRecoveryAction::RevertRendererStrip { .. }
            ) && matches!(
                &outcome.status,
                ResolvedNewTabRecoveryActionStatus::Skipped { reason }
                    if reason == "renderer remained neutral; exact prior lifetime was not reacquired"
            )
        }));
        assert!(matches!(
            commands.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
        assert!(maestro_shell::SessionReleaseService::new(&paths)
            .claim_next()
            .expect("claim parked release")
            .is_some());
        assert!(
            scratch.exists(),
            "renderer failure cannot authorize scratch deletion"
        );
    }

    #[test]
    fn production_new_tab_recovery_replacement_session_refuses_every_followup_effect() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        let scratch = tmp.path().join("scratch-replacement");
        std::fs::create_dir_all(&scratch).expect("create scratch");
        let (session_a, snapshot_a) =
            seed_production_new_tab_recovery_graph(&paths, &scratch, Some("generation-a"), true);
        let mut error = created_tab_recovery_error(
            snapshot_a,
            session_a.clone(),
            "generation-a",
            Some(scratch.clone()),
        );
        let mut session_b = session_a;
        session_b.last_known_generation = Some(s("generation-b"));
        session_b.last_attached_at_ms = 9;
        maestro_shell::write_record(
            &paths,
            maestro_shell::RecordKind::Session,
            &session_b.session_id,
            9,
            &session_b,
        )
        .expect("replace Session A with B");
        let socket = tmp.path().join("must-not-connect.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind probe socket");
        listener
            .set_nonblocking(true)
            .expect("set probe nonblocking");
        let (mut runtime, commands) = RendererTabRuntime::new();

        let report = execute_production_new_tab_recovery(
            &paths,
            &socket,
            10,
            &mut error,
            &[],
            &[],
            &mut runtime,
        );

        assert_eq!(report.outcomes.len(), 1);
        assert!(report.outcomes[0].status.is_skipped());
        assert!(commands.try_recv().is_err(), "renderer remains untouched");
        assert_no_socket_connection(&listener);
        assert!(
            maestro_shell::SessionReleaseService::new(&paths)
                .claim_next()
                .unwrap()
                .is_none(),
            "a replacement lifetime never enters the journal"
        );
        let loaded = maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &session_b.session_id,
        )
        .unwrap()
        .expect("Session B remains");
        assert!(matches!(loaded, maestro_shell::LoadOutcome::Loaded(value) if value == session_b));
        assert!(scratch.exists());

        let second = execute_production_new_tab_recovery(
            &paths,
            &socket,
            11,
            &mut error,
            &[],
            &[],
            &mut runtime,
        );
        assert!(second.outcomes.is_empty());
        assert_no_socket_connection(&listener);
    }

    #[test]
    fn production_new_tab_layout_record_failure_deletes_only_exact_session_and_journals() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        let scratch = tmp.path().join("scratch-layout-record");
        std::fs::create_dir_all(&scratch).expect("create scratch");
        let (session, empty_snapshot) =
            seed_production_new_tab_recovery_graph(&paths, &scratch, Some("generation-a"), false);
        let mut error = NewTabForegroundError::GenerationBoundLayoutRecord {
            cwd: scratch.clone(),
            session_id: session.session_id.clone(),
            session_generation: s("generation-a"),
            rollback_authority: Some(NewTabSessionRollbackAuthority {
                expected_layout_without_tab: empty_snapshot,
                expected_session: session.clone(),
                expected_generation: s("generation-a"),
                created_tab_id: s("tab-recovery"),
                scratch_cwd: Some(scratch.clone()),
                attachment_handoff: None,
            }),
            error: NewTabLayoutRecordError::WindowLayout(
                maestro_shell::WindowLayoutError::WindowLayoutNotFound {
                    window_id: s("window-recovery"),
                },
            ),
        };
        let (mut runtime, commands) = RendererTabRuntime::new();

        let report = execute_production_new_tab_recovery(
            &paths,
            &tmp.path().join("offline.sock"),
            3,
            &mut error,
            &[],
            &[],
            &mut runtime,
        );

        assert_eq!(report.failed_count(), 0);
        assert!(
            commands.try_recv().is_err(),
            "no renderer state was published"
        );
        assert!(maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            &session.session_id,
        )
        .unwrap()
        .is_none());
        assert!(maestro_shell::SessionReleaseService::new(&paths)
            .claim_next()
            .unwrap()
            .is_some());
        assert!(scratch.exists());
    }

    #[test]
    fn production_new_tab_recovery_missing_grid_generation_safe_leaks_without_effects() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        let scratch = tmp.path().join("scratch-unresolved");
        std::fs::create_dir_all(&scratch).expect("create scratch");
        let (session, _snapshot) =
            seed_production_new_tab_recovery_graph(&paths, &scratch, None, true);
        let mut error = NewTabForegroundError::StartedSessionGenerationMissing {
            session_id: session.session_id.clone(),
        };
        let socket = tmp.path().join("must-not-connect.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind probe socket");
        listener
            .set_nonblocking(true)
            .expect("set probe nonblocking");
        let (mut runtime, commands) = RendererTabRuntime::new();

        let report = execute_production_new_tab_recovery(
            &paths,
            &socket,
            3,
            &mut error,
            &[],
            &[],
            &mut runtime,
        );

        assert!(commands.try_recv().is_err());
        assert_no_socket_connection(&listener);
        assert!(
            maestro_shell::SessionReleaseService::new(&paths)
                .claim_next()
                .unwrap()
                .is_none(),
            "unproven generation is a safe leak, never an ID fallback"
        );
        assert!(report.outcomes.is_empty());
        assert!(
            maestro_shell::load_one::<maestro_shell::SessionRecord>(
                &paths,
                maestro_shell::RecordKind::Session,
                &session.session_id,
            )
            .unwrap()
            .is_some(),
            "missing Grid generation retains the entire durable graph"
        );
        assert_eq!(
            maestro_shell::WindowLayoutService::new(&paths)
                .load("window-recovery")
                .unwrap()
                .unwrap()
                .tabs
                .len(),
            1
        );
        assert!(scratch.exists());
    }

    #[test]
    fn production_new_tab_rollback_debug_is_payload_redacted() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        let secret_cwd = tmp.path().join("secret-cwd-marker");
        std::fs::create_dir_all(&secret_cwd).expect("create cwd");
        let (session, snapshot) = seed_production_new_tab_recovery_graph(
            &paths,
            &secret_cwd,
            Some("secret-generation-marker"),
            true,
        );
        let authority = NewTabCreatedTabRollbackAuthority {
            expected_post_layout: snapshot,
            expected_session: session,
            expected_generation: s("secret-generation-marker"),
            created_tab_id: s("tab-recovery"),
            scratch_cwd: Some(secret_cwd.clone()),
            attachment_handoff: None,
        };
        let authority_debug = format!("{authority:?}");
        let error = NewTabForegroundError::GenerationBoundSetTabStrip {
            session_id: s("secret-session-marker"),
            session_generation: s("secret-generation-marker"),
            rollback_authority: Some(authority),
            error: NewTabSetTabStripError::RendererControlClosed,
        };
        let error_debug = format!("{error:?}");

        for rendered in [&authority_debug, &error_debug] {
            assert!(!rendered.contains("secret-cwd-marker"), "{rendered}");
            assert!(!rendered.contains("secret-argv"), "{rendered}");
            assert!(!rendered.contains("secret-tab-title"), "{rendered}");
            assert!(!rendered.contains("secret-generation-marker"), "{rendered}");
            assert!(!rendered.contains("secret-launch-spec"), "{rendered}");
        }
    }

    struct RepresentSessionDuringRendererRecovery {
        paths: maestro_shell::AppPaths,
        session_id: String,
    }

    impl NewTabRecoveryRendererStateController for RepresentSessionDuringRendererRecovery {
        type Error = String;

        fn revert_renderer_strip(
            &mut self,
            _strip_tabs: &[WindowTabJson],
            _selection: &[TabSelection],
        ) -> Result<RendererStateRecoveryEffectResult, Self::Error> {
            maestro_shell::WindowLayoutService::new(&self.paths)
                .open_tab(
                    "w-race",
                    "tab-race-owner",
                    &self.session_id,
                    "Concurrent owner",
                    false,
                    maestro_shell::AttentionState::default(),
                    2,
                )
                .map_err(|error| error.to_string())?;
            Ok(RendererStateRecoveryEffectResult::Restored)
        }

        fn reconcile_renderer_state(
            &mut self,
            strip_tabs: &[WindowTabJson],
            selection: &[TabSelection],
        ) -> Result<RendererStateRecoveryEffectResult, Self::Error> {
            self.revert_renderer_strip(strip_tabs, selection)
        }
    }

    #[test]
    fn legacy_recovery_diagnostic_preserves_concurrent_owner_when_killer_refuses() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path().join("Maestro"));
        let windows = maestro_shell::WindowLayoutService::new(&paths);
        windows.create_empty("w-live", 1).unwrap();
        windows.create_empty("w-race", 1).unwrap();
        windows
            .open_tab(
                "w-live",
                "tab-new",
                "sess-new",
                "New",
                false,
                maestro_shell::AttentionState::default(),
                1,
            )
            .unwrap();

        let err = post_record_set_tab_strip_failure();
        let plan = resolve_new_tab_recovery(
            &err,
            &NewTabRecoveryContext {
                window_id: Some("w-live".into()),
                tab_id: Some("tab-new".into()),
                session_id: Some("sess-new".into()),
                session_generation: Some("gen-new".into()),
                previous_strip_tabs: Some(vec![]),
                previous_selection: Some(vec![]),
                scratch_cwd: None,
            },
        );

        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Represented),
            calls: Vec::new(),
        };
        let controller = RepresentSessionDuringRendererRecovery {
            paths: paths.clone(),
            session_id: "sess-new".into(),
        };
        let mut effects =
            ResolvedNewTabRecoveryCompleteEffects::new(paths.clone(), 2, killer, controller);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);
        assert!(matches!(
            report.outcomes.last().map(|outcome| &outcome.status),
            Some(ResolvedNewTabRecoveryActionStatus::Skipped { reason })
                if reason == "session is represented by a durable pane"
        ));
        assert!(
            windows
                .load("w-race")
                .unwrap()
                .unwrap()
                .tabs
                .iter()
                .any(|tab| tab.session_id == "sess-new"),
            "the owner inserted between rollback and release remains durable"
        );

        assert_eq!(effects.session_killer().calls, vec![s("sess-new@gen-new")]);
    }

    #[test]
    fn live_recovery_is_not_reachable_without_a_foreground_failure() {
        // Decline and abort never call `run_new_tab_foreground_pipeline`, so there is no
        // `NewTabForegroundError` to classify and therefore no resolved plan and no executor run.
        // Recovery planning is total over the error type only: there is no input that yields a plan
        // for a success/decline/abort disposition. We assert the structural gate directly — every
        // resolved plan is keyed to a real failure stage — so the listener cannot reach the executor
        // on a non-failure path.
        let plan = resolve_new_tab_recovery(
            &post_record_set_tab_strip_failure(),
            &NewTabRecoveryContext {
                window_id: Some(s("w-live")),
                tab_id: Some(s("tab-new")),
                session_id: Some(s("sess-new")),
                session_generation: Some(s("gen-new")),
                previous_strip_tabs: Some(vec![snapshot_tab("tab-old", "sess-old", 0)]),
                previous_selection: Some(vec![TabSelection {
                    tab_id: s("tab-old"),
                    session_id: s("sess-old"),
                }]),
                scratch_cwd: None,
            },
        );
        assert!(
            !plan.actions.is_empty(),
            "a real foreground failure resolves to a non-empty recovery plan"
        );
        // No success/decline/abort disposition is even representable as a `NewTabForegroundError`,
        // so the listener's Ok/decline/abort arms never build a plan or invoke the executor.
    }

    #[test]
    fn live_recovery_executor_runs_plan_and_logs_both_diagnostics_on_failure() {
        let err = post_record_set_tab_strip_failure();
        let context = NewTabRecoveryContext {
            window_id: Some(s("w-live")),
            tab_id: Some(s("tab-new")),
            session_id: Some(s("sess-new")),
            session_generation: Some(s("gen-new")),
            previous_strip_tabs: Some(vec![snapshot_tab("tab-old", "sess-old", 0)]),
            previous_selection: Some(vec![TabSelection {
                tab_id: s("tab-old"),
                session_id: s("sess-old"),
            }]),
            scratch_cwd: None,
        };
        let plan = resolve_new_tab_recovery(&err, &context);
        // The listener keeps the plan log; this is the same line it emits before executing.
        let plan_log = render_resolved_recovery_log_line(&plan);
        assert!(plan_log.contains("new-tab recovery:"));
        assert!(plan_log.contains("actions=["));

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        // No exact prior viewport authority is available in this legacy recovery payload. The
        // production controller must stay neutral and still allow the later generation-bound kill.
        let (mut runtime, rx) = RendererTabRuntime::new();
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let controller = ForegroundRendererStateController::new(&mut runtime, s("w-live"));
        let mut effects =
            ResolvedNewTabRecoveryCompleteEffects::new(paths, 1_234_567, killer, controller);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);
        let execution_log = render_resolved_recovery_execution_log_line(&report);

        // Both diagnostics are single-line and distinct.
        assert!(!plan_log.contains('\n'));
        assert!(!execution_log.contains('\n'));
        assert!(execution_log.contains("new-tab recovery executed"));
        // SetTabStrip stage plan = rollback (skip: no record), prior projection (skip: neutral),
        // kill session (ok: fake killer). No raw renderer command is authorized.
        assert_eq!(report.outcomes.len(), 3);
        assert_eq!(report.failed_count(), 0);
        assert_eq!(report.succeeded_count(), 1);
        assert_eq!(report.skipped_count(), 2);
        assert!(matches!(
            rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ));
    }

    #[test]
    fn live_recovery_scratch_cleanup_has_exactly_one_owner() {
        // Production takes the opaque capability out of the error. A second pass cannot replay
        // even an idempotent delete, so ownership does not depend on filesystem state.
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let (prepared, receipt) =
            maestro_shell::prepare_fresh_scratch_cwd(&paths, "ws-new", "sess-new", "")
                .unwrap()
                .into_parts();
        let scratch = prepared.cwd;
        let mut err = NewTabForegroundError::StartParams {
            cwd: scratch.clone(),
            scratch: Some(NewTabScratchRemovalAuthority::from_fresh_receipt(receipt)),
            error: NewTabStartParamsError::NotCreate,
        };
        let (mut runtime, _rx) = RendererTabRuntime::new();
        let missing_socket = tmp.path().join("missing.sock");
        let report = execute_production_new_tab_recovery(
            &paths,
            &missing_socket,
            1,
            &mut err,
            &[],
            &[],
            &mut runtime,
        );

        assert_eq!(report.failed_count(), 0);
        assert!(
            !scratch.exists(),
            "executor-owned RemoveScratch removed the orphan scratch dir exactly once"
        );
        let replay = execute_production_new_tab_recovery(
            &paths,
            &missing_socket,
            2,
            &mut err,
            &[],
            &[],
            &mut runtime,
        );
        assert!(
            replay.outcomes.is_empty(),
            "consumed authority is not replayed"
        );
    }

    #[test]
    fn production_recovery_never_deletes_worktree_or_repo_write_cwd() {
        for (_policy, suffix) in [
            (maestro_shell::WorkspacePolicy::Worktree, "worktree"),
            (maestro_shell::WorkspacePolicy::RepoWrite, "repo-write"),
        ] {
            let tmp = tempfile::tempdir().expect("tempdir");
            let paths = maestro_shell::AppPaths::with_base(tmp.path());
            let checkout = tmp.path().join(suffix);
            let nested = checkout.join("nested");
            std::fs::create_dir_all(&nested).expect("create checkout");
            let sentinel = nested.join("KEEP");
            std::fs::write(&sentinel, b"user data").expect("write sentinel");
            let mut error = NewTabForegroundError::StartParams {
                cwd: checkout,
                scratch: None,
                error: NewTabStartParamsError::NotCreate,
            };
            let (mut runtime, _rx) = RendererTabRuntime::new();
            let report = execute_production_new_tab_recovery(
                &paths,
                &tmp.path().join("missing.sock"),
                1,
                &mut error,
                &[],
                &[],
                &mut runtime,
            );
            assert!(report.outcomes.is_empty());
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"user data");
        }
    }

    #[test]
    fn prepared_scratch_cleanup_requires_proven_unpublication_and_exact_app_paths() {
        let shell_error = || {
            maestro_shell::ShellRuntimeError::Daemon(maestro_shell::DaemonClientError::Timeout {
                during: "test",
            })
        };
        assert!(NewTabPreparedSessionError::GraphAuthority {
            detail: "pre-wire".into()
        }
        .permits_scratch_removal());
        assert!(NewTabPreparedSessionError::DefinitelyUnpublished {
            error: shell_error(),
            compensation: NewTabPreparedCompensationStatus::RolledBack,
        }
        .permits_scratch_removal());
        assert!(!NewTabPreparedSessionError::Refused {
            error: shell_error(),
            compensation: NewTabPreparedCompensationStatus::RolledBack,
        }
        .permits_scratch_removal());
        for status in [
            NewTabPreparedCompensationStatus::Missing,
            NewTabPreparedCompensationStatus::Changed,
            NewTabPreparedCompensationStatus::Referenced,
            NewTabPreparedCompensationStatus::Failed {
                detail: "failed".into(),
            },
        ] {
            assert!(!NewTabPreparedSessionError::DefinitelyUnpublished {
                error: shell_error(),
                compensation: status,
            }
            .permits_scratch_removal());
        }
        assert!(!NewTabPreparedSessionError::PossiblyApplied {
            detail: "ambiguous".into()
        }
        .permits_scratch_removal());
        assert!(!NewTabPreparedSessionError::FinalizedInvariant {
            detail: "post-grid".into(),
            compensation: NewTabPreparedCompensationStatus::RolledBack,
        }
        .permits_scratch_removal());

        let tmp_a = tempfile::tempdir().unwrap();
        let tmp_b = tempfile::tempdir().unwrap();
        let paths_a = maestro_shell::AppPaths::with_base(tmp_a.path());
        let paths_b = maestro_shell::AppPaths::with_base(tmp_b.path());
        let (prepared, receipt) = maestro_shell::prepare_fresh_scratch_cwd(
            &paths_a,
            "wrong-base-workspace",
            "wrong-base-session",
            "",
        )
        .unwrap()
        .into_parts();
        let scratch = prepared.cwd;
        let sentinel = scratch.join("KEEP");
        std::fs::write(&sentinel, b"keep").unwrap();
        let mut error = NewTabForegroundError::StartParams {
            cwd: scratch.clone(),
            scratch: Some(NewTabScratchRemovalAuthority::from_fresh_receipt(receipt)),
            error: NewTabStartParamsError::NotCreate,
        };
        let (mut runtime, _rx) = RendererTabRuntime::new();
        let report = execute_production_new_tab_recovery(
            &paths_b,
            &tmp_b.path().join("missing.sock"),
            1,
            &mut error,
            &[],
            &[],
            &mut runtime,
        );
        assert_eq!(report.outcomes.len(), 1);
        assert_eq!(report.failed_count(), 1);
        assert!(matches!(
            &report.outcomes[0].action,
            ResolvedNewTabRecoveryAction::RemoveScratch(path) if path == &scratch
        ));
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep");
        let replay = execute_production_new_tab_recovery(
            &paths_a,
            &tmp_a.path().join("missing.sock"),
            2,
            &mut error,
            &[],
            &[],
            &mut runtime,
        );
        assert!(
            replay.outcomes.is_empty(),
            "wrong-base use still consumed authority"
        );
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"keep");
    }

    #[test]
    fn live_recovery_without_exact_prior_authority_stays_neutral_with_closed_channel() {
        let err = post_record_set_tab_strip_failure();
        let context = NewTabRecoveryContext {
            window_id: Some(s("w-live")),
            tab_id: Some(s("tab-new")),
            session_id: Some(s("sess-new")),
            session_generation: Some(s("gen-new")),
            previous_strip_tabs: Some(vec![snapshot_tab("tab-old", "sess-old", 0)]),
            previous_selection: Some(vec![TabSelection {
                tab_id: s("tab-old"),
                session_id: s("sess-old"),
            }]),
            scratch_cwd: None,
        };
        let plan = resolve_new_tab_recovery(&err, &context);

        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let (mut runtime, closed_rx) = RendererTabRuntime::new();
        // A textual seed is deliberately not a lifetime proof. The exact-authority gate is reached
        // before transport, so even a closed channel cannot turn this into a raw restore attempt.
        runtime.seed_active_tab("w-other", "tab-old", "sess-old");
        let active_before = runtime.active_tab_id().map(str::to_string);
        drop(closed_rx); // closed renderer command channel
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let controller = ForegroundRendererStateController::new(&mut runtime, s("w-live"));
        let mut effects = ResolvedNewTabRecoveryCompleteEffects::new(paths, 1, killer, controller);
        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(report.failed_count(), 0);
        let revert_neutral = report.outcomes.iter().any(|outcome| {
            matches!(
                outcome.action,
                ResolvedNewTabRecoveryAction::RevertRendererStrip { .. }
            ) && matches!(
                &outcome.status,
                ResolvedNewTabRecoveryActionStatus::Skipped { reason }
                    if reason == "renderer remained neutral; exact prior lifetime was not reacquired"
            )
        });
        assert!(
            revert_neutral,
            "the prior projection is explicitly classified neutral"
        );
        // The controller never advanced the live active tab or emitted a command.
        assert_eq!(runtime.active_tab_id().map(str::to_string), active_before);
    }

    #[test]
    fn live_recovery_effects_unavailable_logs_empty_outcome_diagnostic() {
        // When the live effects object cannot be constructed (daemon client connect fails), the
        // listener emits exactly one execution diagnostic built from the resolved plan's diagnostic
        // with an EMPTY outcomes vector — the executor never ran. This pins that exact line shape.
        let err = post_record_set_tab_strip_failure();
        let diagnostic = classify_new_tab_foreground_failure(&err);
        let empty_report = ResolvedNewTabRecoveryExecutionReport {
            diagnostic,
            outcomes: Vec::new(),
        };
        let line = render_resolved_recovery_execution_log_line(&empty_report);

        assert!(!line.contains('\n'));
        assert!(line.contains("succeeded=0 skipped=0 failed=0"));
        assert!(line.contains("outcomes=[]"));
        assert!(!line.contains("=ok"));
        assert!(!line.contains("=skip("));
        assert!(!line.contains("=fail("));
    }

    #[test]
    fn live_recovery_production_controller_requires_exact_prior_authority_or_stays_neutral() {
        let (strip_tabs, selection) = renderer_state_payload();

        // A presentation-only recovery payload cannot reacquire a prior PTY lifetime.
        let (mut runtime, rx) = RendererTabRuntime::new();
        let mut controller = ForegroundRendererStateController::new(&mut runtime, "w-live");
        let restored = controller
            .revert_renderer_strip(&strip_tabs, &selection)
            .expect("neutral recovery is non-fatal");
        assert_eq!(restored, RendererStateRecoveryEffectResult::Neutralized);
        assert!(
            matches!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "neutral recovery sends no generation-free renderer command"
        );

        // A textual seed remains non-authoritative and cannot change that classification.
        let (mut runtime, rx) = RendererTabRuntime::new();
        runtime.seed_active_tab("w-live", "tab-old", "sess-old");
        let mut controller = ForegroundRendererStateController::new(&mut runtime, "w-live");
        let reconciled = controller
            .reconcile_renderer_state(&strip_tabs, &selection)
            .expect("textual prior state stays neutral");
        assert_eq!(reconciled, RendererStateRecoveryEffectResult::Neutralized);
        let revert = controller
            .revert_renderer_strip(&strip_tabs, &selection)
            .expect("repeated neutral recovery is stable");
        assert_eq!(revert, RendererStateRecoveryEffectResult::Neutralized);
        assert!(
            matches!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "neither attempt emits a raw strip/Attach command"
        );

        // Proof refusal precedes transport, so a closed channel still produces a neutral skip.
        let (mut runtime, closed_rx) = RendererTabRuntime::new();
        drop(closed_rx);
        let renderer_controller = ForegroundRendererStateController::new(&mut runtime, "w-live");
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let mut effects =
            ResolvedNewTabRecoveryCompleteEffects::new(paths, 1, killer, renderer_controller);
        let plan =
            resolved_recovery_plan(vec![ResolvedNewTabRecoveryAction::RevertRendererStrip {
                strip_tabs: strip_tabs.clone(),
                selection: selection.clone(),
            }]);
        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);
        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 1);
        assert_eq!(report.failed_count(), 0);
        let line = render_resolved_recovery_execution_log_line(&report);
        assert!(
            line.contains(
                "revert_renderer_strip(tabs=2,selection=2)=skip(renderer remained neutral; exact prior lifetime was not reacquired)"
            ),
            "{line}"
        );
    }

    #[test]
    fn resolved_new_tab_recovery_end_to_end_execution_log_for_post_record_set_tab_strip_failure() {
        // End-to-end through the real resolver, the real complete effects object, and the real
        // execution log line for a realistic post-record `SetTabStrip` failure. No live wiring: the
        // session killer and renderer-state controller are fakes; the tab record is real and backed
        // by `WindowLayoutService`, so the rollback action exercises the durable store.
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_exact_test_session(&paths, "sess-old", "gen-old");
        seed_exact_test_session(&paths, "sess-new", "gen-new");
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w-live", 0).expect("create layout");
        service
            .open_tab(
                "w-live",
                "tab-old",
                "sess-old",
                "old",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed prior tab");
        service
            .open_tab(
                "w-live",
                "tab-new",
                "sess-new",
                "new",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed planned tab");

        // Pre-attempt strip/selection snapshot the foreground listener would have captured.
        let previous_strip_tabs = vec![snapshot_tab("tab-old", "sess-old", 0)];
        let previous_selection = vec![TabSelection {
            tab_id: s("tab-old"),
            session_id: s("sess-old"),
        }];

        let err = generation_bound_set_tab_strip_failure();
        let context = foreground_new_tab_recovery_context(
            "w-live",
            "tab-new",
            "sess-new",
            &previous_strip_tabs,
            &previous_selection,
            &err,
        );

        // Resolver produces the post-record plan: rollback -> revert -> kill.
        let plan = resolve_new_tab_recovery(&err, &context);
        assert_eq!(
            plan.actions,
            vec![
                ResolvedNewTabRecoveryAction::RollbackTabRecord {
                    window_id: s("w-live"),
                    tab_id: s("tab-new"),
                },
                ResolvedNewTabRecoveryAction::RevertRendererStrip {
                    strip_tabs: previous_strip_tabs.clone(),
                    selection: previous_selection.clone(),
                },
                ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                    session_id: s("sess-new"),
                    expected_generation: s("gen-new"),
                },
            ],
            "resolver emits the post-record SetTabStrip recovery order"
        );

        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let controller = FakeRendererStateController {
            revert_result: Ok(RendererStateRecoveryEffectResult::Restored),
            reconcile_result: Ok(RendererStateRecoveryEffectResult::Restored),
            calls: Vec::new(),
        };
        let mut effects =
            ResolvedNewTabRecoveryCompleteEffects::new(paths.clone(), 7, killer, controller);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        // The durable record is actually rolled back: planned tab gone, prior tab kept.
        let reloaded = maestro_shell::WindowLayoutService::new(&paths)
            .load("w-live")
            .expect("load layout")
            .expect("layout exists");
        assert_eq!(reloaded.tabs.len(), 1);
        assert_eq!(reloaded.tabs[0].tab_id, "tab-old");

        // Fakes saw exactly the resolved calls.
        assert_eq!(effects.session_killer().calls, vec![s("sess-new@gen-new")]);
        assert_eq!(
            effects.renderer_controller().calls,
            vec![s("revert:1:1:tab-old")]
        );

        assert_eq!(report.succeeded_count(), 3);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 0);

        // The execution log line agrees end to end.
        let line = render_resolved_recovery_execution_log_line(&report);
        assert!(
            !line.contains('\n'),
            "execution line is single-line: {line}"
        );
        assert!(line.contains("stage=SetTabStrip"), "{line}");
        assert!(line.contains("succeeded=3 skipped=0 failed=0"), "{line}");
        let rollback = line
            .find("rollback_tab_record(w-live,tab-new)=ok")
            .expect("rollback outcome");
        let revert = line
            .find("revert_renderer_strip(tabs=1,selection=1)=ok")
            .expect("revert outcome");
        let kill = line
            .find("kill_session(sess-new)=ok")
            .expect("kill outcome");
        assert!(
            rollback < revert && revert < kill,
            "execution outcomes preserve resolved plan order: {line}"
        );
        assert!(
            !line.contains("missing"),
            "a fully-populated context renders no missing marker: {line}"
        );
    }

    #[test]
    fn resolved_new_tab_recovery_end_to_end_execution_log_for_pre_record_session_start_failure() {
        // End-to-end through the real resolver, the real complete effects object, and the real
        // execution log line for a realistic pre-record `SessionStart` failure. No live wiring: the
        // session killer is a fake, and there is no tab record or renderer state to restore.
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let scratch = tmp.path().join("scratch-cwd");
        std::fs::create_dir_all(scratch.join("nested")).expect("create scratch");
        std::fs::write(scratch.join("nested").join("marker"), b"orphan").expect("write marker");

        let err = session_start_foreground_error(scratch.clone());
        let context =
            foreground_new_tab_recovery_context("w-live", "tab-new", "sess-new", &[], &[], &err);

        // This legacy path-only SessionStart error has neither accepted Grid/generation proof nor
        // an owned fresh-scratch receipt. Recovery must synthesize neither an id-only Kill nor
        // recursive-delete authority from the diagnostic cwd string.
        let plan = resolve_new_tab_recovery(&err, &context);
        assert_eq!(
            plan.actions,
            vec![],
            "path-only SessionStart diagnostics grant no destructive recovery authority"
        );

        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let controller = FakeRendererStateController {
            revert_result: Ok(RendererStateRecoveryEffectResult::Restored),
            reconcile_result: Ok(RendererStateRecoveryEffectResult::Restored),
            calls: Vec::new(),
        };
        let mut effects = ResolvedNewTabRecoveryCompleteEffects::new(paths, 11, killer, controller);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert!(
            scratch.exists(),
            "path-only diagnostic cwd must remain untouched without an owned receipt"
        );
        assert!(
            effects.session_killer().calls.is_empty(),
            "no generation proof means no daemon kill call"
        );
        assert!(
            effects.renderer_controller().calls.is_empty(),
            "pre-record recovery must not call renderer-state effects"
        );
        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 0);

        let line = render_resolved_recovery_execution_log_line(&report);
        assert!(
            !line.contains('\n'),
            "execution line is single-line: {line}"
        );
        assert!(line.contains("stage=SessionStart"), "{line}");
        assert!(line.contains("succeeded=0 skipped=0 failed=0"), "{line}");
        assert!(
            !line.contains("remove_scratch("),
            "path-only cwd must not render scratch cleanup authority: {line}"
        );
        assert!(
            !line.contains("kill_session("),
            "pre-Grid failure must not render a kill authority: {line}"
        );
    }

    #[test]
    fn resolved_new_tab_recovery_end_to_end_execution_log_for_mixed_outcome_set_tab_strip_failure()
    {
        // End-to-end through the real resolver, the real complete effects object, and the real
        // execution log line for a realistic post-record `SetTabStrip` failure where one recovery
        // action fails non-fatally and later actions still run.
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        seed_exact_test_session(&paths, "sess-old", "gen-old");
        seed_exact_test_session(&paths, "sess-new", "gen-new");
        let service = maestro_shell::WindowLayoutService::new(&paths);
        service.create_empty("w-live", 0).expect("create layout");
        service
            .open_tab(
                "w-live",
                "tab-old",
                "sess-old",
                "old",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed prior tab");
        service
            .open_tab(
                "w-live",
                "tab-new",
                "sess-new",
                "new",
                false,
                maestro_shell::AttentionState::default(),
                0,
            )
            .expect("seed planned tab");
        let previous_strip_tabs = vec![snapshot_tab("tab-old", "sess-old", 0)];
        let previous_selection = vec![TabSelection {
            tab_id: s("tab-old"),
            session_id: s("sess-old"),
        }];
        let err = generation_bound_set_tab_strip_failure();
        let context = foreground_new_tab_recovery_context(
            "w-live",
            "tab-new",
            "sess-new",
            &previous_strip_tabs,
            &previous_selection,
            &err,
        );
        let plan = resolve_new_tab_recovery(&err, &context);
        assert_eq!(
            plan.actions,
            vec![
                ResolvedNewTabRecoveryAction::RollbackTabRecord {
                    window_id: s("w-live"),
                    tab_id: s("tab-new"),
                },
                ResolvedNewTabRecoveryAction::RevertRendererStrip {
                    strip_tabs: previous_strip_tabs,
                    selection: previous_selection,
                },
                ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                    session_id: s("sess-new"),
                    expected_generation: s("gen-new"),
                },
            ],
            "resolver emits rollback -> revert -> kill before mixed execution"
        );

        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::Killed),
            calls: Vec::new(),
        };
        let controller = FakeRendererStateController {
            revert_result: Err(s("renderer control closed")),
            reconcile_result: Ok(RendererStateRecoveryEffectResult::Restored),
            calls: Vec::new(),
        };
        let mut effects =
            ResolvedNewTabRecoveryCompleteEffects::new(paths.clone(), 13, killer, controller);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        let reloaded = maestro_shell::WindowLayoutService::new(&paths)
            .load("w-live")
            .expect("load layout")
            .expect("layout exists");
        assert_eq!(
            reloaded
                .tabs
                .iter()
                .map(|tab| tab.tab_id.as_str())
                .collect::<Vec<_>>(),
            vec!["tab-old"],
            "rollback succeeds before the renderer-state failure"
        );
        assert_eq!(
            effects.renderer_controller().calls,
            vec![s("revert:1:1:tab-old")]
        );
        assert_eq!(
            effects.session_killer().calls,
            vec![s("sess-new@gen-new")],
            "kill still runs after the non-fatal revert failure"
        );
        assert_eq!(report.succeeded_count(), 2);
        assert_eq!(report.skipped_count(), 0);
        assert_eq!(report.failed_count(), 1);

        let line = render_resolved_recovery_execution_log_line(&report);
        assert!(
            !line.contains('\n'),
            "execution line is single-line: {line}"
        );
        assert!(line.contains("stage=SetTabStrip"), "{line}");
        assert!(line.contains("succeeded=2 skipped=0 failed=1"), "{line}");
        let rollback = line
            .find("rollback_tab_record(w-live,tab-new)=ok")
            .expect("rollback outcome");
        let revert = line
            .find("revert_renderer_strip(tabs=1,selection=1)=fail(renderer control closed)")
            .expect("failed revert outcome");
        let kill = line
            .find("kill_session(sess-new)=ok")
            .expect("later kill outcome");
        assert!(
            rollback < revert && revert < kill,
            "execution outcomes preserve mixed plan order: {line}"
        );
    }

    #[test]
    fn resolved_new_tab_recovery_end_to_end_execution_log_for_missing_and_idempotent_skips() {
        // End-to-end through the real resolver, complete effects object, and execution log line for
        // a partial-context `AttachSession` failure: the record target is missing, while concrete
        // renderer/session targets are already current/already gone.
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let previous_strip_tabs = vec![snapshot_tab("tab-old", "sess-old", 0)];
        let previous_selection = vec![TabSelection {
            tab_id: s("tab-old"),
            session_id: s("sess-old"),
        }];
        let err =
            NewTabForegroundError::AttachSession(NewTabAttachSessionError::RendererControlClosed);
        let context = NewTabRecoveryContext {
            session_id: Some(s("sess-gone")),
            session_generation: Some(s("gen-gone")),
            previous_strip_tabs: Some(previous_strip_tabs.clone()),
            previous_selection: Some(previous_selection.clone()),
            ..Default::default()
        };

        let plan = resolve_new_tab_recovery(&err, &context);
        assert_eq!(
            plan.actions,
            vec![
                ResolvedNewTabRecoveryAction::MissingTabRecordTarget,
                ResolvedNewTabRecoveryAction::ReconcileRendererState {
                    strip_tabs: previous_strip_tabs,
                    selection: previous_selection,
                },
                ResolvedNewTabRecoveryAction::KillSessionIfGeneration {
                    session_id: s("sess-gone"),
                    expected_generation: s("gen-gone"),
                },
            ],
            "resolver preserves AttachSession recovery order with partial context"
        );

        let killer = FakeRecoverySessionKiller {
            result: Ok(KillSessionRecoveryEffectResult::AlreadyGone),
            calls: Vec::new(),
        };
        let controller = FakeRendererStateController {
            revert_result: Ok(RendererStateRecoveryEffectResult::Restored),
            reconcile_result: Ok(RendererStateRecoveryEffectResult::AlreadyCurrent),
            calls: Vec::new(),
        };
        let mut effects = ResolvedNewTabRecoveryCompleteEffects::new(paths, 17, killer, controller);

        let report = execute_resolved_new_tab_recovery_plan(&plan, &mut effects);

        assert_eq!(
            effects.renderer_controller().calls,
            vec![s("reconcile:1:1:sess-old")]
        );
        assert_eq!(
            effects.session_killer().calls,
            vec![s("sess-gone@gen-gone")]
        );
        assert_eq!(report.succeeded_count(), 0);
        assert_eq!(report.skipped_count(), 3);
        assert_eq!(report.failed_count(), 0);

        let line = render_resolved_recovery_execution_log_line(&report);
        assert!(
            !line.contains('\n'),
            "execution line is single-line: {line}"
        );
        assert!(line.contains("stage=AttachSession"), "{line}");
        assert!(line.contains("succeeded=0 skipped=3 failed=0"), "{line}");
        let missing = line
            .find("missing_tab_record_target=skip(missing_tab_record_target)")
            .expect("missing record target skip");
        let reconcile = line
            .find(
                "reconcile_renderer_state(tabs=1,selection=1)=skip(renderer state already reconciled)",
            )
            .expect("idempotent renderer reconcile skip");
        let kill = line
            .find("kill_session(sess-gone)=skip(session already gone)")
            .expect("idempotent kill skip");
        assert!(
            missing < reconcile && reconcile < kill,
            "execution outcomes preserve missing/idempotent plan order: {line}"
        );
    }

    // ---- NewTab foreground scratch-cwd outlier + tab-strip snapshot + event-wiring tests --------
    //
    // These were localized here from `lib.rs` beside their owning items
    // (`run_new_tab_foreground_pipeline`/`new_tab_failure_scratch_to_remove`,
    // `new_tab_snapshot_from_strip_tabs`, `plan_new_tab`). They reuse the private `new_tab::tests`
    // helpers above (`one_existing_tab_window`, `MapEnv`, `create_plan`, `snapshot_tab`,
    // `ScriptedIdGen`, `scratch_policy`). The retained NewTab planner id-collision/exhaustion/
    // determinism/mutation tests stay in `lib.rs`.

    #[test]
    fn new_tab_foreground_session_start_failure_carries_actual_prepared_scratch_cwd() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        one_existing_tab_window(&paths, "maestro-app-dev-project");

        let env = MapEnv::new(&[]);
        let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
        let argv = vec![s("/bin/zsh"), s("-l")];
        let (mut rt, _rx) = RendererTabRuntime::new();
        rt.seed_active_tab("w1", "t0", "sess-t0");
        let missing_socket = tmp.path().join("missing.sock");

        let mut err = run_new_tab_foreground_pipeline(
            NewTabForegroundRequest {
                paths: &paths,
                socket_path: missing_socket.clone(),
                window_id: "w1",
                plan: &plan,
                launch: NewTabForegroundLaunch::shell_adhoc(&argv),
                cols: 80,
                rows: 24,
                now_ms: 1_700_000_000,
                split_from: None,
                split_source_session: None,
                expected_project_id: None,
            },
            &env,
            &mut rt,
        )
        .expect_err("missing socket fails after scratch prepare");

        let expected = paths.scratch_base().join("sess-1");
        match &err {
            NewTabForegroundError::PreparedSessionStart {
                cwd,
                scratch: Some(_),
                error:
                    NewTabPreparedSessionError::DefinitelyUnpublished {
                        compensation: NewTabPreparedCompensationStatus::RolledBack,
                        ..
                    },
            } => {
                assert_eq!(cwd, &expected);
                assert!(cwd.is_dir(), "prepared scratch cwd exists before cleanup");
            }
            other => panic!("expected compensated prepared-start failure, got {other:?}"),
        }
        assert_eq!(
            new_tab_failure_scratch_to_remove(&err),
            Some(expected.as_path())
        );
        let report = execute_production_new_tab_recovery(
            &paths,
            &missing_socket,
            1_700_000_001,
            &mut err,
            &[],
            &[],
            &mut rt,
        );
        assert_eq!(report.succeeded_count(), 1);
        assert!(!expected.exists(), "D.U.+RolledBack consumes fresh receipt");
    }

    #[test]
    fn prepared_agent_reprobe_failure_cleans_owned_scratch_without_graph_or_path_log() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        one_existing_tab_window(&paths, "maestro-app-dev-project");
        let env = MapEnv::new(&[]);
        let plan = create_plan(
            "tab-agent",
            "sess-agent",
            NewTabLaunchSource::PreparedAgentAdHoc,
        );
        let expected = paths.scratch_base().join("sess-agent");
        let (mut runtime, rx) = RendererTabRuntime::new();
        runtime.seed_active_tab("w1", "t0", "sess-t0");
        let missing_socket = tmp.path().join("must-not-connect.sock");

        let mut error = run_new_tab_foreground_pipeline(
            NewTabForegroundRequest {
                paths: &paths,
                socket_path: missing_socket.clone(),
                window_id: "w1",
                plan: &plan,
                launch: NewTabForegroundLaunch::agent_adhoc(
                    vec!["/definitely/missing/hydra-agent".into()],
                    None,
                )
                .expect("absolute custom Agent source is valid"),
                cols: 80,
                rows: 24,
                now_ms: 1_700_000_000,
                split_from: None,
                split_source_session: None,
                expected_project_id: None,
            },
            &env,
            &mut runtime,
        )
        .expect_err("actual prepared-cwd reprobe refuses missing executable");
        assert!(matches!(
            &error,
            NewTabForegroundError::StartParams {
                scratch: Some(_),
                error: NewTabStartParamsError::PreparedLaunch,
                ..
            }
        ));
        assert!(
            expected.is_dir(),
            "exclusive scratch exists until recovery consumes it"
        );
        assert!(
            !error
                .to_string()
                .contains(&expected.to_string_lossy().to_string()),
            "user/log diagnostics must not expose prepared cwd bytes"
        );
        let report = execute_production_new_tab_recovery(
            &paths,
            &missing_socket,
            1_700_000_001,
            &mut error,
            &[],
            &[],
            &mut runtime,
        );
        assert_eq!(report.succeeded_count(), 1);
        assert!(!expected.exists());
        assert!(
            rx.try_recv().is_err(),
            "reprobe failure emits no renderer command"
        );
        assert!(maestro_shell::load_one::<maestro_shell::SessionRecord>(
            &paths,
            maestro_shell::RecordKind::Session,
            "sess-agent",
        )
        .unwrap()
        .is_none());
        assert_eq!(
            maestro_shell::WindowLayoutService::new(&paths)
                .load("w1")
                .unwrap()
                .unwrap()
                .tabs
                .len(),
            1
        );
    }

    #[test]
    fn new_tab_foreground_plain_and_consented_scratch_refuse_preexisting_same_id_cwd() {
        for consent_route in [false, true] {
            let tmp = tempfile::tempdir().expect("tempdir");
            let paths = maestro_shell::AppPaths::with_base(tmp.path());
            one_existing_tab_window(&paths, "maestro-app-dev-project");
            let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
            let cwd = paths.scratch_base().join("sess-1");
            std::fs::create_dir_all(&cwd).unwrap();
            let sentinel = cwd.join("KEEP");
            std::fs::write(&sentinel, b"earlier lifetime").unwrap();
            let argv = vec![s("/bin/zsh"), s("-l")];
            let env = MapEnv::new(&[]);
            let (mut runtime, rx) = RendererTabRuntime::new();
            runtime.seed_active_tab("w1", "t0", "sess-t0");
            let request = NewTabForegroundRequest {
                paths: &paths,
                socket_path: tmp.path().join("must-not-connect.sock"),
                window_id: "w1",
                plan: &plan,
                launch: NewTabForegroundLaunch::shell_adhoc(&argv),
                cols: 80,
                rows: 24,
                now_ms: 1_700_000_000,
                split_from: None,
                split_source_session: None,
                expected_project_id: None,
            };
            let result = if consent_route {
                let workspace = match maestro_shell::load_one::<maestro_shell::Workspace>(
                    &paths,
                    maestro_shell::RecordKind::Workspace,
                    "maestro-app-dev",
                )
                .unwrap()
                {
                    Some(maestro_shell::LoadOutcome::Loaded(workspace)) => workspace,
                    other => panic!("expected exact Scratch workspace, got {other:?}"),
                };
                run_new_tab_foreground_pipeline_with_consent(
                    request,
                    &workspace,
                    &env,
                    &mut runtime,
                )
            } else {
                run_new_tab_foreground_pipeline(request, &env, &mut runtime)
            };
            assert!(matches!(
                result,
                Err(NewTabForegroundError::WorkspacePrepare(
                    NewTabWorkspacePrepareError::WorkspaceExec(
                        maestro_shell::WorkspaceExecError::FreshScratchCwdAlreadyExists { .. }
                    )
                ))
            ));
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"earlier lifetime");
            assert!(rx.try_recv().is_err(), "refusal sends zero renderer bytes");
            let layout = maestro_shell::WindowLayoutService::new(&paths)
                .load("w1")
                .unwrap()
                .unwrap();
            assert_eq!(layout.tabs.len(), 1, "refusal writes no prepared tab");
        }
    }

    #[test]
    fn new_tab_foreground_graph_refusal_consumes_only_its_fresh_scratch_receipt() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        let plan = create_plan("tab-1", "sess-1", NewTabLaunchSource::DefaultShellDev);
        let argv = vec![s("/bin/zsh"), s("-l")];
        let env = MapEnv::new(&[]);
        let (mut runtime, rx) = RendererTabRuntime::new();
        let mut error = run_new_tab_foreground_pipeline(
            NewTabForegroundRequest {
                paths: &paths,
                socket_path: tmp.path().join("must-not-connect.sock"),
                window_id: "missing-window",
                plan: &plan,
                launch: NewTabForegroundLaunch::shell_adhoc(&argv),
                cols: 80,
                rows: 24,
                now_ms: 1,
                split_from: None,
                split_source_session: None,
                expected_project_id: None,
            },
            &env,
            &mut runtime,
        )
        .expect_err("missing exact window graph must fail before daemon wire");
        assert!(matches!(
            &error,
            NewTabForegroundError::PreparedSessionStart {
                scratch: Some(_),
                error: NewTabPreparedSessionError::GraphAuthority { .. },
                ..
            }
        ));
        assert!(rx.try_recv().is_err());
        let cwd = paths.scratch_base().join("sess-1");
        assert!(cwd.is_dir());
        let report = execute_production_new_tab_recovery(
            &paths,
            &tmp.path().join("unused.sock"),
            2,
            &mut error,
            &[],
            &[],
            &mut runtime,
        );
        assert_eq!(report.succeeded_count(), 1);
        assert!(!cwd.exists());
    }

    #[test]
    fn refused_and_possibly_applied_never_consume_fresh_scratch_cleanup() {
        for possibly_applied in [false, true] {
            let tmp = tempfile::tempdir().unwrap();
            let paths = maestro_shell::AppPaths::with_base(tmp.path());
            let session_id = if possibly_applied {
                "possibly-session"
            } else {
                "refused-session"
            };
            let (prepared, receipt) =
                maestro_shell::prepare_fresh_scratch_cwd(&paths, "workspace", session_id, "")
                    .unwrap()
                    .into_parts();
            let sentinel = prepared.cwd.join("KEEP");
            std::fs::write(&sentinel, b"may be daemon-owned").unwrap();
            let prepared_error = if possibly_applied {
                NewTabPreparedSessionError::PossiblyApplied {
                    detail: "request admission ambiguous".into(),
                }
            } else {
                NewTabPreparedSessionError::Refused {
                    error: maestro_shell::ShellRuntimeError::Daemon(
                        maestro_shell::DaemonClientError::Timeout { during: "test" },
                    ),
                    compensation: NewTabPreparedCompensationStatus::RolledBack,
                }
            };
            let mut error = NewTabForegroundError::PreparedSessionStart {
                cwd: prepared.cwd.clone(),
                scratch: Some(NewTabScratchRemovalAuthority::from_fresh_receipt(receipt)),
                error: prepared_error,
            };
            let (mut runtime, _rx) = RendererTabRuntime::new();
            let report = execute_production_new_tab_recovery(
                &paths,
                &tmp.path().join("unused.sock"),
                1,
                &mut error,
                &[],
                &[],
                &mut runtime,
            );
            assert!(report.outcomes.is_empty());
            assert_eq!(std::fs::read(&sentinel).unwrap(), b"may be daemon-owned");
            assert!(new_tab_failure_scratch_to_remove(&error).is_none());
        }
    }

    #[test]
    fn new_tab_snapshot_collects_tab_and_session_ids() {
        let tabs = vec![
            snapshot_tab("tab-0", "sess-0", 0),
            snapshot_tab("tab-1", "sess-1", 1),
        ];
        let snapshot = new_tab_snapshot_from_strip_tabs(&tabs, None);
        assert_eq!(snapshot.existing_tab_ids, vec![s("tab-0"), s("tab-1")]);
        assert_eq!(
            snapshot.existing_session_ids,
            vec![s("sess-0"), s("sess-1")]
        );
        assert_eq!(snapshot.active_tab_id, None);
    }

    #[test]
    fn new_tab_snapshot_carries_active_tab_id_when_supplied() {
        let tabs = vec![snapshot_tab("tab-0", "sess-0", 0)];
        let snapshot = new_tab_snapshot_from_strip_tabs(&tabs, Some("tab-0"));
        assert_eq!(snapshot.active_tab_id, Some(s("tab-0")));
    }

    #[test]
    fn new_tab_event_wiring_no_policy_declines_without_id_gen() {
        // Mirrors the foreground `NewTabRequested` arm: a `None` policy (no
        // `--new-tab-default-shell`) must decline WITHOUT minting any id, even when a scripted
        // generator is supplied. Proves the listener can match and plan a window-bound event with no
        // tab/session identity safely.
        let tabs = vec![snapshot_tab("tab-0", "sess-0", 0)];
        let snapshot = new_tab_snapshot_from_strip_tabs(&tabs, Some("tab-0"));
        let mut id_gen = ScriptedIdGen::new(&["unused"], &["unused"]);
        let plan = plan_new_tab(None, &snapshot, &mut id_gen);
        assert_eq!(plan, NewTabPlan::Decline);
        assert_eq!(id_gen.tab_calls, 0);
        assert_eq!(id_gen.session_calls, 0);
    }

    #[test]
    fn new_tab_event_wiring_explicit_policy_creates_uuid_shaped_ids() {
        // Mirrors the foreground `NewTabRequested` arm with the EXPLICIT policy + production
        // `UuidIdGen`: a `Create` with UUID-shaped, distinct, snapshot-unique ids. The planner returns
        // a plan only — no renderer command is constructed or sent by this planning step.
        let tabs = vec![snapshot_tab("tab-0", "sess-0", 0)];
        let snapshot = new_tab_snapshot_from_strip_tabs(&tabs, Some("tab-0"));
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut UuidIdGen);
        match plan {
            NewTabPlan::Create {
                tab_id, session_id, ..
            } => {
                // UUID v4 string form: 36 chars, 4 hyphens at the canonical positions.
                for id in [&tab_id, &session_id] {
                    assert_eq!(id.len(), 36, "expected UUID-shaped id, got {id:?}");
                    assert_eq!(id.matches('-').count(), 4, "expected 4 hyphens in {id:?}");
                }
                assert_ne!(tab_id, session_id);
                assert!(!snapshot.existing_tab_ids.contains(&tab_id));
                assert!(!snapshot.existing_session_ids.contains(&session_id));
            }
            other => panic!("expected Create, got {other:?}"),
        }
    }

    // ---- new-tab planner / id-generator edge cases -----------------------------------------
    // Localized here (from `lib.rs`) beside their owning items (`plan_new_tab`, `NewTabPlan`,
    // `NewTabAbortReason`, `ID_MINT_ATTEMPTS`, `IdGen`/`UuidIdGen`), reached via `use super::*;`.
    // They reuse the existing private `new_tab::tests` fixtures `ScriptedIdGen`, `scratch_policy`,
    // and `snapshot_with` (defined above in this module).

    #[test]
    fn new_tab_tab_id_collision_remints() {
        // First minted tab id collides with the snapshot; the second is taken.
        let mut id_gen = ScriptedIdGen::new(&["dup", "tab-ok"], &["sess-1"]);
        let snapshot = snapshot_with(&["dup"], &[]);
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        if let NewTabPlan::Create { tab_id, .. } = plan {
            assert_eq!(tab_id, "tab-ok");
            assert_eq!(
                id_gen.tab_calls, 2,
                "must re-mint exactly once on collision"
            );
        } else {
            panic!("expected Create after re-mint");
        }
    }

    #[test]
    fn new_tab_session_id_collision_remints() {
        let mut id_gen = ScriptedIdGen::new(&["tab-1"], &["dup", "sess-ok"]);
        let snapshot = snapshot_with(&[], &["dup"]);
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        if let NewTabPlan::Create { session_id, .. } = plan {
            assert_eq!(session_id, "sess-ok");
            assert_eq!(id_gen.session_calls, 2, "must re-mint exactly once");
        } else {
            panic!("expected Create after re-mint");
        }
    }

    #[test]
    fn new_tab_tab_id_exhaustion_aborts() {
        // Every minted tab id collides: ID_MINT_ATTEMPTS mints, then abort. Session ids never run.
        let dups: Vec<&str> = std::iter::repeat_n("dup", ID_MINT_ATTEMPTS as usize).collect();
        let mut id_gen = ScriptedIdGen::new(&dups, &["sess-1"]);
        let snapshot = snapshot_with(&["dup"], &[]);
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        assert_eq!(
            plan,
            NewTabPlan::Abort {
                reason: NewTabAbortReason::TabIdMintExhausted
            }
        );
        assert_eq!(id_gen.tab_calls, ID_MINT_ATTEMPTS);
        assert_eq!(
            id_gen.session_calls, 0,
            "tab exhaustion must abort before any session mint"
        );
    }

    #[test]
    fn new_tab_session_id_exhaustion_aborts() {
        let tab = ["tab-ok"];
        let dups: Vec<&str> = std::iter::repeat_n("dup", ID_MINT_ATTEMPTS as usize).collect();
        let mut id_gen = ScriptedIdGen::new(&tab, &dups);
        let snapshot = snapshot_with(&[], &["dup"]);
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        assert_eq!(
            plan,
            NewTabPlan::Abort {
                reason: NewTabAbortReason::SessionIdMintExhausted
            }
        );
        assert_eq!(id_gen.tab_calls, 1);
        assert_eq!(id_gen.session_calls, ID_MINT_ATTEMPTS);
    }

    #[test]
    fn new_tab_deterministic_id_gen_is_predictable() {
        let snapshot = snapshot_with(&[], &[]);
        let make = || {
            let mut g = ScriptedIdGen::new(&["tab-1"], &["sess-1"]);
            plan_new_tab(Some(&scratch_policy()), &snapshot, &mut g)
        };
        assert_eq!(make(), make(), "same script must yield the same plan");
    }

    #[test]
    fn new_tab_planner_does_not_mutate_snapshot() {
        let snapshot = snapshot_with(&["tab-old"], &["sess-old"]);
        let before = snapshot.clone();
        let mut id_gen = ScriptedIdGen::new(&["tab-1"], &["sess-1"]);
        let _ = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        assert_eq!(snapshot, before, "planner must not mutate the snapshot");
    }

    #[test]
    fn new_tab_session_id_equal_to_tab_id_remints() {
        // The generator hands out the SAME string ("same") for the tab id and the first session id.
        // The planner must treat the equal session candidate as a collision and re-mint a distinct
        // value, never producing Create { tab_id: "same", session_id: "same" }.
        let mut id_gen = ScriptedIdGen::new(&["same"], &["same", "sess-ok"]);
        let snapshot = snapshot_with(&[], &[]);
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        if let NewTabPlan::Create {
            tab_id, session_id, ..
        } = plan
        {
            assert_eq!(tab_id, "same");
            assert_eq!(session_id, "sess-ok");
            assert_ne!(
                tab_id, session_id,
                "tab_id and session_id must never be equal"
            );
            assert_eq!(
                id_gen.session_calls, 2,
                "an equal-to-tab session candidate must re-mint exactly once"
            );
        } else {
            panic!("expected Create after re-minting the tab-equal session id");
        }
    }

    #[test]
    fn new_tab_session_id_always_equal_to_tab_id_aborts() {
        // Every session candidate equals the accepted tab id for the bounded attempts -> abort.
        let dups: Vec<&str> = std::iter::repeat_n("same", ID_MINT_ATTEMPTS as usize).collect();
        let mut id_gen = ScriptedIdGen::new(&["same"], &dups);
        let snapshot = snapshot_with(&[], &[]);
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        assert_eq!(
            plan,
            NewTabPlan::Abort {
                reason: NewTabAbortReason::SessionIdMintExhausted
            }
        );
        assert_eq!(id_gen.tab_calls, 1);
        assert_eq!(id_gen.session_calls, ID_MINT_ATTEMPTS);
    }

    #[test]
    fn uuid_id_gen_tab_ids_are_v4_uuids() {
        let mut g = UuidIdGen;
        let id = g.next_tab_id();
        let parsed = uuid::Uuid::parse_str(&id).expect("tab id must parse as a UUID");
        assert_eq!(parsed.get_version(), Some(uuid::Version::Random));
    }

    #[test]
    fn uuid_id_gen_session_ids_are_v4_uuids() {
        let mut g = UuidIdGen;
        let id = g.next_session_id();
        let parsed = uuid::Uuid::parse_str(&id).expect("session id must parse as a UUID");
        assert_eq!(parsed.get_version(), Some(uuid::Version::Random));
    }

    #[test]
    fn uuid_id_gen_tab_and_session_mints_are_independent() {
        let mut g = UuidIdGen;
        let tab = g.next_tab_id();
        let session = g.next_session_id();
        assert_ne!(tab, session, "independent v4 mints must differ");
    }

    #[test]
    fn new_tab_with_uuid_id_gen_creates_uuid_ids() {
        let mut id_gen = UuidIdGen;
        let snapshot = snapshot_with(&[], &[]);
        let plan = plan_new_tab(Some(&scratch_policy()), &snapshot, &mut id_gen);
        if let NewTabPlan::Create {
            tab_id, session_id, ..
        } = plan
        {
            let tab = uuid::Uuid::parse_str(&tab_id).expect("tab_id must parse as a UUID");
            let session =
                uuid::Uuid::parse_str(&session_id).expect("session_id must parse as a UUID");
            assert_eq!(tab.get_version(), Some(uuid::Version::Random));
            assert_eq!(session.get_version(), Some(uuid::Version::Random));
            // Both the independent mint calls and the planner's reserved-id guard ensure this.
            assert_ne!(tab_id, session_id, "tab_id and session_id must be distinct");
        } else {
            panic!("expected Create with the production generator");
        }
    }

    // ---- preset restore availability gate -------------------------------------------------------
    //
    // Non-empty restore remains fail-closed until exact topology + renderer coordination exists.
    // These tests pin ordered refusal and zero mutation; the binary smoke pins the callsite before
    // target/log/daemon effects.

    fn restore_slot(
        index: u32,
        title: &str,
        action: maestro_shell::PresetRestoreAction,
    ) -> maestro_shell::PresetRestoreSlot {
        maestro_shell::PresetRestoreSlot {
            index,
            title: title.to_string(),
            pinned: false,
            split_from: None,
            action,
        }
    }

    fn preset_source_tab(
        index: u32,
        source_tab_id: &str,
    ) -> maestro_shell::records::LayoutPresetTab {
        maestro_shell::records::LayoutPresetTab {
            index,
            title: format!("slot-{index}"),
            pinned: false,
            split_from: None,
            session_id: None,
            source_tab_id: source_tab_id.to_string(),
        }
    }

    fn reattach(session_id: &str) -> maestro_shell::PresetRestoreAction {
        maestro_shell::PresetRestoreAction::Reattach {
            session_id: session_id.to_string(),
        }
    }

    #[test]
    fn preset_restore_preflight_is_ordered_empty_safe_and_pending_aware() {
        assert!(preflight_preset_restore(&[], false).is_ok());
        assert!(
            preflight_preset_restore(&[], true).is_ok(),
            "an empty preset is a no-op even while another viewport request is pending"
        );

        let launch = vec![restore_slot(
            4,
            "fresh",
            maestro_shell::PresetRestoreAction::LaunchFresh,
        )];
        assert!(matches!(
            preflight_preset_restore(&launch, false),
            Err(PresetRestoreError::LaunchFreshRequiresAsyncHandoff { index: 4 })
        ));
        assert!(matches!(
            preflight_preset_restore(&launch, true),
            Err(PresetRestoreError::RendererHandoffPending)
        ));

        let reattach_then_launch = vec![
            restore_slot(7, "retained", reattach("sess-live")),
            restore_slot(8, "fresh", maestro_shell::PresetRestoreAction::LaunchFresh),
        ];
        assert!(matches!(
            preflight_preset_restore(&reattach_then_launch, false),
            Err(PresetRestoreError::ReattachRequiresExactViewport { index: 7 })
        ));

        let launch_then_reattach = vec![
            restore_slot(9, "fresh", maestro_shell::PresetRestoreAction::LaunchFresh),
            restore_slot(10, "retained", reattach("sess-live")),
        ];
        assert!(matches!(
            preflight_preset_restore(&launch_then_reattach, false),
            Err(PresetRestoreError::LaunchFreshRequiresAsyncHandoff { index: 9 })
        ));
    }

    #[test]
    fn execute_preset_restore_reattach_fails_closed_before_id_or_layout_mutation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        // The restore target window must already have a layout record (the caller load_or_creates it).
        maestro_shell::WindowLayoutService::new(&paths)
            .create_empty("win-restore", 1)
            .expect("seed empty target layout");

        let plan = vec![
            restore_slot(0, "backend", reattach("sess-live-0")),
            restore_slot(1, "logs", reattach("sess-live-1")),
        ];
        let source_tabs = vec![
            preset_source_tab(0, "orig-0"),
            preset_source_tab(1, "orig-1"),
        ];
        // Mint two fresh tab ids; reattach never mints session ids (sessions already exist).
        let mut id_gen = ScriptedIdGen::new(&["new-0", "new-1"], &[]);
        let (mut runtime, _commands) = RendererTabRuntime::new();
        let env = MapEnv::new(&[]);

        let error = execute_preset_restore(
            PresetRestoreRequest {
                paths: &paths,
                socket_path: tmp.path().join("does-not-open.sock"),
                window_id: "win-restore",
                plan: &plan,
                source_tabs: &source_tabs,
                policy: &scratch_policy(),
                argv: &[s("/bin/sh")],
                cols: 80,
                rows: 24,
                now_ms: 2,
            },
            &env,
            &mut id_gen,
            &mut runtime,
        )
        .expect_err("id-only reattach must fail closed");
        assert!(matches!(
            error,
            PresetRestoreError::ReattachRequiresExactViewport { index: 0 }
        ));
        assert_eq!(id_gen.tab_calls, 0);
        assert_eq!(id_gen.session_calls, 0);
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-restore")
            .unwrap()
            .unwrap();
        assert!(layout.tabs.is_empty());
    }

    #[test]
    fn execute_preset_restore_split_reattach_fails_before_parent_or_child_mutation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        maestro_shell::WindowLayoutService::new(&paths)
            .create_empty("win-restore", 1)
            .expect("seed empty target layout");

        // Slot 1 is a split CHILD of slot 0 (capture-time source id "orig-0"), with a captured ratio.
        let mut child = restore_slot(1, "child", reattach("sess-live-1"));
        child.split_from = Some(maestro_shell::records::SplitFrom {
            tab_id: "orig-0".to_string(),
            axis: maestro_shell::SplitAxis::Right,
            ratio_per_mille: Some(700),
        });
        child.pinned = true;
        let plan = vec![restore_slot(0, "parent", reattach("sess-live-0")), child];
        let source_tabs = vec![
            preset_source_tab(0, "orig-0"),
            preset_source_tab(1, "orig-1"),
        ];
        let mut id_gen = ScriptedIdGen::new(&["new-0", "new-1"], &[]);
        let (mut runtime, _commands) = RendererTabRuntime::new();
        let env = MapEnv::new(&[]);

        let error = execute_preset_restore(
            PresetRestoreRequest {
                paths: &paths,
                socket_path: tmp.path().join("does-not-open.sock"),
                window_id: "win-restore",
                plan: &plan,
                source_tabs: &source_tabs,
                policy: &scratch_policy(),
                argv: &[s("/bin/sh")],
                cols: 80,
                rows: 24,
                now_ms: 2,
            },
            &env,
            &mut id_gen,
            &mut runtime,
        )
        .expect_err("split reattach requires exact viewport authority");
        assert!(matches!(
            error,
            PresetRestoreError::ReattachRequiresExactViewport { index: 0 }
        ));
        assert_eq!(id_gen.tab_calls, 0);
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-restore")
            .unwrap()
            .unwrap();
        assert!(layout.tabs.is_empty());
    }

    #[test]
    fn execute_preset_restore_orphan_reattach_fails_before_fallback_mutation() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let paths = maestro_shell::AppPaths::with_base(tmp.path());
        maestro_shell::WindowLayoutService::new(&paths)
            .create_empty("win-restore", 1)
            .expect("seed empty target layout");

        // A single slot that claims to split from a source NOT present in this restore.
        let mut orphan = restore_slot(0, "orphan", reattach("sess-live-0"));
        orphan.split_from = Some(maestro_shell::records::SplitFrom {
            tab_id: "absent-source".to_string(),
            axis: maestro_shell::SplitAxis::Down,
            ratio_per_mille: Some(300),
        });
        let plan = vec![orphan];
        let source_tabs = vec![preset_source_tab(0, "orig-0")];
        let mut id_gen = ScriptedIdGen::new(&["new-0"], &[]);
        let (mut runtime, _commands) = RendererTabRuntime::new();
        let env = MapEnv::new(&[]);

        let error = execute_preset_restore(
            PresetRestoreRequest {
                paths: &paths,
                socket_path: tmp.path().join("does-not-open.sock"),
                window_id: "win-restore",
                plan: &plan,
                source_tabs: &source_tabs,
                policy: &scratch_policy(),
                argv: &[s("/bin/sh")],
                cols: 80,
                rows: 24,
                now_ms: 2,
            },
            &env,
            &mut id_gen,
            &mut runtime,
        )
        .expect_err("orphan reattach requires exact viewport authority");
        assert!(matches!(
            error,
            PresetRestoreError::ReattachRequiresExactViewport { index: 0 }
        ));
        assert_eq!(id_gen.tab_calls, 0);
        let layout = maestro_shell::WindowLayoutService::new(&paths)
            .load("win-restore")
            .unwrap()
            .unwrap();
        assert!(layout.tabs.is_empty());
    }
}
