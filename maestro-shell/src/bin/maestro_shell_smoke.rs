//! `maestro-shell-smoke` — a minimal dev/smoke CLI over [`ShellRuntime`].
//!
//! It makes the runtime exercisable from the command line against an ALREADY-RUNNING
//! `pty-daemon`: resolve/connect, then either start+attach one session or reconcile persisted
//! session records, printing a machine-readable JSON summary. It is NOT the final app UI and does
//! NOT spawn, supervise, probe, or kill a daemon, attach a raw PTY, or launch the renderer.
//!
//! Commands:
//! - `start    --session-id <id> --workspace-id <id>`
//!   `           (--cwd <dir> | --scratch | --worktree <repo-root> --allow-worktree-create`
//!   `            | --repo-write <repo-root> --allow-repo-write)`
//!   `           [--base <path>] [--socket <path>] [--cols <u16>] [--rows <u16>]`
//!   `           [--kind <shell|agent>] -- <argv...>`
//!   Plain shell/session start — always `SessionKind::Shell` unless `--kind agent` is passed
//!   explicitly (it never becomes an agent TASK; that is what `agent-start` is for).
//! - `reconcile [--base <path>] [--socket <path>]`
//!   Session-record reconciliation; the success JSON now also lists `recovered_sessions`
//!   (live daemon ids with no loadable current-version record — surfaced read-only).
//! - `task-reconcile --base <path>` (local-only, no daemon): read-only join of
//!   AgentTask records against session records via [`AgentTaskReconciler`].
//! - `agent-start  --agent-task-id <id> --project-id <id> --goal <text>`
//!   `              --session-id <id> --workspace-id <id> <cwd-mode> -- <argv...>`
//!   Create a NEW agent task and start its first session (`SessionKind::Agent`) via
//!   [`AgentTaskRuntime::start_new_agent_task`].
//! - `agent-resume --agent-task-id <id> --session-id <id> --workspace-id <id>`
//!   `              <cwd-mode> -- <argv...>`
//!   Resume/retry an EXISTING agent task on a fresh session (`SessionKind::Agent`) via
//!   [`AgentTaskRuntime::resume_agent_task`]. The caller supplies fresh argv — the task's
//!   stored `LaunchSpec` is never replayed.
//!
//! Cwd selection — exactly one of:
//! - `--cwd <dir>`: the caller's existing directory, verbatim.
//! - `--scratch`: prepare the shell-owned `<app-support>/scratch/<session-id>`
//!   directory (owner-only `0700`) and run the session there.
//! - `--worktree <repo-root> --allow-worktree-create` (dev-facing and explicit):
//!   create or load the Workspace record for `--workspace-id` under `--base` (policy `Worktree`,
//!   root `<repo-root>`), grant ONLY `worktree_create` consent, then drive the consent-gated
//!   worktree executor and run the session in the prepared worktree.
//!
//!   WARNING: worktree creation MUTATES git administrative state under the source repo
//!   (`<repo-root>/.git/worktrees/...`) and creates the checkout under app-support
//!   (`<base>/worktrees/<workspace-id>/<session-id>` on branch
//!   `maestro/<workspace-id>/<session-id>`). That is why `--allow-worktree-create` is required —
//!   there is no default, no repo-root inference from the current directory, no `RepoWrite`
//!   grant, and no worktree removal/cleanup here. An existing Workspace record with the same id
//!   but a different root/policy is a hard error, never silently overwritten.
//! - `--repo-write <repo-root> --allow-repo-write` (dev-facing and explicit):
//!   create or load the Workspace record for `--workspace-id` under `--base` (policy
//!   `RepoWrite`, root `<repo-root>`), grant ONLY `repo_write` consent (never
//!   `worktree_create`), then drive the consent-gated repo-write executor and run the session
//!   with cwd EQUAL to `<repo-root>` itself.
//!
//!   WARNING: this runs the session DIRECTLY IN THE LIVE CHECKOUT / repo root and may allow the
//!   process to write there — no scratch dir, no worktree, no isolation. That is why
//!   `--allow-repo-write` is required; there is no default and no repo-root inference. The
//!   preparation itself runs no git and creates/deletes/chmods nothing; only the session you
//!   start may write. Same record rules: a same-id record with a different root/policy is a
//!   hard error, never silently overwritten.
//!
//! Output contract: success -> one JSON object on STDOUT (`ok: true`, ...); failure -> one JSON
//! object on STDERR (`ok: false`, `error_kind`, `message`) and a non-zero exit. The parsing and
//! JSON-shaping are pure helpers (below) so they unit-test without a daemon.

use std::path::PathBuf;
use std::process::ExitCode;

use maestro_shell::{
    grant_consent, load_one, prepare_scratch_cwd, prepare_workspace_with_consent, write_record,
    AgentTaskReconcileReport, AgentTaskReconciler, AgentTaskRuntime, AgentTaskRuntimeError,
    AgentTaskState, AppPaths, Attention, AttentionSource, AttentionState, DashboardSnapshot,
    DashboardSnapshotService, LoadOutcome, ReconcileOutcome, RecordKind, SessionKind, ShellRuntime,
    ShellRuntimeError, SplitAxis, StartAgentTaskOutcome, StartParams, StartSessionOutcome,
    WindowLayout, WindowLayoutError, WindowLayoutService, WindowTabView, Workspace,
    WorkspaceConsent, WorkspaceConsentError, WorkspaceConsentKind, WorkspaceExecError,
    WorkspacePolicy,
};
use serde_json::json;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(json_line) => {
            println!("{json_line}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("{}", err.to_json_line());
            ExitCode::FAILURE
        }
    }
}

/// Parse `args` and dispatch to the chosen command, returning the success JSON line. All real IO
/// (resolve/connect/start/reconcile) happens here; the helpers it calls are pure.
fn run(args: &[String]) -> Result<String, SmokeError> {
    let command = args.first().ok_or_else(|| {
        SmokeError::usage(
            "missing command; expected `start`, `reconcile`, `task-reconcile`, `agent-start`, \
             `agent-resume`, `window`, or `dashboard`",
        )
    })?;
    match command.as_str() {
        "start" => {
            let parsed = StartArgs::parse(&args[1..])?;
            let outcome = run_start(&parsed)?;
            Ok(start_success_json(&outcome).to_string())
        }
        "reconcile" => {
            let parsed = ReconcileArgs::parse(&args[1..])?;
            let outcome = run_reconcile(&parsed)?;
            Ok(reconcile_success_json(&outcome).to_string())
        }
        "task-reconcile" => {
            let parsed = TaskReconcileArgs::parse(&args[1..])?;
            let report = run_task_reconcile(&parsed)?;
            Ok(task_reconcile_success_json(&report).to_string())
        }
        "agent-start" => {
            let parsed = AgentStartArgs::parse(&args[1..])?;
            let outcome = run_agent_start(&parsed)?;
            Ok(agent_start_success_json(&outcome).to_string())
        }
        "agent-resume" => {
            let parsed = AgentResumeArgs::parse(&args[1..])?;
            let outcome = run_agent_resume(&parsed)?;
            Ok(agent_resume_success_json(&outcome).to_string())
        }
        "window" => run_window(&args[1..]),
        "dashboard" => {
            let parsed = DashboardArgs::parse(&args[1..])?;
            let outcome = run_dashboard(&parsed)?;
            Ok(dashboard_success_json(&outcome).to_string())
        }
        other => Err(SmokeError::usage(format!(
            "unknown command {other:?}; expected `start`, `reconcile`, `task-reconcile`, \
             `agent-start`, `agent-resume`, `window`, or `dashboard`"
        ))),
    }
}

/// `window <subcommand>` group: local-only durable window/tab layout operations over
/// [`WindowLayoutService`]. No daemon, no socket. Every layout-mutating subcommand prints the
/// updated layout JSON; `view` joins the layout against [`AgentTaskReconciler`].
fn run_window(args: &[String]) -> Result<String, SmokeError> {
    let sub = args.first().ok_or_else(window_usage)?;
    match sub.as_str() {
        "create" => {
            let parsed = WindowCreateArgs::parse(&args[1..])?;
            let layout = run_window_create(&parsed)?;
            Ok(layout_success_json("window create", &layout).to_string())
        }
        "show" => {
            let parsed = WindowShowArgs::parse(&args[1..])?;
            let layout = run_window_show(&parsed)?;
            Ok(layout_success_json("window show", &layout).to_string())
        }
        "open-tab" => {
            let parsed = WindowOpenTabArgs::parse(&args[1..])?;
            let layout = run_window_open_tab(&parsed)?;
            Ok(layout_success_json("window open-tab", &layout).to_string())
        }
        "split-tab" => {
            let parsed = WindowSplitTabArgs::parse(&args[1..])?;
            let layout = run_window_split_tab(&parsed)?;
            Ok(layout_success_json("window split-tab", &layout).to_string())
        }
        "close-tab" => {
            let parsed = WindowTabRefArgs::parse(&args[1..], "close-tab")?;
            let layout = run_window_mutate(&parsed, WindowMutation::Close)?;
            Ok(layout_success_json("window close-tab", &layout).to_string())
        }
        "rename-tab" => {
            let parsed = WindowRenameTabArgs::parse(&args[1..])?;
            let layout = run_window_rename(&parsed)?;
            Ok(layout_success_json("window rename-tab", &layout).to_string())
        }
        "pin-tab" => {
            let parsed = WindowPinTabArgs::parse(&args[1..])?;
            let layout = run_window_pin(&parsed)?;
            Ok(layout_success_json("window pin-tab", &layout).to_string())
        }
        "reorder-tabs" => {
            let parsed = WindowReorderArgs::parse(&args[1..])?;
            let layout = run_window_reorder(&parsed)?;
            Ok(layout_success_json("window reorder-tabs", &layout).to_string())
        }
        "attention" => {
            let parsed = WindowAttentionArgs::parse(&args[1..])?;
            let layout = run_window_attention(&parsed)?;
            Ok(layout_success_json("window attention", &layout).to_string())
        }
        "view" => {
            let parsed = WindowShowArgs::parse_named(&args[1..], "view")?;
            let views = run_window_view(&parsed)?;
            Ok(window_view_success_json(&parsed.window_id, &views).to_string())
        }
        other => Err(SmokeError::usage(format!(
            "unknown window subcommand {other:?}; expected `create`, `show`, `open-tab`, \
             `split-tab`, `close-tab`, `rename-tab`, `pin-tab`, `reorder-tabs`, `attention`, or \
             `view`"
        ))),
    }
}

fn window_usage() -> SmokeError {
    SmokeError::usage(
        "missing window subcommand; expected `create`, `show`, `open-tab`, `split-tab`, \
         `close-tab`, `rename-tab`, `pin-tab`, `reorder-tabs`, `attention`, or `view`",
    )
}

// ---- command execution (the only IO) --------------------------------------------------------

fn run_start(parsed: &StartArgs) -> Result<StartSessionOutcome, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let now = now_ms();
    let cwd = resolve_cwd(
        &paths,
        &parsed.workspace_id,
        &parsed.session_id,
        &parsed.cwd,
        now,
    )?;
    let rt = ShellRuntime::new(&paths);
    let params = StartParams::adhoc(
        parsed.session_id.clone(),
        parsed.workspace_id.clone(),
        parsed.kind,
        cwd,
        &parsed.argv,
        parsed.cols,
        parsed.rows,
        now,
    );
    rt.start_session(parsed.socket.clone(), &maestro_shell::ProcessEnv, &params)
        .map_err(SmokeError::from)
}

/// Create a NEW agent task and start its first session (`SessionKind::Agent`). Same cwd-mode
/// preparation as `start`; the runtime forces `params.agent_task_id` to the task being created.
fn run_agent_start(parsed: &AgentStartArgs) -> Result<StartAgentTaskOutcome, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let now = now_ms();
    let cwd = resolve_cwd(
        &paths,
        &parsed.workspace_id,
        &parsed.session_id,
        &parsed.cwd,
        now,
    )?;
    let rt = AgentTaskRuntime::new(&paths);
    let params = StartParams::adhoc(
        parsed.session_id.clone(),
        parsed.workspace_id.clone(),
        SessionKind::Agent,
        cwd,
        &parsed.argv,
        parsed.cols,
        parsed.rows,
        now,
    );
    rt.start_new_agent_task(
        parsed.socket.clone(),
        &maestro_shell::ProcessEnv,
        parsed.agent_task_id.clone(),
        parsed.project_id.clone(),
        parsed.goal.clone(),
        params,
    )
    .map_err(SmokeError::from)
}

/// Resume/retry an EXISTING agent task on a fresh session (`SessionKind::Agent`). The caller's
/// fresh argv is used verbatim; the task's stored `LaunchSpec` is never replayed.
fn run_agent_resume(parsed: &AgentResumeArgs) -> Result<StartAgentTaskOutcome, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let now = now_ms();
    let cwd = resolve_cwd(
        &paths,
        &parsed.workspace_id,
        &parsed.session_id,
        &parsed.cwd,
        now,
    )?;
    let rt = AgentTaskRuntime::new(&paths);
    let params = StartParams::adhoc(
        parsed.session_id.clone(),
        parsed.workspace_id.clone(),
        SessionKind::Agent,
        cwd,
        &parsed.argv,
        parsed.cols,
        parsed.rows,
        now,
    );
    rt.resume_agent_task(
        parsed.socket.clone(),
        &maestro_shell::ProcessEnv,
        &parsed.agent_task_id,
        params,
    )
    .map_err(SmokeError::from)
}

fn run_task_reconcile(parsed: &TaskReconcileArgs) -> Result<AgentTaskReconcileReport, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let reconciler = AgentTaskReconciler::new(&paths);
    reconciler
        .reconcile()
        .map_err(|e| SmokeError::store(e.to_string()))
}

/// Result of `run_dashboard`: the projected [`DashboardSnapshot`] plus whether the optional
/// daemon reconcile ran, and (when it did) the socket path the reconcile actually used.
struct DashboardOutcome {
    snapshot: DashboardSnapshot,
    session_reconcile: bool,
    socket_path: Option<PathBuf>,
}

/// `dashboard` supports two modes:
///
/// - Default: local-only read-only dashboard projection. Builds a [`DashboardSnapshot`]
///   over the durable records via [`DashboardSnapshotService::snapshot`] with no `ReconcileReport`
///   (so `recovered_sessions` is empty and session statuses are the on-disk / task-linked values,
///   never daemon-derived). Never connects to the daemon, never mutates records, never creates
///   scratch/worktree directories. Reports `session_reconcile = false`.
///
/// - Opt-in (`--with-session-reconcile`): first runs
///   [`ShellRuntime::reconcile_sessions`] (which resolves the endpoint — `--socket` override or the
///   stored/default endpoint — connects, and persists the endpoint only after a successful
///   connect), then projects with `snapshot(Some(&report))` so reconciled `Live`/`Exited` statuses
///   and `recovered_sessions` flow into the dashboard. Reports `session_reconcile = true` and the
///   `socket_path` the reconcile used. Records are only mutated by the normal
///   `SessionService::reconcile` side effects owned by `ShellRuntime`; this command writes nothing
///   else.
fn run_dashboard(parsed: &DashboardArgs) -> Result<DashboardOutcome, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    if parsed.with_session_reconcile {
        let rt = ShellRuntime::new(&paths);
        let outcome = rt
            .reconcile_sessions(parsed.socket.clone(), &maestro_shell::ProcessEnv, now_ms())
            .map_err(SmokeError::from)?;
        let svc = DashboardSnapshotService::new(&paths);
        let snapshot = svc
            .snapshot(Some(&outcome.report))
            .map_err(|e| SmokeError::store(e.to_string()))?;
        Ok(DashboardOutcome {
            snapshot,
            session_reconcile: true,
            socket_path: Some(outcome.socket_path),
        })
    } else {
        let svc = DashboardSnapshotService::new(&paths);
        let snapshot = svc
            .snapshot(None)
            .map_err(|e| SmokeError::store(e.to_string()))?;
        Ok(DashboardOutcome {
            snapshot,
            session_reconcile: false,
            socket_path: None,
        })
    }
}

// ---- window layout commands (local-only, no daemon) ------------------------------------------

fn run_window_create(parsed: &WindowCreateArgs) -> Result<WindowLayout, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let svc = WindowLayoutService::new(&paths);
    svc.create_empty(&parsed.window_id, now_ms())
        .map_err(SmokeError::from)
}

fn run_window_show(parsed: &WindowShowArgs) -> Result<WindowLayout, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let svc = WindowLayoutService::new(&paths);
    svc.load(&parsed.window_id)?.ok_or_else(|| {
        SmokeError::from(WindowLayoutError::WindowLayoutNotFound {
            window_id: parsed.window_id.clone(),
        })
    })
}

fn run_window_open_tab(parsed: &WindowOpenTabArgs) -> Result<WindowLayout, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let svc = WindowLayoutService::new(&paths);
    svc.open_tab(
        &parsed.window_id,
        &parsed.tab_id,
        &parsed.session_id,
        &parsed.title,
        parsed.pinned,
        AttentionState::default(),
        now_ms(),
    )
    .map_err(SmokeError::from)
}

fn run_window_split_tab(parsed: &WindowSplitTabArgs) -> Result<WindowLayout, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let svc = WindowLayoutService::new(&paths);
    svc.split_tab(
        &parsed.window_id,
        &parsed.from_tab_id,
        &parsed.tab_id,
        &parsed.session_id,
        &parsed.title,
        parsed.axis,
        now_ms(),
    )
    .map_err(SmokeError::from)
}

/// Which single-tab-ref mutation `close-tab` drives. (Only `Close` for now; the enum keeps the
/// shared `WindowTabRefArgs` parser reusable if more ref-only mutations are added.)
enum WindowMutation {
    Close,
}

fn run_window_mutate(
    parsed: &WindowTabRefArgs,
    mutation: WindowMutation,
) -> Result<WindowLayout, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let svc = WindowLayoutService::new(&paths);
    match mutation {
        WindowMutation::Close => svc.close_tab(&parsed.window_id, &parsed.tab_id, now_ms()),
    }
    .map_err(SmokeError::from)
}

fn run_window_rename(parsed: &WindowRenameTabArgs) -> Result<WindowLayout, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let svc = WindowLayoutService::new(&paths);
    svc.rename_tab(&parsed.window_id, &parsed.tab_id, &parsed.title, now_ms())
        .map_err(SmokeError::from)
}

fn run_window_pin(parsed: &WindowPinTabArgs) -> Result<WindowLayout, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let svc = WindowLayoutService::new(&paths);
    svc.set_pinned(&parsed.window_id, &parsed.tab_id, parsed.pinned, now_ms())
        .map_err(SmokeError::from)
}

fn run_window_reorder(parsed: &WindowReorderArgs) -> Result<WindowLayout, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let svc = WindowLayoutService::new(&paths);
    svc.reorder_tabs(&parsed.window_id, &parsed.order, now_ms())
        .map_err(SmokeError::from)
}

fn run_window_attention(parsed: &WindowAttentionArgs) -> Result<WindowLayout, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let svc = WindowLayoutService::new(&paths);
    let attention = AttentionState {
        attention: parsed.attention,
        unseen: parsed.unseen,
        since_ms: parsed.since_ms.unwrap_or_else(now_ms),
        source: parsed.source,
    };
    svc.update_attention(&parsed.window_id, &parsed.tab_id, attention, now_ms())
        .map_err(SmokeError::from)
}

/// `window view`: reconcile agent tasks (read-only, no daemon), then project the layout's tabs
/// joined with that reconciliation via [`WindowLayoutService::tab_view`].
fn run_window_view(parsed: &WindowShowArgs) -> Result<Vec<WindowTabView>, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let report = AgentTaskReconciler::new(&paths)
        .reconcile()
        .map_err(|e| SmokeError::store(e.to_string()))?;
    let svc = WindowLayoutService::new(&paths);
    svc.tab_view(&parsed.window_id, &report)
        .map_err(SmokeError::from)
}

/// Turn a parsed cwd mode into the actual session cwd handed to `StartParams`. This is where the
/// side-effecting workspace preparation happens (scratch mkdir / consent-gated worktree). Shared
/// by `start`, `agent-start`, and `agent-resume` so all three prepare cwd identically.
fn resolve_cwd(
    paths: &AppPaths,
    workspace_id: &str,
    session_id: &str,
    cwd: &CwdMode,
    now_ms: u64,
) -> Result<String, SmokeError> {
    match cwd {
        CwdMode::Explicit(dir) => Ok(dir.clone()),
        // Prepare the shell-owned scratch dir (0700) and run the session there.
        // No associated repo root in this dev CLI, hence "".
        CwdMode::Scratch => Ok(prepare_scratch_cwd(paths, workspace_id, session_id, "")?
            .cwd
            .to_string_lossy()
            .into_owned()),
        // Workspace record (with worktree_create consent) -> worktree executor.
        CwdMode::Worktree { repo_root } => {
            let workspace = ensure_worktree_workspace(paths, workspace_id, repo_root, now_ms)?;
            let prepared = prepare_workspace_with_consent(
                paths,
                WorkspacePolicy::Worktree,
                &workspace,
                session_id,
            )?;
            Ok(prepared.cwd.to_string_lossy().into_owned())
        }
        // Workspace record (with repo_write consent) -> consent-gated executor that
        // verifies the root and returns it VERBATIM as the session cwd. No git, no mutation.
        CwdMode::RepoWrite { repo_root } => {
            let workspace = ensure_repo_write_workspace(paths, workspace_id, repo_root, now_ms)?;
            let prepared = prepare_workspace_with_consent(
                paths,
                WorkspacePolicy::RepoWrite,
                &workspace,
                session_id,
            )?;
            Ok(prepared.cwd.to_string_lossy().into_owned())
        }
    }
}

/// Create or load the Workspace record backing `--worktree` mode. The parser already proved the
/// caller passed `--allow-worktree-create`, so a created/updated record grants ONLY
/// `worktree_create` — never `repo_write`.
///
/// Existing-record rules (no silent overwrite):
/// - same id, same `Worktree` policy, same root -> reused (consent granted via the store-backed
///   consent helper if not already recorded)
/// - same id but different root or policy -> typed `workspace` conflict error, record untouched
/// - future-version / corrupt records surface as `store` errors per store semantics (a
///   future-version record is never rewritten; a corrupt one is quarantined, not overwritten)
fn ensure_worktree_workspace(
    paths: &AppPaths,
    workspace_id: &str,
    repo_root: &str,
    now_ms: u64,
) -> Result<Workspace, SmokeError> {
    let existing = load_one::<Workspace>(paths, RecordKind::Workspace, workspace_id)
        .map_err(|e| SmokeError::store(e.to_string()))?;
    match existing {
        None => {
            let workspace = Workspace {
                workspace_id: workspace_id.to_string(),
                project_id: "smoke-cli".to_string(),
                root: repo_root.to_string(),
                policy: WorkspacePolicy::Worktree,
                consent: WorkspaceConsent {
                    worktree_create: true,
                    repo_write: false,
                    granted_at_ms: Some(now_ms),
                },
            };
            write_record(
                paths,
                RecordKind::Workspace,
                workspace_id,
                now_ms,
                &workspace,
            )
            .map_err(|e| SmokeError::store(e.to_string()))?;
            Ok(workspace)
        }
        Some(LoadOutcome::Loaded(workspace)) => {
            if workspace.policy != WorkspacePolicy::Worktree || workspace.root != repo_root {
                return Err(SmokeError {
                    kind: "workspace",
                    message: format!(
                        "existing workspace record {workspace_id:?} conflicts with --worktree \
                         {repo_root:?}: it has policy {:?} and root {:?}; refusing to overwrite \
                         it — pass a different --workspace-id",
                        workspace.policy, workspace.root
                    ),
                });
            }
            if workspace.consent.worktree_create {
                Ok(workspace)
            } else {
                grant_consent(
                    paths,
                    workspace_id,
                    WorkspaceConsentKind::WorktreeCreate,
                    now_ms,
                )
                .map_err(SmokeError::from)
            }
        }
        Some(LoadOutcome::FutureVersion { path, ours, got }) => Err(SmokeError::store(format!(
            "workspace record {} has future schema_version {got} (this build understands {ours}); \
             left unmodified",
            path.display()
        ))),
        Some(LoadOutcome::Quarantined {
            original,
            moved_to,
            reason,
        }) => Err(SmokeError::store(format!(
            "workspace record {} was corrupt ({reason}); quarantined to {}",
            original.display(),
            moved_to.display()
        ))),
    }
}

/// Create or load the Workspace record backing `--repo-write` mode. The parser already proved
/// the caller passed `--allow-repo-write`, so a created/updated record grants ONLY `repo_write`
/// — never `worktree_create`.
///
/// Existing-record rules (no silent overwrite), mirroring `ensure_worktree_workspace`:
/// - same id, same `RepoWrite` policy, same root -> reused (consent granted via the store-backed
///   consent helper if not already recorded)
/// - same id but different root or policy -> typed `workspace` conflict error, record untouched
/// - future-version / corrupt records surface as `store` errors per store semantics (a
///   future-version record is never rewritten; a corrupt one is quarantined, not overwritten)
fn ensure_repo_write_workspace(
    paths: &AppPaths,
    workspace_id: &str,
    repo_root: &str,
    now_ms: u64,
) -> Result<Workspace, SmokeError> {
    let existing = load_one::<Workspace>(paths, RecordKind::Workspace, workspace_id)
        .map_err(|e| SmokeError::store(e.to_string()))?;
    match existing {
        None => {
            let workspace = Workspace {
                workspace_id: workspace_id.to_string(),
                project_id: "smoke-cli".to_string(),
                root: repo_root.to_string(),
                policy: WorkspacePolicy::RepoWrite,
                consent: WorkspaceConsent {
                    worktree_create: false,
                    repo_write: true,
                    granted_at_ms: Some(now_ms),
                },
            };
            write_record(
                paths,
                RecordKind::Workspace,
                workspace_id,
                now_ms,
                &workspace,
            )
            .map_err(|e| SmokeError::store(e.to_string()))?;
            Ok(workspace)
        }
        Some(LoadOutcome::Loaded(workspace)) => {
            if workspace.policy != WorkspacePolicy::RepoWrite || workspace.root != repo_root {
                return Err(SmokeError {
                    kind: "workspace",
                    message: format!(
                        "existing workspace record {workspace_id:?} conflicts with --repo-write \
                         {repo_root:?}: it has policy {:?} and root {:?}; refusing to overwrite \
                         it — pass a different --workspace-id",
                        workspace.policy, workspace.root
                    ),
                });
            }
            if workspace.consent.repo_write {
                Ok(workspace)
            } else {
                grant_consent(paths, workspace_id, WorkspaceConsentKind::RepoWrite, now_ms)
                    .map_err(SmokeError::from)
            }
        }
        Some(LoadOutcome::FutureVersion { path, ours, got }) => Err(SmokeError::store(format!(
            "workspace record {} has future schema_version {got} (this build understands {ours}); \
             left unmodified",
            path.display()
        ))),
        Some(LoadOutcome::Quarantined {
            original,
            moved_to,
            reason,
        }) => Err(SmokeError::store(format!(
            "workspace record {} was corrupt ({reason}); quarantined to {}",
            original.display(),
            moved_to.display()
        ))),
    }
}

fn run_reconcile(parsed: &ReconcileArgs) -> Result<ReconcileOutcome, SmokeError> {
    let paths = resolve_paths(parsed.base.as_deref())?;
    let rt = ShellRuntime::new(&paths);
    rt.reconcile_sessions(parsed.socket.clone(), &maestro_shell::ProcessEnv, now_ms())
        .map_err(SmokeError::from)
}

/// Resolve the app-support base: an explicit `--base` override, else `AppPaths::production()`.
fn resolve_paths(base: Option<&std::path::Path>) -> Result<AppPaths, SmokeError> {
    match base {
        Some(b) => Ok(AppPaths::with_base(b.to_path_buf())),
        None => AppPaths::production().map_err(|e| {
            SmokeError::usage(format!("cannot resolve production app-support base: {e}"))
        }),
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ---- parsed args ----------------------------------------------------------------------------

/// How the session cwd is chosen — exactly one of `--cwd <dir>` / `--scratch` /
/// `--worktree <repo-root> --allow-worktree-create` /
/// `--repo-write <repo-root> --allow-repo-write`.
#[derive(Debug, PartialEq, Eq)]
enum CwdMode {
    /// `--cwd <dir>`: the caller's existing directory, used verbatim.
    Explicit(String),
    /// `--scratch`: prepare `<app-support>/scratch/<session-id>` (0700) and run there.
    Scratch,
    /// `--worktree <repo-root>` (parse-gated on `--allow-worktree-create`): consent-gated git
    /// worktree under `<app-support>/worktrees/<workspace-id>/<session-id>`.
    Worktree { repo_root: String },
    /// `--repo-write <repo-root>` (parse-gated on `--allow-repo-write`): consent-gated session
    /// cwd EQUAL to the live repo root itself — the process may write directly into the
    /// checkout.
    RepoWrite { repo_root: String },
}

/// Shared accumulator for the four mutually-exclusive cwd-mode flags. Every command that runs a
/// session (`start`, `agent-start`, `agent-resume`) collects these identically and calls
/// [`CwdModeBuilder::resolve`], so the exactly-one-mode rule and the allow-flag gating are
/// defined in ONE place and cannot drift between commands.
#[derive(Default)]
struct CwdModeBuilder {
    cwd: Option<String>,
    scratch: bool,
    worktree: Option<String>,
    allow_worktree_create: bool,
    repo_write: Option<String>,
    allow_repo_write: bool,
}

impl CwdModeBuilder {
    /// Try to consume a value-less cwd-mode flag (`--scratch` / `--allow-*`). Returns `true` if
    /// `tok` was one of them (and was recorded), so the caller can `continue`.
    fn try_valueless_flag(&mut self, tok: &str) -> bool {
        match tok {
            "--scratch" => self.scratch = true,
            "--allow-worktree-create" => self.allow_worktree_create = true,
            "--allow-repo-write" => self.allow_repo_write = true,
            _ => return false,
        }
        true
    }

    /// Try to consume a value-taking cwd-mode flag (`--cwd` / `--worktree` / `--repo-write`).
    /// Returns `Some(Ok(()))` if `tok` matched (value recorded), `Some(Err(_))` if it matched but
    /// the value was malformed, or `None` if `tok` is not a cwd-mode flag.
    fn try_value_flag(&mut self, tok: &str, value: String) -> Option<Result<(), SmokeError>> {
        match tok {
            "--cwd" => self.cwd = Some(value),
            "--worktree" => self.worktree = Some(value),
            "--repo-write" => self.repo_write = Some(value),
            _ => return None,
        }
        Some(Ok(()))
    }

    /// Apply the exactly-one-mode rule and the allow-flag gating, producing a `CwdMode`. This is
    /// the single source of truth shared by all session-starting commands.
    fn resolve(self) -> Result<CwdMode, SmokeError> {
        let chosen_modes = usize::from(self.cwd.is_some())
            + usize::from(self.scratch)
            + usize::from(self.worktree.is_some())
            + usize::from(self.repo_write.is_some());
        if chosen_modes > 1 {
            return Err(SmokeError::usage(
                "--cwd, --scratch, --worktree, and --repo-write are mutually exclusive; pass \
                 exactly one",
            ));
        }
        // A stray allow flag (without its mode) is a usage error, never silently ignored.
        if self.allow_worktree_create && self.worktree.is_none() {
            return Err(SmokeError::usage(
                "--allow-worktree-create only applies to --worktree <repo-root>",
            ));
        }
        if self.allow_repo_write && self.repo_write.is_none() {
            return Err(SmokeError::usage(
                "--allow-repo-write only applies to --repo-write <repo-root>",
            ));
        }
        match (self.cwd, self.scratch, self.worktree, self.repo_write) {
            (Some(dir), false, None, None) => Ok(CwdMode::Explicit(dir)),
            (None, true, None, None) => Ok(CwdMode::Scratch),
            (None, false, Some(repo_root), None) => {
                if !self.allow_worktree_create {
                    return Err(SmokeError::usage(
                        "--worktree requires --allow-worktree-create: creating a worktree \
                         mutates git administrative state under the source repo \
                         (.git/worktrees/...) and creates a checkout under app-support",
                    ));
                }
                Ok(CwdMode::Worktree { repo_root })
            }
            (None, false, None, Some(repo_root)) => {
                if !self.allow_repo_write {
                    return Err(SmokeError::usage(
                        "--repo-write requires --allow-repo-write: this runs the session \
                         directly in the live checkout / repo root and may allow the process \
                         to write there — no scratch dir, no worktree, no isolation",
                    ));
                }
                Ok(CwdMode::RepoWrite { repo_root })
            }
            _ => Err(SmokeError::usage(
                "one of --cwd, --scratch, --worktree <repo-root>, or --repo-write <repo-root> \
                 is required",
            )),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct StartArgs {
    base: Option<PathBuf>,
    socket: Option<PathBuf>,
    session_id: String,
    workspace_id: String,
    cwd: CwdMode,
    cols: u16,
    rows: u16,
    kind: SessionKind,
    /// The real command argv after `--` (first token is the command).
    argv: Vec<String>,
}

impl StartArgs {
    /// Parse `start` arguments from the tokens AFTER the `start` command word.
    ///
    /// Everything after a bare `--` is the command argv (taken verbatim, NOT interpreted as
    /// flags), so a session command may itself contain `--flags`.
    fn parse(tokens: &[String]) -> Result<StartArgs, SmokeError> {
        let mut base = None;
        let mut socket = None;
        let mut session_id = None;
        let mut workspace_id = None;
        let mut cwd_modes = CwdModeBuilder::default();
        let mut cols: u16 = 80;
        let mut rows: u16 = 24;
        let mut kind = SessionKind::Shell;
        let mut argv: Option<Vec<String>> = None;

        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            if tok == "--" {
                // Everything after `--` is the command argv, verbatim.
                argv = Some(tokens[i + 1..].to_vec());
                break;
            }
            // Value-less cwd-mode flags (--scratch / --allow-*) consumed by the shared builder.
            if cwd_modes.try_valueless_flag(tok) {
                i += 1;
                continue;
            }
            // All other known flags take exactly one value.
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            if let Some(res) = cwd_modes.try_value_flag(tok, value()?) {
                res?;
                i += 2;
                continue;
            }
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--socket" => socket = Some(PathBuf::from(value()?)),
                "--session-id" => session_id = Some(value()?),
                "--workspace-id" => workspace_id = Some(value()?),
                "--cols" => {
                    cols = value()?
                        .parse()
                        .map_err(|_| SmokeError::usage("--cols must be a u16"))?
                }
                "--rows" => {
                    rows = value()?
                        .parse()
                        .map_err(|_| SmokeError::usage("--rows must be a u16"))?
                }
                "--kind" => kind = parse_kind(&value()?)?,
                other => {
                    return Err(SmokeError::usage(format!("unknown flag {other:?}")));
                }
            }
            i += 2;
        }

        let session_id = session_id.ok_or_else(|| SmokeError::usage("--session-id is required"))?;
        let workspace_id =
            workspace_id.ok_or_else(|| SmokeError::usage("--workspace-id is required"))?;
        let cwd = cwd_modes.resolve()?;
        let argv = require_argv(argv)?;

        Ok(StartArgs {
            base,
            socket,
            session_id,
            workspace_id,
            cwd,
            cols,
            rows,
            kind,
            argv,
        })
    }
}

/// Shared `-- <argv>` requirement for every session-starting command: the argv must be present
/// (a `--` was seen) and non-empty.
fn require_argv(argv: Option<Vec<String>>) -> Result<Vec<String>, SmokeError> {
    let argv = argv.ok_or_else(|| {
        SmokeError::usage("missing command; pass `-- <command> [args...]` after the flags")
    })?;
    if argv.is_empty() {
        return Err(SmokeError::usage(
            "command argv after `--` must be non-empty",
        ));
    }
    Ok(argv)
}

#[derive(Debug, PartialEq, Eq)]
struct ReconcileArgs {
    base: Option<PathBuf>,
    socket: Option<PathBuf>,
}

impl ReconcileArgs {
    fn parse(tokens: &[String]) -> Result<ReconcileArgs, SmokeError> {
        let mut base = None;
        let mut socket = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--socket" => socket = Some(PathBuf::from(value()?)),
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        Ok(ReconcileArgs { base, socket })
    }
}

/// `task-reconcile` args: local-only, so NO `--socket` and NO command argv. Only
/// `--base` selects which app-support tree to read.
#[derive(Debug, PartialEq, Eq)]
struct TaskReconcileArgs {
    base: Option<PathBuf>,
}

impl TaskReconcileArgs {
    fn parse(tokens: &[String]) -> Result<TaskReconcileArgs, SmokeError> {
        let mut base = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            if tok == "--" {
                return Err(SmokeError::usage(
                    "task-reconcile takes no command argv: it is a local read-only reconcile \
                     and never starts a session",
                ));
            }
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        Ok(TaskReconcileArgs { base })
    }
}

/// `dashboard` args: a read-only dashboard projection. By default it is local-only — no daemon
/// connect, no socket, no endpoint write. An explicit opt-in enables session reconciliation:
///
/// - `--with-session-reconcile` connects to an already-running daemon, runs
///   `ShellRuntime::reconcile_sessions`, and feeds the resulting `ReconcileReport` into the
///   snapshot (in-memory session-status override + live recovered sessions).
/// - `--socket <path>` is accepted ONLY together with `--with-session-reconcile`; on its own it is
///   a usage error (the local path never connects to a daemon), so a caller can't mistake the
///   default command for a daemon-aware one.
///
/// `--` (command argv) is always rejected (this command never starts a session); duplicate
/// `--base`, `--socket`, and `--with-session-reconcile` are each rejected.
#[derive(Debug, PartialEq, Eq)]
struct DashboardArgs {
    base: Option<PathBuf>,
    with_session_reconcile: bool,
    socket: Option<PathBuf>,
}

impl DashboardArgs {
    fn parse(tokens: &[String]) -> Result<DashboardArgs, SmokeError> {
        let mut base = None;
        let mut with_session_reconcile = false;
        let mut socket = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            if tok == "--" {
                return Err(SmokeError::usage(
                    "dashboard takes no command argv: it is a read-only dashboard projection \
                     and never starts a session",
                ));
            }
            // `--with-session-reconcile` is a boolean flag (no value) — handle it before the
            // value-taking flags so it advances by one token, not two.
            if tok == "--with-session-reconcile" {
                if with_session_reconcile {
                    return Err(SmokeError::usage(
                        "--with-session-reconcile may only be given once",
                    ));
                }
                with_session_reconcile = true;
                i += 1;
                continue;
            }
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => {
                    if base.is_some() {
                        return Err(SmokeError::usage("--base may only be given once"));
                    }
                    base = Some(PathBuf::from(value()?));
                }
                "--socket" => {
                    if socket.is_some() {
                        return Err(SmokeError::usage("--socket may only be given once"));
                    }
                    socket = Some(PathBuf::from(value()?));
                }
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        // `--socket` is meaningful only on the daemon-aware path.
        if socket.is_some() && !with_session_reconcile {
            return Err(SmokeError::usage(
                "dashboard --socket requires --with-session-reconcile: the default dashboard is \
                 local-only and never connects to the daemon",
            ));
        }
        Ok(DashboardArgs {
            base,
            with_session_reconcile,
            socket,
        })
    }
}

// ---- window layout args (local-only) --------------------------------------------------------

/// Parse a strict `true`/`false` flag value. Anything else is a usage error (never a silent
/// default), so a typo can't quietly flip a tab's pinned/unseen state.
fn parse_bool(flag: &str, value: &str) -> Result<bool, SmokeError> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(SmokeError::usage(format!(
            "{flag} must be `true` or `false`, got {other:?}"
        ))),
    }
}

/// Parse the `--attention` value into an [`Attention`], matching its serde `snake_case` repr.
fn parse_attention(value: &str) -> Result<Attention, SmokeError> {
    match value {
        "none" => Ok(Attention::None),
        "activity" => Ok(Attention::Activity),
        "needs_input" => Ok(Attention::NeedsInput),
        "error" => Ok(Attention::Error),
        "done" => Ok(Attention::Done),
        other => Err(SmokeError::usage(format!(
            "--attention must be one of `none|activity|needs_input|error|done`, got {other:?}"
        ))),
    }
}

/// Parse the `--source` value into an [`AttentionSource`], matching its serde `snake_case` repr.
fn parse_attention_source(value: &str) -> Result<AttentionSource, SmokeError> {
    match value {
        "process" => Ok(AttentionSource::Process),
        "agent" => Ok(AttentionSource::Agent),
        "user" => Ok(AttentionSource::User),
        other => Err(SmokeError::usage(format!(
            "--source must be one of `process|agent|user`, got {other:?}"
        ))),
    }
}

/// `window create` / args: just `--window-id` (required) and optional `--base`.
#[derive(Debug, PartialEq, Eq)]
struct WindowCreateArgs {
    base: Option<PathBuf>,
    window_id: String,
}

impl WindowCreateArgs {
    fn parse(tokens: &[String]) -> Result<WindowCreateArgs, SmokeError> {
        let mut base = None;
        let mut window_id = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--window-id" => window_id = Some(value()?),
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        let window_id = window_id.ok_or_else(|| SmokeError::usage("--window-id is required"))?;
        Ok(WindowCreateArgs { base, window_id })
    }
}

/// `window show` / `window view`: `--window-id` (required) and optional `--base`. The command
/// name is threaded only for the unknown-flag message via [`WindowShowArgs::parse_named`].
#[derive(Debug, PartialEq, Eq)]
struct WindowShowArgs {
    base: Option<PathBuf>,
    window_id: String,
}

impl WindowShowArgs {
    fn parse(tokens: &[String]) -> Result<WindowShowArgs, SmokeError> {
        Self::parse_named(tokens, "show")
    }

    fn parse_named(tokens: &[String], _command: &str) -> Result<WindowShowArgs, SmokeError> {
        let mut base = None;
        let mut window_id = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--window-id" => window_id = Some(value()?),
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        let window_id = window_id.ok_or_else(|| SmokeError::usage("--window-id is required"))?;
        Ok(WindowShowArgs { base, window_id })
    }
}

/// `window open-tab`: `--window-id`, `--tab-id`, `--session-id`, `--title` (all required),
/// optional `--pinned` (value-less flag) and `--base`.
#[derive(Debug, PartialEq, Eq)]
struct WindowOpenTabArgs {
    base: Option<PathBuf>,
    window_id: String,
    tab_id: String,
    session_id: String,
    title: String,
    pinned: bool,
}

impl WindowOpenTabArgs {
    fn parse(tokens: &[String]) -> Result<WindowOpenTabArgs, SmokeError> {
        let mut base = None;
        let mut window_id = None;
        let mut tab_id = None;
        let mut session_id = None;
        let mut title = None;
        let mut pinned = false;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            if tok == "--pinned" {
                pinned = true;
                i += 1;
                continue;
            }
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--window-id" => window_id = Some(value()?),
                "--tab-id" => tab_id = Some(value()?),
                "--session-id" => session_id = Some(value()?),
                "--title" => title = Some(value()?),
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        Ok(WindowOpenTabArgs {
            base,
            window_id: window_id.ok_or_else(|| SmokeError::usage("--window-id is required"))?,
            tab_id: tab_id.ok_or_else(|| SmokeError::usage("--tab-id is required"))?,
            session_id: session_id.ok_or_else(|| SmokeError::usage("--session-id is required"))?,
            title: title.ok_or_else(|| SmokeError::usage("--title is required"))?,
            pinned,
        })
    }
}

/// `window split-tab`: `--window-id`, `--from-tab-id`, `--tab-id`, `--session-id`, `--title`,
/// `--axis` (all required; `--axis` must be `right|down`), optional `--base`.
#[derive(Debug, PartialEq, Eq)]
struct WindowSplitTabArgs {
    base: Option<PathBuf>,
    window_id: String,
    from_tab_id: String,
    tab_id: String,
    session_id: String,
    title: String,
    axis: SplitAxis,
}

impl WindowSplitTabArgs {
    fn parse(tokens: &[String]) -> Result<WindowSplitTabArgs, SmokeError> {
        let mut base = None;
        let mut window_id = None;
        let mut from_tab_id = None;
        let mut tab_id = None;
        let mut session_id = None;
        let mut title = None;
        let mut axis = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--window-id" => window_id = Some(value()?),
                "--from-tab-id" => from_tab_id = Some(value()?),
                "--tab-id" => tab_id = Some(value()?),
                "--session-id" => session_id = Some(value()?),
                "--title" => title = Some(value()?),
                "--axis" => {
                    axis = Some(match value()?.as_str() {
                        "right" => SplitAxis::Right,
                        "down" => SplitAxis::Down,
                        other => {
                            return Err(SmokeError::usage(format!(
                                "--axis must be `right` or `down` (got {other:?})"
                            )))
                        }
                    });
                }
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        Ok(WindowSplitTabArgs {
            base,
            window_id: window_id.ok_or_else(|| SmokeError::usage("--window-id is required"))?,
            from_tab_id: from_tab_id
                .ok_or_else(|| SmokeError::usage("--from-tab-id is required"))?,
            tab_id: tab_id.ok_or_else(|| SmokeError::usage("--tab-id is required"))?,
            session_id: session_id.ok_or_else(|| SmokeError::usage("--session-id is required"))?,
            title: title.ok_or_else(|| SmokeError::usage("--title is required"))?,
            axis: axis.ok_or_else(|| SmokeError::usage("--axis is required"))?,
        })
    }
}

/// Shared `--window-id` + `--tab-id` (+ `--base`) args for tab-ref-only mutations (`close-tab`).
#[derive(Debug, PartialEq, Eq)]
struct WindowTabRefArgs {
    base: Option<PathBuf>,
    window_id: String,
    tab_id: String,
}

impl WindowTabRefArgs {
    fn parse(tokens: &[String], _command: &str) -> Result<WindowTabRefArgs, SmokeError> {
        let mut base = None;
        let mut window_id = None;
        let mut tab_id = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--window-id" => window_id = Some(value()?),
                "--tab-id" => tab_id = Some(value()?),
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        Ok(WindowTabRefArgs {
            base,
            window_id: window_id.ok_or_else(|| SmokeError::usage("--window-id is required"))?,
            tab_id: tab_id.ok_or_else(|| SmokeError::usage("--tab-id is required"))?,
        })
    }
}

/// `window rename-tab`: `--window-id`, `--tab-id`, `--title` (all required) + optional `--base`.
#[derive(Debug, PartialEq, Eq)]
struct WindowRenameTabArgs {
    base: Option<PathBuf>,
    window_id: String,
    tab_id: String,
    title: String,
}

impl WindowRenameTabArgs {
    fn parse(tokens: &[String]) -> Result<WindowRenameTabArgs, SmokeError> {
        let mut base = None;
        let mut window_id = None;
        let mut tab_id = None;
        let mut title = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--window-id" => window_id = Some(value()?),
                "--tab-id" => tab_id = Some(value()?),
                "--title" => title = Some(value()?),
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        Ok(WindowRenameTabArgs {
            base,
            window_id: window_id.ok_or_else(|| SmokeError::usage("--window-id is required"))?,
            tab_id: tab_id.ok_or_else(|| SmokeError::usage("--tab-id is required"))?,
            title: title.ok_or_else(|| SmokeError::usage("--title is required"))?,
        })
    }
}

/// `window pin-tab`: `--window-id`, `--tab-id`, `--pinned <true|false>` (all required) + `--base`.
#[derive(Debug, PartialEq, Eq)]
struct WindowPinTabArgs {
    base: Option<PathBuf>,
    window_id: String,
    tab_id: String,
    pinned: bool,
}

impl WindowPinTabArgs {
    fn parse(tokens: &[String]) -> Result<WindowPinTabArgs, SmokeError> {
        let mut base = None;
        let mut window_id = None;
        let mut tab_id = None;
        let mut pinned = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--window-id" => window_id = Some(value()?),
                "--tab-id" => tab_id = Some(value()?),
                "--pinned" => pinned = Some(parse_bool("--pinned", &value()?)?),
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        Ok(WindowPinTabArgs {
            base,
            window_id: window_id.ok_or_else(|| SmokeError::usage("--window-id is required"))?,
            tab_id: tab_id.ok_or_else(|| SmokeError::usage("--tab-id is required"))?,
            pinned: pinned.ok_or_else(|| SmokeError::usage("--pinned <true|false> is required"))?,
        })
    }
}

/// `window reorder-tabs`: `--window-id` and `--order <tab1,tab2,...>` (required) + `--base`. The
/// order string is split on commas; an empty order is a usage error (the service requires an
/// exact permutation, never an empty set).
#[derive(Debug, PartialEq, Eq)]
struct WindowReorderArgs {
    base: Option<PathBuf>,
    window_id: String,
    order: Vec<String>,
}

impl WindowReorderArgs {
    fn parse(tokens: &[String]) -> Result<WindowReorderArgs, SmokeError> {
        let mut base = None;
        let mut window_id = None;
        let mut order = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--window-id" => window_id = Some(value()?),
                "--order" => order = Some(value()?),
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        let window_id = window_id.ok_or_else(|| SmokeError::usage("--window-id is required"))?;
        let order_raw =
            order.ok_or_else(|| SmokeError::usage("--order <tab1,tab2,...> is required"))?;
        let order: Vec<String> = order_raw
            .split(',')
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        // An empty value, or any empty comma-separated segment, can't name a real tab id.
        if order.iter().any(|s| s.is_empty()) {
            return Err(SmokeError::usage(
                "--order must be a non-empty comma-separated list of tab ids with no empty \
                 entries",
            ));
        }
        Ok(WindowReorderArgs {
            base,
            window_id,
            order,
        })
    }
}

/// `window attention`: `--window-id`, `--tab-id`, `--attention <state>`, `--unseen <true|false>`
/// (required), optional `--source <process|agent|user>` (default `process`), `--since-ms <u64>`
/// (default `now`), and `--base`.
#[derive(Debug, PartialEq, Eq)]
struct WindowAttentionArgs {
    base: Option<PathBuf>,
    window_id: String,
    tab_id: String,
    attention: Attention,
    unseen: bool,
    source: AttentionSource,
    since_ms: Option<u64>,
}

impl WindowAttentionArgs {
    fn parse(tokens: &[String]) -> Result<WindowAttentionArgs, SmokeError> {
        let mut base = None;
        let mut window_id = None;
        let mut tab_id = None;
        let mut attention = None;
        let mut unseen = None;
        let mut source = AttentionSource::Process;
        let mut since_ms = None;
        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--window-id" => window_id = Some(value()?),
                "--tab-id" => tab_id = Some(value()?),
                "--attention" => attention = Some(parse_attention(&value()?)?),
                "--unseen" => unseen = Some(parse_bool("--unseen", &value()?)?),
                "--source" => source = parse_attention_source(&value()?)?,
                "--since-ms" => {
                    since_ms = Some(
                        value()?
                            .parse()
                            .map_err(|_| SmokeError::usage("--since-ms must be a u64"))?,
                    )
                }
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }
        Ok(WindowAttentionArgs {
            base,
            window_id: window_id.ok_or_else(|| SmokeError::usage("--window-id is required"))?,
            tab_id: tab_id.ok_or_else(|| SmokeError::usage("--tab-id is required"))?,
            attention: attention.ok_or_else(|| {
                SmokeError::usage("--attention <none|activity|needs_input|error|done> is required")
            })?,
            unseen: unseen.ok_or_else(|| SmokeError::usage("--unseen <true|false> is required"))?,
            source,
            since_ms,
        })
    }
}

/// `agent-start` args: create a NEW agent task and start its first session. Adds
/// `--agent-task-id`, `--project-id`, and `--goal` to the shared session-start surface; the cwd
/// mode parsing and `-- <argv>` rule are shared with `start` via [`CwdModeBuilder`].
#[derive(Debug, PartialEq, Eq)]
struct AgentStartArgs {
    base: Option<PathBuf>,
    socket: Option<PathBuf>,
    session_id: String,
    workspace_id: String,
    agent_task_id: String,
    project_id: String,
    goal: String,
    cwd: CwdMode,
    cols: u16,
    rows: u16,
    argv: Vec<String>,
}

impl AgentStartArgs {
    fn parse(tokens: &[String]) -> Result<AgentStartArgs, SmokeError> {
        let mut base = None;
        let mut socket = None;
        let mut session_id = None;
        let mut workspace_id = None;
        let mut agent_task_id = None;
        let mut project_id = None;
        let mut goal = None;
        let mut cwd_modes = CwdModeBuilder::default();
        let mut cols: u16 = 80;
        let mut rows: u16 = 24;
        let mut argv: Option<Vec<String>> = None;

        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            if tok == "--" {
                argv = Some(tokens[i + 1..].to_vec());
                break;
            }
            if cwd_modes.try_valueless_flag(tok) {
                i += 1;
                continue;
            }
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            if let Some(res) = cwd_modes.try_value_flag(tok, value()?) {
                res?;
                i += 2;
                continue;
            }
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--socket" => socket = Some(PathBuf::from(value()?)),
                "--session-id" => session_id = Some(value()?),
                "--workspace-id" => workspace_id = Some(value()?),
                "--agent-task-id" => agent_task_id = Some(value()?),
                "--project-id" => project_id = Some(value()?),
                "--goal" => goal = Some(value()?),
                "--cols" => {
                    cols = value()?
                        .parse()
                        .map_err(|_| SmokeError::usage("--cols must be a u16"))?
                }
                "--rows" => {
                    rows = value()?
                        .parse()
                        .map_err(|_| SmokeError::usage("--rows must be a u16"))?
                }
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }

        let session_id = session_id.ok_or_else(|| SmokeError::usage("--session-id is required"))?;
        let workspace_id =
            workspace_id.ok_or_else(|| SmokeError::usage("--workspace-id is required"))?;
        let agent_task_id =
            agent_task_id.ok_or_else(|| SmokeError::usage("--agent-task-id is required"))?;
        let project_id = project_id.ok_or_else(|| SmokeError::usage("--project-id is required"))?;
        let goal = goal.ok_or_else(|| SmokeError::usage("--goal is required"))?;
        let cwd = cwd_modes.resolve()?;
        let argv = require_argv(argv)?;

        Ok(AgentStartArgs {
            base,
            socket,
            session_id,
            workspace_id,
            agent_task_id,
            project_id,
            goal,
            cwd,
            cols,
            rows,
            argv,
        })
    }
}

/// `agent-resume` args: resume/retry an EXISTING agent task on a fresh session.
/// Requires only `--agent-task-id` (no `--project-id`/`--goal` — the task already exists). The
/// caller supplies fresh argv; the task's stored `LaunchSpec` is never replayed.
#[derive(Debug, PartialEq, Eq)]
struct AgentResumeArgs {
    base: Option<PathBuf>,
    socket: Option<PathBuf>,
    session_id: String,
    workspace_id: String,
    agent_task_id: String,
    cwd: CwdMode,
    cols: u16,
    rows: u16,
    argv: Vec<String>,
}

impl AgentResumeArgs {
    fn parse(tokens: &[String]) -> Result<AgentResumeArgs, SmokeError> {
        let mut base = None;
        let mut socket = None;
        let mut session_id = None;
        let mut workspace_id = None;
        let mut agent_task_id = None;
        let mut cwd_modes = CwdModeBuilder::default();
        let mut cols: u16 = 80;
        let mut rows: u16 = 24;
        let mut argv: Option<Vec<String>> = None;

        let mut i = 0;
        while i < tokens.len() {
            let tok = tokens[i].as_str();
            if tok == "--" {
                argv = Some(tokens[i + 1..].to_vec());
                break;
            }
            if cwd_modes.try_valueless_flag(tok) {
                i += 1;
                continue;
            }
            let value = || {
                tokens
                    .get(i + 1)
                    .cloned()
                    .ok_or_else(|| SmokeError::usage(format!("flag {tok} requires a value")))
            };
            if let Some(res) = cwd_modes.try_value_flag(tok, value()?) {
                res?;
                i += 2;
                continue;
            }
            match tok {
                "--base" => base = Some(PathBuf::from(value()?)),
                "--socket" => socket = Some(PathBuf::from(value()?)),
                "--session-id" => session_id = Some(value()?),
                "--workspace-id" => workspace_id = Some(value()?),
                "--agent-task-id" => agent_task_id = Some(value()?),
                "--cols" => {
                    cols = value()?
                        .parse()
                        .map_err(|_| SmokeError::usage("--cols must be a u16"))?
                }
                "--rows" => {
                    rows = value()?
                        .parse()
                        .map_err(|_| SmokeError::usage("--rows must be a u16"))?
                }
                other => return Err(SmokeError::usage(format!("unknown flag {other:?}"))),
            }
            i += 2;
        }

        let session_id = session_id.ok_or_else(|| SmokeError::usage("--session-id is required"))?;
        let workspace_id =
            workspace_id.ok_or_else(|| SmokeError::usage("--workspace-id is required"))?;
        let agent_task_id =
            agent_task_id.ok_or_else(|| SmokeError::usage("--agent-task-id is required"))?;
        let cwd = cwd_modes.resolve()?;
        let argv = require_argv(argv)?;

        Ok(AgentResumeArgs {
            base,
            socket,
            session_id,
            workspace_id,
            agent_task_id,
            cwd,
            cols,
            rows,
            argv,
        })
    }
}

fn parse_kind(s: &str) -> Result<SessionKind, SmokeError> {
    match s {
        "shell" => Ok(SessionKind::Shell),
        "agent" => Ok(SessionKind::Agent),
        other => Err(SmokeError::usage(format!(
            "--kind must be `shell` or `agent`, got {other:?}"
        ))),
    }
}

// ---- error model ----------------------------------------------------------------------------

/// A CLI error carrying a machine-readable `error_kind` and a human message. `Usage` is for
/// bad arguments; the rest mirror the `ShellRuntimeError` layers so a script can branch on cause.
#[derive(Debug, PartialEq, Eq)]
struct SmokeError {
    kind: &'static str,
    message: String,
}

impl SmokeError {
    fn usage(message: impl Into<String>) -> Self {
        SmokeError {
            kind: "usage",
            message: message.into(),
        }
    }

    fn store(message: impl Into<String>) -> Self {
        SmokeError {
            kind: "store",
            message: message.into(),
        }
    }

    /// The one-line JSON object printed to stderr on failure.
    fn to_json_line(&self) -> String {
        json!({
            "ok": false,
            "error_kind": self.kind,
            "message": self.message,
        })
        .to_string()
    }
}

impl From<WorkspaceExecError> for SmokeError {
    fn from(e: WorkspaceExecError) -> Self {
        SmokeError {
            kind: "workspace",
            message: e.to_string(),
        }
    }
}

impl From<WorkspaceConsentError> for SmokeError {
    fn from(e: WorkspaceConsentError) -> Self {
        SmokeError {
            kind: "workspace",
            message: e.to_string(),
        }
    }
}

impl From<ShellRuntimeError> for SmokeError {
    fn from(e: ShellRuntimeError) -> Self {
        let kind = match e {
            ShellRuntimeError::Store(_) => "store",
            ShellRuntimeError::Daemon(_) => "daemon",
            ShellRuntimeError::Session(_) => "session",
        };
        SmokeError {
            kind,
            message: e.to_string(),
        }
    }
}

impl From<WindowLayoutError> for SmokeError {
    /// All window-layout failures (not-found / already-exists / bad tab / bad order /
    /// future-version / corrupt / wrapped store error) surface under one machine-readable kind so
    /// a script can branch on `error_kind == "window_layout"`. The store-id refusal (unsafe id)
    /// still arrives here wrapped as `Store(Id(_))` and stays `window_layout`.
    fn from(e: WindowLayoutError) -> Self {
        SmokeError {
            kind: "window_layout",
            message: e.to_string(),
        }
    }
}

impl From<AgentTaskRuntimeError> for SmokeError {
    /// Keep each layer distinguishable for scripting:
    /// - `Task` (task-store refusal: exists/not-found/future-version/corrupt) -> `"task"`.
    /// - `Shell` (endpoint/daemon/session) -> the underlying `ShellRuntimeError` category, so a
    ///   missing daemon stays `"daemon"` exactly like `start`/`reconcile` report it.
    /// - validation (`InvalidSessionKind` / `AgentTaskIdMismatch`) -> `"agent_runtime"`; these
    ///   are caller-internal invariants this CLI never actually violates (it always sets the
    ///   kind/FK correctly), so they are not `"usage"`.
    fn from(e: AgentTaskRuntimeError) -> Self {
        match e {
            AgentTaskRuntimeError::Task(_) => SmokeError {
                kind: "task",
                message: e.to_string(),
            },
            AgentTaskRuntimeError::Shell(shell) => SmokeError::from(shell),
            AgentTaskRuntimeError::InvalidSessionKind { .. }
            | AgentTaskRuntimeError::AgentTaskIdMismatch { .. } => SmokeError {
                kind: "agent_runtime",
                message: e.to_string(),
            },
        }
    }
}

// ---- JSON success shaping (pure) ------------------------------------------------------------

/// The success JSON for `start`: includes ok/socket_path/session_id/status/generation (+ kind).
fn start_success_json(outcome: &StartSessionOutcome) -> serde_json::Value {
    json!({
        "ok": true,
        "command": "start",
        "socket_path": outcome.socket_path.to_string_lossy(),
        "session_id": outcome.record.session_id,
        "status": status_str(outcome.record.status),
        "generation": outcome.record.last_known_generation,
    })
}

/// The success JSON for `reconcile`: ok/socket_path/sessions[]/recovered_sessions[]/
/// skipped_future_version[]. `recovered_sessions` lists live daemon ids with no
/// loadable current-version record — surfaced read-only, never written/attached/killed.
fn reconcile_success_json(outcome: &ReconcileOutcome) -> serde_json::Value {
    let sessions: Vec<serde_json::Value> = outcome
        .report
        .sessions
        .iter()
        .map(|s| {
            json!({
                "session_id": s.session_id,
                "status": status_str(s.status),
                "rewritten": s.rewritten,
            })
        })
        .collect();
    let recovered_sessions: Vec<serde_json::Value> = outcome
        .report
        .recovered_sessions
        .iter()
        .map(|r| json!({ "session_id": r.session_id }))
        .collect();
    let skipped: Vec<String> = outcome
        .report
        .skipped_future_version
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    json!({
        "ok": true,
        "command": "reconcile",
        "socket_path": outcome.socket_path.to_string_lossy(),
        "sessions": sessions,
        "recovered_sessions": recovered_sessions,
        "skipped_future_version": skipped,
    })
}

/// The wire-stable string for a session status, matching the record's serde repr.
fn status_str(status: maestro_shell::SessionStatus) -> &'static str {
    use maestro_shell::SessionStatus::*;
    match status {
        Live => "live",
        Exited => "exited",
        Unknown => "unknown",
    }
}

/// The wire-stable string for an `AgentTaskState`, matching its serde `snake_case` repr.
fn agent_state_str(state: AgentTaskState) -> &'static str {
    match state {
        AgentTaskState::Draft => "draft",
        AgentTaskState::Running => "running",
        AgentTaskState::WaitingOnUser => "waiting_on_user",
        AgentTaskState::Blocked => "blocked",
        AgentTaskState::Succeeded => "succeeded",
        AgentTaskState::Failed => "failed",
        AgentTaskState::Cancelled => "cancelled",
    }
}

/// The wire-stable string for an [`Attention`], matching its serde `snake_case` repr.
fn attention_str(attention: Attention) -> &'static str {
    match attention {
        Attention::None => "none",
        Attention::Activity => "activity",
        Attention::NeedsInput => "needs_input",
        Attention::Error => "error",
        Attention::Done => "done",
    }
}

/// The wire-stable string for an [`AttentionSource`], matching its serde `snake_case` repr.
fn attention_source_str(source: AttentionSource) -> &'static str {
    match source {
        AttentionSource::Process => "process",
        AttentionSource::Agent => "agent",
        AttentionSource::User => "user",
    }
}

/// Shape a persisted [`AttentionState`] into the stable nested JSON object used by every
/// window-layout command that prints tabs.
fn attention_json(attention: &AttentionState) -> serde_json::Value {
    json!({
        "attention": attention_str(attention.attention),
        "unseen": attention.unseen,
        "since_ms": attention.since_ms,
        "source": attention_source_str(attention.source),
    })
}

/// One layout-returning command's success JSON: `ok`/`command`/`window_id`/`tabs[]` (ordered by
/// index, each with its persisted attention state). Shared by create/show/open-tab/close-tab/
/// rename-tab/pin-tab/reorder-tabs/attention.
fn layout_success_json(command: &'static str, layout: &WindowLayout) -> serde_json::Value {
    let tabs: Vec<serde_json::Value> = layout
        .tabs
        .iter()
        .map(|t| {
            json!({
                "tab_id": t.tab_id,
                "session_id": t.session_id,
                "index": t.index,
                "title": t.title,
                "pinned": t.pinned,
                "attention": attention_json(&t.attention),
                "split_from": split_from_json(t.split_from.as_ref()),
            })
        })
        .collect();
    json!({
        "ok": true,
        "command": command,
        "window_id": layout.window_id,
        "tabs": tabs,
    })
}

/// Shape a tab's optional split provenance into the stable JSON used by `layout_success_json`:
/// `null` when the tab was not split, else `{ "tab_id": <source>, "axis": "right"|"down" }`.
fn split_from_json(split_from: Option<&maestro_shell::SplitFrom>) -> serde_json::Value {
    match split_from {
        None => serde_json::Value::Null,
        Some(s) => json!({
            "tab_id": s.tab_id,
            "axis": match s.axis {
                SplitAxis::Right => "right",
                SplitAxis::Down => "down",
            },
        }),
    }
}

/// The `window view` success JSON: each projected [`WindowTabView`] row, carrying the persisted
/// tab fields plus the joined agent-task/session reconciliation fields and `needs_attention`.
fn window_view_success_json(window_id: &str, views: &[WindowTabView]) -> serde_json::Value {
    let tabs: Vec<serde_json::Value> = views
        .iter()
        .map(|v| {
            json!({
                "tab_id": v.tab_id,
                "session_id": v.session_id,
                "index": v.index,
                "title": v.title,
                "pinned": v.pinned,
                "attention": attention_json(&v.attention),
                "session_status": v.session_status.map(status_str),
                "agent_task_id": v.agent_task_id,
                "agent_task_state": v.agent_task_state.map(agent_state_str),
                "needs_attention": v.needs_attention,
                "session_record_missing": v.session_record_missing,
                "split_from": split_from_json(v.split_from.as_ref()),
            })
        })
        .collect();
    json!({
        "ok": true,
        "command": "window view",
        "window_id": window_id,
        "tabs": tabs,
    })
}

/// Shared task/session shaping for `agent-start` / `agent-resume`. Both report the same fields;
/// `agent-resume` additionally carries the session history (added by the caller).
fn agent_outcome_json(command: &'static str, outcome: &StartAgentTaskOutcome) -> serde_json::Value {
    json!({
        "ok": true,
        "command": command,
        "socket_path": outcome.socket_path.to_string_lossy(),
        "agent_task_id": outcome.task.agent_task_id,
        "task_state": agent_state_str(outcome.task.state),
        "session_id": outcome.session.session_id,
        "session_status": status_str(outcome.session.status),
        "generation": outcome.session.last_known_generation,
    })
}

/// The success JSON for `agent-start`: ok/command/socket_path + task/session fields.
fn agent_start_success_json(outcome: &StartAgentTaskOutcome) -> serde_json::Value {
    agent_outcome_json("agent-start", outcome)
}

/// The success JSON for `agent-resume`: like `agent-start` plus the task's `session_history`
/// (oldest first) so a caller can see prior sessions for the resumed task.
fn agent_resume_success_json(outcome: &StartAgentTaskOutcome) -> serde_json::Value {
    let mut value = agent_outcome_json("agent-resume", outcome);
    value["session_history"] = json!(outcome.task.session_history);
    value
}

/// The success JSON for `task-reconcile` (local, no daemon): the full read-only join of agent
/// tasks against session records.
fn task_reconcile_success_json(report: &AgentTaskReconcileReport) -> serde_json::Value {
    let tasks: Vec<serde_json::Value> = report
        .tasks
        .iter()
        .map(|t| {
            json!({
                "agent_task_id": t.agent_task_id,
                "state": agent_state_str(t.state),
                "current_session_id": t.current_session_id,
                "current_session_status": t.current_session_status.map(status_str),
                "session_record_missing": t.session_record_missing,
                "needs_attention": t.needs_attention,
            })
        })
        .collect();
    let dangling: Vec<serde_json::Value> = report
        .dangling_session_task_refs
        .iter()
        .map(|d| {
            json!({
                "session_id": d.session_id,
                "agent_task_id": d.agent_task_id,
                "session_status": status_str(d.session_status),
            })
        })
        .collect();
    json!({
        "ok": true,
        "command": "task-reconcile",
        "tasks": tasks,
        "dangling_session_task_refs": dangling,
        "skipped_future_tasks": paths_to_strings(&report.skipped_future_tasks),
        "skipped_future_sessions": paths_to_strings(&report.skipped_future_sessions),
        "quarantined_tasks": quarantined_to_json(&report.quarantined_tasks),
        "quarantined_sessions": quarantined_to_json(&report.quarantined_sessions),
    })
}

fn paths_to_strings(paths: &[PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

fn quarantined_to_json(records: &[maestro_shell::QuarantinedRecord]) -> Vec<serde_json::Value> {
    records
        .iter()
        .map(|q| {
            json!({
                "original": q.original.to_string_lossy(),
                "moved_to": q.moved_to.to_string_lossy(),
                "reason": q.reason,
            })
        })
        .collect()
}

// ---- dashboard JSON shaping (pure) -----------------------------------------------------------

/// Shape one projected [`DashboardTab`] into stable JSON. Carries the persisted tab fields plus
/// the joined agent-task / session-status fields and the derived `needs_attention`, all under the
/// same `snake_case` keys the `window view` command uses.
fn dashboard_tab_json(tab: &maestro_shell::DashboardTab) -> serde_json::Value {
    json!({
        "window_id": tab.window_id,
        "tab_id": tab.tab_id,
        "session_id": tab.session_id,
        "index": tab.index,
        "title": tab.title,
        "pinned": tab.pinned,
        "attention": attention_json(&tab.attention),
        "agent_task_id": tab.agent_task_id,
        "agent_task_state": tab.agent_task_state.map(agent_state_str),
        "session_status": tab.session_status.map(status_str),
        "session_record_missing": tab.session_record_missing,
        "needs_attention": tab.needs_attention,
    })
}

/// Shape one [`DashboardWindow`] (its id plus its ordered projected tabs).
fn dashboard_window_json(window: &maestro_shell::DashboardWindow) -> serde_json::Value {
    let tabs: Vec<serde_json::Value> = window.tabs.iter().map(dashboard_tab_json).collect();
    json!({
        "window_id": window.window_id,
        "tabs": tabs,
    })
}

/// Shape one [`Workspace`] record for the dashboard (id / project / root / policy / consent).
fn dashboard_workspace_json(ws: &Workspace) -> serde_json::Value {
    json!({
        "workspace_id": ws.workspace_id,
        "project_id": ws.project_id,
        "root": ws.root,
        "policy": ws.policy,
        "consent": ws.consent,
    })
}

/// Shape one [`maestro_shell::AgentTask`] record for the dashboard.
fn dashboard_task_json(task: &maestro_shell::AgentTask) -> serde_json::Value {
    json!({
        "agent_task_id": task.agent_task_id,
        "project_id": task.project_id,
        "goal": task.goal,
        "state": agent_state_str(task.state),
        "current_session_id": task.current_session_id,
        "session_history": task.session_history,
        "created_at_ms": task.created_at_ms,
        "updated_at_ms": task.updated_at_ms,
        "result_summary": task.result_summary,
    })
}

/// Shape one [`maestro_shell::ProjectSnapshot`]: the project header plus its grouped
/// workspaces / tasks / windows.
fn dashboard_project_json(project: &maestro_shell::ProjectSnapshot) -> serde_json::Value {
    let workspaces: Vec<serde_json::Value> = project
        .workspaces
        .iter()
        .map(dashboard_workspace_json)
        .collect();
    let tasks: Vec<serde_json::Value> = project.tasks.iter().map(dashboard_task_json).collect();
    let windows: Vec<serde_json::Value> =
        project.windows.iter().map(dashboard_window_json).collect();
    json!({
        "project_id": project.project_id,
        "name": project.name,
        "root": project.root,
        "last_active_at_ms": project.last_active_at_ms,
        "workspaces": workspaces,
        "tasks": tasks,
        "windows": windows,
    })
}

/// The `dashboard` success JSON: the full read-only projection — projects (each
/// with grouped workspaces/tasks/windows/tabs), windows that couldn't be associated to a project,
/// recovered sessions (empty unless `--with-session-reconcile` supplied a `ReconcileReport`), the
/// per-kind future-version skip buckets, and quarantined/corrupt records. Reconcile mode adds
/// `session_reconcile` (whether the daemon reconcile ran) and, when it did, the `socket_path` the
/// reconcile used.
fn dashboard_success_json(outcome: &DashboardOutcome) -> serde_json::Value {
    let snapshot = &outcome.snapshot;
    let projects: Vec<serde_json::Value> = snapshot
        .projects
        .iter()
        .map(dashboard_project_json)
        .collect();
    let unassigned_windows: Vec<serde_json::Value> = snapshot
        .unassigned_windows
        .iter()
        .map(dashboard_window_json)
        .collect();
    let recovered_sessions: Vec<serde_json::Value> = snapshot
        .recovered_sessions
        .iter()
        .map(|r| json!({ "session_id": r.session_id }))
        .collect();
    let mut value = json!({
        "ok": true,
        "command": "dashboard",
        "session_reconcile": outcome.session_reconcile,
        "projects": projects,
        "unassigned_windows": unassigned_windows,
        "recovered_sessions": recovered_sessions,
        "skipped_future_projects": paths_to_strings(&snapshot.skipped_future_projects),
        "skipped_future_workspaces": paths_to_strings(&snapshot.skipped_future_workspaces),
        "skipped_future_windows": paths_to_strings(&snapshot.skipped_future_windows),
        "skipped_future_tasks": paths_to_strings(&snapshot.skipped_future_tasks),
        "skipped_future_sessions": paths_to_strings(&snapshot.skipped_future_sessions),
        "quarantined": quarantined_to_json(&snapshot.quarantined),
    });
    if let Some(socket_path) = &outcome.socket_path {
        value["socket_path"] = json!(socket_path.display().to_string());
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use maestro_shell::{AgentTask, ReconciledSession, SessionRecord, SessionStatus};

    fn toks(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }

    // ---- parser: start ----

    #[test]
    fn parses_valid_start_with_command_after_dashdash() {
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--cwd",
            "/tmp",
            "--cols",
            "120",
            "--rows",
            "40",
            "--kind",
            "agent",
            "--socket",
            "/run/d.sock",
            "--",
            "/bin/zsh",
            "-l",
        ]);
        let parsed = StartArgs::parse(&t).unwrap();
        assert_eq!(parsed.session_id, "s1");
        assert_eq!(parsed.workspace_id, "ws1");
        assert_eq!(parsed.cwd, CwdMode::Explicit("/tmp".into()));
        assert_eq!(parsed.cols, 120);
        assert_eq!(parsed.rows, 40);
        assert_eq!(parsed.kind, SessionKind::Agent);
        assert_eq!(parsed.socket, Some(PathBuf::from("/run/d.sock")));
        assert_eq!(parsed.argv, vec!["/bin/zsh".to_string(), "-l".to_string()]);
    }

    #[test]
    fn start_defaults_cols_rows_kind_when_omitted() {
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--cwd",
            "/tmp",
            "--",
            "/bin/sh",
        ]);
        let parsed = StartArgs::parse(&t).unwrap();
        assert_eq!(parsed.cols, 80);
        assert_eq!(parsed.rows, 24);
        assert_eq!(parsed.kind, SessionKind::Shell);
        assert_eq!(parsed.base, None);
        assert_eq!(parsed.socket, None);
    }

    #[test]
    fn start_command_after_dashdash_may_contain_flags() {
        // Tokens that LOOK like our flags but come after `--` are part of the session command.
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--cwd",
            "/tmp",
            "--",
            "/usr/bin/env",
            "--cols",
            "FAKE",
        ]);
        let parsed = StartArgs::parse(&t).unwrap();
        assert_eq!(
            parsed.argv,
            vec![
                "/usr/bin/env".to_string(),
                "--cols".to_string(),
                "FAKE".to_string()
            ]
        );
        assert_eq!(
            parsed.cols, 80,
            "post-`--` tokens must not be parsed as flags"
        );
    }

    #[test]
    fn start_rejects_missing_required_fields() {
        // No session-id.
        let t = toks(&["--workspace-id", "ws1", "--cwd", "/tmp", "--", "/bin/sh"]);
        assert_eq!(StartArgs::parse(&t).unwrap_err().kind, "usage");
        // No workspace-id.
        let t = toks(&["--session-id", "s1", "--cwd", "/tmp", "--", "/bin/sh"]);
        assert_eq!(StartArgs::parse(&t).unwrap_err().kind, "usage");
        // No cwd.
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--",
            "/bin/sh",
        ]);
        assert_eq!(StartArgs::parse(&t).unwrap_err().kind, "usage");
    }

    #[test]
    fn start_scratch_replaces_cwd() {
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--scratch",
            "--",
            "/bin/sh",
        ]);
        let parsed = StartArgs::parse(&t).unwrap();
        assert_eq!(parsed.cwd, CwdMode::Scratch);
        assert_eq!(parsed.argv, vec!["/bin/sh".to_string()]);
    }

    #[test]
    fn start_scratch_conflicts_with_explicit_cwd() {
        // Passing BOTH is an intentional usage error, not a silent precedence rule.
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--cwd",
            "/tmp",
            "--scratch",
            "--",
            "/bin/sh",
        ]);
        let e = StartArgs::parse(&t).unwrap_err();
        assert_eq!(e.kind, "usage");
        assert!(
            e.message.contains("--scratch") && e.message.contains("--cwd"),
            "conflict message must name both flags, got {:?}",
            e.message
        );
    }

    #[test]
    fn start_rejects_missing_command_argv() {
        // No `--` at all.
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--cwd",
            "/tmp",
        ]);
        let e = StartArgs::parse(&t).unwrap_err();
        assert_eq!(e.kind, "usage");
        // `--` present but empty argv.
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--cwd",
            "/tmp",
            "--",
        ]);
        let e = StartArgs::parse(&t).unwrap_err();
        assert_eq!(e.kind, "usage");
    }

    #[test]
    fn start_rejects_bad_kind_and_nonnumeric_cols() {
        let base = [
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--cwd",
            "/tmp",
        ];
        let mut t = toks(&base);
        t.extend(toks(&["--kind", "wizard", "--", "/bin/sh"]));
        assert_eq!(StartArgs::parse(&t).unwrap_err().kind, "usage");

        let mut t = toks(&base);
        t.extend(toks(&["--cols", "huge", "--", "/bin/sh"]));
        assert_eq!(StartArgs::parse(&t).unwrap_err().kind, "usage");
    }

    #[test]
    fn start_rejects_flag_missing_value() {
        let t = toks(&["--session-id"]);
        assert_eq!(StartArgs::parse(&t).unwrap_err().kind, "usage");
    }

    // ---- parser: worktree mode ----

    #[test]
    fn worktree_parse_accepts_repo_root_with_allow_flag() {
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--worktree",
            "/repos/demo",
            "--allow-worktree-create",
            "--",
            "/bin/sh",
        ]);
        let parsed = StartArgs::parse(&t).unwrap();
        assert_eq!(
            parsed.cwd,
            CwdMode::Worktree {
                repo_root: "/repos/demo".into()
            }
        );
        assert_eq!(parsed.argv, vec!["/bin/sh".to_string()]);
    }

    #[test]
    fn worktree_parse_requires_allow_worktree_create() {
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--worktree",
            "/repos/demo",
            "--",
            "/bin/sh",
        ]);
        let e = StartArgs::parse(&t).unwrap_err();
        assert_eq!(e.kind, "usage");
        assert!(
            e.message.contains("--allow-worktree-create") && e.message.contains("administrative"),
            "message must explain the git administrative-state mutation, got {:?}",
            e.message
        );
    }

    #[test]
    fn worktree_parse_conflicts_with_cwd_and_scratch() {
        for extra in [&["--cwd", "/tmp"][..], &["--scratch"][..]] {
            let mut t = toks(&[
                "--session-id",
                "s1",
                "--workspace-id",
                "ws1",
                "--worktree",
                "/repos/demo",
                "--allow-worktree-create",
            ]);
            t.extend(toks(extra));
            t.extend(toks(&["--", "/bin/sh"]));
            let e = StartArgs::parse(&t).unwrap_err();
            assert_eq!(e.kind, "usage", "extra {extra:?} must conflict");
            assert!(
                e.message.contains("mutually exclusive"),
                "got {:?}",
                e.message
            );
        }
    }

    #[test]
    fn worktree_allow_flag_without_worktree_is_usage_error() {
        for cwd_flags in [&["--cwd", "/tmp"][..], &["--scratch"][..], &[][..]] {
            let mut t = toks(&["--session-id", "s1", "--workspace-id", "ws1"]);
            t.extend(toks(cwd_flags));
            t.extend(toks(&["--allow-worktree-create", "--", "/bin/sh"]));
            let e = StartArgs::parse(&t).unwrap_err();
            assert_eq!(e.kind, "usage", "cwd flags {cwd_flags:?}");
            assert!(
                e.message.contains("--allow-worktree-create"),
                "got {:?}",
                e.message
            );
        }
    }

    // ---- parser: repo-write mode ----

    #[test]
    fn repo_write_parse_accepts_repo_root_with_allow_flag() {
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--repo-write",
            "/repos/demo",
            "--allow-repo-write",
            "--",
            "/bin/sh",
        ]);
        let parsed = StartArgs::parse(&t).unwrap();
        assert_eq!(
            parsed.cwd,
            CwdMode::RepoWrite {
                repo_root: "/repos/demo".into()
            }
        );
        assert_eq!(parsed.argv, vec!["/bin/sh".to_string()]);
    }

    #[test]
    fn repo_write_parse_requires_allow_repo_write() {
        let t = toks(&[
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--repo-write",
            "/repos/demo",
            "--",
            "/bin/sh",
        ]);
        let e = StartArgs::parse(&t).unwrap_err();
        assert_eq!(e.kind, "usage");
        assert!(
            e.message.contains("--allow-repo-write")
                && e.message.contains("live checkout")
                && e.message.contains("repo root")
                && e.message.contains("write there"),
            "message must say it runs directly in the live checkout / repo root and may allow \
             writes there, got {:?}",
            e.message
        );
    }

    #[test]
    fn repo_write_parse_conflicts_with_other_cwd_modes() {
        for extra in [
            &["--cwd", "/tmp"][..],
            &["--scratch"][..],
            &["--worktree", "/repos/other", "--allow-worktree-create"][..],
        ] {
            let mut t = toks(&[
                "--session-id",
                "s1",
                "--workspace-id",
                "ws1",
                "--repo-write",
                "/repos/demo",
                "--allow-repo-write",
            ]);
            t.extend(toks(extra));
            t.extend(toks(&["--", "/bin/sh"]));
            let e = StartArgs::parse(&t).unwrap_err();
            assert_eq!(e.kind, "usage", "extra {extra:?} must conflict");
            assert!(
                e.message.contains("mutually exclusive"),
                "got {:?}",
                e.message
            );
        }
    }

    #[test]
    fn repo_write_allow_flag_without_repo_write_is_usage_error() {
        for cwd_flags in [
            &["--cwd", "/tmp"][..],
            &["--scratch"][..],
            &["--worktree", "/repos/demo", "--allow-worktree-create"][..],
            &[][..],
        ] {
            let mut t = toks(&["--session-id", "s1", "--workspace-id", "ws1"]);
            t.extend(toks(cwd_flags));
            t.extend(toks(&["--allow-repo-write", "--", "/bin/sh"]));
            let e = StartArgs::parse(&t).unwrap_err();
            assert_eq!(e.kind, "usage", "cwd flags {cwd_flags:?}");
            assert!(
                e.message.contains("--allow-repo-write"),
                "got {:?}",
                e.message
            );
        }
    }

    // ---- worktree mode: workspace record + prepared cwd (temp dirs/repos ONLY) ----

    use tempfile::TempDir;

    fn temp_paths() -> (TempDir, AppPaths) {
        let tmp = TempDir::new().expect("temp dir");
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        (tmp, paths)
    }

    /// Seed a Project row so a Workspace referencing it satisfies the SQLite FK
    /// `workspaces.project_id → projects` (FK-safe order: project before workspace). Idempotent:
    /// a duplicate id is ignored so callers can seed every id they might touch.
    fn seed_project(paths: &AppPaths, project_id: &str) {
        maestro_shell::project::ProjectService::new(paths)
            .create(
                project_id.to_string(),
                project_id.to_string(),
                "/r",
                maestro_shell::project::NewProject::default(),
                1,
            )
            .ok();
    }

    fn load_workspace(paths: &AppPaths, id: &str) -> Workspace {
        match load_one::<Workspace>(paths, RecordKind::Workspace, id)
            .expect("load")
            .expect("record must exist")
        {
            LoadOutcome::Loaded(ws) => ws,
            other => panic!("expected Loaded, got {other:?}"),
        }
    }

    #[test]
    fn worktree_mode_creates_record_granting_only_worktree_create() {
        let (_tmp, paths) = temp_paths();
        seed_project(&paths, "smoke-cli");
        let ws = ensure_worktree_workspace(&paths, "ws1", "/repos/demo", 42).unwrap();
        assert_eq!(ws.policy, WorkspacePolicy::Worktree);
        assert_eq!(ws.root, "/repos/demo");
        assert!(ws.consent.worktree_create);
        assert!(!ws.consent.repo_write, "RepoWrite must NEVER be granted");
        assert_eq!(ws.consent.granted_at_ms, Some(42));
        // The record is durable and identical on disk.
        assert_eq!(load_workspace(&paths, "ws1"), ws);
    }

    #[test]
    fn worktree_mode_reuses_matching_record_and_grants_missing_consent() {
        let (_tmp, paths) = temp_paths();
        seed_project(&paths, "someone-else");
        // Pre-existing matching record WITHOUT consent.
        let bare = Workspace {
            workspace_id: "ws1".into(),
            project_id: "someone-else".into(),
            root: "/repos/demo".into(),
            policy: WorkspacePolicy::Worktree,
            consent: WorkspaceConsent {
                worktree_create: false,
                repo_write: false,
                granted_at_ms: None,
            },
        };
        write_record(&paths, RecordKind::Workspace, "ws1", 1, &bare).unwrap();

        let ws = ensure_worktree_workspace(&paths, "ws1", "/repos/demo", 99).unwrap();
        assert!(ws.consent.worktree_create);
        assert!(!ws.consent.repo_write);
        assert_eq!(ws.consent.granted_at_ms, Some(99));
        // Unrelated fields are preserved — reuse, not replacement.
        assert_eq!(ws.project_id, "someone-else");

        // Already-granted record is reused untouched (timestamp not refreshed).
        let again = ensure_worktree_workspace(&paths, "ws1", "/repos/demo", 12345).unwrap();
        assert_eq!(again.consent.granted_at_ms, Some(99));
        assert_eq!(load_workspace(&paths, "ws1"), again);
    }

    #[test]
    fn worktree_mode_conflicting_record_errors_and_is_not_overwritten() {
        let (_tmp, paths) = temp_paths();
        seed_project(&paths, "p");
        let other = Workspace {
            workspace_id: "ws1".into(),
            project_id: "p".into(),
            root: "/repos/OTHER".into(),
            policy: WorkspacePolicy::Worktree,
            consent: WorkspaceConsent {
                worktree_create: false,
                repo_write: false,
                granted_at_ms: None,
            },
        };
        write_record(&paths, RecordKind::Workspace, "ws1", 1, &other).unwrap();

        // Different root.
        let e = ensure_worktree_workspace(&paths, "ws1", "/repos/demo", 99).unwrap_err();
        assert_eq!(e.kind, "workspace");
        assert!(e.message.contains("conflicts"), "got {:?}", e.message);

        // Different policy (same root).
        let mut scratch_ws = other.clone();
        scratch_ws.policy = WorkspacePolicy::ScratchCwd;
        scratch_ws.root = "/repos/demo".into();
        write_record(&paths, RecordKind::Workspace, "ws1", 2, &scratch_ws).unwrap();
        let e = ensure_worktree_workspace(&paths, "ws1", "/repos/demo", 99).unwrap_err();
        assert_eq!(e.kind, "workspace");

        // The conflicting record was NOT overwritten or consent-mutated.
        let on_disk = load_workspace(&paths, "ws1");
        assert_eq!(on_disk, scratch_ws);
        assert!(!on_disk.consent.worktree_create);
    }

    /// Run git in a TEST temp repo, asserting success. Never pointed at the real repo.
    fn git(args: &[&str]) {
        let out = std::process::Command::new("git")
            .args(args)
            .output()
            .expect("spawn git");
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn init_temp_repo() -> TempDir {
        let repo = TempDir::new().expect("repo dir");
        let r = repo.path().to_str().expect("utf8 temp path");
        git(&["-C", r, "init", "-q"]);
        git(&["-C", r, "config", "user.email", "maestro-test@example.com"]);
        git(&["-C", r, "config", "user.name", "Maestro Test"]);
        std::fs::write(repo.path().join("seed.txt"), "seed\n").expect("seed file");
        git(&["-C", r, "add", "seed.txt"]);
        git(&["-C", r, "commit", "-q", "-m", "seed"]);
        repo
    }

    #[test]
    fn worktree_mode_prepared_cwd_flows_into_start_params() {
        let (_tmp, paths) = temp_paths();
        seed_project(&paths, "smoke-cli");
        let repo = init_temp_repo();
        let parsed = StartArgs {
            base: Some(paths.base().to_path_buf()),
            socket: None,
            session_id: "sess1".into(),
            workspace_id: "ws1".into(),
            cwd: CwdMode::Worktree {
                repo_root: repo.path().to_str().expect("utf8").into(),
            },
            cols: 80,
            rows: 24,
            kind: SessionKind::Shell,
            argv: vec!["/bin/sh".into()],
        };

        let cwd = resolve_cwd(
            &paths,
            &parsed.workspace_id,
            &parsed.session_id,
            &parsed.cwd,
            7,
        )
        .unwrap();
        let expected = paths.worktree_base().join("ws1").join("sess1");
        assert_eq!(PathBuf::from(&cwd), expected);
        assert!(expected.join("seed.txt").is_file(), "real checkout");

        // Exactly this prepared cwd lands in StartParams.
        let params = StartParams::adhoc(
            parsed.session_id.clone(),
            parsed.workspace_id.clone(),
            parsed.kind,
            cwd.clone(),
            &parsed.argv,
            parsed.cols,
            parsed.rows,
            7,
        );
        assert_eq!(params.cwd, cwd);
        // And the workspace record got ONLY worktree_create.
        let ws = load_workspace(&paths, "ws1");
        assert!(ws.consent.worktree_create);
        assert!(!ws.consent.repo_write);
    }

    // ---- repo-write mode: workspace record + prepared cwd (temp dirs ONLY, NO git) ----

    #[test]
    fn repo_write_mode_creates_record_granting_only_repo_write() {
        let (_tmp, paths) = temp_paths();
        seed_project(&paths, "smoke-cli");
        let ws = ensure_repo_write_workspace(&paths, "ws1", "/repos/demo", 42).unwrap();
        assert_eq!(ws.policy, WorkspacePolicy::RepoWrite);
        assert_eq!(ws.root, "/repos/demo");
        assert!(ws.consent.repo_write);
        assert!(
            !ws.consent.worktree_create,
            "worktree_create must NEVER be granted by --repo-write"
        );
        assert_eq!(ws.consent.granted_at_ms, Some(42));
        // The record is durable and identical on disk.
        assert_eq!(load_workspace(&paths, "ws1"), ws);
    }

    #[test]
    fn repo_write_mode_reuses_matching_record_and_grants_missing_consent() {
        let (_tmp, paths) = temp_paths();
        seed_project(&paths, "someone-else");
        // Pre-existing matching record WITHOUT the grant.
        let bare = Workspace {
            workspace_id: "ws1".into(),
            project_id: "someone-else".into(),
            root: "/repos/demo".into(),
            policy: WorkspacePolicy::RepoWrite,
            consent: WorkspaceConsent {
                worktree_create: false,
                repo_write: false,
                granted_at_ms: None,
            },
        };
        write_record(&paths, RecordKind::Workspace, "ws1", 1, &bare).unwrap();

        let ws = ensure_repo_write_workspace(&paths, "ws1", "/repos/demo", 99).unwrap();
        assert!(ws.consent.repo_write);
        assert!(!ws.consent.worktree_create);
        assert_eq!(ws.consent.granted_at_ms, Some(99));
        // Unrelated fields are preserved — reuse, not replacement.
        assert_eq!(ws.project_id, "someone-else");

        // Already-granted record is reused untouched (timestamp not refreshed).
        let again = ensure_repo_write_workspace(&paths, "ws1", "/repos/demo", 12345).unwrap();
        assert_eq!(again.consent.granted_at_ms, Some(99));
        assert_eq!(load_workspace(&paths, "ws1"), again);
    }

    #[test]
    fn repo_write_mode_conflicting_record_errors_and_is_not_overwritten() {
        let (_tmp, paths) = temp_paths();
        seed_project(&paths, "p");
        // Different root.
        let other = Workspace {
            workspace_id: "ws1".into(),
            project_id: "p".into(),
            root: "/repos/OTHER".into(),
            policy: WorkspacePolicy::RepoWrite,
            consent: WorkspaceConsent {
                worktree_create: false,
                repo_write: false,
                granted_at_ms: None,
            },
        };
        write_record(&paths, RecordKind::Workspace, "ws1", 1, &other).unwrap();
        let e = ensure_repo_write_workspace(&paths, "ws1", "/repos/demo", 99).unwrap_err();
        assert_eq!(e.kind, "workspace");
        assert!(e.message.contains("conflicts"), "got {:?}", e.message);

        // Different policy (same root) — e.g. an existing worktree record.
        let mut worktree_ws = other.clone();
        worktree_ws.policy = WorkspacePolicy::Worktree;
        worktree_ws.root = "/repos/demo".into();
        write_record(&paths, RecordKind::Workspace, "ws1", 2, &worktree_ws).unwrap();
        let e = ensure_repo_write_workspace(&paths, "ws1", "/repos/demo", 99).unwrap_err();
        assert_eq!(e.kind, "workspace");

        // The conflicting record was NOT overwritten or consent-mutated.
        let on_disk = load_workspace(&paths, "ws1");
        assert_eq!(on_disk, worktree_ws);
        assert!(!on_disk.consent.repo_write);
    }

    #[test]
    fn repo_write_mode_prepared_cwd_flows_into_start_params() {
        let (_tmp, paths) = temp_paths();
        seed_project(&paths, "smoke-cli");
        // A plain temp dir — NO git anywhere in repo-write tests.
        let root = TempDir::new().expect("root dir");
        let root_str = root.path().to_str().expect("utf8").to_string();
        let parsed = StartArgs {
            base: Some(paths.base().to_path_buf()),
            socket: None,
            session_id: "sess1".into(),
            workspace_id: "ws1".into(),
            cwd: CwdMode::RepoWrite {
                repo_root: root_str.clone(),
            },
            cols: 80,
            rows: 24,
            kind: SessionKind::Shell,
            argv: vec!["/bin/sh".into()],
        };

        let cwd = resolve_cwd(
            &paths,
            &parsed.workspace_id,
            &parsed.session_id,
            &parsed.cwd,
            7,
        )
        .unwrap();
        assert_eq!(cwd, root_str, "session cwd must be exactly the repo root");
        // Nothing was created in the root or under app-support scratch/worktrees.
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
        assert!(!paths.scratch_base().exists());
        assert!(!paths.worktree_base().exists());

        // Exactly this prepared cwd lands in StartParams.
        let params = StartParams::adhoc(
            parsed.session_id.clone(),
            parsed.workspace_id.clone(),
            parsed.kind,
            cwd.clone(),
            &parsed.argv,
            parsed.cols,
            parsed.rows,
            7,
        );
        assert_eq!(params.cwd, cwd);
        // And the workspace record got ONLY repo_write.
        let ws = load_workspace(&paths, "ws1");
        assert!(ws.consent.repo_write);
        assert!(!ws.consent.worktree_create);
    }

    // ---- parser: reconcile ----

    #[test]
    fn parses_reconcile_with_and_without_flags() {
        assert_eq!(
            ReconcileArgs::parse(&toks(&[])).unwrap(),
            ReconcileArgs {
                base: None,
                socket: None
            }
        );
        let parsed = ReconcileArgs::parse(&toks(&["--base", "/b", "--socket", "/s.sock"])).unwrap();
        assert_eq!(parsed.base, Some(PathBuf::from("/b")));
        assert_eq!(parsed.socket, Some(PathBuf::from("/s.sock")));
    }

    #[test]
    fn reconcile_rejects_unknown_flag() {
        assert_eq!(
            ReconcileArgs::parse(&toks(&["--nope", "x"]))
                .unwrap_err()
                .kind,
            "usage"
        );
    }

    // ---- top-level dispatch ----

    #[test]
    fn run_rejects_missing_or_unknown_command() {
        assert_eq!(run(&[]).unwrap_err().kind, "usage");
        assert_eq!(run(&toks(&["frobnicate"])).unwrap_err().kind, "usage");
    }

    // ---- JSON shaping ----

    fn record(status: SessionStatus, gen: Option<&str>) -> SessionRecord {
        SessionRecord {
            session_id: "s1".into(),
            workspace_id: "ws1".into(),
            kind: SessionKind::Shell,
            launch: maestro_shell::LaunchSpec::KnownSafe {
                launch_spec_id: "ls".into(),
                params: vec![],
            },
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 2,
            last_known_generation: gen.map(|g| g.to_string()),
            status,
        }
    }

    #[test]
    fn start_success_json_has_required_fields() {
        let outcome = StartSessionOutcome {
            socket_path: PathBuf::from("/run/d.sock"),
            record: record(SessionStatus::Live, Some("gen-7")),
        };
        let v = start_success_json(&outcome);
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["socket_path"], json!("/run/d.sock"));
        assert_eq!(v["session_id"], json!("s1"));
        assert_eq!(v["status"], json!("live"));
        assert_eq!(v["generation"], json!("gen-7"));
    }

    #[test]
    fn start_success_json_generation_null_when_absent() {
        let outcome = StartSessionOutcome {
            socket_path: PathBuf::from("/s.sock"),
            record: record(SessionStatus::Unknown, None),
        };
        let v = start_success_json(&outcome);
        assert_eq!(v["status"], json!("unknown"));
        assert_eq!(v["generation"], serde_json::Value::Null);
    }

    #[test]
    fn reconcile_success_json_lists_sessions_and_skipped() {
        let outcome = ReconcileOutcome {
            socket_path: PathBuf::from("/s.sock"),
            report: maestro_shell::ReconcileReport {
                sessions: vec![
                    ReconciledSession {
                        session_id: "alive".into(),
                        status: SessionStatus::Live,
                        rewritten: true,
                    },
                    ReconciledSession {
                        session_id: "dead".into(),
                        status: SessionStatus::Exited,
                        rewritten: true,
                    },
                ],
                recovered_sessions: vec![maestro_shell::RecoveredSession {
                    session_id: "orphan".into(),
                }],
                skipped_future_version: vec![PathBuf::from("/x/future.json")],
            },
        };
        let v = reconcile_success_json(&outcome);
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["socket_path"], json!("/s.sock"));
        assert_eq!(v["sessions"].as_array().unwrap().len(), 2);
        assert_eq!(v["sessions"][0]["session_id"], json!("alive"));
        assert_eq!(v["sessions"][0]["status"], json!("live"));
        assert_eq!(v["sessions"][1]["status"], json!("exited"));
        // Recovered (orphan) live ids surface read-only in the reconcile JSON.
        assert_eq!(v["recovered_sessions"], json!([{ "session_id": "orphan" }]));
        assert_eq!(v["skipped_future_version"], json!(["/x/future.json"]));
    }

    #[test]
    fn reconcile_success_json_recovered_sessions_empty_by_default() {
        let outcome = ReconcileOutcome {
            socket_path: PathBuf::from("/s.sock"),
            report: maestro_shell::ReconcileReport::default(),
        };
        let v = reconcile_success_json(&outcome);
        assert_eq!(v["recovered_sessions"], json!([]));
    }

    // ---- parser: agent-start / agent-resume / task-reconcile ----

    fn agent_start_toks() -> Vec<String> {
        toks(&[
            "--agent-task-id",
            "t1",
            "--project-id",
            "p1",
            "--goal",
            "ship it",
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--scratch",
            "--",
            "/bin/sh",
            "-lc",
            "true",
        ])
    }

    #[test]
    fn agent_start_parses_required_fields() {
        let parsed = AgentStartArgs::parse(&agent_start_toks()).unwrap();
        assert_eq!(parsed.agent_task_id, "t1");
        assert_eq!(parsed.project_id, "p1");
        assert_eq!(parsed.goal, "ship it");
        assert_eq!(parsed.session_id, "s1");
        assert_eq!(parsed.workspace_id, "ws1");
        assert_eq!(parsed.cwd, CwdMode::Scratch);
        assert_eq!(parsed.argv, vec!["/bin/sh", "-lc", "true"]);
    }

    #[test]
    fn agent_start_rejects_missing_task_project_or_goal() {
        // Missing --agent-task-id.
        let t = toks(&[
            "--project-id",
            "p1",
            "--goal",
            "g",
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--scratch",
            "--",
            "/bin/sh",
        ]);
        let e = AgentStartArgs::parse(&t).unwrap_err();
        assert_eq!(e.kind, "usage");
        assert!(e.message.contains("--agent-task-id"));
        // Missing --project-id.
        let t = toks(&[
            "--agent-task-id",
            "t1",
            "--goal",
            "g",
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--scratch",
            "--",
            "/bin/sh",
        ]);
        let e = AgentStartArgs::parse(&t).unwrap_err();
        assert_eq!(e.kind, "usage");
        assert!(e.message.contains("--project-id"));
        // Missing --goal.
        let t = toks(&[
            "--agent-task-id",
            "t1",
            "--project-id",
            "p1",
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--scratch",
            "--",
            "/bin/sh",
        ]);
        let e = AgentStartArgs::parse(&t).unwrap_err();
        assert_eq!(e.kind, "usage");
        assert!(e.message.contains("--goal"));
    }

    #[test]
    fn agent_resume_parses_required_fields_and_rejects_missing_task() {
        let t = toks(&[
            "--agent-task-id",
            "t1",
            "--session-id",
            "s2",
            "--workspace-id",
            "ws1",
            "--repo-write",
            "/repos/demo",
            "--allow-repo-write",
            "--",
            "/bin/sh",
        ]);
        let parsed = AgentResumeArgs::parse(&t).unwrap();
        assert_eq!(parsed.agent_task_id, "t1");
        assert_eq!(parsed.session_id, "s2");
        assert_eq!(
            parsed.cwd,
            CwdMode::RepoWrite {
                repo_root: "/repos/demo".into()
            }
        );

        // Missing --agent-task-id is a usage error.
        let t = toks(&[
            "--session-id",
            "s2",
            "--workspace-id",
            "ws1",
            "--scratch",
            "--",
            "/bin/sh",
        ]);
        let e = AgentResumeArgs::parse(&t).unwrap_err();
        assert_eq!(e.kind, "usage");
        assert!(e.message.contains("--agent-task-id"));
    }

    #[test]
    fn agent_commands_share_cwd_mode_rules() {
        // Shared exactly-one-mode rule: passing two modes is a usage error for both commands.
        let dup = |first: &str| {
            toks(&[
                "--agent-task-id",
                "t1",
                "--project-id",
                "p1",
                "--goal",
                "g",
                "--session-id",
                "s1",
                "--workspace-id",
                "ws1",
                "--cwd",
                "/tmp",
                first,
                "--",
                "/bin/sh",
            ])
        };
        let e = AgentStartArgs::parse(&dup("--scratch")).unwrap_err();
        assert_eq!(e.kind, "usage");
        assert!(e.message.contains("mutually exclusive"));

        // Shared allow-flag gating: --repo-write without --allow-repo-write is rejected.
        let t = toks(&[
            "--agent-task-id",
            "t1",
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--repo-write",
            "/repos/demo",
            "--",
            "/bin/sh",
        ]);
        let e = AgentResumeArgs::parse(&t).unwrap_err();
        assert_eq!(e.kind, "usage");
        assert!(e.message.contains("--allow-repo-write"));
    }

    #[test]
    fn agent_commands_require_argv_after_dashdash() {
        // No `--` at all.
        let t = toks(&[
            "--agent-task-id",
            "t1",
            "--project-id",
            "p1",
            "--goal",
            "g",
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--scratch",
        ]);
        assert_eq!(AgentStartArgs::parse(&t).unwrap_err().kind, "usage");
        // `--` with no command.
        let t = toks(&[
            "--agent-task-id",
            "t1",
            "--session-id",
            "s1",
            "--workspace-id",
            "ws1",
            "--scratch",
            "--",
        ]);
        assert_eq!(AgentResumeArgs::parse(&t).unwrap_err().kind, "usage");
    }

    #[test]
    fn task_reconcile_parses_base_and_rejects_socket_and_argv() {
        let parsed = TaskReconcileArgs::parse(&toks(&["--base", "/tmp/base"])).unwrap();
        assert_eq!(parsed.base, Some(PathBuf::from("/tmp/base")));
        // task-reconcile must not require (or accept) a daemon socket.
        assert_eq!(
            TaskReconcileArgs::parse(&toks(&["--socket", "/s.sock"]))
                .unwrap_err()
                .kind,
            "usage"
        );
        // task-reconcile must not accept a command argv.
        assert_eq!(
            TaskReconcileArgs::parse(&toks(&["--", "/bin/sh"]))
                .unwrap_err()
                .kind,
            "usage"
        );
    }

    #[test]
    fn task_reconcile_accepts_no_args() {
        // Local read-only reconcile against the production base — args are all optional.
        assert!(TaskReconcileArgs::parse(&[]).is_ok());
    }

    // ---- JSON shaping: agent-start / agent-resume / task-reconcile ----

    fn agent_task(state: AgentTaskState, history: &[&str]) -> AgentTask {
        AgentTask {
            agent_task_id: "t1".into(),
            project_id: "p1".into(),
            goal: "g".into(),
            state,
            current_session_id: Some("s1".into()),
            session_history: history.iter().map(|s| s.to_string()).collect(),
            created_at_ms: 1,
            updated_at_ms: 2,
            result_summary: None,
        }
    }

    #[test]
    fn agent_start_success_json_has_task_and_session_fields() {
        let outcome = StartAgentTaskOutcome {
            socket_path: PathBuf::from("/run/d.sock"),
            task: agent_task(AgentTaskState::Running, &[]),
            session: record(SessionStatus::Live, Some("gen-1")),
        };
        let v = agent_start_success_json(&outcome);
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["command"], json!("agent-start"));
        assert_eq!(v["socket_path"], json!("/run/d.sock"));
        assert_eq!(v["agent_task_id"], json!("t1"));
        assert_eq!(v["task_state"], json!("running"));
        assert_eq!(v["session_id"], json!("s1"));
        assert_eq!(v["session_status"], json!("live"));
        assert_eq!(v["generation"], json!("gen-1"));
        // agent-start does not carry session_history.
        assert!(v.get("session_history").is_none());
    }

    #[test]
    fn agent_resume_success_json_includes_session_history() {
        let outcome = StartAgentTaskOutcome {
            socket_path: PathBuf::from("/run/d.sock"),
            task: agent_task(AgentTaskState::Running, &["old-a", "old-b"]),
            session: record(SessionStatus::Live, None),
        };
        let v = agent_resume_success_json(&outcome);
        assert_eq!(v["command"], json!("agent-resume"));
        assert_eq!(v["session_history"], json!(["old-a", "old-b"]));
        assert_eq!(v["generation"], serde_json::Value::Null);
    }

    #[test]
    fn task_reconcile_success_json_lists_all_buckets() {
        use maestro_shell::{DanglingSessionTaskRef, QuarantinedRecord, ReconciledAgentTask};
        let report = AgentTaskReconcileReport {
            tasks: vec![ReconciledAgentTask {
                agent_task_id: "t1".into(),
                state: AgentTaskState::WaitingOnUser,
                current_session_id: Some("s1".into()),
                current_session_status: Some(SessionStatus::Live),
                session_record_missing: false,
                needs_attention: true,
            }],
            dangling_session_task_refs: vec![DanglingSessionTaskRef {
                session_id: "s9".into(),
                agent_task_id: "gone".into(),
                session_status: SessionStatus::Exited,
            }],
            skipped_future_tasks: vec![PathBuf::from("/x/ft.json")],
            skipped_future_sessions: vec![PathBuf::from("/x/fs.json")],
            quarantined_tasks: vec![QuarantinedRecord {
                original: PathBuf::from("/x/bad.json"),
                moved_to: PathBuf::from("/x/bad.quarantine"),
                reason: "corrupt".into(),
            }],
            quarantined_sessions: vec![],
        };
        let v = task_reconcile_success_json(&report);
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["command"], json!("task-reconcile"));
        assert_eq!(v["tasks"][0]["agent_task_id"], json!("t1"));
        assert_eq!(v["tasks"][0]["state"], json!("waiting_on_user"));
        assert_eq!(v["tasks"][0]["current_session_id"], json!("s1"));
        assert_eq!(v["tasks"][0]["current_session_status"], json!("live"));
        assert_eq!(v["tasks"][0]["session_record_missing"], json!(false));
        assert_eq!(v["tasks"][0]["needs_attention"], json!(true));
        assert_eq!(
            v["dangling_session_task_refs"][0]["session_id"],
            json!("s9")
        );
        assert_eq!(
            v["dangling_session_task_refs"][0]["session_status"],
            json!("exited")
        );
        assert_eq!(v["skipped_future_tasks"], json!(["/x/ft.json"]));
        assert_eq!(v["skipped_future_sessions"], json!(["/x/fs.json"]));
        assert_eq!(v["quarantined_tasks"][0]["reason"], json!("corrupt"));
        assert_eq!(v["quarantined_sessions"], json!([]));
    }

    #[test]
    fn task_reconcile_json_null_session_when_absent() {
        use maestro_shell::ReconciledAgentTask;
        let report = AgentTaskReconcileReport {
            tasks: vec![ReconciledAgentTask {
                agent_task_id: "t1".into(),
                state: AgentTaskState::Draft,
                current_session_id: None,
                current_session_status: None,
                session_record_missing: false,
                needs_attention: false,
            }],
            ..Default::default()
        };
        let v = task_reconcile_success_json(&report);
        assert_eq!(v["tasks"][0]["state"], json!("draft"));
        assert_eq!(v["tasks"][0]["current_session_id"], serde_json::Value::Null);
        assert_eq!(
            v["tasks"][0]["current_session_status"],
            serde_json::Value::Null
        );
    }

    // ---- error mapping: AgentTaskRuntimeError ----

    #[test]
    fn agent_runtime_task_error_maps_to_task_kind() {
        use maestro_shell::AgentTaskServiceError;
        let e: SmokeError = AgentTaskRuntimeError::Task(AgentTaskServiceError::TaskNotFound {
            agent_task_id: "t1".into(),
        })
        .into();
        assert_eq!(e.kind, "task");
    }

    #[test]
    fn agent_runtime_validation_error_maps_to_agent_runtime_kind() {
        let e: SmokeError = AgentTaskRuntimeError::InvalidSessionKind {
            kind: SessionKind::Shell,
        }
        .into();
        assert_eq!(e.kind, "agent_runtime");
    }

    #[test]
    fn error_json_is_machine_readable() {
        let e = SmokeError::usage("boom");
        let parsed: serde_json::Value = serde_json::from_str(&e.to_json_line()).unwrap();
        assert_eq!(parsed["ok"], json!(false));
        assert_eq!(parsed["error_kind"], json!("usage"));
        assert_eq!(parsed["message"], json!("boom"));
    }

    // ---- window layout: parser ----

    #[test]
    fn window_create_parser_accepts_required_flags() {
        let p = WindowCreateArgs::parse(&toks(&["--window-id", "w1", "--base", "/tmp/b"])).unwrap();
        assert_eq!(p.window_id, "w1");
        assert_eq!(p.base, Some(PathBuf::from("/tmp/b")));
    }

    #[test]
    fn window_create_parser_rejects_missing_window_id() {
        let err = WindowCreateArgs::parse(&toks(&["--base", "/tmp/b"])).unwrap_err();
        assert_eq!(err.kind, "usage");
    }

    #[test]
    fn window_open_tab_parser_accepts_all_flags_and_pinned() {
        let p = WindowOpenTabArgs::parse(&toks(&[
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--session-id",
            "s1",
            "--title",
            "Task 1",
            "--pinned",
        ]))
        .unwrap();
        assert_eq!(p.window_id, "w1");
        assert_eq!(p.tab_id, "t1");
        assert_eq!(p.session_id, "s1");
        assert_eq!(p.title, "Task 1");
        assert!(p.pinned);
    }

    #[test]
    fn window_open_tab_parser_defaults_pinned_false_and_requires_fields() {
        let p = WindowOpenTabArgs::parse(&toks(&[
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--session-id",
            "s1",
            "--title",
            "T",
        ]))
        .unwrap();
        assert!(!p.pinned);
        // Missing --title is a usage error.
        let err = WindowOpenTabArgs::parse(&toks(&[
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--session-id",
            "s1",
        ]))
        .unwrap_err();
        assert_eq!(err.kind, "usage");
    }

    #[test]
    fn window_pin_tab_parser_rejects_invalid_bool() {
        let err = WindowPinTabArgs::parse(&toks(&[
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--pinned",
            "yes",
        ]))
        .unwrap_err();
        assert_eq!(err.kind, "usage");
    }

    #[test]
    fn window_attention_parser_rejects_invalid_attention_and_source() {
        let bad_attn = WindowAttentionArgs::parse(&toks(&[
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--attention",
            "bogus",
            "--unseen",
            "true",
        ]))
        .unwrap_err();
        assert_eq!(bad_attn.kind, "usage");
        let bad_source = WindowAttentionArgs::parse(&toks(&[
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--attention",
            "activity",
            "--unseen",
            "true",
            "--source",
            "robot",
        ]))
        .unwrap_err();
        assert_eq!(bad_source.kind, "usage");
    }

    #[test]
    fn window_attention_parser_defaults_source_process_and_since_none() {
        let p = WindowAttentionArgs::parse(&toks(&[
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--attention",
            "needs_input",
            "--unseen",
            "true",
        ]))
        .unwrap();
        assert_eq!(p.attention, Attention::NeedsInput);
        assert!(p.unseen);
        assert_eq!(p.source, AttentionSource::Process);
        assert_eq!(p.since_ms, None);
    }

    #[test]
    fn window_reorder_parser_splits_order_and_rejects_empty() {
        let p =
            WindowReorderArgs::parse(&toks(&["--window-id", "w1", "--order", "a,b,c"])).unwrap();
        assert_eq!(
            p.order,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
        // Empty value.
        let err =
            WindowReorderArgs::parse(&toks(&["--window-id", "w1", "--order", ""])).unwrap_err();
        assert_eq!(err.kind, "usage");
        // An empty inner segment ("a,,b") names no real tab.
        let err2 =
            WindowReorderArgs::parse(&toks(&["--window-id", "w1", "--order", "a,,b"])).unwrap_err();
        assert_eq!(err2.kind, "usage");
    }

    #[test]
    fn window_unknown_subcommand_is_usage_error() {
        let err = run(&toks(&["window", "frobnicate"])).unwrap_err();
        assert_eq!(err.kind, "usage");
    }

    #[test]
    fn window_missing_subcommand_is_usage_error() {
        let err = run(&toks(&["window"])).unwrap_err();
        assert_eq!(err.kind, "usage");
    }

    // ---- window layout: error mapping & JSON shaping ----

    #[test]
    fn window_layout_error_maps_to_window_layout_kind() {
        let e: SmokeError = WindowLayoutError::WindowLayoutNotFound {
            window_id: "w1".into(),
        }
        .into();
        assert_eq!(e.kind, "window_layout");
    }

    #[test]
    fn layout_success_json_lists_ordered_tabs_with_attention() {
        let layout = WindowLayout {
            window_id: "w1".into(),
            name: None,
            tabs: vec![
                maestro_shell::TabRecord {
                    tab_id: "t0".into(),
                    session_id: "s0".into(),
                    index: 0,
                    title: "First".into(),
                    pinned: true,
                    attention: AttentionState {
                        attention: Attention::Activity,
                        unseen: true,
                        since_ms: 42,
                        source: AttentionSource::Agent,
                    },
                    split_from: None,
                    pane_rect: None,
                    stashed_from: None,
                    stashed: false,
                },
                maestro_shell::TabRecord {
                    tab_id: "t1".into(),
                    session_id: "s1".into(),
                    index: 1,
                    title: "Second".into(),
                    pinned: false,
                    attention: AttentionState::default(),
                    split_from: None,
                    pane_rect: None,
                    stashed_from: None,
                    stashed: false,
                },
            ],
        };
        let v = layout_success_json("window show", &layout);
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["command"], json!("window show"));
        assert_eq!(v["window_id"], json!("w1"));
        assert_eq!(v["tabs"][0]["tab_id"], json!("t0"));
        assert_eq!(v["tabs"][0]["index"], json!(0));
        assert_eq!(v["tabs"][0]["pinned"], json!(true));
        assert_eq!(v["tabs"][0]["attention"]["attention"], json!("activity"));
        assert_eq!(v["tabs"][0]["attention"]["unseen"], json!(true));
        assert_eq!(v["tabs"][0]["attention"]["since_ms"], json!(42));
        assert_eq!(v["tabs"][0]["attention"]["source"], json!("agent"));
        assert_eq!(v["tabs"][1]["attention"]["attention"], json!("none"));
        assert_eq!(v["tabs"][1]["attention"]["source"], json!("process"));
    }

    #[test]
    fn window_view_success_json_includes_joined_task_fields() {
        let views = vec![
            WindowTabView {
                tab_id: "t0".into(),
                session_id: "s0".into(),
                index: 0,
                title: "Linked".into(),
                pinned: false,
                attention: AttentionState::default(),
                session_status: Some(SessionStatus::Live),
                agent_task_id: Some("task-a".into()),
                agent_task_state: Some(AgentTaskState::Running),
                needs_attention: true,
                session_record_missing: false,
                split_from: Some(maestro_shell::SplitFrom {
                    tab_id: "src".into(),
                    axis: SplitAxis::Down,
                    ratio_per_mille: None,
                }),
                pane_rect: None,
                stashed: false,
            },
            WindowTabView {
                tab_id: "t1".into(),
                session_id: "s1".into(),
                index: 1,
                title: "Unlinked".into(),
                pinned: false,
                attention: AttentionState::default(),
                session_status: None,
                agent_task_id: None,
                agent_task_state: None,
                needs_attention: false,
                session_record_missing: false,
                split_from: None,
                pane_rect: None,
                stashed: false,
            },
        ];
        let v = window_view_success_json("w1", &views);
        assert_eq!(v["command"], json!("window view"));
        assert_eq!(v["window_id"], json!("w1"));
        assert_eq!(v["tabs"][0]["agent_task_id"], json!("task-a"));
        assert_eq!(v["tabs"][0]["agent_task_state"], json!("running"));
        assert_eq!(v["tabs"][0]["session_status"], json!("live"));
        assert_eq!(v["tabs"][0]["needs_attention"], json!(true));
        // Split tab carries its source id + axis in the view JSON.
        assert_eq!(v["tabs"][0]["split_from"]["tab_id"], json!("src"));
        assert_eq!(v["tabs"][0]["split_from"]["axis"], json!("down"));
        // Unlinked tab: joined fields are null, not omitted.
        assert_eq!(v["tabs"][1]["agent_task_id"], serde_json::Value::Null);
        assert_eq!(v["tabs"][1]["agent_task_state"], serde_json::Value::Null);
        assert_eq!(v["tabs"][1]["session_status"], serde_json::Value::Null);
        assert_eq!(v["tabs"][1]["needs_attention"], json!(false));
        assert_eq!(v["tabs"][1]["split_from"], serde_json::Value::Null);
    }

    // ---- window layout: local integration over a temp base (no daemon) ----

    #[test]
    fn window_end_to_end_over_temp_base() {
        let tmp = std::env::temp_dir().join(format!("hydra-win-smoke-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let base = tmp.to_string_lossy().into_owned();

        // create
        let created = run(&toks(&[
            "window",
            "create",
            "--base",
            &base,
            "--window-id",
            "w1",
        ]))
        .unwrap();
        let cv: serde_json::Value = serde_json::from_str(&created).unwrap();
        assert_eq!(cv["ok"], json!(true));
        assert_eq!(cv["tabs"].as_array().unwrap().len(), 0);

        // open two tabs
        run(&toks(&[
            "window",
            "open-tab",
            "--base",
            &base,
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--session-id",
            "s1",
            "--title",
            "Task 1",
        ]))
        .unwrap();
        run(&toks(&[
            "window",
            "open-tab",
            "--base",
            &base,
            "--window-id",
            "w1",
            "--tab-id",
            "t2",
            "--session-id",
            "s2",
            "--title",
            "Task 2",
        ]))
        .unwrap();

        // rename t1, pin t2
        run(&toks(&[
            "window",
            "rename-tab",
            "--base",
            &base,
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--title",
            "Renamed",
        ]))
        .unwrap();
        run(&toks(&[
            "window",
            "pin-tab",
            "--base",
            &base,
            "--window-id",
            "w1",
            "--tab-id",
            "t2",
            "--pinned",
            "true",
        ]))
        .unwrap();

        // reorder t2 before t1
        let reordered = run(&toks(&[
            "window",
            "reorder-tabs",
            "--base",
            &base,
            "--window-id",
            "w1",
            "--order",
            "t2,t1",
        ]))
        .unwrap();
        let rv: serde_json::Value = serde_json::from_str(&reordered).unwrap();
        assert_eq!(rv["tabs"][0]["tab_id"], json!("t2"));
        assert_eq!(rv["tabs"][0]["index"], json!(0));
        assert_eq!(rv["tabs"][0]["pinned"], json!(true));
        assert_eq!(rv["tabs"][1]["tab_id"], json!("t1"));
        assert_eq!(rv["tabs"][1]["index"], json!(1));
        assert_eq!(rv["tabs"][1]["title"], json!("Renamed"));

        // update attention on t1
        run(&toks(&[
            "window",
            "attention",
            "--base",
            &base,
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--attention",
            "needs_input",
            "--unseen",
            "true",
            "--source",
            "agent",
            "--since-ms",
            "1000",
        ]))
        .unwrap();

        // show reflects everything
        let shown = run(&toks(&[
            "window",
            "show",
            "--base",
            &base,
            "--window-id",
            "w1",
        ]))
        .unwrap();
        let sv: serde_json::Value = serde_json::from_str(&shown).unwrap();
        assert_eq!(sv["tabs"][0]["tab_id"], json!("t2"));
        assert_eq!(sv["tabs"][1]["tab_id"], json!("t1"));
        assert_eq!(
            sv["tabs"][1]["attention"]["attention"],
            json!("needs_input")
        );
        assert_eq!(sv["tabs"][1]["attention"]["unseen"], json!(true));
        assert_eq!(sv["tabs"][1]["attention"]["since_ms"], json!(1000));
        assert_eq!(sv["tabs"][1]["attention"]["source"], json!("agent"));

        // view works without a daemon and carries needs_attention from persisted attention.
        let viewed = run(&toks(&[
            "window",
            "view",
            "--base",
            &base,
            "--window-id",
            "w1",
        ]))
        .unwrap();
        let vv: serde_json::Value = serde_json::from_str(&viewed).unwrap();
        assert_eq!(vv["command"], json!("window view"));
        assert_eq!(vv["tabs"][0]["tab_id"], json!("t2"));
        // t1 has unseen+needs_input persisted attention with no joined task -> needs_attention.
        assert_eq!(vv["tabs"][1]["tab_id"], json!("t1"));
        assert_eq!(vv["tabs"][1]["needs_attention"], json!(true));
        assert_eq!(vv["tabs"][1]["agent_task_id"], serde_json::Value::Null);

        // show on a missing window is a window_layout error.
        let err = run(&toks(&[
            "window",
            "show",
            "--base",
            &base,
            "--window-id",
            "nope",
        ]))
        .unwrap_err();
        assert_eq!(err.kind, "window_layout");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn window_split_tab_over_temp_base() {
        let tmp = std::env::temp_dir().join(format!("hydra-split-smoke-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let base = tmp.to_string_lossy().into_owned();

        run(&toks(&[
            "window",
            "create",
            "--base",
            &base,
            "--window-id",
            "w1",
        ]))
        .unwrap();
        run(&toks(&[
            "window",
            "open-tab",
            "--base",
            &base,
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--session-id",
            "s1",
            "--title",
            "Source",
        ]))
        .unwrap();

        // successful split appends the new tab with split metadata, preserving order.
        let split = run(&toks(&[
            "window",
            "split-tab",
            "--base",
            &base,
            "--window-id",
            "w1",
            "--from-tab-id",
            "t1",
            "--tab-id",
            "t2",
            "--session-id",
            "s2",
            "--title",
            "Split",
            "--axis",
            "right",
        ]))
        .unwrap();
        let sv: serde_json::Value = serde_json::from_str(&split).unwrap();
        assert_eq!(sv["command"], json!("window split-tab"));
        assert_eq!(sv["tabs"][0]["tab_id"], json!("t1"));
        assert_eq!(sv["tabs"][1]["tab_id"], json!("t2"));
        assert_eq!(sv["tabs"][1]["index"], json!(1));
        assert_eq!(sv["tabs"][1]["split_from"]["tab_id"], json!("t1"));
        assert_eq!(sv["tabs"][1]["split_from"]["axis"], json!("right"));
        // the source tab carries no split metadata.
        assert_eq!(sv["tabs"][0]["split_from"], serde_json::Value::Null);

        // refuses a missing source tab.
        let err = run(&toks(&[
            "window",
            "split-tab",
            "--base",
            &base,
            "--window-id",
            "w1",
            "--from-tab-id",
            "nope",
            "--tab-id",
            "t3",
            "--session-id",
            "s3",
            "--title",
            "X",
            "--axis",
            "down",
        ]))
        .unwrap_err();
        assert_eq!(err.kind, "window_layout");

        // refuses a duplicate new tab id.
        let err = run(&toks(&[
            "window",
            "split-tab",
            "--base",
            &base,
            "--window-id",
            "w1",
            "--from-tab-id",
            "t1",
            "--tab-id",
            "t2",
            "--session-id",
            "s3",
            "--title",
            "X",
            "--axis",
            "down",
        ]))
        .unwrap_err();
        assert_eq!(err.kind, "window_layout");

        // refuses an invalid axis at the parse layer.
        let err = run(&toks(&[
            "window",
            "split-tab",
            "--base",
            &base,
            "--window-id",
            "w1",
            "--from-tab-id",
            "t1",
            "--tab-id",
            "t4",
            "--session-id",
            "s4",
            "--title",
            "X",
            "--axis",
            "sideways",
        ]))
        .unwrap_err();
        assert_eq!(err.kind, "usage");

        let _ = std::fs::remove_dir_all(&tmp);
    }

    // ---- dashboard (local-only, no daemon) ----

    mod dashboard {
        use super::*;
        use maestro_shell::{
            store, LaunchSpec, Project, RecordKind, TabRecord, WindowLayout, WorkspaceConsent,
        };

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

        fn task(
            id: &str,
            project_id: &str,
            state: AgentTaskState,
            current: Option<&str>,
        ) -> AgentTask {
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
        fn write_workspace(paths: &AppPaths, w: &Workspace) {
            store::write_record(paths, RecordKind::Workspace, &w.workspace_id, 1, w).unwrap();
        }
        fn write_task(paths: &AppPaths, t: &AgentTask) {
            store::write_record(paths, RecordKind::AgentTask, &t.agent_task_id, 1, t).unwrap();
        }
        fn write_session(paths: &AppPaths, s: &SessionRecord) {
            store::write_record(paths, RecordKind::Session, &s.session_id, 1, s).unwrap();
        }
        fn write_window(paths: &AppPaths, w: &WindowLayout) {
            store::write_record(paths, RecordKind::WindowLayout, &w.window_id, 1, w).unwrap();
        }

        // -- parser --

        #[test]
        fn parser_accepts_base() {
            let parsed = DashboardArgs::parse(&toks(&["--base", "/b"])).unwrap();
            assert_eq!(parsed.base, Some(PathBuf::from("/b")));
        }

        #[test]
        fn parser_accepts_no_args() {
            let parsed = DashboardArgs::parse(&toks(&[])).unwrap();
            assert_eq!(parsed.base, None);
        }

        #[test]
        fn parser_rejects_socket() {
            let err = DashboardArgs::parse(&toks(&["--socket", "/run/d.sock"])).unwrap_err();
            assert_eq!(err.kind, "usage");
            assert!(err.message.contains("--socket"));
        }

        #[test]
        fn parser_rejects_command_argv_after_dashdash() {
            let err = DashboardArgs::parse(&toks(&["--", "bash"])).unwrap_err();
            assert_eq!(err.kind, "usage");
            assert!(err.message.contains("command argv"));
        }

        #[test]
        fn parser_rejects_unknown_flag() {
            let err = DashboardArgs::parse(&toks(&["--nope", "x"])).unwrap_err();
            assert_eq!(err.kind, "usage");
            assert!(err.message.contains("unknown flag"));
        }

        #[test]
        fn parser_rejects_duplicate_base() {
            let err = DashboardArgs::parse(&toks(&["--base", "/a", "--base", "/b"])).unwrap_err();
            assert_eq!(err.kind, "usage");
            assert!(err.message.contains("--base may only be given once"));
        }

        // -- parser: reconcile flags --

        #[test]
        fn parser_accepts_base_reconcile_and_socket() {
            let parsed = DashboardArgs::parse(&toks(&[
                "--base",
                "/b",
                "--with-session-reconcile",
                "--socket",
                "/run/d.sock",
            ]))
            .unwrap();
            assert_eq!(parsed.base, Some(PathBuf::from("/b")));
            assert!(parsed.with_session_reconcile);
            assert_eq!(parsed.socket, Some(PathBuf::from("/run/d.sock")));
        }

        #[test]
        fn parser_accepts_reconcile_without_socket() {
            // --socket is OPTIONAL with reconcile: endpoint resolution falls back to stored/default.
            let parsed = DashboardArgs::parse(&toks(&["--with-session-reconcile"])).unwrap();
            assert!(parsed.with_session_reconcile);
            assert_eq!(parsed.socket, None);
        }

        #[test]
        fn parser_rejects_socket_without_reconcile() {
            let err = DashboardArgs::parse(&toks(&["--socket", "/run/d.sock"])).unwrap_err();
            assert_eq!(err.kind, "usage");
            assert!(err.message.contains("--with-session-reconcile"));
        }

        #[test]
        fn parser_rejects_duplicate_with_session_reconcile() {
            let err = DashboardArgs::parse(&toks(&[
                "--with-session-reconcile",
                "--with-session-reconcile",
            ]))
            .unwrap_err();
            assert_eq!(err.kind, "usage");
            assert!(err
                .message
                .contains("--with-session-reconcile may only be given once"));
        }

        #[test]
        fn parser_rejects_duplicate_socket() {
            let err = DashboardArgs::parse(&toks(&[
                "--with-session-reconcile",
                "--socket",
                "/a.sock",
                "--socket",
                "/b.sock",
            ]))
            .unwrap_err();
            assert_eq!(err.kind, "usage");
            assert!(err.message.contains("--socket may only be given once"));
        }

        // -- output --

        #[test]
        fn empty_dashboard_includes_all_top_level_buckets() {
            let (_tmp, paths) = temp_paths();
            let snap = run_dashboard(&DashboardArgs {
                base: Some(paths.base().to_path_buf()),
                with_session_reconcile: false,
                socket: None,
            })
            .unwrap();
            let v = dashboard_success_json(&snap);
            assert_eq!(v["ok"], json!(true));
            assert_eq!(v["command"], json!("dashboard"));
            assert_eq!(v["projects"], json!([]));
            assert_eq!(v["unassigned_windows"], json!([]));
            assert_eq!(v["recovered_sessions"], json!([]));
            assert_eq!(v["skipped_future_projects"], json!([]));
            assert_eq!(v["skipped_future_workspaces"], json!([]));
            assert_eq!(v["skipped_future_windows"], json!([]));
            assert_eq!(v["skipped_future_tasks"], json!([]));
            assert_eq!(v["skipped_future_sessions"], json!([]));
            assert_eq!(v["quarantined"], json!([]));
        }

        #[test]
        fn populated_dashboard_exposes_project_workspace_task_window_tab_fields() {
            let (_tmp, paths) = temp_paths();
            write_project(&paths, &project("p1", "One", 100));
            write_workspace(&paths, &workspace("ws1", "p1"));
            // A task whose current session links a window to the project.
            write_task(
                &paths,
                &task("tk1", "p1", AgentTaskState::Running, Some("s1")),
            );
            // Missing session record on purpose: drives session_record_missing + needs_attention.
            write_window(
                &paths,
                &window("w1", vec![tab("t1", "s1", 0, attn(Attention::None, false))]),
            );

            let snap = run_dashboard(&DashboardArgs {
                base: Some(paths.base().to_path_buf()),
                with_session_reconcile: false,
                socket: None,
            })
            .unwrap();
            let v = dashboard_success_json(&snap);

            let p = &v["projects"][0];
            assert_eq!(p["project_id"], json!("p1"));
            assert_eq!(p["name"], json!("One"));
            assert_eq!(p["root"], json!("/repos/p1"));
            assert_eq!(p["last_active_at_ms"], json!(100));
            assert_eq!(p["workspaces"][0]["workspace_id"], json!("ws1"));
            assert_eq!(p["tasks"][0]["agent_task_id"], json!("tk1"));
            assert_eq!(p["tasks"][0]["state"], json!("running"));

            let tab0 = &p["windows"][0]["tabs"][0];
            assert_eq!(tab0["window_id"], json!("w1"));
            assert_eq!(tab0["tab_id"], json!("t1"));
            assert_eq!(tab0["session_id"], json!("s1"));
            assert_eq!(tab0["index"], json!(0));
            assert_eq!(tab0["title"], json!("title-t1"));
            assert_eq!(tab0["pinned"], json!(false));
            assert_eq!(tab0["agent_task_id"], json!("tk1"));
            assert_eq!(tab0["agent_task_state"], json!("running"));
            assert_eq!(tab0["session_record_missing"], json!(true));
            // Running task with a missing session record needs attention.
            assert_eq!(tab0["needs_attention"], json!(true));
        }

        #[test]
        fn tab_carries_attention_status_and_unassigned_window() {
            let (_tmp, paths) = temp_paths();
            write_project(&paths, &project("p1", "One", 100));
            write_workspace(&paths, &workspace("ws1", "p1"));
            // Live session on a workspace-linked window (no task) -> session_status surfaced.
            write_session(&paths, &session("s1", "ws1", SessionStatus::Live));
            write_window(
                &paths,
                &window(
                    "w1",
                    vec![tab("t1", "s1", 0, attn(Attention::NeedsInput, true))],
                ),
            );
            // A second window with no associable tab -> unassigned, not dropped.
            // Distinct tab_id: `tabs.tab_id` is a global PRIMARY KEY in SQLite, so w2's tab
            // cannot reuse "t1" from w1.
            write_window(
                &paths,
                &window(
                    "w2",
                    vec![tab("t2", "ghost", 0, attn(Attention::None, false))],
                ),
            );

            let snap = run_dashboard(&DashboardArgs {
                base: Some(paths.base().to_path_buf()),
                with_session_reconcile: false,
                socket: None,
            })
            .unwrap();
            let v = dashboard_success_json(&snap);

            let tab0 = &v["projects"][0]["windows"][0]["tabs"][0];
            assert_eq!(tab0["session_status"], json!("live"));
            assert_eq!(tab0["session_record_missing"], json!(false));
            assert_eq!(tab0["attention"]["attention"], json!("needs_input"));
            assert_eq!(tab0["attention"]["unseen"], json!(true));
            // Unseen non-None persisted attention -> needs_attention even without a task.
            assert_eq!(tab0["needs_attention"], json!(true));

            assert_eq!(v["unassigned_windows"][0]["window_id"], json!("w2"));
            assert_eq!(v["projects"][0]["windows"].as_array().unwrap().len(), 1);
        }

        // The file-era `future_version_skipped_buckets_serialize` and
        // `quarantined_corrupt_records_serialize` tests hand-wrote raw JSON envelope FILES into the
        // records dir (a schema_version=9999 project and a malformed project) and asserted they
        // flowed through `run_dashboard` into the `skipped_future_projects` / `quarantined` JSON
        // buckets. That mechanism is gone now that records are SQLite rows: future-version is a
        // DB-LEVEL guard (the whole DB is refused on open — see
        // store.rs::future_version_db_is_refused_on_open), and a row that won't deserialize surfaces
        // as `Quarantined` and is excluded from the loaded set (see
        // store.rs::row_that_wont_deserialize_is_quarantined_and_excluded). There is no longer a
        // per-record file to forge in this smoke bin; the snapshot's bucket plumbing still passes
        // through whatever `load_all` reports and is covered at the DB level in store.rs and by
        // dashboard_snapshot.rs's own bucket tests.

        #[test]
        fn run_dispatch_dashboard_returns_ok_json() {
            let (_tmp, paths) = temp_paths();
            let base = paths.base().to_string_lossy().into_owned();
            let out = run(&toks(&["dashboard", "--base", &base])).unwrap();
            let v: serde_json::Value = serde_json::from_str(&out).unwrap();
            assert_eq!(v["ok"], json!(true));
            assert_eq!(v["command"], json!("dashboard"));
            // Default local path is NOT daemon-aware.
            assert_eq!(v["session_reconcile"], json!(false));
        }

        // -- opt-in daemon reconcile (local stub socket, no real pty-daemon) --

        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::net::UnixListener;
        use std::path::PathBuf;

        /// A loopback stub daemon: bind `path`, accept one connection, read the single
        /// `ListSessions` request line, then answer `{"ev":"sessions","ids":[...]}`. Mirrors the
        /// reconcile wire flow used by `ShellRuntime::reconcile_sessions`. The join handle is kept
        /// so the test waits for the thread to finish.
        fn spawn_sessions_stub(path: PathBuf, ids: Vec<String>) -> std::thread::JoinHandle<()> {
            let listener = UnixListener::bind(&path).unwrap();
            std::thread::spawn(move || {
                if let Ok((mut stream, _)) = listener.accept() {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    let _ = reader.read_line(&mut line); // ListSessions
                    let ids_json = serde_json::to_string(&ids).unwrap();
                    let resp = format!("{{\"ev\":\"sessions\",\"ids\":{ids_json}}}\n");
                    stream.write_all(resp.as_bytes()).unwrap();
                    stream.flush().unwrap();
                }
            })
        }

        fn stub_socket() -> (TempDir, PathBuf) {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("stub.sock");
            (dir, path)
        }

        /// Default (no `--with-session-reconcile`) does NOT connect: it succeeds with no daemon and
        /// reports `session_reconcile:false` (no `socket_path` emitted).
        #[test]
        fn opt_out_default_does_not_connect() {
            let (_tmp, paths) = temp_paths();
            let outcome = run_dashboard(&DashboardArgs {
                base: Some(paths.base().to_path_buf()),
                with_session_reconcile: false,
                socket: None,
            })
            .unwrap();
            assert!(!outcome.session_reconcile);
            assert!(outcome.socket_path.is_none());
            let v = dashboard_success_json(&outcome);
            assert_eq!(v["session_reconcile"], json!(false));
            assert_eq!(v.get("socket_path"), None);
        }

        /// Opt-in path connects to the daemon over the explicit socket, sends `ListSessions`, and
        /// reports `session_reconcile:true` plus the `socket_path` the reconcile used.
        #[test]
        fn opt_in_connects_and_reports_socket_path() {
            let (_tmp, paths) = temp_paths();
            // A persisted record the daemon reports live, so reconcile has something to project.
            // FK-safe order: project → workspace → session.
            write_project(&paths, &project("p1", "One", 100));
            write_workspace(&paths, &workspace("ws1", "p1"));
            write_session(&paths, &session("s1", "ws1", SessionStatus::Unknown));
            let (_sock_dir, sock_path) = stub_socket();
            let stub = spawn_sessions_stub(sock_path.clone(), vec!["s1".into()]);

            let outcome = run_dashboard(&DashboardArgs {
                base: Some(paths.base().to_path_buf()),
                with_session_reconcile: true,
                socket: Some(sock_path.clone()),
            })
            .unwrap();
            stub.join().unwrap();

            assert!(outcome.session_reconcile);
            assert_eq!(outcome.socket_path.as_deref(), Some(sock_path.as_path()));
            let v = dashboard_success_json(&outcome);
            assert_eq!(v["session_reconcile"], json!(true));
            assert_eq!(v["socket_path"], json!(sock_path.display().to_string()));
        }

        /// A live daemon id with no persisted session record surfaces in `recovered_sessions`.
        #[test]
        fn opt_in_recovers_live_ids_without_records() {
            let (_tmp, paths) = temp_paths();
            // No "ghost" record on disk; the daemon reports it live.
            // FK-safe order: project → workspace → session.
            write_project(&paths, &project("p1", "One", 100));
            write_workspace(&paths, &workspace("ws1", "p1"));
            write_session(&paths, &session("kept", "ws1", SessionStatus::Unknown));
            let (_sock_dir, sock_path) = stub_socket();
            let stub = spawn_sessions_stub(sock_path.clone(), vec!["kept".into(), "ghost".into()]);

            let outcome = run_dashboard(&DashboardArgs {
                base: Some(paths.base().to_path_buf()),
                with_session_reconcile: true,
                socket: Some(sock_path.clone()),
            })
            .unwrap();
            stub.join().unwrap();

            let v = dashboard_success_json(&outcome);
            let recovered: Vec<&str> = v["recovered_sessions"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r["session_id"].as_str().unwrap())
                .collect();
            assert!(recovered.contains(&"ghost"));
        }

        /// Reconciled `Live`/`Exited` statuses are projected into the in-memory dashboard tab rows:
        /// a record the daemon reports live → `live`; one it omits → `exited`.
        #[test]
        fn opt_in_projects_live_and_exited_into_tab_rows() {
            let (_tmp, paths) = temp_paths();
            write_project(&paths, &project("p1", "One", 100));
            write_workspace(&paths, &workspace("ws1", "p1"));
            // Two sessions on the same project; daemon reports only s_live alive.
            write_session(&paths, &session("s_live", "ws1", SessionStatus::Unknown));
            write_session(&paths, &session("s_dead", "ws1", SessionStatus::Unknown));
            write_window(
                &paths,
                &window(
                    "w1",
                    vec![
                        tab("t_live", "s_live", 0, attn(Attention::None, false)),
                        tab("t_dead", "s_dead", 1, attn(Attention::None, false)),
                    ],
                ),
            );
            let (_sock_dir, sock_path) = stub_socket();
            let stub = spawn_sessions_stub(sock_path.clone(), vec!["s_live".into()]);

            let outcome = run_dashboard(&DashboardArgs {
                base: Some(paths.base().to_path_buf()),
                with_session_reconcile: true,
                socket: Some(sock_path.clone()),
            })
            .unwrap();
            stub.join().unwrap();

            let v = dashboard_success_json(&outcome);
            let tabs = &v["projects"][0]["windows"][0]["tabs"];
            let status_of = |session_id: &str| -> String {
                tabs.as_array()
                    .unwrap()
                    .iter()
                    .find(|t| t["session_id"] == json!(session_id))
                    .unwrap()["session_status"]
                    .as_str()
                    .unwrap()
                    .to_string()
            };
            assert_eq!(status_of("s_live"), "live");
            assert_eq!(status_of("s_dead"), "exited");
        }

        /// Daemon unavailable in the opt-in path → structured error JSON (error_kind set) and a
        /// non-`Ok` result that `run()` maps to a non-zero exit.
        #[test]
        fn opt_in_daemon_unavailable_is_structured_error() {
            let (_tmp, paths) = temp_paths();
            let base = paths.base().to_string_lossy().into_owned();
            let missing = paths.base().join("nonexistent.sock");
            let err = run(&toks(&[
                "dashboard",
                "--base",
                &base,
                "--with-session-reconcile",
                "--socket",
                &missing.to_string_lossy(),
            ]))
            .unwrap_err();
            let v = err.to_json_line();
            let parsed: serde_json::Value = serde_json::from_str(&v).unwrap();
            assert_eq!(parsed["ok"], json!(false));
            assert!(parsed["error_kind"].is_string());
            assert!(!parsed["error_kind"].as_str().unwrap().is_empty());
        }
    }
}
