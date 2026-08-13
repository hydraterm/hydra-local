//! `maestro-app` CLI surface: the top-level [`Command`] enum, its parsed argument DTOs, the
//! [`usage`] help text, the root [`parse_args`] dispatcher, and the self-contained
//! launch / attach-tab / window / worktree argument parsers.
//!
//! This module is a mechanical extraction from `lib.rs`: every public item here is re-exported from
//! the crate root so existing `maestro_app::<Item>` paths (main.rs, binary_smoke.rs, and the
//! in-crate test module) keep working unchanged. The agent/dashboard argument parsers also live
//! here now; their parsed-argument DTOs continue to live in their feature modules (`agent.rs`,
//! `dashboard.rs`) and are constructed through the crate-root re-exports.

use std::path::PathBuf;

use crate::{
    validate_window_title, AttachTabChromeFlags, NewTabCwdBasis, NewTabLaunchPolicy,
    NewTabLaunchSource, DEFAULT_SESSION_ID,
};
use crate::{
    AgentFinishArgs, AgentFinishIntent, AgentMarkArgs, AgentMarkIntent, AgentResumeArgs,
    AgentStartArgs, DashboardArgs, AGENT_FINISH_SUMMARY_MAX_LEN, AGENT_MARK_REASON_MAX_LEN,
};

/// Which top-level subcommand was requested.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    /// Print usage and exit 0.
    Help,
    /// Run the one-session dev harness. Boxed so this large-payload variant does not bloat every
    /// `Command` value (the `Help` variant carries no data).
    Launch(Box<LaunchArgs>),
    /// Print a read-only local records snapshot (the dashboard model) as one structured JSON value.
    /// Connects to nothing, spawns nothing, and mutates no records.
    Dashboard(DashboardArgs),
    /// Create a NEW agent task and start its first session through
    /// [`maestro_shell::agent_task_runtime::AgentTaskRuntime::start_new_agent_task`]. Boxed for the
    /// same large-payload reason as [`Command::Launch`].
    AgentStart(Box<AgentStartArgs>),
    /// Resume an EXISTING agent task on a brand-new session through
    /// [`maestro_shell::agent_task_runtime::AgentTaskRuntime::resume_agent_task`]. Boxed for the
    /// same large-payload reason as [`Command::Launch`].
    AgentResume(Box<AgentResumeArgs>),
    /// Headless window/tab layout commands over `maestro-shell::WindowLayoutService`. Local-only:
    /// connects to no daemon, spawns nothing, touches no sockets. See [`WindowCommand`].
    Window(WindowCommand),
    /// Open an EXISTING persisted window tab in the native renderer by loading the tab's `session_id`
    /// from its `WindowLayout`. Unlike `window`, this connects to the daemon and can open a renderer,
    /// so it is a separate top-level command. Boxed for the same large-payload reason as
    /// [`Command::Launch`].
    AttachTab(Box<AttachTabArgs>),
    /// Mark an EXISTING running agent task as `WaitingOnUser` or `Blocked` via an explicit,
    /// task-scoped, trusted-local assertion. Local-only: connects to no daemon, spawns nothing,
    /// touches no sockets/renderer. This is the first reliable detection seam — NOT automatic
    /// terminal-text classification. See [`AgentMarkArgs`] and `maestro_shell::classify_task_signal`.
    AgentMark(AgentMarkArgs),
    /// Finish an EXISTING agent task into a terminal state (`Succeeded` / `Failed` / `Cancelled`)
    /// via an explicit, task-scoped, trusted-local assertion, with an optional bounded summary.
    /// Local-only: connects to no daemon, spawns nothing, touches no sockets/renderer. Terminal
    /// state is asserted by the caller, never inferred from process exit or session status. See
    /// [`AgentFinishArgs`].
    AgentFinish(AgentFinishArgs),
    /// Reclaim ONE Maestro-owned worktree checkout for an explicitly supplied `workspace_id` +
    /// `session_id`. Dry-run by default (plan + report, delete nothing); with `--confirm` it
    /// re-plans against freshly-reloaded records and delegates the single deletion to
    /// [`maestro_shell::remove_worktree_with_consent`]. Local-only: connects to no daemon, spawns
    /// nothing, touches no sockets/renderer, deletes no branches, and never targets a path outside
    /// `worktree_base()`. See [`WorktreeCleanupArgs`] and [`crate::plan_worktree_cleanup`].
    WorktreeCleanup(WorktreeCleanupArgs),
    /// List candidate Maestro worktree checkouts for ONE explicitly supplied `workspace_id`,
    /// classify each, and print a single read-only JSON inventory. Strictly read-only: deletes
    /// nothing, writes no records, talks to no daemon/renderer, and runs no mutating git
    /// subcommand — at most read-only `git worktree list --porcelain`/`rev-parse` inspection.
    /// See [`WorktreeListArgs`] and [`crate::build_worktree_list`].
    WorktreeList(WorktreeListArgs),
    /// Read-only settings namespace. Currently only `settings show`, which prints the app's
    /// effective built-in defaults as one structured JSON value. Connects to no daemon, spawns
    /// nothing, opens no renderer, reads/writes no records, and creates no settings file. See
    /// [`SettingsCommand`] and [`crate::effective_settings`].
    Settings(SettingsCommand),
    /// Print the read-only command-palette action catalog (`command-palette --list`) that a future
    /// interactive palette UI can consume. Strictly read-only and side-effect-free: connects to no
    /// daemon, opens no socket/renderer/terminal, mutates no records, writes no settings, and touches
    /// no filesystem. See [`CommandPaletteArgs`] and [`crate::build_command_palette`].
    CommandPalette(CommandPaletteArgs),
    /// Manage named workspace layout presets. Daemon-free: `save` reads a
    /// persisted `WindowLayout` and writes a `LayoutPreset`; `list`/`delete` operate on the preset
    /// store; `restore-plan` prints the non-executing restore plan (which slots reattach vs. launch
    /// fresh) as JSON. See [`LayoutPresetCommand`] and `maestro_shell::LayoutPresetService`.
    LayoutPreset(LayoutPresetCommand),
    /// Project management over `maestro_shell::ProjectService`. Create/update/reorder are local
    /// record writes and list is read-only; delete additionally contacts the retained PTY daemon so
    /// it can release the complete prepared session set before cascading records. Backs the
    /// dashboard/sidebar project surface. See [`ProjectCommand`].
    Project(ProjectCommand),
}

/// One of the `project` subcommands. `list` is read-only; the rest mutate the project record store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProjectCommand {
    /// `project create --project-id <id> --name <text> --root <dir> [--policy <p>] [--icon <g>]
    /// [--accent <#rrggbb>] [--base <dir>]`: create a new project record.
    Create(ProjectCreateArgs),
    /// `project list [--base <dir>]`: list projects, recency-desc then id.
    List(ProjectListArgs),
    /// `project update --project-id <id> [--name <text>] [--root <dir>] [--policy <p>]
    /// [--icon <g>|--clear-icon] [--accent <#rrggbb>|--clear-accent] [--clear-launch-defaults]
    /// [--base <dir>]`: patch a project. Unsupplied fields are unchanged.
    Update(ProjectUpdateArgs),
    /// `project delete --project-id <id> [--base <dir>]`: release every unshared owned PTY, then
    /// delete the project graph (idempotent when the project is absent).
    Delete(ProjectRefArgs),
    /// `project reorder --order <id,id,...> [--base <dir>]`: realize an explicit project order.
    Reorder(ProjectReorderArgs),
}

/// Parsed `project create` args. `project_id`/`name`/`root` are required; the rest optional. Ids
/// are safe-id-validated; `policy` is one of `scratch`/`worktree`/`repo-write`; `accent` must be
/// `#rrggbb`; `icon` is 1..=8 chars. Stored optionally for incremental assembly.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectCreateArgs {
    pub project_id: Option<String>,
    pub name: Option<String>,
    pub root: Option<String>,
    pub policy: Option<String>,
    pub icon: Option<String>,
    pub accent_color: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed `project list` args. Read-only; only `--base` selects the records base.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectListArgs {
    pub base: Option<PathBuf>,
}

/// Parsed `project update` args. `project_id` is required; every other field is optional. The
/// `clear_icon`/`clear_accent` flags request CLEARING the optional field (mutually exclusive with
/// supplying the corresponding value).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectUpdateArgs {
    pub project_id: Option<String>,
    pub name: Option<String>,
    pub root: Option<String>,
    pub policy: Option<String>,
    pub icon: Option<String>,
    pub clear_icon: bool,
    pub accent_color: Option<String>,
    pub clear_accent: bool,
    /// `--clear-launch-defaults`: drop the project's saved launch defaults (agent/model/folders), so new
    /// windows fall back to the global default. Leaves pinned `directories` untouched.
    pub clear_launch_defaults: bool,
    pub base: Option<PathBuf>,
}

/// Parsed args for project subcommands naming a single project by id (`delete`). `project_id` is
/// required + safe-id-validated; `base` selects the records base.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectRefArgs {
    pub project_id: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed `project reorder` args. `order` is a required comma-separated list of safe-validated
/// project ids (an exact permutation of existing projects); `base` selects the records base.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProjectReorderArgs {
    pub order: Option<Vec<String>>,
    pub base: Option<PathBuf>,
}

/// One of the `layout-preset` subcommands. `save` is the only one that writes a preset record;
/// `delete` removes one; `list`/`restore-plan` are strictly read-only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LayoutPresetCommand {
    /// `layout-preset save --window-id <id> --name <text> --preset-id <id> [--project-id <id>]
    /// [--base <dir>]`: capture a window's current tab topology into a named preset.
    Save(LayoutPresetSaveArgs),
    /// `layout-preset list [--project-id <id>] [--base <dir>]`: list saved presets (newest-first),
    /// optionally scoped to a project.
    List(LayoutPresetListArgs),
    /// `layout-preset delete --preset-id <id> [--base <dir>]`: delete a saved preset.
    Delete(LayoutPresetRefArgs),
    /// `layout-preset restore-plan --preset-id <id> [--base <dir>]`: print the non-executing restore
    /// plan for a preset (each slot marked reattach-live vs. launch-fresh) as JSON.
    RestorePlan(LayoutPresetRefArgs),
    /// `layout-preset restore --preset-id <id> --window-id <id> [--base <dir>]`: EXECUTE a restore —
    /// walk the plan and, per slot, reattach the still-live hinted session or launch a fresh one,
    /// appending the rebuilt tabs/splits into `window-id`'s layout. Prints the per-slot outcomes.
    Restore(LayoutPresetRestoreArgs),
}

/// Parsed `layout-preset save` arguments. `window_id`/`name`/`preset_id` are required; `project_id`
/// is optional (an unassigned/global preset when absent). All id fields are safe-id-validated;
/// `name` is validated as a window title (non-empty, no control chars). `base` selects the records
/// base. Stored optionally so a partial parse can be assembled incrementally.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LayoutPresetSaveArgs {
    pub window_id: Option<String>,
    pub name: Option<String>,
    pub preset_id: Option<String>,
    pub project_id: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed `layout-preset list` arguments. `project_id` optionally scopes the listing; `base`
/// selects the records base. Read-only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LayoutPresetListArgs {
    pub project_id: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed arguments for the preset commands that name a single preset by id (`delete`,
/// `restore-plan`). `preset_id` is required + safe-id-validated; `base` selects the records base.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LayoutPresetRefArgs {
    pub preset_id: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed `layout-preset restore` arguments. `preset_id` (the preset to restore) and `window_id`
/// (the target window the rebuilt tabs are appended into) are both required + safe-id-validated;
/// `base` selects the records base. `socket`/`daemon`/`log_dir` mirror `launch`: a LaunchFresh slot
/// starts a real session, so the executor must reach (and may spawn) a daemon. The executing
/// counterpart to `restore-plan`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LayoutPresetRestoreArgs {
    pub preset_id: Option<String>,
    pub window_id: Option<String>,
    pub base: Option<PathBuf>,
    pub socket: Option<PathBuf>,
    pub daemon_bin: Option<PathBuf>,
    pub log_dir: Option<PathBuf>,
}

/// One of the `settings` subcommands. `show` is read-only; `set` persists the single supported
/// `appearance.font_size_px` override to a local versioned JSON file (no daemon/renderer/records).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsCommand {
    /// `settings show [--base <dir>]`: print the effective settings (defaults + any persisted
    /// font-size override) as JSON.
    Show(SettingsShowArgs),
    /// `settings set appearance.<key> <value> [--base <dir>]`: persist a font-size or theme override.
    Set(SettingsSetArgs),
    /// `settings reset appearance.<key> [--base <dir>]`: clear a font-size or theme override back to
    /// its built-in default (local-only settings-file mutation).
    Reset(SettingsResetArgs),
}

/// Parsed `settings show` arguments. `base` selects the app-support base used to resolve the
/// settings file and echo `base_dir` in the JSON (default dev-safe path when absent). Stored
/// optionally so a partial parse can be assembled incrementally. `panel_lines` is the show-only
/// `--panel-lines` flag: when set, `settings show` prints the compact `SettingsPanelLines` panel
/// projection instead of the full `EffectiveSettings` JSON (the default output is byte-unchanged).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SettingsShowArgs {
    pub base: Option<PathBuf>,
    pub panel_lines: bool,
}

/// Parsed `command-palette` arguments for its two read-only modes: list
/// (`--list [--base <dir>] [--query <text>] [--preview]`) and describe
/// (`--describe <action-id> [--base <dir>]`). EXACTLY ONE of `--list` / `--describe` is required and
/// the two modes are mutually exclusive. `--query`/`--preview` belong to list mode only and are
/// rejected alongside `--describe`. `base` optionally selects the base directory echoed into the JSON
/// for display context (default dev-safe path when absent). All flags are at-most-once; `--base`,
/// `--query`, and `--describe` require a value, and a `--query`/`--describe` that is empty/whitespace-
/// only after trimming is rejected. The flags may appear in any order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandPaletteArgs {
    pub list: bool,
    pub base: Option<PathBuf>,
    pub query: Option<String>,
    pub preview: bool,
    pub describe: Option<String>,
}

/// The validated target of a `settings set` command: an `appearance.font_size_px` override (a
/// validated 10..=32 value), an `appearance.theme` override (a validated supported theme id), or one
/// of the three configurable `chrome.*_default` overrides (a parsed `true`/`false` bool).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsSetTarget {
    FontSizePx(u32),
    Theme(String),
    TopTabBarDefault(bool),
    DashboardStatusDefault(bool),
    DashboardPanelDefault(bool),
    PickerOverlayDefault(bool),
    ShellDefaultArgv(Vec<String>),
    WorkspaceDefaultPolicy(String),
    WorkspaceWorktreeRequiresConsent(bool),
    WorkspaceRepoWriteRequiresConsent(bool),
}

/// Parsed `settings set <key> <value>` arguments. `target` is the validated key+value to persist;
/// `base` selects the app-support base (default dev-safe path when absent). Settable keys are
/// `appearance.font_size_px`, `appearance.theme`, `chrome.top_tab_bar_default`,
/// `chrome.dashboard_status_default`, `chrome.dashboard_panel_default`, and `shell.default_argv`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsSetArgs {
    pub target: SettingsSetTarget,
    pub base: Option<PathBuf>,
}

/// What a `settings reset` clears: a single keyed override, or every persisted setting via `--all`.
/// `--all` and a key are mutually exclusive (enforced by the parser).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SettingsResetSelection {
    Key(crate::SettingsResetTarget),
    All,
}

/// Parsed `settings reset (<key> | --all) [--base <dir>]` arguments. `selection` is either one keyed
/// override to clear back to its built-in default, or `All` to remove every persisted setting; `base`
/// selects the app-support base (default dev-safe path when absent). Resettable keys are
/// `appearance.font_size_px`, `appearance.theme`, `chrome.top_tab_bar_default`,
/// `chrome.dashboard_status_default`, `chrome.dashboard_panel_default`,
/// `chrome.picker_overlay_default`, and `shell.default_argv`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsResetArgs {
    pub selection: SettingsResetSelection,
    pub base: Option<PathBuf>,
}

/// Parsed `worktree-cleanup` arguments. `workspace_id`/`session_id` are required and validated as
/// safe ids by the parser; `base` selects the app-support records base (default dev-safe path);
/// `confirm` gates actual deletion (absent = dry-run only). Fields are `Option`/`bool` so partial
/// parses can be assembled incrementally; a fully-parsed value always has both ids set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorktreeCleanupArgs {
    pub workspace_id: Option<String>,
    pub session_id: Option<String>,
    pub base: Option<PathBuf>,
    pub confirm: bool,
}

/// Parsed `worktree-list` arguments. Exactly one scope selector is required: `--workspace-id <id>`
/// (single-workspace mode, validated as a safe id) XOR `--all` (record-backed all-workspaces mode).
/// `base` selects the app-support records base (default dev-safe path). Both scope fields are stored
/// optionally so a partial parse can be assembled incrementally; a fully-parsed value always has
/// exactly one of `workspace_id`/`all` set. This command is strictly read-only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WorktreeListArgs {
    pub workspace_id: Option<String>,
    pub all: bool,
    /// `--include-orphans`: extend `--all` with a read-only directory inventory under
    /// `worktree_base`. Valid ONLY with `--all`; rejected without `--all` or with `--workspace-id`.
    pub include_orphans: bool,
    pub base: Option<PathBuf>,
}

/// One of the four headless `window` subcommands. Each is daemon-free and operates only on the
/// persisted `WindowLayout` store under `--base`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WindowCommand {
    /// `window create --window-id <id> [--base <dir>]`: create a new empty window layout.
    Create(WindowCreateArgs),
    /// `window show --window-id <id> [--base <dir>]`: read a persisted window layout.
    Show(WindowShowArgs),
    /// `window open-tab --window-id <id> --tab-id <id> --session-id <id> --title <text> [--base <dir>]`:
    /// append a tab to a window layout.
    OpenTab(WindowOpenTabArgs),
    /// `window split-tab --window-id <id> --from-tab-id <id> --tab-id <id> --session-id <id>
    /// --title <text> --axis <right|down> [--base <dir>]`: append a tab that records it was split
    /// from an existing tab along an axis (storage-only; no renderer pane geometry yet).
    SplitTab(WindowSplitTabArgs),
    /// `window view --window-id <id> [--base <dir>]`: read-only projected view joining each tab with
    /// the agent-task reconcile report (session status, task state, attention).
    View(WindowViewArgs),
    /// `window close-tab --window-id <id> --tab-id <id> [--base <dir>]`: remove a tab and compact
    /// the remaining indices.
    CloseTab(WindowTabRefArgs),
    /// `window rename-tab --window-id <id> --tab-id <id> --title <text> [--base <dir>]`: change a
    /// single tab's title, preserving order.
    RenameTab(WindowRenameTabArgs),
    /// `window pin-tab --window-id <id> --tab-id <id> --pinned <true|false> [--base <dir>]`: set a
    /// single tab's pinned flag, preserving order.
    PinTab(WindowPinTabArgs),
    /// `window reorder-tabs --window-id <id> --order <tab1,tab2,...> [--base <dir>]`: reorder the
    /// tabs to an exact permutation of the existing ids.
    ReorderTabs(WindowReorderTabsArgs),
    /// `window attention --window-id <id> --tab-id <id> --attention <state> --unseen <true|false>
    /// [--source <source>] [--since-ms <u64>] [--base <dir>]`: update a single tab's persisted
    /// attention object, preserving order.
    Attention(Box<WindowAttentionArgs>),
    /// `window attention-clear --window-id <id> --tab-id <id> [--base <dir>]`: clear a single tab's
    /// persisted attention to seen/none with `source: user`, preserving order.
    AttentionClear(WindowTabRefArgs),
}

/// Parsed `window create` arguments. `window_id` is `Option` here (a pure record of what the user
/// typed); `main` enforces presence — but the parser already rejects a missing `--window-id` value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowCreateArgs {
    pub window_id: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed `window show` arguments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowShowArgs {
    pub window_id: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed `window open-tab` arguments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowOpenTabArgs {
    pub window_id: Option<String>,
    pub tab_id: Option<String>,
    pub session_id: Option<String>,
    pub title: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed `window split-tab` arguments: mirrors `window open-tab` plus `--from-tab-id` (the existing
/// source tab) and `--axis` (`right|down`). `main` enforces presence; `--axis` is validated to one of
/// the two accepted values at parse time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowSplitTabArgs {
    pub window_id: Option<String>,
    pub from_tab_id: Option<String>,
    pub tab_id: Option<String>,
    pub session_id: Option<String>,
    pub title: Option<String>,
    pub axis: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed `window view` arguments.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowViewArgs {
    pub window_id: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed args for tab-ref-only mutations (`close-tab`): `--window-id` + `--tab-id` (both required)
/// plus optional `--base`. `main` enforces presence; the parser already rejects missing values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowTabRefArgs {
    pub window_id: Option<String>,
    pub tab_id: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed `window rename-tab` arguments: `--window-id`, `--tab-id`, `--title` (all required) plus
/// optional `--base`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowRenameTabArgs {
    pub window_id: Option<String>,
    pub tab_id: Option<String>,
    pub title: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed `window pin-tab` arguments: `--window-id`, `--tab-id`, `--pinned <true|false>` (all
/// required) plus optional `--base`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowPinTabArgs {
    pub window_id: Option<String>,
    pub tab_id: Option<String>,
    pub pinned: Option<bool>,
    pub base: Option<PathBuf>,
}

/// Parsed `window reorder-tabs` arguments: `--window-id`, `--order <tab1,tab2,...>` (both required)
/// plus optional `--base`. `order` is the already-split, validated non-empty tab id list.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowReorderTabsArgs {
    pub window_id: Option<String>,
    pub order: Option<Vec<String>>,
    pub base: Option<PathBuf>,
}

/// Parsed `window attention` arguments. `attention` and `source` are pre-validated wire strings
/// (snake_case enum reprs); `main` maps them to `maestro-shell`'s `Attention`/`AttentionSource` so
/// `lib.rs` keeps no `maestro-shell` dependency. `since_ms` defaults to `now_ms()` in `main` when
/// absent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowAttentionArgs {
    pub window_id: Option<String>,
    pub tab_id: Option<String>,
    pub attention: Option<String>,
    pub unseen: Option<bool>,
    pub source: Option<String>,
    pub since_ms: Option<u64>,
    pub base: Option<PathBuf>,
}

/// Parsed `attach-tab` arguments. `--window-id`/`--tab-id` are required (enforced by the parser).
/// The socket/daemon/renderer/log/lifecycle flags mirror `launch`. This command never accepts a
/// post-`--` argv — it opens an EXISTING session's tab, never starts a new shell/agent session.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AttachTabArgs {
    /// `--window-id <id>`: the persisted window layout to load the tab from (required).
    pub window_id: Option<String>,
    /// `--tab-id <id>`: the tab whose `session_id` the renderer attaches to (required).
    pub tab_id: Option<String>,
    /// `--base <dir>`: app-support/storage base for records. When `None`, the dev-safe default base
    /// is used (same policy as `launch`).
    pub base: Option<PathBuf>,
    /// `--socket <path>`: explicit daemon socket path. When `None`, a private dev socket is used.
    pub socket: Option<PathBuf>,
    /// `--daemon <path>`: explicit `pty-daemon` binary path.
    pub daemon_bin: Option<PathBuf>,
    /// `--renderer <path>`: explicit `maestro-renderer` binary path (only required/used in detached
    /// renderer mode).
    pub renderer_bin: Option<PathBuf>,
    /// `--log-dir <dir>`: opt-in child-process log directory (same behavior as `launch`).
    pub log_dir: Option<PathBuf>,
    /// `--no-run-renderer`: resolve/load/reconcile/report without opening a GUI.
    pub no_run_renderer: bool,
    /// `--detach-renderer`: spawn a `maestro-renderer <socket> <session-id>` child (same policy as
    /// `launch`). Invalid together with `--no-run-renderer`.
    pub detach_renderer: bool,
    /// `--keep-daemon`: when this process spawned the daemon, leave it running after the app finishes
    /// (same lifecycle policy as `launch`).
    pub keep_daemon: bool,
    /// `--title <text>`: an explicit foreground window title override. Validated by
    /// [`validate_window_title`]; rejected with `--detach-renderer` (same as `launch`).
    pub title: Option<String>,
    /// `--top-tab-bar`: opt in to drawing the app-owned tabs as a minimal native chrome row at the
    /// top of the foreground window (instead of only the bottom overlay text). Accepted only for the
    /// foreground in-process renderer: rejected with `--detach-renderer` (the detached renderer CLI
    /// never receives the app-owned tab strip). Compatible with `--no-run-renderer` so the parse and
    /// resulting JSON (`top_tab_bar`) can be inspected without a GUI. Default `false`.
    ///
    /// On the foreground in-process renderer (and the `--no-run-renderer` inspection path) the top
    /// tab bar now defaults ON when NEITHER `--top-tab-bar` nor `--no-top-tab-bar` is given; this
    /// raw field records only the explicit `--top-tab-bar` ENABLE. The effective value is computed by
    /// [`crate::resolve_attach_tab_chrome`] from [`AttachTabArgs::chrome_flags`].
    pub top_tab_bar: bool,
    /// `--no-top-tab-bar`: explicitly turn the top tab bar OFF, overriding the foreground default-on
    /// policy. Mutually exclusive with `--top-tab-bar`. Companion negation to `--top-tab-bar`; the
    /// two together form the tri-state (absent / enable / disable) consumed by
    /// [`AttachTabArgs::chrome_flags`]. Default `false`.
    pub no_top_tab_bar: bool,
    /// `--new-tab-default-shell`: opt in to an explicit dev/test new-tab launch policy that lets a
    /// future `RendererEvent::NewTabRequested` handler spawn a default shell tab. This is the ONLY
    /// way a `+` press may currently create a tab; without it `NewTabRequested` declines/logs. It is
    /// NOT a command palette or workspace picker. Requires `--top-tab-bar` (the only visible `+`
    /// surface today). The resolved policy is exposed via [`AttachTabArgs::new_tab_launch_policy`];
    /// no raw argv/env/token/socket is stored. Default `false`.
    pub new_tab_default_shell: bool,
    /// `--new-tab-title <title>`: presentation-only title for the explicit default-shell new-tab
    /// policy (defaults to `"shell"`). Only valid with `--new-tab-default-shell`; validated by
    /// [`validate_window_title`].
    pub new_tab_title: Option<String>,
    /// `--new-tab-workspace-id <id>`: explicit dev/test override for the new-tab workspace IDENTITY
    /// stamped into [`NewTabLaunchPolicy::workspace_id`]. Only valid with `--new-tab-default-shell`;
    /// when absent the policy keeps the default [`DEFAULT_SESSION_ID`] (`"maestro-app-dev"`). Custom
    /// values are validated through [`maestro_shell::validate_id`] (single safe path component), so a
    /// value that could escape app-support paths is rejected at parse time. NOT a workspace picker or
    /// final UX surface.
    pub new_tab_workspace_id: Option<String>,
    /// `--dashboard-status`: opt in to a compact read-only dashboard summary appended to the
    /// app-owned `status_label` (active/waiting/blocked/failed/attention counts derived from
    /// [`crate::build_dashboard_view_model`]). The same composed label is reported in the structured
    /// `attach-tab` success JSON, so it is inspectable with `--no-run-renderer` without opening a
    /// GUI. Rejected with `--detach-renderer` (the detached renderer CLI never receives the
    /// app-owned status label). Default `false`.
    ///
    /// On the foreground in-process renderer (and the `--no-run-renderer` inspection path) the
    /// dashboard status suffix now defaults ON when NEITHER `--dashboard-status` nor
    /// `--no-dashboard-status` is given; this raw field records only the explicit `--dashboard-status`
    /// ENABLE. The effective value is computed by [`crate::resolve_attach_tab_chrome`] from
    /// [`AttachTabArgs::chrome_flags`].
    pub dashboard_status: bool,
    /// `--no-dashboard-status`: explicitly turn the dashboard status suffix OFF, overriding the
    /// foreground default-on policy. Mutually exclusive with `--dashboard-status`. Companion negation
    /// that, with `--dashboard-status`, forms the tri-state (absent / enable / disable) consumed by
    /// [`AttachTabArgs::chrome_flags`]. Default `false`.
    pub no_dashboard_status: bool,
    /// `--dashboard-panel`: opt in to drawing a static, read-only dashboard panel as app-owned top
    /// chrome ABOVE the single-session renderer grid (built from [`crate::DashboardPanelLines`] via the same
    /// snapshot/view-model the `--dashboard-status` suffix uses). Launch-time only: no live refresh,
    /// no click handling, no second window/surface, no daemon/protocol/schema change. Accepted only
    /// for the foreground in-process renderer: rejected with `--detach-renderer` (the detached
    /// renderer CLI cannot carry app-owned chrome data). Compatible with `--no-run-renderer` (the
    /// computed panel is reported in the success JSON without opening a GUI) and with
    /// `--dashboard-status` (panel is top chrome; the status summary stays bottom label text).
    ///
    /// On the foreground in-process renderer (and the `--no-run-renderer` inspection path) the
    /// dashboard panel now follows the persisted `chrome.dashboard_panel_default` when NEITHER
    /// `--dashboard-panel` nor `--no-dashboard-panel` is given; this raw field records only the
    /// explicit `--dashboard-panel` ENABLE. The effective value is computed by
    /// [`crate::resolve_attach_tab_chrome`] from [`AttachTabArgs::chrome_flags`]. Default `false`.
    pub dashboard_panel: bool,
    /// `--no-dashboard-panel`: explicitly turn the dashboard panel OFF, overriding a persisted
    /// `chrome.dashboard_panel_default: true`. Mutually exclusive with `--dashboard-panel`. Companion
    /// negation that, with `--dashboard-panel`, forms the tri-state (absent / enable / disable)
    /// consumed by [`AttachTabArgs::chrome_flags`]. Accepted with `--detach-renderer` as a harmless
    /// no-op (the detached renderer resolves the panel to `false` regardless), matching
    /// `--no-top-tab-bar` / `--no-dashboard-status`. Default `false`.
    pub no_dashboard_panel: bool,
    /// `--picker-overlay`: explicit ENABLE of the read-only foreground project/workspace picker overlay
    /// (built from [`crate::build_picker_overlay_model`] over the same `PickerProjection` the headless
    /// `dashboard --picker` produces). Browse only: activating a selectable row emits an intent event
    /// the app merely logs — no record write, daemon call, consent grant, cwd change, or session launch.
    /// Foreground in-process renderer only: rejected with both `--detach-renderer` and
    /// `--no-run-renderer` (a detached/headless mode cannot display the in-process overlay). Folds into
    /// the tri-state [`AttachTabChromeFlags::picker_overlay`] (`Some(true)`).
    pub picker_overlay: bool,
    /// `--no-picker-overlay`: explicit DISABLE of the foreground picker overlay, used to opt out of a
    /// persisted `chrome.picker_overlay_default true` for a single run. Mutually exclusive with
    /// `--picker-overlay`. Accepted with `--detach-renderer` / `--no-run-renderer` as a harmless no-op
    /// (those modes never resolve the overlay true anyway). Folds into the tri-state
    /// [`AttachTabChromeFlags::picker_overlay`] (`Some(false)`).
    pub no_picker_overlay: bool,
    /// `--settings-panel`: opt in to drawing the read-only in-app settings panel as app-owned top
    /// chrome ABOVE the single-session renderer grid (built from [`crate::SettingsPanelLines`] via the
    /// same `build_settings_panel_lines` projection `settings show --panel-lines` reports). Launch-time
    /// only: no interactive controls, no settings mutation, no live re-apply, no second window/surface,
    /// no daemon/protocol/schema change. Accepted only for the foreground in-process renderer and the
    /// `--no-run-renderer` inspection path (the computed panel is reported in the success JSON without
    /// opening a GUI): rejected with `--detach-renderer` (the detached renderer CLI carries no app-owned
    /// chrome). Mutually exclusive with both `--dashboard-panel` and `--no-dashboard-panel` so there is
    /// never an ambiguous top-panel source. Standalone bool — NOT folded into the chrome tri-state.
    /// Default `false`.
    pub settings_panel: bool,
    /// `--command-palette`: opt in to showing a static, display-only command-palette overlay as a
    /// foreground modal OVER the renderer grid (built from the same command-palette catalog/query/
    /// preview model the headless `command-palette --list ... --preview` command produces). First
    /// visible command palette: browse/read-only only -- no search input, keyboard shortcuts,
    /// row selection/activation, command execution, placeholder prompting, or live filtering.
    /// Accepted only for the foreground in-process renderer and the `--no-run-renderer` inspection
    /// path (the computed palette JSON is reported in the success output without opening a GUI):
    /// rejected with `--detach-renderer` (the detached renderer CLI carries no app-owned overlay).
    /// Mutually exclusive with `--picker-overlay` (both are foreground modal overlays). Standalone
    /// bool -- NOT folded into the chrome tri-state. Default `false`.
    pub command_palette: bool,
    /// `--command-palette-query <text>`: opt-in filter text for the command-palette overlay. When
    /// supplied, the filtered catalog builder is used (the same path `command-palette --query`
    /// drives); when absent the unfiltered catalog is shown. Requires `--command-palette`,
    /// at-most-once, requires a value, and is rejected when empty/whitespace-only after trimming.
    /// Default `None`.
    pub command_palette_query: Option<String>,
    /// `--file-preview <path>`: a read-only local text file to paint as the renderer's bounded
    /// file-preview band when `attach-tab` runs the renderer in-process. The app reads the file
    /// through the bounded [`crate::read_file_preview`] reader BEFORE the daemon starts (a missing,
    /// binary, or unreadable path fails cleanly), and seeds exactly one
    /// `RendererCommand::SetFilePreview { Some(..) }` through the foreground renderer's existing
    /// command channel. Read-only and local-only: the renderer opens nothing. Compatible with
    /// `--no-run-renderer` (the preview metadata is reported in the success JSON without a GUI).
    /// Rejected with `--detach-renderer` and `--new-tab-default-shell` (those paths have no command
    /// channel that can deliver the preview). At-most-once, value required. Default `None`.
    pub file_preview: Option<PathBuf>,
}

impl AttachTabArgs {
    /// The explicit dev/test new-tab launch policy this invocation opted into, or `None` when
    /// `--new-tab-default-shell` was absent. Pure: derived solely from the parsed flags. The policy
    /// is secret-free (no raw argv/env/token/socket): it only records the default-shell source, a
    /// scratch workspace mode, a workspace-derived cwd basis, a workspace identity, and a
    /// presentation title. The workspace identity is the `--new-tab-workspace-id` override when
    /// given, else the default [`DEFAULT_SESSION_ID`].
    pub fn new_tab_launch_policy(&self) -> Option<NewTabLaunchPolicy> {
        if !self.new_tab_default_shell {
            return None;
        }
        Some(NewTabLaunchPolicy {
            source: NewTabLaunchSource::DefaultShellDev,
            workspace: maestro_shell::WorkspacePolicy::ScratchCwd,
            workspace_id: self
                .new_tab_workspace_id
                .clone()
                .unwrap_or_else(|| DEFAULT_SESSION_ID.to_string()),
            cwd_basis: NewTabCwdBasis::WorkspaceDerived,
            title: self
                .new_tab_title
                .clone()
                .unwrap_or_else(|| "shell".to_string()),
        })
    }

    /// The raw chrome flags this invocation parsed, as the tri-state input to
    /// [`crate::resolve_attach_tab_chrome`]. `top_tab_bar` / `dashboard_status` / `dashboard_panel`
    /// fold their explicit enable (`--top-tab-bar` / `--dashboard-status` / `--dashboard-panel`) and
    /// explicit disable (`--no-top-tab-bar` / `--no-dashboard-status` / `--no-dashboard-panel`)
    /// companion fields into `Option<bool>`: `None` when neither was given (so the mode-aware default
    /// applies), `Some(true)` on explicit enable, `Some(false)` on explicit disable. The parser rejects
    /// the contradictory enable+disable pair, so at most one side is ever set here. `picker_overlay`
    /// folds its `--picker-overlay` / `--no-picker-overlay` pair the same way (foreground-only: the
    /// resolver discards the default/flag in None/detached modes).
    pub fn chrome_flags(&self) -> AttachTabChromeFlags {
        AttachTabChromeFlags {
            top_tab_bar: tri_state(self.top_tab_bar, self.no_top_tab_bar),
            dashboard_status: tri_state(self.dashboard_status, self.no_dashboard_status),
            dashboard_panel: tri_state(self.dashboard_panel, self.no_dashboard_panel),
            picker_overlay: tri_state(self.picker_overlay, self.no_picker_overlay),
        }
    }
}

/// Fold an explicit-enable / explicit-disable flag pair into a tri-state `Option<bool>`: `None` when
/// neither is set, `Some(true)` on enable, `Some(false)` on disable. The parser guarantees the two
/// are never both set (the contradictory pair is a usage error), so `enable` is checked first.
fn tri_state(enable: bool, disable: bool) -> Option<bool> {
    if enable {
        Some(true)
    } else if disable {
        Some(false)
    } else {
        None
    }
}

/// Parsed `launch` arguments. All optional; defaults are applied in `main` (where the process
/// environment / cwd are available), not here, so this stays a pure record of what the user typed.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LaunchArgs {
    /// `--socket <path>`: explicit daemon socket path. When `None`, the harness uses a private dev
    /// socket (see [`crate::dev_socket_path`]).
    pub socket: Option<PathBuf>,
    /// `--session-id <id>`: session id. When `None`, [`DEFAULT_SESSION_ID`] is used.
    pub session_id: Option<String>,
    /// `--cwd <dir>`: session cwd. When `None`, the process cwd is used.
    pub cwd: Option<PathBuf>,
    /// `--base <dir>`: app-support/storage base for `maestro-shell` records. When `None`, a
    /// dev-safe base is used (see [`crate::default_base_dir`]).
    pub base: Option<PathBuf>,
    /// `--daemon <path>`: explicit `pty-daemon` binary path.
    pub daemon_bin: Option<PathBuf>,
    /// `--renderer <path>`: explicit `maestro-renderer` binary path.
    pub renderer_bin: Option<PathBuf>,
    /// `--no-run-renderer`: start/attach + print the renderer command, but do not open a window.
    pub no_run_renderer: bool,
    /// `--detach-renderer`: launch the renderer fire-and-forget — do NOT wait for it, and leave any
    /// daemon this process spawned running. Invalid together with `--no-run-renderer` (nothing to
    /// detach).
    pub detach_renderer: bool,
    /// `--keep-daemon`: when this process spawned the daemon, leave it running after the app
    /// finishes — in BOTH foreground/renderer mode and `--no-run-renderer` smoke mode.
    pub keep_daemon: bool,
    /// `--log-dir <dir>`: an opt-in local directory for child-process logs. When `None`, child
    /// stdin/stdout/stderr go to null (the existing behavior; the app's own stdout/stderr stays a
    /// single structured JSON value). When set, spawned daemon and detached renderer stdout/stderr
    /// are captured to deterministic files under this directory (see [`crate::child_log_path`]).
    pub log_dir: Option<PathBuf>,
    /// `--title <window-title>`: an explicit foreground window title. When `None`, the app uses the
    /// default `Hydra - <session-id>` (see [`crate::default_window_title`]). Validated by
    /// [`validate_window_title`]; only meaningful in foreground mode (rejected with
    /// `--detach-renderer`, accepted-but-no-GUI with `--no-run-renderer`).
    pub title: Option<String>,
    /// Everything after `--`: the session command/argv. Empty means "use the shell fallback".
    pub session_argv: Vec<String>,
    /// `--product-startup`: open the installed product's stable built-in Terminal target. This
    /// owns the startup session/window ids and reattaches that retained PTY on subsequent opens;
    /// it is intentionally separate from the generic `--record-window` dev/test mechanism.
    pub product_startup: bool,
    /// `--record-window`: opt into recording this launched session into the app-owned window/tab
    /// layout records. Default launch behavior is unchanged unless this is present. The four
    /// `--window-id`/`--tab-id`/`--tab-title`/`--tab-pinned` flags are only valid alongside this.
    pub record_window: bool,
    /// `--fresh-window`: replace the selected recorded window layout before recording this launch tab.
    /// Only valid with `--record-window`; useful for clean product/test launches without stale panes.
    pub fresh_window: bool,
    /// `--window-id <id>`: explicit window id for recording. Only valid with `--record-window`;
    /// defaults to `"main"` when omitted.
    pub record_window_id: Option<String>,
    /// `--tab-id <id>`: explicit tab id for recording. Only valid with `--record-window`; defaults
    /// to the launch `session_id` when omitted.
    pub record_tab_id: Option<String>,
    /// `--tab-title <text>`: explicit tab title for recording. Only valid with `--record-window`;
    /// defaults to `--title`, else the launch `session_id`, when omitted.
    pub record_tab_title: Option<String>,
    /// `--tab-pinned <true|false>`: explicit pinned flag for the recorded tab. Only valid with
    /// `--record-window`; defaults to `false` when omitted.
    pub record_tab_pinned: Option<bool>,
    /// `--top-tab-bar`: opt in to drawing the app-owned tabs as a minimal native chrome row at the
    /// top of the foreground launch window (mirrors `attach-tab --top-tab-bar`). Accepted only for
    /// the foreground in-process renderer: rejected with `--detach-renderer`. Compatible with
    /// `--no-run-renderer` so the parse and resulting JSON (`top_tab_bar`) can be inspected without a
    /// GUI. Mutually exclusive with `--no-top-tab-bar`. The effective value is computed by
    /// [`crate::resolve_attach_tab_chrome`] from [`LaunchArgs::chrome_flags`]. Default `false`.
    pub top_tab_bar: bool,
    /// `--no-top-tab-bar`: explicitly turn the top tab bar OFF, overriding the foreground default-on
    /// policy. Mutually exclusive with `--top-tab-bar`. Companion negation forming the tri-state
    /// consumed by [`LaunchArgs::chrome_flags`]. Default `false`.
    pub no_top_tab_bar: bool,
    /// `--dashboard-status` / `--no-dashboard-status`: tri-state opt-in/out for the app-owned dashboard
    /// status suffix (mirrors `attach-tab`). Folded into [`LaunchArgs::chrome_flags`]. Default `false`.
    pub dashboard_status: bool,
    pub no_dashboard_status: bool,
    /// `--dashboard-panel` / `--no-dashboard-panel`: tri-state opt-in/out for the dashboard data
    /// surface (now the LEFT DOCK; mirrors `attach-tab`). Folded into [`LaunchArgs::chrome_flags`];
    /// overrides the persisted `chrome.dashboard_panel_default`. Mutually exclusive. Default `false`.
    pub dashboard_panel: bool,
    pub no_dashboard_panel: bool,
    /// `--new-tab-default-shell`: opt in to the explicit dev/test new-tab launch policy that lets the
    /// `+` action spawn a default shell tab (mirrors `attach-tab --new-tab-default-shell`). Requires
    /// `--top-tab-bar` (the only visible `+` surface today). Resolved via
    /// [`LaunchArgs::new_tab_launch_policy`]. Default `false`.
    pub new_tab_default_shell: bool,
    /// `--new-tab-title <title>`: presentation-only title for the explicit default-shell new-tab
    /// policy (defaults to `"shell"`). Only valid with `--new-tab-default-shell`; validated by
    /// [`validate_window_title`].
    pub new_tab_title: Option<String>,
    /// `--new-tab-workspace-id <id>`: explicit dev/test override for the new-tab workspace IDENTITY.
    /// Only valid with `--new-tab-default-shell`; validated through [`maestro_shell::validate_id`].
    pub new_tab_workspace_id: Option<String>,
    /// `--file-preview <path>`: open a bounded, read-only preview of a local text file beside the
    /// foreground terminal. The path is read by the bounded reader at launch (missing/binary/
    /// unreadable paths fail with a usage/read error). Valid in all modes: under `--no-run-renderer`
    /// the path and read status are reported on the success JSON without opening a GUI. Read-only:
    /// the file is never edited, watched, or executed.
    pub file_preview: Option<PathBuf>,
}

impl LaunchArgs {
    /// The explicit dev/test new-tab launch policy this launch opted into, or `None` when
    /// `--new-tab-default-shell` was absent. Mirrors [`AttachTabArgs::new_tab_launch_policy`].
    pub fn new_tab_launch_policy(&self) -> Option<NewTabLaunchPolicy> {
        if !self.new_tab_default_shell {
            return None;
        }
        Some(NewTabLaunchPolicy {
            source: NewTabLaunchSource::DefaultShellDev,
            workspace: maestro_shell::WorkspacePolicy::ScratchCwd,
            workspace_id: self
                .new_tab_workspace_id
                .clone()
                .unwrap_or_else(|| DEFAULT_SESSION_ID.to_string()),
            cwd_basis: NewTabCwdBasis::WorkspaceDerived,
            title: self
                .new_tab_title
                .clone()
                .unwrap_or_else(|| "shell".to_string()),
        })
    }

    /// The raw chrome flags this launch parsed, as the tri-state input to
    /// [`crate::resolve_attach_tab_chrome`]. Launch carries the top-tab-bar and dashboard
    /// status/panel tri-states; the picker tri-state stays `None` (launch never parses it).
    pub fn chrome_flags(&self) -> AttachTabChromeFlags {
        AttachTabChromeFlags {
            top_tab_bar: tri_state(self.top_tab_bar, self.no_top_tab_bar),
            dashboard_status: tri_state(self.dashboard_status, self.no_dashboard_status),
            dashboard_panel: tri_state(self.dashboard_panel, self.no_dashboard_panel),
            picker_overlay: None,
        }
    }
}

/// A parse error for the CLI. Kept as a typed value so `main` can map it to the structured failure
/// JSON contract rather than panicking.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
}

impl ParseError {
    fn new(message: impl Into<String>) -> Self {
        ParseError {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for ParseError {}

/// Concise usage text for `--help`.
pub fn usage() -> &'static str {
    "maestro-app — Hydra local desktop runtime and developer CLI\n\
     \n\
     USAGE:\n\
     \x20\x20maestro-app --help\n\
     \x20\x20maestro-app launch [FLAGS] [-- <session-command> [args...]]\n\
     \x20\x20maestro-app dashboard [--base <dir>] [--with-session-reconcile [--socket <path>]]\n\
     \x20\x20maestro-app agent-start [FLAGS] -- <agent-command> [args...]\n\
     \x20\x20maestro-app agent-resume [FLAGS] -- <agent-command> [args...]\n\
     \x20\x20maestro-app window create --window-id <id> [--base <dir>]\n\
     \x20\x20maestro-app window show --window-id <id> [--base <dir>]\n\
     \x20\x20maestro-app window open-tab --window-id <id> --tab-id <id> --session-id <id> --title <text> [--base <dir>]\n\
     \x20\x20maestro-app window split-tab --window-id <id> --from-tab-id <id> --tab-id <id> --session-id <id> --title <text> --axis <right|down> [--base <dir>]\n\
     \x20\x20maestro-app window view --window-id <id> [--base <dir>]\n\
     \x20\x20maestro-app window close-tab --window-id <id> --tab-id <id> [--base <dir>]\n\
     \x20\x20maestro-app window rename-tab --window-id <id> --tab-id <id> --title <text> [--base <dir>]\n\
     \x20\x20maestro-app window pin-tab --window-id <id> --tab-id <id> --pinned <true|false> [--base <dir>]\n\
     \x20\x20maestro-app window reorder-tabs --window-id <id> --order <tab1,tab2,...> [--base <dir>]\n\
     \x20\x20maestro-app window attention --window-id <id> --tab-id <id> --attention <state> --unseen <true|false> [--source <source>] [--since-ms <u64>] [--base <dir>]\n\
     \x20\x20maestro-app window attention-clear --window-id <id> --tab-id <id> [--base <dir>]\n\
     \x20\x20maestro-app attach-tab --window-id <id> --tab-id <id> [FLAGS]\n\
     \x20\x20maestro-app agent-mark --agent-task-id <id> (--waiting-on-user | --blocked) --reason <text> [--base <dir>]\n\
     \x20\x20maestro-app agent-finish --agent-task-id <id> (--succeeded | --failed | --cancelled) [--summary <text>] [--base <dir>]\n\
     \x20\x20maestro-app worktree-cleanup --workspace-id <id> --session-id <id> [--base <dir>] [--confirm]\n\
     \x20\x20maestro-app settings show [--panel-lines] [--base <dir>]\n\
     \x20\x20maestro-app settings set appearance.font_size_px <px> [--base <dir>]\n\
     \x20\x20maestro-app settings set appearance.theme <theme> [--base <dir>]\n\
     \x20\x20maestro-app settings set chrome.top_tab_bar_default <true|false> [--base <dir>]\n\
     \x20\x20maestro-app settings set chrome.dashboard_status_default <true|false> [--base <dir>]\n\
     \x20\x20maestro-app settings set chrome.dashboard_panel_default <true|false> [--base <dir>]\n\
     \x20\x20maestro-app settings set chrome.picker_overlay_default <true|false> [--base <dir>]\n\
     \x20\x20maestro-app settings set shell.default_argv '<json-array>' [--base <dir>]\n\
     \x20\x20maestro-app settings set workspace.default_policy <scratch_cwd|worktree|repo_write> [--base <dir>]\n\
     \x20\x20maestro-app settings set workspace.worktree_requires_consent <true|false> [--base <dir>]\n\
     \x20\x20maestro-app settings set workspace.repo_write_requires_consent <true|false> [--base <dir>]\n\
     \x20\x20maestro-app settings reset <key> [--base <dir>]\n\
     \x20\x20maestro-app settings reset --all [--base <dir>]\n\
     \x20\x20maestro-app command-palette --list [--base <dir>] [--query <text>] [--preview]\n\
     \x20\x20maestro-app command-palette --describe <action-id> [--base <dir>]\n\
     \x20\x20maestro-app layout-preset save --window-id <id> --name <text> --preset-id <id> [--project-id <id>] [--base <dir>]\n\
     \x20\x20maestro-app layout-preset list [--project-id <id>] [--base <dir>]\n\
     \x20\x20maestro-app layout-preset delete --preset-id <id> [--base <dir>]\n\
     \x20\x20maestro-app layout-preset restore-plan --preset-id <id> [--base <dir>]\n\
     \x20\x20maestro-app layout-preset restore --preset-id <id> --window-id <id> [--base <dir>] [--socket <path>] [--daemon <path>] [--log-dir <dir>]\n\
     \n\
     The 'settings show' command prints the app's effective settings (foreground chrome defaults,\n\
     workspace consent policy, local safety policy, and appearance) as one structured JSON value and\n\
     exits 0, merging any persisted appearance and chrome overrides. The 'settings set' command\n\
     persists appearance.font_size_px (10..=32), appearance.theme (built_in_dark | high_contrast_dark),\n\
     a chrome default chrome.top_tab_bar_default / chrome.dashboard_status_default /\n\
     chrome.dashboard_panel_default / chrome.picker_overlay_default (true|false),\n\
     shell.default_argv (a JSON array of command argv strings, e.g. '[\"/bin/zsh\",\"-l\"]'),\n\
     workspace.default_policy (scratch_cwd | worktree | repo_write), or a workspace consent toggle\n\
     workspace.worktree_requires_consent / workspace.repo_write_requires_consent (true|false; the\n\
     safety.* policy keys stay report-only and cannot be relaxed via settings);\n\
     'settings reset' clears one override back to its built-in default (font_size_px -> 16, theme ->\n\
     built_in_dark, chrome defaults -> ON, shell.default_argv -> unset/$SHELL fallback), preserving\n\
     non-default siblings and removing\n\
     <base>/settings/settings.json entirely once every override is back to its default. With --all\n\
     (mutually exclusive with a key), 'settings reset' restores ALL local settings to built-in\n\
     defaults by removing the settings file in one step; an absent file reports changed:false and a\n\
     foreign/unsupported file is refused (left untouched). Both\n\
     'set' and 'reset' are local-only settings-file mutations on the versioned JSON file at\n\
     <base>/settings/settings.json (0700 dir, 0600 file, atomic temp+rename) and print one success\n\
     JSON value. All three connect to no daemon, spawn nothing, open no renderer, and read/write no\n\
     app records. --base resolves the settings file + base_dir.\n\
     \n\
     The 'agent-mark' command marks an EXISTING running agent task as waiting-on-user or blocked\n\
     via an explicit, task-scoped, trusted-local assertion (NOT automatic text classification). It\n\
     is local-only: connects to no daemon, spawns nothing, touches no sockets/renderer. A transition\n\
     happens only when the task is currently running and exactly one intent is asserted; otherwise\n\
     it reports changed:false with the unchanged durable state. Prints one structured JSON value.\n\
     \n\
     The 'agent-finish' command records a terminal outcome (succeeded, failed, or cancelled) for an\n\
     EXISTING agent task via an explicit, task-scoped, trusted-local transition (NOT inferred from a\n\
     process exit or session status). It is local-only: connects to no daemon, spawns nothing,\n\
     touches no sockets/renderer. An optional --summary (bounded, trimmed) is stored as the task's\n\
     result summary. Prints one structured JSON value.\n\
     \n\
     The 'attach-tab' command opens an EXISTING persisted window tab in the native renderer: it\n\
     loads the tab's session_id from the WindowLayout, ensures a connectable daemon (reuse or spawn,\n\
     like 'launch'), reconciles sessions, and refuses (tab_session_not_live) if the tab's session is\n\
     not live before opening any GUI. It never starts a new session and never accepts a '-- <cmd>'\n\
     argv. The renderer remains one active session at a time.\n\
     \n\
     The 'worktree-cleanup' command removes ONE explicitly named worktree-policy workspace/session\n\
     pair. It is dry-run by default: it loads fresh records, runs a pure app-side planner, prints one\n\
     structured JSON plan (decision removable|refused with a stable reason), and deletes nothing. With\n\
     --confirm it re-loads fresh records, re-runs the planner, and ONLY if still removable delegates\n\
     to the consent-gated remove_worktree_with_consent primitive exactly once (no rm -rf, no forced\n\
     removal, no branch deletion). It connects to no daemon, spawns nothing, and mutates no other\n\
     records. Removal is refused unless the workspace exists, its policy is exactly Worktree, worktree\n\
     consent is present, the session is not live, and no fresh session still references the target cwd.\n\
     \n\
     The 'dashboard' command prints a read-only local records snapshot (projects, workspaces,\n\
     agent tasks, sessions, window layouts) as one structured JSON value. By default it connects\n\
     to no daemon, spawns nothing, and mutates no records. With --with-session-reconcile it first\n\
     runs a daemon-aware session reconcile (connecting to --socket or the stored/default endpoint)\n\
     so live/exited statuses and recovered sessions flow into the snapshot.\n\
     \n\
     The 'agent-start' command creates a durable agent task and starts its live PTY session\n\
     (composing maestro-shell's AgentTaskRuntime over a fresh post-'--' argv), then prints one\n\
     structured JSON value. 'agent-resume' attaches a NEW live session to an existing agent task.\n\
     Both ensure a connectable daemon (reuse or spawn) exactly like 'launch'; on success a daemon\n\
     this command spawned is left running so the task PTY survives, even without --keep-daemon.\n\
     \n\
     The 'window' commands are headless window/tab layout operations over the local WindowLayout\n\
     store. They connect to no daemon, spawn nothing, and touch no sockets. 'create' makes a new\n\
     empty layout; 'show' reads a persisted layout; 'open-tab' appends a tab; 'split-tab' appends\n\
     a tab that records it was split from an existing tab along an axis (right|down), storage-only\n\
     with no renderer pane geometry yet; 'view' prints a\n\
     read-only projection joining each tab with the agent-task reconcile report (session status,\n\
     task state, attention). The mutations 'close-tab' (remove + compact indices), 'rename-tab'\n\
     (title only), 'pin-tab' (pinned flag only), 'reorder-tabs' (exact permutation of tab ids),\n\
     'attention' (persisted attention object), and 'attention-clear' (clear persisted attention to\n\
     seen/none with source user) operate in place. Each prints exactly one structured JSON value.\n\
     \n\
     The 'layout-preset' commands manage named, reopenable window arrangements over\n\
     the local LayoutPreset store. They connect to no daemon, spawn nothing, and open no renderer.\n\
     'save' captures a persisted window's current tab topology (order, title, pin, split provenance,\n\
     plus a best-effort per-slot session-id hint) into a new named preset, skipping stashed tabs and\n\
     refusing to clobber an existing preset id; running-session identity is kept separate from layout\n\
     position so a restore never relabels or restarts the wrong pane. 'list' prints saved presets\n\
     newest-first (optionally scoped to a --project-id); 'delete' removes one preset; 'restore-plan'\n\
     prints the NON-EXECUTING restore plan — each captured slot marked reattach (its hinted session is\n\
     still live) or launch_fresh — derived from the fresh set of non-exited session records. 'restore'\n\
     EXECUTES that plan into --window-id's layout: it walks the slots in order, reattaching a live\n\
     hinted session (no relaunch) or launching a fresh one through the ordinary new-tab pipeline,\n\
     minting fresh tab ids and rebuilding splits inside one top-level tab list. Each command prints\n\
     exactly one structured JSON value; --base resolves the records base.\n\
     \n\
     FLAGS (attach-tab):\n\
     \x20\x20--window-id <id>     persisted window layout to open from (required)\n\
     \x20\x20--tab-id <id>        tab whose session_id the renderer attaches to (required)\n\
     \x20\x20--base <dir>         app-support base for records (default: a dev-safe app-support path)\n\
     \x20\x20--socket <path>      explicit daemon socket path (default: a private dev socket)\n\
     \x20\x20--daemon <path>      explicit pty-daemon binary path\n\
     \x20\x20--renderer <path>    explicit maestro-renderer binary path (used in --detach-renderer)\n\
     \x20\x20--log-dir <dir>      capture spawned daemon/detached renderer stdout/stderr under <dir>\n\
     \x20\x20--no-run-renderer    resolve/load/reconcile/report without opening a GUI window\n\
     \x20\x20--detach-renderer    spawn the renderer fire-and-forget (invalid with --no-run-renderer)\n\
     \x20\x20--keep-daemon        if this process spawned the daemon, leave it running afterward\n\
     \x20\x20--title <text>       foreground window title override (rejected with --detach-renderer)\n\
     \x20\x20--top-tab-bar        draw app tabs as a native top chrome row (foreground default ON; explicit enable; rejected with --detach-renderer)\n\
     \x20\x20--no-top-tab-bar     opt OUT of the foreground top tab bar (mutually exclusive with --top-tab-bar)\n\
     \x20\x20--new-tab-default-shell  opt in to an EXPLICIT dev/test new-tab policy so '+' may spawn a default shell\n\
     \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20(requires --top-tab-bar; NOT a command palette or workspace picker; without it '+' only declines/logs)\n\
     \x20\x20--new-tab-title <text>   presentation title for that default-shell tab (default 'shell'; requires --new-tab-default-shell)\n\
     \x20\x20--new-tab-workspace-id <id>  explicit dev/test override for that tab's workspace identity (default 'maestro-app-dev'; requires --new-tab-default-shell; validated as a safe id; NOT a workspace picker)\n\
     \x20\x20--dashboard-status   append a compact read-only dashboard summary to the app-owned status label (foreground default ON; explicit enable; rejected with --detach-renderer)\n\
     \x20\x20--no-dashboard-status  opt OUT of the foreground dashboard status suffix (mutually exclusive with --dashboard-status)\n\
     \x20\x20--dashboard-panel    draw a static read-only dashboard panel as app-owned top chrome above the grid (explicit enable, overrides persisted chrome.dashboard_panel_default; rejected with --detach-renderer)\n\
     \x20\x20--no-dashboard-panel  opt OUT of the dashboard panel, overriding a persisted chrome.dashboard_panel_default:true (mutually exclusive with --dashboard-panel; no-op with --detach-renderer)\n\
     \x20\x20--picker-overlay     draw the read-only foreground project/workspace picker overlay (explicit enable, overrides persisted chrome.picker_overlay_default; foreground only; rejected with --detach-renderer and --no-run-renderer)\n\
     \x20\x20--no-picker-overlay  opt OUT of the foreground picker overlay, overriding a persisted chrome.picker_overlay_default:true (mutually exclusive with --picker-overlay; no-op with --detach-renderer/--no-run-renderer)\n\
     \x20\x20--settings-panel     draw the read-only in-app settings panel as app-owned top chrome above the grid (reports the panel in --no-run-renderer JSON; rejected with --detach-renderer, --dashboard-panel, and --no-dashboard-panel)\n\
     \x20\x20--command-palette    draw the static read-only command-palette overlay over the grid (reports the palette in --no-run-renderer JSON; rejected with --detach-renderer and --picker-overlay)\n\
     \x20\x20--command-palette-query <text>  filter the command-palette overlay rows (requires --command-palette; non-empty)\n\
     \n\
     FLAGS (dashboard):\n\
     \x20\x20--base <dir>         app-support base for records (default: a dev-safe app-support path)\n\
     \x20\x20--with-session-reconcile  opt in to a daemon-aware session reconcile before projecting\n\
     \x20\x20--socket <path>      reconcile endpoint; valid ONLY with --with-session-reconcile\n\
     \n\
     FLAGS (agent-start):\n\
     \x20\x20--agent-task-id <id> agent task id to create (required)\n\
     \x20\x20--project-id <id>    owning project id (required)\n\
     \x20\x20--goal <text>        the agent task goal (required)\n\
     \x20\x20--session-id <id>    live session id for the task PTY (required)\n\
     \x20\x20--workspace-id <id>  owning workspace id (required)\n\
     \x20\x20--cwd <dir>          session working directory; must be an existing directory (required)\n\
     \x20\x20--base <dir>         app-support base for records (default: a dev-safe app-support path)\n\
     \x20\x20--socket <path>      explicit daemon socket path (default: a private dev socket)\n\
     \x20\x20--daemon <path>      explicit pty-daemon binary path\n\
     \x20\x20--cols <n>           initial PTY columns (default: 80)\n\
     \x20\x20--rows <n>           initial PTY rows (default: 24)\n\
     \x20\x20--keep-daemon        accepted for symmetry with launch; agent commands always keep\n\
     \x20\x20                     a spawned daemon on success, and failures clean up owned daemons\n\
     \x20\x20--log-dir <dir>      capture a spawned daemon's stdout/stderr under <dir> (else null)\n\
     \x20\x20--record-window      record the agent task into the app-owned window/tab layout\n\
     \x20\x20                     (opt-in; default agent-start behavior is unchanged without it)\n\
     \x20\x20--window-id <id>     window id for recording (requires --record-window; default 'main')\n\
     \x20\x20--tab-id <id>        tab id for recording (requires --record-window; default agent-task-id)\n\
     \x20\x20--tab-title <text>   tab title for recording (requires --record-window; default the goal)\n\
     \x20\x20--tab-pinned <bool>  pinned flag, strictly true|false (requires --record-window; default false)\n\
     \x20\x20--                   everything after this is the agent command + argv (required)\n\
     \n\
     FLAGS (agent-resume):\n\
     \x20\x20--agent-task-id <id> existing agent task id to resume (required)\n\
     \x20\x20--session-id <id>    live session id for the new task PTY (required)\n\
     \x20\x20--workspace-id <id>  owning workspace id (required)\n\
     \x20\x20--cwd <dir>          session working directory; must be an existing directory (required)\n\
     \x20\x20--base / --socket / --daemon / --cols / --rows / --keep-daemon / --log-dir  as agent-start\n\
     \x20\x20--record-window      record/retarget the resumed task's tab in the window/tab layout\n\
     \x20\x20                     (opt-in; default agent-resume behavior is unchanged without it)\n\
     \x20\x20--window-id <id>     window id for recording (requires --record-window; default 'main')\n\
     \x20\x20--tab-id <id>        tab id for recording (requires --record-window; default agent-task-id)\n\
     \x20\x20--tab-title <text>   title for a newly-opened tab (requires --record-window; default the goal)\n\
     \x20\x20--tab-pinned <bool>  pinned flag for a newly-opened tab, strictly true|false (requires --record-window; default false)\n\
     \x20\x20--                   everything after this is the agent command + argv (required)\n\
     \n\
     FLAGS (worktree-cleanup):\n\
     \x20\x20--workspace-id <id>  worktree workspace to clean up (required; validated as a safe id)\n\
     \x20\x20--session-id <id>    session whose worktree subdir is the removal target (required; safe id)\n\
     \x20\x20--base <dir>         app-support base for records (default: a dev-safe app-support path)\n\
     \x20\x20--confirm            opt in to actual removal; without it the command is dry-run only and\n\
     \x20\x20                     deletes nothing (re-validates removability before deleting)\n\
     \n\
     FLAGS (window):\n\
     \x20\x20--window-id <id>     window layout id (required for every window subcommand)\n\
     \x20\x20--tab-id <id>        tab id (required for open-tab/split-tab/close-tab/rename-tab/pin-tab/attention)\n\
     \x20\x20--from-tab-id <id>   existing source tab the split derives from (split-tab only; required)\n\
     \x20\x20--session-id <id>    session id the new tab binds to (open-tab/split-tab; required)\n\
     \x20\x20--title <text>       tab title (required for open-tab/split-tab/rename-tab)\n\
     \x20\x20--axis <right|down>  split direction relative to the source tab (split-tab only; required)\n\
     \x20\x20--pinned <bool>      pinned flag, strictly true|false (pin-tab only; required)\n\
     \x20\x20--order <ids>        non-empty comma-separated tab id permutation (reorder-tabs; required)\n\
     \x20\x20--attention <state>  attention none|activity|needs_input|error|done (attention; required)\n\
     \x20\x20--unseen <bool>      unseen flag, strictly true|false (attention only; required)\n\
     \x20\x20--source <source>    attention source process|agent|user (attention only; default process)\n\
     \x20\x20--since-ms <u64>     attention since-ms timestamp (attention only; default now)\n\
     \x20\x20--base <dir>         app-support base for records (default: a dev-safe app-support path)\n\
     \n\
     FLAGS (launch):\n\
     \x20\x20--socket <path>      explicit daemon socket path (default: a private dev socket)\n\
     \x20\x20--session-id <id>    session id (default: maestro-app-dev)\n\
     \x20\x20--title <title>      foreground window title (default: 'Hydra - <session-id>');\n\
     \x20\x20                     rejected with --detach-renderer; accepted but no GUI effect\n\
     \x20\x20                     under --no-run-renderer\n\
     \x20\x20--cwd <dir>          session working directory (default: current directory)\n\
     \x20\x20--base <dir>         app-support base for records (default: a dev-safe app-support path)\n\
     \x20\x20--daemon <path>      explicit pty-daemon binary path\n\
     \x20\x20--renderer <path>    explicit maestro-renderer binary path\n\
     \x20\x20--no-run-renderer    start/attach the session and print the renderer command,\n\
     \x20\x20                     but do not open a GUI window (smoke mode)\n\
     \x20\x20--detach-renderer    launch the renderer fire-and-forget: do not wait for it, and\n\
     \x20\x20                     leave any daemon this process spawned running (invalid with\n\
     \x20\x20                     --no-run-renderer). Default foreground mode waits for the\n\
     \x20\x20                     renderer to exit, then stops only a daemon it spawned.\n\
     \x20\x20--keep-daemon        if this process spawned the daemon, leave it running after the\n\
     \x20\x20                     app finishes (applies in GUI and --no-run-renderer modes)\n\
     \x20\x20--product-startup    installed-app startup: ensure/reuse the stable built-in Terminal\n\
     \x20\x20                     project/window/tab/session and bind dashboard window actions;\n\
     \x20\x20                     incompatible with session/cwd/record/detach overrides\n\
     \x20\x20--top-tab-bar        draw app tabs as a native top chrome row (foreground default ON; explicit enable; rejected with --detach-renderer)\n\
     \x20\x20--no-top-tab-bar     opt OUT of the foreground top tab bar (mutually exclusive with --top-tab-bar)\n\
     \x20\x20--new-tab-default-shell  opt in to an EXPLICIT dev/test new-tab policy so '+' may spawn a default shell\n\
     \x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20(requires --top-tab-bar; '+' mints a real tab only with --record-window; without the policy '+' only declines/logs)\n\
     \x20\x20--new-tab-title <text>   presentation title for that default-shell tab (default 'shell'; requires --new-tab-default-shell)\n\
     \x20\x20--new-tab-workspace-id <id>  explicit dev/test override for that tab's workspace identity (default 'maestro-app-dev'; requires --new-tab-default-shell; validated as a safe id)\n\
     \x20\x20--log-dir <dir>      capture spawned daemon and detached renderer stdout/stderr to\n\
     \x20\x20                     deterministic files under <dir> (created 0700 if missing). When\n\
     \x20\x20                     absent, child streams go to null. The app's own stdout/stderr stay\n\
     \x20\x20                     exactly one structured JSON value either way\n\
     \x20\x20--record-window      record the launched session into the app-owned window/tab layout\n\
     \x20\x20                     (opt-in; default launch behavior is unchanged without it)\n\
     \x20\x20--fresh-window       replace the selected recorded window layout before recording this\n\
     \x20\x20                     launch tab (requires --record-window; sessions are not deleted)\n\
     \x20\x20--window-id <id>     window id for recording (requires --record-window; default 'main')\n\
     \x20\x20--tab-id <id>        tab id for recording (requires --record-window; default session-id)\n\
     \x20\x20--tab-title <text>   tab title for recording (requires --record-window; default --title\n\
     \x20\x20                     else session-id)\n\
     \x20\x20--tab-pinned <bool>  pinned flag, strictly true|false (requires --record-window;\n\
     \x20\x20                     default false)\n\
     \x20\x20--                   everything after this is the session command + argv\n"
}

/// Parse `args` (WITHOUT the program name) into a [`Command`].
///
/// Recognized shapes:
/// - `[]`, `--help`, `-h`, `help` -> [`Command::Help`];
/// - `launch [flags] [-- argv...]` -> [`Command::Launch`].
///
/// Flag values that require an argument error if the value is missing. Unknown flags error. Once
/// `--` is seen, the remainder is taken verbatim as the session argv (so a session command may
/// itself use `--foo` flags without colliding with ours).
pub fn parse_args(args: &[String]) -> Result<Command, ParseError> {
    let mut iter = args.iter();
    let Some(first) = iter.next() else {
        return Ok(Command::Help);
    };

    match first.as_str() {
        "--help" | "-h" | "help" => Ok(Command::Help),
        "launch" => parse_launch(iter).map(|a| Command::Launch(Box::new(a))),
        "dashboard" => parse_dashboard(iter).map(Command::Dashboard),
        "agent-start" => parse_agent_start(iter).map(|a| Command::AgentStart(Box::new(a))),
        "agent-resume" => parse_agent_resume(iter).map(|a| Command::AgentResume(Box::new(a))),
        "window" => parse_window(iter).map(Command::Window),
        "attach-tab" => parse_attach_tab(iter).map(|a| Command::AttachTab(Box::new(a))),
        "agent-mark" => parse_agent_mark(iter).map(Command::AgentMark),
        "agent-finish" => parse_agent_finish(iter).map(Command::AgentFinish),
        "worktree-cleanup" => parse_worktree_cleanup(iter).map(Command::WorktreeCleanup),
        "worktree-list" => parse_worktree_list(iter).map(Command::WorktreeList),
        "settings" => parse_settings(iter).map(Command::Settings),
        "command-palette" => parse_command_palette(iter).map(Command::CommandPalette),
        "layout-preset" => parse_layout_preset(iter).map(Command::LayoutPreset),
        "project" => parse_project(iter).map(Command::Project),
        other => Err(ParseError::new(format!(
            "unknown command '{other}' (expected 'launch', 'dashboard', 'agent-start', \
             'agent-resume', 'window', 'attach-tab', 'agent-mark', 'agent-finish', \
             'worktree-cleanup', 'worktree-list', 'settings', 'command-palette', \
             'layout-preset', 'project', or '--help')"
        ))),
    }
}

/// Parse `settings <subcommand>`. Subcommands are `show` and `set`. A missing subcommand, an unknown
/// subcommand, and `--help`/`-h` are all parse errors.
fn parse_settings<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<SettingsCommand, ParseError> {
    let Some(sub) = iter.next() else {
        return Err(ParseError::new(
            "settings requires a subcommand (expected 'show', 'set', or 'reset')",
        ));
    };
    match sub.as_str() {
        "show" => parse_settings_show(iter).map(SettingsCommand::Show),
        "set" => parse_settings_set(iter).map(SettingsCommand::Set),
        "reset" => parse_settings_reset(iter).map(SettingsCommand::Reset),
        "--help" | "-h" => Err(ParseError::new("use 'maestro-app --help' for usage")),
        other => Err(ParseError::new(format!(
            "unknown settings subcommand '{other}' (expected 'show', 'set', or 'reset')"
        ))),
    }
}

/// The keys `settings set`/`settings reset` accept, and a human-readable hint listing them for error
/// messages. The four `chrome.*_default` keys cover the configurable chrome defaults;
/// `chrome.picker_overlay_default` is foreground-only (it only takes effect for the in-process
/// foreground renderer; `--no-run-renderer`/detached always resolve the overlay false).
const SETTINGS_SETTABLE_KEYS: [&str; 10] = [
    "appearance.font_size_px",
    "appearance.theme",
    "chrome.top_tab_bar_default",
    "chrome.dashboard_status_default",
    "chrome.dashboard_panel_default",
    "chrome.picker_overlay_default",
    "shell.default_argv",
    "workspace.default_policy",
    "workspace.worktree_requires_consent",
    "workspace.repo_write_requires_consent",
];
const SETTINGS_KEYS_HINT: &str = "settable: 'appearance.font_size_px', 'appearance.theme', 'chrome.top_tab_bar_default', 'chrome.dashboard_status_default', 'chrome.dashboard_panel_default', 'chrome.picker_overlay_default', 'shell.default_argv', 'workspace.default_policy', 'workspace.worktree_requires_consent', 'workspace.repo_write_requires_consent'";

/// Parse a `chrome.*_default` value: exactly `true` or `false`. Any other token is `bad_usage`.
fn parse_settings_bool(key: &str, raw: &str) -> Result<bool, ParseError> {
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(ParseError::new(format!(
            "settings set {key} value must be 'true' or 'false' (got '{other}')"
        ))),
    }
}

/// Parse `settings reset <key> [--base <dir>]`.
///
/// Rules: the key (`appearance.font_size_px`, `appearance.theme`, `chrome.top_tab_bar_default`, or
/// `chrome.dashboard_status_default`) is required and positional. No value may follow the key (reset
/// takes no value). `--base` is optional + singleton (duplicate or missing value is an error). A `--`
/// argv, `--help`/`-h`, unknown flags, a missing/unknown key, and
/// an unexpected positional value after the key are all parse errors.
fn reset_target_for_key(key: &str) -> Option<crate::SettingsResetTarget> {
    Some(match key {
        "appearance.font_size_px" => crate::SettingsResetTarget::FontSizePx,
        "appearance.theme" => crate::SettingsResetTarget::Theme,
        "chrome.top_tab_bar_default" => crate::SettingsResetTarget::TopTabBarDefault,
        "chrome.dashboard_status_default" => crate::SettingsResetTarget::DashboardStatusDefault,
        "chrome.dashboard_panel_default" => crate::SettingsResetTarget::DashboardPanelDefault,
        "chrome.picker_overlay_default" => crate::SettingsResetTarget::PickerOverlayDefault,
        "shell.default_argv" => crate::SettingsResetTarget::ShellDefaultArgv,
        "workspace.default_policy" => crate::SettingsResetTarget::WorkspaceDefaultPolicy,
        "workspace.worktree_requires_consent" => {
            crate::SettingsResetTarget::WorkspaceWorktreeRequiresConsent
        }
        "workspace.repo_write_requires_consent" => {
            crate::SettingsResetTarget::WorkspaceRepoWriteRequiresConsent
        }
        _ => return None,
    })
}

fn parse_settings_reset<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<SettingsResetArgs, ParseError> {
    // Tri-state during parse: no target chosen yet / a keyed target / the `--all` whole-file reset.
    // `--all` and a key are mutually exclusive; duplicate `--all` and a second key are both rejected.
    let mut target: Option<crate::SettingsResetTarget> = None;
    let mut all = false;
    let mut base: Option<PathBuf> = None;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "settings reset does not accept a '--' argv",
                ))
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            "--all" => {
                if all {
                    return Err(ParseError::new(
                        "settings reset --all may be given at most once",
                    ));
                }
                if target.is_some() {
                    return Err(ParseError::new(
                        "settings reset --all cannot be combined with a key",
                    ));
                }
                all = true;
            }
            "--base" => {
                if base.is_some() {
                    return Err(ParseError::new(
                        "settings reset --base may be given at most once",
                    ));
                }
                base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            other if other.starts_with('-') => {
                return Err(ParseError::new(format!(
                    "unknown settings reset flag '{other}' (see 'maestro-app --help')"
                )))
            }
            other => {
                if all {
                    return Err(ParseError::new(
                        "settings reset --all cannot be combined with a key",
                    ));
                }
                if target.is_some() {
                    return Err(ParseError::new(format!(
                        "settings reset takes a single key (unexpected '{other}')"
                    )));
                }
                match reset_target_for_key(other) {
                    Some(t) => target = Some(t),
                    None => {
                        return Err(ParseError::new(format!(
                            "unknown settings key '{other}' (resettable: {SETTINGS_KEYS_HINT}, or --all)"
                        )))
                    }
                }
            }
        }
    }

    let selection = match (all, target) {
        (true, _) => SettingsResetSelection::All,
        (false, Some(t)) => SettingsResetSelection::Key(t),
        (false, None) => {
            return Err(ParseError::new(format!(
                "settings reset requires a key ({SETTINGS_KEYS_HINT}) or --all"
            )))
        }
    };
    Ok(SettingsResetArgs { selection, base })
}

/// Parse `settings set <key> <value> [--base <dir>]`.
///
/// Rules: the key and a value are required and positional, in that order. For `appearance.font_size_px`
/// the value must be an integer in `10..=32`; for `appearance.theme` it must be one of the supported
/// theme identifiers; for `chrome.top_tab_bar_default` / `chrome.dashboard_status_default` /
/// `chrome.dashboard_panel_default` it must be exactly `true` or `false`; for `shell.default_argv` it
/// must be a JSON array of command argv strings. `--base` is optional + singleton (duplicate or missing value is an
/// error). A `--` argv, `--help`/`-h`, unknown flags, a missing/unknown key, and a missing/invalid
/// value are all parse errors.
fn parse_settings_set<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<SettingsSetArgs, ParseError> {
    let Some(key) = iter.next() else {
        return Err(ParseError::new(format!(
            "settings set requires a key ({SETTINGS_KEYS_HINT})"
        )));
    };
    if key == "--" {
        return Err(ParseError::new("settings set does not accept a '--' argv"));
    }
    if key == "--help" || key == "-h" {
        return Err(ParseError::new("use 'maestro-app --help' for usage"));
    }
    if !SETTINGS_SETTABLE_KEYS.contains(&key.as_str()) {
        return Err(ParseError::new(format!(
            "unknown settings key '{key}' (settable: {SETTINGS_KEYS_HINT})"
        )));
    }

    let Some(raw_value) = iter.next() else {
        return Err(ParseError::new(format!(
            "settings set {key} requires a value"
        )));
    };
    let target = match key.as_str() {
        "appearance.font_size_px" => {
            let value: u32 = raw_value.parse().map_err(|_| {
                ParseError::new(format!(
                    "settings set appearance.font_size_px value must be an integer (got '{raw_value}')"
                ))
            })?;
            let value = crate::validate_font_size_px(value).map_err(ParseError::new)?;
            SettingsSetTarget::FontSizePx(value)
        }
        "appearance.theme" => {
            let theme = crate::validate_theme(raw_value).map_err(ParseError::new)?;
            SettingsSetTarget::Theme(theme)
        }
        "chrome.top_tab_bar_default" => {
            SettingsSetTarget::TopTabBarDefault(parse_settings_bool(key, raw_value)?)
        }
        "chrome.dashboard_status_default" => {
            SettingsSetTarget::DashboardStatusDefault(parse_settings_bool(key, raw_value)?)
        }
        "chrome.dashboard_panel_default" => {
            SettingsSetTarget::DashboardPanelDefault(parse_settings_bool(key, raw_value)?)
        }
        "chrome.picker_overlay_default" => {
            SettingsSetTarget::PickerOverlayDefault(parse_settings_bool(key, raw_value)?)
        }
        "shell.default_argv" => {
            let argv = crate::validate_shell_default_argv(raw_value).map_err(ParseError::new)?;
            SettingsSetTarget::ShellDefaultArgv(argv)
        }
        "workspace.default_policy" => {
            let policy = crate::validate_workspace_policy(raw_value).map_err(ParseError::new)?;
            SettingsSetTarget::WorkspaceDefaultPolicy(policy)
        }
        "workspace.worktree_requires_consent" => {
            SettingsSetTarget::WorkspaceWorktreeRequiresConsent(parse_settings_bool(
                key, raw_value,
            )?)
        }
        // The settable-key guard above already rejected anything else, so this is the last key.
        _ => SettingsSetTarget::WorkspaceRepoWriteRequiresConsent(parse_settings_bool(
            key, raw_value,
        )?),
    };

    let mut base: Option<PathBuf> = None;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => return Err(ParseError::new("settings set does not accept a '--' argv")),
            "--base" => {
                if base.is_some() {
                    return Err(ParseError::new(
                        "settings set --base may be given at most once",
                    ));
                }
                base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown settings set flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    Ok(SettingsSetArgs { target, base })
}

/// Parse `settings show [--base <dir>]`.
///
/// Rules: `--base` optional + singleton (a duplicate `--base`, or `--base` with no value, is an
/// error); a `--` argv, `--help`/`-h`, and unknown flags are all parse errors. Read-only command —
/// there are no mutating flags.
fn parse_settings_show<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<SettingsShowArgs, ParseError> {
    let mut out = SettingsShowArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => return Err(ParseError::new("settings show does not accept a '--' argv")),
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "settings show --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--panel-lines" => {
                if out.panel_lines {
                    return Err(ParseError::new(
                        "settings show --panel-lines may be given at most once",
                    ));
                }
                out.panel_lines = true;
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown settings show flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    Ok(out)
}

/// Parse `command-palette --list [--base <dir>] [--query <text>] [--preview]` (list mode) or
/// `command-palette --describe <action-id> [--base <dir>]` (describe mode).
///
/// Rules: EXACTLY ONE of `--list` / `--describe` is required and the two are mutually exclusive;
/// `--query`/`--preview` are list-mode only and rejected with `--describe`. `--base`, `--query`, and
/// `--describe` are at-most-once and require a value; a `--query`/`--describe` that trims to empty
/// (whitespace-only) is rejected; `--list`/`--preview` are value-less and at-most-once. The flags may
/// appear in any order. A `--` argv, `--help`/`-h`, unknown flags, extra positionals, and duplicate
/// flags are all parse errors.
fn parse_command_palette<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<CommandPaletteArgs, ParseError> {
    let mut out = CommandPaletteArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "command-palette does not accept a '--' argv",
                ))
            }
            "--list" => {
                if out.list {
                    return Err(ParseError::new(
                        "command-palette --list may be given at most once",
                    ));
                }
                out.list = true;
            }
            "--describe" => {
                if out.describe.is_some() {
                    return Err(ParseError::new(
                        "command-palette --describe may be given at most once",
                    ));
                }
                let value = value_for(&mut iter, "--describe")?;
                if value.trim().is_empty() {
                    return Err(ParseError::new(
                        "command-palette --describe must not be empty or whitespace-only",
                    ));
                }
                out.describe = Some(value.clone());
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "command-palette --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--query" => {
                if out.query.is_some() {
                    return Err(ParseError::new(
                        "command-palette --query may be given at most once",
                    ));
                }
                let value = value_for(&mut iter, "--query")?;
                if value.trim().is_empty() {
                    return Err(ParseError::new(
                        "command-palette --query must not be empty or whitespace-only",
                    ));
                }
                out.query = Some(value.clone());
            }
            "--preview" => {
                if out.preview {
                    return Err(ParseError::new(
                        "command-palette --preview may be given at most once",
                    ));
                }
                out.preview = true;
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown command-palette flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    match (out.list, out.describe.is_some()) {
        (true, true) => {
            return Err(ParseError::new(
                "command-palette --list and --describe are mutually exclusive",
            ));
        }
        (false, false) => {
            return Err(ParseError::new(
                "command-palette requires exactly one of --list or --describe",
            ));
        }
        _ => {}
    }
    if out.describe.is_some() && (out.query.is_some() || out.preview) {
        return Err(ParseError::new(
            "command-palette --describe does not accept --query or --preview",
        ));
    }
    Ok(out)
}

/// Parse `worktree-cleanup --workspace-id <id> --session-id <id> [--base <dir>] [--confirm]`.
///
/// Rules: `--workspace-id` and `--session-id` are each required + singleton and validated with
/// [`maestro_shell::validate_id`] (so a path-traversal or otherwise unsafe id is a parse error,
/// not a runtime surprise); `--base` optional + singleton; `--confirm` is a value-less boolean
/// flag, singleton (a second `--confirm` is an error). A `--` argv, `--help`/`-h`, unknown flags,
/// and duplicate flags are all parse errors.
fn parse_worktree_cleanup<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WorktreeCleanupArgs, ParseError> {
    let mut out = WorktreeCleanupArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "worktree-cleanup does not accept a '--' argv",
                ))
            }
            "--workspace-id" => {
                if out.workspace_id.is_some() {
                    return Err(ParseError::new(
                        "worktree-cleanup --workspace-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--workspace-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("worktree-cleanup --workspace-id is invalid: {e}"))
                })?;
                out.workspace_id = Some(raw);
            }
            "--session-id" => {
                if out.session_id.is_some() {
                    return Err(ParseError::new(
                        "worktree-cleanup --session-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--session-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("worktree-cleanup --session-id is invalid: {e}"))
                })?;
                out.session_id = Some(raw);
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "worktree-cleanup --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--confirm" => {
                if out.confirm {
                    return Err(ParseError::new(
                        "worktree-cleanup --confirm may be given at most once",
                    ));
                }
                out.confirm = true;
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown worktree-cleanup flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.workspace_id.is_none() {
        return Err(ParseError::new(
            "worktree-cleanup requires --workspace-id <id>",
        ));
    }
    if out.session_id.is_none() {
        return Err(ParseError::new(
            "worktree-cleanup requires --session-id <id>",
        ));
    }
    Ok(out)
}

/// Parse `worktree-list --workspace-id <id> [--base <dir>]`.
///
/// Rules: `--workspace-id` required + singleton + safe-id-validated; `--base` optional + singleton;
/// a `--` argv, `--help`/`-h`, unknown flags, and duplicate flags are all parse errors. Read-only
/// command — there are no mutating flags.
fn parse_worktree_list<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WorktreeListArgs, ParseError> {
    let mut out = WorktreeListArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => return Err(ParseError::new("worktree-list does not accept a '--' argv")),
            "--workspace-id" => {
                if out.workspace_id.is_some() {
                    return Err(ParseError::new(
                        "worktree-list --workspace-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--workspace-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("worktree-list --workspace-id is invalid: {e}"))
                })?;
                out.workspace_id = Some(raw);
            }
            "--all" => {
                if out.all {
                    return Err(ParseError::new(
                        "worktree-list --all may be given at most once",
                    ));
                }
                out.all = true;
            }
            "--include-orphans" => {
                if out.include_orphans {
                    return Err(ParseError::new(
                        "worktree-list --include-orphans may be given at most once",
                    ));
                }
                out.include_orphans = true;
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "worktree-list --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown worktree-list flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    match (out.workspace_id.is_some(), out.all) {
        (true, true) => Err(ParseError::new(
            "worktree-list accepts either --workspace-id <id> or --all, not both",
        )),
        (false, false) => Err(ParseError::new(
            "worktree-list requires exactly one scope: --workspace-id <id> or --all",
        )),
        // `--include-orphans` extends the all-workspaces filesystem inventory; it is meaningless
        // (and rejected) for a single-workspace, record-only listing.
        (true, false) if out.include_orphans => Err(ParseError::new(
            "worktree-list --include-orphans is only valid with --all",
        )),
        _ => Ok(out),
    }
}

/// Parse `layout-preset <subcommand>`. Subcommands are `save`, `list`, `delete`, `restore-plan`.
/// A missing subcommand, an unknown subcommand, and `--help`/`-h` are all parse errors.
fn parse_layout_preset<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<LayoutPresetCommand, ParseError> {
    let Some(sub) = iter.next() else {
        return Err(ParseError::new(
            "layout-preset requires a subcommand (expected 'save', 'list', 'delete', \
             'restore-plan', or 'restore')",
        ));
    };
    match sub.as_str() {
        "save" => parse_layout_preset_save(iter).map(LayoutPresetCommand::Save),
        "list" => parse_layout_preset_list(iter).map(LayoutPresetCommand::List),
        "delete" => parse_layout_preset_ref(iter, "delete").map(LayoutPresetCommand::Delete),
        "restore-plan" => {
            parse_layout_preset_ref(iter, "restore-plan").map(LayoutPresetCommand::RestorePlan)
        }
        "restore" => parse_layout_preset_restore(iter).map(LayoutPresetCommand::Restore),
        "--help" | "-h" => Err(ParseError::new("use 'maestro-app --help' for usage")),
        other => Err(ParseError::new(format!(
            "unknown layout-preset subcommand '{other}' (expected 'save', 'list', 'delete', \
             'restore-plan', or 'restore')"
        ))),
    }
}

/// Parse `layout-preset save --window-id <id> --name <text> --preset-id <id> [--project-id <id>]
/// [--base <dir>]`. All ids are safe-id-validated; `--name` is validated as a window title;
/// duplicates, a `--` argv, `--help`/`-h`, and unknown flags are parse errors. `--window-id`,
/// `--name`, and `--preset-id` are required.
fn parse_layout_preset_save<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<LayoutPresetSaveArgs, ParseError> {
    let mut out = LayoutPresetSaveArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "layout-preset save does not accept a '--' argv",
                ))
            }
            "--window-id" => {
                if out.window_id.is_some() {
                    return Err(ParseError::new(
                        "layout-preset save --window-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--window-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("layout-preset save --window-id is invalid: {e}"))
                })?;
                out.window_id = Some(raw);
            }
            "--name" => {
                if out.name.is_some() {
                    return Err(ParseError::new(
                        "layout-preset save --name may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--name")?;
                validate_window_title(&raw).map_err(|e| {
                    ParseError::new(format!("layout-preset save --name is invalid: {e}"))
                })?;
                out.name = Some(raw);
            }
            "--preset-id" => {
                if out.preset_id.is_some() {
                    return Err(ParseError::new(
                        "layout-preset save --preset-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--preset-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("layout-preset save --preset-id is invalid: {e}"))
                })?;
                out.preset_id = Some(raw);
            }
            "--project-id" => {
                if out.project_id.is_some() {
                    return Err(ParseError::new(
                        "layout-preset save --project-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--project-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("layout-preset save --project-id is invalid: {e}"))
                })?;
                out.project_id = Some(raw);
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "layout-preset save --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown layout-preset save flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new(
            "layout-preset save requires --window-id <id>",
        ));
    }
    if out.name.is_none() {
        return Err(ParseError::new("layout-preset save requires --name <text>"));
    }
    if out.preset_id.is_none() {
        return Err(ParseError::new(
            "layout-preset save requires --preset-id <id>",
        ));
    }
    Ok(out)
}

/// Parse `layout-preset list [--project-id <id>] [--base <dir>]`. Read-only; both flags optional +
/// singleton + (for `--project-id`) safe-id-validated. A `--` argv, `--help`/`-h`, unknown flags,
/// and duplicates are parse errors.
fn parse_layout_preset_list<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<LayoutPresetListArgs, ParseError> {
    let mut out = LayoutPresetListArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "layout-preset list does not accept a '--' argv",
                ))
            }
            "--project-id" => {
                if out.project_id.is_some() {
                    return Err(ParseError::new(
                        "layout-preset list --project-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--project-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("layout-preset list --project-id is invalid: {e}"))
                })?;
                out.project_id = Some(raw);
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "layout-preset list --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown layout-preset list flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    Ok(out)
}

/// Parse the preset commands that name one preset by id (`delete`, `restore-plan`):
/// `layout-preset <sub> --preset-id <id> [--base <dir>]`. `--preset-id` required + singleton +
/// safe-id-validated; `--base` optional + singleton; a `--` argv, `--help`/`-h`, unknown flags, and
/// duplicates are parse errors. `sub` names the subcommand for precise error messages.
fn parse_layout_preset_ref<'a>(
    mut iter: impl Iterator<Item = &'a String>,
    sub: &str,
) -> Result<LayoutPresetRefArgs, ParseError> {
    let mut out = LayoutPresetRefArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(format!(
                    "layout-preset {sub} does not accept a '--' argv"
                )))
            }
            "--preset-id" => {
                if out.preset_id.is_some() {
                    return Err(ParseError::new(format!(
                        "layout-preset {sub} --preset-id may be given at most once"
                    )));
                }
                let raw = value_for(&mut iter, "--preset-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("layout-preset {sub} --preset-id is invalid: {e}"))
                })?;
                out.preset_id = Some(raw);
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(format!(
                        "layout-preset {sub} --base may be given at most once"
                    )));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown layout-preset {sub} flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.preset_id.is_none() {
        return Err(ParseError::new(format!(
            "layout-preset {sub} requires --preset-id <id>"
        )));
    }
    Ok(out)
}

/// Parse `layout-preset restore --preset-id <id> --window-id <id> [--base <dir>]`. Both `--preset-id`
/// and `--window-id` are required + safe-id-validated; `--base` optional + singleton; a `--` argv,
/// `--help`/`-h`, unknown flags, and duplicates are parse errors.
fn parse_layout_preset_restore<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<LayoutPresetRestoreArgs, ParseError> {
    let mut out = LayoutPresetRestoreArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "layout-preset restore does not accept a '--' argv",
                ))
            }
            "--preset-id" => {
                if out.preset_id.is_some() {
                    return Err(ParseError::new(
                        "layout-preset restore --preset-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--preset-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("layout-preset restore --preset-id is invalid: {e}"))
                })?;
                out.preset_id = Some(raw);
            }
            "--window-id" => {
                if out.window_id.is_some() {
                    return Err(ParseError::new(
                        "layout-preset restore --window-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--window-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("layout-preset restore --window-id is invalid: {e}"))
                })?;
                out.window_id = Some(raw);
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "layout-preset restore --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--socket" => {
                if out.socket.is_some() {
                    return Err(ParseError::new(
                        "layout-preset restore --socket may be given at most once",
                    ));
                }
                out.socket = Some(PathBuf::from(value_for(&mut iter, "--socket")?));
            }
            "--daemon" => {
                if out.daemon_bin.is_some() {
                    return Err(ParseError::new(
                        "layout-preset restore --daemon may be given at most once",
                    ));
                }
                out.daemon_bin = Some(PathBuf::from(value_for(&mut iter, "--daemon")?));
            }
            "--log-dir" => {
                if out.log_dir.is_some() {
                    return Err(ParseError::new(
                        "layout-preset restore --log-dir may be given at most once",
                    ));
                }
                out.log_dir = Some(PathBuf::from(value_for(&mut iter, "--log-dir")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown layout-preset restore flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.preset_id.is_none() {
        return Err(ParseError::new(
            "layout-preset restore requires --preset-id <id>",
        ));
    }
    if out.window_id.is_none() {
        return Err(ParseError::new(
            "layout-preset restore requires --window-id <id>",
        ));
    }
    Ok(out)
}

/// Parse `project <subcommand>`. Subcommands: `create`, `list`, `update`, `delete`, `reorder`.
fn parse_project<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<ProjectCommand, ParseError> {
    let Some(sub) = iter.next() else {
        return Err(ParseError::new(
            "project requires a subcommand (expected 'create', 'list', 'update', 'delete', or \
             'reorder')",
        ));
    };
    match sub.as_str() {
        "create" => parse_project_create(iter).map(ProjectCommand::Create),
        "list" => parse_project_list(iter).map(ProjectCommand::List),
        "update" => parse_project_update(iter).map(ProjectCommand::Update),
        "delete" => parse_project_delete(iter).map(ProjectCommand::Delete),
        "reorder" => parse_project_reorder(iter).map(ProjectCommand::Reorder),
        "--help" | "-h" => Err(ParseError::new("use 'maestro-app --help' for usage")),
        other => Err(ParseError::new(format!(
            "unknown project subcommand '{other}' (expected 'create', 'list', 'update', \
             'delete', or 'reorder')"
        ))),
    }
}

/// Validate a `--policy` token into the canonical wire string (`scratch_cwd`/`worktree`/
/// `repo_write`) the records layer serializes. Accepts hyphen or underscore spellings.
fn parse_project_policy(raw: &str) -> Result<String, ParseError> {
    match raw {
        "scratch" | "scratch-cwd" | "scratch_cwd" => Ok("scratch_cwd".into()),
        "worktree" => Ok("worktree".into()),
        "repo-write" | "repo_write" => Ok("repo_write".into()),
        other => Err(ParseError::new(format!(
            "project --policy must be 'scratch', 'worktree', or 'repo-write' (got '{other}')"
        ))),
    }
}

fn parse_project_create<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<ProjectCreateArgs, ParseError> {
    let mut out = ProjectCreateArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "project create does not accept a '--' argv",
                ))
            }
            "--project-id" => {
                if out.project_id.is_some() {
                    return Err(ParseError::new(
                        "project create --project-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--project-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("project create --project-id is invalid: {e}"))
                })?;
                out.project_id = Some(raw);
            }
            "--name" => {
                if out.name.is_some() {
                    return Err(ParseError::new(
                        "project create --name may be given at most once",
                    ));
                }
                out.name = Some(value_for(&mut iter, "--name")?);
            }
            "--root" => {
                if out.root.is_some() {
                    return Err(ParseError::new(
                        "project create --root may be given at most once",
                    ));
                }
                out.root = Some(value_for(&mut iter, "--root")?);
            }
            "--policy" => {
                if out.policy.is_some() {
                    return Err(ParseError::new(
                        "project create --policy may be given at most once",
                    ));
                }
                out.policy = Some(parse_project_policy(&value_for(&mut iter, "--policy")?)?);
            }
            "--icon" => {
                if out.icon.is_some() {
                    return Err(ParseError::new(
                        "project create --icon may be given at most once",
                    ));
                }
                out.icon = Some(value_for(&mut iter, "--icon")?);
            }
            "--accent" => {
                if out.accent_color.is_some() {
                    return Err(ParseError::new(
                        "project create --accent may be given at most once",
                    ));
                }
                out.accent_color = Some(value_for(&mut iter, "--accent")?);
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "project create --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown project create flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.project_id.is_none() {
        return Err(ParseError::new("project create requires --project-id <id>"));
    }
    if out.name.is_none() {
        return Err(ParseError::new("project create requires --name <text>"));
    }
    if out.root.is_none() {
        return Err(ParseError::new("project create requires --root <dir>"));
    }
    Ok(out)
}

fn parse_project_list<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<ProjectListArgs, ParseError> {
    let mut out = ProjectListArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => return Err(ParseError::new("project list does not accept a '--' argv")),
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "project list --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown project list flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    Ok(out)
}

fn parse_project_update<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<ProjectUpdateArgs, ParseError> {
    let mut out = ProjectUpdateArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "project update does not accept a '--' argv",
                ))
            }
            "--project-id" => {
                if out.project_id.is_some() {
                    return Err(ParseError::new(
                        "project update --project-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--project-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("project update --project-id is invalid: {e}"))
                })?;
                out.project_id = Some(raw);
            }
            "--name" => {
                if out.name.is_some() {
                    return Err(ParseError::new(
                        "project update --name may be given at most once",
                    ));
                }
                out.name = Some(value_for(&mut iter, "--name")?);
            }
            "--root" => {
                if out.root.is_some() {
                    return Err(ParseError::new(
                        "project update --root may be given at most once",
                    ));
                }
                out.root = Some(value_for(&mut iter, "--root")?);
            }
            "--policy" => {
                if out.policy.is_some() {
                    return Err(ParseError::new(
                        "project update --policy may be given at most once",
                    ));
                }
                out.policy = Some(parse_project_policy(&value_for(&mut iter, "--policy")?)?);
            }
            "--icon" => {
                if out.icon.is_some() || out.clear_icon {
                    return Err(ParseError::new(
                        "project update --icon conflicts with a prior --icon/--clear-icon",
                    ));
                }
                out.icon = Some(value_for(&mut iter, "--icon")?);
            }
            "--clear-icon" => {
                if out.icon.is_some() || out.clear_icon {
                    return Err(ParseError::new(
                        "project update --clear-icon conflicts with --icon",
                    ));
                }
                out.clear_icon = true;
            }
            "--accent" => {
                if out.accent_color.is_some() || out.clear_accent {
                    return Err(ParseError::new(
                        "project update --accent conflicts with a prior --accent/--clear-accent",
                    ));
                }
                out.accent_color = Some(value_for(&mut iter, "--accent")?);
            }
            "--clear-accent" => {
                if out.accent_color.is_some() || out.clear_accent {
                    return Err(ParseError::new(
                        "project update --clear-accent conflicts with --accent",
                    ));
                }
                out.clear_accent = true;
            }
            "--clear-launch-defaults" => {
                if out.clear_launch_defaults {
                    return Err(ParseError::new(
                        "project update --clear-launch-defaults may be given at most once",
                    ));
                }
                out.clear_launch_defaults = true;
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "project update --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown project update flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.project_id.is_none() {
        return Err(ParseError::new("project update requires --project-id <id>"));
    }
    Ok(out)
}

fn parse_project_delete<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<ProjectRefArgs, ParseError> {
    let mut out = ProjectRefArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "project delete does not accept a '--' argv",
                ))
            }
            "--project-id" => {
                if out.project_id.is_some() {
                    return Err(ParseError::new(
                        "project delete --project-id may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--project-id")?;
                maestro_shell::validate_id(&raw).map_err(|e| {
                    ParseError::new(format!("project delete --project-id is invalid: {e}"))
                })?;
                out.project_id = Some(raw);
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "project delete --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown project delete flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.project_id.is_none() {
        return Err(ParseError::new("project delete requires --project-id <id>"));
    }
    Ok(out)
}

fn parse_project_reorder<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<ProjectReorderArgs, ParseError> {
    let mut out = ProjectReorderArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "project reorder does not accept a '--' argv",
                ))
            }
            "--order" => {
                if out.order.is_some() {
                    return Err(ParseError::new(
                        "project reorder --order may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--order")?;
                if raw.is_empty() {
                    return Err(ParseError::new(
                        "project reorder --order must be a non-empty comma-separated list of \
                         project ids",
                    ));
                }
                let parts: Vec<String> = raw.split(',').map(|s| s.to_string()).collect();
                if parts.iter().any(|s| s.is_empty()) {
                    return Err(ParseError::new(
                        "project reorder --order must not contain empty comma segments",
                    ));
                }
                for id in &parts {
                    maestro_shell::validate_id(id).map_err(|e| {
                        ParseError::new(format!(
                            "project reorder --order id '{id}' is invalid: {e}"
                        ))
                    })?;
                }
                out.order = Some(parts);
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "project reorder --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown project reorder flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.order.is_none() {
        return Err(ParseError::new(
            "project reorder requires --order <id,id,...>",
        ));
    }
    Ok(out)
}

/// Parse the `attach-tab` command. `--window-id`/`--tab-id` are required; the socket/daemon/
/// renderer/log/lifecycle flags mirror `launch`. Singleton flags reject duplicates; unknown flags
/// and any post-`--` argv are usage errors (this command never starts a new session). `--title` is
/// validated up front and rejected under `--detach-renderer`, exactly like `launch`.
fn parse_attach_tab<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<AttachTabArgs, ParseError> {
    let mut out = AttachTabArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "attach-tab does not accept a '-- <command>' argv: it opens an existing \
                     session's tab, it never starts a new session",
                ))
            }
            "--window-id" => {
                if out.window_id.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --window-id may be given at most once",
                    ));
                }
                out.window_id = Some(value_for(&mut iter, "--window-id")?);
            }
            "--tab-id" => {
                if out.tab_id.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --tab-id may be given at most once",
                    ));
                }
                out.tab_id = Some(value_for(&mut iter, "--tab-id")?);
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--socket" => {
                if out.socket.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --socket may be given at most once",
                    ));
                }
                out.socket = Some(PathBuf::from(value_for(&mut iter, "--socket")?));
            }
            "--daemon" => {
                if out.daemon_bin.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --daemon may be given at most once",
                    ));
                }
                out.daemon_bin = Some(PathBuf::from(value_for(&mut iter, "--daemon")?));
            }
            "--renderer" => {
                if out.renderer_bin.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --renderer may be given at most once",
                    ));
                }
                out.renderer_bin = Some(PathBuf::from(value_for(&mut iter, "--renderer")?));
            }
            "--log-dir" => {
                if out.log_dir.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --log-dir may be given at most once",
                    ));
                }
                out.log_dir = Some(PathBuf::from(value_for(&mut iter, "--log-dir")?));
            }
            "--title" => {
                if out.title.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --title may be given at most once",
                    ));
                }
                out.title = Some(value_for(&mut iter, "--title")?);
            }
            "--no-run-renderer" => {
                if out.no_run_renderer {
                    return Err(ParseError::new(
                        "attach-tab --no-run-renderer may be given at most once",
                    ));
                }
                out.no_run_renderer = true;
            }
            "--detach-renderer" => {
                if out.detach_renderer {
                    return Err(ParseError::new(
                        "attach-tab --detach-renderer may be given at most once",
                    ));
                }
                out.detach_renderer = true;
            }
            "--keep-daemon" => {
                if out.keep_daemon {
                    return Err(ParseError::new(
                        "attach-tab --keep-daemon may be given at most once",
                    ));
                }
                out.keep_daemon = true;
            }
            "--top-tab-bar" => {
                if out.top_tab_bar {
                    return Err(ParseError::new(
                        "attach-tab --top-tab-bar may be given at most once",
                    ));
                }
                out.top_tab_bar = true;
            }
            "--no-top-tab-bar" => {
                if out.no_top_tab_bar {
                    return Err(ParseError::new(
                        "attach-tab --no-top-tab-bar may be given at most once",
                    ));
                }
                out.no_top_tab_bar = true;
            }
            "--new-tab-default-shell" => {
                if out.new_tab_default_shell {
                    return Err(ParseError::new(
                        "attach-tab --new-tab-default-shell may be given at most once",
                    ));
                }
                out.new_tab_default_shell = true;
            }
            "--new-tab-title" => {
                if out.new_tab_title.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --new-tab-title may be given at most once",
                    ));
                }
                out.new_tab_title = Some(value_for(&mut iter, "--new-tab-title")?);
            }
            "--new-tab-workspace-id" => {
                if out.new_tab_workspace_id.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --new-tab-workspace-id may be given at most once",
                    ));
                }
                out.new_tab_workspace_id = Some(value_for(&mut iter, "--new-tab-workspace-id")?);
            }
            "--dashboard-status" => {
                if out.dashboard_status {
                    return Err(ParseError::new(
                        "attach-tab --dashboard-status may be given at most once",
                    ));
                }
                out.dashboard_status = true;
            }
            "--no-dashboard-status" => {
                if out.no_dashboard_status {
                    return Err(ParseError::new(
                        "attach-tab --no-dashboard-status may be given at most once",
                    ));
                }
                out.no_dashboard_status = true;
            }
            "--dashboard-panel" => {
                if out.dashboard_panel {
                    return Err(ParseError::new(
                        "attach-tab --dashboard-panel may be given at most once",
                    ));
                }
                out.dashboard_panel = true;
            }
            "--no-dashboard-panel" => {
                if out.no_dashboard_panel {
                    return Err(ParseError::new(
                        "attach-tab --no-dashboard-panel may be given at most once",
                    ));
                }
                out.no_dashboard_panel = true;
            }
            "--picker-overlay" => {
                if out.picker_overlay {
                    return Err(ParseError::new(
                        "attach-tab --picker-overlay may be given at most once",
                    ));
                }
                out.picker_overlay = true;
            }
            "--no-picker-overlay" => {
                if out.no_picker_overlay {
                    return Err(ParseError::new(
                        "attach-tab --no-picker-overlay may be given at most once",
                    ));
                }
                out.no_picker_overlay = true;
            }
            "--settings-panel" => {
                if out.settings_panel {
                    return Err(ParseError::new(
                        "attach-tab --settings-panel may be given at most once",
                    ));
                }
                out.settings_panel = true;
            }
            "--command-palette" => {
                if out.command_palette {
                    return Err(ParseError::new(
                        "attach-tab --command-palette may be given at most once",
                    ));
                }
                out.command_palette = true;
            }
            "--command-palette-query" => {
                if out.command_palette_query.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --command-palette-query may be given at most once",
                    ));
                }
                let value = value_for(&mut iter, "--command-palette-query")?;
                if value.trim().is_empty() {
                    return Err(ParseError::new(
                        "attach-tab --command-palette-query must not be empty or whitespace-only",
                    ));
                }
                out.command_palette_query = Some(value);
            }
            "--file-preview" => {
                if out.file_preview.is_some() {
                    return Err(ParseError::new(
                        "attach-tab --file-preview may be given at most once",
                    ));
                }
                out.file_preview = Some(PathBuf::from(value_for(&mut iter, "--file-preview")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown attach-tab flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }

    if out.window_id.is_none() {
        return Err(ParseError::new("attach-tab requires --window-id"));
    }
    if out.tab_id.is_none() {
        return Err(ParseError::new("attach-tab requires --tab-id"));
    }

    // Same renderer-mode contract as launch: nothing to detach when no GUI is opened.
    if out.no_run_renderer && out.detach_renderer {
        return Err(ParseError::new(
            "--no-run-renderer and --detach-renderer are mutually exclusive (no renderer to detach)",
        ));
    }
    // The tri-state top-tab-bar flag distinguishes absent / explicit-enable / explicit-disable. Giving
    // both the enable and the disable is contradictory, so reject rather than pick a silent winner.
    if out.top_tab_bar && out.no_top_tab_bar {
        return Err(ParseError::new(
            "--top-tab-bar and --no-top-tab-bar are mutually exclusive",
        ));
    }
    // Same contradiction for the tri-state dashboard-status flag.
    if out.dashboard_status && out.no_dashboard_status {
        return Err(ParseError::new(
            "--dashboard-status and --no-dashboard-status are mutually exclusive",
        ));
    }
    // Same contradiction for the tri-state dashboard-panel flag.
    if out.dashboard_panel && out.no_dashboard_panel {
        return Err(ParseError::new(
            "--dashboard-panel and --no-dashboard-panel are mutually exclusive",
        ));
    }
    // A custom title only applies to the in-process foreground renderer; a detached child cannot set
    // it yet, so reject rather than silently drop it (mirrors launch).
    if out.title.is_some() && out.detach_renderer {
        return Err(ParseError::new(
            "--title is not supported with --detach-renderer (detached renderer cannot set the window title yet)",
        ));
    }
    if let Some(t) = &out.title {
        validate_window_title(t).map_err(ParseError::new)?;
    }
    // The top tab bar is drawn by the in-process foreground renderer from the app-owned tab strip.
    // A detached `maestro-renderer <socket> <session-id>` child never receives that strip, so the
    // flag cannot apply there: reject rather than silently drop it.
    if out.top_tab_bar && out.detach_renderer {
        return Err(ParseError::new(
            "--top-tab-bar is not supported with --detach-renderer (the detached renderer does not receive the app-owned tab strip)",
        ));
    }
    // The dashboard status summary is appended to the app-owned `status_label`, which only the
    // in-process foreground renderer paints. A detached `maestro-renderer <socket> <session-id>` child
    // never receives that label, so the flag cannot apply there: reject rather than silently drop it.
    // (Compatible with `--no-run-renderer`: no GUI opens, but the composed label is still reported in
    // the success JSON.)
    if out.dashboard_status && out.detach_renderer {
        return Err(ParseError::new(
            "--dashboard-status is not supported with --detach-renderer (the detached renderer does not receive the app-owned status label)",
        ));
    }
    // The dashboard panel is drawn as app-owned top chrome by the in-process foreground renderer. A
    // detached `maestro-renderer <socket> <session-id>` child launches via CLI and cannot carry the
    // app-computed panel data, so the ENABLE cannot apply there: reject rather than silently drop it.
    // (Compatible with `--no-run-renderer`: no GUI opens, but the computed panel is still reported in
    // the success JSON.) `--no-dashboard-panel` is accepted with `--detach-renderer` as a harmless
    // no-op (detached resolves the panel to `false` regardless), matching `--no-dashboard-status`.
    if out.dashboard_panel && out.detach_renderer {
        return Err(ParseError::new(
            "--dashboard-panel is not supported with --detach-renderer (the detached renderer cannot carry app-owned chrome data)",
        ));
    }
    // `--picker-overlay` (explicit enable) and `--no-picker-overlay` (explicit disable) are
    // contradictory; reject the pair rather than silently picking one.
    if out.picker_overlay && out.no_picker_overlay {
        return Err(ParseError::new(
            "--picker-overlay and --no-picker-overlay are mutually exclusive",
        ));
    }
    // The read-only picker overlay is drawn IN-PROCESS by the foreground renderer from app-owned model
    // data. A detached `maestro-renderer <socket> <session-id>` child cannot carry that model, and a
    // `--no-run-renderer` invocation opens no GUI at all, so the overlay cannot display in either mode:
    // reject the explicit ENABLE in both. `--no-picker-overlay` (disable) is accepted as a harmless
    // no-op there since those modes already resolve the overlay false.
    if out.picker_overlay && out.detach_renderer {
        return Err(ParseError::new(
            "--picker-overlay is not supported with --detach-renderer (the detached renderer cannot carry the app-owned picker overlay model)",
        ));
    }
    if out.picker_overlay && out.no_run_renderer {
        return Err(ParseError::new(
            "--picker-overlay is not supported with --no-run-renderer (the picker overlay needs the in-process foreground renderer to display)",
        ));
    }
    // The read-only settings panel is drawn as app-owned top chrome by the in-process foreground
    // renderer (and reported in the success JSON under `--no-run-renderer`). A detached
    // `maestro-renderer <socket> <session-id>` child carries no app-owned chrome, so the flag cannot
    // apply there: reject rather than silently drop it.
    if out.settings_panel && out.detach_renderer {
        return Err(ParseError::new(
            "--settings-panel is not supported with --detach-renderer (the detached renderer carries no app-owned chrome)",
        ));
    }
    // The settings panel and the dashboard panel both claim the single app-owned top-panel slot. To
    // avoid an ambiguous top-panel source, reject the explicit combination with EITHER the enable or
    // the disable side of the dashboard-panel tri-state.
    if out.settings_panel && out.dashboard_panel {
        return Err(ParseError::new(
            "--settings-panel and --dashboard-panel are mutually exclusive (one app-owned top panel at a time)",
        ));
    }
    if out.settings_panel && out.no_dashboard_panel {
        return Err(ParseError::new(
            "--settings-panel and --no-dashboard-panel are mutually exclusive (--settings-panel already selects the top panel source)",
        ));
    }
    // `--command-palette-query` only filters the command-palette overlay/model; without
    // `--command-palette` there is nothing to filter, so reject rather than silently drop it.
    if out.command_palette_query.is_some() && !out.command_palette {
        return Err(ParseError::new(
            "--command-palette-query requires --command-palette (it filters the command-palette overlay)",
        ));
    }
    // The read-only command palette is drawn IN-PROCESS by the foreground renderer from app-owned model
    // data (and reported in the success JSON under `--no-run-renderer`). A detached
    // `maestro-renderer <socket> <session-id>` child carries no app-owned model, so the overlay cannot
    // apply there: reject rather than silently drop it.
    if out.command_palette && out.detach_renderer {
        return Err(ParseError::new(
            "--command-palette is not supported with --detach-renderer (the detached renderer cannot carry the app-owned command-palette model)",
        ));
    }
    // The command palette and the picker overlay are both foreground modal overlays drawn over the grid;
    // allowing both would stack two modals. Reject the explicit ENABLE pair (the `--no-picker-overlay`
    // disable side is a harmless no-op and may coexist).
    if out.command_palette && out.picker_overlay {
        return Err(ParseError::new(
            "--command-palette and --picker-overlay are mutually exclusive (both are foreground modal overlays)",
        ));
    }
    // `--new-tab-title` only names the title of the explicit default-shell new-tab policy; without
    // `--new-tab-default-shell` there is no policy to title, so reject rather than silently drop it.
    if out.new_tab_title.is_some() && !out.new_tab_default_shell {
        return Err(ParseError::new(
            "--new-tab-title requires --new-tab-default-shell (it titles that explicit dev/test new-tab policy)",
        ));
    }
    // The explicit dev/test new-tab policy is tied to the only current visible `+` surface (the top
    // tab bar). Requiring `--top-tab-bar` keeps the opt-in from creating an unreachable policy.
    if out.new_tab_default_shell && !out.top_tab_bar {
        return Err(ParseError::new(
            "--new-tab-default-shell requires --top-tab-bar (the top tab bar is the only current visible '+' surface for the opt-in dev/test new-tab policy)",
        ));
    }
    // Same title validation as `--title`: non-empty, no control characters, bounded length.
    if let Some(t) = &out.new_tab_title {
        validate_window_title(t).map_err(ParseError::new)?;
    }
    // `--new-tab-workspace-id` overrides the IDENTITY of the explicit default-shell new-tab policy;
    // without `--new-tab-default-shell` there is no policy to stamp, so reject rather than silently
    // drop it (mirrors `--new-tab-title`).
    if out.new_tab_workspace_id.is_some() && !out.new_tab_default_shell {
        return Err(ParseError::new(
            "--new-tab-workspace-id requires --new-tab-default-shell (it overrides that explicit dev/test new-tab policy's workspace identity)",
        ));
    }
    // The workspace id becomes a single path component under app-support (scratch/worktree dirs and
    // `SessionRecord` files), so validate it as a safe id at parse time. A traversing/separator value
    // is rejected here rather than escaping a directory later.
    if let Some(ws) = &out.new_tab_workspace_id {
        maestro_shell::validate_id(ws)
            .map_err(|e| ParseError::new(format!("--new-tab-workspace-id is invalid: {e}")))?;
    }
    // The file preview is seeded through the in-process foreground renderer's command channel as
    // exactly one `SetFilePreview`. A detached `maestro-renderer <socket> <session-id>` child has no
    // such channel, so the preview could not be delivered: reject rather than silently drop it.
    // (Compatible with `--no-run-renderer`: no GUI opens, but the preview metadata is still reported
    // in the success JSON.)
    if out.file_preview.is_some() && out.detach_renderer {
        return Err(ParseError::new(
            "--file-preview is not supported with --detach-renderer (the detached renderer has no command channel to receive the preview)",
        ));
    }
    // The explicit dev/test new-tab default-shell policy drives a different new-tab renderer path that
    // does not carry the file preview; reject the combination rather than silently drop
    // the preview (mirrors launch).
    if out.file_preview.is_some() && out.new_tab_default_shell {
        return Err(ParseError::new(
            "--file-preview is not supported with --new-tab-default-shell (that new-tab launch path does not carry the preview)",
        ));
    }

    Ok(out)
}

/// Parse the `window` command: route to one of the four headless subcommands. A missing or unknown
/// subcommand is a usage error. Each subcommand parser enforces its own required/duplicate-flag and
/// no-`--`-argv rules.
fn parse_window<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowCommand, ParseError> {
    let Some(sub) = iter.next() else {
        return Err(ParseError::new(
            "window requires a subcommand (expected 'create', 'show', 'open-tab', 'split-tab', \
             'view', 'close-tab', 'rename-tab', 'pin-tab', 'reorder-tabs', or 'attention')",
        ));
    };
    match sub.as_str() {
        "create" => parse_window_create(iter).map(WindowCommand::Create),
        "show" => parse_window_show(iter).map(WindowCommand::Show),
        "open-tab" => parse_window_open_tab(iter).map(WindowCommand::OpenTab),
        "split-tab" => parse_window_split_tab(iter).map(WindowCommand::SplitTab),
        "view" => parse_window_view(iter).map(WindowCommand::View),
        "close-tab" => parse_window_close_tab(iter).map(WindowCommand::CloseTab),
        "rename-tab" => parse_window_rename_tab(iter).map(WindowCommand::RenameTab),
        "pin-tab" => parse_window_pin_tab(iter).map(WindowCommand::PinTab),
        "reorder-tabs" => parse_window_reorder_tabs(iter).map(WindowCommand::ReorderTabs),
        "attention" => parse_window_attention(iter).map(|a| WindowCommand::Attention(Box::new(a))),
        "attention-clear" => parse_window_attention_clear(iter).map(WindowCommand::AttentionClear),
        other => Err(ParseError::new(format!(
            "unknown window subcommand '{other}' (expected 'create', 'show', 'open-tab', \
             'split-tab', 'view', 'close-tab', 'rename-tab', 'pin-tab', 'reorder-tabs', \
             'attention', or 'attention-clear')"
        ))),
    }
}

/// Reject a duplicate `--window-id` for any window subcommand.
fn set_window_id(slot: &mut Option<String>, value: String) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::new(
            "window --window-id may be given at most once",
        ));
    }
    *slot = Some(value);
    Ok(())
}

/// Reject a duplicate `--base` for any window subcommand.
fn set_window_base(slot: &mut Option<PathBuf>, value: String) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::new("window --base may be given at most once"));
    }
    *slot = Some(PathBuf::from(value));
    Ok(())
}

fn parse_window_create<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowCreateArgs, ParseError> {
    let mut out = WindowCreateArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => return Err(ParseError::new("window create does not accept a '--' argv")),
            "--window-id" => {
                set_window_id(&mut out.window_id, value_for(&mut iter, "--window-id")?)?
            }
            "--base" => set_window_base(&mut out.base, value_for(&mut iter, "--base")?)?,
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown window create flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new("window create requires --window-id"));
    }
    Ok(out)
}

fn parse_window_show<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowShowArgs, ParseError> {
    let mut out = WindowShowArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => return Err(ParseError::new("window show does not accept a '--' argv")),
            "--window-id" => {
                set_window_id(&mut out.window_id, value_for(&mut iter, "--window-id")?)?
            }
            "--base" => set_window_base(&mut out.base, value_for(&mut iter, "--base")?)?,
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown window show flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new("window show requires --window-id"));
    }
    Ok(out)
}

fn parse_window_open_tab<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowOpenTabArgs, ParseError> {
    let mut out = WindowOpenTabArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "window open-tab does not accept a '--' argv",
                ))
            }
            "--window-id" => {
                set_window_id(&mut out.window_id, value_for(&mut iter, "--window-id")?)?
            }
            "--tab-id" => {
                if out.tab_id.is_some() {
                    return Err(ParseError::new("window --tab-id may be given at most once"));
                }
                out.tab_id = Some(value_for(&mut iter, "--tab-id")?);
            }
            "--session-id" => {
                if out.session_id.is_some() {
                    return Err(ParseError::new(
                        "window --session-id may be given at most once",
                    ));
                }
                out.session_id = Some(value_for(&mut iter, "--session-id")?);
            }
            "--title" => {
                if out.title.is_some() {
                    return Err(ParseError::new("window --title may be given at most once"));
                }
                out.title = Some(value_for(&mut iter, "--title")?);
            }
            "--base" => set_window_base(&mut out.base, value_for(&mut iter, "--base")?)?,
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown window open-tab flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new("window open-tab requires --window-id"));
    }
    if out.tab_id.is_none() {
        return Err(ParseError::new("window open-tab requires --tab-id"));
    }
    if out.session_id.is_none() {
        return Err(ParseError::new("window open-tab requires --session-id"));
    }
    if out.title.is_none() {
        return Err(ParseError::new("window open-tab requires --title"));
    }
    Ok(out)
}

fn parse_window_split_tab<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowSplitTabArgs, ParseError> {
    let mut out = WindowSplitTabArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "window split-tab does not accept a '--' argv",
                ))
            }
            "--window-id" => {
                set_window_id(&mut out.window_id, value_for(&mut iter, "--window-id")?)?
            }
            "--from-tab-id" => {
                if out.from_tab_id.is_some() {
                    return Err(ParseError::new(
                        "window --from-tab-id may be given at most once",
                    ));
                }
                out.from_tab_id = Some(value_for(&mut iter, "--from-tab-id")?);
            }
            "--tab-id" => {
                if out.tab_id.is_some() {
                    return Err(ParseError::new("window --tab-id may be given at most once"));
                }
                out.tab_id = Some(value_for(&mut iter, "--tab-id")?);
            }
            "--session-id" => {
                if out.session_id.is_some() {
                    return Err(ParseError::new(
                        "window --session-id may be given at most once",
                    ));
                }
                out.session_id = Some(value_for(&mut iter, "--session-id")?);
            }
            "--title" => {
                if out.title.is_some() {
                    return Err(ParseError::new("window --title may be given at most once"));
                }
                out.title = Some(value_for(&mut iter, "--title")?);
            }
            "--axis" => {
                if out.axis.is_some() {
                    return Err(ParseError::new("window --axis may be given at most once"));
                }
                let value = value_for(&mut iter, "--axis")?;
                if value != "right" && value != "down" {
                    return Err(ParseError::new(format!(
                        "window split-tab --axis must be 'right' or 'down' (got '{value}')"
                    )));
                }
                out.axis = Some(value);
            }
            "--base" => set_window_base(&mut out.base, value_for(&mut iter, "--base")?)?,
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown window split-tab flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new("window split-tab requires --window-id"));
    }
    if out.from_tab_id.is_none() {
        return Err(ParseError::new("window split-tab requires --from-tab-id"));
    }
    if out.tab_id.is_none() {
        return Err(ParseError::new("window split-tab requires --tab-id"));
    }
    if out.session_id.is_none() {
        return Err(ParseError::new("window split-tab requires --session-id"));
    }
    if out.title.is_none() {
        return Err(ParseError::new("window split-tab requires --title"));
    }
    if out.axis.is_none() {
        return Err(ParseError::new("window split-tab requires --axis"));
    }
    Ok(out)
}

fn parse_window_view<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowViewArgs, ParseError> {
    let mut out = WindowViewArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => return Err(ParseError::new("window view does not accept a '--' argv")),
            "--window-id" => {
                set_window_id(&mut out.window_id, value_for(&mut iter, "--window-id")?)?
            }
            "--base" => set_window_base(&mut out.base, value_for(&mut iter, "--base")?)?,
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown window view flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new("window view requires --window-id"));
    }
    Ok(out)
}

/// Reject a duplicate `--tab-id` for any window subcommand that takes one.
fn set_window_tab_id(slot: &mut Option<String>, value: String) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::new("window --tab-id may be given at most once"));
    }
    *slot = Some(value);
    Ok(())
}

/// Parse a strict boolean window flag value: only `true` or `false`.
fn parse_window_bool(flag: &str, raw: &str) -> Result<bool, ParseError> {
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(ParseError::new(format!(
            "window {flag} must be 'true' or 'false' (got '{other}')"
        ))),
    }
}

/// Validate an `--attention` value against the wire-stable snake_case states. Returned as the same
/// string so `main` (which owns the `maestro-shell` types) maps it; the parser keeps no shell dep.
fn parse_window_attention_value(raw: &str) -> Result<String, ParseError> {
    match raw {
        "none" | "activity" | "needs_input" | "error" | "done" => Ok(raw.to_string()),
        other => Err(ParseError::new(format!(
            "window --attention must be one of 'none|activity|needs_input|error|done' (got '{other}')"
        ))),
    }
}

/// Validate a `--source` value against the wire-stable snake_case sources.
fn parse_window_source_value(raw: &str) -> Result<String, ParseError> {
    match raw {
        "process" | "agent" | "user" => Ok(raw.to_string()),
        other => Err(ParseError::new(format!(
            "window --source must be one of 'process|agent|user' (got '{other}')"
        ))),
    }
}

/// Split an `--order` value into a non-empty comma-separated tab id list, rejecting an empty string
/// and any empty comma segment as a usage error (so an exact-permutation request can be validated
/// downstream by the service).
fn parse_window_order_value(raw: &str) -> Result<Vec<String>, ParseError> {
    if raw.is_empty() {
        return Err(ParseError::new(
            "window --order must be a non-empty comma-separated list of tab ids",
        ));
    }
    let parts: Vec<String> = raw.split(',').map(|s| s.to_string()).collect();
    if parts.iter().any(|s| s.is_empty()) {
        return Err(ParseError::new(
            "window --order must not contain empty comma segments",
        ));
    }
    Ok(parts)
}

fn parse_window_close_tab<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowTabRefArgs, ParseError> {
    let mut out = WindowTabRefArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "window close-tab does not accept a '--' argv",
                ))
            }
            "--window-id" => {
                set_window_id(&mut out.window_id, value_for(&mut iter, "--window-id")?)?
            }
            "--tab-id" => set_window_tab_id(&mut out.tab_id, value_for(&mut iter, "--tab-id")?)?,
            "--base" => set_window_base(&mut out.base, value_for(&mut iter, "--base")?)?,
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown window close-tab flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new("window close-tab requires --window-id"));
    }
    if out.tab_id.is_none() {
        return Err(ParseError::new("window close-tab requires --tab-id"));
    }
    Ok(out)
}

fn parse_window_attention_clear<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowTabRefArgs, ParseError> {
    let mut out = WindowTabRefArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "window attention-clear does not accept a '--' argv",
                ))
            }
            "--window-id" => {
                set_window_id(&mut out.window_id, value_for(&mut iter, "--window-id")?)?
            }
            "--tab-id" => set_window_tab_id(&mut out.tab_id, value_for(&mut iter, "--tab-id")?)?,
            "--base" => set_window_base(&mut out.base, value_for(&mut iter, "--base")?)?,
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown window attention-clear flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new(
            "window attention-clear requires --window-id",
        ));
    }
    if out.tab_id.is_none() {
        return Err(ParseError::new("window attention-clear requires --tab-id"));
    }
    Ok(out)
}

fn parse_window_rename_tab<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowRenameTabArgs, ParseError> {
    let mut out = WindowRenameTabArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "window rename-tab does not accept a '--' argv",
                ))
            }
            "--window-id" => {
                set_window_id(&mut out.window_id, value_for(&mut iter, "--window-id")?)?
            }
            "--tab-id" => set_window_tab_id(&mut out.tab_id, value_for(&mut iter, "--tab-id")?)?,
            "--title" => {
                if out.title.is_some() {
                    return Err(ParseError::new("window --title may be given at most once"));
                }
                out.title = Some(value_for(&mut iter, "--title")?);
            }
            "--base" => set_window_base(&mut out.base, value_for(&mut iter, "--base")?)?,
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown window rename-tab flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new("window rename-tab requires --window-id"));
    }
    if out.tab_id.is_none() {
        return Err(ParseError::new("window rename-tab requires --tab-id"));
    }
    if out.title.is_none() {
        return Err(ParseError::new("window rename-tab requires --title"));
    }
    Ok(out)
}

fn parse_window_pin_tab<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowPinTabArgs, ParseError> {
    let mut out = WindowPinTabArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "window pin-tab does not accept a '--' argv",
                ))
            }
            "--window-id" => {
                set_window_id(&mut out.window_id, value_for(&mut iter, "--window-id")?)?
            }
            "--tab-id" => set_window_tab_id(&mut out.tab_id, value_for(&mut iter, "--tab-id")?)?,
            "--pinned" => {
                if out.pinned.is_some() {
                    return Err(ParseError::new("window --pinned may be given at most once"));
                }
                out.pinned = Some(parse_window_bool(
                    "--pinned",
                    &value_for(&mut iter, "--pinned")?,
                )?);
            }
            "--base" => set_window_base(&mut out.base, value_for(&mut iter, "--base")?)?,
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown window pin-tab flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new("window pin-tab requires --window-id"));
    }
    if out.tab_id.is_none() {
        return Err(ParseError::new("window pin-tab requires --tab-id"));
    }
    if out.pinned.is_none() {
        return Err(ParseError::new(
            "window pin-tab requires --pinned <true|false>",
        ));
    }
    Ok(out)
}

fn parse_window_reorder_tabs<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowReorderTabsArgs, ParseError> {
    let mut out = WindowReorderTabsArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "window reorder-tabs does not accept a '--' argv",
                ))
            }
            "--window-id" => {
                set_window_id(&mut out.window_id, value_for(&mut iter, "--window-id")?)?
            }
            "--order" => {
                if out.order.is_some() {
                    return Err(ParseError::new("window --order may be given at most once"));
                }
                out.order = Some(parse_window_order_value(&value_for(&mut iter, "--order")?)?);
            }
            "--base" => set_window_base(&mut out.base, value_for(&mut iter, "--base")?)?,
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown window reorder-tabs flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new("window reorder-tabs requires --window-id"));
    }
    if out.order.is_none() {
        return Err(ParseError::new(
            "window reorder-tabs requires --order <tab1,tab2,...>",
        ));
    }
    Ok(out)
}

fn parse_window_attention<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<WindowAttentionArgs, ParseError> {
    let mut out = WindowAttentionArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                return Err(ParseError::new(
                    "window attention does not accept a '--' argv",
                ))
            }
            "--window-id" => {
                set_window_id(&mut out.window_id, value_for(&mut iter, "--window-id")?)?
            }
            "--tab-id" => set_window_tab_id(&mut out.tab_id, value_for(&mut iter, "--tab-id")?)?,
            "--attention" => {
                if out.attention.is_some() {
                    return Err(ParseError::new(
                        "window --attention may be given at most once",
                    ));
                }
                out.attention = Some(parse_window_attention_value(&value_for(
                    &mut iter,
                    "--attention",
                )?)?);
            }
            "--unseen" => {
                if out.unseen.is_some() {
                    return Err(ParseError::new("window --unseen may be given at most once"));
                }
                out.unseen = Some(parse_window_bool(
                    "--unseen",
                    &value_for(&mut iter, "--unseen")?,
                )?);
            }
            "--source" => {
                if out.source.is_some() {
                    return Err(ParseError::new("window --source may be given at most once"));
                }
                out.source = Some(parse_window_source_value(&value_for(
                    &mut iter, "--source",
                )?)?);
            }
            "--since-ms" => {
                if out.since_ms.is_some() {
                    return Err(ParseError::new(
                        "window --since-ms may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--since-ms")?;
                let v = raw.parse::<u64>().map_err(|_| {
                    ParseError::new(format!("window --since-ms requires a u64 (got '{raw}')"))
                })?;
                out.since_ms = Some(v);
            }
            "--base" => set_window_base(&mut out.base, value_for(&mut iter, "--base")?)?,
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown window attention flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.window_id.is_none() {
        return Err(ParseError::new("window attention requires --window-id"));
    }
    if out.tab_id.is_none() {
        return Err(ParseError::new("window attention requires --tab-id"));
    }
    if out.attention.is_none() {
        return Err(ParseError::new(
            "window attention requires --attention <none|activity|needs_input|error|done>",
        ));
    }
    if out.unseen.is_none() {
        return Err(ParseError::new(
            "window attention requires --unseen <true|false>",
        ));
    }
    Ok(out)
}

/// Parse a `u16` flag value, mapping a non-numeric or out-of-range value to a usage error.
fn parse_u16(raw: &str, flag: &str) -> Result<u16, ParseError> {
    raw.parse::<u16>().map_err(|_| {
        ParseError::new(format!(
            "flag '{flag}' requires an integer in 1..=65535 (got '{raw}')"
        ))
    })
}

fn parse_launch<'a>(mut iter: impl Iterator<Item = &'a String>) -> Result<LaunchArgs, ParseError> {
    let mut out = LaunchArgs::default();

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                // Everything after `--` is the session argv, taken verbatim.
                out.session_argv = iter.map(|s| s.to_string()).collect();
                break;
            }
            "--no-run-renderer" => out.no_run_renderer = true,
            "--detach-renderer" => out.detach_renderer = true,
            "--keep-daemon" => out.keep_daemon = true,
            "--product-startup" => {
                if out.product_startup {
                    return Err(ParseError::new(
                        "--product-startup may be given at most once",
                    ));
                }
                out.product_startup = true;
            }
            "--record-window" => {
                if out.record_window {
                    return Err(ParseError::new("--record-window may be given at most once"));
                }
                out.record_window = true;
            }
            "--fresh-window" => {
                if out.fresh_window {
                    return Err(ParseError::new("--fresh-window may be given at most once"));
                }
                out.fresh_window = true;
            }
            "--window-id" => {
                if out.record_window_id.is_some() {
                    return Err(ParseError::new("--window-id may be given at most once"));
                }
                out.record_window_id = Some(value_for(&mut iter, "--window-id")?);
            }
            "--tab-id" => {
                if out.record_tab_id.is_some() {
                    return Err(ParseError::new("--tab-id may be given at most once"));
                }
                out.record_tab_id = Some(value_for(&mut iter, "--tab-id")?);
            }
            "--tab-title" => {
                if out.record_tab_title.is_some() {
                    return Err(ParseError::new("--tab-title may be given at most once"));
                }
                out.record_tab_title = Some(value_for(&mut iter, "--tab-title")?);
            }
            "--tab-pinned" => {
                if out.record_tab_pinned.is_some() {
                    return Err(ParseError::new("--tab-pinned may be given at most once"));
                }
                let raw = value_for(&mut iter, "--tab-pinned")?;
                out.record_tab_pinned = Some(parse_launch_bool("--tab-pinned", &raw)?);
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            "--socket" => out.socket = Some(PathBuf::from(value_for(&mut iter, "--socket")?)),
            "--session-id" => out.session_id = Some(value_for(&mut iter, "--session-id")?),
            "--title" => out.title = Some(value_for(&mut iter, "--title")?),
            "--cwd" => out.cwd = Some(PathBuf::from(value_for(&mut iter, "--cwd")?)),
            "--base" => out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?)),
            "--log-dir" => out.log_dir = Some(PathBuf::from(value_for(&mut iter, "--log-dir")?)),
            "--daemon" => out.daemon_bin = Some(PathBuf::from(value_for(&mut iter, "--daemon")?)),
            "--renderer" => {
                out.renderer_bin = Some(PathBuf::from(value_for(&mut iter, "--renderer")?))
            }
            "--top-tab-bar" => {
                if out.top_tab_bar {
                    return Err(ParseError::new("--top-tab-bar may be given at most once"));
                }
                out.top_tab_bar = true;
            }
            "--no-top-tab-bar" => {
                if out.no_top_tab_bar {
                    return Err(ParseError::new(
                        "--no-top-tab-bar may be given at most once",
                    ));
                }
                out.no_top_tab_bar = true;
            }
            "--dashboard-status" => {
                if out.dashboard_status {
                    return Err(ParseError::new(
                        "--dashboard-status may be given at most once",
                    ));
                }
                out.dashboard_status = true;
            }
            "--no-dashboard-status" => {
                if out.no_dashboard_status {
                    return Err(ParseError::new(
                        "--no-dashboard-status may be given at most once",
                    ));
                }
                out.no_dashboard_status = true;
            }
            "--dashboard-panel" => {
                if out.dashboard_panel {
                    return Err(ParseError::new(
                        "--dashboard-panel may be given at most once",
                    ));
                }
                out.dashboard_panel = true;
            }
            "--no-dashboard-panel" => {
                if out.no_dashboard_panel {
                    return Err(ParseError::new(
                        "--no-dashboard-panel may be given at most once",
                    ));
                }
                out.no_dashboard_panel = true;
            }
            "--new-tab-default-shell" => {
                if out.new_tab_default_shell {
                    return Err(ParseError::new(
                        "--new-tab-default-shell may be given at most once",
                    ));
                }
                out.new_tab_default_shell = true;
            }
            "--new-tab-title" => {
                if out.new_tab_title.is_some() {
                    return Err(ParseError::new("--new-tab-title may be given at most once"));
                }
                out.new_tab_title = Some(value_for(&mut iter, "--new-tab-title")?);
            }
            "--new-tab-workspace-id" => {
                if out.new_tab_workspace_id.is_some() {
                    return Err(ParseError::new(
                        "--new-tab-workspace-id may be given at most once",
                    ));
                }
                out.new_tab_workspace_id = Some(value_for(&mut iter, "--new-tab-workspace-id")?);
            }
            "--file-preview" => {
                if out.file_preview.is_some() {
                    return Err(ParseError::new("--file-preview may be given at most once"));
                }
                out.file_preview = Some(PathBuf::from(value_for(&mut iter, "--file-preview")?));
            }
            other => {
                return Err(ParseError::new(format!(
                    "unknown launch flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }

    // `--detach-renderer` only makes sense when a renderer is actually launched.
    if out.no_run_renderer && out.detach_renderer {
        return Err(ParseError::new(
            "--no-run-renderer and --detach-renderer are mutually exclusive (no renderer to detach)",
        ));
    }

    // A custom title only applies to the foreground in-process renderer. Detached mode spawns the
    // bare `maestro-renderer <socket> <id>` child, which has no title argument yet, so accepting
    // `--title` there would silently drop it — reject instead to keep the contract honest.
    if out.title.is_some() && out.detach_renderer {
        return Err(ParseError::new(
            "--title is not supported with --detach-renderer (detached renderer cannot set the window title yet)",
        ));
    }

    // Validate any explicit title up front so a bad title is a usage error, not a late failure.
    if let Some(t) = &out.title {
        validate_window_title(t).map_err(ParseError::new)?;
    }

    // The window-layout recording flags are only meaningful when `--record-window` opts in. Without
    // it, a stray `--window-id`/`--tab-id`/`--tab-title`/`--tab-pinned`/`--fresh-window` is a usage
    // error rather than a silently ignored flag, keeping the default launch contract honest.
    if !out.record_window {
        for (flag, present) in [
            ("--window-id", out.record_window_id.is_some()),
            ("--tab-id", out.record_tab_id.is_some()),
            ("--tab-title", out.record_tab_title.is_some()),
            ("--tab-pinned", out.record_tab_pinned.is_some()),
            ("--fresh-window", out.fresh_window),
        ] {
            if present {
                return Err(ParseError::new(format!("{flag} requires --record-window")));
            }
        }
    }

    // Installed-product startup owns one stable built-in Terminal project/window/tab/session. The
    // generic recording/session overrides would create a second identity or erase/retarget the
    // stable topology, while detached mode cannot provide the record-bound dashboard listener.
    if out.product_startup {
        for (flag, present) in [
            ("--record-window", out.record_window),
            ("--session-id", out.session_id.is_some()),
            ("--cwd", out.cwd.is_some()),
            ("--detach-renderer", out.detach_renderer),
        ] {
            if present {
                return Err(ParseError::new(format!(
                    "--product-startup is mutually exclusive with {flag}"
                )));
            }
        }
        if !out.session_argv.is_empty() {
            return Err(ParseError::new(
                "--product-startup does not accept a session command after -- (it owns the stable Terminal launch)",
            ));
        }
    }

    // The tri-state top-tab-bar flag distinguishes absent / explicit-enable / explicit-disable. Giving
    // both the enable and the disable is contradictory, so reject rather than pick a silent winner.
    // (Same policy as `attach-tab`.)
    if out.top_tab_bar && out.no_top_tab_bar {
        return Err(ParseError::new(
            "--top-tab-bar and --no-top-tab-bar are mutually exclusive",
        ));
    }
    // The top tab bar is drawn by the in-process foreground renderer from the app-owned tab strip. A
    // detached `maestro-renderer <socket> <session-id>` child never receives that strip, so the flag
    // cannot apply there: reject rather than silently drop it. (Same policy as `attach-tab`.)
    if out.top_tab_bar && out.detach_renderer {
        return Err(ParseError::new(
            "--top-tab-bar is not supported with --detach-renderer (the detached renderer does not receive the app-owned tab strip)",
        ));
    }
    // `--new-tab-title` only names the title of the explicit default-shell new-tab policy; without
    // `--new-tab-default-shell` there is no policy to title, so reject rather than silently drop it.
    if out.new_tab_title.is_some() && !out.new_tab_default_shell {
        return Err(ParseError::new(
            "--new-tab-title requires --new-tab-default-shell (it titles that explicit dev/test new-tab policy)",
        ));
    }
    // The explicit dev/test new-tab policy is tied to the only current visible `+` surface (the top
    // tab bar). Requiring `--top-tab-bar` keeps the opt-in from creating an unreachable policy.
    if out.new_tab_default_shell && !out.top_tab_bar {
        return Err(ParseError::new(
            "--new-tab-default-shell requires --top-tab-bar (the top tab bar is the only current visible '+' surface for the opt-in dev/test new-tab policy)",
        ));
    }
    // Same title validation as `--title`: non-empty, no control characters, bounded length.
    if let Some(t) = &out.new_tab_title {
        validate_window_title(t).map_err(ParseError::new)?;
    }
    // `--new-tab-workspace-id` overrides the IDENTITY of the explicit default-shell new-tab policy;
    // without `--new-tab-default-shell` there is no policy to stamp, so reject rather than silently
    // drop it (mirrors `--new-tab-title`).
    if out.new_tab_workspace_id.is_some() && !out.new_tab_default_shell {
        return Err(ParseError::new(
            "--new-tab-workspace-id requires --new-tab-default-shell (it overrides that explicit dev/test new-tab policy's workspace identity)",
        ));
    }
    // The workspace id becomes a single path component under app-support, so validate it as a safe id
    // at parse time (mirrors `attach-tab`).
    if let Some(ws) = &out.new_tab_workspace_id {
        maestro_shell::validate_id(ws)
            .map_err(|e| ParseError::new(format!("--new-tab-workspace-id is invalid: {e}")))?;
    }

    // The file preview is painted by the in-process foreground renderer via its command channel. A
    // detached `maestro-renderer <socket> <id>` child has no such channel, so the preview could not be
    // sent — reject rather than silently drop it. (`--no-run-renderer` IS allowed: it reports the
    // requested path/status on the JSON without opening a GUI.)
    if out.file_preview.is_some() && out.detach_renderer {
        return Err(ParseError::new(
            "--file-preview is not supported with --detach-renderer (the detached renderer has no command channel to receive the preview)",
        ));
    }
    // The explicit `--new-tab-default-shell` launch drives a different foreground renderer path (one
    // wired for the `+` new-tab pipeline) that does not carry the file preview. Reject
    // the combination rather than silently dropping the requested preview.
    if out.file_preview.is_some() && out.new_tab_default_shell {
        return Err(ParseError::new(
            "--file-preview is not supported with --new-tab-default-shell (that launch uses the new-tab renderer path, which does not carry the preview)",
        ));
    }

    Ok(out)
}

/// Strict boolean for launch flags (`--tab-pinned`): only the literals `true`/`false`. Mirrors the
/// `window` command bool policy but with a launch-stamped message. Pure.
fn parse_launch_bool(flag: &str, raw: &str) -> Result<bool, ParseError> {
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(ParseError::new(format!(
            "{flag} must be 'true' or 'false' (got '{other}')"
        ))),
    }
}

/// Resolve a required flag value (the next token) or error if missing.
fn value_for<'a>(
    iter: &mut impl Iterator<Item = &'a String>,
    flag: &str,
) -> Result<String, ParseError> {
    iter.next()
        .map(|s| s.to_string())
        .ok_or_else(|| ParseError::new(format!("flag '{flag}' requires a value")))
}

/// Parse `agent-mark --agent-task-id <id> (--waiting-on-user | --blocked) --reason <text>
/// [--base <dir>]`.
///
/// Rules: `--agent-task-id` required + singleton; exactly one of `--waiting-on-user` / `--blocked`
/// (mutually exclusive, neither repeatable); `--reason` required + singleton + non-empty after
/// trimming and bounded to [`AGENT_MARK_REASON_MAX_LEN`] chars; `--base` optional + singleton. A
/// `--` argv, post-`--` tokens, `--help`, unknown flags, and duplicate flags are all parse errors.
fn parse_agent_mark<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<AgentMarkArgs, ParseError> {
    let mut out = AgentMarkArgs::default();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => return Err(ParseError::new("agent-mark does not accept a '--' argv")),
            "--agent-task-id" => {
                if out.agent_task_id.is_some() {
                    return Err(ParseError::new(
                        "agent-mark --agent-task-id may be given at most once",
                    ));
                }
                out.agent_task_id = Some(value_for(&mut iter, "--agent-task-id")?);
            }
            "--waiting-on-user" => {
                set_agent_mark_intent(&mut out.intent, AgentMarkIntent::WaitingOnUser)?;
            }
            "--blocked" => {
                set_agent_mark_intent(&mut out.intent, AgentMarkIntent::Blocked)?;
            }
            "--reason" => {
                if out.reason.is_some() {
                    return Err(ParseError::new(
                        "agent-mark --reason may be given at most once",
                    ));
                }
                let raw = value_for(&mut iter, "--reason")?;
                let trimmed = raw.trim();
                if trimmed.is_empty() {
                    return Err(ParseError::new("agent-mark --reason must not be empty"));
                }
                if trimmed.chars().count() > AGENT_MARK_REASON_MAX_LEN {
                    return Err(ParseError::new(format!(
                        "agent-mark --reason must be at most {AGENT_MARK_REASON_MAX_LEN} characters"
                    )));
                }
                out.reason = Some(trimmed.to_string());
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "agent-mark --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown agent-mark flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.agent_task_id.is_none() {
        return Err(ParseError::new("agent-mark requires --agent-task-id"));
    }
    if out.intent.is_none() {
        return Err(ParseError::new(
            "agent-mark requires exactly one of --waiting-on-user or --blocked",
        ));
    }
    if out.reason.is_none() {
        return Err(ParseError::new("agent-mark requires --reason <text>"));
    }
    Ok(out)
}

/// Set the `agent-mark` intent exactly once. A second intent flag (whether the same or the other) is
/// a parse error, enforcing "exactly one of --waiting-on-user / --blocked".
fn set_agent_mark_intent(
    slot: &mut Option<AgentMarkIntent>,
    intent: AgentMarkIntent,
) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::new(
            "agent-mark accepts exactly one of --waiting-on-user or --blocked",
        ));
    }
    *slot = Some(intent);
    Ok(())
}

/// Parse `agent-finish --agent-task-id <id> (--succeeded | --failed | --cancelled)
/// [--summary <text>] [--base <dir>]`.
///
/// Rules: `--agent-task-id` required + singleton; exactly one of `--succeeded` / `--failed` /
/// `--cancelled` (mutually exclusive, none repeatable); `--summary` optional + singleton, trimmed,
/// bounded to [`AGENT_FINISH_SUMMARY_MAX_LEN`] chars, and stored as `None` when empty after
/// trimming; `--base` optional + singleton. A `--` argv, post-`--` tokens, `--help`, unknown flags,
/// and duplicate flags are all parse errors.
fn parse_agent_finish<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<AgentFinishArgs, ParseError> {
    let mut out = AgentFinishArgs::default();
    let mut saw_summary = false;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => return Err(ParseError::new("agent-finish does not accept a '--' argv")),
            "--agent-task-id" => {
                if out.agent_task_id.is_some() {
                    return Err(ParseError::new(
                        "agent-finish --agent-task-id may be given at most once",
                    ));
                }
                out.agent_task_id = Some(value_for(&mut iter, "--agent-task-id")?);
            }
            "--succeeded" => {
                set_agent_finish_intent(&mut out.intent, AgentFinishIntent::Succeeded)?;
            }
            "--failed" => {
                set_agent_finish_intent(&mut out.intent, AgentFinishIntent::Failed)?;
            }
            "--cancelled" => {
                set_agent_finish_intent(&mut out.intent, AgentFinishIntent::Cancelled)?;
            }
            "--summary" => {
                if saw_summary {
                    return Err(ParseError::new(
                        "agent-finish --summary may be given at most once",
                    ));
                }
                saw_summary = true;
                let raw = value_for(&mut iter, "--summary")?;
                let trimmed = raw.trim();
                if trimmed.chars().count() > AGENT_FINISH_SUMMARY_MAX_LEN {
                    return Err(ParseError::new(format!(
                        "agent-finish --summary must be at most \
                         {AGENT_FINISH_SUMMARY_MAX_LEN} characters"
                    )));
                }
                // Empty-after-trim is stored as None (no summary).
                out.summary = if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                };
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "agent-finish --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown agent-finish flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    if out.agent_task_id.is_none() {
        return Err(ParseError::new("agent-finish requires --agent-task-id"));
    }
    if out.intent.is_none() {
        return Err(ParseError::new(
            "agent-finish requires exactly one of --succeeded, --failed, or --cancelled",
        ));
    }
    Ok(out)
}

/// Set the `agent-finish` terminal intent exactly once. A second intent flag (whether the same or a
/// different one) is a parse error, enforcing "exactly one of --succeeded / --failed / --cancelled".
fn set_agent_finish_intent(
    slot: &mut Option<AgentFinishIntent>,
    intent: AgentFinishIntent,
) -> Result<(), ParseError> {
    if slot.is_some() {
        return Err(ParseError::new(
            "agent-finish accepts exactly one of --succeeded, --failed, or --cancelled",
        ));
    }
    *slot = Some(intent);
    Ok(())
}

fn parse_dashboard<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<DashboardArgs, ParseError> {
    let mut out = DashboardArgs::default();
    let mut saw_reconcile = false;
    let mut saw_active_tasks = false;
    let mut saw_task_results = false;
    let mut saw_view_model = false;
    let mut saw_panel_lines = false;
    let mut saw_picker = false;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--active-tasks" => {
                if saw_active_tasks {
                    return Err(ParseError::new(
                        "dashboard --active-tasks may be given at most once",
                    ));
                }
                saw_active_tasks = true;
                out.active_tasks = true;
            }
            "--task-results" => {
                if saw_task_results {
                    return Err(ParseError::new(
                        "dashboard --task-results may be given at most once",
                    ));
                }
                saw_task_results = true;
                out.task_results = true;
            }
            "--view-model" => {
                if saw_view_model {
                    return Err(ParseError::new(
                        "dashboard --view-model may be given at most once",
                    ));
                }
                saw_view_model = true;
                out.view_model = true;
            }
            "--panel-lines" => {
                if saw_panel_lines {
                    return Err(ParseError::new(
                        "dashboard --panel-lines may be given at most once",
                    ));
                }
                saw_panel_lines = true;
                out.panel_lines = true;
            }
            "--picker" => {
                if saw_picker {
                    return Err(ParseError::new(
                        "dashboard --picker may be given at most once",
                    ));
                }
                saw_picker = true;
                out.picker = true;
            }
            "--base" => {
                if out.base.is_some() {
                    return Err(ParseError::new(
                        "dashboard --base may be given at most once",
                    ));
                }
                out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?));
            }
            "--socket" => {
                if out.socket.is_some() {
                    return Err(ParseError::new(
                        "dashboard --socket may be given at most once",
                    ));
                }
                out.socket = Some(PathBuf::from(value_for(&mut iter, "--socket")?));
            }
            "--with-session-reconcile" => {
                if saw_reconcile {
                    return Err(ParseError::new(
                        "dashboard --with-session-reconcile may be given at most once",
                    ));
                }
                saw_reconcile = true;
                out.with_session_reconcile = true;
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown dashboard flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    // `--active-tasks`, `--task-results`, `--view-model`, `--panel-lines`, and `--picker` each replace
    // the `snapshot` payload with a different compact projection, so at most one may apply per
    // invocation.
    if (out.active_tasks as u8)
        + (out.task_results as u8)
        + (out.view_model as u8)
        + (out.panel_lines as u8)
        + (out.picker as u8)
        > 1
    {
        return Err(ParseError::new(
            "dashboard --active-tasks, --task-results, --view-model, --panel-lines, and --picker are \
             mutually exclusive",
        ));
    }
    // `--socket` is meaningful only on the daemon-aware path; on its own it would silently never
    // connect, so reject it to keep the default command honestly local-only.
    if out.socket.is_some() && !out.with_session_reconcile {
        return Err(ParseError::new(
            "dashboard --socket requires --with-session-reconcile: the default dashboard is \
             local-only and never connects to the daemon",
        ));
    }
    Ok(out)
}

fn parse_agent_start<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<AgentStartArgs, ParseError> {
    let mut out = AgentStartArgs::default();
    let mut saw_dashdash = false;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                out.agent_argv = iter.map(|s| s.to_string()).collect();
                saw_dashdash = true;
                break;
            }
            "--agent-task-id" => out.agent_task_id = Some(value_for(&mut iter, "--agent-task-id")?),
            "--project-id" => out.project_id = Some(value_for(&mut iter, "--project-id")?),
            "--goal" => out.goal = Some(value_for(&mut iter, "--goal")?),
            "--session-id" => out.session_id = Some(value_for(&mut iter, "--session-id")?),
            "--workspace-id" => out.workspace_id = Some(value_for(&mut iter, "--workspace-id")?),
            "--cwd" => out.cwd = Some(PathBuf::from(value_for(&mut iter, "--cwd")?)),
            "--base" => out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?)),
            "--socket" => out.socket = Some(PathBuf::from(value_for(&mut iter, "--socket")?)),
            "--daemon" => out.daemon_bin = Some(PathBuf::from(value_for(&mut iter, "--daemon")?)),
            "--log-dir" => out.log_dir = Some(PathBuf::from(value_for(&mut iter, "--log-dir")?)),
            "--cols" => out.cols = Some(parse_u16(&value_for(&mut iter, "--cols")?, "--cols")?),
            "--rows" => out.rows = Some(parse_u16(&value_for(&mut iter, "--rows")?, "--rows")?),
            "--keep-daemon" => out.keep_daemon = true,
            "--record-window" => {
                if out.record_window {
                    return Err(ParseError::new("--record-window may be given at most once"));
                }
                out.record_window = true;
            }
            "--window-id" => {
                if out.record_window_id.is_some() {
                    return Err(ParseError::new("--window-id may be given at most once"));
                }
                out.record_window_id = Some(value_for(&mut iter, "--window-id")?);
            }
            "--tab-id" => {
                if out.record_tab_id.is_some() {
                    return Err(ParseError::new("--tab-id may be given at most once"));
                }
                out.record_tab_id = Some(value_for(&mut iter, "--tab-id")?);
            }
            "--tab-title" => {
                if out.record_tab_title.is_some() {
                    return Err(ParseError::new("--tab-title may be given at most once"));
                }
                out.record_tab_title = Some(value_for(&mut iter, "--tab-title")?);
            }
            "--tab-pinned" => {
                if out.record_tab_pinned.is_some() {
                    return Err(ParseError::new("--tab-pinned may be given at most once"));
                }
                let raw = value_for(&mut iter, "--tab-pinned")?;
                out.record_tab_pinned = Some(parse_launch_bool("--tab-pinned", &raw)?);
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            other => {
                return Err(ParseError::new(format!(
                    "unknown agent-start flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    require_agent_argv(saw_dashdash, &out.agent_argv, "agent-start")?;

    // The window-layout recording flags are only meaningful when `--record-window` opts in. Without
    // it, a stray `--window-id`/`--tab-id`/`--tab-title`/`--tab-pinned` is a usage error rather than
    // a silently ignored flag, keeping the default agent-start contract honest.
    if !out.record_window {
        for (flag, present) in [
            ("--window-id", out.record_window_id.is_some()),
            ("--tab-id", out.record_tab_id.is_some()),
            ("--tab-title", out.record_tab_title.is_some()),
            ("--tab-pinned", out.record_tab_pinned.is_some()),
        ] {
            if present {
                return Err(ParseError::new(format!("{flag} requires --record-window")));
            }
        }
    }

    Ok(out)
}

fn parse_agent_resume<'a>(
    mut iter: impl Iterator<Item = &'a String>,
) -> Result<AgentResumeArgs, ParseError> {
    let mut out = AgentResumeArgs::default();
    let mut saw_dashdash = false;
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                out.agent_argv = iter.map(|s| s.to_string()).collect();
                saw_dashdash = true;
                break;
            }
            "--agent-task-id" => out.agent_task_id = Some(value_for(&mut iter, "--agent-task-id")?),
            "--session-id" => out.session_id = Some(value_for(&mut iter, "--session-id")?),
            "--workspace-id" => out.workspace_id = Some(value_for(&mut iter, "--workspace-id")?),
            "--cwd" => out.cwd = Some(PathBuf::from(value_for(&mut iter, "--cwd")?)),
            "--base" => out.base = Some(PathBuf::from(value_for(&mut iter, "--base")?)),
            "--socket" => out.socket = Some(PathBuf::from(value_for(&mut iter, "--socket")?)),
            "--daemon" => out.daemon_bin = Some(PathBuf::from(value_for(&mut iter, "--daemon")?)),
            "--log-dir" => out.log_dir = Some(PathBuf::from(value_for(&mut iter, "--log-dir")?)),
            "--cols" => out.cols = Some(parse_u16(&value_for(&mut iter, "--cols")?, "--cols")?),
            "--rows" => out.rows = Some(parse_u16(&value_for(&mut iter, "--rows")?, "--rows")?),
            "--keep-daemon" => out.keep_daemon = true,
            "--record-window" => {
                if out.record_window {
                    return Err(ParseError::new("--record-window may be given at most once"));
                }
                out.record_window = true;
            }
            "--window-id" => {
                if out.record_window_id.is_some() {
                    return Err(ParseError::new("--window-id may be given at most once"));
                }
                out.record_window_id = Some(value_for(&mut iter, "--window-id")?);
            }
            "--tab-id" => {
                if out.record_tab_id.is_some() {
                    return Err(ParseError::new("--tab-id may be given at most once"));
                }
                out.record_tab_id = Some(value_for(&mut iter, "--tab-id")?);
            }
            "--tab-title" => {
                if out.record_tab_title.is_some() {
                    return Err(ParseError::new("--tab-title may be given at most once"));
                }
                out.record_tab_title = Some(value_for(&mut iter, "--tab-title")?);
            }
            "--tab-pinned" => {
                if out.record_tab_pinned.is_some() {
                    return Err(ParseError::new("--tab-pinned may be given at most once"));
                }
                let raw = value_for(&mut iter, "--tab-pinned")?;
                out.record_tab_pinned = Some(parse_launch_bool("--tab-pinned", &raw)?);
            }
            "--help" | "-h" => return Err(ParseError::new("use 'maestro-app --help' for usage")),
            "--project-id" | "--goal" => {
                return Err(ParseError::new(format!(
                    "agent-resume does not accept '{arg}' (the task already exists); \
                     use agent-start to create a task"
                )))
            }
            other => {
                return Err(ParseError::new(format!(
                    "unknown agent-resume flag '{other}' (see 'maestro-app --help')"
                )))
            }
        }
    }
    require_agent_argv(saw_dashdash, &out.agent_argv, "agent-resume")?;

    // Same contract as agent-start: the layout flags only mean something when `--record-window`
    // opts in. Without it, a stray `--window-id`/`--tab-id`/`--tab-title`/`--tab-pinned` is a usage
    // error rather than a silently ignored flag.
    if !out.record_window {
        for (flag, present) in [
            ("--window-id", out.record_window_id.is_some()),
            ("--tab-id", out.record_tab_id.is_some()),
            ("--tab-title", out.record_tab_title.is_some()),
            ("--tab-pinned", out.record_tab_pinned.is_some()),
        ] {
            if present {
                return Err(ParseError::new(format!("{flag} requires --record-window")));
            }
        }
    }

    Ok(out)
}

/// Both agent commands require a non-empty argv after `--` (the actual agent command to spawn).
/// A missing `--` and an empty post-`--` argv are both usage errors.
fn require_agent_argv(
    saw_dashdash: bool,
    argv: &[String],
    command: &str,
) -> Result<(), ParseError> {
    if !saw_dashdash {
        return Err(ParseError::new(format!(
            "{command} requires '-- <agent-command> [args...]'"
        )));
    }
    if argv.is_empty() {
        return Err(ParseError::new(format!(
            "{command} requires a non-empty command after '--'"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TITLE_MAX_LEN;
    use std::path::Path;

    /// `usage()` must list the three foreground-only
    /// flags that are already parsed and enforced by `parse_attach_tab` (`--dashboard-status`,
    /// `--dashboard-panel`, `--picker-overlay`). This test fails if any line is dropped or renamed.
    #[test]
    fn usage_mentions_attach_tab_dashboard_and_picker_flags() {
        let u = usage();
        assert!(
            u.contains("--dashboard-status"),
            "usage() must mention --dashboard-status"
        );
        assert!(
            u.contains("--dashboard-panel"),
            "usage() must mention --dashboard-panel"
        );
        assert!(
            u.contains("--picker-overlay"),
            "usage() must mention --picker-overlay"
        );
        assert!(
            u.contains("--no-top-tab-bar"),
            "usage() must mention --no-top-tab-bar"
        );
        assert!(
            u.contains("--no-dashboard-status"),
            "usage() must mention --no-dashboard-status"
        );
    }

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|x| x.to_string()).collect()
    }

    fn s(v: &str) -> String {
        v.to_string()
    }

    #[test]
    fn settings_show_parses_with_no_flags() {
        let cmd = parse_args(&argv(&["settings", "show"])).unwrap();
        assert_eq!(
            cmd,
            Command::Settings(SettingsCommand::Show(SettingsShowArgs {
                base: None,
                panel_lines: false,
            }))
        );
    }

    #[test]
    fn settings_show_parses_base_flag() {
        let cmd = parse_args(&argv(&["settings", "show", "--base", "/tmp/base"])).unwrap();
        assert_eq!(
            cmd,
            Command::Settings(SettingsCommand::Show(SettingsShowArgs {
                base: Some(PathBuf::from("/tmp/base")),
                panel_lines: false,
            }))
        );
    }

    #[test]
    fn settings_show_parses_panel_lines_flag() {
        let cmd = parse_args(&argv(&["settings", "show", "--panel-lines"])).unwrap();
        assert_eq!(
            cmd,
            Command::Settings(SettingsCommand::Show(SettingsShowArgs {
                base: None,
                panel_lines: true,
            }))
        );
    }

    #[test]
    fn settings_show_parses_panel_lines_then_base() {
        let cmd = parse_args(&argv(&[
            "settings",
            "show",
            "--panel-lines",
            "--base",
            "/b",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Settings(SettingsCommand::Show(SettingsShowArgs {
                base: Some(PathBuf::from("/b")),
                panel_lines: true,
            }))
        );
    }

    #[test]
    fn settings_show_parses_base_then_panel_lines() {
        let cmd = parse_args(&argv(&[
            "settings",
            "show",
            "--base",
            "/b",
            "--panel-lines",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Settings(SettingsCommand::Show(SettingsShowArgs {
                base: Some(PathBuf::from("/b")),
                panel_lines: true,
            }))
        );
    }

    #[test]
    fn settings_show_rejects_duplicate_panel_lines() {
        let err = parse_args(&argv(&[
            "settings",
            "show",
            "--panel-lines",
            "--panel-lines",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("at most once"), "got {err}");
    }

    #[test]
    fn settings_set_rejects_panel_lines_flag() {
        let err = parse_args(&argv(&[
            "settings",
            "set",
            "appearance.font_size_px",
            "16",
            "--panel-lines",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--panel-lines") || err.to_string().contains("unknown"),
            "got {err}"
        );
    }

    #[test]
    fn settings_reset_rejects_panel_lines_flag() {
        let err = parse_args(&argv(&["settings", "reset", "--all", "--panel-lines"])).unwrap_err();
        assert!(
            err.to_string().contains("--panel-lines") || err.to_string().contains("unknown"),
            "got {err}"
        );
    }

    #[test]
    fn settings_requires_a_subcommand() {
        let err = parse_args(&argv(&["settings"])).unwrap_err();
        assert!(err.to_string().contains("subcommand"), "got {err}");
    }

    #[test]
    fn settings_rejects_unknown_subcommand() {
        let err = parse_args(&argv(&["settings", "bogus"])).unwrap_err();
        assert!(
            err.to_string().contains("unknown settings subcommand"),
            "got {err}"
        );
    }

    #[test]
    fn settings_show_rejects_duplicate_base() {
        let err =
            parse_args(&argv(&["settings", "show", "--base", "/a", "--base", "/b"])).unwrap_err();
        assert!(err.to_string().contains("at most once"), "got {err}");
    }

    #[test]
    fn settings_show_rejects_base_without_value() {
        let err = parse_args(&argv(&["settings", "show", "--base"])).unwrap_err();
        assert!(err.to_string().contains("--base"), "got {err}");
    }

    #[test]
    fn settings_show_rejects_unknown_flag() {
        let err = parse_args(&argv(&["settings", "show", "--nope"])).unwrap_err();
        assert!(
            err.to_string().contains("unknown settings show flag"),
            "got {err}"
        );
    }

    #[test]
    fn settings_show_rejects_trailing_argv() {
        let err = parse_args(&argv(&["settings", "show", "--", "x"])).unwrap_err();
        assert!(err.to_string().contains("'--'"), "got {err}");
    }

    fn settings_set(cmd: Command) -> SettingsSetArgs {
        match cmd {
            Command::Settings(SettingsCommand::Set(args)) => args,
            other => panic!("expected settings set, got {other:?}"),
        }
    }

    fn settings_set_font_size(cmd: Command) -> u32 {
        match settings_set(cmd).target {
            SettingsSetTarget::FontSizePx(px) => px,
            other => panic!("expected font-size target, got {other:?}"),
        }
    }

    fn settings_set_theme(cmd: Command) -> String {
        match settings_set(cmd).target {
            SettingsSetTarget::Theme(theme) => theme,
            other => panic!("expected theme target, got {other:?}"),
        }
    }

    #[test]
    fn settings_set_parses_font_size_without_base() {
        let cmd = parse_args(&argv(&["settings", "set", "appearance.font_size_px", "18"])).unwrap();
        assert_eq!(
            settings_set(cmd.clone()).target,
            SettingsSetTarget::FontSizePx(18)
        );
        assert_eq!(settings_set(cmd).base, None);
    }

    #[test]
    fn settings_set_parses_font_size_with_base() {
        let cmd = parse_args(&argv(&[
            "settings",
            "set",
            "appearance.font_size_px",
            "12",
            "--base",
            "/tmp/base",
        ]))
        .unwrap();
        let args = settings_set(cmd);
        assert_eq!(args.target, SettingsSetTarget::FontSizePx(12));
        assert_eq!(args.base, Some(PathBuf::from("/tmp/base")));
    }

    #[test]
    fn settings_set_accepts_range_bounds() {
        assert_eq!(
            settings_set_font_size(
                parse_args(&argv(&["settings", "set", "appearance.font_size_px", "10"])).unwrap()
            ),
            10
        );
        assert_eq!(
            settings_set_font_size(
                parse_args(&argv(&["settings", "set", "appearance.font_size_px", "32"])).unwrap()
            ),
            32
        );
    }

    #[test]
    fn settings_set_parses_theme_without_base() {
        let cmd = parse_args(&argv(&[
            "settings",
            "set",
            "appearance.theme",
            "high_contrast_dark",
        ]))
        .unwrap();
        assert_eq!(settings_set_theme(cmd), "high_contrast_dark");
    }

    #[test]
    fn settings_set_parses_theme_with_base() {
        let cmd = parse_args(&argv(&[
            "settings",
            "set",
            "appearance.theme",
            "built_in_dark",
            "--base",
            "/tmp/base",
        ]))
        .unwrap();
        let args = settings_set(cmd);
        assert_eq!(
            args.target,
            SettingsSetTarget::Theme("built_in_dark".to_string())
        );
        assert_eq!(args.base, Some(PathBuf::from("/tmp/base")));
    }

    #[test]
    fn settings_set_rejects_unknown_theme() {
        let err = parse_args(&argv(&["settings", "set", "appearance.theme", "neon"])).unwrap_err();
        assert!(
            err.to_string().contains("theme must be one of"),
            "got {err}"
        );
    }

    #[test]
    fn settings_set_theme_requires_value() {
        let err = parse_args(&argv(&["settings", "set", "appearance.theme"])).unwrap_err();
        assert!(err.to_string().contains("requires a value"), "got {err}");
    }

    #[test]
    fn settings_set_requires_key() {
        let err = parse_args(&argv(&["settings", "set"])).unwrap_err();
        assert!(err.to_string().contains("requires a key"), "got {err}");
    }

    #[test]
    fn settings_set_rejects_unknown_key() {
        let err = parse_args(&argv(&["settings", "set", "appearance.bogus", "x"])).unwrap_err();
        assert!(
            err.to_string().contains("unknown settings key"),
            "got {err}"
        );
    }

    #[test]
    fn settings_set_requires_value() {
        let err = parse_args(&argv(&["settings", "set", "appearance.font_size_px"])).unwrap_err();
        assert!(err.to_string().contains("requires a value"), "got {err}");
    }

    #[test]
    fn settings_set_rejects_non_integer_value() {
        let err = parse_args(&argv(&[
            "settings",
            "set",
            "appearance.font_size_px",
            "big",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("must be an integer"), "got {err}");
    }

    #[test]
    fn settings_set_rejects_out_of_range_value() {
        let low =
            parse_args(&argv(&["settings", "set", "appearance.font_size_px", "9"])).unwrap_err();
        assert!(low.to_string().contains("10..=32"), "got {low}");
        let high =
            parse_args(&argv(&["settings", "set", "appearance.font_size_px", "33"])).unwrap_err();
        assert!(high.to_string().contains("10..=32"), "got {high}");
    }

    #[test]
    fn settings_set_rejects_duplicate_base() {
        let err = parse_args(&argv(&[
            "settings",
            "set",
            "appearance.font_size_px",
            "16",
            "--base",
            "/a",
            "--base",
            "/b",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("at most once"), "got {err}");
    }

    #[test]
    fn settings_set_rejects_base_without_value() {
        let err = parse_args(&argv(&[
            "settings",
            "set",
            "appearance.font_size_px",
            "16",
            "--base",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("requires a value"), "got {err}");
    }

    #[test]
    fn settings_set_rejects_unknown_flag() {
        let err = parse_args(&argv(&[
            "settings",
            "set",
            "appearance.font_size_px",
            "16",
            "--nope",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("unknown settings set flag"),
            "got {err}"
        );
    }

    #[test]
    fn settings_set_rejects_trailing_argv() {
        let err = parse_args(&argv(&[
            "settings",
            "set",
            "appearance.font_size_px",
            "16",
            "--",
            "x",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("'--'"), "got {err}");
    }

    fn settings_set_shell_default_argv(cmd: Command) -> Vec<String> {
        match settings_set(cmd).target {
            SettingsSetTarget::ShellDefaultArgv(argv) => argv,
            other => panic!("expected shell.default_argv target, got {other:?}"),
        }
    }

    #[test]
    fn settings_set_parses_shell_default_argv() {
        let cmd = parse_args(&argv(&[
            "settings",
            "set",
            "shell.default_argv",
            r#"["/bin/zsh","-l"]"#,
        ]))
        .unwrap();
        assert_eq!(
            settings_set_shell_default_argv(cmd),
            vec!["/bin/zsh".to_string(), "-l".to_string()]
        );
    }

    #[test]
    fn settings_set_parses_shell_default_argv_with_base() {
        let cmd = parse_args(&argv(&[
            "settings",
            "set",
            "shell.default_argv",
            r#"["/bin/bash"]"#,
            "--base",
            "/tmp/base",
        ]))
        .unwrap();
        let args = settings_set(cmd);
        assert_eq!(
            args.target,
            SettingsSetTarget::ShellDefaultArgv(vec!["/bin/bash".to_string()])
        );
        assert_eq!(args.base, Some(PathBuf::from("/tmp/base")));
    }

    #[test]
    fn settings_set_rejects_invalid_shell_default_argv() {
        // Empty array, non-array, and non-string members are all rejected at parse time.
        assert!(parse_args(&argv(&["settings", "set", "shell.default_argv", "[]"])).is_err());
        assert!(parse_args(&argv(&[
            "settings",
            "set",
            "shell.default_argv",
            r#"{"cmd":"x"}"#
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "settings",
            "set",
            "shell.default_argv",
            r#"["x",1]"#
        ]))
        .is_err());
        assert!(parse_args(&argv(&["settings", "set", "shell.default_argv", "nope"])).is_err());
    }

    fn settings_reset(cmd: Command) -> SettingsResetArgs {
        match cmd {
            Command::Settings(SettingsCommand::Reset(args)) => args,
            other => panic!("expected settings reset, got {other:?}"),
        }
    }

    #[test]
    fn settings_reset_parses_font_size_key() {
        let cmd = parse_args(&argv(&["settings", "reset", "appearance.font_size_px"])).unwrap();
        let args = settings_reset(cmd);
        assert_eq!(
            args.selection,
            SettingsResetSelection::Key(crate::SettingsResetTarget::FontSizePx)
        );
        assert_eq!(args.base, None);
    }

    #[test]
    fn settings_reset_parses_theme_key() {
        let cmd = parse_args(&argv(&["settings", "reset", "appearance.theme"])).unwrap();
        let args = settings_reset(cmd);
        assert_eq!(
            args.selection,
            SettingsResetSelection::Key(crate::SettingsResetTarget::Theme)
        );
        assert_eq!(args.base, None);
    }

    #[test]
    fn settings_reset_parses_shell_default_argv_key() {
        let cmd = parse_args(&argv(&["settings", "reset", "shell.default_argv"])).unwrap();
        let args = settings_reset(cmd);
        assert_eq!(
            args.selection,
            SettingsResetSelection::Key(crate::SettingsResetTarget::ShellDefaultArgv)
        );
        assert_eq!(args.base, None);
    }

    #[test]
    fn settings_reset_parses_with_base() {
        let cmd = parse_args(&argv(&[
            "settings",
            "reset",
            "appearance.theme",
            "--base",
            "/tmp/base",
        ]))
        .unwrap();
        let args = settings_reset(cmd);
        assert_eq!(
            args.selection,
            SettingsResetSelection::Key(crate::SettingsResetTarget::Theme)
        );
        assert_eq!(args.base, Some(PathBuf::from("/tmp/base")));
    }

    #[test]
    fn settings_reset_parses_all() {
        let cmd = parse_args(&argv(&["settings", "reset", "--all"])).unwrap();
        let args = settings_reset(cmd);
        assert_eq!(args.selection, SettingsResetSelection::All);
        assert_eq!(args.base, None);
    }

    #[test]
    fn settings_reset_parses_all_with_base() {
        let cmd = parse_args(&argv(&[
            "settings",
            "reset",
            "--all",
            "--base",
            "/tmp/base",
        ]))
        .unwrap();
        let args = settings_reset(cmd);
        assert_eq!(args.selection, SettingsResetSelection::All);
        assert_eq!(args.base, Some(PathBuf::from("/tmp/base")));
    }

    #[test]
    fn settings_reset_parses_base_before_all() {
        let cmd = parse_args(&argv(&[
            "settings",
            "reset",
            "--base",
            "/tmp/base",
            "--all",
        ]))
        .unwrap();
        let args = settings_reset(cmd);
        assert_eq!(args.selection, SettingsResetSelection::All);
        assert_eq!(args.base, Some(PathBuf::from("/tmp/base")));
    }

    #[test]
    fn settings_reset_rejects_all_with_key_after() {
        let err =
            parse_args(&argv(&["settings", "reset", "--all", "appearance.theme"])).unwrap_err();
        assert!(
            err.to_string().contains("cannot be combined with a key"),
            "got {err}"
        );
    }

    #[test]
    fn settings_reset_rejects_key_then_all() {
        let err =
            parse_args(&argv(&["settings", "reset", "appearance.theme", "--all"])).unwrap_err();
        assert!(
            err.to_string().contains("cannot be combined with a key"),
            "got {err}"
        );
    }

    #[test]
    fn settings_reset_rejects_duplicate_all() {
        let err = parse_args(&argv(&["settings", "reset", "--all", "--all"])).unwrap_err();
        assert!(err.to_string().contains("at most once"), "got {err}");
    }

    #[test]
    fn settings_set_rejects_all_flag() {
        // `--all` is reset-only; `settings set` must never accept it.
        let err = parse_args(&argv(&["settings", "set", "--all"])).unwrap_err();
        assert!(
            !err.to_string().is_empty(),
            "expected a parse error, got {err}"
        );
        assert!(
            parse_args(&argv(&["settings", "set", "appearance.theme", "--all"])).is_err(),
            "settings set must reject a trailing --all"
        );
    }

    #[test]
    fn settings_reset_requires_key() {
        let err = parse_args(&argv(&["settings", "reset"])).unwrap_err();
        assert!(
            err.to_string().contains("requires a key") && err.to_string().contains("--all"),
            "got {err}"
        );
    }

    #[test]
    fn settings_reset_rejects_unknown_key() {
        let err = parse_args(&argv(&["settings", "reset", "appearance.bogus"])).unwrap_err();
        assert!(
            err.to_string().contains("unknown settings key"),
            "got {err}"
        );
    }

    #[test]
    fn settings_reset_rejects_unexpected_value() {
        let err = parse_args(&argv(&[
            "settings",
            "reset",
            "appearance.font_size_px",
            "16",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("takes a single key"), "got {err}");
    }

    #[test]
    fn settings_reset_rejects_duplicate_base() {
        let err = parse_args(&argv(&[
            "settings",
            "reset",
            "appearance.theme",
            "--base",
            "/a",
            "--base",
            "/b",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("at most once"), "got {err}");
    }

    #[test]
    fn settings_reset_rejects_base_without_value() {
        let err =
            parse_args(&argv(&["settings", "reset", "appearance.theme", "--base"])).unwrap_err();
        assert!(err.to_string().contains("requires a value"), "got {err}");
    }

    #[test]
    fn settings_reset_rejects_unknown_flag() {
        let err =
            parse_args(&argv(&["settings", "reset", "appearance.theme", "--nope"])).unwrap_err();
        assert!(
            err.to_string().contains("unknown settings reset flag"),
            "got {err}"
        );
    }

    #[test]
    fn settings_reset_rejects_trailing_argv() {
        let err =
            parse_args(&argv(&["settings", "reset", "appearance.theme", "--", "x"])).unwrap_err();
        assert!(err.to_string().contains("'--'"), "got {err}");
    }

    #[test]
    fn settings_set_parses_chrome_top_tab_bar_default() {
        let on = parse_args(&argv(&[
            "settings",
            "set",
            "chrome.top_tab_bar_default",
            "true",
        ]))
        .unwrap();
        assert_eq!(
            settings_set(on).target,
            SettingsSetTarget::TopTabBarDefault(true)
        );
        let off = parse_args(&argv(&[
            "settings",
            "set",
            "chrome.top_tab_bar_default",
            "false",
        ]))
        .unwrap();
        let args = settings_set(off);
        assert_eq!(args.target, SettingsSetTarget::TopTabBarDefault(false));
        assert_eq!(args.base, None);
    }

    #[test]
    fn settings_set_parses_chrome_dashboard_status_default_with_base() {
        let cmd = parse_args(&argv(&[
            "settings",
            "set",
            "chrome.dashboard_status_default",
            "false",
            "--base",
            "/tmp/base",
        ]))
        .unwrap();
        let args = settings_set(cmd);
        assert_eq!(
            args.target,
            SettingsSetTarget::DashboardStatusDefault(false)
        );
        assert_eq!(args.base, Some(PathBuf::from("/tmp/base")));
    }

    #[test]
    fn settings_set_parses_chrome_dashboard_panel_default() {
        let on = parse_args(&argv(&[
            "settings",
            "set",
            "chrome.dashboard_panel_default",
            "true",
        ]))
        .unwrap();
        assert_eq!(
            settings_set(on).target,
            SettingsSetTarget::DashboardPanelDefault(true)
        );
        let off = parse_args(&argv(&[
            "settings",
            "set",
            "chrome.dashboard_panel_default",
            "false",
            "--base",
            "/tmp/base",
        ]))
        .unwrap();
        let args = settings_set(off);
        assert_eq!(args.target, SettingsSetTarget::DashboardPanelDefault(false));
        assert_eq!(args.base, Some(PathBuf::from("/tmp/base")));
    }

    #[test]
    fn settings_set_rejects_non_bool_chrome_value() {
        let err = parse_args(&argv(&[
            "settings",
            "set",
            "chrome.top_tab_bar_default",
            "yes",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("must be 'true' or 'false'"),
            "got {err}"
        );
    }

    #[test]
    fn settings_set_chrome_requires_value() {
        let err = parse_args(&argv(&[
            "settings",
            "set",
            "chrome.dashboard_status_default",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("requires a value"), "got {err}");
    }

    #[test]
    fn settings_reset_parses_chrome_keys() {
        let top = settings_reset(
            parse_args(&argv(&["settings", "reset", "chrome.top_tab_bar_default"])).unwrap(),
        );
        assert_eq!(
            top.selection,
            SettingsResetSelection::Key(crate::SettingsResetTarget::TopTabBarDefault)
        );
        let status = settings_reset(
            parse_args(&argv(&[
                "settings",
                "reset",
                "chrome.dashboard_status_default",
            ]))
            .unwrap(),
        );
        assert_eq!(
            status.selection,
            SettingsResetSelection::Key(crate::SettingsResetTarget::DashboardStatusDefault)
        );
        let panel = settings_reset(
            parse_args(&argv(&[
                "settings",
                "reset",
                "chrome.dashboard_panel_default",
            ]))
            .unwrap(),
        );
        assert_eq!(
            panel.selection,
            SettingsResetSelection::Key(crate::SettingsResetTarget::DashboardPanelDefault)
        );
    }

    fn attach_tab(items: &[&str]) -> Result<AttachTabArgs, ParseError> {
        let base = ["attach-tab", "--window-id", "w1", "--tab-id", "t1"];
        let mut all: Vec<&str> = base.to_vec();
        all.extend_from_slice(items);
        match parse_args(&argv(&all))? {
            Command::AttachTab(a) => Ok(*a),
            other => panic!("expected AttachTab, got {other:?}"),
        }
    }

    fn attach_tab_args(cmd: Command) -> AttachTabArgs {
        match cmd {
            Command::AttachTab(args) => *args,
            other => panic!("expected attach-tab command, got {other:?}"),
        }
    }

    #[test]
    fn attach_tab_absent_chrome_flags_are_tri_state_none() {
        let a = attach_tab(&[]).expect("parses");
        let flags = a.chrome_flags();
        assert_eq!(flags.top_tab_bar, None);
        assert_eq!(flags.dashboard_status, None);
        assert_eq!(flags.dashboard_panel, None);
        assert_eq!(flags.picker_overlay, None);
    }

    #[test]
    fn attach_tab_no_top_tab_bar_is_explicit_false() {
        let a = attach_tab(&["--no-top-tab-bar"]).expect("parses");
        assert_eq!(a.chrome_flags().top_tab_bar, Some(false));
    }

    #[test]
    fn attach_tab_no_dashboard_status_is_explicit_false() {
        let a = attach_tab(&["--no-dashboard-status"]).expect("parses");
        assert_eq!(a.chrome_flags().dashboard_status, Some(false));
    }

    #[test]
    fn attach_tab_explicit_top_tab_bar_is_explicit_true() {
        let a = attach_tab(&["--top-tab-bar"]).expect("parses");
        assert_eq!(a.chrome_flags().top_tab_bar, Some(true));
    }

    #[test]
    fn attach_tab_contradictory_top_tab_bar_flags_error() {
        let err = attach_tab(&["--top-tab-bar", "--no-top-tab-bar"]).unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn attach_tab_contradictory_dashboard_status_flags_error() {
        let err = attach_tab(&["--dashboard-status", "--no-dashboard-status"]).unwrap_err();
        assert!(
            err.to_string().contains("mutually exclusive"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn attach_tab_bare_detach_renderer_parses() {
        let a = attach_tab(&["--detach-renderer"]).expect("bare --detach-renderer must parse");
        assert!(a.detach_renderer);
    }

    #[test]
    fn attach_tab_negations_with_detach_renderer_are_harmless_no_ops() {
        // Explicit negations are accepted (not rejected) with --detach-renderer; the resolver maps
        // detached mode to all-false chrome regardless, so they cannot make a window appear.
        attach_tab(&["--detach-renderer", "--no-top-tab-bar"]).expect("negation is a no-op");
        attach_tab(&["--detach-renderer", "--no-dashboard-status"]).expect("negation is a no-op");
    }

    // ---- window parsing ---------------------------------------------------------------------

    #[test]
    fn window_create_parses() {
        let cmd = parse_args(&argv(&[
            "window",
            "create",
            "--window-id",
            "w1",
            "--base",
            "/base",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::Create(WindowCreateArgs {
                window_id: Some(s("w1")),
                base: Some(PathBuf::from("/base")),
            }))
        );
    }

    #[test]
    fn window_create_base_is_optional() {
        let cmd = parse_args(&argv(&["window", "create", "--window-id", "w1"])).unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::Create(WindowCreateArgs {
                window_id: Some(s("w1")),
                base: None,
            }))
        );
    }

    #[test]
    fn window_show_parses() {
        let cmd = parse_args(&argv(&["window", "show", "--window-id", "w1"])).unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::Show(WindowShowArgs {
                window_id: Some(s("w1")),
                base: None,
            }))
        );
    }

    #[test]
    fn window_open_tab_parses_all_fields() {
        let cmd = parse_args(&argv(&[
            "window",
            "open-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--session-id",
            "s1",
            "--title",
            "First",
            "--base",
            "/base",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::OpenTab(WindowOpenTabArgs {
                window_id: Some(s("w1")),
                tab_id: Some(s("t1")),
                session_id: Some(s("s1")),
                title: Some(s("First")),
                base: Some(PathBuf::from("/base")),
            }))
        );
    }

    #[test]
    fn window_view_parses() {
        let cmd = parse_args(&argv(&["window", "view", "--window-id", "w1"])).unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::View(WindowViewArgs {
                window_id: Some(s("w1")),
                base: None,
            }))
        );
    }

    #[test]
    fn window_without_subcommand_is_usage_error() {
        let err = parse_args(&argv(&["window"])).unwrap_err();
        assert!(err.message.contains("window requires a subcommand"));
    }

    #[test]
    fn window_unknown_subcommand_is_usage_error() {
        let err = parse_args(&argv(&["window", "frobnicate"])).unwrap_err();
        assert!(err.message.contains("unknown window subcommand"));
    }

    #[test]
    fn window_unknown_flag_is_usage_error() {
        let err =
            parse_args(&argv(&["window", "create", "--window-id", "w1", "--nope"])).unwrap_err();
        assert!(err.message.contains("unknown window create flag"));
    }

    #[test]
    fn window_create_missing_window_id_is_usage_error() {
        let err = parse_args(&argv(&["window", "create"])).unwrap_err();
        assert!(err.message.contains("window create requires --window-id"));
    }

    #[test]
    fn window_missing_required_flag_value_is_usage_error() {
        let err = parse_args(&argv(&["window", "create", "--window-id"])).unwrap_err();
        assert!(err.message.contains("flag '--window-id' requires a value"));
    }

    #[test]
    fn window_open_tab_missing_each_required_field_is_usage_error() {
        // Missing --tab-id.
        let err = parse_args(&argv(&[
            "window",
            "open-tab",
            "--window-id",
            "w1",
            "--session-id",
            "s1",
            "--title",
            "t",
        ]))
        .unwrap_err();
        assert!(err.message.contains("requires --tab-id"));
        // Missing --session-id.
        let err = parse_args(&argv(&[
            "window",
            "open-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--title",
            "t",
        ]))
        .unwrap_err();
        assert!(err.message.contains("requires --session-id"));
        // Missing --title.
        let err = parse_args(&argv(&[
            "window",
            "open-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--session-id",
            "s1",
        ]))
        .unwrap_err();
        assert!(err.message.contains("requires --title"));
    }

    #[test]
    fn window_duplicate_required_flags_are_usage_errors() {
        let err = parse_args(&argv(&[
            "window",
            "create",
            "--window-id",
            "w1",
            "--window-id",
            "w2",
        ]))
        .unwrap_err();
        assert!(err
            .message
            .contains("--window-id may be given at most once"));

        let err = parse_args(&argv(&[
            "window",
            "create",
            "--window-id",
            "w1",
            "--base",
            "/a",
            "--base",
            "/b",
        ]))
        .unwrap_err();
        assert!(err.message.contains("--base may be given at most once"));

        let dup = |flag: &str, v1: &str, v2: &str| {
            let mut a = vec![
                "window",
                "open-tab",
                "--window-id",
                "w1",
                "--tab-id",
                "t1",
                "--session-id",
                "s1",
                "--title",
                "First",
            ];
            a.push(flag);
            a.push(v1);
            a.push(flag);
            a.push(v2);
            parse_args(&argv(&a)).unwrap_err()
        };
        assert!(dup("--tab-id", "t1", "t2")
            .message
            .contains("--tab-id may be given at most once"));
        assert!(dup("--session-id", "s1", "s2")
            .message
            .contains("--session-id may be given at most once"));
        assert!(dup("--title", "a", "b")
            .message
            .contains("--title may be given at most once"));
    }

    #[test]
    fn window_subcommands_reject_dashdash_argv() {
        for sub in ["create", "show", "view"] {
            let err =
                parse_args(&argv(&["window", sub, "--window-id", "w1", "--", "x"])).unwrap_err();
            assert!(
                err.message.contains("does not accept a '--' argv"),
                "{sub}: {}",
                err.message
            );
        }
        let err = parse_args(&argv(&[
            "window",
            "open-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--session-id",
            "s1",
            "--title",
            "First",
            "--",
            "x",
        ]))
        .unwrap_err();
        assert!(err.message.contains("does not accept a '--' argv"));
    }

    // ---- window mutation parsing ------------------------------------------------------------

    #[test]
    fn window_close_tab_parses() {
        let cmd = parse_args(&argv(&[
            "window",
            "close-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--base",
            "/base",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::CloseTab(WindowTabRefArgs {
                window_id: Some(s("w1")),
                tab_id: Some(s("t1")),
                base: Some(PathBuf::from("/base")),
            }))
        );
    }

    #[test]
    fn window_attention_clear_parses_required_ids() {
        let cmd = parse_args(&argv(&[
            "window",
            "attention-clear",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::AttentionClear(WindowTabRefArgs {
                window_id: Some(s("w1")),
                tab_id: Some(s("t1")),
                base: None,
            }))
        );
    }

    #[test]
    fn window_attention_clear_accepts_optional_base() {
        let cmd = parse_args(&argv(&[
            "window",
            "attention-clear",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--base",
            "/base",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::AttentionClear(WindowTabRefArgs {
                window_id: Some(s("w1")),
                tab_id: Some(s("t1")),
                base: Some(PathBuf::from("/base")),
            }))
        );
    }

    #[test]
    fn window_attention_clear_rejects_missing_window_id() {
        let err = parse_args(&argv(&["window", "attention-clear", "--tab-id", "t1"])).unwrap_err();
        assert!(
            err.to_string().contains("requires --window-id"),
            "got: {err}"
        );
    }

    #[test]
    fn window_attention_clear_rejects_missing_tab_id() {
        let err =
            parse_args(&argv(&["window", "attention-clear", "--window-id", "w1"])).unwrap_err();
        assert!(err.to_string().contains("requires --tab-id"), "got: {err}");
    }

    #[test]
    fn window_attention_clear_rejects_duplicate_singleton() {
        let err = parse_args(&argv(&[
            "window",
            "attention-clear",
            "--window-id",
            "w1",
            "--window-id",
            "w2",
            "--tab-id",
            "t1",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--window-id"), "got: {err}");
    }

    #[test]
    fn window_attention_clear_rejects_unknown_flag() {
        let err = parse_args(&argv(&[
            "window",
            "attention-clear",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--bogus",
            "x",
        ]))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown window attention-clear flag"),
            "got: {err}"
        );
    }

    #[test]
    fn window_attention_clear_rejects_trailing_dashdash() {
        let err = parse_args(&argv(&[
            "window",
            "attention-clear",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("does not accept a '--' argv"),
            "got: {err}"
        );
    }

    #[test]
    fn window_rename_tab_parses() {
        let cmd = parse_args(&argv(&[
            "window",
            "rename-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--title",
            "Renamed",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::RenameTab(WindowRenameTabArgs {
                window_id: Some(s("w1")),
                tab_id: Some(s("t1")),
                title: Some(s("Renamed")),
                base: None,
            }))
        );
    }

    #[test]
    fn window_pin_tab_parses_true_and_false() {
        let cmd = parse_args(&argv(&[
            "window",
            "pin-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--pinned",
            "true",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::PinTab(WindowPinTabArgs {
                window_id: Some(s("w1")),
                tab_id: Some(s("t1")),
                pinned: Some(true),
                base: None,
            }))
        );
        let cmd = parse_args(&argv(&[
            "window",
            "pin-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--pinned",
            "false",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::PinTab(WindowPinTabArgs {
                window_id: Some(s("w1")),
                tab_id: Some(s("t1")),
                pinned: Some(false),
                base: None,
            }))
        );
    }

    #[test]
    fn window_reorder_tabs_parses_order_list() {
        let cmd = parse_args(&argv(&[
            "window",
            "reorder-tabs",
            "--window-id",
            "w1",
            "--order",
            "t3,t1,t2",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::ReorderTabs(WindowReorderTabsArgs {
                window_id: Some(s("w1")),
                order: Some(vec![s("t3"), s("t1"), s("t2")]),
                base: None,
            }))
        );
    }

    #[test]
    fn window_attention_parses_all_fields() {
        let cmd = parse_args(&argv(&[
            "window",
            "attention",
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
            "42",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::Attention(Box::new(WindowAttentionArgs {
                window_id: Some(s("w1")),
                tab_id: Some(s("t1")),
                attention: Some(s("needs_input")),
                unseen: Some(true),
                source: Some(s("agent")),
                since_ms: Some(42),
                base: None,
            })))
        );
    }

    #[test]
    fn window_attention_source_and_since_ms_are_optional() {
        let cmd = parse_args(&argv(&[
            "window",
            "attention",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--attention",
            "done",
            "--unseen",
            "false",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Window(WindowCommand::Attention(Box::new(WindowAttentionArgs {
                window_id: Some(s("w1")),
                tab_id: Some(s("t1")),
                attention: Some(s("done")),
                unseen: Some(false),
                source: None,
                since_ms: None,
                base: None,
            })))
        );
    }

    #[test]
    fn window_mutation_missing_required_fields_are_usage_errors() {
        // close-tab requires --tab-id
        let err = parse_args(&argv(&["window", "close-tab", "--window-id", "w1"])).unwrap_err();
        assert!(err.message.contains("requires --tab-id"), "{}", err.message);
        // rename-tab requires --title
        let err = parse_args(&argv(&[
            "window",
            "rename-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
        ]))
        .unwrap_err();
        assert!(err.message.contains("requires --title"), "{}", err.message);
        // pin-tab requires --pinned
        let err = parse_args(&argv(&[
            "window",
            "pin-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
        ]))
        .unwrap_err();
        assert!(err.message.contains("requires --pinned"), "{}", err.message);
        // reorder-tabs requires --order
        let err = parse_args(&argv(&["window", "reorder-tabs", "--window-id", "w1"])).unwrap_err();
        assert!(err.message.contains("requires --order"), "{}", err.message);
        // attention requires --attention and --unseen
        let err = parse_args(&argv(&[
            "window",
            "attention",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--unseen",
            "true",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("requires --attention"),
            "{}",
            err.message
        );
        let err = parse_args(&argv(&[
            "window",
            "attention",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--attention",
            "none",
        ]))
        .unwrap_err();
        assert!(err.message.contains("requires --unseen"), "{}", err.message);
    }

    #[test]
    fn window_mutation_duplicate_flags_are_usage_errors() {
        // duplicate --tab-id
        let err = parse_args(&argv(&[
            "window",
            "close-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--tab-id",
            "t2",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("--tab-id may be given at most once"),
            "{}",
            err.message
        );
        // duplicate --pinned
        let err = parse_args(&argv(&[
            "window",
            "pin-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--pinned",
            "true",
            "--pinned",
            "false",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("--pinned may be given at most once"),
            "{}",
            err.message
        );
        // duplicate --order
        let err = parse_args(&argv(&[
            "window",
            "reorder-tabs",
            "--window-id",
            "w1",
            "--order",
            "t1",
            "--order",
            "t2",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("--order may be given at most once"),
            "{}",
            err.message
        );
        // duplicate --attention / --unseen / --source / --since-ms
        for (flag, second) in [
            ("--attention", "activity"),
            ("--unseen", "false"),
            ("--source", "user"),
            ("--since-ms", "9"),
        ] {
            let err = parse_args(&argv(&[
                "window",
                "attention",
                "--window-id",
                "w1",
                "--tab-id",
                "t1",
                "--attention",
                "none",
                "--unseen",
                "true",
                "--source",
                "process",
                "--since-ms",
                "1",
                flag,
                second,
            ]))
            .unwrap_err();
            assert!(
                err.message
                    .contains(&format!("{flag} may be given at most once")),
                "{flag}: {}",
                err.message
            );
        }
    }

    #[test]
    fn window_mutation_subcommands_reject_dashdash_argv() {
        let cases: &[&[&str]] = &[
            &["window", "close-tab", "--window-id", "w1", "--tab-id", "t1"],
            &[
                "window",
                "rename-tab",
                "--window-id",
                "w1",
                "--tab-id",
                "t1",
                "--title",
                "x",
            ],
            &[
                "window",
                "pin-tab",
                "--window-id",
                "w1",
                "--tab-id",
                "t1",
                "--pinned",
                "true",
            ],
            &[
                "window",
                "reorder-tabs",
                "--window-id",
                "w1",
                "--order",
                "t1",
            ],
            &[
                "window",
                "attention",
                "--window-id",
                "w1",
                "--tab-id",
                "t1",
                "--attention",
                "none",
                "--unseen",
                "true",
            ],
        ];
        for base in cases {
            let mut full: Vec<&str> = base.to_vec();
            full.push("--");
            full.push("x");
            let err = parse_args(&argv(&full)).unwrap_err();
            assert!(
                err.message.contains("does not accept a '--' argv"),
                "{base:?}: {}",
                err.message
            );
        }
    }

    #[test]
    fn window_pin_and_attention_reject_invalid_booleans() {
        let err = parse_args(&argv(&[
            "window",
            "pin-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--pinned",
            "yes",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("--pinned must be 'true' or 'false'"),
            "{}",
            err.message
        );
        let err = parse_args(&argv(&[
            "window",
            "attention",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--attention",
            "none",
            "--unseen",
            "1",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("--unseen must be 'true' or 'false'"),
            "{}",
            err.message
        );
    }

    #[test]
    fn window_attention_rejects_invalid_attention_and_source() {
        let err = parse_args(&argv(&[
            "window",
            "attention",
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
        assert!(
            err.message.contains("--attention must be one of"),
            "{}",
            err.message
        );
        let err = parse_args(&argv(&[
            "window",
            "attention",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--attention",
            "none",
            "--unseen",
            "true",
            "--source",
            "robot",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("--source must be one of"),
            "{}",
            err.message
        );
    }

    #[test]
    fn window_attention_rejects_non_u64_since_ms() {
        let err = parse_args(&argv(&[
            "window",
            "attention",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--attention",
            "none",
            "--unseen",
            "true",
            "--since-ms",
            "-1",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("--since-ms requires a u64"),
            "{}",
            err.message
        );
    }

    #[test]
    fn window_reorder_rejects_empty_and_empty_segment_orders() {
        let err = parse_args(&argv(&[
            "window",
            "reorder-tabs",
            "--window-id",
            "w1",
            "--order",
            "",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("non-empty comma-separated list"),
            "{}",
            err.message
        );
        let err = parse_args(&argv(&[
            "window",
            "reorder-tabs",
            "--window-id",
            "w1",
            "--order",
            "t1,,t2",
        ]))
        .unwrap_err();
        assert!(
            err.message
                .contains("must not contain empty comma segments"),
            "{}",
            err.message
        );
    }

    #[test]
    fn attach_tab_requires_window_and_tab() {
        let err = parse_args(&argv(&["attach-tab"])).unwrap_err();
        assert!(err.to_string().contains("--window-id"), "{err}");

        let err = parse_args(&argv(&["attach-tab", "--window-id", "w1"])).unwrap_err();
        assert!(err.to_string().contains("--tab-id"), "{err}");
    }

    #[test]
    fn attach_tab_parses_required_flags() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert_eq!(args.window_id.as_deref(), Some("w1"));
        assert_eq!(args.tab_id.as_deref(), Some("t1"));
        assert!(!args.no_run_renderer);
        assert!(!args.detach_renderer);
    }

    #[test]
    fn attach_tab_rejects_unknown_flag() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--nope",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--nope"), "{err}");
    }

    #[test]
    fn attach_tab_rejects_duplicate_singleton_flag() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--window-id",
            "w2",
            "--tab-id",
            "t1",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--window-id"), "{err}");
    }

    #[test]
    fn attach_tab_no_run_conflicts_with_detach() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--no-run-renderer",
            "--detach-renderer",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--no-run-renderer")
                && err.to_string().contains("--detach-renderer"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_top_tab_bar_parses_with_no_run() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--no-run-renderer",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.top_tab_bar);
        assert!(args.no_run_renderer);
    }

    #[test]
    fn attach_tab_top_tab_bar_conflicts_with_detach() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--detach-renderer",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--top-tab-bar")
                && err.to_string().contains("--detach-renderer"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_top_tab_bar_rejects_duplicate() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--top-tab-bar",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--top-tab-bar"), "{err}");
    }

    #[test]
    fn attach_tab_new_tab_default_shell_produces_scratch_policy() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-default-shell",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.new_tab_default_shell);
        assert_eq!(args.new_tab_title, None);
        let policy = args
            .new_tab_launch_policy()
            .expect("default-shell opt-in yields a policy");
        assert_eq!(policy.source, NewTabLaunchSource::DefaultShellDev);
        assert_eq!(policy.workspace, maestro_shell::WorkspacePolicy::ScratchCwd);
        assert_eq!(
            policy.workspace_id, DEFAULT_SESSION_ID,
            "default-shell dev policy stamps the dev workspace id"
        );
        assert_eq!(policy.cwd_basis, NewTabCwdBasis::WorkspaceDerived);
        assert_eq!(policy.title, "shell");
    }

    #[test]
    fn attach_tab_no_new_tab_flag_carries_no_policy() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(!args.new_tab_default_shell);
        assert_eq!(args.new_tab_launch_policy(), None);
    }

    #[test]
    fn attach_tab_new_tab_title_overrides_title() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-default-shell",
            "--new-tab-title",
            "scratch",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        let policy = args.new_tab_launch_policy().unwrap();
        assert_eq!(policy.title, "scratch");
    }

    #[test]
    fn attach_tab_new_tab_title_requires_default_shell() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-title",
            "scratch",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--new-tab-title")
                && err.to_string().contains("--new-tab-default-shell"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_new_tab_default_shell_requires_top_tab_bar() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--new-tab-default-shell",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--new-tab-default-shell")
                && err.to_string().contains("--top-tab-bar"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_new_tab_default_shell_rejects_duplicate() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-default-shell",
            "--new-tab-default-shell",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--new-tab-default-shell"), "{err}");
    }

    #[test]
    fn attach_tab_new_tab_title_rejects_duplicate() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-default-shell",
            "--new-tab-title",
            "a",
            "--new-tab-title",
            "b",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--new-tab-title"), "{err}");
    }

    #[test]
    fn attach_tab_new_tab_title_rejects_invalid() {
        let empty = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-default-shell",
            "--new-tab-title",
            "",
        ]))
        .unwrap_err();
        assert!(empty.to_string().contains("empty"), "{empty}");

        let control = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-default-shell",
            "--new-tab-title",
            "bad\u{7}name",
        ]))
        .unwrap_err();
        assert!(control.to_string().contains("control"), "{control}");

        let long: String = "x".repeat(TITLE_MAX_LEN + 1);
        let too_long = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-default-shell",
            "--new-tab-title",
            &long,
        ]))
        .unwrap_err();
        assert!(too_long.to_string().contains("too long"), "{too_long}");
    }

    #[test]
    fn attach_tab_new_tab_workspace_id_overrides_default() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-default-shell",
            "--new-tab-workspace-id",
            "ws-1",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert_eq!(args.new_tab_workspace_id.as_deref(), Some("ws-1"));
        let policy = args.new_tab_launch_policy().unwrap();
        assert_eq!(
            policy.workspace_id, "ws-1",
            "explicit --new-tab-workspace-id overrides the default workspace identity"
        );
    }

    #[test]
    fn attach_tab_new_tab_workspace_id_absent_keeps_default() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-default-shell",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert_eq!(args.new_tab_workspace_id, None);
        let policy = args.new_tab_launch_policy().unwrap();
        assert_eq!(
            policy.workspace_id, DEFAULT_SESSION_ID,
            "absent --new-tab-workspace-id keeps the default dev workspace id"
        );
    }

    #[test]
    fn attach_tab_new_tab_workspace_id_requires_default_shell() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-workspace-id",
            "ws-1",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--new-tab-workspace-id")
                && err.to_string().contains("--new-tab-default-shell"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_new_tab_workspace_id_rejects_duplicate() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--top-tab-bar",
            "--new-tab-default-shell",
            "--new-tab-workspace-id",
            "ws-1",
            "--new-tab-workspace-id",
            "ws-2",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--new-tab-workspace-id"), "{err}");
    }

    #[test]
    fn attach_tab_new_tab_workspace_id_rejects_unsafe_values() {
        for bad in ["", ".", "..", "a/b", "a\\b"] {
            let err = parse_args(&argv(&[
                "attach-tab",
                "--window-id",
                "w1",
                "--tab-id",
                "t1",
                "--top-tab-bar",
                "--new-tab-default-shell",
                "--new-tab-workspace-id",
                bad,
            ]))
            .unwrap_err();
            assert!(
                err.to_string().contains("--new-tab-workspace-id"),
                "value {bad:?} should be rejected and name the flag: {err}"
            );
        }
    }

    #[test]
    fn attach_tab_rejects_trailing_command_argv() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--",
            "vim",
        ]))
        .unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn attach_tab_title_accepted_in_foreground_and_no_run() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--title",
            "My Tab",
        ]))
        .unwrap();
        assert_eq!(attach_tab_args(cmd).title.as_deref(), Some("My Tab"));

        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--no-run-renderer",
            "--title",
            "My Tab",
        ]))
        .unwrap();
        assert_eq!(attach_tab_args(cmd).title.as_deref(), Some("My Tab"));
    }

    #[test]
    fn attach_tab_title_rejected_under_detach() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--detach-renderer",
            "--title",
            "My Tab",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--title"), "{err}");
    }

    // The `attach_tab_window_title_*` / `attach_tab_status_label_*` direct-helper tests now live
    // beside their helpers in `output.rs` (`output::tests`).

    // ---- dashboard status strip (attach-tab --dashboard-status) -----------------------------

    #[test]
    fn attach_tab_dashboard_status_parses_with_no_run() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--dashboard-status",
            "--no-run-renderer",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.dashboard_status);
        assert!(args.no_run_renderer);
    }

    #[test]
    fn attach_tab_dashboard_status_parses_in_foreground() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--dashboard-status",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.dashboard_status);
        assert!(!args.no_run_renderer);
        assert!(!args.detach_renderer);
    }

    #[test]
    fn attach_tab_dashboard_status_absent_defaults_false() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(!args.dashboard_status);
    }

    #[test]
    fn attach_tab_dashboard_status_rejects_duplicate() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--dashboard-status",
            "--dashboard-status",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--dashboard-status"), "{err}");
    }

    #[test]
    fn attach_tab_dashboard_status_conflicts_with_detach() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--dashboard-status",
            "--detach-renderer",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--dashboard-status")
                && err.to_string().contains("--detach-renderer"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_dashboard_panel_parses() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--dashboard-panel",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.dashboard_panel);
        assert!(!args.no_run_renderer);
        assert!(!args.detach_renderer);
    }

    #[test]
    fn attach_tab_dashboard_panel_absent_defaults_false() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(!args.dashboard_panel);
    }

    #[test]
    fn attach_tab_dashboard_panel_rejects_duplicate() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--dashboard-panel",
            "--dashboard-panel",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--dashboard-panel"), "{err}");
    }

    #[test]
    fn attach_tab_dashboard_panel_conflicts_with_detach() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--dashboard-panel",
            "--detach-renderer",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--dashboard-panel")
                && err.to_string().contains("--detach-renderer"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_dashboard_panel_accepts_no_run_renderer() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--dashboard-panel",
            "--no-run-renderer",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.dashboard_panel);
        assert!(args.no_run_renderer);
    }

    #[test]
    fn attach_tab_dashboard_panel_combines_with_status() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--dashboard-panel",
            "--dashboard-status",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.dashboard_panel);
        assert!(args.dashboard_status);
    }

    #[test]
    fn attach_tab_no_dashboard_panel_is_explicit_false() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--no-dashboard-panel",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.no_dashboard_panel);
        assert!(!args.dashboard_panel);
        assert_eq!(args.chrome_flags().dashboard_panel, Some(false));
    }

    #[test]
    fn attach_tab_no_dashboard_panel_rejects_duplicate() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--no-dashboard-panel",
            "--no-dashboard-panel",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--no-dashboard-panel"), "{err}");
    }

    #[test]
    fn attach_tab_dashboard_panel_and_no_dashboard_panel_mutually_exclusive() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--dashboard-panel",
            "--no-dashboard-panel",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--dashboard-panel")
                && err.to_string().contains("--no-dashboard-panel"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_no_dashboard_panel_is_noop_with_detach() {
        // The negation is accepted with --detach-renderer as a harmless no-op (matching
        // --no-top-tab-bar / --no-dashboard-status); the detached renderer carries no app chrome.
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--no-dashboard-panel",
            "--detach-renderer",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.no_dashboard_panel);
        assert!(args.detach_renderer);
    }

    #[test]
    fn attach_tab_no_dashboard_panel_accepts_no_run_renderer() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--no-dashboard-panel",
            "--no-run-renderer",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.no_dashboard_panel);
        assert!(args.no_run_renderer);
    }

    #[test]
    fn attach_tab_settings_panel_parses() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--settings-panel",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.settings_panel);
        assert!(!args.no_run_renderer);
        assert!(!args.detach_renderer);
        // Standalone bool: it is NOT folded into the chrome dashboard-panel tri-state.
        assert_eq!(args.chrome_flags().dashboard_panel, None);
    }

    #[test]
    fn attach_tab_settings_panel_absent_defaults_false() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(!args.settings_panel);
    }

    #[test]
    fn attach_tab_settings_panel_rejects_duplicate() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--settings-panel",
            "--settings-panel",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--settings-panel")
                && err.to_string().contains("at most once"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_settings_panel_conflicts_with_detach() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--settings-panel",
            "--detach-renderer",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--settings-panel")
                && err.to_string().contains("--detach-renderer"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_settings_panel_conflicts_with_dashboard_panel() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--settings-panel",
            "--dashboard-panel",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--settings-panel")
                && err.to_string().contains("--dashboard-panel"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_settings_panel_conflicts_with_no_dashboard_panel() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--settings-panel",
            "--no-dashboard-panel",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--settings-panel")
                && err.to_string().contains("--no-dashboard-panel"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_settings_panel_accepts_no_run_renderer() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--settings-panel",
            "--no-run-renderer",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.settings_panel);
        assert!(args.no_run_renderer);
    }

    #[test]
    fn attach_tab_settings_panel_combines_with_status() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--settings-panel",
            "--dashboard-status",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.settings_panel);
        assert!(args.dashboard_status);
    }

    #[test]
    fn attach_tab_command_palette_parses() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.command_palette);
        assert!(args.command_palette_query.is_none());
        assert!(!args.no_run_renderer);
        assert!(!args.detach_renderer);
    }

    #[test]
    fn attach_tab_command_palette_absent_defaults_false() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(!args.command_palette);
        assert!(args.command_palette_query.is_none());
    }

    #[test]
    fn attach_tab_command_palette_query_parses() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette",
            "--command-palette-query",
            "settings",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.command_palette);
        assert_eq!(args.command_palette_query.as_deref(), Some("settings"));
    }

    #[test]
    fn attach_tab_command_palette_rejects_duplicate() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette",
            "--command-palette",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--command-palette")
                && err.to_string().contains("at most once"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_command_palette_query_rejects_duplicate() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette",
            "--command-palette-query",
            "a",
            "--command-palette-query",
            "b",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--command-palette-query")
                && err.to_string().contains("at most once"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_command_palette_query_rejects_missing_value() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette",
            "--command-palette-query",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--command-palette-query"), "{err}");
    }

    #[test]
    fn attach_tab_command_palette_query_rejects_empty_value() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette",
            "--command-palette-query",
            "   ",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--command-palette-query")
                && err.to_string().contains("empty"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_command_palette_query_requires_command_palette() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette-query",
            "settings",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--command-palette-query")
                && err.to_string().contains("--command-palette"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_command_palette_conflicts_with_detach() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette",
            "--detach-renderer",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--command-palette")
                && err.to_string().contains("--detach-renderer"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_command_palette_conflicts_with_picker_overlay() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette",
            "--picker-overlay",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--command-palette")
                && err.to_string().contains("--picker-overlay"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_command_palette_accepts_no_picker_overlay() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette",
            "--no-picker-overlay",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.command_palette);
        assert!(args.no_picker_overlay);
    }

    #[test]
    fn attach_tab_command_palette_accepts_no_run_renderer() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette",
            "--no-run-renderer",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.command_palette);
        assert!(args.no_run_renderer);
    }

    #[test]
    fn attach_tab_command_palette_combines_with_status_and_top_bar() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--command-palette",
            "--dashboard-status",
            "--top-tab-bar",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.command_palette);
        assert!(args.dashboard_status);
        assert!(args.top_tab_bar);
    }

    #[test]
    fn attach_tab_file_preview_parses_path() {
        let a = attach_tab(&["--file-preview", "/tmp/notes.txt"]).expect("parses");
        assert_eq!(a.file_preview, Some(PathBuf::from("/tmp/notes.txt")));
    }

    #[test]
    fn attach_tab_file_preview_defaults_to_none() {
        let a = attach_tab(&[]).expect("parses");
        assert_eq!(a.file_preview, None);
    }

    #[test]
    fn attach_tab_file_preview_requires_a_value() {
        let err = attach_tab(&["--file-preview"]).unwrap_err();
        assert!(
            err.to_string().contains("requires a value"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn attach_tab_file_preview_rejected_more_than_once() {
        let err = attach_tab(&[
            "--file-preview",
            "/tmp/a.txt",
            "--file-preview",
            "/tmp/b.txt",
        ])
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("--file-preview may be given at most once"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn attach_tab_file_preview_rejected_with_detach_renderer() {
        let err = attach_tab(&["--file-preview", "/tmp/a.txt", "--detach-renderer"]).unwrap_err();
        assert!(
            err.to_string()
                .contains("--file-preview is not supported with --detach-renderer"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn attach_tab_file_preview_rejected_with_new_tab_default_shell() {
        let err = attach_tab(&[
            "--file-preview",
            "/tmp/a.txt",
            "--top-tab-bar",
            "--new-tab-default-shell",
        ])
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("--file-preview is not supported with --new-tab-default-shell"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn attach_tab_file_preview_allowed_with_no_run_renderer() {
        let a = attach_tab(&["--file-preview", "/tmp/a.txt", "--no-run-renderer"]).expect("parses");
        assert_eq!(a.file_preview, Some(PathBuf::from("/tmp/a.txt")));
        assert!(a.no_run_renderer);
    }

    #[test]
    fn attach_tab_picker_overlay_parses() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--picker-overlay",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(args.picker_overlay);
        assert!(!args.no_run_renderer);
        assert!(!args.detach_renderer);
    }

    #[test]
    fn attach_tab_picker_overlay_absent_defaults_false() {
        let cmd = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
        ]))
        .unwrap();
        let args = attach_tab_args(cmd);
        assert!(!args.picker_overlay);
    }

    #[test]
    fn attach_tab_picker_overlay_rejects_duplicate() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--picker-overlay",
            "--picker-overlay",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("--picker-overlay"), "{err}");
    }

    #[test]
    fn attach_tab_picker_overlay_conflicts_with_detach() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--picker-overlay",
            "--detach-renderer",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--picker-overlay")
                && err.to_string().contains("--detach-renderer"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_picker_overlay_conflicts_with_no_run_renderer() {
        let err = parse_args(&argv(&[
            "attach-tab",
            "--window-id",
            "w1",
            "--tab-id",
            "t1",
            "--picker-overlay",
            "--no-run-renderer",
        ]))
        .unwrap_err();
        assert!(
            err.to_string().contains("--picker-overlay")
                && err.to_string().contains("--no-run-renderer"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_no_picker_overlay_is_explicit_false() {
        let a = attach_tab(&["--no-picker-overlay"]).expect("parses");
        assert!(a.no_picker_overlay);
        assert!(!a.picker_overlay);
        assert_eq!(a.chrome_flags().picker_overlay, Some(false));
    }

    #[test]
    fn attach_tab_no_picker_overlay_rejects_duplicate() {
        let err = attach_tab(&["--no-picker-overlay", "--no-picker-overlay"]).unwrap_err();
        assert!(err.to_string().contains("--no-picker-overlay"), "{err}");
    }

    #[test]
    fn attach_tab_picker_overlay_conflicts_with_no_picker_overlay() {
        let err = attach_tab(&["--picker-overlay", "--no-picker-overlay"]).unwrap_err();
        assert!(
            err.to_string().contains("--picker-overlay")
                && err.to_string().contains("--no-picker-overlay"),
            "{err}"
        );
    }

    #[test]
    fn attach_tab_no_picker_overlay_noop_with_detach() {
        let a = attach_tab(&["--no-picker-overlay", "--detach-renderer"]).expect("parses");
        assert!(a.no_picker_overlay);
        assert!(a.detach_renderer);
    }

    #[test]
    fn attach_tab_no_picker_overlay_noop_with_no_run_renderer() {
        let a = attach_tab(&["--no-picker-overlay", "--no-run-renderer"]).expect("parses");
        assert!(a.no_picker_overlay);
        assert!(a.no_run_renderer);
    }

    #[test]
    fn settings_set_parses_chrome_picker_overlay_default() {
        let on = parse_args(&argv(&[
            "settings",
            "set",
            "chrome.picker_overlay_default",
            "true",
        ]))
        .unwrap();
        assert_eq!(
            settings_set(on).target,
            SettingsSetTarget::PickerOverlayDefault(true)
        );
        let off = parse_args(&argv(&[
            "settings",
            "set",
            "chrome.picker_overlay_default",
            "false",
            "--base",
            "/tmp/base",
        ]))
        .unwrap();
        let args = settings_set(off);
        assert_eq!(args.target, SettingsSetTarget::PickerOverlayDefault(false));
        assert_eq!(args.base, Some(PathBuf::from("/tmp/base")));
    }

    #[test]
    fn settings_reset_parses_chrome_picker_overlay_default() {
        let reset = settings_reset(
            parse_args(&argv(&[
                "settings",
                "reset",
                "chrome.picker_overlay_default",
            ]))
            .unwrap(),
        );
        assert_eq!(
            reset.selection,
            SettingsResetSelection::Key(crate::SettingsResetTarget::PickerOverlayDefault)
        );
    }

    // ---- worktree-cleanup: parser ------------------------------------------------------------

    fn worktree_cleanup_args(items: &[&str]) -> WorktreeCleanupArgs {
        let mut full = vec!["worktree-cleanup"];
        full.extend_from_slice(items);
        let Command::WorktreeCleanup(a) =
            parse_args(&argv(&full)).expect("worktree-cleanup parses")
        else {
            panic!("expected WorktreeCleanup");
        };
        a
    }

    #[test]
    fn worktree_cleanup_parses_required_ids() {
        let a = worktree_cleanup_args(&["--workspace-id", "ws", "--session-id", "sess"]);
        assert_eq!(a.workspace_id.as_deref(), Some("ws"));
        assert_eq!(a.session_id.as_deref(), Some("sess"));
        assert_eq!(a.base, None);
        assert!(!a.confirm);
    }

    #[test]
    fn worktree_cleanup_parses_optional_base_and_confirm() {
        let a = worktree_cleanup_args(&[
            "--workspace-id",
            "ws",
            "--session-id",
            "sess",
            "--base",
            "/tmp/base",
            "--confirm",
        ]);
        assert_eq!(a.base.as_deref(), Some(Path::new("/tmp/base")));
        assert!(a.confirm);
    }

    #[test]
    fn worktree_cleanup_rejects_missing_required_flags() {
        assert!(parse_args(&argv(&["worktree-cleanup", "--workspace-id", "ws"])).is_err());
        assert!(parse_args(&argv(&["worktree-cleanup", "--session-id", "sess"])).is_err());
        assert!(parse_args(&argv(&["worktree-cleanup"])).is_err());
    }

    #[test]
    fn worktree_cleanup_rejects_duplicate_flags() {
        assert!(parse_args(&argv(&[
            "worktree-cleanup",
            "--workspace-id",
            "ws",
            "--workspace-id",
            "ws2",
            "--session-id",
            "sess",
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "worktree-cleanup",
            "--workspace-id",
            "ws",
            "--session-id",
            "sess",
            "--session-id",
            "sess2",
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "worktree-cleanup",
            "--workspace-id",
            "ws",
            "--session-id",
            "sess",
            "--base",
            "/a",
            "--base",
            "/b",
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "worktree-cleanup",
            "--workspace-id",
            "ws",
            "--session-id",
            "sess",
            "--confirm",
            "--confirm",
        ]))
        .is_err());
    }

    #[test]
    fn worktree_cleanup_rejects_unsafe_ids() {
        assert!(parse_args(&argv(&[
            "worktree-cleanup",
            "--workspace-id",
            "../escape",
            "--session-id",
            "sess",
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "worktree-cleanup",
            "--workspace-id",
            "ws",
            "--session-id",
            "bad/slash",
        ]))
        .is_err());
    }

    #[test]
    fn worktree_cleanup_rejects_double_dash_and_unknown_flags() {
        assert!(parse_args(&argv(&[
            "worktree-cleanup",
            "--workspace-id",
            "ws",
            "--session-id",
            "sess",
            "--",
            "rm",
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "worktree-cleanup",
            "--workspace-id",
            "ws",
            "--session-id",
            "sess",
            "--force",
        ]))
        .is_err());
    }

    #[test]
    fn worktree_cleanup_help_is_usage_error() {
        assert!(parse_args(&argv(&["worktree-cleanup", "--help"])).is_err());
        assert!(parse_args(&argv(&["worktree-cleanup", "-h"])).is_err());
    }

    // ---- worktree-list: parser ----------------------------------------------------------------

    fn worktree_list_args(items: &[&str]) -> WorktreeListArgs {
        let mut full = vec!["worktree-list"];
        full.extend_from_slice(items);
        let Command::WorktreeList(a) = parse_args(&argv(&full)).expect("worktree-list parses")
        else {
            panic!("expected WorktreeList");
        };
        a
    }

    #[test]
    fn worktree_list_parses_required_workspace_id() {
        let a = worktree_list_args(&["--workspace-id", "ws"]);
        assert_eq!(a.workspace_id.as_deref(), Some("ws"));
        assert_eq!(a.base, None);
    }

    #[test]
    fn worktree_list_parses_optional_base() {
        let a = worktree_list_args(&["--workspace-id", "ws", "--base", "/tmp/base"]);
        assert_eq!(a.base.as_deref(), Some(Path::new("/tmp/base")));
    }

    #[test]
    fn worktree_list_rejects_missing_workspace_id() {
        assert!(parse_args(&argv(&["worktree-list"])).is_err());
        assert!(parse_args(&argv(&["worktree-list", "--base", "/tmp/base"])).is_err());
    }

    #[test]
    fn worktree_list_rejects_duplicate_flags() {
        assert!(parse_args(&argv(&[
            "worktree-list",
            "--workspace-id",
            "ws",
            "--workspace-id",
            "ws2",
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "worktree-list",
            "--workspace-id",
            "ws",
            "--base",
            "/a",
            "--base",
            "/b",
        ]))
        .is_err());
    }

    #[test]
    fn worktree_list_rejects_unsafe_workspace_id() {
        assert!(parse_args(&argv(&["worktree-list", "--workspace-id", "../escape"])).is_err());
        assert!(parse_args(&argv(&["worktree-list", "--workspace-id", "bad/slash"])).is_err());
    }

    #[test]
    fn worktree_list_rejects_double_dash_and_unknown_flags() {
        assert!(parse_args(&argv(&[
            "worktree-list",
            "--workspace-id",
            "ws",
            "--",
            "rm",
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "worktree-list",
            "--workspace-id",
            "ws",
            "--confirm"
        ]))
        .is_err());
    }

    #[test]
    fn worktree_list_help_is_usage_error() {
        assert!(parse_args(&argv(&["worktree-list", "--help"])).is_err());
        assert!(parse_args(&argv(&["worktree-list", "-h"])).is_err());
    }

    #[test]
    fn worktree_list_parses_all_scope() {
        let a = worktree_list_args(&["--all"]);
        assert!(a.all);
        assert_eq!(a.workspace_id, None);
        assert_eq!(a.base, None);
    }

    #[test]
    fn worktree_list_parses_all_with_base() {
        let a = worktree_list_args(&["--all", "--base", "/tmp/base"]);
        assert!(a.all);
        assert_eq!(a.base.as_deref(), Some(Path::new("/tmp/base")));
    }

    #[test]
    fn worktree_list_rejects_missing_scope() {
        // Neither --workspace-id nor --all is a usage error.
        assert!(parse_args(&argv(&["worktree-list"])).is_err());
        assert!(parse_args(&argv(&["worktree-list", "--base", "/tmp/base"])).is_err());
    }

    #[test]
    fn worktree_list_rejects_both_scopes() {
        assert!(parse_args(&argv(&["worktree-list", "--workspace-id", "ws", "--all"])).is_err());
        assert!(parse_args(&argv(&["worktree-list", "--all", "--workspace-id", "ws"])).is_err());
    }

    #[test]
    fn worktree_list_rejects_duplicate_all() {
        assert!(parse_args(&argv(&["worktree-list", "--all", "--all"])).is_err());
    }

    #[test]
    fn worktree_list_parses_all_include_orphans() {
        let a = worktree_list_args(&["--all", "--include-orphans"]);
        assert!(a.all);
        assert!(a.include_orphans);
        assert_eq!(a.workspace_id, None);
        assert_eq!(a.base, None);
    }

    #[test]
    fn worktree_list_parses_all_include_orphans_with_base() {
        let a = worktree_list_args(&["--all", "--include-orphans", "--base", "/tmp/base"]);
        assert!(a.all);
        assert!(a.include_orphans);
        assert_eq!(a.base.as_deref(), Some(Path::new("/tmp/base")));
    }

    #[test]
    fn worktree_list_rejects_include_orphans_without_all() {
        // --include-orphans alone has no scope -> missing-scope usage error.
        assert!(parse_args(&argv(&["worktree-list", "--include-orphans"])).is_err());
        // --include-orphans with a base but no --all is still rejected.
        assert!(parse_args(&argv(&[
            "worktree-list",
            "--include-orphans",
            "--base",
            "/tmp/base",
        ]))
        .is_err());
    }

    #[test]
    fn worktree_list_rejects_include_orphans_with_workspace_id() {
        // Scoped (--workspace-id) + --include-orphans is invalid; orphans require --all.
        assert!(parse_args(&argv(&[
            "worktree-list",
            "--workspace-id",
            "ws",
            "--include-orphans",
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "worktree-list",
            "--include-orphans",
            "--workspace-id",
            "ws",
        ]))
        .is_err());
    }

    #[test]
    fn worktree_list_rejects_duplicate_include_orphans() {
        assert!(parse_args(&argv(&[
            "worktree-list",
            "--all",
            "--include-orphans",
            "--include-orphans",
        ]))
        .is_err());
    }

    // ---- command-palette: parser --------------------------------------------------------------

    fn command_palette_args(items: &[&str]) -> CommandPaletteArgs {
        let mut full = vec!["command-palette"];
        full.extend_from_slice(items);
        let Command::CommandPalette(a) = parse_args(&argv(&full)).expect("command-palette parses")
        else {
            panic!("expected CommandPalette");
        };
        a
    }

    #[test]
    fn command_palette_parses_list() {
        let a = command_palette_args(&["--list"]);
        assert!(a.list);
        assert_eq!(a.base, None);
    }

    #[test]
    fn command_palette_parses_base_before_list() {
        let a = command_palette_args(&["--base", "/tmp/base", "--list"]);
        assert!(a.list);
        assert_eq!(a.base.as_deref(), Some(Path::new("/tmp/base")));
    }

    #[test]
    fn command_palette_parses_list_before_base() {
        let a = command_palette_args(&["--list", "--base", "/tmp/base"]);
        assert!(a.list);
        assert_eq!(a.base.as_deref(), Some(Path::new("/tmp/base")));
    }

    #[test]
    fn command_palette_rejects_missing_list() {
        assert!(parse_args(&argv(&["command-palette"])).is_err());
        assert!(parse_args(&argv(&["command-palette", "--base", "/tmp/base"])).is_err());
    }

    #[test]
    fn command_palette_rejects_duplicate_list() {
        assert!(parse_args(&argv(&["command-palette", "--list", "--list"])).is_err());
    }

    #[test]
    fn command_palette_rejects_duplicate_base() {
        assert!(parse_args(&argv(&[
            "command-palette",
            "--list",
            "--base",
            "/a",
            "--base",
            "/b",
        ]))
        .is_err());
    }

    #[test]
    fn command_palette_rejects_unknown_flag_extra_arg_and_dashdash() {
        assert!(parse_args(&argv(&["command-palette", "--list", "--bogus"])).is_err());
        assert!(parse_args(&argv(&["command-palette", "--list", "extra"])).is_err());
        assert!(parse_args(&argv(&["command-palette", "--list", "--"])).is_err());
        // --base requires a value.
        assert!(parse_args(&argv(&["command-palette", "--list", "--base"])).is_err());
    }

    #[test]
    fn command_palette_parses_list_with_query() {
        let a = command_palette_args(&["--list", "--query", "settings"]);
        assert!(a.list);
        assert_eq!(a.query.as_deref(), Some("settings"));
    }

    #[test]
    fn command_palette_parses_query_before_list() {
        let a = command_palette_args(&["--query", "settings", "--list"]);
        assert!(a.list);
        assert_eq!(a.query.as_deref(), Some("settings"));
    }

    #[test]
    fn command_palette_parses_base_list_query_mixed_order() {
        let a = command_palette_args(&["--query", "settings", "--base", "/tmp/base", "--list"]);
        assert!(a.list);
        assert_eq!(a.base.as_deref(), Some(Path::new("/tmp/base")));
        assert_eq!(a.query.as_deref(), Some("settings"));
    }

    #[test]
    fn command_palette_rejects_duplicate_query() {
        assert!(parse_args(&argv(&[
            "command-palette",
            "--list",
            "--query",
            "a",
            "--query",
            "b",
        ]))
        .is_err());
    }

    #[test]
    fn command_palette_rejects_missing_query_value() {
        assert!(parse_args(&argv(&["command-palette", "--list", "--query"])).is_err());
    }

    #[test]
    fn command_palette_rejects_empty_or_whitespace_query() {
        assert!(parse_args(&argv(&["command-palette", "--list", "--query", ""])).is_err());
        assert!(parse_args(&argv(&["command-palette", "--list", "--query", "   "])).is_err());
        assert!(parse_args(&argv(&["command-palette", "--list", "--query", " \t "])).is_err());
    }

    #[test]
    fn command_palette_parses_list_with_preview() {
        let a = command_palette_args(&["--list", "--preview"]);
        assert!(a.list);
        assert!(a.preview);
        assert!(a.query.is_none());
    }

    #[test]
    fn command_palette_parses_preview_mixed_order_with_base_and_query() {
        let a = command_palette_args(&[
            "--preview",
            "--query",
            "settings",
            "--base",
            "/tmp/base",
            "--list",
        ]);
        assert!(a.list);
        assert!(a.preview);
        assert_eq!(a.base.as_deref(), Some(Path::new("/tmp/base")));
        assert_eq!(a.query.as_deref(), Some("settings"));
    }

    #[test]
    fn command_palette_rejects_duplicate_preview() {
        assert!(parse_args(&argv(&[
            "command-palette",
            "--list",
            "--preview",
            "--preview"
        ]))
        .is_err());
    }

    #[test]
    fn command_palette_rejects_value_or_extra_after_preview() {
        // --preview takes no value, so a trailing positional is an extra-arg error.
        assert!(parse_args(&argv(&["command-palette", "--list", "--preview", "extra"])).is_err());
    }

    #[test]
    fn command_palette_preview_still_requires_list() {
        assert!(parse_args(&argv(&["command-palette", "--preview"])).is_err());
    }

    #[test]
    fn command_palette_parses_describe() {
        let a = command_palette_args(&["--describe", "settings.show"]);
        assert!(!a.list);
        assert_eq!(a.describe.as_deref(), Some("settings.show"));
        assert!(a.base.is_none());
    }

    #[test]
    fn command_palette_parses_describe_with_base_any_order() {
        let a = command_palette_args(&["--base", "/tmp/base", "--describe", "settings.show"]);
        assert_eq!(a.describe.as_deref(), Some("settings.show"));
        assert_eq!(a.base.as_deref(), Some(Path::new("/tmp/base")));
        let b = command_palette_args(&["--describe", "settings.show", "--base", "/tmp/base"]);
        assert_eq!(b.describe.as_deref(), Some("settings.show"));
        assert_eq!(b.base.as_deref(), Some(Path::new("/tmp/base")));
    }

    #[test]
    fn command_palette_rejects_list_with_describe() {
        assert!(parse_args(&argv(&[
            "command-palette",
            "--list",
            "--describe",
            "settings.show"
        ]))
        .is_err());
    }

    #[test]
    fn command_palette_rejects_describe_with_query_or_preview() {
        assert!(parse_args(&argv(&[
            "command-palette",
            "--describe",
            "settings.show",
            "--query",
            "settings"
        ]))
        .is_err());
        assert!(parse_args(&argv(&[
            "command-palette",
            "--describe",
            "settings.show",
            "--preview"
        ]))
        .is_err());
    }

    #[test]
    fn command_palette_rejects_duplicate_describe() {
        assert!(parse_args(&argv(&[
            "command-palette",
            "--describe",
            "settings.show",
            "--describe",
            "dashboard.show"
        ]))
        .is_err());
    }

    #[test]
    fn command_palette_rejects_missing_describe_value() {
        assert!(parse_args(&argv(&["command-palette", "--describe"])).is_err());
    }

    #[test]
    fn command_palette_rejects_empty_or_whitespace_describe() {
        assert!(parse_args(&argv(&["command-palette", "--describe", ""])).is_err());
        assert!(parse_args(&argv(&["command-palette", "--describe", "   "])).is_err());
    }

    #[test]
    fn command_palette_rejects_neither_mode() {
        assert!(parse_args(&argv(&["command-palette"])).is_err());
        assert!(parse_args(&argv(&["command-palette", "--base", "/tmp/base"])).is_err());
    }

    #[test]
    fn unknown_command_list_includes_command_palette() {
        let err = parse_args(&argv(&["not-a-command"])).expect_err("unknown command errors");
        assert!(err.message.contains("command-palette"));
    }

    #[test]
    fn usage_mentions_command_palette() {
        assert!(usage().contains("command-palette --list"));
        assert!(usage().contains("command-palette --describe <action-id>"));
    }

    // ---- agent-start / agent-resume parsing -------------------------------------------------

    fn full_agent_start_args() -> Vec<String> {
        argv(&[
            "agent-start",
            "--agent-task-id",
            "t-1",
            "--project-id",
            "p-1",
            "--goal",
            "do the thing",
            "--session-id",
            "s-1",
            "--workspace-id",
            "ws-1",
            "--cwd",
            "/work",
            "--base",
            "/base",
            "--socket",
            "/tmp/x.sock",
            "--daemon",
            "/bin/d",
            "--log-dir",
            "/logs",
            "--cols",
            "100",
            "--rows",
            "40",
            "--keep-daemon",
            "--",
            "claude",
            "--dangerously",
        ])
    }

    #[test]
    fn agent_start_parses_all_required_and_optional_with_argv() {
        let Command::AgentStart(a) = parse_args(&full_agent_start_args()).unwrap() else {
            panic!("expected AgentStart");
        };
        assert_eq!(a.agent_task_id.as_deref(), Some("t-1"));
        assert_eq!(a.project_id.as_deref(), Some("p-1"));
        assert_eq!(a.goal.as_deref(), Some("do the thing"));
        assert_eq!(a.session_id.as_deref(), Some("s-1"));
        assert_eq!(a.workspace_id.as_deref(), Some("ws-1"));
        assert_eq!(a.cwd.as_deref(), Some(Path::new("/work")));
        assert_eq!(a.base.as_deref(), Some(Path::new("/base")));
        assert_eq!(a.socket.as_deref(), Some(Path::new("/tmp/x.sock")));
        assert_eq!(a.daemon_bin.as_deref(), Some(Path::new("/bin/d")));
        assert_eq!(a.log_dir.as_deref(), Some(Path::new("/logs")));
        assert_eq!(a.cols, Some(100));
        assert_eq!(a.rows, Some(40));
        assert!(a.keep_daemon);
        assert_eq!(a.agent_argv, argv(&["claude", "--dangerously"]));
    }

    #[test]
    fn agent_resume_parses_required_and_argv_without_project_or_goal() {
        let cmd = parse_args(&argv(&[
            "agent-resume",
            "--agent-task-id",
            "t-9",
            "--session-id",
            "s-2",
            "--workspace-id",
            "ws-2",
            "--cwd",
            "/work",
            "--",
            "claude",
            "resume",
        ]))
        .unwrap();
        let Command::AgentResume(a) = cmd else {
            panic!("expected AgentResume");
        };
        assert_eq!(a.agent_task_id.as_deref(), Some("t-9"));
        assert_eq!(a.session_id.as_deref(), Some("s-2"));
        assert_eq!(a.workspace_id.as_deref(), Some("ws-2"));
        assert_eq!(a.cwd.as_deref(), Some(Path::new("/work")));
        assert_eq!(a.agent_argv, argv(&["claude", "resume"]));
    }

    #[test]
    fn agent_resume_rejects_project_id_and_goal() {
        for bad in ["--project-id", "--goal"] {
            let err = parse_args(&argv(&[
                "agent-resume",
                "--agent-task-id",
                "t-1",
                bad,
                "x",
                "--",
                "claude",
            ]))
            .unwrap_err();
            assert!(
                err.message.contains("agent-resume does not accept"),
                "got: {}",
                err.message
            );
        }
    }

    #[test]
    fn agent_start_requires_dashdash() {
        let err = parse_args(&argv(&["agent-start", "--agent-task-id", "t-1"])).unwrap_err();
        assert!(
            err.message.contains("requires '-- "),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn agent_start_rejects_empty_argv_after_dashdash() {
        let err = parse_args(&argv(&["agent-start", "--agent-task-id", "t-1", "--"])).unwrap_err();
        assert!(
            err.message.contains("non-empty command after"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn agent_resume_requires_dashdash() {
        let err = parse_args(&argv(&["agent-resume", "--agent-task-id", "t-1"])).unwrap_err();
        assert!(
            err.message.contains("requires '-- "),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn agent_start_rejects_unknown_flag() {
        let err = parse_args(&argv(&["agent-start", "--nope", "--", "claude"])).unwrap_err();
        assert!(
            err.message.contains("unknown agent-start flag '--nope'"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn agent_resume_rejects_unknown_flag() {
        let err = parse_args(&argv(&["agent-resume", "--nope", "--", "claude"])).unwrap_err();
        assert!(
            err.message.contains("unknown agent-resume flag '--nope'"),
            "got: {}",
            err.message
        );
    }

    // ---- agent-start window-layout recording flags ------------------------------------------

    // Pure agent-start window-record resolver tests now live beside their resolver in
    // `agent.rs` (`resolve_agent_window_record`). Parser-error tests for the same flags stay here.

    #[test]
    fn agent_start_layout_flags_without_record_window_are_usage_errors() {
        for flag in [
            &["--window-id", "w"][..],
            &["--tab-id", "t"][..],
            &["--tab-title", "Title"][..],
            &["--tab-pinned", "true"][..],
        ] {
            let mut items = vec!["agent-start"];
            items.extend_from_slice(flag);
            items.extend_from_slice(&["--", "claude"]);
            let err = parse_args(&argv(&items)).unwrap_err();
            assert!(
                err.to_string().contains("requires --record-window"),
                "flag {flag:?} got: {err}"
            );
        }
    }

    #[test]
    fn agent_start_record_window_duplicate_flags_are_usage_errors() {
        for flag in [
            &["--record-window", "--record-window"][..],
            &["--record-window", "--window-id", "a", "--window-id", "b"][..],
            &["--record-window", "--tab-id", "a", "--tab-id", "b"][..],
            &["--record-window", "--tab-title", "a", "--tab-title", "b"][..],
            &[
                "--record-window",
                "--tab-pinned",
                "true",
                "--tab-pinned",
                "false",
            ][..],
        ] {
            let mut items = vec!["agent-start"];
            items.extend_from_slice(flag);
            items.extend_from_slice(&["--", "claude"]);
            let err = parse_args(&argv(&items)).unwrap_err();
            assert!(
                err.to_string().contains("at most once"),
                "flag {flag:?} got: {err}"
            );
        }
    }

    #[test]
    fn agent_start_record_tab_pinned_invalid_is_usage_error() {
        let err = parse_args(&argv(&[
            "agent-start",
            "--record-window",
            "--tab-pinned",
            "yes",
            "--",
            "claude",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("true"), "got: {err}");
    }

    // ---- agent-resume window-layout recording flags -----------------------------------------

    // Pure agent-resume window-record resolver tests now live beside their resolver in
    // `agent.rs` (`resolve_agent_resume_window_record`). Parser-error tests stay here.

    #[test]
    fn agent_resume_layout_flags_without_record_window_are_usage_errors() {
        for flag in [
            &["--window-id", "w"][..],
            &["--tab-id", "t"][..],
            &["--tab-title", "Title"][..],
            &["--tab-pinned", "true"][..],
        ] {
            let mut items = vec!["agent-resume"];
            items.extend_from_slice(flag);
            items.extend_from_slice(&["--", "claude"]);
            let err = parse_args(&argv(&items)).unwrap_err();
            assert!(
                err.to_string().contains("requires --record-window"),
                "flag {flag:?} got: {err}"
            );
        }
    }

    #[test]
    fn agent_resume_record_window_duplicate_flags_are_usage_errors() {
        for flag in [
            &["--record-window", "--record-window"][..],
            &["--record-window", "--window-id", "a", "--window-id", "b"][..],
            &["--record-window", "--tab-id", "a", "--tab-id", "b"][..],
            &["--record-window", "--tab-title", "a", "--tab-title", "b"][..],
            &[
                "--record-window",
                "--tab-pinned",
                "true",
                "--tab-pinned",
                "false",
            ][..],
        ] {
            let mut items = vec!["agent-resume"];
            items.extend_from_slice(flag);
            items.extend_from_slice(&["--", "claude"]);
            let err = parse_args(&argv(&items)).unwrap_err();
            assert!(
                err.to_string().contains("at most once"),
                "flag {flag:?} got: {err}"
            );
        }
    }

    #[test]
    fn agent_resume_record_tab_pinned_invalid_is_usage_error() {
        let err = parse_args(&argv(&[
            "agent-resume",
            "--record-window",
            "--tab-pinned",
            "yes",
            "--",
            "claude",
        ]))
        .unwrap_err();
        assert!(err.to_string().contains("true"), "got: {err}");
    }

    #[test]
    fn agent_start_rejects_non_numeric_and_out_of_range_cols_rows() {
        for (flag, val) in [("--cols", "abc"), ("--rows", "99999")] {
            let err = parse_args(&argv(&["agent-start", flag, val, "--", "claude"])).unwrap_err();
            assert!(
                err.message.contains("requires an integer in 1..=65535"),
                "flag {flag}={val} got: {}",
                err.message
            );
        }
    }

    #[test]
    fn agent_start_missing_flag_value_is_usage_error() {
        let err = parse_args(&argv(&["agent-start", "--agent-task-id"])).unwrap_err();
        assert!(
            err.message.contains("requires a value"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn unknown_command_message_lists_agent_commands() {
        let err = parse_args(&argv(&["frobnicate"])).unwrap_err();
        assert!(err.message.contains("agent-start"));
        assert!(err.message.contains("agent-resume"));
    }

    #[test]
    fn usage_mentions_agent_commands() {
        let u = usage();
        assert!(u.contains("maestro-app agent-start"));
        assert!(u.contains("maestro-app agent-resume"));
        assert!(u.contains("FLAGS (agent-start)"));
        assert!(u.contains("FLAGS (agent-resume)"));
        // The agent commands never keep a daemon on failure-after-spawn; the help must not
        // claim otherwise (it always keeps on success and cleans up owned daemons on failure).
        assert!(!u.contains("failure-after-spawn"));
    }

    // ---- agent-mark parser / DTO ----

    #[test]
    fn agent_mark_parses_waiting_form() {
        let cmd = parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--waiting-on-user",
            "--reason",
            "needs approval",
        ]))
        .unwrap();
        let Command::AgentMark(a) = cmd else {
            panic!("expected AgentMark");
        };
        assert_eq!(a.agent_task_id.as_deref(), Some("t"));
        assert_eq!(a.intent, Some(AgentMarkIntent::WaitingOnUser));
        assert_eq!(a.reason.as_deref(), Some("needs approval"));
        assert_eq!(a.base, None);
    }

    #[test]
    fn agent_mark_parses_blocked_form_with_base() {
        let cmd = parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--blocked",
            "--reason",
            "no creds",
            "--base",
            "/base",
        ]))
        .unwrap();
        let Command::AgentMark(a) = cmd else {
            panic!("expected AgentMark");
        };
        assert_eq!(a.intent, Some(AgentMarkIntent::Blocked));
        assert_eq!(a.reason.as_deref(), Some("no creds"));
        assert_eq!(a.base.as_deref(), Some(Path::new("/base")));
    }

    #[test]
    fn agent_mark_trims_reason() {
        let Command::AgentMark(a) = parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--blocked",
            "--reason",
            "  spaced  ",
        ]))
        .unwrap() else {
            panic!("expected AgentMark");
        };
        assert_eq!(a.reason.as_deref(), Some("spaced"));
    }

    #[test]
    fn agent_mark_rejects_missing_id() {
        assert!(parse_args(&argv(&["agent-mark", "--blocked", "--reason", "r"])).is_err());
    }

    #[test]
    fn agent_mark_rejects_missing_reason() {
        assert!(parse_args(&argv(&["agent-mark", "--agent-task-id", "t", "--blocked"])).is_err());
    }

    #[test]
    fn agent_mark_rejects_empty_reason() {
        assert!(parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--blocked",
            "--reason",
            "   ",
        ]))
        .is_err());
    }

    #[test]
    fn agent_mark_rejects_overlong_reason() {
        let long = "x".repeat(AGENT_MARK_REASON_MAX_LEN + 1);
        assert!(parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--blocked",
            "--reason",
            &long,
        ]))
        .is_err());
    }

    #[test]
    fn agent_mark_accepts_max_len_reason() {
        let max = "x".repeat(AGENT_MARK_REASON_MAX_LEN);
        let Command::AgentMark(a) = parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--blocked",
            "--reason",
            &max,
        ]))
        .unwrap() else {
            panic!("expected AgentMark");
        };
        assert_eq!(
            a.reason.as_deref().map(str::len),
            Some(AGENT_MARK_REASON_MAX_LEN)
        );
    }

    #[test]
    fn agent_mark_rejects_both_intents() {
        assert!(parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--waiting-on-user",
            "--blocked",
            "--reason",
            "r",
        ]))
        .is_err());
    }

    #[test]
    fn agent_mark_rejects_no_intent() {
        assert!(parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--reason",
            "r",
        ]))
        .is_err());
    }

    #[test]
    fn agent_mark_rejects_duplicate_id() {
        assert!(parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--agent-task-id",
            "u",
            "--blocked",
            "--reason",
            "r",
        ]))
        .is_err());
    }

    #[test]
    fn agent_mark_rejects_duplicate_reason() {
        assert!(parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--blocked",
            "--reason",
            "r1",
            "--reason",
            "r2",
        ]))
        .is_err());
    }

    #[test]
    fn agent_mark_rejects_repeated_same_intent() {
        assert!(parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--blocked",
            "--blocked",
            "--reason",
            "r",
        ]))
        .is_err());
    }

    #[test]
    fn agent_mark_rejects_unknown_flag() {
        assert!(parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--blocked",
            "--reason",
            "r",
            "--nope",
        ]))
        .is_err());
    }

    #[test]
    fn agent_mark_rejects_double_dash_argv() {
        assert!(parse_args(&argv(&[
            "agent-mark",
            "--agent-task-id",
            "t",
            "--blocked",
            "--reason",
            "r",
            "--",
            "x",
        ]))
        .is_err());
    }

    #[test]
    fn agent_mark_rejects_help() {
        assert!(parse_args(&argv(&["agent-mark", "--help"])).is_err());
    }

    #[test]
    fn usage_and_unknown_command_mention_agent_mark() {
        assert!(usage().contains("agent-mark"));
        let err = parse_args(&argv(&["bogus"])).unwrap_err();
        assert!(err.to_string().contains("agent-mark"));
    }

    // ---- agent-finish parser / DTO ----

    #[test]
    fn agent_finish_parses_succeeded_form() {
        let cmd = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--succeeded",
        ]))
        .unwrap();
        let Command::AgentFinish(a) = cmd else {
            panic!("expected AgentFinish");
        };
        assert_eq!(a.agent_task_id.as_deref(), Some("t"));
        assert_eq!(a.intent, Some(AgentFinishIntent::Succeeded));
        assert_eq!(a.summary, None);
        assert_eq!(a.base, None);
    }

    #[test]
    fn agent_finish_parses_failed_form_with_summary_and_base() {
        let cmd = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--failed",
            "--summary",
            "tests failed",
            "--base",
            "/base",
        ]))
        .unwrap();
        let Command::AgentFinish(a) = cmd else {
            panic!("expected AgentFinish");
        };
        assert_eq!(a.intent, Some(AgentFinishIntent::Failed));
        assert_eq!(a.summary.as_deref(), Some("tests failed"));
        assert_eq!(a.base.as_deref(), Some(Path::new("/base")));
    }

    #[test]
    fn agent_finish_parses_cancelled_form() {
        let Command::AgentFinish(a) = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--cancelled",
        ]))
        .unwrap() else {
            panic!("expected AgentFinish");
        };
        assert_eq!(a.intent, Some(AgentFinishIntent::Cancelled));
    }

    #[test]
    fn agent_finish_trims_summary() {
        let Command::AgentFinish(a) = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--succeeded",
            "--summary",
            "  shipped it  ",
        ]))
        .unwrap() else {
            panic!("expected AgentFinish");
        };
        assert_eq!(a.summary.as_deref(), Some("shipped it"));
    }

    #[test]
    fn agent_finish_empty_summary_is_none() {
        let Command::AgentFinish(a) = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--succeeded",
            "--summary",
            "   ",
        ]))
        .unwrap() else {
            panic!("expected AgentFinish");
        };
        assert_eq!(a.summary, None);
    }

    #[test]
    fn agent_finish_accepts_max_len_summary() {
        let summary = "x".repeat(AGENT_FINISH_SUMMARY_MAX_LEN);
        let Command::AgentFinish(a) = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--failed",
            "--summary",
            &summary,
        ]))
        .unwrap() else {
            panic!("expected AgentFinish");
        };
        assert_eq!(a.summary.as_deref().map(str::len), Some(summary.len()));
    }

    #[test]
    fn agent_finish_rejects_overlong_summary() {
        let summary = "x".repeat(AGENT_FINISH_SUMMARY_MAX_LEN + 1);
        let err = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--failed",
            "--summary",
            &summary,
        ]))
        .unwrap_err();
        assert!(err.message.contains("at most"), "got: {err}");
    }

    #[test]
    fn agent_finish_rejects_missing_id() {
        let err = parse_args(&argv(&["agent-finish", "--succeeded"])).unwrap_err();
        assert!(
            err.message.contains("requires --agent-task-id"),
            "got: {err}"
        );
    }

    #[test]
    fn agent_finish_rejects_missing_intent() {
        let err = parse_args(&argv(&["agent-finish", "--agent-task-id", "t"])).unwrap_err();
        assert!(
            err.message
                .contains("exactly one of --succeeded, --failed, or --cancelled"),
            "got: {err}"
        );
    }

    #[test]
    fn agent_finish_rejects_multiple_intents() {
        let err = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--succeeded",
            "--failed",
        ]))
        .unwrap_err();
        assert!(
            err.message
                .contains("exactly one of --succeeded, --failed, or --cancelled"),
            "got: {err}"
        );
    }

    #[test]
    fn agent_finish_rejects_repeated_same_intent() {
        let err = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--failed",
            "--failed",
        ]))
        .unwrap_err();
        assert!(
            err.message
                .contains("exactly one of --succeeded, --failed, or --cancelled"),
            "got: {err}"
        );
    }

    #[test]
    fn agent_finish_rejects_duplicate_id() {
        let err = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--agent-task-id",
            "t2",
            "--succeeded",
        ]))
        .unwrap_err();
        assert!(
            err.message
                .contains("--agent-task-id may be given at most once"),
            "got: {err}"
        );
    }

    #[test]
    fn agent_finish_rejects_duplicate_summary() {
        let err = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--succeeded",
            "--summary",
            "a",
            "--summary",
            "b",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("--summary may be given at most once"),
            "got: {err}"
        );
    }

    #[test]
    fn agent_finish_rejects_unknown_flag() {
        let err = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--succeeded",
            "--bogus",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("unknown agent-finish flag"),
            "got: {err}"
        );
    }

    #[test]
    fn agent_finish_rejects_double_dash_argv() {
        let err = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--succeeded",
            "--",
            "x",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("does not accept a '--' argv"),
            "got: {err}"
        );
    }

    #[test]
    fn agent_finish_rejects_help() {
        let err = parse_args(&argv(&[
            "agent-finish",
            "--agent-task-id",
            "t",
            "--succeeded",
            "--help",
        ]))
        .unwrap_err();
        assert!(err.message.contains("--help"), "got: {err}");
    }

    #[test]
    fn usage_and_unknown_command_mention_agent_finish() {
        assert!(usage().contains("agent-finish"));
        let err = parse_args(&argv(&["bogus"])).unwrap_err();
        assert!(err.to_string().contains("agent-finish"));
    }

    // ---- launch command parser --------------------------------------------------------------
    //
    // Pure `launch` CLI parser tests live here beside `parse_launch`, the `Command::Launch` arm,
    // and `LaunchArgs`. Launch-output DTO, title/status-label helper, child-log, and lifecycle
    // tests stay in `output.rs` / `lifecycle.rs` next to their helpers.

    fn launch_args(items: &[&str]) -> LaunchArgs {
        let mut full = vec!["launch"];
        full.extend_from_slice(items);
        match parse_args(&argv(&full)).unwrap() {
            Command::Launch(a) => *a,
            _ => panic!("expected launch"),
        }
    }

    // The explicit launch title/status-label hybrid tests parse `LaunchArgs` through the launch
    // parser (via `launch_args`) and then feed the parsed values into the output helpers, so they
    // live here beside the launch parser tests. The direct `effective_window_title` / `status_label`
    // helper tests stay in `output.rs` (`output::tests`).
    use crate::{effective_window_title, status_label};

    #[test]
    fn default_title_from_explicit_session_id() {
        let a = launch_args(&["--session-id", "work-1"]);
        assert_eq!(a.title, None);
        let sid = a.session_id.as_deref().unwrap_or(DEFAULT_SESSION_ID);
        assert_eq!(
            effective_window_title(a.title.as_deref(), sid),
            "Hydra - work-1"
        );
    }

    #[test]
    fn explicit_title_is_used() {
        let a = launch_args(&["--title", "My Window"]);
        assert_eq!(a.title.as_deref(), Some("My Window"));
        assert_eq!(
            effective_window_title(a.title.as_deref(), DEFAULT_SESSION_ID),
            "My Window"
        );
    }

    #[test]
    fn status_label_from_explicit_session_id() {
        let a = launch_args(&["--session-id", "work-1"]);
        let sid = a.session_id.as_deref().unwrap_or(DEFAULT_SESSION_ID);
        assert_eq!(status_label(sid), "Hydra · work-1");
    }

    #[test]
    fn launch_defaults_are_all_none() {
        let cmd = parse_args(&argv(&["launch"])).unwrap();
        assert_eq!(cmd, Command::Launch(Box::default()));
    }

    #[test]
    fn launch_parses_all_flags() {
        let cmd = parse_args(&argv(&[
            "launch",
            "--socket",
            "/tmp/x.sock",
            "--session-id",
            "sid-1",
            "--cwd",
            "/work",
            "--base",
            "/base",
            "--daemon",
            "/bin/d",
            "--renderer",
            "/bin/r",
            "--no-run-renderer",
        ]))
        .unwrap();
        let Command::Launch(a) = cmd else {
            panic!("expected launch")
        };
        assert_eq!(a.socket, Some(PathBuf::from("/tmp/x.sock")));
        assert_eq!(a.session_id.as_deref(), Some("sid-1"));
        assert_eq!(a.cwd, Some(PathBuf::from("/work")));
        assert_eq!(a.base, Some(PathBuf::from("/base")));
        assert_eq!(a.daemon_bin, Some(PathBuf::from("/bin/d")));
        assert_eq!(a.renderer_bin, Some(PathBuf::from("/bin/r")));
        assert!(a.no_run_renderer);
        assert!(a.session_argv.is_empty());
    }

    #[test]
    fn double_dash_captures_session_argv_verbatim() {
        let cmd = parse_args(&argv(&["launch", "--", "vim", "--clean", "file.txt"])).unwrap();
        let Command::Launch(a) = cmd else {
            panic!("expected launch")
        };
        // `--clean` after `--` is part of the session argv, not a maestro-app flag.
        assert_eq!(a.session_argv, argv(&["vim", "--clean", "file.txt"]));
    }

    #[test]
    fn missing_flag_value_errors() {
        let err = parse_args(&argv(&["launch", "--socket"])).unwrap_err();
        assert!(err.message.contains("requires a value"));
    }

    #[test]
    fn unknown_launch_flag_errors() {
        let err = parse_args(&argv(&["launch", "--nope"])).unwrap_err();
        assert!(err.message.contains("unknown launch flag"));
    }

    #[test]
    fn file_preview_flag_parses_path() {
        let a = launch_args(&["--file-preview", "/tmp/notes.txt"]);
        assert_eq!(a.file_preview, Some(PathBuf::from("/tmp/notes.txt")));
    }

    #[test]
    fn file_preview_defaults_to_none() {
        let a = launch_args(&[]);
        assert_eq!(a.file_preview, None);
    }

    #[test]
    fn file_preview_requires_a_value() {
        let err = parse_args(&argv(&["launch", "--file-preview"])).unwrap_err();
        assert!(err.message.contains("requires a value"));
    }

    #[test]
    fn file_preview_rejected_more_than_once() {
        let err = parse_args(&argv(&[
            "launch",
            "--file-preview",
            "/tmp/a.txt",
            "--file-preview",
            "/tmp/b.txt",
        ]))
        .unwrap_err();
        assert!(err
            .message
            .contains("--file-preview may be given at most once"));
    }

    #[test]
    fn file_preview_rejected_with_detach_renderer() {
        let err = parse_args(&argv(&[
            "launch",
            "--file-preview",
            "/tmp/a.txt",
            "--detach-renderer",
        ]))
        .unwrap_err();
        assert!(err
            .message
            .contains("--file-preview is not supported with --detach-renderer"));
    }

    #[test]
    fn file_preview_rejected_with_new_tab_default_shell() {
        let err = parse_args(&argv(&[
            "launch",
            "--file-preview",
            "/tmp/a.txt",
            "--top-tab-bar",
            "--new-tab-default-shell",
        ]))
        .unwrap_err();
        assert!(err
            .message
            .contains("--file-preview is not supported with --new-tab-default-shell"));
    }

    #[test]
    fn file_preview_allowed_with_no_run_renderer() {
        let a = launch_args(&["--file-preview", "/tmp/a.txt", "--no-run-renderer"]);
        assert_eq!(a.file_preview, Some(PathBuf::from("/tmp/a.txt")));
        assert!(a.no_run_renderer);
    }

    #[test]
    fn layout_flags_without_record_window_are_usage_errors() {
        for flag in [
            &["--window-id", "w"][..],
            &["--tab-id", "t"][..],
            &["--tab-title", "Title"][..],
            &["--tab-pinned", "true"][..],
        ] {
            let mut items = vec!["launch"];
            items.extend_from_slice(flag);
            let err = parse_args(&argv(&items)).unwrap_err();
            assert!(
                err.to_string().contains("requires --record-window"),
                "flag {flag:?} got: {err}"
            );
        }
    }

    #[test]
    fn record_window_duplicate_flags_are_usage_errors() {
        for items in [
            vec!["launch", "--record-window", "--record-window"],
            vec![
                "launch",
                "--record-window",
                "--window-id",
                "a",
                "--window-id",
                "b",
            ],
            vec![
                "launch",
                "--record-window",
                "--tab-id",
                "a",
                "--tab-id",
                "b",
            ],
            vec![
                "launch",
                "--record-window",
                "--tab-title",
                "a",
                "--tab-title",
                "b",
            ],
            vec![
                "launch",
                "--record-window",
                "--fresh-window",
                "--fresh-window",
            ],
            vec![
                "launch",
                "--record-window",
                "--tab-pinned",
                "true",
                "--tab-pinned",
                "false",
            ],
        ] {
            let err = parse_args(&argv(&items)).unwrap_err();
            assert!(
                err.to_string().contains("at most once"),
                "items {items:?} got: {err}"
            );
        }
    }

    #[test]
    fn record_tab_pinned_invalid_is_usage_error() {
        let err =
            parse_args(&argv(&["launch", "--record-window", "--tab-pinned", "yes"])).unwrap_err();
        assert!(err.to_string().contains("true"), "got: {err}");
    }

    #[test]
    fn launch_fresh_window_requires_and_combines_with_record_window() {
        let err = parse_args(&argv(&["launch", "--fresh-window"])).unwrap_err();
        assert!(
            err.to_string().contains("requires --record-window"),
            "got: {err}"
        );

        let a = launch_args(&["--record-window", "--fresh-window"]);
        assert!(a.record_window);
        assert!(a.fresh_window);
    }

    #[test]
    fn product_startup_parses_for_packaged_headless_launch() {
        let a = launch_args(&[
            "--product-startup",
            "--top-tab-bar",
            "--no-dashboard-panel",
            "--new-tab-default-shell",
            "--title",
            "Hydra",
            "--no-run-renderer",
        ]);
        assert!(a.product_startup);
        assert!(!a.record_window);
        assert!(!a.fresh_window);
        assert!(a.top_tab_bar);
        assert!(a.new_tab_default_shell);
        assert!(a.no_run_renderer);
    }

    #[test]
    fn product_startup_rejects_duplicate_and_identity_overrides() {
        let cases = [
            &["launch", "--product-startup", "--product-startup"][..],
            &["launch", "--product-startup", "--record-window"][..],
            &["launch", "--product-startup", "--session-id", "another"][..],
            &["launch", "--product-startup", "--cwd", "/tmp"][..],
            &["launch", "--product-startup", "--detach-renderer"][..],
            &["launch", "--product-startup", "--", "bash"][..],
        ];
        for args in cases {
            let error = parse_args(&argv(args)).unwrap_err();
            assert!(
                error.message.contains("--product-startup"),
                "args={args:?}, error={error}"
            );
        }
    }

    // ---- launch chrome / new-tab flags ------------------------------------------------------

    #[test]
    fn launch_top_tab_bar_new_tab_default_shell_record_window_parses() {
        // The documented launch path must parse cleanly.
        let a = launch_args(&[
            "--top-tab-bar",
            "--new-tab-default-shell",
            "--record-window",
        ]);
        assert!(a.top_tab_bar);
        assert!(!a.no_top_tab_bar);
        assert!(a.new_tab_default_shell);
        assert!(a.record_window);
        // The resolved chrome flags fold the top-tab-bar enable; new-tab policy is present.
        assert_eq!(a.chrome_flags().top_tab_bar, Some(true));
        let policy = a.new_tab_launch_policy().expect("policy present");
        assert_eq!(policy.title, "shell");
        assert_eq!(policy.workspace_id, DEFAULT_SESSION_ID);
    }

    #[test]
    fn launch_new_tab_title_and_workspace_id_parse() {
        let a = launch_args(&[
            "--top-tab-bar",
            "--new-tab-default-shell",
            "--new-tab-title",
            "scratch",
            "--new-tab-workspace-id",
            "ws-1",
        ]);
        let policy = a.new_tab_launch_policy().expect("policy present");
        assert_eq!(policy.title, "scratch");
        assert_eq!(policy.workspace_id, "ws-1");
    }

    #[test]
    fn launch_no_top_tab_bar_folds_disable() {
        let a = launch_args(&["--no-top-tab-bar"]);
        assert_eq!(a.chrome_flags().top_tab_bar, Some(false));
    }

    #[test]
    fn launch_top_tab_bar_default_chrome_flags_are_none() {
        // Neither flag given: the tri-state is absent so the mode-aware default applies later.
        let a = launch_args(&[]);
        assert_eq!(a.chrome_flags().top_tab_bar, None);
        assert!(a.new_tab_launch_policy().is_none());
    }

    #[test]
    fn launch_top_tab_bar_and_no_top_tab_bar_are_mutually_exclusive() {
        let err = parse_args(&argv(&["launch", "--top-tab-bar", "--no-top-tab-bar"])).unwrap_err();
        assert!(
            err.to_string()
                .contains("--top-tab-bar and --no-top-tab-bar are mutually exclusive"),
            "got: {err}"
        );
    }

    #[test]
    fn launch_duplicate_chrome_new_tab_flags_are_usage_errors() {
        for items in [
            vec!["launch", "--top-tab-bar", "--top-tab-bar"],
            vec!["launch", "--no-top-tab-bar", "--no-top-tab-bar"],
            vec![
                "launch",
                "--top-tab-bar",
                "--new-tab-default-shell",
                "--new-tab-default-shell",
            ],
            vec![
                "launch",
                "--top-tab-bar",
                "--new-tab-default-shell",
                "--new-tab-title",
                "a",
                "--new-tab-title",
                "b",
            ],
            vec![
                "launch",
                "--top-tab-bar",
                "--new-tab-default-shell",
                "--new-tab-workspace-id",
                "a",
                "--new-tab-workspace-id",
                "b",
            ],
        ] {
            let err = parse_args(&argv(&items)).unwrap_err();
            assert!(
                err.to_string().contains("at most once"),
                "items {items:?} got: {err}"
            );
        }
    }

    #[test]
    fn launch_new_tab_default_shell_requires_top_tab_bar() {
        let err = parse_args(&argv(&["launch", "--new-tab-default-shell"])).unwrap_err();
        assert!(
            err.to_string()
                .contains("--new-tab-default-shell requires --top-tab-bar"),
            "got: {err}"
        );
    }

    #[test]
    fn launch_new_tab_title_requires_new_tab_default_shell() {
        let err =
            parse_args(&argv(&["launch", "--top-tab-bar", "--new-tab-title", "x"])).unwrap_err();
        assert!(
            err.to_string()
                .contains("--new-tab-title requires --new-tab-default-shell"),
            "got: {err}"
        );
    }

    #[test]
    fn launch_new_tab_workspace_id_requires_new_tab_default_shell() {
        let err = parse_args(&argv(&[
            "launch",
            "--top-tab-bar",
            "--new-tab-workspace-id",
            "ws",
        ]))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("--new-tab-workspace-id requires --new-tab-default-shell"),
            "got: {err}"
        );
    }

    #[test]
    fn launch_new_tab_workspace_id_is_validated_as_safe_id() {
        let err = parse_args(&argv(&[
            "launch",
            "--top-tab-bar",
            "--new-tab-default-shell",
            "--new-tab-workspace-id",
            "../escape",
        ]))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("--new-tab-workspace-id is invalid"),
            "got: {err}"
        );
    }

    #[test]
    fn launch_top_tab_bar_with_detach_renderer_is_rejected() {
        let err = parse_args(&argv(&["launch", "--top-tab-bar", "--detach-renderer"])).unwrap_err();
        assert!(
            err.to_string()
                .contains("--top-tab-bar is not supported with --detach-renderer"),
            "got: {err}"
        );
    }

    #[test]
    fn empty_title_is_rejected() {
        let err = parse_args(&argv(&["launch", "--title", ""])).unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn control_character_title_is_rejected() {
        let err = parse_args(&argv(&["launch", "--title", "bad\u{7}title"])).unwrap_err();
        assert!(err.to_string().contains("control"), "got: {err}");
    }

    #[test]
    fn too_long_title_is_rejected() {
        let long = "x".repeat(TITLE_MAX_LEN + 1);
        let err = parse_args(&argv(&["launch", "--title", &long])).unwrap_err();
        assert!(err.to_string().contains("too long"), "got: {err}");
    }

    #[test]
    fn max_length_title_is_accepted() {
        let exact = "y".repeat(TITLE_MAX_LEN);
        let a = launch_args(&["--title", &exact]);
        assert_eq!(a.title.as_deref(), Some(exact.as_str()));
    }

    #[test]
    fn title_with_detach_renderer_is_rejected() {
        let err = parse_args(&argv(&["launch", "--title", "X", "--detach-renderer"])).unwrap_err();
        assert!(
            err.to_string()
                .contains("--title is not supported with --detach-renderer"),
            "got: {err}"
        );
    }

    #[test]
    fn title_with_no_run_renderer_is_accepted() {
        // In smoke mode `--title` is accepted (parsed), even though it has no GUI effect.
        let a = launch_args(&["--title", "Smoke", "--no-run-renderer"]);
        assert_eq!(a.title.as_deref(), Some("Smoke"));
        assert!(a.no_run_renderer);
    }

    #[test]
    fn log_dir_flag_parses() {
        let a = launch_args(&["--log-dir", "/tmp/logs"]);
        assert_eq!(a.log_dir, Some(PathBuf::from("/tmp/logs")));
    }

    #[test]
    fn log_dir_defaults_to_none() {
        let a = launch_args(&["--no-run-renderer"]);
        assert_eq!(a.log_dir, None);
    }

    #[test]
    fn missing_log_dir_value_is_usage_error() {
        let err = parse_args(&argv(&["launch", "--log-dir"])).unwrap_err();
        assert!(err.message.contains("requires a value"), "got: {err}");
    }

    #[test]
    fn usage_mentions_log_dir() {
        assert!(usage().contains("--log-dir"));
    }

    #[test]
    fn launch_parses_detach_and_keep_daemon() {
        let cmd = parse_args(&argv(&["launch", "--detach-renderer", "--keep-daemon"])).unwrap();
        let Command::Launch(a) = cmd else {
            panic!("expected launch")
        };
        assert!(a.detach_renderer);
        assert!(a.keep_daemon);
        assert!(!a.no_run_renderer);
    }

    #[test]
    fn no_run_renderer_with_detach_is_usage_error() {
        let err =
            parse_args(&argv(&["launch", "--no-run-renderer", "--detach-renderer"])).unwrap_err();
        assert!(
            err.message.contains("mutually exclusive"),
            "got: {}",
            err.message
        );
    }

    #[test]
    fn keep_daemon_valid_in_no_run_renderer_mode() {
        let cmd = parse_args(&argv(&["launch", "--no-run-renderer", "--keep-daemon"])).unwrap();
        let Command::Launch(a) = cmd else {
            panic!("expected launch")
        };
        assert!(a.no_run_renderer);
        assert!(a.keep_daemon);
    }

    #[test]
    fn usage_mentions_lifecycle_flags() {
        let u = usage();
        assert!(u.contains("--detach-renderer"));
        assert!(u.contains("--keep-daemon"));
    }

    #[test]
    fn usage_mentions_launch_and_no_run_renderer() {
        let u = usage();
        assert!(u.contains("launch"));
        assert!(u.contains("--no-run-renderer"));
    }

    // ---- dashboard command parser -----------------------------------------------------------
    //
    // These pure `dashboard` CLI parser tests were localized from `lib.rs::tests` to live beside
    // the parser code they exercise: `parse_args`, the `Command::Dashboard` arm, `DashboardArgs`,
    // and `parse_dashboard`. Dashboard DTO/projection/view-model/panel-line/picker-projection/
    // status-suffix tests stay in `lib.rs`.

    #[test]
    fn dashboard_no_flags_parses_to_default() {
        let cmd = parse_args(&argv(&["dashboard"])).unwrap();
        assert_eq!(cmd, Command::Dashboard(DashboardArgs::default()));
    }

    #[test]
    fn dashboard_with_base_parses() {
        let cmd = parse_args(&argv(&["dashboard", "--base", "/base"])).unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert_eq!(a.base, Some(PathBuf::from("/base")));
    }

    #[test]
    fn dashboard_unknown_flag_errors() {
        let err = parse_args(&argv(&["dashboard", "--nope"])).unwrap_err();
        assert!(err.message.contains("unknown dashboard flag"), "got: {err}");
    }

    #[test]
    fn dashboard_missing_base_value_is_usage_error() {
        let err = parse_args(&argv(&["dashboard", "--base"])).unwrap_err();
        assert!(err.message.contains("requires a value"), "got: {err}");
    }

    #[test]
    fn usage_mentions_dashboard_command() {
        let u = usage();
        assert!(u.contains("dashboard"));
        assert!(u.contains("maestro-app dashboard [--base <dir>]"));
        assert!(u.contains("--with-session-reconcile"));
    }

    #[test]
    fn dashboard_with_session_reconcile_parses() {
        let cmd = parse_args(&argv(&["dashboard", "--with-session-reconcile"])).unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(a.with_session_reconcile);
        assert_eq!(a.socket, None);
    }

    #[test]
    fn dashboard_socket_parses_with_reconcile() {
        let cmd = parse_args(&argv(&[
            "dashboard",
            "--with-session-reconcile",
            "--socket",
            "/run/m.sock",
        ]))
        .unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(a.with_session_reconcile);
        assert_eq!(a.socket, Some(PathBuf::from("/run/m.sock")));
    }

    #[test]
    fn dashboard_socket_without_reconcile_is_usage_error() {
        let err = parse_args(&argv(&["dashboard", "--socket", "/run/m.sock"])).unwrap_err();
        assert!(
            err.message.contains("requires --with-session-reconcile"),
            "got: {err}"
        );
    }

    #[test]
    fn dashboard_duplicate_base_is_usage_error() {
        let err = parse_args(&argv(&[
            "dashboard",
            "--base",
            "/tmp/a",
            "--base",
            "/tmp/b",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("--base may be given at most once"),
            "got: {err}"
        );
    }

    #[test]
    fn dashboard_duplicate_socket_is_usage_error() {
        let err = parse_args(&argv(&[
            "dashboard",
            "--with-session-reconcile",
            "--socket",
            "/tmp/a.sock",
            "--socket",
            "/tmp/b.sock",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("--socket may be given at most once"),
            "got: {err}"
        );
    }

    #[test]
    fn dashboard_duplicate_with_session_reconcile_is_usage_error() {
        let err = parse_args(&argv(&[
            "dashboard",
            "--with-session-reconcile",
            "--with-session-reconcile",
        ]))
        .unwrap_err();
        assert!(
            err.message
                .contains("--with-session-reconcile may be given at most once"),
            "got: {err}"
        );
    }

    #[test]
    fn dashboard_active_tasks_flag_parses() {
        let cmd = parse_args(&argv(&["dashboard", "--active-tasks"])).unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(a.active_tasks);
        assert!(!a.with_session_reconcile);
        assert_eq!(a.socket, None);
    }

    #[test]
    fn dashboard_active_tasks_absent_defaults_false() {
        let cmd = parse_args(&argv(&["dashboard"])).unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(!a.active_tasks);
    }

    #[test]
    fn dashboard_active_tasks_with_reconcile_and_socket_parses() {
        let cmd = parse_args(&argv(&[
            "dashboard",
            "--active-tasks",
            "--with-session-reconcile",
            "--socket",
            "/run/m.sock",
        ]))
        .unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(a.active_tasks);
        assert!(a.with_session_reconcile);
        assert_eq!(a.socket, Some(PathBuf::from("/run/m.sock")));
    }

    #[test]
    fn dashboard_active_tasks_socket_without_reconcile_is_usage_error() {
        // The `--socket` requires `--with-session-reconcile` rule must still hold under
        // `--active-tasks`.
        let err = parse_args(&argv(&[
            "dashboard",
            "--active-tasks",
            "--socket",
            "/run/m.sock",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("requires --with-session-reconcile"),
            "got: {err}"
        );
    }

    #[test]
    fn dashboard_duplicate_active_tasks_is_usage_error() {
        let err =
            parse_args(&argv(&["dashboard", "--active-tasks", "--active-tasks"])).unwrap_err();
        assert!(
            err.message
                .contains("--active-tasks may be given at most once"),
            "got: {err}"
        );
    }

    #[test]
    fn dashboard_task_results_flag_parses() {
        let cmd = parse_args(&argv(&["dashboard", "--task-results"])).unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(a.task_results);
        assert!(!a.active_tasks);
        assert!(!a.with_session_reconcile);
        assert_eq!(a.socket, None);
    }

    #[test]
    fn dashboard_task_results_absent_defaults_false() {
        let cmd = parse_args(&argv(&["dashboard"])).unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(!a.task_results);
    }

    #[test]
    fn dashboard_duplicate_task_results_is_usage_error() {
        let err =
            parse_args(&argv(&["dashboard", "--task-results", "--task-results"])).unwrap_err();
        assert!(
            err.message
                .contains("--task-results may be given at most once"),
            "got: {err}"
        );
    }

    #[test]
    fn dashboard_task_results_with_active_tasks_is_usage_error() {
        let err =
            parse_args(&argv(&["dashboard", "--task-results", "--active-tasks"])).unwrap_err();
        assert!(err.message.contains("mutually exclusive"), "got: {err}");
        // Order-independent.
        let err =
            parse_args(&argv(&["dashboard", "--active-tasks", "--task-results"])).unwrap_err();
        assert!(err.message.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn dashboard_task_results_socket_without_reconcile_is_usage_error() {
        let err = parse_args(&argv(&[
            "dashboard",
            "--task-results",
            "--socket",
            "/run/m.sock",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("requires --with-session-reconcile"),
            "got: {err}"
        );
    }

    #[test]
    fn dashboard_task_results_with_reconcile_and_socket_parses() {
        let cmd = parse_args(&argv(&[
            "dashboard",
            "--task-results",
            "--with-session-reconcile",
            "--socket",
            "/run/m.sock",
        ]))
        .unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(a.task_results);
        assert!(a.with_session_reconcile);
        assert_eq!(a.socket, Some(PathBuf::from("/run/m.sock")));
    }

    #[test]
    fn dashboard_view_model_flag_parses() {
        let cmd = parse_args(&argv(&["dashboard", "--view-model"])).unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(a.view_model);
        assert!(!a.active_tasks);
        assert!(!a.task_results);
        assert!(!a.with_session_reconcile);
        assert_eq!(a.socket, None);
    }

    #[test]
    fn dashboard_view_model_absent_defaults_false() {
        let cmd = parse_args(&argv(&["dashboard"])).unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(!a.view_model);
    }

    #[test]
    fn dashboard_duplicate_view_model_is_usage_error() {
        let err = parse_args(&argv(&["dashboard", "--view-model", "--view-model"])).unwrap_err();
        assert!(
            err.message
                .contains("--view-model may be given at most once"),
            "got: {err}"
        );
    }

    #[test]
    fn dashboard_view_model_with_active_tasks_is_usage_error() {
        let err = parse_args(&argv(&["dashboard", "--view-model", "--active-tasks"])).unwrap_err();
        assert!(err.message.contains("mutually exclusive"), "got: {err}");
        // Order-independent.
        let err = parse_args(&argv(&["dashboard", "--active-tasks", "--view-model"])).unwrap_err();
        assert!(err.message.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn dashboard_view_model_with_task_results_is_usage_error() {
        let err = parse_args(&argv(&["dashboard", "--view-model", "--task-results"])).unwrap_err();
        assert!(err.message.contains("mutually exclusive"), "got: {err}");
        // Order-independent.
        let err = parse_args(&argv(&["dashboard", "--task-results", "--view-model"])).unwrap_err();
        assert!(err.message.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn dashboard_view_model_socket_without_reconcile_is_usage_error() {
        // The `--socket` requires `--with-session-reconcile` rule must still hold under
        // `--view-model`.
        let err = parse_args(&argv(&[
            "dashboard",
            "--view-model",
            "--socket",
            "/run/m.sock",
        ]))
        .unwrap_err();
        assert!(
            err.message.contains("requires --with-session-reconcile"),
            "got: {err}"
        );
    }

    #[test]
    fn dashboard_panel_lines_flag_parses() {
        let cmd = parse_args(&argv(&["dashboard", "--panel-lines"])).unwrap();
        match cmd {
            Command::Dashboard(args) => {
                assert!(args.panel_lines);
                assert!(!args.active_tasks);
                assert!(!args.task_results);
                assert!(!args.view_model);
            }
            other => panic!("expected dashboard, got {other:?}"),
        }
    }

    #[test]
    fn dashboard_panel_lines_absent_defaults_false() {
        let cmd = parse_args(&argv(&["dashboard"])).unwrap();
        match cmd {
            Command::Dashboard(args) => assert!(!args.panel_lines),
            other => panic!("expected dashboard, got {other:?}"),
        }
    }

    #[test]
    fn dashboard_panel_lines_duplicate_is_usage_error() {
        let err = parse_args(&argv(&["dashboard", "--panel-lines", "--panel-lines"])).unwrap_err();
        assert!(
            err.to_string()
                .contains("--panel-lines may be given at most once"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn dashboard_panel_lines_conflicts_with_other_reshapers_any_order() {
        for pair in [
            ["--panel-lines", "--active-tasks"],
            ["--active-tasks", "--panel-lines"],
            ["--panel-lines", "--task-results"],
            ["--task-results", "--panel-lines"],
            ["--panel-lines", "--view-model"],
            ["--view-model", "--panel-lines"],
        ] {
            let err = parse_args(&argv(&["dashboard", pair[0], pair[1]])).unwrap_err();
            assert!(
                err.to_string().contains("mutually exclusive"),
                "expected mutual-exclusion error for {pair:?}, got: {err}"
            );
        }
    }

    #[test]
    fn dashboard_panel_lines_socket_without_reconcile_is_usage_error() {
        let err = parse_args(&argv(&[
            "dashboard",
            "--panel-lines",
            "--socket",
            "/tmp/sock",
        ]))
        .unwrap_err();
        assert!(
            err.to_string()
                .contains("--socket requires --with-session-reconcile"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn dashboard_picker_flag_parses() {
        let cmd = parse_args(&argv(&["dashboard", "--picker"])).unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(a.picker);
        assert!(!a.active_tasks);
        assert!(!a.task_results);
        assert!(!a.view_model);
        assert!(!a.panel_lines);
        assert!(!a.with_session_reconcile);
        assert_eq!(a.socket, None);
    }

    #[test]
    fn dashboard_picker_absent_defaults_false() {
        let cmd = parse_args(&argv(&["dashboard"])).unwrap();
        let Command::Dashboard(a) = cmd else {
            panic!("expected dashboard")
        };
        assert!(!a.picker);
    }

    #[test]
    fn dashboard_duplicate_picker_is_usage_error() {
        let err = parse_args(&argv(&["dashboard", "--picker", "--picker"])).unwrap_err();
        assert!(
            err.message.contains("--picker may be given at most once"),
            "got: {err}"
        );
    }

    #[test]
    fn dashboard_picker_conflicts_with_other_reshapers_any_order() {
        for other in [
            "--active-tasks",
            "--task-results",
            "--view-model",
            "--panel-lines",
        ] {
            let err = parse_args(&argv(&["dashboard", "--picker", other])).unwrap_err();
            assert!(
                err.message.contains("mutually exclusive"),
                "picker+{other}: {err}"
            );
            // Order-independent.
            let err = parse_args(&argv(&["dashboard", other, "--picker"])).unwrap_err();
            assert!(
                err.message.contains("mutually exclusive"),
                "{other}+picker: {err}"
            );
        }
    }

    #[test]
    fn dashboard_picker_socket_without_reconcile_is_usage_error() {
        let err =
            parse_args(&argv(&["dashboard", "--picker", "--socket", "/run/m.sock"])).unwrap_err();
        assert!(
            err.message.contains("requires --with-session-reconcile"),
            "got: {err}"
        );
    }

    // ---- top-level dispatch parser ----------------------------------------------------------
    //
    // These broad top-level `parse_args` dispatch tests (no-args/help/unknown-command) were
    // localized from `lib.rs::tests` to live beside the dispatch code they exercise: `parse_args`,
    // the early `Command::Help` returns, and the root unknown-command error. This was the final
    // parser localization; all command-specific parser tests live here.

    #[test]
    fn no_args_is_help() {
        assert_eq!(parse_args(&[]).unwrap(), Command::Help);
    }

    #[test]
    fn help_flags_map_to_help() {
        for f in ["--help", "-h", "help"] {
            assert_eq!(parse_args(&argv(&[f])).unwrap(), Command::Help);
        }
    }

    #[test]
    fn unknown_command_errors() {
        let err = parse_args(&argv(&["frobnicate"])).unwrap_err();
        assert!(err.message.contains("unknown command"));
    }

    #[test]
    fn project_create_parses_required_and_optional_fields() {
        let cmd = parse_args(&argv(&[
            "project",
            "create",
            "--project-id",
            "alpha",
            "--name",
            "Alpha",
            "--root",
            "/repos/alpha",
            "--policy",
            "worktree",
            "--icon",
            "A",
            "--accent",
            "#abcdef",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Project(ProjectCommand::Create(ProjectCreateArgs {
                project_id: Some(s("alpha")),
                name: Some(s("Alpha")),
                root: Some(s("/repos/alpha")),
                policy: Some(s("worktree")),
                icon: Some(s("A")),
                accent_color: Some(s("#abcdef")),
                base: None,
            }))
        );
    }

    #[test]
    fn project_create_normalizes_policy_spellings() {
        for (raw, wire) in [
            ("scratch", "scratch_cwd"),
            ("scratch-cwd", "scratch_cwd"),
            ("repo-write", "repo_write"),
        ] {
            let cmd = parse_args(&argv(&[
                "project",
                "create",
                "--project-id",
                "p",
                "--name",
                "P",
                "--root",
                "/r",
                "--policy",
                raw,
            ]))
            .unwrap();
            match cmd {
                Command::Project(ProjectCommand::Create(a)) => {
                    assert_eq!(a.policy.as_deref(), Some(wire));
                }
                other => panic!("expected project create, got {other:?}"),
            }
        }
    }

    #[test]
    fn project_create_requires_project_id_name_and_root() {
        for missing in [
            vec!["project", "create", "--name", "P", "--root", "/r"],
            vec!["project", "create", "--project-id", "p", "--root", "/r"],
            vec!["project", "create", "--project-id", "p", "--name", "P"],
        ] {
            assert!(parse_args(&argv(&missing)).is_err());
        }
    }

    #[test]
    fn project_create_rejects_invalid_policy() {
        let err = parse_args(&argv(&[
            "project",
            "create",
            "--project-id",
            "p",
            "--name",
            "P",
            "--root",
            "/r",
            "--policy",
            "nope",
        ]))
        .unwrap_err();
        assert!(err.message.contains("--policy"));
    }

    #[test]
    fn project_list_parses_base_only() {
        let cmd = parse_args(&argv(&["project", "list", "--base", "/tmp/b"])).unwrap();
        assert_eq!(
            cmd,
            Command::Project(ProjectCommand::List(ProjectListArgs {
                base: Some(PathBuf::from("/tmp/b")),
            }))
        );
    }

    #[test]
    fn project_update_parses_clear_flags() {
        let cmd = parse_args(&argv(&[
            "project",
            "update",
            "--project-id",
            "alpha",
            "--name",
            "Renamed",
            "--clear-icon",
            "--clear-accent",
            "--clear-launch-defaults",
        ]))
        .unwrap();
        assert_eq!(
            cmd,
            Command::Project(ProjectCommand::Update(ProjectUpdateArgs {
                project_id: Some(s("alpha")),
                name: Some(s("Renamed")),
                root: None,
                policy: None,
                icon: None,
                clear_icon: true,
                accent_color: None,
                clear_accent: true,
                clear_launch_defaults: true,
                base: None,
            }))
        );
    }

    #[test]
    fn project_update_clear_launch_defaults_defaults_false_and_rejects_duplicate() {
        // not supplying the flag leaves it false (launch defaults unchanged)
        let cmd = parse_args(&argv(&["project", "update", "--project-id", "alpha"])).unwrap();
        match cmd {
            Command::Project(ProjectCommand::Update(a)) => assert!(!a.clear_launch_defaults),
            other => panic!("unexpected command: {other:?}"),
        }
        // supplying it twice is rejected
        let err = parse_args(&argv(&[
            "project",
            "update",
            "--project-id",
            "alpha",
            "--clear-launch-defaults",
            "--clear-launch-defaults",
        ]))
        .unwrap_err();
        assert!(err.message.contains("--clear-launch-defaults"));
    }

    #[test]
    fn project_update_rejects_icon_with_clear_icon() {
        let err = parse_args(&argv(&[
            "project",
            "update",
            "--project-id",
            "alpha",
            "--icon",
            "A",
            "--clear-icon",
        ]))
        .unwrap_err();
        assert!(err.message.contains("--icon") || err.message.contains("--clear-icon"));
    }

    #[test]
    fn project_update_requires_project_id() {
        assert!(parse_args(&argv(&["project", "update", "--name", "X"])).is_err());
    }

    #[test]
    fn project_delete_parses_project_id() {
        let cmd = parse_args(&argv(&["project", "delete", "--project-id", "alpha"])).unwrap();
        assert_eq!(
            cmd,
            Command::Project(ProjectCommand::Delete(ProjectRefArgs {
                project_id: Some(s("alpha")),
                base: None,
            }))
        );
    }

    #[test]
    fn project_reorder_parses_comma_list() {
        let cmd = parse_args(&argv(&["project", "reorder", "--order", "a,b,c"])).unwrap();
        assert_eq!(
            cmd,
            Command::Project(ProjectCommand::Reorder(ProjectReorderArgs {
                order: Some(vec![s("a"), s("b"), s("c")]),
                base: None,
            }))
        );
    }

    #[test]
    fn project_reorder_requires_order() {
        assert!(parse_args(&argv(&["project", "reorder"])).is_err());
    }

    #[test]
    fn project_unknown_subcommand_errors() {
        let err = parse_args(&argv(&["project", "frobnicate"])).unwrap_err();
        assert!(err.message.contains("unknown project subcommand"));
    }
}
