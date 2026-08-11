//! `maestro-app` — the first Rust-native application entrypoint/harness.
//!
//! This crate is intentionally small: it is the smallest native app that composes the existing
//! Rust runtime pieces end to end for ONE local session:
//!
//! 1. resolve or choose a local daemon socket (a PRIVATE dev socket by default — never the user's
//!    real default daemon socket unless `--socket` is explicit);
//! 2. spawn a `pty-daemon` on that socket when one is not already connectable, and wait boundedly
//!    for it to accept connections (reusing an already-running one instead of starting a second);
//! 3. start/attach one session through [`maestro_shell::ShellRuntime`];
//! 4. open the renderer for that session. By default (foreground) the renderer runs IN-PROCESS on
//!    the main thread via [`maestro_renderer::run_renderer`] — no child process and no requirement
//!    that the `maestro-renderer` binary exist. `--detach-renderer` instead spawns a separate
//!    `maestro-renderer <socket-path> <session-id>` child (a winit event loop cannot be detached
//!    from this process/main thread), so that mode still requires the renderer binary;
//! 5. provide a `--no-run-renderer` mode that does everything except open a GUI window, so the
//!    flow is smoke-testable without a display.
//!
//! This `lib.rs` holds the PURE, unit-testable surface (CLI parsing, binary-path resolution, the
//! dev-socket path, the renderer mode/binary policy, and the structured-output shaping). All
//! process IO (spawning the daemon, connecting, and the in-process or child renderer launch) lives
//! in `main.rs` so the helpers here stay deterministic.
//!
//! Non-goals (explicit): no browser/mobile/remote, no cloud auth, no multi-tab UI, no polished
//! window chrome, no daemon protocol change, and no dashboard-host redesign.

mod agent;
/// Provider-session history reader shared with optional authenticated extensions. Content stays on
/// the desktop; callers expose only content-blind metadata across extension boundaries.
pub use maestro_local_services::agent_history;
mod attention;
mod chrome;
mod cli;
mod command_palette;
mod constants;
mod dashboard;
mod dashboard_ui;
pub mod desktop_access_onboarding;
mod file_preview;
mod lifecycle;
/// Remote model catalog: refreshes the per-agent model dropdown lists from the published
/// downloads manifest without requiring an app release.
pub mod model_catalog;
mod new_tab;
pub mod optional_extension;
mod output;
mod picker;
mod settings;
/// Non-blocking new-release check against the published downloads manifest.
pub mod update_check;
mod window;
mod worktree;

// Re-export the lifecycle-support cluster extracted into `lifecycle.rs` (path defaults, binary
// resolution, session argv, the renderer command shape, child-process log paths, renderer-mode
// policy, the spawned-daemon keep policy, and owned-socket cleanup) so existing
// `maestro_app::<Item>` callers (main.rs, binary_smoke.rs, and the in-crate test module via
// `super::*`) keep their current paths. No item is made newly public: each keeps the `pub`
// visibility it had in `lib.rs`.
pub use lifecycle::{
    child_log_path, cleanup_owned_socket, default_base_dir, dev_socket_path,
    effective_session_argv, renderer_binary_required, renderer_command, resolve_binary,
    runtime_base_dir, session_argv, should_cleanup_owned_socket, should_keep_spawned_daemon,
    BinaryKind, BinarySource, ChildLogKind, ChildLogStream, RendererMode, SocketCleanup,
    DEV_SOCKET_FILENAME,
};

// Re-export the output-surface cluster extracted into `output.rs` (the user-visible window title and
// overlay status-label helpers, plus the launch/attach/window JSON output DTOs) so existing
// `maestro_app::<Item>` / `crate::<Item>` callers (main.rs, cli.rs, dashboard.rs, binary_smoke.rs, and
// the in-crate test module via `super::*`) keep their current paths. No item is made newly public:
// each keeps the `pub` visibility it had in `lib.rs`.
pub use output::{
    attach_tab_status_label, attach_tab_window_title, default_window_title, effective_window_title,
    status_label, validate_window_title, AttachTabFailure, AttachTabSuccess, FilePreviewReport,
    LaunchFailure, LaunchSuccess, WindowFailure, WindowLayoutSuccess, WindowViewSuccess,
};

// Re-export the agent-domain DTOs / wire envelopes / pure helpers extracted into `agent.rs` so
// existing `maestro_app::<Item>` callers (main.rs, binary_smoke.rs, and the in-crate test module
// via `super::*`) keep their current paths. No item is made newly public: each keeps the `pub`
// visibility it had in `lib.rs`. The argument PARSERS stay in `lib.rs` and resolve the moved DTOs
// through these re-exports.
pub use agent::{
    agent_task_state_wire_str, resolve_agent_resume_window_record, resolve_agent_window_record,
    AgentFailure, AgentFinishArgs, AgentFinishIntent, AgentFinishSuccess, AgentMarkArgs,
    AgentMarkIntent, AgentMarkSuccess, AgentResumeArgs, AgentStartArgs, AgentSuccess,
    AGENT_FINISH_SUMMARY_MAX_LEN, AGENT_MARK_REASON_MAX_LEN,
};

// Re-export the default one-window attach-tab chrome resolver cluster extracted into `chrome.rs`
// so existing `maestro_app::<Item>` / `crate::<Item>` callers (main.rs, cli.rs, and the in-crate
// test module via `super::*`) keep their current paths. No item is made newly public: each keeps
// the `pub` visibility it had in `lib.rs`. The argument PARSER stays in `lib.rs` and resolves the
// moved DTOs through these re-exports.
pub use chrome::{
    resolve_attach_tab_chrome, AttachTabChromeDefaults, AttachTabChromeFlags,
    EffectiveAttachTabChrome,
};

// Re-export the attention projection / wire-string / clear-refresh / live-refresh cluster extracted
// into `attention.rs` so existing `maestro_app::<Item>` / `crate::<Item>` callers (main.rs,
// dashboard.rs, window.rs, binary_smoke.rs, and the in-crate test module via `super::*`) keep their
// current paths. No item is made newly public: `attention_state_to_json` and `window_tab_view_to_json`
// stay module-private to `attention.rs`; the rest keep the `pub`/`pub(crate)` visibility they had in
// `lib.rs`.
pub use attention::{
    attention_needs_attention, clear_tab_attention_and_refresh_strip, rebuild_live_tab_strip_model,
    tab_attention_indicator, AttentionJson, LiveTabStripRefreshError, TabAttentionClearRefresh,
    TabAttentionClearRefreshError, TabAttentionIndicator,
};
pub(crate) use attention::{
    attention_source_wire_str, attention_wire_str, renderer_attention_indicator,
    session_status_wire_str,
};

pub use maestro_local_services::{inherited_project_launch_inputs, InheritedProjectLaunchInputs};

// Re-export the dashboard-domain DTOs / projections / pure helpers extracted into `dashboard.rs`
// so existing `maestro_app::<Item>` callers (main.rs, binary_smoke.rs, and the in-crate test module
// via `super::*`) keep their current paths. No item is made newly public: `panel_sanitize` and
// `panel_truncate` stay module-private to `dashboard.rs`; the rest keep the `pub` visibility they had
// in `lib.rs`. The argument PARSER stays in `lib.rs` and resolves the moved DTOs through these
// re-exports.
pub use dashboard::{
    attach_tab_dashboard_status_label, build_dashboard_panel_lines, build_dashboard_view_model,
    build_dock_model, dashboard_panel_to_renderer, dashboard_status_suffix, project_active_tasks,
    project_task_results, ActiveTaskRow, ActiveTasksSnapshot, DashboardArgs, DashboardFailure,
    DashboardPanelLimits, DashboardPanelLines, DashboardStateCounts, DashboardSuccess,
    DashboardViewModel, TaskResultRow, TaskResultsSnapshot,
};

// Re-export the React dashboard-chrome asset resolver for the future native WebView host. It is
// path resolution only: no WebView dependency, no process IO beyond the caller's existence check.
pub use dashboard_ui::{
    dashboard_ui_asset_candidates, dashboard_ui_file_url, dashboard_ui_host_preload_script,
    dashboard_ui_index_in_dev_repo, dashboard_ui_index_in_resources,
    dashboard_ui_index_near_macos_executable, dashboard_ui_index_near_packaged_executable,
    resolve_dashboard_ui_asset, DashboardUiAssetCandidates, DashboardUiAssetResolution,
    DashboardUiAssetSource, DASHBOARD_UI_DEFAULT_INTENT_POST, DASHBOARD_UI_INDEX_FILE,
    DASHBOARD_UI_RESOURCE_DIR,
};

// Re-export the bounded read-only file-preview reader extracted into `file_preview.rs`: it turns a
// local path into a small, bounded slice of UTF-8 lines (rejecting binary/oversize input) that the
// renderer projects into a side preview pane. Pure aside from one bounded file read.
pub use file_preview::{
    read_file_preview, read_file_preview_with_limits, FilePreview, FilePreviewError,
    PREVIEW_MAX_BYTES, PREVIEW_MAX_LINES, PREVIEW_MAX_LINE_CHARS,
};

// Re-export the worktree cleanup/list/provenance/staleness/orphan surface extracted into
// `worktree.rs` so existing `maestro_app::<Item>` callers (main.rs, binary_smoke.rs, and the
// in-crate test module via `super::*`) keep their current paths. No item is made newly public:
// `git_status_reason` and `classify_provenance` stay module-private to `worktree.rs` (their
// behavior tests live alongside them there); the rest keep the `pub` visibility they had in
// `lib.rs`.
pub use worktree::{
    build_orphan_candidates, build_worktree_list, build_worktree_list_all,
    classify_worktree_staleness, orphan_counts, plan_worktree_cleanup, worktree_cleanup_branch,
    OrphanFsEntry, OrphanPathStatus, OrphanRecordStatus, OrphanSegmentStatus, ProvenanceMarker,
    WorktreeCleanupDecision, WorktreeCleanupNonLoadedSession, WorktreeCleanupPlan,
    WorktreeCleanupReason, WorktreeCleanupSessionScan, WorktreeListCandidate, WorktreeListCounts,
    WorktreeListInspection, WorktreeListOrphanCandidate, WorktreeListOrphanCounts,
    WorktreeListOutput, WorktreeListOwnership, WorktreeListSessionStatus,
    WorktreeListWorkspaceStatus, WorktreeProvenanceStatus, WorktreeStaleness,
    STALENESS_IDLE_AFTER_MS, STALENESS_STALE_AFTER_MS,
};

// Re-export the picker-domain DTOs / projections / resolvers / pure helpers extracted into
// `picker.rs` so existing `maestro_app::<Item>` callers (main.rs, binary_smoke.rs, and the in-crate
// test module via `super::*`) keep their current paths. No item is made newly public:
// `picker_activation_tab_title`, `worktree_launch_policy`, `repo_write_launch_policy`,
// `lookup_fresh_picker_workspace`, and `classify_grant_consent_target` stay module-private to
// `picker.rs`; the rest keep the `pub` visibility they had in `lib.rs`. The argument PARSER
// (`dashboard --picker`) stays in `lib.rs` and resolves the moved DTOs through these re-exports.
pub use picker::{
    build_picker_overlay_model, build_picker_projection, picker_stale_decline_hint_text,
    project_header_hint_text, resolve_picker_activation, resolve_picker_consent_confirm,
    resolve_picker_consent_request, workspace_policy_wire_str, PickerActivationDeclineReason,
    PickerActivationResolution, PickerActiveTask, PickerConsentConfirmFields,
    PickerConsentConfirmResolution, PickerConsentRequestResolution, PickerProject,
    PickerProjection, PickerWorkspace, PICKER_STALE_DECLINE_HINT,
};

// Re-export the window-domain tab selection / switch / strip projection / close + closed-tab
// session lifecycle surface extracted into `window.rs` so existing `maestro_app::<Item>` callers
// (main.rs, binary_smoke.rs, and the in-crate test module via `super::*`) keep their current paths.
// No item is made newly public: each keeps the `pub` visibility it had in `lib.rs`. The argument
// PARSER (`window ...`), the window success/failure JSON envelopes, and the live runners stay in
// `lib.rs` and resolve the moved DTOs through these re-exports. The `NewTab*` planning/runtime
// surface itself moved into `new_tab.rs` (re-exported below) and resolves these window DTOs in turn.
pub use window::{
    apply_active_tab_close, apply_inactive_tab_close, apply_only_tab_close, apply_tab_activation,
    build_tab_strip_model, build_tab_strip_model_from_window_view, classify_focused_pane_close,
    execute_closed_tab_session_lifecycle, is_active_tab_close, maybe_send_font_size_update,
    maybe_send_theme_update, new_tab_snapshot_from_strip_tabs, plan_closed_tab_session_lifecycle,
    plan_next_active_tab, renderer_tab_strip, resolve_window_record, select_window_tab_session,
    selection_from_strip_tabs, split_subtree_close_order, surviving_active_tab_id, tab_record_json,
    tab_strip_model_changed, ActiveTab, ActiveTabCloseOutcome, ClosedTabKillOutcome,
    ClosedTabSessionLifecycle, FocusedPaneCloseClass, NextActivePlan, OnlyTabCloseOutcome,
    PaneRectJson, RendererCommandSink, RendererFontSizeRuntime, RendererTabRuntime,
    RendererThemeRuntime, SplitFromJson, TabActivation, TabCloseOutcome, TabSelection,
    TabSelectionError, TabStripItem, TabStripModel, TabStripModelError, TabSwitchController,
    TabSwitchError, WindowRecordParams, WindowTabJson, WindowViewTabJson, DEFAULT_WINDOW_ID,
};

// Re-export the NewTab production cluster — the new-tab planner, the prepared-start / workspace-prep
// / session-start / layout-record / strip-projection / renderer-send pipeline, and the foreground
// failure classification + recovery (plan / resolve / execute / effects) surface — extracted into
// `new_tab.rs` so existing `maestro_app::<Item>` callers (main.rs, binary_smoke.rs, and the in-crate
// test module via `super::*`) keep their current paths. No item is made newly public: the private
// helpers (`mint_unique_id`, `resolved_recovery_action_label`, `resolved_recovery_effect_outcome`,
// `run_new_tab_foreground_pipeline_from_prepared`, `new_tab_plan_session_id`) stay module-private to
// `new_tab.rs`; the rest keep the `pub` visibility they had in `lib.rs`. `ID_MINT_ATTEMPTS` now lives
// in `constants.rs` (re-exported from the crate root) and the attention/session wire-string helpers
// stay in `lib.rs`; the moved code resolves all of them via `crate::`.
pub use new_tab::{
    classify_new_tab_foreground_failure, execute_new_tab_recovery_plan, execute_preset_restore,
    execute_resolved_new_tab_recovery_plan, foreground_new_tab_recovery_context,
    kill_session_recovery_effect, new_tab_decline_status_label, new_tab_failure_scratch_to_remove,
    new_tab_prepared_start_params, new_tab_strip_projection, plan_new_tab,
    plan_new_tab_failure_recovery, prepare_new_tab_scratch_workspace,
    reconcile_renderer_state_recovery_effect, record_new_tab_in_window_layout,
    remove_new_tab_scratch, remove_scratch_recovery_effect,
    render_resolved_recovery_execution_log_line, render_resolved_recovery_log_line,
    resolve_new_tab_recovery, resolve_new_tab_recovery_plan, revert_renderer_strip_recovery_effect,
    rollback_tab_record_recovery_effect, run_new_tab_foreground_pipeline,
    run_new_tab_foreground_pipeline_with_consent, send_new_tab_attach_session,
    send_new_tab_set_tab_strip, start_new_tab_prepared_session, DaemonClientRecoverySessionKiller,
    ForegroundRendererStateController, IdGen, KillSessionRecoveryEffectResult, NewTabAbortReason,
    NewTabAttachSession, NewTabAttachSessionError, NewTabCwdBasis, NewTabFailureDiagnostic,
    NewTabFailureStage, NewTabForegroundError, NewTabForegroundRequest, NewTabForegroundSuccess,
    NewTabLaunchPolicy, NewTabLaunchSource, NewTabLayoutRecord, NewTabLayoutRecordError,
    NewTabPlan, NewTabPreparedStart, NewTabRecoveryAction, NewTabRecoveryActionOutcome,
    NewTabRecoveryContext, NewTabRecoveryEffects, NewTabRecoveryExecutionReport,
    NewTabRecoveryPlan, NewTabRecoveryRendererStateController, NewTabRecoverySessionKiller,
    NewTabSessionStart, NewTabSessionStartError, NewTabSetTabStrip, NewTabSetTabStripError,
    NewTabSnapshot, NewTabSplitFrom, NewTabStartParamsError, NewTabStripProjection,
    NewTabStripProjectionError, NewTabWorkspacePrepareError, PresetRestoreError,
    PresetRestoreRequest, PresetRestoreSlotKind, PresetRestoreSlotOutcome,
    RendererStateRecoveryEffectResult, ResolvedNewTabRecoveryAction,
    ResolvedNewTabRecoveryActionOutcome, ResolvedNewTabRecoveryActionStatus,
    ResolvedNewTabRecoveryCompleteEffectError, ResolvedNewTabRecoveryCompleteEffects,
    ResolvedNewTabRecoveryEffectResult, ResolvedNewTabRecoveryEffects,
    ResolvedNewTabRecoveryExecutionReport, ResolvedNewTabRecoveryFilesystemEffects,
    ResolvedNewTabRecoveryLocalEffectError, ResolvedNewTabRecoveryLocalEffects,
    ResolvedNewTabRecoveryPlan, ResolvedNewTabRecoveryRecordLocalEffects, UuidIdGen,
    NEW_TAB_DECLINE_HINT,
};

// Re-export the top-level CLI surface (the [`Command`] enum, its parsed argument DTOs, the
// [`usage`] help text, the root [`parse_args`] dispatcher, and the launch / attach-tab / window /
// worktree argument parsers) extracted into `cli.rs` so existing `maestro_app::<Item>` callers
// (main.rs, binary_smoke.rs, and the in-crate test module via `super::*`) keep their current paths.
// No item is made newly public: each keeps the `pub` visibility it had in `lib.rs`. The private
// parser helpers (`parse_launch`, `parse_window*`, `parse_worktree_*`, the agent/dashboard parsers,
// etc.) stay module-private to `cli.rs` and are NOT re-exported. The agent/dashboard parsed-argument
// DTOs continue to live in their feature modules (`agent.rs`, `dashboard.rs`) and are re-exported
// above; `cli.rs` constructs them through those crate-root re-exports.
pub use cli::{
    parse_args, usage, AttachTabArgs, Command, CommandPaletteArgs, LaunchArgs, LayoutPresetCommand,
    LayoutPresetListArgs, LayoutPresetRefArgs, LayoutPresetRestoreArgs, LayoutPresetSaveArgs,
    ParseError, ProjectCommand, ProjectCreateArgs, ProjectListArgs, ProjectRefArgs,
    ProjectReorderArgs, ProjectUpdateArgs, SettingsCommand, SettingsResetArgs,
    SettingsResetSelection, SettingsSetArgs, SettingsSetTarget, SettingsShowArgs,
    WindowAttentionArgs, WindowCommand, WindowCreateArgs, WindowOpenTabArgs, WindowPinTabArgs,
    WindowRenameTabArgs, WindowReorderTabsArgs, WindowShowArgs, WindowSplitTabArgs,
    WindowTabRefArgs, WindowViewArgs, WorktreeCleanupArgs, WorktreeListArgs,
};

// ---- command-palette action catalog --------------------------------------------------------
// Re-export the read-only palette DTO + pure builder so `main` can build/serialize the catalog and
// tests can assert its shape through the crate root. Nothing here is mutating or I/O-bearing.
pub use command_palette::{
    build_command_palette, build_command_palette_action_detail,
    build_command_palette_execution_plan, build_command_palette_filtered,
    build_command_palette_preview, find_palette_action, palette_command_string,
    palette_placeholders, sanitize_palette_preview_text, with_command_palette_preview,
    CommandPalette, CommandPaletteActionDetail, CommandPaletteExecutionPlan, CommandPalettePreview,
    CommandPalettePreviewRow, PaletteAction, PALETTE_PREVIEW_FIELD_MAX,
};

// ---- settings model + storage --------------------------------------------------------------
// Re-export the settings model, pure builder, and persistence helpers so `main` can resolve the
// base path, merge persisted overrides for `settings show`, and persist `settings set`, and so
// tests can construct/serialize them through the crate root.
pub use settings::{
    build_settings_panel_lines, effective_settings, renderer_font_size_px, renderer_theme_id,
    reset_all_settings, reset_appearance_setting, set_chrome_default, set_font_size_px,
    set_shell_default_argv, set_theme, set_workspace_consent, set_workspace_default_policy,
    settings_dir, settings_file_path, settings_shell_default_argv, validate_font_size_px,
    validate_shell_default_argv, validate_theme, validate_workspace_policy, AppearanceDefaults,
    ChromeDefaultKey, ChromeDefaults, EffectiveSettings, PersistedAppearance, PersistedChrome,
    PersistedSettings, PersistedShell, PersistedWorkspace, SafetyDefaults, SettingsFailure,
    SettingsPanelLines, SettingsPanelRow, SettingsResetTarget, SettingsSetSuccess, ShellDefaults,
    WorkspaceConsentKey, WorkspaceDefaults, BUILT_IN_THEME, DEFAULT_FONT_SIZE_PX, MAX_FONT_SIZE_PX,
    MIN_FONT_SIZE_PX, SETTINGS_PANEL_LINE_MAX, SETTINGS_SCHEMA_VERSION, SUPPORTED_THEMES,
    SUPPORTED_WORKSPACE_POLICIES, THEME_BUILT_IN_DARK, THEME_HIGH_CONTRAST_DARK,
    WORKSPACE_POLICY_REPO_WRITE, WORKSPACE_POLICY_SCRATCH_CWD, WORKSPACE_POLICY_WORKTREE,
};

// Re-export shared app constants so library/binary/package tests use one set of product identities.
pub use constants::{
    DEFAULT_COLS, DEFAULT_ROWS, DEFAULT_SESSION_ID, ID_MINT_ATTEMPTS, PRODUCT_RECOVERY_PROJECT_ID,
    SYSTEM_TERMINAL_PROJECT_ID, SYSTEM_TERMINAL_SESSION_ID, SYSTEM_TERMINAL_TAB_ID,
    SYSTEM_TERMINAL_WINDOW_ID, SYSTEM_TERMINAL_WORKSPACE_ID, TITLE_MAX_LEN,
};

// ---- new-tab planner foundation -------------------------------------------------------------
//
// PURE planning surface for the `RendererEvent::NewTabRequested` handler. It defines
// only the app-owned launch policy, a no-I/O snapshot, an injectable id seam, and a pure planner.
// NOTHING here starts a daemon/session, prepares a workspace, mutates a window layout, or sends a
// renderer command; it only makes the front-half launch decision.
// The planner's `ID_MINT_ATTEMPTS` bound now lives in `constants.rs` and is re-exported above.

// The default one-window attach-tab chrome resolver (`AttachTabChromeFlags`,
// `EffectiveAttachTabChrome`, `resolve_attach_tab_chrome`) now lives beside its policy in
// `chrome.rs` and is re-exported above; the parser builds the flags through that re-export.
