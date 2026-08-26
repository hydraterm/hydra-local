//! `maestro-shell` — shell-owned product metadata for the Maestro app shell.
//!
//! This crate is the App Shell ownership boundary:
//! Project / Workspace / durable Session record / AgentTask / Tab+Window layout / Attention
//! state live HERE, never in the daemon (runtime-only) or the renderer (one-session paint).
//!
//! The crate provides record types, a versioned record envelope, an app-support storage layer
//! (atomic write + corrupt-record quarantine over an INJECTABLE base directory), a secret-aware
//! launch-spec/redaction model, and PURE workspace-policy resolution.
//!
//! [`daemon_client`] is a MINIMAL synchronous client to a RUNNING `pty-daemon` over its
//! Unix-domain-socket protocol (connect to a caller-supplied socket path, drive
//! `StartSession -> Attach{want_raw_output:false} -> Grid`, and `ListSessions`). All wire types come
//! from `maestro-protocol`. It opens a socket and reads/writes newline-JSON, but still does NOT
//! spawn or supervise a daemon, open a PTY, run git, create directories, or paint — and there is no
//! tabs UI. Outside the daemon client, the only process IO is [`workspace_exec`]'s consent-gated
//! `git worktree add` / `git worktree remove` (Phases 2C/2E, reachable only through
//! `prepare_workspace_with_consent` / `remove_worktree_with_consent` with recorded
//! `worktree_create` consent); record storage is local-file only, under a caller-supplied
//! base dir (production resolves to the platform app-support dir — macOS
//! `~/Library/Application Support/Maestro`, Linux `$XDG_DATA_HOME/maestro` — tests use temp dirs).

pub mod agent_task_reconcile;
pub mod agent_task_runtime;
pub mod agent_task_signal;
pub mod agent_task_start_journal;
pub mod agent_task_start_recovery;
pub mod agent_tasks;
pub mod daemon_client;
pub mod daemon_endpoint;
pub mod dashboard_snapshot;
pub mod db;
pub mod desktop_access;
pub mod envelope;
pub mod focus_request_signal;
pub mod ids;
pub mod invariants;
pub mod launch_environment;
pub mod layout_preset;
mod local_store_security;
pub mod migrate;
pub mod names;
pub mod ownership_repair;
pub mod pane_layout;
pub mod pane_rects;
pub mod paths;
pub mod policy;
pub mod project;
pub mod records;
pub mod redact;
pub mod reserved_product_shell;
pub mod restart_recipe;
pub mod schema;
pub mod session_release;
pub mod session_service;
pub mod shell_runtime;
pub mod store;
pub mod store_sqlite;
pub mod window_layout;
pub mod workspace_consent;
pub mod workspace_exec;
pub mod write_trace;

pub use maestro_protocol::{AttachmentHandoff, AttachmentHandoffToken, DaemonInstanceId};

pub use agent_task_reconcile::{
    AgentTaskReconcileReport, AgentTaskReconciler, DanglingSessionTaskRef, QuarantinedRecord,
    ReconciledAgentTask,
};
pub use agent_task_runtime::{AgentTaskRuntime, AgentTaskRuntimeError, StartAgentTaskOutcome};
pub use agent_task_signal::{
    classify_task_signal, TaskStateAssertion, TaskStateEvidence, TaskStateSignal,
};
pub use agent_task_start_journal::{
    AgentTaskStartAppliedMarkOutcome, AgentTaskStartBindingState,
    AgentTaskStartChangedCleanupDeleteOutcome, AgentTaskStartChangedUnappliedDeleteOutcome,
    AgentTaskStartCompensationOutcome, AgentTaskStartDisposition, AgentTaskStartJournalError,
    AgentTaskStartJournalService, AgentTaskStartPublicationOutcome,
    AgentTaskStartReleaseDeleteOutcome, AppliedAgentTaskStartState, ClaimedAgentTaskStart,
    ClaimedAgentTaskStartGraph, CleanedAndRetiredAgentTaskStartOperation,
    ProvenUnappliedAgentTaskStart, RetiredAgentTaskStartOperation,
    AGENT_TASK_START_RECOVERY_LEASE_MS,
};
pub use agent_task_start_recovery::{
    AgentTaskStartRecoveryError, AgentTaskStartRecoveryOutcome, AgentTaskStartRecoveryService,
};
pub use agent_tasks::{AgentTaskService, AgentTaskServiceError};
pub use daemon_client::{
    AttachedSession, AttachmentHandoffAuthority, ConditionalStartPeerIdentity,
    ConditionalStartRecovery, ConditionalStartRecoveryAuthority, DaemonClient, DaemonClientError,
    Direction, GenerationMutationSnapshot, KillSessionPublicationError, KilledSession,
    DEFAULT_TIMEOUT,
};
pub use daemon_endpoint::{
    default_socket_path, default_socket_path_for_uid, load_endpoint, resolve_socket_path,
    store_endpoint, DaemonEndpoint, EnvLookup, ProcessEnv, ENDPOINT_ID,
};
pub use dashboard_snapshot::{
    DashboardSnapshot, DashboardSnapshotService, DashboardTab, DashboardWindow, ProjectSnapshot,
};
pub use envelope::{Envelope, EnvelopeError, SCHEMA_VERSION};
pub use focus_request_signal::{
    take_focus_window_request, write_focus_pane_request, write_focus_window_request,
    FocusWindowRequest, MAX_FOCUS_REQUEST_AGE_MS, MAX_FOCUS_REQUEST_BYTES,
    MAX_FOCUS_REQUEST_FUTURE_SKEW_MS,
};
pub use ids::{validate_id, IdError};
pub use launch_environment::{
    known_safe_provider_login_shell_argv, login_shell_argv, login_shell_argv_with,
    login_shell_program, shell_quote_login_arg, LaunchEnvLookup, ProcessLaunchEnv,
    LOGIN_SHELL_COMMAND_FLAGS,
};
pub use layout_preset::{
    plan_preset_restore, LayoutPresetError, LayoutPresetService, PresetRestoreAction,
    PresetRestoreSlot,
};
pub use names::unique_name;
pub use paths::{AppPaths, RecordKind};
pub use policy::{resolved_cwd, ResolvedCwd, WorkspacePolicy};
pub use project::{
    ConditionalCreatedProjectDelete, CreatedProject, NewProject, ProjectCreationReceipt,
    ProjectDeletionPlan, ProjectDeletionResult, ProjectService, ProjectServiceError, ProjectUpdate,
};
pub use records::{
    AgentTask, AgentTaskState, Attention, AttentionSource, AttentionState, LaunchSpec,
    LayoutPreset, LayoutPresetTab, PaneRect, Project, ProjectDirectory, ProjectLaunchDefaults,
    SessionKind, SessionRecord, SessionStatus, SplitAxis, SplitFrom, TabRecord, WindowLayout,
    Workspace, WorkspaceConsent, WorktreeProvenance,
};
pub use redact::{redact_args, RedactedLaunch};
pub use reserved_product_shell::{
    ReservedProductShellKind, ReservedProductShellStart, PRODUCT_RECOVERY_PROJECT_ID,
    PRODUCT_RECOVERY_SESSION_ID, PRODUCT_RECOVERY_TAB_ID, PRODUCT_RECOVERY_WINDOW_ID,
    PRODUCT_RECOVERY_WORKSPACE_ID, SYSTEM_TERMINAL_PROJECT_ID, SYSTEM_TERMINAL_SESSION_ID,
    SYSTEM_TERMINAL_TAB_ID, SYSTEM_TERMINAL_WINDOW_ID, SYSTEM_TERMINAL_WORKSPACE_ID,
};
pub use restart_recipe::{
    canonical_launch_for_restart, canonicalize_all_session_restart_recipes,
    canonicalize_session_restart_recipe, is_known_provider_id, is_strict_prepared_provider_launch,
    is_valid_prepared_provider_custom_adhoc, known_safe_provider_has_exact_resume,
};
pub use session_release::{
    pre_resolve_session_generations, CasPublication, ConfirmedSessionRelease, DaemonReleaseAttempt,
    ForwardReleaseClaim, PendingReleaseReceipt, PreResolvedSessionGenerations,
    PreResolvedSessionState, ProvenSessionReleaseTarget, ReleaseFailure, ReleaseOperationOutcome,
    SessionReleaseError, SessionReleaseService, SessionReleaseTarget, SessionRowPolicy,
    UnpublishedCompensationReceipt, MAX_PENDING_RELEASE_TARGETS, MAX_RELEASE_TARGETS_PER_OPERATION,
    SESSION_RELEASE_LEASE_MS,
};
pub use session_service::{
    ExistingSessionAttach, ExistingSessionMissingStart, ExistingSessionStart,
    FreshDaemonSessionStart, PreparedNewSessionStartError, PreparedNewSessionStarted,
    ReconcileReport, ReconciledSession, RecoveredSession, SessionExitObservation, SessionService,
    SessionServiceError, StartParams,
};
pub use shell_runtime::{
    PreparedNewSessionRuntimeError, PreparedNewSessionRuntimeOutcome, ReconcileOutcome,
    ShellRuntime, ShellRuntimeError, StartSessionOutcome,
};
pub use store::{
    create_session_record_if_absent, load_one, write_record, CreateSessionRecordOutcome,
    LoadOutcome, StoreError,
};
pub use window_layout::{
    ConditionalCreatedSessionDelete, ConditionalCreatedTabSessionRollback,
    ConditionalFreshWindowGraphDelete, ConditionalPreparedNewSessionCompensation,
    ConditionalWindowDelete, ConditionalWindowProjectAssignment, ConditionalWindowRestore,
    ConditionalWindowStash, CreatedFreshWindowGraph, CreatedPreparedFreshWindowGraph,
    CreatedTabSessionRollback, FreshWindowGraphConflict, FreshWindowGraphCreateOutcome,
    FreshWindowGraphReceipt, FreshWindowGraphSpec, GuardedConditionalWindowDelete,
    GuardedWindowTabClose, PreparedFreshWindowGraphCreateOutcome, PreparedFreshWindowGraphSpec,
    PreparedNewSessionCompensationReceipt, PreparedNewSessionStart, ProjectWindowGraphSnapshot,
    WindowCloseSnapshot, WindowDeletionReceipt, WindowDeletionReceiptState, WindowLayoutError,
    WindowLayoutService, WindowLayoutSnapshot, WindowProjectAssignment,
    WindowProjectAssignmentProof, WindowProjectAssignmentProofOutcome, WindowTabClose,
    WindowTabView, WindowViewportPane, WindowViewportSnapshot, WindowViewportSnapshotError,
};
pub use workspace_consent::{
    check_policy_consent, grant_consent, has_consent, require_consent, required_consent_for_policy,
    WorkspaceConsentError, WorkspaceConsentKind,
};
pub use workspace_exec::{
    cleanup_fresh_scratch_cwd, inspect_worktree, parse_worktree_porcelain,
    prepare_fresh_scratch_cwd, prepare_scratch_cwd, prepare_workspace,
    prepare_workspace_with_consent, remove_worktree_with_consent, FreshScratchCwdCleanupOutcome,
    FreshScratchCwdPreparation, FreshScratchCwdReceipt, PorcelainWorktree, PreparedSessionSpec,
    PreparedWorkspace, RemovedWorkspace, WorkspaceExecError, WorktreeInspection,
};
