// Dashboard data model for Hydra's native desktop interface.
//
// These types mirror the Rust shapes 1:1 so the mock payload is wire-faithful
// and a later IPC bridge can drop real JSON in unchanged:
//   - The flat envelope mirrors `maestro-app dashboard --view-model`
//     (active_project / projects[].is_active|active_task_count|window_count /
//      counts / active_tasks / stashed_tabs).
//   - The richer tree (windows -> tabs and workspaces) mirrors
//     maestro-shell `DashboardSnapshot` / `ProjectSnapshot` / `DashboardWindow`
//     / `DashboardTab`, used for the expandable project detail.
//
// Field names are kept in the Rust snake_case so no remapping layer is needed.

// records.rs SessionStatus
export type SessionStatus = 'live' | 'exited' | 'unknown'

// records.rs AgentTaskState
export type AgentTaskState =
  | 'draft'
  | 'running'
  | 'waiting_on_user'
  | 'blocked'
  | 'succeeded'
  | 'failed'
  | 'cancelled'

// records.rs Attention
export type Attention = 'none' | 'activity' | 'needs_input' | 'error' | 'done'

// Agent backing a session, derived UI-side from the launch command (mirrors
// the provider associated with the pane). Not a persisted Rust field — the real bridge
// derives it from SessionRecord.launch / the agent task.
export type { AgentKind, RunnableAgentKind } from '../model/agent-provider'
import type { AgentKind, RunnableAgentKind } from '../model/agent-provider'

export interface AgentFolderSession {
  id: string
  agent: RunnableAgentKind
  title: string
  first_message: string
  modified_at_ms: number
  /** Present only when the provider can report an exact count without scanning the transcript. */
  message_count?: number
  folder_index: number
  file_path: string
  in_use: boolean
  custom_name?: string | null
}

export interface SessionPreviewLine {
  role: 'user' | 'assistant' | 'system'
  text: string
}

// records.rs WorkspacePolicy (subset surfaced read-only by ProjectSnapshot)
export type WorkspacePolicy = 'scratch_cwd' | 'worktree' | 'repo_write'

// --view-model: snapshot.active_project
export interface ActiveProjectRef {
  project_id: string
  name: string
  icon: string | null
  accent_color: string | null
}

// --view-model: snapshot.projects[]
export interface ProjectCardView {
  project_id: string
  name: string
  icon: string | null
  accent_color: string | null
  default_workspace_policy: WorkspacePolicy
  is_active: boolean
  active_task_count: number
  window_count: number
}

// --view-model: snapshot.counts (AgentTaskState roll-up)
export interface TaskCounts {
  draft: number
  running: number
  waiting_on_user: number
  blocked: number
  succeeded: number
  failed: number
  cancelled: number
}

// dashboard_snapshot.rs DashboardTab
export interface DashboardTab {
  window_id: string
  tab_id: string
  session_id: string
  index: number
  title: string
  pinned: boolean
  attention: Attention
  agent_task_id: string | null
  agent_task_state: AgentTaskState | null
  session_status: SessionStatus | null
  session_record_missing: boolean
  needs_attention: boolean
  stashed: boolean
  /** The pane's session working directory — used to default a split's folder to the source pane's folder. */
  cwd?: string
  // UI-derived agent identity for the pane badge (not a Rust field).
  agent: AgentKind
}

// dashboard_snapshot.rs DashboardWindow
export interface DashboardWindow {
  window_id: string
  name?: string | null
  root?: string | null
  stashed?: boolean
  tabs: DashboardTab[]
}

// records.rs AgentTask (active task list)
export interface AgentTask {
  agent_task_id: string
  project_id: string
  goal: string
  state: AgentTaskState
  current_session_id: string | null
  updated_at_ms: number
  result_summary: string | null
}

export interface ProjectLaunchDefaults {
  agent?: AgentKind | string | null
  model?: string | null
  resume_mode?: 'continue' | 'resume' | 'none' | string | null
  dangerous_skip_permissions?: boolean | null
  custom_command?: string | null
}

// dashboard_snapshot.rs ProjectSnapshot (the deep tree under each project)
export interface ProjectDetail {
  project_id: string
  name: string
  root: string
  icon: string | null
  accent_color: string | null
  default_workspace_policy: WorkspacePolicy
  last_active_at_ms: number
  launch_defaults?: ProjectLaunchDefaults | null
  extra_folders?: Array<{ id: string; name: string; path: string }>
  /** The built-in "Terminal" project: plain-bash terminals, simplified dialogs (rename/color/icon only, no
   * agent/folder), renameable + hideable but never deletable. */
  system?: boolean
  /** User hid this project from the sidebar (still exists). */
  hidden?: boolean
  windows: DashboardWindow[]
  tasks: AgentTask[]
}

export type DesktopAccessStatus = 'granted' | 'required' | 'unknown' | 'not_applicable'

export interface DesktopAccessModel {
  /** Live native capability probe; persisted onboarding acknowledgement never changes this value. */
  status: DesktopAccessStatus
  /** Copy-only acknowledgement for the frozen signed desktop identity. Never permission authority. */
  onboarding_acknowledged: boolean
  /** Stable structured error code mirrored by native/remote protected-path refusals. */
  required_error_code: 'macos_full_disk_access_required'
}

export type DesktopUpdateStatus =
  | 'not_checked'
  | 'checking'
  | 'up_to_date'
  | 'available'
  | 'unavailable'
  | 'disabled'

export interface DesktopUpdateModel {
  status: DesktopUpdateStatus
  current_version: string
  latest_version: string | null
  release_git_sha: string | null
  published_at: string | null
  download_artifact: string | null
  download_sha256: string | null
  /** True only when native code validated the exact manifest and this platform's immutable artifact. */
  action_available: boolean
}

export type FilesystemModeMigrationPhase = 'ready_to_apply' | 'interrupted' | 'applied'

export type LegacyFilesystemMode = '0660' | '0664' | '0770' | '0775'
export type SecuredFilesystemMode = '0640' | '0644' | '0700' | '0750' | '0755'

export interface FilesystemModeMigrationChange {
  /** Canonical absolute Linux path validated by the native host. */
  path: string
  old_mode: LegacyFilesystemMode
  new_mode: SecuredFilesystemMode
  /** Copy-only command constructed from the validated path and old mode by native Rust. */
  rollback_command: string
}

export interface ModelDeprecation {
  since_revision: number
  message: string
  replacement?: string
}

export interface ModelCatalog {
  agents?: Record<string, string[]>
  deprecations?: Record<string, Record<string, ModelDeprecation>>
}

interface FilesystemModeMigrationNoticeBase {
  /** Exact capability-bound native notice id. Dashboard actions echo only this id. */
  notice_id: string
  changes: FilesystemModeMigrationChange[]
}

export type FilesystemModeMigrationNotice = FilesystemModeMigrationNoticeBase &
  (
    | { phase: 'ready_to_apply'; recovery_record_path?: never }
    | {
        phase: 'interrupted' | 'applied'
        /** Exact temporary recovery record created by the native host before it changes any mode. */
        recovery_record_path: string
      }
  )

// The full payload the prototype renders. `projects` (cards) + `active_project`
// + `counts` + `active_tasks` come straight from --view-model; `details` is native project state.
// `recovered_sessions` is retained as an always-empty compatibility field. Native reconciliation
// ids never cross the WebView boundary.
export interface DashboardModel {
  active_project: ActiveProjectRef | null
  active_window_id?: string | null
  active_tab_id?: string | null
  projects: ProjectCardView[]
  counts: TaskCounts
  attention_count: number
  active_tasks: AgentTask[]
  details: Record<string, ProjectDetail>
  recovered_sessions: []
  /** True only after the optional private Remote extension negotiated a compatible capability.
   * Absent/false hides every Remote control and is the fail-closed local-only default. */
  remote_available?: boolean
  /** Display-only Remote state supplied by the negotiated private extension. The public app neither owns nor writes
   * the effective gate. Absent is treated as CLOSED. */
  remote_open?: boolean
  /** Desktop enrollment: true once this computer is bound to an account (durable). Drives the sidebar "Add Remote" flow —
   * when false, show the paste-code field; when true, show the enrolled account. */
  enrolled?: boolean
  /** The account this desktop is enrolled under (null/absent when not enrolled). */
  account_id?: string | null
  /** One-shot inline error from the last "Add Remote" attempt (e.g. expired/used/wrong code). Null when none. */
  enroll_error?: string | null
  /** Linux-only, private-extension-owned folder-mode migration. Ordinary Remote actions stay blocked until Ack. */
  filesystem_mode_migration?: FilesystemModeMigrationNotice | null
  /** macOS-only protected-folder capability. Absent on Linux and older native hosts. */
  desktop_access?: DesktopAccessModel
  /** Native stable-feed state. Absent on older hosts; JavaScript never receives or chooses the URL. */
  update?: DesktopUpdateModel
  /** Stable model catalog cache: per-agent model lists merged over the
   * built-in dropdown entries, so new vendor models appear without an app release. Null/absent →
   * built-ins only. */
  model_catalog?: ModelCatalog | null
}

export type LoadState =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; model: DashboardModel }
