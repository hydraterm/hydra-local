// Browser↔agent control-channel messages for "New session". These mirror the agent's serde enums
// (InboundMsg::CreateSession, OutboundMsg::SessionCreated / SessionCreateError) and fit the existing
// control envelope ({ type, request_id, ... }). Content-blind: ids/codes and launch metadata only, never
// terminal payload.

import { isRunnableAgentKind, type RemoteAgentKind } from '../model/agent-provider-core.js'
import { MAX_COLS, MAX_ROWS, MIN_COLS, MIN_ROWS } from '../terminal/viewport.js'
export type { RemoteAgentKind } from '../model/agent-provider-core.js'

export const PROVIDER_SESSION_ID_MAX_CHARS = 256

/** Provider resume identities are opaque, but never unbounded. Reject rather than truncate: truncation could
 * alias two distinct provider sessions and make a later preview/manage request target the wrong one. */
export function normalizeProviderSessionId(value: string): string | null {
  const trimmed = value.trim()
  if (!trimmed || trimmed.startsWith('-') || Array.from(trimmed).length > PROVIDER_SESSION_ID_MAX_CHARS) return null
  return /[\u0000-\u001F\u007F-\u009F]/u.test(trimmed) ? null : trimmed
}

function requireProviderSessionId(value: string): string {
  const normalized = normalizeProviderSessionId(value)
  if (normalized === null) throw new RangeError('invalid provider session id')
  return normalized
}

export interface RemoteLaunchFlags {
  readonly resumeMode?: 'new' | 'resume' | 'continue'
  readonly resumeSessionId?: string
  readonly resumeSessionFile?: string
  readonly model?: string
  readonly dangerouslySkipPermissions?: boolean
}

export interface CreationGeometryOptions {
  readonly cols?: number
  readonly rows?: number
}

export interface CreateSessionOptions extends CreationGeometryOptions {
  readonly label?: string
  readonly cwd?: string
  readonly agent?: RemoteAgentKind
  readonly launchFlags?: RemoteLaunchFlags
}

export interface ListAgentSessionsMsg {
  readonly type: 'list_agent_sessions'
  readonly request_id: string
  readonly agent: RemoteAgentKind
  readonly cwd?: string
  readonly include_hidden?: boolean
}

export interface ListDirectoriesMsg {
  readonly type: 'list_directories'
  readonly request_id: string
  readonly path?: string
}

export interface PreviewAgentSessionMsg {
  readonly type: 'preview_agent_session'
  readonly request_id: string
  readonly agent: RemoteAgentKind
  readonly session_id: string
  readonly cwd?: string
  readonly max_lines?: number
}

export type ManageAgentSessionAction = 'rename' | 'hide' | 'unhide' | 'delete'

export interface ManageAgentSessionMsg {
  readonly type: 'manage_agent_session'
  readonly request_id: string
  readonly action: ManageAgentSessionAction
  readonly agent: RemoteAgentKind
  readonly session_id: string
  readonly cwd?: string
  readonly name?: string
}

export interface AgentSessionMeta {
  readonly id: string
  readonly agent: RemoteAgentKind
  readonly modifiedAtMs?: number
  readonly messageCount?: number
  readonly inUse?: boolean
  /** The user-chosen short name from the desktop (custom_name), so the browser shows the SAME label as local. */
  readonly customName?: string
}

export interface AgentSessionPreviewLine {
  readonly role: string
  readonly text: string
}

export interface AgentSessionsResultMsg {
  readonly type: 'agent_sessions_result'
  readonly request_id: string
  readonly sessions: readonly AgentSessionMeta[]
}

export interface AgentSessionsErrorMsg {
  readonly type: 'agent_sessions_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type AgentSessionsReply = AgentSessionsResultMsg | AgentSessionsErrorMsg

export interface AgentSessionPreviewMsg {
  readonly type: 'agent_session_preview'
  readonly request_id: string
  readonly lines: readonly AgentSessionPreviewLine[]
}

export interface AgentSessionPreviewErrorMsg {
  readonly type: 'agent_session_preview_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export interface DirectoryEntry {
  readonly name: string
  readonly path: string
}

export interface DirectoriesResultMsg {
  readonly type: 'directories_result'
  readonly request_id: string
  readonly path: string
  readonly parent?: string
  readonly entries: readonly DirectoryEntry[]
}

export interface DirectoriesErrorMsg {
  readonly type: 'directories_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type DirectoriesReply = DirectoriesResultMsg | DirectoriesErrorMsg

export type DesktopPlatform = 'macos' | 'linux' | 'other'
export type FullDiskAccessStatus = 'granted' | 'required' | 'unknown' | 'not_applicable'

/** Agent → browser, after auth: bounded desktop filesystem-access readiness. */
export interface DesktopAccessStatusMsg {
  readonly type: 'desktop_access_status'
  readonly platform: DesktopPlatform
  readonly full_disk_access: FullDiskAccessStatus
}

export type AgentSessionPreviewReply = AgentSessionPreviewMsg | AgentSessionPreviewErrorMsg

export interface AgentSessionManagedMsg {
  readonly type: 'agent_session_managed'
  readonly request_id: string
}

export interface AgentSessionManageErrorMsg {
  readonly type: 'agent_session_manage_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type AgentSessionManageReply = AgentSessionManagedMsg | AgentSessionManageErrorMsg

/** Browser → agent: create a new local terminal session on demand. Old clients can still send only
 * `request_id`/`label`. New browser dashboard paths can carry the same launch intent desktop has:
 * project cwd, agent choice, and structured non-command launch flags. */
export interface CreateSessionMsg {
  readonly type: 'create_session'
  readonly request_id: string
  readonly cols?: number
  readonly rows?: number
  readonly label?: string
  readonly cwd?: string
  readonly agent?: RemoteAgentKind
  readonly launch_flags?: RemoteLaunchFlags
}

/** Agent → browser: a session was created; attach to `session_id` via the existing attach path. F1: carries
 * back the optional `label` when one was set. */
export interface SessionCreatedMsg {
  readonly type: 'session_created'
  readonly request_id: string
  readonly session_id: string
  readonly label?: string
}

export type SessionCreateErrorCode =
  | 'unauthenticated'
  | 'revoked'
  | 'unsupported_provider'
  | 'daemon_unavailable'
  | 'limit_reached'
  | 'macos_full_disk_access_required'
  | 'internal'

/** Agent → browser: create failed/refused. `message` is a short, non-sensitive reason. */
export interface SessionCreateErrorMsg {
  readonly type: 'session_create_error'
  readonly request_id: string
  readonly code: SessionCreateErrorCode
  readonly message: string
}

/** Any agent reply to a create_session request. */
export type CreateSessionReply = SessionCreatedMsg | SessionCreateErrorMsg

/** Build the outbound create_session request (the browser sends this over the data channel). A string
 * second argument keeps the old label-only call shape working. */
export function buildCreateSession(requestId: string, labelOrOptions?: string | CreateSessionOptions): CreateSessionMsg {
  const opts: CreateSessionOptions = typeof labelOrOptions === 'string'
    ? { label: labelOrOptions }
    : (labelOrOptions ?? {})
  const msg: CreateSessionMsg = { type: 'create_session', request_id: requestId }
  const label = opts.label?.trim()
  const cwd = opts.cwd?.trim()
  if (label) (msg as { label?: string }).label = label
  if (cwd) (msg as { cwd?: string }).cwd = cwd
  if (opts.agent) (msg as { agent?: RemoteAgentKind }).agent = opts.agent
  if (opts.launchFlags && Object.keys(opts.launchFlags).length > 0) {
    (msg as { launch_flags?: RemoteLaunchFlags }).launch_flags = opts.launchFlags
  }
  appendCreationGeometry(msg, opts)
  return msg
}

export function buildListAgentSessions(requestId: string, agent: RemoteAgentKind, cwd?: string, includeHidden = false): ListAgentSessionsMsg {
  const trimmed = cwd?.trim()
  const base: ListAgentSessionsMsg = trimmed
    ? { type: 'list_agent_sessions', request_id: requestId, agent, cwd: trimmed }
    : { type: 'list_agent_sessions', request_id: requestId, agent }
  // include_hidden = list the REMOVED (⊘-hidden) sessions for the browser "Removed sessions" section.
  return includeHidden ? { ...base, include_hidden: true } : base
}

export function buildListDirectories(requestId: string, path?: string): ListDirectoriesMsg {
  const trimmed = path?.trim()
  return trimmed
    ? { type: 'list_directories', request_id: requestId, path: trimmed }
    : { type: 'list_directories', request_id: requestId }
}

export function buildPreviewAgentSession(
  requestId: string,
  agent: RemoteAgentKind,
  sessionId: string,
  cwd?: string,
  maxLines?: number,
): PreviewAgentSessionMsg {
  const msg: PreviewAgentSessionMsg = {
    type: 'preview_agent_session',
    request_id: requestId,
    agent,
    session_id: requireProviderSessionId(sessionId),
  }
  const trimmedCwd = cwd?.trim()
  if (trimmedCwd) (msg as { cwd?: string }).cwd = trimmedCwd
  if (typeof maxLines === 'number' && Number.isFinite(maxLines)) {
    ;(msg as { max_lines?: number }).max_lines = Math.max(1, Math.floor(maxLines))
  }
  return msg
}

export function buildManageAgentSession(
  requestId: string,
  action: ManageAgentSessionAction,
  agent: RemoteAgentKind,
  sessionId: string,
  opts: { cwd?: string; name?: string } = {},
): ManageAgentSessionMsg {
  const msg: ManageAgentSessionMsg = {
    type: 'manage_agent_session',
    request_id: requestId,
    action,
    agent,
    session_id: requireProviderSessionId(sessionId),
  }
  const cwd = opts.cwd?.trim()
  const name = opts.name?.trim()
  if (cwd) (msg as { cwd?: string }).cwd = cwd
  if (action === 'rename') (msg as { name?: string }).name = name ?? ''
  return msg
}

// ---- split_pane (gap-doc Step 3, desktop-authoritative split) ----
export type SplitPaneDir = 'right' | 'down' // vertical(UI) = right(h), horizontal(UI) = down(v)

export interface SplitPaneOptions extends CreationGeometryOptions {
  readonly cwd?: string
  readonly agent?: RemoteAgentKind
  readonly launchFlags?: RemoteLaunchFlags
  /** The split dialog's pane name — becomes the desktop TabRecord title. Metadata only. */
  readonly paneName?: string
}

export type NewPaneOptions = SplitPaneOptions

export interface NewWindowOptions extends CreationGeometryOptions {
  readonly cwd?: string
  readonly agent?: RemoteAgentKind
  readonly launchFlags?: RemoteLaunchFlags
}

/** Project default resume policy — the DESKTOP vocabulary (maestro-shell ProjectLaunchDefaults):
 * 'continue' | 'resume' | 'none'. Early remote builds used 'new' for the fresh policy; the builders
 * normalize any legacy 'new' to 'none' so only desktop vocabulary crosses the wire. */
export type ProjectResumeMode = 'none' | 'resume' | 'continue'

export interface ProjectEditOptions {
  readonly name?: string
  readonly root?: string
  readonly icon?: string
  readonly accentColor?: string
  readonly agent?: RemoteAgentKind
  readonly resumeMode?: ProjectResumeMode | 'new'
  /** New Project resume TARGET: the prior session the seeded first pane should resume (paired with
   * resumeMode 'resume'). An opaque provider session id — never a path. Create-only. */
  readonly resumeSessionId?: string
  readonly model?: RemoteLaunchFlags['model']
  readonly dangerouslySkipPermissions?: RemoteLaunchFlags['dangerouslySkipPermissions']
  readonly customCommand?: string
  readonly directories?: readonly ProjectDirectoryEdit[]
}

export type ProjectCreateOptions = ProjectEditOptions & CreationGeometryOptions

export interface ProjectDirectoryEdit {
  readonly name?: string
  readonly path: string
}

export interface SplitPaneMsg {
  readonly type: 'split_pane'
  readonly request_id: string
  readonly window_id: string
  readonly from_pane_id: string
  readonly dir: SplitPaneDir
  readonly cols?: number
  readonly rows?: number
  readonly cwd?: string
  readonly agent?: RemoteAgentKind
  readonly launch_flags?: RemoteLaunchFlags
  readonly pane_name?: string
}

export interface NewPaneMsg {
  readonly type: 'new_pane'
  readonly request_id: string
  readonly window_id: string
  readonly from_pane_id: string
  readonly cols?: number
  readonly rows?: number
  readonly cwd?: string
  readonly agent?: RemoteAgentKind
  readonly launch_flags?: RemoteLaunchFlags
  readonly pane_name?: string
}

export interface SplitPaneOkMsg {
  readonly type: 'split_pane_ok'
  readonly request_id: string
  readonly session_id: string
  readonly tab_id: string
}
export interface SplitPaneErrorMsg {
  readonly type: 'split_pane_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}
export type SplitPaneReply = SplitPaneOkMsg | SplitPaneErrorMsg

/** Build the outbound split_pane request — ask the DESKTOP to split `fromPaneId` in `windowId` (right|down).
 * Launch context (agent/flags) is resolved on the desktop; never a command on the wire. */
export function buildSplitPane(
  requestId: string,
  windowId: string,
  fromPaneId: string,
  dir: SplitPaneDir,
  opts: SplitPaneOptions = {},
): SplitPaneMsg {
  const msg: SplitPaneMsg = { type: 'split_pane', request_id: requestId, window_id: windowId, from_pane_id: fromPaneId, dir }
  // Optional cwd for the new pane: when absent the desktop inherits the split source pane's cwd; when present
  // (a real dir picked in the split dialog) it overrides. Mirrors NewWindowOptions.cwd.
  if (opts.cwd?.trim()) (msg as { cwd?: string }).cwd = opts.cwd.trim()
  if (opts.agent) (msg as { agent?: RemoteAgentKind }).agent = opts.agent
  if (opts.launchFlags && Object.keys(opts.launchFlags).length > 0) {
    (msg as { launch_flags?: RemoteLaunchFlags }).launch_flags = opts.launchFlags
  }
  // Pane display name (the dialog's "Pane name") — trimmed, only when non-empty; the desktop uses it as
  // the tab title and falls back to its agent-derived title otherwise.
  if (opts.paneName?.trim()) (msg as { pane_name?: string }).pane_name = opts.paneName.trim()
  appendCreationGeometry(msg, opts)
  return msg
}

/** Build the outbound new_pane request — create a NEW desktop pane record/session under `windowId`.
 * The desktop persists it as a stashed existence record; the browser waits for metadata and then
 * places/attaches it through the remote viewport without changing local desktop geometry. */
export function buildNewPane(
  requestId: string,
  windowId: string,
  fromPaneId: string,
  opts: NewPaneOptions = {},
): NewPaneMsg {
  const msg: NewPaneMsg = { type: 'new_pane', request_id: requestId, window_id: windowId, from_pane_id: fromPaneId }
  if (opts.cwd?.trim()) (msg as { cwd?: string }).cwd = opts.cwd.trim()
  if (opts.agent) (msg as { agent?: RemoteAgentKind }).agent = opts.agent
  if (opts.launchFlags && Object.keys(opts.launchFlags).length > 0) {
    (msg as { launch_flags?: RemoteLaunchFlags }).launch_flags = opts.launchFlags
  }
  if (opts.paneName?.trim()) (msg as { pane_name?: string }).pane_name = opts.paneName.trim()
  appendCreationGeometry(msg, opts)
  return msg
}

/** Parse an inbound message into a typed split_pane reply, or null if it isn't one. */
export function parseSplitPaneReply(raw: unknown): SplitPaneReply | null {
  if (typeof raw !== 'object' || raw === null) return null
  const m = raw as Record<string, unknown>
  if (m.type === 'split_pane_ok' && typeof m.request_id === 'string' && typeof m.session_id === 'string' && typeof m.tab_id === 'string') {
    return { type: 'split_pane_ok', request_id: m.request_id, session_id: m.session_id, tab_id: m.tab_id }
  }
  if (m.type === 'split_pane_error' && typeof m.request_id === 'string') {
    return { type: 'split_pane_error', request_id: m.request_id, code: typeof m.code === 'string' ? m.code : 'internal', message: typeof m.message === 'string' ? m.message : '' }
  }
  return null
}

// ---- revive_pane (gap-doc Step 3b, desktop-authoritative stashed pane revive) ----
export interface RevivePaneMsg {
  readonly type: 'revive_pane'
  readonly request_id: string
  readonly window_id: string
  readonly pane_id: string
  readonly cols?: number
  readonly rows?: number
}

export type RevivePaneOptions = CreationGeometryOptions

export interface RevivePaneOkMsg {
  readonly type: 'revive_pane_ok'
  readonly request_id: string
  readonly session_id: string
}

export interface RevivePaneErrorMsg {
  readonly type: 'revive_pane_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type RevivePaneReply = RevivePaneOkMsg | RevivePaneErrorMsg

export function buildRevivePane(
  requestId: string,
  windowId: string,
  paneId: string,
  opts: RevivePaneOptions = {},
): RevivePaneMsg {
  const msg: RevivePaneMsg = { type: 'revive_pane', request_id: requestId, window_id: windowId, pane_id: paneId }
  appendCreationGeometry(msg, opts)
  return msg
}

export function parseRevivePaneReply(raw: unknown): RevivePaneReply | null {
  if (typeof raw !== 'object' || raw === null) return null
  const m = raw as Record<string, unknown>
  if (m.type === 'revive_pane_ok' && typeof m.request_id === 'string' && typeof m.session_id === 'string') {
    return { type: 'revive_pane_ok', request_id: m.request_id, session_id: m.session_id }
  }
  if (m.type === 'revive_pane_error' && typeof m.request_id === 'string') {
    return { type: 'revive_pane_error', request_id: m.request_id, code: typeof m.code === 'string' ? m.code : 'internal', message: typeof m.message === 'string' ? m.message : '' }
  }
  return null
}

// ---- start_pane_session (virtual viewport: start recorded pane without desktop layout mutation) ----
export interface StartPaneSessionMsg {
  readonly type: 'start_pane_session'
  readonly request_id: string
  readonly window_id: string
  readonly pane_id: string
  readonly cols?: number
  readonly rows?: number
}

export type StartPaneSessionOptions = CreationGeometryOptions

export interface StartPaneSessionOkMsg {
  readonly type: 'start_pane_session_ok'
  readonly request_id: string
  readonly session_id: string
}

export interface StartPaneSessionErrorMsg {
  readonly type: 'start_pane_session_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type StartPaneSessionReply = StartPaneSessionOkMsg | StartPaneSessionErrorMsg

export function buildStartPaneSession(
  requestId: string,
  windowId: string,
  paneId: string,
  opts: StartPaneSessionOptions = {},
): StartPaneSessionMsg {
  const msg: StartPaneSessionMsg = {
    type: 'start_pane_session',
    request_id: requestId,
    window_id: windowId,
    pane_id: paneId,
  }
  appendCreationGeometry(msg, opts)
  return msg
}

export function parseStartPaneSessionReply(raw: unknown): StartPaneSessionReply | null {
  if (typeof raw !== 'object' || raw === null) return null
  const m = raw as Record<string, unknown>
  if (m.type === 'start_pane_session_ok' && typeof m.request_id === 'string' && typeof m.session_id === 'string') {
    return { type: 'start_pane_session_ok', request_id: m.request_id, session_id: m.session_id }
  }
  if (m.type === 'start_pane_session_error' && typeof m.request_id === 'string') {
    return { type: 'start_pane_session_error', request_id: m.request_id, code: typeof m.code === 'string' ? m.code : 'internal', message: typeof m.message === 'string' ? m.message : '' }
  }
  return null
}

// ---- stash_pane (desktop pane Close -> stash; inverse of revive_pane) ----
export interface StashPaneMsg {
  readonly type: 'stash_pane'
  readonly request_id: string
  readonly window_id: string
  readonly pane_id: string
}

export interface StashPaneOkMsg {
  readonly type: 'stash_pane_ok'
  readonly request_id: string
}

export interface StashPaneErrorMsg {
  readonly type: 'stash_pane_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type StashPaneReply = StashPaneOkMsg | StashPaneErrorMsg

export function buildStashPane(requestId: string, windowId: string, paneId: string): StashPaneMsg {
  return { type: 'stash_pane', request_id: requestId, window_id: windowId, pane_id: paneId }
}

export function parseStashPaneReply(raw: unknown): StashPaneReply | null {
  if (typeof raw !== 'object' || raw === null) return null
  const m = raw as Record<string, unknown>
  if (m.type === 'stash_pane_ok' && typeof m.request_id === 'string') {
    return { type: 'stash_pane_ok', request_id: m.request_id }
  }
  if (m.type === 'stash_pane_error' && typeof m.request_id === 'string') {
    return { type: 'stash_pane_error', request_id: m.request_id, code: typeof m.code === 'string' ? m.code : 'internal', message: typeof m.message === 'string' ? m.message : '' }
  }
  return null
}

// ---- remove_pane (desktop "Remove from shelf": drop the pane record via close_pane; session not killed) ----
export interface RemovePaneMsg {
  readonly type: 'remove_pane'
  readonly request_id: string
  readonly window_id: string
  readonly pane_id: string
}

export interface RemovePaneOkMsg {
  readonly type: 'remove_pane_ok'
  readonly request_id: string
}

export interface RemovePaneErrorMsg {
  readonly type: 'remove_pane_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type RemovePaneReply = RemovePaneOkMsg | RemovePaneErrorMsg

export function buildRemovePane(requestId: string, windowId: string, paneId: string): RemovePaneMsg {
  return { type: 'remove_pane', request_id: requestId, window_id: windowId, pane_id: paneId }
}

export function parseRemovePaneReply(raw: unknown): RemovePaneReply | null {
  if (typeof raw !== 'object' || raw === null) return null
  const m = raw as Record<string, unknown>
  if (m.type === 'remove_pane_ok' && typeof m.request_id === 'string') {
    return { type: 'remove_pane_ok', request_id: m.request_id }
  }
  if (m.type === 'remove_pane_error' && typeof m.request_id === 'string') {
    return { type: 'remove_pane_error', request_id: m.request_id, code: typeof m.code === 'string' ? m.code : 'internal', message: typeof m.message === 'string' ? m.message : '' }
  }
  return null
}

// ---- rename (desktop pane/window inline rename) ----
export interface RenameMsg {
  readonly type: 'rename'
  readonly request_id: string
  readonly window_id: string
  readonly pane_id?: string
  readonly name: string
}

export interface RenameOkMsg {
  readonly type: 'rename_ok'
  readonly request_id: string
}

export interface RenameErrorMsg {
  readonly type: 'rename_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type RenameReply = RenameOkMsg | RenameErrorMsg

export function buildRename(requestId: string, windowId: string, name: string, paneId?: string): RenameMsg {
  const msg: RenameMsg = {
    type: 'rename',
    request_id: requestId,
    window_id: windowId,
    name: name.trim(),
  }
  const pane = paneId?.trim()
  if (pane) (msg as { pane_id?: string }).pane_id = pane
  return msg
}

export function parseRenameReply(raw: unknown): RenameReply | null {
  if (typeof raw !== 'object' || raw === null) return null
  const m = raw as Record<string, unknown>
  if (m.type === 'rename_ok' && typeof m.request_id === 'string') {
    return { type: 'rename_ok', request_id: m.request_id }
  }
  if (m.type === 'rename_error' && typeof m.request_id === 'string') {
    return { type: 'rename_error', request_id: m.request_id, code: typeof m.code === 'string' ? m.code : 'internal', message: typeof m.message === 'string' ? m.message : '' }
  }
  return null
}

// ---- focus_window (desktop-authoritative window tab selection) ----
export interface FocusWindowMsg {
  readonly type: 'focus_window'
  readonly request_id: string
  readonly window_id: string
}

export interface FocusWindowOkMsg {
  readonly type: 'focus_window_ok'
  readonly request_id: string
}

export interface FocusWindowErrorMsg {
  readonly type: 'focus_window_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type FocusWindowReply = FocusWindowOkMsg | FocusWindowErrorMsg

export function buildFocusWindow(requestId: string, windowId: string): FocusWindowMsg {
  return { type: 'focus_window', request_id: requestId, window_id: windowId }
}

export function parseFocusWindowReply(raw: unknown): FocusWindowReply | null {
  if (typeof raw !== 'object' || raw === null) return null
  const m = raw as Record<string, unknown>
  if (m.type === 'focus_window_ok' && typeof m.request_id === 'string') {
    return { type: 'focus_window_ok', request_id: m.request_id }
  }
  if (m.type === 'focus_window_error' && typeof m.request_id === 'string') {
    return { type: 'focus_window_error', request_id: m.request_id, code: typeof m.code === 'string' ? m.code : 'internal', message: typeof m.message === 'string' ? m.message : '' }
  }
  return null
}

// ---- close_window (desktop destructive window remove) ----
export interface CloseWindowMsg {
  readonly type: 'close_window'
  readonly request_id: string
  readonly window_id: string
}

export interface CloseWindowOkMsg {
  readonly type: 'close_window_ok'
  readonly request_id: string
}

export interface CloseWindowErrorMsg {
  readonly type: 'close_window_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type CloseWindowReply = CloseWindowOkMsg | CloseWindowErrorMsg

export function buildCloseWindow(requestId: string, windowId: string): CloseWindowMsg {
  return { type: 'close_window', request_id: requestId, window_id: windowId }
}

export function parseCloseWindowReply(raw: unknown): CloseWindowReply | null {
  if (typeof raw !== 'object' || raw === null) return null
  const m = raw as Record<string, unknown>
  if (m.type === 'close_window_ok' && typeof m.request_id === 'string') {
    return { type: 'close_window_ok', request_id: m.request_id }
  }
  if (m.type === 'close_window_error' && typeof m.request_id === 'string') {
    return { type: 'close_window_error', request_id: m.request_id, code: typeof m.code === 'string' ? m.code : 'internal', message: typeof m.message === 'string' ? m.message : '' }
  }
  return null
}

// ---- new_window (gap-doc Step 4, desktop-authoritative Project -> Window -> Pane creation) ----
export interface NewWindowMsg {
  readonly type: 'new_window'
  readonly request_id: string
  readonly project_id: string
  readonly name: string
  readonly cols?: number
  readonly rows?: number
  readonly cwd?: string
  readonly agent?: RemoteAgentKind
  readonly launch_flags?: RemoteLaunchFlags
}

export interface NewWindowOkMsg {
  readonly type: 'new_window_ok'
  readonly request_id: string
  readonly window_id: string
  readonly session_id: string
}

export interface NewWindowErrorMsg {
  readonly type: 'new_window_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type NewWindowReply = NewWindowOkMsg | NewWindowErrorMsg

export function buildNewWindow(
  requestId: string,
  projectId: string,
  name: string,
  opts: NewWindowOptions = {},
): NewWindowMsg {
  const msg: NewWindowMsg = {
    type: 'new_window',
    request_id: requestId,
    project_id: projectId,
    name: name.trim() || 'Window',
  }
  const cwd = opts.cwd?.trim()
  if (cwd) (msg as { cwd?: string }).cwd = cwd
  if (opts.agent) (msg as { agent?: RemoteAgentKind }).agent = opts.agent
  if (opts.launchFlags && Object.keys(opts.launchFlags).length > 0) {
    (msg as { launch_flags?: RemoteLaunchFlags }).launch_flags = opts.launchFlags
  }
  appendCreationGeometry(msg, opts)
  return msg
}

export function parseNewWindowReply(raw: unknown): NewWindowReply | null {
  if (typeof raw !== 'object' || raw === null) return null
  const m = raw as Record<string, unknown>
  if (m.type === 'new_window_ok' && typeof m.request_id === 'string' && typeof m.window_id === 'string' && typeof m.session_id === 'string') {
    return { type: 'new_window_ok', request_id: m.request_id, window_id: m.window_id, session_id: m.session_id }
  }
  if (m.type === 'new_window_error' && typeof m.request_id === 'string') {
    return { type: 'new_window_error', request_id: m.request_id, code: typeof m.code === 'string' ? m.code : 'internal', message: typeof m.message === 'string' ? m.message : '' }
  }
  return null
}

// ---- project_create / project_update (desktop project-form parity: name/root/icon/accent/agent) ----
export interface ProjectCreateMsg {
  readonly type: 'project_create'
  readonly request_id: string
  readonly name: string
  readonly root: string
  readonly cols?: number
  readonly rows?: number
  readonly icon?: string
  readonly accent_color?: string
  readonly agent?: RemoteAgentKind
  readonly resume_mode?: ProjectResumeMode
  readonly resume_session_id?: string
  readonly model?: RemoteLaunchFlags['model']
  readonly dangerous?: RemoteLaunchFlags['dangerouslySkipPermissions']
  readonly custom_command?: string
  readonly directories?: readonly ProjectDirectoryEdit[]
}

export interface ProjectUpdateMsg {
  readonly type: 'project_update'
  readonly request_id: string
  readonly project_id: string
  readonly name?: string
  readonly root?: string
  readonly icon?: string
  readonly accent_color?: string
  readonly agent?: RemoteAgentKind
  readonly resume_mode?: ProjectResumeMode
  readonly model?: RemoteLaunchFlags['model']
  readonly dangerous?: RemoteLaunchFlags['dangerouslySkipPermissions']
  readonly custom_command?: string
  readonly directories?: readonly ProjectDirectoryEdit[]
}

export interface ProjectDeleteMsg {
  readonly type: 'delete_project'
  readonly request_id: string
  readonly project_id: string
}

export interface ProjectEditOkMsg {
  readonly type: 'project_edit_ok'
  readonly request_id: string
  readonly project_id: string
  /** The session id of the pane a project CREATE seeded (so the browser can auto-attach it, like new_window_ok).
   * Absent on project update/delete replies and from older agents — both remain fully compatible. */
  readonly session_id?: string
}

export interface ProjectEditErrorMsg {
  readonly type: 'project_edit_error'
  readonly request_id: string
  readonly code: string
  readonly message: string
}

export type ProjectEditReply = ProjectEditOkMsg | ProjectEditErrorMsg

export function buildProjectCreate(requestId: string, opts: ProjectCreateOptions): ProjectCreateMsg {
  const msg: ProjectCreateMsg = {
    type: 'project_create',
    request_id: requestId,
    name: opts.name?.trim() ?? '',
    root: opts.root?.trim() ?? '',
  }
  const icon = opts.icon?.trim()
  const accentColor = opts.accentColor?.trim()
  if (icon) (msg as { icon?: string }).icon = icon
  if (accentColor) (msg as { accent_color?: string }).accent_color = accentColor
  if (opts.agent) (msg as { agent?: RemoteAgentKind }).agent = opts.agent
  const createResumeMode = normalizeProjectResumeMode(opts.resumeMode)
  if (createResumeMode) (msg as { resume_mode?: ProjectResumeMode }).resume_mode = createResumeMode
  const resumeSessionId = opts.resumeSessionId?.trim()
  if (resumeSessionId) (msg as { resume_session_id?: string }).resume_session_id = resumeSessionId
  const model = opts.model?.trim()
  if (model) (msg as { model?: string }).model = model
  if (opts.dangerouslySkipPermissions !== undefined) (msg as { dangerous?: boolean }).dangerous = opts.dangerouslySkipPermissions
  if (opts.customCommand !== undefined) (msg as { custom_command?: string }).custom_command = opts.customCommand.trim()
  if (opts.directories !== undefined) (msg as { directories?: ProjectDirectoryEdit[] }).directories = normalizeProjectDirectories(opts.directories)
  appendCreationGeometry(msg, opts)
  return msg
}

function normalizeCreationGeometry(
  opts: CreationGeometryOptions,
): { cols: number; rows: number } | undefined {
  const { cols, rows } = opts
  if (
    typeof cols !== 'number'
    || typeof rows !== 'number'
    || !Number.isInteger(cols)
    || !Number.isInteger(rows)
    || cols < MIN_COLS
    || rows < MIN_ROWS
    || cols > MAX_COLS
    || rows > MAX_ROWS
  ) return undefined
  return { cols, rows }
}

function appendCreationGeometry(msg: object, opts: CreationGeometryOptions): void {
  const geometry = normalizeCreationGeometry(opts)
  if (geometry) Object.assign(msg, geometry)
}

/** Map the legacy 'new' fresh-policy value to the desktop's 'none' so only desktop vocabulary
 * (continue|resume|none) ever reaches the wire. */
function normalizeProjectResumeMode(mode: ProjectEditOptions['resumeMode']): ProjectResumeMode | undefined {
  if (!mode) return undefined
  return mode === 'new' ? 'none' : mode
}

export function buildProjectUpdate(requestId: string, projectId: string, opts: ProjectEditOptions): ProjectUpdateMsg {
  const msg: ProjectUpdateMsg = {
    type: 'project_update',
    request_id: requestId,
    project_id: projectId,
  }
  const name = opts.name?.trim()
  const root = opts.root?.trim()
  const icon = opts.icon?.trim()
  const accentColor = opts.accentColor?.trim()
  if (name) (msg as { name?: string }).name = name
  if (root) (msg as { root?: string }).root = root
  if (icon) (msg as { icon?: string }).icon = icon
  if (accentColor) (msg as { accent_color?: string }).accent_color = accentColor
  if (opts.agent) (msg as { agent?: RemoteAgentKind }).agent = opts.agent
  const updateResumeMode = normalizeProjectResumeMode(opts.resumeMode)
  if (updateResumeMode) (msg as { resume_mode?: ProjectResumeMode }).resume_mode = updateResumeMode
  const model = opts.model?.trim()
  if (model) (msg as { model?: string }).model = model
  if (opts.dangerouslySkipPermissions !== undefined) (msg as { dangerous?: boolean }).dangerous = opts.dangerouslySkipPermissions
  if (opts.customCommand !== undefined) (msg as { custom_command?: string }).custom_command = opts.customCommand.trim()
  if (opts.directories !== undefined) (msg as { directories?: ProjectDirectoryEdit[] }).directories = normalizeProjectDirectories(opts.directories)
  return msg
}

function normalizeProjectDirectories(directories: readonly ProjectDirectoryEdit[]): ProjectDirectoryEdit[] {
  return directories
    .map((dir) => ({ name: dir.name?.trim() || undefined, path: dir.path.trim() }))
    .filter((dir) => dir.path.length > 0)
}

export function buildProjectDelete(requestId: string, projectId: string): ProjectDeleteMsg {
  return { type: 'delete_project', request_id: requestId, project_id: projectId }
}

export function parseProjectEditReply(raw: unknown): ProjectEditReply | null {
  if (typeof raw !== 'object' || raw === null) return null
  const m = raw as Record<string, unknown>
  if (m.type === 'project_edit_ok' && typeof m.request_id === 'string' && typeof m.project_id === 'string') {
    return {
      type: 'project_edit_ok',
      request_id: m.request_id,
      project_id: m.project_id,
      // Only a real string rides through (defensive: a malformed/absent session_id parses as "no seed pane").
      ...(typeof m.session_id === 'string' && m.session_id ? { session_id: m.session_id } : {}),
    }
  }
  if (m.type === 'project_edit_error' && typeof m.request_id === 'string') {
    return { type: 'project_edit_error', request_id: m.request_id, code: typeof m.code === 'string' ? m.code : 'internal', message: typeof m.message === 'string' ? m.message : '' }
  }
  return null
}

const ERROR_CODES: ReadonlySet<string> = new Set([
  'unauthenticated',
  'revoked',
  'unsupported_provider',
  'daemon_unavailable',
  'limit_reached',
  'macos_full_disk_access_required',
  'internal',
])

/** Parse an inbound control message into a typed create-session reply, or null if it isn't one (so the
 * caller can fall through to the other message handlers). Defensive: validates shape + the error code. */
export function parseCreateSessionReply(msg: unknown): CreateSessionReply | null {
  if (typeof msg !== 'object' || msg === null) return null
  const m = msg as Record<string, unknown>
  if (m.type === 'session_created') {
    if (typeof m.request_id !== 'string' || typeof m.session_id !== 'string') return null
    const label = typeof m.label === 'string' && m.label.trim() ? m.label : undefined
    return { type: 'session_created', request_id: m.request_id, session_id: m.session_id, ...(label ? { label } : {}) }
  }
  if (m.type === 'session_create_error') {
    if (typeof m.request_id !== 'string' || typeof m.message !== 'string') return null
    const code = ERROR_CODES.has(m.code as string) ? (m.code as SessionCreateErrorCode) : 'internal'
    return { type: 'session_create_error', request_id: m.request_id, code, message: m.message }
  }
  return null
}

export function parseAgentSessionsResult(msg: unknown): AgentSessionsResultMsg | null {
  const reply = parseAgentSessionsReply(msg)
  return reply?.type === 'agent_sessions_result' ? reply : null
}

export function parseAgentSessionsReply(msg: unknown): AgentSessionsReply | null {
  if (typeof msg !== 'object' || msg === null) return null
  const m = msg as Record<string, unknown>
  if (m.type === 'agent_sessions_error') {
    if (typeof m.request_id !== 'string' || typeof m.code !== 'string' || typeof m.message !== 'string') return null
    return {
      type: 'agent_sessions_error',
      request_id: m.request_id,
      code: m.code,
      message: m.message,
    }
  }
  if (m.type !== 'agent_sessions_result') return null
  if (typeof m.request_id !== 'string' || !Array.isArray(m.sessions)) return null
  const sessions: AgentSessionMeta[] = []
  for (const raw of m.sessions) {
    if (typeof raw !== 'object' || raw === null) continue
    const s = raw as Record<string, unknown>
    if (typeof s.id !== 'string') continue
    const id = normalizeProviderSessionId(s.id)
    if (id === null || id !== s.id) continue
    const agent = s.agent
    if (!isRunnableAgentKind(agent)) continue
    const modifiedAt = typeof s.modified_at_ms === 'number' && Number.isFinite(s.modified_at_ms)
      ? Math.max(0, Math.floor(s.modified_at_ms))
      : undefined
    const count = typeof s.message_count === 'number' && Number.isFinite(s.message_count)
      ? Math.max(0, Math.floor(s.message_count))
      : undefined
    sessions.push({
      id,
      agent,
      ...(modifiedAt !== undefined ? { modifiedAtMs: modifiedAt } : {}),
      ...(count !== undefined ? { messageCount: count } : {}),
      ...(typeof s.in_use === 'boolean' ? { inUse: s.in_use } : {}),
      ...(typeof s.custom_name === 'string' && s.custom_name.trim() ? { customName: s.custom_name.trim() } : {}),
    })
  }
  return { type: 'agent_sessions_result', request_id: m.request_id, sessions }
}

export function parseDirectoriesResult(msg: unknown): DirectoriesResultMsg | null {
  const reply = parseDirectoriesReply(msg)
  return reply?.type === 'directories_result' ? reply : null
}

/** Parse the typed list-directories success/error pair. Free-form error text remains untrusted. */
export function parseDirectoriesReply(msg: unknown): DirectoriesReply | null {
  if (typeof msg !== 'object' || msg === null) return null
  const m = msg as Record<string, unknown>
  if (m.type === 'directories_error') {
    if (typeof m.request_id !== 'string' || typeof m.code !== 'string' || typeof m.message !== 'string') return null
    return {
      type: 'directories_error',
      request_id: m.request_id,
      code: m.code,
      message: m.message,
    }
  }
  if (m.type === 'directories_result') {
    if (typeof m.request_id !== 'string' || typeof m.path !== 'string' || !Array.isArray(m.entries)) return null
    const entries: DirectoryEntry[] = []
    for (const raw of m.entries) {
      if (typeof raw !== 'object' || raw === null) continue
      const entry = raw as Record<string, unknown>
      if (typeof entry.name !== 'string' || typeof entry.path !== 'string') continue
      entries.push({ name: entry.name, path: entry.path })
    }
    return {
      type: 'directories_result',
      request_id: m.request_id,
      path: m.path,
      ...(typeof m.parent === 'string' && m.parent.trim() ? { parent: m.parent } : {}),
      entries,
    }
  }
  return null
}

/** Strictly parse the negotiated post-auth desktop access status message. */
export function parseDesktopAccessStatus(msg: unknown): DesktopAccessStatusMsg | null {
  if (typeof msg !== 'object' || msg === null) return null
  const m = msg as Record<string, unknown>
  if (m.type !== 'desktop_access_status') return null
  if (!['macos', 'linux', 'other'].includes(String(m.platform))) return null
  if (!['granted', 'required', 'unknown', 'not_applicable'].includes(String(m.full_disk_access))) return null
  if (Object.keys(m).some((key) => !['type', 'platform', 'full_disk_access'].includes(key))) return null
  return {
    type: 'desktop_access_status',
    platform: m.platform as DesktopPlatform,
    full_disk_access: m.full_disk_access as FullDiskAccessStatus,
  }
}

export function parseAgentSessionPreviewReply(msg: unknown): AgentSessionPreviewReply | null {
  if (typeof msg !== 'object' || msg === null) return null
  const m = msg as Record<string, unknown>
  if (m.type === 'agent_session_preview') {
    if (typeof m.request_id !== 'string' || !Array.isArray(m.lines)) return null
    const lines: AgentSessionPreviewLine[] = []
    for (const raw of m.lines) {
      if (typeof raw !== 'object' || raw === null) continue
      const line = raw as Record<string, unknown>
      if (typeof line.role !== 'string' || typeof line.text !== 'string') continue
      lines.push({ role: line.role, text: line.text })
    }
    return { type: 'agent_session_preview', request_id: m.request_id, lines }
  }
  if (m.type === 'agent_session_preview_error' && typeof m.request_id === 'string') {
    return {
      type: 'agent_session_preview_error',
      request_id: m.request_id,
      code: typeof m.code === 'string' ? m.code : 'internal',
      message: typeof m.message === 'string' ? m.message : '',
    }
  }
  return null
}

export function parseAgentSessionManageReply(msg: unknown): AgentSessionManageReply | null {
  if (typeof msg !== 'object' || msg === null) return null
  const m = msg as Record<string, unknown>
  if (m.type === 'agent_session_managed' && typeof m.request_id === 'string') {
    return { type: 'agent_session_managed', request_id: m.request_id }
  }
  if (m.type === 'agent_session_manage_error' && typeof m.request_id === 'string') {
    return {
      type: 'agent_session_manage_error',
      request_id: m.request_id,
      code: typeof m.code === 'string' ? m.code : 'internal',
      message: typeof m.message === 'string' ? m.message : '',
    }
  }
  return null
}
