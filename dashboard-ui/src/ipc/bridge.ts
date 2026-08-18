// Hybrid IPC bridge.
//
// Standalone development mode falls back to a lazily loaded mock payload and console-logged
// intents. Production fails closed when the native bridge is unavailable. When embedded in the native Rust app, the host injects
// `window.hydraDashboard`; this same UI then reads real models and emits
// structured intents without changing component code.

import type {
  AgentFolderSession,
  DashboardModel,
  RunnableAgentKind,
  SessionPreviewLine,
} from '../types/model'

export type Intent =
  | { type: 'dashboardBundleLoaded'; has_host: boolean; has_ipc: boolean; href: string }
  | { type: 'dashboardOverlayReady' }
  | { type: 'focusTerminal' }
  | {
      type: 'preflightLaunch'
      request_id: string
      agent?: string
      resolved_launch_command?: string
      cwd?: string
    }
  | { type: 'pickProjectFolder'; request_id: string }
  | { type: 'listFolderSessions'; request_id: string; agent: RunnableAgentKind; cwd: string }
  | { type: 'cancelFolderSessionRequest'; request_id: string }
  | {
      type: 'previewFolderSession'
      request_id: string
      agent: RunnableAgentKind
      cwd: string
      session_id: string
    }
  | { type: 'cancelFolderSessionPreview'; request_id: string }
  | {
      type: 'setFolderSessionName'
      request_id: string
      agent: RunnableAgentKind
      cwd: string
      session_id: string
      name: string | null
    }
  | {
      type: 'hideFolderSession' | 'deleteFolderSession' | 'unhideFolderSession'
      request_id: string
      agent: RunnableAgentKind
      cwd: string
      session_id: string
    }
  | {
      type: 'listHiddenFolderSessions'
      request_id: string
      agent: RunnableAgentKind
      cwd: string
    }
  | { type: 'reviveSession'; session_id: string; window_id: string; tab_id: string }
  | { type: 'openWorkspace'; project_id: string; workspace_id?: string }
  | {
      type: 'focusSessionOrPane'
      project_id: string
      window_id: string
      tab_id: string
      session_id: string
    }
  | { type: 'openLayoutPreset'; project_id: string; preset_id: string }
  | {
      type: 'saveLayoutPreset'
      project_id: string
      window_id: string
      preset_id: string
      name: string
    }
  | { type: 'updateProjectOrder'; ordered_project_ids: string[] }
  | { type: 'updateWindowOrder'; project_id: string; ordered_window_ids: string[] }
  | {
      type: 'createProject'
      name: string
      root: string
      icon?: string
      accent_color?: string
      default_agent?: string
      default_model?: string
      resume_mode?: 'continue' | 'resume' | 'none'
      dangerous_skip_permissions?: boolean
      custom_command?: string | null
      resolved_launch_command?: string
      resume_session_id?: string | null
      resume_session_title?: string | null
      resume_session_file?: string | null
      extra_folders?: Array<{ id: string; name: string; path: string }>
      create_initial_session?: boolean
    }
  | {
      type: 'updateProject'
      project_id: string
      name?: string
      root?: string
      icon?: string
      accent_color?: string
    }
  | {
      type: 'deleteProject'
      project_id: string
      remove_record: boolean
      keep_working_directory: boolean
      close_open_windows: boolean
    }
  | { type: 'focusWindow'; project_id: string; window_id: string }
  | {
      type: 'updateWindow'
      project_id: string
      window_id: string
      name?: string
      root?: string
    }
  | { type: 'stashWindow'; project_id: string; window_id: string }
  | { type: 'removeWindow'; project_id: string; window_id: string }
  | {
      type: 'updatePane'
      project_id: string
      window_id: string
      tab_id: string
      name: string
    }
  | { type: 'stashPane'; project_id: string; window_id: string; tab_id: string }
  | { type: 'removePane'; project_id: string; window_id: string; tab_id: string }
  | {
      type: 'beginStashedPaneDrag'
      project_id: string
      window_id: string
      tab_id: string
      session_id: string
    }
  | { type: 'moveStashedPaneDrag'; x: number; y: number }
  | { type: 'completeStashedPaneDrop'; x: number; y: number }
  | { type: 'cancelStashedPaneDrag' }
  | { type: 'openSplitDialog'; project_id: string; window_id: string; tab_id: string; dir: 'h' | 'v' }
  | { type: 'setRemoteAccess'; open: boolean }
  | { type: 'enrollDesktop'; code: string }
  | { type: 'removeRemote' }
  | { type: 'applyRemoteFilesystemMigration'; notice_id: string }
  | { type: 'acknowledgeRemoteFilesystemMigration'; notice_id: string }
  | { type: 'openAvailableUpdate' }
  | { type: 'openFullDiskAccessSettings' }
  | { type: 'refreshDesktopAccess' }
  | { type: 'openProjectDialog' }
  | { type: 'openEditProjectDialog'; project_id: string }
  | { type: 'openWindowDialog'; project_id: string }
  | { type: 'closeOverlay' }
  | {
      type: 'createWindow'
      project_id: string
      name?: string
      root?: string
      agent?: string
      model?: string
      session_mode?: string
      resume_session_id?: string | null
      resume_session_title?: string | null
      resume_session_file?: string | null
      resolved_launch_command?: string
    }
  | {
      type: 'splitPane'
      project_id: string
      window_id: string
      tab_id: string
      dir: 'h' | 'v'
      agent?: string
      resume_session_id?: string | null
      resume_session_title?: string | null
      resume_session_file?: string | null
      resolved_launch_command?: string
      /** Optional name for the new pane's tab; defaults to "Pane N" in the UI. */
      pane_name?: string
      /** Optional working directory for the new pane; when absent the pane inherits the split source's folder. */
      cwd?: string
    }
  | { type: 'setSidebarWidth'; width: number }

type DashboardModelListener = (model: DashboardModel) => void

export type DashboardHost = {
  getDashboardModel?: () => DashboardModel | Promise<DashboardModel>
  postIntent?: (intent: Intent) => void
  onDashboardModel?: (listener: DashboardModelListener) => void | (() => void)
}

declare global {
  interface Window {
    hydraDashboard?: DashboardHost
    ipc?: {
      postMessage?: (message: string) => void
    }
    webkit?: {
      messageHandlers?: {
        ipc?: {
          postMessage?: (message: string) => void
        }
      }
    }
    __HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__?: (requestId: string, path: string | null) => void
    __HYDRA_DASHBOARD_RESOLVE_FOLDER_SESSIONS__?: (
      requestId: string,
      sessions: AgentFolderSession[],
    ) => void
    __HYDRA_DASHBOARD_RESOLVE_SESSION_PREVIEW__?: (
      requestId: string,
      lines: SessionPreviewLine[],
    ) => void
    __HYDRA_DASHBOARD_RESOLVE_SESSION_NAME__?: (
      requestId: string,
      ok: boolean,
      sessions: AgentFolderSession[],
    ) => void
    __HYDRA_DASHBOARD_RESOLVE_HIDDEN_SESSIONS__?: (
      requestId: string,
      sessions: AgentFolderSession[],
    ) => void
    __HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?: (
      requestId: string,
      ok: boolean,
      message: string | null,
      code?: unknown,
    ) => void
    __HYDRA_DASHBOARD_APPLY_SIDEBAR_STATE__?: (state: NativeSidebarState) => void
    __HYDRA_PENDING_SIDEBAR_STATE__?: NativeSidebarState
  }
}

export type LaunchPreflightResult = { ok: boolean; message: string | null; code: string | null }
export type NativeSidebarState = {
  width_logical_px: number
  last_expanded_width_logical_px: number
}

let nextFolderRequestId = 1
let nextSessionRequestId = 1
let nextPreviewRequestId = 1
let nextSessionNameRequestId = 1
const folderPickers = new Map<string, (path: string | null) => void>()
type AbortableNativeRequest<T> = {
  resolve: (value: T) => void
  reject: (reason: unknown) => void
  timeoutId: number
  signal?: AbortSignal
  abortListener?: () => void
}
const folderSessionRequests = new Map<string, AbortableNativeRequest<AgentFolderSession[]>>()
const sessionPreviewRequests = new Map<string, AbortableNativeRequest<SessionPreviewLine[]>>()
const sessionNameRequests = new Map<string, (result: { ok: boolean; sessions: AgentFolderSession[] }) => void>()
const hiddenSessionRequests = new Map<string, AbortableNativeRequest<AgentFolderSession[]>>()
let nextHiddenSessionRequestId = 1
let nextLaunchPreflightRequestId = 1
// A WebView reload creates a fresh JS page while a delayed native callback from the old page may
// still arrive. A page-unique epoch prevents its request id from colliding with the new page's
// counters and resolving the wrong promise.
const requestPageEpoch = (() => {
  try {
    if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID()
  } catch {
    // Fall through to a non-secret uniqueness token; these ids are correlation, not authority.
  }
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`
})()

function nextNativeRequestId(prefix: string, sequence: number): string {
  return `${prefix}-${requestPageEpoch}-${sequence}`
}

const launchPreflightRequests = new Map<
  string,
  { resolve: (result: LaunchPreflightResult) => void; timeoutId: number }
>()

const LAUNCH_PREFLIGHT_TIMEOUT_MS = 8_000
const LAUNCH_PREFLIGHT_MESSAGE_MAX = 320
const LAUNCH_PREFLIGHT_CODE_MAX = 64
const SIDEBAR_NATIVE_MIN = 24
const SIDEBAR_NATIVE_MAX = 720
let latestNativeSidebarState: NativeSidebarState | null = null
const sidebarStateListeners = new Set<(state: NativeSidebarState) => void>()

function normalizeNativeSidebarState(value: unknown): NativeSidebarState | null {
  if (!value || typeof value !== 'object') return null
  const candidate = value as Partial<NativeSidebarState>
  if (!Number.isFinite(candidate.width_logical_px)) return null
  if (!Number.isFinite(candidate.last_expanded_width_logical_px)) return null
  const width_logical_px = Math.min(
    SIDEBAR_NATIVE_MAX,
    Math.max(SIDEBAR_NATIVE_MIN, Math.round(candidate.width_logical_px as number)),
  )
  const last_expanded_width_logical_px = Math.min(
    SIDEBAR_NATIVE_MAX,
    Math.max(180, Math.round(candidate.last_expanded_width_logical_px as number)),
  )
  return { width_logical_px, last_expanded_width_logical_px }
}

function installSidebarStateResolver(): void {
  if (typeof window === 'undefined') return
  window.__HYDRA_DASHBOARD_APPLY_SIDEBAR_STATE__ = (value) => {
    const state = normalizeNativeSidebarState(value)
    if (!state) return
    latestNativeSidebarState = state
    window.__HYDRA_PENDING_SIDEBAR_STATE__ = state
    for (const listener of sidebarStateListeners) listener(state)
  }
  const pending = normalizeNativeSidebarState(window.__HYDRA_PENDING_SIDEBAR_STATE__)
  if (pending) window.__HYDRA_DASHBOARD_APPLY_SIDEBAR_STATE__(pending)
}

function boundedPreflightMessage(message: unknown): string | null {
  if (typeof message !== 'string') return null
  const trimmed = message.trim()
  if (!trimmed) return null
  if (trimmed.length <= LAUNCH_PREFLIGHT_MESSAGE_MAX) return trimmed
  return `${trimmed.slice(0, LAUNCH_PREFLIGHT_MESSAGE_MAX - 1)}…`
}

function requestAbortError(): Error {
  // DOMException is available in the WebViews we ship, but Error keeps this helper usable in
  // non-browser test environments as well. Consumers branch on the standard AbortError name.
  const error = new Error('The folder-session request was cancelled.')
  error.name = 'AbortError'
  return error
}

function clearAbortableRequest<T>(
  requests: Map<string, AbortableNativeRequest<T>>,
  requestId: string,
): AbortableNativeRequest<T> | undefined {
  const pending = requests.get(requestId)
  if (!pending) return undefined
  requests.delete(requestId)
  window.clearTimeout(pending.timeoutId)
  if (pending.signal && pending.abortListener) {
    pending.signal.removeEventListener('abort', pending.abortListener)
  }
  return pending
}

function installFolderSessionResolvers(): void {
  if (typeof window === 'undefined') return
  window.__HYDRA_DASHBOARD_RESOLVE_FOLDER_SESSIONS__ = (requestId, sessions) => {
    const pending = clearAbortableRequest(folderSessionRequests, requestId)
    if (!pending) return
    pending.resolve(Array.isArray(sessions) ? sessions : [])
  }
  window.__HYDRA_DASHBOARD_RESOLVE_SESSION_PREVIEW__ = (requestId, lines) => {
    const pending = clearAbortableRequest(sessionPreviewRequests, requestId)
    if (!pending) return
    pending.resolve(Array.isArray(lines) ? lines : [])
  }
  window.__HYDRA_DASHBOARD_RESOLVE_HIDDEN_SESSIONS__ = (requestId, sessions) => {
    const pending = clearAbortableRequest(hiddenSessionRequests, requestId)
    if (!pending) return
    pending.resolve(Array.isArray(sessions) ? sessions : [])
  }
}

function installLaunchPreflightResolver(): void {
  if (typeof window === 'undefined') return
  window.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__ = (requestId, ok, message, code) => {
    const pending = launchPreflightRequests.get(requestId)
    if (!pending) return
    launchPreflightRequests.delete(requestId)
    window.clearTimeout(pending.timeoutId)
    pending.resolve({
      ok: Boolean(ok),
      message: boundedPreflightMessage(message),
      code:
        typeof code === 'string' &&
        code.length <= LAUNCH_PREFLIGHT_CODE_MAX &&
        /^[a-z0-9_]+$/.test(code)
          ? code
          : null,
    })
  }
}

if (typeof window !== 'undefined') {
  installLaunchPreflightResolver()
  installSidebarStateResolver()
  installFolderSessionResolvers()
  window.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__ = (requestId, path) => {
    const resolve = folderPickers.get(requestId)
    if (!resolve) return
    folderPickers.delete(requestId)
    resolve(path || null)
  }
  window.__HYDRA_DASHBOARD_RESOLVE_SESSION_NAME__ = (requestId, ok, sessions) => {
    const resolve = sessionNameRequests.get(requestId)
    if (!resolve) return
    sessionNameRequests.delete(requestId)
    resolve({ ok: Boolean(ok), sessions: Array.isArray(sessions) ? sessions : [] })
  }
}

function host(): DashboardHost | undefined {
  return globalThis.window?.hydraDashboard
}

function logMockIntent(intent: Intent): void {
  // Development/browser fallback logs must stay content-blind: intents can contain launch commands,
  // local paths, transcript ids, and enrollment codes. The discriminant is enough to debug routing.
  // eslint-disable-next-line no-console
  console.info('[dashboard intent]', intent.type)
}

async function loadDevelopmentMockModel(): Promise<DashboardModel> {
  if (!import.meta.env.DEV) {
    throw new Error('Hydra dashboard host is unavailable.')
  }
  const { mockDashboardModel } = await import('../data/mock')
  return mockDashboardModel
}

// Shared request/response for the remove ("hideFolderSession") and delete ("deleteFolderSession") folder
// actions: both resolve via the session-name channel with the refreshed folder listing.
function folderSessionMutation(
  type: 'hideFolderSession' | 'deleteFolderSession' | 'unhideFolderSession',
  agent: RunnableAgentKind,
  cwd: string,
  session_id: string,
): Promise<AgentFolderSession[]> {
  const trimmed = cwd.trim()
  if (!trimmed || !session_id.trim()) return Promise.resolve([])
  const canPostNative = Boolean(
    host()?.postIntent || window.ipc?.postMessage || window.webkit?.messageHandlers?.ipc?.postMessage,
  )
  if (!canPostNative) {
    logMockIntent({ type, request_id: 'mock', agent, cwd: trimmed, session_id })
    return Promise.resolve([])
  }
  const request_id = nextNativeRequestId('session-name', nextSessionNameRequestId++)
  return new Promise((resolve) => {
    sessionNameRequests.set(request_id, ({ sessions }) => resolve(sessions))
    window.setTimeout(() => {
      if (!sessionNameRequests.has(request_id)) return
      sessionNameRequests.delete(request_id)
      resolve([])
    }, 15_000)
    postIntent({ type, request_id, agent, cwd: trimmed, session_id })
  })
}

// Intent types that MUTATE the project→window→pane model (create / delete / stash / revive / split / swap / swallow /
// rename). After one of these the native side pushes ONE refresh, but that single push can be dropped (busy webview /
// fast next action), leaving the sidebar/topbar stale until the app is reopened. So React follows up: it POLLS the
// model a few times after a mutation until it changes, then stops. Pure display-refresh — no extra mutation. Non-
// mutating intents (focus, hover probes, document-click, dashboardBundleLoaded, debug) do NOT poll.
const MUTATION_INTENTS = new Set([
  'createProject', 'deleteProject', 'updateProject', 'updateProjectOrder',
  'createWindow', 'updateWindow', 'removeWindow', 'stashWindow', 'updateWindowOrder',
  'splitPane', 'removePane', 'stashPane', 'updatePane', 'reviveSession',
  'completeStashedPaneDrop', 'openLayoutPreset', 'saveLayoutPreset',
])

let pollTimer: ReturnType<typeof setTimeout> | null = null

/** After a mutation, re-fetch the model a few times (200ms × 5) and push each result to React via the same
 * `hydra-dashboard-model` event `subscribeDashboardModel` listens to. Stops early once the model changes vs the last
 * one delivered. This makes a dropped single refresh self-correct WITHOUT reopening the app. */
function pollModelAfterMutation(): void {
  if (pollTimer) clearTimeout(pollTimer)
  let tries = 0
  let last: string | null = null
  const tick = (): void => {
    tries += 1
    void bridge.getDashboardModel().then((model) => {
      const json = JSON.stringify(model)
      if (json !== last) {
        last = json
        window.dispatchEvent(new CustomEvent('hydra-dashboard-model', { detail: model }))
      }
      if (tries < 6) pollTimer = setTimeout(tick, 200)
      else pollTimer = null
    })
  }
  pollTimer = setTimeout(tick, 120) // first check shortly after the mutation lands on disk
}

function postIntent(intent: Intent): void {
  // Kick the follow-up poll for model-changing intents so a dropped native refresh self-heals in the browser.
  if (typeof window !== 'undefined' && MUTATION_INTENTS.has((intent as { type?: string }).type ?? '')) {
    pollModelAfterMutation()
  }
  const h = host()
  if (h?.postIntent) {
    h.postIntent(intent)
    return
  }
  const message = JSON.stringify(intent)
  if (window.ipc?.postMessage) {
    window.ipc.postMessage(message)
    return
  }
  if (window.webkit?.messageHandlers?.ipc?.postMessage) {
    window.webkit.messageHandlers.ipc.postMessage(message)
    return
  }
  logMockIntent(intent)
}

if (typeof window !== 'undefined') {
  window.setTimeout(() => {
    postIntent({
      type: 'dashboardBundleLoaded',
      has_host: Boolean(window.hydraDashboard?.postIntent),
      has_ipc: Boolean(window.ipc?.postMessage),
      href: window.location.href,
    })
  }, 0)
}

export const bridge = {
  // Read path. Native host should return the same DashboardModel shape as the
  // development mock. A production bundle without its native host must surface
  // an error instead of silently presenting development data.
  async getDashboardModel(): Promise<DashboardModel> {
    const h = host()
    if (h?.getDashboardModel) return h.getDashboardModel()
    await new Promise((r) => setTimeout(r, 150))
    return loadDevelopmentMockModel()
  },

  // Push refresh path. Native host can either expose onDashboardModel(listener)
  // or dispatch `new CustomEvent('hydra-dashboard-model', { detail: model })`.
  subscribeDashboardModel(listener: DashboardModelListener): () => void {
    const h = host()
    const cleanup = h?.onDashboardModel?.(listener)
    if (cleanup) return cleanup

    const onEvent = (event: Event): void => {
      listener((event as CustomEvent<DashboardModel>).detail)
    }
    window.addEventListener('hydra-dashboard-model', onEvent)
    return () => window.removeEventListener('hydra-dashboard-model', onEvent)
  },

  subscribeSidebarState(listener: (state: NativeSidebarState) => void): () => void {
    installSidebarStateResolver()
    sidebarStateListeners.add(listener)
    if (latestNativeSidebarState) listener(latestNativeSidebarState)
    return () => sidebarStateListeners.delete(listener)
  },

  dashboardOverlayReady(): void {
    postIntent({ type: 'dashboardOverlayReady' })
  },

  focusTerminal(): void {
    postIntent({ type: 'focusTerminal' })
  },

  openAvailableUpdate(): void {
    postIntent({ type: 'openAvailableUpdate' })
  },

  async preflightLaunch(input: {
    agent?: string
    resolved_launch_command?: string
    cwd?: string
  }): Promise<LaunchPreflightResult> {
    const resolved_launch_command = input.resolved_launch_command?.trim()
    const selectedAgent = input.agent?.trim().toLowerCase()
    // Project creation without an initial session has no launch to validate.
    // Terminal launches still go native so the working directory is checked.
    if (!resolved_launch_command && !selectedAgent) {
      return { ok: true, message: null, code: null }
    }

    const canPostNative = Boolean(
      host()?.postIntent || window.ipc?.postMessage || window.webkit?.messageHandlers?.ipc?.postMessage,
    )
    if (!canPostNative) {
      logMockIntent({
        type: 'preflightLaunch',
        request_id: 'mock',
        agent: input.agent,
        resolved_launch_command,
        cwd: input.cwd?.trim() || undefined,
      })
      return { ok: true, message: null, code: null }
    }

    // Tests and dynamically-installed development hosts can replace `window`
    // after this module is evaluated. Re-installing is idempotent and keeps the
    // same native callback contract in every environment.
    installLaunchPreflightResolver()
    const request_id = nextNativeRequestId('launch-preflight', nextLaunchPreflightRequestId++)
    return new Promise((resolve) => {
      const timeoutId = window.setTimeout(() => {
        if (!launchPreflightRequests.has(request_id)) return
        launchPreflightRequests.delete(request_id)
        resolve({
          ok: false,
          message: 'Hydra could not verify that launch command. Check the desktop app and try again.',
          code: null,
        })
      }, LAUNCH_PREFLIGHT_TIMEOUT_MS)
      launchPreflightRequests.set(request_id, { resolve, timeoutId })
      postIntent({
        type: 'preflightLaunch',
        request_id,
        agent: input.agent,
        resolved_launch_command,
        cwd: input.cwd?.trim() || undefined,
      })
    })
  },

  reviveSession(session_id: string, window_id: string, tab_id: string): void {
    postIntent({ type: 'reviveSession', session_id, window_id, tab_id })
  },

  openWorkspace(project_id: string, workspace_id?: string): void {
    postIntent({ type: 'openWorkspace', project_id, workspace_id })
  },

  focusSessionOrPane(
    project_id: string,
    window_id: string,
    tab_id: string,
    session_id: string,
  ): void {
    postIntent({ type: 'focusSessionOrPane', project_id, window_id, tab_id, session_id })
  },

  openLayoutPreset(project_id: string, preset_id: string): void {
    postIntent({ type: 'openLayoutPreset', project_id, preset_id })
  },

  saveLayoutPreset(project_id: string, window_id: string, preset_id: string, name: string): void {
    postIntent({ type: 'saveLayoutPreset', project_id, window_id, preset_id, name })
  },

  updateProjectOrder(ordered_project_ids: string[]): void {
    postIntent({ type: 'updateProjectOrder', ordered_project_ids })
  },

  updateWindowOrder(project_id: string, ordered_window_ids: string[]): void {
    postIntent({ type: 'updateWindowOrder', project_id, ordered_window_ids })
  },

  createProject(input: {
    name: string
    root: string
    icon?: string
    accent_color?: string
    default_agent?: string
    default_model?: string
    resume_mode?: 'continue' | 'resume' | 'none'
    dangerous_skip_permissions?: boolean
    custom_command?: string | null
    resolved_launch_command?: string
    resume_session_id?: string | null
    resume_session_title?: string | null
    resume_session_file?: string | null
    extra_folders?: Array<{ id: string; name: string; path: string }>
    create_initial_session?: boolean
  }): void {
    postIntent({ type: 'createProject', ...input })
  },

  updateProject(input: {
    project_id: string
    name?: string
    root?: string
    icon?: string
    accent_color?: string
  }): void {
    postIntent({ type: 'updateProject', ...input })
  },

  deleteProject(input: {
    project_id: string
    remove_record: boolean
    keep_working_directory: boolean
    close_open_windows: boolean
  }): void {
    // Keep the privileged native boundary exact. Callers may hold view-only
    // metadata (for example the confirmation dialog's project name/root), and
    // TypeScript permits such a wider object when it is passed through a
    // variable. Forwarding that object with a spread makes Rust correctly
    // reject the intent for unknown fields.
    postIntent({
      type: 'deleteProject',
      project_id: input.project_id,
      remove_record: input.remove_record,
      keep_working_directory: input.keep_working_directory,
      close_open_windows: input.close_open_windows,
    })
  },

  async pickProjectFolder(): Promise<string | null> {
    const canPostNative = Boolean(
      host()?.postIntent || window.ipc?.postMessage || window.webkit?.messageHandlers?.ipc?.postMessage,
    )
    if (!canPostNative) {
      logMockIntent({ type: 'pickProjectFolder', request_id: 'mock' })
      return null
    }

    const request_id = nextNativeRequestId('folder', nextFolderRequestId++)
    return new Promise((resolve) => {
      folderPickers.set(request_id, resolve)
      window.setTimeout(() => {
        if (!folderPickers.has(request_id)) return
        folderPickers.delete(request_id)
        resolve(null)
      }, 60_000)
      postIntent({ type: 'pickProjectFolder', request_id })
    })
  },

  async listFolderSessions(
    agent: RunnableAgentKind,
    cwd: string,
    signal?: AbortSignal,
  ): Promise<AgentFolderSession[]> {
    const trimmed = cwd.trim()
    if (!trimmed) return []
    if (signal?.aborted) throw requestAbortError()
    const canPostNative = Boolean(
      host()?.postIntent || window.ipc?.postMessage || window.webkit?.messageHandlers?.ipc?.postMessage,
    )
    if (!canPostNative) {
      logMockIntent({ type: 'listFolderSessions', request_id: 'mock', agent, cwd: trimmed })
      return []
    }

    installFolderSessionResolvers()
    const request_id = nextNativeRequestId('sessions', nextSessionRequestId++)
    return new Promise((resolve, reject) => {
      const timeoutId = window.setTimeout(() => {
        const pending = clearAbortableRequest(folderSessionRequests, request_id)
        if (!pending) return
        postIntent({ type: 'cancelFolderSessionRequest', request_id })
        pending.resolve([])
      }, 15_000)
      const abortListener = signal
        ? () => {
            const pending = clearAbortableRequest(folderSessionRequests, request_id)
            if (!pending) return
            postIntent({ type: 'cancelFolderSessionRequest', request_id })
            pending.reject(requestAbortError())
          }
        : undefined
      folderSessionRequests.set(request_id, {
        resolve,
        reject,
        timeoutId,
        signal,
        abortListener,
      })
      if (signal && abortListener) signal.addEventListener('abort', abortListener, { once: true })
      postIntent({ type: 'listFolderSessions', request_id, agent, cwd: trimmed })
    })
  },

  async previewFolderSession(
    agent: RunnableAgentKind,
    cwd: string,
    session_id: string,
    signal?: AbortSignal,
  ): Promise<SessionPreviewLine[]> {
    const trimmed = cwd.trim()
    if (!trimmed || !session_id.trim()) return []
    if (signal?.aborted) throw requestAbortError()
    const canPostNative = Boolean(
      host()?.postIntent || window.ipc?.postMessage || window.webkit?.messageHandlers?.ipc?.postMessage,
    )
    if (!canPostNative) {
      logMockIntent({
        type: 'previewFolderSession',
        request_id: 'mock',
        agent,
        cwd: trimmed,
        session_id,
      })
      return []
    }

    installFolderSessionResolvers()
    const request_id = nextNativeRequestId('preview', nextPreviewRequestId++)
    return new Promise((resolve, reject) => {
      const timeoutId = window.setTimeout(() => {
        const pending = clearAbortableRequest(sessionPreviewRequests, request_id)
        if (!pending) return
        postIntent({ type: 'cancelFolderSessionPreview', request_id })
        pending.resolve([])
      }, 15_000)
      const abortListener = signal
        ? () => {
            const pending = clearAbortableRequest(sessionPreviewRequests, request_id)
            if (!pending) return
            postIntent({ type: 'cancelFolderSessionPreview', request_id })
            pending.reject(requestAbortError())
          }
        : undefined
      sessionPreviewRequests.set(request_id, {
        resolve,
        reject,
        timeoutId,
        signal,
        abortListener,
      })
      if (signal && abortListener) signal.addEventListener('abort', abortListener, { once: true })
      postIntent({ type: 'previewFolderSession', request_id, agent, cwd: trimmed, session_id })
    })
  },

  async setFolderSessionName(
    agent: RunnableAgentKind,
    cwd: string,
    session_id: string,
    name: string | null,
  ): Promise<AgentFolderSession[]> {
    const trimmed = cwd.trim()
    if (!trimmed || !session_id.trim()) return []
    const canPostNative = Boolean(
      host()?.postIntent || window.ipc?.postMessage || window.webkit?.messageHandlers?.ipc?.postMessage,
    )
    if (!canPostNative) {
      logMockIntent({
        type: 'setFolderSessionName',
        request_id: 'mock',
        agent,
        cwd: trimmed,
        session_id,
        name,
      })
      return []
    }

    const request_id = nextNativeRequestId('session-name', nextSessionNameRequestId++)
    return new Promise((resolve) => {
      sessionNameRequests.set(request_id, ({ sessions }) => resolve(sessions))
      window.setTimeout(() => {
        if (!sessionNameRequests.has(request_id)) return
        sessionNameRequests.delete(request_id)
        resolve([])
      }, 15_000)
      postIntent({ type: 'setFolderSessionName', request_id, agent, cwd: trimmed, session_id, name })
    })
  },

  // REMOVE a folder session from the list non-destructively (hidden from future checks; file kept), or
  // DELETE it from disk completely. Both return the refreshed folder-session list via the shared
  // session-name resolver channel.
  async removeFolderSession(
    agent: RunnableAgentKind,
    cwd: string,
    session_id: string,
  ): Promise<AgentFolderSession[]> {
    return folderSessionMutation('hideFolderSession', agent, cwd, session_id)
  },

  async deleteFolderSession(
    agent: RunnableAgentKind,
    cwd: string,
    session_id: string,
  ): Promise<AgentFolderSession[]> {
    return folderSessionMutation('deleteFolderSession', agent, cwd, session_id)
  },

  // ADD BACK a removed session: returns the refreshed VISIBLE list.
  async unhideFolderSession(
    agent: RunnableAgentKind,
    cwd: string,
    session_id: string,
  ): Promise<AgentFolderSession[]> {
    return folderSessionMutation('unhideFolderSession', agent, cwd, session_id)
  },

  // List the REMOVED (hidden) sessions for a folder, for the "Removed" view.
  async listHiddenFolderSessions(
    agent: RunnableAgentKind,
    cwd: string,
    signal?: AbortSignal,
  ): Promise<AgentFolderSession[]> {
    const trimmed = cwd.trim()
    if (!trimmed) return []
    if (signal?.aborted) throw requestAbortError()
    const canPostNative = Boolean(
      host()?.postIntent || window.ipc?.postMessage || window.webkit?.messageHandlers?.ipc?.postMessage,
    )
    if (!canPostNative) {
      logMockIntent({ type: 'listHiddenFolderSessions', request_id: 'mock', agent, cwd: trimmed })
      return []
    }
    installFolderSessionResolvers()
    const request_id = nextNativeRequestId('hidden-sessions', nextHiddenSessionRequestId++)
    return new Promise((resolve, reject) => {
      const timeoutId = window.setTimeout(() => {
        const pending = clearAbortableRequest(hiddenSessionRequests, request_id)
        if (!pending) return
        postIntent({ type: 'cancelFolderSessionRequest', request_id })
        pending.resolve([])
      }, 15_000)
      const abortListener = signal
        ? () => {
            const pending = clearAbortableRequest(hiddenSessionRequests, request_id)
            if (!pending) return
            postIntent({ type: 'cancelFolderSessionRequest', request_id })
            pending.reject(requestAbortError())
          }
        : undefined
      hiddenSessionRequests.set(request_id, {
        resolve,
        reject,
        timeoutId,
        signal,
        abortListener,
      })
      if (signal && abortListener) signal.addEventListener('abort', abortListener, { once: true })
      postIntent({ type: 'listHiddenFolderSessions', request_id, agent, cwd: trimmed })
    })
  },

  focusWindow(project_id: string, window_id: string): void {
    postIntent({ type: 'focusWindow', project_id, window_id })
  },

  updateWindow(input: {
    project_id: string
    window_id: string
    name?: string
    root?: string
  }): void {
    postIntent({ type: 'updateWindow', ...input })
  },

  stashWindow(project_id: string, window_id: string): void {
    postIntent({ type: 'stashWindow', project_id, window_id })
  },

  removeWindow(project_id: string, window_id: string): void {
    postIntent({ type: 'removeWindow', project_id, window_id })
  },

  updatePane(project_id: string, window_id: string, tab_id: string, name: string): void {
    postIntent({ type: 'updatePane', project_id, window_id, tab_id, name })
  },

  stashPane(project_id: string, window_id: string, tab_id: string): void {
    postIntent({ type: 'stashPane', project_id, window_id, tab_id })
  },

  removePane(project_id: string, window_id: string, tab_id: string): void {
    postIntent({ type: 'removePane', project_id, window_id, tab_id })
  },

  beginStashedPaneDrag(
    project_id: string,
    window_id: string,
    tab_id: string,
    session_id: string,
  ): void {
    postIntent({ type: 'beginStashedPaneDrag', project_id, window_id, tab_id, session_id })
  },

  cancelStashedPaneDrag(): void {
    postIntent({ type: 'cancelStashedPaneDrag' })
  },

  moveStashedPaneDrag(x: number, y: number): void {
    postIntent({ type: 'moveStashedPaneDrag', x: Math.round(x), y: Math.round(y) })
  },

  completeStashedPaneDrop(x: number, y: number): void {
    postIntent({ type: 'completeStashedPaneDrop', x: Math.round(x), y: Math.round(y) })
  },

  createWindow(
    project_id: string,
    options?: {
      name?: string
      root?: string
      agent?: string
      model?: string
      session_mode?: string
      resume_session_id?: string | null
      resume_session_title?: string | null
      resume_session_file?: string | null
      resolved_launch_command?: string
    },
  ): void {
    postIntent({ type: 'createWindow', project_id, ...options })
  },

  splitPane(
    project_id: string,
    window_id: string,
    tab_id: string,
    dir: 'h' | 'v',
    options?: {
      agent?: string
      resume_session_id?: string | null
      resume_session_title?: string | null
      resume_session_file?: string | null
      resolved_launch_command?: string
      pane_name?: string
      cwd?: string
    },
  ): void {
    postIntent({ type: 'splitPane', project_id, window_id, tab_id, dir, ...options })
  },

  openSplitDialog(project_id: string, window_id: string, tab_id: string, dir: 'h' | 'v'): void {
    postIntent({ type: 'openSplitDialog', project_id, window_id, tab_id, dir })
  },

  /** Remote-access intent. The host may forward it to a negotiated private extension; neither this bridge nor the
   * public app owns the effective gate. A host without that capability must reject it fail-closed. */
  setRemoteAccess(open: boolean): void {
    postIntent({ type: 'setRemoteAccess', open })
  },

  /** Enrollment intent carrying a short-lived code to the host. A compatible private extension consumes it over its
   * bounded private channel; it must never be placed in process arguments, environment, logs, or persistent UI. */
  enrollDesktop(code: string): void {
    postIntent({ type: 'enrollDesktop', code })
  },

  /** Un-enrollment intent. Device identity and the effective gate remain private-extension authority. */
  removeRemote(): void {
    postIntent({ type: 'removeRemote' })
  },

  /** Apply only the fixed native folder-mode plan already bound to this notice id. */
  applyRemoteFilesystemMigration(notice_id: string): void {
    postIntent({ type: 'applyRemoteFilesystemMigration', notice_id })
  },

  /** Acknowledge the exact applied plan so native code can remove its temporary recovery record. */
  acknowledgeRemoteFilesystemMigration(notice_id: string): void {
    postIntent({ type: 'acknowledgeRemoteFilesystemMigration', notice_id })
  },

  /** Open the fixed native macOS Full Disk Access settings target. */
  openFullDiskAccessSettings(): void {
    postIntent({ type: 'openFullDiskAccessSettings' })
  },

  /** Re-run the native capability probe after the user returns from System Settings. */
  refreshDesktopAccess(): void {
    postIntent({ type: 'refreshDesktopAccess' })
  },

  openProjectDialog(): void {
    postIntent({ type: 'openProjectDialog' })
  },

  openEditProjectDialog(project_id: string): void {
    postIntent({ type: 'openEditProjectDialog', project_id })
  },

  openWindowDialog(project_id: string): void {
    postIntent({ type: 'openWindowDialog', project_id })
  },

  closeOverlay(): void {
    postIntent({ type: 'closeOverlay' })
  },

  setSidebarWidth(width: number): void {
    postIntent({ type: 'setSidebarWidth', width })
  },
}
