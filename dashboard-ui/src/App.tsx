import { useCallback, useEffect, useRef, useState, type MutableRefObject } from 'react'
import { flushSync } from 'react-dom'
import type {
  AgentFolderSession,
  DashboardModel,
  DashboardWindow,
  LoadState,
  ProjectCardView,
  ProjectDetail,
  RunnableAgentKind,
  SessionPreviewLine,
} from './types/model'
import { bridge } from './ipc/bridge'
import { Sidebar } from './components/Sidebar'
import { Topbar } from './components/Topbar'
import { TerminalHost } from './components/TerminalHost'
import { EmptyState, ErrorState, LoadingState } from './components/States'
import { AgentBadge } from './components/AgentBadge'
import { ModelSelector } from './components/ModelSelector'
import {
  AGENT_PROVIDERS,
  SELECTABLE_AGENT_OPTIONS,
  buildAgentLaunchArgv,
  defaultsFreshWithoutProviderHistory,
  isLegacyAgentKind,
  isOverlayAgentKind,
  isRunnableAgentKind,
  quoteAgentLaunchArg,
  resumeModeOptionsForAgent,
  supportsPermanentHistoryDelete,
  supportsProviderHistory,
  type OverlayAgentKind,
} from './model/agent-provider'

type OverlayModal =
  | {
      kind: 'split'
      project_id: string
      window_id: string
      tab_id: string
      dir: 'h' | 'v'
    }
  | { kind: 'newProject' }
  | { kind: 'editProject'; project_id: string }
  | { kind: 'newWindow'; project_id: string }
  | null

type OverlayHostWindow = Window & {
  __HYDRA_LAZY_OVERLAY_HOST__?: boolean
  __HYDRA_SHOW_OVERLAY_MODAL__?: (modal: OverlayModal) => void
}

const SIDEBAR_MIN = 220
const SIDEBAR_MAX = 560
const SIDEBAR_HOST_MAX = 720
const SIDEBAR_DEFAULT = 460
const SIDEBAR_COLLAPSED = 24
const OVERLAY_AGENT_OPTIONS = SELECTABLE_AGENT_OPTIONS
const OVERLAY_PREFLIGHT_ERROR_MAX = 320
const DIALOG_FOCUSABLE_SELECTOR = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[contenteditable="true"]',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

function clampResizableSidebarWidth(width: number): number {
  return Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, Math.round(width)))
}

/** Return the focus target needed to keep one Tab sequence inside a dialog.
 * `null` means the browser can advance to the adjacent target normally. */
export function dialogFocusWrapIndex(
  targetCount: number,
  activeIndex: number,
  backwards: boolean,
): number | null {
  if (targetCount <= 0) return null
  if (activeIndex < 0) return backwards ? targetCount - 1 : 0
  if (backwards && activeIndex === 0) return targetCount - 1
  if (!backwards && activeIndex === targetCount - 1) return 0
  return null
}

function dialogFocusTargets(dialog: HTMLElement): HTMLElement[] {
  return Array.from(dialog.querySelectorAll<HTMLElement>(DIALOG_FOCUSABLE_SELECTOR)).filter(
    (element) =>
      !element.hidden &&
      element.getAttribute('aria-hidden') !== 'true' &&
      element.getAttribute('aria-disabled') !== 'true' &&
      !element.closest('[hidden], [inert], [aria-hidden="true"]'),
  )
}

function containDialogKeyboard(
  event: React.KeyboardEvent<HTMLElement>,
  closeDialog: () => void,
): void {
  if (event.defaultPrevented) return
  if (event.key === 'Escape') {
    event.preventDefault()
    event.stopPropagation()
    closeDialog()
    return
  }
  if (event.key !== 'Tab') return

  const targets = dialogFocusTargets(event.currentTarget)
  if (targets.length === 0) {
    // A temporarily disabled dialog must not let Tab escape into another native WebView.
    event.preventDefault()
    event.stopPropagation()
    return
  }
  const activeIndex = targets.indexOf(
    event.currentTarget.ownerDocument.activeElement as HTMLElement,
  )
  const nextIndex = dialogFocusWrapIndex(targets.length, activeIndex, event.shiftKey)
  if (nextIndex === null) return
  event.preventDefault()
  event.stopPropagation()
  targets[nextIndex].focus()
}

function isVisibleWindow(win: DashboardWindow): boolean {
  return !win.stashed && win.tabs.some((tab) => !tab.stashed)
}

type OverlayAgent = OverlayAgentKind
type OverlayResumeMode = 'continue' | 'resume' | 'none'

type OverlayExtraFolderDraft = {
  id: string
  name: string
  path: string
}

type OverlayProjectDraft = {
  name: string
  root: string
  icon: string
  accent_color: string
  default_agent: OverlayAgent
  default_model: string
  resume_mode: OverlayResumeMode
  dangerous_skip_permissions: boolean
  custom_command: string
  resume_session_id: string | null
  resume_session_title: string | null
  resume_session_file: string | null
  extra_folders: OverlayExtraFolderDraft[]
  create_initial_session: boolean
}

type OverlayProjectEditDraft = {
  project_id: string
  name: string
  root: string
  icon: string
  accent_color: string
}

type OverlayWindowDraft = {
  name: string
  root: string
  agent: OverlayAgent
  model: string
  session_mode: OverlayResumeMode
  dangerous_skip_permissions: boolean
  resume_session_id: string | null
  resume_session_title: string | null
  resume_session_file: string | null
  custom_command: string
}

type FolderSessionState = {
  key: string
  loading: boolean
  sessions: AgentFolderSession[]
}

type PreviewState = {
  sessionId: string | null
  loading: boolean
  lines: SessionPreviewLine[] | null
}

const OVERLAY_COLOR_OPTIONS = ['#fbbf24', '#34d399', '#60a5fa', '#f87171', '#a78bfa', '#f472b6', '#e5e7eb']
const OVERLAY_ICON_OPTIONS = ['◆', '🪙', '📄', '🧪', '🚀', '📚', '🛠️', '🐙', '🧠', '🎯', '🌱', '⚙️']
const OVERLAY_MORE_ICONS = ['◇', '●', '○', '■', '□', '▲', '★', '☆', '✦', '✺', '❖', '💻', '🖥️', '⌨️', '🔌', '📦', '🗄️', '📈', '📉', '🏦', '🔬', '🧬', '🌊', '⚡', '✨']

const OVERLAY_AGENTS = AGENT_PROVIDERS

function normalizeHexColor(value: string | null | undefined, fallback = '#fbbf24'): string {
  if (!value) return fallback
  const trimmed = value.trim()
  if (/^#[0-9a-fA-F]{6}$/.test(trimmed)) return trimmed
  return fallback
}

function rotateHexColor(hex: string, degrees: number): string {
  const clean = normalizeHexColor(hex).slice(1)
  const r = parseInt(clean.slice(0, 2), 16) / 255
  const g = parseInt(clean.slice(2, 4), 16) / 255
  const b = parseInt(clean.slice(4, 6), 16) / 255
  const max = Math.max(r, g, b)
  const min = Math.min(r, g, b)
  const l = (max + min) / 2
  const d = max - min
  let h = 0
  let s = 0
  if (d !== 0) {
    s = d / (1 - Math.abs(2 * l - 1))
    if (max === r) h = 60 * (((g - b) / d) % 6)
    else if (max === g) h = 60 * ((b - r) / d + 2)
    else h = 60 * ((r - g) / d + 4)
  }
  h = (h + degrees + 360) % 360
  const c = (1 - Math.abs(2 * l - 1)) * s
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1))
  const m = l - c / 2
  const [rr, gg, bb] =
    h < 60
      ? [c, x, 0]
      : h < 120
        ? [x, c, 0]
        : h < 180
          ? [0, c, x]
          : h < 240
            ? [0, x, c]
            : h < 300
              ? [x, 0, c]
              : [c, 0, x]
  const toHex = (n: number): string =>
    Math.round((n + m) * 255)
      .toString(16)
      .padStart(2, '0')
  return `#${toHex(rr)}${toHex(gg)}${toHex(bb)}`
}

function folderName(path: string): string {
  const parts = path.split('/').filter(Boolean)
  return parts[parts.length - 1] ?? path
}

function relTime(ms: number): string {
  const diff = Math.max(0, Date.now() - ms)
  const minutes = Math.floor(diff / 60_000)
  if (minutes < 1) return 'now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

function boundedLaunchPreflightError(message: string | null): string {
  const fallback = 'That launch command is unavailable. Install the selected agent or choose another command.'
  const trimmed = message?.trim() || fallback
  if (trimmed.length <= OVERLAY_PREFLIGHT_ERROR_MAX) return trimmed
  return `${trimmed.slice(0, OVERLAY_PREFLIGHT_ERROR_MAX - 1)}…`
}

function isOverlayAgent(value: string | null | undefined): value is OverlayAgent {
  return isOverlayAgentKind(value)
}

function defaultProjectDraft(): OverlayProjectDraft {
  return {
    name: '',
    root: '',
    icon: OVERLAY_ICON_OPTIONS[0],
    accent_color: OVERLAY_COLOR_OPTIONS[0],
    default_agent: 'claude',
    default_model: 'default',
    // A new PROJECT starts a FRESH session by default (not resume/continue) — see the window-draft note.
    resume_mode: 'none',
    dangerous_skip_permissions: false,
    custom_command: '',
    resume_session_id: null,
    resume_session_title: null,
    resume_session_file: null,
    extra_folders: [],
    create_initial_session: true,
  }
}

function defaultProjectEditDraft(
  project: ProjectCardView | undefined,
  detail: ProjectDetail | undefined,
): OverlayProjectEditDraft {
  return {
    project_id: project?.project_id ?? '',
    name: project?.name ?? '',
    root: detail?.root ?? '',
    icon: project?.icon ?? OVERLAY_ICON_OPTIONS[0],
    accent_color: project?.accent_color ?? OVERLAY_COLOR_OPTIONS[0],
  }
}

function defaultWindowDraft(model: DashboardModel, projectId: string): OverlayWindowDraft {
  const detail = model.details[projectId]
  const defaults = detail?.launch_defaults
  const agent = isOverlayAgent(defaults?.agent) ? defaults.agent : 'claude'
  return {
    name: '',
    root: detail?.root ?? '',
    agent,
    model: defaults?.model?.trim() || 'default',
    // A FRESH create (new window) defaults to a BRAND-NEW session, NOT resume/continue. Defaulting to
    // 'continue' made `claude --continue` / `codex resume --last` reopen the folder's LAST session (or exit
    // with "no conversation to continue" when none existed — the "claude session exited" bug). Resuming is an
    // explicit choice via the session picker. Only honor an explicit project default of 'resume'/'none'.
    session_mode: defaults?.resume_mode === 'resume' || defaults?.resume_mode === 'none'
      ? defaults.resume_mode
      : 'none',
    dangerous_skip_permissions: Boolean(defaults?.dangerous_skip_permissions),
    resume_session_id: null,
    resume_session_title: null,
    resume_session_file: null,
    custom_command: defaults?.custom_command?.trim() || '',
  }
}

export function quoteOverlayLaunchArg(value: string): string {
  return quoteAgentLaunchArg(value)
}

export function joinOverlayLaunchArgv(parts: string[]): string {
  return parts.map(quoteOverlayLaunchArg).join(' ')
}

function resolveOverlayLaunchCommand(draft: OverlayProjectDraft): string {
  if (draft.default_agent === 'terminal') return ''
  const custom = draft.custom_command.trim()
  if (custom) return custom
  return joinOverlayLaunchArgv(buildAgentLaunchArgv({
    agent: draft.default_agent,
    resumeMode: draft.resume_mode,
    sessionId: draft.resume_session_id,
    sessionFile: draft.resume_session_file,
    model: draft.default_model,
    dangerous: draft.dangerous_skip_permissions,
  }))
}

function resolveOverlayWindowLaunchCommand(draft: OverlayWindowDraft): string {
  if (draft.agent === 'terminal') return ''
  const custom = draft.custom_command.trim()
  if (custom) return custom
  return joinOverlayLaunchArgv(buildAgentLaunchArgv({
    agent: draft.agent,
    resumeMode: draft.session_mode,
    sessionId: draft.resume_session_id,
    sessionFile: draft.resume_session_file,
    model: draft.model,
    dangerous: draft.dangerous_skip_permissions,
  }))
}

function actionableFilesystemMigrationNoticeKey(model: DashboardModel): string | null {
  const notice = model.filesystem_mode_migration
  if (!notice) return null
  if (notice.phase === 'ready_to_apply') {
    return notice.recovery_record_path === undefined
      ? `${notice.notice_id}:${notice.phase}`
      : null
  }
  if (notice.phase === 'interrupted' || notice.phase === 'applied') {
    return typeof notice.recovery_record_path === 'string' && notice.recovery_record_path.length > 0
      ? `${notice.notice_id}:${notice.phase}`
      : null
  }
  return null
}

export function App(): JSX.Element {
  const [state, setState] = useState<LoadState>({ kind: 'loading' })
  const latestModelRef = useRef<DashboardModel | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [focusedWindowId, setFocusedWindowId] = useState<string | null>(null)
  const [sidebarWidth, setSidebarWidth] = useState(SIDEBAR_DEFAULT)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [lastExpandedSidebarWidth, setLastExpandedSidebarWidth] = useState(SIDEBAR_DEFAULT)
  const lastAutoExpandedMigrationNoticeKeyRef = useRef<string | null>(null)
  const sidebarResize = useRef<{
    pointerId: number
    startScreenX: number
    startWidth: number
    lastWidth: number
    target: HTMLDivElement
  } | null>(null)
  const chromeMode = new URLSearchParams(window.location.search).get('chrome')
  const sidebarOnly = chromeMode === 'sidebar'
  const topbarOnly = chromeMode === 'topbar'
  const overlayOnly = chromeMode === 'overlay'

  const finishSidebarResize = useCallback((): void => {
    const drag = sidebarResize.current
    sidebarResize.current = null
    if (drag) {
      try {
        if (drag.target.hasPointerCapture(drag.pointerId)) {
          drag.target.releasePointerCapture(drag.pointerId)
        }
      } catch {
        // WebKit can release capture while a native overlay makes this WebView insensitive.
      }
    }
    document.body.classList.remove('is-resizing-sidebar')
  }, [])

  useEffect(() => () => finishSidebarResize(), [finishSidebarResize])

  useEffect(() => {
    let alive = true

    const applyModel = (model: DashboardModel): void => {
      if (!alive) return
      // Native may push the model script and the modal script back-to-back. Keep a synchronous
      // source for the overlay handler; React's state commit intentionally remains asynchronous.
      latestModelRef.current = model
      setState({ kind: 'ready', model })
      setSelectedId((prevSelectedId) => {
        const activeWindowProjectId = model.active_window_id
          ? Object.values(model.details).find((detail) =>
              detail.windows.some((w) => w.window_id === model.active_window_id),
            )?.project_id
          : null
        const selectedStillExists = model.projects.some((p) => p.project_id === prevSelectedId)
        const nextSelectedId = selectedStillExists
          ? (activeWindowProjectId ?? prevSelectedId)
          : (model.active_project?.project_id ?? model.projects[0]?.project_id ?? null)

        setFocusedWindowId((prevWindowId) => {
          if (!nextSelectedId) return null
          const windows = (model.details[nextSelectedId]?.windows ?? []).filter(isVisibleWindow)
          const activeWindowStillVisible =
            model.active_window_id && windows.some((w) => w.window_id === model.active_window_id)
          if (activeWindowStillVisible) return model.active_window_id ?? null
          const focusedStillExists = windows.some((w) => w.window_id === prevWindowId)
          return focusedStillExists ? prevWindowId : (windows[0]?.window_id ?? null)
        })

        return nextSelectedId
      })
    }

    bridge
      .getDashboardModel()
      .then(applyModel)
      .catch((err) => {
        if (!alive) return
        setState({ kind: 'error', message: String(err) })
      })

    const unsubscribe = bridge.subscribeDashboardModel(applyModel)

    return () => {
      alive = false
      unsubscribe()
    }
  }, [])

  useEffect(
    () =>
      bridge.subscribeSidebarState((native) => {
        const width = Math.min(
          SIDEBAR_HOST_MAX,
          Math.max(SIDEBAR_COLLAPSED, native.width_logical_px),
        )
        const lastExpanded = Math.min(
          SIDEBAR_HOST_MAX,
          Math.max(SIDEBAR_MIN, native.last_expanded_width_logical_px),
        )
        setSidebarWidth(width)
        setSidebarCollapsed(width <= SIDEBAR_COLLAPSED)
        setLastExpandedSidebarWidth(lastExpanded)
      }),
    [],
  )

  useEffect(() => {
    const noticeKey =
      state.kind === 'ready' ? actionableFilesystemMigrationNoticeKey(state.model) : null
    if (!noticeKey || lastAutoExpandedMigrationNoticeKeyRef.current === noticeKey) return

    // Reveal each actionable phase once. The same notice id advances Ready→Interrupted/Applied,
    // and the user must see the result at the time native code changes the folders. A deliberate
    // collapse is still respected for repeated models within the same exact phase.
    lastAutoExpandedMigrationNoticeKeyRef.current = noticeKey
    if (!sidebarCollapsed) return
    setSidebarCollapsed(false)
    setSidebarWidth(lastExpandedSidebarWidth)
    bridge.setSidebarWidth(lastExpandedSidebarWidth)
  }, [lastExpandedSidebarWidth, sidebarCollapsed, state])

  if (state.kind === 'loading') return <LoadingState />
  if (state.kind === 'error') return <ErrorState message={state.message} />

  const { model } = state
  const selected =
    (selectedId ? model.projects.find((p) => p.project_id === selectedId) : undefined) ??
    model.projects[0]
  const detail = selected ? model.details[selected.project_id] : undefined
  const visibleWindows = detail?.windows.filter(isVisibleWindow) ?? []
  const focusedWindow =
    visibleWindows.find((w) => w.window_id === focusedWindowId) ?? visibleWindows[0] ?? null
  const selectedAccent = normalizeHexColor(selected?.accent_color)
  const selectedAccent2 = rotateHexColor(selectedAccent, 38)
  const selectedAccent3 = rotateHexColor(selectedAccent, -42)
  const accentStyle = {
    ['--accent' as string]: selectedAccent,
    ['--accent-2' as string]: selectedAccent2,
    ['--accent-3' as string]: selectedAccent3,
  }

  const selectProject = (id: string): void => {
    setSelectedId(id)
    const firstWin = (model.details[id]?.windows ?? []).find(isVisibleWindow)?.window_id ?? null
    setFocusedWindowId(firstWin)
    bridge.openWorkspace(id)
    if (firstWin) bridge.focusWindow(id, firstWin)
  }

  const focusWindow = (windowId: string): void => {
    setFocusedWindowId(windowId)
    if (selected) bridge.focusWindow(selected.project_id, windowId)
  }

  const applySidebarWidth = (width: number): void => {
    const next = clampResizableSidebarWidth(width)
    setSidebarCollapsed(false)
    setLastExpandedSidebarWidth(next)
    setSidebarWidth(next)
    bridge.setSidebarWidth(next)
  }

  const setSidebarRailCollapsed = (collapsed: boolean): void => {
    setSidebarCollapsed(collapsed)
    const next = collapsed ? SIDEBAR_COLLAPSED : lastExpandedSidebarWidth
    setSidebarWidth(next)
    bridge.setSidebarWidth(next)
  }

  const toggleSidebarRail = (event: React.MouseEvent<HTMLButtonElement>): void => {
    const collapse = !sidebarCollapsed
    setSidebarRailCollapsed(collapse)
    // A pointer click into WebKit moves focus away from the native terminal.
    // Restore it only after mouse collapse, when the user's next keystroke is
    // overwhelmingly intended for the newly-expanded terminal. Keyboard
    // activation has detail=0 and intentionally keeps focus on the rail button.
    if (collapse && event.detail > 0) bridge.focusTerminal()
  }

  const startSidebarResize = (e: React.PointerEvent<HTMLDivElement>): void => {
    if (sidebarCollapsed || !e.isPrimary || e.button !== 0) return
    e.preventDefault()
    finishSidebarResize()
    try {
      e.currentTarget.setPointerCapture(e.pointerId)
    } catch {
      return
    }
    sidebarResize.current = {
      pointerId: e.pointerId,
      startScreenX: e.screenX,
      startWidth: sidebarWidth,
      lastWidth: clampResizableSidebarWidth(sidebarWidth),
      target: e.currentTarget,
    }
    document.body.classList.add('is-resizing-sidebar')
  }

  const moveSidebarResize = (e: React.PointerEvent<HTMLDivElement>): void => {
    const drag = sidebarResize.current
    if (!drag || e.pointerId !== drag.pointerId) return
    if ((e.buttons & 1) === 0 || !drag.target.hasPointerCapture(drag.pointerId)) {
      finishSidebarResize()
      return
    }
    e.preventDefault()
    const next = clampResizableSidebarWidth(
      drag.startWidth + e.screenX - drag.startScreenX,
    )
    if (next === drag.lastWidth) return
    drag.lastWidth = next
    applySidebarWidth(next)
  }

  const endSidebarResize = (e: React.PointerEvent<HTMLDivElement>): void => {
    const drag = sidebarResize.current
    if (!drag || e.pointerId !== drag.pointerId) return
    finishSidebarResize()
  }

  const loseSidebarPointerCapture = (e: React.PointerEvent<HTMLDivElement>): void => {
    const drag = sidebarResize.current
    if (!drag || e.pointerId !== drag.pointerId) return
    finishSidebarResize()
  }

  const resizeSidebarFromKeyboard = (event: React.KeyboardEvent<HTMLDivElement>): void => {
    let next: number | null = null
    if (event.key === 'ArrowLeft') next = sidebarWidth - 16
    if (event.key === 'ArrowRight') next = sidebarWidth + 16
    if (event.key === 'Home') next = SIDEBAR_MIN
    if (event.key === 'End') next = SIDEBAR_MAX
    if (next === null) return
    event.preventDefault()
    applySidebarWidth(next)
  }

  if (sidebarOnly) {
    return (
      <div
        className={`shell shell--sidebar-only ${sidebarCollapsed ? 'is-sidebar-collapsed' : ''}`}
        style={accentStyle}
      >
        <Sidebar
          model={model}
          selectedId={selected?.project_id ?? null}
          focusedWindowId={focusedWindow?.window_id ?? null}
          collapsed={sidebarCollapsed}
          onToggleCollapsed={toggleSidebarRail}
          onSelect={selectProject}
          onReorder={(ids) => bridge.updateProjectOrder(ids)}
          onWindowReorder={(projectId, ids) => bridge.updateWindowOrder(projectId, ids)}
          onFocusWindow={focusWindow}
        />
        {!sidebarCollapsed && (
          <div
            className="sidebar-resizer sidebar-resizer--embedded"
            role="separator"
            aria-orientation="vertical"
            aria-label="Resize project sidebar"
            aria-valuemin={SIDEBAR_MIN}
            aria-valuemax={SIDEBAR_MAX}
            aria-valuenow={sidebarWidth}
            tabIndex={0}
            onKeyDown={resizeSidebarFromKeyboard}
            onPointerDown={startSidebarResize}
            onPointerMove={moveSidebarResize}
            onPointerUp={endSidebarResize}
            onPointerCancel={endSidebarResize}
            onLostPointerCapture={loseSidebarPointerCapture}
          />
        )}
      </div>
    )
  }

  if (topbarOnly) {
    return (
      <div className="shell shell--topbar-only" style={accentStyle}>
        {!selected ? (
          <div className="window-tabs window-tabs--empty" />
        ) : (
          <Topbar
            project={selected}
            detail={detail}
            focusedWindowId={focusedWindow?.window_id ?? null}
            activeTabId={model.active_tab_id ?? null}
            onFocusWindow={focusWindow}
          />
        )}
      </div>
    )
  }

  if (overlayOnly) {
    return <OverlayChrome model={model} latestModelRef={latestModelRef} />
  }

  return (
    <div
      className={`shell ${sidebarCollapsed ? 'is-sidebar-collapsed' : ''}`}
      style={{
        ...accentStyle,
        gridTemplateColumns: sidebarCollapsed
          ? `${sidebarWidth}px 1fr`
          : `${sidebarWidth}px 6px 1fr`,
      }}
    >
      <Sidebar
        model={model}
        selectedId={selected?.project_id ?? null}
        focusedWindowId={focusedWindow?.window_id ?? null}
        collapsed={sidebarCollapsed}
        onToggleCollapsed={toggleSidebarRail}
        onSelect={selectProject}
        onReorder={(ids) => bridge.updateProjectOrder(ids)}
        onWindowReorder={(projectId, ids) => bridge.updateWindowOrder(projectId, ids)}
        onFocusWindow={focusWindow}
      />
      {!sidebarCollapsed && (
        <div
          className="sidebar-resizer"
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize project sidebar"
          aria-valuemin={SIDEBAR_MIN}
          aria-valuemax={SIDEBAR_MAX}
          aria-valuenow={sidebarWidth}
          tabIndex={0}
          onKeyDown={resizeSidebarFromKeyboard}
          onPointerDown={startSidebarResize}
          onPointerMove={moveSidebarResize}
          onPointerUp={endSidebarResize}
          onPointerCancel={endSidebarResize}
          onLostPointerCapture={loseSidebarPointerCapture}
        />
      )}
      <div className="workspace">
        {!selected ? (
          <EmptyState
            title="No projects yet"
            hint="Create or open a project to see it here."
          />
        ) : (
          <>
            <Topbar
              project={selected}
              detail={detail}
              focusedWindowId={focusedWindow?.window_id ?? null}
              activeTabId={model.active_tab_id ?? null}
              onFocusWindow={focusWindow}
            />
            <TerminalHost projectName={selected.name} window={focusedWindow} />
          </>
        )}
      </div>
    </div>
  )
}

function OverlayChrome({
  model,
  latestModelRef,
}: {
  model: DashboardModel
  latestModelRef: MutableRefObject<DashboardModel | null>
}): JSX.Element {
  const [modal, setModal] = useState<OverlayModal>(null)
  const [agent, setAgent] = useState<OverlayAgent>('claude')
  const [splitModel, setSplitModel] = useState<string>('default')
  const [splitDangerous, setSplitDangerous] = useState(false)
  const [sessionId, setSessionId] = useState<string | null>(null)
  // Name for the pane created by a split. Defaults to "Pane N"; user can override, keeping the default is fine.
  const [paneName, setPaneName] = useState<string>('')
  // Working directory for a split's new pane. `splitCwd` is the currently-selected folder (defaults to the source
  // window's folder). `splitWindowCwd` is that source-window default, kept separately so the picker can render it as
  // its own "Window folder" button (when it isn't a project folder) and distinguish it from an "Other folder…" pick.
  const [splitCwd, setSplitCwd] = useState<string | null>(null)
  const [splitWindowCwd, setSplitWindowCwd] = useState<string | null>(null)
  const [projectDraft, setProjectDraft] = useState<OverlayProjectDraft>(defaultProjectDraft)
  const [projectEditDraft, setProjectEditDraft] = useState<OverlayProjectEditDraft>(() =>
    defaultProjectEditDraft(undefined, undefined),
  )
  const [windowDraft, setWindowDraft] = useState<OverlayWindowDraft>(() =>
    defaultWindowDraft(model, model.projects[0]?.project_id ?? ''),
  )
  const [folderSessions, setFolderSessions] = useState<FolderSessionState>({
    key: '',
    loading: false,
    sessions: [],
  })
  const [previewState, setPreviewState] = useState<PreviewState>({
    sessionId: null,
    loading: false,
    lines: null,
  })
  const [editingSessionId, setEditingSessionId] = useState<string | null>(null)
  const [sessionNameDraft, setSessionNameDraft] = useState('')
  const [deleteConfirmSessionId, setDeleteConfirmSessionId] = useState<string | null>(null)
  // Screen anchor (top + the popup's right edge) of the row whose delete is being confirmed, so the
  // confirm card floats just to the RIGHT of the picker, aligned with the relevant row.
  const [deleteConfirmAnchor, setDeleteConfirmAnchor] = useState<{ top: number; left: number } | null>(
    null,
  )
  const deleteConfirmReturnFocusRef = useRef<HTMLElement | null>(null)
  const deleteConfirmFocusOwnerRef = useRef(false)
  const deleteConfirmFocusTimerRef = useRef<number | null>(null)
  const deleteConfirmFocusEpochRef = useRef(0)
  const parentDialogRef = useRef<HTMLElement | null>(null)
  const cancelDeleteConfirmFocusRestore = useCallback((): void => {
    deleteConfirmFocusEpochRef.current += 1
    if (deleteConfirmFocusTimerRef.current !== null) {
      window.clearTimeout(deleteConfirmFocusTimerRef.current)
      deleteConfirmFocusTimerRef.current = null
    }
  }, [])
  const queueParentDialogFocus = useCallback((preferOpener: boolean): void => {
    const opener = deleteConfirmReturnFocusRef.current
    const parent = parentDialogRef.current
    deleteConfirmReturnFocusRef.current = null
    cancelDeleteConfirmFocusRestore()
    const focusEpoch = deleteConfirmFocusEpochRef.current
    deleteConfirmFocusTimerRef.current = window.setTimeout(() => {
      deleteConfirmFocusTimerRef.current = null
      if (deleteConfirmFocusEpochRef.current !== focusEpoch) return
      deleteConfirmFocusOwnerRef.current = false
      // The ref and epoch jointly own this restore. A later modal must never inherit a timer or
      // opener from the nested confirmation that belonged to the previous parent dialog.
      if (!parent || parentDialogRef.current !== parent || parent.isConnected === false) return
      if (
        preferOpener &&
        opener?.isConnected &&
        parent.contains(opener) &&
        !opener.closest('[hidden], [inert], [aria-hidden="true"]') &&
        !('disabled' in opener && (opener as HTMLButtonElement).disabled)
      ) {
        opener.focus()
        return
      }
      dialogFocusTargets(parent)[0]?.focus()
    }, 0)
  }, [cancelDeleteConfirmFocusRestore])
  const [showRemoved, setShowRemoved] = useState(false)
  const [showAllSessions, setShowAllSessions] = useState(false)
  const [hiddenSessions, setHiddenSessions] = useState<AgentFolderSession[]>([])
  const folderSessionAbortRef = useRef<AbortController | null>(null)
  const sessionPreviewAbortRef = useRef<AbortController | null>(null)
  const hiddenSessionAbortRef = useRef<AbortController | null>(null)
  const cancelFolderSessionWork = useCallback((): void => {
    folderSessionAbortRef.current?.abort()
    folderSessionAbortRef.current = null
    sessionPreviewAbortRef.current?.abort()
    sessionPreviewAbortRef.current = null
    hiddenSessionAbortRef.current?.abort()
    hiddenSessionAbortRef.current = null
  }, [])
  const [launchPreflightPending, setLaunchPreflightPending] = useState(false)
  const [launchPreflightError, setLaunchPreflightError] = useState<string | null>(null)
  const launchPreflightPendingRef = useRef(false)
  const launchPreflightAttemptRef = useRef(0)
  const launchPreflightDraftRef = useRef('')
  const autoPickerKey = useRef<string | null>(null)
  const modalProjectId = modal?.kind === 'newProject' || !modal ? null : modal.project_id
  const project = modalProjectId ? model.projects.find((p) => p.project_id === modalProjectId) : undefined
  const detail = modalProjectId ? model.details[modalProjectId] : undefined
  useEffect(() => {
    document.body.classList.add('is-overlay-chrome')
    const linuxLazyOverlay = Boolean((window as OverlayHostWindow).__HYDRA_LAZY_OVERLAY_HOST__)
    if (linuxLazyOverlay) document.body.classList.add('is-linux-lazy-overlay')
    return () => {
      document.body.classList.remove('is-overlay-chrome')
      if (linuxLazyOverlay) document.body.classList.remove('is-linux-lazy-overlay')
    }
  }, [])

  useEffect(() => {
    const hostWindow = window as OverlayHostWindow
    hostWindow.__HYDRA_SHOW_OVERLAY_MODAL__ = (next) => {
      cancelFolderSessionWork()
      const restoreParentFocus = deleteConfirmFocusOwnerRef.current && next !== null
      cancelDeleteConfirmFocusRestore()
      // `__HYDRA_DASHBOARD_SET_MODEL__` notifies its listeners synchronously. Reading this ref
      // makes a modal sent immediately afterwards derive its draft from that model rather than
      // from the previous render's closure.
      const currentModel = latestModelRef.current ?? model
      // This hook is called by the native host, outside a React event. The Linux host does not
      // expose the GtkStack document until WebKit reports that this JavaScript task completed, so
      // commit the modal (including autofocus and derived draft state) before returning from the
      // task. Without `flushSync`, React 18 may batch the update past the native completion callback
      // and briefly expose a ready document with no dialog.
      flushSync(() => {
        launchPreflightAttemptRef.current += 1
        launchPreflightPendingRef.current = false
        setLaunchPreflightPending(false)
        setLaunchPreflightError(null)
        setDeleteConfirmSessionId(null)
        setDeleteConfirmAnchor(null)
        deleteConfirmReturnFocusRef.current = null
        setModal(next)
        setSessionId(null)
        setSplitModel('default')
        setPaneName('') // fresh split → empty field shows the "Pane N" placeholder default
        if (next?.kind === 'split') {
          const detail = currentModel.details[next.project_id]
          const srcWindow = detail?.windows.find((w) => w.window_id === next.window_id)
          const pane = srcWindow?.tabs.find((t) => t.tab_id === next.tab_id)
          // Default the split's dangerous/yolo mode from the project's launch defaults (same
          // source the new-window form inherits); the dialog checkbox can override per split.
          setSplitDangerous(Boolean(detail?.launch_defaults?.dangerous_skip_permissions))
          // Default the split's folder to the SOURCE WINDOW's folder (every pane in a window shares it): prefer the
          // clicked pane's cwd, else any pane in that window. The picker pre-selects the matching folder button.
          const windowCwd =
            pane?.cwd?.trim() || srcWindow?.tabs.find((t) => t.cwd?.trim())?.cwd?.trim() || null
          setSplitWindowCwd(windowCwd)
          setSplitCwd(windowCwd)
          setAgent(isRunnableAgentKind(pane?.agent)
            ? pane.agent
            : pane?.agent === 'shell'
              ? 'terminal'
              : 'claude')
        } else if (next?.kind === 'newProject') {
          setProjectDraft(defaultProjectDraft())
        } else if (next?.kind === 'editProject') {
          const project = currentModel.projects.find((p) => p.project_id === next.project_id)
          setProjectEditDraft(defaultProjectEditDraft(project, currentModel.details[next.project_id]))
        } else if (next?.kind === 'newWindow') {
          setWindowDraft(defaultWindowDraft(currentModel, next.project_id))
        }
      })
      if (restoreParentFocus) {
        // React reuses the parent and its first input for same-kind replacements, so `autoFocus`
        // does not run again after the nested dialog is removed. Restore actual DOM focus after
        // the flush has made the replacement parent current and non-inert.
        queueParentDialogFocus(false)
      } else {
        deleteConfirmFocusOwnerRef.current = false
      }
    }
    return () => {
      delete hostWindow.__HYDRA_SHOW_OVERLAY_MODAL__
    }
    // `latestModelRef` is App-owned and stable. Keeping this handler installed avoids a gap while
    // React commits a new model; every invocation reads the ref instead of relying on this render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    cancelDeleteConfirmFocusRestore,
    cancelFolderSessionWork,
    latestModelRef,
    queueParentDialogFocus,
  ])

  useEffect(
    () => () => {
      cancelFolderSessionWork()
      cancelDeleteConfirmFocusRestore()
      deleteConfirmFocusOwnerRef.current = false
      deleteConfirmReturnFocusRef.current = null
    },
    [cancelDeleteConfirmFocusRestore, cancelFolderSessionWork],
  )

  useEffect(() => {
    const hostWindow = window as OverlayHostWindow
    if (!hostWindow.__HYDRA_LAZY_OVERLAY_HOST__) return
    // Run after the handler-installing effect above. Cancelling the first StrictMode setup timer prevents
    // a transient ready marker from escaping its immediate setup/cleanup rehearsal.
    const readyTimer = window.setTimeout(() => bridge.dashboardOverlayReady(), 0)
    return () => window.clearTimeout(readyTimer)
  }, [])

  useEffect(() => {
    if (modal?.kind !== 'newProject') return
    if (autoPickerKey.current === 'newProject') return
    autoPickerKey.current = 'newProject'
    bridge.pickProjectFolder().then((path) => {
      if (!path) return
      setProjectDraft((draft) => ({
        ...draft,
        root: path,
        name: draft.name.trim() ? draft.name : folderName(path),
        resume_session_id: null,
        resume_session_title: null,
        resume_session_file: null,
      }))
    })
  }, [modal])

  // Terminal panes/windows have no LLM history, so they never drive a folder-session lookup.
  const pickedAgent =
    modal?.kind === 'newProject'
      ? projectDraft.default_agent
      : modal?.kind === 'newWindow'
        ? windowDraft.agent
        : modal?.kind === 'split'
          ? agent
          : null
  const folderSessionAgent: RunnableAgentKind | null =
    supportsProviderHistory(pickedAgent) ? pickedAgent : null
  const folderSessionCwd =
    modal?.kind === 'newProject'
      ? projectDraft.root.trim()
      : modal?.kind === 'newWindow'
        ? windowDraft.root.trim()
        : modal?.kind === 'split'
          ? splitCwd?.trim() || splitWindowCwd?.trim() || detail?.root?.trim() || ''
          : ''
  const folderSessionKey =
    folderSessionAgent && folderSessionCwd ? `${folderSessionAgent}|${folderSessionCwd}` : ''
  const folderSessionModalKey =
    modal?.kind === 'split'
      ? `split|${modal.project_id}|${modal.window_id}|${modal.tab_id}|${modal.dir}`
      : modal?.kind === 'newWindow' || modal?.kind === 'editProject'
        ? `${modal.kind}|${modal.project_id}`
        : modal?.kind ?? ''

  useEffect(() => {
    folderSessionAbortRef.current?.abort()
    folderSessionAbortRef.current = null
    if (!folderSessionAgent || !folderSessionCwd) {
      setFolderSessions({ key: '', loading: false, sessions: [] })
      return
    }
    const key = `${folderSessionAgent}|${folderSessionCwd}`
    const controller = new AbortController()
    folderSessionAbortRef.current = controller
    let alive = true
    setFolderSessions({ key, loading: true, sessions: [] })
    // Reset the Removed view when the folder/agent changes so it never shows another folder's removals.
    setShowRemoved(false)
    setHiddenSessions([])
    bridge
      .listFolderSessions(folderSessionAgent, folderSessionCwd, controller.signal)
      .then((sessions) => {
        if (!alive || controller.signal.aborted) return
        setFolderSessions({ key, loading: false, sessions })
      })
      .catch(() => {
        if (!alive || controller.signal.aborted) return
        setFolderSessions({ key, loading: false, sessions: [] })
      })
    return () => {
      alive = false
      controller.abort()
      if (folderSessionAbortRef.current === controller) folderSessionAbortRef.current = null
    }
  }, [folderSessionAgent, folderSessionCwd, folderSessionModalKey])

  useEffect(() => {
    sessionPreviewAbortRef.current?.abort()
    sessionPreviewAbortRef.current = null
    hiddenSessionAbortRef.current?.abort()
    hiddenSessionAbortRef.current = null
    const restoreParentFocus = deleteConfirmFocusOwnerRef.current
    setPreviewState({ sessionId: null, loading: false, lines: null })
    setShowAllSessions(false)
    setEditingSessionId(null)
    setSessionNameDraft('')
    setDeleteConfirmSessionId(null)
    setDeleteConfirmAnchor(null)
    if (restoreParentFocus) queueParentDialogFocus(false)
    else deleteConfirmReturnFocusRef.current = null
  }, [folderSessionKey, folderSessionModalKey, queueParentDialogFocus])

  const closeDeleteConfirm = useCallback((): void => {
    setDeleteConfirmSessionId(null)
    setDeleteConfirmAnchor(null)
    queueParentDialogFocus(true)
  }, [queueParentDialogFocus])

  const confirmSessions = folderSessions.key === folderSessionKey ? folderSessions.sessions : []
  const deleteConfirmSession = deleteConfirmSessionId
    ? confirmSessions.find((session) => session.id === deleteConfirmSessionId) ??
      hiddenSessions.find((session) => session.id === deleteConfirmSessionId)
    : undefined
  const deleteConfirmActive = deleteConfirmSession !== undefined
  const syncParentDialogInert = useCallback(
    (node: HTMLElement | null): void => {
      parentDialogRef.current = node
      node?.toggleAttribute('inert', deleteConfirmActive)
    },
    [deleteConfirmActive],
  )

  useEffect(() => {
    if (!deleteConfirmSessionId || deleteConfirmActive) return
    // A concurrent list refresh can remove the target. Never leave the parent dialog hidden and
    // inert when no nested confirmation exists to own keyboard/accessibility focus.
    setDeleteConfirmSessionId(null)
    setDeleteConfirmAnchor(null)
    queueParentDialogFocus(false)
  }, [deleteConfirmActive, deleteConfirmSessionId, queueParentDialogFocus])

  if (!modal) return <div className="overlay-root" />

  // Default name for a split's new pane: "Pane N" where N is (current pane count + 1) in the split's window. The user
  // can override; keeping the default is fine (an empty field falls back to this).
  const splitDefaultPaneName =
    modal?.kind === 'split'
      ? `Pane ${((detail?.windows.find((w) => w.window_id === modal.window_id)?.tabs.length ?? 0) + 1)}`
      : 'Pane 1'

  const discoveredSessions =
    folderSessions.key === folderSessionKey ? folderSessions.sessions : []
  const sessionsLoading = folderSessions.key === folderSessionKey && folderSessions.loading
  const selectedResumeSessionId =
    modal.kind === 'split'
      ? sessionId
      : modal.kind === 'newProject' && projectDraft.resume_mode === 'resume'
        ? projectDraft.resume_session_id
        : modal.kind === 'newWindow' && windowDraft.session_mode === 'resume'
          ? windowDraft.resume_session_id
          : null
  const selectedResumeSession = selectedResumeSessionId
    ? discoveredSessions.find((session) => session.id === selectedResumeSessionId)
    : undefined
  // Render-time fingerprint of every launch-relevant draft plus the currently discovered identity
  // behind a selected resume id. A native check is asynchronous; removal, rename, or file replacement
  // must invalidate the click-time closure just like a visible form edit. Do not include transcript
  // activity counters/timestamps: background agent output is not a change of launch identity.
  launchPreflightDraftRef.current = JSON.stringify({
    modal,
    projectDraft,
    windowDraft,
    agent,
    splitModel,
    splitDangerous,
    sessionId,
    paneName,
    splitCwd,
    splitWindowCwd,
    selected_session_identity: selectedResumeSessionId
      ? selectedResumeSession
        ? {
            id: selectedResumeSession.id,
            agent: selectedResumeSession.agent,
            file_path: selectedResumeSession.file_path,
            title: selectedResumeSession.title,
            custom_name: selectedResumeSession.custom_name,
          }
        : { id: selectedResumeSessionId, missing: true }
      : null,
  })
  const activeProjectAgent = OVERLAY_AGENTS[projectDraft.default_agent]
  const resolvedProjectLaunch = resolveOverlayLaunchCommand(projectDraft)
  // WebKitGTK's native select popup can emit `input` without React observing the usual `change`
  // event. Snapshot the value synchronously and feed both events through one idempotent setter;
  // browser/macOS behavior stays on the standard change path while Linux cannot silently retain
  // the previous model.
  const selectSplitModel = (value: string): void => setSplitModel(value)
  const selectProjectDefaultModel = (value: string): void => {
    setProjectDraft((draft) => ({ ...draft, default_model: value }))
  }
  const selectWindowModel = (value: string): void => {
    setWindowDraft((draft) => ({ ...draft, model: value }))
  }
  const selectProjectMoreIcon = (value: string): void => {
    if (value) setProjectDraft((draft) => ({ ...draft, icon: value }))
  }
  const selectProjectEditMoreIcon = (value: string): void => {
    if (value) setProjectEditDraft((draft) => ({ ...draft, icon: value }))
  }
  const windowFolders =
    modal.kind === 'newWindow' || modal.kind === 'split'
      ? [
          ...(detail?.root ? [{ id: 'root', name: 'Project root', path: detail.root }] : []),
          ...(detail?.extra_folders ?? []),
        ]
      : []

  const close = (): void => {
    cancelFolderSessionWork()
    cancelDeleteConfirmFocusRestore()
    deleteConfirmFocusOwnerRef.current = false
    launchPreflightAttemptRef.current += 1
    launchPreflightPendingRef.current = false
    setLaunchPreflightPending(false)
    setLaunchPreflightError(null)
    setDeleteConfirmSessionId(null)
    setDeleteConfirmAnchor(null)
    deleteConfirmReturnFocusRef.current = null
    setModal(null)
    autoPickerKey.current = null
    bridge.closeOverlay()
  }

  const preflightThenMutate = async (
    input: { agent?: string; resolved_launch_command?: string; cwd?: string },
    mutate: () => void,
  ): Promise<void> => {
    const selectedAgent = input.agent?.trim().toLowerCase()
    // A project intentionally created without an initial session has nothing
    // to check. Terminal launches still reach native preflight so their cwd is
    // validated before durable topology is written.
    if (!input.resolved_launch_command?.trim() && !selectedAgent) {
      mutate()
      close()
      return
    }
    // React state does not update synchronously, so the ref is the actual
    // double-submit guard for two clicks in the same browser task.
    if (launchPreflightPendingRef.current) return
    launchPreflightPendingRef.current = true
    const attempt = ++launchPreflightAttemptRef.current
    const checkedDraft = launchPreflightDraftRef.current
    setLaunchPreflightPending(true)
    setLaunchPreflightError(null)
    try {
      const result = await bridge.preflightLaunch(input)
      // Cancel/reopen invalidates the in-flight submission. A late native
      // response must never create a window from a dialog that is gone.
      if (launchPreflightAttemptRef.current !== attempt) return
      if (!result.ok) {
        setLaunchPreflightError(boundedLaunchPreflightError(result.message))
        return
      }
      if (launchPreflightDraftRef.current !== checkedDraft) {
        setLaunchPreflightError('The launch settings changed while Hydra was checking them. Review and try again.')
        return
      }
      mutate()
      close()
    } catch {
      if (launchPreflightAttemptRef.current !== attempt) return
      setLaunchPreflightError(
        boundedLaunchPreflightError('Hydra could not verify that launch command. Try again.'),
      )
    } finally {
      if (launchPreflightAttemptRef.current === attempt) {
        launchPreflightPendingRef.current = false
        setLaunchPreflightPending(false)
      }
    }
  }

  const rejectStaleResumeSelection = (): void => {
    setLaunchPreflightError(
      'The selected session changed or is no longer available. Select it again and retry.',
    )
  }

  const revalidateResumeSession = (
    selectedId: string,
    selectedFile: string | null,
  ): AgentFolderSession | null => {
    const current = discoveredSessions.find((session) => session.id === selectedId)
    if (!current || current.file_path !== (selectedFile ?? '')) {
      rejectStaleResumeSelection()
      return null
    }
    return current
  }

  const submitSplit = async (): Promise<void> => {
    if (modal.kind !== 'split') return
    const selected = discoveredSessions.find((session) => session.id === sessionId)
    if (sessionId !== null && !selected) {
      rejectStaleResumeSelection()
      return
    }
    const splitDraft: OverlayWindowDraft = {
      name: '',
      root: folderSessionCwd,
      agent,
      model: splitModel,
      session_mode: selected ? 'resume' : 'none',
      dangerous_skip_permissions: splitDangerous,
      resume_session_id: selected?.id ?? null,
      resume_session_title: selected ? selected.custom_name || selected.title : null,
      resume_session_file: selected?.file_path ?? null,
      custom_command: '',
    }
    // Always send the picked agent. Terminal panes launch plain bash (no LLM command, no resume).
    const isTerminal = agent === 'terminal'
    const resolvedLaunchCommand = isTerminal ? undefined : resolveOverlayWindowLaunchCommand(splitDraft)
    await preflightThenMutate(
      {
        agent,
        resolved_launch_command: resolvedLaunchCommand,
        cwd: splitCwd?.trim() || splitWindowCwd?.trim() || folderSessionCwd.trim() || undefined,
      },
      () =>
        bridge.splitPane(modal.project_id, modal.window_id, modal.tab_id, modal.dir, {
          agent,
          resume_session_id: isTerminal ? null : selected?.id ?? null,
          resume_session_title: isTerminal ? null : selected ? selected.custom_name || selected.title : null,
          resume_session_file: isTerminal ? null : selected?.file_path ?? null,
          resolved_launch_command: resolvedLaunchCommand,
          pane_name: paneName.trim() || undefined,
          // null → omit cwd so the backend inherits the split source pane's folder; a chosen folder overrides.
          ...(splitCwd ? { cwd: splitCwd } : {}),
        }),
    )
  }

  const toggleSessionPreview = (session: AgentFolderSession): void => {
    if (!folderSessionAgent || !folderSessionCwd) return
    if (previewState.sessionId === session.id) {
      sessionPreviewAbortRef.current?.abort()
      sessionPreviewAbortRef.current = null
      setPreviewState({ sessionId: null, loading: false, lines: null })
      return
    }
    sessionPreviewAbortRef.current?.abort()
    const controller = new AbortController()
    sessionPreviewAbortRef.current = controller
    setPreviewState({ sessionId: session.id, loading: true, lines: null })
    bridge
      .previewFolderSession(folderSessionAgent, folderSessionCwd, session.id, controller.signal)
      .then((lines) => {
        if (controller.signal.aborted) return
        setPreviewState((current) => {
          if (current.sessionId !== session.id) return current
          return { sessionId: session.id, loading: false, lines }
        })
      })
      .catch(() => {
        if (controller.signal.aborted) return
        setPreviewState((current) => {
          if (current.sessionId !== session.id) return current
          return { sessionId: session.id, loading: false, lines: [] }
        })
      })
      .finally(() => {
        if (sessionPreviewAbortRef.current === controller) sessionPreviewAbortRef.current = null
      })
  }

  const startSessionRename = (session: AgentFolderSession): void => {
    if (launchPreflightPendingRef.current) return
    setEditingSessionId(session.id)
    setSessionNameDraft(session.custom_name ?? '')
  }

  const commitSessionRename = (session: AgentFolderSession): void => {
    if (launchPreflightPendingRef.current) return
    if (!folderSessionAgent || !folderSessionCwd) return
    const nextName = sessionNameDraft.trim()
    setEditingSessionId(null)
    setSessionNameDraft('')
    bridge
      .setFolderSessionName(folderSessionAgent, folderSessionCwd, session.id, nextName || null)
      .then((sessions) => {
        if (sessions.length === 0) return
        setFolderSessions({ key: folderSessionKey, loading: false, sessions })
      })
      .catch(() => {})
  }

  // REMOVE: hide the session from the list (non-destructive). DELETE: erase the file from disk after a
  // confirmation. Both refresh the listing on success. `deleteConfirmSession` drives the inline confirm.
  const refreshAfterMutation = (sessions: AgentFolderSession[]): void => {
    setFolderSessions({ key: folderSessionKey, loading: false, sessions })
  }
  const clearMissingResumeSelection = (
    session: AgentFolderSession,
    sessions: AgentFolderSession[],
  ): void => {
    if (sessions.some((candidate) => candidate.id === session.id)) return
    setSessionId((current) => (current === session.id ? null : current))
    setProjectDraft((draft) =>
      draft.resume_session_id === session.id
        ? {
            ...draft,
            resume_mode: 'none',
            resume_session_id: null,
            resume_session_title: null,
            resume_session_file: null,
          }
        : draft,
    )
    setWindowDraft((draft) =>
      draft.resume_session_id === session.id
        ? {
            ...draft,
            session_mode: 'none',
            resume_session_id: null,
            resume_session_title: null,
            resume_session_file: null,
          }
        : draft,
    )
  }
  const removeFolderSession = (session: AgentFolderSession): void => {
    if (launchPreflightPendingRef.current) return
    if (!folderSessionAgent || !folderSessionCwd) return
    if (previewState.sessionId === session.id)
      setPreviewState({ sessionId: null, loading: false, lines: null })
    bridge
      .removeFolderSession(folderSessionAgent, folderSessionCwd, session.id)
      .then((sessions) => {
        clearMissingResumeSelection(session, sessions)
        refreshAfterMutation(sessions)
      })
      .catch(() => {})
  }
  const confirmDeleteFolderSession = (session: AgentFolderSession): void => {
    if (launchPreflightPendingRef.current) return
    if (!folderSessionAgent || !folderSessionCwd) return
    setDeleteConfirmSessionId(null)
    setDeleteConfirmAnchor(null)
    queueParentDialogFocus(false)
    if (previewState.sessionId === session.id)
      setPreviewState({ sessionId: null, loading: false, lines: null })
    bridge
      .deleteFolderSession(folderSessionAgent, folderSessionCwd, session.id)
      .then((sessions) => {
        setHiddenSessions((current) => current.filter((candidate) => candidate.id !== session.id))
        clearMissingResumeSelection(session, sessions)
        refreshAfterMutation(sessions)
      })
      .catch(() => {})
  }

  // Open the delete confirm anchored to the right edge of the picker popup, vertically aligned with the
  // clicked session row. `e` is the 🗑 button's click; we read its row and the enclosing dialog.
  const openDeleteConfirm = (
    e: React.MouseEvent<HTMLButtonElement>,
    sessionId: string,
  ): void => {
    if (launchPreflightPendingRef.current) return
    cancelDeleteConfirmFocusRestore()
    deleteConfirmFocusOwnerRef.current = true
    const row = (e.currentTarget as HTMLElement).closest(
      '.split-session, .session-picker__opt',
    ) as HTMLElement | null
    const dialog = (e.currentTarget as HTMLElement).closest('.split-dialog') as HTMLElement | null
    if (row && dialog) {
      const rr = row.getBoundingClientRect()
      const dr = dialog.getBoundingClientRect()
      setDeleteConfirmAnchor({ top: rr.top, left: dr.right + 10 })
    } else {
      setDeleteConfirmAnchor(null)
    }
    deleteConfirmReturnFocusRef.current = e.currentTarget
    setDeleteConfirmSessionId(sessionId)
  }

  // Toggle the "Removed" view; load the hidden sessions for this folder when opening it.
  const toggleShowRemoved = (): void => {
    const next = !showRemoved
    setShowRemoved(next)
    hiddenSessionAbortRef.current?.abort()
    hiddenSessionAbortRef.current = null
    if (next && folderSessionAgent && folderSessionCwd) {
      const controller = new AbortController()
      hiddenSessionAbortRef.current = controller
      bridge
        .listHiddenFolderSessions(folderSessionAgent, folderSessionCwd, controller.signal)
        .then((sessions) => {
          if (controller.signal.aborted) return
          setHiddenSessions(sessions)
        })
        .catch(() => {
          if (controller.signal.aborted) return
          setHiddenSessions([])
        })
        .finally(() => {
          if (hiddenSessionAbortRef.current === controller) hiddenSessionAbortRef.current = null
        })
    }
  }
  // Rename a session in the REMOVED view: the rename API returns the visible list (which won't contain a
  // hidden session), so update the hidden row optimistically instead.
  const commitHiddenSessionRename = (session: AgentFolderSession): void => {
    if (launchPreflightPendingRef.current) return
    if (!folderSessionAgent || !folderSessionCwd) return
    const nextName = sessionNameDraft.trim()
    setEditingSessionId(null)
    setSessionNameDraft('')
    setHiddenSessions((current) =>
      current.map((s) => (s.id === session.id ? { ...s, custom_name: nextName || null } : s)),
    )
    bridge
      .setFolderSessionName(folderSessionAgent, folderSessionCwd, session.id, nextName || null)
      .catch(() => {})
  }

  // Add a removed session back: it returns to the visible list and drops out of the removed view.
  const addBackFolderSession = (session: AgentFolderSession): void => {
    if (launchPreflightPendingRef.current) return
    if (!folderSessionAgent || !folderSessionCwd) return
    setHiddenSessions((current) => current.filter((s) => s.id !== session.id))
    bridge
      .unhideFolderSession(folderSessionAgent, folderSessionCwd, session.id)
      .then((sessions) => {
        if (sessions.length > 0)
          setFolderSessions({ key: folderSessionKey, loading: false, sessions })
      })
      .catch(() => {})
  }

  const visibleFolderSessions = (initialLimit: number): AgentFolderSession[] =>
    showAllSessions ? discoveredSessions : discoveredSessions.slice(0, initialLimit)

  const renderSessionExpansion = (initialLimit: number): JSX.Element | null => {
    if (discoveredSessions.length <= initialLimit) return null
    return (
      <button
        type="button"
        className="session-removed__toggle"
        aria-expanded={showAllSessions}
        onClick={() => setShowAllSessions((current) => !current)}
      >
        {showAllSessions ? 'Show fewer sessions' : `Show all ${discoveredSessions.length} sessions`}
      </button>
    )
  }

  // The "Removed (N)" toggle + the list of hidden sessions (each with Add back / Delete), rendered under
  // the visible session list in every picker so a user can recover anything they removed.
  const renderRemovedSection = (): JSX.Element | null => {
    if (!folderSessionAgent || !folderSessionCwd) return null
    return (
      <div className="session-removed">
        <button type="button" className="session-removed__toggle" onClick={toggleShowRemoved}>
          {showRemoved ? '▾' : '▸'} Removed sessions
          {showRemoved && ` (${hiddenSessions.length})`}
        </button>
        {showRemoved && (
          <div className="session-removed__list">
            {hiddenSessions.length === 0 ? (
              <div className="session-picker__empty">No removed sessions in this folder.</div>
            ) : (
              hiddenSessions.map((session) => (
                <div key={session.id} className="session-removed__row">
                  {editingSessionId === session.id ? (
                    <input
                      className="session-picker__rename"
                      autoFocus
                      disabled={launchPreflightPending}
                      value={sessionNameDraft}
                      placeholder="Name this session..."
                      onChange={(event) => setSessionNameDraft(event.target.value)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') commitHiddenSessionRename(session)
                        if (event.key === 'Escape') {
                          event.preventDefault()
                          event.stopPropagation()
                          setEditingSessionId(null)
                          setSessionNameDraft('')
                        }
                      }}
                      onBlur={() => commitHiddenSessionRename(session)}
                    />
                  ) : (
                    <div className="session-picker__pick">
                      <div className="session-picker__title">
                        {session.custom_name ? (
                          <span className="session-picker__named">{session.custom_name}</span>
                        ) : (
                          session.title
                        )}
                      </div>
                      <div className="session-picker__hint">
                        {relTime(session.modified_at_ms)} ·{' '}
                        {typeof session.message_count === 'number' && (
                          <>{session.message_count} events · </>
                        )}
                        <code>{session.id.slice(0, 8)}</code>
                      </div>
                    </div>
                  )}
                  <div className="session-removed__acts">
                    <button
                      type="button"
                      className={`session-picker__act ${previewState.sessionId === session.id ? 'is-on' : ''}`}
                      title="Preview this session"
                      onClick={() => toggleSessionPreview(session)}
                    >
                      👁
                    </button>
                    <button
                      type="button"
                      className="session-picker__act"
                      title="Name this session"
                      disabled={launchPreflightPending}
                      onClick={() => startSessionRename(session)}
                    >
                      ✎
                    </button>
                    <button
                      type="button"
                      className="session-removed__addback"
                      title="Add this session back to the list"
                      disabled={launchPreflightPending}
                      onClick={() => addBackFolderSession(session)}
                    >
                      ＋ Add back
                    </button>
                    {supportsPermanentHistoryDelete(session.agent, session.in_use) && (
                      <button
                        type="button"
                        className="session-picker__act session-picker__act--danger"
                        title="Delete the session file from your computer"
                        disabled={launchPreflightPending}
                        onClick={(event) => openDeleteConfirm(event, session.id)}
                      >
                        🗑
                      </button>
                    )}
                  </div>
                  {previewState.sessionId === session.id && (
                    <div className="session-picker__rowpreview">
                      {previewState.loading && (
                        <div className="session-preview__loading">Loading preview...</div>
                      )}
                      {!previewState.loading && previewState.lines?.length === 0 && (
                        <div className="session-preview__empty">No readable transcript to preview.</div>
                      )}
                      {previewState.lines?.map((line, index) => (
                        <div key={`${line.role}-${index}`} className={`session-preview__line is-${line.role}`}>
                          <span className="session-preview__role">{line.role}</span>
                          <span className="session-preview__text">{line.text}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    )
  }

  // The per-session action buttons (preview / rename / remove / delete), shared across every session
  // picker. Delete asks for confirmation inline; remove is immediate and non-destructive.
  const renderSessionActions = (session: AgentFolderSession): JSX.Element => {
    return (
      <div className="session-picker__actions">
        <button
          type="button"
          className={`session-picker__act ${previewState.sessionId === session.id ? 'is-on' : ''}`}
          title="Preview this session"
          onClick={() => toggleSessionPreview(session)}
        >
          👁
        </button>
        <button
          type="button"
          className="session-picker__act"
          title="Name this session"
          disabled={launchPreflightPending}
          onClick={() => startSessionRename(session)}
        >
          ✎
        </button>
        <button
          type="button"
          className="session-picker__act session-picker__act--remove"
          title="Remove from list (keeps the file; won't show in future)"
          disabled={launchPreflightPending}
          onClick={() => removeFolderSession(session)}
        >
          ⊘
        </button>
        {supportsPermanentHistoryDelete(session.agent, session.in_use) && (
          <button
            type="button"
            className="session-picker__act session-picker__act--danger"
            title="Delete the session file from your computer"
            disabled={launchPreflightPending}
            onClick={(e) => openDeleteConfirm(e, session.id)}
          >
            🗑
          </button>
        )}
      </div>
    )
  }

  const chooseProjectRoot = async (): Promise<void> => {
    const path = await bridge.pickProjectFolder()
    if (!path) return
    setProjectDraft((draft) => ({
      ...draft,
      root: path,
      name: draft.name.trim() ? draft.name : folderName(path),
      resume_session_id: null,
      resume_session_title: null,
      resume_session_file: null,
    }))
  }

  const addProjectFolder = async (): Promise<void> => {
    const path = await bridge.pickProjectFolder()
    if (!path) return
    setProjectDraft((draft) => ({
      ...draft,
      extra_folders: [
        ...draft.extra_folders,
        {
          id: `folder-${Date.now()}`,
          name: folderName(path),
          path,
        },
      ],
    }))
  }

  const submitProject = async (): Promise<void> => {
    if (!projectDraft.name.trim() || !projectDraft.root.trim()) return
    const currentResumeSession =
      projectDraft.create_initial_session &&
      projectDraft.default_agent !== 'terminal' &&
      projectDraft.resume_mode === 'resume' &&
      projectDraft.resume_session_id
        ? revalidateResumeSession(
            projectDraft.resume_session_id,
            projectDraft.resume_session_file,
          )
        : undefined
    if (currentResumeSession === null) return
    const isTerminalProject = projectDraft.default_agent === 'terminal'
    const resolvedProjectCommand = isTerminalProject ? undefined : resolvedProjectLaunch
    const input = {
      name: projectDraft.name.trim(),
      root: projectDraft.root.trim(),
      icon: projectDraft.icon,
      accent_color: projectDraft.accent_color,
      default_agent: projectDraft.default_agent,
      default_model: isTerminalProject ? 'default' : projectDraft.default_model.trim() || 'default',
      resume_mode: isTerminalProject ? 'none' : projectDraft.resume_mode,
      resume_session_id: isTerminalProject
        ? null
        : currentResumeSession?.id ?? projectDraft.resume_session_id,
      resume_session_title: isTerminalProject
        ? null
        : currentResumeSession
          ? currentResumeSession.custom_name || currentResumeSession.title
          : projectDraft.resume_session_title,
      resume_session_file: isTerminalProject
        ? null
        : currentResumeSession?.file_path ?? projectDraft.resume_session_file,
      dangerous_skip_permissions: isTerminalProject
        ? false
        : projectDraft.dangerous_skip_permissions,
      custom_command: isTerminalProject ? null : projectDraft.custom_command.trim() || null,
      resolved_launch_command: resolvedProjectCommand,
      extra_folders: projectDraft.extra_folders
        .filter((folder) => folder.path.trim())
        .map((folder) => ({
          id: folder.id,
          name: folder.name.trim() || folderName(folder.path),
          path: folder.path.trim(),
        })),
      create_initial_session: projectDraft.create_initial_session,
    }
    await preflightThenMutate(
      {
        agent: projectDraft.create_initial_session ? projectDraft.default_agent : undefined,
        resolved_launch_command:
          projectDraft.create_initial_session && projectDraft.default_agent !== 'terminal'
            ? resolvedProjectCommand
            : undefined,
        cwd: projectDraft.root.trim(),
      },
      () => bridge.createProject(input),
    )
  }

  const chooseEditProjectRoot = async (): Promise<void> => {
    const path = await bridge.pickProjectFolder()
    if (!path) return
    setProjectEditDraft((draft) => ({
      ...draft,
      root: path,
      name: draft.name.trim() ? draft.name : folderName(path),
    }))
  }

  const submitProjectEdit = (): void => {
    if (modal.kind !== 'editProject') return
    const name = projectEditDraft.name.trim()
    const root = projectEditDraft.root.trim()
    if (!projectEditDraft.project_id || !name || !root) return
    bridge.updateProject({
      project_id: projectEditDraft.project_id,
      name,
      root,
      icon: projectEditDraft.icon,
      accent_color: projectEditDraft.accent_color,
    })
    close()
  }

  const chooseWindowRoot = async (): Promise<void> => {
    const path = await bridge.pickProjectFolder()
    if (!path) return
    setWindowDraft((draft) => ({
      ...draft,
      root: path,
      name: draft.name.trim() ? draft.name : folderName(path),
      session_mode: 'none',
      resume_session_id: null,
      resume_session_title: null,
      resume_session_file: null,
    }))
  }

  const submitWindow = async (): Promise<void> => {
    if (modal.kind !== 'newWindow') return
    // Terminal windows launch plain bash: keep the name + root, drop agent chrome (no model/session/command).
    const isTerminal = windowDraft.agent === 'terminal'
    const currentResumeSession =
      !isTerminal && windowDraft.session_mode === 'resume' && windowDraft.resume_session_id
        ? revalidateResumeSession(windowDraft.resume_session_id, windowDraft.resume_session_file)
        : undefined
    if (currentResumeSession === null) return
    const options = {
      name: windowDraft.name.trim() || undefined,
      root: windowDraft.root.trim() || undefined,
      agent: windowDraft.agent,
      model: isTerminal ? 'default' : windowDraft.model.trim() || 'default',
      session_mode: isTerminal ? 'none' : windowDraft.session_mode,
      resume_session_id: isTerminal
        ? null
        : currentResumeSession?.id ?? windowDraft.resume_session_id,
      resume_session_title: isTerminal
        ? null
        : currentResumeSession
          ? currentResumeSession.custom_name || currentResumeSession.title
          : windowDraft.resume_session_title,
      resume_session_file: isTerminal
        ? null
        : currentResumeSession?.file_path ?? windowDraft.resume_session_file,
      resolved_launch_command: isTerminal ? undefined : resolveOverlayWindowLaunchCommand(windowDraft),
    }
    await preflightThenMutate(
      {
        agent: windowDraft.agent,
        resolved_launch_command: options.resolved_launch_command,
        cwd: windowDraft.root.trim() || undefined,
      },
      () => bridge.createWindow(modal.project_id, options),
    )
  }

  return (
    <div
      className="overlay-root overlay-root--active"
      onClick={(event) => {
        if (event.target !== event.currentTarget) return
        // Close only after the complete backdrop click. On Linux the overlay and sidebar are
        // separate native WebViews; hiding the overlay on mouse-down lets the matching release
        // land on the sidebar underneath and activate a different workspace/session.
        if (deleteConfirmSessionId) closeDeleteConfirm()
        else close()
      }}
    >
      {modal.kind === 'split' && (
        <section
          className="split-dialog"
          role="dialog"
          aria-modal="true"
          aria-label={modal.dir === 'h' ? 'Split right' : 'Split down'}
          aria-hidden={deleteConfirmActive ? 'true' : undefined}
          ref={syncParentDialogInert}
          onKeyDown={(event) => containDialogKeyboard(event, close)}
          onMouseDown={(e) => e.stopPropagation()}
        >
          <div className="split-dialog__head">
            <div>
              <h2>{modal.dir === 'h' ? 'Split right' : 'Split down'}</h2>
              <p>{detail?.root ?? project?.name ?? modal.project_id}</p>
            </div>
          </div>
          {/* Pane name — shown for ALL projects. Defaults to "Pane N"; user can override. */}
          <div className="split-dialog__section">
            <div className="split-dialog__label">Pane name</div>
            <input
              className="overlay-input"
              aria-label="Pane name"
              autoFocus
              value={paneName}
              placeholder={splitDefaultPaneName}
              onChange={(e) => setPaneName(e.target.value)}
            />
          </div>
          {/* Working directory — the split source WINDOW's folder is the default-selected button. If that folder is a
              project folder (root/pinned) it's just pre-selected; if not, it's shown as its own "Window folder" button
              so it never duplicates. "Other folder…" (native picker) overrides. Mirrors the New Window dialog. */}
          <div className="split-dialog__section">
            <div className="split-dialog__label">Working directory</div>
            <div className="folder-pick">
              {/* The window's own folder, ONLY when it isn't already one of the project folders below (no duplicate). */}
              {splitWindowCwd && !windowFolders.some((f) => f.path === splitWindowCwd) && (
                <button
                  type="button"
                  className={`folder-pick__opt ${splitCwd === splitWindowCwd ? 'is-active' : ''}`}
                  onClick={() => setSplitCwd(splitWindowCwd)}
                >
                  <span className="folder-pick__name">Window folder</span>
                  <span className="folder-pick__path">{splitWindowCwd}</span>
                </button>
              )}
              {windowFolders.map((folder) => (
                <button
                  key={folder.id}
                  type="button"
                  className={`folder-pick__opt ${splitCwd === folder.path ? 'is-active' : ''}`}
                  onClick={() => setSplitCwd(folder.path)}
                >
                  <span className="folder-pick__name">{folder.name}</span>
                  <span className="folder-pick__path">{folder.path}</span>
                </button>
              ))}
              <button
                type="button"
                className={`folder-pick__opt folder-pick__opt--other ${
                  splitCwd !== null &&
                  splitCwd !== splitWindowCwd &&
                  !windowFolders.some((f) => f.path === splitCwd)
                    ? 'is-active'
                    : ''
                }`}
                onClick={async () => {
                  const path = await bridge.pickProjectFolder()
                  if (path) setSplitCwd(path)
                }}
              >
                <span className="folder-pick__name">
                  {splitCwd !== null && splitCwd !== splitWindowCwd && !windowFolders.some((f) => f.path === splitCwd)
                    ? splitCwd
                    : 'Other folder…'}
                </span>
                <span className="folder-pick__path">
                  {splitCwd !== null && splitCwd !== splitWindowCwd && !windowFolders.some((f) => f.path === splitCwd)
                    ? '(custom)'
                    : 'pick from filesystem'}
                </span>
              </button>
            </div>
          </div>
          <div className="split-dialog__section">
            <div className="split-dialog__label">Agent</div>
            {/* Dropdown-with-icon (converged with New Project + remote), not three buttons. */}
            <div className="overlay-agent-row">
              <AgentBadge agent={agent === 'terminal' ? 'shell' : agent} size={13} />
              <select
                className="overlay-select"
                aria-label="Split agent"
                value={agent}
                onChange={(e) => {
                  setAgent(e.target.value as OverlayAgent)
                  setSplitModel('default')
                  setSessionId(null)
                }}
              >
                {isLegacyAgentKind(agent) && (
                  <option value={agent} disabled>Gemini (legacy)</option>
                )}
                {OVERLAY_AGENT_OPTIONS.map((candidate) => (
                  <option key={candidate} value={candidate}>
                    {OVERLAY_AGENTS[candidate].label}
                  </option>
                ))}
              </select>
            </div>
            {agent !== 'terminal' && (<>
            <div className="overlay-sublabel overlay-sublabel--spaced">Model</div>
            <ModelSelector
              ariaLabel="Split model"
              agent={agent}
              catalog={model.model_catalog}
              value={splitModel}
              onValue={selectSplitModel}
            />
            <label className="overlay-check">
              <input
                type="checkbox"
                aria-label="Split dangerous mode"
                checked={splitDangerous}
                onChange={(e) => setSplitDangerous(e.target.checked)}
              />
              <code>{OVERLAY_AGENTS[agent].dangerousFlag}</code>
            </label>
            </>)}
          </div>
          {agent !== 'terminal' && (
          <div className="split-dialog__section">
            <div className="split-dialog__label">{agent} session</div>
            <button
              type="button"
              className={`split-session ${sessionId === null ? 'is-active' : ''}`}
              onClick={() => setSessionId(null)}
            >
              <strong>+ New session</strong>
              <span>Start fresh in {agent}</span>
            </button>
            {supportsProviderHistory(agent) && (<>
            {sessionsLoading && (
              <div className="session-picker__empty">Scanning folder sessions...</div>
            )}
            {!sessionsLoading && discoveredSessions.length === 0 && (
              <div className="session-picker__empty">No past {agent} sessions in this folder.</div>
            )}
            {visibleFolderSessions(5).map((session) => (
              <div
                key={session.id}
                className={`split-session split-session--row ${sessionId === session.id ? 'is-active' : ''}`}
              >
                {editingSessionId === session.id ? (
                  <input
                    className="session-picker__rename"
                    autoFocus
                    disabled={launchPreflightPending}
                    value={sessionNameDraft}
                    placeholder="Name this session..."
                    onChange={(event) => setSessionNameDraft(event.target.value)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter') commitSessionRename(session)
                      if (event.key === 'Escape') {
                        event.preventDefault()
                        event.stopPropagation()
                        setEditingSessionId(null)
                        setSessionNameDraft('')
                      }
                    }}
                    onBlur={() => commitSessionRename(session)}
                  />
                ) : (
                  <button
                    type="button"
                    className="split-session__main"
                    onClick={() => setSessionId(session.id)}
                  >
                    <strong>{session.custom_name || session.title}</strong>
                    <span>
                      {session.custom_name && `${session.title} · `}
                      #{session.folder_index} · {relTime(session.modified_at_ms)}
                      {session.in_use && ' · open in pane'}
                      {!session.in_use && typeof session.message_count === 'number' &&
                        ` · ${session.message_count} events`}
                    </span>
                  </button>
                )}
                {renderSessionActions(session)}
                {previewState.sessionId === session.id && (
                  <div className="session-picker__rowpreview">
                    {previewState.loading && (
                      <div className="session-preview__loading">Loading preview...</div>
                    )}
                    {!previewState.loading && previewState.lines?.length === 0 && (
                      <div className="session-preview__empty">No readable transcript to preview.</div>
                    )}
                    {previewState.lines?.map((line, index) => (
                      <div key={`${line.role}-${index}`} className={`session-preview__line is-${line.role}`}>
                        <span className="session-preview__role">{line.role}</span>
                        <span className="session-preview__text">{line.text}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
            {renderSessionExpansion(5)}
            {renderRemovedSection()}
            </>)}
          </div>
          )}
          <div className="split-dialog__footer">
            {launchPreflightError && (
              <div className="overlay-preflight-error" role="alert">
                {launchPreflightError}
              </div>
            )}
            <button type="button" className="split-dialog__cancel" onClick={close}>
              Cancel
            </button>
            <button
              type="button"
              className="split-dialog__submit"
              disabled={launchPreflightPending}
              onClick={() => void submitSplit()}
            >
              {launchPreflightPending ? 'Checking...' : 'Split'}
            </button>
          </div>
        </section>
      )}

      {modal.kind === 'newProject' && (
        <section
          className="split-dialog overlay-dialog--wide"
          role="dialog"
          aria-modal="true"
          aria-label="New project"
          aria-hidden={deleteConfirmActive ? 'true' : undefined}
          ref={syncParentDialogInert}
          onKeyDown={(event) => containDialogKeyboard(event, close)}
          onMouseDown={(e) => e.stopPropagation()}
        >
          <div className="split-dialog__head">
            <div>
              <h2>New project</h2>
            </div>
          </div>
          <div className="split-dialog__section">
            <label className="overlay-field">
              <span>Name</span>
              <input
                value={projectDraft.name}
                autoFocus
                placeholder="Capacity Paper"
                onChange={(e) => setProjectDraft((draft) => ({ ...draft, name: e.target.value }))}
              />
            </label>
            <label className="overlay-field">
              <span>Working directory</span>
              <div className="overlay-path-row">
                <input
                  value={projectDraft.root}
                  placeholder="~/path/to/project"
                  onChange={(e) =>
                    setProjectDraft((draft) => ({
                      ...draft,
                      root: e.target.value,
                      resume_session_id: null,
                      resume_session_title: null,
                      resume_session_file: null,
                    }))
                  }
                />
                <button type="button" onClick={() => void chooseProjectRoot()}>
                  Choose...
                </button>
              </div>
            </label>
            <div className="overlay-folder-list">
              <div className="split-dialog__label">Additional folders</div>
              {projectDraft.extra_folders.map((folder) => (
                <div className="overlay-dir-row" key={folder.id}>
                  <input
                    value={folder.name}
                    placeholder="Folder name"
                    onChange={(e) =>
                      setProjectDraft((draft) => ({
                        ...draft,
                        extra_folders: draft.extra_folders.map((item) =>
                          item.id === folder.id ? { ...item, name: e.target.value } : item,
                        ),
                      }))
                    }
                  />
                  <input
                    value={folder.path}
                    placeholder="/path/to/folder"
                    onChange={(e) =>
                      setProjectDraft((draft) => ({
                        ...draft,
                        extra_folders: draft.extra_folders.map((item) =>
                          item.id === folder.id ? { ...item, path: e.target.value } : item,
                        ),
                      }))
                    }
                  />
                  <button
                    type="button"
                    aria-label="Remove folder"
                    onClick={() =>
                      setProjectDraft((draft) => ({
                        ...draft,
                        extra_folders: draft.extra_folders.filter((item) => item.id !== folder.id),
                      }))
                    }
                  >
                    x
                  </button>
                </div>
              ))}
              <button type="button" className="overlay-secondary-action" onClick={() => void addProjectFolder()}>
                + Add folder
              </button>
              <span className="overlay-hint">Saved folders become quick choices for windows.</span>
            </div>
          </div>
          <div className="split-dialog__section">
            <div className="split-dialog__label">Default launch</div>
            <div className="overlay-launch-grid">
              <div className="overlay-launch-grid__col">
                <div className="overlay-sublabel">Agent</div>
                {/* Dropdown-with-icon: a live AgentBadge sits next to a compact select whose options carry
                    each agent's glyph. */}
                <div className="overlay-agent-row">
                  <AgentBadge agent={projectDraft.default_agent === 'terminal' ? 'shell' : projectDraft.default_agent} size={13} />
                  <select
                    className="overlay-select"
                    aria-label="Default agent"
                    value={projectDraft.default_agent}
                    onChange={(e) => {
                      const nextAgent = e.target.value as OverlayAgent
                      setProjectDraft((draft) => ({
                        ...draft,
                        default_agent: nextAgent,
                        default_model: 'default',
                        ...(defaultsFreshWithoutProviderHistory(nextAgent)
                          ? { resume_mode: 'none' as const }
                          : {}),
                        resume_session_id: null,
                        resume_session_title: null,
                        resume_session_file: null,
                      }))
                    }}
                  >
                    {isLegacyAgentKind(projectDraft.default_agent) && (
                      <option value={projectDraft.default_agent} disabled>Gemini (legacy)</option>
                    )}
                    {OVERLAY_AGENT_OPTIONS.map((candidate) => (
                      <option key={candidate} value={candidate}>
                        {OVERLAY_AGENTS[candidate].label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              {projectDraft.default_agent !== 'terminal' && (
              <div className="overlay-launch-grid__col overlay-launch-grid__model">
                <div className="overlay-sublabel">Model</div>
                <ModelSelector
                  ariaLabel="Default model"
                  agent={projectDraft.default_agent}
                  catalog={model.model_catalog}
                  value={projectDraft.default_model}
                  onValue={selectProjectDefaultModel}
                />
              </div>
              )}
            </div>
            {projectDraft.default_agent !== 'terminal' && (<>
            <div className="overlay-sublabel overlay-sublabel--spaced">Resume mode</div>
            <div className="overlay-pills">
              {resumeModeOptionsForAgent(projectDraft.default_agent).map(([mode, label]) => (
                <button
                  key={mode}
                  type="button"
                  className={`overlay-pill ${projectDraft.resume_mode === mode ? 'is-active' : ''}`}
                  onClick={() =>
                    setProjectDraft((draft) => ({
                      ...draft,
                      resume_mode: mode as OverlayResumeMode,
                      ...(mode === 'resume'
                        ? {}
                        : {
                            resume_session_id: null,
                            resume_session_title: null,
                            resume_session_file: null,
                          }),
                    }))
                  }
                >
                  {label}
                </button>
              ))}
            </div>
            {supportsProviderHistory(projectDraft.default_agent) && (
            <div className="session-picker session-picker--compact session-picker--panel">
              {sessionsLoading && (
                <div className="session-picker__empty">Scanning {projectDraft.default_agent} history...</div>
              )}
              {!sessionsLoading && projectDraft.root.trim() && discoveredSessions.length === 0 && (
                <div className="session-picker__empty">
                  No past {OVERLAY_AGENTS[projectDraft.default_agent].label} sessions in this folder yet.
                </div>
              )}
              {!projectDraft.root.trim() && (
                <div className="session-picker__empty">Choose a working directory to list past sessions.</div>
              )}
              {visibleFolderSessions(6).map((session) => (
                <div
                  key={session.id}
                  className={`session-picker__opt session-picker__row ${
                    projectDraft.resume_session_id === session.id ? 'is-active' : ''
                  } ${session.in_use ? 'is-open' : ''}`}
                >
                  {editingSessionId === session.id ? (
                    <input
                      className="session-picker__rename"
                      autoFocus
                      disabled={launchPreflightPending}
                      value={sessionNameDraft}
                      placeholder="Name this session..."
                      onChange={(event) => setSessionNameDraft(event.target.value)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') commitSessionRename(session)
                        if (event.key === 'Escape') {
                          event.preventDefault()
                          event.stopPropagation()
                          setEditingSessionId(null)
                          setSessionNameDraft('')
                        }
                      }}
                      onBlur={() => commitSessionRename(session)}
                    />
                  ) : (
                    <button
                      type="button"
                      className="session-picker__rowmain"
                      onClick={() =>
                        setProjectDraft((draft) => ({
                          ...draft,
                          resume_mode: 'resume',
                          resume_session_id: session.id,
                          resume_session_title: session.custom_name || session.title,
                          resume_session_file: session.file_path,
                          name: draft.name.trim() ? draft.name : folderName(draft.root),
                        }))
                      }
                    >
                      <div className="session-picker__pick">
                        <div className="session-picker__title">
                          <span className="session-picker__num">#{session.folder_index}</span>
                          {session.custom_name ? (
                            <span className="session-picker__named">{session.custom_name}</span>
                          ) : (
                            session.title
                          )}
                        </div>
                        <div className="session-picker__hint">
                          {session.custom_name && `${session.title} · `}
                          {session.in_use && <span className="session-picker__inuse">open in pane</span>}
                          {session.in_use && ' · '}
                          {relTime(session.modified_at_ms)} ·{' '}
                          {typeof session.message_count === 'number' && (
                            <>{session.message_count} events · </>
                          )}
                          <code>{session.id.slice(0, 8)}</code>
                        </div>
                      </div>
                    </button>
                  )}
                  {renderSessionActions(session)}
                  {previewState.sessionId === session.id && (
                    <div className="session-picker__rowpreview">
                      {previewState.loading && (
                        <div className="session-preview__loading">Loading preview...</div>
                      )}
                      {!previewState.loading && previewState.lines?.length === 0 && (
                        <div className="session-preview__empty">No readable transcript to preview.</div>
                      )}
                      {previewState.lines?.map((line, index) => (
                        <div key={`${line.role}-${index}`} className={`session-preview__line is-${line.role}`}>
                          <span className="session-preview__role">{line.role}</span>
                          <span className="session-preview__text">{line.text}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              {renderSessionExpansion(6)}
              {renderRemovedSection()}
            </div>
            )}
            <div className="overlay-launch-options">
              <label className="overlay-check">
                <input
                  type="checkbox"
                  checked={projectDraft.dangerous_skip_permissions}
                  onChange={(e) =>
                    setProjectDraft((draft) => ({
                      ...draft,
                      dangerous_skip_permissions: e.target.checked,
                    }))
                  }
                />
                <code>{activeProjectAgent.dangerousFlag}</code>
              </label>
              <input
                className="overlay-input"
                value={projectDraft.custom_command}
                placeholder="Custom command (overrides above) -- e.g. claude mcp ..."
                onChange={(e) =>
                  setProjectDraft((draft) => ({ ...draft, custom_command: e.target.value }))
                }
              />
              <div className="overlay-launch-preview">
                <span>Resolves to</span>
                <code>{resolvedProjectLaunch}</code>
              </div>
            </div>
            </>)}
          </div>
          <div className="split-dialog__section">
            <div className="split-dialog__label">Icon</div>
            <div className="overlay-icon-grid">
              {OVERLAY_ICON_OPTIONS.map((icon) => (
                <button
                  key={icon}
                  type="button"
                  className={`overlay-icon ${projectDraft.icon === icon ? 'is-active' : ''}`}
                  onClick={() => setProjectDraft((draft) => ({ ...draft, icon }))}
                >
                  {icon}
                </button>
              ))}
              <select
                className="overlay-icon-more"
                aria-label="More project icons"
                value={OVERLAY_ICON_OPTIONS.includes(projectDraft.icon) ? '' : projectDraft.icon}
                onInput={(e) => selectProjectMoreIcon(e.currentTarget.value)}
                onChange={(e) => selectProjectMoreIcon(e.currentTarget.value)}
              >
                <option value="">More...</option>
                {OVERLAY_MORE_ICONS.map((icon) => (
                  <option key={icon} value={icon}>
                    {icon}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="split-dialog__section">
            <div className="split-dialog__label">Color</div>
            <div className="overlay-color-grid">
              {OVERLAY_COLOR_OPTIONS.map((color) => (
                <button
                  key={color}
                  type="button"
                  className={`overlay-color ${projectDraft.accent_color === color ? 'is-active' : ''}`}
                  style={{ backgroundColor: color }}
                  aria-label={color}
                  onClick={() => setProjectDraft((draft) => ({ ...draft, accent_color: color }))}
                />
              ))}
            </div>
          </div>
          <div className="split-dialog__footer">
            {launchPreflightError && (
              <div className="overlay-preflight-error" role="alert">
                {launchPreflightError}
              </div>
            )}
            <button type="button" className="split-dialog__cancel" onClick={close}>
              Cancel
            </button>
            <button
              type="button"
              className="split-dialog__submit"
              disabled={
                launchPreflightPending || !projectDraft.name.trim() || !projectDraft.root.trim()
              }
              onClick={() => void submitProject()}
            >
              {launchPreflightPending ? 'Checking...' : 'Create'}
            </button>
          </div>
        </section>
      )}

      {modal.kind === 'editProject' && (
        <section
          className="split-dialog overlay-dialog--narrow"
          role="dialog"
          aria-modal="true"
          aria-label="Edit project"
          aria-hidden={deleteConfirmActive ? 'true' : undefined}
          ref={syncParentDialogInert}
          onKeyDown={(event) => containDialogKeyboard(event, close)}
          onMouseDown={(e) => e.stopPropagation()}
        >
          <div className="split-dialog__head">
            <div>
              <h2>Edit project</h2>
              <p>{project?.name ?? modal.project_id}</p>
            </div>
          </div>
          <div className="split-dialog__section">
            <label className="overlay-field">
              <span>Name</span>
              <input
                value={projectEditDraft.name}
                autoFocus
                placeholder="Project name"
                onChange={(e) =>
                  setProjectEditDraft((draft) => ({ ...draft, name: e.target.value }))
                }
              />
            </label>
            <label className="overlay-field">
              <span>Working directory</span>
              <div className="overlay-path-row">
                <input
                  value={projectEditDraft.root}
                  placeholder="~/path/to/project"
                  onChange={(e) =>
                    setProjectEditDraft((draft) => ({ ...draft, root: e.target.value }))
                  }
                />
                <button type="button" onClick={() => void chooseEditProjectRoot()}>
                  Choose...
                </button>
              </div>
            </label>
          </div>
          <div className="split-dialog__section">
            <div className="split-dialog__label">Icon</div>
            <div className="overlay-icon-grid">
              {OVERLAY_ICON_OPTIONS.map((icon) => (
                <button
                  key={icon}
                  type="button"
                  className={`overlay-icon ${projectEditDraft.icon === icon ? 'is-active' : ''}`}
                  onClick={() => setProjectEditDraft((draft) => ({ ...draft, icon }))}
                >
                  {icon}
                </button>
              ))}
              <select
                className="overlay-icon-more"
                aria-label="More edit project icons"
                value={OVERLAY_ICON_OPTIONS.includes(projectEditDraft.icon) ? '' : projectEditDraft.icon}
                onInput={(e) => selectProjectEditMoreIcon(e.currentTarget.value)}
                onChange={(e) => selectProjectEditMoreIcon(e.currentTarget.value)}
              >
                <option value="">More...</option>
                {OVERLAY_MORE_ICONS.map((icon) => (
                  <option key={icon} value={icon}>
                    {icon}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="split-dialog__section">
            <div className="split-dialog__label">Color</div>
            <div className="overlay-color-grid">
              {OVERLAY_COLOR_OPTIONS.map((color) => (
                <button
                  key={color}
                  type="button"
                  className={`overlay-color ${projectEditDraft.accent_color === color ? 'is-active' : ''}`}
                  style={{ backgroundColor: color }}
                  aria-label={color}
                  onClick={() =>
                    setProjectEditDraft((draft) => ({ ...draft, accent_color: color }))
                  }
                />
              ))}
            </div>
          </div>
          <div className="split-dialog__footer">
            <button type="button" className="split-dialog__cancel" onClick={close}>
              Cancel
            </button>
            <button
              type="button"
              className="split-dialog__submit"
              disabled={!projectEditDraft.name.trim() || !projectEditDraft.root.trim()}
              onClick={submitProjectEdit}
            >
              Save
            </button>
          </div>
        </section>
      )}

      {modal.kind === 'newWindow' && (
        <section
          className="split-dialog overlay-dialog--narrow"
          role="dialog"
          aria-modal="true"
          aria-label="New window"
          aria-hidden={deleteConfirmActive ? 'true' : undefined}
          ref={syncParentDialogInert}
          onKeyDown={(event) => containDialogKeyboard(event, close)}
          onMouseDown={(e) => e.stopPropagation()}
        >
          <div className="split-dialog__head">
            <div>
              <h2>New window</h2>
              <p>{project?.name ?? modal.project_id}</p>
            </div>
          </div>
          <div className="split-dialog__section">
            <label className="overlay-field">
              <span>Name</span>
              <input
                value={windowDraft.name}
                autoFocus
                placeholder="literature, experiment, deployment..."
                onChange={(e) => setWindowDraft((draft) => ({ ...draft, name: e.target.value }))}
              />
            </label>
            <div className="overlay-field">
              <span>Working directory</span>
              <div className="folder-pick">
                {windowFolders.map((folder) => (
                  <button
                    key={folder.id}
                    type="button"
                    className={`folder-pick__opt ${windowDraft.root === folder.path ? 'is-active' : ''}`}
                    onClick={() =>
                      setWindowDraft((draft) => ({
                        ...draft,
                        root: folder.path,
                        name: draft.name.trim() ? draft.name : folder.name,
                        session_mode: 'none',
                        resume_session_id: null,
                        resume_session_title: null,
                        resume_session_file: null,
                      }))
                    }
                  >
                    <div className="folder-pick__name">{folder.name}</div>
                    <div className="folder-pick__path">{folder.path}</div>
                  </button>
                ))}
                <button
                  type="button"
                  className={`folder-pick__opt folder-pick__opt--other ${
                    windowFolders.every((folder) => folder.path !== windowDraft.root)
                      ? 'is-active'
                      : ''
                  }`}
                  onClick={() => void chooseWindowRoot()}
                >
                  <div className="folder-pick__name">
                    {windowFolders.every((folder) => folder.path !== windowDraft.root)
                      ? windowDraft.root
                      : 'Other folder...'}
                  </div>
                  <div className="folder-pick__path">
                    {windowFolders.every((folder) => folder.path !== windowDraft.root)
                      ? '(custom)'
                      : 'pick from filesystem'}
                  </div>
                </button>
              </div>
            </div>
          </div>
          <div className="split-dialog__section">
            <div className="split-dialog__label">Agent</div>
            {/* Keep the same compact dropdown-with-icon pattern as the new-project dialog; a select scales as
                more agents are added. */}
            <div className="overlay-agent-row">
              <AgentBadge agent={windowDraft.agent === 'terminal' ? 'shell' : windowDraft.agent} size={13} />
              <select
                className="overlay-select"
                aria-label="Window agent"
                value={windowDraft.agent}
                onChange={(e) =>
                  setWindowDraft((draft) => ({
                    ...draft,
                    agent: e.target.value as OverlayAgent,
                    model: 'default',
                    session_mode: 'none',
                    resume_session_id: null,
                    resume_session_title: null,
                    resume_session_file: null,
                  }))
                }
              >
                {isLegacyAgentKind(windowDraft.agent) && (
                  <option value={windowDraft.agent} disabled>Gemini (legacy)</option>
                )}
                {OVERLAY_AGENT_OPTIONS.map((candidate) => (
                  <option key={candidate} value={candidate}>
                    {OVERLAY_AGENTS[candidate].label}
                  </option>
                ))}
              </select>
            </div>
          {windowDraft.agent !== 'terminal' && (<>
          <div className="overlay-sublabel overlay-sublabel--spaced">Model</div>
          <ModelSelector
            ariaLabel="Window model"
            agent={windowDraft.agent}
            catalog={model.model_catalog}
            value={windowDraft.model}
            onValue={selectWindowModel}
          />
          <label className="overlay-check">
            <input
              type="checkbox"
              aria-label="Window dangerous mode"
              checked={windowDraft.dangerous_skip_permissions}
              onChange={(e) =>
                setWindowDraft((draft) => ({
                  ...draft,
                  dangerous_skip_permissions: e.target.checked,
                }))
              }
            />
            <code>{OVERLAY_AGENTS[windowDraft.agent].dangerousFlag}</code>
          </label>
          </>)}
          </div>
          {windowDraft.agent !== 'terminal' && (
          <div className="split-dialog__section">
            <div className="split-dialog__label">{windowDraft.agent} session</div>
            <div className="session-picker session-picker--panel">
              <button
                type="button"
                className={`session-picker__opt session-picker__opt--special ${windowDraft.session_mode === 'none' ? 'is-active' : ''}`}
                onClick={() =>
                  setWindowDraft((draft) => ({
                    ...draft,
                    session_mode: 'none',
                    resume_session_id: null,
                    resume_session_title: null,
                    resume_session_file: null,
                  }))
                }
              >
                <div className="session-picker__title">+ New session</div>
                <div className="session-picker__hint">
                  Start fresh in {OVERLAY_AGENTS[windowDraft.agent].label}
                </div>
              </button>
              <button
                type="button"
                className={`session-picker__opt session-picker__opt--special ${windowDraft.session_mode === 'continue' ? 'is-active' : ''}`}
                onClick={() =>
                  setWindowDraft((draft) => ({
                    ...draft,
                    session_mode: 'continue',
                    resume_session_id: null,
                    resume_session_title: null,
                    resume_session_file: null,
                  }))
                }
              >
                <div className="session-picker__title">↻ Continue most recent</div>
                <div className="session-picker__hint">
                  <code>{resolveOverlayWindowLaunchCommand({ ...windowDraft, session_mode: 'continue' })}</code>
                </div>
              </button>
              {supportsProviderHistory(windowDraft.agent) && (<>
              {sessionsLoading && (
                <div className="session-picker__empty">Scanning {windowDraft.agent} history...</div>
              )}
              {!sessionsLoading && discoveredSessions.length === 0 && (
                <div className="session-picker__empty">
                  No past {OVERLAY_AGENTS[windowDraft.agent].label} sessions in this folder.
                </div>
              )}
              {visibleFolderSessions(8).map((session) => (
                <div
                  key={session.id}
                  className={`session-picker__opt session-picker__row ${
                    windowDraft.resume_session_id === session.id ? 'is-active' : ''
                  } ${session.in_use ? 'is-open' : ''}`}
                >
                  {editingSessionId === session.id ? (
                    <input
                      className="session-picker__rename"
                      autoFocus
                      disabled={launchPreflightPending}
                      value={sessionNameDraft}
                      placeholder="Name this session..."
                      onChange={(event) => setSessionNameDraft(event.target.value)}
                      onKeyDown={(event) => {
                        if (event.key === 'Enter') commitSessionRename(session)
                        if (event.key === 'Escape') {
                          event.preventDefault()
                          event.stopPropagation()
                          setEditingSessionId(null)
                          setSessionNameDraft('')
                        }
                      }}
                      onBlur={() => commitSessionRename(session)}
                    />
                  ) : (
                    <button
                      type="button"
                      className="session-picker__rowmain"
                      onClick={() =>
                        setWindowDraft((draft) => ({
                          ...draft,
                          session_mode: 'resume',
                          resume_session_id: session.id,
                          resume_session_title: session.custom_name || session.title,
                          resume_session_file: session.file_path,
                          name: draft.name.trim() ? draft.name : session.custom_name || session.title,
                        }))
                      }
                    >
                      <div className="session-picker__pick">
                        <div className="session-picker__title">
                          <span className="session-picker__num">#{session.folder_index}</span>
                          {session.custom_name ? (
                            <span className="session-picker__named">{session.custom_name}</span>
                          ) : (
                            session.title
                          )}
                        </div>
                        <div className="session-picker__hint">
                          {session.custom_name && `${session.title} · `}
                          {session.in_use && <span className="session-picker__inuse">open in pane</span>}
                          {session.in_use && ' · '}
                          {relTime(session.modified_at_ms)} ·{' '}
                          {typeof session.message_count === 'number' && (
                            <>{session.message_count} events · </>
                          )}
                          <code>{session.id.slice(0, 8)}</code>
                        </div>
                      </div>
                    </button>
                  )}
                  {renderSessionActions(session)}
                  {previewState.sessionId === session.id && (
                    <div className="session-picker__rowpreview">
                      {previewState.loading && (
                        <div className="session-preview__loading">Loading preview...</div>
                      )}
                      {!previewState.loading && previewState.lines?.length === 0 && (
                        <div className="session-preview__empty">No readable transcript to preview.</div>
                      )}
                      {previewState.lines?.map((line, index) => (
                        <div key={`${line.role}-${index}`} className={`session-preview__line is-${line.role}`}>
                          <span className="session-preview__role">{line.role}</span>
                          <span className="session-preview__text">{line.text}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              {renderSessionExpansion(8)}
              {renderRemovedSection()}
              </>)}
            </div>
          </div>
          )}
          <div className="split-dialog__footer">
            {launchPreflightError && (
              <div className="overlay-preflight-error" role="alert">
                {launchPreflightError}
              </div>
            )}
            <button type="button" className="split-dialog__cancel" onClick={close}>
              Cancel
            </button>
            <button
              type="button"
              className="split-dialog__submit"
              disabled={launchPreflightPending}
              onClick={() => void submitWindow()}
            >
              {launchPreflightPending ? 'Checking...' : 'Create'}
            </button>
          </div>
        </section>
      )}

      {(() => {
        if (!deleteConfirmSession) return null
        const style = deleteConfirmAnchor
          ? { top: deleteConfirmAnchor.top, left: deleteConfirmAnchor.left }
          : undefined
        return (
          <div
            className={`session-delete-confirm ${deleteConfirmAnchor ? 'is-anchored' : ''}`}
            role="dialog"
            aria-modal="true"
            aria-label="Delete session from disk"
            style={style}
            onKeyDown={(event) => containDialogKeyboard(event, closeDeleteConfirm)}
            onMouseDown={(e) => e.stopPropagation()}
          >
            <div className="session-delete-confirm__title">Delete from disk?</div>
            <div className="session-delete-confirm__name">
              {deleteConfirmSession.custom_name || deleteConfirmSession.title}
            </div>
            <div className="session-delete-confirm__hint">
              Permanently removes the session file. This can&apos;t be undone — use ⊘ Remove to just
              hide it.
            </div>
            <div className="session-delete-confirm__actions">
              <button
                type="button"
                className="session-delete-confirm__danger"
                disabled={launchPreflightPending}
                onClick={() => confirmDeleteFolderSession(deleteConfirmSession)}
              >
                Delete
              </button>
              <button
                type="button"
                className="session-delete-confirm__cancel"
                autoFocus
                onClick={closeDeleteConfirm}
              >
                Cancel
              </button>
            </div>
          </div>
        )
      })()}
    </div>
  )
}
