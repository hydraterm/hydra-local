import { useEffect, useRef, useState, type FocusEvent, type KeyboardEvent } from 'react'
import type {
  AgentKind,
  DashboardModel,
  DashboardWindow,
  ProjectCardView,
  ProjectDetail,
} from '../types/model'
import { bridge } from '../ipc/bridge'
import { AgentBadge } from './AgentBadge'
import { InlineWindowRename } from './InlineWindowRename'

type Props = {
  project: ProjectCardView
  projects: ProjectCardView[]
  details: DashboardModel['details']
  windowOrder?: DashboardModel['global_window_order']
  windowOrderWarning?: DashboardModel['window_order_warning']
  focusedWindowId: string | null
  activeTabId: string | null
  onFocusWindow: (projectId: string, windowId: string) => void
}

type OwnedWindow = {
  project: ProjectCardView
  window: DashboardWindow
}

// Distinct agents in a window, for the tab badge cluster.
function windowAgents(tabs: ProjectDetail['windows'][number]['tabs']): AgentKind[] {
  const seen: AgentKind[] = []
  for (const t of tabs) {
    if (t.stashed) continue
    if (!seen.includes(t.agent)) seen.push(t.agent)
  }
  return seen
}

function isVisibleWindow(win: ProjectDetail['windows'][number]): boolean {
  return !win.stashed && win.tabs.some((tab) => !tab.stashed)
}

const NEW_WINDOW_CONTROL = 'action:new-window'
const SPLIT_RIGHT_CONTROL = 'action:split-right'
const SPLIT_DOWN_CONTROL = 'action:split-down'
const OPEN_WORKSPACE_CONTROL = 'action:open-workspace'

function focusWindowControl(projectId: string, windowId: string): string {
  return `window:${projectId}:${windowId}:focus`
}

function closeWindowControl(projectId: string, windowId: string): string {
  return `window:${projectId}:${windowId}:close`
}

function moveToolbarFocus(
  event: KeyboardEvent<HTMLElement>,
  setTabStop: (controlId: string) => void,
): void {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) return
  const buttons = Array.from(
    event.currentTarget.querySelectorAll<HTMLButtonElement>('button:not(:disabled)'),
  )
  if (buttons.length === 0) return
  const current = buttons.indexOf(event.target as HTMLButtonElement)
  if (current < 0) return

  let next = current
  if (event.key === 'Home') next = 0
  if (event.key === 'End') next = buttons.length - 1
  if (event.key === 'ArrowLeft') next = (current - 1 + buttons.length) % buttons.length
  if (event.key === 'ArrowRight') next = (current + 1) % buttons.length
  const controlId = buttons[next].dataset.toolbarControl
  if (!controlId) return
  event.preventDefault()
  setTabStop(controlId)
  buttons[next].focus()
}

function keepToolbarTabStop(
  event: FocusEvent<HTMLElement>,
  setTabStop: (controlId: string) => void,
): void {
  const buttons = Array.from(
    event.currentTarget.querySelectorAll<HTMLButtonElement>('button:not(:disabled)'),
  )
  const target = event.target as HTMLButtonElement
  if (!buttons.includes(target)) return
  const controlId = target.dataset.toolbarControl
  if (controlId) setTabStop(controlId)
}

export function Topbar({
  project,
  projects,
  details,
  windowOrder,
  windowOrderWarning,
  focusedWindowId,
  activeTabId,
  onFocusWindow,
}: Props): JSX.Element {
  const accent = project.accent_color ?? '#5b6470'
  const windows: OwnedWindow[] = projects.flatMap((owner) =>
    (details[owner.project_id]?.windows ?? [])
      .filter(isVisibleWindow)
      .map((window) => ({ project: owner, window })),
  )
  if (windowOrder) {
    const ranks = new Map(windowOrder.map((id, index) => [id, index]))
    // Sort observed owned rows only: stale/hidden IDs cannot manufacture a window or change owner.
    // Stable sort leaves windows unknown to an older projection in their existing relative order.
    windows.sort((left, right) =>
      (ranks.get(left.window.window_id) ?? windowOrder.length) -
      (ranks.get(right.window.window_id) ?? windowOrder.length),
    )
  }
  const globalVisibleWindowCount = windows.length
  const focusedWindow = windows.find(
    ({ project: owner, window }) =>
      owner.project_id === project.project_id && window.window_id === focusedWindowId,
  )
  const focusedTab =
    focusedWindow?.window.tabs.find((t) => !t.stashed && t.tab_id === activeTabId) ??
    focusedWindow?.window.tabs.find((t) => !t.stashed)
  const defaultTabStop = focusedWindow
    ? focusWindowControl(focusedWindow.project.project_id, focusedWindow.window.window_id)
    : NEW_WINDOW_CONTROL
  const [requestedTabStop, setRequestedTabStop] = useState(defaultTabStop)
  const [renaming, setRenaming] = useState<string | null>(null)
  const orderPending = useRef(false)
  const [orderStatus, setOrderStatus] = useState<{ message: string; error: boolean } | null>(null)
  const [dragWindow, setDragWindow] = useState<string | null>(null)
  const [dropTarget, setDropTarget] = useState<{ id: string; edge: 'before' | 'after' } | null>(null)
  const restoreFocusRef = useRef<string | null>(null)
  useEffect(() => {
    if (
      renaming && !windows.some(({ project: owner, window }) =>
        focusWindowControl(owner.project_id, window.window_id) === renaming)
    ) setRenaming(null)
  }, [renaming, windows])
  useEffect(() => setRequestedTabStop(defaultTabStop), [defaultTabStop])
  const availableControls = windows.flatMap(({ project: owner, window }) => [
    focusWindowControl(owner.project_id, window.window_id),
    ...(globalVisibleWindowCount > 1
      ? [closeWindowControl(owner.project_id, window.window_id)]
      : []),
  ])
  availableControls.push(NEW_WINDOW_CONTROL, OPEN_WORKSPACE_CONTROL)
  if (focusedTab) availableControls.push(SPLIT_RIGHT_CONTROL, SPLIT_DOWN_CONTROL)
  const tabStop = availableControls.includes(requestedTabStop)
    ? requestedTabStop
    : defaultTabStop
  const tabIndexFor = (controlId: string): 0 | -1 => (tabStop === controlId ? 0 : -1)

  const moveWindow = (fromId: string, toId: string, edge: 'before' | 'after'): void => {
    if (orderPending.current || fromId === toId) return
    const ids = windows.map(({ window }) => window.window_id)
    if (!ids.includes(fromId) || !ids.includes(toId)) return
    const next = ids.filter((id) => id !== fromId)
    next.splice(next.indexOf(toId) + (edge === 'after' ? 1 : 0), 0, fromId)
    if (next.every((id, index) => id === ids[index])) return
    orderPending.current = true
    setOrderStatus({ message: 'Saving window order…', error: false })
    void bridge.reorderWindowPresentation(next).then((result) => {
      orderPending.current = false
      setOrderStatus(result.status === 'saved' ? null : { message: result.message, error: true })
    })
  }

  const handOffFocusBeforeClose = (
    closingProjectId: string,
    closingWindowId: string,
    toolbar: HTMLElement | null,
  ): void => {
    const remaining = windows.filter(
      ({ project: owner, window }) =>
        owner.project_id !== closingProjectId || window.window_id !== closingWindowId,
    )
    if (remaining.length === 0) return
    const focusedStillExists = remaining.find(
      ({ project: owner, window }) =>
        owner.project_id === project.project_id && window.window_id === focusedWindowId,
    )
    const sameProjectFallback = remaining.find(
      ({ project: owner }) => owner.project_id === closingProjectId,
    )
    const targetWindow =
      focusedStillExists ?? sameProjectFallback ?? remaining[0]
    const targetControl = focusWindowControl(
      targetWindow.project.project_id,
      targetWindow.window.window_id,
    )
    setRequestedTabStop(targetControl)
    const buttons = Array.from(
      toolbar?.querySelectorAll<HTMLButtonElement>('button[data-toolbar-control]') ?? [],
    )
    buttons.find((button) => button.dataset.toolbarControl === targetControl)?.focus()
  }
  const openSplit = (dir: 'h' | 'v'): void => {
    if (!focusedTab) return
    bridge.openSplitDialog(project.project_id, focusedTab.window_id, focusedTab.tab_id, dir)
  }
  const openWorkspaceFolder = async (): Promise<void> => {
    const root = await bridge.pickProjectFolder()
    if (!root) return
    bridge.updateProject({ project_id: project.project_id, root })
  }

  return (
    <header
      className="window-tabs"
      style={{ ['--accent' as string]: accent }}
      role="toolbar"
      aria-label="Window controls"
      aria-orientation="horizontal"
      onKeyDown={(event) => moveToolbarFocus(event, setRequestedTabStop)}
      onFocusCapture={(event) => keepToolbarTabStop(event, setRequestedTabStop)}
    >
      {orderStatus && (
        <span className="window-tabs__order-warning" role={orderStatus.error ? 'alert' : 'status'} title={orderStatus.message}>
          {orderStatus.message}
        </span>
      )}
      {windowOrderWarning && (
        <span className="window-tabs__order-warning" role="status" title={windowOrderWarning}>
          {windowOrderWarning}
        </span>
      )}
      <div className="window-tabs__left">
        {windows.map(({ project: owner, window: w }) => {
          const controlId = focusWindowControl(owner.project_id, w.window_id)
          const isRenaming = renaming === controlId
          const isActive =
            owner.project_id === project.project_id && w.window_id === focusedWindowId
          const agents = windowAgents(w.tabs)
          const canClose = globalVisibleWindowCount > 1
          return (
            <span
              key={`${owner.project_id}:${w.window_id}`}
              className={`window-tab-group ${isActive ? 'is-active' : ''} ${isRenaming ? 'is-renaming' : ''} ${dropTarget?.id === w.window_id ? `drop-${dropTarget.edge}` : ''}`}
              onDragOver={(event) => {
                if (!dragWindow || orderPending.current) return
                event.preventDefault()
                const rect = event.currentTarget.getBoundingClientRect()
                setDropTarget({ id: w.window_id, edge: event.clientX < rect.left + rect.width / 2 ? 'before' : 'after' })
              }}
              onDragLeave={() => setDropTarget(null)}
              onDrop={(event) => {
                event.preventDefault()
                if (dragWindow) {
                  const rect = event.currentTarget.getBoundingClientRect()
                  moveWindow(dragWindow, w.window_id, event.clientX < rect.left + rect.width / 2 ? 'before' : 'after')
                }
                setDragWindow(null)
                setDropTarget(null)
              }}
            >
              {isRenaming ? (
                <InlineWindowRename
                  projectId={owner.project_id}
                  windowId={w.window_id}
                  name={w.name || w.window_id}
                  onFinish={(restoreFocus) => {
                    if (restoreFocus) restoreFocusRef.current = controlId
                    setRenaming(null)
                  }}
                />
              ) : (
                <button
                  ref={(node) => {
                    if (node && restoreFocusRef.current === controlId) {
                      restoreFocusRef.current = null
                      node.focus()
                    }
                  }}
                  type="button"
                  aria-keyshortcuts="F2 Alt+Shift+ArrowLeft Alt+Shift+ArrowRight"
                  draggable={!orderPending.current}
                  onDragStart={(event) => {
                    event.dataTransfer.setData('application/x-hydra-topbar-window-id', w.window_id)
                    event.dataTransfer.effectAllowed = 'move'
                    setDragWindow(w.window_id)
                  }}
                  onDragEnd={() => { setDragWindow(null); setDropTarget(null) }}
                  aria-pressed={isActive}
                  aria-label={`Focus ${w.name || w.window_id} in ${owner.name}`}
                  data-toolbar-control={focusWindowControl(owner.project_id, w.window_id)}
                  tabIndex={tabIndexFor(focusWindowControl(owner.project_id, w.window_id))}
                  className={`window-tab ${isActive ? 'is-active' : ''}`}
                  title={`${owner.name} · ${w.name || w.window_id} — ${w.tabs.filter((t) => !t.stashed).length} pane(s). Drag or Alt+Shift+Left/Right to reorder.`}
                  onClick={() => onFocusWindow(owner.project_id, w.window_id)}
                  onKeyDown={(event) => {
                    if (event.altKey && event.shiftKey && ['ArrowLeft', 'ArrowRight'].includes(event.key)) {
                      event.preventDefault()
                      event.stopPropagation()
                      const offset = event.key === 'ArrowLeft' ? -1 : 1
                      const neighbor = windows[windows.findIndex(({ window }) => window.window_id === w.window_id) + offset]
                      if (neighbor) moveWindow(w.window_id, neighbor.window.window_id, offset < 0 ? 'before' : 'after')
                      return
                    }
                    if (event.key === 'F2') {
                      event.preventDefault()
                      event.stopPropagation()
                      setRenaming(controlId)
                    }
                  }}
                >
                  {agents.length > 0 && (
                    <span className="window-tab__agents">
                      {agents.map((a) => (
                        <AgentBadge key={a} agent={a} size={12} />
                      ))}
                    </span>
                  )}
                  <span
                    className="window-tab__name"
                    onDoubleClick={(event) => {
                      event.stopPropagation()
                      setRenaming(controlId)
                    }}
                  >
                    {w.name || w.window_id}
                  </span>
                </button>
              )}
              <button
                type="button"
                className="window-tab__close"
                title={canClose ? 'Close window' : 'Keep one window open globally'}
                aria-label={`Close ${w.name || w.window_id} in ${owner.name}`}
                data-toolbar-control={closeWindowControl(owner.project_id, w.window_id)}
                tabIndex={tabIndexFor(closeWindowControl(owner.project_id, w.window_id))}
                disabled={!canClose}
                onClick={(e) => {
                  e.stopPropagation()
                  handOffFocusBeforeClose(
                    owner.project_id,
                    w.window_id,
                    e.currentTarget.closest<HTMLElement>('[role="toolbar"]'),
                  )
                  bridge.stashWindow(owner.project_id, w.window_id)
                }}
              >
                ×
              </button>
            </span>
          )
        })}
      </div>

      <button
        type="button"
        className="window-tab window-tab__add"
        title="New window"
        aria-label="New window"
        data-toolbar-control={NEW_WINDOW_CONTROL}
        tabIndex={tabIndexFor(NEW_WINDOW_CONTROL)}
        onClick={() => bridge.openWindowDialog(project.project_id)}
      >
        + window
      </button>

      <div className="window-tabs__spacer" />

      <button
        type="button"
        className="window-tab window-tab__action"
        disabled={!focusedTab}
        title="Split right"
        aria-label="Split right"
        data-toolbar-control={SPLIT_RIGHT_CONTROL}
        tabIndex={tabIndexFor(SPLIT_RIGHT_CONTROL)}
        onClick={() => openSplit('h')}
      >
        ⊟ split right
      </button>
      <button
        type="button"
        className="window-tab window-tab__action"
        disabled={!focusedTab}
        title="Split down"
        aria-label="Split down"
        data-toolbar-control={SPLIT_DOWN_CONTROL}
        tabIndex={tabIndexFor(SPLIT_DOWN_CONTROL)}
        onClick={() => openSplit('v')}
      >
        ⊟ split down
      </button>
      <button
        type="button"
        className="window-tab window-tab__action"
        title="Open workspace"
        aria-label="Open workspace"
        data-toolbar-control={OPEN_WORKSPACE_CONTROL}
        tabIndex={tabIndexFor(OPEN_WORKSPACE_CONTROL)}
        onClick={() => void openWorkspaceFolder()}
      >
        ⊡ open workspace
      </button>
    </header>
  )
}
