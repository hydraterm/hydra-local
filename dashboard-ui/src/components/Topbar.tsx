import { useState, type FocusEvent, type KeyboardEvent } from 'react'
import type { AgentKind, ProjectCardView, ProjectDetail } from '../types/model'
import { bridge } from '../ipc/bridge'
import { AgentBadge } from './AgentBadge'

type Props = {
  project: ProjectCardView
  detail: ProjectDetail | undefined
  focusedWindowId: string | null
  activeTabId: string | null
  onFocusWindow: (windowId: string) => void
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

function focusWindowControl(windowId: string): string {
  return `window:${windowId}:focus`
}

function closeWindowControl(windowId: string): string {
  return `window:${windowId}:close`
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
  detail,
  focusedWindowId,
  activeTabId,
  onFocusWindow,
}: Props): JSX.Element {
  const accent = project.accent_color ?? '#5b6470'
  const windows = (detail?.windows ?? []).filter(isVisibleWindow)
  const visibleWindowCount = windows.length
  const focusedWindow = windows.find((w) => w.window_id === focusedWindowId)
  const focusedTab =
    focusedWindow?.tabs.find((t) => !t.stashed && t.tab_id === activeTabId) ??
    focusedWindow?.tabs.find((t) => !t.stashed)
  const defaultTabStop = focusedWindow
    ? focusWindowControl(focusedWindow.window_id)
    : NEW_WINDOW_CONTROL
  const [requestedTabStop, setRequestedTabStop] = useState(defaultTabStop)
  const availableControls = windows.flatMap((window) => [
    focusWindowControl(window.window_id),
    ...(visibleWindowCount > 1 ? [closeWindowControl(window.window_id)] : []),
  ])
  availableControls.push(NEW_WINDOW_CONTROL, OPEN_WORKSPACE_CONTROL)
  if (focusedTab) availableControls.push(SPLIT_RIGHT_CONTROL, SPLIT_DOWN_CONTROL)
  const tabStop = availableControls.includes(requestedTabStop)
    ? requestedTabStop
    : defaultTabStop
  const tabIndexFor = (controlId: string): 0 | -1 => (tabStop === controlId ? 0 : -1)

  const handOffFocusBeforeClose = (
    closingWindowId: string,
    closingIndex: number,
    toolbar: HTMLElement | null,
  ): void => {
    const remaining = windows.filter((window) => window.window_id !== closingWindowId)
    if (remaining.length === 0) return
    const focusedStillExists = remaining.find((window) => window.window_id === focusedWindowId)
    const targetWindow =
      focusedStillExists ?? remaining[Math.min(closingIndex, remaining.length - 1)]
    const targetControl = focusWindowControl(targetWindow.window_id)
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
      <div className="window-tabs__left">
        {windows.map((w, windowIndex) => {
          const isActive = w.window_id === focusedWindowId
          const agents = windowAgents(w.tabs)
          const canClose = visibleWindowCount > 1
          return (
            <span key={w.window_id} className={`window-tab-group ${isActive ? 'is-active' : ''}`}>
              <button
                type="button"
                aria-pressed={isActive}
                aria-label={`Focus ${w.name || w.window_id}`}
                data-toolbar-control={focusWindowControl(w.window_id)}
                tabIndex={tabIndexFor(focusWindowControl(w.window_id))}
                className={`window-tab ${isActive ? 'is-active' : ''}`}
                title={`${w.name || w.window_id} — ${w.tabs.filter((t) => !t.stashed).length} pane(s)`}
                onClick={() => onFocusWindow(w.window_id)}
              >
                {agents.length > 0 && (
                  <span className="window-tab__agents">
                    {agents.map((a) => (
                      <AgentBadge key={a} agent={a} size={12} />
                    ))}
                  </span>
                )}
                <span className="window-tab__name">{w.name || w.window_id}</span>
              </button>
              <button
                type="button"
                className="window-tab__close"
                title={canClose ? 'Close window' : 'Keep one window open'}
                aria-label={`Close ${w.name || w.window_id}`}
                data-toolbar-control={closeWindowControl(w.window_id)}
                tabIndex={tabIndexFor(closeWindowControl(w.window_id))}
                disabled={!canClose}
                onClick={(e) => {
                  e.stopPropagation()
                  handOffFocusBeforeClose(
                    w.window_id,
                    windowIndex,
                    e.currentTarget.closest<HTMLElement>('[role="toolbar"]'),
                  )
                  bridge.stashWindow(project.project_id, w.window_id)
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
