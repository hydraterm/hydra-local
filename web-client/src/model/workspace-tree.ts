import type { RemoteClientView, RemoteWorkspaceProjectMetadata } from '../bridge/remote-client.js'
import { sessionRowModel, UNGROUPED_PROJECT_LABEL, type SessionRow } from './session-row.js'
import { leaves, readingOrderPanes } from './pane-layout.js'

export const DESKTOP_PROJECT_ACCENTS = ['#fbbf24', '#34d399', '#60a5fa', '#f87171', '#a78bfa', '#f472b6', '#e5e7eb'] as const

export interface WorkspacePaneNode {
  readonly id: string
  readonly sessionId: string
  readonly name: string
  readonly statusDot: 'active' | 'live' | 'starting' | 'stashed'
  readonly isActive: boolean
  readonly isLive: boolean
  /** The session is PLACED in some browser window layout (active mirror or paneLayoutsByWindow) — R1: a placed
   * pane reads green in the sidebar even when its window is not the active one. Distinct from `isLive`, which
   * also covers desktop-live-but-unplaced sessions (rendered as switchable grey per the R4 landing rule). */
  readonly isPlaced: boolean
  readonly isStashed: boolean
  /** Mid-creation limbo ('landing-pending', pane lifecycle contract): the pane's session_id is still REDACTED
   * ("" until its PTY is live), so the row is session-less — visible but not placeable/revivable yet. Renders
   * amber "starting…" instead of the stashed grey (grey implies revivable-by-click; this is not). */
  readonly isStarting: boolean
  readonly source: 'desktop-metadata' | 'session-fallback'
  readonly session?: SessionRow
  /** The pane's session working directory, so the split picker can default to the source window's folder. */
  readonly cwd?: string
}

export interface WorkspaceWindowNode {
  readonly id: string
  readonly name: string
  readonly statusDot: 'active' | 'live' | 'starting' | 'stashed'
  readonly isFocused: boolean
  readonly isStashed: boolean
  /** The window is in the R7 `landing-pending` state (designated for the first-sight landing, nothing placeable
   * yet — `RemoteClientController.landingPendingWindowIds()`), or every pane it has is still session-less. */
  readonly isStarting: boolean
  readonly source: 'desktop-metadata' | 'session-fallback'
  readonly panes: readonly WorkspacePaneNode[]
}

export interface WorkspaceProjectNode {
  readonly id: string
  readonly name: string
  readonly root?: string
  readonly icon: string
  readonly accentColor: string
  readonly statusDot: 'active' | 'live' | 'starting' | 'stashed'
  readonly isSelected: boolean
  readonly source: 'desktop-metadata' | 'cwd-fallback'
  readonly launchDefaults?: RemoteWorkspaceProjectMetadata['launchDefaults']
  readonly directories?: RemoteWorkspaceProjectMetadata['directories']
  /** The built-in "Terminal" project: plain-bash, name-only dialogs, never deletable. */
  readonly system?: boolean
  /** User hid this project. */
  readonly hidden?: boolean
  readonly windows: readonly WorkspaceWindowNode[]
}

export interface WorkspaceTree {
  readonly projects: readonly WorkspaceProjectNode[]
}

export function projectAccent(project: string | null): string {
  const key = project ?? UNGROUPED_PROJECT_LABEL
  let hash = 0
  for (let i = 0; i < key.length; i += 1) {
    hash = (hash * 31 + key.charCodeAt(i)) >>> 0
  }
  return DESKTOP_PROJECT_ACCENTS[hash % DESKTOP_PROJECT_ACCENTS.length]
}

/** Options for {@link workspaceTreeFromRemoteView}. `pendingLandingWindows` comes from
 * `RemoteClientController.landingPendingWindowIds()` (read-only lifecycle observability) and marks those
 * windows — mid-creation, nothing placeable yet — as `isStarting` instead of stashed-grey. */
export interface WorkspaceTreeOptions {
  readonly pendingLandingWindows?: readonly string[]
}

export function workspaceTreeFromRemoteView(view: RemoteClientView, opts: WorkspaceTreeOptions = {}): WorkspaceTree {
  // Parity with the local desktop dashboard: the tree reflects the LIVE desktop workspace (projects → windows →
  // open panes), driven ONLY by desktop workspace_metadata. When there's no metadata we return an EMPTY tree (the
  // shell shows a "no active desktop workspace — reconnect" empty state) instead of dumping every historical
  // session grouped by folder — which is what the old cwd-fallback did and why "all sessions" appeared.
  if (view.workspaceMetadata) return treeFromDesktopMetadata(view, opts)
  return { projects: [] }
}

function treeFromDesktopMetadata(view: RemoteClientView, opts: WorkspaceTreeOptions): WorkspaceTree {
  const pendingLandingWindows = new Set(opts.pendingLandingWindows ?? [])
  // Single-visible-pane model: desktop-live panes stay switchable by behavior, but only the pane this browser is
  // currently attached to should read GREEN. Other live panes are visually grey so the sidebar behaves like a clear
  // remote switcher instead of implying several panes are simultaneously active in this one browser.
  const mirrorPlacedSessions = new Set(
    readingOrderPanes(view.paneLayout).map((p) => p.sessionId).filter((s): s is string => s !== null),
  )
  // Slice 5 (parity plan S1-3): a pane's stashed badge reads ITS OWN window's browser layout
  // (`paneLayoutsByWindow[windowId]`), NOT the active window's mirror — panes placed in a non-active window
  // used to read STASHED, and switching windows flipped every badge wholesale. The ACTIVE window still reads
  // the live mirror (it can lead the map mid-mutation); a window with no map entry has nothing placed there;
  // pre-window single-grid mode (activeWindowId null) keeps the old mirror read for every window.
  const placedSessionsFor = (windowId: string): ReadonlySet<string> => {
    if (view.activeWindowId == null || view.activeWindowId === windowId) return mirrorPlacedSessions
    const ws = view.paneLayoutsByWindow?.[windowId]
    if (!ws?.layout) return new Set()
    return new Set(leaves(ws.layout.root).map((l) => l.sessionId).filter((s): s is string => s !== null))
  }
  const swappedOutSessionsFor = (windowId: string): ReadonlySet<string> => {
    const rows = view.activeWindowId == null || view.activeWindowId === windowId
      ? view.browserStashed
      : view.paneLayoutsByWindow?.[windowId]?.stashed ?? []
    return new Set(rows.filter((s) => s.swappedOut && s.sessionId).map((s) => s.sessionId as string))
  }
  const plainStashedSessionsFor = (windowId: string): ReadonlySet<string> => {
    const rows = view.activeWindowId == null || view.activeWindowId === windowId
      ? view.browserStashed
      : view.paneLayoutsByWindow?.[windowId]?.stashed ?? []
    return new Set(rows.filter((s) => !s.swappedOut && s.sessionId).map((s) => s.sessionId as string))
  }
  return {
    projects: view.workspaceMetadata!.projects.map((project) => {
      const windows = project.windows.map((windowNode): WorkspaceWindowNode => {
        const placedSessions = placedSessionsFor(windowNode.id)
        const swappedOutSessions = swappedOutSessionsFor(windowNode.id)
        const plainStashedSessions = plainStashedSessionsFor(windowNode.id)
        const panes = windowNode.panes.flatMap((pane): WorkspacePaneNode[] => {
          // STARTING (mid-creation): a session-less pane (session_id redacted to "" until the PTY is live) is in
          // the creation redaction window — visible, but neither live nor a revivable stash row. It ALWAYS exists
          // (the desktop just pushed it), so it must not fall through the liveness existence check below.
          const isStarting = !pane.sessionId
          // Only surface panes that still EXIST on the desktop (live or desktop-stashed); drop truly gone ones.
          const existsOnDesktop = isStarting || Boolean(pane.stashed) || (pane.live ?? view.sessions.includes(pane.sessionId))
          if (!existsOnDesktop) return []
          const isPlaced = !isStarting && placedSessions.has(pane.sessionId)
          const isDesktopLive = !isStarting && (pane.live ?? view.sessions.includes(pane.sessionId))
          const isSwappedOut = !isStarting && !isPlaced && swappedOutSessions.has(pane.sessionId)
          const isPlainBrowserStashed = !isStarting && !isPlaced && plainStashedSessions.has(pane.sessionId)
          const isActive = !isStarting && view.attachedSession === pane.sessionId
          const isLive = !isPlainBrowserStashed && (isPlaced || isSwappedOut || isDesktopLive)
          const isStashed = isPlainBrowserStashed || (!isLive && !isStarting)
          const statusDot = isStarting ? 'starting' : isActive ? 'live' : 'stashed'
          return [{
            id: pane.id,
            sessionId: pane.sessionId,
            // A starting pane has no session to derive a label from — an honest placeholder, not a raw "" lookup.
            name: pane.name?.trim() || (isStarting ? 'New pane' : sessionLabelForMetadata(view, pane.sessionId)),
            statusDot,
            isActive,
            isLive,
            isPlaced,
            isStashed,
            isStarting,
            source: 'desktop-metadata',
            ...(pane.cwd ? { cwd: pane.cwd } : {}),
          }]
        })
        // 'is-starting' window: designated for the R7 first-sight landing but nothing placeable yet (the
        // controller's landing-pending set), or all it has are session-less mid-creation rows. Distinct from
        // stashed: a stashed window revives on click; this one just hasn't finished starting on the desktop.
        const windowIsStarting = pendingLandingWindows.has(windowNode.id)
          || (panes.length > 0 && panes.every((pane) => pane.isStarting))
        const paneStatus = aggregatePaneStatus(panes)
        return {
          id: windowNode.id,
          name: windowNode.name?.trim() || windowNode.id,
          statusDot: windowIsStarting && paneStatus === 'stashed' ? 'starting' : paneStatus,
          // PER-WINDOW: the REMOTE's active window (the tab whose grid is shown) drives selection when set — so the
          // topbar tab highlight follows the grid the user is actually looking at, not the desktop's focused window.
          // Falls back to metadata focused / active-pane when the remote hasn't picked a window yet (activeWindowId null).
          isFocused: view.activeWindowId != null
            ? view.activeWindowId === windowNode.id
            : Boolean(windowNode.focused) || panes.some((pane) => pane.isActive),
          // A desktop-live pane keeps the window green/clickable even if the remote has not placed that window yet.
          // A STARTING window is never stashed-grey (its redacted panes parse `stashed: true`, which is limbo).
          isStashed: !windowIsStarting
            && (Boolean(view.paneLayoutsByWindow?.[windowNode.id]?.windowStashed
                && !view.paneLayoutsByWindow?.[windowNode.id]?.layout)
              || (Boolean(windowNode.stashed) && panes.length > 0 && panes.every((pane) => pane.isStashed))),
          isStarting: windowIsStarting,
          source: 'desktop-metadata',
          panes,
        }
      })
      // Parity with local `focusedWindow` (App.tsx): the focused window is the one holding the active pane; if none
      // (the agent can't report the live focused window from records), fall back to the FIRST VISIBLE window —
      // exactly local's `visibleWindows.find(focused) ?? visibleWindows[0]`. Guarantees one focused window so the
      // shell can render a single active window like the desktop, not every window. Skipped when the remote already
      // picked an active window (activeWindowId set → that window is authoritative, even if it currently has no panes).
      if (view.activeWindowId == null && !windows.some((w) => w.isFocused)) {
        const firstVisible = windows.find((w) => w.panes.some((p) => !p.isStashed)) ?? windows.find((w) => w.panes.length > 0) ?? windows[0]
        if (firstVisible) (firstVisible as { isFocused: boolean }).isFocused = true
      }
      return {
        id: project.id,
        name: project.name,
        root: project.root,
        icon: project.icon?.trim() || '◆',
        accentColor: project.accentColor?.trim() || projectAccent(project.name),
        statusDot: aggregateWindowStatus(windows),
        isSelected: Boolean(project.selected) || windows.some((windowNode) => windowNode.isFocused),
        source: 'desktop-metadata',
        ...(project.launchDefaults ? { launchDefaults: project.launchDefaults } : {}),
        ...(project.directories !== undefined ? { directories: project.directories } : {}),
        ...(project.system ? { system: true } : {}),
        ...(project.hidden ? { hidden: true } : {}),
        windows,
      }
    }),
  }
}

function sessionLabelForMetadata(view: RemoteClientView, sessionId: string): string {
  return sessionRowModel(view, sessionId).label
}

function aggregatePaneStatus(panes: readonly WorkspacePaneNode[]): 'active' | 'live' | 'starting' | 'stashed' {
  if (panes.some((pane) => pane.statusDot === 'active')) return 'active'
  if (panes.some((pane) => pane.statusDot === 'live')) return 'live'
  if (panes.some((pane) => pane.statusDot === 'starting')) return 'starting'
  return 'stashed'
}

function aggregateWindowStatus(windows: readonly WorkspaceWindowNode[]): 'active' | 'live' | 'starting' | 'stashed' {
  if (windows.some((windowNode) => windowNode.statusDot === 'active')) return 'active'
  if (windows.some((windowNode) => windowNode.statusDot === 'live')) return 'live'
  if (windows.some((windowNode) => windowNode.statusDot === 'starting')) return 'starting'
  return 'stashed'
}
