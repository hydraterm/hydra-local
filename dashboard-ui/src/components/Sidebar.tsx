import { useEffect, useRef, useState } from 'react'
import type {
  AgentKind,
  DashboardModel,
  DashboardWindow,
  FilesystemModeMigrationChange,
  ProjectCardView,
  ProjectDetail,
  SessionStatus,
} from '../types/model'
import { bridge } from '../ipc/bridge'
import { AgentBadge } from './AgentBadge'

const ENROLL_CONFIRMATION_TIMEOUT_MS = 70_000


type DeleteDraft = {
  project_id: string
  name: string
  root: string
  runtime_label: string
  open_count: number
  remove_record: boolean
  keep_working_directory: boolean
  close_open_windows: boolean
}

type WindowRenameDraft = {
  project_id: string
  window_id: string
  name: string
}

type PaneRenameDraft = {
  project_id: string
  window_id: string
  tab_id: string
  name: string
}



function actionableFilesystemModeMigrationNotice(
  notice: DashboardModel['filesystem_mode_migration'],
): NonNullable<DashboardModel['filesystem_mode_migration']> | null {
  if (!notice) return null
  if (notice.phase === 'ready_to_apply') {
    return notice.recovery_record_path === undefined ? notice : null
  }
  if (notice.phase === 'interrupted' || notice.phase === 'applied') {
    return typeof notice.recovery_record_path === 'string' && notice.recovery_record_path.length > 0
      ? notice
      : null
  }
  return null
}

type Props = {
  model: DashboardModel
  selectedId: string | null
  focusedWindowId: string | null
  collapsed?: boolean
  onToggleCollapsed?: (event: React.MouseEvent<HTMLButtonElement>) => void
  onSelect: (projectId: string) => void
  onReorder: (orderedIds: string[]) => void
  onWindowReorder: (projectId: string, orderedWindowIds: string[]) => void
  onFocusWindow: (windowId: string) => void
}

function statusDotClass(status: SessionStatus | null, stashed: boolean): string {
  if (stashed) return 'dot--stashed'
  if (status === 'live') return 'dot--live'
  if (status === 'exited') return 'dot--exited'
  return 'dot--unknown'
}

// A window's aggregate status: live if any live pane, else exited/unknown.
function windowStatus(win: DashboardWindow): SessionStatus {
  if (win.stashed) return 'unknown'
  const live = win.tabs.filter((t) => !t.stashed)
  if (live.some((t) => t.session_status === 'live')) return 'live'
  if (live.some((t) => t.session_status === 'exited')) return 'exited'
  return 'unknown'
}

// Running/total + distinct agents, for the project-row summary chip.
function projectSummary(detail: ProjectDetail | undefined): {
  running: number
  total: number
  agents: AgentKind[]
} {
  let running = 0
  let total = 0
  const agents = new Set<AgentKind>()
  for (const w of detail?.windows ?? []) {
    for (const t of w.tabs) {
      if (t.stashed) continue
      total++
      agents.add(t.agent)
      if (t.session_status === 'live') running++
    }
  }
  return { running, total, agents: [...agents] }
}

export function Sidebar({
  model,
  selectedId,
  focusedWindowId,
  collapsed = false,
  onToggleCollapsed,
  onSelect,
  onReorder,
  onWindowReorder,
  onFocusWindow,
}: Props): JSX.Element {
  // Independent expand state at each level. Projects default-expand when
  // selected; windows default-open inside the selected/focused project.
  const [expandedProjects, setExpandedProjects] = useState<Record<string, boolean>>({})
  const [expandedWindows, setExpandedWindows] = useState<Record<string, boolean>>({})
  // "Add Remote": the enrollment code the user pastes from the browser (local input state only).
  const [enrollCode, setEnrollCode] = useState('')
  const [enrollPending, setEnrollPending] = useState(false)
  const [enrollUiError, setEnrollUiError] = useState<string | null>(null)
  const [copiedRollbackPath, setCopiedRollbackPath] = useState<string | null>(null)
  const remoteAvailable = model.remote_available === true
  const filesystemModeMigrationCandidate = model.filesystem_mode_migration ?? null
  const filesystemModeMigration = actionableFilesystemModeMigrationNotice(
    filesystemModeMigrationCandidate,
  )
  // Malformed native data never becomes actionable UI, but it also must not reopen Remote as a side effect.
  const filesystemMigrationPending = filesystemModeMigrationCandidate !== null
  const desktopAccessNeedsAction =
    model.desktop_access?.status === 'required' || model.desktop_access?.status === 'unknown'
  // Remember the exact model that was visible when the request was sent. An old inline error must not make a
  // newly-submitted attempt look complete before the host publishes its authoritative result model.
  const enrollSubmissionModelRef = useRef<DashboardModel | null>(null)
  // "Remove Remote": two-click inline confirm (window.confirm is a no-op in this WebView). First click arms, second
  // removes. Auto-disarms after a few seconds so a stray arm doesn't linger.
  const [confirmRemoveRemote, setConfirmRemoveRemote] = useState(false)
  const [orderedProjectIds, setOrderedProjectIds] = useState<string[]>(() =>
    model.projects.map((p) => p.project_id),
  )
  const [dragProjectId, setDragProjectId] = useState<string | null>(null)
  const [dropTarget, setDropTarget] = useState<{ id: string; edge: 'before' | 'after' } | null>(
    null,
  )
  const [dragWindow, setDragWindow] = useState<{ projectId: string; windowId: string } | null>(
    null,
  )
  const [windowDropTarget, setWindowDropTarget] = useState<{
    windowId: string
    edge: 'before' | 'after'
  } | null>(null)
  const [openProjectMenuId, setOpenProjectMenuId] = useState<string | null>(null)
  const [renameDraft, setRenameDraft] = useState<{ project_id: string; name: string } | null>(null)
  const [deleteDraft, setDeleteDraft] = useState<DeleteDraft | null>(null)
  const [openWindowMenuKey, setOpenWindowMenuKey] = useState<string | null>(null)
  const [windowRenameDraft, setWindowRenameDraft] = useState<WindowRenameDraft | null>(null)
  const [openPaneMenuKey, setOpenPaneMenuKey] = useState<string | null>(null)
  const [paneRenameDraft, setPaneRenameDraft] = useState<PaneRenameDraft | null>(null)
  const paneRenameInputRef = useRef<HTMLInputElement | null>(null)
  const projectRenameInputRef = useRef<HTMLInputElement | null>(null)
  const windowRenameInputRef = useRef<HTMLInputElement | null>(null)
  const [stashedDragKey, setStashedDragKey] = useState<string | null>(null)

  const closeOpenMenus = (): void => {
    setOpenProjectMenuId(null)
    setOpenWindowMenuKey(null)
    setOpenPaneMenuKey(null)
  }

  const submitEnrollment = (): void => {
    const code = enrollCode.trim()
    if (
      !remoteAvailable ||
      !code ||
      enrollPending ||
      desktopAccessNeedsAction ||
      filesystemMigrationPending
    ) return
    enrollSubmissionModelRef.current = model
    setEnrollUiError(null)
    setEnrollPending(true)
    bridge.enrollDesktop(code)
  }

  useEffect(() => {
    setCopiedRollbackPath(null)
  }, [filesystemModeMigration?.notice_id, filesystemModeMigration?.phase])

  useEffect(() => {
    if (remoteAvailable) return
    // Capability loss is authoritative and fail-closed. Do not retain a one-time enrollment secret in component
    // state after the private extension disappears or negotiation fails.
    setEnrollCode('')
    setEnrollPending(false)
    setEnrollUiError(null)
    setConfirmRemoveRemote(false)
    enrollSubmissionModelRef.current = null
  }, [remoteAvailable])

  const copyRollbackCommand = async (change: FilesystemModeMigrationChange): Promise<void> => {
    const command = change.rollback_command
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(command)
      } else {
        const textarea = document.createElement('textarea')
        try {
          textarea.value = command
          textarea.setAttribute('readonly', '')
          textarea.style.position = 'fixed'
          textarea.style.opacity = '0'
          document.body.appendChild(textarea)
          textarea.select()
          if (!document.execCommand('copy')) throw new Error('copy command was rejected')
        } finally {
          textarea.remove()
        }
      }
      setCopiedRollbackPath(change.path)
    } catch {
      // The read-only command field remains manually selectable when a platform clipboard policy rejects the API.
      setCopiedRollbackPath(null)
    }
  }

  useEffect(() => {
    // A late native success still authoritatively clears the code after the UI's bounded confirmation timeout.
    if (model.enrolled && !model.enroll_error) {
      setEnrollCode('')
      setEnrollPending(false)
      setEnrollUiError(null)
      enrollSubmissionModelRef.current = null
      return
    }
    if (!enrollPending || enrollSubmissionModelRef.current === model) return
    // Native always publishes either an enrolled model or an inline error after the typed intent completes.
    // Keep the one-time code in memory on every failure; clear it only after the complete enrollment + service
    // readiness transaction succeeds. A partial result (identity exists but the service stayed fail-closed) keeps
    // the code and exposes the native error below instead of pretending Add Remote fully succeeded.
    if (model.enroll_error) {
      setEnrollPending(false)
      enrollSubmissionModelRef.current = null
    }
  }, [enrollPending, model])

  useEffect(() => {
    if (!enrollPending) return
    // The native transaction is bounded, but a WebView model-delivery failure must not leave the form disabled
    // forever. This timer changes UI state only: it never assumes enrollment failed, opens the remote gate, or
    // clears the one-time code. A later authoritative success model still wins in the effect above.
    const timeout = window.setTimeout(() => {
      setEnrollPending(false)
      setEnrollUiError('Hydra could not confirm setup. The code was kept so you can check the status and try again.')
      enrollSubmissionModelRef.current = null
    }, ENROLL_CONFIRMATION_TIMEOUT_MS)
    return () => window.clearTimeout(timeout)
  }, [enrollPending])

  useEffect(() => {
    setOrderedProjectIds((prev) => {
      const liveIds = model.projects.map((p) => p.project_id)
      const live = new Set(liveIds)
      const kept = prev.filter((id) => live.has(id))
      const added = liveIds.filter((id) => !kept.includes(id))
      return [...kept, ...added]
    })
  }, [model.projects])

  useEffect(() => {
    const onMouseDown = (event: MouseEvent): void => {
      const target = event.target as Element | null
      if (target?.closest('.tree-menu-wrap')) return
      closeOpenMenus()
    }
    const onKeyDown = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') closeOpenMenus()
    }
    document.addEventListener('mousedown', onMouseDown)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onMouseDown)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [])

  // Focus + select-all ONCE when a pane rename starts (keyed on the pane identity, not the whole draft).
  // Depending on `paneRenameDraft` re-ran this on every keystroke (each onChange makes a new draft),
  // re-selecting all text so the next character replaced the selection — you could only type one char.
  useEffect(() => {
    if (!paneRenameDraft) return
    const input = paneRenameInputRef.current
    if (!input) return
    input.focus()
    input.select()
  }, [paneRenameDraft?.tab_id])

  // Same one-time focus+select for the in-place project / window renames (keyed on identity).
  useEffect(() => {
    if (!renameDraft) return
    const input = projectRenameInputRef.current
    if (!input) return
    input.focus()
    input.select()
  }, [renameDraft?.project_id])

  useEffect(() => {
    if (!windowRenameDraft) return
    const input = windowRenameInputRef.current
    if (!input) return
    input.focus()
    input.select()
  }, [windowRenameDraft?.window_id])

  const projectById = new Map(model.projects.map((p) => [p.project_id, p]))
  const orderedProjects = [
    ...orderedProjectIds.map((id) => projectById.get(id)).filter((p): p is ProjectCardView => !!p),
    ...model.projects.filter((p) => !orderedProjectIds.includes(p.project_id)),
  ]

  const toggleProject = (id: string): void =>
    setExpandedProjects((p) => ({ ...p, [id]: !(p[id] ?? id === selectedId) }))
  const selectProjectAndExpand = (id: string): void => {
    setExpandedProjects((p) => ({ ...p, [id]: true }))
    onSelect(id)
  }
  const toggleWindow = (key: string): void =>
    setExpandedWindows((p) => ({ ...p, [key]: !p[key] }))

  const projectDropEdge = (e: React.DragEvent<HTMLElement>, element: HTMLElement): 'before' | 'after' => {
    const rect = element.getBoundingClientRect()
    return e.clientY < rect.top + rect.height / 2 ? 'before' : 'after'
  }

  const WINDOW_DND_MIME = 'application/x-hydra-window-id'

  const windowDropEdge = (
    e: React.DragEvent<HTMLElement>,
    element: HTMLElement,
  ): 'before' | 'after' => {
    const rect = element.getBoundingClientRect()
    return e.clientY < rect.top + rect.height / 2 ? 'before' : 'after'
  }

  const moveProject = (fromId: string, toId: string, edge: 'before' | 'after'): void => {
    if (fromId === toId) return
    const ids = orderedProjects.map((p) => p.project_id)
    const from = ids.indexOf(fromId)
    let to = ids.indexOf(toId)
    if (from < 0 || to < 0) return
    const next = [...ids]
    const [moved] = next.splice(from, 1)
    if (from < to) to -= 1
    if (edge === 'after') to += 1
    next.splice(to, 0, moved)
    setOrderedProjectIds(next)
    onReorder(next)
  }

  const moveWindow = (
    projectId: string,
    windows: DashboardWindow[],
    fromId: string,
    toId: string,
    edge: 'before' | 'after',
  ): void => {
    if (fromId === toId) return
    const ids = windows.map((w) => w.window_id)
    const from = ids.indexOf(fromId)
    let to = ids.indexOf(toId)
    if (from < 0 || to < 0) return
    const next = [...ids]
    const [moved] = next.splice(from, 1)
    if (from < to) to -= 1
    if (edge === 'after') to += 1
    next.splice(to, 0, moved)
    onWindowReorder(projectId, next)
  }

  const armStashedPaneDrag = (
    projectId: string,
    windowId: string,
    tabId: string,
    sessionId: string,
  ): void => {
    const key = paneMenuKey(projectId, windowId, tabId)
    setStashedDragKey(key)
    bridge.beginStashedPaneDrag(projectId, windowId, tabId, sessionId)
  }

  // While a stashed pane is being dragged, forward the LIVE cursor to the native renderer so the drop
  // PREVIEW highlight tracks the pointer. Without this, moveStashedPaneDrag was never called, so the
  // highlight stayed at a stale position while the drop (onDragEnd) landed elsewhere — the preview and
  // the actual drop disagreed. The window-level `dragover` gives reliable clientX/clientY (HTML5
  // `onDrag` often reports 0,0). Only active while a stashed drag is in flight.
  useEffect(() => {
    if (!stashedDragKey) return
    const onDragOver = (e: DragEvent): void => {
      // 0,0 is the spurious "no position" report some browsers emit; ignore it.
      if (e.clientX === 0 && e.clientY === 0) return
      bridge.moveStashedPaneDrag(e.clientX, e.clientY)
    }
    window.addEventListener('dragover', onDragOver)
    return () => window.removeEventListener('dragover', onDragOver)
  }, [stashedDragKey])

  const cancelStashedPaneDrag = (): void => {
    setStashedDragKey(null)
    bridge.cancelStashedPaneDrag()
  }

  const pickUpStashedPane = (
    event: React.MouseEvent<HTMLButtonElement>,
    projectId: string,
    windowId: string,
    tabId: string,
    sessionId: string,
  ): void => {
    if (event.button !== 0) return
    event.preventDefault()
    event.stopPropagation()
    const key = paneMenuKey(projectId, windowId, tabId)
    if (stashedDragKey === key) {
      cancelStashedPaneDrag()
      return
    }
    armStashedPaneDrag(projectId, windowId, tabId, sessionId)
  }

  const reviveStashedPane = (projectId: string, windowId: string, tabId: string, sessionId: string): void => {
    const key = paneMenuKey(projectId, windowId, tabId)
    if (stashedDragKey === key) {
      cancelStashedPaneDrag()
    }
    bridge.reviveSession(sessionId, windowId, tabId)
  }


  const openCreateProject = (): void => {
    bridge.openProjectDialog()
    setOpenProjectMenuId(null)
  }

  const startRenameProject = (project: ProjectCardView): void => {
    setRenameDraft({ project_id: project.project_id, name: project.name })
    setOpenProjectMenuId(null)
  }

  const startEditProject = (project: ProjectCardView, detail: ProjectDetail | undefined): void => {
    void detail
    bridge.openEditProjectDialog(project.project_id)
    setOpenProjectMenuId(null)
  }

  const startDeleteProject = (project: ProjectCardView, detail: ProjectDetail | undefined): void => {
    setDeleteDraft({
      project_id: project.project_id,
      name: project.name,
      root: detail?.root ?? '',
      runtime_label: `hydra-${project.project_id}`,
      open_count: detail?.windows.reduce((sum, w) => sum + w.tabs.filter((t) => !t.stashed).length, 0) ?? 0,
      remove_record: true,
      keep_working_directory: true,
      close_open_windows: true,
    })
    setOpenProjectMenuId(null)
  }

  const startNewWindow = (project: ProjectCardView, _detail: ProjectDetail | undefined): void => {
    bridge.openWindowDialog(project.project_id)
    setOpenProjectMenuId(null)
  }

  const openProjectActions = (projectId: string): void => {
    setOpenWindowMenuKey(null)
    setOpenPaneMenuKey(null)
    setOpenProjectMenuId((id) => (id === projectId ? null : projectId))
  }

  const windowMenuKey = (projectId: string, windowId: string): string => `${projectId}:${windowId}`
  const paneMenuKey = (projectId: string, windowId: string, tabId: string): string =>
    `${projectId}:${windowId}:${tabId}`

  const openWindowActions = (projectId: string, windowId: string): void => {
    const key = windowMenuKey(projectId, windowId)
    setOpenProjectMenuId(null)
    setOpenPaneMenuKey(null)
    setOpenWindowMenuKey((id) => (id === key ? null : key))
  }

  const openPaneActions = (projectId: string, windowId: string, tabId: string): void => {
    const key = paneMenuKey(projectId, windowId, tabId)
    setOpenProjectMenuId(null)
    setOpenWindowMenuKey(null)
    setOpenPaneMenuKey((id) => (id === key ? null : key))
  }

  const reviveWindowPanes = (targetWindow: DashboardWindow): void => {
    targetWindow.tabs
      .filter((tab) => tab.stashed)
      .forEach((pane, index) => {
        globalThis.setTimeout(
          () => bridge.reviveSession(pane.session_id, targetWindow.window_id, pane.tab_id),
          index * 35,
        )
      })
  }

  const reopenExitedWindowPanes = (targetWindow: DashboardWindow): void => {
    targetWindow.tabs
      .filter((tab) => !tab.stashed && tab.session_status === 'exited')
      .forEach((pane, index) => {
        globalThis.setTimeout(
          () => bridge.reviveSession(pane.session_id, targetWindow.window_id, pane.tab_id),
          index * 35,
        )
      })
  }

  const startRenameWindow = (projectId: string, windowId: string): void => {
    const windowName =
      model.details[projectId]?.windows.find((window) => window.window_id === windowId)?.name ??
      windowId
    setWindowRenameDraft({ project_id: projectId, window_id: windowId, name: windowName })
    setOpenWindowMenuKey(null)
  }

  const startRenamePane = (
    projectId: string,
    windowId: string,
    tabId: string,
    name: string,
  ): void => {
    closeOpenMenus()
    setPaneRenameDraft({ project_id: projectId, window_id: windowId, tab_id: tabId, name })
  }

  const changeWindowFolder = async (projectId: string, windowId: string): Promise<void> => {
    setOpenWindowMenuKey(null)
    const root = await bridge.pickProjectFolder()
    if (!root) return
    bridge.updateWindow({ project_id: projectId, window_id: windowId, root })
  }

  const submitRenamePane = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault()
    commitPaneRename()
  }

  const commitPaneRename = (): void => {
    if (!paneRenameDraft) return
    const name = paneRenameDraft.name.trim()
    if (!name) {
      setPaneRenameDraft(null)
      return
    }
    bridge.updatePane(
      paneRenameDraft.project_id,
      paneRenameDraft.window_id,
      paneRenameDraft.tab_id,
      name,
    )
    setPaneRenameDraft(null)
  }

  const paneRenameKey = (draft: PaneRenameDraft | null): string | null =>
    draft ? paneMenuKey(draft.project_id, draft.window_id, draft.tab_id) : null


  // Commit an in-place project rename (onBlur / Enter): persist a non-empty name, then close the editor.
  const commitProjectRename = (): void => {
    if (!renameDraft) return
    const name = renameDraft.name.trim()
    if (name) bridge.updateProject({ project_id: renameDraft.project_id, name })
    setRenameDraft(null)
  }
  const commitWindowRename = (): void => {
    if (!windowRenameDraft) return
    const name = windowRenameDraft.name.trim()
    if (name) bridge.updateWindow({ ...windowRenameDraft, name })
    setWindowRenameDraft(null)
  }

  const submitDeleteProject = (): void => {
    if (!deleteDraft) return
    bridge.deleteProject(deleteDraft)
    setExpandedProjects((prev) => {
      const next = { ...prev }
      delete next[deleteDraft.project_id]
      return next
    })
    setDeleteDraft(null)
  }

  return (
    <nav
      className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''}`}
      aria-label="Projects, windows and panes"
    >
      <div className="sidebar__brand">
        <span className="sidebar__brand-glyph" aria-hidden>
          <span className="sidebar__brand-letter">H</span>
        </span>
        <span className="sidebar__brand-name">Hydra</span>
        {model.attention_count > 0 && (
          <span className="pill pill--attention" title="Tabs needing attention">
            {model.attention_count}
          </span>
        )}
        {onToggleCollapsed && (
          <button
            type="button"
            className="sidebar__collapse"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            onClick={onToggleCollapsed}
          >
            {collapsed ? '>' : '‹'}
          </button>
        )}
      </div>

      <div className="tree" role="tree">
        {model.projects.length === 0 && (
          <div className="tree-empty">
            <div className="tree-empty__title">No projects</div>
            <div className="tree-empty__hint">Open or record a workspace to populate this sidebar.</div>
          </div>
        )}
        {orderedProjects.map((p: ProjectCardView, i) => {
          const detail = model.details[p.project_id]
          const accent = p.accent_color ?? '#5b6470'
          const isSel = p.project_id === selectedId
          const hasWindows = (detail?.windows.length ?? 0) > 0
          const isOpen = expandedProjects[p.project_id] ?? isSel
          const sum = projectSummary(detail)
          const projStatus: SessionStatus =
            sum.running > 0 ? 'live' : sum.total > 0 ? 'exited' : 'unknown'

          return (
            <div
              key={p.project_id}
              className={`tree-project ${isSel ? 'is-selected' : ''} ${
                dragProjectId === p.project_id ? 'is-dragging' : ''
              } ${dropTarget?.id === p.project_id ? `is-drop-${dropTarget.edge}` : ''}`}
              style={{ ['--accent' as string]: accent }}
              role="treeitem"
              aria-expanded={hasWindows ? isOpen : undefined}
              onDragOver={(e) => {
                if (!dragProjectId || dragProjectId === p.project_id) return
                e.preventDefault()
                e.dataTransfer.dropEffect = 'move'
                setDropTarget({
                  id: p.project_id,
                  edge: projectDropEdge(e, e.currentTarget),
                })
              }}
              onDragLeave={(e) => {
                if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
                  setDropTarget((target) => (target?.id === p.project_id ? null : target))
                }
              }}
              onDrop={(e) => {
                e.preventDefault()
                const fromId = e.dataTransfer.getData('text/plain') || dragProjectId
                const edge = projectDropEdge(e, e.currentTarget)
                if (fromId) moveProject(fromId, p.project_id, edge)
                setDragProjectId(null)
                setDropTarget(null)
              }}
            >
              <span className="tree-project__accent" aria-hidden />
              <div
                className="tree-row tree-row--project"
                draggable
                onDragStart={(e) => {
                  e.dataTransfer.effectAllowed = 'move'
                  e.dataTransfer.setData('text/plain', p.project_id)
                  setDragProjectId(p.project_id)
                }}
                onDragEnd={() => {
                  setDragProjectId(null)
                  setDropTarget(null)
                }}
                onContextMenu={(e) => {
                  if (collapsed) return
                  e.preventDefault()
                  setOpenWindowMenuKey(null)
                  setOpenPaneMenuKey(null)
                  setOpenProjectMenuId(p.project_id)
                }}
              >
                <button
                  type="button"
                  className="tree-chevron"
                  disabled={!hasWindows}
                  aria-label={isOpen ? 'Collapse' : 'Expand'}
                  onClick={() => {
                    if (!collapsed) toggleProject(p.project_id)
                  }}
                >
                  {!collapsed && hasWindows ? (isOpen ? '▾' : '▸') : ''}
                </button>
                <button
                  type="button"
                  className="tree-label"
                  aria-current={isSel ? 'true' : undefined}
                  onClick={() => selectProjectAndExpand(p.project_id)}
                  onDoubleClick={(e) => {
                    if (collapsed) return
                    e.preventDefault()
                    e.stopPropagation()
                    startRenameProject(p)
                  }}
                  onKeyDown={(e) => {
                    if (!e.altKey || (e.key !== 'ArrowUp' && e.key !== 'ArrowDown')) return
                    e.preventDefault()
                    const ids = orderedProjects.map((x) => x.project_id)
                    const j = e.key === 'ArrowUp' ? i - 1 : i + 1
                    if (j < 0 || j >= ids.length) return
                    ;[ids[i], ids[j]] = [ids[j], ids[i]]
                    setOrderedProjectIds(ids)
                    onReorder(ids)
                  }}
                >
                  <span className={`dot ${statusDotClass(projStatus, false)}`} aria-hidden />
                  <span className="tree-project__icon" style={{ color: accent }}>
                    {p.icon ?? '◆'}
                  </span>
                  {!collapsed &&
                    (renameDraft?.project_id === p.project_id ? (
                      <input
                        ref={projectRenameInputRef}
                        className="tree-rename-input"
                        value={renameDraft.name}
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) =>
                          setRenameDraft((d) => d && { ...d, name: e.target.value })
                        }
                        onBlur={commitProjectRename}
                        onKeyDown={(e) => {
                          e.stopPropagation()
                          if (e.key === 'Enter') {
                            e.preventDefault()
                            commitProjectRename()
                          } else if (e.key === 'Escape') {
                            e.preventDefault()
                            setRenameDraft(null)
                          }
                        }}
                      />
                    ) : (
                      <span className="tree-project__name">{p.name}</span>
                    ))}
                  {!collapsed && sum.total > 0 && (
                    <span className="tree-summary">
                      <span className="tree-agents">
                        {sum.agents.map((a) => (
                          <AgentBadge key={a} agent={a} size={12} />
                        ))}
                      </span>
                      <span
                        className={`count-pill ${sum.running > 0 ? 'is-live' : ''}`}
                        title={`${sum.running} running / ${sum.total} open`}
                      >
                        {sum.running}/{sum.total}
                      </span>
                    </span>
                  )}
                </button>
                {!collapsed && (
                  <button
                    type="button"
                    className="tree-add"
                    title="New window"
                    onClick={() => startNewWindow(p, detail)}
                  >
                    +
                  </button>
                )}
	                {!collapsed && <div className="tree-menu-wrap">
	                  <button
	                    type="button"
	                    className="tree-more"
	                    title="Project actions"
	                    aria-expanded={openProjectMenuId === p.project_id}
	                    onClick={() => openProjectActions(p.project_id)}
	                  >
	                    ···
	                  </button>
	                  {openProjectMenuId === p.project_id && (
	                    <div className="project-menu" role="menu">
	                      <button type="button" role="menuitem" onClick={() => startRenameProject(p)}>
	                        Rename
	                      </button>
	                      <button
	                        type="button"
	                        role="menuitem"
	                        onClick={() => startEditProject(p, detail)}
	                      >
	                        Edit project…
	                      </button>
	                      <button
	                        type="button"
	                        role="menuitem"
	                        onClick={() => {
	                          startNewWindow(p, detail)
	                          setOpenProjectMenuId(null)
	                        }}
	                      >
	                        New window
	                      </button>
	                      <button
	                        type="button"
	                        role="menuitem"
	                        className="is-danger"
	                        onClick={() => startDeleteProject(p, detail)}
	                      >
                        Delete project…
                      </button>
                    </div>
                  )}
	                </div>}
	              </div>
	
	              {!collapsed &&
                isOpen &&
	                hasWindows &&
	                (detail?.windows ?? []).map((w) => {
                  const projectWindows = detail?.windows ?? []
                  const visibleWindowCount = projectWindows.filter(
                    (window) => !window.stashed && window.tabs.some((tab) => !tab.stashed),
                  ).length
                  const winKey = `${p.project_id}:${w.window_id}`
                  const hasPanes = w.tabs.length > 0
                  const isFocused = w.window_id === focusedWindowId
                  const winOpen = expandedWindows[winKey] ?? (isFocused || isSel)
                  const menuKey = windowMenuKey(p.project_id, w.window_id)
                  const paneMenuOpenInWindow = w.tabs.some(
                    (tab) =>
                      openPaneMenuKey === paneMenuKey(p.project_id, tab.window_id, tab.tab_id),
                  )
                  const isWindowStashed =
                    Boolean(w.stashed) || (w.tabs.length > 0 && w.tabs.every((tab) => tab.stashed))
                  const firstStashedPane = w.tabs.find((tab) => tab.stashed)
                  const visiblePanes = w.tabs.filter((tab) => !tab.stashed)
                  const allVisiblePanesExited =
                    visiblePanes.length > 0 &&
                    visiblePanes.every((tab) => tab.session_status === 'exited')
                  const canCloseWindow = !isWindowStashed && visibleWindowCount > 1
                  const windowDropBefore =
                    windowDropTarget?.windowId === w.window_id &&
                    windowDropTarget.edge === 'before'
                  const windowDropAfter =
                    windowDropTarget?.windowId === w.window_id &&
                    windowDropTarget.edge === 'after'
                  return (
                    <div
                      key={w.window_id}
                      className={`tree-window ${
                        dragWindow?.windowId === w.window_id ? 'is-dragging' : ''
                      } ${windowDropBefore ? 'is-drop-before' : ''} ${
                        windowDropAfter ? 'is-drop-after' : ''
                      } ${openWindowMenuKey === menuKey || paneMenuOpenInWindow ? 'is-menu-open' : ''}`}
                      role="group"
                      onDragOver={(e) => {
                        if (
                          !dragWindow ||
                          dragWindow.projectId !== p.project_id ||
                          !e.dataTransfer.types.includes(WINDOW_DND_MIME)
                        ) {
                          return
                        }
                        e.preventDefault()
                        e.stopPropagation()
                        e.dataTransfer.dropEffect = 'move'
                        const edge = windowDropEdge(e, e.currentTarget)
                        if (
                          windowDropTarget?.windowId !== w.window_id ||
                          windowDropTarget.edge !== edge
                        ) {
                          setWindowDropTarget({ windowId: w.window_id, edge })
                        }
                      }}
                      onDragLeave={(e) => {
                        if (!e.currentTarget.contains(e.relatedTarget as Node | null)) {
                          setWindowDropTarget((target) =>
                            target?.windowId === w.window_id ? null : target,
                          )
                        }
                      }}
                      onDrop={(e) => {
                        if (
                          !dragWindow ||
                          dragWindow.projectId !== p.project_id ||
                          !e.dataTransfer.types.includes(WINDOW_DND_MIME)
                        ) {
                          return
                        }
                        e.preventDefault()
                        e.stopPropagation()
                        const fromId = e.dataTransfer.getData(WINDOW_DND_MIME) || dragWindow.windowId
                        moveWindow(
                          p.project_id,
                          projectWindows,
                          fromId,
                          w.window_id,
                          windowDropEdge(e, e.currentTarget),
                        )
                        setDragWindow(null)
                        setWindowDropTarget(null)
                      }}
                    >
                      <div
                        className={`tree-row tree-row--window ${isFocused ? 'is-focused' : ''} ${isWindowStashed ? 'is-stashed' : ''} ${allVisiblePanesExited ? 'is-restartable' : ''} ${openWindowMenuKey === menuKey ? 'is-menu-open' : ''}`}
                        draggable
                        onDragStart={(e) => {
                          e.stopPropagation()
                          e.dataTransfer.effectAllowed = 'move'
                          e.dataTransfer.setData(WINDOW_DND_MIME, w.window_id)
                          e.dataTransfer.setData('text/plain', w.name || w.window_id)
                          setDragWindow({ projectId: p.project_id, windowId: w.window_id })
                        }}
                        onDragEnd={() => {
                          setDragWindow(null)
                          setWindowDropTarget(null)
                        }}
                        onContextMenu={(e) => {
                          e.preventDefault()
                          setOpenProjectMenuId(null)
                          setOpenPaneMenuKey(null)
                          setOpenWindowMenuKey(menuKey)
                        }}
                      >
                        <button
                          type="button"
                          className="tree-chevron tree-chevron--nested"
                          disabled={!hasPanes}
                          aria-label={winOpen ? 'Collapse' : 'Expand'}
                          onClick={() => toggleWindow(winKey)}
                        >
                          {hasPanes ? (winOpen ? '▾' : '▸') : ''}
                        </button>
                        <button
                          type="button"
                          className="tree-label"
                          onClick={() => {
                            if (isWindowStashed && firstStashedPane) {
                              reviveWindowPanes(w)
                            } else if (allVisiblePanesExited) {
                              reopenExitedWindowPanes(w)
                            } else {
                              onFocusWindow(w.window_id)
                            }
                          }}
                          onDoubleClick={(e) => {
                            e.preventDefault()
                            e.stopPropagation()
                            startRenameWindow(p.project_id, w.window_id)
                          }}
                          title={
                            isWindowStashed
                              ? 'Click to revive window'
                              : allVisiblePanesExited
                                ? 'Exited — click to reopen window'
                                : 'Click to focus window'
                          }
                          aria-label={
                            isWindowStashed
                              ? `Revive ${w.name || w.window_id}`
                              : allVisiblePanesExited
                                ? `Reopen ${w.name || w.window_id}`
                                : `Focus ${w.name || w.window_id}`
                          }
                        >
                          <span
                            className={`dot dot--sm ${statusDotClass(windowStatus(w), isWindowStashed)}`}
                            aria-hidden
                          />
                          {windowRenameDraft?.window_id === w.window_id ? (
                            <input
                              ref={windowRenameInputRef}
                              className="tree-rename-input"
                              value={windowRenameDraft.name}
                              onClick={(e) => e.stopPropagation()}
                              onChange={(e) =>
                                setWindowRenameDraft((d) => d && { ...d, name: e.target.value })
                              }
                              onBlur={commitWindowRename}
                              onKeyDown={(e) => {
                                e.stopPropagation()
                                if (e.key === 'Enter') {
                                  e.preventDefault()
                                  commitWindowRename()
                                } else if (e.key === 'Escape') {
                                  e.preventDefault()
                                  setWindowRenameDraft(null)
                                }
                              }}
                            />
                          ) : (
                            <span className="tree-window__name">{w.name || w.window_id}</span>
                          )}
                          <span className="tree-window__count">
                            {allVisiblePanesExited
                              ? 'Reopen'
                              : w.tabs.filter((t) => !t.stashed).length}
                          </span>
                        </button>
                        <div
                          className={`tree-menu-wrap ${openWindowMenuKey === menuKey ? 'is-open' : ''}`}
                        >
                          <button
                            type="button"
                            className="tree-more"
                            title="Window actions"
                            aria-expanded={openWindowMenuKey === menuKey}
                            onClick={() => openWindowActions(p.project_id, w.window_id)}
                          >
                            ···
                          </button>
                          {openWindowMenuKey === menuKey && (
                            <div className="project-menu" role="menu">
                              <button
                                type="button"
                                role="menuitem"
                                onClick={() => startRenameWindow(p.project_id, w.window_id)}
                              >
                                Rename
                              </button>
                              <button
                                type="button"
                                role="menuitem"
                                onClick={() => void changeWindowFolder(p.project_id, w.window_id)}
                              >
                                Change folder…
                              </button>
                              <button
                                type="button"
                                role="menuitem"
                                disabled={!isWindowStashed || !firstStashedPane}
                                onClick={() => {
                                  setOpenWindowMenuKey(null)
                                  if (!firstStashedPane) return
                                  reviveWindowPanes(w)
                                }}
                              >
                                Revive
                              </button>
                              <button
                                type="button"
                                role="menuitem"
                                disabled={!canCloseWindow}
                                onClick={() => {
                                  setOpenWindowMenuKey(null)
                                  bridge.stashWindow(p.project_id, w.window_id)
                                }}
                              >
                                Close (stash)
                              </button>
                              <button
                                type="button"
                                role="menuitem"
                                className="is-danger"
                                disabled={visibleWindowCount <= 1 && !isWindowStashed}
                                onClick={() => {
                                  setOpenWindowMenuKey(null)
                                  bridge.removeWindow(p.project_id, w.window_id)
                                }}
                              >
                                Remove from shelf
                              </button>
                            </div>
                          )}
                        </div>
                      </div>

                      {winOpen &&
                        w.tabs.map((t) => {
                          const pMenuKey = paneMenuKey(p.project_id, t.window_id, t.tab_id)
                          const livePaneCount =
                            detail?.windows.reduce(
                              (sum, window) => sum + window.tabs.filter((tab) => !tab.stashed).length,
                              0,
                            ) ?? 0
                          return (
                            <div
                              key={t.tab_id}
                              className={`tree-row tree-row--pane ${
                                isFocused ? 'is-active-window-pane' : 'is-inactive-window-pane'
                              } ${t.stashed ? 'is-stashed' : ''} ${
                                stashedDragKey === pMenuKey ? 'is-picked' : ''
                              } ${!t.stashed && t.session_status === 'exited' ? 'is-restartable' : ''} ${openPaneMenuKey === pMenuKey ? 'is-menu-open' : ''}`}
                              draggable={t.stashed}
                              onDragStart={(e) => {
                                if (!t.stashed) return
                                e.stopPropagation()
                                e.dataTransfer.effectAllowed = 'move'
                                e.dataTransfer.setData('application/x-hydra-pane-id', t.tab_id)
                                e.dataTransfer.setData('text/plain', t.title)
                                e.dataTransfer.setDragImage(e.currentTarget, 24, 14)
                                armStashedPaneDrag(
                                  p.project_id,
                                  t.window_id,
                                  t.tab_id,
                                  t.session_id,
                                )
                              }}
                              onDragEnd={(e) => {
                                if (!t.stashed) return
                                if (e.clientX === 0 && e.clientY === 0) return
                                bridge.completeStashedPaneDrop(e.clientX, e.clientY)
                              }}
                              onClick={(e) => {
                                if (!t.stashed) return
                                if ((e.target as Element | null)?.closest('.tree-menu-wrap')) return
                                if ((e.target as Element | null)?.closest('.tree-pane__drag-handle')) return
                                e.preventDefault()
                                e.stopPropagation()
                                reviveStashedPane(p.project_id, t.window_id, t.tab_id, t.session_id)
                              }}
                              onContextMenu={(e) => {
                                e.preventDefault()
                                openPaneActions(p.project_id, t.window_id, t.tab_id)
                              }}
                            >
                              {paneRenameKey(paneRenameDraft) === pMenuKey ? (
                                <form
                                  className="tree-label tree-label--pane tree-pane__rename-form"
                                  onSubmit={submitRenamePane}
                                  onClick={(e) => e.stopPropagation()}
                                >
                                  <span
                                    className={`dot dot--xs ${statusDotClass(t.session_status, t.stashed)}`}
                                    aria-hidden
                                  />
                                  <AgentBadge agent={t.agent} size={11} dim={t.stashed} />
                                    <input
                                      ref={paneRenameInputRef}
                                      className="tree-pane__rename-input"
                                      value={paneRenameDraft?.name ?? ''}
                                      onChange={(e) =>
                                        setPaneRenameDraft(
                                          (draft) => draft && { ...draft, name: e.target.value },
                                        )
                                      }
                                      onBlur={commitPaneRename}
                                      onKeyDown={(e) => {
                                        if (e.key === 'Escape') {
                                          e.preventDefault()
                                          setPaneRenameDraft(null)
                                        }
                                      }}
                                    />
                                </form>
                              ) : (
                                <>
                                  {t.stashed && (
                                    <button
                                      type="button"
                                      className={`tree-pane__drag-handle ${
                                        stashedDragKey === pMenuKey ? 'is-dragging' : ''
                                      }`}
                                      title={
                                        stashedDragKey === pMenuKey
                                          ? 'Picked up: click a terminal pane edge to place'
                                          : 'Click to pick up this stashed pane'
                                      }
                                      aria-label={
                                        stashedDragKey === pMenuKey
                                          ? 'Cancel stashed pane placement'
                                          : 'Pick up stashed pane'
                                      }
                                      onMouseDown={(e) =>
                                        pickUpStashedPane(
                                          e,
                                          p.project_id,
                                          t.window_id,
                                          t.tab_id,
                                          t.session_id,
                                        )
                                      }
                                    >
                                      ⋮⋮
                                    </button>
                                  )}
                                <button
                                  type="button"
                                  className="tree-label tree-label--pane"
                                  onMouseDown={(e) => {
                                    if (e.detail !== 2) return
                                    e.preventDefault()
                                    e.stopPropagation()
                                    startRenamePane(p.project_id, t.window_id, t.tab_id, t.title)
                                  }}
                                  onClick={(e) => {
                                    if (t.stashed || t.session_status === 'exited') {
                                      e.stopPropagation()
                                    }
                                    if (e.detail > 1) return
                                    if (t.stashed) {
                                      reviveStashedPane(p.project_id, t.window_id, t.tab_id, t.session_id)
                                    } else if (t.session_status === 'exited') {
                                      bridge.reviveSession(t.session_id, t.window_id, t.tab_id)
                                    } else {
                                      onFocusWindow(t.window_id)
                                      bridge.focusSessionOrPane(
                                        p.project_id,
                                        t.window_id,
                                        t.tab_id,
                                        t.session_id,
                                      )
                                    }
                                  }}
                                  onDoubleClick={(e) => {
                                    e.preventDefault()
                                    e.stopPropagation()
                                    startRenamePane(p.project_id, t.window_id, t.tab_id, t.title)
                                  }}
                                  title={
                                    t.stashed
                                      ? 'Click to revive; use the grip to drag'
                                      : t.session_status === 'exited'
                                        ? 'Exited — click to reopen'
                                        : 'Click to focus pane'
                                  }
                                  aria-label={
                                    t.stashed
                                      ? `Revive ${t.title}`
                                      : t.session_status === 'exited'
                                        ? `Reopen ${t.title}`
                                        : `Focus ${t.title}`
                                  }
                                >
                                  <span
                                    className={`dot dot--xs ${statusDotClass(t.session_status, t.stashed)}`}
                                    aria-hidden
                                  />
                                  <AgentBadge agent={t.agent} size={11} dim={t.stashed} />
                                  <span className="tree-pane__name">{t.title}</span>
                                  {!t.stashed && t.session_status === 'exited' && (
                                    <span className="tree-pane__exit-status">Reopen</span>
                                  )}
                                  {t.needs_attention && (
                                    <span className="pill pill--attention" title="Needs attention">
                                      !
                                    </span>
                                  )}
                                  {t.stashed && <span className="tree-pane__revive">⟲</span>}
                                </button>
                                </>
                              )}
                              <div
                                className={`tree-menu-wrap ${openPaneMenuKey === pMenuKey ? 'is-open' : ''}`}
                              >
                                <button
                                  type="button"
                                  className="tree-more"
                                  title="Pane actions"
                                  aria-expanded={openPaneMenuKey === pMenuKey}
                                  onClick={() => openPaneActions(p.project_id, t.window_id, t.tab_id)}
                                >
                                  ···
                                </button>
                                {openPaneMenuKey === pMenuKey && (
                                  <div className="project-menu" role="menu">
                                    <button
                                      type="button"
                                      role="menuitem"
                                      onClick={() =>
                                        startRenamePane(p.project_id, t.window_id, t.tab_id, t.title)
                                      }
                                    >
                                      Rename
                                    </button>
                                    <button
                                      type="button"
                                      role="menuitem"
                                      disabled={t.stashed || livePaneCount <= 1}
                                      onClick={() => {
                                        setOpenPaneMenuKey(null)
                                        bridge.stashPane(p.project_id, t.window_id, t.tab_id)
                                      }}
                                    >
                                      Close (stash)
                                    </button>
                                    <button
                                      type="button"
                                      role="menuitem"
                                      className="is-danger"
                                      disabled={!t.stashed && livePaneCount <= 1}
                                      onClick={() => {
                                        setOpenPaneMenuKey(null)
                                        bridge.removePane(p.project_id, t.window_id, t.tab_id)
                                      }}
                                    >
                                      Remove from shelf
                                    </button>
                                  </div>
                                )}
                              </div>
                            </div>
                          )
                        })}
                    </div>
                  )
                })}
            </div>
          )
        })}
      </div>

      <div className="sidebar__footer">
        <div
          className="sidebar__update-status"
          role="status"
          aria-live="polite"
          aria-atomic="true"
        >
          {!collapsed &&
          model.update?.status === 'available' &&
          model.update.action_available &&
          model.update.latest_version
            ? `Hydra ${model.update.latest_version} update available.`
            : ''}
        </div>
        {!collapsed &&
          model.update?.status === 'available' &&
          model.update.action_available &&
          model.update.latest_version && (
            <button
              type="button"
              className="sidebar__update"
              aria-label={`Download Hydra ${model.update.latest_version} update`}
              title={`Opens the Hydra ${model.update.latest_version} download in your browser. Install it when ready; your running terminals stay open.`}
              onClick={() => bridge.openAvailableUpdate()}
            >
              <span className="sidebar__update-mark" aria-hidden>
                ↑
              </span>
              <span className="sidebar__update-copy">
                <span className="sidebar__update-title">Update available</span>
                <span className="sidebar__update-version">
                  v{model.update.latest_version} · current v{model.update.current_version}
                </span>
              </span>
              <span className="sidebar__update-action">Download</span>
            </button>
          )}
          <button
            type="button"
            className="sidebar__new-project"
            onClick={() => void openCreateProject()}
          >
            + New project
          </button>

        {!collapsed && filesystemModeMigration && (
          <section
            className={`sidebar__filesystem-migration is-${filesystemModeMigration.phase}`}
            role="alert"
            aria-label="Linux file and folder security update required"
            data-notice-id={filesystemModeMigration.notice_id}
          >
            <div className="sidebar__filesystem-migration-title">
              {filesystemModeMigration.phase === 'applied'
                ? 'File and folder security updated'
                : filesystemModeMigration.phase === 'interrupted'
                  ? 'Finish securing Hydra files and folders'
                  : 'Secure Hydra files and folders'}
            </div>
            <div className="sidebar__filesystem-migration-copy">
              {filesystemModeMigration.phase === 'applied'
                ? 'Hydra applied the fixed Linux file-and-folder permission update.'
                : filesystemModeMigration.phase === 'interrupted'
                  ? 'The update was interrupted. Retry the same fixed plan before Remote can start.'
                  : 'Hydra found older files and folders with group-write access. Review the exact changes before applying them.'}
            </div>
            <div className="sidebar__filesystem-migration-reversible">
              This change is reversible. Keep a rollback command below if you may need to restore an older mode.
            </div>
            <ul className="sidebar__filesystem-migration-changes">
              {filesystemModeMigration.changes.map((change) => {
                return (
                  <li key={change.path} className="sidebar__filesystem-migration-change">
                    <code className="sidebar__filesystem-migration-path">{change.path}</code>
                    <div className="sidebar__filesystem-migration-modes">
                      <span>{change.old_mode}</span>
                      <span aria-hidden>→</span>
                      <span>{change.new_mode}</span>
                    </div>
                    <div className="sidebar__filesystem-migration-rollback-label">Rollback</div>
                    <div className="sidebar__filesystem-migration-rollback">
                      <input
                        type="text"
                        readOnly
                        aria-label={`Rollback command for ${change.path}`}
                        value={change.rollback_command}
                        onFocus={(event) => event.currentTarget.select()}
                      />
                      <button
                        type="button"
                        aria-label={`Copy rollback command for ${change.path}`}
                        onClick={() => void copyRollbackCommand(change)}
                      >
                        {copiedRollbackPath === change.path ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                  </li>
                )
              })}
            </ul>
            <div className="sidebar__filesystem-migration-warning">
              Restoring these older modes may make Hydra Remote fail closed until the files and folders are secured again.
            </div>
            {(filesystemModeMigration.phase === 'interrupted' ||
              filesystemModeMigration.phase === 'applied') && (
              <div className="sidebar__filesystem-migration-recovery">
                Temporary recovery record:{' '}
                <code>{filesystemModeMigration.recovery_record_path}</code>.{' '}
                {filesystemModeMigration.phase === 'applied'
                  ? 'Got it removes this record.'
                  : 'After the retry succeeds, Got it removes this record.'}
              </div>
            )}
            <button
              type="button"
              className="sidebar__filesystem-migration-action"
              onClick={() => {
                if (filesystemModeMigration.phase === 'applied') {
                  bridge.acknowledgeRemoteFilesystemMigration(filesystemModeMigration.notice_id)
                } else {
                  bridge.applyRemoteFilesystemMigration(filesystemModeMigration.notice_id)
                }
              }}
            >
              {filesystemModeMigration.phase === 'applied' ? 'Got it' : 'Secure files and folders'}
            </button>
          </section>
        )}

        {!collapsed && remoteAvailable && desktopAccessNeedsAction && model.desktop_access && (
          <section
            className="sidebar__desktop-access"
            aria-label="Full Disk Access required"
            data-error-code={model.desktop_access.required_error_code}
          >
            <div className="sidebar__desktop-access-title">
              {model.desktop_access.onboarding_acknowledged
                ? 'Full Disk Access still needed'
                : 'Allow protected-folder access'}
            </div>
            <div className="sidebar__desktop-access-copy">
              Hydra needs Full Disk Access so a remote session can open projects in Desktop,
              Documents, Downloads, iCloud, or external drives while you are away.
            </div>
            <div className="sidebar__desktop-access-actions">
              <button
                type="button"
                className="sidebar__desktop-access-primary"
                onClick={() => bridge.openFullDiskAccessSettings()}
              >
                Open System Settings
              </button>
              <button
                type="button"
                className="sidebar__desktop-access-secondary"
                onClick={() => bridge.refreshDesktopAccess()}
              >
                Check Again
              </button>
            </div>
            <div className="sidebar__desktop-access-fallback">
              If the pane does not open, choose Privacy &amp; Security → Full Disk Access and enable
              Hydra on this Mac.
            </div>
          </section>
        )}

        {/* "Add Remote": one-time enrollment. The release-bound native host decides which Hydra web environment
            issued the code; the shared dashboard copy stays correct on both macOS and Linux. */}
        {!collapsed && remoteAvailable && !model.enrolled && (
          <div className="sidebar__add-remote" aria-busy={enrollPending}>
            <div className="sidebar__add-remote-hint">
              Get a one-time code from the Hydra web app, then paste it here to add this computer.
            </div>
            <div className="sidebar__add-remote-row">
              <input
                type="text"
                className="sidebar__add-remote-input"
                placeholder="Paste code"
                aria-label="Enrollment code"
                value={enrollCode}
                disabled={enrollPending || desktopAccessNeedsAction || filesystemMigrationPending}
                onChange={(e) => setEnrollCode(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    e.preventDefault()
                    submitEnrollment()
                  }
                }}
              />
              <button
                type="button"
                className="sidebar__add-remote-btn"
                disabled={
                  enrollPending ||
                  desktopAccessNeedsAction ||
                  filesystemMigrationPending ||
                  !enrollCode.trim()
                }
                onClick={submitEnrollment}
              >
                {enrollPending ? 'Adding…' : 'Add Remote'}
              </button>
            </div>
          </div>
        )}
        {!collapsed && remoteAvailable && model.enrolled && (
          <div className="sidebar__enrolled" title={`This computer is enrolled under ${model.account_id ?? 'your account'}`}>
            <span className="sidebar__enrolled-check" aria-hidden>✓</span>
            <span className="sidebar__enrolled-text">
              On account <span className="sidebar__enrolled-acct">{model.account_id ?? '—'}</span>
            </span>
            {/* Local escape hatch: ask the private extension to un-enroll this computer so the button flips back to
                "Add Remote". For state desynchronization or an intentional machine detach, the first click arms
                an inline confirmation and the second submits the request. */}
            <button
              type="button"
              className={`sidebar__remove-remote-btn${confirmRemoveRemote ? ' is-armed' : ''}`}
              title={
                confirmRemoveRemote
                  ? 'Click again to confirm un-enrolling this computer'
                  : 'Un-enroll this computer from the account (flips back to Add Remote)'
              }
              disabled={filesystemMigrationPending}
              onClick={() => {
                if (confirmRemoveRemote) {
                  setConfirmRemoveRemote(false)
                  bridge.removeRemote()
                } else {
                  setConfirmRemoveRemote(true)
                  window.setTimeout(() => setConfirmRemoveRemote(false), 4000)
                }
              }}
            >
              {confirmRemoveRemote ? 'Confirm remove?' : 'Remove Remote'}
            </button>
          </div>
        )}
        {!enrollPending && (model.enroll_error || enrollUiError) && (
          <div className="sidebar__add-remote-error" role="alert">
            {model.enroll_error ?? enrollUiError}
          </div>
        )}

        {/* Remote-access state is projected by the negotiated private extension. This control emits only an intent;
            the public app cannot write or bypass the effective private gate. */}
        {!collapsed && remoteAvailable && model.enrolled && (
          <button
            type="button"
            className={`sidebar__remote-toggle ${model.remote_open ? 'is-open' : 'is-closed'}`}
            title={
              model.remote_open
                ? 'Remote access is OPEN — a browser can reach this machine. Click to close.'
                : 'Remote access is CLOSED — no browser can reach this machine. Click to open.'
            }
            aria-label={model.remote_open ? 'Close remote access' : 'Open remote access'}
            disabled={filesystemMigrationPending}
            onClick={() => bridge.setRemoteAccess(!model.remote_open)}
          >
            <span className="sidebar__remote-toggle-label">
              {model.remote_open ? 'Close Remote' : 'Open Remote'}
            </span>
            <span className="sidebar__remote-toggle-dot" aria-hidden />
          </button>
        )}

      </div>


      {deleteDraft && (
        <div className="sidebar-create project-dialog project-dialog--danger" role="dialog">
          <div className="sidebar-create__header">
            <div>
              <div className="sidebar-create__title">Delete project</div>
              <div className="sidebar-create__subtitle">{deleteDraft.name}</div>
            </div>
            <button
              type="button"
              className="sidebar-create__close"
              aria-label="Cancel"
              onClick={() => setDeleteDraft(null)}
            >
              ×
            </button>
          </div>
	          <div className="project-delete-copy">
	            This removes <strong>{deleteDraft.name}</strong> from the shelf and stops its live panes.
	            The working folder, project files, and provider session history remain on disk.
	          </div>
	          <label className="delete-option">
	            <input type="checkbox" checked={deleteDraft.close_open_windows} disabled readOnly />
	            <span>
	              <strong>Stop live panes</strong>
	              <span className="delete-option__hint">
	                <code>{deleteDraft.runtime_label}</code> — required
	              </span>
	            </span>
	          </label>
	          <label className="delete-option">
	            <input type="checkbox" checked={deleteDraft.remove_record} disabled readOnly />
	            <span>
	              <strong>Remove from shelf</strong>
	              <span className="delete-option__hint">project entry will be deleted</span>
	            </span>
	          </label>
	          <div className="sidebar-create__actions">
	            <button type="button" className="sidebar-create__danger" onClick={submitDeleteProject}>
	              Delete project
	            </button>
            <button
              type="button"
              className="sidebar-create__secondary"
              onClick={() => setDeleteDraft(null)}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </nav>
  )
}
