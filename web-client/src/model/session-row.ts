// Pure session-row derivation (R2). Turns one session id + the app view into the small set of display facts
// a sessions-list row needs — label (with id fallback), whether it's the ACTIVE (currently-attached) row,
// whether it's the quiet LAST OPENED hint, the visible row badges, the suffixed display label, and the edit-mode initial value. No DOM, no network, content-blind. Derived
// PER ID so callers map over view.sessions WITHOUT sorting (order preserved by the caller).
//
// "Active" == currently attached only (view.attachedSession). After detach the sessions view has
// attachedSession=null, so no row is active — that is intentional. "Last opened" has its OWN explicit view
// state and quiet copy; it must NOT reuse `isActive`.

import type { RemoteClientView } from '../bridge/remote-client.js'
import { applySessionOrder } from './session-order.js'
import { cleanHiddenSessions, visibleSessions } from './session-visibility.js'

export interface SessionRow {
  readonly id: string
  /** The custom label if set, else the session id (F1 fallback). */
  readonly label: string
  /** True only when this id is the currently-attached session (view.attachedSession). */
  readonly isActive: boolean
  /** Quiet hint for the last opened session when it is not currently active. */
  readonly isLastOpened: boolean
  /** True when the user pinned this session (browser-local favorites — §2#5). */
  readonly isFavorite: boolean
  /** Small non-action labels rendered beside the row. Content-blind: no terminal text. */
  readonly badges: readonly string[]
  /** True when this session has output activity since it was last focused/opened. Content-blind marker only. */
  readonly hasUnread: boolean
  /** The label shown on the open button — suffixes Active first, else Last opened. */
  readonly displayLabel: string
  /** The value the inline rename input is seeded with (the current display label). */
  readonly editValue: string
  /** Desktop-parity status dot. 'active' = the currently-attached session (highlighted, like the desktop's
   * focused tab); 'live' = a session the connected desktop reports in `view.sessions`. Mirrors the desktop
   * dashboard's tab status dot (dot--live). Honest: every session in `view.sessions` is live on the desktop. */
  readonly statusDot: 'active' | 'live'
}

/**
 * The display label for a session: the user's custom label if set, else the daemon-reported cwd basename, else
 * a FRIENDLY fallback ("Terminal N" by the session's position in the daemon's list) instead of the raw `s-…`
 * id. This is what gives parity with the desktop dashboard: sessions created on the desktop or in another
 * browser show readable project context, not cryptic ids. Stable per the daemon's session order; pure;
 * content-blind (no terminal output).
 */
export function sessionLabel(view: RemoteClientView, id: string): string {
  const custom = view.sessionLabels[id]
  if (custom) return custom
  const cwdLabel = cwdBasename(view.sessionCwds[id])
  if (cwdLabel) return cwdLabel
  const index = view.sessions.indexOf(id)
  return index >= 0 ? `Terminal ${index + 1}` : id
}

function cwdBasename(cwd: string | undefined): string | null {
  const trimmed = cwd?.trim()
  if (!trimmed) return null
  const withoutTrailing = trimmed.replace(/[\\/]+$/, '')
  if (!withoutTrailing) return '/'
  const parts = withoutTrailing.split(/[\\/]+/)
  return parts[parts.length - 1] || null
}

/** A run of sessions sharing one project root — the browser's honest echo of a desktop WINDOW (a project's
 * group of tabs). The project name is the session cwd's basename; sessions with no known cwd fall into a final
 * unnamed group (project = null) so nothing is hidden. */
export interface SessionGroup {
  /** The project label (cwd basename) for this group, or null for the "no known project" catch-all. */
  readonly project: string | null
  readonly rows: readonly SessionRow[]
  /** Aggregate status dot for the group header — mirrors the desktop's window aggregate (windowStatus):
   * 'active' if the attached session is in this group (highlighted, like the desktop's focused window), else
   * 'live' (every grouped session is reported live by the desktop). */
  readonly statusDot: 'active' | 'live'
}

/** Fallback header shown for the project=null catch-all group. */
export const UNGROUPED_PROJECT_LABEL = 'Other sessions'

/** The group's aggregate dot: 'active' if it holds the attached session, else 'live'. Mirrors the desktop's
 * windowStatus ("live if any live; highlighted when focused"). Honest — grouped sessions are all live. */
function groupStatusDot(rows: readonly SessionRow[]): 'active' | 'live' {
  return rows.some((r) => r.statusDot === 'active') ? 'active' : 'live'
}

/**
 * Group the visible session rows by project (cwd basename) — the browser's honest parity with the desktop's
 * Project→Window→tabs hierarchy, derived ONLY from the flat remote data we actually have (`view.sessionCwds`):
 * NO invented cloud project model. Groups appear in first-seen daemon order; within a group, sessions keep their
 * `orderedSessionRows` order (favorites-first, then daemon order). Sessions with no known cwd collect in a final
 * `project: null` group. Pure.
 */
export function groupSessionsByProject(view: RemoteClientView): SessionGroup[] {
  const order: (string | null)[] = []
  const byProject = new Map<string | null, SessionRow[]>()
  for (const row of orderedSessionRows(view)) {
    const project = cwdBasename(view.sessionCwds[row.id])
    let bucket = byProject.get(project)
    if (!bucket) {
      bucket = []
      byProject.set(project, bucket)
      if (project !== null) order.push(project) // named groups keep first-seen order; null sorts last
    }
    bucket.push(row)
  }
  if (byProject.has(null)) order.push(null) // the catch-all group always renders last
  return order.map((project) => {
    const rows = byProject.get(project)!
    return { project, rows, statusDot: groupStatusDot(rows) }
  })
}

/** Derive the row facts for ONE session id (preserves caller order — no sort). Pure given the view. */
export function sessionRowModel(view: RemoteClientView, id: string): SessionRow {
  const label = sessionLabel(view, id)
  const isActive = view.attachedSession === id
  const isLastOpened = !isActive && view.lastOpenedSessionId === id
  const isFavorite = view.favoriteSessions.includes(id)
  const hasUnread = view.unreadSessions.includes(id)
  return {
    id,
    label,
    isActive,
    isLastOpened,
    isFavorite,
    badges: isFavorite ? ['Pinned'] : [],
    hasUnread,
    displayLabel: isActive ? `${label} · Active` : isLastOpened ? `${label} · Last opened` : label,
    editValue: label,
    statusDot: isActive ? 'active' : 'live',
  }
}

/**
 * The session rows in DISPLAY order: pinned (favorite) sessions first, then the rest — each group keeping the
 * daemon's original relative order (a STABLE partition, no full sort). Pure given the view.
 */
export function orderedSessionRows(view: RemoteClientView): SessionRow[] {
  const rows = applySessionOrder(visibleSessions(view.sessions, view.hiddenSessions), view.sessionOrder)
    .map((id) => sessionRowModel(view, id))
  const favorites = rows.filter((r) => r.isFavorite)
  const rest = rows.filter((r) => !r.isFavorite)
  return [...favorites, ...rest]
}

/** Hidden-but-recoverable session ids in the same manual order they will use once unhidden. */
export function orderedHiddenSessionIds(view: RemoteClientView): string[] {
  const hidden = cleanHiddenSessions(view.hiddenSessions).filter((id) => view.sessions.includes(id))
  return applySessionOrder(hidden, view.sessionOrder)
}

/** Filter the already-ordered rows by session id or display label. Empty query keeps all rows. */
export function filteredSessionRows(view: RemoteClientView, query: string): SessionRow[] {
  const q = query.trim().toLocaleLowerCase()
  const rows = orderedSessionRows(view)
  if (!q) return rows
  return rows.filter((r) => r.id.toLocaleLowerCase().includes(q) || r.label.toLocaleLowerCase().includes(q))
}
