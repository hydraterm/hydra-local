import type { WorkspacePanes } from '../model/pane-layout.js'
import {
  parseRemoteLayoutRowJson,
  REMOTE_LAYOUT_SCHEMA_VERSION,
  serializeRemoteLayoutV3,
} from './remote-layout-schema.js'

/** Durable layout storage for the composition's current account, keyed by desktop device.
 * Implementations retain account isolation; callers retain connection-generation and hydration guards.
 * Values contain only the versioned content-blind layout DTO, never titles, paths or terminal content. */
export interface RemoteLayoutPort {
  fetchLayout: (deviceId: string) => Promise<string | null>
  putLayout: (deviceId: string, layoutJson: string) => void
}

/** Schema version of the persisted layout row. v1 was the BARE per-window map `{ [windowId]: WorkspacePanes }`;
 * v2 wrapped it as `{ v: 2, activeWindowId, windows }` so the browser also lands back on the window the user
 * was on (pane lifecycle contract Slice 2). v3 adds the REAL known-id ledger (rule R13,
 * pane lifecycle contract): `{ v: 3, activeWindowId, windows, known: { projects, windows, panes } }` — first
 * handoff is project-scoped and RECORDED, no longer inferred from window keys. Readers stay tolerant of v1
 * (no `v` key) and v2 (no `known`) rows. */
export const REMOTE_LAYOUT_SCHEMA_V = REMOTE_LAYOUT_SCHEMA_VERSION

/** R13: the persisted known-id ledger — ids the remote has recorded (handed-off). Content-blind. */
export interface RemoteLayoutKnownLedger {
  projects: string[]
  windows: string[]
  panes: string[]
}

/** The parsed durable layout row, version-normalized: the exact safe per-window DTO plus the active window
 * (null for v1 rows) and v3 known-id ledger (null for v1/v2 rows). */
export interface SavedRemoteLayout {
  activeWindowId: string | null
  windows: Record<string, WorkspacePanes>
  known: RemoteLayoutKnownLedger | null
}

/** Serialize the current per-window map + active window (+ the R13 known-id ledger) as a v3 row. */
export function serializeRemoteLayout(
  activeWindowId: string | null,
  windows: Record<string, WorkspacePanes>,
  known?: RemoteLayoutKnownLedger,
): string {
  const encoded = serializeRemoteLayoutV3(activeWindowId, windows, known)
  if (!encoded) throw new TypeError('remote layout state does not satisfy the bounded v3 schema')
  return encoded
}

/** Parse an exact safe v1/v2/v3 row. Unknown versions, fields, names, paths and malformed shapes fail closed. */
export function parseRemoteLayout(json: string): SavedRemoteLayout | null {
  const row = parseRemoteLayoutRowJson(json)
  if (!row) return null
  return {
    activeWindowId: row.activeWindowId,
    windows: row.windows as Record<string, WorkspacePanes>,
    known: row.known
      ? { projects: [...row.known.projects], windows: [...row.known.windows], panes: [...row.known.panes] }
      : null,
  }
}
