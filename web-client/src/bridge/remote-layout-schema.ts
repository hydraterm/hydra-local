// Exact content-blind wire schema for durable browser layouts. Keep this file byte-identical to
// web-client/src/bridge/remote-layout-schema.ts; the cross-wire test enforces that mirror.

export const REMOTE_LAYOUT_SCHEMA_VERSION = 3
export const REMOTE_LAYOUT_MAX_JSON_BYTES = 32 * 1024
export const REMOTE_LAYOUT_MAX_ID_BYTES = 128
export const REMOTE_LAYOUT_MAX_WINDOWS = 128
export const REMOTE_LAYOUT_MAX_STASHED_PANES = 256
export const REMOTE_LAYOUT_MAX_KNOWN_IDS = 512
export const REMOTE_LAYOUT_MAX_PANES = 4
export const REMOTE_LAYOUT_MAX_NODES = REMOTE_LAYOUT_MAX_PANES * 2 - 1
export const REMOTE_LAYOUT_MAX_NODE_DEPTH = REMOTE_LAYOUT_MAX_PANES - 1

export type RemoteLayoutSplitDirection = 'horizontal' | 'vertical'

export interface RemoteLayoutLeafDto {
  readonly kind: 'leaf'
  readonly id: string
  readonly sessionId: string | null
}

export interface RemoteLayoutSplitDto {
  readonly kind: 'split'
  readonly id: string
  readonly dir: RemoteLayoutSplitDirection
  readonly ratio: number
  readonly first: RemoteLayoutNodeDto
  readonly second: RemoteLayoutNodeDto
}

export type RemoteLayoutNodeDto = RemoteLayoutLeafDto | RemoteLayoutSplitDto

export interface RemoteLayoutPaneDto {
  readonly root: RemoteLayoutNodeDto
  readonly activePaneId: string
}

export interface RemoteLayoutStashedPaneDto {
  readonly paneId: string
  readonly sessionId: string | null
  readonly swappedOut?: boolean
}

export interface RemoteLayoutWorkspaceDto {
  readonly layout: RemoteLayoutPaneDto | null
  readonly stashed: readonly RemoteLayoutStashedPaneDto[]
  readonly windowStashed?: boolean
}

export interface RemoteLayoutKnownLedgerDto {
  readonly projects: readonly string[]
  readonly windows: readonly string[]
  readonly panes: readonly string[]
}

export interface ParsedRemoteLayoutRow {
  readonly version: 1 | 2 | 3
  readonly activeWindowId: string | null
  readonly windows: Readonly<Record<string, RemoteLayoutWorkspaceDto>>
  readonly known: RemoteLayoutKnownLedgerDto | null
}

type JsonRecord = Record<string, unknown>

function record(value: unknown): JsonRecord | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonRecord
    : null
}

function hasOwn(value: JsonRecord, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key)
}

function exactKeys(value: JsonRecord, required: readonly string[], optional: readonly string[] = []): boolean {
  if (required.some((key) => !hasOwn(value, key))) return false
  const allowed = new Set([...required, ...optional])
  return Object.keys(value).every((key) => allowed.has(key))
}

export function isRemoteLayoutId(value: unknown): value is string {
  return typeof value === 'string' &&
    value.length >= 1 &&
    value.length <= REMOTE_LAYOUT_MAX_ID_BYTES &&
    /^[A-Za-z0-9_-]+$/u.test(value) &&
    value !== '__proto__' &&
    value !== 'prototype' &&
    value !== 'constructor'
}

interface NodeState {
  readonly ids: Set<string>
  readonly leafIds: Set<string>
  nodeCount: number
  leafCount: number
}

function validSessionId(value: unknown, allowEmptySessionId: boolean): value is string | null {
  return value === null || isRemoteLayoutId(value) || (allowEmptySessionId && value === '')
}

function parseNode(
  value: unknown,
  depth: number,
  state: NodeState,
  strict: boolean,
  allowEmptySessionId: boolean,
): RemoteLayoutNodeDto | null {
  if (depth > REMOTE_LAYOUT_MAX_NODE_DEPTH || state.nodeCount >= REMOTE_LAYOUT_MAX_NODES) return null
  const obj = record(value)
  if (!obj || !isRemoteLayoutId(obj.id) || state.ids.has(obj.id)) return null

  if (obj.kind === 'leaf') {
    if (strict && !exactKeys(obj, ['kind', 'id', 'sessionId'])) return null
    const sessionId = !strict && obj.sessionId === '' ? null : obj.sessionId
    if (!validSessionId(sessionId, allowEmptySessionId)) return null
    state.ids.add(obj.id)
    state.leafIds.add(obj.id)
    state.nodeCount += 1
    state.leafCount += 1
    if (state.leafCount > REMOTE_LAYOUT_MAX_PANES) return null
    return { kind: 'leaf', id: obj.id, sessionId: sessionId as string | null }
  }

  if (obj.kind !== 'split') return null
  if (strict && !exactKeys(obj, ['kind', 'id', 'dir', 'ratio', 'first', 'second'])) return null
  if (obj.dir !== 'horizontal' && obj.dir !== 'vertical') return null
  if (typeof obj.ratio !== 'number' || !Number.isFinite(obj.ratio) || obj.ratio < 0.1 || obj.ratio > 0.9) {
    return null
  }
  state.ids.add(obj.id)
  state.nodeCount += 1
  const first = parseNode(obj.first, depth + 1, state, strict, allowEmptySessionId)
  if (!first) return null
  const second = parseNode(obj.second, depth + 1, state, strict, allowEmptySessionId)
  if (!second) return null
  return { kind: 'split', id: obj.id, dir: obj.dir, ratio: obj.ratio, first, second }
}

function parsePaneLayout(
  value: unknown,
  strict: boolean,
  allowEmptySessionId: boolean,
): { dto: RemoteLayoutPaneDto; nodeIds: Set<string> } | null {
  const obj = record(value)
  if (!obj || (strict && !exactKeys(obj, ['root', 'activePaneId'])) || !isRemoteLayoutId(obj.activePaneId)) {
    return null
  }
  const state: NodeState = { ids: new Set(), leafIds: new Set(), nodeCount: 0, leafCount: 0 }
  const root = parseNode(obj.root, 0, state, strict, allowEmptySessionId)
  if (!root || state.leafCount < 1 || !state.leafIds.has(obj.activePaneId)) return null
  return { dto: { root, activePaneId: obj.activePaneId }, nodeIds: state.ids }
}

function parseStashedPane(
  value: unknown,
  strict: boolean,
  allowEmptySessionId: boolean,
): RemoteLayoutStashedPaneDto | null {
  const obj = record(value)
  if (!obj || (strict && !exactKeys(obj, ['paneId', 'sessionId'], ['swappedOut']))) return null
  const sessionId = !strict && obj.sessionId === '' ? null : obj.sessionId
  if (!isRemoteLayoutId(obj.paneId) || !validSessionId(sessionId, allowEmptySessionId)) return null
  if (hasOwn(obj, 'swappedOut') && typeof obj.swappedOut !== 'boolean') return null
  return {
    paneId: obj.paneId,
    sessionId: sessionId as string | null,
    ...(hasOwn(obj, 'swappedOut') ? { swappedOut: obj.swappedOut as boolean } : {}),
  }
}

function parseWorkspace(value: unknown, strict: boolean, allowEmptySessionId: boolean): RemoteLayoutWorkspaceDto | null {
  const obj = record(value)
  if (!obj || (strict && !exactKeys(obj, ['layout', 'stashed'], ['windowStashed']))) return null
  if (!Array.isArray(obj.stashed) || obj.stashed.length > REMOTE_LAYOUT_MAX_STASHED_PANES) return null
  if (hasOwn(obj, 'windowStashed') && typeof obj.windowStashed !== 'boolean') return null

  const layoutResult = obj.layout === null ? null : parsePaneLayout(obj.layout, strict, allowEmptySessionId)
  if (obj.layout !== null && !layoutResult) return null
  const occupiedIds = layoutResult?.nodeIds ?? new Set<string>()
  const stashIds = new Set<string>()
  const stashed: RemoteLayoutStashedPaneDto[] = []
  for (const raw of obj.stashed) {
    const pane = parseStashedPane(raw, strict, allowEmptySessionId)
    if (!pane || occupiedIds.has(pane.paneId) || stashIds.has(pane.paneId)) return null
    stashIds.add(pane.paneId)
    stashed.push(pane)
  }

  return {
    layout: layoutResult?.dto ?? null,
    stashed,
    ...(hasOwn(obj, 'windowStashed') ? { windowStashed: obj.windowStashed as boolean } : {}),
  }
}

function parseWindows(
  value: unknown,
  strict: boolean,
  allowEmptySessionId = false,
): Record<string, RemoteLayoutWorkspaceDto> | null {
  const obj = record(value)
  if (!obj) return null
  const entries = Object.entries(obj)
  if (entries.length > REMOTE_LAYOUT_MAX_WINDOWS) return null
  const windows: Record<string, RemoteLayoutWorkspaceDto> = Object.create(null) as Record<string, RemoteLayoutWorkspaceDto>
  for (const [windowId, raw] of entries) {
    if (!isRemoteLayoutId(windowId)) return null
    const workspace = parseWorkspace(raw, strict, allowEmptySessionId)
    if (!workspace) return null
    windows[windowId] = workspace
  }
  return windows
}

function parseIdArray(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > REMOTE_LAYOUT_MAX_KNOWN_IDS) return null
  const seen = new Set<string>()
  const ids: string[] = []
  for (const raw of value) {
    if (!isRemoteLayoutId(raw) || seen.has(raw)) return null
    seen.add(raw)
    ids.push(raw)
  }
  return ids
}

function parseKnown(value: unknown, strict: boolean): RemoteLayoutKnownLedgerDto | null {
  const obj = record(value)
  if (!obj || (strict && !exactKeys(obj, ['projects', 'windows', 'panes']))) return null
  const projects = parseIdArray(obj.projects)
  const windows = parseIdArray(obj.windows)
  const panes = parseIdArray(obj.panes)
  return projects && windows && panes ? { projects, windows, panes } : null
}

function activeWindowId(value: unknown): string | null | undefined {
  if (value === null) return null
  return isRemoteLayoutId(value) ? value : undefined
}

/** Strictly parse an encoded persisted row. Unknown fields and unsafe legacy rows fail closed. */
export function parseRemoteLayoutRowJson(json: string): ParsedRemoteLayoutRow | null {
  // Every permitted string is ASCII, so JS code-unit length is also the encoded UTF-8 byte length.
  if (json.length > REMOTE_LAYOUT_MAX_JSON_BYTES) return null
  let raw: unknown
  try {
    raw = JSON.parse(json)
  } catch {
    return null
  }
  const obj = record(raw)
  if (!obj) return null

  if (obj.v === 2 || obj.v === 3) {
    const version = obj.v
    const optional = version === 3 ? ['known'] : []
    if (!exactKeys(obj, ['v', 'activeWindowId', 'windows'], optional)) return null
    const active = activeWindowId(obj.activeWindowId)
    const windows = parseWindows(obj.windows, true, version === 2)
    if (active === undefined || !windows) return null
    let known: RemoteLayoutKnownLedgerDto | null = null
    if (version === 3 && hasOwn(obj, 'known')) {
      known = parseKnown(obj.known, true)
      if (!known) return null
    }
    return { version, activeWindowId: active, windows, known }
  }

  // A numeric marker is a wrapper version, never a v1 window id. Unknown versions fail closed.
  if (typeof obj.v === 'number') return null
  const windows = parseWindows(obj, true, true)
  return windows ? { version: 1, activeWindowId: null, windows, known: null } : null
}

/** Canonical JSON removes duplicate raw keys and any non-semantic representation differences. */
export function stringifyRemoteLayoutRow(row: ParsedRemoteLayoutRow): string {
  if (row.version === 1) return JSON.stringify(row.windows)
  return JSON.stringify({
    v: row.version,
    activeWindowId: row.activeWindowId,
    windows: row.windows,
    ...(row.version === 3 && row.known ? { known: row.known } : {}),
  })
}

/** Validate and canonicalize an encoded row in one fail-closed operation. */
export function canonicalRemoteLayoutJson(json: string): string | null {
  const parsed = parseRemoteLayoutRowJson(json)
  if (!parsed) return null
  const encoded = stringifyRemoteLayoutRow(parsed)
  return encoded.length <= REMOTE_LAYOUT_MAX_JSON_BYTES ? encoded : null
}

/**
 * Project browser state into the exact v3 DTO. Unlike the strict parser this deliberately ignores unknown
 * source-object properties, so UI-only names/titles/paths can never enter the encoded cloud row.
 */
export function serializeRemoteLayoutV3(
  active: unknown,
  sourceWindows: unknown,
  sourceKnown?: unknown,
): string | null {
  const activeId = activeWindowId(active)
  if (activeId === undefined) return null
  const windows = parseWindows(sourceWindows, false)
  if (!windows) return null
  let known: RemoteLayoutKnownLedgerDto | null = null
  if (sourceKnown !== undefined) {
    known = parseKnown(sourceKnown, false)
    if (!known) return null
  }
  const encoded = JSON.stringify({
    v: REMOTE_LAYOUT_SCHEMA_VERSION,
    activeWindowId: activeId,
    windows,
    ...(known ? { known } : {}),
  })
  return encoded.length <= REMOTE_LAYOUT_MAX_JSON_BYTES ? encoded : null
}
