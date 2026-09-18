// Pure model for the terminal header's "Set current as default" workspace chip. A preset is a named snapshot of
// a pane layout — the split structure + which session each leaf held — that can be saved and later restored.
// DOM-free, storage-free, network-free. The old multi-preset management panel was removed; this model remains live
// only because the default-layout chip and fresh-connect default restore still use it.
//
// Restore rule (§8: "restore into live sessions where possible; launch fresh sessions when needed"): each
// saved leaf keeps its sessionId only if that session is still available; otherwise the leaf becomes a fresh
// (sessionId=null) slot the caller can spawn into. The split shape/ratios are always preserved.

import {
  deserializeLayout, leaves, serializeLayout, type PaneLayout, type PaneNode,
} from './pane-layout.js'

export interface LayoutPreset {
  readonly id: string
  readonly name: string
  readonly createdAtMs: number
  /** The saved pane layout (structure + session bindings at save time). */
  readonly layout: PaneLayout
}

export interface LayoutPresetState {
  readonly presets: readonly LayoutPreset[]
  /** Optional browser-local preset to prefer on a fresh desktop connect. */
  readonly defaultPresetId?: string | null
}

function cleanName(name: string): string {
  return name.trim().slice(0, 80)
}

/** Create a preset from the current layout. id/name/time are injected (pure + deterministic — no clock/uuid). */
export function createPreset(
  state: LayoutPresetState,
  input: { id: string; name: string; layout: PaneLayout; nowMs: number },
): LayoutPresetState {
  const name = cleanName(input.name) || 'Untitled layout'
  const preset: LayoutPreset = { id: input.id, name, createdAtMs: input.nowMs, layout: input.layout }
  return { ...state, presets: [...state.presets, preset] }
}

export function renamePreset(state: LayoutPresetState, id: string, name: string): LayoutPresetState {
  const clean = cleanName(name)
  if (!clean) return state // ignore blank renames
  return { ...state, presets: state.presets.map((p) => (p.id === id ? { ...p, name: clean } : p)) }
}

export function deletePreset(state: LayoutPresetState, id: string): LayoutPresetState {
  const presets = state.presets.filter((p) => p.id !== id)
  return state.defaultPresetId === id ? { presets } : { ...state, presets }
}

export function setDefaultPreset(state: LayoutPresetState, id: string | null): LayoutPresetState {
  if (id === null) return state.defaultPresetId ? { presets: state.presets } : state
  if (!state.presets.some((p) => p.id === id)) return state
  return { ...state, defaultPresetId: id }
}

export interface RestoredLayout {
  readonly layout: PaneLayout
  /** Pane ids whose saved session is gone → the caller should spawn a fresh session into them. */
  readonly freshPaneIds: readonly string[]
}

/**
 * Restore a preset against the currently-available sessions. Leaves whose saved sessionId is still available
 * keep it; the rest become fresh (null) slots, reported in `freshPaneIds` so the caller can launch sessions.
 */
export function restorePreset(preset: LayoutPreset, availableSessionIds: readonly string[]): RestoredLayout {
  const available = new Set(availableSessionIds)
  const freshPaneIds: string[] = []
  // walk the tree, keeping a leaf's session only if it's still available; else mark it for a fresh session
  const rebind = (node: PaneNode): PaneNode => {
    if (node.kind === 'leaf') {
      const keep = node.sessionId !== null && available.has(node.sessionId)
      if (!keep) freshPaneIds.push(node.id)
      return { ...node, sessionId: keep ? node.sessionId : null }
    }
    return { ...node, first: rebind(node.first), second: rebind(node.second) }
  }
  const newRoot = rebind(preset.layout.root)
  // keep the saved active pane if it still exists, else the first leaf
  const allIds = leaves(newRoot).map((l) => l.id)
  const activePaneId = allIds.includes(preset.layout.activePaneId) ? preset.layout.activePaneId : allIds[0]
  return { layout: { root: newRoot, activePaneId }, freshPaneIds }
}

// ── serialize / deserialize (browser-local persistence is a later slice) ──────

export function serializePresetState(state: LayoutPresetState): string {
  const defaultPresetId = state.defaultPresetId && state.presets.some((p) => p.id === state.defaultPresetId)
    ? state.defaultPresetId
    : undefined
  return JSON.stringify({
    presets: state.presets.map((p) => ({
      id: p.id, name: p.name, createdAtMs: p.createdAtMs, layout: JSON.parse(serializeLayout(p.layout)),
    })),
    ...(defaultPresetId ? { defaultPresetId } : {}),
  })
}

export function deserializePresetState(raw: string): LayoutPresetState {
  let parsed: unknown
  try {
    parsed = JSON.parse(raw)
  } catch {
    return { presets: [] }
  }
  const presetsRaw = (parsed as { presets?: unknown }).presets
  if (!Array.isArray(presetsRaw)) return { presets: [] }
  const presets: LayoutPreset[] = []
  for (const p of presetsRaw) {
    if (!p || typeof p !== 'object') continue
    const r = p as Record<string, unknown>
    if (typeof r.id !== 'string' || typeof r.name !== 'string' || typeof r.createdAtMs !== 'number') continue
    const layout = deserializeLayout(JSON.stringify(r.layout))
    if (!layout) continue // a preset with a broken layout is dropped, not fatal
    presets.push({ id: r.id, name: r.name, createdAtMs: r.createdAtMs, layout })
  }
  const defaultPresetId = typeof (parsed as { defaultPresetId?: unknown }).defaultPresetId === 'string'
    && presets.some((p) => p.id === (parsed as { defaultPresetId: string }).defaultPresetId)
    ? (parsed as { defaultPresetId: string }).defaultPresetId
    : undefined
  return defaultPresetId ? { presets, defaultPresetId } : { presets }
}
