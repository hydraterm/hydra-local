// Browser-local persistence for the terminal header's "Set current as default" workspace chip. Scoped by account,
// content-blind: stores only preset ids/names/timestamps and pane layout/session ids. No terminal payload, tokens,
// or transport data. The old multi-preset management panel was removed; keep this store only while the live
// default-layout chip remains product scope.

import {
  deserializePresetState,
  serializePresetState,
  type LayoutPresetState,
} from '../model/layout-preset.js'
import { accountScopedKey } from './scoped-storage-key.js'

const PREFIX = 'hydra.remote.layoutPresets'

const EMPTY: LayoutPresetState = { presets: [] }

function key(accountId: string): string {
  return accountScopedKey(PREFIX, accountId)
}

/** Load this account's layout presets. Corrupt, absent, or inaccessible storage returns an empty state. */
export function loadLayoutPresetState(accountId: string): LayoutPresetState {
  try {
    const raw = localStorage.getItem(key(accountId))
    if (!raw) return EMPTY
    return deserializePresetState(raw)
  } catch {
    return EMPTY
  }
}

/** Persist layout presets best-effort. Empty state removes the item to avoid stale sentinels. */
export function saveLayoutPresetState(accountId: string, state: LayoutPresetState): void {
  try {
    const k = key(accountId)
    if (!state.presets.length) localStorage.removeItem(k)
    else localStorage.setItem(k, serializePresetState(state))
  } catch {
    // private mode / disabled storage / quota: persistence is best-effort only.
  }
}
