// Browser-local hidden sessions (roadmap §2#5 persistent session organization). Scoped by account + desktop,
// content-blind: stores only session ids. This never deletes daemon sessions.

import { cleanHiddenSessions } from '../model/session-visibility.js'
import { scopedKey } from './scoped-storage-key.js'

const PREFIX = 'hydra.remote.hiddenSessions'

function key(accountId: string, desktopDeviceId: string): string {
  return scopedKey(PREFIX, accountId, desktopDeviceId)
}

export function loadHiddenSessions(accountId: string, desktopDeviceId: string): string[] {
  try {
    const raw = localStorage.getItem(key(accountId, desktopDeviceId))
    return raw ? cleanHiddenSessions(JSON.parse(raw)) : []
  } catch {
    return []
  }
}

export function saveHiddenSessions(accountId: string, desktopDeviceId: string, hidden: readonly string[]): void {
  try {
    const cleaned = cleanHiddenSessions(hidden)
    const k = key(accountId, desktopDeviceId)
    if (cleaned.length === 0) localStorage.removeItem(k)
    else localStorage.setItem(k, JSON.stringify(cleaned))
  } catch {
    // private mode / disabled storage / quota: persistence is best-effort only.
  }
}
