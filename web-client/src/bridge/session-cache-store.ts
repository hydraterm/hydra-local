// Browser-local "known sessions" cache for dashboard visibility. Scoped by account + desktop, content-blind:
// stores only session ids from the last authoritative daemon session_list. It is a hint, not authority.

import { cleanSessionOrder } from '../model/session-order.js'
import { scopedKey } from './scoped-storage-key.js'

const PREFIX = 'hydra.remote.knownSessions'

function key(accountId: string, desktopDeviceId: string): string {
  return scopedKey(PREFIX, accountId, desktopDeviceId)
}

export function loadKnownSessions(accountId: string, desktopDeviceId: string): string[] {
  try {
    const raw = localStorage.getItem(key(accountId, desktopDeviceId))
    return raw ? cleanSessionOrder(JSON.parse(raw)) : []
  } catch {
    return []
  }
}

export function saveKnownSessions(accountId: string, desktopDeviceId: string, sessions: readonly string[]): void {
  try {
    const cleaned = cleanSessionOrder(sessions)
    const k = key(accountId, desktopDeviceId)
    if (cleaned.length === 0) localStorage.removeItem(k)
    else localStorage.setItem(k, JSON.stringify(cleaned))
  } catch {
    // private mode / disabled storage / quota: dashboard visibility cache is best-effort only.
  }
}
