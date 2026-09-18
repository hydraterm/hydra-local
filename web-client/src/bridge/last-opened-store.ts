// Browser-only "last opened session" hint. Content-blind and non-authoritative:
// stores only a session id scoped by account + desktop, never tokens or terminal content.

import { scopedKey } from './scoped-storage-key.js'

const PREFIX = 'hydra.remote.lastOpenedSession'

function key(accountId: string, desktopDeviceId: string): string {
  return scopedKey(PREFIX, accountId, desktopDeviceId)
}

export function loadLastOpenedSession(accountId: string, desktopDeviceId: string): string | null {
  try {
    const raw = localStorage.getItem(key(accountId, desktopDeviceId))
    const trimmed = raw?.trim() ?? ''
    return trimmed || null
  } catch {
    return null
  }
}

export function saveLastOpenedSession(accountId: string, desktopDeviceId: string, sessionId: string | null): void {
  try {
    const k = key(accountId, desktopDeviceId)
    const trimmed = sessionId?.trim() ?? ''
    if (trimmed) localStorage.setItem(k, trimmed)
    else localStorage.removeItem(k)
  } catch {
    // storage unavailable: the marker remains in-memory only for this controller instance.
  }
}
