// Browser-local manual session order (roadmap §2#5 persistent session organization). Scoped by account +
// desktop, content-blind: stores only session ids. Persistence is best-effort like labels/favorites.

import { cleanSessionOrder } from '../model/session-order.js'
import { scopedKey } from './scoped-storage-key.js'

const PREFIX = 'hydra.remote.sessionOrder'

function key(accountId: string, desktopDeviceId: string): string {
  return scopedKey(PREFIX, accountId, desktopDeviceId)
}

export function loadSessionOrder(accountId: string, desktopDeviceId: string): string[] {
  try {
    const raw = localStorage.getItem(key(accountId, desktopDeviceId))
    return raw ? cleanSessionOrder(JSON.parse(raw)) : []
  } catch {
    return []
  }
}

export function saveSessionOrder(accountId: string, desktopDeviceId: string, order: readonly string[]): void {
  try {
    const cleaned = cleanSessionOrder(order)
    const k = key(accountId, desktopDeviceId)
    if (cleaned.length === 0) localStorage.removeItem(k)
    else localStorage.setItem(k, JSON.stringify(cleaned))
  } catch {
    // private mode / disabled storage / quota: persistence is best-effort only.
  }
}
