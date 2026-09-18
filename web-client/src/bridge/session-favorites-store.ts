// Browser-only "favorite / pinned sessions" (roadmap §2#5 persistent session organization). A set of session
// ids the user pinned, scoped by account + desktop. Content-blind: stores only session ids — never tokens,
// labels, or terminal content. If storage is unavailable, favorites stay in-memory for that controller.

import { scopedKey } from './scoped-storage-key.js'

const PREFIX = 'hydra.remote.favoriteSessions'

function key(accountId: string, desktopDeviceId: string): string {
  return scopedKey(PREFIX, accountId, desktopDeviceId)
}

/** Sanitize a parsed value into a clean, de-duped list of non-empty string ids. */
function clean(input: unknown): string[] {
  if (!Array.isArray(input)) return []
  const out: string[] = []
  for (const v of input) {
    if (typeof v !== 'string') continue
    const id = v.trim()
    if (id && !out.includes(id)) out.push(id)
  }
  return out
}

export function loadFavoriteSessions(accountId: string, desktopDeviceId: string): string[] {
  try {
    const raw = localStorage.getItem(key(accountId, desktopDeviceId))
    return raw ? clean(JSON.parse(raw)) : []
  } catch {
    return []
  }
}

export function saveFavoriteSessions(accountId: string, desktopDeviceId: string, favorites: readonly string[]): void {
  try {
    const cleaned = clean(favorites)
    const k = key(accountId, desktopDeviceId)
    if (cleaned.length === 0) localStorage.removeItem(k)
    else localStorage.setItem(k, JSON.stringify(cleaned))
  } catch {
    // private mode / disabled storage / quota: persistence is best-effort only.
  }
}

/** Toggle a session id in the favorites set (pure — returns the new list). */
export function toggleFavorite(favorites: readonly string[], sessionId: string): string[] {
  const id = sessionId.trim()
  if (!id) return clean(favorites)
  const current = clean(favorites)
  return current.includes(id) ? current.filter((x) => x !== id) : [...current, id]
}
