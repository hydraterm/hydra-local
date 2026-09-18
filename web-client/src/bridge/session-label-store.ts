// Browser-only persistence for user-visible session labels/renames.
// Stores no tokens, no terminal payload, and no session contents: just session id -> display label,
// scoped by account + desktop device. If storage is unavailable, labels stay in-memory.

import { scopedKey } from './scoped-storage-key.js'

const PREFIX = 'hydra.remote.sessionLabels'

export type SessionLabels = Record<string, string>

function key(accountId: string, desktopDeviceId: string): string {
  return scopedKey(PREFIX, accountId, desktopDeviceId)
}

function clean(input: unknown): SessionLabels {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {}
  const out: SessionLabels = {}
  for (const [sid, label] of Object.entries(input as Record<string, unknown>)) {
    if (typeof sid !== 'string' || typeof label !== 'string') continue
    const trimmed = label.trim()
    if (sid && trimmed) out[sid] = trimmed
  }
  return out
}

export function loadSessionLabels(accountId: string, desktopDeviceId: string): SessionLabels {
  try {
    const raw = localStorage.getItem(key(accountId, desktopDeviceId))
    return raw ? clean(JSON.parse(raw)) : {}
  } catch {
    return {}
  }
}

export function saveSessionLabels(accountId: string, desktopDeviceId: string, labels: SessionLabels): void {
  try {
    const cleaned = clean(labels)
    const k = key(accountId, desktopDeviceId)
    if (Object.keys(cleaned).length === 0) localStorage.removeItem(k)
    else localStorage.setItem(k, JSON.stringify(cleaned))
  } catch {
    // private mode / disabled storage / quota: persistence is best-effort only.
  }
}
