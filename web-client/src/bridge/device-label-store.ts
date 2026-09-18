// Browser-local desktop label overrides. Content-blind and account-scoped: stores only device id -> label,
// never tokens, terminal content, or cloud metadata. This is a UI-only bridge until a real backend PATCH
// endpoint is explicitly approved.

const PREFIX = 'hydra.remote.deviceLabels'

export type DeviceLabels = Record<string, string>

function key(accountId: string): string {
  return `${PREFIX}:${encodeURIComponent(accountId)}`
}

function clean(input: unknown): DeviceLabels {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return {}
  const out: DeviceLabels = {}
  for (const [deviceId, label] of Object.entries(input as Record<string, unknown>)) {
    if (typeof deviceId !== 'string' || typeof label !== 'string') continue
    const id = deviceId.trim()
    const trimmed = label.trim().replace(/\s+/g, ' ')
    if (id && trimmed) out[id] = trimmed
  }
  return out
}

export function loadDeviceLabels(accountId: string): DeviceLabels {
  try {
    const raw = localStorage.getItem(key(accountId))
    return raw ? clean(JSON.parse(raw)) : {}
  } catch {
    return {}
  }
}

export function saveDeviceLabels(accountId: string, labels: DeviceLabels): void {
  try {
    const cleaned = clean(labels)
    const k = key(accountId)
    if (Object.keys(cleaned).length === 0) localStorage.removeItem(k)
    else localStorage.setItem(k, JSON.stringify(cleaned))
  } catch {
    // private mode / disabled storage / quota: persistence is best-effort only.
  }
}
