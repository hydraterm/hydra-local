// SECURITY: a canonical "clear all account-scoped browser state" reset, run on sign-out (and before a
// new account signs in on the same browser), so user B never sees residue from user A on a shared machine.
//
// Two categories of `hydra.remote.*` storage:
//   - ACCOUNT-SCOPED (device labels, session labels/order/favorites/hidden, known sessions, layouts,
//     presets, last-opened, reconnect hint, per-device token): these belong to a specific account and
//     MUST be wiped on logout. Most are already namespaced by accountId so B wouldn't READ A's values,
//     but wiping guarantees no residue at all (and covers the genuinely-global reconnect hint + token).
//   - DEVICE PREFERENCES (renderer mode, terminal font size): NOT account data — a display choice for this
//     browser. Preserved across logout so a user isn't reset to defaults every time.
//
// Implemented as a prefix sweep so a NEW account-scoped store added later is cleared automatically
// (fail-safe: a new key is wiped unless explicitly added to the preserve list).

/** `hydra.remote.*` keys that are device PREFERENCES, not account data — preserved across logout. */
const PRESERVE_KEYS = new Set<string>(['hydra.remote.rendererMode', 'hydra.remote.terminalFontSize'])

const ACCOUNT_KEY_PREFIX = 'hydra.remote.'

/** Remove every account-scoped `hydra.remote.*` entry from BOTH localStorage and sessionStorage,
 * preserving only the device-preference keys. Safe to call anytime; no-op where storage is unavailable. */
export function clearAllAccountState(
  storages: Array<Storage | undefined> = [
    typeof localStorage !== 'undefined' ? localStorage : undefined,
    typeof sessionStorage !== 'undefined' ? sessionStorage : undefined,
  ],
): void {
  for (const store of storages) {
    if (!store) continue
    // Collect first (removing while iterating by index is unsafe), then delete.
    const toRemove: string[] = []
    for (let i = 0; i < store.length; i++) {
      const key = store.key(i)
      if (key && key.startsWith(ACCOUNT_KEY_PREFIX) && !PRESERVE_KEYS.has(key)) {
        toRemove.push(key)
      }
    }
    for (const key of toRemove) {
      try {
        store.removeItem(key)
      } catch {
        // storage disabled / quota — best-effort
      }
    }
  }
}
