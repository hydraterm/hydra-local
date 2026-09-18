// Shared key builder for browser-local stores scoped by account + desktop device (P1 session labels, P2
// last-opened). The id segments are URI-encoded so a ':' inside an id can't collide one scope into another.
// Keeping this in one place means the encoding rule can't drift between stores.

export function scopedKey(prefix: string, accountId: string, desktopDeviceId: string): string {
  return `${prefix}:${encodeURIComponent(accountId)}:${encodeURIComponent(desktopDeviceId)}`
}

/** Account-only browser-local stores (layout presets) use the same encoding rule without desktop. */
export function accountScopedKey(prefix: string, accountId: string): string {
  return `${prefix}:${encodeURIComponent(accountId)}`
}
