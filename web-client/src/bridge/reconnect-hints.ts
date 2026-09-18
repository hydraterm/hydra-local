// Reconnect/resume hints — the NON-SECRET state needed to reattach to the same Mac session after a
// refresh / drop / mobile sleep. We persist ONLY: account id, desktop device id, session id, renderer
// mode. NO token, NO credential (those are minted/fetched fresh on reconnect). sessionStorage = per-tab,
// cleared when the tab closes — appropriate for a resume hint.
//
// The PTY survives on the Mac regardless (the daemon owns the session); these hints just let the browser
// re-run connect → mint fresh token → new signaling → auth → attach the SAME session id (a no-op respawn
// on the daemon, so no duplicate session).

const KEY = 'hydra.remote.reconnect'

export interface ReconnectHints {
  accountId: string
  desktopDeviceId: string
  sessionId: string | null // the attached session to resume (null = stop at the session list)
  renderer: 'grid' | 'xterm'
}

export function saveHints(h: ReconnectHints): void {
  try {
    sessionStorage.setItem(KEY, JSON.stringify(h))
  } catch {
    // storage unavailable (private mode / disabled) — reconnect just won't auto-resume.
  }
}

export function loadHints(): ReconnectHints | null {
  try {
    const raw = sessionStorage.getItem(KEY)
    if (!raw) return null
    const h = JSON.parse(raw) as Partial<ReconnectHints>
    if (typeof h.accountId !== 'string' || typeof h.desktopDeviceId !== 'string') return null
    return {
      accountId: h.accountId,
      desktopDeviceId: h.desktopDeviceId,
      sessionId: typeof h.sessionId === 'string' ? h.sessionId : null,
      renderer: h.renderer === 'grid' ? 'grid' : 'xterm',
    }
  } catch {
    return null
  }
}

export function clearHints(): void {
  try {
    sessionStorage.removeItem(KEY)
  } catch {
    // ignore
  }
}
