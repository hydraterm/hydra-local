// Create-session error copy (pure). Owns BOTH the friendly message per error code AND the predicate the
// readiness model uses to detect the soft "daemon not ready yet" case — so the two never drift apart on a
// magic string (R1: previously readiness regex-matched the literal text createSessionMessage produced).
// Content-blind: codes/copy only, no terminal payload.

/** The exact message shown when the desktop is reachable but its local terminal daemon isn't up yet. Shared
 * so readiness can detect this state without re-typing the string. */
export const DAEMON_NOT_READY_MESSAGE = 'Desktop terminal service is not ready.'
export const CREATE_INTERRUPTED_MESSAGE = 'Session creation was interrupted. Please try again.'
export const MACOS_FULL_DISK_ACCESS_REQUIRED_CODE = 'macos_full_disk_access_required'
export const MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE =
  'This desktop needs Full Disk Access. Grant it on the Mac in System Settings → Privacy & Security → Full Disk Access, then retry.'

/** Map a create_session error code to a short, human-readable message (no raw codes in the UI). */
export function createSessionMessage(code: string): string {
  switch (code) {
    case 'daemon_unavailable':
      return DAEMON_NOT_READY_MESSAGE
    case 'limit_reached':
      // UX1: actionable + truthful — we don't have a close-session UI yet, but existing sessions are openable.
      return 'Session limit reached — open an existing session instead.'
    case 'revoked':
      return 'This desktop was unlinked.'
    case 'unauthenticated':
      return 'Please sign in again.'
    case 'unsupported_provider':
      return 'This desktop app does not support that provider yet. Update Hydra and try again.'
    case MACOS_FULL_DISK_ACCESS_REQUIRED_CODE:
      return MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE
    default:
      // UX1: tell the user what to do next, matching the "Something went wrong · Please try again" pattern.
      return 'Could not create a session. Please try again.'
  }
}

/** True when a (rendered) create-session error is the transient daemon-not-ready message — a soft, retryable
 * state, not a hard refusal. Compares against the shared constant (no duplicated literal). */
export function isDaemonNotReadyMessage(createSessionError: string | null | undefined): boolean {
  return createSessionError === DAEMON_NOT_READY_MESSAGE
}
