import { describe, it, expect } from 'vitest'
import {
  createSessionMessage,
  isDaemonNotReadyMessage,
  DAEMON_NOT_READY_MESSAGE,
  CREATE_INTERRUPTED_MESSAGE,
  MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE,
} from './create-session-messages'

describe('create-session-messages', () => {
  it('maps known codes to friendly, actionable copy', () => {
    expect(createSessionMessage('daemon_unavailable')).toBe(DAEMON_NOT_READY_MESSAGE)
    // UX1: actionable next step appended
    expect(createSessionMessage('limit_reached')).toBe('Session limit reached — open an existing session instead.')
    expect(createSessionMessage('revoked')).toBe('This desktop was unlinked.')
    expect(createSessionMessage('unauthenticated')).toBe('Please sign in again.')
    expect(createSessionMessage('unsupported_provider')).toBe(
      'This desktop app does not support that provider yet. Update Hydra and try again.',
    )
    expect(createSessionMessage('macos_full_disk_access_required')).toBe(
      MACOS_FULL_DISK_ACCESS_REQUIRED_MESSAGE,
    )
  })

  it('unknown code → a safe, actionable default', () => {
    expect(createSessionMessage('weird')).toBe('Could not create a session. Please try again.')
  })

  it('UX1: every create-session message is actionable or clearly final (no dead-end "X reached." with no next step)', () => {
    for (const code of ['limit_reached', 'unauthenticated', 'internal']) {
      const msg = createSessionMessage(code)
      // either it tells the user what to do, or it states a clear final fact (revoked/unlinked)
      expect(/try again|open an existing|sign in/i.test(msg) || /unlinked/i.test(msg)).toBe(true)
    }
  })

  it('isDaemonNotReadyMessage matches ONLY the daemon-unavailable message (no magic-string drift)', () => {
    // R1 invariant: the predicate is coupled to the message via the shared constant, so a copy edit can't
    // silently break readiness's daemon-unavailable detection.
    expect(isDaemonNotReadyMessage(createSessionMessage('daemon_unavailable'))).toBe(true)
    expect(isDaemonNotReadyMessage(createSessionMessage('limit_reached'))).toBe(false)
    expect(isDaemonNotReadyMessage(null)).toBe(false)
    expect(isDaemonNotReadyMessage(undefined)).toBe(false)
  })

  it('interrupted create copy is retryable and separate from daemon-not-ready detection', () => {
    expect(CREATE_INTERRUPTED_MESSAGE).toMatch(/try again/i)
    expect(isDaemonNotReadyMessage(CREATE_INTERRUPTED_MESSAGE)).toBe(false)
  })
})
