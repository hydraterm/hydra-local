import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ProgressDeadline } from './connect-deadline'

describe('ProgressDeadline', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('extends inactivity only for new meaningful stages', () => {
    const expired: string[] = []
    const deadline = new ProgressDeadline({ inactivityMs: 100, absoluteMs: 1_000, onExpire: (kind) => expired.push(kind) })

    vi.advanceTimersByTime(80)
    expect(deadline.progress('relay_credentials')).toBe(true)
    vi.advanceTimersByTime(80)
    expect(expired).toEqual([])
    expect(deadline.progress('relay_credentials')).toBe(false)
    vi.advanceTimersByTime(20)

    expect(expired).toEqual(['inactivity'])
    expect(deadline.signal.aborted).toBe(true)
  })

  it('fires the absolute cap despite continuing unique progress', () => {
    const expired: string[] = []
    const deadline = new ProgressDeadline({ inactivityMs: 100, absoluteMs: 250, onExpire: (kind) => expired.push(kind) })

    vi.advanceTimersByTime(80)
    deadline.progress('one')
    vi.advanceTimersByTime(80)
    deadline.progress('two')
    vi.advanceTimersByTime(80)
    deadline.progress('three')
    vi.advanceTimersByTime(10)

    expect(expired).toEqual(['absolute'])
  })

  it('pauses only inactivity and resumes with its remaining budget', () => {
    const expired: string[] = []
    const deadline = new ProgressDeadline({ inactivityMs: 100, absoluteMs: 500, onExpire: (kind) => expired.push(kind) })

    vi.advanceTimersByTime(70)
    deadline.pauseInactivity('passkey')
    vi.advanceTimersByTime(300)
    expect(expired).toEqual([])
    deadline.resumeInactivity('passkey')
    vi.advanceTimersByTime(29)
    expect(expired).toEqual([])
    vi.advanceTimersByTime(1)
    expect(expired).toEqual(['inactivity'])
  })

  it('never pauses the absolute cap', () => {
    const expired: string[] = []
    const deadline = new ProgressDeadline({ inactivityMs: 100, absoluteMs: 250, onExpire: (kind) => expired.push(kind) })
    deadline.pauseInactivity('passkey')

    vi.advanceTimersByTime(250)

    expect(expired).toEqual(['absolute'])
  })

  it('gives progress observed while paused one fresh budget after resume without double-counting the pause', () => {
    const expired: string[] = []
    const deadline = new ProgressDeadline({ inactivityMs: 100, absoluteMs: 1_000, onExpire: (kind) => expired.push(kind) })

    vi.advanceTimersByTime(70)
    deadline.pauseInactivity('passkey')
    vi.advanceTimersByTime(200)
    deadline.progress('authenticator-ready')
    vi.advanceTimersByTime(200)
    deadline.resumeInactivity('passkey')
    vi.advanceTimersByTime(99)
    expect(expired).toEqual([])
    vi.advanceTimersByTime(1)

    expect(expired).toEqual(['inactivity'])
  })

  it('makes stale timers and late progress inert after completion or abort', () => {
    const completed: string[] = []
    const first = new ProgressDeadline({ inactivityMs: 100, absoluteMs: 200, onExpire: (kind) => completed.push(kind) })
    first.complete()
    vi.advanceTimersByTime(500)
    expect(first.progress('late')).toBe(false)
    expect(completed).toEqual([])
    expect(first.signal.aborted).toBe(false)

    const aborted: string[] = []
    const second = new ProgressDeadline({ inactivityMs: 100, absoluteMs: 200, onExpire: (kind) => aborted.push(kind) })
    second.abort()
    vi.advanceTimersByTime(500)
    expect(second.progress('late')).toBe(false)
    expect(aborted).toEqual([])
    expect(second.signal.aborted).toBe(true)
  })
})
