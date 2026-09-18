import { describe, it, expect } from 'vitest'
import { MultiAttachManager } from './multi-attach-manager'

describe('MultiAttachManager', () => {
  it('tracks two concurrent attaches on distinct channels', () => {
    const m = new MultiAttachManager()
    m.onAttached('s-a', 1)
    m.onAttached('s-b', 2)
    expect(m.attachedCount).toBe(2)
    expect(m.channelForSession('s-a')).toBe(1)
    expect(m.channelForSession('s-b')).toBe(2)
    expect(m.sessionForChannel(1)).toBe('s-a')
    expect(m.sessionForChannel(2)).toBe('s-b')
    expect(m.isAttached('s-a')).toBe(true)
    expect(m.isAttached('s-zz')).toBe(false)
  })

  it('the most-recently-attached session is active (input/resize target)', () => {
    const m = new MultiAttachManager()
    m.onAttached('s-a', 1)
    expect(m.activeSession()).toBe('s-a')
    expect(m.activeChannel()).toBe(1)
    m.onAttached('s-b', 2) // newly opened pane takes input focus
    expect(m.activeSession()).toBe('s-b')
    expect(m.activeChannel()).toBe(2)
  })

  it('setActive switches the input target between attached sessions only', () => {
    const m = new MultiAttachManager()
    m.onAttached('s-a', 1)
    m.onAttached('s-b', 2)
    m.setActive('s-a')
    expect(m.activeSession()).toBe('s-a')
    expect(m.activeChannel()).toBe(1)
    m.setActive('s-ghost') // not attached → no-op
    expect(m.activeSession()).toBe('s-a')
  })

  it('detach drops the binding; active re-focuses to a remaining session', () => {
    const m = new MultiAttachManager()
    m.onAttached('s-a', 1)
    m.onAttached('s-b', 2) // active = s-b
    m.detachSession('s-b') // active gone → falls back to s-a
    expect(m.attachedCount).toBe(1)
    expect(m.channelForSession('s-b')).toBeNull()
    expect(m.activeSession()).toBe('s-a')
    m.detachSession('s-a') // last one → active null
    expect(m.activeSession()).toBeNull()
    expect(m.activeChannel()).toBeNull()
    expect(m.attachedCount).toBe(0)
  })

  it('detaching a non-active session leaves the active one intact', () => {
    const m = new MultiAttachManager()
    m.onAttached('s-a', 1)
    m.onAttached('s-b', 2)
    m.setActive('s-b')
    m.detachSession('s-a')
    expect(m.activeSession()).toBe('s-b')
    expect(m.attachedCount).toBe(1)
  })

  it('re-attaching a session updates its channel (no stale channel binding)', () => {
    const m = new MultiAttachManager()
    m.onAttached('s-a', 1)
    m.onAttached('s-a', 5) // re-attach on a new channel
    expect(m.channelForSession('s-a')).toBe(5)
    expect(m.sessionForChannel(1)).toBeNull() // old channel released
    expect(m.sessionForChannel(5)).toBe('s-a')
    expect(m.attachedCount).toBe(1)
  })

  it('bindings() lists every attach; clear() resets', () => {
    const m = new MultiAttachManager()
    m.onAttached('s-a', 1)
    m.onAttached('s-b', 2)
    expect(m.bindings()).toEqual([
      { sessionId: 's-a', channel: 1 },
      { sessionId: 's-b', channel: 2 },
    ])
    m.clear()
    expect(m.attachedCount).toBe(0)
    expect(m.activeSession()).toBeNull()
  })
})
