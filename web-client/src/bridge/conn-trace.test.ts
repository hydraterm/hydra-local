import { describe, it, expect, beforeEach } from 'vitest'
import { ConnTrace, mintTraceId, TRACE_BUFFER_MAX } from './conn-trace'

describe('ConnTrace', () => {
  let t: ConnTrace
  beforeEach(() => {
    t = new ConnTrace()
  })

  it('mints unique, greppable trace ids', () => {
    const a = mintTraceId()
    const b = mintTraceId()
    expect(a).toMatch(/^t_/)
    expect(a).not.toBe(b)
  })

  it('records structured events with side=browser and monotonic elapsed within a leg', () => {
    const id = 't_x'
    const e1 = t.log(id, 'connect', 'start', 'pending', 'dev_a')
    const e2 = t.log(id, 'connect', 'auth_ok', 'ok')
    expect(e1.side).toBe('browser')
    expect(e1.leg).toBe('connect')
    expect(e1.stage).toBe('start')
    expect(e1.elapsedMs).toBe(0) // first event in the leg
    expect(e2.elapsedMs).toBeGreaterThanOrEqual(0)
    expect(t.events()).toHaveLength(2)
  })

  it('tracks elapsed PER (traceId, leg) — a new leg restarts the clock', () => {
    const id = 't_y'
    const a = t.log(id, 'connect', 'start', 'pending')
    const b = t.log(id, 'attach', 'start', 'pending') // different leg → its own start
    expect(a.elapsedMs).toBe(0)
    expect(b.elapsedMs).toBe(0)
  })

  it('bounds memory with a ring buffer (oldest dropped)', () => {
    for (let i = 0; i < TRACE_BUFFER_MAX + 50; i++) t.log('t_ring', 'connect', `s${i}`, 'ok')
    expect(t.events().length).toBe(TRACE_BUFFER_MAX)
    // the oldest 50 were dropped → first kept event is s50
    expect(t.events()[0].stage).toBe('s50')
  })

  it('forTrace filters to a single correlation id', () => {
    t.log('t_1', 'connect', 'start', 'pending')
    t.log('t_2', 'connect', 'start', 'pending')
    t.log('t_1', 'connect', 'auth_ok', 'ok')
    expect(t.forTrace('t_1')).toHaveLength(2)
    expect(t.forTrace('t_2')).toHaveLength(1)
  })

  it('dump() is a content-blind, greppable text block including the traceId', () => {
    t.log('t_dump', 'session_list', 'timeout', 'error', '2 sessions')
    const d = t.dump()
    expect(d).toContain('session_list/timeout')
    expect(d).toContain('t_dump')
    expect(d).toContain('2 sessions')
  })

  it('scrubs secret/signaling shaped details before buffering or dumping', () => {
    t.log('t_scrub', 'wire', 'out', 'ok', 'auth token=secret candidate=opaque')
    const ev = t.events()[0]!
    expect(ev.detail).toContain('token=<redacted>')
    expect(ev.detail).toContain('candidate=<redacted>')
    expect(ev.detail).not.toContain('secret')
    expect(t.dump()).not.toContain('secret')
  })

  it('scrubs filesystem paths, project names, and session names before buffering or dumping', () => {
    t.log(
      't_path',
      'folder',
      'reply',
      'ok',
      'cwd=/Users/test/home/Desktop/project-example path=/Users/test/home/private project=SecretProject sessionName=ClaudeRun',
    )
    const detail = t.events()[0]!.detail
    expect(detail).toContain('cwd=<redacted>')
    expect(detail).toContain('path=<redacted>')
    expect(detail).toContain('project=<redacted>')
    expect(detail).toContain('sessionName=<redacted>')
    expect(t.dump()).not.toContain('/Users/test/home')
    expect(t.dump()).not.toContain('SecretProject')
    expect(t.dump()).not.toContain('ClaudeRun')
  })

  it('scrubs Linux paths even when an internal request id embeds the cwd', () => {
    t.log(
      't_linux_path',
      'wire',
      'out',
      'ok',
      'rid=agent-sessions-folder:claude:/home/test/home/private source=/var/lib/hydra https://example.test/ok',
    )
    const detail = t.events()[0]!.detail
    expect(detail).not.toContain('/home/test/home')
    expect(detail).not.toContain('/var/lib')
    expect(detail).toContain('https://example.test/ok')
  })

  it('notifies listeners on each event', () => {
    const seen: string[] = []
    const off = t.onEvent((e) => seen.push(e.stage))
    t.log('t_l', 'connect', 'start', 'pending')
    t.log('t_l', 'connect', 'auth_ok', 'ok')
    off()
    t.log('t_l', 'connect', 'session_list', 'ok')
    expect(seen).toEqual(['start', 'auth_ok']) // stopped after off()
  })
})
