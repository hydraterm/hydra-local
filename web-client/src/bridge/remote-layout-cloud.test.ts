import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest'
import { RemoteLayoutCloud, parseRemoteLayout, serializeRemoteLayout, REMOTE_LAYOUT_SCHEMA_V } from './remote-layout-cloud'

describe('RemoteLayoutCloud', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  function fakeFetch(impl?: (url: string, init?: RequestInit) => Response) {
    return vi.fn(async (url: string, init?: RequestInit) =>
      impl ? impl(url, init) : new Response(JSON.stringify({ layout: null }), { status: 200 }))
  }

  it('fetchLayout returns the layout string on 200, null on non-ok / error / non-string', async () => {
    const okFetch = fakeFetch(() => new Response(JSON.stringify({ layout: '{"win":1}' }), { status: 200 }))
    const c = new RemoteLayoutCloud({ baseUrl: 'https://c', authToken: 'dev:a' }, okFetch as unknown as typeof fetch)
    expect(await c.fetchLayout('dev_x')).toBe('{"win":1}')

    const notFound = new RemoteLayoutCloud({ baseUrl: 'https://c', authToken: 'dev:a' },
      fakeFetch(() => new Response('', { status: 404 })) as unknown as typeof fetch)
    expect(await notFound.fetchLayout('dev_x')).toBeNull()

    const throws = new RemoteLayoutCloud({ baseUrl: 'https://c', authToken: 'dev:a' },
      (vi.fn(async () => { throw new Error('offline') })) as unknown as typeof fetch)
    expect(await throws.fetchLayout('dev_x')).toBeNull() // never throws — a restore must not block the grid
  })

  it('fetchLayout GETs the right URL with the deviceId query + dev Bearer auth', async () => {
    const f = fakeFetch()
    const c = new RemoteLayoutCloud({ baseUrl: 'https://c', authToken: 'dev:a1' }, f as unknown as typeof fetch)
    await c.fetchLayout('dev_x')
    expect(f).toHaveBeenCalledWith('https://c/v1/remote-layout?deviceId=dev_x', expect.objectContaining({
      headers: expect.objectContaining({ authorization: 'Bearer dev:a1' }),
    }))
  })

  it('cookie auth mode sends credentials:include and NO Authorization header', async () => {
    const f = fakeFetch()
    const c = new RemoteLayoutCloud({ baseUrl: 'https://c', authToken: 'cookie' }, f as unknown as typeof fetch)
    await c.fetchLayout('dev_x')
    const init = f.mock.calls[0]![1] as RequestInit
    expect(init.credentials).toBe('include')
    expect((init.headers as Record<string, string> | undefined)?.authorization).toBeUndefined()
  })

  it('putLayout DEBOUNCES + COALESCES: three fast writes → one PUT with the LAST layout', async () => {
    const f = fakeFetch()
    const c = new RemoteLayoutCloud({ baseUrl: 'https://c', authToken: 'dev:a' }, f as unknown as typeof fetch, 1000)
    c.putLayout('dev_x', 'A')
    c.putLayout('dev_x', 'B')
    c.putLayout('dev_x', 'C')
    expect(f).not.toHaveBeenCalled() // nothing sent yet (debouncing)
    await vi.advanceTimersByTimeAsync(1000)
    const puts = f.mock.calls.filter((call) => (call[1] as RequestInit)?.method === 'PUT')
    expect(puts).toHaveLength(1)
    expect(JSON.parse((puts[0]![1] as RequestInit).body as string)).toEqual({ deviceId: 'dev_x', layout: 'C' })
  })

  it('a second burst after the first flush sends a second PUT', async () => {
    const f = fakeFetch()
    const c = new RemoteLayoutCloud({ baseUrl: 'https://c', authToken: 'dev:a' }, f as unknown as typeof fetch, 1000)
    c.putLayout('dev_x', 'A')
    await vi.advanceTimersByTimeAsync(1000)
    c.putLayout('dev_x', 'B')
    await vi.advanceTimersByTimeAsync(1000)
    const puts = f.mock.calls.filter((call) => (call[1] as RequestInit)?.method === 'PUT')
    expect(puts.map((p) => JSON.parse((p[1] as RequestInit).body as string).layout)).toEqual(['A', 'B'])
  })

  it('dispose cancels a pending write', async () => {
    const f = fakeFetch()
    const c = new RemoteLayoutCloud({ baseUrl: 'https://c', authToken: 'dev:a' }, f as unknown as typeof fetch, 1000)
    c.putLayout('dev_x', 'A')
    c.dispose()
    await vi.advanceTimersByTimeAsync(2000)
    expect(f.mock.calls.filter((call) => (call[1] as RequestInit)?.method === 'PUT')).toHaveLength(0)
  })
})

// Schema v3 (rule R13, pane lifecycle contract): the row carries { v, activeWindowId, windows, known }.
// Safe v1/v2 rows remain readable, but every version is an exact content-blind DTO rather than arbitrary JSON.
describe('remote-layout schema (serialize/parse, exact safe v1/v2/v3)', () => {
  it('v3 round-trips: serialize → parse restores activeWindowId + windows + the known ledger', () => {
    const windows = { 'win-a': { layout: null, stashed: [] } }
    const known = { projects: ['proj-1'], windows: ['win-a'], panes: ['p-1'] }
    const parsed = parseRemoteLayout(serializeRemoteLayout('win-a', windows, known))
    expect(parsed).toEqual({ activeWindowId: 'win-a', windows, known })
    expect(JSON.parse(serializeRemoteLayout(null, {})).v).toBe(REMOTE_LAYOUT_SCHEMA_V)
  })

  it('a null active window serializes and parses as null (not "null"/undefined); no ledger → known null', () => {
    const windows = { w: { layout: null, stashed: [] } }
    expect(parseRemoteLayout(serializeRemoteLayout(null, windows))).toEqual({ activeWindowId: null, windows, known: null })
  })

  it('tolerant v1 read: a bare window map parses with activeWindowId null and the map as windows (known null)', () => {
    const v1 = JSON.stringify({ 'win-a': { layout: null, stashed: [] }, 'win-b': { layout: null, stashed: [] } })
    const parsed = parseRemoteLayout(v1)
    expect(parsed?.activeWindowId).toBeNull()
    expect(parsed?.known).toBeNull()
    expect(Object.keys(parsed?.windows ?? {}).sort()).toEqual(['win-a', 'win-b'])
  })

  it('tolerant v2 read: a v2 row (no known ledger) parses with known null', () => {
    const v2 = JSON.stringify({ v: 2, activeWindowId: 'win-a', windows: { 'win-a': { layout: null, stashed: [] } } })
    const parsed = parseRemoteLayout(v2)
    expect(parsed?.activeWindowId).toBe('win-a')
    expect(parsed?.known).toBeNull()
    expect(Object.keys(parsed?.windows ?? {})).toEqual(['win-a'])
  })

  it('keeps the deployed v1/v2 empty-session repair shape readable, but never emits it in v3', () => {
    const legacy = JSON.stringify({
      v: 2,
      activeWindowId: 'win-a',
      windows: {
        'win-a': {
          layout: { root: { kind: 'leaf', id: 'pane-a', sessionId: '' }, activePaneId: 'pane-a' },
          stashed: [],
        },
      },
    })
    expect(parseRemoteLayout(legacy)?.windows['win-a']?.layout?.root).toMatchObject({ sessionId: '' })
    const rewritten = JSON.parse(serializeRemoteLayout('win-a', parseRemoteLayout(legacy)!.windows))
    expect(rewritten.v).toBe(3)
    expect(rewritten.windows['win-a'].layout.root.sessionId).toBeNull()
  })

  it('malformed or non-exact rows parse to null rather than projecting unknown legacy content', () => {
    expect(parseRemoteLayout('not json')).toBeNull()
    expect(parseRemoteLayout('42')).toBeNull()
    expect(parseRemoteLayout('[1,2]')).toBeNull()
    expect(parseRemoteLayout('null')).toBeNull()
    expect(parseRemoteLayout(JSON.stringify({ v: 2, activeWindowId: 7, windows: [1] }))).toBeNull()
    expect(parseRemoteLayout(JSON.stringify({ v: 3, activeWindowId: null, windows: {}, known: { projects: [1, 'p'], windows: 'x', panes: null } })))
      .toBeNull()
    expect(parseRemoteLayout(JSON.stringify({ v: 4, activeWindowId: null, windows: {} }))).toBeNull()
  })

  it('constructs a name-free v3 DTO instead of serializing arbitrary workspace objects', () => {
    const encoded = serializeRemoteLayout('win-a', {
      'win-a': {
        layout: { root: { kind: 'leaf', id: 'pane-a', sessionId: 'session-a', title: 'PRIVATE' }, activePaneId: 'pane-a', path: '/private' },
        stashed: [{ paneId: 'pane-b', sessionId: 'session-b', name: 'PRIVATE STASH', cwd: '/private' }],
        windowStashed: false,
        name: 'PRIVATE WINDOW',
      },
    } as unknown as Record<string, import('../model/pane-layout').WorkspacePanes>, {
      projects: ['proj-a'], windows: ['win-a'], panes: ['pane-a', 'pane-b'],
    })
    expect(encoded).not.toContain('PRIVATE')
    expect(encoded).not.toContain('/private')
    expect(JSON.parse(encoded)).toEqual({
      v: 3,
      activeWindowId: 'win-a',
      windows: {
        'win-a': {
          layout: { root: { kind: 'leaf', id: 'pane-a', sessionId: 'session-a' }, activePaneId: 'pane-a' },
          stashed: [{ paneId: 'pane-b', sessionId: 'session-b' }],
          windowStashed: false,
        },
      },
      known: { projects: ['proj-a'], windows: ['win-a'], panes: ['pane-a', 'pane-b'] },
    })
  })

  it('rejects names, paths and unknown fields when parsing stored v1/v2/v3 rows', () => {
    const safeWorkspace = { layout: null, stashed: [] }
    for (const row of [
      { 'win-a': { ...safeWorkspace, name: 'PRIVATE' } },
      { v: 2, activeWindowId: 'win-a', windows: { 'win-a': { layout: null, stashed: [{ paneId: 'p', sessionId: 's', name: 'PRIVATE' }] } } },
      { v: 3, activeWindowId: null, windows: {}, known: { projects: [], windows: [], panes: [], path: '/private' } },
      { v: 3, activeWindowId: null, windows: {}, terminalOutput: 'PRIVATE' },
    ]) {
      expect(parseRemoteLayout(JSON.stringify(row))).toBeNull()
    }
  })
})
