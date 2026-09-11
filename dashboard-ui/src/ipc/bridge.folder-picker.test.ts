import { afterEach, describe, expect, it, vi } from 'vitest'

type PickerWindow = Window & {
  __HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__?: (id: string, path: string | null) => void
}

async function nativePicker(post?: (intent: Record<string, unknown>) => void) {
  vi.useFakeTimers()
  vi.resetModules()
  const intents: Array<Record<string, unknown>> = []
  const browserWindow = Object.assign(new EventTarget(), {
    location: { href: 'hydra://localhost/index.html?chrome=overlay', search: '?chrome=overlay' },
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    hydraDashboard: {
      postIntent: (intent: Record<string, unknown>) => {
        intents.push(intent)
        if (intent.type === 'pickProjectFolder') post?.(intent)
      },
    },
  }) as unknown as PickerWindow
  vi.stubGlobal('window', browserWindow)
  const { bridge } = await import('./bridge')
  await vi.advanceTimersByTimeAsync(0)
  intents.length = 0
  return { bridge, browserWindow, intents }
}

afterEach(() => {
  vi.clearAllTimers()
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('native folder picker lifetime', () => {
  it('keeps a human-owned chooser pending beyond a minute and accepts its eventual selection', async () => {
    vi.useFakeTimers()
    const { bridge, browserWindow, intents } = await nativePicker()
    const picked = vi.fn()
    const request = bridge.pickProjectFolder().then(picked)
    const id = String(intents[0].request_id)

    await vi.advanceTimersByTimeAsync(5 * 60_000)
    expect(picked).not.toHaveBeenCalled()
    expect(intents).toEqual([{ type: 'pickProjectFolder', request_id: id }])

    browserWindow.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__!(id, '/chosen/workspace')
    await request
    expect(picked).toHaveBeenCalledExactlyOnceWith('/chosen/workspace')
    browserWindow.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__!(id, '/late/duplicate')
    await Promise.resolve()
    expect(picked).toHaveBeenCalledTimes(1)
  })

  it('correlates selection and native cancellation without consuming another chooser', async () => {
    const { bridge, browserWindow, intents } = await nativePicker()
    const first = bridge.pickProjectFolder()
    const secondPicked = vi.fn()
    const second = bridge.pickProjectFolder().then(secondPicked)
    const firstId = String(intents[0].request_id)
    const secondId = String(intents[1].request_id)
    expect(firstId).not.toBe(secondId)

    browserWindow.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__!('unrelated-request', '/wrong')
    browserWindow.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__!(firstId, null)
    await expect(first).resolves.toBeNull()
    expect(secondPicked).not.toHaveBeenCalled()
    browserWindow.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__!(firstId, '/stale')
    browserWindow.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__!(secondId, '/second/workspace')
    await second
    expect(secondPicked).toHaveBeenCalledExactlyOnceWith('/second/workspace')
  })

  it('retains native dispatch errors instead of leaving an abandoned resolver', async () => {
    const failure = new Error('Native picker could not be dispatched')
    const { bridge, browserWindow, intents } = await nativePicker(() => { throw failure })
    await expect(bridge.pickProjectFolder()).rejects.toBe(failure)
    expect(() => browserWindow.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__!(
      String(intents[0].request_id), '/late',
    )).not.toThrow()
  })

  it('returns no selection immediately when no native picker is available', async () => {
    const { bridge, browserWindow, intents } = await nativePicker()
    delete (browserWindow as unknown as { hydraDashboard?: unknown }).hydraDashboard
    await expect(bridge.pickProjectFolder()).resolves.toBeNull()
    expect(intents).toEqual([])
  })
})
