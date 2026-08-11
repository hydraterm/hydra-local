import { afterEach, describe, expect, it, vi } from 'vitest'
import { bridge } from './bridge'
import { installDevHost } from './devHost'

function developmentWindow(search: string): Window {
  return Object.assign(new EventTarget(), {
    location: { href: `http://localhost/${search}`, search },
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
  }) as unknown as Window
}

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllEnvs()
  vi.unstubAllGlobals()
})

describe('development-only dashboard fallback', () => {
  it('loads the mock model lazily for standalone development', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('window', developmentWindow(''))

    const modelPromise = bridge.getDashboardModel()
    await vi.advanceTimersByTimeAsync(150)
    const model = await modelPromise

    expect(model.active_project?.project_id).toBe('sample_workspace')
    expect(model.projects.length).toBeGreaterThan(0)
  })

  it('installs the mock native host only when the development query requests it', async () => {
    const browserWindow = developmentWindow('?host=1')
    vi.stubGlobal('window', browserWindow)

    await installDevHost()

    expect(browserWindow.hydraDashboard).toBeDefined()
    const model = await browserWindow.hydraDashboard?.getDashboardModel?.()
    expect(model?.active_project?.project_id).toBe('sample_workspace')
  })

  it('fails closed without installing mock state in production mode', async () => {
    vi.useFakeTimers()
    vi.stubEnv('DEV', false)
    const browserWindow = developmentWindow('?host=1')
    vi.stubGlobal('window', browserWindow)

    await installDevHost()
    expect(browserWindow.hydraDashboard).toBeUndefined()

    const modelResult = expect(bridge.getDashboardModel()).rejects.toThrow(
      'Hydra dashboard host is unavailable.',
    )
    await vi.advanceTimersByTimeAsync(150)
    await modelResult
  })
})
