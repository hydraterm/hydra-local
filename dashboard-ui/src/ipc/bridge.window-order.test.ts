import { afterEach, expect, it, vi } from 'vitest'
import { mockDashboardModel } from '../data/mock'

async function setup() {
  vi.useFakeTimers()
  vi.resetModules()
  const intents: Array<Record<string, unknown>> = []
  vi.stubGlobal('window', Object.assign(new EventTarget(), {
    location: { href: 'hydra://localhost/index.html', search: '' },
    setTimeout: globalThis.setTimeout.bind(globalThis), clearTimeout: globalThis.clearTimeout.bind(globalThis),
    hydraDashboard: {
      postIntent: (intent: Record<string, unknown>) => intents.push(intent),
      getDashboardModel: () => structuredClone(mockDashboardModel),
    },
  }))
  const { bridge } = await import('./bridge')
  await vi.advanceTimersByTimeAsync(0)
  intents.length = 0
  return { bridge, intents }
}

afterEach(() => {
  vi.clearAllTimers()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

it('correlates project/global order results and preserves partial native failures', async () => {
  const { bridge, intents } = await setup()
  const project = bridge.updateWindowOrder('p1', ['b', 'a'])
  const global = bridge.reorderWindowPresentation(['c', 'b', 'a'])
  expect(intents.map((intent) => intent.type)).toEqual(['updateWindowOrder', 'reorderWindowPresentation'])
  expect(intents[0].project_id).toBe('p1')
  expect(intents[1].project_id).toBeUndefined()
  const id = String(intents[0].request_id)
  const other = String(intents[1].request_id)
  expect(id).not.toBe(other)
  window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_ORDER__!('stale', { status: 'saved' })
  const partial = { status: 'partial' as const, message: 'Project order was accepted, but global tab order was not saved: write failed' }
  window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_ORDER__!(id, partial)
  await expect(project).resolves.toEqual(partial)
  window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_ORDER__!(id, { status: 'saved' })
  window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_ORDER__!(other, { status: 'saved' })
  await expect(global).resolves.toEqual({ status: 'saved' })
})

it('reports timeout as unconfirmed without retry or consuming a newer acknowledgement', async () => {
  const { bridge, intents } = await setup()
  const first = bridge.reorderWindowPresentation(['b', 'a'])
  await vi.advanceTimersByTimeAsync(8_000)
  await expect(first).resolves.toMatchObject({ status: 'unconfirmed' })
  expect(intents).toHaveLength(1)
  const done = vi.fn()
  const second = bridge.reorderWindowPresentation(['a', 'b']).then(done)
  window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_ORDER__!(String(intents[0].request_id), { status: 'saved' })
  await Promise.resolve()
  expect(done).not.toHaveBeenCalled()
  window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_ORDER__!(String(intents[1].request_id), { status: 'saved' })
  await second
  expect(done).toHaveBeenCalledExactlyOnceWith({ status: 'saved' })
})
