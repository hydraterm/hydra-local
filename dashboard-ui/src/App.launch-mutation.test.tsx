import { afterEach, expect, it, vi } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { App } from './App'
import { mockDashboardModel } from './data/mock'
import { bridge } from './ipc/bridge'

type TestWindow = Window & { __HYDRA_SHOW_OVERLAY_MODAL__?: (modal: object) => void }
let renderer: ReactTestRenderer | null = null
afterEach(() => {
  if (renderer) act(() => renderer!.unmount())
  renderer = null
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

async function open(kind: 'newWindow' | 'split') {
  vi.useFakeTimers()
  vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([])
  const intents: Array<Record<string, unknown>> = []
  const host = Object.assign(new EventTarget(), {
    location: { href: 'hydra://localhost/index.html?chrome=overlay', search: '?chrome=overlay' },
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    hydraDashboard: {
      getDashboardModel: () => structuredClone(mockDashboardModel),
      onDashboardModel: () => () => undefined,
      postIntent: (intent: Record<string, unknown>) => {
        intents.push(intent)
        if (intent.type === 'preflightLaunch') {
          host.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(String(intent.request_id), true, null)
        }
      },
    },
  }) as unknown as TestWindow
  vi.stubGlobal('window', host)
  vi.stubGlobal('document', {
    body: { classList: { add: () => undefined, remove: () => undefined } },
  })
  await act(async () => {
    renderer = create(<App />)
    await Promise.resolve()
  })
  const modal = kind === 'newWindow'
    ? { kind, project_id: 'sample_workspace' }
    : { kind, project_id: 'sample_workspace', window_id: 'w-main', tab_id: 'tab-claude', dir: 'h' }
  act(() => host.__HYDRA_SHOW_OVERLAY_MODAL__?.(modal))
  const name = () => renderer!.root.findByProps(kind === 'newWindow'
    ? { placeholder: 'literature, experiment, deployment...' }
    : { 'aria-label': 'Pane name' })
  act(() => name().props.onChange({ target: { value: 'Retain my draft' } }))
  const submit = () => renderer!.root.findByProps({ className: 'split-dialog__submit' })
  await act(async () => {
    submit().props.onClick()
    await Promise.resolve()
  })
  const request = intents.find(intent => intent.type === (kind === 'split' ? 'splitPane' : 'createWindow'))!
  expect(typeof request.request_id).toBe('string')
  return { host, intents, name, submit, request, modal }
}

it.each(['newWindow', 'split'] as const)('retains %s draft/request through timeout and shows the exact native refusal', async kind => {
  const { host, intents, name, submit, request } = await open(kind)
  expect(submit().props.disabled).toBe(true)
  expect(intents.some(intent => intent.type === 'closeOverlay')).toBe(false)
  await act(async () => {
    await vi.advanceTimersByTimeAsync(10_001)
  })
  expect(renderer!.root.findByProps({ role: 'alert' }).children.join('')).toContain('request are retained')
  expect(name().props.value).toBe('Retain my draft')
  expect(submit().props.disabled).toBe(true)
  await act(async () => {
    submit().props.onClick()
    await Promise.resolve()
  })
  expect(intents.filter(intent => intent.type === request.type)).toEqual([request])
  const reason = 'Scratch creation failed: the selected directory is not writable.'
  await act(async () => {
    host.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_MUTATION__?.(String(request.request_id), false, reason)
    await Promise.resolve()
  })
  expect(renderer!.root.findByProps({ role: 'alert' }).children.join('')).toBe(reason)
  expect(name().props.value).toBe('Retain my draft')
  expect(submit().props.disabled).toBe(false)
  expect(intents.some(intent => intent.type === 'closeOverlay')).toBe(false)
})

it('ignores unrelated/old replies and closes only on its exact native acceptance', async () => {
  const { host, intents, submit, request, modal } = await open('newWindow')
  await act(async () => {
    host.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_MUTATION__?.('wrong-request', true, null)
    await Promise.resolve()
  })
  expect(submit().props.disabled).toBe(true)
  await act(async () => {
    host.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_MUTATION__?.(String(request.request_id), true, null)
    await Promise.resolve()
  })
  expect(renderer!.root.findAllByProps({ role: 'dialog' })).toHaveLength(0)
  expect(intents.filter(intent => intent.type === 'closeOverlay')).toHaveLength(1)
  act(() => host.__HYDRA_SHOW_OVERLAY_MODAL__?.(modal))
  await act(async () => {
    host.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_MUTATION__?.(String(request.request_id), false, 'old failure')
    await Promise.resolve()
  })
  expect(renderer!.root.findAllByProps({ role: 'dialog' })).toHaveLength(1)
  expect(renderer!.root.findAllByProps({ role: 'alert' })).toHaveLength(0)
})

it('does not turn an uncertain host exception into a retryable native refusal', async () => {
  await open('newWindow')
  const controller = new AbortController()
  const onWaiting = vi.fn()
  const posted = vi.fn(() => { throw new Error('host threw after posting') })
  const resolved = vi.fn()
  const response = bridge.awaitLaunchMutation(posted, onWaiting, controller.signal)
  void response.then(resolved)
  await Promise.resolve()
  expect(posted).toHaveBeenCalledOnce()
  expect(onWaiting).toHaveBeenCalledOnce()
  expect(resolved).not.toHaveBeenCalled()
  controller.abort()
  expect((await response).ok).toBe(false)
  expect(posted).toHaveBeenCalledOnce()
})
