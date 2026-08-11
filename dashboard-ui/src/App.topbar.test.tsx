import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { App } from './App'
import { mockDashboardModel } from './data/mock'

let renderer: ReactTestRenderer | null = null

function installWindow(intents: Array<Record<string, unknown>>): void {
  const browserWindow = Object.assign(new EventTarget(), {
    location: {
      href: 'hydra://localhost/index.html?chrome=topbar',
      search: '?chrome=topbar',
    },
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    hydraDashboard: {
      getDashboardModel: () => structuredClone(mockDashboardModel),
      postIntent: (intent: Record<string, unknown>) => intents.push(intent),
      onDashboardModel: () => () => undefined,
    },
  }) as unknown as Window
  vi.stubGlobal('window', browserWindow)
  vi.stubGlobal('document', {
    body: { classList: { add: () => undefined, remove: () => undefined } },
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  })
}

async function mount(): Promise<void> {
  await act(async () => {
    renderer = create(<App />)
    await Promise.resolve()
  })
}

afterEach(() => {
  if (renderer) {
    act(() => renderer?.unmount())
    renderer = null
  }
  vi.unstubAllGlobals()
})

describe('native topbar semantics and intents', () => {
  it('uses honest toolbar/button semantics and exposes every action by name', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow(intents)
    await mount()

    const toolbar = renderer!.root.findByProps({ role: 'toolbar' })
    expect(toolbar.props['aria-label']).toBe('Window controls')
    expect(renderer!.root.findAllByProps({ role: 'tab' })).toHaveLength(0)

    const active = renderer!.root.findByProps({ 'aria-label': 'Focus Dashboard build' })
    const inactive = renderer!.root.findByProps({ 'aria-label': 'Focus Release checks' })
    expect(active.props['aria-pressed']).toBe(true)
    expect(inactive.props['aria-pressed']).toBe(false)
    expect(active.props.tabIndex).toBe(0)
    expect(
      renderer!.root.findAllByType('button').filter((button) => button.props.tabIndex === 0),
    ).toHaveLength(1)

    for (const name of ['New window', 'Split right', 'Split down', 'Open workspace']) {
      expect(renderer!.root.findByProps({ 'aria-label': name })).toBeTruthy()
    }
  })

  it('routes window selection and topbar actions through typed dashboard intents', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow(intents)
    await mount()

    act(() => renderer!.root.findByProps({ 'aria-label': 'Focus Release checks' }).props.onClick())
    expect(intents[intents.length - 1]).toEqual({
      type: 'focusWindow',
      project_id: 'sample_workspace',
      window_id: 'w-2',
    })

    act(() => renderer!.root.findByProps({ 'aria-label': 'New window' }).props.onClick())
    expect(intents[intents.length - 1]).toEqual({
      type: 'openWindowDialog',
      project_id: 'sample_workspace',
    })

    act(() => renderer!.root.findByProps({ 'aria-label': 'Split right' }).props.onClick())
    expect(intents[intents.length - 1]).toEqual({
      type: 'openSplitDialog',
      project_id: 'sample_workspace',
      window_id: 'w-2',
      tab_id: 'tab-w2-claude',
      dir: 'h',
    })

    act(() => renderer!.root.findByProps({ 'aria-label': 'Split down' }).props.onClick())
    expect(intents[intents.length - 1]).toEqual({
      type: 'openSplitDialog',
      project_id: 'sample_workspace',
      window_id: 'w-2',
      tab_id: 'tab-w2-claude',
      dir: 'v',
    })

    const focusFallback = vi.fn()
    const closeRelease = renderer!.root.findByProps({ 'aria-label': 'Close Release checks' })
    act(() =>
      closeRelease.props.onClick({
        stopPropagation: vi.fn(),
        currentTarget: {
          closest: () => ({
            querySelectorAll: () => [
              {
                dataset: { toolbarControl: 'window:w-main:focus' },
                focus: focusFallback,
              },
            ],
          }),
        },
      }),
    )
    expect(focusFallback).toHaveBeenCalledOnce()
    expect(intents[intents.length - 1]).toEqual({
      type: 'stashWindow',
      project_id: 'sample_workspace',
      window_id: 'w-2',
    })
  })

  it('provides wrapping arrow, Home, and End navigation inside the toolbar', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow(intents)
    await mount()

    const toolbar = renderer!.root.findByProps({ role: 'toolbar' })
    const buttons = [
      {
        dataset: { toolbarControl: 'window:w-main:focus' },
        focus: vi.fn(),
      },
      {
        dataset: { toolbarControl: 'window:w-main:close' },
        focus: vi.fn(),
      },
      {
        dataset: { toolbarControl: 'window:w-2:focus' },
        focus: vi.fn(),
      },
    ]
    const fire = (key: string, target: (typeof buttons)[number]) => {
      const preventDefault = vi.fn()
      act(() =>
        toolbar.props.onKeyDown({
          key,
          target,
          currentTarget: { querySelectorAll: () => buttons },
          preventDefault,
        }),
      )
      expect(preventDefault).toHaveBeenCalledOnce()
    }

    fire('ArrowLeft', buttons[0])
    expect(buttons[2].focus).toHaveBeenCalledOnce()
    expect(renderer!.root.findByProps({ 'aria-label': 'Focus Release checks' }).props.tabIndex).toBe(
      0,
    )
    act(() => renderer!.update(<App />))
    expect(
      renderer!.root.findAllByType('button').filter((button) => button.props.tabIndex === 0),
    ).toHaveLength(1)
    expect(renderer!.root.findByProps({ 'aria-label': 'Focus Release checks' }).props.tabIndex).toBe(
      0,
    )
    fire('ArrowRight', buttons[2])
    expect(buttons[0].focus).toHaveBeenCalledOnce()
    fire('Home', buttons[1])
    expect(buttons[0].focus).toHaveBeenCalledTimes(2)
    fire('End', buttons[0])
    expect(buttons[2].focus).toHaveBeenCalledTimes(2)
  })
})
