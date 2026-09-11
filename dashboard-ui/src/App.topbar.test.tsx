import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { App } from './App'
import { mockDashboardModel } from './data/mock'
import type { DashboardModel } from './types/model'

let renderer: ReactTestRenderer | null = null

function installWindow(
  intents: Array<Record<string, unknown>>,
  search = '?chrome=topbar',
  initialModel: DashboardModel = structuredClone(mockDashboardModel),
): void {
  const browserWindow = Object.assign(new EventTarget(), {
    location: {
      href: `hydra://localhost/index.html${search}`,
      search,
    },
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    hydraDashboard: {
      getDashboardModel: () => structuredClone(initialModel),
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
  it.each(['before', 'after'] as const)('drags across projects to the %s edge without changing active focus', async (edge) => {
    const intents: Array<Record<string, unknown>> = []
    installWindow(intents)
    await mount()
    const source = renderer!.root.findByProps({ 'aria-label': 'Focus Analytics report in Sample Analytics' })
    const target = renderer!.root.findByProps({ 'aria-label': 'Focus Dashboard build in Sample Workspace' })
    act(() => source.props.onDragStart({ dataTransfer: { setData: vi.fn() } }))
    const event = {
      preventDefault: vi.fn(), clientX: edge === 'before' ? 10 : 90,
      currentTarget: { getBoundingClientRect: () => ({ left: 0, width: 100 }) },
    }
    act(() => target.parent!.props.onDragOver(event))
    expect(target.parent!.props.className).toContain(`drop-${edge}`)
    act(() => target.parent!.props.onDrop(event))
    expect(intents).toHaveLength(1)
    const request = intents[0]
    expect(request).toEqual({
      type: 'reorderWindowPresentation', request_id: expect.any(String),
      ordered_window_ids: edge === 'before' ? ['w-sample', 'w-main', 'w-2'] : ['w-main', 'w-sample', 'w-2'],
    })
    expect(target.props['aria-pressed']).toBe(true)
    await act(async () => {
      window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_ORDER__!(String(request.request_id), { status: 'saved' })
    })
    expect(renderer!.root.findAllByProps({ role: 'alert' })).toHaveLength(0)
  })

  it('uses modified arrows for order, retains native failure, and does not intercept ordinary focus keys', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow(intents)
    await mount()
    const button = renderer!.root.findByProps({ 'aria-label': 'Focus Dashboard build in Sample Workspace' })
    const event = { key: 'ArrowRight', altKey: false, shiftKey: false, preventDefault: vi.fn(), stopPropagation: vi.fn() }
    act(() => button.props.onKeyDown(event))
    expect(event.preventDefault).not.toHaveBeenCalled()
    expect(intents).toEqual([])
    act(() => button.props.onKeyDown({ ...event, altKey: true, shiftKey: true }))
    expect(intents[0]).toEqual({ type: 'reorderWindowPresentation', request_id: expect.any(String), ordered_window_ids: ['w-2', 'w-main', 'w-sample'] })
    act(() => button.props.onKeyDown({ ...event, altKey: true, shiftKey: true }))
    expect(intents).toHaveLength(1)
    await act(async () => {
      window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_ORDER__!(String(intents[0].request_id), { status: 'failed', message: 'Settings could not be saved.' })
    })
    expect(renderer!.root.findByProps({ role: 'alert' }).children).toEqual(['Settings could not be saved.'])
    expect(button.props['aria-pressed']).toBe(true)
    expect(intents).toHaveLength(1)
  })

  it.each(['?chrome=topbar', ''])(
    'shows the native order-save warning without retrying creation on %s',
    async (search) => {
      const intents: Array<Record<string, unknown>> = []
      const model = structuredClone(mockDashboardModel)
      model.window_order_warning = "Window order wasn't saved: atomic rename failed"
      installWindow(intents, search, model)
      await mount()
      const warning = renderer!.root.findByProps({ className: 'window-tabs__order-warning' })
      expect(warning.props.role).toBe('status')
      expect(warning.props.title).toBe(model.window_order_warning)
      expect(warning.children).toEqual([model.window_order_warning])
      expect(intents).toEqual([])
    },
  )

  it.each(['?chrome=topbar', ''])(
    'projects saved cross-project order on %s without changing focus or ownership',
    async (search) => {
      const intents: Array<Record<string, unknown>> = []
      const model = structuredClone(mockDashboardModel)
      model.global_window_order = ['missing', 'w-2', 'w-sample', 'w-main']
      model.active_window_id = 'w-main'
      model.active_tab_id = 'tab-claude'
      installWindow(intents, search, model)
      await mount()
      const toolbar = renderer!.root.findByProps({ role: 'toolbar' })
      const focusButtons = toolbar.findAll((node) =>
        typeof node.props['aria-label'] === 'string' && node.props['aria-label'].startsWith('Focus '),
      )
      expect(focusButtons.map((button) => button.props['aria-label'])).toEqual([
        'Focus Release checks in Sample Workspace',
        'Focus Analytics report in Sample Analytics',
        'Focus Dashboard build in Sample Workspace',
      ])
      expect(focusButtons.map((button) => button.props['aria-pressed'])).toEqual([false, false, true])
      expect(intents).toEqual([])
      act(() => focusButtons[1].props.onClick())
      expect(intents[intents.length - 1]).toEqual({
        type: 'focusWindow', project_id: 'sample', window_id: 'w-sample',
      })
      expect(model.global_window_order).toEqual(['missing', 'w-2', 'w-sample', 'w-main'])
    },
  )

  it('uses honest toolbar/button semantics and exposes every action by name', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow(intents)
    await mount()

    const toolbar = renderer!.root.findByProps({ role: 'toolbar' })
    expect(toolbar.props['aria-label']).toBe('Window controls')
    expect(renderer!.root.findAllByProps({ role: 'tab' })).toHaveLength(0)

    const focusButtons = renderer!.root.findAll(
      (node) =>
        typeof node.props['aria-label'] === 'string' &&
        node.props['aria-label'].startsWith('Focus '),
    )
    expect(focusButtons.map((button) => button.props['aria-label'])).toEqual([
      'Focus Dashboard build in Sample Workspace',
      'Focus Release checks in Sample Workspace',
      'Focus Analytics report in Sample Analytics',
    ])

    const active = renderer!.root.findByProps({
      'aria-label': 'Focus Dashboard build in Sample Workspace',
    })
    const inactive = renderer!.root.findByProps({
      'aria-label': 'Focus Release checks in Sample Workspace',
    })
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

  it("allows a project's sole visible window to close when another window exists globally", async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow(intents)
    await mount()

    const projectSoleClose = renderer!.root.findByProps({
      'aria-label': 'Close Analytics report in Sample Analytics',
    })
    expect(projectSoleClose.props.disabled).toBe(false)
    expect(projectSoleClose.props.title).toBe('Close window')
  })

  it('keeps the globally sole visible window protected', async () => {
    const intents: Array<Record<string, unknown>> = []
    const initialModel = structuredClone(mockDashboardModel)
    initialModel.projects = initialModel.projects.filter(
      (project) => project.project_id === 'sample',
    )
    initialModel.active_project = {
      project_id: 'sample',
      name: 'Sample Analytics',
      icon: '📊',
      accent_color: '#34d399',
    }
    initialModel.active_window_id = 'w-sample'
    initialModel.active_tab_id = 'tab-report'
    installWindow(intents, '?chrome=topbar', initialModel)
    await mount()

    const globallySoleClose = renderer!.root.findByProps({
      'aria-label': 'Close Analytics report in Sample Analytics',
    })
    expect(globallySoleClose.props.disabled).toBe(true)
    expect(globallySoleClose.props.title).toBe('Keep one window open globally')
  })

  it('uses the active window owner on the first native model', async () => {
    const intents: Array<Record<string, unknown>> = []
    const initialModel = structuredClone(mockDashboardModel)
    initialModel.active_window_id = 'w-sample'
    initialModel.active_tab_id = 'tab-report'
    installWindow(intents, '?chrome=topbar', initialModel)
    await mount()

    const analytics = renderer!.root.findByProps({
      'aria-label': 'Focus Analytics report in Sample Analytics',
    })
    expect(analytics.props['aria-pressed']).toBe(true)
    expect(analytics.props.tabIndex).toBe(0)

    act(() => renderer!.root.findByProps({ 'aria-label': 'New window' }).props.onClick())
    expect(intents[intents.length - 1]).toEqual({
      type: 'openWindowDialog',
      project_id: 'sample',
    })
  })

  it('routes window selection and topbar actions through typed dashboard intents', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow(intents)
    await mount()

    act(() =>
      renderer!.root.findByProps({
        'aria-label': 'Focus Release checks in Sample Workspace',
      }).props.onClick(),
    )
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
    const closeRelease = renderer!.root.findByProps({
      'aria-label': 'Close Release checks in Sample Workspace',
    })
    act(() =>
      closeRelease.props.onClick({
        stopPropagation: vi.fn(),
        currentTarget: {
          closest: () => ({
            querySelectorAll: () => [
              {
                dataset: { toolbarControl: 'window:sample_workspace:w-main:focus' },
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

  it('keeps every project window in the topbar and focuses an exact cross-project window', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow(intents, '')
    await mount()

    const analyticsWindow = renderer!.root.findByProps({
      'aria-label': 'Focus Analytics report in Sample Analytics',
    })
    act(() => analyticsWindow.props.onClick())

    expect(intents.slice(-2)).toEqual([
      { type: 'openWorkspace', project_id: 'sample', workspace_id: undefined },
      { type: 'focusWindow', project_id: 'sample', window_id: 'w-sample' },
    ])
    expect(
      renderer!.root.findByProps({
        'aria-label': 'Focus Analytics report in Sample Analytics',
      }).props['aria-pressed'],
    ).toBe(true)
    expect(
      renderer!.root.findByProps({
        'aria-label': 'Focus Analytics report in Sample Analytics',
      }).props.tabIndex,
    ).toBe(0)
    expect(
      renderer!.root
        .findByProps({ role: 'toolbar' })
        .findAllByType('button')
        .filter((button) => button.props.tabIndex === 0),
    ).toHaveLength(1)
    expect(
      renderer!.root.findByProps({
        'aria-label': 'Focus Dashboard build in Sample Workspace',
      }),
    ).toBeTruthy()
    expect(
      renderer!.root.findByProps({ className: 'terminal-host__detail' }).children.join(''),
    ).toBe('Sample Analytics · Analytics report · 1 pane')

    act(() => renderer!.root.findByProps({ 'aria-label': 'New window' }).props.onClick())
    expect(intents[intents.length - 1]).toEqual({
      type: 'openWindowDialog',
      project_id: 'sample',
    })

    const workspaceProject = renderer!.root.find(
      (node) =>
        node.props.className === 'tree-project__name' &&
        node.children.join('') === 'Sample Workspace',
    ).parent!
    act(() => workspaceProject.props.onClick())

    expect(intents.slice(-2)).toEqual([
      { type: 'openWorkspace', project_id: 'sample_workspace', workspace_id: undefined },
      { type: 'reviveWindow', window_id: 'w-main' },
    ])
    expect(
      renderer!.root.findByProps({
        'aria-label': 'Focus Dashboard build in Sample Workspace',
      }).props['aria-pressed'],
    ).toBe(true)
    expect(
      renderer!.root.findByProps({
        'aria-label': 'Focus Analytics report in Sample Analytics',
      }),
    ).toBeTruthy()
    expect(
      renderer!.root.findByProps({ className: 'terminal-host__detail' }).children.join(''),
    ).toBe('Sample Workspace · Dashboard build · 3 panes')
  })

  it('stashes a background-project window through its owning project', async () => {
    const intents: Array<Record<string, unknown>> = []
    const initialModel = structuredClone(mockDashboardModel)
    const analyticsLogs = structuredClone(initialModel.details.sample.windows[0])
    analyticsLogs.window_id = 'w-sample-logs'
    analyticsLogs.name = 'Analytics logs'
    analyticsLogs.tabs.forEach((tab) => {
      tab.window_id = analyticsLogs.window_id
    })
    initialModel.details.sample.windows.push(analyticsLogs)
    installWindow(intents, '?chrome=topbar', initialModel)
    await mount()

    const close = renderer!.root.findByProps({
      'aria-label': 'Close Analytics logs in Sample Analytics',
    })
    expect(close.props.disabled).toBe(false)
    act(() =>
      close.props.onClick({
        stopPropagation: vi.fn(),
        currentTarget: { closest: () => null },
      }),
    )

    expect(intents[intents.length - 1]).toEqual({
      type: 'stashWindow',
      project_id: 'sample',
      window_id: 'w-sample-logs',
    })
    act(() => renderer!.root.findByProps({ 'aria-label': 'New window' }).props.onClick())
    expect(intents[intents.length - 1]).toEqual({
      type: 'openWindowDialog',
      project_id: 'sample_workspace',
    })
  })

  it('provides wrapping arrow, Home, and End navigation inside the toolbar', async () => {
    const intents: Array<Record<string, unknown>> = []
    installWindow(intents)
    await mount()

    const toolbar = renderer!.root.findByProps({ role: 'toolbar' })
    const buttons = [
      {
        dataset: { toolbarControl: 'window:sample_workspace:w-main:focus' },
        focus: vi.fn(),
      },
      {
        dataset: { toolbarControl: 'window:sample_workspace:w-main:close' },
        focus: vi.fn(),
      },
      {
        dataset: { toolbarControl: 'window:sample_workspace:w-2:focus' },
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
    expect(
      renderer!.root.findByProps({
        'aria-label': 'Focus Release checks in Sample Workspace',
      }).props.tabIndex,
    ).toBe(0)
    act(() => renderer!.update(<App />))
    expect(
      renderer!.root.findAllByType('button').filter((button) => button.props.tabIndex === 0),
    ).toHaveLength(1)
    expect(
      renderer!.root.findByProps({
        'aria-label': 'Focus Release checks in Sample Workspace',
      }).props.tabIndex,
    ).toBe(0)
    fire('ArrowRight', buttons[2])
    expect(buttons[0].focus).toHaveBeenCalledOnce()
    fire('Home', buttons[1])
    expect(buttons[0].focus).toHaveBeenCalledTimes(2)
    fire('End', buttons[0])
    expect(buttons[2].focus).toHaveBeenCalledTimes(2)
  })
})
