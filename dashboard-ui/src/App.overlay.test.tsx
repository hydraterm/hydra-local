import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { App, dialogFocusWrapIndex, joinOverlayLaunchArgv } from './App'
import { mockDashboardModel } from './data/mock'
import { bridge } from './ipc/bridge'
import type { AgentFolderSession, DashboardModel } from './types/model'

type OverlayTestWindow = Window & {
  __HYDRA_SHOW_OVERLAY_MODAL__?: (
    modal:
      | { kind: 'editProject'; project_id: string }
      | { kind: 'newProject' }
      | { kind: 'newWindow'; project_id: string }
      | {
          kind: 'split'
          project_id: string
          window_id: string
          tab_id: string
          dir: 'h' | 'v'
        },
  ) => void
  __HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?: (
    requestId: string,
    ok: boolean,
    message: string | null,
    code?: string | null,
  ) => void
}

let renderer: ReactTestRenderer | null = null

afterEach(() => {
  if (renderer) {
    act(() => renderer?.unmount())
    renderer = null
  }
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('lazy native overlay model delivery', () => {
  it('wraps only the boundary of a dialog Tab sequence', () => {
    expect(dialogFocusWrapIndex(0, -1, false)).toBeNull()
    expect(dialogFocusWrapIndex(3, -1, false)).toBe(0)
    expect(dialogFocusWrapIndex(3, -1, true)).toBe(2)
    expect(dialogFocusWrapIndex(3, 0, true)).toBe(2)
    expect(dialogFocusWrapIndex(3, 2, false)).toBe(0)
    expect(dialogFocusWrapIndex(3, 1, false)).toBeNull()
    expect(dialogFocusWrapIndex(3, 1, true)).toBeNull()
  })

  it('discovers split history from the selected source-window folder, not the project root', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const source = initialModel.details.sample_workspace.windows
      .find((window) => window.window_id === 'w-main')!
      .tabs.find((tab) => tab.tab_id === 'tab-claude')!
    source.cwd = '/Projects/Hydra/dashboard-ui'
    const listSessions = vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([])
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: () => undefined,
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({
        kind: 'split',
        project_id: 'sample_workspace',
        window_id: 'w-main',
        tab_id: 'tab-claude',
        dir: 'h',
      })
      await Promise.resolve()
    })

    expect(listSessions).toHaveBeenLastCalledWith(
      'claude',
      '/Projects/Hydra/dashboard-ui',
      expect.anything(),
    )
  })

  it('aborts folder discovery on Cancel and never applies its late rows', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    let listSignal: AbortSignal | undefined
    let resolveList: ((sessions: AgentFolderSession[]) => void) | undefined
    vi.spyOn(bridge, 'listFolderSessions').mockImplementation((_agent, _cwd, signal) => {
      listSignal = signal
      return new Promise((resolve) => {
        resolveList = resolve
      })
    })
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => intents.push(intent),
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' })
      await Promise.resolve()
    })
    expect(listSignal?.aborted).toBe(false)

    const cancel = renderer!.root
      .findAllByType('button')
      .find((button) => button.children.join('') === 'Cancel')!
    act(() => cancel.props.onClick())
    expect(listSignal?.aborted).toBe(true)

    await act(async () => {
      resolveList?.([{
        id: 'late-session',
        agent: 'claude',
        title: 'Must never render',
        first_message: 'late',
        modified_at_ms: 1,
        message_count: 1,
        folder_index: 1,
        file_path: '/tmp/late-session.jsonl',
        in_use: false,
        custom_name: null,
      }])
      await Promise.resolve()
    })

    expect(renderer!.root.findAllByProps({ className: 'session-picker__rowmain' })).toHaveLength(0)
    expect(intents.filter((intent) => intent.type === 'closeOverlay')).toHaveLength(1)
  })

  it('aborts hidden-session discovery when its view or folder context changes', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([])
    const hiddenSignals: AbortSignal[] = []
    vi.spyOn(bridge, 'listHiddenFolderSessions').mockImplementation(
      (_agent, _cwd, signal) => {
        if (signal) hiddenSignals.push(signal)
        return new Promise(() => {})
      },
    )
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: () => undefined,
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' })
      await Promise.resolve()
      await Promise.resolve()
    })
    const removedToggle = () =>
      renderer!.root
        .findAllByType('button')
        .find((button) => button.children.join('').includes('Removed sessions'))!

    act(() => removedToggle().props.onClick())
    expect(hiddenSignals[0].aborted).toBe(false)
    act(() => removedToggle().props.onClick())
    expect(hiddenSignals[0].aborted).toBe(true)

    act(() => removedToggle().props.onClick())
    expect(hiddenSignals[1].aborted).toBe(false)
    const docsFolder = renderer!.root
      .findAllByType('button')
      .find((button) =>
        button.findAllByProps({ className: 'folder-pick__path' })
          .some((path) => path.children.join('') === '/Projects/Hydra/docs'),
      )!
    await act(async () => {
      docsFolder.props.onClick()
      await Promise.resolve()
    })
    expect(hiddenSignals[1].aborted).toBe(true)

    act(() => removedToggle().props.onClick())
    expect(hiddenSignals[2].aborted).toBe(false)
    const agentSelect = renderer!.root.findByProps({ 'aria-label': 'Window agent' })
    await act(async () => {
      agentSelect.props.onChange({ target: { value: 'codex' } })
      await Promise.resolve()
    })
    expect(hiddenSignals[2].aborted).toBe(true)

    act(() => removedToggle().props.onClick())
    expect(hiddenSignals[3].aborted).toBe(false)
    act(() => browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newProject' }))
    expect(hiddenSignals[3].aborted).toBe(true)
  })

  it('keeps the compact history list but makes every discovered session reachable', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const sessions: AgentFolderSession[] = Array.from({ length: 11 }, (_, index) => ({
      id: `session-${index + 1}`,
      agent: 'claude',
      title: `Session ${index + 1}`,
      first_message: `message ${index + 1}`,
      modified_at_ms: 100 - index,
      ...(index === 0 ? {} : { message_count: 1 }),
      folder_index: index + 1,
      file_path: `/tmp/session-${index + 1}.jsonl`,
      in_use: false,
      custom_name: null,
    }))
    vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue(sessions)
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: () => undefined,
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' })
      await Promise.resolve()
      await Promise.resolve()
    })

    expect(renderer!.root.findAllByProps({ className: 'session-picker__rowmain' })).toHaveLength(8)
    expect(
      renderer!.root.findAll(
        (node) => node.children.some((child) => child === 'undefined events'),
      ),
    ).toHaveLength(0)
    const showAll = renderer!.root
      .findAllByType('button')
      .find((button) => button.children.join('') === 'Show all 11 sessions')!
    act(() => showAll.props.onClick())
    expect(renderer!.root.findAllByProps({ className: 'session-picker__rowmain' })).toHaveLength(11)

    const showFewer = renderer!.root
      .findAllByType('button')
      .find((button) => button.children.join('') === 'Show fewer sessions')!
    act(() => showFewer.props.onClick())
    expect(renderer!.root.findAllByProps({ className: 'session-picker__rowmain' })).toHaveLength(8)

    act(() => showFewer.props.onClick())
    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({
        kind: 'split',
        project_id: 'sample_workspace',
        window_id: 'w-main',
        tab_id: 'tab-claude',
        dir: 'h',
      })
      await Promise.resolve()
    })
    expect(renderer!.root.findAllByProps({ className: 'split-session__main' })).toHaveLength(5)
    expect(
      renderer!.root
        .findAllByType('button')
        .some((button) => button.children.join('') === 'Show all 11 sessions'),
    ).toBe(true)
  })

  it('preempts an in-flight preview when another session is selected', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const sessions: AgentFolderSession[] = [1, 2].map((number) => ({
      id: `preview-session-${number}`,
      agent: 'claude',
      title: `Preview session ${number}`,
      first_message: 'fixture',
      modified_at_ms: number,
      message_count: 1,
      folder_index: number,
      file_path: `/tmp/preview-session-${number}.jsonl`,
      in_use: false,
      custom_name: null,
    }))
    vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue(sessions)
    const previewRequests: Array<{
      signal: AbortSignal | undefined
      resolve: (lines: Array<{ role: 'user' | 'assistant'; text: string }>) => void
    }> = []
    vi.spyOn(bridge, 'previewFolderSession').mockImplementation(
      (_agent, _cwd, _sessionId, signal) => new Promise((resolve) => {
        previewRequests.push({ signal, resolve })
      }),
    )
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: () => undefined,
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' })
      await Promise.resolve()
      await Promise.resolve()
    })
    let previewButtons = renderer!.root
      .findAllByType('button')
      .filter((button) => button.props.title === 'Preview this session')
    act(() => previewButtons[0].props.onClick())
    expect(previewRequests[0].signal?.aborted).toBe(false)

    previewButtons = renderer!.root
      .findAllByType('button')
      .filter((button) => button.props.title === 'Preview this session')
    act(() => previewButtons[1].props.onClick())
    expect(previewRequests[0].signal?.aborted).toBe(true)
    expect(previewRequests[1].signal?.aborted).toBe(false)

    await act(async () => {
      previewRequests[0].resolve([{ role: 'user', text: 'stale preview' }])
      await Promise.resolve()
    })
    expect(
      renderer!.root.findAllByProps({ className: 'session-preview__text' }),
    ).toHaveLength(0)

    await act(async () => {
      previewRequests[1].resolve([{ role: 'assistant', text: 'current preview' }])
      await Promise.resolve()
    })
    expect(
      renderer!.root.findByProps({ className: 'session-preview__text' }).children.join(''),
    ).toBe('current preview')
  })

  it('routes Antigravity history through the shared New Project, split, and New Window lookup', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const source = initialModel.details.sample_workspace.windows
      .find((window) => window.window_id === 'w-main')!
      .tabs.find((tab) => tab.tab_id === 'tab-claude')!
    source.agent = 'antigravity'
    source.cwd = '/Projects/Hydra/dashboard-ui'
    const antigravitySession: AgentFolderSession = {
      id: '30000000-0000-4000-8000-000000000002',
      agent: 'antigravity',
      title: 'Antigravity conversation',
      first_message: '(no preview available)',
      modified_at_ms: 4_000_000_000_000,
      message_count: 0,
      folder_index: 1,
      file_path: 'antigravity://30000000-0000-4000-8000-000000000002',
      in_use: false,
      custom_name: null,
    }
    vi.spyOn(bridge, 'pickProjectFolder').mockResolvedValue(null)
    const listSessions = vi.spyOn(bridge, 'listFolderSessions').mockImplementation(
      async (agent) => agent === 'antigravity' ? [antigravitySession] : [],
    )
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: () => undefined,
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })

    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({
        kind: 'split',
        project_id: 'sample_workspace',
        window_id: 'w-main',
        tab_id: 'tab-claude',
        dir: 'h',
      })
      await Promise.resolve()
      await Promise.resolve()
    })
    await act(async () => {
      await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 0))
    })
    expect(listSessions).toHaveBeenLastCalledWith(
      'antigravity',
      '/Projects/Hydra/dashboard-ui',
      expect.anything(),
    )
    expect(renderer!.root.findByProps({ className: 'split-session__main' })).toBeTruthy()

    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' })
      await Promise.resolve()
    })
    const windowAgent = renderer!.root.findByProps({ 'aria-label': 'Window agent' })
    await act(async () => {
      windowAgent.props.onChange({ target: { value: 'antigravity' } })
      await Promise.resolve()
      await Promise.resolve()
    })
    await act(async () => {
      await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 0))
    })
    expect(listSessions).toHaveBeenLastCalledWith(
      'antigravity',
      '/Projects/Hydra',
      expect.anything(),
    )
    expect(renderer!.root.findByProps({ className: 'session-picker__rowmain' })).toBeTruthy()

    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newProject' })
      await Promise.resolve()
    })
    const projectRoot = renderer!.root.findByProps({ placeholder: '~/path/to/project' })
    const projectAgent = renderer!.root.findByProps({ 'aria-label': 'Default agent' })
    await act(async () => {
      projectRoot.props.onChange({ target: { value: '/Projects/New Antigravity' } })
      projectAgent.props.onChange({ target: { value: 'antigravity' } })
      await Promise.resolve()
      await Promise.resolve()
    })
    await act(async () => {
      await new Promise<void>((resolve) => globalThis.setTimeout(resolve, 0))
    })
    expect(listSessions).toHaveBeenLastCalledWith(
      'antigravity',
      '/Projects/New Antigravity',
      expect.anything(),
    )
    expect(renderer!.root.findByProps({ className: 'session-picker__rowmain' })).toBeTruthy()
  })

  it('focuses one primary control in every modal and closes through the native focus boundary', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    vi.spyOn(bridge, 'pickProjectFolder').mockResolvedValue(null)
    vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([])
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => intents.push(intent),
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })

    const cases = [
      {
        modal: {
          kind: 'split',
          project_id: 'sample_workspace',
          window_id: 'w-main',
          tab_id: 'tab-claude',
          dir: 'h',
        } as const,
        dialogLabel: 'Split right',
        focusProp: ['aria-label', 'Pane name'] as const,
      },
      {
        modal: { kind: 'newProject' } as const,
        dialogLabel: 'New project',
        focusProp: ['placeholder', 'Capacity Paper'] as const,
      },
      {
        modal: { kind: 'editProject', project_id: 'sample_workspace' } as const,
        dialogLabel: 'Edit project',
        focusProp: ['placeholder', 'Project name'] as const,
      },
      {
        modal: { kind: 'newWindow', project_id: 'sample_workspace' } as const,
        dialogLabel: 'New window',
        focusProp: ['placeholder', 'literature, experiment, deployment...'] as const,
      },
    ]

    for (const testCase of cases) {
      // The native host's JavaScript completion callback runs as soon as this external hook
      // returns. Every dialog must therefore already be committed (including autofocus) without
      // awaiting a React task/microtask before the host may expose the overlay WebView.
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.(testCase.modal)

      const dialog = renderer!.root.findByProps({ 'aria-label': testCase.dialogLabel })
      expect(dialog.props['aria-modal']).toBe('true')
      const initialTargets = dialog.findAll((node) => node.props.autoFocus === true)
      expect(initialTargets).toHaveLength(1)
      expect(initialTargets[0].props[testCase.focusProp[0]]).toBe(testCase.focusProp[1])
      expect(dialog.props.onKeyDown).toBeTypeOf('function')

      const first = {
        hidden: false,
        getAttribute: () => null,
        closest: () => null,
        focus: vi.fn(),
      }
      const last = {
        hidden: false,
        getAttribute: () => null,
        closest: () => null,
        focus: vi.fn(),
      }
      const ownerDocument = { activeElement: last }
      const currentTarget = {
        ownerDocument,
        querySelectorAll: () => [first, last],
      }
      const preventDefault = vi.fn()
      const stopPropagation = vi.fn()
      act(() =>
        dialog.props.onKeyDown({
          key: 'Tab',
          shiftKey: false,
          defaultPrevented: false,
          currentTarget,
          preventDefault,
          stopPropagation,
        }),
      )
      expect(first.focus).toHaveBeenCalledOnce()
      expect(preventDefault).toHaveBeenCalledOnce()
      expect(stopPropagation).toHaveBeenCalledOnce()

      ownerDocument.activeElement = first
      act(() =>
        dialog.props.onKeyDown({
          key: 'Tab',
          shiftKey: true,
          defaultPrevented: false,
          currentTarget,
          preventDefault,
          stopPropagation,
        }),
      )
      expect(last.focus).toHaveBeenCalledOnce()
      expect(preventDefault).toHaveBeenCalledTimes(2)
      expect(stopPropagation).toHaveBeenCalledTimes(2)

      const closesBefore = intents.filter((intent) => intent.type === 'closeOverlay').length
      act(() =>
        dialog.props.onKeyDown({
          key: 'Escape',
          shiftKey: false,
          defaultPrevented: false,
          currentTarget,
          preventDefault,
          stopPropagation,
        }),
      )
      expect(intents.filter((intent) => intent.type === 'closeOverlay')).toHaveLength(
        closesBefore + 1,
      )
      expect(renderer!.root.findAllByProps({ 'aria-label': testCase.dialogLabel })).toHaveLength(0)

      await act(async () => {
        browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.(testCase.modal)
        await Promise.resolve()
      })
      const reopenedDialog = renderer!.root.findByProps({ 'aria-label': testCase.dialogLabel })
      const reopenedCancel = reopenedDialog
        .findAllByType('button')
        .find((button) => button.children.join('') === 'Cancel')
      expect(reopenedCancel).toBeDefined()
      act(() => reopenedCancel!.props.onClick())
      expect(intents.filter((intent) => intent.type === 'closeOverlay')).toHaveLength(
        closesBefore + 2,
      )
      expect(renderer!.root.findAllByProps({ 'aria-label': testCase.dialogLabel })).toHaveLength(0)
    }
  })

  it('returns focus from a nested delete confirmation before Escape closes the parent dialog', async () => {
    vi.useFakeTimers()
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    const inertTransitions: boolean[] = []
    const session: AgentFolderSession = {
      id: 'nested-confirm-session',
      agent: 'claude',
      title: 'Nested confirmation',
      first_message: 'hello',
      modified_at_ms: 1,
      message_count: 2,
      folder_index: 1,
      file_path: '/tmp/nested-confirm.jsonl',
      in_use: false,
      custom_name: null,
    }
    vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([session])
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => intents.push(intent),
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })
    const parentNode = {
      isConnected: true,
      contains: () => true,
      querySelectorAll: () => [],
      toggleAttribute: (name: string, force: boolean) => {
        if (name === 'inert') inertTransitions.push(force)
      },
    }

    await act(async () => {
      renderer = create(<App />, {
        createNodeMock: (element) =>
          element.type === 'section' ? parentNode : null,
      })
      await Promise.resolve()
    })
    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' })
      await Promise.resolve()
      await Promise.resolve()
    })

    const parent = renderer!.root.findByProps({ 'aria-label': 'New window' })
    const deleteButton = parent
      .findAllByType('button')
      .find((button) => button.props.title === 'Delete the session file from your computer')!
    const opener = {
      isConnected: true,
      disabled: false,
      closest: () => null,
      focus: vi.fn(),
    }
    act(() => deleteButton.props.onClick({ currentTarget: opener }))

    expect(renderer!.root.findByProps({ 'aria-label': 'New window' }).props['aria-hidden']).toBe(
      'true',
    )
    expect(inertTransitions[inertTransitions.length - 1]).toBe(true)
    const confirm = renderer!.root.findByProps({ 'aria-label': 'Delete session from disk' })
    const preventDefault = vi.fn()
    const stopPropagation = vi.fn()
    act(() =>
      confirm.props.onKeyDown({
        key: 'Escape',
        defaultPrevented: false,
        preventDefault,
        stopPropagation,
      }),
    )
    await act(async () => {
      vi.runAllTimers()
    })

    expect(preventDefault).toHaveBeenCalledOnce()
    expect(stopPropagation).toHaveBeenCalledOnce()
    expect(opener.focus).toHaveBeenCalledOnce()
    expect(renderer!.root.findAllByProps({ 'aria-label': 'Delete session from disk' })).toHaveLength(0)
    const restoredParent = renderer!.root.findByProps({ 'aria-label': 'New window' })
    expect(restoredParent.props['aria-hidden']).toBeUndefined()
    expect(inertTransitions[inertTransitions.length - 1]).toBe(false)

    const reopenedDelete = restoredParent
      .findAllByType('button')
      .find((button) => button.props.title === 'Delete the session file from your computer')!
    const staleOpener = {
      isConnected: true,
      disabled: false,
      closest: () => null,
      focus: vi.fn(),
    }
    act(() => reopenedDelete.props.onClick({ currentTarget: staleOpener }))
    const reopenedConfirm = renderer!.root.findByProps({ 'aria-label': 'Delete session from disk' })
    act(() =>
      reopenedConfirm.props.onKeyDown({
        key: 'Escape',
        defaultPrevented: false,
        preventDefault: vi.fn(),
        stopPropagation: vi.fn(),
      }),
    )
    // Replacing the native modal before the queued restore fires must invalidate the old opener.
    act(() =>
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' }),
    )
    await act(async () => {
      vi.runAllTimers()
    })
    expect(staleOpener.focus).not.toHaveBeenCalled()
    const replacedParent = renderer!.root.findByProps({ 'aria-label': 'New window' })
    expect(replacedParent.findAll((node) => node.props.autoFocus === true)).toHaveLength(1)

    act(() =>
      replacedParent.props.onKeyDown({
        key: 'Escape',
        defaultPrevented: false,
        preventDefault: vi.fn(),
        stopPropagation: vi.fn(),
      }),
    )
    expect(intents.filter((intent) => intent.type === 'closeOverlay')).toHaveLength(1)
  })

  it('unhides the parent and restores a fallback when the confirmed session disappears', async () => {
    vi.useFakeTimers()
    const initialModel = structuredClone(mockDashboardModel)
    const session: AgentFolderSession = {
      id: 'vanishing-confirm-session',
      agent: 'claude',
      title: 'Vanishing confirmation',
      first_message: 'hello',
      modified_at_ms: 1,
      message_count: 2,
      folder_index: 1,
      file_path: '/tmp/vanishing-confirm.jsonl',
      in_use: false,
      custom_name: null,
    }
    let resolveRemoval!: (sessions: AgentFolderSession[]) => void
    const removal = new Promise<AgentFolderSession[]>((resolve) => {
      resolveRemoval = resolve
    })
    vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([session])
    vi.spyOn(bridge, 'removeFolderSession').mockReturnValue(removal)
    const fallback = {
      hidden: false,
      getAttribute: () => null,
      closest: () => null,
      focus: vi.fn(),
    }
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: () => undefined,
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })
    const parentNode = {
      isConnected: true,
      contains: () => false,
      querySelectorAll: () => [fallback],
      toggleAttribute: () => undefined,
    }

    await act(async () => {
      renderer = create(<App />, {
        createNodeMock: (element) =>
          element.type === 'section' ? parentNode : null,
      })
      await Promise.resolve()
    })
    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' })
      await Promise.resolve()
      await Promise.resolve()
    })

    const parent = renderer!.root.findByProps({ 'aria-label': 'New window' })
    const buttons = parent.findAllByType('button')
    const removeButton = buttons.find((button) =>
      String(button.props.className ?? '').includes('session-picker__act--remove'),
    )!
    const deleteButton = buttons.find(
      (button) => button.props.title === 'Delete the session file from your computer',
    )!
    act(() => removeButton.props.onClick())
    const opener = {
      isConnected: true,
      disabled: false,
      closest: () => null,
      focus: vi.fn(),
    }
    act(() => deleteButton.props.onClick({ currentTarget: opener }))
    expect(renderer!.root.findByProps({ 'aria-label': 'New window' }).props['aria-hidden']).toBe(
      'true',
    )
    expect(renderer!.root.findAllByProps({ 'aria-label': 'Delete session from disk' })).toHaveLength(1)

    opener.isConnected = false
    await act(async () => {
      resolveRemoval([])
      await removal
      await Promise.resolve()
    })
    await act(async () => {
      vi.runAllTimers()
    })

    expect(renderer!.root.findAllByProps({ 'aria-label': 'Delete session from disk' })).toHaveLength(0)
    expect(renderer!.root.findByProps({ 'aria-label': 'New window' }).props['aria-hidden']).toBeUndefined()
    expect(fallback.focus).toHaveBeenCalledOnce()
    expect(opener.focus).not.toHaveBeenCalled()
  })

  it('closes from a completed backdrop click without mouse-down click-through', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => intents.push(intent),
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    act(() => browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newProject' }))

    const overlay = renderer!.root.findByProps({
      className: 'overlay-root overlay-root--active',
    })
    expect(overlay.props.onMouseDown).toBeUndefined()

    // A descendant click bubbles to the root but must not close the modal.
    act(() => overlay.props.onClick({ target: {}, currentTarget: {} }))
    expect(intents.filter((intent) => intent.type === 'closeOverlay')).toHaveLength(0)
    expect(renderer!.root.findByProps({ 'aria-label': 'New project' })).toBeTruthy()

    // The native overlay is hidden only after press+release have completed on the backdrop.
    const backdrop = {}
    act(() => overlay.props.onClick({ target: backdrop, currentTarget: backdrop }))
    expect(intents.filter((intent) => intent.type === 'closeOverlay')).toHaveLength(1)
    expect(renderer!.root.findAllByProps({ 'aria-label': 'New project' })).toHaveLength(0)
  })

  it('logs only mock intent types and never fallback payload secrets', async () => {
    const info = vi.spyOn(console, 'info').mockImplementation(() => undefined)
    const browserWindow = Object.assign(new EventTarget(), {
      location: { href: 'http://localhost/', search: '' },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)

    await bridge.preflightLaunch({
      agent: 'claude',
      resolved_launch_command: 'SECRET_COMMAND --token=TOP_SECRET',
      cwd: '/example/private/SECRET_PATH',
    })
    bridge.enrollDesktop('SECRET_ENROLLMENT_CODE')

    expect(info).toHaveBeenCalledWith('[dashboard intent]', 'preflightLaunch')
    expect(info).toHaveBeenCalledWith('[dashboard intent]', 'enrollDesktop')
    const rendered = JSON.stringify(info.mock.calls)
    for (const secret of [
      'SECRET_COMMAND',
      'TOP_SECRET',
      'SECRET_PATH',
      'SECRET_ENROLLMENT_CODE',
    ]) {
      expect(rendered).not.toContain(secret)
    }
  })

  it('quotes launch arguments without splitting paths, quotes, or backslashes', () => {
    expect(
      joinOverlayLaunchArgv([
        'gemini',
        '--session-file',
        '/tmp/Hydra Sessions/a "quoted" transcript.json',
        '--model',
        'model with spaces\\variant',
      ]),
    ).toBe(
      `gemini --session-file '/tmp/Hydra Sessions/a "quoted" transcript.json' --model 'model with spaces\\\\variant'`,
    )
  })

  it('derives a same-task modal from the model pushed immediately before it', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    let pushModel: ((model: DashboardModel) => void) | null = null
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: () => undefined,
        onDashboardModel: (listener: (model: DashboardModel) => void) => {
          pushModel = listener
          return () => {
            pushModel = null
          }
        },
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })

    expect(pushModel).not.toBeNull()
    expect(browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__).toBeTypeOf('function')

    const projectId = initialModel.projects[0].project_id
    const pushedModel = structuredClone(initialModel)
    pushedModel.projects[0].name = 'Current model project'
    pushedModel.details[projectId].name = 'Current model project'
    pushedModel.details[projectId].root = '/current/model/root'

    // This is one native JavaScript task: no render/commit is allowed between the model push and
    // modal dispatch. The modal handler must read App's synchronously updated latest-model ref.
    act(() => {
      pushModel?.(pushedModel)
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'editProject', project_id: projectId })
    })

    const inputs = renderer!.root.findAllByType('input')
    expect(inputs.find((input) => input.props.placeholder === 'Project name')?.props.value).toBe(
      'Current model project',
    )
    expect(
      inputs.find((input) => input.props.placeholder === '~/path/to/project')?.props.value,
    ).toBe('/current/model/root')
  })

  it('commits WebKit input-only model and icon selections through the create intent', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => {
          intents.push(intent)
          if (intent.type === 'preflightLaunch') {
            browserWindow.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(
              String(intent.request_id),
              true,
              null,
            )
          }
        },
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })

    act(() => browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newProject' }))

    const defaultModel = () =>
      renderer!.root.findAllByType('select').find((node) => node.props['aria-label'] === 'Default model')!
    expect(defaultModel().props.value).toBe('default')

    act(() => defaultModel().props.onInput({ currentTarget: { value: 'sonnet' } }))
    expect(defaultModel().props.value).toBe('sonnet')

    const moreIcons = () =>
      renderer!.root.findAllByType('select').find((node) => node.props['aria-label'] === 'More project icons')!
    act(() => moreIcons().props.onInput({ currentTarget: { value: '💻' } }))
    expect(moreIcons().props.value).toBe('💻')

    const preview = renderer!.root.find(
      (node) => node.props.className === 'overlay-launch-preview',
    )
    expect(preview.findByType('code').children.join('')).toBe('claude --model sonnet')

    const inputs = renderer!.root.findAllByType('input')
    const name = inputs.find((node) => node.props.placeholder === 'Capacity Paper')!
    const root = inputs.find(
      (node) => node.props.placeholder === '~/path/to/project',
    )!
    act(() => {
      name.props.onChange({ target: { value: 'Model Event QA' } })
      root.props.onChange({ target: { value: '/tmp/model-event-qa' } })
    })
    const createButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    await act(async () => {
      createButton.props.onClick()
      await Promise.resolve()
    })

    expect(intents).toContainEqual(
      expect.objectContaining({
        type: 'createProject',
        name: 'Model Event QA',
        root: '/tmp/model-event-qa',
        icon: '💻',
        default_model: 'sonnet',
        resolved_launch_command: 'claude --model sonnet',
      }),
    )
  })

  it('keeps Factory fresh until explicit latest and exposes Devin history for exact resume', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const devinSession: AgentFolderSession = {
      id: 'synthetic-devin-session',
      agent: 'devin',
      title: 'Synthetic Devin session',
      first_message: 'fixture',
      modified_at_ms: 1,
      message_count: 2,
      folder_index: 1,
      file_path: 'devin://synthetic-devin-session',
      in_use: false,
      custom_name: null,
    }
    vi.spyOn(bridge, 'pickProjectFolder').mockResolvedValue(null)
    const listSessions = vi.spyOn(bridge, 'listFolderSessions').mockImplementation(
      async (agent) => agent === 'devin' ? [devinSession] : [],
    )
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: () => undefined,
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    act(() => browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newProject' }))

    const rootInput = renderer!.root.findByProps({ placeholder: '~/path/to/project' })
    act(() => rootInput.props.onChange({ target: { value: '/tmp/devin-ui-fixture' } }))
    const agentSelect = renderer!.root.findByProps({ 'aria-label': 'Default agent' })
    act(() => agentSelect.props.onChange({ target: { value: 'factory' } }))
    let pills = renderer!.root.findAll((node) =>
      String(node.props.className ?? '').split(/\s+/).includes('overlay-pill'),
    )
    expect(pills.map((pill) => pill.children.join(''))).toEqual(['--resume', 'fresh'])
    expect(String(pills[1].props.className)).toContain('is-active')
    const preview = () => renderer!.root
      .find((node) => node.props.className === 'overlay-launch-preview')
      .findByType('code')
      .children.join('')
    expect(preview()).toBe('droid')
    act(() => pills[0].props.onClick())
    expect(preview()).toBe('droid --resume')

    act(() => agentSelect.props.onChange({ target: { value: 'devin' } }))
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })
    expect(listSessions).toHaveBeenCalledWith(
      'devin',
      '/tmp/devin-ui-fixture',
      expect.anything(),
    )
    pills = renderer!.root.findAll((node) =>
      String(node.props.className ?? '').split(/\s+/).includes('overlay-pill'),
    )
    expect(pills.map((pill) => pill.children.join(''))).toEqual([
      '--continue', '--resume', 'fresh',
    ])
    const sessionRow = renderer!.root.findByProps({ className: 'session-picker__rowmain' })
    act(() => sessionRow.props.onClick())
    expect(preview()).toBe('devin --resume synthetic-devin-session')
    const modelSelect = renderer!.root.findByProps({ 'aria-label': 'Default model' })
    act(() => modelSelect.props.onChange({ currentTarget: { value: 'swe' } }))
    expect(preview()).toBe('devin --resume synthetic-devin-session --model swe')
  })

  it('keeps a launch modal open and shows a bounded alert when the executable is missing', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => {
          intents.push(intent)
          if (intent.type === 'preflightLaunch') {
            browserWindow.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(
              String(intent.request_id),
              false,
              `Executable claude was not found. ${'x'.repeat(500)}`,
              'agent_executable_missing',
            )
          }
        },
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    act(() => browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newProject' }))

    const inputs = renderer!.root.findAllByType('input')
    act(() => {
      inputs.find((node) => node.props.placeholder === 'Capacity Paper')!.props.onChange({
        target: { value: 'Missing Agent QA' },
      })
      inputs
        .find((node) => node.props.placeholder === '~/path/to/project')!
        .props.onChange({ target: { value: '/tmp/missing-agent-qa' } })
    })
    const createButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    await act(async () => {
      createButton.props.onClick()
      await Promise.resolve()
    })

    expect(intents.filter((intent) => intent.type === 'preflightLaunch')).toHaveLength(1)
    expect(intents.some((intent) => intent.type === 'createProject')).toBe(false)
    expect(renderer!.root.findByProps({ 'aria-label': 'New project' })).toBeTruthy()
    const alert = renderer!.root.findByProps({ role: 'alert' })
    const message = alert.children.join('')
    expect(message).toContain('Claude')
    expect(message).toContain('`claude`')
    expect(message).toContain('`command -v claude`')
    expect(message).toContain('choose Terminal')
    expect(message).not.toContain('Executable claude was not found.')
    expect(message.length).toBeLessThanOrEqual(320)
    const readyButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    expect(readyButton.props.disabled).toBe(false)
  })

  it('fails closed after a bounded timeout when the native preflight never answers', async () => {
    vi.useFakeTimers()
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => intents.push(intent),
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    act(() => browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newProject' }))
    const inputs = renderer!.root.findAllByType('input')
    act(() => {
      inputs.find((node) => node.props.placeholder === 'Capacity Paper')!.props.onChange({
        target: { value: 'Timeout QA' },
      })
      inputs
        .find((node) => node.props.placeholder === '~/path/to/project')!
        .props.onChange({ target: { value: '/tmp/timeout-qa' } })
    })
    const createButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    act(() => createButton.props.onClick())

    await act(async () => {
      vi.advanceTimersByTime(8_000)
      await Promise.resolve()
    })

    expect(intents.filter((intent) => intent.type === 'preflightLaunch')).toHaveLength(1)
    expect(intents.some((intent) => intent.type === 'createProject')).toBe(false)
    expect(renderer!.root.findByProps({ 'aria-label': 'New project' })).toBeTruthy()
    expect(renderer!.root.findByProps({ role: 'alert' }).children.join('')).toContain(
      'could not verify',
    )
  })

  it('deduplicates an in-flight preflight, then creates once and closes on success', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    let pendingRequestId: string | null = null
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => {
          intents.push(intent)
          if (intent.type === 'preflightLaunch') pendingRequestId = String(intent.request_id)
        },
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    act(() => browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newProject' }))
    const inputs = renderer!.root.findAllByType('input')
    act(() => {
      inputs.find((node) => node.props.placeholder === 'Capacity Paper')!.props.onChange({
        target: { value: 'Single Create QA' },
      })
      inputs
        .find((node) => node.props.placeholder === '~/path/to/project')!
        .props.onChange({ target: { value: '/tmp/single-create-qa' } })
    })
    const createButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    act(() => {
      createButton.props.onClick()
      createButton.props.onClick()
    })

    expect(intents.filter((intent) => intent.type === 'preflightLaunch')).toHaveLength(1)
    expect(intents.some((intent) => intent.type === 'createProject')).toBe(false)
    expect(pendingRequestId).not.toBeNull()
    expect(renderer!.root.findByProps({ disabled: true }).children.join('')).toBe('Checking...')

    await act(async () => {
      browserWindow.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(
        pendingRequestId!,
        true,
        null,
      )
      await Promise.resolve()
    })

    expect(intents.filter((intent) => intent.type === 'createProject')).toHaveLength(1)
    expect(intents.filter((intent) => intent.type === 'closeOverlay')).toHaveLength(1)
    expect(renderer!.root.findAllByProps({ 'aria-label': 'New project' })).toHaveLength(0)
  })

  it('does not create click-time values when the visible draft changes during preflight', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    let pendingRequestId: string | null = null
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => {
          intents.push(intent)
          if (intent.type === 'preflightLaunch') pendingRequestId = String(intent.request_id)
        },
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    act(() => browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newProject' }))
    const nameInput = renderer!.root
      .findAllByType('input')
      .find((node) => node.props.placeholder === 'Capacity Paper')!
    const rootInput = renderer!.root
      .findAllByType('input')
      .find((node) => node.props.placeholder === '~/path/to/project')!
    act(() => {
      nameInput.props.onChange({ target: { value: 'Before Check' } })
      rootInput.props.onChange({ target: { value: '/tmp/draft-change' } })
    })
    const createButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    act(() => createButton.props.onClick())
    expect(pendingRequestId).not.toBeNull()

    act(() => nameInput.props.onChange({ target: { value: 'After Check' } }))
    await act(async () => {
      browserWindow.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(
        pendingRequestId!,
        true,
        null,
      )
      await Promise.resolve()
    })

    expect(intents.some((intent) => intent.type === 'createProject')).toBe(false)
    expect(renderer!.root.findByProps({ role: 'alert' }).children.join('')).toContain(
      'settings changed',
    )
    expect(renderer!.root.findByProps({ 'aria-label': 'New project' })).toBeTruthy()
  })

  it('preflights new-window and split launches before either mutation', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => {
          intents.push(intent)
          if (intent.type === 'preflightLaunch') {
            browserWindow.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(
              String(intent.request_id),
              true,
              null,
            )
          }
        },
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })

    act(() =>
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' }),
    )
    const createWindowButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    await act(async () => {
      createWindowButton.props.onClick()
      await Promise.resolve()
    })

    act(() =>
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({
        kind: 'split',
        project_id: 'sample_workspace',
        window_id: 'w-main',
        tab_id: 'tab-claude',
        dir: 'h',
      }),
    )
    const splitButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Split')!
    await act(async () => {
      splitButton.props.onClick()
      await Promise.resolve()
    })

    const launchIntents = intents.filter((intent) =>
      ['preflightLaunch', 'createWindow', 'splitPane'].includes(String(intent.type)),
    )
    expect(launchIntents.map((intent) => intent.type)).toEqual([
      'preflightLaunch',
      'createWindow',
      'preflightLaunch',
      'splitPane',
    ])
    expect(launchIntents[0]).toEqual(
      expect.objectContaining({
        agent: 'claude',
        resolved_launch_command: 'claude --model sonnet',
        cwd: '/Projects/Hydra',
      }),
    )
    expect(launchIntents[2]).toEqual(
      expect.objectContaining({
        agent: 'claude',
        resolved_launch_command: 'claude',
        cwd: '/Projects/Hydra',
      }),
    )
  })

  it('omits the empty launch command when creating a Terminal project', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => {
          intents.push(intent)
          if (intent.type === 'preflightLaunch') {
            browserWindow.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(
              String(intent.request_id),
              true,
              null,
            )
          }
        },
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    act(() => browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newProject' }))
    const inputs = renderer!.root.findAllByType('input')
    act(() => {
      inputs.find((node) => node.props.placeholder === 'Capacity Paper')!.props.onChange({
        target: { value: 'Terminal QA' },
      })
      inputs
        .find((node) => node.props.placeholder === '~/path/to/project')!
        .props.onChange({ target: { value: '/tmp/terminal-project-qa' } })
      inputs
        .find((node) =>
          String(node.props.placeholder).startsWith('Custom command (overrides above)'),
        )!
        .props.onChange({ target: { value: 'claude --stale-hidden-command' } })
      renderer!.root
        .findByProps({ 'aria-label': 'Default agent' })
        .props.onChange({ target: { value: 'terminal' } })
    })
    const createButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    await act(async () => {
      createButton.props.onClick()
      await Promise.resolve()
    })

    const preflight = intents.find((intent) => intent.type === 'preflightLaunch')
    const createProject = intents.find((intent) => intent.type === 'createProject')
    expect(preflight).toEqual(
      expect.objectContaining({
        agent: 'terminal',
        resolved_launch_command: undefined,
        cwd: '/tmp/terminal-project-qa',
      }),
    )
    expect(createProject).toEqual(
      expect.objectContaining({
        name: 'Terminal QA',
        default_agent: 'terminal',
        default_model: 'default',
        resume_mode: 'none',
        resume_session_id: null,
        resume_session_title: null,
        resume_session_file: null,
        dangerous_skip_permissions: false,
        custom_command: null,
        resolved_launch_command: undefined,
        create_initial_session: true,
      }),
    )
  })

  it('preflights a terminal working directory without requiring an agent executable', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => {
          intents.push(intent)
          if (intent.type === 'preflightLaunch') {
            browserWindow.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(
              String(intent.request_id),
              true,
              null,
            )
          }
        },
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    act(() =>
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' }),
    )
    const agentSelect = renderer!.root.findByProps({ 'aria-label': 'Window agent' })
    expect(agentSelect.findAllByType('option').map((option) => option.props.value)).toEqual([
      'claude', 'codex', 'copilot', 'antigravity', 'kimi', 'kiro', 'opencode', 'cursor', 'amp',
      'devin', 'factory', 'terminal',
    ])
    act(() => agentSelect.props.onChange({ target: { value: 'terminal' } }))
    const createButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    await act(async () => {
      createButton.props.onClick()
      await Promise.resolve()
    })

    expect(intents).toContainEqual(
      expect.objectContaining({
        type: 'preflightLaunch',
        agent: 'terminal',
        resolved_launch_command: undefined,
      }),
    )
    expect(intents).toContainEqual(
      expect.objectContaining({
        type: 'createWindow',
        project_id: 'sample_workspace',
        agent: 'terminal',
        resolved_launch_command: undefined,
      }),
    )
  })

  it('disables session mutations while launch preflight is pending', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const session: AgentFolderSession = {
      id: 'resume-session-1',
      agent: 'claude',
      title: 'Resume me',
      first_message: 'hello',
      modified_at_ms: 1,
      message_count: 2,
      folder_index: 1,
      file_path: '/tmp/resume-session-1.jsonl',
      in_use: false,
      custom_name: null,
    }
    vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([session])
    const remove = vi.spyOn(bridge, 'removeFolderSession').mockResolvedValue([])
    const intents: Array<Record<string, unknown>> = []
    let requestId: string | null = null
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => {
          intents.push(intent)
          if (intent.type === 'preflightLaunch') requestId = String(intent.request_id)
        },
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    act(() =>
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' }),
    )
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })
    const sessionRow = renderer!.root.findByProps({ className: 'session-picker__rowmain' })
    act(() => sessionRow.props.onClick())
    const createButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    act(() => createButton.props.onClick())

    expect(requestId).not.toBeNull()
    const removeButton = renderer!.root.findAllByType('button').find((node) =>
      String(node.props.className ?? '').includes('session-picker__act--remove'),
    )!
    const renameButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.props.title === 'Name this session')!
    const deleteButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.props.title === 'Delete the session file from your computer')!
    expect(removeButton.props.disabled).toBe(true)
    expect(renameButton.props.disabled).toBe(true)
    expect(deleteButton.props.disabled).toBe(true)
    act(() => removeButton.props.onClick())
    expect(remove).not.toHaveBeenCalled()

    await act(async () => {
      browserWindow.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(
        requestId!,
        false,
        'Launch unavailable.',
      )
      await Promise.resolve()
    })
    expect(intents.some((intent) => intent.type === 'createWindow')).toBe(false)
  })

  it('previews a session from the Removed section', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const removedSession: AgentFolderSession = {
      id: 'removed-preview-session',
      agent: 'claude',
      title: 'Removed but retained',
      first_message: 'hello',
      modified_at_ms: 1,
      message_count: 3,
      folder_index: 1,
      file_path: '/tmp/removed-preview-session.jsonl',
      in_use: false,
      custom_name: null,
    }
    vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([])
    vi.spyOn(bridge, 'listHiddenFolderSessions').mockResolvedValue([removedSession])
    const preview = vi.spyOn(bridge, 'previewFolderSession').mockResolvedValue([
      { role: 'user', text: 'retained preview line' },
    ])
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: () => undefined,
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' })
      await Promise.resolve()
      await Promise.resolve()
    })
    const removedToggle = renderer!.root
      .findAllByType('button')
      .find((button) => button.children.join('').startsWith('▸ Removed sessions'))!
    await act(async () => {
      removedToggle.props.onClick()
      await Promise.resolve()
    })
    const removedRow = renderer!.root.findByProps({ className: 'session-removed__row' })
    const eye = removedRow.findByProps({ title: 'Preview this session' })
    await act(async () => {
      eye.props.onClick()
      await Promise.resolve()
    })

    expect(preview).toHaveBeenCalledWith(
      'claude',
      '/Projects/Hydra',
      removedSession.id,
      expect.anything(),
    )
    expect(
      removedRow.findByProps({ className: 'session-preview__text' }).children.join(''),
    ).toBe('retained preview line')
  })

  it('removes a permanently deleted hidden session without waiting for another hidden relist', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const removedSession: AgentFolderSession = {
      id: 'removed-delete-session',
      agent: 'claude',
      title: 'Delete this retained session',
      first_message: 'hello',
      modified_at_ms: 1,
      message_count: 3,
      folder_index: 1,
      file_path: '/tmp/removed-delete-session.jsonl',
      in_use: false,
      custom_name: null,
    }
    let resolveDelete!: (sessions: AgentFolderSession[]) => void
    const deleteResult = new Promise<AgentFolderSession[]>((resolve) => {
      resolveDelete = resolve
    })
    vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([])
    const listHidden = vi
      .spyOn(bridge, 'listHiddenFolderSessions')
      .mockResolvedValue([removedSession])
    vi.spyOn(bridge, 'deleteFolderSession').mockReturnValue(deleteResult)
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: () => undefined,
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    await act(async () => {
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' })
      await Promise.resolve()
      await Promise.resolve()
    })
    const removedToggle = renderer!.root
      .findAllByType('button')
      .find((button) => button.children.join('').startsWith('▸ Removed sessions'))!
    await act(async () => {
      removedToggle.props.onClick()
      await Promise.resolve()
    })
    const removedRow = renderer!.root.findByProps({ className: 'session-removed__row' })
    const deleteButton = removedRow.findByProps({
      title: 'Delete the session file from your computer',
    })
    act(() => deleteButton.props.onClick({ currentTarget: { closest: () => null } }))
    const confirmDelete = renderer!.root.findByProps({
      className: 'session-delete-confirm__danger',
    })
    act(() => confirmDelete.props.onClick())

    expect(renderer!.root.findAllByProps({ className: 'session-removed__row' })).toHaveLength(1)
    await act(async () => {
      resolveDelete([])
      await deleteResult
      await Promise.resolve()
    })

    expect(renderer!.root.findAllByProps({ className: 'session-removed__row' })).toHaveLength(0)
    expect(
      renderer!.root
        .findAllByProps({ className: 'session-picker__empty' })
        .some((empty) => empty.children.join('') === 'No removed sessions in this folder.'),
    ).toBe(true)
    expect(listHidden).toHaveBeenCalledOnce()
  })

  it('rejects a stale resume file before sending native preflight', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const session: AgentFolderSession = {
      id: 'resume-session-2',
      agent: 'claude',
      title: 'Resume me',
      first_message: 'hello',
      modified_at_ms: 1,
      message_count: 2,
      folder_index: 1,
      file_path: '/tmp/original-session.jsonl',
      in_use: false,
      custom_name: null,
    }
    vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([session])
    vi.spyOn(bridge, 'removeFolderSession').mockResolvedValue([
      { ...session, file_path: '/tmp/replaced-session.jsonl' },
    ])
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => intents.push(intent),
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    act(() =>
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' }),
    )
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })
    act(() => renderer!.root.findByProps({ className: 'session-picker__rowmain' }).props.onClick())
    const removeButton = renderer!.root.findAllByType('button').find((node) =>
      String(node.props.className ?? '').includes('session-picker__act--remove'),
    )!
    await act(async () => {
      removeButton.props.onClick()
      await Promise.resolve()
    })
    const createButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    act(() => createButton.props.onClick())

    expect(intents.some((intent) => intent.type === 'preflightLaunch')).toBe(false)
    expect(intents.some((intent) => intent.type === 'createWindow')).toBe(false)
    expect(renderer!.root.findByProps({ role: 'alert' }).children.join('')).toContain(
      'selected session changed',
    )
  })

  it('fails closed when a previously-started session removal lands during preflight', async () => {
    const initialModel = structuredClone(mockDashboardModel)
    const session: AgentFolderSession = {
      id: 'resume-session-3',
      agent: 'claude',
      title: 'Race source',
      first_message: 'hello',
      modified_at_ms: 1,
      message_count: 2,
      folder_index: 1,
      file_path: '/tmp/race-source.jsonl',
      in_use: false,
      custom_name: null,
    }
    vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([session])
    let finishRemoval: ((sessions: AgentFolderSession[]) => void) | null = null
    vi.spyOn(bridge, 'removeFolderSession').mockImplementation(
      () => new Promise((resolve) => (finishRemoval = resolve)),
    )
    const intents: Array<Record<string, unknown>> = []
    let requestId: string | null = null
    const browserWindow = Object.assign(new EventTarget(), {
      location: {
        href: 'hydra://localhost/index.html?chrome=overlay',
        search: '?chrome=overlay',
      },
      setTimeout: globalThis.setTimeout.bind(globalThis),
      clearTimeout: globalThis.clearTimeout.bind(globalThis),
      hydraDashboard: {
        getDashboardModel: () => initialModel,
        postIntent: (intent: Record<string, unknown>) => {
          intents.push(intent)
          if (intent.type === 'preflightLaunch') requestId = String(intent.request_id)
        },
        onDashboardModel: () => () => undefined,
      },
    }) as unknown as OverlayTestWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      body: { classList: { add: () => undefined, remove: () => undefined } },
    })

    await act(async () => {
      renderer = create(<App />)
      await Promise.resolve()
    })
    act(() =>
      browserWindow.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind: 'newWindow', project_id: 'sample_workspace' }),
    )
    await act(async () => {
      await Promise.resolve()
      await Promise.resolve()
    })
    act(() => renderer!.root.findByProps({ className: 'session-picker__rowmain' }).props.onClick())
    const removeButton = renderer!.root.findAllByType('button').find((node) =>
      String(node.props.className ?? '').includes('session-picker__act--remove'),
    )!
    act(() => removeButton.props.onClick())
    const createButton = renderer!.root
      .findAllByType('button')
      .find((node) => node.children.join('') === 'Create')!
    act(() => createButton.props.onClick())
    expect(requestId).not.toBeNull()

    await act(async () => {
      finishRemoval?.([])
      await Promise.resolve()
    })
    await act(async () => {
      browserWindow.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(requestId!, true, null)
      await Promise.resolve()
    })

    expect(intents.some((intent) => intent.type === 'createWindow')).toBe(false)
    expect(renderer!.root.findByProps({ role: 'alert' }).children.join('')).toContain(
      'settings changed',
    )
  })
})
