// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { App } from './App'
import { bridge, type WindowRenameResult } from './ipc/bridge'
import { mockDashboardModel } from './data/mock'
import type { DashboardModel } from './types/model'

let renderer: ReactTestRenderer | null = null
let intents: Array<Record<string, unknown>>
let model: DashboardModel
let publish: (model: DashboardModel) => void
let inputNode: { focus: ReturnType<typeof vi.fn>; select: ReturnType<typeof vi.fn> }
let buttonFocus: ReturnType<typeof vi.fn>

async function mount(): Promise<void> {
  vi.useFakeTimers()
  intents = []
  model = structuredClone(mockDashboardModel)
  inputNode = { focus: vi.fn(), select: vi.fn() }
  buttonFocus = vi.fn()
  vi.stubGlobal('window', Object.assign(new EventTarget(), {
    location: { href: 'hydra://localhost/index.html', search: '' },
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    hydraDashboard: {
      getDashboardModel: () => structuredClone(model),
      postIntent: (intent: Record<string, unknown>) => intents.push(intent),
      onDashboardModel: (listener: (model: DashboardModel) => void) => {
        publish = listener
        return () => undefined
      },
    },
  }))
  vi.stubGlobal('document', Object.assign(new EventTarget(), {
    body: { classList: { add: () => undefined, remove: () => undefined } },
    activeElement: inputNode,
    hasFocus: vi.fn(() => true),
  }))
  await act(async () => {
    renderer = create(<App />, {
      createNodeMock: (element) => element.type === 'input' ? inputNode
        : element.type === 'button' ? { focus: buttonFocus }
        : { contains: (node: unknown) => node === inputNode },
    })
    await Promise.resolve()
  })
}

function openEditor(): void {
  act(() => renderer!.root.findAllByProps({ className: 'window-tab__name' })[0].props.onDoubleClick({ stopPropagation: vi.fn() }))
}

function input() {
  return renderer!.root.findByProps({ 'aria-label': 'Rename Dashboard build' })
}

function change(value: string): void {
  act(() => input().props.onChange({ target: { value } }))
}

function key(value: string, overrides = {}) {
  const event = { key: value, preventDefault: vi.fn(), stopPropagation: vi.fn(), nativeEvent: {}, ...overrides }
  act(() => input().props.onKeyDown(event))
  return event
}

async function reply(result: WindowRenameResult): Promise<void> {
  const requests = intents.filter((intent) => intent.type === 'updateWindow')
  const request = requests[requests.length - 1]
  await act(async () => {
    window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_RENAME__!(request.request_id as string, result)
    await Promise.resolve()
  })
}

async function flushFocusLoss(): Promise<void> {
  await act(async () => { await vi.advanceTimersByTimeAsync(0) })
}

afterEach(() => {
  act(() => renderer?.unmount())
  renderer = null
  vi.clearAllTimers()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('topbar inline window rename', () => {
  it('selects the initial title once, saves once on Enter plus blur, and projects the native normalized title to both surfaces', async () => {
    await mount()
    openEditor()
    expect(input().props.value).toBe('Dashboard build')
    expect(inputNode.focus).toHaveBeenCalledOnce()
    expect(inputNode.select).toHaveBeenCalledOnce()
    change('  ledger rewrite  ')
    expect(inputNode.select).toHaveBeenCalledOnce()
    key('Enter')
    act(() => input().props.onBlur())
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toEqual([{
      type: 'updateWindow', project_id: 'sample_workspace', window_id: 'w-main',
      name: 'ledger rewrite', request_id: expect.any(String),
    }])
    expect(input().props.readOnly).toBe(true)
    model.details.sample_workspace.windows[0].name = 'ledger rewrite (2)'
    act(() => publish(model))
    await reply({ ok: true, name: 'ledger rewrite (2)', message: null })
    expect(renderer!.root.findAllByProps({ className: 'window-tab__name' })[0].children).toEqual(['ledger rewrite (2)'])
    expect(renderer!.root.findAllByProps({ className: 'tree-window__name' })[0].children).toEqual(['ledger rewrite (2)'])
    expect(buttonFocus).toHaveBeenCalled()
  })

  it('cancels Escape, whitespace, and unchanged names without a rename intent', async () => {
    await mount()
    for (const value of ['discard this', '   ', 'Dashboard build']) {
      openEditor()
      change(value)
      const staleBlur = input().props.onBlur
      key(value === 'discard this' ? 'Escape' : 'Enter')
      act(() => staleBlur())
      expect(renderer!.root.findAllByProps({ 'aria-label': 'Rename Dashboard build' })).toHaveLength(0)
    }
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(0)
  })

  it('traps Tab and Shift-Tab, leaves arrows to text editing, and ignores composing Enter', async () => {
    await mount()
    openEditor()
    for (const shiftKey of [false, true]) expect(key('Tab', { shiftKey }).preventDefault).toHaveBeenCalled()
    expect(key('ArrowLeft').stopPropagation).toHaveBeenCalled()
    change('draft')
    key('Enter', { nativeEvent: { isComposing: true } })
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(0)
  })

  it('commits a click outside even on a non-focusable target without stealing focus back', async () => {
    await mount()
    openEditor()
    change('outside save')
    act(() => { document.dispatchEvent(new Event('pointerdown')) })
    await reply({ ok: true, name: 'outside save', message: null })
    expect(buttonFocus).not.toHaveBeenCalled()
    expect(renderer!.root.findAllByProps({ 'aria-label': 'Rename Dashboard build' })).toHaveLength(0)
  })

  it('keeps the draft and exact native decline inline, with no automatic duplicate retry', async () => {
    await mount()
    openEditor()
    change('kept draft')
    key('Enter')
    await reply({ ok: false, name: null, message: 'Could not rename window: window no longer exists' })
    expect(input().props.value).toBe('kept draft')
    expect(input().props.readOnly).toBe(false)
    expect(renderer!.root.findByProps({ role: 'alert' }).children).toEqual(['Could not rename window: window no longer exists'])
    act(() => { input().props.onBlur(); document.dispatchEvent(new Event('pointerdown')) })
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(1)
    key('Enter')
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(2)
    await reply({ ok: true, name: 'kept draft', message: null })
  })

  it('saves once when focus leaves the WebView for a native widget without stealing focus back', async () => {
    await mount()
    openEditor()
    change('native terminal outside save')
    vi.mocked(document.hasFocus).mockReturnValue(false)
    act(() => {
      window.dispatchEvent(new Event('blur'))
      window.dispatchEvent(new Event('blur'))
      input().props.onBlur()
    })
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(0)
    await flushFocusLoss()
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(1)
    expect(intents.find((intent) => intent.type === 'updateWindow')?.name).toBe('native terminal outside save')
    await reply({ ok: true, name: 'native terminal outside save', message: null })
    expect(buttonFocus).not.toHaveBeenCalled()
    expect(renderer!.root.findAllByProps({ 'aria-label': 'Rename Dashboard build' })).toHaveLength(0)
    act(() => { window.dispatchEvent(new Event('blur')) })
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(1)
  })

  it('keeps a native-focus-loss decline editable and does not retry on later focus loss', async () => {
    await mount()
    openEditor()
    change('native declined draft')
    vi.mocked(document.hasFocus).mockReturnValue(false)
    act(() => { window.dispatchEvent(new Event('blur')) })
    await flushFocusLoss()
    await reply({ ok: false, name: null, message: 'Could not rename window: project no longer exists' })
    expect(input().props.value).toBe('native declined draft')
    expect(input().props.readOnly).toBe(false)
    expect(buttonFocus).not.toHaveBeenCalled()
    act(() => { window.dispatchEvent(new Event('blur')); input().props.onBlur() })
    await flushFocusLoss()
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(1)
    key('Enter')
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(2)
    await reply({ ok: true, name: 'native declined draft', message: null })
  })

  it('removes the WebView blur listener when editing is cancelled', async () => {
    await mount()
    openEditor()
    change('cancelled draft')
    vi.mocked(document.hasFocus).mockReturnValue(false)
    act(() => { input().props.onBlur(); window.dispatchEvent(new Event('blur')) })
    key('Escape')
    act(() => { window.dispatchEvent(new Event('blur')) })
    await flushFocusLoss()
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(0)
  })

  it('keeps the editor when accessibility briefly blurs and refocuses the same input', async () => {
    await mount()
    openEditor()
    act(() => input().props.onBlur())
    expect(input().props.value).toBe('Dashboard build')
    await flushFocusLoss()
    expect(input().props.value).toBe('Dashboard build')
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(0)
    change('still editing after refocus')
    vi.mocked(document.hasFocus).mockReturnValue(false)
    act(() => { window.dispatchEvent(new Event('blur')); input().props.onBlur() })
    vi.mocked(document.hasFocus).mockReturnValue(true)
    await flushFocusLoss()
    expect(input().props.value).toBe('still editing after refocus')
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(0)
  })

  it('saves on genuine input focus loss within the document using the latest draft', async () => {
    await mount()
    openEditor()
    change('earlier draft')
    act(() => input().props.onBlur())
    change('latest draft')
    Object.assign(document, { activeElement: null })
    await flushFocusLoss()
    expect(intents.find((intent) => intent.type === 'updateWindow')?.name).toBe('latest draft')
    await reply({ ok: true, name: 'latest draft', message: null })
    expect(buttonFocus).not.toHaveBeenCalled()
  })

  it('does not duplicate Enter or outside-pointer saves while focus-loss work is queued', async () => {
    await mount()
    for (const explicit of ['Enter', 'pointer']) {
      openEditor()
      change(`pending ${explicit}`)
      vi.mocked(document.hasFocus).mockReturnValue(false)
      act(() => { input().props.onBlur(); window.dispatchEvent(new Event('blur')) })
      if (explicit === 'Enter') key('Enter')
      else act(() => { document.dispatchEvent(new Event('pointerdown')) })
      const count = intents.filter((intent) => intent.type === 'updateWindow').length
      await flushFocusLoss()
      expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(count)
      await reply({ ok: true, name: `pending ${explicit}`, message: null })
    }
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(2)
  })

  it('preserves ordinary single click, excludes close/agent badges from double-click rename, and offers F2', async () => {
    await mount()
    const focus = renderer!.root.findByProps({ 'aria-label': 'Focus Dashboard build in Sample Workspace' })
    act(() => { focus.props.onClick(); focus.props.onClick() })
    expect(intents.filter((intent) => intent.type === 'focusWindow')).toHaveLength(2)
    expect(focus.props.onDoubleClick).toBeUndefined()
    expect(renderer!.root.findByProps({ 'aria-label': 'Close Dashboard build in Sample Workspace' }).props.onDoubleClick).toBeUndefined()
    expect(renderer!.root.findAllByProps({ className: 'window-tab__agents' })[0].props.onDoubleClick).toBeUndefined()
    act(() => focus.props.onKeyDown({ key: 'F2', preventDefault: vi.fn(), stopPropagation: vi.fn() }))
    expect(input().props.value).toBe('Dashboard build')
  })

  it('uses the same updateWindow operation as sidebar rename and reflects its next native model', async () => {
    await mount()
    const row = renderer!.root.findAllByProps({ className: 'tree-window__name' })[0].parent!
    act(() => row.props.onDoubleClick({ preventDefault: vi.fn(), stopPropagation: vi.fn() }))
    const sidebarInput = renderer!.root.findByProps({ className: 'tree-rename-input' })
    act(() => sidebarInput.props.onChange({ target: { value: 'sidebar title' } }))
    act(() => renderer!.root.findByProps({ className: 'tree-rename-input' }).props.onKeyDown({ key: 'Enter', preventDefault: vi.fn(), stopPropagation: vi.fn() }))
    expect(intents[intents.length - 1]).toEqual({ type: 'updateWindow', project_id: 'sample_workspace', window_id: 'w-main', name: 'sidebar title' })
    model.details.sample_workspace.windows[0].name = 'sidebar title'
    act(() => publish(model))
    expect(renderer!.root.findAllByProps({ className: 'window-tab__name' })[0].children).toEqual(['sidebar title'])
    expect(renderer!.root.findAllByProps({ className: 'tree-window__name' })[0].children).toEqual(['sidebar title'])
  })

  it('returns an explicit connection failure without sending a rename when no host exists', async () => {
    await mount()
    delete window.hydraDashboard
    const result = await bridge.renameWindow({ project_id: 'sample_workspace', window_id: 'w-main', name: 'draft' })
    expect(result).toEqual({ ok: false, name: null, message: 'Hydra desktop connection is unavailable.' })
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(0)
  })

  it('keeps an unconfirmed draft on acknowledgement timeout without resending it', async () => {
    await mount()
    openEditor()
    change('unconfirmed draft')
    key('Enter')
    await act(async () => { await vi.advanceTimersByTimeAsync(8_000) })
    expect(input().props.value).toBe('unconfirmed draft')
    expect(input().props.readOnly).toBe(false)
    expect(renderer!.root.findByProps({ role: 'alert' }).children.join('')).toContain('Save is not confirmed')
    expect(intents.filter((intent) => intent.type === 'updateWindow')).toHaveLength(1)
  })

  it('ignores a late reply from an earlier editor instead of closing a new draft', async () => {
    await mount()
    openEditor()
    change('first draft')
    key('Enter')
    key('Escape')
    openEditor()
    change('new draft')
    await reply({ ok: true, name: 'first draft', message: null })
    expect(input().props.value).toBe('new draft')
    expect(input().props.readOnly).toBe(false)
    key('Escape')
  })
})
