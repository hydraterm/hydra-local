// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { Sidebar } from './components/Sidebar'
import { mockDashboardModel } from './data/mock'

type Kind = 'project' | 'window' | 'pane'
let renderer: ReactTestRenderer | null = null
let intents: Array<Record<string, unknown>>
const names = {
  project: ['Sample Workspace', 'Sample Analytics'],
  window: ['Dashboard build', 'Release checks'],
  pane: ['claude — dashboard', 'codex — renderer'],
}

function sidebar(collapsed = false): JSX.Element {
  return <Sidebar model={structuredClone(mockDashboardModel)} selectedId="sample_workspace"
    focusedWindowId="w-main" collapsed={collapsed} onSelect={vi.fn()} onReorder={vi.fn()}
    onWindowReorder={vi.fn()} onFocusWindow={vi.fn()}
    onFocusPane={vi.fn()} />
}

function mount(): void {
  vi.useFakeTimers()
  vi.spyOn(document, 'hasFocus').mockReturnValue(true)
  intents = []
  window.hydraDashboard = {
    postIntent: (intent) => intents.push(intent as unknown as Record<string, unknown>),
  }
  act(() => {
    renderer = create(sidebar(), {
      createNodeMock: (element) => {
        if (element.type !== 'input') return null
        const input = document.createElement('input')
        document.body.appendChild(input)
        return input
      },
    })
  })
}

function start(kind: Kind, index = 0): void {
  const name = renderer!.root.find((node) =>
    node.props.className === `tree-${kind}__name` && node.children.join('') === names[kind][index])
  act(() => name.parent!.props.onDoubleClick({ preventDefault: vi.fn(), stopPropagation: vi.fn() }))
}

function input(kind: Kind) {
  return renderer!.root.findByProps({
    className: kind === 'pane' ? 'tree-pane__rename-input' : 'tree-rename-input',
  })
}

function change(kind: Kind, value: string): void {
  act(() => input(kind).props.onChange({ target: { value } }))
}

function key(kind: Kind, value: 'Enter' | 'Escape'): void {
  const event = { key: value, preventDefault: vi.fn(), stopPropagation: vi.fn() }
  act(() => {
    if (kind === 'pane' && value === 'Enter') {
      renderer!.root.findByProps({ className: 'tree-label tree-label--pane tree-pane__rename-form' }).props.onSubmit(event)
    } else input(kind).props.onKeyDown(event)
  })
}

function updates(): Array<Record<string, unknown>> {
  return intents.filter((intent) => ['updateProject', 'updateWindow', 'updatePane'].includes(intent.type as string))
}

function expected(kind: Kind, name: string, index = 0): Record<string, unknown> {
  if (kind === 'project') return { type: 'updateProject', project_id: index ? 'sample' : 'sample_workspace', name }
  if (kind === 'window') return { type: 'updateWindow', project_id: 'sample_workspace', window_id: index ? 'w-2' : 'w-main', name }
  return { type: 'updatePane', project_id: 'sample_workspace', window_id: 'w-main', tab_id: index ? 'tab-codex' : 'tab-claude', name }
}

async function flush(): Promise<void> {
  await act(async () => { await vi.advanceTimersByTimeAsync(0) })
}

afterEach(() => {
  act(() => renderer?.unmount())
  renderer = null
  delete window.hydraDashboard
  document.body.replaceChildren()
  vi.clearAllTimers()
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe.each(['project', 'window', 'pane'] as const)('sidebar %s deferred rename', (kind) => {
  it('keeps an unchanged editor alive through accessibility blur/refocus', async () => {
    mount()
    start(kind)
    const focused = document.activeElement as HTMLInputElement
    act(() => input(kind).props.onBlur())
    expect(input(kind).props.value).toBe(names[kind][0])
    focused.blur()
    focused.focus()
    await flush()
    expect(input(kind).props.value).toBe(names[kind][0])
    expect(updates()).toEqual([])
  })

  it('coalesces native and input blur into one save with the exact identity and latest name', async () => {
    mount()
    start(kind)
    change(kind, 'older draft')
    vi.mocked(document.hasFocus).mockReturnValue(false)
    act(() => { input(kind).props.onBlur(); window.dispatchEvent(new Event('blur')) })
    change(kind, '  final draft  ')
    expect(updates()).toEqual([])
    await flush()
    expect(updates()).toEqual([expected(kind, 'final draft')])
    act(() => { window.dispatchEvent(new Event('blur')) })
    await flush()
    expect(updates()).toHaveLength(1)
  })

  it('cancels queued blur on Escape and does not duplicate an immediate Enter save', async () => {
    mount()
    start(kind)
    change(kind, 'discarded')
    vi.mocked(document.hasFocus).mockReturnValue(false)
    act(() => input(kind).props.onBlur())
    key(kind, 'Escape')
    await flush()
    expect(updates()).toEqual([])
    start(kind)
    change(kind, 'explicit save')
    act(() => input(kind).props.onBlur())
    key(kind, 'Enter')
    expect(updates()).toEqual([expected(kind, 'explicit save')])
    await flush()
    expect(updates()).toHaveLength(1)
  })

  it('does not apply a scheduled save to a different target or a reset editor with the same identity', async () => {
    mount()
    start(kind)
    change(kind, 'stale target draft')
    vi.mocked(document.hasFocus).mockReturnValue(false)
    act(() => input(kind).props.onBlur())
    start(kind, 1)
    change(kind, 'new target draft')
    await flush()
    expect(updates()).toEqual([])
    expect(input(kind).props.value).toBe('new target draft')
    act(() => input(kind).props.onBlur())
    key(kind, 'Escape')
    start(kind, 1)
    change(kind, 'reset target draft')
    await flush()
    expect(updates()).toEqual([])
    key(kind, 'Enter')
    expect(updates()).toEqual([expected(kind, 'reset target draft', 1)])
  })

  it('preserves blank-cancels and unchanged-name store semantics on genuine focus loss', async () => {
    mount()
    start(kind)
    change(kind, '   ')
    vi.mocked(document.hasFocus).mockReturnValue(false)
    act(() => input(kind).props.onBlur())
    await flush()
    expect(updates()).toEqual([])
    start(kind)
    act(() => input(kind).props.onBlur())
    await flush()
    expect(updates()).toEqual([expected(kind, names[kind][0])])
  })
})

it('cancels pending sidebar saves when the sidebar unmounts or collapses', async () => {
  mount()
  start('window')
  change('window', 'must not save hidden draft')
  vi.mocked(document.hasFocus).mockReturnValue(false)
  act(() => input('window').props.onBlur())
  act(() => renderer!.update(sidebar(true)))
  await flush()
  expect(updates()).toEqual([])
  act(() => renderer!.update(sidebar()))
  act(() => input('window').props.onBlur())
  act(() => { renderer!.unmount(); renderer = null })
  await flush()
  expect(updates()).toEqual([])
})

it.each(['project', 'window'] as const)('exposes the %s editor outside buttons and restores ordinary row semantics', (kind) => {
  mount()
  const row = () => renderer!.root.find((node) =>
    node.props.className === `tree-${kind}__name` && node.children.join('') === names[kind][0]).parent!
  expect(row().type).toBe('button')
  expect(row().props.onClick).toBeTypeOf('function')
  expect(row().props.type).toBe('button')
  start(kind)
  expect(input(kind).props['aria-label']).toBe(`Rename ${kind} ${names[kind][0]}`)
  expect(input(kind).parent!.type).toBe('div')
  for (let parent = input(kind).parent; parent; parent = parent.parent) {
    expect(parent.type).not.toBe('button')
    expect(parent.props.role).not.toBe('button')
  }
  change(kind, 'keep double-click selection draft')
  act(() => input(kind).parent!.props.onDoubleClick({ preventDefault: vi.fn(), stopPropagation: vi.fn() }))
  expect(input(kind).props.value).toBe('keep double-click selection draft')
  key(kind, 'Escape')
  expect(row().type).toBe('button')
  expect(row().props.onClick).toBeTypeOf('function')
  expect(updates()).toEqual([])
})
