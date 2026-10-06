import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { Topbar } from './Topbar'
import { mockDashboardModel } from '../data/mock'

let renderer: ReactTestRenderer | null = null

afterEach(() => {
  act(() => renderer?.unmount())
  renderer = null
  vi.unstubAllGlobals()
})

describe('topbar external activation visibility', () => {
  it.each([
    ['window shrink', 200, 110],
    ['sidebar expansion', 260, 50],
  ] as const)('reveals the same active tab after %s and disposes its observer', (_cause, narrowedWidth, expectedScroll) => {
    const postIntent = vi.fn()
    vi.stubGlobal('window', { hydraDashboard: { postIntent } })
    const observers: Array<{ notify: () => void; observe: ReturnType<typeof vi.fn>; disconnect: ReturnType<typeof vi.fn> }> = []
    vi.stubGlobal('ResizeObserver', class {
      observe = vi.fn()
      disconnect = vi.fn()
      constructor(callback: () => void) {
        observers.push({ notify: callback, observe: this.observe, disconnect: this.disconnect })
      }
    })
    let stripWidth = 320
    let scrollLeft = 0
    const writes = vi.fn()
    const list = {
      get scrollLeft() { return scrollLeft },
      set scrollLeft(value: number) { writes(value); scrollLeft = value },
      getBoundingClientRect: () => ({ left: 0, right: stripWidth }),
    }
    const focus = vi.fn()
    const active = {
      getBoundingClientRect: () => ({ left: 250 - scrollLeft, right: 310 - scrollLeft }),
      focus,
    }
    const model = structuredClone(mockDashboardModel)
    const onFocusWindow = vi.fn()
    const props = {
      project: model.projects[0], projects: model.projects, details: model.details,
      windowOrder: ['w-2', 'w-main', 'w-sample'],
      focusedWindowId: 'w-main', activeTabId: null, onFocusWindow,
    }
    act(() => {
      renderer = create(<Topbar {...props} />, {
        createNodeMock: element => element.props.className === 'window-tabs__left' ? list : active,
      })
    })
    const order = () => renderer!.root.findAll(node =>
      node.type === 'button' && String(node.props['aria-label']).startsWith('Focus '),
    ).map(node => node.props['aria-label'])
    const originalOrder = order()
    expect(observers).toHaveLength(1)
    expect(observers[0].observe).toHaveBeenCalledWith(list)
    act(() => observers[0].notify()) // initial observer delivery is not another reveal
    expect(writes).not.toHaveBeenCalled()
    stripWidth = narrowedWidth // native topbar viewport or sidebar allocation changed; active ID did not
    act(() => observers[0].notify())
    expect(scrollLeft).toBe(expectedScroll)
    expect(writes).toHaveBeenCalledTimes(1)
    act(() => observers[0].notify())
    scrollLeft = 0 // a person's manual strip scroll must remain theirs until geometry changes
    act(() => observers[0].notify())
    act(() => renderer!.update(<Topbar {...props} details={structuredClone(model.details)} />))
    expect(scrollLeft).toBe(0)
    expect(writes).toHaveBeenCalledTimes(1)
    expect(order()).toEqual(originalOrder)
    expect(focus).not.toHaveBeenCalled()
    expect(onFocusWindow).not.toHaveBeenCalled()
    expect(postIntent).not.toHaveBeenCalled()
    act(() => renderer!.unmount())
    renderer = null
    expect(observers[0].disconnect).toHaveBeenCalledTimes(1)
    stripWidth = 100
    act(() => observers[0].notify()) // a previously queued notification after cleanup is inert
    expect(writes).toHaveBeenCalledTimes(1)
  })

  it.each([
    ['right', { left: 340, right: 440 }, 190],
    ['left', { left: 20, right: 90 }, -80],
    ['already visible', { left: 120, right: 200 }, 0],
  ] as const)('reveals an active group to the %s without focus or order mutation', (_name, nextBounds, delta) => {
    const postIntent = vi.fn()
    vi.stubGlobal('window', { hydraDashboard: { postIntent } })
    const onFocusWindow = vi.fn()
    const focus = vi.fn()
    let bounds = { left: 120, right: 200 }
    const list = {
      scrollLeft: 200,
      getBoundingClientRect: () => ({ left: 100, right: 250 }),
    }
    const active = { getBoundingClientRect: () => bounds, focus }
    const model = structuredClone(mockDashboardModel)
    const props = {
      project: model.projects[0],
      projects: model.projects,
      details: model.details,
      windowOrder: ['w-2', 'w-main', 'w-sample'],
      focusedWindowId: 'w-main',
      activeTabId: null,
      onFocusWindow,
    }
    act(() => {
      renderer = create(<Topbar {...props} />, {
        createNodeMock: (element) =>
          element.props.className === 'window-tabs__left' ? list : active,
      })
    })
    const order = () => renderer!.root.findAll((node) =>
      node.type === 'button' && String(node.props['aria-label']).startsWith('Focus '),
    ).map((node) => node.props['aria-label'])
    const originalOrder = order()
    expect(list.scrollLeft).toBe(200)

    // Model-driven selection (e.g. a sidebar click) does not dispatch a toolbar click.
    bounds = nextBounds
    const selected = { ...props, project: model.projects[1], focusedWindowId: 'w-sample' }
    act(() => renderer!.update(<Topbar {...selected} />))
    expect(list.scrollLeft).toBe(200 + delta)
    expect(order()).toEqual(originalOrder)
    expect(onFocusWindow).not.toHaveBeenCalled()
    expect(focus).not.toHaveBeenCalled()
    expect(postIntent).not.toHaveBeenCalled()

    // An unrelated model refresh must not undo the user's manual strip scrolling.
    list.scrollLeft = 100
    act(() => renderer!.update(<Topbar {...selected} details={structuredClone(model.details)} />))
    expect(list.scrollLeft).toBe(100)
  })
})
