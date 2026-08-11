import { afterEach, describe, expect, it, vi } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { TerminalHost } from './TerminalHost'

let renderer: ReactTestRenderer | null = null

afterEach(() => {
  if (renderer) {
    act(() => renderer?.unmount())
    renderer = null
  }
  vi.unstubAllGlobals()
})

describe('native terminal geometry authority', () => {
  it('reserves the visual slot without posting browser-measured geometry', () => {
    const intents: Array<Record<string, unknown>> = []
    let mounted!: ReactTestRenderer
    vi.stubGlobal(
      'window',
      Object.assign(new EventTarget(), {
        location: { href: 'hydra://localhost/index.html', search: '' },
        hydraDashboard: {
          postIntent: (intent: Record<string, unknown>) => intents.push(intent),
        },
      }),
    )
    const resizeObserver = vi.fn()
    vi.stubGlobal(
      'ResizeObserver',
      class {
        constructor() {
          resizeObserver()
        }
        observe(): void {}
        disconnect(): void {}
      },
    )

    act(() => {
      mounted = create(<TerminalHost projectName="Demo" window={null} />, {
        createNodeMock: (element) =>
          element.props['data-native-terminal-slot']
            ? {
                getBoundingClientRect: () => ({
                  left: 0,
                  top: 48,
                  width: 800,
                  height: 600,
                }),
              }
            : {},
      })
      renderer = mounted
    })

    expect(mounted.root.findByProps({ 'data-native-terminal-slot': true })).toBeTruthy()
    expect(resizeObserver).not.toHaveBeenCalled()
    expect(intents).toEqual([])
  })
})
