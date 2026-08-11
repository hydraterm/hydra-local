// @vitest-environment jsdom

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { App } from './App'
import { mockDashboardModel } from './data/mock'
import { bridge } from './ipc/bridge'
import type { AgentFolderSession, DashboardModel } from './types/model'

type OverlayModal =
  | { kind: 'newWindow'; project_id: string }
  | {
      kind: 'split'
      project_id: string
      window_id: string
      tab_id: string
      dir: 'h' | 'v'
    }

type OverlayTestWindow = Window & {
  __HYDRA_SHOW_OVERLAY_MODAL__?: (modal: OverlayModal) => void
}

const session: AgentFolderSession = {
  id: 'focus-session',
  agent: 'claude',
  title: 'Focus session',
  first_message: 'hello',
  modified_at_ms: 1,
  message_count: 2,
  folder_index: 1,
  file_path: '/tmp/focus-session.jsonl',
  in_use: false,
  custom_name: null,
}

let root: Root | null = null
let container: HTMLDivElement | null = null
let initialModel: DashboardModel
let pushModel: ((model: DashboardModel) => void) | null = null

function requiredElement<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector)
  expect(element).not.toBeNull()
  return element!
}

async function settleReact(): Promise<void> {
  await act(async () => {
    await Promise.resolve()
    await Promise.resolve()
  })
}

async function showModal(modal: OverlayModal): Promise<void> {
  const show = (window as OverlayTestWindow).__HYDRA_SHOW_OVERLAY_MODAL__
  expect(show).toBeTypeOf('function')
  act(() => show?.(modal))
  await settleReact()
}

function openDeleteConfirmation(parent: HTMLElement): HTMLButtonElement {
  const opener = parent.querySelector<HTMLButtonElement>(
    'button[title="Delete the session file from your computer"]',
  )
  expect(opener).not.toBeNull()
  act(() => {
    opener!.focus()
    opener!.click()
  })
  const nestedCancel = requiredElement<HTMLButtonElement>('.session-delete-confirm__cancel')
  expect(document.activeElement).toBe(nestedCancel)
  return opener!
}

beforeEach(async () => {
  vi.useFakeTimers()
  ;(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
    .IS_REACT_ACT_ENVIRONMENT = true
  window.history.replaceState({}, '', '/?chrome=overlay')
  initialModel = structuredClone(mockDashboardModel)
  pushModel = null
  vi.spyOn(bridge, 'getDashboardModel').mockResolvedValue(initialModel)
  vi.spyOn(bridge, 'subscribeDashboardModel').mockImplementation((listener) => {
    pushModel = listener
    return () => {
      pushModel = null
    }
  })
  vi.spyOn(bridge, 'subscribeSidebarState').mockImplementation(() => () => undefined)
  vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([session])

  container = document.createElement('div')
  document.body.append(container)
  root = createRoot(container)
  await act(async () => {
    root!.render(<App />)
    await Promise.resolve()
  })
})

afterEach(async () => {
  if (root) {
    await act(async () => root?.unmount())
  }
  root = null
  container?.remove()
  container = null
  vi.clearAllTimers()
  vi.useRealTimers()
  vi.restoreAllMocks()
  document.body.className = ''
  delete (window as OverlayTestWindow).__HYDRA_SHOW_OVERLAY_MODAL__
})

describe('nested overlay DOM focus ownership', () => {
  it('focuses the now-uninert parent when a model change replaces the folder-session key', async () => {
    await showModal({
      kind: 'split',
      project_id: 'sample_workspace',
      window_id: 'w-main',
      tab_id: 'tab-claude',
      dir: 'h',
    })

    const parent = requiredElement<HTMLElement>('[role="dialog"][aria-label="Split right"]')
    const firstControl = requiredElement<HTMLInputElement>('input[aria-label="Pane name"]')
    const staleOpener = openDeleteConfirmation(parent)
    expect(parent.hasAttribute('inert')).toBe(true)

    const changedModel = structuredClone(initialModel)
    changedModel.details.sample_workspace.root = '/Projects/Hydra-next'
    await act(async () => {
      pushModel?.(changedModel)
      await Promise.resolve()
    })

    expect(document.querySelector('.session-delete-confirm')).toBeNull()
    expect(parent.hasAttribute('inert')).toBe(false)
    expect(document.activeElement).not.toBe(staleOpener)

    await act(async () => {
      vi.runOnlyPendingTimers()
      await Promise.resolve()
    })

    expect(document.activeElement).toBe(firstControl)
    expect(document.activeElement).not.toBe(staleOpener)
  })

  it('focuses the reused parent first control after same-kind replacement and rejects stale restores', async () => {
    const modal = { kind: 'newWindow', project_id: 'sample_workspace' } as const
    await showModal(modal)

    const parent = requiredElement<HTMLElement>('[role="dialog"][aria-label="New window"]')
    const firstControl = requiredElement<HTMLInputElement>(
      'input[placeholder="literature, experiment, deployment..."]',
    )
    const staleOpener = openDeleteConfirmation(parent)

    act(() => (window as OverlayTestWindow).__HYDRA_SHOW_OVERLAY_MODAL__?.(modal))
    expect(requiredElement<HTMLElement>('[role="dialog"][aria-label="New window"]')).toBe(parent)
    expect(
      requiredElement<HTMLInputElement>(
        'input[placeholder="literature, experiment, deployment..."]',
      ),
    ).toBe(firstControl)
    expect(document.querySelector('.session-delete-confirm')).toBeNull()

    await act(async () => {
      vi.runOnlyPendingTimers()
      await Promise.resolve()
    })

    expect(document.activeElement).toBe(firstControl)
    expect(document.activeElement).not.toBe(staleOpener)

    await settleReact()
    const secondStaleOpener = openDeleteConfirmation(parent)
    const nested = requiredElement<HTMLElement>('.session-delete-confirm')
    act(() => {
      nested.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }))
      // The queued opener restore from Escape belongs to the old modal epoch. Replacement must
      // cancel it and focus the reused parent's first control instead.
      ;(window as OverlayTestWindow).__HYDRA_SHOW_OVERLAY_MODAL__?.(modal)
    })

    await act(async () => {
      vi.runOnlyPendingTimers()
      await Promise.resolve()
    })

    expect(document.activeElement).toBe(firstControl)
    expect(document.activeElement).not.toBe(secondStaleOpener)
  })
})
