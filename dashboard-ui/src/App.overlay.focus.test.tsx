// @vitest-environment jsdom

import { act } from 'react'
import { createRoot, type Root } from 'react-dom/client'
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
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

// Execute the actual Linux host script; the fake realm controls cross-process delivery order.
// This proves script/state behavior, not GTK timing or an atomic native/DOM focus transaction.
let linuxHostSource = ''
beforeAll(async () => {
  const fs = await vi.importActual<{
    readFileSync(path: string, encoding: 'utf8'): string
  }>('node:fs')
  linuxHostSource = fs.readFileSync('../maestro-renderer/src/linux_host/overlay.rs', 'utf8')
})

function linuxFocusRealm() {
  const listeners = new Map<string, Set<(event: { type: string; target: unknown }) => void>>()
  const messages: Array<{ type: string; token: string }> = []
  let focused = false
  let focusCalls = 0
  const body = { tagName: 'BODY' }
  const attributes = new Map<string, string>()
  const html = {
    inert: true,
    getAttribute(name: string) { return attributes.get(name) ?? null },
    removeAttribute(name: string) { attributes.delete(name) },
    setAttribute(name: string, value: string) { attributes.set(name, value) },
  }
  const document = {
    body,
    documentElement: html,
    activeElement: body as unknown,
    hasFocus: () => focused,
  }
  const prior = {
    tagName: 'BUTTON',
    isConnected: true,
    focus() {
      focusCalls++
      document.activeElement = prior
    },
  }
  const window = {
    __HYDRA_NATIVE_MODAL_UNDERLAY_STATE__: { inert: false, ariaHidden: null, activeElement: prior },
    __HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__: { active: true },
    ipc: {
      postMessage(json: string) { messages.push(JSON.parse(json)) },
    },
    addEventListener(kind: string, listener: (event: { type: string; target: unknown }) => void) {
      if (!listeners.has(kind)) listeners.set(kind, new Set())
      listeners.get(kind)!.add(listener)
    },
    removeEventListener(kind: string, listener: (event: { type: string; target: unknown }) => void) {
      listeners.get(kind)?.delete(listener)
    },
  }
  function run(name: string, token = '4', restore = true) {
    const script = linuxHostSource.match(
      new RegExp(`const ${name}: &str = r#"([\\s\\S]*?)"#;`),
    )?.[1]
    expect(script).toBeDefined()
    return new Function(
      'window', 'document',
      script!
        .replaceAll('__HYDRA_FOCUS_TRACE_FUNCTION__', 'null')
        .replaceAll('__HYDRA_RESTORE_DOM_FOCUS__', String(restore))
        .replaceAll('__HYDRA_RESTORE_FOCUS_TOKEN__', JSON.stringify(token)),
    )(window, document)
  }
  return {
    run,
    messages,
    document,
    prior,
    window,
    focusCalls: () => focusCalls,
    listenerCount: () => [...listeners.values()].reduce((n, entries) => n + entries.size, 0),
    setFocused(value: boolean) { focused = value },
    emit(kind: string, target: unknown = window) {
      for (const listener of [...(listeners.get(kind) ?? [])]) listener({ type: kind, target })
    },
  }
}

describe('Linux delayed document opener restoration', () => {
  it('keeps the opener through late window focus and requires native acceptance', () => {
    const realm = linuxFocusRealm()
    realm.run('RESTORE_PERSISTENT_DOCUMENTS_SCRIPT')
    expect(realm.document.documentElement.inert).toBe(false)
    expect(realm.window.__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__.active).toBe(false)
    expect(realm.focusCalls()).toBe(0)
    realm.setFocused(true)
    realm.emit('focus')
    expect(realm.messages).toEqual([{ type: '__hydraPersistentFocusReady', token: '4' }])
    expect(realm.focusCalls()).toBe(0)
    realm.run('COMPLETE_PERSISTENT_FOCUS_SCRIPT')
    expect(realm.focusCalls()).toBe(1)
    expect(realm.document.activeElement).toBe(realm.prior)
    expect(realm.listenerCount()).toBe(0)
  })

  it('handles already-focused documents once without readiness granting focus', () => {
    const realm = linuxFocusRealm()
    realm.setFocused(true)
    realm.run('RESTORE_PERSISTENT_DOCUMENTS_SCRIPT')
    realm.emit('focus')
    expect(realm.messages).toHaveLength(1)
    expect(realm.focusCalls()).toBe(0)
    realm.run('COMPLETE_PERSISTENT_FOCUS_SCRIPT')
    realm.run('COMPLETE_PERSISTENT_FOCUS_SCRIPT')
    expect(realm.focusCalls()).toBe(1)
    expect(realm.listenerCount()).toBe(0)
  })

  it.each(['keydown', 'pointerdown', 'blur', 'pagehide', 'focusin'])('retires on newer local %s before acceptance', (kind) => {
    const realm = linuxFocusRealm()
    realm.run('RESTORE_PERSISTENT_DOCUMENTS_SCRIPT')
    realm.emit(kind, { tagName: 'INPUT' })
    realm.setFocused(true)
    realm.emit('focus')
    realm.run('COMPLETE_PERSISTENT_FOCUS_SCRIPT')
    expect(realm.focusCalls()).toBe(0)
    expect(realm.messages).toHaveLength(0)
    expect(realm.listenerCount()).toBe(0)
  })

  it('cannot resurrect a canceled native token or let a stale cancellation retire a newer opener', () => {
    const realm = linuxFocusRealm()
    realm.run('RESTORE_PERSISTENT_DOCUMENTS_SCRIPT')
    realm.run('CANCEL_PERSISTENT_FOCUS_SCRIPT', '3')
    expect(realm.listenerCount()).toBeGreaterThan(0)
    realm.run('CANCEL_PERSISTENT_FOCUS_SCRIPT')
    realm.setFocused(true)
    realm.emit('focus')
    realm.run('COMPLETE_PERSISTENT_FOCUS_SCRIPT')
    expect(realm.focusCalls()).toBe(0)
    expect(realm.listenerCount()).toBe(0)
  })

  it('cancellation delivered before final JS prevents focus; the opposite order cannot undo completed focus', () => {
    for (const cancelFirst of [true, false]) {
      const realm = linuxFocusRealm()
      realm.setFocused(true)
      realm.run('RESTORE_PERSISTENT_DOCUMENTS_SCRIPT')
      const tasks = ['CANCEL_PERSISTENT_FOCUS_SCRIPT', 'COMPLETE_PERSISTENT_FOCUS_SCRIPT']
      if (!cancelFirst) tasks.reverse()
      for (const task of tasks) realm.run(task)
      expect(realm.focusCalls()).toBe(cancelFirst ? 0 : 1)
      expect(realm.listenerCount()).toBe(0)
    }
  })

  it.each(['document', 'target', 'inert', 'firewall', 'removed'])('final JS rechecks %s after native acceptance', (changed) => {
    const realm = linuxFocusRealm()
    realm.setFocused(true)
    realm.run('RESTORE_PERSISTENT_DOCUMENTS_SCRIPT')
    if (changed === 'document') realm.setFocused(false)
    if (changed === 'target') realm.document.activeElement = { tagName: 'INPUT' }
    if (changed === 'inert') realm.document.documentElement.inert = true
    if (changed === 'firewall') realm.window.__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__.active = true
    if (changed === 'removed') realm.prior.isConnected = false
    realm.run('COMPLETE_PERSISTENT_FOCUS_SCRIPT')
    expect(realm.focusCalls()).toBe(0)
    expect(realm.listenerCount()).toBe(0)
  })

  it('new modal suppression and passive Drop release old listeners without autofocus', () => {
    const realm = linuxFocusRealm()
    realm.run('RESTORE_PERSISTENT_DOCUMENTS_SCRIPT')
    realm.run('SUPPRESS_PERSISTENT_DOCUMENTS_SCRIPT')
    realm.run('RESTORE_PERSISTENT_DOCUMENTS_SCRIPT', '5', false)
    realm.setFocused(true)
    realm.emit('focus')
    realm.run('COMPLETE_PERSISTENT_FOCUS_SCRIPT')
    expect(realm.document.documentElement.inert).toBe(false)
    expect(realm.window.__HYDRA_NATIVE_MODAL_UNDERLAY_FIREWALL__.active).toBe(false)
    expect(realm.focusCalls()).toBe(0)
    expect(realm.listenerCount()).toBe(0)
  })
})
