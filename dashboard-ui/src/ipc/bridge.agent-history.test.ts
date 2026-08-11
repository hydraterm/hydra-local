import { afterEach, describe, expect, it, vi } from 'vitest'
import type { AgentFolderSession } from '../types/model'
import { bridge } from './bridge'

type AgentHistoryTestWindow = Window & {
  __HYDRA_DASHBOARD_RESOLVE_FOLDER_SESSIONS__?: (
    requestId: string,
    sessions: AgentFolderSession[],
  ) => void
  __HYDRA_DASHBOARD_RESOLVE_SESSION_PREVIEW__?: (
    requestId: string,
    lines: Array<{ role: 'user' | 'assistant'; text: string }>,
  ) => void
  __HYDRA_DASHBOARD_RESOLVE_HIDDEN_SESSIONS__?: (
    requestId: string,
    sessions: AgentFolderSession[],
  ) => void
}

function nativeWindow(intents: Array<Record<string, unknown>>): AgentHistoryTestWindow {
  return Object.assign(new EventTarget(), {
    location: { href: 'hydra://localhost/index.html?chrome=overlay', search: '?chrome=overlay' },
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    hydraDashboard: {
      postIntent: (intent: Record<string, unknown>) => intents.push(intent),
    },
  }) as unknown as AgentHistoryTestWindow
}

const session: AgentFolderSession = {
  id: 'session-one',
  agent: 'claude',
  title: 'Session one',
  first_message: 'hello',
  modified_at_ms: 1,
  message_count: 1,
  folder_index: 1,
  file_path: '/tmp/session-one.jsonl',
  in_use: false,
  custom_name: null,
}

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('folder-session native request cancellation', () => {
  it('emits exactly one typed list cancellation when its AbortSignal fires', async () => {
    const intents: Array<Record<string, unknown>> = []
    vi.stubGlobal('window', nativeWindow(intents))
    const controller = new AbortController()
    const request = bridge.listFolderSessions('claude', '/tmp/project', controller.signal)
    const listIntent = intents.find((intent) => intent.type === 'listFolderSessions')!
    const rejection = expect(request).rejects.toMatchObject({ name: 'AbortError' })

    controller.abort()
    controller.abort()
    await rejection

    expect(intents.filter((intent) => intent.type === 'cancelFolderSessionRequest')).toEqual([
      { type: 'cancelFolderSessionRequest', request_id: listIntent.request_id },
    ])
  })

  it('cancels hidden-session discovery and ignores its late native response', async () => {
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = nativeWindow(intents)
    vi.stubGlobal('window', browserWindow)
    const controller = new AbortController()
    const request = bridge.listHiddenFolderSessions('claude', '/tmp/project', controller.signal)
    const listIntent = intents.find((intent) => intent.type === 'listHiddenFolderSessions')!
    const rejection = expect(request).rejects.toMatchObject({ name: 'AbortError' })

    controller.abort()
    controller.abort()
    await rejection
    browserWindow.__HYDRA_DASHBOARD_RESOLVE_HIDDEN_SESSIONS__?.(
      String(listIntent.request_id),
      [session],
    )

    expect(intents.filter((intent) => intent.type === 'cancelFolderSessionRequest')).toEqual([
      { type: 'cancelFolderSessionRequest', request_id: listIntent.request_id },
    ])
  })

  it('times out hidden-session discovery by cancelling native work first', async () => {
    vi.useFakeTimers()
    const intents: Array<Record<string, unknown>> = []
    vi.stubGlobal('window', nativeWindow(intents))
    const request = bridge.listHiddenFolderSessions('claude', '/tmp/project')
    const listIntent = intents.find((intent) => intent.type === 'listHiddenFolderSessions')!

    await vi.advanceTimersByTimeAsync(15_000)

    await expect(request).resolves.toEqual([])
    expect(intents.filter((intent) => intent.type === 'cancelFolderSessionRequest')).toEqual([
      { type: 'cancelFolderSessionRequest', request_id: listIntent.request_id },
    ])
  })

  it('times out list and preview requests by cancelling native work before resolving benignly', async () => {
    vi.useFakeTimers()
    const intents: Array<Record<string, unknown>> = []
    vi.stubGlobal('window', nativeWindow(intents))
    const listRequest = bridge.listFolderSessions('claude', '/tmp/project')
    const previewRequest = bridge.previewFolderSession('claude', '/tmp/project', 'session-one')
    const listIntent = intents.find((intent) => intent.type === 'listFolderSessions')!
    const previewIntent = intents.find((intent) => intent.type === 'previewFolderSession')!

    await vi.advanceTimersByTimeAsync(15_000)

    await expect(listRequest).resolves.toEqual([])
    await expect(previewRequest).resolves.toEqual([])
    expect(intents.filter((intent) => intent.type === 'cancelFolderSessionRequest')).toEqual([
      { type: 'cancelFolderSessionRequest', request_id: listIntent.request_id },
    ])
    expect(intents.filter((intent) => intent.type === 'cancelFolderSessionPreview')).toEqual([
      { type: 'cancelFolderSessionPreview', request_id: previewIntent.request_id },
    ])
  })

  it('ignores a late response for an aborted request without resolving the next request', async () => {
    const intents: Array<Record<string, unknown>> = []
    const browserWindow = nativeWindow(intents)
    vi.stubGlobal('window', browserWindow)
    const firstController = new AbortController()
    const first = bridge.listFolderSessions('claude', '/tmp/first', firstController.signal)
    const firstIntent = intents.find((intent) => intent.type === 'listFolderSessions')!
    const firstRejection = expect(first).rejects.toMatchObject({ name: 'AbortError' })
    firstController.abort()
    await firstRejection

    const second = bridge.listFolderSessions('claude', '/tmp/second')
    const listIntents = intents.filter((intent) => intent.type === 'listFolderSessions')
    const secondIntent = listIntents[1]
    let secondResolved = false
    void second.then(() => {
      secondResolved = true
    })

    browserWindow.__HYDRA_DASHBOARD_RESOLVE_FOLDER_SESSIONS__?.(
      String(firstIntent.request_id),
      [session],
    )
    await Promise.resolve()
    expect(secondResolved).toBe(false)

    browserWindow.__HYDRA_DASHBOARD_RESOLVE_FOLDER_SESSIONS__?.(
      String(secondIntent.request_id),
      [session],
    )
    await expect(second).resolves.toEqual([session])
  })
})
