import { afterEach, expect, it, vi } from 'vitest'
import { act, create, type ReactTestRenderer } from 'react-test-renderer'
import { App } from './App'
import { mockDashboardModel } from './data/mock'
import { bridge } from './ipc/bridge'

let renderer: ReactTestRenderer | null = null
afterEach(() => {
  if (renderer) act(() => renderer!.unmount())
  renderer = null
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

async function submitCustom(kind: 'newProject' | 'newWindow', accepted: boolean, storedOverride?: string) {
  const raw = String.raw`"C:\Tools O'Brien 日本語\claude.cmd" "\\server\share" --version`
  const stored = storedOverride ?? String.raw`'C:\\Tools O'\''Brien 日本語\\claude.cmd' '\\\\server\\share' '--version'`
  const model = structuredClone(mockDashboardModel)
  model.details.sample_workspace.launch_defaults = {
    agent: 'claude', custom_command: stored,
  }
  vi.spyOn(bridge, 'listFolderSessions').mockResolvedValue([])
  const intents: Array<Record<string, unknown>> = []
  const host = Object.assign(new EventTarget(), {
    location: { href: 'hydra://localhost/index.html?chrome=overlay', search: '?chrome=overlay' },
    setTimeout: globalThis.setTimeout.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    hydraDashboard: {
      getDashboardModel: () => model,
      onDashboardModel: () => () => undefined,
      postIntent: (intent: Record<string, unknown>) => {
        intents.push(intent)
        if (intent.type === 'preflightLaunch') {
          window.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__?.(
            String(intent.request_id), accepted, accepted ? null : 'The launch command is not valid.',
          )
        }
        if (intent.type === 'createWindow') {
          window.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_MUTATION__?.(String(intent.request_id), true, null)
        }
      },
    },
  }) as unknown as Window & { __HYDRA_SHOW_OVERLAY_MODAL__?: (modal: object) => void }
  vi.stubGlobal('window', host)
  vi.stubGlobal('document', {
    body: { classList: { add: () => undefined, remove: () => undefined } },
  })
  await act(async () => { renderer = create(<App />) })
  act(() => host.__HYDRA_SHOW_OVERLAY_MODAL__?.({ kind, project_id: 'sample_workspace' }))
  if (kind === 'newProject') {
    act(() => {
      renderer!.root.findByProps({ placeholder: 'Capacity Paper' }).props.onChange({ target: { value: 'Custom QA' } })
      renderer!.root.findByProps({ placeholder: '~/path/to/project' }).props.onChange({ target: { value: 'C:\\fixture' } })
      renderer!.root.findByProps({ placeholder: 'Custom command (overrides above) -- e.g. claude mcp ...' })
        .props.onChange({ target: { value: raw } })
    })
  }
  await act(async () => {
    renderer!.root.findByProps({ className: 'split-dialog__submit' }).props.onClick()
    await Promise.resolve()
  })
  return { raw, stored, intents }
}

it.each(['newProject', 'newWindow'] as const)('%s distinguishes new raw text from already-canonical saved defaults', async kind => {
  const { raw, stored, intents } = await submitCustom(kind, true)
  const preflight = intents.find(intent => intent.type === 'preflightLaunch')!
  const createIntent = intents.find(intent => intent.type === (kind === 'newProject' ? 'createProject' : 'createWindow'))!
  expect(preflight.custom_command).toBe(kind === 'newProject' ? raw : undefined)
  expect(createIntent.custom_command).toBe(kind === 'newProject' ? raw : undefined)
  expect(preflight.resolved_launch_command).toBe(kind === 'newProject' ? raw : stored)
  expect(createIntent.resolved_launch_command).toBe(kind === 'newProject' ? raw : stored)
})

it('never reinterprets malformed saved canonical defaults as new native input', async () => {
  const { intents, stored } = await submitCustom('newWindow', false, "claude 'unfinished")
  const preflight = intents.find(intent => intent.type === 'preflightLaunch')!
  expect(preflight.custom_command).toBeUndefined()
  expect(preflight.resolved_launch_command).toBe(stored)
  expect(intents.some(intent => intent.type === 'createWindow')).toBe(false)
})

it('bridge sends custom-only syntax preflight instead of silently approving it', async () => {
  const { intents } = await submitCustom('newProject', false)
  const result = await bridge.preflightLaunch({ custom_command: '"unfinished' })
  expect(result.ok).toBe(false)
  const preflights = intents.filter(intent => intent.type === 'preflightLaunch')
  const preflight = preflights[preflights.length - 1]!
  expect(preflight.custom_command).toBe('"unfinished')
  expect(preflight.agent).toBeUndefined()
  expect(preflight.resolved_launch_command).toBeUndefined()
  expect(intents.some(intent => intent.type === 'createProject')).toBe(false)
})

it.each(['newProject', 'newWindow'] as const)('%s keeps native custom refusal visible without creating fallback sessions', async kind => {
  const { intents } = await submitCustom(kind, false)
  expect(intents.some(intent => intent.type === 'createProject' || intent.type === 'createWindow')).toBe(false)
  expect(renderer!.root.findByProps({ role: 'alert' }).children.join('')).toContain('command is not valid')
})
