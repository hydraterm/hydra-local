import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'vite'
import {
  parseRemoteLayout, serializeRemoteLayout, REMOTE_LAYOUT_SCHEMA_V, type RemoteLayoutPort,
} from './remote-layout-contract'
import * as hosted from './remote-layout-cloud'
import type { AuthProvider, Session } from './auth-contract'
import { RemoteClientController } from './remote-client'
import { StubDeviceIdentity } from './device-identity'
import { FakeTransport } from './remote-transport'
import { leaves, type WorkspacePanes } from '../model/pane-layout'

function memoryStorage(): Storage {
  const values = new Map<string, string>()
  return {
    get length() { return values.size },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(key) },
    setItem: (key, value) => { values.set(key, value) },
  }
}

const controllers: RemoteClientController[] = []
beforeEach(() => {
  vi.stubGlobal('localStorage', memoryStorage())
  vi.stubGlobal('sessionStorage', memoryStorage())
})
afterEach(() => {
  for (const controller of controllers.splice(0)) controller.dispose()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function onePane(paneId: string, sessionId: string): WorkspacePanes {
  return { layout: { root: { kind: 'leaf', id: paneId, sessionId }, activePaneId: paneId }, stashed: [] }
}

const saved = (activeWindowId: string) => serializeRemoteLayout(activeWindowId, {
  'window-a': onePane('pane-a', 'session-a'),
  'window-b': onePane('pane-b', 'session-b'),
}, { projects: ['project-a'], windows: ['window-a', 'window-b'], panes: ['pane-a', 'pane-b'] })

function controllerWith(port: RemoteLayoutPort) {
  let current: Session | null = null
  const auth: AuthProvider = {
    signIn: async () => (current = { accountId: 'synthetic-account', credential: 'synthetic-adapter-marker' }),
    signUp: async () => null,
    restore: async () => current,
    resumeIdentitySession: async () => null,
    current: () => current,
    signOut: async () => { current = null },
  }
  let transport = new FakeTransport()
  const controller = new RemoteClientController({
    auth,
    identity: new StubDeviceIdentity('synthetic-browser'),
    remoteLayout: port,
    listDesktops: async () => [{ deviceId: 'synthetic-desktop', label: 'Synthetic desktop', revoked: false }],
    issueLinkCode: async () => { throw new Error('unexpected enrollment') },
    revokeDevice: async () => false,
    legacyMintToken: async () => 'synthetic-authority-marker',
    reconnectLifecycle: null,
    makeTransport: () => {
      transport = new FakeTransport()
      return { transport, connect: async () => {} }
    },
  })
  controllers.push(controller)
  return {
    controller,
    async connect() {
      await controller.signIn()
      await controller.connectTo('synthetic-desktop')
      transport.emitState('connected')
      transport.emitText(JSON.stringify({
        type: 'auth_ok', account_id: 'synthetic-account', device_id: 'synthetic-browser',
      }))
      transport.emitText(JSON.stringify({
        type: 'session_list_result', request_id: 'synthetic-list', sessions: ['session-a', 'session-b'],
        workspace_metadata: {
          projects: [{
            id: 'project-a', name: 'SYNTHETIC_PROJECT_TITLE', root: '/synthetic-only',
            windows: [
              { id: 'window-a', name: 'SYNTHETIC_WINDOW_TITLE', focused: true, panes: [{ id: 'pane-a', session_id: 'session-a' }] },
              { id: 'window-b', name: 'Second window', panes: [{ id: 'pane-b', session_id: 'session-b' }] },
            ],
          }],
        },
      }))
    },
  }
}

describe('provider-neutral layout storage', () => {
  it('bundles the actual controller without hosted layout or authentication adapters', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hydra-layout-port-'))
    try {
      const result = await build({
        configFile: false, root, envDir: root, publicDir: false,
        cacheDir: join(root, 'cache'), logLevel: 'silent',
        plugins: [{
          name: 'reject-hosted-layout-imports',
          resolveId(id) {
            if (/(?:^|\/)(?:remote-layout-cloud|auth-provider|clerk-[^/]*)(?:\.|$)|^@clerk\//.test(id)) {
              throw new Error('hosted adapter entered neutral layout consumer')
            }
          },
        }],
        build: {
          write: false, minify: false,
          lib: { entry: fileURLToPath(new URL('./remote-client.ts', import.meta.url)), formats: ['es'] },
        },
      })
      const modules = (Array.isArray(result) ? result : [result]).flatMap((bundle) => {
        if (!('output' in bundle)) throw new Error('unexpected watch build')
        return bundle.output.flatMap((chunk) => chunk.type === 'chunk' ? Object.keys(chunk.modules) : [])
      })
      expect(modules.some((id) => id.endsWith('/remote-client.ts'))).toBe(true)
      expect(modules.some((id) => id.endsWith('/remote-layout-contract.ts'))).toBe(true)
      expect(modules.some((id) => /remote-layout-cloud|auth-provider|clerk/i.test(id))).toBe(false)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it('preserves the hosted codec function and schema-version re-exports', () => {
    expect(hosted.parseRemoteLayout).toBe(parseRemoteLayout)
    expect(hosted.serializeRemoteLayout).toBe(serializeRemoteLayout)
    expect(hosted.REMOTE_LAYOUT_SCHEMA_V).toBe(REMOTE_LAYOUT_SCHEMA_V)
  })

  it('restores and persists through a non-HTTP port using the actual controller', async () => {
    const http = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('unexpected HTTP request'))
    const rows = new Map([['synthetic-desktop', saved('window-b')]])
    const fetchLayout = vi.fn(async (deviceId: string) => rows.get(deviceId) ?? null)
    const putLayout = vi.fn((deviceId: string, row: string) => { rows.set(deviceId, row) })
    const port: RemoteLayoutPort = { fetchLayout, putLayout }
    const first = controllerWith(port)
    await first.connect()
    await vi.waitFor(() => expect(first.controller.snapshot().activeWindowId).toBe('window-b'))
    expect(leaves(first.controller.snapshot().paneLayout.root).map((pane) => pane.sessionId)).toEqual(['session-b'])
    expect(fetchLayout).toHaveBeenCalledExactlyOnceWith('synthetic-desktop')
    putLayout.mockClear()
    first.controller.setActiveWindow('window-a')
    expect(putLayout).toHaveBeenCalled()
    const [deviceId, row] = putLayout.mock.lastCall!
    expect(deviceId).toBe('synthetic-desktop')
    expect(parseRemoteLayout(row)?.activeWindowId).toBe('window-a')
    expect(Object.keys(parseRemoteLayout(row)!.windows).sort()).toEqual(['window-a', 'window-b'])
    expect(row).not.toMatch(/SYNTHETIC_PROJECT_TITLE|SYNTHETIC_WINDOW_TITLE|synthetic-only|synthetic-authority/)
    const priorMap = first.controller.snapshot().paneLayoutsByWindow
    first.controller.dispose()
    localStorage.clear()
    sessionStorage.clear()
    const second = controllerWith(port)
    await second.connect()
    await vi.waitFor(() => expect(second.controller.snapshot().paneLayoutsByWindow).toEqual(priorMap))
    expect(second.controller.snapshot().activeWindowId).toBe('window-a')
    expect(http).not.toHaveBeenCalled()
  })

  it('keeps hydration gated and ignores a late restore from a superseded connection', async () => {
    const pending: Array<(row: string | null) => void> = []
    const putLayout = vi.fn()
    const port: RemoteLayoutPort = {
      fetchLayout: () => new Promise((resolve) => { pending.push(resolve) }),
      putLayout,
    }
    const current = controllerWith(port)
    await current.connect()
    expect(pending).toHaveLength(1)
    current.controller.attach('session-a', 80, 24)
    expect(putLayout).not.toHaveBeenCalled()
    current.controller.disconnect()
    await current.connect()
    expect(pending).toHaveLength(2)
    pending[1]!(saved('window-a'))
    await vi.waitFor(() => expect(current.controller.snapshot().activeWindowId).toBe('window-a'))
    const before = current.controller.snapshot().paneLayoutsByWindow
    const writesBefore = putLayout.mock.calls.length
    pending[0]!(saved('window-b'))
    await Promise.resolve()
    await Promise.resolve()
    expect(current.controller.snapshot().activeWindowId).toBe('window-a')
    expect(current.controller.snapshot().paneLayoutsByWindow).toEqual(before)
    expect(putLayout).toHaveBeenCalledTimes(writesBefore)
  })
})
