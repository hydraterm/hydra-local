import { describe, expect, expectTypeOf, it } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { isAbsolute, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import * as ts from 'typescript'
import { build } from 'vite'
import { SignalingBroker, SESSION_TTL_MS } from '../src/domain/signaling.js'
import type { SignalingBrokerStore } from '../src/domain/signaling-ports.js'
import type { AuditEvent, Device, SignalingSession, SignalingSessionHeader } from '../src/domain/types.js'

const METHODS = [
  'appendAudit', 'appendIce', 'createSession', 'getDevice', 'getPeerIceSince', 'getProgress',
  'getSession', 'getSessionHeader', 'listPendingOffers', 'setAnswer', 'setStatus',
] as const

function fixture() {
  let now = 1_000_000
  const devices = new Map<string, Device>([
    ['browser', { deviceId: 'browser', accountId: 'synthetic-account', label: 'Synthetic browser',
      kind: 'browser', publicKey: 'synthetic-public-key', publicKeyAlg: 'p256', createdAtMs: now, revoked: false }],
    ['desktop', { deviceId: 'desktop', accountId: 'synthetic-account', label: 'Synthetic desktop',
      kind: 'desktop', publicKey: 'synthetic-desktop-public-key', createdAtMs: now, revoked: false }],
  ])
  const rows = new Map<string, SignalingSession>()
  const audits: AuditEvent[] = []
  const header = (row: SignalingSession): SignalingSessionHeader => {
    const { ice: _ice, ...rest } = row
    return rest
  }
  const peerIce = (row: SignalingSession, caller: string, since: number) => ({
    candidates: row.ice.filter((ice) => ice.from !== caller && ice.seq > since),
    nextSince: row.ice.at(-1)?.seq ?? 0,
  })
  // A complete independent 11-method adapter: no hosted Store, auth, billing or enrollment implementation.
  const store: SignalingBrokerStore = {
    getDevice: async (id) => devices.get(id) ?? null,
    appendAudit: async (event) => { audits.push(event) },
    createSession: async (row) => { rows.set(row.sessionId, row) },
    getSession: async (id) => rows.get(id) ?? null,
    getSessionHeader: async (id) => rows.has(id) ? header(rows.get(id)!) : null,
    listPendingOffers: async (account, target) => [...rows.values()]
      .filter((row) => row.accountId === account && row.targetDeviceId === target && row.status === 'pending')
      .sort((a, b) => a.createdAtMs - b.createdAtMs)
      .map(({ sessionId, sourceDeviceId, offer, createdAtMs, expiresAtMs }) =>
        ({ sessionId, sourceDeviceId, offer, createdAtMs, expiresAtMs })),
    getPeerIceSince: async (id, caller, since) => peerIce(rows.get(id)!, caller, since),
    getProgress: async (id, caller, since, answerSeen) => {
      const row = rows.get(id)
      if (!row) return null
      return {
        sessionId: id, accountId: row.accountId, sourceDeviceId: row.sourceDeviceId,
        targetDeviceId: row.targetDeviceId, status: row.status, expiresAtMs: row.expiresAtMs,
        ...(!answerSeen && row.answer !== undefined ? { answer: row.answer } : {}),
        ...peerIce(row, caller, since),
      }
    },
    setAnswer: async (id, answer) => { Object.assign(rows.get(id)!, { answer, status: 'answered', updatedAtMs: now }) },
    setStatus: async (id, status) => { Object.assign(rows.get(id)!, { status, updatedAtMs: now }) },
    appendIce: async (id, blob, max) => {
      const row = rows.get(id)
      if (!row) return { status: 'session_not_found' }
      const prior = row.ice.find((ice) => ice.from === blob.from && ice.candidate === blob.candidate)
      if (prior) return { status: 'existing', seq: prior.seq }
      if (row.ice.length >= max) return { status: 'too_many_candidates' }
      const seq = (row.ice.at(-1)?.seq ?? 0) + 1
      row.ice.push({ ...blob, seq })
      return { status: 'appended', seq }
    },
  }
  const broker = new SignalingBroker(store, { nowMs: () => now })
  return { store, broker, devices, audits, advance: (ms: number) => { now += ms } }
}

describe('independently reusable signaling broker port', () => {
  it('uses exactly the 11-method port for real exchange, peer ICE, progress and cancellation', async () => {
    expectTypeOf<keyof SignalingBrokerStore>().toEqualTypeOf<typeof METHODS[number]>()
    const { store, broker, audits } = fixture()
    expect(Object.keys(store).sort()).toEqual([...METHODS])
    const accountId = 'synthetic-account'
    const created = await broker.createSession({ accountId, sourceDeviceId: 'browser', targetDeviceId: 'desktop', offer: 'opaque-offer' })
    expect(await broker.pendingForTarget(accountId, 'desktop')).toMatchObject([{ sessionId: created.sessionId, offer: 'opaque-offer' }])
    await broker.answer({ accountId, deviceId: 'desktop', sessionId: created.sessionId, answer: 'opaque-answer' })
    const input = { accountId, deviceId: 'desktop', sessionId: created.sessionId, candidate: 'opaque-candidate' }
    expect(await broker.addIce(input)).toBe(1)
    expect(await broker.addIce(input)).toBe(1)
    expect(await broker.progress({ accountId, deviceId: 'browser', sessionId: created.sessionId, since: 0, answerSeen: false }))
      .toEqual({ status: 'answered', expiresAtMs: created.expiresAtMs, answer: 'opaque-answer', candidates: [{ candidate: 'opaque-candidate', seq: 1 }], nextSince: 1 })
    await broker.cancel(accountId, 'browser', created.sessionId)
    await expect(broker.getSession(accountId, 'browser', created.sessionId)).rejects.toMatchObject({ refusal: 'cancelled' })
    expect(JSON.stringify(audits)).not.toMatch(/opaque-(offer|answer|candidate)/)
  })

  it('preserves enrollment, same-account, revocation, party and expiry checks on the minimal adapter', async () => {
    const { broker, devices, advance } = fixture()
    const input = { accountId: 'synthetic-account', sourceDeviceId: 'browser', targetDeviceId: 'desktop', offer: 'opaque-offer' }
    await expect(broker.createSession({ ...input, sourceDeviceId: 'missing' })).rejects.toMatchObject({ refusal: 'device_not_enrolled' })
    await expect(broker.createSession({ ...input, accountId: 'other-account' })).rejects.toMatchObject({ refusal: 'cross_account' })
    devices.get('browser')!.revoked = true
    await expect(broker.createSession(input)).rejects.toMatchObject({ refusal: 'revoked' })
    devices.get('browser')!.revoked = false
    const created = await broker.createSession(input)
    devices.set('other-browser', { ...devices.get('browser')!, deviceId: 'other-browser' })
    await expect(broker.getSession(input.accountId, 'other-browser', created.sessionId)).rejects.toMatchObject({ refusal: 'not_a_party' })
    advance(SESSION_TTL_MS)
    await expect(broker.getSession(input.accountId, 'browser', created.sessionId)).rejects.toMatchObject({ refusal: 'expired' })
  })

  it('bundles the actual broker without mixed ports, broad service or hosted implementations', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hydra-signaling-broker-'))
    try {
      const result = await build({
        configFile: false, root, envDir: root, publicDir: false, cacheDir: join(root, 'cache'), logLevel: 'silent',
        plugins: [{
          name: 'reject-hosted-broker-imports',
          resolveId(id) {
            if (/(?:adapters\/ports|service|billing|clerk|server|adapters\/(?:dev|postgres|memory))|^@clerk\//i.test(id)) {
              throw new Error('mixed or hosted module entered broker runtime')
            }
          },
        }],
        build: {
          write: false, minify: false,
          lib: { entry: fileURLToPath(new URL('../src/domain/signaling.ts', import.meta.url)), formats: ['es'] },
          rollupOptions: { external: ['node:crypto'] },
        },
      })
      const modules = (Array.isArray(result) ? result : [result]).flatMap((bundle) => {
        if (!('output' in bundle)) throw new Error('unexpected watch build')
        return bundle.output.flatMap((chunk) => chunk.type === 'chunk' ? Object.keys(chunk.modules) : [])
      })
      expect(modules.some((id) => id.endsWith('/domain/signaling.ts'))).toBe(true)
      expect(modules.some((id) => id.endsWith('/domain/clock.ts'))).toBe(true)
      expect(modules.every((id) => !/(?:adapters\/|service\.ts|billing|clerk|server\.ts)/i.test(id))).toBe(true)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it('compiles and emits the actual broker declaration closure without mixed or hosted types', () => {
    const packageRoot = fileURLToPath(new URL('../', import.meta.url))
    const src = join(packageRoot, 'src')
    const relativeSource = (name: string) => relative(src, name).split(sep).join('/')
    const options: ts.CompilerOptions = {
      target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler,
      strict: true, noUncheckedIndexedAccess: true, exactOptionalPropertyTypes: true, skipLibCheck: true,
      declaration: true, emitDeclarationOnly: true, types: ['node'], typeRoots: [join(packageRoot, 'node_modules/@types')],
    }
    const host = ts.createCompilerHost(options)
    const emitted = new Map<string, string>()
    host.writeFile = (name, text) => { emitted.set(relativeSource(name), text) }
    const program = ts.createProgram([join(src, 'domain/signaling.ts')], options, host)
    const diagnostics = ts.getPreEmitDiagnostics(program)
    expect(diagnostics.map((d) => `${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, '\n')}`)).toEqual([])
    const closure = program.getSourceFiles().map((file) => relativeSource(file.fileName))
      .filter((path) => path !== '..' && !path.startsWith('../') && !isAbsolute(path)).sort()
    expect(closure).toEqual([
      'domain/clock.ts', 'domain/content-blind.ts', 'domain/offer-wake.ts',
      'domain/signaling-ports.ts', 'domain/signaling.ts', 'domain/types.ts',
    ])
    expect(program.emit().emitSkipped).toBe(false)
    expect([...emitted.keys()].sort()).toEqual(closure.map((path) => path.replace(/\.ts$/, '.d.ts')))
    expect(emitted.get('domain/signaling.d.ts')).toContain('SignalingBrokerStore')
    expect(emitted.get('domain/signaling.d.ts')).not.toMatch(/adapters\/ports|service\.js/)
    expect(emitted.get('domain/signaling-ports.d.ts')).not.toMatch(/Clerk|Billing|SessionStore|IdentityVerifier/)
  })
})
