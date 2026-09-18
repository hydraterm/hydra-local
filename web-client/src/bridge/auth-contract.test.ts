import { afterEach, describe, expect, it, vi } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'vite'
import * as ts from 'typescript'
import type { AuthProvider, Session } from './auth-contract'
import { RemoteClientController } from './remote-client'
import { StubDeviceIdentity } from './device-identity'

// The real controller must not load the hosted adapter or its SDK to use another identity provider.
vi.mock('./auth-provider', () => { throw new Error('hosted auth adapter entered neutral controller') })
vi.mock('@clerk/clerk-js', () => { throw new Error('hosted SDK entered neutral controller') })

const controllers: RemoteClientController[] = []
afterEach(() => {
  for (const controller of controllers.splice(0)) controller.dispose()
})

function provider(overrides: Partial<AuthProvider> = {}): AuthProvider {
  return {
    signIn: async () => null,
    signUp: async () => null,
    restore: async () => null,
    resumeIdentitySession: async () => null,
    current: () => null,
    signOut: async () => {},
    ...overrides,
  }
}

function controllerFor(auth: AuthProvider): RemoteClientController {
  const controller = new RemoteClientController({
    auth,
    identity: new StubDeviceIdentity('synthetic-browser'),
    listDesktops: async () => [],
    issueLinkCode: async () => { throw new Error('unexpected enrollment request') },
    revokeDevice: async () => false,
    legacyMintToken: async () => { throw new Error('unexpected authority request') },
    makeTransport: () => { throw new Error('unexpected transport request') },
    reconnectLifecycle: null,
  })
  controllers.push(controller)
  return controller
}

describe('provider-neutral auth contract', () => {
  it('emits the actual controller declaration graph without hosted auth or identity types', () => {
    const root = fileURLToPath(new URL('../', import.meta.url))
    const packageRoot = fileURLToPath(new URL('../../', import.meta.url))
    const normalize = (path: string) => relative(packageRoot, path).split(sep).join('/')
    const hosted = (path: string) => /(?:^|\/)(?:auth-provider|clerk-[^/]*)(?:\.d)?\.ts$|(?:^|\/)@clerk\//.test(path)
    const config = ts.readConfigFile(join(packageRoot, 'tsconfig.json'), ts.sys.readFile)
    expect(config.error).toBeUndefined()
    const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, packageRoot)
    expect(parsed.errors).toEqual([])
    const options: ts.CompilerOptions = {
      ...parsed.options, noEmit: false, declaration: true, emitDeclarationOnly: true,
    }
    const host = ts.createCompilerHost(options)
    const emitted = new Map<string, string>()
    host.writeFile = (path, text) => { emitted.set(normalize(path), text) }
    const program = ts.createProgram([join(root, 'bridge/remote-client.ts'), join(root, 'vite-env.d.ts')], options, host)
    expect(ts.getPreEmitDiagnostics(program).map((d) => `${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, '\n')}`)).toEqual([])
    expect(program.emit().emitSkipped).toBe(false)
    const sources = program.getSourceFiles().map((file) => normalize(file.fileName))
    expect(sources).toContain('src/bridge/remote-client.ts')
    expect(sources).toContain('src/bridge/auth-contract.ts')
    expect(sources.filter(hosted)).toEqual([])
    expect([...emitted.keys()]).toContain('src/bridge/remote-client.d.ts')
    expect([...emitted.keys()].filter(hosted)).toEqual([])
    expect([...emitted.values()].join('\n')).not.toMatch(/(?:from\s*|import\()\s*['"][^'"]*(?:auth-provider|clerk-|@clerk\/)/)
  })

  it('bundles independently without a hosted adapter, SDK or environment file', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hydra-auth-contract-'))
    try {
      const result = await build({
        configFile: false,
        root,
        envDir: root,
        publicDir: false,
        cacheDir: join(root, 'cache'),
        logLevel: 'silent',
        plugins: [{
          name: 'reject-hosted-auth-dependencies',
          resolveId(id) {
            if (/(?:^|\/)(?:auth-provider|clerk-[^/]*)(?:\.|$)|^@clerk\//.test(id)) {
              throw new Error('hosted dependency entered neutral contract bundle')
            }
          },
        }],
        build: {
          write: false,
          minify: false,
          lib: { entry: fileURLToPath(new URL('./auth-contract.ts', import.meta.url)), formats: ['es'] },
        },
      })
      const bundles = Array.isArray(result) ? result : [result]
      const modules = bundles.flatMap((bundle) => {
        if (!('output' in bundle)) throw new Error('unexpected watch build')
        return bundle.output.flatMap((chunk) => chunk.type === 'chunk' ? Object.keys(chunk.modules) : [])
      })
      expect(modules).toHaveLength(1)
      expect(modules[0]).toMatch(/\/auth-contract\.ts$/)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })

  it('uses a non-hosted provider continuation through the actual controller', async () => {
    const calls: string[] = []
    const session: Session = { accountId: 'synthetic-principal', credential: 'synthetic-adapter-marker' }
    const controller = controllerFor(provider({
      restore: async () => { calls.push('restore'); return null },
      resumeIdentitySession: async () => { calls.push('resume'); return session },
    }))
    await controller.restoreSession()
    expect(calls).toEqual(['restore', 'resume'])
    expect(controller.snapshot().phase).toBe('devices')
    expect(controller.snapshot().accountId).toBe(session.accountId)
  })

  it('does not resume a provider when restore already supplied a session', async () => {
    const resumeIdentitySession = vi.fn(async () => null)
    const controller = controllerFor(provider({
      restore: async () => ({ accountId: 'synthetic-restored', credential: 'synthetic-adapter-marker' }),
      resumeIdentitySession,
    }))
    await controller.restoreSession()
    expect(resumeIdentitySession).not.toHaveBeenCalled()
    expect(controller.snapshot().phase).toBe('devices')
  })

  it('keeps a signed-out provider sessionless without inventing an identity', async () => {
    const controller = controllerFor(provider())
    await controller.restoreSession()
    expect(controller.snapshot().phase).toBe('signed_out')
    expect(controller.snapshot().accountId).toBeNull()
  })

  it('keeps pending logout ahead of restoration and provider continuation', async () => {
    const restore = vi.fn(async () => null)
    const resumeIdentitySession = vi.fn(async () => null)
    const settlePendingSignOut = vi.fn(async () => true)
    const controller = controllerFor(provider({
      hasPendingSignOut: () => true,
      settlePendingSignOut,
      restore,
      resumeIdentitySession,
    }))
    await controller.restoreSession()
    expect(settlePendingSignOut).toHaveBeenCalledOnce()
    expect(restore).not.toHaveBeenCalled()
    expect(resumeIdentitySession).not.toHaveBeenCalled()
    expect(controller.snapshot().phase).toBe('signed_out')
  })
})
