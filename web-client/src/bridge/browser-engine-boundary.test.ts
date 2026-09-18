import { describe, expect, it } from 'vitest'
import { mkdtemp, rm } from 'node:fs/promises'
import { mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'vite'
import * as ts from 'typescript'

// Account-scoped local state and the neutral auth contract belong to the engine;
// concrete hosted identity, account/billing UI, deployment composition and artwork do not.
const forbidden = /(?:^|\/)(?:auth-provider|clerk-[^/]*|account-security|billing-client|operator-summary|remote-access-status|remote-entry|remote-prod-entry|remote-app|agent-provider|agent-badge)(?:\.d)?\.ts$|(?:^|\/)(?:assets|landing|remote)\/|(?:^|\/)@clerk\//
const entries = ['remote-client', 'webrtc-bridge', 'signaling-client', 'relay-credential-cache', 'device-identity', 'passkey', 'remote-layout-cloud']
const entry = (name: string) => fileURLToPath(new URL(`./${name}.ts`, import.meta.url))

describe('publishable browser engine closure', () => {
  it('emits the full integration declaration graph without hosted modules or artwork', async () => {
    const packageRoot = fileURLToPath(new URL('../../', import.meta.url))
    const config = ts.readConfigFile(join(packageRoot, 'tsconfig.json'), ts.sys.readFile)
    expect(config.error).toBeUndefined()
    const parsed = ts.parseJsonConfigFileContent(config.config, ts.sys, packageRoot)
    expect(parsed.errors).toEqual([])
    const options = { ...parsed.options, noEmit: false, declaration: true, emitDeclarationOnly: true }
    const host = ts.createCompilerHost(options)
    const emitted = new Map<string, string>()
    const normalize = (path: string) => relative(packageRoot, path).split(sep).join('/')
    host.writeFile = (path, text) => { emitted.set(normalize(path), text) }
    const program = ts.createProgram([...entries.map(entry), join(packageRoot, 'src/vite-env.d.ts')], options, host)
    expect(ts.getPreEmitDiagnostics(program).map((d) => `${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, '\n')}`)).toEqual([])
    expect(program.emit().emitSkipped).toBe(false)
    const sources = program.getSourceFiles().map((file) => normalize(file.fileName))
    expect(sources).toContain('src/model/agent-provider-core.ts')
    expect(sources.filter((path) => forbidden.test(path))).toEqual([])
    expect([...emitted.keys()].filter((path) => forbidden.test(path))).toEqual([])
    expect(emitted.has('src/bridge/remote-client.d.ts')).toBe(true)
    expect(emitted.has('src/terminal/grid-renderer.d.ts')).toBe(true)
    expect([...emitted.values()].join('\n')).not.toMatch(/(?:from\s*|import\()\s*['"][^'"]*(?:auth-provider|clerk-|billing-client|assets\/|model\/agent-provider['"])/)
    const installed = await mkdtemp(join(tmpdir(), 'hydra-engine-declarations-'))
    try {
      writeFileSync(join(installed, 'package.json'), '{"type":"module"}\n')
      for (const [path, body] of emitted) {
        mkdirSync(dirname(join(installed, path)), { recursive: true })
        writeFileSync(join(installed, path), body)
      }
      const consumer = ts.createProgram([...emitted.keys()].map((path) => join(installed, path)), {
        strict: true, skipLibCheck: false, noEmit: true, target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext,
        types: [], lib: ['lib.es2022.d.ts', 'lib.dom.d.ts', 'lib.dom.iterable.d.ts'],
      })
      expect(ts.getPreEmitDiagnostics(consumer).map((d) => `${d.code}: ${ts.flattenDiagnosticMessageText(d.messageText, '\n')}`)).toEqual([])
    } finally {
      await rm(installed, { recursive: true, force: true })
    }
  })

  it('bundles the actual controller, terminal and adapters with no external runtime or artwork', async () => {
    const root = await mkdtemp(join(tmpdir(), 'hydra-browser-engine-'))
    try {
      const result = await build({
        configFile: false, root, envDir: false, publicDir: false,
        cacheDir: join(root, 'cache'), logLevel: 'silent',
        plugins: [{
          name: 'browser-engine-boundary',
          resolveId(id) {
            if (forbidden.test(id) || /\.(svg|png)(?:\?|$)/.test(id)) {
              throw new Error('hosted module or artwork entered browser engine')
            }
          },
        }],
        build: {
          write: false, minify: false,
          lib: { entry: Object.fromEntries(entries.map((name) => [name, entry(name)])), formats: ['es'] },
        },
      })
      const bundles = Array.isArray(result) ? result : [result]
      const chunks = bundles.flatMap((bundle) => {
        if (!('output' in bundle)) throw new Error('unexpected watch build')
        expect(bundle.output.every((part) => part.type === 'chunk')).toBe(true)
        return bundle.output.flatMap((part) => part.type === 'chunk' ? [part] : [])
      })
      const modules = [...new Set(chunks.flatMap((chunk) => Object.keys(chunk.modules)))]
      expect(modules).toContain(entry('remote-client'))
      expect(modules.some((path) => path.endsWith('/terminal/grid-renderer.ts'))).toBe(true)
      expect(modules.filter((path) => forbidden.test(path) || path.includes('/node_modules/'))).toEqual([])
      const files = new Set(chunks.map((chunk) => chunk.fileName))
      expect(chunks.flatMap((chunk) => [...chunk.imports, ...chunk.dynamicImports]).every((path) => files.has(path))).toBe(true)
    } finally {
      await rm(root, { recursive: true, force: true })
    }
  })
})
