import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { relative } from 'node:path'

const root = fileURLToPath(new URL('.', import.meta.url))
const entry = (name: string) => fileURLToPath(new URL('./src/bridge/' + name + '.ts', import.meta.url))

export default {
  envDir: false,
  publicDir: false,
  plugins: [{
    name: 'record-exact-core-runtime',
    generateBundle(_options: unknown, bundle: Record<string, any>) {
      const modules = [...new Set(Object.values(bundle).flatMap((chunk: any) =>
        chunk.type === 'chunk' ? Object.keys(chunk.modules) : [],
      ))].sort()
      const localPath = (id: string) => relative(root, id).replaceAll('\\', '/')
      if (modules.some((id) => id.includes('node_modules') || !localPath(id).startsWith('src/'))) {
        throw new Error('Unreviewed runtime module in core artifact')
      }
      writeFileSync(new URL('./.qa-build-graph.json', import.meta.url), JSON.stringify({
        modules: modules.map(localPath),
        chunks: Object.values(bundle).filter((chunk: any) => chunk.type === 'chunk')
          .map((chunk: any) => ({ file: chunk.fileName, exports: chunk.exports, imports: chunk.imports })),
      }, null, 2) + '\n')
    },
  }],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    minify: false,
    lib: {
      entry: {
        bridge: entry('webrtc-bridge'),
        signaling: entry('signaling-contract'),
        refusal: entry('setup-refusal-contract'),
        transport: entry('remote-transport'),
        'controller': fileURLToPath(new URL('./src/bridge/remote-client.ts', import.meta.url)),
        'session': fileURLToPath(new URL('./src/bridge/remote-session.ts', import.meta.url)),
        'auth': fileURLToPath(new URL('./src/bridge/auth-contract.ts', import.meta.url)),
        'identity': fileURLToPath(new URL('./src/bridge/device-identity.ts', import.meta.url)),
        'passkey': fileURLToPath(new URL('./src/bridge/passkey.ts', import.meta.url)),
        'signaling-http': fileURLToPath(new URL('./src/bridge/signaling-client.ts', import.meta.url)),
        'relay': fileURLToPath(new URL('./src/bridge/relay-credential-cache.ts', import.meta.url)),
        'layout': fileURLToPath(new URL('./src/bridge/remote-layout-cloud.ts', import.meta.url)),
        'protocol': fileURLToPath(new URL('./src/protocol/control-messages.ts', import.meta.url)),
        'terminal-protocol': fileURLToPath(new URL('./src/protocol/web-protocol.ts', import.meta.url)),
        'grid': fileURLToPath(new URL('./src/terminal/grid-renderer.ts', import.meta.url)),
        'input': fileURLToPath(new URL('./src/terminal/input-encoder.ts', import.meta.url)),
        'viewport': fileURLToPath(new URL('./src/terminal/viewport.ts', import.meta.url)),
        'selection': fileURLToPath(new URL('./src/terminal/selection-controller.ts', import.meta.url)),
        'theme': fileURLToPath(new URL('./src/terminal/theme.ts', import.meta.url)),
        'providers': fileURLToPath(new URL('./src/model/agent-provider-core.ts', import.meta.url)),
      },
      formats: ['es'],
      fileName: (_format: string, name: string) => name + '.js',
    },
  },
  test: { include: ['src/**/*.test.ts'] },
}
