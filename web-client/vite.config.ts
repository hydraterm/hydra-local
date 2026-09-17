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
      },
      formats: ['es'],
      fileName: (_format: string, name: string) => name + '.js',
    },
  },
  test: { include: ['src/**/*.test.ts'] },
}
