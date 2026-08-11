import { readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dist = join(root, 'dist')
const indexPath = join(dist, 'index.html')

let html = readFileSync(indexPath, 'utf8')

html = html.replace(
  /<link rel="stylesheet" crossorigin href="\.\/([^"]+)">/,
  (_match, assetPath) => {
    const css = readFileSync(join(dist, assetPath), 'utf8')
    return `<style>\n${css}\n</style>`
  },
)

html = html.replace(
  /<script type="module" crossorigin src="\.\/([^"]+)"><\/script>/,
  (_match, assetPath) => {
    const js = readFileSync(join(dist, assetPath), 'utf8')
    return `<script type="module">\n${js}\n</script>`
  },
)

writeFileSync(indexPath, html)
