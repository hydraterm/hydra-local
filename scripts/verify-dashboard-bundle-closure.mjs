#!/usr/bin/env node

import { readFile } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dashboard = join(root, 'dashboard-ui')
const modulesRoot = join(dashboard, 'node_modules')
const requireFromDashboard = createRequire(join(dashboard, 'package.json'))
const { build } = await import(pathToFileURL(requireFromDashboard.resolve('vite')).href)
let policyPath = join(root, 'scripts', 'third-party-license-policy.json')
if (process.argv.length === 4 && process.argv[2] === '--policy') {
  policyPath = process.argv[3]
} else if (process.argv.length !== 2) {
  throw new Error('dashboard-bundle-closure: usage: verify-dashboard-bundle-closure.mjs [--policy <path>]')
}
const policy = JSON.parse(
  await readFile(policyPath, 'utf8'),
)
const reviewedRuntime = new Set(Object.keys(policy.npm_runtime))
const expected = new Set(policy.npm_bundle_packages)
if ([...expected].some((key) => !reviewedRuntime.has(key))) {
  fail('reviewed bundle package set is outside the licensed runtime closure')
}

function fail(message) {
  throw new Error(`dashboard-bundle-closure: ${message}`)
}

function packageDirectory(moduleId) {
  const normalized = moduleId.replace(/^\0+/, '').split('?')[0].split(sep).join('/')
  const marker = '/node_modules/'
  const markerIndex = normalized.lastIndexOf(marker)
  if (markerIndex < 0) return null
  const packageStart = markerIndex + marker.length
  const segments = normalized.slice(packageStart).split('/')
  const packageSegments = segments[0].startsWith('@') ? segments.slice(0, 2) : segments.slice(0, 1)
  if (packageSegments.length === 0 || packageSegments.some((part) => !part)) {
    fail(`cannot identify package for module ${moduleId}`)
  }
  return normalized.slice(0, packageStart) + packageSegments.join('/')
}

const result = await build({
  root: dashboard,
  configFile: join(dashboard, 'vite.config.ts'),
  logLevel: 'silent',
  build: {
    emptyOutDir: false,
    write: false,
  },
})
const outputs = Array.isArray(result) ? result : [result]
const packageDirectories = new Set()
let shippedModuleCount = 0
for (const buildResult of outputs) {
  for (const output of buildResult.output) {
    if (output.type !== 'chunk') continue
    for (const moduleId of Object.keys(output.modules)) {
      shippedModuleCount += 1
      const directory = packageDirectory(moduleId)
      if (directory !== null) packageDirectories.add(directory)
    }
  }
}
if (shippedModuleCount === 0) fail('Vite emitted no module evidence')

const found = new Set()
for (const directory of [...packageDirectories].sort()) {
  const localPath = relative(modulesRoot, directory)
  if (localPath.startsWith('..') || localPath === '') {
    fail(`resolved package is outside dashboard-ui/node_modules: ${directory}`)
  }
  const manifest = JSON.parse(await readFile(join(directory, 'package.json'), 'utf8'))
  if (typeof manifest.name !== 'string' || typeof manifest.version !== 'string') {
    fail(`bundled package has no exact name/version: ${directory}`)
  }
  found.add(`${manifest.name}@${manifest.version}`)
}

const missing = [...expected].filter((key) => !found.has(key)).sort()
const extra = [...found].filter((key) => !expected.has(key)).sort()
if (missing.length > 0 || extra.length > 0) {
  fail(`runtime package set changed (missing=${JSON.stringify(missing)}, extra=${JSON.stringify(extra)})`)
}

console.log(
  `dashboard-bundle-closure: PASS packages=${found.size} modules=${shippedModuleCount} ` +
    `identities=${[...found].sort().join(',')}`,
)
