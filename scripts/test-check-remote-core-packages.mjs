#!/usr/bin/env node
// Explicit qualified input keeps a skipped/discovered test from masquerading as a package gate.
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { after, test } from 'node:test'
import { childEnvironment, inspectSource } from './check-remote-core-packages.mjs'

const options = {}
for (let i = 2; i < process.argv.length; i += 2) {
  const key = { '--source': 'source', '--output': 'output', '--npm-cli': 'npmCli', '--cache': 'cache' }[process.argv[i]]
  assert.ok(key && !options[key] && process.argv[i + 1], 'Supply exactly --source, --output, --npm-cli and --cache')
  options[key] = process.argv[i + 1]
}
assert.equal(Object.keys(options).length, 4, 'Explicit package qualification inputs required')
const base = realpathSync(mkdtempSync(join(tmpdir(), 'hydra-package-refusals-')))
after(() => rmSync(base, { recursive: true }))
const original = inspectSource(options.source, options.output)
function fixture() {
  const root = mkdtempSync(join(base, 'input-'))
  for (const [name, body] of Object.entries(original)) {
    mkdirSync(dirname(join(root, name)), { recursive: true })
    writeFileSync(join(root, name), body)
  }
  return root
}
const output = () => join(base, 'never-created-' + Math.random().toString(16).slice(2))

test('complete selected source is accepted without writing input or output', () => {
  const root = fixture(), target = output()
  assert.equal(Object.keys(inspectSource(root, target)).length, 38)
  assert.ok(!existsSync(target))
  for (const [path, body] of Object.entries(original)) assert.deepEqual(readFileSync(join(root, path)), body)
})

test('every metadata and MIT digest is enforced before execution', () => {
  const root = fixture()
  for (const path of Object.keys(original).filter(path => !path.includes('/src/') && !path.includes('/test/'))) {
    const target = output(), full = join(root, path)
    writeFileSync(full, Buffer.concat([original[path], Buffer.from('\n')]))
    assert.throws(() => inspectSource(root, target), /digest drift/)
    assert.ok(!existsSync(target)); writeFileSync(full, original[path])
  }
})

test('missing runtime, test or config and extra hosted files/directories refuse', () => {
  const root = fixture()
  for (const path of ['web-client/src/bridge/webrtc-bridge.ts', 'hydra-cloud/test/signaling-port.test.ts', 'hydra-cloud/tsconfig.json']) {
    rmSync(join(root, path)); assert.throws(() => inspectSource(root, output()))
    writeFileSync(join(root, path), original[path])
  }
  for (const path of ['web-client/src/auth-provider.ts', 'hydra-cloud/src/entry.ts', 'web-client/.npmrc']) {
    writeFileSync(join(root, path), 'synthetic extra input\n')
    assert.throws(() => inspectSource(root, output()), /Extra package/); rmSync(join(root, path))
  }
  mkdirSync(join(root, 'web-client/unreviewed'))
  assert.throws(() => inspectSource(root, output()), /Extra package/)
})

test('symlink inputs, escaped or occupied output and in-checkout output refuse', () => {
  const root = fixture(), path = 'web-client/src/bridge/webrtc-bridge.ts'
  rmSync(join(root, path)); symlinkSync(join(options.source, path), join(root, path))
  assert.throws(() => inspectSource(root, output()), /link/)
  rmSync(join(root, path)); writeFileSync(join(root, path), original[path])
  assert.throws(() => inspectSource(root, root), /fresh nonexistent/)
  assert.throws(() => inspectSource(root, join(root, 'generated')), /outside source/)
  assert.throws(() => inspectSource(root, base + '/sub/../escape'), /non-escaping/)
  const fakeCheckout = mkdtempSync(join(base, 'checkout-'))
  writeFileSync(join(fakeCheckout, '.git'), 'synthetic marker\n')
  assert.throws(() => inspectSource(root, join(fakeCheckout, 'out')), /outside a Git checkout/)
  const link = join(base, 'input-link'); symlinkSync(root, link)
  assert.throws(() => inspectSource(link, output()), /Symlink/)
})

test('hosted dependencies, changed exports/tools/scripts never reach execution', () => {
  const root = fixture(), path = 'web-client/package.json', before = original[path]
  for (const [section, key, value] of [
    ['dependencies', '@clerk/clerk-js', '1.0.0'], ['exports', './hosted', './src/private.ts'],
    ['devDependencies', 'typescript', '0.0.1'], ['scripts', 'build', 'node private-entry.js'],
  ]) {
    const body = JSON.parse(before); body[section] ??= {}; body[section][key] = value
    writeFileSync(join(root, path), JSON.stringify(body))
    assert.throws(() => inspectSource(root, output()), /Metadata or MIT digest drift/)
  }
})

test('child environment does not inherit login, tokens, npmrc or loader injection', () => {
  const before = process.env.NODE_OPTIONS
  process.env.NODE_OPTIONS = '--require=synthetic-untrusted-loader'
  try {
    const env = childEnvironment('/synthetic-output', '/synthetic-cache')
    assert.deepEqual(Object.keys(env).sort(), ['HOME', 'NPM_CONFIG_AUDIT', 'NPM_CONFIG_CACHE',
      'NPM_CONFIG_FUND', 'NPM_CONFIG_GLOBALCONFIG', 'NPM_CONFIG_IGNORE_SCRIPTS', 'NPM_CONFIG_OFFLINE',
      'NPM_CONFIG_USERCONFIG', 'PATH', 'TMPDIR'].sort())
    assert.equal(env.HOME, '/synthetic-output/empty-home')
    assert.equal(env.NPM_CONFIG_USERCONFIG, '/synthetic-output/user.npmrc')
    assert.equal(env.NPM_CONFIG_GLOBALCONFIG, '/synthetic-output/global.npmrc')
    assert.equal(env.NPM_CONFIG_OFFLINE, 'true'); assert.equal(env.NPM_CONFIG_IGNORE_SCRIPTS, 'true')
  } finally { if (before === undefined) delete process.env.NODE_OPTIONS; else process.env.NODE_OPTIONS = before }
})

test('actual explicit runner builds packages and an ordinary fresh installed consumer', { timeout: 120_000 }, () => {
  const runner = join(dirname(fileURLToPath(import.meta.url)), 'check-remote-core-packages.mjs')
  const args = [runner, '--source', options.source, '--output', options.output, '--npm-cli', options.npmCli, '--cache', options.cache]
  const child = spawnSync(process.execPath, args, { encoding: 'utf8', timeout: 115_000, maxBuffer: 1024 * 1024 })
  assert.equal(child.status, 0, child.stdout + child.stderr)
  assert.match(child.stdout, /qualification: PASS/)
  const report = JSON.parse(readFileSync(join(options.output, 'RESULT.json')))
  assert.equal(report.complete, true); assert.equal(report.consumerToolLocationCount, 108)
  assert.equal(report.installedDeclarations.length, 17)
  assert.ok(report.operations.length >= 15 && report.operations.every(row => row.exit === 0))
  for (const [path, body] of Object.entries(original)) assert.deepEqual(readFileSync(join(options.source, path)), body)
})
