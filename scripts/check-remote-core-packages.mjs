#!/usr/bin/env node
// Explicit offline package qualification; never an install hook or a publisher.
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const sha = bytes => createHash('sha256').update(bytes).digest('hex')
const json = path => JSON.parse(readFileSync(path, 'utf8'))
const encode = value => JSON.stringify(value, null, 2) + '\n'
const packages = ['web-client', 'hydra-cloud']
const fixtures = ['browser-consumer.ts', 'broker-fixture.ts', 'consumer.test.ts']
const pins = {
  LICENSE: '763a6e17187e1e6998d6d1af0d323c276e89fd54eff401bea96f20ba55d7828b',
  'web-client/package-lock.json': 'ef9c130a7481c2c23f7a02197beccc12a6925c99bc1ab281d347ba9a952c88e3',
  'web-client/package.json': 'f908a8a1db1c62e635dddb6624bc83939c798c130898d6931d9f32f0826ce8f9',
  'web-client/tsconfig.json': '60c13f7d2d8b39dad5f29e8bb39598f26126c41021a129d7f43cf6c3f8edcbef',
  'web-client/tsconfig.core-build.json': 'd5d492691452dd3ac69cc2657d6dbda0379d0b1cb90cf986e43572d35c145c1d',
  'web-client/vite.config.ts': '9e3df78c1e438fe868435ed21c7c4549d43a6b7351fe0cba90f0a45713cc5fa5',
  'hydra-cloud/package-lock.json': '325f475dd0ab2f374d3086d4ed895da61fa0fb59a7c3affc9b1fb9115996d3c8',
  'hydra-cloud/package.json': 'e7a03ce33c58941da71b7a281001c0a251a5e0d17da7ae421ee14c173de66809',
  'hydra-cloud/tsconfig.json': '55686b33aaa6786496c8a8a3c0b49d1f095a7e4a03a4190170b118a2361da4a4',
  'hydra-cloud/tsconfig.core-build.json': '14dac3664fc66ea4bfd2459158c2f9e0f7569975ff8b2cdb91253b07793b9ac4',
}
const browserUnits = ['connect-deadline', 'datachannel-send-queue', 'ice-candidate-security',
  'ice-path-classifier', 'relay-fallback', 'remote-transport', 'sdp-security',
  'setup-refusal-contract', 'signaling-contract', 'webrtc-bridge']
const browserTests = ['connect-deadline', 'datachannel-send-queue', 'ice-candidate-security',
  'ice-path-classifier', 'relay-fallback', 'sdp-security', 'signaling-contract',
  'webrtc-attempt-ownership', 'webrtc-security']
const brokerUnits = ['clock', 'content-blind', 'offer-wake', 'signaling-ports', 'signaling', 'types']
const leaves = [...Object.keys(pins),
  ...browserUnits.map(name => `web-client/src/bridge/${name}.ts`),
  ...browserTests.map(name => `web-client/src/bridge/${name}.test.ts`),
  'web-client/src/protocol/bounded-control-json.ts', 'web-client/src/protocol/bounded-control-json.test.ts',
  ...brokerUnits.map(name => `hydra-cloud/src/domain/${name}.ts`), 'hydra-cloud/test/signaling-port.test.ts',
].sort()
assert.equal(leaves.length, 38)

function safePath(path, existing = true) {
  assert.ok(isAbsolute(path) && resolve(path) === path, 'Use an absolute non-escaping path')
  for (let current = path; ; current = dirname(current)) {
    if (current !== path || existing) assert.ok(!lstatSync(current).isSymbolicLink(), 'Symlink path refused')
    if (dirname(current) === current) break
  }
  return path
}
function readRegular(path) {
  safePath(path)
  const stat = lstatSync(path)
  assert.ok(stat.isFile() && stat.size <= 2 * 1024 * 1024, 'Expected bounded regular input')
  return readFileSync(path)
}
function walk(root) {
  return readdirSync(root).sort().flatMap(name => {
    const path = join(root, name), stat = lstatSync(path)
    assert.ok(!stat.isSymbolicLink() && (stat.isFile() || stat.isDirectory()), 'Unexpected link or special file')
    return stat.isDirectory() ? [path + sep, ...walk(path)] : [path]
  })
}
export function inspectSource(source, output) {
  safePath(source)
  assert.ok(lstatSync(source).isDirectory(), 'Source must be a directory')
  safePath(output, false)
  assert.ok(!existsSync(output), 'Output must be a fresh nonexistent directory')
  assert.ok(!output.startsWith(source + sep) && output !== source, 'Output must be outside source')
  for (let path = dirname(output); ; path = dirname(path)) {
    assert.ok(!existsSync(join(path, '.git')), 'Output must be outside a Git checkout')
    if (dirname(path) === path) break
  }
  const allowed = new Set(leaves)
  for (const path of leaves) for (let parent = dirname(path); parent !== '.'; parent = dirname(parent)) allowed.add(parent + sep)
  for (const pkg of packages) {
    const actual = walk(join(source, pkg)).map(path => relative(source, path) + (path.endsWith(sep) ? sep : ''))
    assert.ok(actual.every(path => allowed.has(path)), 'Extra package leaf or directory')
    assert.deepEqual(actual.filter(path => !path.endsWith(sep)).sort(), leaves.filter(path => path.startsWith(pkg + '/')))
  }
  const inputs = Object.fromEntries(leaves.map(path => [path, readRegular(join(source, path))]))
  for (const [path, pin] of Object.entries(pins)) assert.equal(sha(inputs[path]), pin, 'Metadata or MIT digest drift: ' + path)
  return inputs
}
function write(path, bytes) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  writeFileSync(path, bytes, { flag: 'wx', mode: 0o644 })
}
const compilerOptions = { target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext',
  strict: true, noEmit: true, skipLibCheck: false, lib: ['ES2022', 'DOM', 'DOM.Iterable'], types: ['node'] }

export function childEnvironment(output, cache) {
  return { PATH: dirname(process.execPath) + ':/usr/bin:/bin:/usr/sbin:/sbin',
    HOME: join(output, 'empty-home'), TMPDIR: join(output, 'tmp'),
    NPM_CONFIG_USERCONFIG: join(output, 'user.npmrc'), NPM_CONFIG_GLOBALCONFIG: join(output, 'global.npmrc'),
    NPM_CONFIG_CACHE: cache, NPM_CONFIG_OFFLINE: 'true', NPM_CONFIG_IGNORE_SCRIPTS: 'true',
    NPM_CONFIG_AUDIT: 'false', NPM_CONFIG_FUND: 'false' }
}

export async function qualify({ source, output, npmCli, cache }) {
  const inputs = inspectSource(source, output)
  const ownInputs = Object.fromEntries(fixtures.map(name => [name, readRegular(join(here, 'remote-core-consumer', name))]))
  const guide = readRegular(join(here, '../docs/developer/remote-core-quickstart.md'))
  const snippets = [...guide.toString().matchAll(/```ts\n([\s\S]*?)```/g)].map(match => match[1])
  assert.equal(snippets.length, 2, 'Expected two current quickstart examples')
  const npmBytes = readRegular(npmCli)
  safePath(cache); assert.ok(lstatSync(cache).isDirectory(), 'Existing offline cache required')
  assert.equal(process.versions.node, '22.23.1', 'Run with reviewed Node 22.23.1')
  const env = childEnvironment(output, cache)
  mkdirSync(output, { mode: 0o700 })
  for (const directory of ['empty-home', 'tmp', 'logs', 'artifacts']) mkdirSync(join(output, directory), { mode: 0o700 })
  write(join(output, 'user.npmrc'), ''); write(join(output, 'global.npmrc'), '')
  const version = spawnSync(process.execPath, [npmCli, '--version'], { cwd: '/', env, encoding: 'utf8' })
  write(join(output, 'logs', 'npm-version.log'), version.stdout + version.stderr)
  assert.equal(version.status, 0, 'Cannot inspect npm version')
  assert.equal(version.stdout.trim(), '10.9.8', 'Use reviewed npm 10.9.8')
  const report = { complete: false, source: Object.fromEntries(Object.entries(inputs).map(([p, b]) => [p, sha(b)])),
    runnerSha256: sha(readRegular(fileURLToPath(import.meta.url))),
    fixtures: Object.fromEntries(Object.entries(ownInputs).map(([p, b]) => [p, sha(b)])),
    guideSha256: sha(guide), tools: { node: process.versions.node, npm: version.stdout.trim(), npmCliSha256: sha(npmBytes), nodeSha256: sha(readFileSync(process.execPath)) }, operations: [], packages: {} }
  const save = () => writeFileSync(join(output, 'RESULT.json'), encode(report), { mode: 0o600 })
  const run = (name, args, cwd = output) => {
    const start = performance.now()
    const child = spawnSync(process.execPath, args, { cwd, env, maxBuffer: 16 * 1024 * 1024, timeout: 120_000 })
    const log = Buffer.concat([child.stdout ?? Buffer.alloc(0), child.stderr ?? Buffer.alloc(0)])
    write(join(output, 'logs', name + '.log'), log)
    report.operations.push({ name, exit: child.status, error: child.error?.code ?? null, elapsedMs: Math.round(performance.now() - start), logSha256: sha(log) }); save()
    assert.equal(child.status, 0, name + ' failed; see retained log (offline cache miss is a prerequisite)')
    return child.stdout.toString()
  }
  const npm = (name, args, cwd) => run(name, [npmCli, ...args], cwd)
  try {
    for (const [path, bytes] of Object.entries(inputs)) write(join(output, path), bytes)
    for (const pkg of packages) {
      const root = join(output, pkg)
      npm(pkg + '-ci', ['ci', '--offline', '--ignore-scripts'], root)
      for (const action of ['typecheck', 'test', 'build']) npm(pkg + '-' + action, ['run', action], root)
      const [pack, ...extra] = JSON.parse(npm(pkg + '-pack', ['pack', '--ignore-scripts', '--json', '--pack-destination', join(output, 'artifacts')], root))
      assert.equal(extra.length, 0); assert.deepEqual(pack.bundled, [])
      const declared = json(join(root, 'package.json'))
      assert.equal(pack.name, declared.name); assert.equal(pack.version, '0.0.0')
      const runtime = pkg === 'web-client' ? walk(join(root, 'dist')).filter(p => !p.endsWith(sep)).map(p => relative(root, p)) : brokerUnits.map(name => 'dist/domain/' + name + '.js')
      const types = pkg === 'web-client' ? [...browserUnits.map(name => `types/bridge/${name}.d.ts`), 'types/protocol/bounded-control-json.d.ts'] : brokerUnits.map(name => 'dist/domain/' + name + '.d.ts')
      assert.equal(runtime.length, pkg === 'web-client' ? 5 : 6)
      assert.ok(runtime.every(path => path.endsWith('.js')))
      const expected = ['LICENSE', 'package.json', ...runtime, ...types].sort()
      assert.deepEqual(pack.files.map(row => row.path).sort(), expected, 'Unexpected packed payload')
      assert.ok(pack.files.every(row => row.mode === 0o644), 'Package must have readable regular modes')
      assert.deepEqual(readRegular(join(root, 'LICENSE')), inputs.LICENSE)
      for (const row of pack.files) row.sha256 = sha(readRegular(join(root, row.path)))
      for (const entry of Object.values(declared.exports)) for (const target of Object.values(entry)) assert.ok(expected.includes(target.replace(/^\.\//, '')), 'Missing export target')
      report.packages[pkg] = { ...pack, sha256: sha(readFileSync(join(output, 'artifacts', pack.filename))) }
      if (pkg === 'web-client') {
        const graph = json(join(root, '.qa-build-graph.json'))
        assert.ok(graph.modules.length > 0 && graph.modules.every(p => inputs['web-client/' + p] && !p.endsWith('.test.ts')), 'Unexpected browser source graph')
        report.browserSourceGraph = graph
      }
      save()
    }
    const consumer = join(output, 'consumer'), browser = JSON.parse(inputs['web-client/package.json'])
    const manifest = { name: 'hydra-remote-core-consumer-check', version: '0.0.0', private: true, type: 'module',
      scripts: { typecheck: 'tsc --noEmit', test: 'vitest run consumer.test.ts --maxWorkers 2 --minWorkers 1' },
      dependencies: {}, devDependencies: browser.devDependencies }
    const lock = JSON.parse(inputs['web-client/package-lock.json'])
    lock.name = manifest.name
    for (const pkg of packages) {
      const pack = report.packages[pkg], resolved = 'file:../artifacts/' + pack.filename
      manifest.dependencies[pack.name] = resolved
      lock.packages['node_modules/' + pack.name] = { version: pack.version, resolved, integrity: pack.integrity, license: 'MIT' }
    }
    lock.packages[''] = { name: manifest.name, version: manifest.version, dependencies: manifest.dependencies, devDependencies: manifest.devDependencies }
    write(join(consumer, 'package.json'), encode(manifest)); write(join(consumer, 'package-lock.json'), encode(lock))
    for (const [name, bytes] of Object.entries(ownInputs)) write(join(consumer, name), bytes)
    write(join(consumer, 'guide-snippets.ts'), snippets.join('\n'))
    write(join(consumer, 'tsconfig.json'), encode({ compilerOptions, include: ['*.ts'] }))
    const consumerLock = sha(readRegular(join(consumer, 'package-lock.json')))
    npm('consumer-ci', ['ci', '--offline', '--ignore-scripts'], consumer)
    assert.equal(sha(readRegular(join(consumer, 'package-lock.json'))), consumerLock)
    const declarations = [], javascript = []
    for (const pkg of packages) {
      const pack = report.packages[pkg], installed = join(consumer, 'node_modules', pack.name)
      safePath(installed)
      assert.deepEqual(walk(installed).filter(p => !p.endsWith(sep)).map(p => relative(installed, p)).sort(), pack.files.map(row => row.path).sort())
      for (const row of pack.files) {
        const path = join(installed, row.path)
        assert.equal(sha(readRegular(path)), row.sha256, 'Installed tarball bytes differ')
        if (path.endsWith('.d.ts')) declarations.push(path)
        if (path.endsWith('.js')) javascript.push(path)
      }
    }
    assert.equal(declarations.length, 17)
    write(join(consumer, 'declarations.json'), encode({ compilerOptions: { ...compilerOptions, types: [] }, files: declarations }))
    run('installed-declarations', [join(consumer, 'node_modules/typescript/bin/tsc'), '-p', 'declarations.json'], consumer)
    for (const action of ['typecheck', 'test']) npm('consumer-' + action, ['run', action], consumer)
    const runtimeCheck = `import assert from 'node:assert/strict'; import { readFileSync } from 'node:fs'; import { resolve, dirname } from 'node:path'; import ts from 'typescript';
const files = ${encode(javascript)}; const allowed = new Set(files); let builtins = 0;
for(const path of files) { const ast=ts.createSourceFile(path,readFileSync(path,'utf8'),ts.ScriptTarget.Latest,true,ts.ScriptKind.JS);
function visit(node) { if((ts.isImportDeclaration(node)||ts.isExportDeclaration(node))&&node.moduleSpecifier) { const target=node.moduleSpecifier.text;
if(target==='node:crypto' && /\\/signaling-broker-core\\/dist\\/domain\\/(offer-wake|signaling)\\.js$/.test(path)) builtins++; else { assert.ok(target.startsWith('.')); assert.ok(allowed.has(resolve(dirname(path),target))); } }
if(ts.isCallExpression(node)) assert.ok(node.expression.kind!==ts.SyntaxKind.ImportKeyword && !(ts.isIdentifier(node.expression)&&node.expression.text==='require')); ts.forEachChild(node,visit); } visit(ast); }
assert.equal(builtins,2); const browser=await import('@hydraterm/remote-browser-core'); const broker=await import('@hydraterm/signaling-broker-core'); assert.equal(typeof browser.WebrtcBridge,'function'); assert.equal(typeof broker.SignalingBroker,'function'); console.log('Own-only runtime plus broker node:crypto and native ESM exports pass');`
    write(join(consumer, 'runtime-check.mjs'), runtimeCheck)
    run('runtime-and-native-esm', ['runtime-check.mjs'], consumer)
    const bundleCheck = `import { build } from 'vite'; import { writeFileSync } from 'node:fs'; import { resolve, relative } from 'node:path';
await build({configFile:false,envDir:false,publicDir:false,build:{minify:false,lib:{entry:'browser-consumer.ts',formats:['es'],fileName:()=> 'browser-consumer.js'}},plugins:[{name:'prove-installed-core',generateBundle(_,bundle){
const modules=[...new Set(Object.values(bundle).flatMap(c=>c.type==='chunk'?Object.keys(c.modules):[]))].sort(); const local=modules.map(p=>relative(process.cwd(),p));
if(!local.includes('node_modules/@hydraterm/remote-browser-core/dist/bridge.js')||local.some(p=>p!=='browser-consumer.ts'&&!p.startsWith('node_modules/@hydraterm/remote-browser-core/dist/')))throw Error('Unexpected consumer module graph');
writeFileSync('consumer-graph.json',JSON.stringify(local,null,2)+'\\n');}}]});`
    write(join(consumer, 'bundle-check.mjs'), bundleCheck)
    run('consumer-browser-bundle', ['bundle-check.mjs'], consumer)
    report.consumerGraph = json(join(consumer, 'consumer-graph.json'))
    report.installedDeclarations = declarations.map(p => ({ path: relative(output, p), sha256: sha(readRegular(p)) }))
    report.consumerLockSha256 = consumerLock
    report.consumerToolLocationCount = Object.keys(lock.packages).length - 3
    assert.equal(report.consumerToolLocationCount, 108)
    for (const [path, bytes] of Object.entries(inputs)) {
      assert.deepEqual(readRegular(join(source, path)), bytes, 'Source changed during qualification')
      assert.deepEqual(readRegular(join(output, path)), bytes, 'Staged input changed during qualification')
    }
    report.complete = true; save()
    return report
  } catch (error) { report.failure = error.message; save(); throw error }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  const values = {}
  for (let i = 2; i < process.argv.length; i += 2) {
    const key = { '--source': 'source', '--output': 'output', '--npm-cli': 'npmCli', '--cache': 'cache' }[process.argv[i]]
    assert.ok(key && !values[key] && process.argv[i + 1], 'Usage: --source ABS --output NEW_ABS --npm-cli ABS --cache ABS')
    values[key] = process.argv[i + 1]
  }
  assert.equal(Object.keys(values).length, 4, 'All four explicit options are required')
  await qualify(values)
  console.log('Remote core package/consumer qualification: PASS; synthetic peers, not a deployed Remote service')
}
