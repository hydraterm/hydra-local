// Offline browser regression against the production bundle, not native host qualification.
// npm run build
// HYDRA_BROWSER_MODULE=/absolute/path/to/playwright/index.mjs node scripts/check-topbar-geometry.mjs OUT
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const out = resolve(process.argv[2] ?? 'topbar-geometry-evidence')
await mkdir(out, { recursive: false })
const html = await readFile(resolve(root, 'dist/index.html'), 'utf8')
const { chromium, webkit } = await import(process.env.HYDRA_BROWSER_MODULE ?? 'playwright')
const engine = process.env.HYDRA_BROWSER_ENGINE === 'webkit' ? webkit : chromium
// Only the synthetic model is compiled here. The application and CSS are the exact built asset.
const fixture = await build({ stdin: { contents: "export {mockDashboardModel as default} from './src/data/mock'", resolveDir: root }, bundle: true, write: false, format: 'esm' })
const { default: baseModel } = await import(`data:text/javascript;base64,${Buffer.from(fixture.outputFiles[0].text).toString('base64')}`)
const result = { scope: 'Production dashboard bundle with synthetic host; browser geometry/pointer evidence, not native Linux/macOS qualification', browser: engine.name(), bundle_sha256: createHash('sha256').update(html).digest('hex'), cases: [], errors: [] }
const browser = await engine.launch({ headless: true,
  ...(process.env.HYDRA_BROWSER_EXECUTABLE ? { executablePath: process.env.HYDRA_BROWSER_EXECUTABLE } : {}) })
result.browser_version = browser.version()
let currentPage
const settle = page => page.waitForTimeout(180) // Exceeds the old 140 ms geometry transition.
const geometry = page => page.locator('.window-tab-group').evaluateAll(groups => groups.map(group => {
  const rect = element => {
    const { x, y, width, height } = element.getBoundingClientRect()
    return { x, y, width, height }
  }
  return { id: group.querySelector('.window-tab').dataset.toolbarControl, group: rect(group), close: rect(group.querySelector('.window-tab__close')), scrollTop: group.scrollTop }
}))
function unchanged(before, after, label) {
  assert.equal(after.length, before.length, label)
  before.forEach((row, i) => {
    assert.equal(after[i].id, row.id, `${label}: order`)
    for (const part of ['group', 'close']) for (const axis of ['x', 'y', 'width', 'height']) {
      assert(Math.abs(after[i][part][axis] - row[part][axis]) < 0.1, `${label}: ${row.id} ${part}.${axis} moved from ${row[part][axis]} to ${after[i][part][axis]}`)
    }
  })
}
try {
  for (const [width, count] of [[1440, 3], [1024, 8], [720, 12]]) {
    const model = structuredClone(baseModel)
    model.projects = model.projects.slice(0, 2)
    const template = model.details.sample_workspace.windows[0]
    const windows = Array.from({ length: count }, (_, i) => ({ ...structuredClone(template),
      window_id: `window-${i}`, name: `Window ${i + 1} — long descriptive task name`, stashed: false,
      tabs: template.tabs.map((tab, j) => ({ ...tab, window_id: `window-${i}`, tab_id: `pane-${i}-${j}`, stashed: false })),
    }))
    model.details.sample_workspace.windows = windows.slice(0, count - 1)
    model.details.sample.windows = windows.slice(count - 1)
    model.global_window_order = windows.map(window => window.window_id)
    model.active_window_id = windows[0].window_id
    model.active_tab_id = windows[0].tabs[0].tab_id
    const context = await browser.newContext({ viewport: { width, height: 180 }, deviceScaleFactor: 1 })
    await context.route('**/*', route => route.request().url().startsWith('http://hydra-tabs.invalid/')
      ? route.fulfill({ contentType: 'text/html', body: html }) : route.abort())
    await context.addInitScript(model => {
      window.intents = []
      const listeners = new Set()
      window.hydraDashboard = {
        getDashboardModel: () => structuredClone(model),
        onDashboardModel: listener => { listeners.add(listener); return () => listeners.delete(listener) },
        postIntent: intent => {
          window.intents.push(intent)
          if (intent.type === 'focusWindow') {
            model.active_window_id = intent.window_id
            model.active_project = model.projects.find(project => project.project_id === intent.project_id)
            model.active_tab_id = model.details[intent.project_id].windows.find(window => window.window_id === intent.window_id).tabs[0].tab_id
          }
          if (intent.type === 'reorderWindowPresentation') queueMicrotask(() => {
            model.global_window_order = intent.ordered_window_ids
            listeners.forEach(listener => listener(structuredClone(model)))
            window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_ORDER__(intent.request_id, { status: 'saved' })
          })
        },
      }
    }, model)
    const page = await context.newPage()
    currentPage = page
    page.on('pageerror', error => result.errors.push(error.message))
    await page.goto('http://hydra-tabs.invalid/?chrome=topbar')
    await page.locator('.window-tab-group').last().waitFor()
    await page.mouse.move(0, 100)
    await settle(page)
    await page.screenshot({ path: resolve(out, `${width}-before.png`) })
    const row = { width, count, checked: 0, keyboard_focus_visible: true, passed: false }
    result.cases.push(row)
    for (let i = 0; i < count; i++) {
      const group = page.locator('.window-tab-group').nth(i)
      const focus = group.locator('.window-tab')
      const close = group.locator('.window-tab__close')
      await group.scrollIntoViewIfNeeded()
      await page.mouse.move(0, 100)
      await settle(page)
      const before = await geometry(page)
      const owner = model.projects[i === count - 1 ? 1 : 0].name
      assert.equal(await focus.getAttribute('aria-label'), `Focus ${windows[i].name} in ${owner}`)
      assert.equal(await close.getAttribute('aria-label'), `Close ${windows[i].name} in ${owner}`)
      assert((await focus.getAttribute('title')).includes(`${owner} · ${windows[i].name}`))
      assert.equal(before[i].close.width, 24, 'close target stays 24 px wide')
      const box = before[i].close
      // Use the original coordinates, not locator.click(), which can silently chase a moving tab.
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2)
      await settle(page)
      await page.screenshot({ path: resolve(out, `${width}-hover-${i}.png`) })
      unchanged(before, await geometry(page), 'close hover')
      assert(await close.evaluate(el => {
        const rect = el.getBoundingClientRect()
        return document.elementFromPoint(rect.x + rect.width / 2, rect.y + rect.height / 2) === el
      }), 'close is hit-testable')
      const focusBox = await focus.boundingBox()
      await page.mouse.move(focusBox.x + focusBox.width / 2, focusBox.y + focusBox.height / 2)
      await settle(page)
      unchanged(before, await geometry(page), 'tab hover')
      await page.mouse.click(focusBox.x + focusBox.width / 2, focusBox.y + focusBox.height / 2)
      await settle(page)
      assert.equal(await focus.getAttribute('aria-pressed'), 'true')
      unchanged(before, await geometry(page), 'tab activation')
      // System WebKit may not focus a button on pointer click (full-keyboard-access preference).
      await page.keyboard.press('Tab')
      await focus.focus()
      await page.keyboard.press('ArrowRight')
      await settle(page)
      const focused = await close.evaluate(el => ({ expected: el === document.activeElement, visible: el.matches(':focus-visible'), actual: document.activeElement?.getAttribute('aria-label') }))
      assert(focused.expected, `keyboard focus reaches close: ${JSON.stringify(focused)}`)
      // Record native keyboard-modality heuristics separately from focus/geometry assertions.
      row.keyboard_focus_visible &&= focused.visible
      unchanged(before, await geometry(page), 'keyboard focus')
      await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2)
      const closes = await page.evaluate(() => window.intents.filter(intent => intent.type === 'stashWindow'))
      assert.equal(closes.length, i + 1, 'one close intent per stationary-coordinate click')
      assert.equal(closes.at(-1).window_id, windows[i].window_id)
      row.checked++
    }
    assert.equal(await page.evaluate(() => window.intents.filter(intent => intent.type === 'reorderWindowPresentation').length), 0, 'click/focus never reorders')
    const strip = page.locator('.window-tabs__left')
    await strip.evaluate(el => { el.scrollLeft = 0 })
    await page.mouse.move(0, 100)
    const source = page.locator('.window-tab-group .window-tab').nth(0)
    const target = page.locator('.window-tab-group').nth(1)
    const sourceBox = await source.boundingBox()
    const targetBox = await target.boundingBox()
    await page.mouse.move(sourceBox.x + sourceBox.width / 2, sourceBox.y + sourceBox.height / 2)
    await page.mouse.down()
    await page.mouse.move(targetBox.x + targetBox.width - 5, targetBox.y + targetBox.height / 2, { steps: 12 })
    await page.mouse.move(targetBox.x + targetBox.width - 4, targetBox.y + targetBox.height / 2)
    await page.mouse.up()
    await page.waitForFunction(() => window.intents.some(intent => intent.type === 'reorderWindowPresentation'))
    const reorder = await page.evaluate(() => window.intents.filter(intent => intent.type === 'reorderWindowPresentation'))
    assert.equal(reorder.length, 1, 'one pointer drag saves one new order')
    assert.deepEqual(reorder[0].ordered_window_ids, ['window-1', 'window-0', ...windows.slice(2).map(window => window.window_id)])
    await settle(page)
    assert((await geometry(page))[0].id.includes(':window-1:'), 'authoritative order is rendered')
    await page.screenshot({ path: resolve(out, `${width}-dragged.png`) })
    await writeFile(resolve(out, `${width}-accessibility.txt`), await page.getByRole('toolbar').ariaSnapshot())
    row.passed = true
    await context.close()
  }
} catch (error) {
  result.errors.push(error.message)
  if (currentPage && !currentPage.isClosed()) {
    result.failure_geometry = await geometry(currentPage)
    await currentPage.screenshot({ path: resolve(out, 'failure.png') })
  }
  throw error
} finally {
  await browser.close()
  await writeFile(resolve(out, 'RESULT.json'), JSON.stringify(result, null, 2))
}
assert.equal(result.errors.length, 0, 'no browser errors')
console.log(JSON.stringify(result))
