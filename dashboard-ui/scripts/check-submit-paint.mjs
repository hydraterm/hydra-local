// Optional offline browser qualification. Uses an already installed Playwright module/browser;
// it does not download tools or qualify an installed macOS/WebKit app.
// HYDRA_BROWSER_MODULE=/absolute/path/to/playwright/index.mjs node scripts/check-submit-paint.mjs OUT
import assert from 'node:assert/strict'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { build } from 'esbuild'
import postcss from 'postcss'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const out = resolve(process.argv[2] ?? 'submit-paint-evidence')
await mkdir(out, { recursive: false })
const { chromium, webkit } = await import(process.env.HYDRA_BROWSER_MODULE ?? 'playwright')
const engine = process.env.HYDRA_BROWSER_ENGINE === 'webkit' ? webkit : chromium
const sourceCss = await readFile(resolve(root, 'src/styles.css'), 'utf8')
// Emulate a parser without color-mix, not an old OS: discard unsupported declarations, retaining
// earlier valid declarations and normal cascade. No button-specific CSS is injected into the test.
const legacy = postcss.parse(sourceCss)
legacy.walkDecls(decl => { if (/color-mix\(/i.test(decl.value)) decl.remove() })
legacy.walkAtRules('supports', rule => { if (/color-mix\(/i.test(rule.params)) rule.remove() })
const entry = `import React from 'react'; import {createRoot} from 'react-dom/client';
import {App} from './src/App'; import {mockDashboardModel} from './src/data/mock';
const model=structuredClone(mockDashboardModel); window.intents=[];
window.hydraDashboard={getDashboardModel:()=>model,onDashboardModel:()=>()=>{},postIntent:intent=>{
  window.intents.push(intent);
  if(intent.type==='pickProjectFolder') queueMicrotask(()=>window.__HYDRA_DASHBOARD_RESOLVE_PROJECT_FOLDER__?.(intent.request_id,null));
  if(intent.type==='listFolderSessions') queueMicrotask(()=>window.__HYDRA_DASHBOARD_RESOLVE_FOLDER_SESSIONS__?.(intent.request_id,[]));
}};
createRoot(document.getElementById('root')).render(<App/>);`
const built = await build({ stdin: { contents: entry, loader: 'tsx', resolveDir: root },
  bundle: true, write: false, format: 'iife', jsx: 'automatic', loader: { '.svg': 'dataurl', '.png': 'dataurl' },
  define: { 'process.env.NODE_ENV': '"production"', 'import.meta.env.DEV': 'false' } })
const js = built.outputFiles[0].text
const result = { scope: 'Actual React/browser painted pixels; unsupported color-mix parser emulation, not old-system WebKit qualification',
  browser: engine.name(), css_sha256: createHash('sha256').update(sourceCss).digest('hex'), cases: [], errors: [] }
const browser = await engine.launch({ headless: true,
  ...(process.env.HYDRA_BROWSER_EXECUTABLE ? { executablePath: process.env.HYDRA_BROWSER_EXECUTABLE } : {}) })
try {
  for (const unsupported of [true, false]) {
    const context = await browser.newContext({ viewport: { width: 1280, height: 1100 }, deviceScaleFactor: 1 })
    const html = `<!doctype html><style>${unsupported ? legacy.toString() : sourceCss}</style><div id="root"></div><script>${js.replaceAll('</script', '<\\/script')}</script>`
    await context.route('**/*', route => route.request().url().startsWith('http://hydra-paint.invalid/')
      ? route.fulfill({ contentType: 'text/html', body: html }) : route.abort())
    const page = await context.newPage()
    page.on('pageerror', error => result.errors.push(error.message))
    for (const kind of ['newProject', 'newWindow', 'split']) {
      await page.goto('http://hydra-paint.invalid/?chrome=overlay')
      await page.waitForFunction(() => typeof window.__HYDRA_SHOW_OVERLAY_MODAL__ === 'function')
      await page.evaluate(kind => window.__HYDRA_SHOW_OVERLAY_MODAL__({ kind,
        project_id: 'sample_workspace', window_id: 'w-main', tab_id: 'tab-claude', dir: 'h' }), kind)
      const button = page.locator('.split-dialog__submit')
      await button.waitFor({ state: 'visible' })
      const inspect = async state => {
        await button.scrollIntoViewIfNeeded()
        const box = await button.boundingBox()
        const style = await button.evaluate(el => {
          const s = getComputedStyle(el)
          return { background: s.backgroundColor, color: s.color, opacity: s.opacity,
            outline: s.outlineStyle, disabled: el.disabled, label: el.textContent }
        })
        const png = await button.screenshot({ path: resolve(out, `${unsupported ? 'fallback' : 'modern'}-${kind}-${state}.png`) })
        // Read the screenshot itself through canvas, not a DOM/computed-style substitute. Count
        // opaque colored fill and contrasting dark glyph pixels in the inner painted button.
        const paint = await page.evaluate(async data => {
          const image = new Image(); image.src = `data:image/png;base64,${data}`; await image.decode()
          const canvas = document.createElement('canvas'); canvas.width = image.width; canvas.height = image.height
          const ctx = canvas.getContext('2d'); ctx.drawImage(image, 0, 0)
          const { data: rgba } = ctx.getImageData(0, 0, image.width, image.height)
          let fill = 0, ink = 0
          for (let y = 5; y < image.height - 5; y++) for (let x = 6; x < image.width - 6; x++) {
            const i = (y * image.width + x) * 4, r = rgba[i], g = rgba[i + 1], b = rgba[i + 2]
            if (r > 70 && g > 45 && r > b * 1.5) fill++
            if (r < 65 && g < 65 && b < 65) ink++
          }
          return { fill, ink, area: (image.width - 12) * (image.height - 10) }
        }, png.toString('base64'))
        const passed = box.width > 45 && box.height >= 30 && paint.fill > paint.area * .55 && paint.ink > 15
        result.cases.push({ unsupported, kind, state, style, paint, passed })
      }
      if (kind === 'newProject') {
        await inspect('disabled')
        await page.getByPlaceholder('Capacity Paper', { exact: true }).fill('Paint fixture')
        await page.getByPlaceholder('~/path/to/project', { exact: true }).fill('/tmp/hydra-paint-fixture')
      }
      const agentLabel = kind === 'newProject' ? 'Default agent' : kind === 'newWindow' ? 'Window agent' : 'Split agent'
      const modelLabel = kind === 'newProject' ? 'Default model' : kind === 'newWindow' ? 'Window model' : 'Split model'
      await page.getByLabel(agentLabel, { exact: true }).selectOption('codex')
      const models = page.getByLabel(modelLabel, { exact: true })
      await models.selectOption({ index: await models.locator('option').count() > 1 ? 1 : 0 })
      await inspect('enabled-after-model-selection')
      await button.hover(); await inspect('hover')
      // Sample keyboard-modality paint explicitly. System WebKit may skip buttons during Tab
      // navigation according to the user's full-keyboard-access preference; do not override it.
      await page.keyboard.press('Tab'); await button.focus()
      assert(await button.evaluate(el => el.matches(':focus-visible')), 'keyboard-modality focus is visible')
      await inspect('keyboard-focus')
      await button.click()
      await page.waitForFunction(() => window.intents.some(i => i.type === 'preflightLaunch'))
      await inspect('checking')
      assert(await button.isDisabled(), 'checking action remains disabled')
      await page.evaluate(() => {
        const request = window.intents.find(i => i.type === 'preflightLaunch')
        window.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_PREFLIGHT__(request.request_id, true, null)
      })
      const expected = kind === 'newProject' ? 'createProject' : kind === 'newWindow' ? 'createWindow' : 'splitPane'
      await page.waitForFunction(expected => window.intents.some(i => i.type === expected), expected)
      assert.equal(await page.evaluate(expected => window.intents.filter(i => i.type === expected).length, expected), 1)
    }
    await context.close()
  }
} finally {
  await browser.close()
  await writeFile(resolve(out, 'RESULT.json'), JSON.stringify(result, null, 2))
}
console.log(JSON.stringify({ cases: result.cases.length, failures: result.cases.filter(c => !c.passed).map(c => `${c.unsupported ? 'fallback' : 'modern'}:${c.kind}:${c.state}`), errors: result.errors }))
assert.equal(result.errors.length, 0, 'no browser errors')
assert(result.cases.every(c => c.passed), 'all creation actions visibly paint their background and label')
