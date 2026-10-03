// @vitest-environment jsdom
import { afterEach, beforeAll, expect, it, vi } from 'vitest'
import postcss from 'postcss'

let dashboardStyles = ''
beforeAll(async () => {
  const fs = await vi.importActual<{ readFileSync(path: string, encoding: 'utf8'): string }>('node:fs')
  dashboardStyles = fs.readFileSync('src/styles.css', 'utf8')
})

afterEach(() => { document.head.replaceChildren(); document.body.replaceChildren() })

it.each(['Create', 'Split', 'Checking...'])('keeps %s readable without color-mix support', label => {
  // Model rejection of unsupported declarations, preserving the real fallback cascade. Browser
  // screenshot coverage lives in scripts/check-submit-paint.mjs; jsdom is not native paint proof.
  const parsed = postcss.parse(dashboardStyles)
  parsed.walkDecls(decl => { if (/color-mix\(/i.test(decl.value)) decl.remove() })
  parsed.walkAtRules('supports', rule => { if (/color-mix\(/i.test(rule.params)) rule.remove() })
  const style = document.createElement('style')
  style.textContent = parsed.toString()
  document.head.append(style)
  const button = document.createElement('button')
  button.className = 'split-dialog__submit'
  button.textContent = label
  button.disabled = label === 'Checking...'
  document.body.append(button)
  const computed = getComputedStyle(button)
  expect(computed.backgroundColor).toBe('rgb(251, 191, 36)')
  expect(computed.color).toBe('rgb(18, 18, 24)')
  expect(computed.borderTopColor).toBe('rgb(251, 191, 36)')
  expect(computed.display).not.toBe('none')
  expect(computed.visibility).toBe('visible')
  expect(computed.opacity).toBe(button.disabled ? '0.42' : '')
  expect(button.textContent).toBe(label)
})
