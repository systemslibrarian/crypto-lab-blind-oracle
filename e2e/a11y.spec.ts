import AxeBuilder from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'
import { expectNoHorizontalOverflow } from './reflow'
import { bootReady, mockOracle } from './support'

/**
 * WCAG regression gate. Deploys are already gated on the demo's unit tests;
 * this gates them on accessibility the same way. Scans the full page with
 * every <details> expanded, in both themes.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']

async function expandAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    for (const details of document.querySelectorAll('details')) {
      details.open = true
    }
    // The boot overlay covers the page until the WASM FHE runtime finishes
    // loading and the Oracle answers a health check. The preview server now
    // sends COOP/COEP (see vite.config.ts) so the runtime does start here, but
    // the Oracle is a real remote service and this scan should not depend on
    // it. Hide the overlay so axe scans the underlying content either way.
    document
      .querySelectorAll<HTMLElement>('[data-boot-overlay]')
      .forEach((el) => el.classList.add('boot-overlay--hidden'))
  })
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze()
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5)
  }))
  expect(summary).toEqual([])
}

async function assertGradientContrast(
  page: Page,
  selector: string,
  bgColors: string[]
): Promise<void> {
  const ratio = await page.evaluate(
    ({ sel, bgColors }) => {
      function getLuminance(r: number, g: number, b: number) {
        const [rs, gs, bs] = [r, g, b].map((c) => {
          c /= 255
          return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4)
        })
        return 0.2126 * rs + 0.7152 * gs + 0.0722 * bs
      }
      function parseRGB(c: string) {
        const match = c.match(/rgba?\((\d+),\s*(\d+),\s*(\d+)/)
        if (match) return [parseInt(match[1]), parseInt(match[2]), parseInt(match[3])]

        const ctx = document.createElement('canvas').getContext('2d')!
        ctx.fillStyle = c
        const computed = ctx.fillStyle
        if (computed.startsWith('#')) {
          const r = parseInt(computed.slice(1, 3), 16)
          const g = parseInt(computed.slice(3, 5), 16)
          const b = parseInt(computed.slice(5, 7), 16)
          return [r, g, b]
        }
        return [0, 0, 0]
      }
      function blend(fg: number[], bg: number[], alpha: number) {
        return [
          Math.round(fg[0] * alpha + bg[0] * (1 - alpha)),
          Math.round(fg[1] * alpha + bg[1] * (1 - alpha)),
          Math.round(fg[2] * alpha + bg[2] * (1 - alpha))
        ]
      }
      function parseColorWithAlpha(c: string, bgHex: string) {
        const match = c.match(/rgba\((\d+),\s*(\d+),\s*(\d+),\s*([\d.]+)\)/)
        if (match) {
          const fg = [parseInt(match[1]), parseInt(match[2]), parseInt(match[3])]
          const alpha = parseFloat(match[4])
          const bg = parseRGB(bgHex)
          return blend(fg, bg, alpha)
        }
        return parseRGB(c)
      }
      function getContrastRatio(c1: string, c2: string, bgHex: string) {
        const [r1, g1, b1] = parseColorWithAlpha(c1, bgHex)
        const [r2, g2, b2] = parseColorWithAlpha(c2, bgHex)
        const l1 = getLuminance(r1, g1, b1)
        const l2 = getLuminance(r2, g2, b2)
        const lighter = Math.max(l1, l2)
        const darker = Math.min(l1, l2)
        return (lighter + 0.05) / (darker + 0.05)
      }

      const el = document.querySelector(sel)
      if (!el) return 99
      const style = window.getComputedStyle(el)
      const color = style.color

      let minRatio = 99
      // bgColors[0] is the page background to blend against
      for (let i = 1; i < bgColors.length; i++) {
        const r = getContrastRatio(color, bgColors[i], bgColors[0])
        if (r < minRatio) minRatio = r
      }
      return minRatio
    },
    { sel: selector, bgColors }
  )

  expect(ratio).toBeGreaterThanOrEqual(4.5)
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await page.goto('.')
  await expect(page.locator('.cl-hero')).toBeVisible()
  await page.waitForLoadState('networkidle')
  await expandAll(page)
  await scan(page)
  // Check explain-steps on explain-card gradient over dark bg (#07070f)
  await assertGradientContrast(page, '.explain-steps', [
    '#07070f',
    'rgba(0, 255, 179, 0.059)',
    'rgba(0, 255, 179, 0.02)'
  ])
})

/**
 * WCAG 1.4.10 reflow at phone width.
 *
 * At 380px the single phone column was 770px wide with every scan green: the
 * column track's minimum is its items' min-content, and the multiply bench's
 * 736px table sat in a scroller whose min-content is its content's. body's
 * overflow-x:hidden then clipped every zone at the viewport edge instead of
 * letting it scroll, so the right half of each panel was simply unreachable.
 */
test.describe('reflow at 380px', () => {
  test.use({ viewport: { width: 380, height: 800 } })
  test.setTimeout(120_000)

  test('no horizontal page scroll on first paint, details open', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' })
    await page.goto('.')
    await expect(page.locator('.cl-hero')).toBeVisible()
    await expandAll(page)
    await expectNoHorizontalOverflow(page, '380px / initial')
  })

  test('no horizontal page scroll through a round trip and the multiply bench', async ({
    page
  }) => {
    await mockOracle(page)
    await bootReady(page)
    await expectNoHorizontalOverflow(page, '380px / ready')

    await page.fill('[data-input-a]', '42')
    await page.fill('[data-input-b]', '7')
    await page.click('[data-encrypt]')
    await expect(page.locator('[data-compute]')).toBeEnabled()
    await page.click('[data-compute]')
    await expect(page.locator('[data-state]')).toHaveText('REVEALED', { timeout: 60_000 })
    await expect(page.locator('[data-corr-mismatch]')).toBeVisible()
    await expectNoHorizontalOverflow(page, '380px / revealed, mismatch')

    await page.fill('[data-toy-a]', '11')
    await page.fill('[data-toy-b]', '13')
    for (let i = 0; i < 3; i++) await page.click('[data-toy-mul]')
    await expect(page.locator('[data-toy-verdict]')).toHaveClass(/toy-verdict-bad/)
    await expandAll(page)
    await expectNoHorizontalOverflow(page, '380px / bench over budget, details open')
  })

  test('no horizontal page scroll on the offline path', async ({ page }) => {
    await page.context().route('**/health', (route) => route.abort())
    await page.context().route('**/compute/add', (route) => route.abort())
    await page.goto('.')
    const offlineBtn = page.locator('[data-boot-offline]')
    await expect(offlineBtn).toBeVisible({ timeout: 90_000 })
    await expectNoHorizontalOverflow(page, '380px / boot offline prompt')
    await offlineBtn.click()
    await expect(page.locator('[data-offline-banner]')).toBeVisible()
    await expectNoHorizontalOverflow(page, '380px / offline banner')
  })
})
