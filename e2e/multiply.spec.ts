import { expect, test, type Page } from '@playwright/test'
import { bootReady, mockOracle } from './support'

/**
 * Functional gate for the local multiply bench. The bench itself needs no Oracle
 * and no network — it runs entirely in the tab — but the page's boot overlay
 * covers everything until boot finishes, so these tests boot the page with a
 * stubbed Oracle first. (The oracle spec covers the other route to the bench:
 * declining the Oracle entirely and continuing in degraded mode.)
 *
 * The claims under test are the computed ones: a real homomorphic multiply
 * decrypts to the real product, and the noise ceiling really does arrive and
 * really does break correctness.
 */

const rows = (page: Page) => page.locator('[data-toy-rows] tr')

// Boot runs real TFHE-rs key generation in the browser.
test.setTimeout(120_000)

test.beforeEach(async ({ page }) => {
  await mockOracle(page)
  await bootReady(page)
  await page.locator('#toy-multiply').scrollIntoViewIfNeeded()
})

test('one homomorphic multiply decrypts to the actual product', async ({ page }) => {
  await page.fill('[data-toy-a]', '12')
  await page.fill('[data-toy-b]', '21')
  await page.click('[data-toy-mul]')

  // Row 0 is the encryption, row 1 the multiply.
  await expect(rows(page)).toHaveCount(2)
  const step = rows(page).nth(1)
  await expect(step).toContainText('a × b')
  // 12 * 21 = 252, inside a byte.
  await expect(step.locator('td').nth(3)).toHaveText('252')
  await expect(step.locator('td').nth(4)).toHaveText('252')
  await expect(step).toContainText('correct — inside budget')
  await expect(page.locator('[data-toy-verdict]')).toContainText(
    '1 multiplication(s) and 0 addition(s)'
  )
})

test('the product wraps mod 256 exactly as the byte type requires', async ({ page }) => {
  await page.fill('[data-toy-a]', '30')
  await page.fill('[data-toy-b]', '20')
  await page.click('[data-toy-mul]')
  // 30 * 20 = 600 = 88 mod 256.
  await expect(rows(page).nth(1).locator('td').nth(3)).toHaveText('88')
  await expect(rows(page).nth(1).locator('td').nth(4)).toHaveText('88')
})

test('the third multiply spends the budget and the page reports the break', async ({ page }) => {
  await page.fill('[data-toy-a]', '11')
  await page.fill('[data-toy-b]', '13')
  await page.click('[data-toy-mul]')
  await page.click('[data-toy-mul]')
  await expect(rows(page).nth(2)).toContainText('inside budget')

  await page.click('[data-toy-mul]')
  const broken = rows(page).nth(3)
  await expect(broken).toContainText('OVER')
  await expect(page.locator('[data-toy-status]')).toContainText('over the ceiling')

  const verdict = page.locator('[data-toy-verdict]')
  await expect(verdict).toHaveClass(/toy-verdict-bad/)
  await expect(verdict).toContainText('The budget ran out at step 3')
  await expect(verdict).toContainText('this scheme has no bootstrapping')
})

test('addition is cheap: many adds stay inside the same budget', async ({ page }) => {
  await page.fill('[data-toy-a]', '10')
  await page.fill('[data-toy-b]', '5')
  for (let i = 0; i < 6; i += 1) await page.click('[data-toy-add]')

  await expect(rows(page)).toHaveCount(7)
  const last = rows(page).nth(6)
  // 10 + 5*6 = 40, and no add should come close to the ceiling.
  await expect(last.locator('td').nth(3)).toHaveText('40')
  await expect(last.locator('td').nth(4)).toHaveText('40')
  await expect(last).not.toContainText('OVER')
  await expect(page.locator('[data-toy-verdict]')).toContainText(
    '0 multiplication(s) and 6 addition(s)'
  )
})

test('changing an operand restarts the chain rather than continuing a stale one', async ({
  page
}) => {
  await page.fill('[data-toy-a]', '3')
  await page.fill('[data-toy-b]', '4')
  await page.click('[data-toy-mul]')
  await expect(rows(page)).toHaveCount(2)

  await page.fill('[data-toy-b]', '5')
  await expect(rows(page)).toHaveCount(0)

  await page.click('[data-toy-mul]')
  await expect(rows(page).nth(1).locator('td').nth(3)).toHaveText('15')
})

test('the local bench rejects invalid operands without substituting default numbers', async ({
  page
}) => {
  const a = page.locator('[data-toy-a]')
  const b = page.locator('[data-toy-b]')
  const multiply = page.locator('[data-toy-mul]')

  for (const input of [a, b]) {
    for (const invalid of ['', '-1', '256', '2.5']) {
      await input.fill(invalid)
      await expect(input).toHaveAttribute('aria-invalid', 'true')
      await expect(page.locator('[data-toy-status]')).toContainText('0 to 255')
      await expect(multiply).toBeDisabled()
      await expect(page.locator('[data-toy-add]')).toBeDisabled()
      await expect(rows(page)).toHaveCount(0)
    }
    await input.fill('0')
    await expect(input).toHaveAttribute('aria-invalid', 'false')
  }

  await a.fill('255')
  await multiply.click()
  await expect(rows(page).nth(1).locator('td').nth(4)).toHaveText('0')
  await b.fill('1')
  await expect(rows(page)).toHaveCount(0)
  await multiply.click()
  await expect(rows(page).nth(1).locator('td').nth(4)).toHaveText('255')
})
