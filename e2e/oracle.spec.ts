import { expect, test, type Page } from '@playwright/test'
import { bootReady, mockOracle } from './support'

/**
 * Functional gate for the Oracle round-trip and for what the page does when the
 * Oracle is not there.
 *
 * The Oracle is a remote service, so these tests stand in for it with
 * page.context().route. The mock never invents a ciphertext: it echoes ct_a straight back
 * as the result. That is a genuinely valid FheUint8 under the browser's own
 * client key, which makes the assertions real ones —
 *
 *   - with b = 0 the correct answer IS a, so echoing ct_a is a correct response
 *     and the page must decrypt it to a and declare the tracks matched;
 *   - with b != 0 it is a wrong response, and the page must decrypt it to a,
 *     notice it disagrees with a + b, and say so.
 *
 * The second case is the one that matters: it proves the match verdict is
 * earned from the decrypted number rather than printed alongside it.
 */

// Key generation runs real TFHE-rs WASM in the browser (a few seconds).
test.setTimeout(120_000)

async function encryptAndCompute(page: Page, a: number, b: number): Promise<void> {
  await page.fill('[data-input-a]', String(a))
  await page.fill('[data-input-b]', String(b))
  await page.click('[data-encrypt]')
  await expect(page.locator('[data-compute]')).toBeEnabled()
  await page.click('[data-compute]')
  await expect(page.locator('[data-state]')).toHaveText('REVEALED', { timeout: 60_000 })
}

test('the browser decrypts the Oracle result to the right sum and earns the match', async ({
  page
}) => {
  const computeCalls = await mockOracle(page)
  await bootReady(page)
  // b = 0, so echoing ct_a back is the correct sum: the decrypted value must be
  // 42 and both tracks must agree.
  await encryptAndCompute(page, 42, 0)

  await expect(page.locator('[data-corr-decrypted]')).toHaveText('42')
  await expect(page.locator('[data-corr-plain-sum]')).toHaveText('42')
  await expect(page.locator('[data-result-value]')).toHaveText('42')
  await expect(page.locator('[data-corr-verdict]')).toBeVisible()
  await expect(page.locator('[data-corr-mismatch]')).toBeHidden()
  await expect(page.locator('[data-result-announce]')).toContainText('matching the plaintext track')
  expect(computeCalls()).toBe(1)
})

test('a wrong ciphertext from the Oracle is reported as a mismatch, not a match', async ({
  page
}) => {
  const computeCalls = await mockOracle(page)
  await bootReady(page)
  // b = 7, so ct_a is NOT a valid answer. The page decrypts it to 42 and must
  // notice that 42 is not 49.
  await encryptAndCompute(page, 42, 7)

  await expect(page.locator('[data-corr-decrypted]')).toHaveText('42')
  await expect(page.locator('[data-corr-plain-sum]')).toHaveText('49')
  await expect(page.locator('[data-corr-mismatch]')).toBeVisible()
  await expect(page.locator('[data-corr-verdict]')).toBeHidden()
  await expect(page.locator('[data-result-announce]')).toContainText('does NOT match')
  expect(computeCalls()).toBe(1)
})

test('an unreachable Oracle degrades instead of dead-ending', async ({ page }) => {
  await page.context().route('**/health', (route) => route.abort())
  await page.context().route('**/compute/add', (route) => route.abort())
  await page.goto('.')

  const offlineBtn = page.locator('[data-boot-offline]')
  await expect(offlineBtn).toBeVisible({ timeout: 90_000 })
  await offlineBtn.click()

  const banner = page.locator('[data-offline-banner]')
  await expect(banner).toBeVisible()
  await expect(banner).toContainText('Oracle unreachable')

  // Everything local still works: encryption runs, ciphertext appears...
  await expect(page.locator('[data-encrypt]')).toBeEnabled()
  await page.fill('[data-input-a]', '9')
  await page.fill('[data-input-b]', '4')
  await page.click('[data-encrypt]')
  await expect(page.locator('[data-ct-a-preview]')).not.toHaveText('awaiting ciphertext A...')
  await expect(page.locator('[data-corr-plain-sum]')).toHaveText('13')

  // ...and only the remote step stays unavailable.
  await expect(page.locator('[data-compute]')).toBeDisabled()

  // The local bench is unaffected by the Oracle being gone.
  await page.click('[data-toy-mul]')
  await expect(page.locator('[data-toy-status]')).toContainText('Decrypted')
})
