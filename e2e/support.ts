import { expect, type Page } from '@playwright/test'

/**
 * Shared harness for the functional specs.
 *
 * The Oracle is a remote service, so the browser tests stand in for it with
 * page.context().route. The mock never invents a ciphertext: it echoes ct_a back as the
 * result, which is a genuinely valid FheUint8 under the browser's own client
 * key. With b = 0 that echo IS the correct sum; with b != 0 it is a wrong
 * answer the page has to notice.
 */
export async function mockOracle(page: Page): Promise<() => number> {
  let computeCalls = 0
  await page.context().route('**/health', (route) =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ status: 'ok', fhe: true })
    })
  )
  await page.context().route('**/compute/add', async (route) => {
    computeCalls++
    const body = route.request().postDataJSON() as { ctA: string }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        ctResult: body.ctA,
        operation: 'add',
        plaintextAccessed: false,
        scheme: 'TFHE-rs (mocked in test)',
        bootstrapping: 'programmable_bootstrapping_per_operation'
      })
    })
  })
  return () => computeCalls
}

/** Load the page and wait for real in-browser TFHE key generation to finish. */
export async function bootReady(page: Page): Promise<void> {
  await page.goto('.')
  await expect(page.locator('[data-state]')).toHaveText('READY', { timeout: 90_000 })
}
