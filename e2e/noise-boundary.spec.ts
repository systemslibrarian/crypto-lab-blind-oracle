import { expect, test } from '@playwright/test'
import { bootReady, mockOracle } from './support'

test.setTimeout(120_000)

for (const width of [1280, 380, 320]) {
  test(`the real bench earns correctness above p/2 and detects a later wrap at ${width}px`, async ({
    page
  }, testInfo) => {
    await page.setViewportSize({ width, height: 900 })
    const computes = await mockOracle(page)
    await bootReady(page) // Real TFHE WASM/key generation finishes before the RNG control.
    await page.fill('[data-toy-a]', '0')
    await page.fill('[data-toy-b]', '0')
    await page.locator('[data-toy-b]').blur() // Commit the input change before starting the chain.

    // Control only the subsequent toy RNG. No ciphertext, decryption, budget
    // function or DOM verdict is replaced. Other RNG sizes retain their real RNG.
    await page.evaluate(() => {
      const real = crypto.getRandomValues.bind(crypto)
      const calls: number[] = []
      Object.defineProperty(window, '__toyRngCalls', { value: calls })
      Object.defineProperty(crypto, 'getRandomValues', {
        value(array: Uint8Array) {
          if (!(array instanceof Uint8Array) || ![1, 6, 10].includes(array.length)) {
            return real(array)
          }
          calls.push(array.length)
          array.fill(0)
          if (array.length === 6) {
            array[0] = 0x80
            array[5] = 1 // p = 2^47 + 1; r = 32; q = 2^79 after normal top-bit logic.
          }
          return array
        }
      })
      const add = document.querySelector<HTMLButtonElement>('[data-toy-add]')!
      for (let i = 0; i < 128; i++) add.click()
    })
    await page.click('[data-toy-mul]')
    await page.click('[data-toy-mul]')

    const calls = await page.evaluate(
      () => (window as unknown as { __toyRngCalls: number[] }).__toyRngCalls
    )
    expect(calls.filter((n) => n === 6)).toHaveLength(1)
    expect(calls.filter((n) => n === 1)).toHaveLength(131)
    expect(calls.filter((n) => n === 10)).toHaveLength(131)
    const p = (1n << 47n) + 1n
    const noise = 129n * 8192n ** 3n
    expect(noise).toBeGreaterThan(p / 2n)
    expect(noise).toBeLessThan(p)
    const rows = page.locator('[data-toy-rows] tr')
    await expect(rows).toHaveCount(131)
    const result = rows.last()
    await expect(result.locator('td').nth(3)).toHaveText('0')
    await expect(result.locator('td').nth(4)).toHaveText('0')
    await expect(result).toContainText('correct — inside budget')
    await expect(result).toHaveClass('toy-ok')
    await expect(result).not.toContainText('luck')
    await expect(page.locator('[data-toy-caption]')).toContainText('140737488355329')
    await expect(page.locator('.toy-scale')).toContainText('unsigned')
    await expect(page.locator('.toy-scale')).toContainText('centered')

    await page.click('[data-toy-mul]')
    const wrapped = noise * 8192n
    const expected = Number((wrapped % p) % 256n)
    expect(expected).toBe(225)
    await expect(rows.last().locator('td').nth(3)).toHaveText(String(expected))
    await expect(rows.last()).toHaveClass('toy-bad')
    await expect(rows.last()).toContainText('OVER')
    await expect(page.locator('[data-toy-verdict]')).toContainText('The budget ran out at step 131')
    expect(computes()).toBe(0) // The real local computation never uses the mocked compute API.
    expect(
      await page.evaluate(() => document.documentElement.scrollWidth - innerWidth)
    ).toBeLessThanOrEqual(1)
    const evidence = {
      p: p.toString(),
      noise: noise.toString(),
      wrappedNoise: wrapped.toString(),
      expected,
      calls: calls.length,
      width,
      computes: computes()
    }
    console.log('Actual unsigned-bench boundary control:', JSON.stringify(evidence))
    await testInfo.attach('unsigned-boundary-control', {
      body: JSON.stringify(evidence),
      contentType: 'application/json'
    })
  })
}
