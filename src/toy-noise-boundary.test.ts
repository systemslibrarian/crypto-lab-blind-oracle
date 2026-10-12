import { describe, expect, it } from 'vitest'
import { budgetBits, noiseBudget, noiseIsConsistent, toyDecrypt, withinBudget } from './toyFhe'

// Fixed, valid 48-bit odd modulus. The oracle below is integer division and
// normalized byte reduction, independent of the implementation's budget helper.
const key = { p: (1n << 47n) + 1n }
const byte = (n: bigint) => Number(((n % 256n) + 256n) % 256n)
const ciphertext = (noise: bigint, q = 17n) => ({ c: noise + q * key.p, noise })

describe('unsigned toy decoder boundary', () => {
  it('uses p as an exclusive boundary, with its actual bit length', () => {
    expect(noiseBudget(key)).toBe(key.p)
    expect(budgetBits(key)).toBe(48)
  })

  for (const noise of [0n, key.p / 2n - 1n, key.p / 2n, key.p / 2n + 1n, key.p - 1n]) {
    it(`guarantees the actual byte for nonnegative noise ${noise}, including above p/2`, () => {
      for (const q of [17n, -17n]) {
        const ct = ciphertext(noise, q)
        expect(noiseIsConsistent(ct, key)).toBe(true)
        expect(toyDecrypt(ct, key)).toBe(byte(noise))
        expect(withinBudget(ct, key)).toBe(true)
      }
    })
  }

  for (const noise of [key.p, key.p + 1n]) {
    it(`detects the first modulus wrap at ${noise}, even when bit lengths agree`, () => {
      const ct = ciphertext(noise)
      expect(noise.toString(2).length).toBe(key.p.toString(2).length)
      expect(noiseIsConsistent(ct, key)).toBe(true)
      expect(withinBudget(ct, key)).toBe(false)
      expect(toyDecrypt(ct, key)).toBe(byte(noise - key.p))
      expect(toyDecrypt(ct, key)).not.toBe(byte(noise))
    })
  }

  it('does not promise centered-decoder correctness for a negative noise term', () => {
    const ct = ciphertext(-1n)
    expect(noiseIsConsistent(ct, key)).toBe(true)
    expect(toyDecrypt(ct, key)).toBe(byte(key.p - 1n))
    expect(toyDecrypt(ct, key)).not.toBe(byte(-1n))
    expect(withinBudget(ct, key)).toBe(false)
  })

  it('retains an observed match after 256 wraps without restoring the no-wrap guarantee', () => {
    const ct = ciphertext(256n * key.p + 1n)
    expect(noiseIsConsistent(ct, key)).toBe(true)
    expect(toyDecrypt(ct, key)).toBe(byte(ct.noise))
    expect(withinBudget(ct, key)).toBe(false)
  })
})
