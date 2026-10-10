import { describe, expect, it } from 'vitest'
import {
  TOY_BASE,
  ToyChain,
  budgetBits,
  noiseBits,
  toyAdd,
  toyDecrypt,
  toyEncrypt,
  toyKeyGen,
  toyMul,
  noiseIsConsistent,
  withinBudget
} from './toyFhe'

describe('toy DGHV scheme', () => {
  it('generates an odd secret modulus of the stated size', () => {
    for (let run = 0; run < 10; run += 1) {
      const key = toyKeyGen()
      expect(key.p % 2n).toBe(1n)
      expect(key.p.toString(2).length).toBe(48)
    }
  })

  it('round-trips every byte value', () => {
    const key = toyKeyGen()
    for (let m = 0; m < TOY_BASE; m += 1) {
      expect(toyDecrypt(toyEncrypt(m, key), key)).toBe(m)
    }
  })

  it('is probabilistic: the same value encrypts to different ciphertexts', () => {
    const key = toyKeyGen()
    const first = toyEncrypt(42, key)
    const second = toyEncrypt(42, key)
    expect(first).not.toBe(second)
    expect(toyDecrypt(first, key)).toBe(42)
    expect(toyDecrypt(second, key)).toBe(42)
  })

  it('hides the plaintext from anyone without p', () => {
    const key = toyKeyGen()
    const ct = toyEncrypt(7, key)
    // The ciphertext is far larger than the message; without p there is no
    // reduction to perform, and the wrong p gives the wrong answer.
    expect(ct.c).toBeGreaterThan(1n << 100n)
    expect(toyDecrypt(ct, toyKeyGen())).not.toBe(7)
  })
})

describe('homomorphic addition', () => {
  it('adds under encryption, wrapping mod 256 exactly like the Oracle track', () => {
    const key = toyKeyGen()
    for (const [a, b] of [
      [3, 4],
      [200, 100],
      [255, 1],
      [0, 0]
    ]) {
      const sum = toyAdd(toyEncrypt(a, key), toyEncrypt(b, key))
      expect(toyDecrypt(sum, key)).toBe((a + b) % TOY_BASE)
    }
  })

  it('grows noise slowly enough that long addition chains stay correct', () => {
    const key = toyKeyGen()
    let ct = toyEncrypt(1, key)
    for (let i = 0; i < 200; i += 1) ct = toyAdd(ct, toyEncrypt(1, key))
    expect(withinBudget(ct, key)).toBe(true)
    expect(noiseIsConsistent(ct, key)).toBe(true)
    expect(toyDecrypt(ct, key)).toBe(201 % TOY_BASE)
  })
})

describe('homomorphic multiplication', () => {
  it('multiplies under encryption for one level', () => {
    const key = toyKeyGen()
    for (const [a, b] of [
      [3, 4],
      [12, 21],
      [255, 255],
      [16, 16]
    ]) {
      const product = toyMul(toyEncrypt(a, key), toyEncrypt(b, key))
      expect(withinBudget(product, key)).toBe(true)
      expect(toyDecrypt(product, key)).toBe((a * b) % TOY_BASE)
    }
  })

  it('squares the noise, unlike addition which merely adds it', () => {
    const key = toyKeyGen()
    const a = toyEncrypt(100, key)
    const b = toyEncrypt(100, key)
    const sumBits = noiseBits(toyAdd(a, b))
    const productBits = noiseBits(toyMul(a, b))
    expect(sumBits).toBeLessThan(noiseBits(a) + 2)
    expect(productBits).toBeGreaterThan(sumBits * 1.7)
  })

  it('spends the whole budget by the third multiply — the ceiling is real', () => {
    // With these parameters the noise starts at ~2^14 and is multiplied by a
    // fresh ~2^14 every time, so it lands at ~2^28, ~2^42, ~2^56 while the
    // exclusive no-wrap boundary p is 48 bits. Two multiplies fit; the third cannot.
    const key = toyKeyGen()
    const one = toyMul(toyEncrypt(7, key), toyEncrypt(9, key))
    const two = toyMul(one, toyEncrypt(9, key))
    const three = toyMul(two, toyEncrypt(9, key))
    expect(withinBudget(one, key)).toBe(true)
    expect(withinBudget(two, key)).toBe(true)
    expect(withinBudget(three, key)).toBe(false)
    expect(noiseBits(three)).toBeGreaterThan(budgetBits(key))
    // The tracked noise is not a story told about the ciphertext — it is the
    // ciphertext's real offset from a multiple of p, at every stage.
    for (const ct of [one, two, three]) expect(noiseIsConsistent(ct, key)).toBe(true)
  })

  it('loses correctness once the budget is gone', () => {
    // Outside the no-wrap interval, agreement is not generally guaranteed.
    // Particular wrap counts can still preserve a byte. This controls the
    // observed frequency for the random default chain, not a universal theorem.
    let wrong = 0
    const runs = 50
    for (let i = 0; i < runs; i += 1) {
      const key = toyKeyGen()
      const chain = new ToyChain(11, key)
      chain.apply('multiply', 13, 'b')
      chain.apply('multiply', 13, 'b')
      const third = chain.apply('multiply', 13, 'b')
      expect(third.withinBudget).toBe(false)
      if (!third.correct) wrong += 1
    }
    expect(wrong).toBeGreaterThanOrEqual(runs - 5)
  })
})

describe('ToyChain bookkeeping', () => {
  it('tracks the expected value alongside the decrypted one', () => {
    const chain = new ToyChain(12)
    const start = chain.start()
    expect(start.expected).toBe(12)
    expect(start.decrypted).toBe(12)
    expect(start.correct).toBe(true)
    expect(start.withinBudget).toBe(true)

    const step = chain.apply('multiply', 21, 'b')
    expect(step.expected).toBe((12 * 21) % TOY_BASE)
    expect(step.decrypted).toBe(step.expected)
    expect(step.correct).toBe(true)
    expect(step.expression).toBe('a × b')
    expect(step.noiseBits).toBeGreaterThan(start.noiseBits)
    expect(step.ciphertextDigits).toBeGreaterThan(start.ciphertextDigits)
  })

  it('keeps addition steps correct and inside budget', () => {
    const chain = new ToyChain(200)
    const step = chain.apply('add', 100, 'b')
    expect(step.expected).toBe(44)
    expect(step.decrypted).toBe(44)
    expect(step.withinBudget).toBe(true)
    expect(step.expression).toBe('(a + b)')
  })
})
