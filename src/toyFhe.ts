/**
 * A real somewhat-homomorphic scheme, small enough to run entirely in this tab.
 *
 * WHY THIS EXISTS
 * The Oracle round-trip demonstrates addition. Multiplication was only ever
 * described — the page said it is slower and heavier and left it at that. This
 * module lets the page actually perform one, locally, and lets the learner keep
 * multiplying until decryption breaks. That failure is the entire reason TFHE
 * spends its time on bootstrapping, and it is much more convincing performed
 * than asserted.
 *
 * THE SCHEME
 * DGHV-inspired (van Dijk, Gentry, Halevi, Vaikuntanathan 2010), with unsigned
 * residues and a base-256 message space so it lines up with the FheUint8 the
 * Oracle handles. The original paper uses centered residues and bit messages;
 * its p/2 bound does not describe this unsigned adaptation:
 *
 *     Enc(m) = m + B*r + q*p          (p secret, B = 256, r small, q large)
 *     Dec(c) = (c mod p) mod B
 *
 * Add and multiply on ciphertexts really do add and multiply the plaintexts,
 * because both operations pass straight through the p-multiple. The noise term
 * (m + B*r) adds on addition and MULTIPLIES on multiplication — which is why an
 * addition chain runs for hundreds of steps here and a multiplication chain dies
 * on the third with the default parameters. For a consistent ciphertext,
 * 0 <= noise < p guarantees correctness: unsigned reduction has not wrapped.
 * Beyond that interval a byte can still match; this does not restore a general
 * correctness guarantee for later operations.
 *
 * SCALE, STATED PLAINLY
 * These parameters are chosen so the noise ceiling is reachable in three clicks:
 * p is 48 bits. The original paper's security analysis does not apply to this
 * tiny base-256 model. This is NOT secure encryption and must not be used as
 * such. It demonstrates local noise growth and a first modulus wrap, not TFHE's
 * parameters or a bootstrapping implementation.
 */

export const TOY_BASE = 256
export const TOY_P_BITS = 48
export const TOY_Q_BITS = 80
export const TOY_RHO_BITS = 6

export interface ToyKey {
  /** Secret odd modulus. Decryption is reduction mod p, then mod B. */
  p: bigint
}

/**
 * A ciphertext plus its exact noise term, tracked alongside.
 *
 * The noise is bookkeeping for the page, never an input to decryption: `c` is
 * the whole ciphertext and `toyDecrypt` touches nothing else. It has to be
 * tracked explicitly because it cannot be recovered from `c` once it passes p —
 * `c mod p` is an unsigned representative in [0,p), whatever the full noise was.
 * `noiseIsConsistent()` below re-derives
 * the invariant (c - noise is a multiple of p) so the bookkeeping cannot drift
 * from the ciphertext it describes.
 */
export interface ToyCiphertext {
  c: bigint
  noise: bigint
}

function randomBigInt(bits: number): bigint {
  const bytes = crypto.getRandomValues(new Uint8Array(Math.ceil(bits / 8)))
  let value = 0n
  for (const byte of bytes) value = (value << 8n) | BigInt(byte)
  // Trim to exactly `bits` and set the top bit so the magnitude is predictable.
  const mask = (1n << BigInt(bits)) - 1n
  return (value & mask) | (1n << BigInt(bits - 1))
}

export function toyKeyGen(): ToyKey {
  // p must be odd: an even p would make (c mod p) mod 2 — and every derived
  // reduction — degenerate.
  return { p: randomBigInt(TOY_P_BITS) | 1n }
}

/** Exclusive upper boundary of the nonnegative no-wrap interval: 0 <= noise < p. */
export function noiseBudget(key: ToyKey): bigint {
  return key.p
}

export function budgetBits(key: ToyKey): number {
  return noiseBudget(key).toString(2).length
}

export function toyEncrypt(m: number, key: ToyKey): ToyCiphertext {
  const value = BigInt(((m % TOY_BASE) + TOY_BASE) % TOY_BASE)
  const r = randomBigInt(TOY_RHO_BITS) % (1n << BigInt(TOY_RHO_BITS))
  const q = randomBigInt(TOY_Q_BITS)
  const noise = value + BigInt(TOY_BASE) * r
  return { c: noise + q * key.p, noise }
}

/** Addition adds the noise terms — cheap, which is why add chains run long. */
export function toyAdd(a: ToyCiphertext, b: ToyCiphertext): ToyCiphertext {
  return { c: a.c + b.c, noise: a.noise + b.noise }
}

/** Multiplication MULTIPLIES them. That is the whole story of the budget. */
export function toyMul(a: ToyCiphertext, b: ToyCiphertext): ToyCiphertext {
  return { c: a.c * b.c, noise: a.noise * b.noise }
}

/** The tracked noise really is this ciphertext's distance from a multiple of p. */
export function noiseIsConsistent(ct: ToyCiphertext, key: ToyKey): boolean {
  return (ct.c - ct.noise) % key.p === 0n
}

export function noiseBits(ct: ToyCiphertext): number {
  const magnitude = ct.noise < 0n ? -ct.noise : ct.noise
  return magnitude === 0n ? 0 : magnitude.toString(2).length
}

export function withinBudget(ct: ToyCiphertext, key: ToyKey): boolean {
  return ct.noise >= 0n && ct.noise < noiseBudget(key)
}

export function toyDecrypt(ct: ToyCiphertext, key: ToyKey): number {
  let n = ct.c % key.p
  if (n < 0n) n += key.p
  return Number(n % BigInt(TOY_BASE))
}

export type ToyOp = 'encrypt' | 'add' | 'multiply'

export interface ChainStep {
  index: number
  op: ToyOp
  /** Human-readable expression so far, e.g. "a × b × b". */
  expression: string
  /** What the plaintext track says the answer must be (mod 256). */
  expected: number
  /** What decrypting the ciphertext actually returned. */
  decrypted: number
  correct: boolean
  noiseBits: number
  budgetBits: number
  /** True in the no-wrap interval 0 <= noise < p for model-generated ciphertexts. */
  withinBudget: boolean
  /** Decimal digits in the ciphertext, so growth is visible. */
  ciphertextDigits: number
}

/**
 * A running chain of homomorphic operations. Every step records what the
 * ciphertext decrypted to AND what it should have been, so the page never has to
 * take correctness on faith — and so the step where the noise ceiling is crossed
 * announces itself.
 */
export class ToyChain {
  readonly key: ToyKey
  private ct: ToyCiphertext
  private expectedValue: number
  private expression: string
  private stepCount = 0

  constructor(seedValue: number, key: ToyKey = toyKeyGen(), label = 'a') {
    this.key = key
    this.ct = toyEncrypt(seedValue, key)
    this.expectedValue = ((seedValue % TOY_BASE) + TOY_BASE) % TOY_BASE
    this.expression = label
  }

  private snapshot(op: ToyOp): ChainStep {
    const decrypted = toyDecrypt(this.ct, this.key)
    return {
      index: this.stepCount,
      op,
      expression: this.expression,
      expected: this.expectedValue,
      decrypted,
      correct: decrypted === this.expectedValue,
      noiseBits: noiseBits(this.ct),
      budgetBits: budgetBits(this.key),
      withinBudget: withinBudget(this.ct, this.key),
      ciphertextDigits: this.ct.c.toString().length
    }
  }

  /** The state right after encryption, before any operation. */
  start(): ChainStep {
    return this.snapshot('encrypt')
  }

  apply(op: 'add' | 'multiply', operandValue: number, label: string): ChainStep {
    const operandCt = toyEncrypt(operandValue, this.key)
    const operand = ((operandValue % TOY_BASE) + TOY_BASE) % TOY_BASE
    if (op === 'add') {
      this.ct = toyAdd(this.ct, operandCt)
      this.expectedValue = (this.expectedValue + operand) % TOY_BASE
      this.expression = `(${this.expression} + ${label})`
    } else {
      this.ct = toyMul(this.ct, operandCt)
      this.expectedValue = (this.expectedValue * operand) % TOY_BASE
      this.expression = `${this.expression} × ${label}`
    }
    this.stepCount += 1
    return this.snapshot(op)
  }
}
