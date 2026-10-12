/**
 * TFHE-rs WASM Client
 *
 * Uses Zama AI's TFHE-rs library for true fully homomorphic encryption.
 * FheUint8 values are radix-decomposed into shortint blocks, and each block
 * operation runs a programmable bootstrap (PBS) - no circuit depth limit.
 * (Gate bootstrapping is the term for TFHE's boolean API, which this does not use.)
 *
 * CRITICAL: Client key NEVER leaves this browser.
 * Server receives only the compressed server key for evaluation.
 */

import initTfhe, { TfheConfigBuilder, TfheClientKey, TfheCompressedServerKey, FheUint8 } from 'tfhe'
import { uint8ArrayToBase64, base64ToUint8Array, bytesToHex, isValidFheUint8 } from './encoding'

export interface FheContext {
  clientKey: TfheClientKey // Decryption only — never serialized, never leaves browser
  serverKeyB64: string // Safely serialized compressed server key — sent for evaluation
  ready: boolean
  keyGenTimeMs: number // For display in oracle log
}

// TFHE safe serialization enforces explicit byte ceilings while adding type
// and version metadata. The HTTP body limit is the tighter bound for requests;
// these limits also protect local serialization/deserialization calls.
const SERVER_KEY_SIZE_LIMIT = 96n * 1024n * 1024n
const CIPHERTEXT_SIZE_LIMIT = 16n * 1024n * 1024n

export interface EncryptedValue {
  base64: string // Serialized FheUint8 → base64
  fullHex: string // Full hex for inspector modal
  originalValue: number // Stored locally only — never transmitted
}

function validateValue(value: number): void {
  if (!isValidFheUint8(value)) {
    throw new Error('Value must be an integer between 0 and 255 (FheUint8 range)')
  }
}

/**
 * Initialize TFHE-rs WASM and generate key pair.
 *
 * Key generation takes 10-15 seconds in browser due to the bootstrapping
 * key material (bootstrap key plus key-switching key). This is the cost of true FHE — unlimited computation depth.
 */
export async function initFhe(): Promise<FheContext> {
  console.log('[FHE] TFHE-rs WebAssembly loading...')

  // Initialize WASM module
  await initTfhe()

  console.log('[FHE] Generating FHE key pair — please wait (10–15 seconds)...')
  const startTime = performance.now()

  // Create default config for FheUint8 operations
  const config = TfheConfigBuilder.default().build()

  // Generate client key (contains secret key — NEVER leaves browser)
  const clientKey = TfheClientKey.generate(config)

  // Derive compressed server key for evaluation (safe to transmit)
  const compressedServerKey = TfheCompressedServerKey.new(clientKey)

  // Versioned, type-checked serialization shared with the Rust service.
  const serverKeyBytes = compressedServerKey.safe_serialize(SERVER_KEY_SIZE_LIMIT)
  const serverKeyB64 = uint8ArrayToBase64(serverKeyBytes)

  const keyGenTimeMs = Math.round(performance.now() - startTime)

  console.log(
    `[FHE] TFHE-rs WASM ready. Key gen: ${(keyGenTimeMs / 1000).toFixed(1)}s. Programmable bootstrapping: ACTIVE.`
  )
  console.log(`[FHE] Server key size: ${(serverKeyBytes.length / 1024 / 1024).toFixed(2)} MB`)

  return {
    clientKey,
    serverKeyB64,
    ready: true,
    keyGenTimeMs
  }
}

/**
 * Encrypt an integer value (0-255) using FheUint8.
 */
export async function encryptValue(value: number, ctx: FheContext): Promise<EncryptedValue> {
  validateValue(value)

  // Encrypt with client key
  const encrypted = FheUint8.encrypt_with_client_key(value, ctx.clientKey)

  // Versioned, type-checked serialization shared with the Rust service.
  const bytes = encrypted.safe_serialize(CIPHERTEXT_SIZE_LIMIT)
  const base64 = uint8ArrayToBase64(bytes)
  const fullHex = bytesToHex(bytes)

  return {
    base64,
    fullHex,
    originalValue: value
  }
}

/**
 * Decrypt a result ciphertext received from the server.
 */
export async function decryptResult(ctBase64: string, ctx: FheContext): Promise<number> {
  // Decode base64 to bytes
  const bytes = base64ToUint8Array(ctBase64)

  // Reject wrong types, unsupported versions and oversized ciphertexts.
  const ciphertext = FheUint8.safe_deserialize(bytes, CIPHERTEXT_SIZE_LIMIT)

  // Decrypt with client key
  const result = ciphertext.decrypt(ctx.clientKey)

  return result
}

/**
 * Check if SharedArrayBuffer is available (required for TFHE WASM).
 */
export function checkSharedArrayBuffer(): boolean {
  return typeof SharedArrayBuffer === 'function'
}
