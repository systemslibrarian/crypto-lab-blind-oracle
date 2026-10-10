import './style.css'
import {
  checkHealth,
  computeAdd,
  InvalidCiphertextError,
  OracleInitializingError,
  OracleOfflineError,
  OracleTimeoutError
} from './apiClient'
import { animateCountUp, WireAnimator } from './animations'
import {
  decryptResult,
  encryptValue,
  initFhe,
  checkSharedArrayBuffer,
  type FheContext,
  type EncryptedValue
} from './clientFhe'
import { base64ToHex, base64ToUint8Array, ciphertextFingerprint } from './encoding'
import { OracleLog } from './oracleLog'
import { StateMachine } from './stateMachine'
import { ToyChain, TOY_P_BITS, type ChainStep } from './toyFhe'

const state = new StateMachine('BOOTING')

let fheCtx: FheContext | null = null
let cipherA: EncryptedValue | null = null
let cipherB: EncryptedValue | null = null
let lastResultCt = ''
/**
 * The plaintext-track answer for the currently-encrypted inputs, computed with
 * the SAME u8 semantics FheUint8 uses (wrapping mod 256). Null until a pair of
 * values has been encrypted. The verdict below is gated on this matching the
 * decrypted ciphertext-track result, so the page can never claim a match it did
 * not actually observe.
 */
let plainSum: number | null = null

/** FheUint8 arithmetic is mod 256; mirror it exactly on the plaintext track. */
const U8_MODULUS = 256
function wrapU8(n: number): number {
  return ((n % U8_MODULUS) + U8_MODULUS) % U8_MODULUS
}

const statusEl = document.querySelector('[data-state]') as HTMLElement
const responseTimeEl = document.querySelector('[data-response-time]') as HTMLElement
const logEl = document.querySelector('[data-oracle-log]') as HTMLElement
const inputA = document.querySelector('[data-input-a]') as HTMLInputElement
const inputB = document.querySelector('[data-input-b]') as HTMLInputElement
const encryptButton = document.querySelector('[data-encrypt]') as HTMLButtonElement
const computeButton = document.querySelector('[data-compute]') as HTMLButtonElement
const resultBar = document.querySelector('[data-result-bar]') as HTMLElement
const resultValueEl = document.querySelector('[data-result-value]') as HTMLElement
const resultAnnounceEl = document.querySelector('[data-result-announce]') as HTMLElement
const errorEl = document.querySelector('[data-error]') as HTMLElement
const ctAPreviewEl = document.querySelector('[data-ct-a-preview]') as HTMLElement
const ctBPreviewEl = document.querySelector('[data-ct-b-preview]') as HTMLElement
const ctASwatchEl = document.querySelector('[data-ct-a-swatch]') as HTMLElement
const ctBSwatchEl = document.querySelector('[data-ct-b-swatch]') as HTMLElement
const ctADigestEl = document.querySelector('[data-ct-a-digest]') as HTMLElement
const ctBDigestEl = document.querySelector('[data-ct-b-digest]') as HTMLElement
const fingerprintNoteEl = document.querySelector('[data-fingerprint-note]') as HTMLElement
const reencryptButton = document.querySelector('[data-reencrypt]') as HTMLButtonElement
const responseCostEl = document.querySelector('[data-response-cost]') as HTMLElement
const multiplyInfoBtn = document.querySelector('[data-multiply-info]') as HTMLButtonElement
const multiplyWhyEl = document.querySelector('[data-multiply-why]') as HTMLElement
// Parallel-tracks correspondence panel.
const corrPlainAEl = document.querySelector('[data-corr-plain-a]') as HTMLElement
const corrPlainBEl = document.querySelector('[data-corr-plain-b]') as HTMLElement
const corrPlainSumEl = document.querySelector('[data-corr-plain-sum]') as HTMLElement
const corrCtAEl = document.querySelector('[data-corr-ct-a]') as HTMLElement
const corrCtBEl = document.querySelector('[data-corr-ct-b]') as HTMLElement
const corrCtSumEl = document.querySelector('[data-corr-ct-sum]') as HTMLElement
const corrDecryptedEl = document.querySelector('[data-corr-decrypted]') as HTMLElement
const corrVerdictEl = document.querySelector('[data-corr-verdict]') as HTMLElement
const corrMismatchEl = document.querySelector('[data-corr-mismatch]') as HTMLElement
const corrWrapNoteEl = document.querySelector('[data-corr-wrap-note]') as HTMLElement
const corrTracksEl = document.querySelector('.corr-tracks') as HTMLElement
const peekToggle = document.querySelector('[data-peek-toggle]') as HTMLButtonElement
const peekBody = document.querySelector('[data-peek-body]') as HTMLElement
const modal = document.querySelector('[data-inspector-modal]') as HTMLDialogElement
const modalOpenBtn = document.querySelector('[data-open-inspector]') as HTMLButtonElement
const modalCloseBtn = document.querySelector('[data-close-inspector]') as HTMLButtonElement
const modalCtA = document.querySelector('[data-modal-ct-a]') as HTMLElement
const modalCtB = document.querySelector('[data-modal-ct-b]') as HTMLElement
const modalCtR = document.querySelector('[data-modal-ct-r]') as HTMLElement
const resetBtn = document.querySelector('[data-reset]') as HTMLButtonElement
const infoModal = document.querySelector('[data-info-modal]') as HTMLDialogElement
const infoOpenBtn = document.querySelector('[data-open-info]') as HTMLButtonElement
const infoCloseBtn = document.querySelector('[data-close-info]') as HTMLButtonElement
const lastRequestEl = document.querySelector('[data-last-request]') as HTMLElement
const reqPreviewEl = document.querySelector('[data-req-preview]') as HTMLElement
const themeToggleBtn = document.querySelector('[data-theme-toggle]') as HTMLButtonElement | null
const bootOverlay = document.querySelector('[data-boot-overlay]') as HTMLElement
const bootDetailEl = document.querySelector('[data-boot-detail]') as HTMLElement
const bootRetryBtn = document.querySelector('[data-boot-retry]') as HTMLButtonElement
const bootOfflineBtn = document.querySelector('[data-boot-offline]') as HTMLButtonElement
const offlineBanner = document.querySelector('[data-offline-banner]') as HTMLElement
const toyAInput = document.querySelector('[data-toy-a]') as HTMLInputElement
const toyBInput = document.querySelector('[data-toy-b]') as HTMLInputElement
const toyMulBtn = document.querySelector('[data-toy-mul]') as HTMLButtonElement
const toyAddBtn = document.querySelector('[data-toy-add]') as HTMLButtonElement
const toyResetBtn = document.querySelector('[data-toy-reset]') as HTMLButtonElement
const toyStatusEl = document.querySelector('[data-toy-status]') as HTMLElement
const toyRowsEl = document.querySelector('[data-toy-rows]') as HTMLElement
const toyCaptionEl = document.querySelector('[data-toy-caption]') as HTMLElement
const toyVerdictEl = document.querySelector('[data-toy-verdict]') as HTMLElement

const oracleLog = new OracleLog(logEl)
const animator = new WireAnimator()
animator.start()

function getCurrentTheme(): 'dark' | 'light' {
  return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark'
}

function syncThemeToggle(theme: 'dark' | 'light'): void {
  if (!themeToggleBtn) {
    return
  }

  themeToggleBtn.textContent = theme === 'dark' ? '🌙' : '☀️'
  themeToggleBtn.setAttribute(
    'aria-label',
    theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'
  )
}

function setTheme(theme: 'dark' | 'light'): void {
  document.documentElement.setAttribute('data-theme', theme)
  localStorage.setItem('theme', theme)
  syncThemeToggle(theme)
}

function setError(message: string): void {
  state.setState('ERROR')
  errorEl.textContent = message
  errorEl.hidden = false
  oracleLog.logError(message)
}

function clearError(): void {
  errorEl.hidden = true
  errorEl.textContent = ''
}

function setBootDetail(message: string): void {
  bootDetailEl.textContent = message
}

function hideBootOverlay(): void {
  bootOverlay.classList.add('boot-overlay--hidden')
}

function showBootError(message: string): void {
  bootOverlay.classList.remove('boot-overlay--hidden')
  bootOverlay.classList.add('boot-overlay--error')
  setBootDetail(message)
  bootRetryBtn.hidden = false
}

/** Disable the action controls while an async operation is in flight. */
function lockControls(): void {
  encryptButton.disabled = true
  reencryptButton.disabled = true
  computeButton.disabled = true
  resetBtn.disabled = true
}

/** Re-enable controls after work finishes. Compute/re-encrypt require live ciphertext. */
function unlockControls(): void {
  const fheReady = degraded !== 'fhe-unavailable'
  encryptButton.disabled = !fheReady
  resetBtn.disabled = false
  computeButton.disabled = !(cipherA && cipherB) || degraded !== 'none'
  reencryptButton.disabled = !(cipherA && cipherB) || !fheReady
}

/**
 * Degraded mode. The Oracle is a remote service on a free tier; when it is
 * asleep, unreachable, or gone, the page used to dead-end behind a boot overlay
 * with nothing but a retry button — every local capability (key generation,
 * encryption, the ciphertext inspector, the whole local multiply bench) was
 * locked behind a failure that had nothing to do with any of them.
 *
 * Now the failure is scoped to the thing that actually failed, and the page says
 * plainly which parts still work.
 */
type DegradedMode = 'none' | 'oracle-offline' | 'fhe-unavailable'
let degraded: DegradedMode = 'none'

function enterDegraded(mode: Exclude<DegradedMode, 'none'>, detail: string): void {
  degraded = mode
  offlineBanner.hidden = false
  offlineBanner.innerHTML =
    mode === 'oracle-offline'
      ? `<strong>Oracle unreachable.</strong> ${detail} Key generation, encryption, the ciphertext ` +
        'inspector and the <a href="#toy-multiply">local multiply bench</a> all run in this browser ' +
        'and still work — only the remote homomorphic add is unavailable. Reload to try the Oracle again.'
      : `<strong>TFHE runtime unavailable.</strong> ${detail} The <a href="#toy-multiply">local ` +
        'multiply bench</a> below does not use TFHE and still runs in full.'
  hideBootOverlay()
  bootOverlay.classList.remove('boot-overlay--error')
  clearError()
  unlockControls()
}

syncThemeToggle(getCurrentTheme())
themeToggleBtn?.addEventListener('click', () => {
  const nextTheme = getCurrentTheme() === 'dark' ? 'light' : 'dark'
  setTheme(nextTheme)
})

state.onChange((next) => {
  statusEl.textContent = next
  if (next === 'WAKING_ORACLE') {
    oracleLog.logState(next)
  }
})

/** What entering degraded mode would mean, if the learner chooses to. */
let pendingDegraded: { mode: Exclude<DegradedMode, 'none'>; detail: string } | null = null

async function boot(): Promise<void> {
  clearError()
  pendingDegraded = null
  bootOfflineBtn.hidden = true
  offlineBanner.hidden = true
  degraded = 'none'
  bootRetryBtn.hidden = true
  bootOverlay.classList.remove('boot-overlay--error', 'boot-overlay--hidden')
  state.setState('BOOTING')
  // Keep the action controls disabled (and out of keyboard reach behind the
  // overlay) until boot reaches READY, so they can't race the boot flow.
  lockControls()

  // Check SharedArrayBuffer availability (required for TFHE WASM)
  if (!checkSharedArrayBuffer()) {
    const msg =
      'SharedArrayBuffer is not available, so TFHE-rs cannot start. The page needs to be cross-origin isolated (COOP/COEP).'
    showBootError(msg)
    bootOfflineBtn.hidden = false
    pendingDegraded = { mode: 'fhe-unavailable', detail: msg }
    return
  }

  // Skip key generation on retry — keys persist across boot attempts, so a
  // failed oracle wake-up shouldn't cost another ~15s of key gen.
  if (!fheCtx || !fheCtx.ready) {
    try {
      setBootDetail('Generating FHE key pair in your browser (~10–15s)…')
      fheCtx = await initFhe()
      oracleLog.logBoot(fheCtx.keyGenTimeMs)
    } catch (error) {
      const detail = error instanceof Error ? error.message : 'Unknown initialization error'
      console.error('[FHE] Boot failure:', error)
      showBootError(`Failed to initialize FHE runtime: ${detail}`)
      bootOfflineBtn.hidden = false
      pendingDegraded = { mode: 'fhe-unavailable', detail: `Initialization failed: ${detail}.` }
      return
    }
  }

  state.setState('CHECKING_SERVER')
  setBootDetail('Keys ready. Contacting the Oracle…')
  const healthy = await checkHealth()

  if (healthy) {
    degraded = 'none'
    offlineBanner.hidden = true
    hideBootOverlay()
    unlockControls()
    state.setState('READY')
    return
  }

  state.setState('WAKING_ORACLE')
  const wakeDeadline = Date.now() + 45000

  while (Date.now() < wakeDeadline) {
    const secondsLeft = Math.ceil((wakeDeadline - Date.now()) / 1000)
    setBootDetail(`Waking the Oracle from cold start… (${secondsLeft}s remaining)`)
    await new Promise((resolve) => setTimeout(resolve, 3000))
    const ok = await checkHealth()
    if (ok) {
      degraded = 'none'
      offlineBanner.hidden = true
      hideBootOverlay()
      unlockControls()
      state.setState('READY')
      return
    }
  }

  showBootError(
    'Oracle did not wake in time (free-tier cold start). Retry, or continue without it.'
  )
  bootOfflineBtn.hidden = false
  pendingDegraded = {
    mode: 'oracle-offline',
    detail:
      'It did not answer a health check within 45 seconds — a free-tier cold start, a deploy, or a service that is simply gone.'
  }
}

bootRetryBtn.addEventListener('click', () => {
  void boot()
})

bootOfflineBtn.addEventListener('click', () => {
  if (!pendingDegraded) return
  bootOfflineBtn.hidden = true
  enterDegraded(pendingDegraded.mode, pendingDegraded.detail)
})

function requireReadyContext(): FheContext {
  if (!fheCtx || !fheCtx.ready) {
    throw new Error('FHE context unavailable')
  }
  return fheCtx
}

/** A valid operand is an integer byte in [0, 255]. */
function isValidByte(raw: string): boolean {
  if (raw === '') {
    return false
  }
  const n = Number(raw)
  return Number.isInteger(n) && n >= 0 && n <= 255
}

function readInputValues(): [number, number] {
  const rawA = inputA.value.trim()
  const rawB = inputB.value.trim()
  const aValid = isValidByte(rawA)
  const bValid = isValidByte(rawB)

  // Mark fields for assistive tech so the offending input is identifiable.
  inputA.setAttribute('aria-invalid', String(!aValid))
  inputB.setAttribute('aria-invalid', String(!bValid))

  if (!aValid || !bValid) {
    throw new Error('Inputs must be integers in the range 0 to 255 (FheUint8)')
  }
  return [Number(rawA), Number(rawB)]
}

/**
 * Render the value-dependent fingerprint (colour swatch + short digest) for a
 * ciphertext preview. Derived from the REAL serialized bytes, so it changes
 * whenever the ciphertext changes — including on re-encryption of the same
 * value (TFHE encryption is probabilistic). Returns the digest for logging.
 */
function renderFingerprint(base64: string, swatchEl: HTMLElement, digestEl: HTMLElement): string {
  const fp = ciphertextFingerprint(base64ToUint8Array(base64))
  swatchEl.style.backgroundColor = `hsl(${fp.hue} 80% 55%)`
  digestEl.textContent = fp.hex
  return fp.hex
}

/** Reset the correspondence panel + result reveal so a fresh run starts clean. */
function resetCorrespondence(): void {
  corrPlainAEl.textContent = 'a = ?'
  corrPlainBEl.textContent = 'b = ?'
  corrPlainSumEl.textContent = '?'
  corrCtAEl.textContent = 'Enc(a)'
  corrCtBEl.textContent = 'Enc(b)'
  corrCtSumEl.textContent = 'Enc(sum)'
  corrDecryptedEl.textContent = '?'
  corrVerdictEl.hidden = true
  corrMismatchEl.hidden = true
  corrWrapNoteEl.hidden = true
  corrWrapNoteEl.textContent = ''
  plainSum = null
  corrTracksEl.classList.remove('corr-tracks--matched')
}

/**
 * Encrypt the current inputs, refresh previews/fingerprints/correspondence, and
 * animate the outbound flow. Shared by ENCRYPT and RE-ENCRYPT so both produce a
 * real, freshly-randomised ciphertext.
 */
async function encryptCurrentInputs(): Promise<void> {
  const [a, b] = readInputValues()
  const ctx = requireReadyContext()

  state.setState('ENCRYPTING')
  cipherA = await encryptValue(a, ctx)
  cipherB = await encryptValue(b, ctx)

  ctAPreviewEl.textContent = `${cipherA.base64.slice(0, 80)}...`
  ctBPreviewEl.textContent = `${cipherB.base64.slice(0, 80)}...`

  const digestA = renderFingerprint(cipherA.base64, ctASwatchEl, ctADigestEl)
  const digestB = renderFingerprint(cipherB.base64, ctBSwatchEl, ctBDigestEl)
  fingerprintNoteEl.hidden = false

  modalCtA.textContent = cipherA.fullHex
  modalCtB.textContent = cipherB.fullHex

  // Populate the plaintext + ciphertext tracks; the sum fills in after compute.
  corrPlainAEl.textContent = `a = ${a}`
  corrPlainBEl.textContent = `b = ${b}`
  // Both tracks are u8: the plaintext track must wrap mod 256 exactly as
  // FheUint8 does, otherwise a + b > 255 would show two different numbers.
  plainSum = wrapU8(a + b)
  corrPlainSumEl.textContent = String(plainSum)
  if (a + b >= U8_MODULUS) {
    corrWrapNoteEl.textContent = `${a} + ${b} = ${a + b}, which overflows one byte, so the u8 answer is ${a + b} − 256 = ${plainSum}. FheUint8 is mod 256 too — the ciphertext track wraps the same way, which is why the two still agree.`
    corrWrapNoteEl.hidden = false
  } else {
    corrWrapNoteEl.textContent = ''
    corrWrapNoteEl.hidden = true
  }
  corrCtAEl.textContent = `Enc(${a})·${digestA.slice(0, 4)}`
  corrCtBEl.textContent = `Enc(${b})·${digestB.slice(0, 4)}`
  corrCtSumEl.textContent = 'Enc(sum)'
  corrDecryptedEl.textContent = '?'
  corrVerdictEl.hidden = true
  corrMismatchEl.hidden = true
  corrTracksEl.classList.remove('corr-tracks--matched')

  // A fresh encryption invalidates any prior computed result.
  lastResultCt = ''
  resultBar.classList.remove('revealed')

  state.setState('TRANSMITTING')
  animator.triggerTransmission('out')
  oracleLog.logTransmit(cipherA.base64, cipherB.base64, digestA, digestB)

  state.setState('READY')
}

encryptButton.addEventListener('click', async () => {
  clearError()
  lockControls()

  try {
    await encryptCurrentInputs()
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Encryption failed'
    setError(message)
  } finally {
    unlockControls()
  }
})

reencryptButton.addEventListener('click', async () => {
  clearError()
  lockControls()

  try {
    await encryptCurrentInputs()
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Re-encryption failed'
    setError(message)
  } finally {
    unlockControls()
  }
})

multiplyInfoBtn.addEventListener('click', () => {
  const nowHidden = !multiplyWhyEl.hidden
  multiplyWhyEl.hidden = nowHidden
  multiplyInfoBtn.setAttribute('aria-expanded', String(!nowHidden))
})

// "Peek inside the ciphertext": reveal a static LWE-style diagram showing the
// hidden value buried under noise. No motion — just show/hide the diagram.
peekToggle.addEventListener('click', () => {
  const willShow = peekBody.hidden
  peekBody.hidden = !willShow
  peekToggle.setAttribute('aria-expanded', String(willShow))
})

computeButton.addEventListener('click', async () => {
  clearError()

  if (!cipherA || !cipherB) {
    setError('Encrypt both values before compute')
    return
  }

  lockControls()

  try {
    const ctx = requireReadyContext()

    state.setState('TRANSMITTING')
    animator.triggerTransmission()

    const result = await computeAdd(ctx.serverKeyB64, cipherA.base64, cipherB.base64, () => {
      if (state.getState() !== 'WAKING_ORACLE') {
        state.setState('WAKING_ORACLE')
      }
    })

    // Fingerprint of the REAL result ciphertext bytes returned by the Oracle.
    const resultFp = ciphertextFingerprint(base64ToUint8Array(result.ctResultBase64))

    state.setState('ORACLE_COMPUTING')
    oracleLog.logComputing(result.responseTimeMs, result.scheme, result.bootstrapping, resultFp.hex)

    // Update devtools panel with last request preview
    if (lastRequestEl && reqPreviewEl && cipherA && cipherB) {
      lastRequestEl.hidden = false
      reqPreviewEl.textContent = `ct_a: ${cipherA.base64.slice(0, 32)}...\nct_b: ${cipherB.base64.slice(0, 32)}...\nct_result: ${result.ctResultBase64.slice(0, 32)}...`
    }

    if (result.plaintextAccessed !== false) {
      setError('Oracle response violated plaintextAccessed policy')
      return
    }

    state.setState('RECEIVING')
    // Animate the encrypted result travelling back to the browser.
    animator.triggerTransmission('return')
    responseTimeEl.textContent = `${result.responseTimeMs}ms`
    responseCostEl.hidden = false
    corrCtSumEl.textContent = `Enc(sum)·${resultFp.hex.slice(0, 4)}`
    lastResultCt = result.ctResultBase64
    // Decode the base64 ciphertext to its true bytes before hex (matches ct_a/ct_b).
    modalCtR.textContent = base64ToHex(lastResultCt)

    state.setState('DECRYPTING')
    oracleLog.logDecrypt()
    const resultValue = await decryptResult(result.ctResultBase64, ctx)

    // Complete the correspondence: decrypted ciphertext-track result equals the
    // plaintext-track sum, making Enc(a) ⊞ Enc(b) = Enc(a + b) literally visible.
    corrDecryptedEl.textContent = String(resultValue)
    // The verdict is EARNED, not assumed: compare the decrypted ciphertext-track
    // result against the plaintext-track u8 sum and only claim a match when the
    // two numbers are actually equal. If they differ, say so instead.
    const tracksMatch = plainSum !== null && resultValue === plainSum
    corrVerdictEl.hidden = !tracksMatch
    corrMismatchEl.hidden = tracksMatch
    // Static (motion-free) emphasis: mark the tracks matched so the "same answer"
    // link and both result cells get a persistent highlight — the payoff moment
    // gets visual weight without any count-up or flash animation.
    corrTracksEl.classList.toggle('corr-tracks--matched', tracksMatch)

    state.setState('REVEALED')
    resultBar.classList.add('revealed')
    await animateCountUp(resultValueEl, resultValue)
    // Announce the final total once, after the visual count-up settles, so
    // screen readers aren't flooded with the intermediate tween values.
    resultAnnounceEl.textContent = tracksMatch
      ? `The Oracle computed on ciphertext only. Decrypted locally, the sum is ${resultValue}, matching the plaintext track.`
      : `The Oracle computed on ciphertext only. Decrypted locally, the result is ${resultValue}, which does NOT match the plaintext track's ${plainSum}.`
  } catch (error) {
    if (error instanceof OracleTimeoutError) {
      setError('Oracle timed out after 45s. Use retry.')
      return
    }
    if (error instanceof OracleOfflineError) {
      setError('Oracle is offline. Check API deployment.')
      return
    }
    if (error instanceof InvalidCiphertextError) {
      setError('Oracle rejected ciphertext payload.')
      return
    }
    if (error instanceof OracleInitializingError) {
      setError('Oracle still initializing. Retry in a few seconds.')
      return
    }

    setError(error instanceof Error ? error.message : 'Compute failed')
  } finally {
    unlockControls()
  }
})

modalOpenBtn.addEventListener('click', () => {
  if (typeof modal.showModal === 'function') {
    modal.showModal()
  }
})

modalCloseBtn.addEventListener('click', () => {
  modal.close()
})

// Close the inspector when clicking the backdrop (parity with the info modal).
modal.addEventListener('click', (e) => {
  if (e.target === modal) {
    modal.close()
  }
})

infoOpenBtn?.addEventListener('click', () => {
  if (infoModal && typeof infoModal.showModal === 'function') {
    infoModal.showModal()
  }
})

infoCloseBtn?.addEventListener('click', () => {
  infoModal?.close()
})

infoModal?.addEventListener('click', (e) => {
  if (e.target === infoModal) {
    infoModal.close()
  }
})

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    infoModal?.close()
  }
})

resetBtn.addEventListener('click', () => {
  cipherA = null
  cipherB = null
  lastResultCt = ''
  ctAPreviewEl.textContent = 'awaiting ciphertext A...'
  ctBPreviewEl.textContent = 'awaiting ciphertext B...'
  ctASwatchEl.style.backgroundColor = ''
  ctBSwatchEl.style.backgroundColor = ''
  ctADigestEl.textContent = '—'
  ctBDigestEl.textContent = '—'
  fingerprintNoteEl.hidden = true
  responseTimeEl.textContent = '--ms'
  responseCostEl.hidden = true
  resultValueEl.textContent = '0'
  resultAnnounceEl.textContent = ''
  inputA.setAttribute('aria-invalid', 'false')
  inputB.setAttribute('aria-invalid', 'false')
  modalCtA.textContent = ''
  modalCtB.textContent = ''
  modalCtR.textContent = ''
  resetCorrespondence()
  animator.clearTransmission()
  if (lastRequestEl && reqPreviewEl) {
    lastRequestEl.hidden = true
    reqPreviewEl.textContent = ''
  }
  resultBar.classList.remove('revealed')
  computeButton.disabled = true
  reencryptButton.disabled = true
  clearError()
  state.setState('READY')
})

/* ── Local multiply bench ──────────────────────────────────────────────────
 * The Oracle does the add. This does the multiply — locally, with no network,
 * on a scheme small enough to run in the tab (see src/toyFhe.ts). Every cell in
 * the table is measured from the chain: what the ciphertext decrypted to, what
 * it should have been, how many bits of noise it is carrying, and how many bits
 * of budget remain. The learner is the one who spends the budget.
 */

let toyChain: ToyChain | null = null
const toySteps: ChainStep[] = []

function readToyOperands(): { a: number; b: number } {
  const clamp = (raw: string, fallback: number): number => {
    const n = Number(raw)
    if (!Number.isInteger(n) || n < 0 || n > 255) return fallback
    return n
  }
  return { a: clamp(toyAInput.value, 12), b: clamp(toyBInput.value, 21) }
}

function toyVerdictFor(step: ChainStep): string {
  if (step.withinBudget) {
    return step.correct
      ? 'correct — inside budget'
      : 'WRONG despite budget — this should not happen'
  }
  return step.correct ? 'outside budget, observed match' : 'WRONG — noise passed the ceiling'
}

function renderToyChain(): void {
  toyRowsEl.innerHTML = toySteps
    .map((step) => {
      const cls = step.withinBudget ? (step.correct ? 'toy-ok' : 'toy-bad') : 'toy-bad'
      const label = step.op === 'encrypt' ? 'Enc(a)' : step.op === 'add' ? '+ Enc(b)' : '× Enc(b)'
      return `<tr class="${cls}">
        <th scope="row">${step.index}</th>
        <td>${label} → <code>${step.expression}</code></td>
        <td>${step.noiseBits} / ${step.budgetBits} bits${step.withinBudget ? '' : ' <strong>OVER</strong>'}</td>
        <td>${step.ciphertextDigits} digits</td>
        <td>${step.decrypted}</td>
        <td>${step.expected}</td>
        <td>${toyVerdictFor(step)}</td>
      </tr>`
    })
    .join('')

  const last = toySteps[toySteps.length - 1]
  toyCaptionEl.textContent = last
    ? `Unsigned budget: 0 ≤ noise < p, where p = ${toyChain!.key.p} (${TOY_P_BITS} bits). ` +
      `The table shows bit lengths; verdicts use exact integers. ${toySteps.length} step(s) so far.`
    : 'No chain yet.'

  if (!last) {
    toyVerdictEl.hidden = true
    toyVerdictEl.textContent = ''
    return
  }

  const multiplies = toySteps.filter((s) => s.op === 'multiply').length
  const adds = toySteps.filter((s) => s.op === 'add').length
  const firstBroken = toySteps.find((s) => !s.withinBudget)
  toyVerdictEl.hidden = false
  toyVerdictEl.classList.toggle('toy-verdict-bad', Boolean(firstBroken))
  if (!firstBroken) {
    toyVerdictEl.textContent =
      `${multiplies} multiplication(s) and ${adds} addition(s) done under encryption, ` +
      `every one decrypting to exactly the plaintext answer. Noise is at ${last.noiseBits} of ` +
      `${last.budgetBits} bits. Keep multiplying.`
    return
  }
  toyVerdictEl.textContent =
    `The budget ran out at step ${firstBroken.index}: noise reached ${firstBroken.noiseBits} bits ` +
    `against a ceiling of ${firstBroken.budgetBits}. That step decrypted to ${firstBroken.decrypted} ` +
    `where the plaintext answer is ${firstBroken.expected}` +
    (firstBroken.correct
      ? ' — an observed match outside the no-wrap interval, not a general correctness guarantee.'
      : '.') +
    ' This scheme has no bootstrapping or noise refresh. Some later wrap counts can preserve the ' +
    'low byte, but arbitrary later operations are no longer guaranteed correct. TFHE uses ' +
    'programmable bootstrapping to refresh its own ciphertexts; this tiny model does not implement it.'
}

function toyApply(op: 'add' | 'multiply'): void {
  const { a, b } = readToyOperands()
  if (!toyChain) {
    toyChain = new ToyChain(a)
    toySteps.length = 0
    toySteps.push(toyChain.start())
  }
  toySteps.push(toyChain.apply(op, b, 'b'))
  const last = toySteps[toySteps.length - 1]
  toyStatusEl.textContent =
    `Step ${last.index}: ${op === 'multiply' ? 'multiplied' : 'added'} under encryption. ` +
    `Decrypted ${last.decrypted}, expected ${last.expected}. ` +
    `Noise ${last.noiseBits} of ${last.budgetBits} bits${last.withinBudget ? '.' : ' — over the ceiling.'}`
  renderToyChain()
}

function toyReset(): void {
  toyChain = null
  toySteps.length = 0
  toyStatusEl.textContent = 'Bench idle. Press an operation to encrypt a and start a chain.'
  renderToyChain()
}

toyMulBtn.addEventListener('click', () => toyApply('multiply'))
toyAddBtn.addEventListener('click', () => toyApply('add'))
toyResetBtn.addEventListener('click', toyReset)
// Changing the operands starts a fresh chain rather than silently continuing
// one built from different numbers.
toyAInput.addEventListener('change', toyReset)
toyBInput.addEventListener('change', toyReset)

void boot()
