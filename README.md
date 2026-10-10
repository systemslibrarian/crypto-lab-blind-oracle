# crypto-lab-blind-oracle

## What It Is

Blind Oracle is a browser-to-server demonstration of **Fully Homomorphic Encryption** using [TFHE-rs](https://github.com/zama-ai/tfhe-rs) and programmable bootstrapping (PBS) over encrypted `FheUint8` values. An `FheUint8` is radix-decomposed into shortint blocks and each block operation runs a PBS; _gate_ bootstrapping is the term for TFHE's boolean API, which this demo does not use. The client encrypts two inputs, the server performs homomorphic addition, and the client decrypts the encrypted result locally. This solves the problem of outsourcing computation while keeping plaintext hidden from the compute provider. The security model is asymmetric homomorphic encryption (public evaluation key on the server, secret decryption key kept client-side), with post-quantum lattice-based foundations through TFHE.

### Why one step runs off-device

Every crypto-lab demo is browser-only, and this one is the exception in exactly one place: the homomorphic **add** runs on a small remote service. That is not a shortcut. Zama's browser (WASM) build of TFHE-rs exposes key generation, encryption, decryption and serialization — and no evaluation operations at all: there is no `add`, `mul` or any other homomorphic method on `FheUint8` in the bundled `tfhe.d.ts`, and `set_server_key` has nothing to apply. The evaluation therefore has to happen where the TFHE-rs evaluation API exists. That split is also, conveniently, the real FHE deployment shape: a client that holds the secret key, and a compute provider that holds only an evaluation key.

Two things follow, and the demo now does both:

- **A remote dependency must degrade, not dead-end.** If the Oracle is asleep, redeployed, or gone for good, the page offers _Continue without the Oracle_ and keeps everything local working — key generation, encryption, the ciphertext inspector, and the local multiply bench — with a banner naming exactly which one step is unavailable.
- **A multiplication that is only described is not demonstrated.** The **local multiply bench** performs real homomorphic multiplications in the tab, on a second (deliberately tiny) scheme, and lets you keep going until the noise budget runs out.

### The local multiply bench

`src/toyFhe.ts` implements a DGHV-inspired (van Dijk–Gentry–Halevi–Vaikuntanathan, 2010) unsigned, base-256 teaching model: `Enc(m) = m + 256r + qp`, `Dec(c) = (c mod p) mod 256`. Addition adds the tracked noise term; multiplication multiplies it. The decoder reduces into `[0,p)`, so the exact first no-wrap interval is `0 ≤ noise < p`, including the entire interval between `p/2` and `p`. The table displays bit lengths, while the verdict checks exact integers; equal bit lengths alone do not establish whether noise is below `p`. With the default parameters, hundreds of additions stay inside this interval while the **third** multiplication crosses it. Each step reports actual decryption against the expected plaintext byte.

**Toy scale, stated on the page and here:** the original paper's security analysis does not apply to this tiny 48-bit adaptation. This is not secure encryption and must never be used as such. [DGHV 2010, §2](https://www.uvm.edu/~cvincen1/files/teaching/pcmi/DGHV2010.pdf) defines centered residues in `(-p/2,p/2]`; its `p/2` bound belongs to that decoder, not this unsigned byte model. At `noise = p` the first wrap changes the decoded byte. Beyond the no-wrap interval, particular wrap counts can preserve the byte (for example, 256 wraps because `p` is odd), but an observed match does not restore a general correctness guarantee. The bench demonstrates local noise growth and wrapping; it does not reproduce TFHE's parameters or implement programmable bootstrapping.

Verification includes fixed-key controls at `floor(p/2)`, `p-1`, `p`, `p+1`, negative noise and a matching byte after 256 wraps. A production-browser control runs the actual bench with scoped toy randomness after real TFHE key generation: 128 additions and two multiplications reach noise `129 × 8192³` between `p/2` and `p`; the next multiplication wraps and decodes to a demonstrably different byte. The backend compute endpoint is mocked in browser CI, so those controls do not establish remote-service availability or correct remote evaluation.

Beyond showing that the server's evaluation key cannot decrypt, the demo now makes the _mechanism_ visible: a side-by-side **plaintext world vs ciphertext world** panel runs both computations at once so the homomorphic correspondence `Enc(a) ⊞ Enc(b) → decrypt = a + b` is shown rather than asserted; **value-dependent ciphertext fingerprints** plus a **Re-encrypt same values** control demonstrate that TFHE encryption is probabilistic (same number, different ciphertext, still-correct sum); a **schematic wire** animates the actual payloads (`ct_a`, `ct_b`, `serverKey`, `ct_result`) crossing the trust boundary while the secret key stays pinned client-side; and a short **gate-bootstrapping / noise-budget** explainer plus an honest cost framing replace the earlier "unlimited computation depth" over-claim.

## When to Use It

- FHE is the right technique when arithmetic on sensitive values has to run on a server you do not trust with the plaintext, because with TFHE-rs the server computes directly on ciphertexts and only the key holder can decrypt the result.
- It suits privacy-preserving analytics, because the inputs sent to the server and the results it returns stay encrypted end to end.
- It suits multi-tenant compute where the provider should evaluate but never read, because the server key enables evaluation but not plaintext recovery.
- The Oracle behind this demo is for demonstration only and should never receive real sensitive values.
- Do not use it for low-latency, high-throughput production paths where plaintext processing is acceptable because bootstrapping and large ciphertexts add substantial performance overhead.
- Do NOT treat this as a production cryptographic service — it is a teaching demo with no authentication, rate limiting, or key rotation.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-blind-oracle](https://systemslibrarian.github.io/crypto-lab-blind-oracle/)**

Watch a server add two encrypted numbers: it holds an evaluation key that cannot decrypt, while your browser holds the decryption key and keeps the result verdict local. Enter two secret values in the 0–255 range, encrypt and transmit them, and trigger homomorphic addition on the oracle. The UI shows ciphertext previews with value-dependent fingerprints, a schematic of the payloads crossing the wire, the parallel plaintext-vs-ciphertext tracks that fill in as you compute, a gate-bootstrapping/noise explainer, response time (the price of one homomorphic add), the oracle log, and a modal showing exactly what the oracle received — without plaintext access. Below that, the **local multiply bench** does real homomorphic multiplications in your browser with no oracle at all, until the noise budget runs out. Controls: **SECRET VALUE A**, **SECRET VALUE B**, **ENCRYPT & TRANSMIT**, **RE-ENCRYPT SAME VALUES** (fresh randomness, different ciphertext), **COMPUTE (FHE ADD)**, **MULTIPLY — WHY SLOWER?** (explains the operation/cost tradeoff, and links to the local bench that performs one), **WHAT THE ORACLE SAW**, and **RESET**.

> First load generates an FHE key pair in your browser (~10–15s) — a boot overlay shows progress. On the free-tier backend, the oracle may also take a moment to wake from cold start.

Backend API source: <https://github.com/systemslibrarian/blind-oracle-api>

## What Can Go Wrong

- **Performance overhead:** FHE ciphertexts are large and bootstrapping is slow, so throughput and latency are far worse than plaintext computation.
- **Limited operations:** practical FHE supports a constrained set of operations and bit-widths (here, addition over `FheUint8`); arbitrary programs are expensive or infeasible.
- **No result integrity:** homomorphic evaluation hides inputs but does not by itself prove the server computed the right function — a malicious server could return a wrong-but-valid ciphertext.
- **Malicious-server feedback oracle:** a server can alter returned ciphertexts and learn from a client that reports decryption errors. Chaturvedi et al. demonstrated full key recovery against TFHE/FHEW under repeated client feedback, which does not demonstrate a break of this demo. Blind Oracle compares the result in the browser and sends neither the plaintext nor its match/mismatch verdict back to the server. This closes that feedback path in the demonstrated flow, but does not establish side-channel resistance on the client. See the [original attack (ePrint 2022/1563)](https://eprint.iacr.org/2022/1563) and the [2025 survey (ePrint 2025/867)](https://eprint.iacr.org/2025/867).
- **Metadata still leaks:** request timing, ciphertext sizes, and access patterns remain visible to the server even though plaintext does not.
- **Client-side key management:** security depends entirely on the client key never leaking — lose it and the data is unrecoverable, expose it and confidentiality is gone.
- **The Oracle is a free-tier service and can be unavailable.** The demo handles that explicitly (degraded mode) rather than pretending otherwise, but the headline add genuinely does require it.
- **The local bench is a teaching model, not secure encryption.** Its 48-bit DGHV-inspired modulus is trivially breakable. The unsigned no-wrap interval applies to this local model, not to TFHE's parameters or security.

## Real-World Usage

- FHE targets privacy-preserving cloud computation, where a provider processes ciphertext without a decryption key; application-level feedback and side channels still require separate controls.
- Use cases include encrypted machine-learning inference and private analytics over sensitive records.
- Private database and set queries can be served without revealing the query or contents to the server.
- TFHE-rs (Zama) is an actively developed library bringing FHE to practical experimentation, though real deployments remain early and specialized.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-blind-oracle
cd crypto-lab-blind-oracle
npm install
npm run dev
```

In development, `/api` is proxied to the hosted backend via Vite (see `vite.config.ts`), so the demo works out of the box. To point at a different backend, set `VITE_API_URL` (for example in `.env.development`). TFHE-rs requires `SharedArrayBuffer`, which needs a cross-origin-isolated context; the bundled `coi-serviceworker` sets the required COOP/COEP headers automatically on GitHub Pages and `vite dev`.

## Related Demos

- [crypto-lab-ckks-lab](https://systemslibrarian.github.io/crypto-lab-ckks-lab/) — CKKS approximate FHE for encrypted inference.
- [crypto-lab-fhe-arena](https://systemslibrarian.github.io/crypto-lab-fhe-arena/) — BGV/BFV with noise budget and SIMD batching.
- [crypto-lab-paillier-gate](https://systemslibrarian.github.io/crypto-lab-paillier-gate/) — additively homomorphic encryption for private aggregation.
- [crypto-lab-elgamal-plain](https://systemslibrarian.github.io/crypto-lab-elgamal-plain/) — ElGamal homomorphism and re-randomization.

## How It Works

```
┌──────────────────────────┐         encrypted wire          ┌──────────────────────────┐
│        YOUR BROWSER       │   ── ct_a, ct_b, serverKey ──▶  │       THE BLIND ORACLE     │
│                          │                                  │                          │
│  client key (secret) ◀── never leaves the browser          │  server key (evaluation)  │
│  encrypt a, b → ct       │                                  │  ct_result = ct_a ⊞ ct_b  │
│  decrypt ct_result → sum │   ◀──────── ct_result ───────    │  plaintext never accessed │
└──────────────────────────┘                                  └──────────────────────────┘
```

1. **Key generation** — the browser builds a TFHE config and generates a client key (secret) plus a compressed server key (evaluation only).
2. **Encrypt** — values `a` and `b` are encrypted to `FheUint8` ciphertexts; only ciphertext (and the public server key) crosses the wire.
3. **Compute** — the server runs `ct_a + ct_b` homomorphically with a programmable bootstrap on every block operation, and returns `ct_result`.
4. **Decrypt** — the browser decrypts `ct_result` with the client key. The server never sees a plaintext.

### Source layout

| File                  | Responsibility                                                                                                                                                |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/main.ts`         | UI wiring, app state transitions, boot overlay, event handlers                                                                                                |
| `src/clientFhe.ts`    | TFHE-rs WASM: key generation, encryption, decryption                                                                                                          |
| `src/toyFhe.ts`       | Toy DGHV scheme powering the local multiply bench: encrypt/add/multiply/decrypt plus exact noise-budget tracking (unit-tested)                                |
| `src/apiClient.ts`    | Typed fetch client for the oracle, with timeouts and error taxonomy                                                                                           |
| `src/encoding.ts`     | Pure base64/hex helpers, FheUint8 range validation, and a non-cryptographic ciphertext fingerprint used only to render value-dependent swatches (unit-tested) |
| `src/stateMachine.ts` | Minimal observable state machine driving the UI (unit-tested)                                                                                                 |
| `src/animations.ts`   | Canvas "wire" effect and count-up, both reduced-motion aware                                                                                                  |
| `src/oracleLog.ts`    | Append-only activity log rendering                                                                                                                            |

## Scripts

| Script                 | What it does                                                                                       |
| ---------------------- | -------------------------------------------------------------------------------------------------- |
| `npm run dev`          | Start the Vite dev server                                                                          |
| `npm run build`        | Type-check and build for production                                                                |
| `npm run preview`      | Serve the production build locally                                                                 |
| `npm test`             | Run the Vitest unit suite                                                                          |
| `npm run test:watch`   | Run tests in watch mode                                                                            |
| `npm run typecheck`    | Type-check without emitting                                                                        |
| `npm run format`       | Format the codebase with Prettier                                                                  |
| `npm run format:check` | Verify formatting (used in CI)                                                                     |
| `npm run test:a11y`    | Playwright: axe WCAG A/AA scans plus the functional Oracle, degraded-mode and multiply-bench specs |
| `npm run deploy`       | Request the existing gated main-branch publishing workflow                                         |

## Security Notes

- **The client key never leaves the browser.** Only the _compressed server key_ (an evaluation key that cannot decrypt) and ciphertexts are transmitted.
- **Original plaintext values are never sent.** They are held in memory client-side purely so the UI can confirm the decrypted sum.
- **The local comparison is not sent back.** Neither a decryption error nor the match/mismatch verdict is reported to the Oracle. A production client must preserve this boundary when handling malicious results.
- The client asserts the oracle's `plaintextAccessed === false` policy flag on every response and surfaces an error otherwise.
- This is a teaching demo. It does not implement authentication, rate limiting, or key rotation, and should not be treated as a production cryptographic service.

## Tech Stack

TypeScript · Vite · [TFHE-rs](https://github.com/zama-ai/tfhe-rs) (Zama) WebAssembly · Vitest · Prettier · GitHub Actions · GitHub Pages.

## License

[MIT](./LICENSE)

---

_Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite._

_"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31_
