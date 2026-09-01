# Secure Messaging Protocol — Core

Transport-agnostic PQXDH + Double Ratchet secure messaging protocol core, per
`docs/spec.md`. Built in-memory-first per the spec's Phase 33 implementation
order: no UI, no transport (Waku) integration yet — just the cryptographic
protocol, tested against real, independently-verified test vectors.

## Status

Implemented and tested (see commit history for the phase each one landed in):

- **Phase 1 — CryptoProvider**: abstraction over X25519, Ed25519, ML-KEM-1024,
  HKDF-SHA512, XChaCha20-Poly1305, backed by audited `@noble/*` libraries.
  Primitive tests cross-checked against RFC 7748 vectors, Node's independent
  OpenSSL-backed HKDF/SHA-256, and Python's `hashlib` — not hand-typed
  "known" constants trusted from memory alone.
- **Phase 2 — Identity**: identity generation, `identityId` derivation,
  symmetric out-of-band verification fingerprint.
- **Phase 3 — Prekey infrastructure**: signed EC/PQ prekeys with a signing
  scheme that binds id+publicKey (not just the key), one-time prekeys with an
  atomic `AVAILABLE → RESERVED → CONSUMED` lifecycle store.
- **Phase 4 — Prekey bundle**: canonical wire structure + full six-step
  validation pipeline (version, lengths, encodings, both signatures, id
  sanity), with adversarial tests for tampering, substitution, and
  cross-domain signature reuse.
- **Phase 5 — PQXDH**: initiator/responder session establishment, using the
  *exact* KDF construction from Signal's real PQXDH spec (fetched and
  verified, not reconstructed from memory) — not the ad-hoc
  `HKDF(DH1‖DH2‖DH3‖SS)` the spec explicitly warns against. Verified
  end-to-end: initiator and responder independently derive byte-identical
  `SK`/`AD`.

Not yet built: Double Ratchet (Phase 6) onward — see `docs/spec.md`'s
Phase 33 implementation order for what's next. PQXDH is deliberately scoped
to SK/AD derivation only for now; full initial-message envelope assembly
depends on the Double Ratchet existing first (the "initial ciphertext" *is*
the first Double Ratchet message per the real spec).

## Structure

```
src/
  crypto/       CryptoProvider abstraction + Noble-backed implementation
  encoding/      Deterministic canonical byte encoding (length-prefixed,
                 unambiguous — used for every signed/AEAD-authenticated structure)
  identity/      Long-term identity, identityId, verification fingerprint
  prekeys/       Signed/PQ/one-time prekeys, PrekeyStore, PreKeyBundle + validation
  pqxdh/         PQXDH initiator/responder, KDF, associated data
  errors.ts      Shared protocol error taxonomy (Phase 17 codes)
test/            Mirrors src/, one test file per module
```

## Build / test

```bash
npm install
npm run typecheck   # tsc --noEmit, src + test
npm test             # vitest run
```

All tests currently pass (129 as of Phase 5). No network access is required
to run the tests — the RFC/NIST vectors baked into the crypto tests were
verified against independent implementations (Node's `crypto`, Python's
`hashlib`) at the time they were written, not fetched at test time.

## Design decisions worth knowing before extending this

- **Identity keys are dual-use.** `Identity.keyPair` is a single Ed25519
  keypair; PQXDH's DH1/DH2 need it as an X25519 key too. `CryptoProvider`
  exposes `x25519PrivateFromIdentity`/`x25519PublicFromIdentity` (a
  standard Edwards↔Montgomery birational map) rather than implementing
  Signal's XEdDSA construction bit-for-bit. See the note in
  `src/identity/types.ts`.
- **Signed prekeys do NOT bind `expiresAt` into their signature.** The wire
  `PreKeyBundle` never transmits `expiresAt`, so a recipient couldn't
  reconstruct that payload anyway — expiry is local rotation policy, not a
  cryptographically authenticated property. See `src/prekeys/signing.ts`.
- **AEAD (`aeadEncrypt`/`aeadDecrypt`) is XChaCha20-Poly1305** with a
  randomly generated nonce prepended to the ciphertext output — the
  `CryptoProvider` interface has no separate nonce parameter, so nonce
  management is entirely internal to the primitive layer.
- **`PrekeyStore`'s atomicity is currently process-local**, relying on
  JavaScript's synchronous execution model (no `await` point between a
  reservation's check and its transition). A persistent (Phase 13) backend
  MUST implement `reserve` as a single atomic transaction — see the doc
  comment in `src/prekeys/PrekeyStore.ts` for exactly what that requires.
