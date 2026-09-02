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
- **Phase 6 + 8 — Double Ratchet, with out-of-order/skipped messages**:
  the real Double Ratchet spec (also fetched and verified), consolidating
  Phase 6 and Phase 8 into one pass since skipped-key handling isn't
  meaningfully separable from `RatchetDecrypt` — trying skipped keys first
  is step one of the real algorithm. `ratchetDecrypt` derives everything on
  a cloned working state and only commits after the AEAD decrypt actually
  succeeds, so the spec's "failed messages must not mutate state"
  requirement is structural, not best-effort — verified by a dedicated test
  suite asserting a full state snapshot is byte-identical before/after every
  adversarial failure case.
- **Phase 9 + 14 + 16 + 23 — SessionManager**: the integration glue Phase 5
  and Phase 6 each deliberately left unconnected. `createSession` runs
  PQXDH, initializes the Double Ratchet, and encrypts the first message in
  one call; `receiveMessage` implements the Phase 22/23 routing rules
  (unknown session + `MESSAGE` is rejected outright; unknown session +
  `SESSION_INIT` runs the full responder flow; an already-known session's
  repeated `SESSION_INIT` converges on the same session instead of creating
  a second one, per Phase 16). The one-time prekey commit ordering from
  Phase 5.3 is preserved end-to-end: consumed only after the initial
  message actually decrypts, released on any failure.

**A real bug surfaced and got fixed here**: `ratchetInitBob`'s pseudocode
(`state.RK = SK`) is a direct assignment in Python with no aliasing
implications — but the equivalent JS/TS assignment aliases the caller's
buffer. A caller erasing `sk` right after ratchet init (correct key
hygiene) would silently zero out Bob's live root key. Every message from
Alice to Bob failed AEAD authentication until this was traced to that one
missing defensive copy. Notably, Phase 6's own test suite never exercised
this because it never happened to erase `sk` immediately after
`ratchetInitBob` — it took the SessionManager's real end-to-end handshake
(which does erase `sk` right after, on both sides, as it should) to surface
it. A regression test now lives in `test/ratchet/DoubleRatchet.test.ts`.
- **Phase 13 — encrypted-at-rest session persistence**: `serializeSession`/
  `deserializeSession` convert a live `Session` to/from a plain hex-string
  record (deliberately excluding the local identity's private key — only a
  reference id is stored, since identity and session persistence are
  separate concerns). `encryptSessionRecord`/`decryptSessionRecord` AEAD-seal
  that record with the session id as associated data, so a swapped
  ciphertext under the wrong storage key fails to decrypt rather than
  silently loading the wrong session. `MasterKeyProvider` is an
  abstraction, not an implementation — real platform-keychain backing
  (Electron's `safeStorage`) is desktop-shell code, deliberately outside
  this portable core. The test that matters most here simulates an actual
  process restart (fresh store handle, fresh `SessionManager` instance,
  nothing else carried over) and proves messaging continues correctly in
  both directions afterward — Phase 34's literal "session state survives
  process restart" requirement, exercised end-to-end.

Not yet built: the Waku transport layer (Phase 20+) — see `docs/spec.md`'s
Phase 33 implementation order.

## Structure

```
src/
  crypto/       CryptoProvider abstraction + Noble-backed implementation
  encoding/      Deterministic canonical byte encoding (length-prefixed,
                 unambiguous — used for every signed/AEAD-authenticated structure)
  identity/      Long-term identity, identityId, verification fingerprint
  prekeys/       Signed/PQ/one-time prekeys, PrekeyStore, PreKeyBundle + validation
  pqxdh/         PQXDH initiator/responder, KDF, associated data
  ratchet/       Double Ratchet: state, KDF_RK/KDF_CK, encrypt/decrypt, header AD
  session/       SessionManager: PQXDH + Double Ratchet integration, envelopes
  persistence/   Encrypted-at-rest session storage (Phase 13)
  errors.ts      Shared protocol error taxonomy (Phase 17 codes)
test/            Mirrors src/, one test file per module
```

## Build / test

```bash
npm install
npm run typecheck   # tsc --noEmit, src + test
npm test             # vitest run
```

All tests currently pass (181 as of Phase 13 persistence). No network access
is required
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
- **The Double Ratchet's root KDF and PQXDH's KDF use opposite HKDF
  conventions on purpose** — PQXDH keys HKDF by a fixed salt with the
  secret as input key material; the ratchet's `KDF_RK` uses the running
  root key as the HKDF *salt* and the fresh DH output as the *input key
  material*. Both are correct per their respective specs; it's just easy to
  transpose them by habit. See `src/ratchet/kdf.ts`.
