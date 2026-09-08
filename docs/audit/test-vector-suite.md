# Test Vector Suite

Phase 31, item 9 of [docs/spec.md](../spec.md): "independently sourced,
not just self-consistent." This document catalogs exactly how each
primitive in `test/crypto/CryptoProvider.test.ts` is verified — three
genuinely different methods are in use, with different strength
guarantees, and one primitive has **none** of them. Conflating "there are
tests" with "there are independently-sourced test vectors" is exactly
the gap this Phase 31 item exists to close, so this document is
deliberately precise about which method applies where.

## Method A: fixed, published test vectors (strongest — a known-answer
test against a public standard)

| Primitive | Source | What's checked |
|---|---|---|
| X25519 | RFC 7748 §5.2, test vectors 1 and 2 | Exact scalar/u-coordinate inputs from the RFC text produce the exact published output, byte-for-byte |
| SHA-256 | NIST/well-known vectors (empty string, `"abc"`) | Exact hash of fixed inputs matches the published/well-known digest |

Both were, per the test file's own comments, verified against the actual
RFC/standard text and independently cross-checked against this exact
library call before being hardcoded into the test — not typed from
memory and trusted. `src/crypto/constants.ts`'s `KEY_LENGTHS` similarly
documents that byte lengths were confirmed by introspecting the installed
`@noble/*` libraries directly rather than assumed.

## Method B: live cross-implementation comparison (strong — a
second, independent implementation agrees, every test run, not just once)

| Primitive | Compared against | What's checked |
|---|---|---|
| HKDF-SHA512 | Node's built-in `crypto.hkdfSync("sha512", ...)` | This project's `hkdfExtract`/`hkdfExpand` composition produces byte-identical output to Node's own OpenSSL-backed HKDF, for the same (randomly generated, fresh per test run) inputs |
| HMAC-SHA512 | Node's built-in `crypto.createHmac("sha512", ...)` | Same comparison, for HMAC |

This is arguably a *stronger* ongoing guarantee than a fixed vector in
one respect (it runs against fresh random inputs every single test
execution, not just once against one historical set of bytes) while
being weaker in another (it validates agreement between two
implementations, not agreement with a formally published standard
document the way an RFC vector does) — both properties matter and neither
subsumes the other.

## Method C: self-consistency only — **the gap this document exists to
surface**

| Primitive | What's actually tested | What's *not* tested |
|---|---|---|
| **ML-KEM-1024** | `encapsulate`/`decapsulate` round-trips to the same shared secret; a bit-flipped ciphertext produces implicit rejection (a *different*, unusable shared secret, per FIPS 203 — not a thrown error) | **No independently-sourced test vectors at all.** Nothing in this codebase's test suite checks ML-KEM-1024 output against NIST's own published FIPS 203 Known-Answer-Test (KAT) vectors, and nothing cross-checks it against a second, independent ML-KEM implementation the way HKDF/HMAC are cross-checked against Node's. |

This is the exact primitive `docs/audit/dependency-inventory.md` already
flags as the one unaudited library in this project's dependency tree —
the two gaps compound. `@noble/post-quantum`'s own README (see the
dependency inventory) mentions an independent reproducibility study
comparing its v0.7.0 against NIST's test vectors *at the library level*
— but that's a check on the upstream library by a third party, not
something this project's own test suite does or can independently
confirm without redoing that work.

**What closing this gap would take**: NIST publishes official FIPS 203
ML-KEM Known-Answer-Test vectors (deterministic keygen/encaps/decaps
given a fixed seed, expected outputs for `ML-KEM-1024` specifically).
Adding a KAT-based test would require either a deterministic
(seed-injectable) code path into `@noble/post-quantum`'s keygen — which
`CryptoProvider.generateKemKeyPair()` doesn't currently expose (it always
uses fresh randomness) — or driving the underlying library's KAT-mode
API directly in a dedicated test bypassing the `CryptoProvider`
abstraction for that one test. Either is a real, scoped piece of future
work, not something to silently skip at the actual audit.

## Everything else in `test/crypto/CryptoProvider.test.ts`

Rounds out the primitive suite with structural/property tests that don't
need external vectors to be meaningful (determinism, correct output
length, rejecting malformed-length inputs, AEAD round-trip/tamper/
wrong-key rejection, `secureErase` actually zeroing a buffer, DH
agreement between two independently generated keypairs) — these validate
*this codebase's own usage* of the underlying primitives is correct, a
different and complementary concern from "is the primitive itself
correct," which is what Methods A/B (and the gap in Method C) are about.

## Where protocol-level correctness is verified (not primitive-level,
listed here for completeness — see the individual test files, not
duplicated)

The primitive-level vectors above feed into, but are distinct from,
this project's protocol-level correctness proofs:

- `test/pqxdh/pqxdh.test.ts` — initiator and responder independently
  derive byte-identical `SK`/`AD` (Phase 28.2's "same shared secret, same
  authenticated data" requirement) — a protocol-level *agreement* check,
  not a primitive-level vector.
- `test/ratchet/DoubleRatchet.test.ts`, `test/property/ratchet.property.test.ts`
  — the Double Ratchet's own correctness and adversarial properties,
  fuzzed via `fast-check` rather than fixed vectors (appropriate here,
  since there's no external "Double Ratchet KAT" standard to check
  against — the real spec doesn't publish one the way NIST does for
  ML-KEM).
- `test/fuzz/` — genuinely random/malformed input at volume against the
  three untrusted-input boundaries (see `docs/audit/dependency-inventory.md`'s
  cross-reference and `CHANGELOG.md`'s Fuzzing entry).
