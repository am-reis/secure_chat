# Security

## Status: pre-audit, not production ready

This is a from-scratch implementation of a PQXDH + Double Ratchet secure
messaging protocol. It has **not** undergone a third-party security audit.
Do not use it to protect real communications until it has.

What exists today toward that eventually happening:

- **Phase 28** — an adversarial test suite: tampering (ciphertext, header,
  associated data), replay, out-of-order/reordering, signature/prekey
  substitution, malformed input, transport faults (drop, duplicate, delay,
  corrupt, partition).
- **Phase 29** — property-based tests (`fast-check`) running the protocol's
  core correctness/security properties over hundreds of randomized inputs
  each, not just hand-picked examples.
- **Phase 30** — crash-recovery tests, including one that formalized a real
  defect (see the "Required reading" section of [README.md](README.md) and
  [CHANGELOG.md](CHANGELOG.md)) before it was fixed.
- **Security invariants** — [docs/security-invariants.md](docs/security-invariants.md)
  maps each of Phase 32's ten invariants to exactly what enforces it and
  exactly what proves that enforcement holds (a runtime test, a type-level
  guarantee, or a documented inspection), honestly noting the one place a
  gap existed (Invariant 3's global skipped-key cap had no test until
  writing this document surfaced that) instead of glossing over it.
- **Fuzzing** — `test/fuzz/` runs random/malformed bytes at volume against
  the three boundaries where attacker- or corruption-controlled input first
  reaches this codebase (wire-format decode, persisted-session decrypt,
  prekey bundle validation). It has already found one genuine, non-obvious
  (if benign) design property worth knowing: `validatePreKeyBundle` does
  not and cannot reject a corrupted one-time prekey, because that field
  isn't signed in the wire format at all — its integrity is instead
  enforced downstream, by PQXDH's own DH computation making the two
  parties' derived session keys diverge on a tampered OTK. See the
  README's "Fuzzing" entry for the full explanation and the test that
  proves the downstream guarantee actually holds.

**Known current issue — not this project's own code, but worth stating
plainly rather than leaving to `npm audit`:** `@waku/sdk` (added for
`RealWakuTransport`, Phase 20/33) pulls in a `uuid` version with a
moderate-severity advisory (missing bounds check when a buffer is
explicitly supplied — [GHSA-w5hq-g745-h8pq](https://github.com/advisories/GHSA-w5hq-g745-h8pq)),
transitively via `@waku/core`/`@waku/discovery`. No fix is published
upstream as of this writing. This project's own cryptographic code never
calls into `uuid`; the exposure, if any, is entirely inside js-waku's own
internals. Re-run `npm audit` before deploying `RealWakuTransport` and
check whether this has since been resolved upstream.

All 8 of Phase 31's audit-preparation documents now exist, under
`docs/audit/`:

1. [Threat model](docs/audit/threat-model.md) — every Phase 0 adversary
   capability mapped to its actual defense, plus an honest "out of
   scope" section (live device compromise, transport metadata, first-
   contact bundle authenticity, side channels, multi-device).
2. [Cryptographic design document](docs/audit/cryptographic-design.md) —
   every KDF/AEAD/AD construction with exact formulas and source
   pointers.
3. [Protocol state machine](docs/audit/protocol-state-machine.md) —
   session state (deliberately binary, no partial states), ratchet field
   validity, envelope routing, and the Phase 25 delivery-state model
   (specified, not implemented at this layer).
4. [Wire format specification](docs/audit/wire-format.md) — the protobuf
   envelope, field by field, plus the canonical byte encoding used for
   every signed/AD payload.
5. [Key lifecycle specification](docs/audit/key-lifecycle.md) — every key
   type's generation/rotation/destruction, including a real gap found
   while writing it (skipped message keys have no time-based expiry,
   only size bounds).
6. [Persistence specification](docs/audit/persistence-spec.md) — the
   at-rest format, AEAD-at-rest scheme, and the outbox write-ahead
   mechanism.
7. [Test vector suite](docs/audit/test-vector-suite.md) — which
   primitives are checked against independently-sourced vectors (X25519
   against RFC 7748, HKDF/HMAC live-cross-checked against Node's own
   implementation) versus self-consistency only (**ML-KEM-1024 has no
   independent vectors at all** — the same primitive
   `@noble/post-quantum`'s own audit gap applies to).
8. [Dependency inventory](docs/audit/dependency-inventory.md) — every
   runtime dependency's independent-audit status, verified directly
   from each project's own current documentation. **The single most
   important finding across all 8 documents**: `@noble/post-quantum`
   (ML-KEM-1024 — the entire reason this protocol is post-quantum) has
   **not** been independently audited.

These are audit *preparation* — they make an eventual third-party review
tractable and give it a documented starting point. **They are not a
substitute for that review actually happening.** The status at the top
of this document doesn't change until it does.

## Design principles this codebase tries to hold to

- **No hand-rolled cryptography.** `CryptoProvider` wraps audited
  `@noble/*` libraries only — no custom KDFs, no reimplemented curve
  arithmetic, no custom signature schemes.
- **Fail closed, not open.** A failed AEAD decrypt, a bad signature, or a
  malformed envelope must never partially mutate session state — see the
  Double Ratchet's clone-then-commit pattern in
  `src/ratchet/DoubleRatchet.ts` and the same principle applied to
  `SessionManager.receiveSessionReset` (Phase 19).
- **Domain-separated signatures.** Every signed payload (signed prekeys, PQ
  prekeys, session resets) is bound to a distinct domain-separation label,
  so a valid signature in one context can never be replayed as valid in
  another — see `src/prekeys/signing.ts` and `src/session/reset.ts`.
- **Never trust an unauthenticated trigger to create or destroy state.** An
  unknown session cannot be created from an arbitrary `MESSAGE` envelope
  (Phase 23), and a live session cannot be destroyed by an unauthenticated
  `SESSION_RESET` (Phase 19) — both are real denial-of-service surfaces if
  relaxed.
- **Secrets are erased, not just dropped.** Root keys, chain keys, DH
  private keys, and skipped message keys are zeroed via
  `CryptoProvider.secureErase` once consumed or superseded, not left for
  the garbage collector.

## Reporting a vulnerability

This repository is public (`github.com/am-reis/secure_chat`) and the
package is in the process of being published to npm, but it's still
pre-audit (see the top of this document) and doesn't yet have a formal
disclosure process set up (no dedicated security contact address, no
GitHub Private Vulnerability Reporting configured yet). If you've found a
security issue, please do **not** open a public GitHub issue or otherwise
disclose it publicly before it's been addressed — reach out to the
maintainer (`am-reis`) privately instead.
