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

What's still outstanding before a real audit is meaningful (Phase 31 of
[docs/spec.md](docs/spec.md)):

1. Threat model (write-up, not just the informal notes in Phase 0)
2. Cryptographic design document
3. Protocol state machine diagram
4. Wire format specification
5. Key lifecycle specification
6. Persistence specification
7. Security invariants doc (Phase 32's list, with each one mapped to the
   test(s) that enforce it)
8. Test vector suite (independently sourced, not just self-consistent)
9. Dependency inventory (crypto libraries, provenance, version pinning)

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

This is currently a personal/internal project with no public release and no
external users. If you've found a security issue in code derived from this
repository, please reach out to the maintainer directly rather than opening
a public issue.
