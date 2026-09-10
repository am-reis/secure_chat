# Security Invariants

Phase 32 of [spec.md](spec.md) lists ten invariants this implementation must
preserve. This document is item 7 of Phase 31's security-audit-preparation
list: each invariant mapped to exactly what enforces it and exactly what
proves that enforcement holds, rather than left as an assertion in prose.

Three different kinds of evidence appear below, and each entry says which
kind it is:

- **Runtime-tested** — a test actually exercises the failure mode and
  asserts the invariant held.
- **Structural** — enforced by the type system or a function signature that
  makes the violation impossible to express, not just unlikely.
- **Verified by inspection** — a property of what code does *not* do
  (never logs a key, never touches the transport layer), confirmed here by
  a repo-wide search rather than a positive runtime assertion, because
  there's no failure mode to trigger and observe.

Where a gap exists, it's stated as a gap, not glossed over — see
Invariant 3's note on how this document itself found one.

---

## 1. A message key is never reused

**Runtime-tested.** A message key is deleted from `skippedMessageKeys`
the instant it's used (`state.skippedMessageKeys.delete(skippedIdx)`,
[`src/ratchet/DoubleRatchet.ts:277`](../src/ratchet/DoubleRatchet.ts)), and
the normal chain-advancement path only ever moves forward via `KDF_CK`
(one-way by construction — see Invariant 2). A second decrypt attempt with
the same `(ratchetPublicKey, messageNumber)` has no key left to find.

- [`test/ratchet/DoubleRatchet.test.ts:299`](../test/ratchet/DoubleRatchet.test.ts) — "a replayed (already-consumed) message fails without changing state"
- [`test/ratchet/DoubleRatchet.test.ts:312`](../test/ratchet/DoubleRatchet.test.ts) — "replaying a skipped-and-since-consumed message fails without changing state"
- [`test/property/ratchet.property.test.ts:148`](../test/property/ratchet.property.test.ts) — "Property: replay(message) -> not delivered twice", fuzzed over hundreds of random cases

## 2. A message key is never derived from plaintext

**Structural.** `kdfChainKey(provider: CryptoProvider, ck: Uint8Array)`
([`src/ratchet/kdf.ts:50`](../src/ratchet/kdf.ts)) takes only the current
chain key. There is no plaintext parameter anywhere in its signature or
`kdfRootKey`'s — a violation would have to be a different function
entirely, not a misuse of this one. No runtime test is meaningful here;
the type signature is the proof.

## 3. A remote party cannot force unbounded key derivation

**Runtime-tested**, two independent bounds:

- `MAX_SKIP` (1000) caps how many keys a *single* out-of-order message can
  force derived in one call — [`src/ratchet/DoubleRatchet.ts:186-190`](../src/ratchet/DoubleRatchet.ts).
  [`test/ratchet/DoubleRatchet.test.ts:205`](../test/ratchet/DoubleRatchet.test.ts) — "rejects a message that skips further than MAX_SKIP"
- `MAX_STORED_SKIPPED_KEYS` (2000) is a separate, global, *cumulative*
  bound across the whole session's lifetime — [`src/ratchet/DoubleRatchet.ts:194-198`](../src/ratchet/DoubleRatchet.ts).
  [`test/ratchet/DoubleRatchet.test.ts` — "rejects skipping past the global MAX_STORED_SKIPPED_KEYS cap, even spread across multiple calls each individually under MAX_SKIP"](../test/ratchet/DoubleRatchet.test.ts)

**Gap found and closed while writing this document**: the global cap was
enforced in code from the start, but until now had no test at all — only
the per-call `MAX_SKIP` bound did. Without the second bound, a remote party
sending a slow drip of individually-small out-of-order messages (each
comfortably under `MAX_SKIP`) could have grown `skippedMessageKeys`
unboundedly across many calls, and nothing would have caught a regression
that broke the cap. The test above was added specifically to close that.

## 4. Failed AEAD authentication does not permanently mutate session state

**Runtime-tested.** `ratchetDecrypt` derives everything on a cloned working
state and only commits (`commitState`,
[`src/ratchet/DoubleRatchet.ts:169`](../src/ratchet/DoubleRatchet.ts)) after
the AEAD decrypt actually succeeds — this makes "no partial mutation on
failure" structural, not best-effort, and Invariant 4 is provable by
snapshotting full state before/after every adversarial case rather than
checking a handful of fields.

- [`test/ratchet/DoubleRatchet.test.ts:265`](../test/ratchet/DoubleRatchet.test.ts) — `describe("Double Ratchet — Invariant 4: failed AEAD auth never mutates state")`, covering tampered ciphertext (with and without a pending DH ratchet), tampered header, tampered AD, and replay — each asserting a full state snapshot is byte-identical before and after the rejected attempt
- The same principle, applied one layer up: [`test/session/SessionManager.test.ts:178`](../test/session/SessionManager.test.ts) — "a corrupted initial ciphertext leaves no session registered and releases the reserved OTK" (Phase 5.3)
- And again at the identity-key layer (Phase 19): [`test/session/sessionReset.test.ts:138`](../test/session/sessionReset.test.ts) — "rejects a forged reset (wrong signature) and leaves the session intact"

## 5. A consumed one-time prekey cannot be reused

**Runtime-tested.** The atomic `AVAILABLE → RESERVED → CONSUMED` lifecycle
([`src/prekeys/PrekeyStore.ts`](../src/prekeys/PrekeyStore.ts),
[`InMemoryPrekeyStore.ts`](../src/prekeys/InMemoryPrekeyStore.ts)) has no
transition back to `AVAILABLE` from `CONSUMED`.

- [`test/prekeys/prekeyStore.test.ts:91`](../test/prekeys/prekeyStore.test.ts) — "consuming an already-consumed key throws (Invariant 5: cannot reuse a consumed key)"
- [`test/session/SessionManager.test.ts:159`](../test/session/SessionManager.test.ts) — Phase 16's idempotent-retransmission test confirms a replayed `SESSION_INIT` consumes the OTK exactly once, not once per delivery attempt

## 6. Old message keys are deleted

**Runtime-tested at the primitive level, verified by inspection at every
call site.** `secureErase` actually zeroes the backing buffer in place
(not just drops the reference):
[`test/crypto/CryptoProvider.test.ts:314`](../test/crypto/CryptoProvider.test.ts)
— "secureErase zeroizes a buffer in place". Every point in the ratchet
where a key is superseded or consumed calls it: old chain keys
([`DoubleRatchet.ts:117`](../src/ratchet/DoubleRatchet.ts)), message keys
after use ([`:129`](../src/ratchet/DoubleRatchet.ts),
[`:312`](../src/ratchet/DoubleRatchet.ts)), consumed skipped keys
([`:274`](../src/ratchet/DoubleRatchet.ts)), and everything superseded by a
DH ratchet step, erased on commit
([`:170`](../src/ratchet/DoubleRatchet.ts)). Session-level destruction
(Phase 19's `resetSession`/`receiveSessionReset`,
[`src/session/SessionManager.ts`](../src/session/SessionManager.ts)) erases
the root key, both chain keys, the DH private key, and every remaining
skipped key the same way.

There is no single test asserting "every key that should be erased, is,
across the whole codebase" — that would need to be re-derived by inspection
each time this changes. What's tested is that the primitive itself does
what it claims; what's inspectable is that every consumption site calls it.

## 7. Ratchet private keys are never serialized into logs

**Verified by inspection.** There are zero `console.*`/logger calls
anywhere under `src/` — confirmed by a repo-wide search at the time this
document was written. There is nothing to log a key *into*. This is worth
re-verifying (`grep -rn "console\.\|logger\." src/`) whenever logging is
added to this codebase for the first time, and worth eventually enforcing
with a lint rule rather than a one-time manual check — see the open items
in [SECURITY.md](../SECURITY.md).

## 8. Identity private keys never enter the transport layer

**Structural, verified by inspection.** `PublicIdentity`
([`src/identity/types.ts`](../src/identity/types.ts)) — the only identity
projection anything in `src/transport/` or a wire envelope ever carries —
has no field that could hold a private key; `SessionInitEnvelope` only
carries `senderIdentityPublicKey`. A repo-wide search for `privateKey`
under `src/transport/` returns zero matches.

## 9. Transport metadata is never assumed confidential

**Design decision, documented at the point it's applied.** Content topics
are shared across all sessions and all users of the application
specifically so an observer of the pubsub topic learns nothing about who
is messaging whom — see the design-rationale comment in
[`src/transport/contentTopics.ts`](../src/transport/contentTopics.ts).
Recipient routing happens entirely inside the encrypted envelope
(`sessionId`), never in topic strings or other transport-visible metadata.

## 10. The application never directly manipulates ratchet state

**Structural.** `SessionManager`'s public surface
(`createSession`/`sendMessage`/`receiveMessage`,
[`src/session/SessionManager.ts`](../src/session/SessionManager.ts)) only
ever takes or returns plaintext `Uint8Array` and opaque `Session` handles —
`DoubleRatchetState`, `rootKey`, `chainKey`, and DH private keys never
appear in that surface's types. `src/receipts/applicationContent.ts` (which
also carries Phase 24's attachment descriptors) exists specifically because
content structure has to live *above* this boundary, not inside it — see
the design-rationale comments at
[`SessionManager.ts:43`](../src/session/SessionManager.ts) and
[`applicationContent.ts:15`](../src/receipts/applicationContent.ts).
