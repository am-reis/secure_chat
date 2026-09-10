# Threat Model

Phase 31, item 1 of [docs/spec.md](../spec.md). `docs/spec.md`'s own
Phase 0 already defines this protocol's trust boundaries, assumed
adversary capabilities, and security goals — that's the *design*
threat model, written before implementation, as a constraint on it. This
document is the *audit-prep* elaboration: for every capability Phase 0
assumes an attacker has, where in the actual implementation that's
defended against (with a citation an auditor can go verify), and — just
as importantly — an honest accounting of what is genuinely **not**
defended against, or not defended against as fully as Phase 0's goals
would suggest.

## Assets

What this protocol exists to protect:

- **Message plaintext** — confidentiality against anyone but the intended
  recipient(s), including the transport and anyone who later compromises
  a device (forward secrecy for past messages).
- **Message integrity/authenticity** — a message that decrypts
  successfully really was sent by the claimed session peer, unmodified.
- **Identity private keys, ratchet private keys, message keys** —
  never transmitted (identity/ratchet), and message keys erased
  immediately after single use.
- **Session continuity** — an attacker who compromises a device at time
  T should not be able to silently intercept messages sent after the
  legitimate parties' next DH ratchet step (post-compromise recovery).

**Not** an asset this protocol protects, by design (see "Out of scope"
below): transport-level metadata (who is talking to whom, when, how
often), and anything beyond what's listed above once an endpoint device
is *actively, currently* compromised (an attacker reading plaintext off a
live, compromised device sees exactly what that device sees — no E2E
protocol changes that).

## Trust boundaries (from `docs/spec.md` Phase 0.1)

```
User Device
    │
    ├── Identity / Key Manager     ─┐
    ├── Prekey Manager               │  trusted — this device's own
    ├── PQXDH                        │  private key material never
    ├── Double Ratchet                │  leaves this boundary
    ├── Session Manager              │
    └── Persistence                 ─┘
             │
             │ encrypted envelope only
             ▼
           Waku            ── untrusted transport (Phase 0.1: "the Waku
                               network must be treated as an untrusted
                               transport")
```

The remote party's device is trusted with *its own* keys, not with this
device's — the entire protocol is built to remain secure even if the
remote party's device is fully malicious (an "attacker" in Phase 28.3's
adversarial test sense can simply *be* the other party sending malformed
or malicious envelopes, not just a network-level observer).

## Adversary capability → implementation mapping

Phase 0.1 lists twelve things to assume an attacker can do. Each mapped
to what actually defends against it:

| Phase 0.1 capability | Defense | Evidence |
|---|---|---|
| Read all Waku messages | AEAD confidentiality (XChaCha20-Poly1305) on every ratchet message; Phase 21's shared content topics don't leak *who* is messaging *whom*, only that traffic exists on a topic | Cryptographic design doc's AEAD section; `src/transport/contentTopics.ts`'s privacy rationale |
| Copy / replay messages | Message keys are single-use and deleted on use (Invariant 1); a replayed ciphertext has no matching key to decrypt with | `test/ratchet/DoubleRatchet.test.ts`'s replay tests; `test/property/ratchet.property.test.ts`'s replay property (hundreds of randomized cases) |
| Delay / drop / reorder messages | The Double Ratchet's out-of-order handling (skipped-key storage, bounded — Invariant 3) tolerates arbitrary reordering within `MAX_SKIP`/`MAX_STORED_SKIPPED_KEYS`; Store-based catch-up for delayed/offline delivery | `test/transport/MockWakuTransport.test.ts`'s adversarial suite (drop, delay, reorder — Phase 28.4); `test/property/ratchet.property.test.ts`'s reorder property |
| Inject arbitrary malformed messages | Cheap structural validation before any crypto (Phase 22); `decodeEnvelope`/bundle validation reject malformed input with a classified `ProtocolError`, never an unclassified crash | `test/fuzz/decodeEnvelope.fuzz.test.ts`, `test/fuzz/validatePreKeyBundle.fuzz.test.ts` — thousands of random/malformed inputs, not just hand-picked cases |
| Modify messages (ciphertext/header/AD) | AEAD authentication over ciphertext + the three-layer associated-data chain (cryptographic design doc); any modification fails decryption | `test/ratchet/DoubleRatchet.test.ts`'s Invariant 4 suite; `test/property/ratchet.property.test.ts`'s three tamper properties |
| Substitute public keys | Signed prekeys/PQ prekeys are Ed25519-signed by the identity key and verified before use (Phase 4); identity substitution is only defeatable by an attacker who compromises the *out-of-band* fingerprint-verification step — see "First-contact trust" below, this is a real, only-partially-closed gap |
| Observe Waku metadata | Not defended against — Phase 0.1 itself says not to assume metadata confidentiality; Invariant 9 makes this explicit as a design stance, not an oversight | `docs/security-invariants.md` Invariant 9 |
| Operate malicious Waku nodes | The protocol assumes zero trust in any Waku node — every guarantee above holds regardless of which/how many nodes are malicious, because none of them ever see anything but ciphertext (and, for Store nodes, ciphertext that may or may not actually be returned — Phase 20's "Store does not guarantee availability" is itself treated as adversarial, not just unreliable) | `src/transport/WakuTransport.ts`'s module doc; `test/transport/MockWakuTransport.test.ts`'s Store-incompleteness tests |
| Obtain historical ciphertexts, later compromise a device | Forward secrecy: message keys are erased on use, so a later key compromise cannot decrypt ciphertexts whose keys were already deleted (this is what "forward secrecy" *means* operationally in this codebase, not just a claimed property) | `docs/security-invariants.md` Invariant 6; cryptographic design document's key hierarchy |
| Temporarily compromise a device, then lose access | Post-compromise recovery: the next DH ratchet step introduces fresh entropy (a new ephemeral keypair) the attacker never saw, so subsequent messages are secure again even though the attacker had a window of full access | Cryptographic design document's `KDF_RK` section; this is a property of the Double Ratchet's DH-ratchet-per-round-trip structure itself, not a separate mechanism |

## Security goals → implementation mapping (Phase 0.2)

| Goal | Status |
|---|---|
| Authentication | Met for the *cryptographic* binding (a session is bound to the two identity keys via PQXDH's AD, and the identity key that established a session is exactly the one whose signature is checked at every layer) — **not** fully met for the *human* question "is this really the person I think it is," which depends on out-of-band fingerprint verification the application must actually surface (see below) |
| Confidentiality | Met — AEAD on every message, no primitive here is unaudited-and-load-bearing for confidentiality except ML-KEM itself (see "Residual risks") |
| Integrity | Met — AEAD + three-layer AD, proven adversarially and via property tests |
| Forward secrecy | Met, structurally (erase-on-use) |
| Post-compromise recovery | Met, structurally (DH-ratchet-per-round-trip) |
| Replay resistance | Met (Invariant 1) |
| Out-of-order support | Met, bounded (Invariant 3) |
| Offline support | Met for the *messaging* half (Store-based catch-up); **not yet met** for *session establishment while genuinely offline from a bundle-hosting party* — see Phase 36 in `docs/spec.md`, this protocol has no bundle-discovery mechanism at all yet, so "Alice can establish a session while Bob is offline" (Phase 34's own Definition of Done) currently depends entirely on however the integrating application gets Bob's bundle to Alice, which is outside this codebase |

## First-contact trust: what PQXDH does and does not protect against

PQXDH's identity-binding AD cryptographically proves that a session
really was established using the exact identity keys `IK_A`/`IK_B` that
went into it — but it does **not**, by itself, prove those identity keys
belong to the *humans* Alice and Bob believe they're talking to. If an
active network attacker (or a compromised/malicious bundle-hosting
intermediary, once Phase 36 exists) substitutes Bob's bundle with one
containing an attacker-controlled identity key *before* Alice ever fetches
it, PQXDH will faithfully establish a fully-authenticated, fully-secure
session — with the attacker, not Bob. This is not a flaw in PQXDH; it's
the fundamental trust-on-first-use (TOFU) limitation every asynchronous
key-agreement protocol without a trusted PKI has, Signal included.

**What this codebase provides to close that gap**:
`computeIdentityFingerprint` (`src/identity/fingerprint.ts`, Phase 2.2) —
a symmetric (`fingerprint(A,B) === fingerprint(B,A)`), HKDF-derived,
human-comparable value (12 groups of 5 digits, Signal-safety-number
style) the two parties can compare out-of-band (read aloud, scan a QR
code) to confirm neither identity key was substituted.

**What this codebase does not provide**: any mechanism that *forces* or
even *prompts* that comparison to happen. Whether an application built on
this library actually surfaces fingerprint verification to its users, and
whether users actually do it, is entirely outside this protocol core's
control — the same boundary as the UI itself. An audit of a real
*application* built on this library should specifically check whether
first-contact verification is exposed and how prominently, since this
codebase can only provide the primitive, not the practice.

## Out of scope — not defended against, by design or by current gap

Stated plainly rather than left implicit:

- **Live device compromise.** An attacker with current read access to a
  device's memory sees plaintext and live keys, by definition — no E2E
  protocol prevents this. Forward secrecy/post-compromise recovery bound
  the *temporal* window, not eliminate it.
- **Transport metadata.** Explicitly out of scope per Phase 0.1/Invariant
  9 — traffic timing, volume, and (for a real deployment, depending on
  peer-discovery/IP-level exposure) network-level identity are not
  protected by this protocol layer.
- **First-contact bundle authenticity beyond out-of-band verification.**
  See above — this is a real, only-partially-closed gap, not a solved
  problem, and gets worse until Phase 36 (bundle discovery) exists and
  its own trust model is designed.
- **Side-channel attacks (timing, power, cache).** `@noble/post-quantum`
  explicitly disclaims constant-time guarantees for the exact reasons a
  JS runtime can't provide them (JIT, GC, bigint arithmetic) — see
  `docs/audit/dependency-inventory.md`. This protocol's own code adds no
  additional side-channel hardening on top of what the underlying
  libraries provide.
- **Denial of service at the network/infrastructure level.** Rate
  limiting, Sybil resistance, and general Waku-network-availability
  concerns are Waku's own concern (RLN, etc.) — this codebase's fault
  injection testing (`MockWakuNetwork`) validates that *cryptographic
  correctness* survives an unreliable network, not that the network
  itself resists being taken down.
- **Multi-device.** Not built — see `docs/multi-device-future.md`. The
  threat model above assumes exactly one device per identity; a
  multi-device design will need its own threat-model addendum when
  built (device linking/revocation is itself a security-relevant surface
  — see that document's WhatsApp mutual-signature discussion).
- **This codebase itself has not been independently audited.** See
  `SECURITY.md`. Everything in this document describes intended behavior,
  verified by this project's own (extensive) test suite — not verified
  by a third party yet.

## Residual risks worth an auditor's explicit attention (consolidated)

Cross-referenced from the other Phase 31 documents rather than
re-derived here:

1. `@noble/post-quantum` (ML-KEM-1024) is unaudited —
   `docs/audit/dependency-inventory.md`.
2. Skipped message keys have no time-based expiry, only size bounds —
   `docs/audit/key-lifecycle.md`.
3. `RealWakuTransport` has been verified for correct SDK wiring and
   separately run end to end against the live public Waku network
   (`npm run validate:live-waku`) — see `docs/integration-guide.md`. That
   run used `defaultBootstrap: true` (whichever ENR trees `@waku/sdk`
   itself resolves that to — see the script's own doc comment) with no
   custom `networkConfig`; a deployment using a different cluster/shard
   configuration should re-run this validation under its own actual
   configuration rather than assume the default-config result
   generalizes.
4. `@waku/sdk`'s dependency tree carries a known, unfixed moderate `uuid`
   advisory — `docs/audit/dependency-inventory.md`.
5. No prekey bundle discovery/exchange mechanism exists, which is both a
   missing feature (`docs/spec.md` Phase 36) and, per "First-contact
   trust" above, a trust-model question that gets *harder*, not easier,
   once one is built.
