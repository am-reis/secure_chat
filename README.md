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
- **Phase 20/21/28.4 — mock Waku transport**: built against a mock rather
  than real `js-waku` for now (Waku is mature/simple enough that this
  doesn't cost much, and it decouples protocol-robustness testing from
  network/infra setup). Every fault-injection parameter traces to a
  specific, current, documented Waku characteristic rather than generic
  P2P assumptions — see `src/transport/WakuTransport.ts` and
  `MockWakuNetwork.ts` for the sources (RFC 64's 150 KiB message cap,
  Store's documented non-guarantee of availability, RLN rate limiting,
  fire-and-forget publish semantics). `WakuMessagingClient` is the
  `SessionManager`↔`WakuTransport` binding — real code, not test
  scaffolding, so swapping in a real `js-waku`-backed transport later
  changes nothing above this layer. The test suite runs Phase 28.4's full
  adversarial list (drop, duplicate, delay/reorder, corrupt, partition,
  rate-limit, Store-based offline catch-up and its own incompleteness,
  injected/malicious messages) through actual `SessionManager` instances
  talking over the mock, not just unit-level fault-injection checks.

**A second, more serious aliasing bug surfaced and got fixed here** — this
one was latent in already-delivered code, not something newly introduced.
`ratchetInitBob` stored Bob's SPK keypair directly as the new state's
`DHs`, unguarded, the same class of bug as the `sk` aliasing fix in the
SessionManager commit — except this one meant the *first* of several
concurrent sessions to complete its DH ratchet step would silently
zeroize Bob's signed prekey's private key out from under every other
session started from the same published bundle (completely normal usage —
an SPK is reused across every session established before its next
rotation, unlike a one-time prekey). It surfaced only once the transport
tests exercised two independent parties establishing sessions from the same
bundle concurrently — exactly the kind of realistic multi-session scenario
unit tests at the ratchet/session layer alone hadn't happened to construct.
Fixed with the same remedy (a defensive copy), with a dedicated regression
test now at the Double Ratchet layer itself.

- **Phase 26 — delivery/read receipts**: a small, optional
  `ApplicationContent` wrapper (`TEXT` / `DELIVERY_RECEIPT` / `READ_RECEIPT`)
  applications can use on top of `SessionManager.sendMessage`/
  `receiveMessage`. Deliberately does NOT change `SessionManager` itself —
  it stays completely content-agnostic (Invariant 10), and plain
  `Uint8Array` plaintext with no wrapper continues to work unchanged. A
  receipt identifies which message it acknowledges by the same
  `(ratchetPublicKey, messageNumber)` pair that's already a message's
  logical identity (Phase 15).
- **Phase 29 — property-based testing**: `fast-check`-driven tests running
  the exact properties the spec lists — `decrypt(encrypt(M)) == M`,
  tamper(ciphertext/header/AD) always rejects, replay never delivers twice,
  arbitrary reordering still lets every message decrypt — over hundreds of
  randomized inputs each, on top of (not instead of) the existing
  example-based test suite. No new bugs surfaced across ~1000 randomized
  cases, a useful signal given this exact layer's history (see the two
  `ratchetInitBob` aliasing fixes above).
- **Phase 30 — crash recovery**: see the prominent callout immediately
  below — `src/persistence/outbox.ts` + `src/session/durableMessaging.ts`.

## ⚠️ Required reading before persisting sessions: safe message sending

Phase 30 (crash recovery testing) found a real defect, not just a
theoretical risk. **Never call `sessionManager.sendMessage` again "to
retry" a message after restoring a session from persistence.**

`ratchetEncrypt`'s chain-key derivation is a pure function of the current
chain key. If your app encrypts and transmits a message but crashes before
persisting the *advanced* session state, restoring the last-persisted
(stale, pre-send) state and calling `sendMessage` again for different
content deterministically derives the **same** message key and the same
`(ratchetPublicKey, messageNumber)` identity as the message that was
already sent. If the recipient already received the first one — entirely
plausible over a P2P/store-and-forward transport, where the sender can't
know whether delivery happened before the crash — the second message
becomes **permanently undecryptable** to them, indistinguishable from a
replay attack. This is proven as a standing regression test in
`test/crashRecovery/crashRecovery.test.ts`.

**Use `sendMessageDurably` / `resumePendingOutbox`
(`src/session/durableMessaging.ts`) instead of calling `sendMessage`
directly whenever the session is persisted:**

```ts
// Sending:
await sendMessageDurably(manager, store, provider, masterKeyProvider, transport, sessionId, plaintext);

// On startup, for every restored session, BEFORE anything else touches it:
await resumePendingOutbox(store, transport, sessionId);
```

This persists the advanced state and the exact outgoing envelope bytes
*before* attempting transmission, and only clears that record once
transmission succeeds — so a resumed send after a crash always retransmits
identically rather than re-deriving a new message. A duplicate delivery
from a retransmission-after-transmission-already-succeeded is safely
deduped by the ratchet's own existing replay protection (Phase 6) — the
application still only ever sees it once.

The receiving side needed no such fix: `ratchetDecrypt` is already
side-effect-free until commit (Phase 6), so a crash before persisting a
*received* message is automatically safe — redelivery of the same message
after restart just decrypts correctly again.

- **Phase 27 — protocol versioning stress test**: proves the versioning
  *mechanism*'s isolation properties (topic-level isolation, defense-in-depth
  version rejection, exact-match semantics with no silent range tolerance,
  and zero cross-talk when two version tags coexist on one network) — not a
  claim that a real, differing-crypto v2 exists yet, since that's Phase 35
  territory and explicitly out of scope for now.
- **Phase 19 — session reset**: `SessionManager.resetSession`/
  `receiveSessionReset` handle the case where cryptographic state is
  uncertain (storage corruption, device restore, excessive
  skipped-message state, explicit user action) — per the spec, "do not
  attempt to repair inconsistent Double Ratchet state by guessing or
  reconstructing missing keys," so this only ever destroys and starts
  over, never repairs. Local destruction zeroes the root key, both chain
  keys, the DH ratchet private key, and every stored skipped key via
  `secureErase` (Invariant 6/7), then notifies the peer with a
  `SESSION_RESET` envelope. That envelope is authenticated with the
  sender's long-term Ed25519 identity key rather than the Double Ratchet's
  associated data — deliberately, since Phase 19 exists precisely for the
  case where ratchet state can't be trusted, so the authentication for
  "forget this session" can't depend on it. On receipt, the signature is
  verified against the identity key already on file for that session
  before anything is destroyed (an unauthenticated `SESSION_RESET` must
  never be able to kill a live session — the same DoS concern Phase 23
  raises for auto-creating sessions, mirrored here for destruction); a
  failed check leaves the session untouched, matching the "failed
  authentication must not mutate state" invariant enforced everywhere else
  in this protocol. Wired all the way through the wire format
  (`EnvelopeType.SESSION_RESET`, a new `signature` field) and
  `WakuMessagingClient` (a dedicated content topic, `resetSession()`, and
  an `onSessionReset` callback), not just at the `SessionManager` layer.
- **Phase 32 — security invariants**: [docs/security-invariants.md](docs/security-invariants.md)
  maps each of the spec's ten invariants to what actually enforces it and
  what proves that enforcement holds — a runtime test, a type-level
  guarantee the compiler enforces, or a documented repo-wide search for
  something that must never appear (a logged key, a private key reaching
  the transport layer). Writing it surfaced a real gap: the global
  `MAX_STORED_SKIPPED_KEYS` cap (Invariant 3) had been enforced in code
  since the ratchet was first built but had no test at all, only the
  per-call `MAX_SKIP` bound did — closed with a new regression test rather
  than just noted and left.
- **Fuzzing** (Phase 33's implementation-order item 20, distinct from
  Phase 29's targeted property tests): `test/fuzz/` feeds genuinely
  random/malformed bytes, at volume, at the three boundaries where
  attacker- or corruption-controlled input first reaches this codebase —
  `decodeEnvelope` (the wire format), `decryptSessionRecord` (persisted
  session data), and `validatePreKeyBundle` (a fetched prekey bundle) —
  and checks one property each time: never anything but a classified
  `ProtocolError`, never a raw/unclassified exception, never a hang.
  **A genuine, non-obvious finding surfaced here**: corrupting a bundle's
  one-time prekey (`oneTimePreKey.publicKey`) is the one field
  `validatePreKeyBundle` does *not* reject — by design, not a bug: unlike
  every other bundle field, the wire format never carries a signature over
  the OTK (matching real X3DH/PQXDH bundle formats), so there is nothing
  for that layer to check it against. What actually protects it is PQXDH's
  own DH4 = DH(EK_A, OPK_B): Alice computes it from whatever bytes were in
  the bundle, but Bob computes his mirror of DH4 from his own stored
  private key, never from Alice's bundle — so a corrupted OTK makes the
  two sides' derived `SK` diverge, and the initial message's AEAD
  authentication on Bob's side fails cleanly (Phase 5.3's existing
  no-partial-state guarantee). `test/fuzz/validatePreKeyBundle.fuzz.test.ts`
  proves this full chain end to end, not just the two halves separately.
- **Phase 24 — attachments**: `src/attachments/attachmentCrypto.ts`
  implements the spec's flow — encrypt the attachment under its own fresh
  random key, hand the caller the ciphertext to upload, and let
  `AttachmentDescriptor` (key, hash, size, mimeType, objectId) travel as
  ordinary structured content via the same `ApplicationContent` wrapper
  Phase 26 built for receipts (`src/receipts/applicationContent.ts`'s new
  `ATTACHMENT` kind) — "the entire descriptor must be encrypted inside the
  Double Ratchet message," so no new SessionManager/wire-format surface was
  needed, only a new content kind. `objectId` is deliberately NOT produced
  by this module: encryption and upload are separate steps, and which
  object-storage backend to integrate with is out of scope for this
  transport-agnostic core (same reasoning as the mock-vs-real Waku split).
  `hash` is a digest of the *encrypted* blob, checked before decryption —
  the recipient's only defense against a storage backend serving back a
  substituted blob under a different attachment's key, which could
  plausibly decrypt to garbage without necessarily surfacing as an AEAD
  failure the caller expects to mean "tampered."
- **Phase 10 — real (protobuf) wire format**: replaces the earlier JSON
  placeholder codec entirely. Chosen over hand-rolling a binary format
  (despite already having the length-prefixed encoding primitives to do
  so) because this project's stated direction is desktop first, mobile
  later, and protobuf has mature Kotlin/Swift codegen — a hand-rolled
  format would need bit-for-bit reimplementation on every future platform.
  Generated via `protobufjs`'s own pure-JS `pbjs`/`pbts` (no system
  `protoc` binary needed — `npm run proto:generate` regenerates from
  `src/transport/proto/envelope.proto`). `protoEnvelopeCodec.ts` exposes
  the identical `encodeEnvelope`/`decodeEnvelope` signatures the JSON
  placeholder had, so nothing above the transport boundary changed.

Not yet built: real `js-waku` integration and multi-device — see
`docs/spec.md`'s Phase 33 implementation order and
[CHANGELOG.md](CHANGELOG.md) for what's landed so far.

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
  transport/     Mock Waku transport, fault injection, content topics, messaging
                 client, protobuf wire format (Phase 10/20/21/28.4)
  receipts/      Delivery/read receipts + the ApplicationContent wrapper
                 (also carries attachment descriptors) (Phase 26/24)
  attachments/   Attachment encryption/decryption + descriptor type (Phase 24)
  errors.ts      Shared protocol error taxonomy (Phase 17 codes)
test/            Mirrors src/, one test file per module
```

## Build / test

```bash
npm install
npm run typecheck      # tsc --noEmit, src + test
npm test                # vitest run
npm run proto:generate  # regenerate src/transport/proto/envelope.pb.{js,d.ts} after editing envelope.proto
```

All tests currently pass (269, including a new regression test the
security-invariants review itself motivated). No
network access is required
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
