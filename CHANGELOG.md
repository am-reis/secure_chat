# Changelog

All notable changes to this project are documented here, newest first.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); this
project hasn't cut a tagged release yet, so entries are grouped by
implementation phase (see [docs/spec.md](docs/spec.md)) rather than a
version number. See the [README](README.md#status) for the fuller, prose
version of each phase — this file is the scannable index.

## Unreleased

### Added

- **Phase 19 — Session reset.** `SessionManager.resetSession` /
  `receiveSessionReset` destroy local session state (root key, chain keys,
  DH private key, all skipped keys — securely erased, not just dropped)
  when cryptographic state is uncertain, and notify the peer with a
  `SESSION_RESET` envelope authenticated by the sender's long-term identity
  key rather than the ratchet state itself. Wired through the wire format
  (`EnvelopeType.SESSION_RESET`) and `WakuMessagingClient`
  (`resetSession()`, a dedicated content topic, `onSessionReset`).

## Phase 10 — Real (protobuf) wire format

- Replaced the JSON placeholder envelope codec with a real, deterministic
  protobuf wire format (`src/transport/proto/envelope.proto`,
  `protoEnvelopeCodec.ts`), generated via `protobufjs`'s pure-JS `pbjs`/`pbts`
  (no system `protoc` dependency).

## Phase 27 — Protocol versioning stress test

- Adversarial test suite proving the versioning mechanism's isolation
  properties: topic-level isolation, defense-in-depth version rejection,
  exact-match semantics, zero cross-talk between coexisting version tags.

## Phase 30 — Crash recovery

- `src/persistence/outbox.ts` + `src/session/durableMessaging.ts`:
  `sendMessageDurably` / `resumePendingOutbox` persist the advanced ratchet
  state and the exact outgoing envelope *before* transmission, closing a
  real defect where restoring a stale persisted session and calling
  `sendMessage` again could silently produce a permanently undecryptable
  message. See the README's "Required reading" callout.
- Regression test in `test/crashRecovery/crashRecovery.test.ts` formalizing
  the bug that was found.

## Phase 29 — Property-based testing

- `fast-check`-driven properties over hundreds of randomized cases each:
  `decrypt(encrypt(M)) == M`, ciphertext/header/AD tampering always
  rejects, replay never delivers twice, arbitrary reordering still lets
  every message decrypt.

## Phase 26 — Delivery / read receipts

- `src/receipts/applicationContent.ts`: an optional `ApplicationContent`
  wrapper (`TEXT` / `DELIVERY_RECEIPT` / `READ_RECEIPT`) built entirely on
  top of `SessionManager.sendMessage`/`receiveMessage` — `SessionManager`
  itself stays content-agnostic (Invariant 10).

## Phase 20 / 21 / 28.4 — Mock Waku transport

- `src/transport/WakuTransport.ts`, `MockWakuNetwork.ts`,
  `WakuMessagingClient.ts`: transport abstraction plus a mock network with
  fault injection (drop, duplicate, delay/reorder, corrupt, partition,
  rate-limit) driven by real, cited Waku characteristics (RFC 64's 150 KiB
  cap, Store's non-guarantee of availability, RLN rate limiting).
- **Fix:** `ratchetInitBob` stored Bob's signed prekey keypair directly as
  the new ratchet state's `DHs`, unguarded — the first of several
  concurrent sessions from the same published bundle would silently
  zeroize that SPK's private key out from under every other session. Found
  by the transport tests exercising concurrent session establishment; fixed
  with a defensive copy, same remedy as the SessionManager-layer aliasing
  fix below.

## Phase 13 — Persistent session state

- `src/persistence/`: `serializeSession`/`deserializeSession` +
  `encryptSessionRecord`/`decryptSessionRecord` (AEAD-sealed with the
  session id as associated data). `MasterKeyProvider` is an abstraction
  only — real platform-keychain backing is desktop-shell code, deliberately
  outside this portable core.
- Test simulates an actual process restart (fresh store, fresh
  `SessionManager`) and proves messaging continues correctly afterward.

## Phase 9 / 14 / 16 / 23 — SessionManager

- `src/session/SessionManager.ts`: the integration glue connecting PQXDH
  and the Double Ratchet. `createSession` runs PQXDH, initializes the
  ratchet, and encrypts the first message in one call; `receiveMessage`
  implements the session-lookup routing rules (unknown session + `MESSAGE`
  is rejected; unknown session + `SESSION_INIT` runs the full responder
  flow; a repeated `SESSION_INIT` for an already-known session converges on
  the same session rather than creating a second one).
- **Fix:** `ratchetInitBob`'s pseudocode (`state.RK = SK`) is a direct
  assignment in Python with no aliasing implications, but the equivalent
  JS/TS assignment aliases the caller's buffer — a caller erasing `sk`
  right after ratchet init (correct key hygiene) would silently zero out
  Bob's live root key. Traced from every Alice→Bob message failing AEAD
  authentication; fixed with a defensive copy, regression test added to
  `test/ratchet/DoubleRatchet.test.ts`.

## Phase 6 / 8 — Double Ratchet

- `src/ratchet/`: state, `KDF_RK`/`KDF_CK`, encrypt/decrypt, header
  associated data, out-of-order and skipped-message handling. `RatchetDecrypt`
  derives everything on a cloned working state and only commits after the
  AEAD decrypt succeeds, so "failed messages must not mutate state" is
  structural, verified by full state-snapshot equality tests across every
  adversarial failure case.

## Phase 5 — PQXDH

- `src/pqxdh/`: initiator/responder session establishment using the exact
  KDF construction from Signal's real PQXDH spec — not the ad-hoc
  `HKDF(DH1‖DH2‖DH3‖SS)` the spec explicitly warns against.

## Phase 4 — Prekey bundle

- `src/prekeys/PreKeyBundle.ts`, `validateBundle.ts`: canonical wire
  structure plus a six-step validation pipeline (version, lengths,
  encodings, both signatures, id sanity), with adversarial tests for
  tampering, substitution, and cross-domain signature reuse.

## Phase 3 — Prekey infrastructure

- `src/prekeys/`: signed EC/PQ prekeys with a signing scheme binding
  id+publicKey, one-time prekeys with an atomic
  `AVAILABLE → RESERVED → CONSUMED` lifecycle store.

## Phase 2 — Identity

- `src/identity/`: identity generation, `identityId` derivation, symmetric
  out-of-band verification fingerprint.

## Phase 1 — CryptoProvider

- `src/crypto/`: abstraction over X25519, Ed25519, ML-KEM-1024, HKDF-SHA512,
  XChaCha20-Poly1305, backed by audited `@noble/*` libraries. Primitive
  tests cross-checked against RFC 7748 vectors, Node's OpenSSL-backed
  HKDF/SHA-256, and Python's `hashlib`.

## Phase 0 — Project scaffold

- TypeScript + Vitest project setup, `docs/spec.md`.
