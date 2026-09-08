# Changelog

All notable changes to this project are documented here, newest first.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/); this
project hasn't cut a tagged release yet, so entries are grouped by
implementation phase (see [docs/spec.md](docs/spec.md)) rather than a
version number. See the [README](README.md#status) for the fuller, prose
version of each phase — this file is the scannable index.

## Unreleased

Nothing in flight right now.

## Developer-facing integration guides

- [docs/getting-started.md](docs/getting-started.md): a minimal two-party,
  in-memory chat walkthrough, and [docs/integration-guide.md](docs/integration-guide.md):
  persistence + safe sending, transport setup (including a non-obvious
  self-delivery gotcha on shared content topics), session reset, receipts/
  attachments, an accurate error-code reference table (including which
  `ProtocolErrorCode` values are declared but not currently thrown
  anywhere), and an explicit "what this library does not do" list.
- Every non-trivial snippet in both guides is backed by a real, passing
  test under `test/examples/` — the guides narrate tested code rather than
  contain untested prose that could silently drift out of sync with the
  API.
- **Fixed a real, previously-undiscovered packaging bug found while
  verifying this**: `npm run build` alone produced a `dist/` missing
  `envelope.pb.js`/`envelope.pb.d.ts` (`tsc` doesn't copy non-`.ts`
  source files — those are hand-generated and committed as `.js`/`.d.ts`
  directly), which would have broken every consumer importing anything
  that touches the wire format. Caught by actually running `npm pack`,
  installing the tarball into a separate scratch project, and executing
  the getting-started flow against the installed package — not just by
  `tsc` succeeding.
- Added `src/index.ts`, a curated public entrypoint (`import { ... } from
  "secure-messaging-protocol"`) and the corresponding `package.json`
  `main`/`types`/`exports` fields — this library previously had **no**
  configured way to be consumed as an installed dependency at all.
  Internal implementation modules (raw Double Ratchet/PQXDH functions,
  the KDF chain, etc.) are deliberately not exported, mirroring Invariant
  10 at the package boundary.

## Multi-device — documented as deferred, not implemented

- [docs/multi-device-future.md](docs/multi-device-future.md): records the
  decision to defer multi-device to a future version rather than design it
  from scratch now. Grounded in the two proven real-world models (Signal's
  Sesame algorithm, WhatsApp's per-device-key architecture — both fetched
  from their own current public specs, not assumed from memory) and maps
  out what this codebase already has ready to build on (`SessionManager`'s
  existing 1:1 sessions are exactly what both models fan out over — no
  changes needed there) versus what's genuinely new work (device-list
  storage/sync, the fan-out orchestration layer, link/revoke signed
  payloads, stale-session pruning).

## Real Waku transport

- `src/transport/RealWakuTransport.ts`: a `@waku/sdk`-backed `WakuTransport`
  implementation, plugged into the existing `WakuMessagingClient` with zero
  changes needed there — confirms the transport abstraction actually
  holds. Verified against `@waku/sdk`'s real, current source rather than
  assumed: routing is now derived from a `NetworkConfig`
  (cluster/shards), `lightPush.send` returns a `{successes, failures}`
  result instead of throwing, and `ephemeral` is bound to the encoder
  rather than passed per publish call. `networkConfig` and peer-discovery
  options are passed straight through, deliberately undefaulted.
- `test/transport/RealWakuTransport.test.ts`: wiring tests against a
  mocked `@waku/sdk` (this project's tests still need zero network
  access) — proves the right SDK calls happen with the right arguments and
  every failure path maps to a classified `ProtocolError`. Does not, and
  cannot, prove live delivery.
- Adds `@waku/sdk` as a real dependency. Its transitive dependency tree
  currently carries a moderate-severity `npm audit` advisory in `uuid`
  (no upstream fix yet) — noted in README/SECURITY.md rather than left
  for `npm audit` to surface as a surprise later.

## Phase 32 — Security invariants

- [docs/security-invariants.md](docs/security-invariants.md): each of the
  spec's ten invariants mapped to what enforces it and what proves that
  enforcement holds — runtime test, type-level guarantee, or a documented
  repo-wide search for an absence (a logged key, a private key reaching
  the transport layer).
- **Found and fixed while writing it**: `MAX_STORED_SKIPPED_KEYS` (the
  global, cumulative skipped-key cap — distinct from the per-call
  `MAX_SKIP` bound) had been enforced in `src/ratchet/DoubleRatchet.ts`
  since the ratchet was first built, but had no test proving it actually
  worked. Added a regression test
  (`test/ratchet/DoubleRatchet.test.ts`) that accumulates skipped keys
  across multiple calls, each individually under `MAX_SKIP`, and confirms
  the global cap still trips — and that the rejected call doesn't
  partially mutate state either (Invariant 4).

## Fuzzing

- `test/fuzz/`: random/malformed-byte fuzzing (fast-check, thousands of
  runs) at the three boundaries where attacker- or corruption-controlled
  input first reaches this codebase — `decodeEnvelope`,
  `decryptSessionRecord`, `validatePreKeyBundle` — checking that failures
  are always a classified `ProtocolError`, never a raw exception or a
  hang. Surfaced a genuine, benign-by-design finding: bundle validation
  cannot catch a corrupted one-time prekey (it isn't signed in the wire
  format), but PQXDH's own DH computation makes a corrupted OTK cause a
  clean AEAD authentication failure downstream instead — proven end to
  end by a dedicated test, not just asserted. See README/SECURITY.md.

## Phase 24 — Attachments

- `src/attachments/attachmentCrypto.ts`: `encryptAttachment`/
  `decryptAttachment` encrypt an attachment under its own fresh random key
  and verify a digest of the *encrypted* blob before decrypting (defense
  against a storage backend serving back a substituted attachment). The
  resulting `AttachmentDescriptor` travels as a new `ATTACHMENT` kind on
  the existing `ApplicationContent` wrapper
  (`src/receipts/applicationContent.ts`), reusing the same "ordinary
  encrypted Double Ratchet message" mechanism Phase 26 built for receipts —
  no SessionManager or wire-format changes needed.

## Phase 19 — Session reset

- `SessionManager.resetSession`/`receiveSessionReset` destroy local session
  state (root key, chain keys, DH private key, all skipped keys — securely
  erased, not just dropped) when cryptographic state is uncertain, and
  notify the peer with a `SESSION_RESET` envelope authenticated by the
  sender's long-term identity key rather than the ratchet state itself.
  Wired through the wire format (`EnvelopeType.SESSION_RESET`) and
  `WakuMessagingClient` (`resetSession()`, a dedicated content topic,
  `onSessionReset`).

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
