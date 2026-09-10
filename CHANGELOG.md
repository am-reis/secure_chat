# Changelog

All notable changes to this project are documented here, newest first.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).
Entries are grouped by implementation phase (see
[docs/spec.md](docs/spec.md)) rather than strictly by version — most
phases are small enough that a version-per-entry index would be noisier,
not clearer. See [docs/git-workflow.md](docs/git-workflow.md) for how
releases are actually tagged, and the [README](README.md#status) for the
fuller, prose version of each phase — this file is the scannable index.

**v0.1.0** (tag: `v0.1.0`) is the retroactive baseline covering everything
from Phase 0 through the developer integration guides — tagged once the
git workflow this project now follows was established, not because
anything changed at that point.

**v0.2.0** (tag: `v0.2.0`) adds Phase 31 (all 8 security audit-prep
documents) and Phase 36 (the prekey bundle discovery gap, recorded and
deferred to a future protocol version) on top of v0.1.0.

**v0.3.0** (tag: `v0.3.0`) adds live-network validation for
`RealWakuTransport` (`npm run validate:live-waku`) on top of v0.2.0 —
closes the "never run against a live network" gap that had stood since
the real transport was first built.

## Unreleased

- **GitHub Pages docs site.** `.github/workflows/docs.yml` assembles
  `docs/` plus the root README/SECURITY/CHANGELOG/CONTRIBUTING/LICENSE
  and force-pushes them to a `gh-pages` branch on every push to
  `main`/`develop` that touches those paths — plain git + the built-in
  `GITHUB_TOKEN`, no third-party action. `docs-site/index.md` is a
  purpose-built landing page linking every doc; GitHub Pages' own Jekyll
  build (once enabled — see `docs/git-workflow.md`) renders it, not a
  build step in the workflow itself. Also synced `package-lock.json`'s
  root metadata, which had drifted from `package.json` across this
  session's version bumps.

## Public npm packaging + CI/release automation

- Removed `"private": true`; added `license` (Apache-2.0), `repository`,
  `homepage`, `bugs`, `keywords`, `engines` (`node >=20`, now actually
  verified by CI, not just asserted), and `publishConfig.access: public`
  to `package.json`. Added an `Apache-2.0` `LICENSE` file (canonical text
  from apache.org, not reproduced from memory).
- `.github/workflows/ci.yml`: typecheck + test + build on every push to
  `main`/`develop` and every PR, on a Node 20 + 22 matrix. Also runs a
  real packaging smoke test every time — pack the tarball, install it
  into a genuinely separate temp project, import from the published
  entrypoint, assert every expected export exists. This is now automated
  forever the exact check that caught a real bug (missing
  `envelope.pb.js`/`.d.ts` in `dist/`) before this package's entrypoint
  first shipped.
- `.github/workflows/release.yml`: triggered by pushing a `vX.Y.Z` tag.
  Re-verifies everything on the exact tagged commit, confirms the tag
  matches `package.json`'s version, and only then makes an `npm publish
  --provenance` job available — gated behind the `npm-publish` GitHub
  Environment's required-reviewer approval, so a human approves every
  release of this now-public, installable package. Also creates a
  GitHub Release from the tag's own annotated message.
- Documented the one-time manual setup this needs (an npm Automation
  token as the `NPM_TOKEN` repo secret, and the `npm-publish` environment
  with a required reviewer) in `docs/git-workflow.md` — neither can be
  configured from a workflow file or by an agent; both need the repo
  owner's GitHub/npm account access.

## Live Waku network validation

- `scripts/live-waku-validation.mjs` (`npm run validate:live-waku`):
  manual, deployment-time validation of `RealWakuTransport` against the
  real public Waku network — outside `npm test` for the same
  no-network-required-for-automated-tests reason as the rest of this
  project's suite. Two independent nodes (Alice, Bob) ran a full PQXDH
  handshake and message exchange live: `createSession` published and
  received over a real Filter subscription, a reply received the same
  way, and a Store-protocol history query returning real results.
  Closes the "never run against a live network" gap noted in
  `docs/integration-guide.md` and `docs/audit/threat-model.md`'s
  residual risks list since `RealWakuTransport` was first built.
- Confirmed live, not just predicted from the mock: each node saw
  exactly one `AEAD_AUTHENTICATION_FAILED` from hearing its own
  published envelope back over the shared content topic — the
  self-delivery behavior the integration guide already documented from
  `MockWakuNetwork`'s design now holds on the real network too.
- Imports from `dist/`, not `src/` — deliberately, so every run also
  doubles as a packaging sanity check against the actual public
  entrypoint an external consumer would use.

## Phase 31 — Security audit preparation

- All 8 of Phase 31's audit-prep documents, under `docs/audit/`: threat
  model, cryptographic design, protocol state machine, wire format, key
  lifecycle, persistence spec, test vector suite, dependency inventory.
  These prepare for a real third-party audit; they don't substitute for
  one — `SECURITY.md`'s status doesn't change until that actually
  happens.
- **The single most important finding across all 8**: `@noble/post-quantum`
  (ML-KEM-1024, the entire reason this protocol is post-quantum) has not
  been independently audited (per its own README) — the *dependency
  inventory* document's finding — and this project's own test suite has
  no independently-sourced test vectors for ML-KEM either, only
  self-consistency (round-trip, tamper-behavior) checks — the *test
  vector suite* document's finding. Same underlying gap, surfaced twice
  from two different angles rather than once and forgotten.
- Also surfaced: skipped message keys have no time-based expiry, only
  size bounds, against `docs/spec.md`'s own stated four-trigger deletion
  policy (key lifecycle document); and PQXDH's identity-binding
  authenticates a session to whatever keys went into it, not that those
  keys belong to the humans the parties believe they're talking to —
  the existing fingerprint-verification mechanism (Phase 2.2) closes
  that gap only if an application actually surfaces it, which nothing in
  this codebase forces (threat model document's "First-contact trust"
  section).

## Phase 36 — Prekey bundle discovery, recorded as a deferred protocol v2 gap

- `docs/spec.md` amended to acknowledge a real gap surfaced while writing
  the integration guide: nothing in this protocol defines how a
  `PreKeyBundle` actually gets from the device that generated it to the
  device that wants to start a session with it. Recorded as its own
  phase (36), not fixed here — it needs its own metadata-privacy analysis
  (a naive per-identity content topic would leak exactly what Phase 21's
  shared-topic design was built to avoid) and its own answer for
  one-time-prekey reservation races under a directory model, and per
  Phase 27's existing versioning discipline, ships as a new
  `protocolVersion` when it's actually built — not a silent extension of
  the current one. See the integration guide's "what this library does
  not do" section for the practical, right-now consequence.

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
