# Dependency Inventory

Phase 31, item 10 of [docs/spec.md](../spec.md). Every runtime dependency
this package ships, its role, and — the part that actually matters for an
audit — its independent security-review status, verified directly from
each project's own current documentation at the time this was written
(not assumed from general reputation). Where a library turns out to be
**unaudited**, that's stated as plainly as where one is audited; burying
that would defeat the point of this document.

Versions below are what `package-lock.json` currently resolves to. Re-run
`npm list --all` and re-check upstream audit pages before relying on this
document if meaningful time has passed since its last update (see
"Renewal policy" at the bottom).

## Cryptographic primitives — the highest-scrutiny tier

These four packages are what `src/crypto/NobleCryptoProvider.ts` wraps.
Everything this protocol's confidentiality/integrity guarantees rest on
ultimately reduces to these implementations being correct.

| Package | Version | Used for | Independent audit status |
|---|---|---|---|
| `@noble/curves` | 2.4.0 | X25519, Ed25519 (identity keys, signed prekeys, PQXDH's DH1-DH3, ratchet DH) | **Audited**: Cure53 (Feb 2022, ed25519), Trail of Bits (Jan 2023), Kudelski Security (Sep 2023), Cure53 again (Sep 2024, alongside ciphers), Trail of Bits again (Aug 2026, with OpenAI) — see [paulmillr.com/noble](https://paulmillr.com/noble/) for the full report list and links. Most-reviewed package in this inventory. |
| `@noble/hashes` | 2.4.0 | SHA-256/512, HMAC, HKDF | **Audited**: Cure53 (Jan 2022). |
| `@noble/ciphers` | 2.4.0 | XChaCha20-Poly1305 (all AEAD in this protocol — ratchet messages, session records at rest, attachments) | **Audited**: Cure53 (Sep 2024). |
| `@noble/post-quantum` | 0.7.1 | ML-KEM-1024 (PQXDH's post-quantum KEM — the whole reason this protocol is post-quantum) | **Not independently audited.** The library's own README states this explicitly: *"The library has not been independently audited yet."* What exists instead: a self-audit at v0.6.1 (Apr 2026, predates the 0.7.1 pinned here) and an independent reproducibility study (not a security audit) comparing v0.7.0 against NIST's own test vectors. The library also explicitly disclaims constant-time execution — JS engines' JIT/GC/bigint arithmetic don't provide the guarantees needed for that property, and the README specifically calls out ML-DSA/Falcon signing (not used by this protocol, which only uses ML-KEM) as having weaker-than-native timing/microarchitectural security. **This is the single most important line in this document**: the post-quantum guarantee this entire protocol is built around rests on the one primitive library here without a third-party audit. |

**Consequence for the threat model and the actual security audit (Phase
31 item 1/9)**: `@noble/post-quantum`'s audit gap should be treated as a
standing, explicit risk-acceptance decision, not a detail to discover
later — and re-checking whether it's been audited since should be one of
the first things done before this project's own audit, since it may
change the audit's own scope (an unaudited dependency the audit itself
should scrutinize, versus one it can reasonably take on faith).

## Transport and serialization

| Package | Version | Used for | Notes |
|---|---|---|---|
| `@waku/sdk` | 0.0.36 | `RealWakuTransport` — Light Push/Filter/Store client for the real Waku network | Not a cryptographic library — this project's own `NobleCryptoProvider` handles everything sensitive before bytes ever reach this layer (Invariant 8/9: identity keys never enter the transport layer, transport metadata is never assumed confidential). Still pre-1.0 (`0.0.x`) upstream — its own API has moved meaningfully even across minor versions (see `src/transport/RealWakuTransport.ts`'s own doc comment on what had to be verified against current source rather than assumed). |
| `@waku/core` | 0.0.40 (transitive, via `@waku/sdk`) | Waku protocol implementations `@waku/sdk` wraps | — |
| `@waku/discovery` | 0.0.13 (transitive) | Peer discovery for `@waku/sdk` | — |
| `uuid` | 9.0.1 (transitive, via `@waku/core`) | Internal to `@waku/core`/`@waku/discovery` | **Known moderate-severity advisory**: [GHSA-w5hq-g745-h8pq](https://github.com/advisories/GHSA-w5hq-g745-h8pq) — a missing bounds check when a buffer is explicitly supplied to certain UUID generation functions. No upstream fix published as of this writing (`npm audit` surfaces this via `@waku/core`/`@waku/discovery`/`@waku/sdk`). This project's own code never calls `uuid` directly or supplies it a buffer; the exposure, if any, is entirely inside `@waku/sdk`'s own internals, not this codebase. Documented in [SECURITY.md](../../SECURITY.md) since it was first added. Re-check `npm audit` before every release. |
| `protobufjs` | 8.8.0 | The real wire-format codec (`src/transport/protoEnvelopeCodec.ts`, `src/transport/proto/envelope.pb.js`) | Not cryptographic, but a genuine attack surface: it's what parses attacker-controlled bytes off the wire before this codebase's own decode logic runs. `test/fuzz/decodeEnvelope.fuzz.test.ts` exists specifically because *this* boundary — not just this codebase's own hand-written parsing — needs to survive arbitrary/malformed input, at volume, without crashing or misbehaving. |
| `protobufjs-cli` | 2.7.0 | Dev-only: `pbjs`/`pbts` code generation (`npm run proto:generate`) | Never ships — not in `dependencies`, doesn't reach `dist/` or the published package. |

## Dev-only dependencies (not shipped, lower scrutiny warranted)

`@types/node`, `@vitest/coverage-v8`, `fast-check`, `typescript`,
`vitest` — none of these reach `dist/` or a consumer's `node_modules` in
production (see `package.json`'s `files` field: only `dist` is packed).
`fast-check` is worth a one-line mention since it's load-bearing for this
project's own confidence, not just tooling: `test/property/` and
`test/fuzz/` both depend on it generating genuinely good random coverage,
not just running fast.

## Version pinning policy

Every dependency here uses a caret range (`^X.Y.Z`) in `package.json`
today, meaning `npm install` can silently pick up a newer patch/minor
release — for the `@noble/*` packages, that's the tension between "get
security fixes automatically" and "know exactly what code you're
running," and this project currently accepts caret ranges specifically so
security patches aren't blocked on a manual bump. **Before the real
security audit**, revisit this: an audit is only meaningful against a
known, exact dependency tree — `npm ci` against a committed
`package-lock.json` already pins exact resolved versions for
reproducible installs, so the auditable state does already exist; what's
worth deciding is whether `package.json`'s own ranges should tighten
(e.g. `~X.Y.Z` or exact) for the four `@noble/*` packages specifically,
trading slower security-patch pickup for a smaller "what actually
changed" surface on every `npm install`.

## Renewal policy

Re-verify this document (re-run `npm list --all` and `npm audit`,
re-check each `@noble/*` package's audit page, re-check
`@noble/post-quantum`'s audit status specifically) — before every
tagged release (see [docs/git-workflow.md](../git-workflow.md)), and
immediately before the real security audit (Phase 31) regardless of
release timing.
