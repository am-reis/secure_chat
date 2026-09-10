# Integration Guide

Read [docs/getting-started.md](getting-started.md) first if you haven't —
this picks up right where it leaves off: a session established, first
messages exchanged, all in memory. This guide covers everything you need
to make that real: persisting sessions safely, wiring a transport,
structured content, error handling, and — just as important — an explicit
list of what this library does **not** do, so you don't discover those
gaps by surprise.

Every non-trivial code block below is backed by a real, passing test under
[`test/examples/`](../test/examples/) — referenced by name so you can run
it yourself (`npm test -- examples`) rather than trust prose.

## Safety first: sending after persistence

Read this before you persist a single session. It's the one rule in this
whole library that's actively dangerous to get wrong, because getting it
wrong doesn't fail loudly — it silently produces a message the recipient
can never decrypt.

**Once a session is persisted, never call `sessionManager.sendMessage`
directly again for that session. Use `sendMessageDurably` instead.**

Why: `sendMessage`'s underlying chain-key derivation is a pure,
deterministic function of the current chain key. If your process crashes
after `sendMessage` encrypts-and-transmits but before the *advanced*
session state is persisted, and you restore from the last-persisted
(stale) state and call `sendMessage` again for a *different* plaintext,
you get the exact same message key and the same `(ratchetPublicKey,
messageNumber)` identity as the message that may have already reached the
recipient. If it did, the second message is permanently undecryptable to
them — indistinguishable from a replay attack, even though it's a
legitimate different message. This was a real defect found during this
project's own crash-recovery testing (Phase 30 — see
[CHANGELOG.md](../CHANGELOG.md) and `test/crashRecovery/crashRecovery.test.ts`
for the regression test that proves it), not a theoretical concern.

The fix, `sendMessageDurably`/`resumePendingOutbox`, is write-ahead
logging: persist the *advanced* state and the *exact outgoing envelope
bytes* before transmitting, and only clear that record once transmission
succeeds — so a retry after a crash always retransmits identically instead
of re-deriving a new message.

```ts
import {
    NobleCryptoProvider,
    SessionManager,
    sendMessageDurably,
    resumePendingOutbox,
    saveSession,
    loadSession,
    InMemoryKeyValueStore,
    StaticMasterKeyProvider,
} from "secure-messaging-protocol";
```

```ts
// Persist a session (e.g. right after creating/receiving it):
await saveSession(store, provider, masterKeyProvider, session);

// On every app startup, for every session you restore, BEFORE anything
// else touches it — retransmits anything that was mid-send when a crash
// happened; the common case is nothing pending, and it returns false:
const restored = await loadSession(store, provider, masterKeyProvider, sessionId, localIdentity);
sessionManager.restoreSession(restored);
await resumePendingOutbox(store, transport, sessionId);

// From then on, send through this instead of sessionManager.sendMessage:
await sendMessageDurably(sessionManager, store, provider, masterKeyProvider, transport, sessionId, plaintext);
```

The receiving side needs no equivalent care: `receiveMessage`'s ratchet
decrypt is already side-effect-free until the AEAD check succeeds (see
[docs/security-invariants.md](security-invariants.md), Invariant 4), so a
crash before persisting a *received* message is automatically safe —
redelivery after restart just decrypts correctly again.

Full working example:
[`test/examples/persistenceAndDurableMessaging.test.ts`](../test/examples/persistenceAndDurableMessaging.test.ts).

## Persistence setup

`saveSession`/`loadSession`/`deleteSession`/`listSessionIds` (all in the
example above) are built on two abstractions you supply real
implementations for:

- **`RawKeyValueStore`** — `get`/`set`/`delete`/`list(prefix)`, all async.
  `InMemoryKeyValueStore` is what this library ships and what its own test
  suite uses — it is **not durable**; it's gone when the process exits.
  For a real app, implement this against whatever you actually persist to
  (SQLite, IndexedDB, a filesystem, ...) — it's a small, deliberately
  generic interface.
- **`MasterKeyProvider`** — one method, `getMasterKey(): Promise<Uint8Array>`
  (must return 32 bytes), sourcing the symmetric key session records are
  encrypted with at rest. `StaticMasterKeyProvider` (a fixed,
  caller-supplied key) is explicitly test-only — **its own doc comment
  says so.** A real deployment needs this backed by an actual OS
  keychain: Electron's `safeStorage` (itself backed by Keychain/DPAPI/
  libsecret) on desktop, the platform Keychain/Keystore on mobile. That
  binding is deliberately outside this portable, transport-agnostic core
  — it's genuinely platform-specific, the same way a UI is.

Session records never include the local identity's private key — only a
reference id (`session.localIdentity` must be supplied again on
`loadSession`). Identity persistence is a separate concern this library
doesn't prescribe an interface for; store `Identity.keyPair.privateKey`
with at least the same rigor as `MasterKeyProvider`'s key, since it's
longer-lived and shared across every session.

## Transport setup

`WakuMessagingClient` is the binding between a `SessionManager` and a
`WakuTransport` — your application code calls `client.createSession`/
`client.sendMessage`/`client.resetSession` and gets an `onMessage`
callback; it never encodes an envelope or touches a content topic itself.
Two `WakuTransport` implementations exist:

- **`MockWakuTransport`** (+ `MockWakuNetwork`) — an in-process, no-network
  stand-in. This is what this library's own test suite runs against
  exclusively (see README: "no network access is required to run the
  tests"), and it's a reasonable choice for local development too — it
  supports fault injection (drop/duplicate/delay/corrupt/partition; see
  `test/transport/MockWakuTransport.test.ts`) if you want to exercise your
  own app's error handling against an unreliable network without standing
  up real infrastructure.
- **`RealWakuTransport`** — backed by the actual `@waku/sdk`. Needs a real
  decision from you about `networkConfig` (which cluster/shards) and peer
  discovery (`defaultBootstrap` vs. explicit `bootstrapPeers`) —
  deliberately not defaulted; see `src/transport/RealWakuTransport.ts`'s
  own doc comment and `test/transport/RealWakuTransport.test.ts` for the
  wiring (mocked-SDK) tests. Verified for correct wiring against
  `@waku/sdk`'s real API, **and separately run end to end against the live
  public Waku network** — `npm run validate:live-waku`
  (`scripts/live-waku-validation.mjs`) runs two independent nodes through
  a full PQXDH handshake and message exchange over real infrastructure,
  outside `npm test` for the same no-network-required reason as the rest
  of this project's automated suite. Re-run it after any `@waku/sdk`
  upgrade or before a release that touches the transport layer — it's not
  a one-time check.

```ts
import { MockWakuNetwork, MockWakuTransport, WakuMessagingClient } from "secure-messaging-protocol";

const network = new MockWakuNetwork(); // one shared instance per simulated "network"
const transport = new MockWakuTransport("alice", network);
const client = new WakuMessagingClient(sessionManager, transport, {
    onMessage: (sessionId, plaintext) => { /* ... */ },
    onError: (err, contentTopic) => { /* log/report — never throw here, see below */ },
});
await client.start();
```

**A non-obvious gotcha worth knowing before it surprises you**: content
topics are shared across every session and user (deliberately — see
`src/transport/contentTopics.ts`'s privacy rationale), which means a
client also receives its *own* published messages back, the same way real
gossipsub/Waku Relay delivers to all of a topic's subscribers including
the publisher. Trying to decrypt your own outgoing envelope with your own
ratchet fails (wrong direction) and lands in `onError` — this is expected,
benign noise, not a bug to chase down. `onError` should log/report, never
throw or crash your app; `WakuMessagingClient`'s own doc comment says the
same. See
[`test/examples/transportWithMockWaku.test.ts`](../test/examples/transportWithMockWaku.test.ts)
for this asserted explicitly rather than just described.

## Session reset

If a session's cryptographic state becomes uncertain (storage corruption,
device restore, excessive skipped-message state, an explicit "forget this
conversation" user action), don't try to repair it:

```ts
// Local side: destroys local state, returns a signed notice to send the peer.
const resetEnvelope = sessionManager.resetSession(sessionId);
await transport.publish(sessionResetContentTopic(resetEnvelope.protocolVersion), encodeEnvelope(resetEnvelope));
// Or, via the client, in one call:
await client.resetSession(sessionId);
```

```ts
// Peer side, on receiving that envelope: verifies the signature against
// the identity already on file for that session, then destroys it.
// WakuMessagingClient routes this automatically if you're using it —
// otherwise call sessionManager.receiveSessionReset(envelope) yourself.
```

After a reset, the old `sessionId` is gone on both sides. Continuing the
conversation needs a **fresh** `createSession` call with a **fresh**
prekey bundle — see the gap below about bundle exchange not being
something this library does for you. See
[`test/session/sessionReset.test.ts`](../test/session/sessionReset.test.ts)
and
[`test/transport/sessionReset.transport.test.ts`](../test/transport/sessionReset.transport.test.ts)
for the full behavior, including what happens on a forged reset attempt
(rejected, session left untouched).

## Structured content: receipts and attachments

`SessionManager` only ever sees opaque `Uint8Array` plaintext — it has no
concept of "this is a text message" vs. "this is a receipt" vs. "this is
an attachment." `ApplicationContent` (and `encryptAttachment`/
`decryptAttachment` for the attachment case specifically) is an entirely
optional, application-level convention layered on top, not a protocol
requirement:

```ts
import { encodeApplicationContent, decodeApplicationContent, buildDeliveryReceipt, buildAttachmentContent, encryptAttachment, decryptAttachment } from "secure-messaging-protocol";

// Sending a text message:
const envelope = sessionManager.sendMessage(sessionId, encodeApplicationContent({ kind: "TEXT", text: "hello" }));

// Receiving and dispatching by kind:
const content = decodeApplicationContent(plaintext);
if (content.kind === "TEXT") { /* ... */ }
if (content.kind === "DELIVERY_RECEIPT" || content.kind === "READ_RECEIPT") { /* ... */ }
if (content.kind === "ATTACHMENT") { /* ... */ }

// Acknowledging a received message (identified by the SAME
// (ratchetPublicKey, messageNumber) pair that's already the message's
// protocol-level identity — no separate id scheme needed):
const receipt = buildDeliveryReceipt(receivedEnvelope.ratchetHeader);
sessionManager.sendMessage(sessionId, encodeApplicationContent(receipt));

// Attachments: encrypt under a fresh random key BEFORE upload, send only
// the descriptor through the encrypted channel:
const encrypted = encryptAttachment(provider, fileBytes, "image/jpeg");
const objectId = await myObjectStorage.upload(encrypted.ciphertext); // NOT this library's job
sessionManager.sendMessage(sessionId, encodeApplicationContent(buildAttachmentContent({ objectId, ...encrypted })));

// Receiving: download by objectId (again, your own object storage), then:
const plaintext = decryptAttachment(provider, receivedDescriptor, downloadedCiphertext);
```

If you don't need any of this, plain `Uint8Array` plaintext with no
wrapper continues to work exactly as shown in the getting-started guide —
this layer is opt-in.

Full working examples:
[`test/examples/receiptsAndAttachments.test.ts`](../test/examples/receiptsAndAttachments.test.ts).

## Error handling

Every rejection path in this library throws `ProtocolError`, never a bare
`Error` or an unclassified exception — check `.code`, not the message
string, which per Phase 17 is never meant to leak cryptographic detail to
a remote peer. The full taxonomy (`src/errors.ts`), and, accurately,
which of these are actually thrown somewhere today versus reserved for
future use:

| Code | Thrown by | Meaning |
|---|---|---|
| `INVALID_FORMAT` | bundle/envelope validation, malformed wire bytes | Structurally malformed input — rejected before any crypto is attempted. |
| `UNSUPPORTED_VERSION` | `receiveMessage`, bundle validation | Protocol version not in `SUPPORTED_PROTOCOL_VERSIONS`. |
| `UNKNOWN_SESSION` | `receiveMessage`, `sendMessage`, `resetSession`, `receiveSessionReset` | No session registered for that id — for an unauthenticated `MESSAGE`/`SESSION_RESET`, this is deliberate: never auto-create or auto-destroy a session from an arbitrary/unauthenticated envelope. |
| `INVALID_SIGNATURE` | bundle validation, `receiveSessionReset` | A signature (prekey, or a `SESSION_RESET` notice) failed verification. |
| `INVALID_PQ_CIPHERTEXT` | PQXDH processing | The ML-KEM ciphertext failed to decapsulate cleanly. |
| `AEAD_AUTHENTICATION_FAILED` | ratchet decrypt, attachment decrypt | Ciphertext/header/AD tampering, a replayed message (no distinct `REPLAY` code — a replay simply has no matching key left to decrypt with, so it surfaces here), or a corrupted attachment download. |
| `MESSAGE_TOO_FAR_AHEAD` | ratchet decrypt | `MAX_SKIP` or the global `MAX_STORED_SKIPPED_KEYS` cap tripped (Invariant 3 — see the security invariants doc). |
| `SESSION_STATE_CORRUPTED` | `restoreSession` (duplicate id) | An internal consistency check failed — should generally be unreachable; treat it as a signal something upstream violated an assumption. |
| `KEY_NOT_FOUND` | responding to a `SESSION_INIT` | The referenced signed/PQ prekey id isn't in your `LocalPrekeyLookup`. |
| `TRANSPORT_FAILURE` | `MockWakuTransport`/`RealWakuTransport` | Publish/subscribe/query failed at the transport layer — see each transport's own error mapping. `WakuMessagingClient` never throws this itself; it only *catches* errors (including this one) from the transport/codec/`SessionManager` and routes them to `onError` — see the self-delivery gotcha above for the most common source of these. |
| `STORAGE_FAILURE` | `decryptSessionRecord`, persistence layer | A session record failed to decrypt (wrong key, or corrupted/tampered data) or wasn't valid JSON after decryption. |
| `INVALID_IDENTITY`, `INVALID_PREKEY` | *(declared, not currently thrown anywhere)* | Reserved in the taxonomy for future, more granular use. |

Nowhere in this library should a raw `TypeError`/`RangeError`/generic
`Error` escape from a rejection path — `test/fuzz/` exists specifically to
keep that true at volume, not just for hand-picked cases (see
[CHANGELOG.md](../CHANGELOG.md)'s Fuzzing entry).

## Security invariants you must not violate as an integrator

This library enforces a lot on its own — see
[docs/security-invariants.md](security-invariants.md) for the full,
tested list. Two are worth calling out here specifically because
*violating them from the outside* is easy to do accidentally and the
library can't stop you:

- **Never call `sendMessage` directly on a persisted session — see
  "Safety first," above.** This is the one this project's own crash
  testing actually caught in practice.
- **Never construct or mutate `Session`/`DoubleRatchetState` fields
  yourself.** Everything you need is reachable through
  `SessionManager`'s own methods (Invariant 10) — reaching into a
  `Session` object to hand-edit its ratchet state defeats the guarantees
  this library exists to provide.

## What this library does not do (you build these yourself)

Being explicit about this is more useful than discovering it midway
through building an app:

1. **Prekey bundle discovery/exchange.** `createSession` requires you to
   already have the recipient's `PreKeyBundle` in hand. There is no
   content topic, wire format, or directory service anywhere in this
   codebase for publishing or fetching one — you need a mechanism for
   that (a server, publishing over a Waku content topic yourself, a QR
   code for a first contact, ...). This is a recorded, deliberate gap,
   not an oversight — see `docs/spec.md`'s Phase 36 for why it's planned
   as a new protocol version rather than something to bolt onto the
   current one, and the two directions worth evaluating when it's
   actually scheduled.
2. **Real key-at-rest storage.** `StaticMasterKeyProvider` is explicitly
   test-only; see "Persistence setup," above.
3. **Prekey rotation policy.** This library generates prekeys and lets you
   check expiry (`isSignedPreKeyExpired`/`isPQPreKeyExpired`) — deciding
   *when* to rotate and republish, and replenishing one-time prekeys
   before they run out, is your application's job.
4. **Multi-device.** Deliberately deferred — see
   [docs/multi-device-future.md](multi-device-future.md) for what that
   would build on (Signal's Sesame algorithm, WhatsApp's per-device-key
   model) rather than a design invented here.
5. **A UI.** This is a protocol core by design (`docs/spec.md`'s Phase
   33: "do not start with the UI").
6. **A security audit.** See [SECURITY.md](../SECURITY.md) — this has not
   happened yet. Don't use this to protect real communications until it
   has.

## Where to go next

- [docs/spec.md](spec.md) — the full protocol specification this
  implementation follows, phase by phase.
- [docs/security-invariants.md](security-invariants.md) — every invariant
  this library enforces, mapped to what proves it.
- [SECURITY.md](../SECURITY.md) — current audit status and design
  principles.
- [CHANGELOG.md](../CHANGELOG.md) — what's landed, phase by phase,
  including the real bugs found and fixed along the way.
