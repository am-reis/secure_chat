# Persistence Specification

Phase 31, item 6 of [docs/spec.md](../spec.md). The at-rest format for
everything this protocol persists, the encryption scheme protecting it,
and the write-ahead mechanism that makes sending safe across a crash.
Scoped to `src/persistence/` and the two records it defines — this
document does not repeat `docs/integration-guide.md`'s "how to use this"
walkthrough, only the exact format and guarantees an audit needs.

## What gets persisted, and what deliberately doesn't

| Persisted | Not persisted (by this library) |
|---|---|
| Session state (ratchet keys, chain state, skipped keys, session metadata) | Identity private key — only a reference id (`localIdentityId`) is stored; the caller supplies the real `Identity` again on load |
| A pending outbox entry (the exact envelope bytes of an unconfirmed send) | The session master key itself — sourced fresh each time via `MasterKeyProvider` |
| — | Prekeys (signed/PQ/one-time) — no persistence module exists for these; see the key lifecycle document |

Excluding the identity private key from session records is deliberate,
not an oversight: an identity is long-lived and shared across many
sessions, so duplicating its private key into every session record would
multiply the attack surface (every session record becomes an identity-key
exposure vector) for no benefit — the caller already has the identity
object in hand to restore a session with.

## Session record format

### 1. `SerializedSession` — the plaintext, JSON-safe projection

`src/persistence/serialize.ts` / `types.ts`. Every `Uint8Array` field is
hex-encoded so the structure survives `JSON.stringify` without a custom
serializer — this is a **local storage format**, not something exchanged
with a remote party, so JSON's lack of canonical byte-for-byte
determinism (unlike the wire format's protobuf/canonical encoding) is
fine here.

| Field | Type | Notes |
|---|---|---|
| `stateVersion` | number | Schema version for *this record shape*, independent of `protocolVersion` — see below |
| `protocolVersion` | number | The session's wire protocol version |
| `sessionId` | hex string | |
| `localIdentityId` | hex string | Reference only — validated, not trusted blindly, on load (see below) |
| `remoteIdentityPublicKey` | hex string | |
| `associatedData` | hex string | The full session AD (cryptographic design doc), fixed for the session's lifetime |
| `createdAt` | number | |
| `ratchetPublicKey` / `ratchetPrivateKey` | hex string | `DHs` keypair — the only place a ratchet private key is ever written to storage |
| `remoteRatchetPublicKey` | hex string or `null` | `DHr` |
| `rootKey` | hex string | |
| `sendingChainKey` / `receivingChainKey` | hex string or `null` | |
| `sendingMessageNumber` / `receivingMessageNumber` / `previousSendingChainLength` | number | |
| `skippedMessageKeys` | array of `{index, key}` | `index` is the same `${hex(ratchetPublicKey)}:${messageNumber}` string used in memory (`skippedKeyIndex`) |

**Two independent version fields, deliberately**: `stateVersion` (this
record *shape*) and `protocolVersion` (the *wire protocol* the session
speaks) can change independently — a schema migration doesn't imply a
protocol version bump, and vice versa. Conflating them would be the same
class of mistake `docs/git-workflow.md` warns about for the package
SemVer vs. protocol version distinction, one layer down.

**Round-trip validation on load** (`deserializeSession`) — fails closed
on either mismatch, rather than silently producing broken state:

- The supplied `localIdentity.identityId` must match
  `serialized.localIdentityId` exactly, or it throws
  `SESSION_STATE_CORRUPTED`. Loading against the wrong identity would
  otherwise silently produce ratchet state that can never successfully
  encrypt or decrypt anything — a confusing failure to debug later, so
  it's rejected immediately instead.
- `serialized.stateVersion` must equal `CURRENT_SESSION_STATE_VERSION`
  (currently `1`), or it throws the same error. There is currently no
  migration path from an older `stateVersion` — a schema change today
  would need one added, not just the constant bumped.

### 2. Encryption at rest

`src/persistence/encryptedStorage.ts`. The `SerializedSession` above is
`JSON.stringify`'d, then AEAD-sealed:

```
plaintext = JSON.stringify(SerializedSession)
ciphertext = AEAD-Seal(masterKey, plaintext, associatedData = sessionId)
```

Using `sessionId` as associated data means an attacker with raw access to
the underlying key-value store cannot swap which encrypted blob lives
under which session's storage key without the swap being detected as an
AEAD authentication failure on load — the ciphertext is cryptographically
bound to the specific record it's stored under, not just encrypted in
place. `decryptSessionRecord` maps any AEAD failure (wrong key, or
corrupted/tampered data) to `ProtocolError("STORAGE_FAILURE")`, and any
post-decrypt JSON parse failure to the same code — both fail-closed, both
classified, never a raw exception (`test/fuzz/decryptSessionRecord.fuzz.test.ts`
exercises this at volume with random ciphertext bytes).

`MasterKeyProvider` (`getMasterKey(): Promise<32 bytes>`) sources the
encryption key. Entirely out of this library's scope how that key is
actually stored — see the key lifecycle document and the integration
guide; `StaticMasterKeyProvider` is explicitly test-only.

### 3. Storage key layout

`RawKeyValueStore` (`get`/`set`/`delete`/`list(prefix)`) is a flat,
prefix-queryable key-value abstraction — no assumption about the backend
(disk, IndexedDB, SQLite, ...). Two key prefixes are used:

| Prefix | Format | Holds |
|---|---|---|
| `session:` | `session:` + hex(sessionId) | An encrypted `SerializedSession` record |
| `outbox:` | `outbox:` + hex(sessionId) | A pending outbox entry (see below) — at most one per session at a time |

`listSessionIds` lists everything under the `session:` prefix and strips
it back off to recover the raw session ids.
`InMemoryKeyValueStore` (what this library ships, and what its own test
suite runs against) is **not durable** — it exists to make the interface
testable without a real backend; a production deployment must supply its
own implementation.

## Outbox: write-ahead logging for safe sending

`src/persistence/outbox.ts`, `src/session/durableMessaging.ts`. Exists
because of a real defect found during this project's own crash-recovery
testing (Phase 30 — see `CHANGELOG.md`): `ratchetEncrypt`'s chain-key
derivation is a pure, deterministic function of the current chain key, so
persisting session state *alone* isn't sufficient write-ahead protection
— a crash could still happen after the state advances but before the
resulting envelope is actually handed to the transport, and a naive retry
(call `sendMessage` again after restoring the stale, pre-advance state)
would derive a *different* message under the *same*
`(ratchetPublicKey, messageNumber)` identity as whatever was already
transmitted — permanently undecryptable to the recipient if the first one
arrived.

**The single-slot record**: at most one pending outbox entry per session,
keyed the same way session records are (`outbox:` + hex(sessionId)) —
just the raw encoded envelope bytes, no encryption of its own (it's
already either plaintext-adjacent ratchet ciphertext, or — for a
`SESSION_RESET` — a signed-but-otherwise-non-secret notice; nothing in an
outbox entry is sensitive in a way the session record encryption isn't
already covering at the transport-envelope level).

**The safe sequence** (`sendMessageDurably`):

```
1. sessionManager.sendMessage(...)   — advances in-memory ratchet state
2. saveSession(...)                   — persist the ADVANCED state
3. saveOutboxEntry(...)               — persist the envelope itself
4. transport.publish(...)             — attempt transmission
5. clearOutboxEntry(...)              — only once transmission succeeded
```

If steps 1-3 complete but the process dies before step 4 or 5 confirms,
`resumePendingOutbox` (called on every session restore, before anything
else touches it) finds the pending entry and retransmits the **exact**
saved bytes — never re-derives a new message. A duplicate delivery from
retransmitting an already-successfully-sent message is safely deduped by
the ratchet's own existing replay protection (Invariant 1) — the
recipient's application still only ever sees it once.

The receiving side needs no equivalent mechanism: `ratchetDecrypt` is
already side-effect-free until the AEAD check succeeds (Invariant 4), so
a crash before persisting a *received* message is automatically safe —
redelivery after restart just decrypts correctly again, no write-ahead
step required.

See `test/crashRecovery/crashRecovery.test.ts` (the original regression
test formalizing the defect this exists to prevent) and
`test/examples/persistenceAndDurableMessaging.test.ts` (the recipe,
narrated in the integration guide) for this proven end to end rather than
just described.
