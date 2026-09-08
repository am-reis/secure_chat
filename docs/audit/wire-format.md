# Wire Format Specification

Phase 31, item 4 of [docs/spec.md](../spec.md). Two distinct encodings
exist in this protocol, serving different purposes and audiences — this
document covers both, since conflating them is an easy mistake for a
reader (or an interoperating implementation) to make:

1. **The transport envelope** (protobuf) — what actually crosses the
   network between two parties.
2. **Canonical byte encoding** — a custom, deterministic length-prefixed
   format used *only* for building the byte payloads that get signed or
   fed into AEAD as associated data. It never appears on the wire by
   itself; it's always inside something protobuf already carries as
   opaque `bytes`.

## 1. Transport envelope (protobuf)

Source of truth: `src/transport/proto/envelope.proto`. Generated bindings
(`envelope.pb.js`/`.d.ts`) via `protobufjs`'s pure-JS `pbjs`/`pbts` — no
system `protoc` dependency (`npm run proto:generate`). Codec:
`src/transport/protoEnvelopeCodec.ts`.

Chosen over a hand-rolled binary format (this codebase already has the
length-prefixed canonical-encoding primitives to build one) because this
project's stated direction is desktop first, mobile later, and protobuf
has mature Kotlin/Swift codegen — a hand-rolled format would need
bit-for-bit reimplementation on every future platform.

### `RatchetHeaderProto`

| Field | # | Type | Corresponds to |
|---|---|---|---|
| `ratchet_public_key` | 1 | `bytes` | Double Ratchet header's `dh` (real spec §6.4) |
| `previous_chain_length` | 2 | `uint32` | `pn` |
| `message_number` | 3 | `uint32` | `n` |

### `EnvelopeType` (enum)

| Value | # | Notes |
|---|---|---|
| `ENVELOPE_TYPE_UNSPECIFIED` | 0 | Never used on the wire deliberately — proto3 scalar defaults mean an absent/corrupt `type` field decodes to `0` rather than throwing, so this value exists specifically to make that case explicitly rejected (`INVALID_FORMAT`) rather than silently misinterpreted as one of the two real types below it happened to alias to. |
| `SESSION_INIT` | 1 | |
| `MESSAGE` | 2 | |
| `SESSION_RESET` | 3 | Phase 19 |

`SESSION_CONFIRM`, `DELIVERY_RECEIPT`/`READ_RECEIPT`/`ATTACHMENT`/
`KEY_UPDATE` from `docs/spec.md`'s Phase 11 minimal/optional type lists
are **not** separate envelope types here — receipts and attachments ride
inside an ordinary `MESSAGE`'s ciphertext as `ApplicationContent`
(`src/receipts/applicationContent.ts`), a plaintext-level convention, not
a wire-envelope-level one. `SESSION_CONFIRM` and `KEY_UPDATE` are not
implemented at all yet.

### `EnvelopeProto`

| Field | # | Type | Populated for | Notes |
|---|---|---|---|---|
| `type` | 1 | `EnvelopeType` | all | — |
| `protocol_version` | 2 | `uint32` | all | Checked against `SUPPORTED_PROTOCOL_VERSIONS` before any cryptographic processing (Phase 22) |
| `session_id` | 3 | `bytes` | all | 32 bytes, cryptographically random (Phase 12) |
| `ratchet_header` | 4 | `RatchetHeaderProto` | `SESSION_INIT`, `MESSAGE` | zero-value/absent for `SESSION_RESET` |
| `ciphertext` | 5 | `bytes` | `SESSION_INIT`, `MESSAGE` | XChaCha20-Poly1305 sealed output (24-byte nonce prepended — see the cryptographic design doc's AEAD section); zero-value/absent for `SESSION_RESET` |
| `sender_identity_public_key` | 6 | `bytes` | `SESSION_INIT` only | Alice's long-term Ed25519 public key, 32 bytes |
| `ephemeral_public_key` | 7 | `bytes` | `SESSION_INIT` only | PQXDH's `EK_A`, X25519, 32 bytes |
| `pq_ciphertext` | 8 | `bytes` | `SESSION_INIT` only | ML-KEM-1024 encapsulation ciphertext, 1568 bytes |
| `signed_prekey_id` | 9 | `uint32` | `SESSION_INIT` only | Which of Bob's signed prekeys was used |
| `one_time_prekey_id` | 10 | `optional uint32` | `SESSION_INIT` only | Proto3 `optional` specifically to distinguish "no OTK used" from "OTK id 0" — a plain (non-optional) `uint32` cannot represent that distinction, since proto3 never wire-encodes a scalar at its zero value. **This is load-bearing, not cosmetic** — `test/transport/protoEnvelopeCodec.test.ts` has a dedicated test proving id `0` and "absent" decode to observably different values. |
| `pq_prekey_id` | 11 | `uint32` | `SESSION_INIT` only | Which of Bob's PQ prekeys was used |
| `signature` | 12 | `bytes` | `SESSION_RESET` only | Ed25519 signature, 64 bytes — see below |

Fields 6-11 being present on the same message type as fields 1-5 (rather
than a `oneof` or separate message types per envelope type) is a
deliberate choice: proto3's own field-presence rules already give
`SESSION_INIT`-vs-`MESSAGE` discrimination via `type`, so a `oneof` would
add generated-code complexity without adding any safety this codec
doesn't already have.

### `SESSION_RESET` field semantics

`signature` is an Ed25519 signature over a canonically-encoded payload
(§2 below) built from `domain || protocol_version || session_id` — using
the sender's long-term identity key, not anything derived from the
(possibly-uncertain) ratchet state being reset. See the cryptographic
design document's domain-separation table and `src/session/reset.ts`.

### Content topics (what carries which envelope type)

Per Phase 21, one shared content topic per envelope type, not per
session or per user — see `src/transport/contentTopics.ts`:

| Content topic | Carries |
|---|---|
| `/secure-messaging/{protocolVersion}/session-init/proto` | `SESSION_INIT` |
| `/secure-messaging/{protocolVersion}/message/proto` | `MESSAGE` |
| `/secure-messaging/{protocolVersion}/session-reset/proto` | `SESSION_RESET` |

### Message size limit

150 KiB (`MAX_WAKU_MESSAGE_SIZE`, `src/transport/WakuTransport.ts`) — RFC
64 / nwaku spec (https://github.com/waku-org/nwaku/commit/ed09074c).
Enforced client-side before publish, not assumed as a network-level
guarantee.

## 2. Canonical byte encoding (signed/AD payloads)

Source: `src/encoding/canonical.ts`. Used for every structure this
protocol signs or feeds into an AEAD call as associated data — never for
the transport envelope itself (that's protobuf, above).

**Why not just concatenate the fields?** Plain concatenation is
ambiguous: `concat("ab", "c")` produces byte-for-byte the same output as
`concat("a", "bc")`. An attacker who can influence field boundaries could
exploit that ambiguity against a signature check or an AEAD associated-
data comparison. Every variable-length field here is length-prefixed so
its end is unambiguous regardless of its content.

**`encodeUint32BE(n)`**: 4 bytes, big-endian, for fixed-size numeric
fields (protocol versions, counters, lengths). Throws (`RangeError`) if
`n` isn't a safe non-negative integer in `[0, 0xFFFFFFFF]`.

**`encodeLengthPrefixed(data)`**: `encodeUint32BE(data.length) || data`
— a 4-byte big-endian length header followed by the raw bytes.

**`canonicalEncodeFields(...fields)`**: each field individually
length-prefixed, then concatenated, in argument order:

```
canonicalEncodeFields(f1, f2, f3) =
    encodeUint32BE(len(f1)) || f1 ||
    encodeUint32BE(len(f2)) || f2 ||
    encodeUint32BE(len(f3)) || f3
```

Field **order** is part of the encoding — the same fields in a different
order produce a different (non-colliding) output, so order must match
identically on both sides of any verification.

### Every structure built this way

| Structure | Built by | Fields (in order) |
|---|---|---|
| Signed prekey payload | `src/prekeys/signing.ts` | `domain`, `id` (uint32), `publicKey` |
| PQXDH associated data | `src/pqxdh/associatedData.ts` | `domain`, `initiatorIdentityPublicKey`, `responderIdentityPublicKey` |
| Session associated data | `src/session/associatedData.ts` | `domain`, `protocolVersion` (uint32), PQXDH AD (opaque, already encoded), `sessionId` |
| Per-message associated data | `src/ratchet/header.ts` | `domain`, session AD (opaque), `ratchetPublicKey`, `previousChainLength` (uint32), `messageNumber` (uint32) |
| `SESSION_RESET` signed payload | `src/session/reset.ts` | `domain`, `protocolVersion` (uint32), `sessionId` |

See the cryptographic design document's associated-data-chain section
for how the session/message AD layers compose (each layer's output is
the next layer's opaque input field).

## Fixed byte lengths (from `src/crypto/constants.ts`, cross-checked
against the installed `@noble/*` libraries' own metadata rather than
hand-typed)

| Value | Bytes |
|---|---|
| Ed25519 public key | 32 |
| Ed25519 signature | 64 |
| X25519 public key | 32 |
| ML-KEM-1024 public key | 1568 |
| ML-KEM-1024 ciphertext | 1568 |
| Session id | 32 |
| AEAD nonce (XChaCha20) | 24 |
| Root/chain/message key | 32 each |
