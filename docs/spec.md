# Secure Messaging Protocol — Implementation Specification

## 0. Mission

Implement a secure 1:1 asynchronous messaging protocol whose transport is **Waku**.

The system must provide:

- Authenticated user identities.
- Asynchronous session establishment.
- Forward secrecy.
- Post-compromise recovery through DH ratcheting.
- Per-message encryption keys.
- Replay protection.
- Out-of-order message handling.
- Offline message delivery.
- Crash-safe persistent cryptographic state.
- Protection against malicious, replayed, or malformed protocol messages.
- Clean separation between cryptographic state and transport.

The cryptographic design is structurally based on:

```
PQXDH
   ↓
Double Ratchet
   ↓
AEAD
   ↓
Application envelope
   ↓
Waku transport
```

The implementation does **not** need interoperability with Signal.

However, where this specification refers to PQXDH or Double Ratchet, **follow the corresponding Signal specification rather than inventing a protocol variant.**

**Primary references:**

- Signal PQXDH specification: https://signal.org/docs/specifications/pqxdh/
- Signal Double Ratchet specification: https://signal.org/docs/specifications/doubleratchet/

---

## Phase 0 — Architecture and Threat Model

### 0.1 Trust boundaries

The system consists of:

```
User Device
    │
    ├── Identity / Key Manager
    ├── Prekey Manager
    ├── PQXDH
    ├── Double Ratchet
    ├── Session Manager
    ├── Message Store
    └── Waku Adapter
             │
             ▼
           Waku
```

The Waku network must be treated as an **untrusted transport**.

**Assume an attacker can:**

- Read all Waku messages.
- Copy messages.
- Replay messages.
- Delay messages.
- Drop messages.
- Reorder messages.
- Inject arbitrary malformed messages.
- Modify messages.
- Attempt to substitute public keys.
- Observe Waku metadata.
- Operate malicious Waku nodes.
- Obtain historical ciphertexts and later compromise a device.
- Temporarily compromise a device and subsequently lose access.

**Do not assume:**

- Reliable delivery.
- Ordered delivery.
- Exactly-once delivery.
- Waku availability.
- Honest storage nodes.
- Honest routing nodes.
- Confidentiality of Waku metadata.

### 0.2 Security goals

| Goal | Description |
|---|---|
| **Authentication** | A session must be cryptographically associated with the intended identities. |
| **Confidentiality** | Only the intended participants can decrypt messages. |
| **Integrity** | Modification of ciphertext, headers, or authenticated metadata must cause decryption failure. |
| **Forward secrecy** | Compromise of current state must not expose previously deleted message keys. |
| **Post-compromise recovery** | After a compromise, subsequent DH ratchet steps must introduce fresh entropy the attacker does not possess. |
| **Replay resistance** | A previously accepted message must not be accepted as a new message. |
| **Out-of-order support** | Messages may arrive in arbitrary order within protocol limits. |
| **Offline support** | Either participant may be offline while the other initiates or sends messages. |

---

## Phase 1 — Cryptographic Primitives

**Do not implement cryptographic primitives manually.** Use established, maintained implementations.

The protocol requires:

- X25519.
- Ed25519/XEdDSA-compatible identity/signature functionality as required by the selected PQXDH profile.
- A standardized post-quantum KEM.
- HKDF.
- SHA-256 or SHA-512 according to the selected protocol profile.
- AEAD.
- Cryptographically secure random number generation.

Create a crypto abstraction:

```typescript
interface CryptoProvider {
    generateX25519KeyPair(): KeyPair;

    x25519(
        privateKey: Uint8Array,
        publicKey: Uint8Array
    ): Uint8Array;

    generateIdentityKeyPair(): IdentityKeyPair;

    sign(
        privateKey: Uint8Array,
        data: Uint8Array
    ): Uint8Array;

    verify(
        publicKey: Uint8Array,
        data: Uint8Array,
        signature: Uint8Array
    ): boolean;

    generateKemKeyPair(): KemKeyPair;

    kemEncapsulate(
        publicKey: Uint8Array
    ): {
        ciphertext: Uint8Array;
        sharedSecret: Uint8Array;
    };

    kemDecapsulate(
        privateKey: Uint8Array,
        ciphertext: Uint8Array
    ): Uint8Array;

    hkdfExtract(
        salt: Uint8Array,
        inputKeyMaterial: Uint8Array
    ): Uint8Array;

    hkdfExpand(
        prk: Uint8Array,
        info: Uint8Array,
        length: number
    ): Uint8Array;

    aeadEncrypt(
        key: Uint8Array,
        plaintext: Uint8Array,
        associatedData: Uint8Array
    ): Uint8Array;

    aeadDecrypt(
        key: Uint8Array,
        ciphertext: Uint8Array,
        associatedData: Uint8Array
    ): Uint8Array;

    randomBytes(length: number): Uint8Array;

    secureErase(buffer: Uint8Array): void;
}
```

The rest of the application must depend on this abstraction rather than directly on crypto libraries.

### 1.1 Primitive tests

Before implementing the protocol, create deterministic tests for every primitive.

Test:

- X25519 known vectors.
- Signature verification.
- Signature failure.
- KEM encapsulation/decapsulation.
- HKDF.
- AEAD encryption/decryption.
- AEAD tampering.
- Invalid public keys.
- Invalid ciphertexts.
- Randomness failures.

**No protocol work proceeds until these tests pass.**

---

## Phase 2 — Identity System

Each user has a long-term identity.

```typescript
interface IdentityKeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

interface Identity {
    identityId: Uint8Array;
    keyPair: IdentityKeyPair;
    createdAt: number;
    version: number;
}
```

The identity private key must:

- Never leave the device.
- Never be transmitted.
- Never be included in plaintext application messages.
- Be stored using platform-secure storage where available.
- Be encrypted at rest if persisted outside secure hardware/keychain facilities.

### 2.1 Identity identifier

```
identityId = Hash(canonicalIdentityPublicKey)
```

Use a fixed-length binary identifier.

Do not use a raw public key as a Waku content topic.

### 2.2 Identity verification

The application must support an explicit identity-verification mechanism.

Possible mechanisms:

- QR code.
- Safety number.
- Short authentication string.
- Manual public-key fingerprint comparison.

The verification mechanism must be cryptographically bound to the identity key.

---

## Phase 3 — Prekey Infrastructure

PQXDH is asynchronous: Bob can publish prekey material while offline, allowing Alice to initiate a session later.

Implement:

- Identity Key
- Signed EC Prekey
- Signed PQ Prekey
- One-Time EC Prekeys

### 3.1 Signed prekey

Generate `SPK_B`. Sign it using Bob's identity authentication capability.

```typescript
interface SignedPreKey {
    id: number;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    signature: Uint8Array;
    createdAt: number;
    expiresAt: number;
}
```

Rotate signed prekeys periodically.

Never delete the currently active signed prekey until its replacement is safely deployed.

### 3.2 One-time prekeys

Generate a pool:

```
OPK_001
OPK_002
OPK_003
...
```

Each must be:

- Unique.
- Randomly generated.
- Used at most once.
- Marked consumed atomically.

State transition:

```
AVAILABLE
    ↓
RESERVED
    ↓
CONSUMED
```

A crash must never cause the same one-time key to be handed to two sessions.

### 3.3 PQ prekeys

Generate and publish the PQ KEM prekey according to the selected PQXDH profile.

Sign it with the identity authentication key.

```typescript
interface PQPreKey {
    id: number;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    signature: Uint8Array;
    createdAt: number;
    expiresAt: number;
}
```

---

## Phase 4 — Prekey Bundle

Define the canonical prekey bundle:

```typescript
interface PreKeyBundle {
    protocolVersion: number;

    identityPublicKey: Uint8Array;

    signedPreKey: {
        id: number;
        publicKey: Uint8Array;
        signature: Uint8Array;
    };

    oneTimePreKey?: {
        id: number;
        publicKey: Uint8Array;
    };

    pqPreKey: {
        id: number;
        publicKey: Uint8Array;
        signature: Uint8Array;
    };
}
```

The exact cryptographic encoding must be deterministic. Never sign ambiguous serialization.

Use `canonicalEncode(value)` for all signed structures.

### 4.1 Bundle validation

Before use:

```
validateProtocolVersion()
validateKeyLengths()
validateKeyEncodings()
verifySignedPreKey()
verifyPQPreKey()
validateIdentifiers()
```

Reject the entire bundle if any required validation fails.

---

## Phase 5 — PQXDH Implementation

Implement PQXDH as an isolated module:

- `PQXDHInitiator`
- `PQXDHResponder`

Do not mix PQXDH state with Double Ratchet state.

The PQXDH protocol consists conceptually of:

1. Bob publishes key material.
2. Alice retrieves the bundle and initiates.
3. Bob processes the initial message.
4. Both derive the same initial shared secret.
5. The resulting secret initializes the Double Ratchet.

### 5.1 Initiator

**Input:** Alice identity, Bob prekey bundle

Alice:

1. Validates Bob's bundle.
2. Verifies Bob's signed prekeys.
3. Selects a one-time prekey if available.
4. Generates an ephemeral X25519 key pair.
5. Performs the required classical DH operations.
6. Performs PQ KEM encapsulation.
7. Derives the PQXDH shared secret.
8. Derives the associated-data value.
9. Initializes the Double Ratchet.
10. Encrypts the initial message.
11. Produces the PQXDH initial envelope.

Conceptually, the classical portion contains DH values equivalent to:

```
DH1 = DH(IK_A, SPK_B)
DH2 = DH(EK_A, IK_B)
DH3 = DH(EK_A, SPK_B)

if OPK_B exists:
    DH4 = DH(EK_A, OPK_B)
```

The PQ component is:

```
(pqCiphertext, pqSharedSecret) =
    KEM.Encapsulate(PQPreKey_B)
```

The final `SK` must be derived using the **exact PQXDH KDF construction**, including its domain separation, encoding, padding, and role/context binding.

**Do not** replace the specification with an ad-hoc:

```
HKDF(DH1 || DH2 || DH3 || pqSharedSecret)
```

implementation.

### 5.2 Initial message

```typescript
interface PQXDHInitialMessage {
    protocolVersion: number;

    initiatorIdentityKey: Uint8Array;
    initiatorEphemeralKey: Uint8Array;

    signedPreKeyId: number;
    oneTimePreKeyId?: number;
    pqPreKeyId: number;

    pqCiphertext: Uint8Array;

    initialRatchetMessage: Uint8Array;
}
```

The exact cryptographic fields must follow the selected PQXDH profile.

### 5.3 Responder

Bob:

1. Validates protocol version.
2. Validates Alice's identity key encoding.
3. Finds the referenced signed prekey.
4. Finds the referenced one-time prekey.
5. Finds the referenced PQ prekey.
6. Validates all identifiers.
7. Performs the corresponding DH operations.
8. Performs PQ decapsulation.
9. Reconstructs SK.
10. Reconstructs AD.
11. Initializes Double Ratchet.
12. Attempts to authenticate/decrypt the initial message.
13. Only after successful authentication commits session state.
14. Atomically consumes the one-time prekey.

**Important:** Do not permanently mutate session state before authentication succeeds.

---

## Phase 6 — Double Ratchet

Implement the Double Ratchet as an explicit state machine.

Core state:

```typescript
interface DoubleRatchetState {
    DHs: KeyPair;
    DHr: Uint8Array | null;

    rootKey: Uint8Array;

    sendingChainKey: Uint8Array | null;
    receivingChainKey: Uint8Array | null;

    sendingMessageNumber: number;
    receivingMessageNumber: number;

    previousSendingChainLength: number;

    skippedMessageKeys: Map<string, Uint8Array>;
}
```

The exact state and transition rules must follow the Double Ratchet specification.

### 6.1 Root chain

When a DH ratchet occurs:

```
oldRootKey
      +
new DH shared secret
      ↓
newRootKey
newChainKey
```

The DH output is never directly used as a message-encryption key.

### 6.2 Symmetric ratchet

For every message:

```
chainKey
    ↓
   KDF
    ├── nextChainKey
    └── messageKey
```

Then:

```
plaintext
    ↓
AEAD(messageKey)
    ↓
ciphertext
```

Delete the message key after successful use.

### 6.3 DH ratchet

When a new remote ratchet public key is received:

```
receive remote DH public key
        ↓
DH(localPrivate, remotePublic)
        ↓
     root KDF
        ↓
new receiving chain
        ↓
generate new local DH keypair
        ↓
DH(newLocalPrivate, remotePublic)
        ↓
     root KDF
        ↓
new sending chain
```

Then decrypt using the appropriate receiving-chain message key.

### 6.4 Message header

```typescript
interface RatchetHeader {
    ratchetPublicKey: Uint8Array;
    previousChainLength: number;
    messageNumber: number;
}
```

These correspond conceptually to `DH`, `PN`, `N` in the Double Ratchet specification.

---

## Phase 7 — Associated Data

Every encrypted message must authenticate its protocol context.

Construct canonical associated data containing at least:

- `protocolVersion`
- `initiatorIdentity`
- `responderIdentity`
- `sessionId`
- `ratchetHeader`

For example:

```
AD =
    Encode(protocolVersion)
    ||
    Encode(initiatorIdentity)
    ||
    Encode(responderIdentity)
    ||
    Encode(sessionId)
    ||
    Encode(ratchetHeader)
```

The exact encoding must be deterministic.

Never allow the recipient to decrypt successfully if authenticated protocol metadata has been modified.

---

## Phase 8 — Out-of-Order and Skipped Messages

**This is mandatory.**

If the current receive-chain position is `10` and a message arrives with `messageNumber = 17`, derive and temporarily store:

```
MK_10
MK_11
MK_12
MK_13
MK_14
MK_15
MK_16
```

Then use `MK_17` for the received message.

Store skipped keys using `(remoteRatchetPublicKey, messageNumber)` as the logical index.

### 8.1 Maximum skip

```typescript
const MAX_SKIP = ...;
```

Do not permit an attacker to force derivation of millions of keys.

If:

```
incomingMessageNumber - currentMessageNumber > MAX_SKIP
```

reject the message.

Also enforce a global maximum number of stored skipped keys.

---

## Phase 9 — Application Message Protocol

Do not expose internal Double Ratchet state to the UI.

```typescript
interface MessagingSession {
    createSession(remoteIdentity: Identity): Promise<SessionId>;

    sendMessage(
        sessionId: SessionId,
        plaintext: Uint8Array
    ): Promise<EncryptedEnvelope>;

    receiveMessage(
        envelope: EncryptedEnvelope
    ): Promise<Uint8Array>;

    getSessionState(
        sessionId: SessionId
    ): Promise<SessionState>;
}
```

The application sees:

```
plaintext
    ↓
MessagingSession
    ↓
encrypted envelope
```

The application never directly manipulates: `rootKey`, `chainKey`, `messageKey`, DH private key.

---

## Phase 10 — Message Envelope

Use a deterministic binary serialization format. Protobuf is a suitable option.

Example logical structure:

```
EncryptedMessage {
    protocolVersion

    messageType

    sessionId

    senderIdentityId

    ratchetPublicKey

    previousChainLength

    messageNumber

    ciphertext

    pqxdhInitialData
}
```

Keep the envelope minimal. Do not put unnecessary plaintext metadata into the envelope.

---

## Phase 11 — Message Types

At minimum:

- `SESSION_INIT`
- `MESSAGE`
- `SESSION_CONFIRM`
- `SESSION_RESET`

Optional later:

- `DELIVERY_RECEIPT`
- `READ_RECEIPT`
- `ATTACHMENT`
- `KEY_UPDATE`

---

## Phase 12 — Session IDs

Generate a cryptographically random session identifier.

Do not derive it from `userA + userB`. Instead:

```
sessionId = random(128 or 256 bits)
```

Bind the session ID into the authenticated data.

---

## Phase 13 — Persistent Session State

The Double Ratchet is stateful. Persist:

```typescript
interface PersistentSession {
    sessionId: Uint8Array;

    remoteIdentity: Uint8Array;

    localRatchetPrivateKey: Uint8Array;
    localRatchetPublicKey: Uint8Array;

    remoteRatchetPublicKey: Uint8Array;

    rootKey: Uint8Array;

    sendingChainKey: Uint8Array | null;
    receivingChainKey: Uint8Array | null;

    sendingMessageNumber: number;
    receivingMessageNumber: number;

    previousChainLength: number;

    skippedMessageKeys: SkippedMessageKey[];

    protocolVersion: number;
    stateVersion: number;
}
```

Private cryptographic state must be encrypted at rest.

Use platform-secure key storage for the master encryption key where possible.

---

## Phase 14 — Transactional Message Processing

Receiving a message must be atomic.

Conceptually:

```
BEGIN TRANSACTION

load session

validate envelope

derive temporary ratchet state

derive message key

AEAD decrypt

if successful:
    commit new ratchet state
    delete consumed message key
    persist skipped keys

COMMIT
```

On failure: `ROLLBACK`

Never permanently advance ratchet state merely because a message was received. Advance it only after successful authentication/decryption.

---

## Phase 15 — Replay Protection

Every accepted message must have a logical identity:

```
sessionId
+
ratchetPublicKey
+
messageNumber
```

Rules:

- Already decrypted → reject/ignore replay
- New message → process
- Invalid authentication → reject
- Message outside `MAX_SKIP` → reject

Do not advance the ratchet merely because a replay was observed.

---

## Phase 16 — Initial Message Retransmission

The initial PQXDH message may be lost.

Alice must be able to retransmit the initial message. Retransmission must not create multiple independent sessions.

Bob must recognize duplicate initial messages and converge on the same session state.

The implementation should make initial-session creation idempotent.

---

## Phase 17 — Failure Handling

Every failure must have an explicit classification:

- `INVALID_FORMAT`
- `UNSUPPORTED_VERSION`
- `UNKNOWN_SESSION`
- `INVALID_IDENTITY`
- `INVALID_SIGNATURE`
- `INVALID_PREKEY`
- `INVALID_PQ_CIPHERTEXT`
- `AEAD_AUTHENTICATION_FAILED`
- `REPLAY`
- `MESSAGE_TOO_FAR_AHEAD`
- `SESSION_STATE_CORRUPTED`
- `KEY_NOT_FOUND`
- `TRANSPORT_FAILURE`
- `STORAGE_FAILURE`

Never expose detailed cryptographic errors to the remote peer.

Internally, diagnostics may be logged, but: **never log private keys, root keys, chain keys, message keys, plaintext, or raw session secrets.**

---

## Phase 18 — Key Lifecycle

| Key | Policy |
|---|---|
| **Identity key** | Long-lived. Recovery/backup requires a separate security design. |
| **Signed prekey** | Rotated periodically. |
| **One-time prekeys** | Consumed exactly once. |
| **PQ prekey** | Rotated according to the selected PQXDH deployment policy. |
| **Ratchet private keys** | Rotated by the DH ratchet. |
| **Message keys** | Delete immediately after use. |
| **Old chain keys** | Delete when no longer needed. |
| **Skipped keys** | Delete after: successful use, expiry, session reset, or security-policy timeout. |

---

## Phase 19 — Session Reset

A session may become unrecoverable because of:

- Database corruption.
- Device restore.
- Lost ratchet state.
- Incompatible protocol version.
- Explicit user action.
- Excessive skipped-message state.
- Key material loss.

Implement `RESET_SESSION`.

If cryptographic state is uncertain: destroy session, establish new PQXDH session.

Do not attempt to repair inconsistent Double Ratchet state by guessing or reconstructing missing keys.

---

## Phase 20 — Waku Transport Adapter

Waku is transport, not cryptographic session state.

```typescript
interface WakuTransport {
    connect(): Promise<void>;

    disconnect(): Promise<void>;

    publish(
        envelope: Uint8Array
    ): Promise<void>;

    subscribe(
        callback: (envelope: Uint8Array) => Promise<void>
    ): Promise<void>;

    retrieveHistory(
        ...
    ): Promise<Uint8Array[]>;
}
```

The application protocol must not depend on whether the underlying Waku mechanism is: Relay, Filter, Store, Light Push, or another future transport.

For mobile/light clients, a possible architecture is:

```
Mobile App
    │
    ├── Light Push → sending
    │
    ├── Filter     → receiving
    │
    └── Store      → missed messages
```

Waku documentation describes these as separate transport capabilities.

---

## Phase 21 — Waku Content Topics

Do not use `/user/<public-key>` as a content topic. Content topics can be visible to infrastructure participants.

Use an application-level topic such as:

```
/myapp/1/message/proto
```

or another privacy-conscious partitioning scheme.

Keep recipient/session identity inside the encrypted application envelope whenever possible.

---

## Phase 22 — Message Routing

A received Waku message goes through:

```
Waku
 ↓
Envelope parser
 ↓
Protocol version validation
 ↓
Structural validation
 ↓
Session lookup
 ↓
PQXDH processing OR Double Ratchet processing
 ↓
AEAD authentication
 ↓
plaintext
 ↓
application
```

Perform cheap structural validation before expensive cryptographic processing.

---

## Phase 23 — Session Lookup

**Known session:** If the `sessionId` exists → Double Ratchet processes the message.

**Unknown session + `SESSION_INIT`:** Process PQXDH and create the session only after successful authentication.

**Unknown session + ordinary `MESSAGE`:** Reject.

Never automatically create a session from an arbitrary encrypted message.

---

## Phase 24 — Attachments

Do not put large attachments directly into encrypted messaging envelopes. Instead:

```
random attachment key
        ↓
encrypt attachment
        ↓
upload encrypted blob
        ↓
send encrypted attachment descriptor
```

The descriptor may contain:

```typescript
AttachmentDescriptor {
    objectId
    encryptionKey
    hash
    size
    mimeType
}
```

The entire descriptor must be encrypted inside the Double Ratchet message.

The attachment storage system therefore sees encrypted data only.

---

## Phase 25 — Delivery Semantics

Do not treat successful Waku publication as successful recipient delivery.

Use application states:

```
CREATED → ENCRYPTED → QUEUED → PUBLISHED → RECEIVED → DECRYPTED → ACKNOWLEDGED
```

A transport-level acknowledgement means the transport accepted the message. It does not prove that the intended recipient received or decrypted it.

If delivery receipts are implemented, they must themselves be encrypted application messages.

---

## Phase 26 — Delivery and Read Receipts

Optional for the first version.

Define `DELIVERY_RECEIPT` and `READ_RECEIPT`.

Both are ordinary encrypted Double Ratchet messages.

Do not use transport metadata as delivery/read receipts.

---

## Phase 27 — Protocol Versioning

Every envelope contains `protocolVersion` (e.g. `1`).

Never silently change cryptographic parameters under an existing protocol version. A cryptographic parameter change requires a new protocol version.

For example:

```
/myapp/1/message/proto
/myapp/2/message/proto
```

---

## Phase 28 — Testing Strategy

Testing must occur at four levels.

### 28.1 Primitive tests

Test every cryptographic primitive independently.

### 28.2 Protocol tests

Test Alice ↔ Bob using deterministic test vectors. Verify:

- Same shared secret
- Same authenticated data
- Same initial session
- Same root state
- Same chain keys
- Same message keys

### 28.3 Adversarial protocol tests

Automatically test:

- Modified ciphertext.
- Modified header.
- Modified identity.
- Modified session ID.
- Replay.
- Duplicate initial message.
- Deleted message.
- Duplicated message.
- Reordered messages.
- Skipped messages.
- Excessive message skip.
- Wrong ratchet key.
- Wrong session.
- Wrong prekey.
- Expired prekey.
- Reused one-time prekey.
- Invalid PQ ciphertext.
- Invalid public key.
- Corrupted database state.
- Crash during encryption.
- Crash during decryption.
- Crash during ratchet advancement.

### 28.4 Transport tests

Simulate transport as an adversarial unreliable network:

```
drop()
duplicate()
delay()
reorder()
corrupt()
partition()
reconnect()
```

Cryptographic correctness must remain independent of transport reliability.

---

## Phase 29 — Property-Based Testing

Add properties such as:

```
decrypt(encrypt(M)) == M
```

for arbitrary messages.

Tampering properties:

```
tamper(ciphertext) → decrypt fails
tamper(header)     → decrypt fails
tamper(AD)         → decrypt fails
```

Replay property:

```
replay(message) → message is not delivered twice
```

Ordering property:

```
reorder(messages) → valid messages eventually decrypt
```

---

## Phase 30 — Crash and Recovery Testing

Inject crashes at every state transition:

- before encryption
- after message-key derivation
- after encryption
- before persistence
- after persistence
- before key deletion
- after key deletion

After restart: load persisted state, continue protocol.

No message should become permanently undecryptable merely because the process crashed.

---

## Phase 31 — Security Audit Preparation

Before production, produce:

1. Threat Model
2. Cryptographic Design Document
3. Protocol State Machine
4. Wire Format Specification
5. Key Lifecycle Specification
6. Persistence Specification
7. Security Invariants
8. Test Vector Suite
9. Fuzzing Results
10. Dependency Inventory

Every cryptographic assumption must have: property, mechanism, assumption, test.

---

## Phase 32 — Security Invariants

The implementation must preserve these invariants.

1. A message key is never reused.
2. A message key is never derived from plaintext.
3. A remote party cannot force unbounded key derivation.
4. Failed AEAD authentication does not permanently mutate session state.
5. A consumed one-time prekey cannot be reused.
6. Old message keys are deleted.
7. Ratchet private keys are never serialized into logs.
8. Identity private keys never enter the transport layer.
9. Transport metadata is never assumed confidential.
10. The application never directly manipulates ratchet state.

---

## Phase 33 — Implementation Order

The coding agent must implement in this order:

1. Repository / architecture
2. CryptoProvider abstraction
3. Cryptographic primitive tests
4. Identity management
5. Prekey generation
6. Prekey bundle
7. PQXDH
8. PQXDH test vectors
9. Double Ratchet
10. Double Ratchet test vectors
11. Out-of-order handling
12. Persistent session state
13. Application envelope
14. Session manager
15. Waku adapter
16. Offline/store synchronization
17. Replay protection
18. Crash recovery
19. Adversarial transport tests
20. Fuzzing
21. Security hardening
22. Performance testing
23. Multi-device
24. Attachments
25. Delivery/read receipts

**Do not** start with the UI. **Do not** start with Waku integration. **Do not** start with message persistence.

The first milestone must be a completely in-memory implementation:

```
Alice
  │
  │ PQXDH
  ▼
Shared session
  │
  │ Double Ratchet
  ▼
Message 1
  │
  │ Double Ratchet
  ▼
Message 2
```

It must pass deterministic tests before transport integration begins.

---

## Phase 34 — Definition of Done

**Identity**
- Two users have independently generated identities.
- Identity fingerprints can be compared.
- Identity private keys never leave local storage.

**PQXDH**
- Alice can establish a session while Bob is offline.
- Bob can later reconstruct the session.
- One-time prekeys are consumed exactly once.
- Invalid signatures are rejected.
- Invalid PQ ciphertexts are rejected.
- Initial ciphertext authentication works.
- Duplicate initial messages do not create duplicate sessions.

**Double Ratchet**
- Every message receives a unique message key.
- DH ratchets occur correctly.
- Sending and receiving chains remain synchronized.
- Out-of-order messages decrypt.
- Skipped keys are bounded.
- Replayed messages are rejected.
- Old message keys are deleted.
- Session state survives process restart.

**Transport**
- Messages can be delayed.
- Messages can be duplicated.
- Messages can be reordered.
- Messages can be dropped.
- Offline messages can be retrieved.
- None of these conditions compromise cryptographic correctness.

**Security**
- Ciphertext tampering fails.
- Header tampering fails.
- Associated-data tampering fails.
- Identity substitution fails.
- Prekey substitution fails.
- Session confusion fails.
- Malformed messages cannot corrupt persistent state.
- No secret key appears in application logs.

---

## Phase 35 — Future Post-Quantum Ratcheting

Do not implement this in the first milestone.

PQXDH provides post-quantum protection for session establishment, but the classical Double Ratchet itself is based on DH.

The current Signal specification defines a **Sparse Post-Quantum Ratchet (SPQR)** and a **Triple Ratchet** that combine classical and post-quantum ratcheting for ongoing conversations.

The future architecture is:

```
PQXDH
   ↓
Double Ratchet + SPQR
   ↓
Triple Ratchet
```

The Triple Ratchet combines classical and PQ ratchet outputs so that an attacker needs to compromise both cryptographic assumptions to recover subsequent message keys.

Implement this as a separate protocol version rather than silently modifying the first implementation.

---

## Phase 36 — Prekey Bundle Discovery and Directory Service (Protocol v2)

**Do not implement this in the first milestone.** Recorded here as a
known, deliberate gap in the first implementation, not an oversight
discovered late: `PQXDHInitiator`/`SessionManager.createSession` (Phase 5,
Phase 9) both require the caller to already have the recipient's
`PreKeyBundle` (Phase 4) in hand. Nothing in Phase 1 through Phase 35
defines how a bundle actually gets from the device that generated it
(Phase 3) to the device that wants to start a session with it. Every other
piece of data this protocol moves — session envelopes, resets, receipts,
attachment descriptors — has an explicit content-topic and wire-format
answer (Phase 10, Phase 21). Bundle discovery does not, and that's a real
gap in "Alice can establish a session while Bob is offline" (Phase 34's
own Definition of Done), not just an application-integration detail.

It is being deferred rather than retrofitted into the current protocol
version for the same reason Phase 35 is: this needs its own explicit
design, reviewed on its own terms, not one invented mid-implementation of
something else. It also isn't a small addition — unlike a new message
type (Phase 11's `optional later` list), a directory mechanism touches
metadata-privacy analysis (Phase 21's own reasoning: a naive
`/app/<identityId>/bundle` content topic would leak exactly the kind of
"who has published an identity" information Phase 21 designed shared
topics specifically to avoid), freshness/staleness semantics for
published bundles, and — for one-time prekeys specifically — a
consumption race that a passive directory doesn't solve on its own (two
initiators fetching the "same" bundle concurrently must not be able to
both consume the same one-time prekey; Phase 3's `AVAILABLE → RESERVED →
CONSUMED` lifecycle assumes a single trusted party, the bundle's own
owner, arbitrates reservation — a public directory serving bundles to
arbitrary fetchers is a different trust structure).

Two directions worth evaluating when this is actually scheduled, not a
decision made here:

1. **A dedicated Waku content topic per identity, sharded/rotated the way
   Phase 21 already discusses as a real deployment's option for the
   existing shared topics** — keeps everything on the same transport this
   protocol already depends on, but needs its own metadata-privacy
   analysis (a per-identity topic is inherently more linkable than the
   current shared topics) and doesn't have an obvious answer for one-time
   prekey reservation races without the identity's own device being
   online to arbitrate.
2. **A separate directory/lookup service**, outside Waku, that identities
   publish signed bundles to and that can enforce one-time prekey
   reservation server-side — closer to how Signal's own key server works,
   at the cost of a centralized (or federated) component this
   transport-agnostic core has otherwise avoided needing.

Whatever is chosen, per Phase 27's existing versioning discipline: this
is a wire-format and protocol-behavior change, so it ships as a new
`protocolVersion` value, not a silent extension of the version this
implementation currently speaks. `SUPPORTED_PROTOCOL_VERSIONS` already
exists precisely to make an old client's explicit rejection of a v2-only
message clean rather than a confusing failure deep in PQXDH processing.

---

## Final Architecture

The final system should have these boundaries:

```
┌───────────────────────────────────────────┐
│                 Application               │
│                                           │
│   conversations / messages / attachments  │
└─────────────────────┬─────────────────────┘
                      │
┌─────────────────────▼─────────────────────┐
│              Session Manager              │
│                                           │
│     session lifecycle / persistence       │
└─────────────────────┬─────────────────────┘
                      │
          ┌───────────┴───────────┐
          │                       │
┌─────────▼─────────┐   ┌─────────▼─────────┐
│      PQXDH        │   │  Double Ratchet   │
│                   │   │                   │
│ session bootstrap │   │ message security  │
└─────────┬─────────┘   └─────────┬─────────┘
          │                       │
          └───────────┬───────────┘
                      │
┌─────────────────────▼─────────────────────┐
│               CryptoProvider              │
│                                           │
│ X25519 / signatures / KEM / HKDF / AEAD  │
└─────────────────────┬─────────────────────┘
                      │
                      │ encrypted envelope
                      ▼
┌───────────────────────────────────────────┐
│              WakuTransport                │
│                                           │
│ Relay / Filter / Light Push / Store       │
└───────────────────────────────────────────┘
```

### Core architectural principle

The cryptographic protocol must be completely functional and testable with an unreliable fake transport before it is connected to Waku.

Waku must be replaceable with another transport without changing:

- PQXDH.
- Double Ratchet.
- Session state.
- Message encryption.
- Key lifecycle.
- Replay protection.
- Out-of-order handling.

---

## Primary References

- **Signal PQXDH Specification** — https://signal.org/docs/specifications/pqxdh/
- **Signal Double Ratchet Specification** — https://signal.org/docs/specifications/doubleratchet/
- **Signal X3DH Specification** — https://signal.org/docs/specifications/x3dh/
- **Signal Protocol Specifications** — https://signal.org/docs/
- **Waku Protocol Documentation** — https://docs.waku.org/learn/concepts/protocols
- **Waku JavaScript SDK Documentation** — https://docs.waku.org/build/javascript/

---

## Implementation Rule

When the implementation conflicts with an informal description in this document, **the selected cryptographic protocol specification takes precedence.**

The coding agent must never "simplify" cryptographic constructions for convenience.

In particular, do not:

- Replace PQXDH with a custom DH scheme.
- Replace the Double Ratchet with a static session key.
- Invent a custom KDF.
- Invent a custom signature construction.
- Reuse message keys.
- Skip associated-data authentication.
- Persist ratchet state non-atomically.
- Treat transport acknowledgements as recipient delivery.
- Assume transport ordering.
- Assume transport confidentiality.
- Implement cryptographic primitives from scratch.

**The objective is to build a new application protocol using established cryptographic constructions, not to create a new cryptographic protocol.**
