# Cryptographic Design Document

Phase 31, item 2 of [docs/spec.md](../spec.md). Every cryptographic
construction this protocol uses, exactly as implemented — not a
restatement of the Signal specs this follows (see "Primary References" in
`docs/spec.md`), but the concrete choices this codebase made within them,
with pointers to the source. Where a construction deviates from the most
obvious/naive approach, this document says why.

See [docs/audit/dependency-inventory.md](dependency-inventory.md) for
which library implements each primitive and its independent-audit status
— not repeated here.

## Primitive suite

| Primitive | Algorithm | Source module |
|---|---|---|
| Classical DH | X25519 | `src/crypto/NobleCryptoProvider.ts` |
| Signatures | Ed25519 | `src/crypto/NobleCryptoProvider.ts` |
| Post-quantum KEM | ML-KEM-1024 (FIPS 203) | `src/crypto/NobleCryptoProvider.ts` |
| Hash | SHA-512 (KDFs), SHA-256 (`CryptoProvider.hash` — identifiers/fingerprints) | `src/crypto/NobleCryptoProvider.ts` |
| KDF | HKDF-SHA512 (`hkdfExtract`/`hkdfExpand`); raw HMAC-SHA512 for the ratchet's `KDF_CK` specifically | `src/crypto/NobleCryptoProvider.ts` |
| AEAD | XChaCha20-Poly1305, 24-byte random nonce | `src/crypto/NobleCryptoProvider.ts` |

No primitive here is hand-implemented — `CryptoProvider`
(`src/crypto/CryptoProvider.ts`) is an abstraction over the `@noble/*`
libraries specifically so this codebase never has to be the thing an
audit needs to verify constant-time behavior or side-channel resistance
of raw curve/cipher arithmetic in.

## Key hierarchy

```
Identity (Ed25519 keypair, long-term)
   │
   ├─ dual-use as X25519 (birational map — see "Design decisions" below)
   │
   ├─ signs → SignedPreKey (X25519, medium-term, rotated)
   ├─ signs → PQPreKey (ML-KEM-1024, medium-term, rotated)
   └─ (OneTimePreKey: X25519, NOT signed — see dependency-inventory.md's
       fuzzing finding on why this is safe despite that)
        │
        ▼
   PQXDH (DH1..DH4 + KEM) ──► SK (32 bytes) ──► Double Ratchet root key
                                                    │
                                            KDF_RK per DH ratchet step
                                                    │
                                            (root key, chain key) pairs
                                                    │
                                            KDF_CK per message
                                                    │
                                            (chain key, message key) pairs
                                                    │
                                            message key ──► AEAD seal/open
                                                              (used once, erased)
```

Every arrow that produces a new key erases what it consumed
(`CryptoProvider.secureErase`) once the value it fed into is derived — see
[docs/security-invariants.md](../security-invariants.md), Invariant 6.

## PQXDH: session establishment

`src/pqxdh/PQXDHInitiator.ts` / `PQXDHResponder.ts`, following Signal's
real PQXDH spec (fetched and verified against the actual spec text, not
reconstructed from memory — see the README's own note on this).

**DH/KEM computation** (Alice = initiator, Bob = responder):

```
DH1 = DH(IK_A, SPK_B)
DH2 = DH(EK_A, IK_B)
DH3 = DH(EK_A, SPK_B)
DH4 = DH(EK_A, OPK_B)                    (only if Bob's bundle had a one-time prekey)
(CT, SS) = ML-KEM-1024.Encapsulate(PQPK_B)
KM = DH1 || DH2 || DH3 [|| DH4] || SS
```

**KDF(KM)** — spec §2.2, reproduced exactly in `src/pqxdh/params.ts`:

```
ikm    = F || KM                          (F = 32 bytes of 0xFF for curve25519, prepended
                                            exactly as in XEdDSA)
salt   = 64 zero bytes                    (SHA-512's output length)
info   = "SecureMessagingProtocol_CURVE25519_SHA-512_ML-KEM-1024"
output = HKDF-Extract(salt, ikm) → HKDF-Expand(prk, info, 32 bytes) = SK
```

This is deliberately **not** the ad-hoc `HKDF(DH1‖DH2‖DH3‖SS)` construction
the PQXDH spec explicitly warns implementers against — the `F` prefix,
the fixed all-zero salt, and the parameter-derived `info` string are all
required by the real spec, not simplifications this codebase chose to
skip.

**Associated data** (`src/pqxdh/associatedData.ts`):

```
AD = domain("secure-messaging/pqxdh-ad/v1") || IK_A || IK_B
```

Notably does **not** append the PQ public key (`EncodeKEM(PQPK_B)`) to
`AD` — the real spec only requires that when the KEM does *not* fold its
own public key into the shared secret it produces. ML-KEM does this
internally as part of its IND-CCA construction (inherited from its Kyber
submission lineage), so the re-encapsulation attack `AD`'s KEM-binding
exists to prevent is already closed without it. `EncodeEC` here is a
domain-labeled, length-prefixed canonical encoding rather than the
spec's literal "single-byte curve tag || raw u-coordinate" — a different
but equally valid way to satisfy the spec's actual requirement (pairwise-
disjoint encoding ranges between DH and KEM key types), and length alone
already makes 32-byte X25519 keys and 1568-byte ML-KEM-1024 keys
trivially disjoint here.

Per spec §3.3, Alice's ephemeral private key, all DH outputs, and the raw
shared secret `SS` are erased immediately after `SK` is derived — not
left for the caller to remember to clean up.

## Double Ratchet

`src/ratchet/DoubleRatchet.ts` / `src/ratchet/kdf.ts`, following the real
Double Ratchet spec's §7.2 KDF recommendations exactly.

**`KDF_RK(rk, dh_out)`** — one HKDF call per DH ratchet step:

```
prk    = HKDF-Extract(salt = rk, ikm = dh_out)
output = HKDF-Expand(prk, info = "SecureMessagingProtocol_DR_KDF_RK_v1", 64 bytes)
(new root key, new chain key) = output[0:32], output[32:64]
```

**Deliberately the opposite HKDF salt/IKM convention from PQXDH's own
KDF above** — here the running secret (`rk`) is the *salt*, and the fresh
DH output is the *input key material*; PQXDH does the reverse (`SS`/DH
outputs as IKM against a fixed salt). Both are correct per their
respective specs; this is flagged explicitly (in code and here) because
it is easy to transpose them by habit, and doing so would be a silent,
hard-to-notice deviation from both specs at once.

**`KDF_CK(ck)`** — deliberately raw HMAC, not HKDF (the spec is explicit
about this):

```
message key    = HMAC-SHA512(ck, 0x01)[0:32]
next chain key = HMAC-SHA512(ck, 0x02)[0:32]
```

## Associated data chain (three layers, composed)

Every AEAD operation in this protocol authenticates against
context-specific associated data, composed in layers rather than one flat
blob — each layer is itself the input to the next:

```
1. PQXDH AD           domain("pqxdh-ad/v1") || IK_A || IK_B
                          │
2. Session AD          domain("session-ad/v1") || protocolVersion || (1) || sessionId
   (session/associatedData.ts — fixed for the session's whole lifetime,
    computed once at establishment, reused for every message)
                          │
3. Per-message AD       domain("dr-message-ad/v1") || (2) || ratchetPublicKey ||
   (ratchet/header.ts)   previousChainLength || messageNumber
```

Binding `sessionId` in at layer 2 (Phase 12) means a ciphertext can never
be replayed into a different session even if two sessions somehow shared
a root key by coincidence or implementation bug. Binding `protocolVersion`
in at the same layer (Phase 27) means a downgrade/version-substitution
attack can't silently reinterpret a message under a different parameter
set. Every field at every layer is length-prefixed
(`canonicalEncodeFields`, `src/encoding/canonical.ts`) specifically so
`encode(["ab","c"])` can never collide with `encode(["a","bc"])` — the
concatenation-ambiguity attack this exists to prevent.

## AEAD

XChaCha20-Poly1305 exclusively (`src/crypto/NobleCryptoProvider.ts`).
`CryptoProvider.aeadEncrypt`/`aeadDecrypt` has no separate nonce
parameter by design — a fresh random 24-byte nonce is generated per call
and prepended to the ciphertext output; `aeadDecrypt` reads it back off
the front. Nonce management is entirely internal to the primitive layer,
where "never reuse a nonce under the same key" is enforced structurally
(every call generates a fresh one) rather than left to callers to get
right — and XChaCha's extended 192-bit nonce makes random collision
negligible even at high message volume, unlike standard 96-bit
ChaCha20-Poly1305/AES-GCM nonces, where random generation alone isn't a
safe nonce strategy at scale.

## Domain separation strategy (complete list)

Every signed or AEAD-associated-data structure in this protocol carries
its own domain-separation label, so a value valid in one context can
never be replayed as valid in another — this is the specific mechanism
behind Invariant 2/several others in
[docs/security-invariants.md](../security-invariants.md):

| Domain string | Protects |
|---|---|
| `secure-messaging/signed-prekey/v1` | Signed EC prekey signatures |
| `secure-messaging/pq-prekey/v1` | Signed PQ prekey signatures |
| `secure-messaging/pqxdh-ad/v1` | PQXDH's identity-binding AD |
| `secure-messaging/session-ad/v1` | Session-level AD |
| `secure-messaging/dr-message-ad/v1` | Per-message AD |
| `secure-messaging/session-reset/v1` | `SESSION_RESET` signatures (Phase 19) |

One-time prekeys are deliberately **not** in this list — they carry no
signature at all in this wire format (matching real X3DH/PQXDH bundle
formats), and their authenticity is instead enforced downstream by
PQXDH's own DH4 computation, not by a domain-separated signature. See
`docs/audit/dependency-inventory.md`'s fuzzing cross-reference and
`test/fuzz/validatePreKeyBundle.fuzz.test.ts` for why this is a
deliberate, verified-safe design property rather than a gap.

## Design decisions worth an auditor's attention

- **Identity keys are dual-use** (`src/identity/types.ts`). One Ed25519
  keypair serves both signing (identity, prekey signatures) and — via
  `CryptoProvider.x25519PrivateFromIdentity`/`x25519PublicFromIdentity`, a
  standard Edwards↔Montgomery birational map — PQXDH's DH1/DH2, which
  need an X25519 key. This is a real Edwards-curve/Montgomery-curve
  coordinate transform (mathematically standard, not a novel
  construction), not Signal's own XEdDSA bit-for-bit — worth an auditor
  confirming the transform itself rather than taking the naming on faith.
- **Signed prekeys do not bind `expiresAt` into their signature**
  (`src/prekeys/signing.ts`). The wire `PreKeyBundle` never transmits
  `expiresAt` at all, so a recipient has no value to reconstruct that
  payload with even if it were signed — expiry is local rotation policy,
  not a cryptographically authenticated property, by necessity of what's
  actually on the wire.
- **`PrekeyStore`'s one-time-prekey atomicity is process-local**
  (`src/prekeys/PrekeyStore.ts`), relying on JavaScript's synchronous
  execution model (no `await` between a reservation's check and its
  transition). A persistent backend implementing this interface MUST
  make `reserve` a single atomic transaction — this is a contract
  obligation on any real storage implementation, not something this
  codebase enforces for you.
- **`@noble/post-quantum` (ML-KEM-1024) is the one unaudited primitive
  in this suite** — see `docs/audit/dependency-inventory.md` for the full
  detail. Worth restating here because it's the single fact in this
  document most likely to matter to an external audit's own scoping
  decision.
