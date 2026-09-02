import type {
    KeyPair,
    IdentityKeyPair,
    KemKeyPair,
    KemEncapsulationResult,
} from "./types.js";

/**
 * Crypto abstraction (Phase 1). The rest of the application depends on this
 * interface rather than directly on any crypto library, so the underlying
 * primitive implementations can be swapped or upgraded (e.g. a future
 * protocol version moving to SPQR / Triple Ratchet, Phase 35) without
 * touching protocol logic.
 *
 * Implementations MUST NOT hand-roll primitives (no custom KDFs, no custom
 * signature schemes, no reimplemented curve arithmetic) — they wrap
 * established, maintained libraries only.
 */
export interface CryptoProvider {
    generateX25519KeyPair(): KeyPair;

    x25519(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;

    /**
     * Raw cryptographic hash (SHA-256). Not part of the spec's original
     * interface sketch, but Phase 1's primitive list requires SHA-256/512
     * and Phase 2.1 (`identityId = Hash(canonicalIdentityPublicKey)`) needs
     * a direct hash — `hkdfExtract`/`hkdfExpand` alone can't express that
     * cleanly. Reserved for identifiers and content hashes; the KDF chain
     * (HKDF, PQXDH) uses SHA-512 per the selected profile.
     */
    hash(data: Uint8Array): Uint8Array;

    generateIdentityKeyPair(): IdentityKeyPair;

    /**
     * Derive the X25519 private scalar corresponding to an Ed25519 identity
     * private key (birational Edwards->Montgomery map). Needed because the
     * identity key is a single dual-use keypair (Phase 2 design note in
     * identity/types.ts): Ed25519 for signing, and — via this derivation —
     * X25519 for the DH operations PQXDH's DH1/DH2 require.
     */
    x25519PrivateFromIdentity(identityPrivateKey: Uint8Array): Uint8Array;

    /** Derive the X25519 public key corresponding to an Ed25519 identity public key. See x25519PrivateFromIdentity. */
    x25519PublicFromIdentity(identityPublicKey: Uint8Array): Uint8Array;

    sign(privateKey: Uint8Array, data: Uint8Array): Uint8Array;

    verify(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean;

    generateKemKeyPair(): KemKeyPair;

    kemEncapsulate(publicKey: Uint8Array): KemEncapsulationResult;

    kemDecapsulate(privateKey: Uint8Array, ciphertext: Uint8Array): Uint8Array;

    hkdfExtract(salt: Uint8Array, inputKeyMaterial: Uint8Array): Uint8Array;

    hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array;

    /**
     * Raw HMAC. Added for the Double Ratchet's KDF_CK, which the Double
     * Ratchet spec (§7.2) recommends as literal HMAC with the chain key as
     * the HMAC key and single-byte constants as input — not HKDF. Output
     * length matches the underlying hash (SHA-512 = 64 bytes).
     */
    hmac(key: Uint8Array, data: Uint8Array): Uint8Array;

    aeadEncrypt(
        key: Uint8Array,
        plaintext: Uint8Array,
        associatedData: Uint8Array,
    ): Uint8Array;

    aeadDecrypt(
        key: Uint8Array,
        ciphertext: Uint8Array,
        associatedData: Uint8Array,
    ): Uint8Array;

    randomBytes(length: number): Uint8Array;

    secureErase(buffer: Uint8Array): void;
}
