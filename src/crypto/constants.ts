/**
 * Byte lengths for the primitive suite chosen in NobleCryptoProvider.
 * These are NOT memorized/guessed — confirmed by directly introspecting the
 * installed @noble library versions at build time (`.lengths` metadata plus
 * an actual keygen/sign/encapsulate call), the same way the RFC 7748 and
 * SHA-256 test vectors were cross-checked rather than hand-typed from
 * recollection. If the underlying library major version changes, re-verify
 * these rather than assuming they still hold.
 */
export const KEY_LENGTHS = {
    /** Ed25519 identity public key (also the seed for the derived X25519 identity DH key). */
    ed25519PublicKey: 32,
    /** Ed25519 signature. */
    ed25519Signature: 64,
    /** X25519 public key (ephemeral keys, signed prekeys, one-time prekeys). */
    x25519PublicKey: 32,
    /** ML-KEM-1024 encapsulation public key. */
    mlKem1024PublicKey: 1568,
    /** ML-KEM-1024 encapsulation ciphertext. */
    mlKem1024Ciphertext: 1568,
} as const;
