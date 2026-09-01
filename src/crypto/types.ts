/**
 * Shared cryptographic types (Phase 1 / Phase 2 of the spec).
 *
 * NOTE on identity keys (design decision — flagged for review):
 * Phase 2 defines `IdentityKeyPair` as a *single* {publicKey, privateKey}
 * pair, and Phase 5 uses that same identity key directly inside classical
 * DH operations (DH1 = DH(IK_A, SPK_B), DH2 = DH(EK_A, IK_B)). That means
 * one Curve25519 key must serve both as an X25519 DH key AND support
 * signing — exactly the problem Signal's XEdDSA construction solves.
 *
 * This implementation generates the identity key as an Ed25519 keypair
 * (so `sign`/`verify` are plain, standard Ed25519 — no custom signature
 * scheme) and derives the corresponding X25519 keypair on demand via the
 * standard birational Edwards<->Montgomery map exposed by @noble/curves
 * (`toMontgomery` / `toMontgomerySecret`). This is mathematically the same
 * curve25519/ed25519 correspondence XEdDSA relies on, just entered from
 * the Edwards side rather than the Montgomery side. It keeps `sign`/`verify`
 * as textbook Ed25519 (auditable, no hand-rolled construction) while still
 * giving Phase 5 a single dual-use identity key per the spec's data model.
 */

export interface KeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

export interface IdentityKeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

export interface KemKeyPair {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}

export interface KemEncapsulationResult {
    ciphertext: Uint8Array;
    sharedSecret: Uint8Array;
}
