/**
 * Signed EC (X25519) prekey — Phase 3.1. `privateKey` is Bob's local secret
 * and must never be included in anything sent over the wire; the wire form
 * is the `signedPreKey` field inside `PreKeyBundle` (Phase 4), which omits it.
 */
export interface SignedPreKey {
    id: number;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    signature: Uint8Array;
    createdAt: number;
    expiresAt: number;
}

/**
 * Signed PQ (ML-KEM-1024) prekey — Phase 3.3. Same shape and same
 * private-key-never-leaves-the-device rule as SignedPreKey.
 */
export interface PQPreKey {
    id: number;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    signature: Uint8Array;
    createdAt: number;
    expiresAt: number;
}

export type OneTimePreKeyState = "AVAILABLE" | "RESERVED" | "CONSUMED";

/**
 * One-time X25519 prekey — Phase 3.2. Not signed individually (the signed
 * prekey / identity key already authenticate the bundle as a whole; Signal's
 * X3DH/PQXDH designs don't sign one-time prekeys either, since a forged
 * unsigned OPK only gives an attacker the ability to remove forward secrecy
 * on one message, not to impersonate anyone — DH1/DH2 via the identity and
 * signed prekey already provide authentication).
 */
export interface OneTimePreKey {
    id: number;
    publicKey: Uint8Array;
    privateKey: Uint8Array;
    state: OneTimePreKeyState;
    createdAt: number;
}
