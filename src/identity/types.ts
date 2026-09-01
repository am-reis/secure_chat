import type { IdentityKeyPair } from "../crypto/types.js";

/**
 * A user's long-term identity. `keyPair.privateKey` must never leave the
 * device, never be transmitted, and never be included in a plaintext
 * application message (Phase 2). Anything that crosses the transport
 * boundary should use `PublicIdentity` instead, not this type — see
 * `toPublicIdentity` below.
 */
export interface Identity {
    identityId: Uint8Array;
    keyPair: IdentityKeyPair;
    createdAt: number;
    version: number;
}

/**
 * The transmittable, public-only projection of an Identity. Deliberately has
 * no field that could hold a private key, so code built against this type
 * cannot accidentally serialize or transmit private key material
 * (Invariant 8: identity private keys never enter the transport layer).
 */
export interface PublicIdentity {
    identityId: Uint8Array;
    publicKey: Uint8Array;
    version: number;
}

export function toPublicIdentity(identity: Identity): PublicIdentity {
    return {
        identityId: identity.identityId,
        publicKey: identity.keyPair.publicKey,
        version: identity.version,
    };
}
