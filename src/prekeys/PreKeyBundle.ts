/**
 * Canonical prekey bundle (Phase 4). This is what Bob publishes and Alice
 * fetches to asynchronously start a PQXDH session. Deliberately matches the
 * spec's literal field shape — no `expiresAt` on the individual prekeys (see
 * the note in prekeys/signing.ts for why that matters).
 */
export interface PreKeyBundle {
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

/**
 * Phase 27: every envelope/bundle carries a protocolVersion, and a
 * cryptographic parameter change requires a new version rather than
 * silently changing behavior under an existing one. This is the only
 * version this implementation currently understands or accepts.
 */
export const CURRENT_PROTOCOL_VERSION = 1;

export const SUPPORTED_PROTOCOL_VERSIONS: ReadonlySet<number> = new Set([CURRENT_PROTOCOL_VERSION]);
