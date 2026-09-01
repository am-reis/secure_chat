import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import { canonicalEncodeFields } from "../encoding/canonical.js";
import type { Identity } from "./types.js";

/** Domain-separation label so this hash can never be reinterpreted as some other hash of the same public key elsewhere in the system. */
const IDENTITY_ID_DOMAIN = new TextEncoder().encode("secure-messaging/identity-id/v1");

/**
 * identityId = Hash(canonicalEncode(domain-label, identityPublicKey))  — Phase 2.1.
 *
 * A fixed-length (32-byte) binary identifier, safe to use as e.g. a database
 * key or lookup index. Per Phase 2.1, this — not the raw public key — is
 * what should be used as a Waku content-topic-adjacent identifier if one is
 * ever needed (Phase 21 goes further and says avoid per-identity topics
 * altogether).
 */
export function computeIdentityId(provider: CryptoProvider, identityPublicKey: Uint8Array): Uint8Array {
    const encoded = canonicalEncodeFields(IDENTITY_ID_DOMAIN, identityPublicKey);
    return provider.hash(encoded);
}

/**
 * Generate a new long-term identity (Phase 2). The resulting private key
 * must be handed off to platform-secure storage by the caller — this
 * function only creates the in-memory key material, it does not persist it.
 */
export function generateIdentity(provider: CryptoProvider, version = 1): Identity {
    const keyPair = provider.generateIdentityKeyPair();
    const identityId = computeIdentityId(provider, keyPair.publicKey);
    return {
        identityId,
        keyPair,
        createdAt: Date.now(),
        version,
    };
}
