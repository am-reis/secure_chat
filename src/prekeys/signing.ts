import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import { canonicalEncodeFields, encodeUint32BE } from "../encoding/canonical.js";

/**
 * Build the exact byte payload that gets signed (and later re-verified) for
 * a signed prekey: `id` and `publicKey`, bound together with a
 * domain-separation label.
 *
 * Binding `id` in means an attacker who intercepts a bundle cannot relabel
 * a signed prekey under a different id without invalidating the signature.
 *
 * NOTE — expiresAt is deliberately NOT part of the signed payload, even
 * though the local SignedPreKey/PQPreKey records carry an `expiresAt`
 * field. Phase 4's wire `PreKeyBundle` shape only transmits
 * `{id, publicKey, signature}` for each prekey — no expiry — so a
 * recipient verifying a received bundle has no `expiresAt` value to
 * reconstruct the payload with. Expiry here is local rotation/hygiene
 * policy for the key's owner (Phase 18), not something the protocol
 * cryptographically proves to the remote party. (An earlier version of
 * this module bound expiresAt into the signature, which would have made
 * bundles genuinely unverifiable by a real recipient — caught before this
 * went further.)
 *
 * `domain` distinguishes prekey types (signed EC prekey vs. PQ prekey) so a
 * valid signature for one can never be replayed as valid for the other.
 */
export function buildSignedPrekeyPayload(
    domain: Uint8Array,
    id: number,
    publicKey: Uint8Array,
): Uint8Array {
    return canonicalEncodeFields(domain, encodeUint32BE(id), publicKey);
}

export function signPrekeyPayload(
    provider: CryptoProvider,
    identityPrivateKey: Uint8Array,
    domain: Uint8Array,
    id: number,
    publicKey: Uint8Array,
): Uint8Array {
    const payload = buildSignedPrekeyPayload(domain, id, publicKey);
    return provider.sign(identityPrivateKey, payload);
}

export function verifyPrekeySignature(
    provider: CryptoProvider,
    identityPublicKey: Uint8Array,
    domain: Uint8Array,
    id: number,
    publicKey: Uint8Array,
    signature: Uint8Array,
): boolean {
    const payload = buildSignedPrekeyPayload(domain, id, publicKey);
    return provider.verify(identityPublicKey, payload, signature);
}
