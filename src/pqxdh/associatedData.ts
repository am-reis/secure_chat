import { canonicalEncodeFields } from "../encoding/canonical.js";

/**
 * AD = EncodeEC(IKA) || EncodeEC(IKB), per PQXDH spec §3.3. Order matters —
 * initiator's identity key first, responder's second — and both sides must
 * independently know their own role (who initiated) to reconstruct the
 * identical AD, unlike the symmetric identity fingerprint in Phase 2.2.
 *
 * We do NOT append EncodeKEM(PQPKB) to AD. The spec (§4.12, and confirmed
 * by §4.11's discussion of Kyber's "contributory" property) only requires
 * that when the pqkem does NOT incorporate its own public key into the
 * shared secret it produces. ML-KEM (like the Kyber submission it's
 * standardized from) hashes the encapsulation public key into its shared
 * secret internally as part of its IND-CCA construction, so this KEM
 * re-encapsulation attack is already prevented without appending the PQ
 * public key here.
 *
 * `EncodeEC` in the real spec is "single-byte curve tag || raw u-coordinate";
 * here it's a domain-labeled, length-prefixed canonical encoding instead —
 * a different but equally valid way to satisfy the same requirement the
 * spec actually cares about (§2.1: "the ranges of all encoding functions
 * must be pairwise disjoint", to prevent the encoding-confusion attack
 * between DH and KEM keys that Signal's PQXDH formal analysis identified).
 * Length alone already makes X25519-derived identity keys (32 bytes) and
 * ML-KEM-1024 keys (1568 bytes) trivially disjoint in this implementation,
 * and the domain label is defense in depth on top of that.
 */
const AD_DOMAIN = new TextEncoder().encode("secure-messaging/pqxdh-ad/v1");

export function buildPQXDHAssociatedData(
    initiatorIdentityPublicKey: Uint8Array,
    responderIdentityPublicKey: Uint8Array,
): Uint8Array {
    return canonicalEncodeFields(AD_DOMAIN, initiatorIdentityPublicKey, responderIdentityPublicKey);
}
