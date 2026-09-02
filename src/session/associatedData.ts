import { canonicalEncodeFields, encodeUint32BE } from "../encoding/canonical.js";

/**
 * The full per-session associated data, used for every message on the
 * session (both the initial one and every ordinary MESSAGE after it) — not
 * just PQXDH's own AD (which only binds the two identity keys), extended
 * with:
 *   - protocolVersion (Phase 27: every cryptographic parameter set gets its
 *     own version; binding it in means a downgrade/version-substitution
 *     can't silently reinterpret a message under different parameters)
 *   - sessionId (Phase 12: "bind the session ID into the authenticated
 *     data" — without this, a ciphertext could conceivably be replayed
 *     into a different session if two sessions ever shared a root key by
 *     coincidence or implementation bug; with it, that's cryptographically
 *     impossible regardless)
 *
 * Computed once at session establishment and reused unchanged for the
 * session's lifetime — see Session.associatedData.
 */
const SESSION_AD_DOMAIN = new TextEncoder().encode("secure-messaging/session-ad/v1");

export function buildSessionAssociatedData(
    protocolVersion: number,
    pqxdhAssociatedData: Uint8Array,
    sessionId: Uint8Array,
): Uint8Array {
    return canonicalEncodeFields(
        SESSION_AD_DOMAIN,
        encodeUint32BE(protocolVersion),
        pqxdhAssociatedData,
        sessionId,
    );
}
