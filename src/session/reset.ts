import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import { canonicalEncodeFields, encodeUint32BE } from "../encoding/canonical.js";
import type { SessionId } from "./types.js";

/**
 * Domain separation for SESSION_RESET signatures (Phase 19), distinct from
 * every other signed payload in the protocol (signed/PQ prekeys, PQXDH) so a
 * signature valid here can never be replayed as valid there or vice versa —
 * same defense-in-depth reasoning as `buildSignedPrekeyPayload`'s `domain`
 * parameter (see src/prekeys/signing.ts).
 *
 * Deliberately signed with the long-term Ed25519 identity key, not
 * authenticated via the session's Double Ratchet associated data: Phase 19
 * exists specifically for the case where ratchet state is corrupted, lost,
 * or otherwise uncertain, so the thing that authenticates a reset notice
 * cannot itself depend on the state being reset.
 */
const SESSION_RESET_DOMAIN = new TextEncoder().encode("secure-messaging/session-reset/v1");

export function buildSessionResetPayload(protocolVersion: number, sessionId: SessionId): Uint8Array {
    return canonicalEncodeFields(SESSION_RESET_DOMAIN, encodeUint32BE(protocolVersion), sessionId);
}

export function signSessionReset(
    provider: CryptoProvider,
    identityPrivateKey: Uint8Array,
    protocolVersion: number,
    sessionId: SessionId,
): Uint8Array {
    return provider.sign(identityPrivateKey, buildSessionResetPayload(protocolVersion, sessionId));
}

export function verifySessionReset(
    provider: CryptoProvider,
    remoteIdentityPublicKey: Uint8Array,
    protocolVersion: number,
    sessionId: SessionId,
    signature: Uint8Array,
): boolean {
    return provider.verify(remoteIdentityPublicKey, buildSessionResetPayload(protocolVersion, sessionId), signature);
}
