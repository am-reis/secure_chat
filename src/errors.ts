/**
 * Protocol-level failure classification (Phase 17). Every rejection path in
 * the protocol — bundle validation, PQXDH processing, ratchet message
 * handling, etc. — should throw a ProtocolError with one of these codes
 * rather than a generic Error, so callers (and eventually the UI) can
 * distinguish "this is malformed" from "this is a replay" from "storage is
 * broken" without parsing message strings.
 *
 * Per Phase 17: never expose detailed cryptographic errors to the REMOTE
 * peer — that's about what goes back out over the transport, not about
 * throwing a typed error locally. These messages must never contain
 * private keys, root keys, chain keys, message keys, plaintext, or raw
 * session secrets (also Phase 17).
 */
export type ProtocolErrorCode =
    | "INVALID_FORMAT"
    | "UNSUPPORTED_VERSION"
    | "UNKNOWN_SESSION"
    | "INVALID_IDENTITY"
    | "INVALID_SIGNATURE"
    | "INVALID_PREKEY"
    | "INVALID_PQ_CIPHERTEXT"
    | "AEAD_AUTHENTICATION_FAILED"
    | "REPLAY"
    | "MESSAGE_TOO_FAR_AHEAD"
    | "SESSION_STATE_CORRUPTED"
    | "KEY_NOT_FOUND"
    | "TRANSPORT_FAILURE"
    | "STORAGE_FAILURE";

export class ProtocolError extends Error {
    constructor(
        message: string,
        public readonly code: ProtocolErrorCode,
    ) {
        super(message);
        this.name = "ProtocolError";
    }
}
