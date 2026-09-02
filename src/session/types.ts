import type { Identity } from "../identity/types.js";
import type { DoubleRatchetState, RatchetHeader } from "../ratchet/types.js";

/**
 * Phase 12: "Generate a cryptographically random session identifier. Do not
 * derive it from userA + userB." 32 bytes (256-bit).
 */
export type SessionId = Uint8Array;

/**
 * In-memory session record (Phase 9/12, without Phase 13's encrypted-at-rest
 * persistence — that's a distinct later concern; this type is deliberately
 * close to what a future `PersistentSession` projection would serialize).
 *
 * `associatedData` is the FULL session AD (protocolVersion + PQXDH's
 * identity-binding AD + sessionId — see associatedData.ts), fixed for the
 * lifetime of the session and reused for every message, not just the first.
 */
export interface Session {
    sessionId: SessionId;
    protocolVersion: number;
    localIdentity: Identity;
    remoteIdentityPublicKey: Uint8Array;
    associatedData: Uint8Array;
    ratchetState: DoubleRatchetState;
    createdAt: number;
}

/**
 * Message envelope (Phase 10/11, minimal set: SESSION_INIT and MESSAGE).
 * A discriminated union rather than Phase 10's single flat struct with an
 * optional `pqxdhInitialData` blob — same information, but the type system
 * can enforce that a MESSAGE envelope never carries PQXDH bootstrap fields
 * and vice versa. This is an in-memory representation; actual wire-format
 * binary serialization (Phase 10's "protobuf is a suitable option") is a
 * later concern once transport (Waku) integration begins.
 */
export type MessageEnvelope = SessionInitEnvelope | MessageEnvelopeData;

export interface SessionInitEnvelope {
    type: "SESSION_INIT";
    protocolVersion: number;
    sessionId: SessionId;
    senderIdentityPublicKey: Uint8Array;
    ephemeralPublicKey: Uint8Array;
    pqCiphertext: Uint8Array;
    signedPreKeyId: number;
    oneTimePreKeyId: number | undefined;
    pqPreKeyId: number;
    ratchetHeader: RatchetHeader;
    ciphertext: Uint8Array;
}

export interface MessageEnvelopeData {
    type: "MESSAGE";
    protocolVersion: number;
    sessionId: SessionId;
    ratchetHeader: RatchetHeader;
    ciphertext: Uint8Array;
}
