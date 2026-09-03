import { bytesToHex, hexToBytes } from "../encoding/canonical.js";
import type { MessageEnvelope, SessionInitEnvelope, MessageEnvelopeData } from "../session/types.js";
import type { RatchetHeader } from "../ratchet/types.js";

/**
 * Placeholder wire encoding for MessageEnvelope <-> Uint8Array: JSON with
 * hex-encoded byte fields, the same style already used for session
 * persistence (Phase 13). This is NOT Phase 10's eventual real wire
 * format — the spec suggests protobuf, which needs a real schema and is
 * meaningfully more work than this transport-robustness pass calls for.
 * Swapping this codec out later doesn't affect anything above the
 * transport boundary: WakuTransport only ever sees opaque bytes.
 */

interface WireHeader {
    ratchetPublicKey: string;
    previousChainLength: number;
    messageNumber: number;
}

interface WireSessionInit {
    type: "SESSION_INIT";
    protocolVersion: number;
    sessionId: string;
    senderIdentityPublicKey: string;
    ephemeralPublicKey: string;
    pqCiphertext: string;
    signedPreKeyId: number;
    oneTimePreKeyId: number | undefined;
    pqPreKeyId: number;
    ratchetHeader: WireHeader;
    ciphertext: string;
}

interface WireMessage {
    type: "MESSAGE";
    protocolVersion: number;
    sessionId: string;
    ratchetHeader: WireHeader;
    ciphertext: string;
}

function encodeHeader(h: RatchetHeader): WireHeader {
    return {
        ratchetPublicKey: bytesToHex(h.ratchetPublicKey),
        previousChainLength: h.previousChainLength,
        messageNumber: h.messageNumber,
    };
}

function decodeHeader(h: WireHeader): RatchetHeader {
    return {
        ratchetPublicKey: hexToBytes(h.ratchetPublicKey),
        previousChainLength: h.previousChainLength,
        messageNumber: h.messageNumber,
    };
}

export function encodeEnvelope(envelope: MessageEnvelope): Uint8Array {
    let wire: WireSessionInit | WireMessage;
    if (envelope.type === "SESSION_INIT") {
        wire = {
            type: "SESSION_INIT",
            protocolVersion: envelope.protocolVersion,
            sessionId: bytesToHex(envelope.sessionId),
            senderIdentityPublicKey: bytesToHex(envelope.senderIdentityPublicKey),
            ephemeralPublicKey: bytesToHex(envelope.ephemeralPublicKey),
            pqCiphertext: bytesToHex(envelope.pqCiphertext),
            signedPreKeyId: envelope.signedPreKeyId,
            oneTimePreKeyId: envelope.oneTimePreKeyId,
            pqPreKeyId: envelope.pqPreKeyId,
            ratchetHeader: encodeHeader(envelope.ratchetHeader),
            ciphertext: bytesToHex(envelope.ciphertext),
        };
    } else {
        wire = {
            type: "MESSAGE",
            protocolVersion: envelope.protocolVersion,
            sessionId: bytesToHex(envelope.sessionId),
            ratchetHeader: encodeHeader(envelope.ratchetHeader),
            ciphertext: bytesToHex(envelope.ciphertext),
        };
    }
    return new TextEncoder().encode(JSON.stringify(wire));
}

export function decodeEnvelope(bytes: Uint8Array): MessageEnvelope {
    let wire: WireSessionInit | WireMessage;
    try {
        wire = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
        throw new Error("Envelope payload is not valid JSON (malformed or corrupted)");
    }

    if (wire.type === "SESSION_INIT") {
        const envelope: SessionInitEnvelope = {
            type: "SESSION_INIT",
            protocolVersion: wire.protocolVersion,
            sessionId: hexToBytes(wire.sessionId),
            senderIdentityPublicKey: hexToBytes(wire.senderIdentityPublicKey),
            ephemeralPublicKey: hexToBytes(wire.ephemeralPublicKey),
            pqCiphertext: hexToBytes(wire.pqCiphertext),
            signedPreKeyId: wire.signedPreKeyId,
            oneTimePreKeyId: wire.oneTimePreKeyId,
            pqPreKeyId: wire.pqPreKeyId,
            ratchetHeader: decodeHeader(wire.ratchetHeader),
            ciphertext: hexToBytes(wire.ciphertext),
        };
        return envelope;
    }
    if (wire.type === "MESSAGE") {
        const envelope: MessageEnvelopeData = {
            type: "MESSAGE",
            protocolVersion: wire.protocolVersion,
            sessionId: hexToBytes(wire.sessionId),
            ratchetHeader: decodeHeader(wire.ratchetHeader),
            ciphertext: hexToBytes(wire.ciphertext),
        };
        return envelope;
    }
    throw new Error(`Unknown envelope type in wire payload: ${(wire as { type?: unknown }).type}`);
}
