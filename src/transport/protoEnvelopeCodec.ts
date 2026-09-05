import { securemessaging } from "./proto/envelope.pb.js";
import type { MessageEnvelope, SessionInitEnvelope, MessageEnvelopeData } from "../session/types.js";
import type { RatchetHeader } from "../ratchet/types.js";
import { ProtocolError } from "../errors.js";

const { EnvelopeProto, EnvelopeType, RatchetHeaderProto } = securemessaging.v1;

/**
 * Phase 10: the real deterministic binary wire format, generated from
 * envelope.proto via protobufjs's own pure-JS pbjs/pbts (no protoc binary
 * dependency — see the .proto file for schema details and the rationale
 * for choosing protobuf over a hand-rolled binary format: cross-platform
 * codegen for the mobile clients planned later). Replaces the earlier JSON
 * placeholder codec with the identical `encodeEnvelope`/`decodeEnvelope`
 * function signatures, so nothing above the transport boundary needed to
 * change to adopt it.
 */

function encodeHeader(h: RatchetHeader): InstanceType<typeof RatchetHeaderProto> {
    return new RatchetHeaderProto({
        ratchetPublicKey: h.ratchetPublicKey,
        previousChainLength: h.previousChainLength,
        messageNumber: h.messageNumber,
    });
}

interface DecodableHeader {
    ratchetPublicKey?: Uint8Array | null;
    previousChainLength?: number | null;
    messageNumber?: number | null;
}

function decodeHeader(h: DecodableHeader | null | undefined): RatchetHeader {
    if (!h || !h.ratchetPublicKey || h.previousChainLength == null || h.messageNumber == null) {
        throw new ProtocolError("Envelope is missing required ratchet header fields", "INVALID_FORMAT");
    }
    return {
        ratchetPublicKey: h.ratchetPublicKey,
        previousChainLength: h.previousChainLength,
        messageNumber: h.messageNumber,
    };
}

export function encodeEnvelope(envelope: MessageEnvelope): Uint8Array {
    if (envelope.type === "SESSION_INIT") {
        const proto = new EnvelopeProto({
            type: EnvelopeType.SESSION_INIT,
            protocolVersion: envelope.protocolVersion,
            sessionId: envelope.sessionId,
            ratchetHeader: encodeHeader(envelope.ratchetHeader),
            ciphertext: envelope.ciphertext,
            senderIdentityPublicKey: envelope.senderIdentityPublicKey,
            ephemeralPublicKey: envelope.ephemeralPublicKey,
            pqCiphertext: envelope.pqCiphertext,
            signedPrekeyId: envelope.signedPreKeyId,
            pqPrekeyId: envelope.pqPreKeyId,
            // Only set when defined — proto3 "optional" presence is
            // tracked by own-property existence at encode time, which is
            // how "no one-time prekey was used" stays distinguishable from
            // "prekey id 0" on the wire (verified against the generated
            // runtime directly, not assumed).
            ...(envelope.oneTimePreKeyId !== undefined ? { oneTimePrekeyId: envelope.oneTimePreKeyId } : {}),
        });
        return EnvelopeProto.encode(proto).finish();
    }

    const proto = new EnvelopeProto({
        type: EnvelopeType.MESSAGE,
        protocolVersion: envelope.protocolVersion,
        sessionId: envelope.sessionId,
        ratchetHeader: encodeHeader(envelope.ratchetHeader),
        ciphertext: envelope.ciphertext,
    });
    return EnvelopeProto.encode(proto).finish();
}

export function decodeEnvelope(bytes: Uint8Array): MessageEnvelope {
    let proto: InstanceType<typeof EnvelopeProto>;
    try {
        proto = EnvelopeProto.decode(bytes);
    } catch (err) {
        throw new ProtocolError(
            `Envelope payload is not valid protobuf (malformed or corrupted): ${(err as Error).message}`,
            "INVALID_FORMAT",
        );
    }

    if (proto.type === EnvelopeType.SESSION_INIT) {
        // `_oneTimePrekeyId` is protobufjs's generated presence marker for
        // the proto3 "optional" field — a string (the field name) when
        // present, undefined when absent. This is the only reliable way to
        // distinguish "absent" from "present with value 0."
        const hasOtk = (proto as unknown as { _oneTimePrekeyId?: string })._oneTimePrekeyId !== undefined;
        const envelope: SessionInitEnvelope = {
            type: "SESSION_INIT",
            protocolVersion: proto.protocolVersion,
            sessionId: proto.sessionId,
            senderIdentityPublicKey: proto.senderIdentityPublicKey,
            ephemeralPublicKey: proto.ephemeralPublicKey,
            pqCiphertext: proto.pqCiphertext,
            signedPreKeyId: proto.signedPrekeyId,
            oneTimePreKeyId: hasOtk ? proto.oneTimePrekeyId! : undefined,
            pqPreKeyId: proto.pqPrekeyId,
            ratchetHeader: decodeHeader(proto.ratchetHeader),
            ciphertext: proto.ciphertext,
        };
        return envelope;
    }

    if (proto.type === EnvelopeType.MESSAGE) {
        const envelope: MessageEnvelopeData = {
            type: "MESSAGE",
            protocolVersion: proto.protocolVersion,
            sessionId: proto.sessionId,
            ratchetHeader: decodeHeader(proto.ratchetHeader),
            ciphertext: proto.ciphertext,
        };
        return envelope;
    }

    throw new ProtocolError(`Unknown or unspecified envelope type in wire payload: ${proto.type}`, "INVALID_FORMAT");
}
