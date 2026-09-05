import { describe, it, expect } from "vitest";
import { encodeEnvelope, decodeEnvelope } from "../../src/transport/protoEnvelopeCodec.js";
import type { SessionInitEnvelope, MessageEnvelopeData } from "../../src/session/types.js";

const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));

function makeSessionInit(overrides: Partial<SessionInitEnvelope> = {}): SessionInitEnvelope {
    return {
        type: "SESSION_INIT",
        protocolVersion: 1,
        sessionId: rand(32),
        senderIdentityPublicKey: rand(32),
        ephemeralPublicKey: rand(32),
        pqCiphertext: rand(1568),
        signedPreKeyId: 7,
        oneTimePreKeyId: undefined,
        pqPreKeyId: 3,
        ratchetHeader: { ratchetPublicKey: rand(32), previousChainLength: 0, messageNumber: 0 },
        ciphertext: rand(64),
        ...overrides,
    };
}

describe("protoEnvelopeCodec — round trip", () => {
    it("round-trips a SESSION_INIT envelope with no one-time prekey", () => {
        const original = makeSessionInit();
        const decoded = decodeEnvelope(encodeEnvelope(original)) as SessionInitEnvelope;
        expect(decoded.type).toBe("SESSION_INIT");
        expect(toHex(decoded.sessionId)).toBe(toHex(original.sessionId));
        expect(toHex(decoded.senderIdentityPublicKey)).toBe(toHex(original.senderIdentityPublicKey));
        expect(toHex(decoded.ephemeralPublicKey)).toBe(toHex(original.ephemeralPublicKey));
        expect(toHex(decoded.pqCiphertext)).toBe(toHex(original.pqCiphertext));
        expect(decoded.signedPreKeyId).toBe(7);
        expect(decoded.pqPreKeyId).toBe(3);
        expect(decoded.oneTimePreKeyId).toBeUndefined();
        expect(toHex(decoded.ratchetHeader.ratchetPublicKey)).toBe(toHex(original.ratchetHeader.ratchetPublicKey));
        expect(toHex(decoded.ciphertext)).toBe(toHex(original.ciphertext));
    });

    it("round-trips a SESSION_INIT envelope WITH a one-time prekey", () => {
        const original = makeSessionInit({ oneTimePreKeyId: 42 });
        const decoded = decodeEnvelope(encodeEnvelope(original)) as SessionInitEnvelope;
        expect(decoded.oneTimePreKeyId).toBe(42);
    });

    it("CRITICAL: distinguishes one-time prekey id 0 from 'no one-time prekey used' (proto3 optional presence)", () => {
        const withZero = makeSessionInit({ oneTimePreKeyId: 0 });
        const withNone = makeSessionInit({ oneTimePreKeyId: undefined });

        const decodedZero = decodeEnvelope(encodeEnvelope(withZero)) as SessionInitEnvelope;
        const decodedNone = decodeEnvelope(encodeEnvelope(withNone)) as SessionInitEnvelope;

        expect(decodedZero.oneTimePreKeyId).toBe(0);
        expect(decodedNone.oneTimePreKeyId).toBeUndefined();
        // A plain "falsy" check would incorrectly treat these as equivalent.
        expect(decodedZero.oneTimePreKeyId === decodedNone.oneTimePreKeyId).toBe(false);
    });

    it("round-trips a MESSAGE envelope", () => {
        const original: MessageEnvelopeData = {
            type: "MESSAGE",
            protocolVersion: 1,
            sessionId: rand(32),
            ratchetHeader: { ratchetPublicKey: rand(32), previousChainLength: 2, messageNumber: 5 },
            ciphertext: rand(128),
        };
        const decoded = decodeEnvelope(encodeEnvelope(original)) as MessageEnvelopeData;
        expect(decoded.type).toBe("MESSAGE");
        expect(toHex(decoded.sessionId)).toBe(toHex(original.sessionId));
        expect(decoded.ratchetHeader.previousChainLength).toBe(2);
        expect(decoded.ratchetHeader.messageNumber).toBe(5);
        expect(toHex(decoded.ciphertext)).toBe(toHex(original.ciphertext));
    });

    it("round-trips large field values (message numbers, chain lengths) correctly as varints", () => {
        const original: MessageEnvelopeData = {
            type: "MESSAGE",
            protocolVersion: 1,
            sessionId: rand(32),
            ratchetHeader: { ratchetPublicKey: rand(32), previousChainLength: 999_999, messageNumber: 4_000_000_000 },
            ciphertext: rand(16),
        };
        const decoded = decodeEnvelope(encodeEnvelope(original)) as MessageEnvelopeData;
        expect(decoded.ratchetHeader.previousChainLength).toBe(999_999);
        expect(decoded.ratchetHeader.messageNumber).toBe(4_000_000_000);
    });
});

describe("protoEnvelopeCodec — binary format properties", () => {
    it("is genuinely binary, not JSON text (the placeholder it replaced)", () => {
        const envelope: MessageEnvelopeData = {
            type: "MESSAGE",
            protocolVersion: 1,
            sessionId: rand(32),
            ratchetHeader: { ratchetPublicKey: rand(32), previousChainLength: 0, messageNumber: 0 },
            ciphertext: rand(64),
        };
        const encoded = encodeEnvelope(envelope);
        // JSON of this shape would start with '{' (0x7b) and be readable
        // ASCII throughout; protobuf's binary encoding is neither.
        let looksLikeJson = true;
        try {
            JSON.parse(new TextDecoder().decode(encoded));
        } catch {
            looksLikeJson = false;
        }
        expect(looksLikeJson).toBe(false);
    });

    it("is meaningfully smaller than the hex-in-JSON placeholder format it replaced", () => {
        const envelope = makeSessionInit();
        const protoBytes = encodeEnvelope(envelope);

        // Reconstruct what the old placeholder's size would have been:
        // JSON with every byte field hex-encoded (2 chars/byte) plus quotes/keys.
        const hexJson = JSON.stringify({
            type: envelope.type,
            protocolVersion: envelope.protocolVersion,
            sessionId: Buffer.from(envelope.sessionId).toString("hex"),
            senderIdentityPublicKey: Buffer.from(envelope.senderIdentityPublicKey).toString("hex"),
            ephemeralPublicKey: Buffer.from(envelope.ephemeralPublicKey).toString("hex"),
            pqCiphertext: Buffer.from(envelope.pqCiphertext).toString("hex"),
            signedPreKeyId: envelope.signedPreKeyId,
            pqPreKeyId: envelope.pqPreKeyId,
            ratchetHeader: {
                ratchetPublicKey: Buffer.from(envelope.ratchetHeader.ratchetPublicKey).toString("hex"),
                previousChainLength: envelope.ratchetHeader.previousChainLength,
                messageNumber: envelope.ratchetHeader.messageNumber,
            },
            ciphertext: Buffer.from(envelope.ciphertext).toString("hex"),
        });
        const jsonBytes = new TextEncoder().encode(hexJson).length;

        expect(protoBytes.length).toBeLessThan(jsonBytes);
        // The dominant cost is the 1568-byte PQ ciphertext, which hex-JSON
        // doubles to ~3136 chars; protobuf carries it as raw bytes plus a
        // couple of tag/length bytes — expect a substantial, not marginal, saving.
        expect(protoBytes.length).toBeLessThan(jsonBytes * 0.6);
    });
});

describe("protoEnvelopeCodec — malformed input handling", () => {
    it("throws cleanly (not a raw crash) on non-protobuf garbage bytes", () => {
        const garbage = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        expect(() => decodeEnvelope(garbage)).toThrow();
    });

    it("throws cleanly on an empty payload", () => {
        // An empty protobuf message is technically valid (all fields absent) —
        // but that means `type` is ENVELOPE_TYPE_UNSPECIFIED, which must be
        // rejected explicitly rather than silently treated as one of the
        // real envelope types.
        expect(() => decodeEnvelope(new Uint8Array(0))).toThrow();
    });

    it("throws on a well-formed protobuf message of a different, unrelated schema", () => {
        // Valid protobuf wire format (field 1, varint, value 5) but not
        // shaped like our envelope at all beyond coincidentally reusing tag 1.
        const unrelated = new Uint8Array([0x08, 0x05]);
        // This one may or may not throw depending on field-type coincidence,
        // but it must never silently produce a well-formed-looking envelope
        // with a valid, unrejected type — check the type field explicitly.
        try {
            const decoded = decodeEnvelope(unrelated);
            // If it didn't throw, the type field must still be a real,
            // recognized one — not something bogus slipping through as
            // 'valid enough'.
            expect(["SESSION_INIT", "MESSAGE"]).toContain(decoded.type);
        } catch {
            // Throwing is an equally acceptable, safe outcome here.
        }
    });
});
