import { describe, it, expect } from "vitest";
import { encodeEnvelope, decodeEnvelope } from "../../src/transport/envelopeCodec.js";
import type { SessionInitEnvelope, MessageEnvelopeData } from "../../src/session/types.js";

const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));

describe("envelopeCodec — round trip", () => {
    it("round-trips a SESSION_INIT envelope, including an undefined oneTimePreKeyId", () => {
        const original: SessionInitEnvelope = {
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
        };
        const decoded = decodeEnvelope(encodeEnvelope(original)) as SessionInitEnvelope;
        expect(decoded.type).toBe("SESSION_INIT");
        expect(toHex(decoded.sessionId)).toBe(toHex(original.sessionId));
        expect(toHex(decoded.senderIdentityPublicKey)).toBe(toHex(original.senderIdentityPublicKey));
        expect(toHex(decoded.pqCiphertext)).toBe(toHex(original.pqCiphertext));
        expect(decoded.oneTimePreKeyId).toBeUndefined();
        expect(decoded.signedPreKeyId).toBe(7);
        expect(toHex(decoded.ratchetHeader.ratchetPublicKey)).toBe(toHex(original.ratchetHeader.ratchetPublicKey));
        expect(toHex(decoded.ciphertext)).toBe(toHex(original.ciphertext));
    });

    it("round-trips a SESSION_INIT envelope with a defined oneTimePreKeyId", () => {
        const original: SessionInitEnvelope = {
            type: "SESSION_INIT",
            protocolVersion: 1,
            sessionId: rand(32),
            senderIdentityPublicKey: rand(32),
            ephemeralPublicKey: rand(32),
            pqCiphertext: rand(1568),
            signedPreKeyId: 1,
            oneTimePreKeyId: 42,
            pqPreKeyId: 1,
            ratchetHeader: { ratchetPublicKey: rand(32), previousChainLength: 0, messageNumber: 0 },
            ciphertext: rand(64),
        };
        const decoded = decodeEnvelope(encodeEnvelope(original)) as SessionInitEnvelope;
        expect(decoded.oneTimePreKeyId).toBe(42);
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

    it("throws cleanly (not a raw JS crash) on non-JSON bytes", () => {
        const garbage = new Uint8Array([0xff, 0x00, 0x13, 0x37, 0xde, 0xad]);
        expect(() => decodeEnvelope(garbage)).toThrow();
    });

    it("throws on JSON with an unknown envelope type", () => {
        const bytes = new TextEncoder().encode(JSON.stringify({ type: "NOT_A_REAL_TYPE" }));
        expect(() => decodeEnvelope(bytes)).toThrow();
    });
});
