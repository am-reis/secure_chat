import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { decodeEnvelope } from "../../src/transport/protoEnvelopeCodec.js";
import { ProtocolError } from "../../src/errors.js";

/**
 * Fuzzing (Phase 33's implementation-order item 20 / Phase 28.3's
 * "corrupted database state" spirit applied to the wire boundary): unlike
 * Phase 29's property tests, which exercise the protocol's *logic* over
 * random valid-shaped inputs, this feeds `decodeEnvelope` — the first thing
 * that touches bytes a remote, potentially adversarial peer controls —
 * genuinely random/malformed byte garbage, at volume, and checks only one
 * property: it never crashes with anything other than a classified
 * `ProtocolError` (Phase 17: "every failure has an explicit
 * classification"). A `RangeError` or other raw exception escaping from
 * protobufjs internals on a truncated varint would be exactly the kind of
 * thing this catches that a handful of hand-picked malformed-input unit
 * tests (see protoEnvelopeCodec.test.ts) could plausibly miss.
 */
describe("Fuzz: decodeEnvelope never crashes on arbitrary bytes", () => {
    it("either decodes to a well-typed envelope or throws a classified ProtocolError — nothing else", () => {
        fc.assert(
            fc.property(fc.uint8Array({ minLength: 0, maxLength: 4096 }), (bytes) => {
                try {
                    const envelope = decodeEnvelope(bytes);
                    return ["SESSION_INIT", "MESSAGE", "SESSION_RESET"].includes(envelope.type);
                } catch (e) {
                    return e instanceof ProtocolError;
                }
            }),
            { numRuns: 2000 },
        );
    });

    it("also holds for byte strings biased toward valid protobuf tag/wire-type bytes (more likely to reach deeper decode paths)", () => {
        // A small alphabet weighted toward real varint tag bytes for our
        // schema's field numbers (1-12, wire types 0/2) and length-prefix-
        // sized values, so the fuzzer spends more of its budget inside
        // actual field decoding rather than bailing out on the first byte.
        const biasedByte = fc.oneof(
            fc.constantFrom(0x08, 0x10, 0x18, 0x1a, 0x22, 0x2a, 0x32, 0x3a, 0x60, 0x62), // common tag bytes for fields 1-12
            fc.integer({ min: 0, max: 255 }),
        );
        fc.assert(
            fc.property(fc.array(biasedByte, { minLength: 0, maxLength: 512 }), (byteList) => {
                const bytes = Uint8Array.from(byteList);
                try {
                    const envelope = decodeEnvelope(bytes);
                    return ["SESSION_INIT", "MESSAGE", "SESSION_RESET"].includes(envelope.type);
                } catch (e) {
                    return e instanceof ProtocolError;
                }
            }),
            { numRuns: 2000 },
        );
    });

    it("never hangs (each run completes well within the test timeout across thousands of inputs)", () => {
        // Implicit in the two properties above actually completing, but
        // asserted explicitly: a decoder that infinite-loops or is
        // algorithmically pathological on some crafted input is a DoS
        // vector distinct from "throws the wrong error type."
        const start = Date.now();
        fc.assert(
            fc.property(fc.uint8Array({ minLength: 0, maxLength: 8192 }), (bytes) => {
                try {
                    decodeEnvelope(bytes);
                } catch {
                    /* expected for most inputs */
                }
                return true;
            }),
            { numRuns: 1000 },
        );
        expect(Date.now() - start).toBeLessThan(10_000);
    });
});
