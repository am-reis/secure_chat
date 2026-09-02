import { describe, it, expect } from "vitest";
import {
    encodeUint32BE,
    encodeUint64BE,
    concatBytes,
    encodeLengthPrefixed,
    canonicalEncodeFields,
    compareBytesLexicographic,
    constantTimeEqual,
    bytesToHex,
    hexToBytes,
} from "../../src/encoding/canonical.js";

const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const utf8 = (s: string) => new TextEncoder().encode(s);

describe("encodeUint32BE", () => {
    it("encodes known values big-endian", () => {
        expect(toHex(encodeUint32BE(0))).toBe("00000000");
        expect(toHex(encodeUint32BE(1))).toBe("00000001");
        expect(toHex(encodeUint32BE(256))).toBe("00000100");
        expect(toHex(encodeUint32BE(0xdeadbeef))).toBe("deadbeef");
        expect(toHex(encodeUint32BE(0xffffffff))).toBe("ffffffff");
    });

    it("rejects out-of-range or non-integer values", () => {
        expect(() => encodeUint32BE(-1)).toThrow(RangeError);
        expect(() => encodeUint32BE(0x100000000)).toThrow(RangeError);
        expect(() => encodeUint32BE(1.5)).toThrow(RangeError);
    });
});

describe("encodeUint64BE", () => {
    it("encodes known values big-endian", () => {
        expect(toHex(encodeUint64BE(0))).toBe("0000000000000000");
        expect(toHex(encodeUint64BE(1))).toBe("0000000000000001");
        expect(toHex(encodeUint64BE(0x1_00000000n))).toBe("0000000100000000");
    });

    it("rejects negative values", () => {
        expect(() => encodeUint64BE(-1)).toThrow(RangeError);
    });
});

describe("concatBytes", () => {
    it("concatenates in order", () => {
        expect(toHex(concatBytes(utf8("a"), utf8("b"), utf8("c")))).toBe(
            toHex(utf8("abc")),
        );
    });

    it("handles empty arrays", () => {
        expect(concatBytes().length).toBe(0);
        expect(toHex(concatBytes(new Uint8Array(0), utf8("x")))).toBe(toHex(utf8("x")));
    });
});

describe("encodeLengthPrefixed / canonicalEncodeFields — unambiguity", () => {
    it("length-prefixes correctly", () => {
        const encoded = encodeLengthPrefixed(utf8("hi"));
        expect(toHex(encoded)).toBe(toHex(concatBytes(encodeUint32BE(2), utf8("hi"))));
    });

    it("CRITICAL: canonical encoding of [ab, c] does not collide with [a, bc]", () => {
        const encoding1 = canonicalEncodeFields(utf8("ab"), utf8("c"));
        const encoding2 = canonicalEncodeFields(utf8("a"), utf8("bc"));
        expect(toHex(encoding1)).not.toBe(toHex(encoding2));

        // Sanity check that naive concatenation WOULD have collided —
        // proving the length-prefixing is actually doing something.
        const naive1 = toHex(concatBytes(utf8("ab"), utf8("c")));
        const naive2 = toHex(concatBytes(utf8("a"), utf8("bc")));
        expect(naive1).toBe(naive2);
    });

    it("field order matters", () => {
        const a = canonicalEncodeFields(utf8("first"), utf8("second"));
        const b = canonicalEncodeFields(utf8("second"), utf8("first"));
        expect(toHex(a)).not.toBe(toHex(b));
    });

    it("is deterministic for the same input", () => {
        const a = canonicalEncodeFields(utf8("x"), utf8("y"), utf8("z"));
        const b = canonicalEncodeFields(utf8("x"), utf8("y"), utf8("z"));
        expect(toHex(a)).toBe(toHex(b));
    });

    it("distinguishes an empty field list from a single empty field", () => {
        const zeroFields = canonicalEncodeFields();
        const oneEmptyField = canonicalEncodeFields(new Uint8Array(0));
        expect(toHex(zeroFields)).not.toBe(toHex(oneEmptyField));
    });
});

describe("compareBytesLexicographic", () => {
    it("orders by first differing byte", () => {
        expect(compareBytesLexicographic(utf8("a"), utf8("b"))).toBeLessThan(0);
        expect(compareBytesLexicographic(utf8("b"), utf8("a"))).toBeGreaterThan(0);
        expect(compareBytesLexicographic(utf8("abc"), utf8("abc"))).toBe(0);
    });

    it("treats a common-prefix shorter array as smaller", () => {
        expect(compareBytesLexicographic(utf8("ab"), utf8("abc"))).toBeLessThan(0);
        expect(compareBytesLexicographic(utf8("abc"), utf8("ab"))).toBeGreaterThan(0);
    });

    it("can be used to produce a stable, order-independent pair ordering", () => {
        const x = utf8("keyX");
        const y = utf8("keyY");
        const orderXY = compareBytesLexicographic(x, y) <= 0 ? [x, y] : [y, x];
        const orderYX = compareBytesLexicographic(y, x) <= 0 ? [y, x] : [x, y];
        expect(toHex(orderXY[0]!)).toBe(toHex(orderYX[0]!));
        expect(toHex(orderXY[1]!)).toBe(toHex(orderYX[1]!));
    });
});

describe("bytesToHex / hexToBytes", () => {
    it("round-trips arbitrary bytes", () => {
        const original = new Uint8Array([0, 1, 2, 253, 254, 255, 16, 17]);
        expect(hexToBytes(bytesToHex(original))).toEqual(original);
    });

    it("pads single-digit bytes with a leading zero", () => {
        expect(bytesToHex(new Uint8Array([0, 5, 15]))).toBe("00050f");
    });

    it("handles the empty array", () => {
        expect(bytesToHex(new Uint8Array(0))).toBe("");
        expect(hexToBytes("")).toEqual(new Uint8Array(0));
    });

    it("rejects odd-length hex input", () => {
        expect(() => hexToBytes("abc")).toThrow(RangeError);
    });

    it("rejects non-hex characters", () => {
        expect(() => hexToBytes("zz")).toThrow(RangeError);
    });
});

describe("constantTimeEqual", () => {
    it("returns true for identical arrays", () => {
        expect(constantTimeEqual(utf8("secret"), utf8("secret"))).toBe(true);
    });

    it("returns false for different content of the same length", () => {
        expect(constantTimeEqual(utf8("secretA"), utf8("secretB"))).toBe(false);
    });

    it("returns false for different lengths", () => {
        expect(constantTimeEqual(utf8("short"), utf8("longer-value"))).toBe(false);
    });

    it("treats two empty arrays as equal", () => {
        expect(constantTimeEqual(new Uint8Array(0), new Uint8Array(0))).toBe(true);
    });
});
