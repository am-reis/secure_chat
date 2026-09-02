/**
 * Deterministic, unambiguous binary encoding primitives.
 *
 * These exist because Phase 4 explicitly requires a `canonicalEncode(value)`
 * used for every signed structure, and Phase 7's associated data concatenates
 * several fields together. A naive `concat(a, b)` is NOT safe for that: with
 * plain concatenation, encode(["ab", "c"]) produces the exact same bytes as
 * encode(["a", "bc"]) — an attacker who can influence field boundaries could
 * exploit that ambiguity against a signature or AEAD associated-data check.
 * Every variable-length field here is length-prefixed so its end is
 * unambiguous regardless of what bytes it contains.
 */

/** Encode a non-negative integer as 4 bytes, big-endian. Used for fixed-size numeric fields (versions, counters, lengths). */
export function encodeUint32BE(n: number): Uint8Array {
    if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) {
        throw new RangeError(`encodeUint32BE: value out of range: ${n}`);
    }
    const out = new Uint8Array(4);
    new DataView(out.buffer).setUint32(0, n, false);
    return out;
}

/** Encode a non-negative integer as 8 bytes, big-endian (for values that may exceed 2^32, e.g. timestamps). */
export function encodeUint64BE(n: number | bigint): Uint8Array {
    const big = typeof n === "bigint" ? n : BigInt(n);
    if (big < 0n || big > 0xffffffffffffffffn) {
        throw new RangeError(`encodeUint64BE: value out of range: ${n}`);
    }
    const out = new Uint8Array(8);
    new DataView(out.buffer).setBigUint64(0, big, false);
    return out;
}

/** Concatenate byte arrays with no delimiting — only safe when every part is already self-delimiting (fixed-size or length-prefixed). */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
        out.set(p, offset);
        offset += p.length;
    }
    return out;
}

/** Length-prefix a variable-length field: 4-byte BE length followed by the raw bytes. Makes the field's boundary unambiguous when concatenated with others. */
export function encodeLengthPrefixed(data: Uint8Array): Uint8Array {
    return concatBytes(encodeUint32BE(data.length), data);
}

/**
 * Canonically encode an ordered sequence of variable-length byte fields.
 * Each field is length-prefixed before concatenation, so the encoding of
 * ["ab", "c"] can never collide with the encoding of ["a", "bc"], and field
 * order is part of the encoded output (order must match on both sides of
 * any signature verification or AEAD check).
 */
export function canonicalEncodeFields(...fields: Uint8Array[]): Uint8Array {
    return concatBytes(...fields.map(encodeLengthPrefixed));
}

/**
 * Lexicographically compare two byte arrays (shorter-is-smaller on a common
 * prefix, like string comparison). Used to produce a canonical, order-
 * independent ordering of two public keys — e.g. for a fingerprint that must
 * be identical regardless of which side computes it.
 */
export function compareBytesLexicographic(a: Uint8Array, b: Uint8Array): number {
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) {
        const ai = a[i]!;
        const bi = b[i]!;
        if (ai !== bi) return ai - bi;
    }
    return a.length - b.length;
}

/**
 * Pure-JS hex encoding (no Buffer/Node dependency) — this module needs to
 * stay portable to environments like React Native where Buffer isn't
 * guaranteed available without a polyfill.
 */
export function bytesToHex(bytes: Uint8Array): string {
    let out = "";
    for (const b of bytes) out += b.toString(16).padStart(2, "0");
    return out;
}

/**
 * Constant-time byte comparison. Use this instead of `===`/`Buffer.equals`
 * whenever comparing secret-derived values (MACs, hashes of secrets, etc.)
 * to avoid leaking information through timing side channels. Always
 * consumes both full buffers before returning, and treats a length mismatch
 * as "not equal" without short-circuiting on the length check itself being
 * the only comparison performed for that case.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    const len = Math.max(a.length, b.length);
    let diff = a.length ^ b.length;
    for (let i = 0; i < len; i++) {
        const ai = i < a.length ? a[i]! : 0;
        const bi = i < b.length ? b[i]! : 0;
        diff |= ai ^ bi;
    }
    return diff === 0;
}
