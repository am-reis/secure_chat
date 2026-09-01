import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import { canonicalEncodeFields, compareBytesLexicographic } from "../encoding/canonical.js";

/**
 * Identity verification fingerprint (Phase 2.2). The two parties in a
 * conversation can compare this out-of-band (read aloud, scan a QR code
 * encoding it, etc.) to confirm neither identity key was substituted by an
 * attacker-in-the-middle.
 *
 * Design:
 *   - Symmetric: computeIdentityFingerprint(A, B) === computeIdentityFingerprint(B, A).
 *     Achieved by lexicographically ordering the two public keys before
 *     encoding, so it doesn't matter which side is "self" vs "remote" —
 *     both parties compute the identical value.
 *   - Cryptographically bound to both identity keys (Phase 2.2's
 *     requirement) via HKDF over their canonical encoding — not a weaker
 *     ad-hoc concatenation-and-hash.
 *   - No new primitive: built entirely from `hkdfExtract`/`hkdfExpand`,
 *     already in the CryptoProvider abstraction.
 *
 * The `display` string groups digits the way Signal's safety numbers do
 * (groups of 5 digits) purely because that's a well-tested, easy-to-read-
 * aloud-and-compare format for humans — not for wire compatibility, since
 * interop isn't required.
 */

const FINGERPRINT_DOMAIN = new TextEncoder().encode("secure-messaging/identity-fingerprint/v1");
const FINGERPRINT_SALT = new TextEncoder().encode("secure-messaging/identity-fingerprint/salt/v1");
const DECIMAL_GROUPS = 12;
const BYTES_PER_GROUP = 5; // 40 bits per group, reduced mod 100000 for a 5-digit display group

export interface IdentityFingerprint {
    /** Raw 32-byte binary fingerprint, for programmatic comparison (e.g. matching a scanned QR payload). */
    raw: Uint8Array;
    /** Human-readable form: 12 space-separated 5-digit groups (60 digits total), for manual comparison. */
    display: string;
}

function bytesToDecimalGroups(bytes: Uint8Array, groups: number): string {
    const parts: string[] = [];
    for (let i = 0; i < groups; i++) {
        const chunk = bytes.subarray(i * BYTES_PER_GROUP, i * BYTES_PER_GROUP + BYTES_PER_GROUP);
        let value = 0n;
        for (const b of chunk) value = (value << 8n) | BigInt(b);
        const digits = (value % 100000n).toString().padStart(5, "0");
        parts.push(digits);
    }
    return parts.join(" ");
}

export function computeIdentityFingerprint(
    provider: CryptoProvider,
    identityPublicKeyA: Uint8Array,
    identityPublicKeyB: Uint8Array,
): IdentityFingerprint {
    const [first, second] =
        compareBytesLexicographic(identityPublicKeyA, identityPublicKeyB) <= 0
            ? [identityPublicKeyA, identityPublicKeyB]
            : [identityPublicKeyB, identityPublicKeyA];

    const combined = canonicalEncodeFields(FINGERPRINT_DOMAIN, first, second);

    const prk = provider.hkdfExtract(FINGERPRINT_SALT, combined);
    const okm = provider.hkdfExpand(
        prk,
        new TextEncoder().encode("display"),
        DECIMAL_GROUPS * BYTES_PER_GROUP,
    );

    return {
        raw: provider.hash(combined),
        display: bytesToDecimalGroups(okm, DECIMAL_GROUPS),
    };
}
