import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { decryptSessionRecord } from "../../src/persistence/encryptedStorage.js";
import { ProtocolError } from "../../src/errors.js";

const provider = new NobleCryptoProvider();

/**
 * Fuzzing the persistence decrypt boundary — Phase 28.3's "corrupted
 * database state," applied at volume rather than as a handful of
 * hand-picked cases. A local storage backend can be corrupted by disk
 * errors, a buggy migration, or (in the threat model this project takes
 * seriously) a compromised device tampering with data at rest — none of
 * that should ever surface as anything other than a classified
 * `ProtocolError("STORAGE_FAILURE")`.
 */
describe("Fuzz: decryptSessionRecord never crashes on arbitrary ciphertext bytes", () => {
    it("either decrypts or throws a classified ProtocolError — nothing else", () => {
        const masterKey = provider.randomBytes(32);
        const sessionId = provider.randomBytes(32);

        fc.assert(
            fc.property(fc.uint8Array({ minLength: 0, maxLength: 2048 }), (garbage) => {
                try {
                    decryptSessionRecord(provider, masterKey, sessionId, garbage);
                    return true; // extraordinarily unlikely to succeed on random bytes, but not a failure if it does
                } catch (e) {
                    return e instanceof ProtocolError && e.code === "STORAGE_FAILURE";
                }
            }),
            { numRuns: 1000 },
        );
    });

    it("a genuinely valid record with a single corrupted byte anywhere always fails cleanly, never silently decrypts wrong", () => {
        const masterKey = provider.randomBytes(32);
        const sessionId = provider.randomBytes(32);
        const validCiphertext = provider.aeadEncrypt(
            masterKey,
            new TextEncoder().encode(JSON.stringify({ hello: "world" })),
            sessionId,
        );

        fc.assert(
            fc.property(
                fc.integer({ min: 0, max: validCiphertext.length - 1 }),
                fc.integer({ min: 1, max: 255 }),
                (byteIndex, xorMask) => {
                    const corrupted = validCiphertext.slice();
                    corrupted[byteIndex]! ^= xorMask;
                    try {
                        decryptSessionRecord(provider, masterKey, sessionId, corrupted);
                        return false; // a single flipped bit must never still authenticate
                    } catch (e) {
                        return e instanceof ProtocolError && e.code === "STORAGE_FAILURE";
                    }
                },
            ),
            { numRuns: 500 },
        );
    });

    it("the unmodified valid record still decrypts correctly (sanity check the fuzz harness itself isn't broken)", () => {
        const masterKey = provider.randomBytes(32);
        const sessionId = provider.randomBytes(32);
        const record = { hello: "world", n: 42 };
        const ciphertext = provider.aeadEncrypt(masterKey, new TextEncoder().encode(JSON.stringify(record)), sessionId);
        const decrypted = decryptSessionRecord(provider, masterKey, sessionId, ciphertext);
        expect(decrypted).toEqual(record);
    });
});
