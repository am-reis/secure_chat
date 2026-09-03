import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import {
    ratchetInitAlice,
    ratchetInitBob,
    ratchetEncrypt,
    ratchetDecrypt,
} from "../../src/ratchet/DoubleRatchet.js";
import type { RatchetHeader } from "../../src/ratchet/types.js";
import { ProtocolError } from "../../src/errors.js";

const provider = new NobleCryptoProvider();
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const AD = new TextEncoder().encode("property-test-ad");

function setupPair() {
    const sk = provider.randomBytes(32);
    const bobKeyPair = provider.generateX25519KeyPair();
    const alice = ratchetInitAlice(provider, sk, bobKeyPair.publicKey);
    const bob = ratchetInitBob(provider, sk, bobKeyPair);
    return { alice, bob };
}

const arbitraryPlaintext = fc.uint8Array({ minLength: 0, maxLength: 2000 });

describe("Property: decrypt(encrypt(M)) == M (Phase 29)", () => {
    it("holds for arbitrary plaintext, across many random sessions", () => {
        fc.assert(
            fc.property(arbitraryPlaintext, (plaintext) => {
                const { alice, bob } = setupPair();
                const { header, ciphertext } = ratchetEncrypt(provider, alice, plaintext, AD);
                const decrypted = ratchetDecrypt(provider, bob, header, ciphertext, AD);
                return toHex(decrypted) === toHex(plaintext);
            }),
            { numRuns: 200 },
        );
    });

    it("holds across a sequence of several messages on the same chain", () => {
        fc.assert(
            fc.property(fc.array(arbitraryPlaintext, { minLength: 1, maxLength: 10 }), (plaintexts) => {
                const { alice, bob } = setupPair();
                for (const plaintext of plaintexts) {
                    const { header, ciphertext } = ratchetEncrypt(provider, alice, plaintext, AD);
                    const decrypted = ratchetDecrypt(provider, bob, header, ciphertext, AD);
                    if (toHex(decrypted) !== toHex(plaintext)) return false;
                }
                return true;
            }),
            { numRuns: 100 },
        );
    });
});

describe("Property: tamper(ciphertext) -> decrypt fails (Phase 29)", () => {
    it("flipping any single bit of the ciphertext always causes rejection, never a different plaintext", () => {
        fc.assert(
            fc.property(
                fc.uint8Array({ minLength: 1, maxLength: 200 }),
                fc.nat(),
                (plaintext, byteIndexSeed) => {
                    const { alice, bob } = setupPair();
                    const { header, ciphertext } = ratchetEncrypt(provider, alice, plaintext, AD);
                    const idx = byteIndexSeed % ciphertext.length;
                    const tampered = ciphertext.slice();
                    tampered[idx] = tampered[idx]! ^ 0xff;

                    try {
                        ratchetDecrypt(provider, bob, header, tampered, AD);
                        return false; // must never succeed
                    } catch (e) {
                        return e instanceof ProtocolError && e.code === "AEAD_AUTHENTICATION_FAILED";
                    }
                },
            ),
            { numRuns: 150 },
        );
    });
});

describe("Property: tamper(header) -> decrypt fails (Phase 29)", () => {
    it("an arbitrary different messageNumber in the header always causes rejection", () => {
        fc.assert(
            fc.property(arbitraryPlaintext, fc.integer({ min: 1, max: 5000 }), (plaintext, delta) => {
                const { alice, bob } = setupPair();
                const { header, ciphertext } = ratchetEncrypt(provider, alice, plaintext, AD);
                const tamperedHeader: RatchetHeader = {
                    ...header,
                    messageNumber: header.messageNumber + delta, // always different, delta >= 1
                };
                try {
                    ratchetDecrypt(provider, bob, tamperedHeader, ciphertext, AD);
                    return false;
                } catch (e) {
                    return e instanceof ProtocolError;
                }
            }),
            { numRuns: 150 },
        );
    });

    it("an arbitrary different ratchet public key in the header always causes rejection", () => {
        fc.assert(
            fc.property(arbitraryPlaintext, (plaintext) => {
                const { alice, bob } = setupPair();
                const { header, ciphertext } = ratchetEncrypt(provider, alice, plaintext, AD);
                const forgedHeader: RatchetHeader = {
                    ...header,
                    ratchetPublicKey: provider.generateX25519KeyPair().publicKey,
                };
                try {
                    ratchetDecrypt(provider, bob, forgedHeader, ciphertext, AD);
                    return false;
                } catch {
                    return true;
                }
            }),
            { numRuns: 100 },
        );
    });
});

describe("Property: tamper(AD) -> decrypt fails (Phase 29)", () => {
    it("any different associated data always causes rejection", () => {
        fc.assert(
            fc.property(
                arbitraryPlaintext,
                fc.uint8Array({ minLength: 0, maxLength: 100 }),
                (plaintext, wrongAdSuffix) => {
                    const { alice, bob } = setupPair();
                    const { header, ciphertext } = ratchetEncrypt(provider, alice, plaintext, AD);
                    // Guaranteed different from AD by appending at least a length marker.
                    const wrongAd = new Uint8Array([...AD, 0xff, ...wrongAdSuffix]);
                    try {
                        ratchetDecrypt(provider, bob, header, ciphertext, wrongAd);
                        return false;
                    } catch (e) {
                        return e instanceof ProtocolError && e.code === "AEAD_AUTHENTICATION_FAILED";
                    }
                },
            ),
            { numRuns: 150 },
        );
    });
});

describe("Property: replay(message) -> not delivered twice (Phase 29)", () => {
    it("decrypting the same valid message a second time always fails, regardless of plaintext content", () => {
        fc.assert(
            fc.property(arbitraryPlaintext, (plaintext) => {
                const { alice, bob } = setupPair();
                const { header, ciphertext } = ratchetEncrypt(provider, alice, plaintext, AD);

                const first = ratchetDecrypt(provider, bob, header, ciphertext, AD);
                if (toHex(first) !== toHex(plaintext)) return false;

                try {
                    ratchetDecrypt(provider, bob, header, ciphertext, AD); // replay
                    return false; // must never succeed twice
                } catch {
                    return true;
                }
            }),
            { numRuns: 100 },
        );
    });
});

describe("Property: reorder(messages) -> valid messages eventually decrypt (Phase 29)", () => {
    it("for any permutation of delivery order, every message decrypts to its original plaintext exactly once", () => {
        fc.assert(
            fc.property(
                fc.array(arbitraryPlaintext, { minLength: 2, maxLength: 8 }),
                fc.integer({ min: 0, max: 2 ** 31 }), // permutation seed
                (plaintexts, permSeed) => {
                    const { alice, bob } = setupPair();
                    const encrypted = plaintexts.map((pt) => ({
                        original: pt,
                        ...ratchetEncrypt(provider, alice, pt, AD),
                    }));

                    // Deterministic Fisher-Yates using the seed, so failures are reproducible.
                    let seed = permSeed;
                    const rand = () => {
                        seed = (seed * 1103515245 + 12345) & 0x7fffffff;
                        return seed / 0x7fffffff;
                    };
                    const order = encrypted.map((_, i) => i);
                    for (let i = order.length - 1; i > 0; i--) {
                        const j = Math.floor(rand() * (i + 1));
                        [order[i], order[j]] = [order[j]!, order[i]!];
                    }

                    const decryptedHex: string[] = [];
                    for (const idx of order) {
                        const item = encrypted[idx]!;
                        const decrypted = ratchetDecrypt(provider, bob, item.header, item.ciphertext, AD);
                        decryptedHex.push(toHex(decrypted));
                    }

                    const expectedHex = plaintexts.map(toHex).sort();
                    decryptedHex.sort();
                    if (decryptedHex.length !== expectedHex.length) return false;
                    for (let i = 0; i < expectedHex.length; i++) {
                        if (decryptedHex[i] !== expectedHex[i]) return false;
                    }
                    return true;
                },
            ),
            { numRuns: 75 },
        );
    });
});
