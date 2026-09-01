import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { computeIdentityFingerprint } from "../../src/identity/fingerprint.js";

const provider = new NobleCryptoProvider();
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("computeIdentityFingerprint", () => {
    it("is symmetric regardless of argument order", () => {
        const alice = generateIdentity(provider);
        const bob = generateIdentity(provider);

        const fpAB = computeIdentityFingerprint(provider, alice.keyPair.publicKey, bob.keyPair.publicKey);
        const fpBA = computeIdentityFingerprint(provider, bob.keyPair.publicKey, alice.keyPair.publicKey);

        expect(toHex(fpAB.raw)).toBe(toHex(fpBA.raw));
        expect(fpAB.display).toBe(fpBA.display);
    });

    it("is deterministic for the same pair of keys", () => {
        const alice = generateIdentity(provider);
        const bob = generateIdentity(provider);
        const fp1 = computeIdentityFingerprint(provider, alice.keyPair.publicKey, bob.keyPair.publicKey);
        const fp2 = computeIdentityFingerprint(provider, alice.keyPair.publicKey, bob.keyPair.publicKey);
        expect(toHex(fp1.raw)).toBe(toHex(fp2.raw));
        expect(fp1.display).toBe(fp2.display);
    });

    it("changes if either identity key changes", () => {
        const alice = generateIdentity(provider);
        const bob = generateIdentity(provider);
        const mallory = generateIdentity(provider);

        const genuine = computeIdentityFingerprint(provider, alice.keyPair.publicKey, bob.keyPair.publicKey);
        const substituted = computeIdentityFingerprint(
            provider,
            alice.keyPair.publicKey,
            mallory.keyPair.publicKey,
        );

        expect(genuine.display).not.toBe(substituted.display);
        expect(toHex(genuine.raw)).not.toBe(toHex(substituted.raw));
    });

    it("produces the documented display format: 12 groups of 5 digits", () => {
        const alice = generateIdentity(provider);
        const bob = generateIdentity(provider);
        const fp = computeIdentityFingerprint(provider, alice.keyPair.publicKey, bob.keyPair.publicKey);
        expect(fp.display).toMatch(/^(\d{5} ){11}\d{5}$/);
    });

    it("raw fingerprint is a fixed 32 bytes", () => {
        const alice = generateIdentity(provider);
        const bob = generateIdentity(provider);
        const fp = computeIdentityFingerprint(provider, alice.keyPair.publicKey, bob.keyPair.publicKey);
        expect(fp.raw.length).toBe(32);
    });

    it("a self-fingerprint (identical keys on both sides) is still well-formed", () => {
        const alice = generateIdentity(provider);
        const fp = computeIdentityFingerprint(provider, alice.keyPair.publicKey, alice.keyPair.publicKey);
        expect(fp.display).toMatch(/^(\d{5} ){11}\d{5}$/);
    });
});
