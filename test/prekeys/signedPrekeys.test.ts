import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey, verifySignedPreKey, isExpired } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey, verifyPQPreKey } from "../../src/prekeys/pqPrekey.js";

const provider = new NobleCryptoProvider();

describe("SignedPreKey (EC / X25519)", () => {
    it("generates a verifiable prekey", () => {
        const identity = generateIdentity(provider);
        const spk = generateSignedPreKey(provider, identity, 1, 30 * 24 * 60 * 60 * 1000);
        expect(verifySignedPreKey(provider, identity.keyPair.publicKey, spk)).toBe(true);
    });

    it("rejects verification against the wrong identity", () => {
        const identity = generateIdentity(provider);
        const impostor = generateIdentity(provider);
        const spk = generateSignedPreKey(provider, identity, 1, 100000);
        expect(verifySignedPreKey(provider, impostor.keyPair.publicKey, spk)).toBe(false);
    });

    it("rejects a tampered public key", () => {
        const identity = generateIdentity(provider);
        const spk = generateSignedPreKey(provider, identity, 1, 100000);
        const tampered = { ...spk, publicKey: spk.publicKey.slice() };
        tampered.publicKey[0]! ^= 0xff;
        expect(verifySignedPreKey(provider, identity.keyPair.publicKey, tampered)).toBe(false);
    });

    it("rejects a tampered id (id is bound into the signature)", () => {
        const identity = generateIdentity(provider);
        const spk = generateSignedPreKey(provider, identity, 1, 100000);
        const tampered = { ...spk, id: 2 };
        expect(verifySignedPreKey(provider, identity.keyPair.publicKey, tampered)).toBe(false);
    });

    it("expiresAt is NOT part of the signed payload (by design — see signing.ts note): changing it does not break verification", () => {
        const identity = generateIdentity(provider);
        const spk = generateSignedPreKey(provider, identity, 1, 100000);
        const tampered = { ...spk, expiresAt: spk.expiresAt + 1_000_000_000 };
        expect(verifySignedPreKey(provider, identity.keyPair.publicKey, tampered)).toBe(true);
    });

    it("a signature from a different domain (PQ prekey) does not verify as an EC signed prekey", () => {
        const identity = generateIdentity(provider);
        const pqPrekey = generatePQPreKey(provider, identity, 1, 100000);
        // Construct an EC-shaped object carrying the PQ prekey's signature.
        const crossTyped = {
            id: pqPrekey.id,
            publicKey: pqPrekey.publicKey,
            signature: pqPrekey.signature,
        };
        expect(verifySignedPreKey(provider, identity.keyPair.publicKey, crossTyped)).toBe(false);
    });

    it("isExpired reflects expiresAt correctly", () => {
        const identity = generateIdentity(provider);
        const spk = generateSignedPreKey(provider, identity, 1, 1000);
        expect(isExpired(spk, spk.createdAt)).toBe(false);
        expect(isExpired(spk, spk.createdAt + 999)).toBe(false);
        expect(isExpired(spk, spk.createdAt + 1000)).toBe(true);
        expect(isExpired(spk, spk.createdAt + 5000)).toBe(true);
    });

    it("an expired prekey's signature still verifies (expiry and signature validity are separate checks)", () => {
        const identity = generateIdentity(provider);
        const spk = generateSignedPreKey(provider, identity, 1, 1000);
        expect(isExpired(spk, spk.createdAt + 5000)).toBe(true);
        expect(verifySignedPreKey(provider, identity.keyPair.publicKey, spk)).toBe(true);
    });
});

describe("PQPreKey (ML-KEM-1024)", () => {
    it("generates a verifiable prekey usable for encapsulation", () => {
        const identity = generateIdentity(provider);
        const pqk = generatePQPreKey(provider, identity, 7, 100000);
        expect(verifyPQPreKey(provider, identity.keyPair.publicKey, pqk)).toBe(true);

        const { ciphertext, sharedSecret } = provider.kemEncapsulate(pqk.publicKey);
        const recovered = provider.kemDecapsulate(pqk.privateKey, ciphertext);
        expect(Buffer.from(recovered).equals(Buffer.from(sharedSecret))).toBe(true);
    });

    it("rejects a tampered public key", () => {
        const identity = generateIdentity(provider);
        const pqk = generatePQPreKey(provider, identity, 7, 100000);
        const tampered = { ...pqk, publicKey: pqk.publicKey.slice() };
        tampered.publicKey[0]! ^= 0xff;
        expect(verifyPQPreKey(provider, identity.keyPair.publicKey, tampered)).toBe(false);
    });

    it("rejects verification against the wrong identity", () => {
        const identity = generateIdentity(provider);
        const impostor = generateIdentity(provider);
        const pqk = generatePQPreKey(provider, identity, 7, 100000);
        expect(verifyPQPreKey(provider, impostor.keyPair.publicKey, pqk)).toBe(false);
    });
});
