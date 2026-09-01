import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity, computeIdentityId } from "../../src/identity/identity.js";
import { toPublicIdentity } from "../../src/identity/types.js";

const provider = new NobleCryptoProvider();
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("generateIdentity", () => {
    it("produces a key pair usable for sign/verify", () => {
        const identity = generateIdentity(provider);
        const message = new TextEncoder().encode("test message");
        const sig = provider.sign(identity.keyPair.privateKey, message);
        expect(provider.verify(identity.keyPair.publicKey, message, sig)).toBe(true);
    });

    it("sets createdAt and version", () => {
        const before = Date.now();
        const identity = generateIdentity(provider);
        const after = Date.now();
        expect(identity.createdAt).toBeGreaterThanOrEqual(before);
        expect(identity.createdAt).toBeLessThanOrEqual(after);
        expect(identity.version).toBe(1);
    });

    it("respects an explicit version argument", () => {
        const identity = generateIdentity(provider, 3);
        expect(identity.version).toBe(3);
    });

    it("produces distinct identities on repeated calls", () => {
        const a = generateIdentity(provider);
        const b = generateIdentity(provider);
        expect(toHex(a.keyPair.publicKey)).not.toBe(toHex(b.keyPair.publicKey));
        expect(toHex(a.identityId)).not.toBe(toHex(b.identityId));
    });

    it("sets identityId consistently with computeIdentityId", () => {
        const identity = generateIdentity(provider);
        expect(toHex(identity.identityId)).toBe(
            toHex(computeIdentityId(provider, identity.keyPair.publicKey)),
        );
    });
});

describe("computeIdentityId", () => {
    it("is deterministic for the same public key", () => {
        const identity = generateIdentity(provider);
        const id1 = computeIdentityId(provider, identity.keyPair.publicKey);
        const id2 = computeIdentityId(provider, identity.keyPair.publicKey);
        expect(toHex(id1)).toBe(toHex(id2));
    });

    it("is a fixed 32-byte length", () => {
        const identity = generateIdentity(provider);
        expect(computeIdentityId(provider, identity.keyPair.publicKey).length).toBe(32);
    });

    it("differs for different public keys", () => {
        const a = generateIdentity(provider);
        const b = generateIdentity(provider);
        expect(toHex(computeIdentityId(provider, a.keyPair.publicKey))).not.toBe(
            toHex(computeIdentityId(provider, b.keyPair.publicKey)),
        );
    });

    it("is not simply the raw public key (domain separation applied)", () => {
        const identity = generateIdentity(provider);
        expect(toHex(computeIdentityId(provider, identity.keyPair.publicKey))).not.toBe(
            toHex(identity.keyPair.publicKey),
        );
    });
});

describe("toPublicIdentity", () => {
    it("carries over identityId and version", () => {
        const identity = generateIdentity(provider, 2);
        const pub = toPublicIdentity(identity);
        expect(toHex(pub.identityId)).toBe(toHex(identity.identityId));
        expect(pub.version).toBe(2);
        expect(toHex(pub.publicKey)).toBe(toHex(identity.keyPair.publicKey));
    });

    it("never exposes a privateKey field", () => {
        const identity = generateIdentity(provider);
        const pub = toPublicIdentity(identity);
        expect("privateKey" in pub).toBe(false);
        expect(Object.keys(pub).sort()).toEqual(["identityId", "publicKey", "version"]);
    });
});
