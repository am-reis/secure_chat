import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { encryptAttachment, decryptAttachment } from "../../src/attachments/attachmentCrypto.js";
import { ProtocolError } from "../../src/errors.js";

const provider = new NobleCryptoProvider();
const utf8 = (s: string) => new TextEncoder().encode(s);
const text = (b: Uint8Array) => new TextDecoder().decode(b);

describe("attachmentCrypto — Phase 24", () => {
    it("round-trips a plaintext attachment through encrypt/decrypt", () => {
        const plaintext = utf8("this is definitely a photo of a cat");
        const encrypted = encryptAttachment(provider, plaintext, "image/jpeg");

        expect(encrypted.size).toBe(plaintext.length);
        expect(encrypted.mimeType).toBe("image/jpeg");
        expect(encrypted.ciphertext).not.toEqual(plaintext);

        const descriptor = { objectId: "obj-1", ...encrypted };
        const decrypted = decryptAttachment(provider, descriptor, encrypted.ciphertext);
        expect(text(decrypted)).toBe(text(plaintext));
    });

    it("each encryption uses a fresh random key, even for identical plaintext", () => {
        const plaintext = utf8("same content");
        const a = encryptAttachment(provider, plaintext, "text/plain");
        const b = encryptAttachment(provider, plaintext, "text/plain");
        expect(a.encryptionKey).not.toEqual(b.encryptionKey);
        expect(a.ciphertext).not.toEqual(b.ciphertext); // fresh nonce too
    });

    it("rejects a downloaded blob that doesn't match the descriptor's hash (substituted attachment)", () => {
        const real = encryptAttachment(provider, utf8("real attachment"), "text/plain");
        const other = encryptAttachment(provider, utf8("a completely different attachment"), "text/plain");
        const descriptor = { objectId: "obj-1", ...real };

        try {
            // Object storage serving back the wrong blob for this objectId.
            decryptAttachment(provider, descriptor, other.ciphertext);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("AEAD_AUTHENTICATION_FAILED");
        }
    });

    it("rejects a bit-flipped (corrupted-in-transit) ciphertext", () => {
        const encrypted = encryptAttachment(provider, utf8("corrupt me"), "text/plain");
        const corrupted = encrypted.ciphertext.slice();
        corrupted[corrupted.length - 1]! ^= 0xff;
        const descriptor = { objectId: "obj-1", ...encrypted };

        expect(() => decryptAttachment(provider, descriptor, corrupted)).toThrow(ProtocolError);
    });

    it("fails AEAD decryption if given the right hash but the wrong key (descriptor/key mismatch)", () => {
        const encrypted = encryptAttachment(provider, utf8("secret payload"), "text/plain");
        const wrongKey = provider.randomBytes(32);
        const tamperedDescriptor = { objectId: "obj-1", ...encrypted, encryptionKey: wrongKey };

        expect(() => decryptAttachment(provider, tamperedDescriptor, encrypted.ciphertext)).toThrow();
    });

    it("handles an empty attachment", () => {
        const encrypted = encryptAttachment(provider, new Uint8Array(0), "application/octet-stream");
        expect(encrypted.size).toBe(0);
        const descriptor = { objectId: "obj-1", ...encrypted };
        const decrypted = decryptAttachment(provider, descriptor, encrypted.ciphertext);
        expect(decrypted.length).toBe(0);
    });
});
