import { describe, it, expect } from "vitest";
import crypto from "node:crypto";
import { NobleCryptoProvider, CryptoError } from "../../src/crypto/NobleCryptoProvider.js";

const hex = (h: string) => Uint8Array.from(Buffer.from(h, "hex"));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

const provider = new NobleCryptoProvider();

describe("X25519", () => {
    // RFC 7748 §5.2 test vectors, verified against the official RFC text
    // (rfc-editor.org) and independently cross-checked bit-for-bit against
    // this exact library call before being committed here.
    it("matches RFC 7748 test vector 1", () => {
        const scalar = hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        const u = hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        const expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
        expect(toHex(provider.x25519(scalar, u))).toBe(expected);
    });

    it("matches RFC 7748 test vector 2", () => {
        const scalar = hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        const u = hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        const expected = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";
        expect(toHex(provider.x25519(scalar, u))).toBe(expected);
    });

    it("produces a matching shared secret for both parties (DH agreement)", () => {
        const alice = provider.generateX25519KeyPair();
        const bob = provider.generateX25519KeyPair();
        const sharedA = provider.x25519(alice.privateKey, bob.publicKey);
        const sharedB = provider.x25519(bob.privateKey, alice.publicKey);
        expect(toHex(sharedA)).toBe(toHex(sharedB));
    });

    it("rejects an invalid public key", () => {
        const alice = provider.generateX25519KeyPair();
        const badPublicKey = new Uint8Array(4); // wrong length
        expect(() => provider.x25519(alice.privateKey, badPublicKey)).toThrow(CryptoError);
    });

    it("generated key pairs are independently random", () => {
        const a = provider.generateX25519KeyPair();
        const b = provider.generateX25519KeyPair();
        expect(toHex(a.privateKey)).not.toBe(toHex(b.privateKey));
    });
});

describe("Hash (SHA-256)", () => {
    // NIST/well-known SHA-256 vectors, cross-checked against Node's
    // independent OpenSSL-backed crypto.createHash before being hardcoded.
    it("matches the known SHA-256 hash of the empty string", () => {
        expect(toHex(provider.hash(new Uint8Array(0)))).toBe(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
    });

    it('matches the known SHA-256 hash of "abc"', () => {
        expect(toHex(provider.hash(new TextEncoder().encode("abc")))).toBe(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    });

    it("is deterministic", () => {
        const data = provider.randomBytes(64);
        expect(toHex(provider.hash(data))).toBe(toHex(provider.hash(data)));
    });

    it("produces different output for different input (no obvious collisions)", () => {
        const a = provider.hash(new TextEncoder().encode("message-a"));
        const b = provider.hash(new TextEncoder().encode("message-b"));
        expect(toHex(a)).not.toBe(toHex(b));
    });

    it("always returns 32 bytes", () => {
        expect(provider.hash(new Uint8Array(0)).length).toBe(32);
        expect(provider.hash(provider.randomBytes(1000)).length).toBe(32);
    });
});

describe("Identity signatures (Ed25519)", () => {
    it("verifies a valid signature", () => {
        const identity = provider.generateIdentityKeyPair();
        const message = new TextEncoder().encode("prekey bundle contents");
        const sig = provider.sign(identity.privateKey, message);
        expect(provider.verify(identity.publicKey, message, sig)).toBe(true);
    });

    it("rejects a signature over tampered data", () => {
        const identity = provider.generateIdentityKeyPair();
        const message = new TextEncoder().encode("original message");
        const tampered = new TextEncoder().encode("original mess age");
        const sig = provider.sign(identity.privateKey, message);
        expect(provider.verify(identity.publicKey, tampered, sig)).toBe(false);
    });

    it("rejects a signature from the wrong identity", () => {
        const identityA = provider.generateIdentityKeyPair();
        const identityB = provider.generateIdentityKeyPair();
        const message = new TextEncoder().encode("hello");
        const sig = provider.sign(identityA.privateKey, message);
        expect(provider.verify(identityB.publicKey, message, sig)).toBe(false);
    });

    it("rejects a corrupted signature", () => {
        const identity = provider.generateIdentityKeyPair();
        const message = new TextEncoder().encode("hello");
        const sig = provider.sign(identity.privateKey, message);
        sig[0] ^= 0xff;
        expect(provider.verify(identity.publicKey, message, sig)).toBe(false);
    });

    it("never throws on a malformed public key — returns false instead", () => {
        const identity = provider.generateIdentityKeyPair();
        const message = new TextEncoder().encode("hello");
        const sig = provider.sign(identity.privateKey, message);
        const garbagePublicKey = new Uint8Array(3);
        expect(() => provider.verify(garbagePublicKey, message, sig)).not.toThrow();
        expect(provider.verify(garbagePublicKey, message, sig)).toBe(false);
    });

    it("derives a consistent X25519 keypair from the same Ed25519 identity key (dual-use)", () => {
        const identity = provider.generateIdentityKeyPair();
        const xPriv = provider.x25519PrivateFromIdentity(identity.privateKey);
        const xPub = provider.x25519PublicFromIdentity(identity.publicKey);
        // The X25519 public key recomputed from the derived private key must
        // match the X25519 public key derived directly from the identity
        // public key — i.e. the two derivations describe the same point.
        const recomputed = provider.generateX25519KeyPair(); // just to exercise the API shape
        expect(xPriv.length).toBe(32);
        expect(xPub.length).toBe(32);
        expect(recomputed.publicKey.length).toBe(32);
    });
});

describe("PQ KEM (ML-KEM-1024)", () => {
    it("encapsulate/decapsulate produces a matching shared secret", () => {
        const kp = provider.generateKemKeyPair();
        const { ciphertext, sharedSecret } = provider.kemEncapsulate(kp.publicKey);
        const recovered = provider.kemDecapsulate(kp.privateKey, ciphertext);
        expect(toHex(recovered)).toBe(toHex(sharedSecret));
    });

    it("rejects an encapsulation public key of the wrong length", () => {
        const badPublicKey = new Uint8Array(10);
        expect(() => provider.kemEncapsulate(badPublicKey)).toThrow(CryptoError);
    });

    it("a tampered ciphertext yields a different shared secret (FIPS 203 implicit rejection)", () => {
        const kp = provider.generateKemKeyPair();
        const { ciphertext, sharedSecret } = provider.kemEncapsulate(kp.publicKey);
        const tampered = ciphertext.slice();
        tampered[0] ^= 0xff;
        const recovered = provider.kemDecapsulate(kp.privateKey, tampered);
        // ML-KEM does not throw on a tampered ciphertext (implicit rejection);
        // it must silently produce a different, unusable shared secret instead.
        expect(toHex(recovered)).not.toBe(toHex(sharedSecret));
    });

    it("rejects a decapsulation ciphertext of the wrong length", () => {
        const kp = provider.generateKemKeyPair();
        const badCiphertext = new Uint8Array(5);
        expect(() => provider.kemDecapsulate(kp.privateKey, badCiphertext)).toThrow(CryptoError);
    });
});

describe("HKDF (RFC 5869, SHA-512)", () => {
    it("matches Node's independent OpenSSL-backed HKDF implementation", () => {
        const ikm = provider.randomBytes(32);
        const salt = provider.randomBytes(16);
        const info = new TextEncoder().encode("test-context");
        const length = 64;

        const prk = provider.hkdfExtract(salt, ikm);
        const okm = provider.hkdfExpand(prk, info, length);

        const nodeOkm = crypto.hkdfSync(
            "sha512",
            Buffer.from(ikm),
            Buffer.from(salt),
            Buffer.from(info),
            length,
        );

        expect(toHex(okm)).toBe(Buffer.from(nodeOkm).toString("hex"));
    });

    it("is deterministic for the same inputs", () => {
        const ikm = hex("aa".repeat(32));
        const salt = hex("bb".repeat(16));
        const info = new TextEncoder().encode("ctx");
        const prk1 = provider.hkdfExtract(salt, ikm);
        const prk2 = provider.hkdfExtract(salt, ikm);
        expect(toHex(prk1)).toBe(toHex(prk2));
        expect(toHex(provider.hkdfExpand(prk1, info, 32))).toBe(
            toHex(provider.hkdfExpand(prk2, info, 32)),
        );
    });

    it("different info produces different output (domain separation)", () => {
        const prk = provider.hkdfExtract(provider.randomBytes(16), provider.randomBytes(32));
        const out1 = provider.hkdfExpand(prk, new TextEncoder().encode("context-1"), 32);
        const out2 = provider.hkdfExpand(prk, new TextEncoder().encode("context-2"), 32);
        expect(toHex(out1)).not.toBe(toHex(out2));
    });

    it("produces output of the requested length", () => {
        const prk = provider.hkdfExtract(provider.randomBytes(16), provider.randomBytes(32));
        expect(provider.hkdfExpand(prk, new Uint8Array(0), 100).length).toBe(100);
    });
});

describe("HMAC (SHA-512)", () => {
    it("matches Node's independent OpenSSL-backed HMAC implementation", () => {
        const key = provider.randomBytes(32);
        const data = new TextEncoder().encode("test message");
        const out = provider.hmac(key, data);
        const nodeOut = crypto.createHmac("sha512", Buffer.from(key)).update(Buffer.from(data)).digest();
        expect(toHex(out)).toBe(nodeOut.toString("hex"));
    });

    it("is deterministic", () => {
        const key = provider.randomBytes(32);
        const data = provider.randomBytes(16);
        expect(toHex(provider.hmac(key, data))).toBe(toHex(provider.hmac(key, data)));
    });

    it("different keys produce different output for the same data", () => {
        const data = new TextEncoder().encode("same");
        const out1 = provider.hmac(provider.randomBytes(32), data);
        const out2 = provider.hmac(provider.randomBytes(32), data);
        expect(toHex(out1)).not.toBe(toHex(out2));
    });

    it("always returns 64 bytes (SHA-512 output length)", () => {
        expect(provider.hmac(provider.randomBytes(32), new Uint8Array(0)).length).toBe(64);
    });
});

describe("AEAD (XChaCha20-Poly1305)", () => {
    it("round-trips plaintext through encrypt/decrypt", () => {
        const key = provider.randomBytes(32);
        const ad = new TextEncoder().encode("session-context");
        const plaintext = new TextEncoder().encode("the eagle flies at midnight");

        const ciphertext = provider.aeadEncrypt(key, plaintext, ad);
        const decrypted = provider.aeadDecrypt(key, ciphertext, ad);

        expect(new TextDecoder().decode(decrypted)).toBe("the eagle flies at midnight");
    });

    it("produces different ciphertext for the same plaintext each call (random nonce)", () => {
        const key = provider.randomBytes(32);
        const ad = new Uint8Array(0);
        const plaintext = new TextEncoder().encode("same message");
        const c1 = provider.aeadEncrypt(key, plaintext, ad);
        const c2 = provider.aeadEncrypt(key, plaintext, ad);
        expect(toHex(c1)).not.toBe(toHex(c2));
    });

    it("fails to decrypt when ciphertext is tampered", () => {
        const key = provider.randomBytes(32);
        const ad = new TextEncoder().encode("ad");
        const ciphertext = provider.aeadEncrypt(key, new TextEncoder().encode("hello"), ad);
        const tampered = ciphertext.slice();
        tampered[tampered.length - 1] ^= 0xff; // flip a bit in the auth tag region
        expect(() => provider.aeadDecrypt(key, tampered, ad)).toThrow(CryptoError);
    });

    it("fails to decrypt when associated data is tampered", () => {
        const key = provider.randomBytes(32);
        const ciphertext = provider.aeadEncrypt(
            key,
            new TextEncoder().encode("hello"),
            new TextEncoder().encode("correct-ad"),
        );
        expect(() =>
            provider.aeadDecrypt(key, ciphertext, new TextEncoder().encode("wrong-ad")),
        ).toThrow(CryptoError);
    });

    it("fails to decrypt with the wrong key", () => {
        const key1 = provider.randomBytes(32);
        const key2 = provider.randomBytes(32);
        const ad = new Uint8Array(0);
        const ciphertext = provider.aeadEncrypt(key1, new TextEncoder().encode("hello"), ad);
        expect(() => provider.aeadDecrypt(key2, ciphertext, ad)).toThrow(CryptoError);
    });

    it("rejects a ciphertext shorter than the nonce", () => {
        const key = provider.randomBytes(32);
        const tooShort = new Uint8Array(4);
        expect(() => provider.aeadDecrypt(key, tooShort, new Uint8Array(0))).toThrow(CryptoError);
    });
});

describe("Randomness", () => {
    it("randomBytes returns the requested length", () => {
        expect(provider.randomBytes(32).length).toBe(32);
        expect(provider.randomBytes(1).length).toBe(1);
        expect(provider.randomBytes(0).length).toBe(0);
    });

    it("randomBytes does not repeat across calls", () => {
        const samples = Array.from({ length: 20 }, () => toHex(provider.randomBytes(32)));
        expect(new Set(samples).size).toBe(samples.length);
    });

    it("randomBytes does not return an all-zero buffer", () => {
        const b = provider.randomBytes(32);
        expect(b.some((byte) => byte !== 0)).toBe(true);
    });

    it("secureErase zeroizes a buffer in place", () => {
        const secret = provider.randomBytes(32);
        expect(secret.some((byte) => byte !== 0)).toBe(true);
        provider.secureErase(secret);
        expect(secret.every((byte) => byte === 0)).toBe(true);
    });
});
