import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { extract as hkdfExtractRaw, expand as hkdfExpandRaw } from "@noble/hashes/hkdf.js";
import { hmac as nobleHmac } from "@noble/hashes/hmac.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils.js";

import type { CryptoProvider } from "./CryptoProvider.js";
import type {
    KeyPair,
    IdentityKeyPair,
    KemKeyPair,
    KemEncapsulationResult,
} from "./types.js";

/** XChaCha20-Poly1305 uses a 24-byte extended nonce. */
const AEAD_NONCE_LENGTH = 24;

export class CryptoError extends Error {
    constructor(
        message: string,
        public readonly code:
            | "INVALID_PUBLIC_KEY"
            | "INVALID_SIGNATURE"
            | "INVALID_PQ_CIPHERTEXT"
            | "AEAD_AUTHENTICATION_FAILED"
            | "INVALID_CIPHERTEXT_FORMAT",
    ) {
        super(message);
        this.name = "CryptoError";
    }
}

/**
 * CryptoProvider implementation backed by @noble/curves, @noble/ciphers,
 * @noble/hashes, and @noble/post-quantum. These are audited, dependency-free,
 * pure-TypeScript implementations — no primitive is reimplemented here.
 *
 * Primitive choices (see spec discussion):
 *   - Classical DH:      X25519            (@noble/curves)
 *   - Signatures:        Ed25519           (@noble/curves)
 *   - PQ KEM:             ML-KEM-1024       (@noble/post-quantum) — matches
 *                          Signal's production PQXDH deployment (Kyber-1024)
 *   - KDF:                HKDF-SHA512       (@noble/hashes)
 *   - AEAD:               XChaCha20-Poly1305 (@noble/ciphers)
 *
 * Identity key dual-use (X25519 DH + Ed25519 signing from one key pair):
 * see the note in ./types.ts. `x25519PrivateFromIdentity` /
 * `x25519PublicFromIdentity` below perform the birational conversion; PQXDH
 * (Phase 5) will call these when it needs to run DH1/DH2 against IK_A/IK_B.
 */
export class NobleCryptoProvider implements CryptoProvider {
    // ---- X25519 ----------------------------------------------------------

    generateX25519KeyPair(): KeyPair {
        const privateKey = x25519.utils.randomSecretKey();
        const publicKey = x25519.getPublicKey(privateKey);
        return { publicKey, privateKey };
    }

    x25519(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
        try {
            return x25519.getSharedSecret(privateKey, publicKey);
        } catch (err) {
            throw new CryptoError(
                `X25519 shared secret computation failed: ${(err as Error).message}`,
                "INVALID_PUBLIC_KEY",
            );
        }
    }

    /** Derive the X25519 private scalar corresponding to an Ed25519 identity private key. */
    x25519PrivateFromIdentity(identityPrivateKey: Uint8Array): Uint8Array {
        return ed25519.utils.toMontgomerySecret(identityPrivateKey);
    }

    /** Derive the X25519 public key corresponding to an Ed25519 identity public key. */
    x25519PublicFromIdentity(identityPublicKey: Uint8Array): Uint8Array {
        try {
            return ed25519.utils.toMontgomery(identityPublicKey);
        } catch (err) {
            throw new CryptoError(
                `Invalid identity public key: ${(err as Error).message}`,
                "INVALID_PUBLIC_KEY",
            );
        }
    }

    // ---- Hash ---------------------------------------------------------------

    hash(data: Uint8Array): Uint8Array {
        return sha256(data);
    }

    // ---- Identity / signatures --------------------------------------------

    generateIdentityKeyPair(): IdentityKeyPair {
        const privateKey = ed25519.utils.randomSecretKey();
        const publicKey = ed25519.getPublicKey(privateKey);
        return { publicKey, privateKey };
    }

    sign(privateKey: Uint8Array, data: Uint8Array): Uint8Array {
        return ed25519.sign(data, privateKey);
    }

    verify(publicKey: Uint8Array, data: Uint8Array, signature: Uint8Array): boolean {
        try {
            return ed25519.verify(signature, data, publicKey);
        } catch {
            // Malformed public key / signature -> treat as verification failure,
            // never throw (Phase 4.1 / Phase 17: reject, don't crash the caller).
            return false;
        }
    }

    // ---- PQ KEM (ML-KEM-1024) ---------------------------------------------

    generateKemKeyPair(): KemKeyPair {
        const kp = ml_kem1024.keygen();
        return { publicKey: kp.publicKey, privateKey: kp.secretKey };
    }

    kemEncapsulate(publicKey: Uint8Array): KemEncapsulationResult {
        try {
            const { cipherText, sharedSecret } = ml_kem1024.encapsulate(publicKey);
            return { ciphertext: cipherText, sharedSecret };
        } catch (err) {
            throw new CryptoError(
                `KEM encapsulation failed: ${(err as Error).message}`,
                "INVALID_PUBLIC_KEY",
            );
        }
    }

    kemDecapsulate(privateKey: Uint8Array, ciphertext: Uint8Array): Uint8Array {
        try {
            return ml_kem1024.decapsulate(ciphertext, privateKey);
        } catch (err) {
            throw new CryptoError(
                `KEM decapsulation failed: ${(err as Error).message}`,
                "INVALID_PQ_CIPHERTEXT",
            );
        }
    }

    // ---- HKDF (RFC 5869, SHA-512) ------------------------------------------

    hkdfExtract(salt: Uint8Array, inputKeyMaterial: Uint8Array): Uint8Array {
        return hkdfExtractRaw(sha512, inputKeyMaterial, salt);
    }

    hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
        return hkdfExpandRaw(sha512, prk, info, length);
    }

    hmac(key: Uint8Array, data: Uint8Array): Uint8Array {
        return nobleHmac(sha512, key, data);
    }

    // ---- AEAD (XChaCha20-Poly1305) -----------------------------------------
    // The interface has no separate nonce parameter, so encrypt() generates a
    // fresh random 24-byte nonce per call and prepends it to the ciphertext;
    // decrypt() reads it back off the front. This keeps nonce management
    // entirely inside the primitive layer, where "never reuse a nonce" is
    // trivially satisfied by using CSPRNG output every call (XChaCha20's
    // extended 192-bit nonce makes random collision negligible).

    aeadEncrypt(key: Uint8Array, plaintext: Uint8Array, associatedData: Uint8Array): Uint8Array {
        const nonce = this.randomBytes(AEAD_NONCE_LENGTH);
        const cipher = xchacha20poly1305(key, nonce, associatedData);
        const sealed = cipher.encrypt(plaintext);
        const out = new Uint8Array(nonce.length + sealed.length);
        out.set(nonce, 0);
        out.set(sealed, nonce.length);
        return out;
    }

    aeadDecrypt(key: Uint8Array, ciphertext: Uint8Array, associatedData: Uint8Array): Uint8Array {
        if (ciphertext.length < AEAD_NONCE_LENGTH) {
            throw new CryptoError(
                "Ciphertext shorter than nonce length",
                "INVALID_CIPHERTEXT_FORMAT",
            );
        }
        const nonce = ciphertext.subarray(0, AEAD_NONCE_LENGTH);
        const sealed = ciphertext.subarray(AEAD_NONCE_LENGTH);
        const cipher = xchacha20poly1305(key, nonce, associatedData);
        try {
            return cipher.decrypt(sealed);
        } catch (err) {
            throw new CryptoError(
                `AEAD authentication failed: ${(err as Error).message}`,
                "AEAD_AUTHENTICATION_FAILED",
            );
        }
    }

    // ---- Randomness ---------------------------------------------------------

    randomBytes(length: number): Uint8Array {
        return nobleRandomBytes(length);
    }

    secureErase(buffer: Uint8Array): void {
        buffer.fill(0);
    }
}
