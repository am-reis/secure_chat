import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import { constantTimeEqual } from "../encoding/canonical.js";
import { ProtocolError } from "../errors.js";
import type { AttachmentDescriptor } from "./types.js";

/**
 * No associated data on the attachment's own AEAD seal (unlike every other
 * AEAD use in this protocol, which binds session/message context into the
 * AD). That binding isn't needed here: the descriptor carrying
 * `encryptionKey`/`hash`/`size`/`mimeType` travels as plaintext *inside* an
 * already-AEAD-authenticated Double Ratchet message (Phase 24: "the entire
 * descriptor must be encrypted inside the Double Ratchet message"), so
 * tampering with any of those fields is already caught one layer up, before
 * this module is ever invoked with attacker-controlled metadata.
 */
const NO_ASSOCIATED_DATA = new Uint8Array(0);

export interface EncryptedAttachment {
    ciphertext: Uint8Array;
    encryptionKey: Uint8Array;
    hash: Uint8Array;
    size: number;
    mimeType: string;
}

/**
 * Encrypts `plaintext` under a freshly generated random key. `hash` is the
 * digest of the *encrypted* blob (what actually gets uploaded to object
 * storage), not the plaintext — it lets `decryptAttachment` cheaply reject
 * a corrupted or substituted download before spending an AEAD decrypt (and
 * before trusting the object storage response) on attacker-controlled
 * bytes, the same fail-fast-on-cheap-checks-first principle Phase 22 uses
 * for envelope routing.
 */
export function encryptAttachment(provider: CryptoProvider, plaintext: Uint8Array, mimeType: string): EncryptedAttachment {
    const encryptionKey = provider.randomBytes(32); // XChaCha20-Poly1305 key length
    const ciphertext = provider.aeadEncrypt(encryptionKey, plaintext, NO_ASSOCIATED_DATA);
    const hash = provider.hash(ciphertext);
    return { ciphertext, encryptionKey, hash, size: plaintext.length, mimeType };
}

/**
 * Verifies `downloadedCiphertext` against `descriptor.hash` before
 * decrypting. Because the object storage system sees only encrypted bytes
 * (Phase 24's stated goal), this check is the recipient's only defense
 * against a storage backend (malicious, compromised, or merely buggy)
 * serving back something other than what was uploaded — without it, a
 * substituted blob would be indistinguishable from a legitimate one until
 * AEAD decryption failed downstream, if it failed at all (a substituted
 * blob under a different key entirely, e.g. from an unrelated attachment,
 * could plausibly decrypt to garbage without necessarily raising an AEAD
 * error the caller expects to mean "tampered").
 */
export function decryptAttachment(
    provider: CryptoProvider,
    descriptor: AttachmentDescriptor,
    downloadedCiphertext: Uint8Array,
): Uint8Array {
    const actualHash = provider.hash(downloadedCiphertext);
    if (!constantTimeEqual(actualHash, descriptor.hash)) {
        throw new ProtocolError(
            "Downloaded attachment ciphertext does not match the descriptor's hash (corrupted or substituted)",
            "AEAD_AUTHENTICATION_FAILED",
        );
    }
    return provider.aeadDecrypt(descriptor.encryptionKey, downloadedCiphertext, NO_ASSOCIATED_DATA);
}
