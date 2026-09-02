import type { KeyPair } from "../crypto/types.js";
import { bytesToHex } from "../encoding/canonical.js";

/**
 * Double Ratchet state (Phase 6 / real spec §3.2). Field names map directly
 * onto the spec's own variable names so the two are easy to cross-reference:
 *   DHs -> DHs, DHr -> DHr, RK -> rootKey, CKs -> sendingChainKey,
 *   CKr -> receivingChainKey, Ns -> sendingMessageNumber,
 *   Nr -> receivingMessageNumber, PN -> previousSendingChainLength,
 *   MKSKIPPED -> skippedMessageKeys
 *
 * skippedMessageKeys is indexed by `${hex(ratchetPublicKey)}:${messageNumber}`
 * (Phase 8: "indexed by ratchet public key and message number").
 */
export interface DoubleRatchetState {
    DHs: KeyPair;
    DHr: Uint8Array | null;

    rootKey: Uint8Array;

    sendingChainKey: Uint8Array | null;
    receivingChainKey: Uint8Array | null;

    sendingMessageNumber: number;
    receivingMessageNumber: number;

    previousSendingChainLength: number;

    skippedMessageKeys: Map<string, Uint8Array>;
}

/**
 * Message header (Phase 6.4). Corresponds to (dh, pn, n) in the real spec.
 */
export interface RatchetHeader {
    ratchetPublicKey: Uint8Array;
    previousChainLength: number;
    messageNumber: number;
}

export interface RatchetEncryptResult {
    header: RatchetHeader;
    ciphertext: Uint8Array;
}

/** MAX_SKIP (real spec §3.1 / Phase 8.1): bounds how many message keys a single SkipMessageKeys call will derive. */
export const MAX_SKIP = 1000;

/** Global cap on total stored skipped keys across the session (Phase 8.1: "enforce a global maximum number of stored skipped keys"), independent of any single SkipMessageKeys call's MAX_SKIP bound. */
export const MAX_STORED_SKIPPED_KEYS = 2000;

export function skippedKeyIndex(ratchetPublicKey: Uint8Array, messageNumber: number): string {
    return `${bytesToHex(ratchetPublicKey)}:${messageNumber}`;
}
