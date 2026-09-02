import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import type { KeyPair } from "../crypto/types.js";
import { constantTimeEqual } from "../encoding/canonical.js";
import { ProtocolError } from "../errors.js";
import { kdfRootKey, kdfChainKey } from "./kdf.js";
import { buildMessageAssociatedData } from "./header.js";
import {
    type DoubleRatchetState,
    type RatchetHeader,
    type RatchetEncryptResult,
    MAX_SKIP,
    MAX_STORED_SKIPPED_KEYS,
    skippedKeyIndex,
} from "./types.js";

// ---- Initialization (real spec §3.3) ---------------------------------------

/**
 * RatchetInitAlice. Alice has PQXDH's SK and Bob's initial ratchet public
 * key (per real spec §7.1: this is Bob's SPK from the PQXDH bundle).
 */
export function ratchetInitAlice(
    provider: CryptoProvider,
    sk: Uint8Array,
    bobRatchetPublicKey: Uint8Array,
): DoubleRatchetState {
    const DHs = provider.generateX25519KeyPair();
    const DHr = bobRatchetPublicKey;
    const dhOut = provider.x25519(DHs.privateKey, DHr);
    const { rootKey, chainKey } = kdfRootKey(provider, sk, dhOut);
    provider.secureErase(dhOut);

    return {
        DHs,
        DHr,
        rootKey,
        sendingChainKey: chainKey,
        receivingChainKey: null,
        sendingMessageNumber: 0,
        receivingMessageNumber: 0,
        previousSendingChainLength: 0,
        skippedMessageKeys: new Map(),
    };
}

/**
 * RatchetInitBob. `bobRatchetKeyPair` must be Bob's SPK keypair from the
 * PQXDH exchange (real spec §7.1: "Bob's signed prekey from PQXDH (SPKB)
 * becomes Bob's initial ratchet public key... for Double Ratchet
 * initialization") — NOT a freshly generated pair. Bob cannot send until he
 * receives Alice's first message and performs his first DH ratchet step
 * (sendingChainKey starts null; ratchetEncrypt will throw if called before
 * that happens).
 */
export function ratchetInitBob(
    provider: CryptoProvider,
    sk: Uint8Array,
    bobRatchetKeyPair: KeyPair,
): DoubleRatchetState {
    return {
        DHs: bobRatchetKeyPair,
        DHr: null,
        rootKey: sk,
        sendingChainKey: null,
        receivingChainKey: null,
        sendingMessageNumber: 0,
        receivingMessageNumber: 0,
        previousSendingChainLength: 0,
        skippedMessageKeys: new Map(),
    };
}

// ---- Encryption (real spec §3.4) -------------------------------------------

/**
 * RatchetEncrypt. Mutates `state` in place — encryption on your own state
 * has no authentication step that can fail, so there's no rollback concern
 * here the way there is for decrypt.
 */
export function ratchetEncrypt(
    provider: CryptoProvider,
    state: DoubleRatchetState,
    plaintext: Uint8Array,
    ad: Uint8Array,
): RatchetEncryptResult {
    if (state.sendingChainKey === null) {
        throw new ProtocolError(
            "Cannot encrypt: no sending chain established (Bob must receive Alice's first message before sending)",
            "SESSION_STATE_CORRUPTED",
        );
    }

    const oldChainKey = state.sendingChainKey;
    const { nextChainKey, messageKey } = kdfChainKey(provider, oldChainKey);
    state.sendingChainKey = nextChainKey;
    provider.secureErase(oldChainKey); // Phase 18: delete old chain key once superseded

    const messageNumber = state.sendingMessageNumber;
    state.sendingMessageNumber += 1;

    const header: RatchetHeader = {
        ratchetPublicKey: state.DHs.publicKey,
        previousChainLength: state.previousSendingChainLength,
        messageNumber,
    };
    const messageAD = buildMessageAssociatedData(ad, header);
    const ciphertext = provider.aeadEncrypt(messageKey, plaintext, messageAD);
    provider.secureErase(messageKey); // Phase 6.2: delete message key after use

    return { header, ciphertext };
}

// ---- Decryption (real spec §3.5) -------------------------------------------

function dhKeysEqual(a: Uint8Array, b: Uint8Array | null): boolean {
    return b !== null && constantTimeEqual(a, b);
}

function cloneState(state: DoubleRatchetState): DoubleRatchetState {
    return {
        DHs: state.DHs,
        DHr: state.DHr,
        rootKey: state.rootKey,
        sendingChainKey: state.sendingChainKey,
        receivingChainKey: state.receivingChainKey,
        sendingMessageNumber: state.sendingMessageNumber,
        receivingMessageNumber: state.receivingMessageNumber,
        previousSendingChainLength: state.previousSendingChainLength,
        skippedMessageKeys: new Map(state.skippedMessageKeys),
    };
}

/** Commit a successfully-derived working state back onto the real state, then erase everything superseded (Phase 18) — only ever called after a successful decrypt. */
function commitState(
    provider: CryptoProvider,
    target: DoubleRatchetState,
    working: DoubleRatchetState,
    obsolete: Uint8Array[],
): void {
    target.DHs = working.DHs;
    target.DHr = working.DHr;
    target.rootKey = working.rootKey;
    target.sendingChainKey = working.sendingChainKey;
    target.receivingChainKey = working.receivingChainKey;
    target.sendingMessageNumber = working.sendingMessageNumber;
    target.receivingMessageNumber = working.receivingMessageNumber;
    target.previousSendingChainLength = working.previousSendingChainLength;
    target.skippedMessageKeys = working.skippedMessageKeys;
    for (const buf of obsolete) provider.secureErase(buf);
}

/**
 * SkipMessageKeys, operating on a working clone. Derives and stores message
 * keys for the receiving chain up to (not including) `until`, bounded by
 * MAX_SKIP (Phase 8.1) and the global MAX_STORED_SKIPPED_KEYS cap. Appends
 * every superseded chain key to `obsolete` for erasure on commit — never
 * erases anything directly, since this may still be rolled back.
 */
function skipMessageKeys(
    provider: CryptoProvider,
    working: DoubleRatchetState,
    until: number,
    obsolete: Uint8Array[],
): void {
    if (working.receivingMessageNumber + MAX_SKIP < until) {
        throw new ProtocolError(
            `Refusing to skip ${until - working.receivingMessageNumber} messages (MAX_SKIP=${MAX_SKIP})`,
            "MESSAGE_TOO_FAR_AHEAD",
        );
    }
    if (working.receivingChainKey !== null && working.DHr !== null) {
        while (working.receivingMessageNumber < until) {
            if (working.skippedMessageKeys.size >= MAX_STORED_SKIPPED_KEYS) {
                throw new ProtocolError(
                    `Refusing to store more than ${MAX_STORED_SKIPPED_KEYS} skipped message keys`,
                    "MESSAGE_TOO_FAR_AHEAD",
                );
            }
            const oldChainKey = working.receivingChainKey;
            const { nextChainKey, messageKey } = kdfChainKey(provider, oldChainKey);
            obsolete.push(oldChainKey);
            working.receivingChainKey = nextChainKey;
            working.skippedMessageKeys.set(
                skippedKeyIndex(working.DHr, working.receivingMessageNumber),
                messageKey,
            );
            working.receivingMessageNumber += 1;
        }
    }
}

/** DHRatchet, operating on a working clone. Two root-KDF steps: one to derive the new receiving chain (matching what the sender just advertised), one to derive a fresh sending chain from a newly generated local ratchet keypair. */
function dhRatchetStep(
    provider: CryptoProvider,
    working: DoubleRatchetState,
    header: RatchetHeader,
    obsolete: Uint8Array[],
): void {
    working.previousSendingChainLength = working.sendingMessageNumber;
    working.sendingMessageNumber = 0;
    working.receivingMessageNumber = 0;
    working.DHr = header.ratchetPublicKey;

    const dhOut1 = provider.x25519(working.DHs.privateKey, working.DHr);
    const receiveStep = kdfRootKey(provider, working.rootKey, dhOut1);
    obsolete.push(working.rootKey, dhOut1);
    if (working.receivingChainKey) obsolete.push(working.receivingChainKey);
    working.rootKey = receiveStep.rootKey;
    working.receivingChainKey = receiveStep.chainKey;

    const oldDHsPrivateKey = working.DHs.privateKey;
    working.DHs = provider.generateX25519KeyPair();
    obsolete.push(oldDHsPrivateKey);

    const dhOut2 = provider.x25519(working.DHs.privateKey, working.DHr);
    const sendStep = kdfRootKey(provider, working.rootKey, dhOut2);
    obsolete.push(working.rootKey, dhOut2);
    if (working.sendingChainKey) obsolete.push(working.sendingChainKey);
    working.rootKey = sendStep.rootKey;
    working.sendingChainKey = sendStep.chainKey;
}

/**
 * RatchetDecrypt. Per the real spec: "If an exception is raised... the
 * message is discarded and changes to the state object are discarded.
 * Otherwise, the decrypted plaintext is accepted and changes to the state
 * object are stored." All derivation happens on a clone (`working`); `state`
 * is only ever touched by the single `commitState` call after a successful
 * AEAD decrypt. On any thrown error, `state` is guaranteed untouched.
 */
export function ratchetDecrypt(
    provider: CryptoProvider,
    state: DoubleRatchetState,
    header: RatchetHeader,
    ciphertext: Uint8Array,
    ad: Uint8Array,
): Uint8Array {
    const messageAD = buildMessageAssociatedData(ad, header);

    // Fast path: a previously-skipped message key for this exact (dh, n).
    const skippedIdx = skippedKeyIndex(header.ratchetPublicKey, header.messageNumber);
    const skippedKey = state.skippedMessageKeys.get(skippedIdx);
    if (skippedKey !== undefined) {
        let plaintext: Uint8Array;
        try {
            plaintext = provider.aeadDecrypt(skippedKey, ciphertext, messageAD);
        } catch {
            throw new ProtocolError(
                "Message authentication failed (skipped-key path)",
                "AEAD_AUTHENTICATION_FAILED",
            );
        } finally {
            provider.secureErase(skippedKey);
        }
        // Only reached on success — commit the one change (delete the consumed entry).
        state.skippedMessageKeys.delete(skippedIdx);
        return plaintext;
    }

    // Full path: work entirely on a clone until decryption is proven successful.
    const working = cloneState(state);
    const obsolete: Uint8Array[] = [];

    if (!dhKeysEqual(header.ratchetPublicKey, working.DHr)) {
        skipMessageKeys(provider, working, header.previousChainLength, obsolete);
        dhRatchetStep(provider, working, header, obsolete);
    }
    skipMessageKeys(provider, working, header.messageNumber, obsolete);

    if (working.receivingChainKey === null) {
        throw new ProtocolError(
            "No receiving chain established (message references an unknown ratchet state)",
            "SESSION_STATE_CORRUPTED",
        );
    }

    const oldReceivingChainKey = working.receivingChainKey;
    const { nextChainKey, messageKey } = kdfChainKey(provider, oldReceivingChainKey);
    obsolete.push(oldReceivingChainKey);
    working.receivingChainKey = nextChainKey;
    working.receivingMessageNumber += 1;

    let plaintext: Uint8Array;
    try {
        plaintext = provider.aeadDecrypt(messageKey, ciphertext, messageAD);
    } catch {
        // `working` and `obsolete` are simply discarded here — `state` was
        // never touched, so this is a correct, complete rollback.
        throw new ProtocolError("Message authentication failed", "AEAD_AUTHENTICATION_FAILED");
    } finally {
        provider.secureErase(messageKey);
    }

    commitState(provider, state, working, obsolete);
    return plaintext;
}
