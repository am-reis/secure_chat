import type { CryptoProvider } from "../crypto/CryptoProvider.js";

/**
 * KDF_RK(rk, dh_out) — real spec §7.2 recommendation:
 *   HKDF salt = rk (the CURRENT root key — the running secret)
 *   HKDF input key material = dh_out (the fresh DH output)
 *   HKDF info = app-specific, distinct from other HKDF uses
 *   output = 64 bytes, split into (new root key, new chain key), 32 bytes each
 *
 * NOTE the direction: rk is the SALT here, dh_out is the IKM — the reverse
 * of PQXDH's own KDF convention (where the secret material was the IKM
 * against a fixed salt). Easy to get backwards; this is the spec's literal
 * convention for KDF_RK specifically.
 */
const ROOT_KDF_INFO = new TextEncoder().encode("SecureMessagingProtocol_DR_KDF_RK_v1");

export interface RootKdfResult {
    rootKey: Uint8Array;
    chainKey: Uint8Array;
}

export function kdfRootKey(provider: CryptoProvider, rk: Uint8Array, dhOut: Uint8Array): RootKdfResult {
    const prk = provider.hkdfExtract(rk, dhOut);
    const output = provider.hkdfExpand(prk, ROOT_KDF_INFO, 64);
    return {
        rootKey: output.subarray(0, 32),
        chainKey: output.subarray(32, 64),
    };
}

/**
 * KDF_CK(ck) — real spec §7.2 recommendation: literal HMAC keyed by the
 * chain key, with distinct single-byte constants as input:
 *   message key      = HMAC(ck, 0x01)
 *   next chain key   = HMAC(ck, 0x02)
 *
 * Not HKDF — the spec is explicit this should be raw HMAC. Output is
 * 64 bytes (SHA-512); only the first 32 are used as the chain key/message
 * key values elsewhere (matching the spec's "32-byte chain key, 32-byte
 * message key" state variable sizes) — see chainKdfOutputToKeySize below.
 */
const CHAIN_KDF_MESSAGE_KEY_CONSTANT = new Uint8Array([0x01]);
const CHAIN_KDF_NEXT_CHAIN_KEY_CONSTANT = new Uint8Array([0x02]);

export interface ChainKdfResult {
    nextChainKey: Uint8Array;
    messageKey: Uint8Array;
}

export function kdfChainKey(provider: CryptoProvider, ck: Uint8Array): ChainKdfResult {
    const messageKeyFull = provider.hmac(ck, CHAIN_KDF_MESSAGE_KEY_CONSTANT);
    const nextChainKeyFull = provider.hmac(ck, CHAIN_KDF_NEXT_CHAIN_KEY_CONSTANT);
    return {
        messageKey: messageKeyFull.subarray(0, 32),
        nextChainKey: nextChainKeyFull.subarray(0, 32),
    };
}
