import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import type { OneTimePreKey } from "./types.js";

/**
 * Generate a pool of one-time prekeys with sequential ids starting at
 * `startId`. Each is a freshly, independently generated X25519 key pair —
 * per Phase 3.2: unique, randomly generated, used at most once.
 */
export function generateOneTimePreKeys(
    provider: CryptoProvider,
    count: number,
    startId: number,
): OneTimePreKey[] {
    if (count < 0 || !Number.isInteger(count)) {
        throw new RangeError(`generateOneTimePreKeys: invalid count: ${count}`);
    }
    const createdAt = Date.now();
    const keys: OneTimePreKey[] = [];
    for (let i = 0; i < count; i++) {
        const { publicKey, privateKey } = provider.generateX25519KeyPair();
        keys.push({
            id: startId + i,
            publicKey,
            privateKey,
            state: "AVAILABLE",
            createdAt,
        });
    }
    return keys;
}
