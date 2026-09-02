import type { MasterKeyProvider } from "./types.js";

/**
 * A MasterKeyProvider backed by a fixed, caller-supplied 32-byte key. This
 * is NOT how a real deployment should source its master key — see the note
 * on MasterKeyProvider in types.ts — but it's what tests and the first
 * milestone need: something that satisfies the interface without requiring
 * an OS keychain to be present in the test environment.
 */
export class StaticMasterKeyProvider implements MasterKeyProvider {
    constructor(private readonly key: Uint8Array) {
        if (key.length !== 32) {
            throw new RangeError(`StaticMasterKeyProvider: key must be 32 bytes, got ${key.length}`);
        }
    }

    async getMasterKey(): Promise<Uint8Array> {
        return this.key;
    }
}
