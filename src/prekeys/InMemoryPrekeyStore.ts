import type { PrekeyStore } from "./PrekeyStore.js";
import type { OneTimePreKey } from "./types.js";

function cloneOneTimePreKey(key: OneTimePreKey): OneTimePreKey {
    return {
        id: key.id,
        publicKey: key.publicKey.slice(),
        privateKey: key.privateKey.slice(),
        state: key.state,
        createdAt: key.createdAt,
    };
}

/**
 * In-memory PrekeyStore. Correct for Phase 3's atomicity requirement WITHIN
 * a single process: JavaScript's synchronous execution model means a
 * `Map` read-check-write inside one non-async function body cannot be
 * interleaved by another call — there's no `await` point for a concurrent
 * caller to run in between the check and the transition. That guarantee
 * disappears the moment this is backed by anything asynchronous (a real
 * database, IPC, etc.) — see the interface doc for what a persistent
 * implementation must do instead (Phase 13).
 *
 * This class holds private key material in memory only; per Phase 13,
 * whatever wraps this for persistence is responsible for encryption at
 * rest.
 */
export class InMemoryPrekeyStore implements PrekeyStore {
    private readonly keys = new Map<number, OneTimePreKey>();

    constructor(private readonly secureErase: (buffer: Uint8Array) => void) {}

    addOneTimePreKeys(newKeys: OneTimePreKey[]): void {
        for (const key of newKeys) {
            if (this.keys.has(key.id)) {
                throw new Error(`InMemoryPrekeyStore: one-time prekey id collision: ${key.id}`);
            }
        }
        for (const key of newKeys) {
            this.keys.set(key.id, cloneOneTimePreKey(key));
        }
    }

    reserveOneTimePreKey(id: number): OneTimePreKey | null {
        const existing = this.keys.get(id);
        if (!existing || existing.state !== "AVAILABLE") {
            return null;
        }
        existing.state = "RESERVED";
        return cloneOneTimePreKey(existing);
    }

    consumeOneTimePreKey(id: number): void {
        const existing = this.keys.get(id);
        if (!existing || existing.state !== "RESERVED") {
            throw new Error(
                `InMemoryPrekeyStore: cannot consume one-time prekey ${id}: not in RESERVED state`,
            );
        }
        existing.state = "CONSUMED";
        // Destroy the private key material now — it will never be needed
        // again (Invariant 5: a consumed one-time prekey cannot be reused;
        // Phase 18: delete keys once no longer needed).
        this.secureErase(existing.privateKey);
    }

    releaseOneTimePreKey(id: number): void {
        const existing = this.keys.get(id);
        if (!existing || existing.state !== "RESERVED") {
            throw new Error(
                `InMemoryPrekeyStore: cannot release one-time prekey ${id}: not in RESERVED state`,
            );
        }
        existing.state = "AVAILABLE";
    }

    getOneTimePreKey(id: number): OneTimePreKey | undefined {
        const existing = this.keys.get(id);
        return existing ? cloneOneTimePreKey(existing) : undefined;
    }

    countAvailableOneTimePreKeys(): number {
        let count = 0;
        for (const key of this.keys.values()) {
            if (key.state === "AVAILABLE") count++;
        }
        return count;
    }
}
