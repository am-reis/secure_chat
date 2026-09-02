import type { RawKeyValueStore } from "./types.js";

/**
 * In-memory RawKeyValueStore. Correct for the first milestone (Phase 33) and
 * for tests, but data does NOT survive a real process restart — that's the
 * whole point of a future real backend (SQLite, IndexedDB, etc.)
 * implementing this same interface. Storing a plain Map here rather than
 * simulating a "restart" is deliberate: persistence tests should construct
 * a SECOND store instance backed by the same underlying data to prove a
 * round trip through encryption, not rely on this store's own object
 * identity surviving.
 */
export class InMemoryKeyValueStore implements RawKeyValueStore {
    constructor(private readonly data = new Map<string, Uint8Array>()) {}

    async get(key: string): Promise<Uint8Array | undefined> {
        const value = this.data.get(key);
        return value ? value.slice() : undefined;
    }

    async set(key: string, value: Uint8Array): Promise<void> {
        this.data.set(key, value.slice());
    }

    async delete(key: string): Promise<void> {
        this.data.delete(key);
    }

    async list(prefix = ""): Promise<string[]> {
        return [...this.data.keys()].filter((k) => k.startsWith(prefix));
    }

    /** Simulate a process restart: a new store instance backed by the SAME underlying map, as if reopened from disk. */
    reopen(): InMemoryKeyValueStore {
        return new InMemoryKeyValueStore(this.data);
    }
}
