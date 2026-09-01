import type { OneTimePreKey } from "./types.js";

/**
 * Manages the one-time prekey pool's lifecycle:
 *
 *     AVAILABLE -> RESERVED -> CONSUMED
 *                      |
 *                      v
 *                  AVAILABLE   (release: rolled back, e.g. downstream AEAD
 *                               authentication failed and the key was never
 *                               actually used)
 *
 * Phase 3.2's core requirement: "A crash must never cause the same one-time
 * key to be handed to two sessions." `reserve` is the operation that makes
 * that guarantee — it must be atomic (check-state-and-transition as one
 * indivisible step), so that if two callers race to reserve the same id,
 * exactly one gets it back and the other gets `null`.
 *
 * `reserve` is deliberately separate from `consume`: Phase 5.3 requires that
 * Bob not permanently commit session state (which includes consuming the
 * OPK) until AFTER the initial message has been successfully authenticated.
 * The intended flow is: `reserve` before attempting decryption (so a
 * concurrent duplicate can't also grab the same key while this attempt is
 * in flight), then `consume` on success or `release` on failure.
 *
 * A persistent (Phase 13) implementation of this interface MUST implement
 * `reserve` as a single atomic transaction (e.g. a conditional
 * `UPDATE ... WHERE id = ? AND state = 'AVAILABLE'`, checking the affected
 * row count) — not a separate read-then-write, which would reintroduce the
 * exact race this interface exists to prevent.
 */
export interface PrekeyStore {
    /** Bulk-add newly generated one-time prekeys, all starting in AVAILABLE state. Throws on an id collision with an existing entry. */
    addOneTimePreKeys(keys: OneTimePreKey[]): void;

    /** Atomically AVAILABLE -> RESERVED. Returns a copy of the key, or null if the id doesn't exist or isn't currently AVAILABLE. */
    reserveOneTimePreKey(id: number): OneTimePreKey | null;

    /** RESERVED -> CONSUMED. Throws if the key isn't currently RESERVED. Implementations should destroy the stored private key material on consumption (Phase 18: delete once no longer needed). */
    consumeOneTimePreKey(id: number): void;

    /** RESERVED -> AVAILABLE (rollback path after a failed authentication attempt). Throws if the key isn't currently RESERVED. */
    releaseOneTimePreKey(id: number): void;

    /** Read-only lookup; does not affect state. Returns a copy, or undefined if the id doesn't exist. */
    getOneTimePreKey(id: number): OneTimePreKey | undefined;

    /** Count of keys currently in AVAILABLE state (useful for deciding when to top up the pool). */
    countAvailableOneTimePreKeys(): number;
}
