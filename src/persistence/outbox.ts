import type { RawKeyValueStore } from "./types.js";
import { bytesToHex } from "../encoding/canonical.js";

/**
 * Phase 30 finding: calling `SessionManager.sendMessage` again after a
 * crash-and-restart is NOT a safe way to retry a message whose
 * transmission was never confirmed. `ratchetEncrypt`'s chain-key
 * derivation (KDF_CK) is a pure, deterministic function of the current
 * chain key — if a crash happens after encrypting-and-transmitting but
 * before the advanced session state is persisted, reloading the stale
 * (pre-send) state and calling `sendMessage` again for a *different*
 * plaintext derives the exact same message key AND the same
 * (ratchetPublicKey, messageNumber) identity as the message that was
 * already sent. If the recipient already received the first one, the
 * second is permanently rejected — indistinguishable from a replay attack
 * at the protocol level, even though it's a legitimate different message.
 *
 * The fix is standard write-ahead logging, but persisting the *session
 * state* alone isn't sufficient — a crash could still happen after the state
 * advances but before the envelope is actually handed to the transport.
 * What must survive a crash is the exact envelope bytes, so a retry after
 * restart can retransmit the identical message rather than re-deriving a
 * new one. This module is that: a single-slot "last envelope not yet
 * confirmed sent" per session, keyed the same way session records are.
 *
 * Recommended safe send sequence (see README / durableSend.ts):
 *   1. sessionManager.sendMessage(...)          — advances in-memory state
 *   2. saveSession(...)                          — persist the ADVANCED state
 *   3. saveOutboxEntry(...)                      — persist the envelope itself
 *   4. transport.publish(...)                    — attempt transmission
 *   5. clearOutboxEntry(...)                     — only once transmission succeeded
 *
 * On restart, before doing anything else with a session: check for a
 * pending outbox entry and retransmit those exact bytes (then clear it) —
 * never call sendMessage again for "the same" content.
 */

const OUTBOX_KEY_PREFIX = "outbox:";

function outboxKey(sessionId: Uint8Array): string {
    return OUTBOX_KEY_PREFIX + bytesToHex(sessionId);
}

export async function saveOutboxEntry(
    store: RawKeyValueStore,
    sessionId: Uint8Array,
    envelopeBytes: Uint8Array,
): Promise<void> {
    await store.set(outboxKey(sessionId), envelopeBytes);
}

/** Returns undefined if there's nothing pending — the common case (no crash occurred, or it already resolved). */
export async function loadOutboxEntry(
    store: RawKeyValueStore,
    sessionId: Uint8Array,
): Promise<Uint8Array | undefined> {
    return store.get(outboxKey(sessionId));
}

export async function clearOutboxEntry(store: RawKeyValueStore, sessionId: Uint8Array): Promise<void> {
    await store.delete(outboxKey(sessionId));
}
