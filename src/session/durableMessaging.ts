import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import type { SessionManager } from "./SessionManager.js";
import type { SessionId, MessageEnvelopeData } from "./types.js";
import type { RawKeyValueStore, MasterKeyProvider } from "../persistence/types.js";
import { saveSession } from "../persistence/encryptedStorage.js";
import { saveOutboxEntry, loadOutboxEntry, clearOutboxEntry } from "../persistence/outbox.js";
import type { WakuTransport } from "../transport/WakuTransport.js";
import { sessionInitContentTopic, messageContentTopic } from "../transport/contentTopics.js";
import { encodeEnvelope, decodeEnvelope } from "../transport/protoEnvelopeCodec.js";
import { ProtocolError } from "../errors.js";

/**
 * The safe way to send a message when the session is persisted (Phase 30):
 * advance the ratchet, persist the ADVANCED state, persist the envelope
 * itself (outbox), THEN attempt transmission, and only clear the outbox
 * entry once that succeeds. See outbox.ts for why persisting session state
 * alone isn't sufficient. If this function itself is interrupted midway,
 * `resumePendingOutbox` on the next startup completes it correctly.
 */
export async function sendMessageDurably(
    manager: SessionManager,
    store: RawKeyValueStore,
    provider: CryptoProvider,
    masterKeyProvider: MasterKeyProvider,
    transport: WakuTransport,
    sessionId: SessionId,
    plaintext: Uint8Array,
): Promise<MessageEnvelopeData> {
    const envelope = manager.sendMessage(sessionId, plaintext);
    const session = manager.getSession(sessionId);
    if (!session) {
        // Should be unreachable — sendMessage above would already have
        // thrown UNKNOWN_SESSION — but never silently proceed on a
        // violated assumption.
        throw new ProtocolError("Session vanished immediately after sendMessage", "SESSION_STATE_CORRUPTED");
    }

    await saveSession(store, provider, masterKeyProvider, session);

    const encoded = encodeEnvelope(envelope);
    await saveOutboxEntry(store, sessionId, encoded);

    await transport.publish(messageContentTopic(envelope.protocolVersion), encoded);

    await clearOutboxEntry(store, sessionId);
    return envelope;
}

/**
 * Call this for a session immediately after restoring it from persistence
 * and before doing anything else with it. If a send was interrupted before
 * transmission was confirmed, this retransmits the EXACT saved envelope —
 * never re-derives a new one, which would silently skip that message
 * number and risk the message-key-reuse failure this module exists to
 * prevent. Returns true if something was retransmitted, false if there was
 * nothing pending (the common case).
 */
export async function resumePendingOutbox(
    store: RawKeyValueStore,
    transport: WakuTransport,
    sessionId: SessionId,
): Promise<boolean> {
    const pending = await loadOutboxEntry(store, sessionId);
    if (!pending) return false;

    const envelope = decodeEnvelope(pending);
    const topic =
        envelope.type === "SESSION_INIT"
            ? sessionInitContentTopic(envelope.protocolVersion)
            : messageContentTopic(envelope.protocolVersion);

    await transport.publish(topic, pending);
    await clearOutboxEntry(store, sessionId);
    return true;
}
