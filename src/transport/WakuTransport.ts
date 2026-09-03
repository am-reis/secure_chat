/**
 * WakuTransport (Phase 20). Richer than the spec's own placeholder sketch
 * (`publish(envelope): Promise<void>`, `subscribe(callback)`,
 * `retrieveHistory(...)`) — filled in against real Waku semantics, verified
 * against current Waku documentation rather than assumed:
 *
 *   - Messages are addressed by content topic (Phase 21), not by recipient
 *     identity — a Waku node relays everything on a topic to everyone
 *     subscribed to it; recipient-specific filtering happens above this
 *     layer (inside the encrypted envelope), never in the topic string.
 *   - publish() is fire-and-forget: nothing in the base Relay/Light Push
 *     protocols guarantees the message reached anyone. A "message
 *     reliability" layer built on top of Store queries is an explicit,
 *     separate ongoing effort in the Waku project, not a base guarantee —
 *     see https://blog.waku.org/2024-06-20-message-reliability/. This
 *     interface reflects that: publish() resolving only means "handed to
 *     the local node," never "delivered."
 *   - Store does not guarantee availability either — "Waku's Store
 *     protocol is designed to temporarily store messages within the
 *     network. However, Waku does not guarantee the message's
 *     availability" (https://docs.waku.org/learn/faq/). retrieveHistory
 *     can legitimately return fewer messages than were actually published.
 *   - Messages carry a maximum size of 150 KiB (RFC 64 / nwaku spec:
 *     https://github.com/waku-org/nwaku/commit/ed09074c). Anything larger
 *     must be rejected before publishing, not silently truncated or split.
 *   - Messages can be marked ephemeral, meaning Store nodes should not
 *     persist them at all (useful for e.g. typing indicators — not used by
 *     this protocol's own SESSION_INIT/MESSAGE envelopes, which need to
 *     survive in Store for offline recipients, but exposed here since it's
 *     part of the real protocol's message model).
 */

/** RFC 64 / nwaku spec: https://rfc.vac.dev/spec/64/#message-size */
export const MAX_WAKU_MESSAGE_SIZE = 150 * 1024;

export interface WakuMessage {
    contentTopic: string;
    payload: Uint8Array;
    /** Milliseconds since epoch. Real Waku messages carry this as part of the message itself, not just transport metadata. */
    timestamp: number;
    ephemeral?: boolean;
}

export interface PublishOptions {
    ephemeral?: boolean;
}

export interface RetrieveHistoryOptions {
    /** Only return messages published at or after this timestamp (ms since epoch). */
    since?: number;
    limit?: number;
}

export interface WakuTransport {
    connect(): Promise<void>;
    disconnect(): Promise<void>;

    /**
     * Fire-and-forget. Resolving does NOT mean the message was delivered to
     * anyone, only that it was handed off. Throws if the payload exceeds
     * MAX_WAKU_MESSAGE_SIZE — that's a caller-side programming error to
     * catch before attempting to publish, not a network condition.
     */
    publish(contentTopic: string, payload: Uint8Array, options?: PublishOptions): Promise<void>;

    /** Returns an unsubscribe function. The callback may be invoked zero, one, or (per real Waku's known duplicate-delivery behavior) more than once for the same logical message. */
    subscribe(contentTopic: string, callback: (message: WakuMessage) => void): Promise<() => void>;

    /** Store protocol query. May legitimately be incomplete — see the module doc above. */
    retrieveHistory(contentTopic: string, options?: RetrieveHistoryOptions): Promise<WakuMessage[]>;
}
