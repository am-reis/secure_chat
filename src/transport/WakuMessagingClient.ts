import type { SessionManager } from "../session/SessionManager.js";
import type { PreKeyBundle } from "../prekeys/PreKeyBundle.js";
import type { Session, SessionId } from "../session/types.js";
import type { WakuTransport, WakuMessage } from "./WakuTransport.js";
import { sessionInitContentTopic, messageContentTopic, sessionResetContentTopic } from "./contentTopics.js";
import { encodeEnvelope, decodeEnvelope } from "./protoEnvelopeCodec.js";
import { CURRENT_PROTOCOL_VERSION } from "../prekeys/PreKeyBundle.js";

export interface WakuMessagingClientOptions {
    protocolVersion?: number;
    onMessage?: (sessionId: SessionId, plaintext: Uint8Array) => void;
    /**
     * Called when a peer-initiated SESSION_RESET (Phase 19) is verified and
     * applied — i.e. the local session with this id has just been
     * destroyed because the peer signaled theirs is gone.
     */
    onSessionReset?: (sessionId: SessionId) => void;
    /**
     * Called for any envelope that fails to decode or fails
     * SessionManager processing (malformed, replayed, tampered, unknown
     * session, etc.) — for observability only. The client always keeps
     * running after a rejected message; per Phase 0.1's untrusted-transport
     * threat model, a single bad message must never take down message
     * processing for everything else.
     */
    onError?: (err: unknown, contentTopic: string) => void;
}

/**
 * Binds a SessionManager to a WakuTransport: incoming envelopes are
 * decoded and fed to `receiveMessage`; outgoing session/message creation is
 * encoded and published on the appropriate content topic (Phase 21).
 * Swapping MockWakuTransport for a real js-waku-backed WakuTransport later
 * requires no changes here or above this layer.
 */
export class WakuMessagingClient {
    private readonly protocolVersion: number;
    private readonly onMessage: WakuMessagingClientOptions["onMessage"];
    private readonly onSessionReset: WakuMessagingClientOptions["onSessionReset"];
    private readonly onError: WakuMessagingClientOptions["onError"];
    private readonly unsubscribes: Array<() => void> = [];

    constructor(
        private readonly sessionManager: SessionManager,
        private readonly transport: WakuTransport,
        options: WakuMessagingClientOptions = {},
    ) {
        this.protocolVersion = options.protocolVersion ?? CURRENT_PROTOCOL_VERSION;
        this.onMessage = options.onMessage;
        this.onSessionReset = options.onSessionReset;
        this.onError = options.onError;
    }

    async start(): Promise<void> {
        await this.transport.connect();
        const initTopic = sessionInitContentTopic(this.protocolVersion);
        const msgTopic = messageContentTopic(this.protocolVersion);
        const resetTopic = sessionResetContentTopic(this.protocolVersion);
        this.unsubscribes.push(
            await this.transport.subscribe(initTopic, (m) => this.handleIncoming(m)),
            await this.transport.subscribe(msgTopic, (m) => this.handleIncoming(m)),
            await this.transport.subscribe(resetTopic, (m) => this.handleIncoming(m)),
        );
    }

    async stop(): Promise<void> {
        for (const unsub of this.unsubscribes) unsub();
        this.unsubscribes.length = 0;
        await this.transport.disconnect();
    }

    private handleIncoming(message: WakuMessage): void {
        try {
            const envelope = decodeEnvelope(message.payload);
            if (envelope.type === "SESSION_RESET") {
                this.sessionManager.receiveSessionReset(envelope);
                this.onSessionReset?.(envelope.sessionId);
                return;
            }
            const { session, plaintext } = this.sessionManager.receiveMessage(envelope);
            this.onMessage?.(session.sessionId, plaintext);
        } catch (err) {
            // Malformed, replayed, tampered, or unknown-session — never let
            // one bad message stop processing subsequent ones.
            this.onError?.(err, message.contentTopic);
        }
    }

    async createSession(remoteBundle: PreKeyBundle, initialPlaintext: Uint8Array): Promise<Session> {
        const { session, envelope } = this.sessionManager.createSession(remoteBundle, initialPlaintext);
        await this.transport.publish(sessionInitContentTopic(envelope.protocolVersion), encodeEnvelope(envelope));
        return session;
    }

    async sendMessage(sessionId: SessionId, plaintext: Uint8Array): Promise<void> {
        const envelope = this.sessionManager.sendMessage(sessionId, plaintext);
        await this.transport.publish(messageContentTopic(envelope.protocolVersion), encodeEnvelope(envelope));
    }

    /**
     * Phase 19: destroy local session state and notify the peer. Local
     * destruction happens (via `sessionManager.resetSession`) regardless of
     * whether the publish below actually reaches the peer — the state was
     * already deemed uncertain, so keeping it around locally doesn't help
     * either way; the notification is a courtesy so the peer stops sending
     * into a session that's already gone on this end.
     */
    async resetSession(sessionId: SessionId): Promise<void> {
        const envelope = this.sessionManager.resetSession(sessionId);
        await this.transport.publish(sessionResetContentTopic(envelope.protocolVersion), encodeEnvelope(envelope));
    }

    /**
     * Phase 16 / real Store-recommended usage pattern: on reconnect, pull
     * history for both content topics and feed each through the same
     * decode-and-process path as a live message. Store's own incompleteness
     * (see MockWakuNetwork/WakuTransport docs) means this is "best effort
     * catch-up," not a completeness guarantee — a message truly lost by
     * both live relay and Store is unrecoverable at this layer, same as
     * real Waku.
     */
    async syncMissedMessages(sinceMs?: number): Promise<void> {
        const topics = [
            sessionInitContentTopic(this.protocolVersion),
            messageContentTopic(this.protocolVersion),
            sessionResetContentTopic(this.protocolVersion),
        ];
        for (const topic of topics) {
            const history = await this.transport.retrieveHistory(topic, sinceMs !== undefined ? { since: sinceMs } : undefined);
            for (const message of history) this.handleIncoming(message);
        }
    }
}
