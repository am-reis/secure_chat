import type { MockWakuNetwork } from "./MockWakuNetwork.js";
import type { WakuTransport, WakuMessage, PublishOptions, RetrieveHistoryOptions } from "./WakuTransport.js";
import { ProtocolError } from "../errors.js";

/**
 * A WakuTransport backed by a shared MockWakuNetwork. Each simulated peer
 * (one per party in a test) gets its own instance, all pointed at the same
 * network so they can actually exchange messages subject to whatever fault
 * injection that network is configured with.
 */
export class MockWakuTransport implements WakuTransport {
    private connected = false;
    private readonly unsubscribes: Array<() => void> = [];

    constructor(
        private readonly peerId: string,
        private readonly network: MockWakuNetwork,
    ) {}

    async connect(): Promise<void> {
        this.connected = true;
    }

    async disconnect(): Promise<void> {
        this.connected = false;
    }

    async publish(contentTopic: string, payload: Uint8Array, options?: PublishOptions): Promise<void> {
        if (!this.connected) {
            throw new ProtocolError("Cannot publish while disconnected", "TRANSPORT_FAILURE");
        }
        this.network.publish(this.peerId, contentTopic, payload, options);
    }

    async subscribe(contentTopic: string, callback: (message: WakuMessage) => void): Promise<() => void> {
        // The wrapped callback checks connection state at delivery time
        // (not subscribe time): a peer that goes offline after subscribing
        // should simply miss live deliveries while offline, exactly like a
        // real disconnected node, without needing to re-subscribe on
        // reconnect. Reconnecting only restores live delivery; anything
        // missed while offline is recoverable solely via retrieveHistory
        // (Store), same as the real protocol.
        const wrapped = (message: WakuMessage) => {
            if (this.connected) callback(message);
        };
        const unsubscribe = this.network.subscribe(this.peerId, contentTopic, wrapped);
        this.unsubscribes.push(unsubscribe);
        return unsubscribe;
    }

    async retrieveHistory(contentTopic: string, options?: RetrieveHistoryOptions): Promise<WakuMessage[]> {
        // Store queries are treated as reachable regardless of live-relay
        // connection state, matching real Waku's Store protocol being
        // separate infrastructure from the Relay/Filter mesh (see
        // MockWakuNetwork's retrieveHistory doc).
        return this.network.retrieveHistory(contentTopic, options);
    }
}
