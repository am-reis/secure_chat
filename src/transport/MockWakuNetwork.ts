import { ProtocolError } from "../errors.js";
import { createSeededRng } from "./rng.js";
import { MAX_WAKU_MESSAGE_SIZE, type WakuMessage, type PublishOptions, type RetrieveHistoryOptions } from "./WakuTransport.js";

/**
 * Fault-injection knobs, each grounded in a real, documented Waku
 * characteristic (see WakuTransport.ts's module doc for sources) rather
 * than generic "P2P is unreliable" assumptions:
 *
 *   - dropRate / delay / reordering: gossipsub relay has no delivery
 *     guarantee and measurable, size-dependent propagation delay.
 *   - duplicateRate: gossipsub mesh flooding routinely delivers the same
 *     message via multiple paths; applications are expected to dedupe.
 *   - corruptRate: the untrusted-transport threat model (spec Phase 0.1)
 *     — any relay could be malicious or simply buggy.
 *   - storeCompletenessRate / storeRetentionMs: Store "does not guarantee
 *     the message's availability" and has a retention window, not
 *     unlimited history.
 *   - rateLimitPerPeer: RLN rejects publishers who exceed their allotted
 *     rate, independent of any other network condition.
 */
export interface FaultInjectionConfig {
    dropRate?: number;
    duplicateRate?: number;
    corruptRate?: number;
    minDelayMs?: number;
    maxDelayMs?: number;
    storeRetentionMs?: number;
    storeCompletenessRate?: number;
    rateLimitPerPeer?: { maxMessages: number; windowMs: number };
    seed?: number;
}

interface QueuedMessage {
    id: number;
    fromPeerId: string;
    contentTopic: string;
    message: WakuMessage;
}

type Subscriber = { peerId: string; callback: (message: WakuMessage) => void };

let nextMessageId = 1;

export class MockWakuNetwork {
    private readonly rng: () => number;
    private readonly subscribers = new Map<string, Subscriber[]>(); // contentTopic -> subscribers
    private readonly queue: QueuedMessage[] = [];
    private readonly store = new Map<string, WakuMessage[]>(); // contentTopic -> messages
    private readonly rateLimitLog = new Map<string, number[]>(); // peerId -> recent publish timestamps
    private partitionGroups: Map<string, string> | null = null;
    private clock = Date.now();

    constructor(private config: FaultInjectionConfig = {}) {
        this.rng = createSeededRng(config.seed ?? 1);
    }

    /** Adjust fault-injection parameters mid-scenario — real network conditions fluctuate; tests shouldn't need a fresh network instance to simulate that. */
    setConfig(partial: Partial<FaultInjectionConfig>): void {
        this.config = { ...this.config, ...partial };
    }

    /** Deterministic virtual clock, independent of wall-clock time, so retention/rate-limit windows are exactly reproducible in tests. */
    now(): number {
        return this.clock;
    }

    advanceTime(ms: number): void {
        this.clock += ms;
    }

    private checkRateLimit(peerId: string): void {
        const limit = this.config.rateLimitPerPeer;
        if (!limit) return;
        const log = this.rateLimitLog.get(peerId) ?? [];
        const cutoff = this.now() - limit.windowMs;
        const recent = log.filter((t) => t > cutoff);
        if (recent.length >= limit.maxMessages) {
            this.rateLimitLog.set(peerId, recent);
            throw new ProtocolError(
                `Rate limit exceeded for peer ${peerId} (RLN-style rejection)`,
                "TRANSPORT_FAILURE",
            );
        }
        recent.push(this.now());
        this.rateLimitLog.set(peerId, recent);
    }

    private canReach(fromPeerId: string, toPeerId: string): boolean {
        if (!this.partitionGroups) return true;
        const g1 = this.partitionGroups.get(fromPeerId);
        const g2 = this.partitionGroups.get(toPeerId);
        if (g1 === undefined || g2 === undefined) return true; // peers not named in the partition are unaffected
        return g1 === g2;
    }

    /**
     * Publish. Throws synchronously for conditions the real local node
     * would know about immediately (oversized payload, local rate limit).
     * Silently drops for conditions only the network decides (gossip loss)
     * — the publisher has no way to know a message was dropped, matching
     * real fire-and-forget Relay/Light Push semantics.
     */
    publish(fromPeerId: string, contentTopic: string, payload: Uint8Array, options?: PublishOptions): void {
        if (payload.length > MAX_WAKU_MESSAGE_SIZE) {
            throw new ProtocolError(
                `Payload of ${payload.length} bytes exceeds the 150 KiB Waku message size limit`,
                "TRANSPORT_FAILURE",
            );
        }
        this.checkRateLimit(fromPeerId);

        if (this.rng() < (this.config.dropRate ?? 0)) {
            return; // silently lost — never enters the queue or the store
        }

        let finalPayload = payload;
        if (this.rng() < (this.config.corruptRate ?? 0)) {
            finalPayload = payload.slice();
            const idx = Math.floor(this.rng() * finalPayload.length);
            finalPayload[idx] = finalPayload[idx]! ^ 0xff;
        }

        const message: WakuMessage = {
            contentTopic,
            payload: finalPayload,
            timestamp: this.now(),
            ...(options?.ephemeral !== undefined ? { ephemeral: options.ephemeral } : {}),
        };

        this.queue.push({ id: nextMessageId++, fromPeerId, contentTopic, message });

        // Store completeness is decided independently of live delivery —
        // real Store nodes are separate infrastructure from the relay mesh
        // a given publish traverses, so a partition affecting live delivery
        // doesn't necessarily affect whether Store eventually has it too.
        if (!message.ephemeral && this.rng() < (this.config.storeCompletenessRate ?? 1)) {
            const existing = this.store.get(contentTopic) ?? [];
            existing.push(message);
            this.store.set(contentTopic, existing);
        }
    }

    getPendingMessageIds(contentTopic?: string): number[] {
        return this.queue
            .filter((q) => !contentTopic || q.contentTopic === contentTopic)
            .map((q) => q.id);
    }

    /** Deliver every currently queued message, in FIFO order, then clear the queue. */
    flush(): void {
        this.flushInOrder(this.queue.map((q) => q.id));
    }

    /** Deliver only the specified queued messages, in the given order — for deterministic reorder tests. Unspecified queued messages remain pending. */
    flushInOrder(ids: number[]): void {
        for (const id of ids) {
            const idx = this.queue.findIndex((q) => q.id === id);
            if (idx === -1) continue; // already delivered or never queued
            const [item] = this.queue.splice(idx, 1);
            this.deliverToSubscribers(item!);
        }
    }

    private deliverToSubscribers(item: QueuedMessage): void {
        const subs = this.subscribers.get(item.contentTopic) ?? [];
        for (const sub of subs) {
            if (!this.canReach(item.fromPeerId, sub.peerId)) continue;
            sub.callback(item.message);
            if (this.rng() < (this.config.duplicateRate ?? 0)) {
                sub.callback(item.message); // real gossipsub mesh flooding: same message via multiple paths
            }
        }
    }

    subscribe(peerId: string, contentTopic: string, callback: (message: WakuMessage) => void): () => void {
        const list = this.subscribers.get(contentTopic) ?? [];
        const entry: Subscriber = { peerId, callback };
        list.push(entry);
        this.subscribers.set(contentTopic, list);
        return () => {
            const current = this.subscribers.get(contentTopic);
            if (!current) return;
            this.subscribers.set(
                contentTopic,
                current.filter((s) => s !== entry),
            );
        };
    }

    /** Store protocol query. NOT affected by partition (see the publish() note) but IS subject to retention and the completeness gap that was rolled at publish time. */
    retrieveHistory(contentTopic: string, options?: RetrieveHistoryOptions): WakuMessage[] {
        let results = this.store.get(contentTopic) ?? [];
        const retention = this.config.storeRetentionMs;
        if (retention !== undefined) {
            const cutoff = this.now() - retention;
            results = results.filter((m) => m.timestamp >= cutoff);
        }
        if (options?.since !== undefined) {
            const since = options.since;
            results = results.filter((m) => m.timestamp >= since);
        }
        if (options?.limit !== undefined) {
            results = results.slice(0, options.limit);
        }
        return results;
    }

    partition(groupA: string[], groupB: string[]): void {
        const map = new Map<string, string>();
        for (const p of groupA) map.set(p, "A");
        for (const p of groupB) map.set(p, "B");
        this.partitionGroups = map;
    }

    healPartition(): void {
        this.partitionGroups = null;
    }
}
