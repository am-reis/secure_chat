import {
    createLightNode,
    Protocols,
    type LightNode,
    type CreateNodeOptions,
    type IEncoder,
    type IDecoder,
    type IDecodedMessage,
} from "@waku/sdk";
import type { WakuTransport, WakuMessage, PublishOptions, RetrieveHistoryOptions } from "./WakuTransport.js";
import { MAX_WAKU_MESSAGE_SIZE } from "./WakuTransport.js";
import { ProtocolError } from "../errors.js";

export interface RealWakuTransportOptions {
    /**
     * Passed straight through to `createLightNode`. Deliberately not
     * defaulted here: `networkConfig` (which cluster/shards), and how peers
     * are discovered (`defaultBootstrap` vs explicit `bootstrapPeers`), are
     * real infrastructure decisions this module has no business making
     * silently — a caller that doesn't set `networkConfig` gets whatever
     * `@waku/sdk` itself currently defaults to (at the time this was
     * written: The Waku Network's public cluster), which may not be what a
     * given deployment wants.
     */
    node: CreateNodeOptions;
    /**
     * How long `connect()` waits for Light Push/Filter/Store peers before
     * giving up. `@waku/sdk`'s own default if omitted (currently no
     * timeout — waits indefinitely), which is rarely what a caller wants in
     * an application with its own connection-progress UI.
     */
    waitForPeersTimeoutMs?: number;
}

function toWakuMessage(msg: IDecodedMessage): WakuMessage {
    const base: WakuMessage = {
        contentTopic: msg.contentTopic,
        payload: msg.payload,
        // Real Waku messages carry their own timestamp (WakuTransport.ts's
        // doc comment already notes this); msg.timestamp is only undefined
        // for a message that predates the field or was sent without one —
        // falling back to receipt time here is strictly better than
        // fabricating a stale one.
        timestamp: msg.timestamp ? msg.timestamp.getTime() : Date.now(),
    };
    // exactOptionalPropertyTypes: omit the key entirely rather than set it
    // to `undefined` when the source message didn't carry it.
    return msg.ephemeral !== undefined ? { ...base, ephemeral: msg.ephemeral } : base;
}

/**
 * Real `@waku/sdk`-backed `WakuTransport` (Phase 20/33's "Waku adapter").
 * Verified against the SDK's actual current source
 * (github.com/waku-org/js-waku, packages/sdk, at the version pinned in
 * package.json) rather than assumed from memory — the API here (routing
 * info derived internally by `node.createEncoder`/`createDecoder` from a
 * `NetworkConfig`, `lightPush.send` returning a `{successes, failures}`
 * result rather than throwing, `ephemeral` being bound to the ENCODER
 * rather than passed per-send) is a real, current, and non-obvious surface
 * that would be easy to get wrong by extrapolating from older js-waku
 * examples.
 *
 * `MockWakuTransport`/`MockWakuNetwork` remain the transport this
 * project's own test suite runs against — this class needs a live network
 * (real bootstrap peers, real Light Push/Filter/Store service nodes) to do
 * anything at all, which is exactly what this project's "no network access
 * required to run the tests" principle (see README) rules out for
 * automated tests. `test/transport/RealWakuTransport.test.ts` verifies the
 * WIRING against a mocked `@waku/sdk` module instead: that the right SDK
 * calls happen with the right arguments and that their results/failures
 * map onto this project's `WakuTransport` contract correctly. It does not,
 * and cannot, prove live message delivery — that remains a manual or
 * deployment-time concern, same boundary this project already draws around
 * `MasterKeyProvider`'s real platform-keychain backing (see README).
 */
export class RealWakuTransport implements WakuTransport {
    private node: LightNode | undefined;
    private readonly encoders = new Map<string, IEncoder>();
    private readonly decoders = new Map<string, IDecoder<IDecodedMessage>>();

    constructor(private readonly options: RealWakuTransportOptions) {}

    async connect(): Promise<void> {
        try {
            const node = await createLightNode(this.options.node);
            await node.waitForPeers([Protocols.LightPush, Protocols.Filter, Protocols.Store], this.options.waitForPeersTimeoutMs);
            this.node = node;
        } catch (err) {
            throw new ProtocolError(`Failed to connect to the Waku network: ${(err as Error).message}`, "TRANSPORT_FAILURE");
        }
    }

    async disconnect(): Promise<void> {
        if (!this.node) return;
        const node = this.node;
        this.node = undefined;
        this.encoders.clear();
        this.decoders.clear();
        await node.stop();
    }

    /**
     * Throws (INVALID_FORMAT) on an oversized payload before touching the
     * node at all — WakuTransport.ts's own contract calls this "a
     * caller-side programming error to catch before attempting to publish,
     * not a network condition," so it must not depend on connection state.
     */
    async publish(contentTopic: string, payload: Uint8Array, options: PublishOptions = {}): Promise<void> {
        if (payload.length > MAX_WAKU_MESSAGE_SIZE) {
            throw new ProtocolError(
                `Payload exceeds max Waku message size (${MAX_WAKU_MESSAGE_SIZE} bytes): ${payload.length}`,
                "INVALID_FORMAT",
            );
        }

        const node = this.requireNode();
        const encoder = this.getEncoder(node, contentTopic, options.ephemeral ?? false);

        let result;
        try {
            result = await node.lightPush.send(encoder, { payload });
        } catch (err) {
            throw new ProtocolError(`Light Push send threw: ${(err as Error).message}`, "TRANSPORT_FAILURE");
        }
        if (result.successes.length === 0) {
            const reasons = result.failures.map((f) => f.error).join(", ") || "no peers available";
            throw new ProtocolError(`Light Push failed to reach any peer: ${reasons}`, "TRANSPORT_FAILURE");
        }
    }

    async subscribe(contentTopic: string, callback: (message: WakuMessage) => void): Promise<() => void> {
        const node = this.requireNode();
        const decoder = this.getDecoder(node, contentTopic);

        let subscribed: boolean;
        try {
            subscribed = await node.filter.subscribe(decoder, (msg) => callback(toWakuMessage(msg)));
        } catch (err) {
            throw new ProtocolError(`Filter subscribe threw: ${(err as Error).message}`, "TRANSPORT_FAILURE");
        }
        if (!subscribed) {
            throw new ProtocolError(`Filter subscribe failed for content topic: ${contentTopic}`, "TRANSPORT_FAILURE");
        }

        return () => {
            void node.filter.unsubscribe(decoder);
        };
    }

    /** Store protocol query. May legitimately be incomplete — see WakuTransport.ts's module doc. */
    async retrieveHistory(contentTopic: string, options: RetrieveHistoryOptions = {}): Promise<WakuMessage[]> {
        const node = this.requireNode();
        const decoder = this.getDecoder(node, contentTopic);
        const results: WakuMessage[] = [];

        try {
            await node.store.queryWithOrderedCallback(
                [decoder],
                (msg) => {
                    results.push(toWakuMessage(msg));
                },
                {
                    ...(options.since !== undefined ? { timeStart: new Date(options.since) } : {}),
                    ...(options.limit !== undefined ? { paginationLimit: options.limit } : {}),
                },
            );
        } catch (err) {
            throw new ProtocolError(`Store query threw: ${(err as Error).message}`, "TRANSPORT_FAILURE");
        }
        return results;
    }

    private requireNode(): LightNode {
        if (!this.node) {
            throw new ProtocolError("RealWakuTransport is not connected — call connect() first", "TRANSPORT_FAILURE");
        }
        return this.node;
    }

    /**
     * Real Waku binds `ephemeral` to the ENCODER, not to an individual
     * send call the way this project's own `PublishOptions.ephemeral` is
     * shaped — so an ephemeral and a non-ephemeral publish on the same
     * content topic need two distinct cached encoders, not one.
     */
    private getEncoder(node: LightNode, contentTopic: string, ephemeral: boolean): IEncoder {
        const key = `${contentTopic} ${ephemeral}`;
        let encoder = this.encoders.get(key);
        if (!encoder) {
            encoder = node.createEncoder({ contentTopic, ephemeral });
            this.encoders.set(key, encoder);
        }
        return encoder;
    }

    private getDecoder(node: LightNode, contentTopic: string): IDecoder<IDecodedMessage> {
        let decoder = this.decoders.get(contentTopic);
        if (!decoder) {
            decoder = node.createDecoder({ contentTopic });
            this.decoders.set(contentTopic, decoder);
        }
        return decoder;
    }
}
