import { describe, it, expect, beforeEach, vi } from "vitest";
import { ProtocolError } from "../../src/errors.js";
import { MAX_WAKU_MESSAGE_SIZE } from "../../src/transport/WakuTransport.js";

/**
 * RealWakuTransport needs a live Waku network (real bootstrap peers, real
 * Light Push/Filter/Store service nodes) to do anything at all — exactly
 * what this project's "no network access required to run the tests"
 * principle rules out for automated tests (see README, and the rationale
 * in RealWakuTransport.ts's own module doc). So this file does NOT test
 * live message delivery; it tests the WIRING against a mocked `@waku/sdk`
 * module — that the right SDK calls happen with the right arguments, and
 * that their results/failures map onto this project's WakuTransport
 * contract (ProtocolError with the right code) correctly. Getting this
 * wiring wrong (e.g. treating `lightPush.send`'s `{successes, failures}`
 * result as throw-on-failure, or forgetting `ephemeral` is bound to the
 * ENCODER rather than passed per-send) would be invisible without a test
 * like this, since it would only surface against a real network.
 */

const { mockNode, createLightNodeMock } = vi.hoisted(() => {
    const mockNode = {
        createEncoder: vi.fn((params: { contentTopic: string; ephemeral?: boolean }) => ({
            contentTopic: params.contentTopic,
            ephemeral: !!params.ephemeral,
        })),
        createDecoder: vi.fn((params: { contentTopic: string }) => ({ contentTopic: params.contentTopic })),
        lightPush: { send: vi.fn() },
        filter: { subscribe: vi.fn(), unsubscribe: vi.fn() },
        store: { queryWithOrderedCallback: vi.fn() },
        waitForPeers: vi.fn(async () => undefined),
        stop: vi.fn(async () => undefined),
    };
    const createLightNodeMock = vi.fn(async () => mockNode);
    return { mockNode, createLightNodeMock };
});

vi.mock("@waku/sdk", () => ({
    createLightNode: createLightNodeMock,
    Protocols: { Relay: "relay", Store: "store", LightPush: "lightpush", Filter: "filter" },
}));

const { RealWakuTransport } = await import("../../src/transport/RealWakuTransport.js");
// (dynamic import, not a static one: RealWakuTransport.ts imports the
// `Protocols` enum's members as values at module-evaluation time to build
// the waitForPeers() argument, so the mock above must already be in place
// before this module is first evaluated — vi.mock's hoisting handles that
// for a static `import` too, but the dynamic form here makes the ordering
// explicit rather than relying on transform-hoisting behavior.)

beforeEach(() => {
    vi.clearAllMocks();
    createLightNodeMock.mockImplementation(async () => mockNode);
    mockNode.waitForPeers.mockImplementation(async () => undefined);
    mockNode.stop.mockImplementation(async () => undefined);
});

function makeTransport() {
    return new RealWakuTransport({ node: { defaultBootstrap: false }, waitForPeersTimeoutMs: 5000 });
}

describe("RealWakuTransport — connect/disconnect wiring", () => {
    it("connect() creates a node with the given options and waits for LightPush/Filter/Store peers", async () => {
        const transport = makeTransport();
        await transport.connect();

        expect(createLightNodeMock).toHaveBeenCalledWith({ defaultBootstrap: false });
        expect(mockNode.waitForPeers).toHaveBeenCalledWith(["lightpush", "filter", "store"], 5000);
    });

    it("connect() wraps a thrown SDK error as a classified TRANSPORT_FAILURE", async () => {
        createLightNodeMock.mockImplementationOnce(async () => {
            throw new Error("no bootstrap peers reachable");
        });
        const transport = makeTransport();
        try {
            await transport.connect();
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("TRANSPORT_FAILURE");
        }
    });

    it("disconnect() stops the node and is a no-op if never connected", async () => {
        const transport = makeTransport();
        await expect(transport.disconnect()).resolves.toBeUndefined(); // never connected
        expect(mockNode.stop).not.toHaveBeenCalled();

        await transport.connect();
        await transport.disconnect();
        expect(mockNode.stop).toHaveBeenCalledTimes(1);
    });

    it("an operation before connect() throws TRANSPORT_FAILURE rather than crashing on a null node", async () => {
        const transport = makeTransport();
        await expect(transport.subscribe("/app/1/x/proto", () => {})).rejects.toThrow(ProtocolError);
    });
});

describe("RealWakuTransport — publish()", () => {
    it("rejects an oversized payload WITHOUT ever touching the node (size check is unconditional)", async () => {
        const transport = makeTransport();
        const oversized = new Uint8Array(MAX_WAKU_MESSAGE_SIZE + 1);
        try {
            await transport.publish("/app/1/x/proto", oversized);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("INVALID_FORMAT");
        }
        expect(createLightNodeMock).not.toHaveBeenCalled();
    });

    it("creates a non-ephemeral encoder by default and calls lightPush.send with it", async () => {
        mockNode.lightPush.send.mockResolvedValueOnce({ successes: ["peer1"], failures: [] });
        const transport = makeTransport();
        await transport.connect();

        const payload = new Uint8Array([1, 2, 3]);
        await transport.publish("/app/1/x/proto", payload);

        expect(mockNode.createEncoder).toHaveBeenCalledWith({ contentTopic: "/app/1/x/proto", ephemeral: false });
        expect(mockNode.lightPush.send).toHaveBeenCalledWith(
            expect.objectContaining({ contentTopic: "/app/1/x/proto", ephemeral: false }),
            { payload },
        );
    });

    it("uses a DIFFERENT (ephemeral) encoder when options.ephemeral is true, not the same cached one", async () => {
        mockNode.lightPush.send.mockResolvedValue({ successes: ["peer1"], failures: [] });
        const transport = makeTransport();
        await transport.connect();

        await transport.publish("/app/1/x/proto", new Uint8Array([1]), { ephemeral: true });
        await transport.publish("/app/1/x/proto", new Uint8Array([2]));

        expect(mockNode.createEncoder).toHaveBeenCalledTimes(2);
        expect(mockNode.createEncoder).toHaveBeenNthCalledWith(1, { contentTopic: "/app/1/x/proto", ephemeral: true });
        expect(mockNode.createEncoder).toHaveBeenNthCalledWith(2, { contentTopic: "/app/1/x/proto", ephemeral: false });
    });

    it("caches and reuses the same encoder across repeated publishes to the same (topic, ephemeral) pair", async () => {
        mockNode.lightPush.send.mockResolvedValue({ successes: ["peer1"], failures: [] });
        const transport = makeTransport();
        await transport.connect();

        await transport.publish("/app/1/x/proto", new Uint8Array([1]));
        await transport.publish("/app/1/x/proto", new Uint8Array([2]));

        expect(mockNode.createEncoder).toHaveBeenCalledTimes(1);
        expect(mockNode.lightPush.send).toHaveBeenCalledTimes(2);
    });

    it("throws TRANSPORT_FAILURE when lightPush.send resolves with zero successes (Light Push's own no-throw failure shape)", async () => {
        mockNode.lightPush.send.mockResolvedValueOnce({
            successes: [],
            failures: [{ error: "No peer available" }],
        });
        const transport = makeTransport();
        await transport.connect();

        try {
            await transport.publish("/app/1/x/proto", new Uint8Array([1]));
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("TRANSPORT_FAILURE");
            expect((e as ProtocolError).message).toContain("No peer available");
        }
    });

    it("throws TRANSPORT_FAILURE if lightPush.send itself throws", async () => {
        mockNode.lightPush.send.mockRejectedValueOnce(new Error("stream aborted"));
        const transport = makeTransport();
        await transport.connect();

        await expect(transport.publish("/app/1/x/proto", new Uint8Array([1]))).rejects.toThrow(ProtocolError);
    });
});

describe("RealWakuTransport — subscribe()", () => {
    it("subscribes with a decoder for the content topic and maps IDecodedMessage back to WakuMessage", async () => {
        let capturedCallback: ((msg: unknown) => void) | undefined;
        mockNode.filter.subscribe.mockImplementationOnce(async (_decoder: unknown, cb: (msg: unknown) => void) => {
            capturedCallback = cb;
            return true;
        });

        const transport = makeTransport();
        await transport.connect();

        const received: unknown[] = [];
        await transport.subscribe("/app/1/x/proto", (msg) => received.push(msg));

        expect(mockNode.createDecoder).toHaveBeenCalledWith({ contentTopic: "/app/1/x/proto" });
        expect(capturedCallback).toBeDefined();

        const fakeTimestamp = new Date(1_700_000_000_000);
        capturedCallback!({
            contentTopic: "/app/1/x/proto",
            payload: new Uint8Array([9, 9]),
            timestamp: fakeTimestamp,
            ephemeral: true,
        });

        expect(received).toEqual([
            { contentTopic: "/app/1/x/proto", payload: new Uint8Array([9, 9]), timestamp: 1_700_000_000_000, ephemeral: true },
        ]);
    });

    it("omits `ephemeral` entirely (not `ephemeral: undefined`) when the decoded message didn't carry it", async () => {
        let capturedCallback: ((msg: unknown) => void) | undefined;
        mockNode.filter.subscribe.mockImplementationOnce(async (_decoder: unknown, cb: (msg: unknown) => void) => {
            capturedCallback = cb;
            return true;
        });
        const transport = makeTransport();
        await transport.connect();
        const received: unknown[] = [];
        await transport.subscribe("/app/1/x/proto", (msg) => received.push(msg));

        capturedCallback!({ contentTopic: "/app/1/x/proto", payload: new Uint8Array([1]), timestamp: undefined, ephemeral: undefined });

        expect(received).toHaveLength(1);
        expect(Object.prototype.hasOwnProperty.call(received[0], "ephemeral")).toBe(false);
    });

    it("returned unsubscribe function calls filter.unsubscribe with the same decoder", async () => {
        mockNode.filter.subscribe.mockResolvedValueOnce(true);
        const transport = makeTransport();
        await transport.connect();

        const unsubscribe = await transport.subscribe("/app/1/x/proto", () => {});
        unsubscribe();

        expect(mockNode.filter.unsubscribe).toHaveBeenCalledWith(
            expect.objectContaining({ contentTopic: "/app/1/x/proto" }),
        );
    });

    it("throws TRANSPORT_FAILURE when filter.subscribe resolves false", async () => {
        mockNode.filter.subscribe.mockResolvedValueOnce(false);
        const transport = makeTransport();
        await transport.connect();
        await expect(transport.subscribe("/app/1/x/proto", () => {})).rejects.toThrow(ProtocolError);
    });
});

describe("RealWakuTransport — retrieveHistory()", () => {
    it("queries the store and collects messages via the ordered callback, mapping fields correctly", async () => {
        mockNode.store.queryWithOrderedCallback.mockImplementationOnce(
            async (_decoders: unknown, cb: (msg: unknown) => void) => {
                cb({ contentTopic: "/app/1/x/proto", payload: new Uint8Array([1]), timestamp: new Date(1000), ephemeral: undefined });
                cb({ contentTopic: "/app/1/x/proto", payload: new Uint8Array([2]), timestamp: new Date(2000), ephemeral: undefined });
            },
        );
        const transport = makeTransport();
        await transport.connect();

        const history = await transport.retrieveHistory("/app/1/x/proto");
        expect(history).toHaveLength(2);
        expect(history[0]!.timestamp).toBe(1000);
        expect(history[1]!.timestamp).toBe(2000);
    });

    it("translates `since`/`limit` options into the store's timeStart/paginationLimit", async () => {
        mockNode.store.queryWithOrderedCallback.mockResolvedValueOnce(undefined);
        const transport = makeTransport();
        await transport.connect();

        await transport.retrieveHistory("/app/1/x/proto", { since: 5_000, limit: 10 });

        expect(mockNode.store.queryWithOrderedCallback).toHaveBeenCalledWith(
            [expect.objectContaining({ contentTopic: "/app/1/x/proto" })],
            expect.any(Function),
            { timeStart: new Date(5_000), paginationLimit: 10 },
        );
    });

    it("throws TRANSPORT_FAILURE if the store query throws", async () => {
        mockNode.store.queryWithOrderedCallback.mockRejectedValueOnce(new Error("no store peers"));
        const transport = makeTransport();
        await transport.connect();
        await expect(transport.retrieveHistory("/app/1/x/proto")).rejects.toThrow(ProtocolError);
    });
});
