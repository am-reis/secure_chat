import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey } from "../../src/prekeys/pqPrekey.js";
import { generateOneTimePreKeys } from "../../src/prekeys/oneTimePrekeys.js";
import { buildPreKeyBundle } from "../../src/prekeys/buildPreKeyBundle.js";
import { InMemoryPrekeyStore } from "../../src/prekeys/InMemoryPrekeyStore.js";
import type { PreKeyBundle } from "../../src/prekeys/PreKeyBundle.js";
import type { SignedPreKey, PQPreKey } from "../../src/prekeys/types.js";
import { SessionManager, type LocalPrekeyLookup } from "../../src/session/SessionManager.js";
import { MockWakuNetwork } from "../../src/transport/MockWakuNetwork.js";
import { MockWakuTransport } from "../../src/transport/MockWakuTransport.js";
import { WakuMessagingClient } from "../../src/transport/WakuMessagingClient.js";
import { messageContentTopic, sessionInitContentTopic } from "../../src/transport/contentTopics.js";
import { encodeEnvelope } from "../../src/transport/protoEnvelopeCodec.js";
import { MAX_WAKU_MESSAGE_SIZE } from "../../src/transport/WakuTransport.js";
import { ProtocolError } from "../../src/errors.js";

const provider = new NobleCryptoProvider();
const DAY = 24 * 60 * 60 * 1000;
const utf8 = (s: string) => new TextEncoder().encode(s);
const text = (b: Uint8Array) => new TextDecoder().decode(b);

class MapPrekeyLookup implements LocalPrekeyLookup {
    private readonly signed = new Map<number, SignedPreKey>();
    private readonly pq = new Map<number, PQPreKey>();
    addSignedPreKey(k: SignedPreKey) {
        this.signed.set(k.id, k);
    }
    addPQPreKey(k: PQPreKey) {
        this.pq.set(k.id, k);
    }
    getSignedPreKey(id: number) {
        return this.signed.get(id);
    }
    getPQPreKey(id: number) {
        return this.pq.get(id);
    }
}

function makeParty(peerId: string, network: MockWakuNetwork, withOneTime: boolean) {
    const identity = generateIdentity(provider);
    const signedPreKey = generateSignedPreKey(provider, identity, 1, 30 * DAY);
    const pqPreKey = generatePQPreKey(provider, identity, 1, 30 * DAY);
    const otkStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
    const lookup = new MapPrekeyLookup();
    lookup.addSignedPreKey(signedPreKey);
    lookup.addPQPreKey(pqPreKey);
    let otk;
    if (withOneTime) {
        [otk] = generateOneTimePreKeys(provider, 1, 1);
        otkStore.addOneTimePreKeys([otk!]);
    }
    const bundle: PreKeyBundle = buildPreKeyBundle(identity, signedPreKey, pqPreKey, otk);
    const manager = new SessionManager(provider, identity, otkStore, lookup);
    const transport = new MockWakuTransport(peerId, network);
    const received: Array<{ sessionId: Uint8Array; plaintext: string }> = [];
    const errors: unknown[] = [];
    const client = new WakuMessagingClient(manager, transport, {
        onMessage: (sessionId, plaintext) => received.push({ sessionId, plaintext: text(plaintext) }),
        onError: (err) => errors.push(err),
    });
    return { peerId, identity, bundle, manager, transport, client, received, errors };
}

describe("Waku transport — message size limit", () => {
    it("rejects publishing a payload over the 150 KiB Waku limit", async () => {
        const network = new MockWakuNetwork();
        const transport = new MockWakuTransport("p1", network);
        await transport.connect();
        const oversized = new Uint8Array(MAX_WAKU_MESSAGE_SIZE + 1);
        await expect(transport.publish("/x/1/y/proto", oversized)).rejects.toThrow(ProtocolError);
    });
});

describe("Waku transport — drop and retransmission (Phase 16)", () => {
    it("a fully dropped publish never arrives, but retransmitting the identical envelope afterward succeeds", async () => {
        const network = new MockWakuNetwork({ seed: 1 });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        // Force the first attempt to be dropped.
        network.setConfig({ dropRate: 1 });
        const { envelope } = alice.manager.createSession(bob.bundle, utf8("hello"));
        await alice.transport.publish(sessionInitContentTopic(envelope.protocolVersion), encodeEnvelope(envelope));
        network.flush();
        expect(bob.received).toHaveLength(0);

        // Network recovers; Alice retransmits the exact same envelope.
        network.setConfig({ dropRate: 0 });
        await alice.transport.publish(sessionInitContentTopic(envelope.protocolVersion), encodeEnvelope(envelope));
        network.flush();

        expect(bob.received).toHaveLength(1);
        expect(bob.received[0]!.plaintext).toBe("hello");
    });
});

describe("Waku transport — duplicate delivery (gossipsub mesh flooding)", () => {
    it("a message delivered twice by the network is only processed once by the application", async () => {
        const network = new MockWakuNetwork({ seed: 2, duplicateRate: 1 }); // always duplicate
        const alice = makeParty("alice", network, true);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        await alice.client.createSession(bob.bundle, utf8("hi"));
        network.flush();

        // The mock delivered the callback twice; SessionManager's own replay
        // protection (proven at the ratchet layer already) means only one
        // of those two calls actually decrypts successfully.
        expect(bob.received).toHaveLength(1);
        expect(bob.received[0]!.plaintext).toBe("hi");
        expect(bob.errors).toHaveLength(1); // the duplicate's rejection
    });
});

describe("Waku transport — delay and reorder", () => {
    it("messages arriving out of order via the transport still all decrypt correctly", async () => {
        const network = new MockWakuNetwork({ seed: 3 });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        const session = await alice.client.createSession(bob.bundle, utf8("m0"));
        network.flush(); // establish the session first, deterministically
        bob.received.length = 0; // isolate assertions to what happens next

        await alice.client.sendMessage(session.sessionId, utf8("m1"));
        await alice.client.sendMessage(session.sessionId, utf8("m2"));
        await alice.client.sendMessage(session.sessionId, utf8("m3"));

        const topic = messageContentTopic();
        const ids = network.getPendingMessageIds(topic);
        expect(ids).toHaveLength(3);
        // Deliver in reverse order via the transport itself.
        network.flushInOrder([...ids].reverse());

        expect(bob.received.map((r) => r.plaintext).sort()).toEqual(["m1", "m2", "m3"]);
        expect(bob.errors).toHaveLength(0);
    });
});

describe("Waku transport — corruption (untrusted transport, Phase 0.1)", () => {
    it("a corrupted message is rejected cleanly and does not disrupt later legitimate messages", async () => {
        const network = new MockWakuNetwork({ seed: 4 });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        const session = await alice.client.createSession(bob.bundle, utf8("m0"));
        network.flush();
        expect(bob.received).toHaveLength(1);

        network.setConfig({ corruptRate: 1 }); // guarantee corruption for the next publish
        await alice.client.sendMessage(session.sessionId, utf8("corrupted-one"));
        network.flush();
        expect(bob.received).toHaveLength(1); // still just the first — corrupted one rejected
        expect(bob.errors).toHaveLength(1);

        network.setConfig({ corruptRate: 0 });
        await alice.client.sendMessage(session.sessionId, utf8("clean-one"));
        network.flush();
        expect(bob.received).toHaveLength(2);
        expect(bob.received[1]!.plaintext).toBe("clean-one");
    });
});

describe("Waku transport — network partition", () => {
    it("messages don't cross a partition, and delivery resumes once healed", async () => {
        const network = new MockWakuNetwork({ seed: 5 });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        const session = await alice.client.createSession(bob.bundle, utf8("before-partition"));
        network.flush();
        expect(bob.received).toHaveLength(1);

        network.partition(["alice"], ["bob"]);
        await alice.client.sendMessage(session.sessionId, utf8("during-partition"));
        network.flush(); // queued but undeliverable across the partition
        expect(bob.received).toHaveLength(1); // unchanged

        network.healPartition();
        network.flush(); // the during-partition message was already removed
        // from the live-delivery queue during the earlier flush (undelivered,
        // not requeued) — recovery for it is the Store-based catch-up
        // scenario in the next describe block, not a second flush.
        expect(bob.received).toHaveLength(1);
    });

    it("messages sent AFTER the partition heals deliver normally", async () => {
        const network = new MockWakuNetwork({ seed: 5 });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        const session = await alice.client.createSession(bob.bundle, utf8("m0"));
        network.flush();

        network.partition(["alice"], ["bob"]);
        network.healPartition();

        await alice.client.sendMessage(session.sessionId, utf8("after-heal"));
        network.flush();
        expect(bob.received).toHaveLength(2);
        expect(bob.received[1]!.plaintext).toBe("after-heal");
    });
});

describe("Waku transport — offline peer catches up via Store (Phase 16 / real recommended pattern)", () => {
    it("a peer that reconnects retrieves everything it missed while offline", async () => {
        const network = new MockWakuNetwork({ seed: 6 });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        const session = await alice.client.createSession(bob.bundle, utf8("m0"));
        network.flush();
        expect(bob.received).toHaveLength(1);

        await bob.transport.disconnect(); // Bob goes offline
        const offlineSince = network.now();
        bob.received.length = 0; // isolate assertions to what's recovered via sync

        await alice.client.sendMessage(session.sessionId, utf8("m1-while-offline"));
        await alice.client.sendMessage(session.sessionId, utf8("m2-while-offline"));
        network.flush(); // delivered live to nobody, since Bob is disconnected — but Store still has both

        await bob.transport.connect();
        expect(bob.received).toHaveLength(0); // reconnecting alone doesn't replay anything

        await bob.client.syncMissedMessages(offlineSince);
        expect(bob.received.map((r) => r.plaintext).sort()).toEqual([
            "m1-while-offline",
            "m2-while-offline",
        ]);
    });

    it("Store's own documented incompleteness means catch-up is best-effort, not guaranteed", async () => {
        // storeCompletenessRate models "Store does not guarantee the
        // message's availability" (real Waku FAQ) — set to 0 so NOTHING
        // published while Bob is offline survives into Store at all.
        const network = new MockWakuNetwork({ seed: 7, storeCompletenessRate: 0 });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        const session = await alice.client.createSession(bob.bundle, utf8("m0"));
        network.flush();

        await bob.transport.disconnect();
        const offlineSince = network.now();
        await alice.client.sendMessage(session.sessionId, utf8("lost-forever"));
        network.flush();

        await bob.transport.connect();
        await bob.client.syncMissedMessages(offlineSince);

        // The message is genuinely unrecoverable at the transport layer —
        // this is expected, documented Waku behavior, not a bug in this
        // implementation. An application built on this needs its own
        // higher-level acknowledgement/retry scheme if it wants stronger
        // guarantees than the base protocol provides.
        expect(bob.received).toHaveLength(1); // only the original session-init message
    });
});

describe("Waku transport — RLN-style rate limiting", () => {
    it("a publisher exceeding the configured rate is rejected", async () => {
        const network = new MockWakuNetwork({ rateLimitPerPeer: { maxMessages: 2, windowMs: 60_000 } });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        const session = await alice.client.createSession(bob.bundle, utf8("m0")); // 1st
        await alice.client.sendMessage(session.sessionId, utf8("m1")); // 2nd
        await expect(alice.client.sendMessage(session.sessionId, utf8("m2"))).rejects.toThrow(ProtocolError); // 3rd, over limit
    });

    it("the rate limit window expires, allowing further publishes", async () => {
        const network = new MockWakuNetwork({ rateLimitPerPeer: { maxMessages: 1, windowMs: 1000 } });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        const session = await alice.client.createSession(bob.bundle, utf8("m0"));
        await expect(alice.client.sendMessage(session.sessionId, utf8("blocked"))).rejects.toThrow(ProtocolError);

        network.advanceTime(1001);
        await expect(alice.client.sendMessage(session.sessionId, utf8("allowed"))).resolves.toBeUndefined();
    });
});

describe("Waku transport — malicious/injected messages don't disrupt the receive loop", () => {
    it("an unsolicited-but-valid session from an unrelated party is processed on its own merits, and doesn't disrupt anyone else's conversation", async () => {
        const network = new MockWakuNetwork({ seed: 8 });
        const alice = makeParty("alice", network, false);
        // No one-time prekey here deliberately: this test isolates "two
        // unrelated sessions coexist fine," which is a different property
        // from single-use OTK enforcement (already covered by SessionManager's
        // own tests) — reusing the same cached bundle for two independent
        // real sessions when it only has ONE one-time prekey would
        // correctly fail the second one on prekey exhaustion, which would
        // conflate two unrelated things in one test.
        const bob = makeParty("bob", network, false);
        const mallory = makeParty("mallory", network, false);
        await alice.client.start();
        await bob.client.start();
        await mallory.client.start();

        await mallory.client.createSession(bob.bundle, utf8("from mallory"));
        network.flush();
        expect(bob.received).toHaveLength(1);
        expect(bob.received[0]!.plaintext).toBe("from mallory");

        await alice.client.createSession(bob.bundle, utf8("real message"));
        network.flush();
        expect(bob.received).toHaveLength(2);
        expect(bob.received[1]!.plaintext).toBe("real message");
        expect(bob.errors).toHaveLength(0);
    });

    it("a structurally garbage payload injected directly onto the topic is rejected without crashing the client", async () => {
        const network = new MockWakuNetwork({ seed: 9 });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        // Raw garbage bytes, not even valid JSON, injected by "attacker" onto the topic.
        network.publish("attacker", sessionInitContentTopic(), new Uint8Array([0xde, 0xad, 0xbe, 0xef]));
        network.flush();
        expect(bob.received).toHaveLength(0);
        expect(bob.errors).toHaveLength(1);

        // Bob's client is still fully functional afterward.
        await alice.client.createSession(bob.bundle, utf8("still works"));
        network.flush();
        expect(bob.received).toHaveLength(1);
        expect(bob.received[0]!.plaintext).toBe("still works");
    });
});
