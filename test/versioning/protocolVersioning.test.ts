import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey } from "../../src/prekeys/pqPrekey.js";
import { buildPreKeyBundle } from "../../src/prekeys/buildPreKeyBundle.js";
import { InMemoryPrekeyStore } from "../../src/prekeys/InMemoryPrekeyStore.js";
import type { PreKeyBundle } from "../../src/prekeys/PreKeyBundle.js";
import type { SignedPreKey, PQPreKey } from "../../src/prekeys/types.js";
import { validateProtocolVersion } from "../../src/prekeys/validateBundle.js";
import { SessionManager, type LocalPrekeyLookup } from "../../src/session/SessionManager.js";
import { MockWakuNetwork } from "../../src/transport/MockWakuNetwork.js";
import { MockWakuTransport } from "../../src/transport/MockWakuTransport.js";
import { WakuMessagingClient } from "../../src/transport/WakuMessagingClient.js";
import { sessionInitContentTopic, messageContentTopic } from "../../src/transport/contentTopics.js";
import { encodeEnvelope } from "../../src/transport/protoEnvelopeCodec.js";
import { ProtocolError } from "../../src/errors.js";

/**
 * Phase 27 stress test. We only have ONE real cryptographic profile (v1) —
 * genuinely simulating a differing-crypto v2 is out of scope (that's
 * Phase 35 territory). What's tested here instead, honestly: the
 * VERSIONING MECHANISM's isolation properties — that a v1 deployment is
 * completely unaffected by traffic tagged with a version it doesn't
 * support, at both the topic level and the explicit version-check level,
 * and that the check is exact-match with no silent range tolerance in
 * either direction. "v2" envelopes below are v1 crypto with the version
 * field manually overridden — sufficient to prove routing/isolation, not a
 * claim that a real v2 protocol exists.
 */

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

function makeParty(peerId: string, network: MockWakuNetwork) {
    const identity = generateIdentity(provider);
    const signedPreKey = generateSignedPreKey(provider, identity, 1, 30 * DAY);
    const pqPreKey = generatePQPreKey(provider, identity, 1, 30 * DAY);
    const otkStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
    const lookup = new MapPrekeyLookup();
    lookup.addSignedPreKey(signedPreKey);
    lookup.addPQPreKey(pqPreKey);
    const bundle: PreKeyBundle = buildPreKeyBundle(identity, signedPreKey, pqPreKey);
    const manager = new SessionManager(provider, identity, otkStore, lookup);
    const transport = new MockWakuTransport(peerId, network);
    const received: string[] = [];
    const errors: unknown[] = [];
    const client = new WakuMessagingClient(manager, transport, {
        onMessage: (_id, plaintext) => received.push(text(plaintext)),
        onError: (err) => errors.push(err),
    });
    return { peerId, identity, bundle, manager, transport, client, received, errors };
}

describe("Phase 27 — content topics are version-distinct", () => {
    it("different versions produce different topics for the same envelope type", () => {
        expect(sessionInitContentTopic(1)).not.toBe(sessionInitContentTopic(2));
        expect(messageContentTopic(1)).not.toBe(messageContentTopic(2));
    });

    it("session-init and message topics never collide, at any version", () => {
        expect(sessionInitContentTopic(1)).not.toBe(messageContentTopic(1));
        expect(sessionInitContentTopic(2)).not.toBe(messageContentTopic(2));
    });

    it("the version number appears literally in the topic path", () => {
        expect(sessionInitContentTopic(1)).toContain("/1/");
        expect(sessionInitContentTopic(7)).toContain("/7/");
    });
});

describe("Phase 27 — topic-level isolation: a v1 deployment never even sees v2-tagged traffic", () => {
    it("a v1-only client's subscriptions receive nothing published on v2 topics", async () => {
        const network = new MockWakuNetwork({ seed: 1 });
        const alice = makeParty("alice", network);
        const bob = makeParty("bob", network); // subscribed only to v1 topics (the default)
        await alice.client.start();
        await bob.client.start();

        // Something claiming to be v2 traffic, published on the v2 topic.
        network.publish("attacker", sessionInitContentTopic(2), new Uint8Array([1, 2, 3, 4]));
        network.publish("attacker", messageContentTopic(2), new Uint8Array([5, 6, 7, 8]));
        network.flush();

        // Bob's v1 subscriptions never fire at all for this — not even to
        // reject it. It's not on a topic he's listening to.
        expect(bob.received).toHaveLength(0);
        expect(bob.errors).toHaveLength(0);

        // Bob's real v1 conversation with Alice is completely unaffected.
        await alice.client.createSession(bob.bundle, utf8("real v1 message"));
        network.flush();
        expect(bob.received).toEqual(["real v1 message"]);
    });
});

describe("Phase 27 — defense in depth: version check rejects even if traffic lands on the wrong topic", () => {
    it("a v2-tagged envelope injected directly onto a v1 topic is cleanly rejected, not silently processed or crashed on", async () => {
        const network = new MockWakuNetwork({ seed: 2 });
        const alice = makeParty("alice", network);
        const bob = makeParty("bob", network);
        await alice.client.start();
        await bob.client.start();

        // Build a real, otherwise-valid v1 SESSION_INIT, then manually
        // override its protocolVersion to 2 before publishing — simulating
        // a misrouted or malicious peer, independent of the topic-isolation
        // mechanism tested above.
        const { envelope } = alice.manager.createSession(bob.bundle, utf8("should never arrive"));
        const misrouted = { ...envelope, protocolVersion: 2 };
        network.publish("alice", sessionInitContentTopic(1), encodeEnvelope(misrouted));
        network.flush();

        expect(bob.received).toHaveLength(0);
        expect(bob.errors).toHaveLength(1);
        expect(bob.errors[0]).toBeInstanceOf(ProtocolError);
        expect((bob.errors[0] as ProtocolError).code).toBe("UNSUPPORTED_VERSION");

        // Bob's client is still fully functional for legitimate v1 traffic afterward.
        await alice.client.createSession(bob.bundle, utf8("legitimate v1 message"));
        network.flush();
        expect(bob.received).toEqual(["legitimate v1 message"]);
    });
});

describe("Phase 27 — exact version match, no silent range tolerance", () => {
    it("validatePreKeyBundle rejects both an older and a newer version — never silently coerces or falls back", () => {
        const alice = makeParty("alice", new MockWakuNetwork());
        const olderBundle = { ...alice.bundle, protocolVersion: 0 };
        const newerBundle = { ...alice.bundle, protocolVersion: 2 };

        try {
            validateProtocolVersion(olderBundle);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("UNSUPPORTED_VERSION");
        }
        try {
            validateProtocolVersion(newerBundle);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("UNSUPPORTED_VERSION");
        }
    });

    it("SessionManager.receiveMessage rejects both directions equally for MESSAGE envelopes", async () => {
        const network = new MockWakuNetwork({ seed: 3 });
        const alice = makeParty("alice", network);
        const bob = makeParty("bob", network);
        await alice.client.start();
        await bob.client.start();

        const { envelope: init } = alice.manager.createSession(bob.bundle, utf8("m0"));
        bob.manager.receiveMessage(init);
        const real = alice.manager.sendMessage(init.sessionId, utf8("real"));

        for (const badVersion of [0, 2, 999]) {
            const forged = { ...real, protocolVersion: badVersion };
            try {
                bob.manager.receiveMessage(forged);
                expect.unreachable();
            } catch (e) {
                expect((e as ProtocolError).code).toBe("UNSUPPORTED_VERSION");
            }
        }

        // The genuinely v1 message still processes correctly, proving the
        // rejections above weren't a side effect of a broken session.
        const { plaintext } = bob.manager.receiveMessage(real);
        expect(text(plaintext)).toBe("real");
    });
});

describe("Phase 27 — two version tags coexist on one shared network without cross-talk", () => {
    it("v1 traffic and v2-tagged traffic proceed independently on the same MockWakuNetwork", async () => {
        const network = new MockWakuNetwork({ seed: 4 });

        // Real v1 pair.
        const alice = makeParty("alice", network);
        const bob = makeParty("bob", network);
        await alice.client.start();
        await bob.client.start();

        // A second pair, publishing/subscribing on v2 topics — using the
        // SAME underlying v1 crypto (see the module doc above), tagged as
        // v2 purely to exercise topic/version routing at scale, alongside
        // real v1 traffic on the same physical network.
        const carol = makeParty("carol", network);
        const dave = makeParty("dave", network);
        await carol.transport.connect();
        const daveTransportV2 = new MockWakuTransport("dave", network);
        await daveTransportV2.connect();
        const daveV2Received: string[] = [];
        await daveTransportV2.subscribe(sessionInitContentTopic(2), (m) => {
            daveV2Received.push(new TextDecoder().decode(m.payload));
        });

        // Alice/Bob exchange several real v1 messages.
        const session = await alice.client.createSession(bob.bundle, utf8("v1-msg-0"));
        network.flush();
        await alice.client.sendMessage(session.sessionId, utf8("v1-msg-1"));
        await alice.client.sendMessage(session.sessionId, utf8("v1-msg-2"));
        network.flush();

        // Meanwhile, Carol publishes v2-tagged traffic on the v2 topic.
        const { envelope: carolInit } = carol.manager.createSession(dave.bundle, utf8("v2-tagged-payload"));
        const carolInitV2Tagged = { ...carolInit, protocolVersion: 2 };
        await carol.transport.publish(sessionInitContentTopic(2), encodeEnvelope(carolInitV2Tagged));
        network.flush();

        // Alice/Bob's conversation is entirely unaffected by Carol's v2-tagged traffic.
        expect(bob.received).toEqual(["v1-msg-0", "v1-msg-1", "v1-msg-2"]);
        expect(bob.errors).toHaveLength(0);

        // Dave's v1-topic subscriptions (via his own client, not used here)
        // never saw Carol's v2-tagged traffic either — it only reached the
        // raw v2-topic subscription set up separately above.
        expect(dave.received).toHaveLength(0);
        expect(daveV2Received).toHaveLength(1);
    });
});
