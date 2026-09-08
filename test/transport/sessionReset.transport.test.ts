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
import { sessionInitContentTopic, sessionResetContentTopic } from "../../src/transport/contentTopics.js";
import { encodeEnvelope } from "../../src/transport/protoEnvelopeCodec.js";

const provider = new NobleCryptoProvider();
const DAY = 24 * 60 * 60 * 1000;
const utf8 = (s: string) => new TextEncoder().encode(s);
const text = (b: Uint8Array) => new TextDecoder().decode(b);
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

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
    const resets: Uint8Array[] = [];
    const errors: unknown[] = [];
    const client = new WakuMessagingClient(manager, transport, {
        onMessage: (sessionId, plaintext) => received.push({ sessionId, plaintext: text(plaintext) }),
        onSessionReset: (sessionId) => resets.push(sessionId),
        onError: (err) => errors.push(err),
    });
    return { peerId, identity, signedPreKey, pqPreKey, bundle, manager, transport, client, received, resets, errors };
}

describe("Waku transport — Phase 19 session reset end to end", () => {
    it("Alice resets, Bob's client verifies and destroys the session, then a fresh session works", async () => {
        const network = new MockWakuNetwork({ seed: 7 });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        const { session: aliceSession, envelope: init } = alice.manager.createSession(bob.bundle, utf8("hi"));
        await alice.transport.publish(sessionInitContentTopic(init.protocolVersion), encodeEnvelope(init));
        network.flush();
        expect(bob.received).toHaveLength(1);
        expect(bob.manager.getSession(aliceSession.sessionId)).toBeDefined();

        await alice.client.resetSession(aliceSession.sessionId);
        network.flush();

        expect(alice.manager.getSession(aliceSession.sessionId)).toBeUndefined();
        expect(bob.manager.getSession(aliceSession.sessionId)).toBeUndefined();
        expect(bob.resets).toHaveLength(1);
        expect(toHex(bob.resets[0]!)).toBe(toHex(aliceSession.sessionId));
        expect(bob.errors).toHaveLength(0);

        // A fresh handshake under a new session id works afterward.
        const freshBundle = buildPreKeyBundle(bob.identity, bob.signedPreKey, bob.pqPreKey, undefined);
        const { session: newSession, envelope: newInit } = alice.manager.createSession(
            freshBundle,
            utf8("second time's the charm"),
        );
        await alice.transport.publish(sessionInitContentTopic(newInit.protocolVersion), encodeEnvelope(newInit));
        network.flush();
        expect(newSession.sessionId).not.toEqual(aliceSession.sessionId);
        expect(bob.received).toHaveLength(2);
        expect(bob.received[1]!.plaintext).toBe("second time's the charm");
    });

    it("a forged SESSION_RESET over the wire is rejected via onError, and the session survives", async () => {
        const network = new MockWakuNetwork({ seed: 8 });
        const alice = makeParty("alice", network, false);
        const bob = makeParty("bob", network, true);
        await alice.client.start();
        await bob.client.start();

        const { session: aliceSession, envelope: init } = alice.manager.createSession(bob.bundle, utf8("hi"));
        await alice.transport.publish(sessionInitContentTopic(init.protocolVersion), encodeEnvelope(init));
        network.flush();
        expect(bob.manager.getSession(aliceSession.sessionId)).toBeDefined();

        // Mallory (a third, unrelated transport peer) publishes a
        // well-formed-looking but unsigned/garbage-signed SESSION_RESET
        // for Alice's session id directly onto the network.
        const mallory = new MockWakuTransport("mallory", network);
        await mallory.connect();
        await mallory.publish(
            sessionResetContentTopic(1),
            encodeEnvelope({
                type: "SESSION_RESET",
                protocolVersion: 1,
                sessionId: aliceSession.sessionId,
                signature: provider.randomBytes(64),
            }),
        );
        network.flush();

        expect(bob.resets).toHaveLength(0);
        expect(bob.errors).toHaveLength(1);
        expect(bob.manager.getSession(aliceSession.sessionId)).toBeDefined();
    });
});
