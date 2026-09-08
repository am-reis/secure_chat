import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey } from "../../src/prekeys/pqPrekey.js";
import { generateOneTimePreKeys } from "../../src/prekeys/oneTimePrekeys.js";
import { buildPreKeyBundle } from "../../src/prekeys/buildPreKeyBundle.js";
import { InMemoryPrekeyStore } from "../../src/prekeys/InMemoryPrekeyStore.js";
import { SessionManager, type LocalPrekeyLookup } from "../../src/session/SessionManager.js";
import { MockWakuNetwork } from "../../src/transport/MockWakuNetwork.js";
import { MockWakuTransport } from "../../src/transport/MockWakuTransport.js";
import { WakuMessagingClient } from "../../src/transport/WakuMessagingClient.js";
import type { SignedPreKey, PQPreKey } from "../../src/prekeys/types.js";

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

/**
 * Backs the "Transport" section of docs/integration-guide.md.
 * `WakuMessagingClient` is the SessionManager<->WakuTransport binding — it
 * doesn't care whether the transport underneath is `MockWakuTransport`
 * (used here, and in this project's own test suite — no live network) or
 * `RealWakuTransport` (see src/transport/RealWakuTransport.ts and its own
 * test file for how that swap works; it needs a real `@waku/sdk` node and
 * so isn't exercised here).
 */
describe("Integration guide — sending and receiving over a transport", () => {
    it("Alice and Bob exchange messages entirely through WakuMessagingClient, never touching SessionManager directly", async () => {
        const provider = new NobleCryptoProvider();
        const utf8 = (s: string) => new TextEncoder().encode(s);
        const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;

        function makeParty(peerId: string, network: MockWakuNetwork) {
            const identity = generateIdentity(provider);
            const signedPreKey = generateSignedPreKey(provider, identity, 1, THIRTY_DAYS);
            const pqPreKey = generatePQPreKey(provider, identity, 1, THIRTY_DAYS);
            const [otk] = generateOneTimePreKeys(provider, 1, 1);
            const otkStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
            otkStore.addOneTimePreKeys([otk!]);
            const lookup = new MapPrekeyLookup();
            lookup.addSignedPreKey(signedPreKey);
            lookup.addPQPreKey(pqPreKey);
            const bundle = buildPreKeyBundle(identity, signedPreKey, pqPreKey, otk);

            const manager = new SessionManager(provider, identity, otkStore, lookup);
            const transport = new MockWakuTransport(peerId, network);
            const received: string[] = [];
            const errors: unknown[] = [];
            const client = new WakuMessagingClient(manager, transport, {
                onMessage: (_sessionId, plaintext) => received.push(new TextDecoder().decode(plaintext)),
                // Every subscriber on a shared topic — including the
                // publisher itself, matching real gossipsub/Waku Relay
                // behavior — gets every message published to it. A
                // publisher "hearing" its own envelope back and failing to
                // decrypt it (wrong ratchet direction) is expected, benign
                // noise, not a real error: onError is exactly where that
                // goes, and a real app should log/report here rather than
                // throw. Never let a single bad/foreign message stop
                // processing of everything else (see WakuMessagingClient's
                // own doc comment).
                onError: (err) => errors.push(err),
            });
            return { bundle, client, received, errors };
        }

        // MockWakuNetwork is a shared, in-process stand-in for the Waku
        // pubsub mesh — every MockWakuTransport pointed at the same
        // instance can reach every other one, subject to whatever fault
        // injection it's configured with (drop/duplicate/delay/corrupt —
        // see test/transport/MockWakuTransport.test.ts for the adversarial
        // suite this project runs against it).
        const network = new MockWakuNetwork();
        const alice = makeParty("alice", network);
        const bob = makeParty("bob", network);

        // start() connects and subscribes to every content topic this
        // protocol version uses (SESSION_INIT, MESSAGE, SESSION_RESET).
        await alice.client.start();
        await bob.client.start();

        // createSession here does everything test/examples/quickstart.test.ts's
        // SessionManager.createSession does, AND publishes the resulting
        // envelope onto the network — no separate "send" call needed for
        // the first message. It returns the established Session, the same
        // one SessionManager.createSession would.
        const aliceSession = await alice.client.createSession(bob.bundle, utf8("hi bob, over the wire"));
        // MockWakuNetwork queues published messages and delivers them on
        // flush() — deterministic timing for tests (and for the fault
        // injection / reordering suite in test/transport/MockWakuTransport.test.ts).
        // A real transport delivers live subscriptions asynchronously with
        // no equivalent step.
        network.flush();
        expect(bob.received).toEqual(["hi bob, over the wire"]);
        // Alice heard her own SESSION_INIT back (self-delivery, see above)
        // and it landed in onError, not onMessage — expected, not a bug.
        expect(alice.received).toEqual([]);
        expect(alice.errors).toHaveLength(1);

        // Ordinary messages after that go through client.sendMessage,
        // keyed by the sessionId from above — WakuMessagingClient handles
        // encoding and publishing to the right content topic itself.
        await bob.client.sendMessage(aliceSession.sessionId, utf8("hi alice, replying over the wire"));
        network.flush();
        expect(alice.received).toEqual(["hi alice, replying over the wire"]);
        expect(bob.errors).toHaveLength(1); // same self-delivery noise, on Bob's side this time
    });
});
