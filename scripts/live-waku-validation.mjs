#!/usr/bin/env node
/**
 * Manual, live-network validation for RealWakuTransport.
 *
 * Deliberately NOT part of `npm test` — this project's automated suite is
 * required to run with zero network access (see README), and this script's
 * entire point is the opposite: prove the real protocol stack (PQXDH +
 * Double Ratchet + RealWakuTransport + WakuMessagingClient) actually works
 * against the live public Waku network, not a mock.
 *
 * Imports from ../dist/, not ../src/ — run `npm run build` first. This is
 * deliberate, not laziness: importing the built output exercises the exact
 * same public entrypoint (`src/index.ts`) an external consumer would use,
 * so this script doubles as a packaging sanity check every time it runs
 * (the same class of check that caught the missing envelope.pb.js bug when
 * this package's entrypoint was first set up).
 *
 * Usage:
 *   npm run build
 *   node scripts/live-waku-validation.mjs
 *
 * What it does: two independent light nodes (Alice, Bob), each with its own
 * generated identity, connect to the real Waku network (`defaultBootstrap:
 * true` — per the installed @waku/sdk version this resolves at the time of
 * writing, that's the SANDBOX + TEST ENR trees, not "production" traffic —
 * see docs/integration-guide.md's transport section and re-verify against
 * the installed @waku/discovery package's own dns/constants.js if this
 * matters to you, since which trees `defaultBootstrap` resolves to is
 * @waku/sdk's own choice, not this project's). Alice creates a session with
 * Bob and sends a message; the script waits for Bob to actually receive and
 * decrypt it over the live network, then has Bob reply and waits for Alice
 * to receive that. It also runs one Store-protocol history query as an
 * additional signal.
 *
 * Known, expected, benign noise: each node will report exactly one
 * AEAD_AUTHENTICATION_FAILED via onError — that's the self-delivery gotcha
 * documented in docs/integration-guide.md (a node hears its own published
 * envelope back over the shared content topic and correctly fails to
 * decrypt it, since it wasn't encrypted for itself). Anything beyond that
 * one-per-node is worth investigating, not dismissing.
 */
import {
    NobleCryptoProvider,
    generateIdentity,
    generateSignedPreKey,
    generatePQPreKey,
    generateOneTimePreKeys,
    buildPreKeyBundle,
    InMemoryPrekeyStore,
    SessionManager,
    RealWakuTransport,
    WakuMessagingClient,
} from "../dist/index.js";
import { messageContentTopic } from "../dist/transport/contentTopics.js";

const provider = new NobleCryptoProvider();
const utf8 = (s) => new TextEncoder().encode(s);
const text = (b) => new TextDecoder().decode(b);
const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
const WAIT_FOR_PEERS_TIMEOUT_MS = 30_000;
const WAIT_FOR_MESSAGE_TIMEOUT_MS = 60_000;

class MapPrekeyLookup {
    signed = new Map();
    pq = new Map();
    addSignedPreKey(k) {
        this.signed.set(k.id, k);
    }
    addPQPreKey(k) {
        this.pq.set(k.id, k);
    }
    getSignedPreKey(id) {
        return this.signed.get(id);
    }
    getPQPreKey(id) {
        return this.pq.get(id);
    }
}

function makeParty(label) {
    const identity = generateIdentity(provider);
    const signedPreKey = generateSignedPreKey(provider, identity, 1, THIRTY_DAYS);
    const pqPreKey = generatePQPreKey(provider, identity, 1, THIRTY_DAYS);
    const [otk] = generateOneTimePreKeys(provider, 1, 1);
    const otkStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
    otkStore.addOneTimePreKeys([otk]);
    const lookup = new MapPrekeyLookup();
    lookup.addSignedPreKey(signedPreKey);
    lookup.addPQPreKey(pqPreKey);
    const bundle = buildPreKeyBundle(identity, signedPreKey, pqPreKey, otk);
    const manager = new SessionManager(provider, identity, otkStore, lookup);
    const transport = new RealWakuTransport({
        node: { defaultBootstrap: true },
        waitForPeersTimeoutMs: WAIT_FOR_PEERS_TIMEOUT_MS,
    });
    const received = [];
    const errors = [];
    const client = new WakuMessagingClient(manager, transport, {
        onMessage: (_sessionId, plaintext) => {
            console.log(`[${label}] onMessage: ${text(plaintext)}`);
            received.push(text(plaintext));
        },
        onError: (err) => {
            console.log(`[${label}] onError: ${err.code ?? "?"} — ${err.message}`);
            errors.push(err);
        },
    });
    return { label, bundle, manager, transport, client, received, errors };
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitUntil(predicate, timeoutMs, intervalMs = 500) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        if (predicate()) return true;
        await sleep(intervalMs);
    }
    return predicate();
}

function fail(message) {
    console.error(`\nFAILED: ${message}`);
    process.exitCode = 1;
}

async function main() {
    console.log("=== Live Waku validation: RealWakuTransport + full protocol stack ===\n");

    const alice = makeParty("alice");
    const bob = makeParty("bob");

    console.log("Starting Alice (connect + waitForPeers + subscribe)...");
    await alice.client.start();
    console.log("Starting Bob...");
    await bob.client.start();

    console.log("\nAlice: createSession(bob.bundle, ...) — full PQXDH handshake, published live.");
    const aliceSession = await alice.client.createSession(bob.bundle, utf8("hello bob, live over waku"));

    console.log(`Waiting up to ${WAIT_FOR_MESSAGE_TIMEOUT_MS / 1000}s for Bob to receive and decrypt it...`);
    const bobGotIt = await waitUntil(() => bob.received.length > 0, WAIT_FOR_MESSAGE_TIMEOUT_MS);
    if (!bobGotIt) {
        fail("Bob never received Alice's SESSION_INIT message over the live network.");
    } else {
        console.log("Bob received it — session established live.\n");

        console.log("Bob: sendMessage(...) — ordinary reply, published live.");
        await bob.client.sendMessage(aliceSession.sessionId, utf8("hi alice, bob here, live too"));
        console.log(`Waiting up to ${WAIT_FOR_MESSAGE_TIMEOUT_MS / 1000}s for Alice to receive Bob's reply...`);
        const aliceGotReply = await waitUntil(() => alice.received.length > 0, WAIT_FOR_MESSAGE_TIMEOUT_MS);
        if (!aliceGotReply) {
            fail("Alice never received Bob's reply over the live network.");
        } else {
            console.log("Alice received it.\n");
        }
    }

    console.log("Store protocol: querying recent history on the message content topic...");
    try {
        const history = await alice.transport.retrieveHistory(messageContentTopic(), { limit: 20 });
        console.log(`Store query returned ${history.length} message(s).`);
    } catch (err) {
        console.log(`Store query failed (non-fatal — Store availability is never guaranteed): ${err.message}`);
    }

    console.log("\n=== Summary ===");
    console.log(`Alice received: ${JSON.stringify(alice.received)}`);
    console.log(`Bob received:   ${JSON.stringify(bob.received)}`);
    console.log(`Alice errors: ${alice.errors.length} (expect exactly 1 — self-delivery of her own SESSION_INIT)`);
    console.log(`Bob errors:   ${bob.errors.length} (expect exactly 1 — self-delivery of his own reply)`);
    if (alice.errors.length !== 1 || bob.errors.length !== 1) {
        console.log("NOTE: error count differs from the expected self-delivery-only baseline — worth investigating.");
    }

    await alice.client.stop();
    await bob.client.stop();

    if (process.exitCode !== 1) {
        console.log("\nPASSED.");
    }
}

main()
    .then(() => process.exit(process.exitCode ?? 0))
    .catch((err) => {
        console.error("\nFATAL:", err);
        process.exit(1);
    });
