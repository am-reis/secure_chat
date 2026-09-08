import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey } from "../../src/prekeys/pqPrekey.js";
import { generateOneTimePreKeys } from "../../src/prekeys/oneTimePrekeys.js";
import { buildPreKeyBundle } from "../../src/prekeys/buildPreKeyBundle.js";
import { InMemoryPrekeyStore } from "../../src/prekeys/InMemoryPrekeyStore.js";
import { SessionManager, type LocalPrekeyLookup } from "../../src/session/SessionManager.js";
import { sendMessageDurably, resumePendingOutbox } from "../../src/session/durableMessaging.js";
import { saveSession, loadSession } from "../../src/persistence/encryptedStorage.js";
import { InMemoryKeyValueStore } from "../../src/persistence/InMemoryKeyValueStore.js";
import { StaticMasterKeyProvider } from "../../src/persistence/StaticMasterKeyProvider.js";
import { MockWakuNetwork } from "../../src/transport/MockWakuNetwork.js";
import { MockWakuTransport } from "../../src/transport/MockWakuTransport.js";
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
 * Backs the "Persistence and safe sending" section of
 * docs/integration-guide.md. Deliberately NOT re-testing what
 * test/persistence/persistence.test.ts and
 * test/crashRecovery/crashRecovery.test.ts already prove thoroughly — this
 * is "the recipe," narrated in the guide; those files are "why the recipe
 * looks like this."
 */
describe("Integration guide — persistence and durable sending", () => {
    it("a session survives a restart, and sendMessageDurably/resumePendingOutbox are how you send safely once it's persisted", async () => {
        const provider = new NobleCryptoProvider();
        const utf8 = (s: string) => new TextEncoder().encode(s);
        const text = (b: Uint8Array) => new TextDecoder().decode(b);
        const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;

        // --- Set up Alice and Bob, establish a session (see getting-started.md) ---
        const bobIdentity = generateIdentity(provider);
        const bobSignedPreKey = generateSignedPreKey(provider, bobIdentity, 1, THIRTY_DAYS);
        const bobPqPreKey = generatePQPreKey(provider, bobIdentity, 1, THIRTY_DAYS);
        const [bobOtk] = generateOneTimePreKeys(provider, 1, 1);
        const bobOtkStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
        bobOtkStore.addOneTimePreKeys([bobOtk!]);
        const bobBundle = buildPreKeyBundle(bobIdentity, bobSignedPreKey, bobPqPreKey, bobOtk);
        const bobLookup = new MapPrekeyLookup();
        bobLookup.addSignedPreKey(bobSignedPreKey);
        bobLookup.addPQPreKey(bobPqPreKey);
        const bobManager = new SessionManager(provider, bobIdentity, bobOtkStore, bobLookup);

        const aliceIdentity = generateIdentity(provider);
        const aliceOtkStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
        const aliceManager = new SessionManager(provider, aliceIdentity, aliceOtkStore, new MapPrekeyLookup());

        const { session: aliceSession, envelope: init } = aliceManager.createSession(bobBundle, utf8("hi bob"));
        bobManager.receiveMessage(init);

        // --- Persist Alice's session ---
        //
        // StaticMasterKeyProvider is test-only (see its own doc comment) —
        // a real app backs this with an OS keychain / Electron safeStorage.
        // InMemoryKeyValueStore is likewise a stand-in for real disk/IndexedDB
        // storage; only RawKeyValueStore's four methods matter to this code.
        const masterKey = provider.randomBytes(32);
        const masterKeyProvider = new StaticMasterKeyProvider(masterKey);
        const store = new InMemoryKeyValueStore();
        await saveSession(store, provider, masterKeyProvider, aliceSession);

        // --- Simulate a process restart: fresh SessionManager, same store ---
        const restoredAliceManager = new SessionManager(provider, aliceIdentity, aliceOtkStore, new MapPrekeyLookup());
        const restoredSession = await loadSession(store, provider, masterKeyProvider, aliceSession.sessionId, aliceIdentity);
        expect(restoredSession).toBeDefined();
        restoredAliceManager.restoreSession(restoredSession!);

        // Before touching a restored session at all: check for (and
        // retransmit) anything that was mid-send when the crash happened.
        // The common case — nothing pending — returns false.
        const network = new MockWakuNetwork();
        const aliceTransport = new MockWakuTransport("alice", network);
        await aliceTransport.connect();
        const resumed = await resumePendingOutbox(store, aliceTransport, aliceSession.sessionId);
        expect(resumed).toBe(false);

        // --- Safe to send now: sendMessageDurably, never sendMessage directly ---
        //
        // See README's "Required reading" and CHANGELOG's Phase 30 entry for
        // exactly what goes wrong if you call sessionManager.sendMessage
        // directly on a persisted session and retry after a crash instead.
        const envelope = await sendMessageDurably(
            restoredAliceManager,
            store,
            provider,
            masterKeyProvider,
            aliceTransport,
            aliceSession.sessionId,
            utf8("still me, after a restart"),
        );
        expect(envelope.type).toBe("MESSAGE");

        // Bob receives the same envelope exactly like any other message —
        // the durability machinery above is entirely on the sending side.
        // (Whether it arrives via a live subscription or Store catch-up is
        // the transport layer's concern — see the "Transport" section of
        // the integration guide and test/examples/transportWithMockWaku.test.ts.)
        const { plaintext } = bobManager.receiveMessage(envelope);
        expect(text(plaintext)).toBe("still me, after a restart");
    });
});
