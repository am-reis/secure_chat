import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey } from "../../src/prekeys/pqPrekey.js";
import { buildPreKeyBundle } from "../../src/prekeys/buildPreKeyBundle.js";
import { InMemoryPrekeyStore } from "../../src/prekeys/InMemoryPrekeyStore.js";
import type { PreKeyBundle } from "../../src/prekeys/PreKeyBundle.js";
import type { SignedPreKey, PQPreKey } from "../../src/prekeys/types.js";
import { SessionManager, type LocalPrekeyLookup } from "../../src/session/SessionManager.js";
import { serializeSession, deserializeSession } from "../../src/persistence/serialize.js";
import { saveSession, loadSession, decryptSessionRecord, encryptSessionRecord } from "../../src/persistence/encryptedStorage.js";
import { saveOutboxEntry, loadOutboxEntry } from "../../src/persistence/outbox.js";
import { InMemoryKeyValueStore } from "../../src/persistence/InMemoryKeyValueStore.js";
import { StaticMasterKeyProvider } from "../../src/persistence/StaticMasterKeyProvider.js";
import { resumePendingOutbox } from "../../src/session/durableMessaging.js";
import { MockWakuNetwork } from "../../src/transport/MockWakuNetwork.js";
import { MockWakuTransport } from "../../src/transport/MockWakuTransport.js";
import { messageContentTopic } from "../../src/transport/contentTopics.js";
import { encodeEnvelope } from "../../src/transport/protoEnvelopeCodec.js";
import { ProtocolError } from "../../src/errors.js";

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

function makeParty() {
    const identity = generateIdentity(provider);
    const signedPreKey = generateSignedPreKey(provider, identity, 1, 30 * DAY);
    const pqPreKey = generatePQPreKey(provider, identity, 1, 30 * DAY);
    const otkStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
    const lookup = new MapPrekeyLookup();
    lookup.addSignedPreKey(signedPreKey);
    lookup.addPQPreKey(pqPreKey);
    const bundle: PreKeyBundle = buildPreKeyBundle(identity, signedPreKey, pqPreKey);
    const manager = new SessionManager(provider, identity, otkStore, lookup);
    return { identity, bundle, manager, otkStore, lookup };
}

describe("Phase 30 — receiving side: crash before persisting is automatically safe", () => {
    it("a crash between decrypt and persist is recovered by simply redelivering the same message", async () => {
        const alice = makeParty();
        const bob = makeParty();
        const { envelope: init } = alice.manager.createSession(bob.bundle, utf8("m0"));
        bob.manager.receiveMessage(init);

        const p1 = alice.manager.sendMessage(alice.manager.getSession(init.sessionId)!.sessionId, utf8("p1"));

        // Snapshot Bob's state BEFORE he processes p1 — simulating "the
        // last thing actually persisted" prior to a crash.
        const preP1Snapshot = serializeSession(bob.manager.getSession(init.sessionId)!);

        const firstAttempt = bob.manager.receiveMessage(p1);
        expect(text(firstAttempt.plaintext)).toBe("p1");
        // CRASH — right here, before Bob persisted his advanced state.

        // Fresh process, fresh manager, only the stale pre-p1 snapshot survived.
        const restored = deserializeSession(preP1Snapshot, bob.identity);
        const freshBobManager = new SessionManager(provider, bob.identity, bob.otkStore, bob.lookup);
        freshBobManager.restoreSession(restored);

        // Store-based (or direct) redelivery of the SAME p1 after restart —
        // this is expected, normal behavior over a P2P/store-and-forward
        // transport, not a bug in the sender.
        const secondAttempt = freshBobManager.receiveMessage(p1);
        expect(text(secondAttempt.plaintext)).toBe("p1");

        // And the conversation continues correctly afterward — no corruption.
        const p2 = alice.manager.sendMessage(init.sessionId, utf8("p2"));
        const p2Result = freshBobManager.receiveMessage(p2);
        expect(text(p2Result.plaintext)).toBe("p2");
    });
});

describe("Phase 30 — sending side: the UNSAFE pattern (regression test for a real finding)", () => {
    it("re-calling sendMessage after restoring stale pre-send state reuses a message key and permanently breaks the recipient's ability to decrypt it", async () => {
        const alice = makeParty();
        const bob = makeParty();
        const { session: aliceSession, envelope: init } = alice.manager.createSession(bob.bundle, utf8("m0"));
        bob.manager.receiveMessage(init);

        // Last-persisted snapshot, taken BEFORE Alice sends P1.
        const preSendSnapshot = serializeSession(aliceSession);

        const p1 = alice.manager.sendMessage(aliceSession.sessionId, utf8("P1-original"));
        bob.manager.receiveMessage(p1); // Bob genuinely received it before Alice's crash.

        // CRASH before Alice persisted her advanced state. Fresh process:
        // only the stale pre-send snapshot survived.
        const restoredAlice = deserializeSession(preSendSnapshot, alice.identity);
        const freshAliceManager = new SessionManager(
            provider,
            alice.identity,
            new InMemoryPrekeyStore(provider.secureErase.bind(provider)),
            alice.lookup,
        );
        freshAliceManager.restoreSession(restoredAlice);

        // Believing P1 was never sent, the restarted app sends something else.
        const p2 = freshAliceManager.sendMessage(restoredAlice.sessionId, utf8("P2-after-restart"));

        // The defect: P1 and P2 claim the identical logical message identity.
        expect(toHex(p2.ratchetHeader.ratchetPublicKey)).toBe(toHex(p1.ratchetHeader.ratchetPublicKey));
        expect(p2.ratchetHeader.messageNumber).toBe(p1.ratchetHeader.messageNumber);
        // Different plaintexts, so different ciphertexts (the AEAD's random
        // nonce prevents the catastrophic same-key-same-nonce break) — but
        // that does NOT save the protocol-level outcome below.
        expect(toHex(p2.ciphertext)).not.toBe(toHex(p1.ciphertext));

        // Bob, who already legitimately received P1, can never decrypt P2 —
        // indistinguishable at the protocol level from a replay attack.
        try {
            bob.manager.receiveMessage(p2);
            expect.unreachable();
        } catch (e) {
            expect(e).toBeInstanceOf(ProtocolError);
            expect((e as ProtocolError).code).toBe("AEAD_AUTHENTICATION_FAILED");
        }
    });
});

describe("Phase 30 — sending side: the SAFE pattern (write-ahead outbox) prevents the defect", () => {
    it("a crash BEFORE transmission is confirmed: restart retransmits the exact same envelope, never a re-derived one", async () => {
        const alice = makeParty();
        const bob = makeParty();
        const { envelope: init } = alice.manager.createSession(bob.bundle, utf8("m0"));
        bob.manager.receiveMessage(init);

        const store = new InMemoryKeyValueStore();
        const masterKeyProvider = new StaticMasterKeyProvider(provider.randomBytes(32));
        const network = new MockWakuNetwork({ seed: 42 });

        // Manually perform sendMessageDurably's first three steps only,
        // simulating a crash exactly before step 4 (transmit).
        const envelope = alice.manager.sendMessage(init.sessionId, utf8("P1-durable"));
        const session = alice.manager.getSession(init.sessionId)!;
        await saveSession(store, provider, masterKeyProvider, session);
        await saveOutboxEntry(store, init.sessionId, encodeEnvelope(envelope));
        // CRASH — transport.publish() and clearOutboxEntry() never ran.

        // Fresh process: reload session, reload outbox, resume.
        const reopenedStore = store.reopen();
        const restoredSession = (await loadSession(
            reopenedStore,
            provider,
            masterKeyProvider,
            init.sessionId,
            alice.identity,
        ))!;
        const freshManager = new SessionManager(
            provider,
            alice.identity,
            new InMemoryPrekeyStore(provider.secureErase.bind(provider)),
            alice.lookup,
        );
        freshManager.restoreSession(restoredSession);

        const freshTransport = new MockWakuTransport("alice", network);
        await freshTransport.connect();

        const retransmitted = await resumePendingOutbox(reopenedStore, freshTransport, init.sessionId);
        expect(retransmitted).toBe(true);
        network.flush();

        // Bob receives it exactly once, correctly.
        const { plaintext } = bob.manager.receiveMessage(envelope);
        expect(text(plaintext)).toBe("P1-durable");

        // Nothing left pending.
        expect(await loadOutboxEntry(reopenedStore, init.sessionId)).toBeUndefined();

        // The conversation continues correctly afterward.
        const p2 = freshManager.sendMessage(init.sessionId, utf8("P2-normal"));
        const p2Result = bob.manager.receiveMessage(p2);
        expect(text(p2Result.plaintext)).toBe("P2-normal");
    });

    it("a crash AFTER transmission but before the outbox is cleared: the retransmitted duplicate is safely deduped by the ratchet's own replay protection", async () => {
        const alice = makeParty();
        const bob = makeParty();
        const { envelope: init } = alice.manager.createSession(bob.bundle, utf8("m0"));
        bob.manager.receiveMessage(init);

        const store = new InMemoryKeyValueStore();
        const masterKeyProvider = new StaticMasterKeyProvider(provider.randomBytes(32));
        const network = new MockWakuNetwork({ seed: 7 });
        const aliceTransport = new MockWakuTransport("alice", network);
        await aliceTransport.connect();

        // Send: state saved, outbox saved, transmission SUCCEEDS, but the
        // crash happens right before clearOutboxEntry would have run.
        const envelope = alice.manager.sendMessage(init.sessionId, utf8("P1-once"));
        const session = alice.manager.getSession(init.sessionId)!;
        await saveSession(store, provider, masterKeyProvider, session);
        const encoded = encodeEnvelope(envelope);
        await saveOutboxEntry(store, init.sessionId, encoded);
        await aliceTransport.publish(messageContentTopic(), encoded);
        network.flush();

        const firstDelivery = bob.manager.receiveMessage(envelope);
        expect(text(firstDelivery.plaintext)).toBe("P1-once");
        // CRASH — clearOutboxEntry() never ran, despite transmission having succeeded.

        // Restart: outbox still shows this envelope as pending (the crash
        // happened before it could be cleared), so it gets retransmitted.
        const retransmitted = await resumePendingOutbox(store, aliceTransport, init.sessionId);
        expect(retransmitted).toBe(true);
        network.flush();

        // Bob receives the duplicate — his own replay protection (already
        // proven at the ratchet layer, Phase 6) rejects it cleanly. The
        // application only ever sees the message delivered once.
        try {
            bob.manager.receiveMessage(envelope);
            expect.unreachable();
        } catch (e) {
            expect(e).toBeInstanceOf(ProtocolError);
        }
    });
});

describe("Phase 30 — a corrupted persisted record is detected, never silently misread", () => {
    it("a bit-flipped session record fails to decrypt rather than loading as valid-but-wrong data", async () => {
        const alice = makeParty();
        const bob = makeParty();
        const { session } = alice.manager.createSession(bob.bundle, utf8("hi"));
        const masterKey = provider.randomBytes(32);

        const ciphertext = encryptSessionRecord(provider, masterKey, session.sessionId, serializeSession(session));
        const corrupted = ciphertext.slice();
        corrupted[Math.floor(corrupted.length / 2)]! ^= 0xff; // simulates a torn/corrupted write landing mid-record

        try {
            decryptSessionRecord(provider, masterKey, session.sessionId, corrupted);
            expect.unreachable();
        } catch (e) {
            expect(e).toBeInstanceOf(ProtocolError);
            expect((e as ProtocolError).code).toBe("STORAGE_FAILURE");
        }
        // Note: InMemoryKeyValueStore's Map.set is inherently atomic, so
        // this test constructs corruption directly rather than simulating a
        // torn write through the store. A real disk-backed RawKeyValueStore
        // implementation MUST provide atomic writes (e.g. write-to-temp-
        // then-rename, or a DB transaction) so an interrupted write never
        // leaves a torn record in place of the last successfully written
        // one — this AEAD failure is the safety net if that discipline is
        // ever violated, not a substitute for it.
    });
});
