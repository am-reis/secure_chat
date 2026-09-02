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
import { serializeSession, deserializeSession } from "../../src/persistence/serialize.js";
import {
    encryptSessionRecord,
    decryptSessionRecord,
    saveSession,
    loadSession,
    deleteSession,
    listSessionIds,
} from "../../src/persistence/encryptedStorage.js";
import { InMemoryKeyValueStore } from "../../src/persistence/InMemoryKeyValueStore.js";
import { StaticMasterKeyProvider } from "../../src/persistence/StaticMasterKeyProvider.js";
import { ProtocolError } from "../../src/errors.js";
import type { Session } from "../../src/session/types.js";

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

function makeParty(withOneTime: boolean) {
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
    return { identity, signedPreKey, pqPreKey, otkStore, lookup, bundle, manager };
}

function snapshotRatchet(session: Session) {
    const r = session.ratchetState;
    return {
        DHsPub: toHex(r.DHs.publicKey),
        DHsPriv: toHex(r.DHs.privateKey),
        DHr: r.DHr ? toHex(r.DHr) : null,
        rootKey: toHex(r.rootKey),
        sendingChainKey: r.sendingChainKey ? toHex(r.sendingChainKey) : null,
        receivingChainKey: r.receivingChainKey ? toHex(r.receivingChainKey) : null,
        Ns: r.sendingMessageNumber,
        Nr: r.receivingMessageNumber,
        PN: r.previousSendingChainLength,
        skipped: [...r.skippedMessageKeys.entries()].map(([k, v]) => [k, toHex(v)]),
    };
}

describe("serializeSession / deserializeSession — round trip", () => {
    it("preserves every field exactly, including skipped message keys", () => {
        const alice = makeParty(false);
        const bob = makeParty(true);
        const { envelope } = alice.manager.createSession(bob.bundle, utf8("m0"));
        // Send a couple more so there's real chain progress and skip state to preserve.
        bob.manager.receiveMessage(envelope);
        const m1 = alice.manager.sendMessage(alice.manager.getSession(envelope.sessionId)!.sessionId, utf8("m1"));
        const m2 = alice.manager.sendMessage(envelope.sessionId, utf8("m2"));
        bob.manager.receiveMessage(m2); // received out of order -> m1 becomes a skipped key
        const bobSession = bob.manager.getSession(envelope.sessionId)!;
        expect(bobSession.ratchetState.skippedMessageKeys.size).toBe(1);

        const serialized = serializeSession(bobSession);
        const restored = deserializeSession(serialized, bob.identity);

        expect(snapshotRatchet(restored)).toEqual(snapshotRatchet(bobSession));
        expect(toHex(restored.sessionId)).toBe(toHex(bobSession.sessionId));
        expect(toHex(restored.remoteIdentityPublicKey)).toBe(toHex(bobSession.remoteIdentityPublicKey));
        expect(toHex(restored.associatedData)).toBe(toHex(bobSession.associatedData));
        void m1;
    });

    it("preserves a null DHr/chain keys (session that never received/sent yet)", () => {
        const alice = makeParty(false);
        const bob = makeParty(false);
        const { session } = alice.manager.createSession(bob.bundle, utf8("hi"));
        // Alice's freshly-created session has receivingChainKey === null.
        expect(session.ratchetState.receivingChainKey).toBeNull();
        const restored = deserializeSession(serializeSession(session), alice.identity);
        expect(restored.ratchetState.receivingChainKey).toBeNull();
        expect(snapshotRatchet(restored)).toEqual(snapshotRatchet(session));
    });

    it("throws if the supplied identity doesn't match the session's original identity", () => {
        const alice = makeParty(false);
        const bob = makeParty(false);
        const stranger = generateIdentity(provider);
        const { session } = alice.manager.createSession(bob.bundle, utf8("hi"));
        const serialized = serializeSession(session);
        expect(() => deserializeSession(serialized, stranger)).toThrow(ProtocolError);
    });

    it("throws on an unsupported stateVersion", () => {
        const alice = makeParty(false);
        const bob = makeParty(false);
        const { session } = alice.manager.createSession(bob.bundle, utf8("hi"));
        const serialized = serializeSession(session);
        const tampered = { ...serialized, stateVersion: 999 };
        expect(() => deserializeSession(tampered, alice.identity)).toThrow(ProtocolError);
    });
});

describe("encryptSessionRecord / decryptSessionRecord — encryption at rest", () => {
    it("round-trips through encryption", () => {
        const alice = makeParty(false);
        const bob = makeParty(false);
        const { session } = alice.manager.createSession(bob.bundle, utf8("hi"));
        const serialized = serializeSession(session);
        const masterKey = provider.randomBytes(32);

        const ciphertext = encryptSessionRecord(provider, masterKey, session.sessionId, serialized);
        const decrypted = decryptSessionRecord(provider, masterKey, session.sessionId, ciphertext);
        expect(decrypted).toEqual(serialized);
    });

    it("fails with the wrong master key", () => {
        const alice = makeParty(false);
        const bob = makeParty(false);
        const { session } = alice.manager.createSession(bob.bundle, utf8("hi"));
        const serialized = serializeSession(session);
        const masterKey = provider.randomBytes(32);
        const wrongKey = provider.randomBytes(32);

        const ciphertext = encryptSessionRecord(provider, masterKey, session.sessionId, serialized);
        expect(() => decryptSessionRecord(provider, wrongKey, session.sessionId, ciphertext)).toThrow(
            ProtocolError,
        );
    });

    it("fails if the ciphertext is decrypted under a different session id (AD binding)", () => {
        const alice = makeParty(false);
        const bob = makeParty(false);
        const { session: s1 } = alice.manager.createSession(bob.bundle, utf8("hi"));
        const { session: s2 } = alice.manager.createSession(bob.bundle, utf8("hi2"));
        const masterKey = provider.randomBytes(32);

        const ciphertext = encryptSessionRecord(provider, masterKey, s1.sessionId, serializeSession(s1));
        // An attacker with raw KV-store access swaps this ciphertext under s2's key.
        expect(() => decryptSessionRecord(provider, masterKey, s2.sessionId, ciphertext)).toThrow(
            ProtocolError,
        );
    });

    it("fails on a tampered ciphertext", () => {
        const alice = makeParty(false);
        const bob = makeParty(false);
        const { session } = alice.manager.createSession(bob.bundle, utf8("hi"));
        const masterKey = provider.randomBytes(32);
        const ciphertext = encryptSessionRecord(provider, masterKey, session.sessionId, serializeSession(session));
        const tampered = ciphertext.slice();
        tampered[tampered.length - 1]! ^= 0xff;
        expect(() => decryptSessionRecord(provider, masterKey, session.sessionId, tampered)).toThrow(
            ProtocolError,
        );
    });
});

describe("saveSession / loadSession — full storage round trip", () => {
    it("saves and loads a session through an in-memory store", async () => {
        const alice = makeParty(false);
        const bob = makeParty(false);
        const { session } = alice.manager.createSession(bob.bundle, utf8("hi"));

        const store = new InMemoryKeyValueStore();
        const masterKeyProvider = new StaticMasterKeyProvider(provider.randomBytes(32));

        await saveSession(store, provider, masterKeyProvider, session);
        const loaded = await loadSession(store, provider, masterKeyProvider, session.sessionId, alice.identity);

        expect(loaded).toBeDefined();
        expect(snapshotRatchet(loaded!)).toEqual(snapshotRatchet(session));
    });

    it("returns undefined for a session id that was never saved", async () => {
        const alice = makeParty(false);
        const store = new InMemoryKeyValueStore();
        const masterKeyProvider = new StaticMasterKeyProvider(provider.randomBytes(32));
        const loaded = await loadSession(store, provider, masterKeyProvider, provider.randomBytes(32), alice.identity);
        expect(loaded).toBeUndefined();
    });

    it("deleteSession removes the record", async () => {
        const alice = makeParty(false);
        const bob = makeParty(false);
        const { session } = alice.manager.createSession(bob.bundle, utf8("hi"));
        const store = new InMemoryKeyValueStore();
        const masterKeyProvider = new StaticMasterKeyProvider(provider.randomBytes(32));

        await saveSession(store, provider, masterKeyProvider, session);
        await deleteSession(store, session.sessionId);
        const loaded = await loadSession(store, provider, masterKeyProvider, session.sessionId, alice.identity);
        expect(loaded).toBeUndefined();
    });

    it("listSessionIds returns all saved session ids", async () => {
        const alice = makeParty(false);
        const bob = makeParty(false);
        const { session: s1 } = alice.manager.createSession(bob.bundle, utf8("a"));
        const { session: s2 } = alice.manager.createSession(bob.bundle, utf8("b"));
        const store = new InMemoryKeyValueStore();
        const masterKeyProvider = new StaticMasterKeyProvider(provider.randomBytes(32));

        await saveSession(store, provider, masterKeyProvider, s1);
        await saveSession(store, provider, masterKeyProvider, s2);
        const ids = (await listSessionIds(store)).map(toHex).sort();
        expect(ids).toEqual([toHex(s1.sessionId), toHex(s2.sessionId)].sort());
    });
});

describe("Phase 13 — session state survives a simulated process restart", () => {
    it("Bob can restart, reload his session, and continue an active conversation seamlessly", async () => {
        const alice = makeParty(false);
        const bob = makeParty(true);

        // --- Before "restart": establish a session and exchange one message each way.
        const { envelope: init } = alice.manager.createSession(bob.bundle, utf8("A0"));
        bob.manager.receiveMessage(init);
        const b0 = bob.manager.sendMessage(init.sessionId, utf8("B0"));
        alice.manager.receiveMessage(b0);

        const store = new InMemoryKeyValueStore();
        const masterKeyProvider = new StaticMasterKeyProvider(provider.randomBytes(32));
        await saveSession(store, provider, masterKeyProvider, bob.manager.getSession(init.sessionId)!);

        // --- Simulate a process restart: fresh store handle onto the same
        // underlying data, and a completely new SessionManager instance
        // (nothing carried over in memory except what gets loaded back).
        const reopenedStore = store.reopen();
        const restoredSession = await loadSession(
            reopenedStore,
            provider,
            masterKeyProvider,
            init.sessionId,
            bob.identity,
        );
        expect(restoredSession).toBeDefined();

        const freshBobManager = new SessionManager(provider, bob.identity, bob.otkStore, bob.lookup);
        freshBobManager.restoreSession(restoredSession!);

        // --- After "restart": conversation continues without missing a beat.
        const a1 = alice.manager.sendMessage(init.sessionId, utf8("A1 after restart"));
        const { plaintext } = freshBobManager.receiveMessage(a1);
        expect(text(plaintext)).toBe("A1 after restart");

        const b1 = freshBobManager.sendMessage(init.sessionId, utf8("B1 after restart"));
        const { plaintext: p2 } = alice.manager.receiveMessage(b1);
        expect(text(p2)).toBe("B1 after restart");
    });
});
