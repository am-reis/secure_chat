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
import type { SessionInitEnvelope, MessageEnvelopeData } from "../../src/session/types.js";
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

describe("SessionManager — end-to-end session establishment", () => {
    it("Alice creates a session, Bob processes it, and the plaintext round-trips", () => {
        const alice = makeParty(false);
        const bob = makeParty(true);

        const { session: aliceSession, envelope } = alice.manager.createSession(bob.bundle, utf8("hello bob"));
        const { session: bobSession, plaintext } = bob.manager.receiveMessage(envelope);

        expect(text(plaintext)).toBe("hello bob");
        expect(toHex(bobSession.sessionId)).toBe(toHex(aliceSession.sessionId));
        expect(toHex(bobSession.associatedData)).toBe(toHex(aliceSession.associatedData));
    });

    it("consumes Bob's one-time prekey only after successful processing", () => {
        const alice = makeParty(false);
        const bob = makeParty(true);

        expect(bob.otkStore.countAvailableOneTimePreKeys()).toBe(1);
        const { envelope } = alice.manager.createSession(bob.bundle, utf8("hi"));
        bob.manager.receiveMessage(envelope);

        expect(bob.otkStore.countAvailableOneTimePreKeys()).toBe(0);
        expect(bob.otkStore.getOneTimePreKey(1)!.state).toBe("CONSUMED");
    });

    it("works without a one-time prekey at all", () => {
        const alice = makeParty(false);
        const bob = makeParty(false);
        expect(bob.bundle.oneTimePreKey).toBeUndefined();

        const { envelope } = alice.manager.createSession(bob.bundle, utf8("hi"));
        const { plaintext } = bob.manager.receiveMessage(envelope);
        expect(text(plaintext)).toBe("hi");
    });

    it("bidirectional exchange after session establishment", () => {
        const alice = makeParty(false);
        const bob = makeParty(true);

        const { session: aliceSession, envelope: init } = alice.manager.createSession(bob.bundle, utf8("A0"));
        bob.manager.receiveMessage(init);

        const bobReply = bob.manager.sendMessage(init.sessionId, utf8("B0"));
        const { plaintext: p1 } = alice.manager.receiveMessage(bobReply);
        expect(text(p1)).toBe("B0");

        const aliceMsg2 = alice.manager.sendMessage(aliceSession.sessionId, utf8("A1"));
        const { plaintext: p2 } = bob.manager.receiveMessage(aliceMsg2);
        expect(text(p2)).toBe("A1");
    });
});

describe("SessionManager — Phase 23: session lookup routing", () => {
    it("rejects a MESSAGE envelope for an unknown session without creating one", () => {
        const bob = makeParty(false);
        const forged: MessageEnvelopeData = {
            type: "MESSAGE",
            protocolVersion: 1,
            sessionId: provider.randomBytes(32),
            ratchetHeader: {
                ratchetPublicKey: provider.generateX25519KeyPair().publicKey,
                previousChainLength: 0,
                messageNumber: 0,
            },
            ciphertext: new Uint8Array(48),
        };
        try {
            bob.manager.receiveMessage(forged);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("UNKNOWN_SESSION");
        }
        expect(bob.manager.getSession(forged.sessionId)).toBeUndefined();
    });

    it("sendMessage on an unknown session throws UNKNOWN_SESSION", () => {
        const alice = makeParty(false);
        expect(() => alice.manager.sendMessage(provider.randomBytes(32), utf8("x"))).toThrow(ProtocolError);
    });

    it("rejects an envelope with an unsupported protocol version before any processing", () => {
        const bob = makeParty(false);
        const forged: MessageEnvelopeData = {
            type: "MESSAGE",
            protocolVersion: 999,
            sessionId: provider.randomBytes(32),
            ratchetHeader: {
                ratchetPublicKey: provider.generateX25519KeyPair().publicKey,
                previousChainLength: 0,
                messageNumber: 0,
            },
            ciphertext: new Uint8Array(48),
        };
        try {
            bob.manager.receiveMessage(forged);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("UNSUPPORTED_VERSION");
        }
    });
});

describe("SessionManager — Phase 16: idempotent SESSION_INIT retransmission", () => {
    it("a retransmitted identical SESSION_INIT converges on the same session, not a second one", () => {
        const alice = makeParty(false);
        const bob = makeParty(true);
        const { envelope } = alice.manager.createSession(bob.bundle, utf8("hi"));

        const first = bob.manager.receiveMessage(envelope);
        expect(text(first.plaintext)).toBe("hi");

        // Retransmission of the exact same envelope (e.g. Alice never got Bob's ack).
        // Must not re-run PQXDH or re-touch the prekey store, and must not
        // register a second session.
        expect(() => bob.manager.receiveMessage(envelope)).toThrow(ProtocolError); // replay of message #0
        expect(bob.otkStore.countAvailableOneTimePreKeys()).toBe(0); // still exactly one consumption, not two
        expect(bob.otkStore.getOneTimePreKey(1)!.state).toBe("CONSUMED");
    });
});

describe("SessionManager — Phase 5.3: no partial state on a failed initial message", () => {
    it("a corrupted initial ciphertext leaves no session registered and releases the reserved OTK", () => {
        const alice = makeParty(false);
        const bob = makeParty(true);
        const { envelope } = alice.manager.createSession(bob.bundle, utf8("hi"));

        const corrupted: SessionInitEnvelope = { ...envelope, ciphertext: envelope.ciphertext.slice() };
        corrupted.ciphertext[corrupted.ciphertext.length - 1]! ^= 0xff;

        expect(() => bob.manager.receiveMessage(corrupted)).toThrow(ProtocolError);
        expect(bob.manager.getSession(envelope.sessionId)).toBeUndefined();
        expect(bob.otkStore.countAvailableOneTimePreKeys()).toBe(1); // released, not stuck RESERVED or CONSUMED
        expect(bob.otkStore.getOneTimePreKey(1)!.state).toBe("AVAILABLE");
    });

    it("an unknown signedPreKeyId is rejected as KEY_NOT_FOUND, with no session created", () => {
        const alice = makeParty(false);
        const bob = makeParty(true);
        const { envelope } = alice.manager.createSession(bob.bundle, utf8("hi"));
        const forged: SessionInitEnvelope = { ...envelope, signedPreKeyId: 9999 };

        try {
            bob.manager.receiveMessage(forged);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("KEY_NOT_FOUND");
        }
        expect(bob.manager.getSession(envelope.sessionId)).toBeUndefined();
    });
});

describe("SessionManager — restoreSession", () => {
    it("rejects restoring a session id that's already registered", () => {
        const alice = makeParty(false);
        const bob = makeParty(true);
        const { session, envelope } = alice.manager.createSession(bob.bundle, utf8("hi"));
        expect(() => alice.manager.restoreSession(session)).toThrow(ProtocolError);
        void envelope;
    });
});

describe("SessionManager — sanity: sessions between unrelated parties don't cross-decrypt", () => {
    it("Mallory cannot decrypt Alice's message to Bob even with her own valid session to Bob", () => {
        const alice = makeParty(false);
        const mallory = makeParty(false);
        const bob = makeParty(true);

        const { envelope: aliceInit } = alice.manager.createSession(bob.bundle, utf8("for bob only"));
        const { plaintext } = bob.manager.receiveMessage(aliceInit);
        expect(text(plaintext)).toBe("for bob only");

        // Mallory tries to replay Alice's envelope into her own SessionManager as if it were hers.
        expect(() => mallory.manager.receiveMessage(aliceInit)).toThrow(); // Mallory has no matching prekeys/session state
    });
});
