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
import { signSessionReset } from "../../src/session/reset.js";
import type { SessionResetEnvelope } from "../../src/session/types.js";
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

function establishedPair() {
    const alice = makeParty(false);
    const bob = makeParty(true);
    const { session: aliceSession, envelope } = alice.manager.createSession(bob.bundle, utf8("hi"));
    const { session: bobSession } = bob.manager.receiveMessage(envelope);
    return { alice, bob, aliceSession, bobSession };
}

describe("SessionManager — Phase 19: session reset", () => {
    it("resetSession destroys local state and produces a verifiable envelope the peer can apply", () => {
        const { alice, bob, aliceSession } = establishedPair();

        const resetEnvelope = alice.manager.resetSession(aliceSession.sessionId);
        expect(resetEnvelope.type).toBe("SESSION_RESET");
        expect(alice.manager.getSession(aliceSession.sessionId)).toBeUndefined();

        expect(bob.manager.getSession(aliceSession.sessionId)).toBeDefined();
        bob.manager.receiveSessionReset(resetEnvelope);
        expect(bob.manager.getSession(aliceSession.sessionId)).toBeUndefined();
    });

    it("after reset, a fresh PQXDH session between the same parties works end to end", () => {
        const { alice, bob, aliceSession } = establishedPair();
        const resetEnvelope = alice.manager.resetSession(aliceSession.sessionId);
        bob.manager.receiveSessionReset(resetEnvelope);

        // Bob publishes a fresh bundle (a real one-time prekey would need
        // replenishing out of band; reuse bob's signed/PQ prekeys here since
        // the point under test is that a brand new session id/handshake
        // works after the old session is gone on both sides).
        const freshBundle = buildPreKeyBundle(bob.identity, bob.signedPreKey, bob.pqPreKey, undefined);
        const { session: newAliceSession, envelope } = alice.manager.createSession(freshBundle, utf8("hello again"));
        expect(newAliceSession.sessionId).not.toEqual(aliceSession.sessionId);

        const { plaintext } = bob.manager.receiveMessage(envelope);
        expect(text(plaintext)).toBe("hello again");
    });

    it("resetSession on an unknown session throws UNKNOWN_SESSION", () => {
        const alice = makeParty(false);
        try {
            alice.manager.resetSession(provider.randomBytes(32));
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("UNKNOWN_SESSION");
        }
    });

    it("receiveSessionReset on an unknown session throws UNKNOWN_SESSION", () => {
        const bob = makeParty(false);
        const forged: SessionResetEnvelope = {
            type: "SESSION_RESET",
            protocolVersion: 1,
            sessionId: provider.randomBytes(32),
            signature: provider.randomBytes(64),
        };
        try {
            bob.manager.receiveSessionReset(forged);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("UNKNOWN_SESSION");
        }
    });

    it("rejects an unsupported protocol version before touching session state", () => {
        const { bob, aliceSession } = establishedPair();
        const forged: SessionResetEnvelope = {
            type: "SESSION_RESET",
            protocolVersion: 999,
            sessionId: aliceSession.sessionId,
            signature: provider.randomBytes(64),
        };
        try {
            bob.manager.receiveSessionReset(forged);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("UNSUPPORTED_VERSION");
        }
        expect(bob.manager.getSession(aliceSession.sessionId)).toBeDefined();
    });

    it("rejects a forged reset (wrong signature) and leaves the session intact", () => {
        const { bob, aliceSession } = establishedPair();
        const forged: SessionResetEnvelope = {
            type: "SESSION_RESET",
            protocolVersion: 1,
            sessionId: aliceSession.sessionId,
            signature: provider.randomBytes(64), // garbage, not a real Ed25519 signature over anything
        };

        try {
            bob.manager.receiveSessionReset(forged);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("INVALID_SIGNATURE");
        }
        // Failed authentication must not mutate state (same invariant as
        // AEAD failures elsewhere in this protocol) — the session is alive.
        expect(bob.manager.getSession(aliceSession.sessionId)).toBeDefined();
    });

    it("Mallory cannot forge a reset for Alice's session to Bob using her own identity key", () => {
        const { bob, aliceSession } = establishedPair();
        const mallory = makeParty(false);

        // Mallory signs a well-formed SESSION_RESET payload for Alice's
        // sessionId, but with her own identity key rather than Alice's.
        const signature = signSessionReset(
            provider,
            mallory.identity.keyPair.privateKey,
            1,
            aliceSession.sessionId,
        );
        const forged: SessionResetEnvelope = {
            type: "SESSION_RESET",
            protocolVersion: 1,
            sessionId: aliceSession.sessionId,
            signature,
        };

        expect(() => bob.manager.receiveSessionReset(forged)).toThrow(ProtocolError);
        expect(bob.manager.getSession(aliceSession.sessionId)).toBeDefined();
    });

    it("a session, once reset, cannot be reset again (already gone)", () => {
        const { alice, aliceSession } = establishedPair();
        alice.manager.resetSession(aliceSession.sessionId);
        expect(() => alice.manager.resetSession(aliceSession.sessionId)).toThrow(ProtocolError);
    });

    it("sendMessage on a reset session throws UNKNOWN_SESSION", () => {
        const { alice, aliceSession } = establishedPair();
        alice.manager.resetSession(aliceSession.sessionId);
        expect(() => alice.manager.sendMessage(aliceSession.sessionId, utf8("x"))).toThrow(ProtocolError);
    });
});
