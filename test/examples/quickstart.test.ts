import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey } from "../../src/prekeys/pqPrekey.js";
import { generateOneTimePreKeys } from "../../src/prekeys/oneTimePrekeys.js";
import { buildPreKeyBundle } from "../../src/prekeys/buildPreKeyBundle.js";
import { InMemoryPrekeyStore } from "../../src/prekeys/InMemoryPrekeyStore.js";
import { SessionManager, type LocalPrekeyLookup } from "../../src/session/SessionManager.js";
import type { SignedPreKey, PQPreKey } from "../../src/prekeys/types.js";

/**
 * This file is not just a test — it's the literal source of the code shown
 * in docs/getting-started.md. Kept here, exercised by `npm test`, so the
 * guide can never silently drift out of sync with the real API the way a
 * markdown-only snippet could. If you're reading the guide and want to
 * run it yourself, this is exactly what runs.
 */
describe("Getting started — a minimal two-party, in-memory chat", () => {
    it("Alice and Bob establish a session and exchange messages", () => {
        const provider = new NobleCryptoProvider();
        const utf8 = (s: string) => new TextEncoder().encode(s);
        const text = (b: Uint8Array) => new TextDecoder().decode(b);
        const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;

        // --- Bob sets up his identity and publishes a prekey bundle ---
        //
        // A real app needs its own way to get this bundle from Bob to
        // Alice (a server, a QR code, Waku — see docs/integration-guide.md's
        // "what you build yourself" section). This library only covers
        // everything from "Alice already has the bundle" onward.
        const bobIdentity = generateIdentity(provider);
        const bobSignedPreKey = generateSignedPreKey(provider, bobIdentity, /* id */ 1, THIRTY_DAYS);
        const bobPqPreKey = generatePQPreKey(provider, bobIdentity, /* id */ 1, THIRTY_DAYS);
        const [bobOneTimePreKey] = generateOneTimePreKeys(provider, /* startId */ 1, /* count */ 1);

        const bobOneTimePreKeyStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
        bobOneTimePreKeyStore.addOneTimePreKeys([bobOneTimePreKey!]);

        const bobBundle = buildPreKeyBundle(bobIdentity, bobSignedPreKey, bobPqPreKey, bobOneTimePreKey);

        // SessionManager needs to look up Bob's OWN signed/PQ prekeys by id
        // when a SESSION_INIT arrives referencing them — a simple Map-backed
        // lookup is enough for a single-identity app; a real deployment
        // might back this with a real store instead.
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
        const bobPrekeyLookup = new MapPrekeyLookup();
        bobPrekeyLookup.addSignedPreKey(bobSignedPreKey);
        bobPrekeyLookup.addPQPreKey(bobPqPreKey);

        const bobManager = new SessionManager(provider, bobIdentity, bobOneTimePreKeyStore, bobPrekeyLookup);

        // --- Alice sets up her identity ---
        //
        // Alice doesn't need her own prekeys to START a conversation — those
        // are only needed by whoever is on the RECEIVING end of a fresh
        // SESSION_INIT. She'd still generate her own bundle so others can
        // start conversations with HER.
        const aliceIdentity = generateIdentity(provider);
        const aliceOneTimePreKeyStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
        const alicePrekeyLookup = new MapPrekeyLookup(); // empty: Alice isn't receiving a SESSION_INIT in this example
        const aliceManager = new SessionManager(provider, aliceIdentity, aliceOneTimePreKeyStore, alicePrekeyLookup);

        // --- Alice establishes a session with Bob and sends the first message ---
        //
        // createSession runs the full PQXDH handshake AND encrypts the
        // first message in one call — there's no separate "connect" step.
        const { session: aliceSession, envelope: sessionInit } = aliceManager.createSession(
            bobBundle,
            utf8("hi bob, this is alice"),
        );

        // --- Bob receives it ---
        //
        // receiveMessage recognizes this is a SESSION_INIT for a session it
        // doesn't know yet, runs the responder side of PQXDH, and decrypts
        // the first message — also in one call.
        const { session: bobSession, plaintext: bobReceived } = bobManager.receiveMessage(sessionInit);
        expect(text(bobReceived)).toBe("hi bob, this is alice");

        // Both sides now agree on the session id and its associated data —
        // this is what "the session is established" means concretely.
        expect(bobSession.sessionId).toEqual(aliceSession.sessionId);
        expect(bobSession.associatedData).toEqual(aliceSession.associatedData);

        // --- Ordinary messages after that, in either direction ---
        const bobReply = bobManager.sendMessage(sessionInit.sessionId, utf8("hi alice, bob here"));
        const { plaintext: aliceReceived } = aliceManager.receiveMessage(bobReply);
        expect(text(aliceReceived)).toBe("hi alice, bob here");

        const aliceSecondMessage = aliceManager.sendMessage(aliceSession.sessionId, utf8("how are you?"));
        const { plaintext: bobReceivedSecond } = bobManager.receiveMessage(aliceSecondMessage);
        expect(text(bobReceivedSecond)).toBe("how are you?");
    });
});
