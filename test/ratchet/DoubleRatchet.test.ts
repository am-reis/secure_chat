import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import {
    ratchetInitAlice,
    ratchetInitBob,
    ratchetEncrypt,
    ratchetDecrypt,
} from "../../src/ratchet/DoubleRatchet.js";
import { MAX_SKIP } from "../../src/ratchet/types.js";
import { ProtocolError } from "../../src/errors.js";
import type { DoubleRatchetState, RatchetHeader } from "../../src/ratchet/types.js";

const provider = new NobleCryptoProvider();
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const utf8 = (s: string) => new TextEncoder().encode(s);
const AD = utf8("shared-pqxdh-associated-data"); // stand-in for PQXDH's real AD in these standalone DR tests

function setupPair() {
    const sk = provider.randomBytes(32);
    const bobRatchetKeyPair = provider.generateX25519KeyPair();
    const alice = ratchetInitAlice(provider, sk, bobRatchetKeyPair.publicKey);
    const bob = ratchetInitBob(provider, sk, bobRatchetKeyPair);
    return { alice, bob };
}

/** Snapshot of the state fields relevant to the "no partial mutation on failure" invariant. */
function snapshot(state: DoubleRatchetState) {
    return {
        DHsPub: toHex(state.DHs.publicKey),
        DHr: state.DHr ? toHex(state.DHr) : null,
        rootKey: toHex(state.rootKey),
        sendingChainKey: state.sendingChainKey ? toHex(state.sendingChainKey) : null,
        receivingChainKey: state.receivingChainKey ? toHex(state.receivingChainKey) : null,
        Ns: state.sendingMessageNumber,
        Nr: state.receivingMessageNumber,
        PN: state.previousSendingChainLength,
        skippedKeys: [...state.skippedMessageKeys.entries()].map(([k, v]) => [k, toHex(v)]),
    };
}

describe("Double Ratchet — basic protocol correctness", () => {
    it("Bob cannot encrypt before receiving Alice's first message", () => {
        const { bob } = setupPair();
        expect(() => ratchetEncrypt(provider, bob, utf8("hi"), AD)).toThrow(ProtocolError);
    });

    it("REGRESSION: erasing sk immediately after ratchetInitBob does not corrupt the returned root key", () => {
        // ratchetInitAlice derives a fresh root key via KDF_RK, decoupled
        // from its `sk` input. ratchetInitBob's pseudocode is `state.RK =
        // SK` — a direct assignment that, without a defensive copy, would
        // alias the caller's buffer. A caller following normal key-hygiene
        // practice (erase secrets right after they're consumed) would then
        // silently zero out Bob's live root key.
        const sk = provider.randomBytes(32);
        const skHex = toHex(sk);
        const bobRatchetKeyPair = provider.generateX25519KeyPair();
        const bob = ratchetInitBob(provider, sk, bobRatchetKeyPair);
        provider.secureErase(sk);
        expect(toHex(bob.rootKey)).toBe(skHex);
        expect(bob.rootKey.every((b) => b === 0)).toBe(false);
    });

    it("REGRESSION: a shared SPK keypair reused across two independent sessions survives both sessions' first DH ratchet step intact", () => {
        // Bob's SPK (real spec §7.1) is reused across every concurrently-
        // establishing session — it is NOT a single-use ratchet key. Each
        // session's first DH ratchet step zeroizes the "old" DHs.privateKey
        // it's superseding (correct for an ordinary one-time ratchet key).
        // Without a defensive copy in ratchetInitBob, that erasure would
        // reach through to the SHARED SPK object, silently destroying it
        // for every other in-flight session the moment the first one
        // completes its own ratchet step.
        const sharedSpk = provider.generateX25519KeyPair();
        const spkPrivateHex = toHex(sharedSpk.privateKey);
        const spkPublicHex = toHex(sharedSpk.publicKey);

        const sessionASk = provider.randomBytes(32);
        const sessionBSk = provider.randomBytes(32);
        const bobForSessionA = ratchetInitBob(provider, sessionASk, sharedSpk);
        const bobForSessionB = ratchetInitBob(provider, sessionBSk, sharedSpk);

        // Simulate session A's first received message (any independent
        // Alice ephemeral key works here — this test only cares about what
        // happens to the shared SPK, not about a real handshake).
        const aliceA = ratchetInitAlice(provider, sessionASk, sharedSpk.publicKey);
        const msgA = ratchetEncrypt(provider, aliceA, utf8("A"), AD);
        const plaintextA = ratchetDecrypt(provider, bobForSessionA, msgA.header, msgA.ciphertext, AD);
        expect(new TextDecoder().decode(plaintextA)).toBe("A");

        // The shared SPK object itself must be completely untouched.
        expect(toHex(sharedSpk.privateKey)).toBe(spkPrivateHex);
        expect(toHex(sharedSpk.publicKey)).toBe(spkPublicHex);

        // Session B, started from the SAME shared SPK object, must still
        // work correctly after session A's ratchet step.
        const aliceB = ratchetInitAlice(provider, sessionBSk, sharedSpk.publicKey);
        const msgB = ratchetEncrypt(provider, aliceB, utf8("B"), AD);
        const plaintextB = ratchetDecrypt(provider, bobForSessionB, msgB.header, msgB.ciphertext, AD);
        expect(new TextDecoder().decode(plaintextB)).toBe("B");
    });

    it("round-trips a single message from Alice to Bob", () => {
        const { alice, bob } = setupPair();
        const { header, ciphertext } = ratchetEncrypt(provider, alice, utf8("hello bob"), AD);
        const plaintext = ratchetDecrypt(provider, bob, header, ciphertext, AD);
        expect(new TextDecoder().decode(plaintext)).toBe("hello bob");
    });

    it("after receiving Alice's first message, Bob can reply (DH ratchet completed)", () => {
        const { alice, bob } = setupPair();
        const msg1 = ratchetEncrypt(provider, alice, utf8("hi"), AD);
        ratchetDecrypt(provider, bob, msg1.header, msg1.ciphertext, AD);

        const reply = ratchetEncrypt(provider, bob, utf8("hi alice"), AD);
        const plaintext = ratchetDecrypt(provider, alice, reply.header, reply.ciphertext, AD);
        expect(new TextDecoder().decode(plaintext)).toBe("hi alice");
    });

    it("full ping-pong exchange over several DH ratchet steps", () => {
        const { alice, bob } = setupPair();

        const a1 = ratchetEncrypt(provider, alice, utf8("A1"), AD);
        expect(new TextDecoder().decode(ratchetDecrypt(provider, bob, a1.header, a1.ciphertext, AD))).toBe("A1");

        const b1 = ratchetEncrypt(provider, bob, utf8("B1"), AD);
        expect(new TextDecoder().decode(ratchetDecrypt(provider, alice, b1.header, b1.ciphertext, AD))).toBe("B1");

        const a2 = ratchetEncrypt(provider, alice, utf8("A2"), AD);
        expect(new TextDecoder().decode(ratchetDecrypt(provider, bob, a2.header, a2.ciphertext, AD))).toBe("A2");

        const b2 = ratchetEncrypt(provider, bob, utf8("B2"), AD);
        expect(new TextDecoder().decode(ratchetDecrypt(provider, alice, b2.header, b2.ciphertext, AD))).toBe("B2");

        const a3 = ratchetEncrypt(provider, alice, utf8("A3"), AD);
        expect(new TextDecoder().decode(ratchetDecrypt(provider, bob, a3.header, a3.ciphertext, AD))).toBe("A3");
    });

    it("each message gets a distinct ratchet public key advertised only when the DH ratchet actually steps", () => {
        const { alice, bob } = setupPair();
        const a1 = ratchetEncrypt(provider, alice, utf8("A1"), AD);
        ratchetDecrypt(provider, bob, a1.header, a1.ciphertext, AD);
        const a2 = ratchetEncrypt(provider, alice, utf8("A2"), AD); // same sending chain, no new DH step
        expect(toHex(a2.header.ratchetPublicKey)).toBe(toHex(a1.header.ratchetPublicKey));
    });
});

describe("Double Ratchet — out-of-order and skipped messages (Phase 8)", () => {
    it("messages received out of order all decrypt correctly via the skipped-key store", () => {
        const { alice, bob } = setupPair();
        const m0 = ratchetEncrypt(provider, alice, utf8("msg0"), AD);
        const m1 = ratchetEncrypt(provider, alice, utf8("msg1"), AD);
        const m2 = ratchetEncrypt(provider, alice, utf8("msg2"), AD);

        // Bob receives them out of order: 2, 0, 1
        const p2 = ratchetDecrypt(provider, bob, m2.header, m2.ciphertext, AD);
        expect(new TextDecoder().decode(p2)).toBe("msg2");
        expect(bob.skippedMessageKeys.size).toBe(2); // msg0, msg1 skipped and stored

        const p0 = ratchetDecrypt(provider, bob, m0.header, m0.ciphertext, AD);
        expect(new TextDecoder().decode(p0)).toBe("msg0");
        expect(bob.skippedMessageKeys.size).toBe(1);

        const p1 = ratchetDecrypt(provider, bob, m1.header, m1.ciphertext, AD);
        expect(new TextDecoder().decode(p1)).toBe("msg1");
        expect(bob.skippedMessageKeys.size).toBe(0);
    });

    it("a skipped message that never arrives leaves a permanently stored key without blocking later messages", () => {
        const { alice, bob } = setupPair();
        const m0 = ratchetEncrypt(provider, alice, utf8("lost"), AD);
        const m1 = ratchetEncrypt(provider, alice, utf8("delivered"), AD);
        void m0; // simulate m0 being lost — never delivered to Bob

        const plaintext = ratchetDecrypt(provider, bob, m1.header, m1.ciphertext, AD);
        expect(new TextDecoder().decode(plaintext)).toBe("delivered");
        expect(bob.skippedMessageKeys.size).toBe(1); // m0's key still stored, in case it arrives later
    });

    it("skips correctly across a DH ratchet boundary (Bob's DR spec example scenario)", () => {
        const { alice, bob } = setupPair();

        // A1 -> B receives
        const a1 = ratchetEncrypt(provider, alice, utf8("A1"), AD);
        ratchetDecrypt(provider, bob, a1.header, a1.ciphertext, AD);

        // B1 -> A receives (triggers Alice's DH ratchet)
        const b1 = ratchetEncrypt(provider, bob, utf8("B1"), AD);
        ratchetDecrypt(provider, alice, b1.header, b1.ciphertext, AD);

        // Bob sends B2, B3, B4 (same sending chain from B1)
        const b2 = ratchetEncrypt(provider, bob, utf8("B2"), AD);
        const b3 = ratchetEncrypt(provider, bob, utf8("B3"), AD);
        const b4 = ratchetEncrypt(provider, bob, utf8("B4"), AD);

        // Alice receives B4 directly, skipping B2 and B3 in the process.
        const p4 = ratchetDecrypt(provider, alice, b4.header, b4.ciphertext, AD);
        expect(new TextDecoder().decode(p4)).toBe("B4");
        expect(alice.skippedMessageKeys.size).toBe(2);

        // B2 and B3 arrive later and still decrypt correctly.
        expect(new TextDecoder().decode(ratchetDecrypt(provider, alice, b2.header, b2.ciphertext, AD))).toBe("B2");
        expect(new TextDecoder().decode(ratchetDecrypt(provider, alice, b3.header, b3.ciphertext, AD))).toBe("B3");
        expect(alice.skippedMessageKeys.size).toBe(0);
    });

    it("rejects a message that skips further than MAX_SKIP", () => {
        const { alice, bob } = setupPair();
        const a1 = ratchetEncrypt(provider, alice, utf8("A1"), AD);
        ratchetDecrypt(provider, bob, a1.header, a1.ciphertext, AD);

        const forgedHeader: RatchetHeader = {
            ratchetPublicKey: a1.header.ratchetPublicKey,
            previousChainLength: 0,
            messageNumber: MAX_SKIP + 500,
        };
        try {
            ratchetDecrypt(provider, bob, forgedHeader, new Uint8Array(32), AD);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("MESSAGE_TOO_FAR_AHEAD");
        }
    });
});

describe("Double Ratchet — Invariant 4: failed AEAD auth never mutates state", () => {
    it("a tampered ciphertext fails without changing any state field (simple case, no DH ratchet)", () => {
        const { alice, bob } = setupPair();
        const a1 = ratchetEncrypt(provider, alice, utf8("A1"), AD);
        ratchetDecrypt(provider, bob, a1.header, a1.ciphertext, AD); // establish Bob's receiving chain

        const a2 = ratchetEncrypt(provider, alice, utf8("A2"), AD);
        const tampered = a2.ciphertext.slice();
        tampered[tampered.length - 1]! ^= 0xff;

        const before = snapshot(bob);
        expect(() => ratchetDecrypt(provider, bob, a2.header, tampered, AD)).toThrow(ProtocolError);
        expect(snapshot(bob)).toEqual(before);
    });

    it("a tampered ciphertext fails without changing state even when it would have triggered a DH ratchet", () => {
        const { alice, bob } = setupPair();
        const a1 = ratchetEncrypt(provider, alice, utf8("A1"), AD);
        ratchetDecrypt(provider, bob, a1.header, a1.ciphertext, AD);
        const b1 = ratchetEncrypt(provider, bob, utf8("B1"), AD);
        ratchetDecrypt(provider, alice, b1.header, b1.ciphertext, AD);

        // Alice sends A2 on a NEW ratchet key (post-DH-ratchet); tamper with it before Bob sees it.
        const a2 = ratchetEncrypt(provider, alice, utf8("A2"), AD);
        const tampered = a2.ciphertext.slice();
        tampered[0]! ^= 0xff;

        const before = snapshot(bob);
        expect(() => ratchetDecrypt(provider, bob, a2.header, tampered, AD)).toThrow(ProtocolError);
        expect(snapshot(bob)).toEqual(before); // DHr, rootKey, receivingChainKey must be exactly as before the attempt
    });

    it("a tampered header (message number) fails without changing state", () => {
        const { alice, bob } = setupPair();
        const a1 = ratchetEncrypt(provider, alice, utf8("A1"), AD);
        ratchetDecrypt(provider, bob, a1.header, a1.ciphertext, AD);

        const a2 = ratchetEncrypt(provider, alice, utf8("A2"), AD);
        const tamperedHeader: RatchetHeader = { ...a2.header, messageNumber: a2.header.messageNumber + 5 };

        const before = snapshot(bob);
        expect(() => ratchetDecrypt(provider, bob, tamperedHeader, a2.ciphertext, AD)).toThrow(ProtocolError);
        expect(snapshot(bob)).toEqual(before);
    });

    it("a message encrypted under different AD fails without changing state", () => {
        const { alice, bob } = setupPair();
        const a1 = ratchetEncrypt(provider, alice, utf8("A1"), AD);
        ratchetDecrypt(provider, bob, a1.header, a1.ciphertext, AD);

        const a2 = ratchetEncrypt(provider, alice, utf8("A2"), AD);
        const wrongAD = utf8("wrong-associated-data");

        const before = snapshot(bob);
        expect(() => ratchetDecrypt(provider, bob, a2.header, a2.ciphertext, wrongAD)).toThrow(ProtocolError);
        expect(snapshot(bob)).toEqual(before);
    });

    it("a forged ratchet public key from an unrelated keypair fails without changing state", () => {
        const { alice, bob } = setupPair();
        const a1 = ratchetEncrypt(provider, alice, utf8("A1"), AD);
        ratchetDecrypt(provider, bob, a1.header, a1.ciphertext, AD);

        const attacker = provider.generateX25519KeyPair();
        const forgedHeader: RatchetHeader = {
            ratchetPublicKey: attacker.publicKey,
            previousChainLength: 0,
            messageNumber: 0,
        };

        const before = snapshot(bob);
        expect(() => ratchetDecrypt(provider, bob, forgedHeader, new Uint8Array(48), AD)).toThrow();
        expect(snapshot(bob)).toEqual(before);
    });

    it("a replayed (already-consumed) message fails without changing state", () => {
        const { alice, bob } = setupPair();
        const a1 = ratchetEncrypt(provider, alice, utf8("A1"), AD);
        ratchetDecrypt(provider, bob, a1.header, a1.ciphertext, AD);

        const a2 = ratchetEncrypt(provider, alice, utf8("A2"), AD);
        ratchetDecrypt(provider, bob, a2.header, a2.ciphertext, AD); // consume it once, legitimately

        const before = snapshot(bob);
        expect(() => ratchetDecrypt(provider, bob, a2.header, a2.ciphertext, AD)).toThrow(ProtocolError);
        expect(snapshot(bob)).toEqual(before);
    });

    it("replaying a skipped-and-since-consumed message fails without changing state", () => {
        const { alice, bob } = setupPair();
        const m0 = ratchetEncrypt(provider, alice, utf8("m0"), AD);
        const m1 = ratchetEncrypt(provider, alice, utf8("m1"), AD);
        ratchetDecrypt(provider, bob, m1.header, m1.ciphertext, AD); // skips m0
        ratchetDecrypt(provider, bob, m0.header, m0.ciphertext, AD); // consumes the skipped key for m0

        const before = snapshot(bob);
        expect(() => ratchetDecrypt(provider, bob, m0.header, m0.ciphertext, AD)).toThrow(ProtocolError);
        expect(snapshot(bob)).toEqual(before);
    });
});

describe("Double Ratchet — message key uniqueness (Invariant 1)", () => {
    it("consecutive messages on the same chain produce different ciphertexts for the same plaintext", () => {
        const { alice } = setupPair();
        const m1 = ratchetEncrypt(provider, alice, utf8("same plaintext"), AD);
        const m2 = ratchetEncrypt(provider, alice, utf8("same plaintext"), AD);
        expect(toHex(m1.ciphertext)).not.toBe(toHex(m2.ciphertext));
    });
});
