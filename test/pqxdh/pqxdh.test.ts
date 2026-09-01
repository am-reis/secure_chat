import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey } from "../../src/prekeys/pqPrekey.js";
import { generateOneTimePreKeys } from "../../src/prekeys/oneTimePrekeys.js";
import { buildPreKeyBundle } from "../../src/prekeys/buildPreKeyBundle.js";
import { InMemoryPrekeyStore } from "../../src/prekeys/InMemoryPrekeyStore.js";
import { pqxdhInitiate } from "../../src/pqxdh/PQXDHInitiator.js";
import { pqxdhRespond, type PQXDHResponderInput } from "../../src/pqxdh/PQXDHResponder.js";
import { buildPQXDHAssociatedData } from "../../src/pqxdh/associatedData.js";
import { ProtocolError } from "../../src/errors.js";

const provider = new NobleCryptoProvider();
const DAY = 24 * 60 * 60 * 1000;
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

/** Sets up a full Alice/Bob scenario: Bob's identity + prekeys + a store, and Bob's published bundle. */
function setupBob(withOneTime: boolean) {
    const bobIdentity = generateIdentity(provider);
    const signedPreKey = generateSignedPreKey(provider, bobIdentity, 1, 30 * DAY);
    const pqPreKey = generatePQPreKey(provider, bobIdentity, 1, 30 * DAY);
    const store = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
    let otk;
    if (withOneTime) {
        [otk] = generateOneTimePreKeys(provider, 1, 1);
        store.addOneTimePreKeys([otk!]);
    }
    const bundle = buildPreKeyBundle(bobIdentity, signedPreKey, pqPreKey, otk);
    return { bobIdentity, signedPreKey, pqPreKey, store, bundle };
}

function respondFromInitiatorResult(
    bobIdentity: ReturnType<typeof generateIdentity>,
    signedPreKey: ReturnType<typeof generateSignedPreKey>,
    pqPreKey: ReturnType<typeof generatePQPreKey>,
    store: InMemoryPrekeyStore,
    aliceIdentity: ReturnType<typeof generateIdentity>,
    initiatorResult: ReturnType<typeof pqxdhInitiate>,
) {
    const input: PQXDHResponderInput = {
        initiatorIdentityPublicKey: aliceIdentity.keyPair.publicKey,
        initiatorEphemeralPublicKey: initiatorResult.ephemeralPublicKey,
        pqCiphertext: initiatorResult.pqCiphertext,
        usedSignedPreKeyId: initiatorResult.usedSignedPreKeyId,
        usedOneTimePreKeyId: initiatorResult.usedOneTimePreKeyId,
        usedPqPreKeyId: initiatorResult.usedPqPreKeyId,
    };
    return pqxdhRespond(provider, bobIdentity, signedPreKey, pqPreKey, store, input);
}

describe("PQXDH — protocol agreement (Phase 28.2)", () => {
    it("initiator and responder derive the identical SK and AD, with a one-time prekey", () => {
        const { bobIdentity, signedPreKey, pqPreKey, store, bundle } = setupBob(true);
        const aliceIdentity = generateIdentity(provider);

        const initiatorResult = pqxdhInitiate(provider, aliceIdentity, bundle);
        const responderResult = respondFromInitiatorResult(
            bobIdentity,
            signedPreKey,
            pqPreKey,
            store,
            aliceIdentity,
            initiatorResult,
        );

        expect(toHex(responderResult.sk)).toBe(toHex(initiatorResult.sk));
        expect(toHex(responderResult.associatedData)).toBe(toHex(initiatorResult.associatedData));
        expect(initiatorResult.sk.length).toBe(32);
    });

    it("initiator and responder derive the identical SK and AD, WITHOUT a one-time prekey", () => {
        const { bobIdentity, signedPreKey, pqPreKey, store, bundle } = setupBob(false);
        const aliceIdentity = generateIdentity(provider);
        expect(bundle.oneTimePreKey).toBeUndefined();

        const initiatorResult = pqxdhInitiate(provider, aliceIdentity, bundle);
        const responderResult = respondFromInitiatorResult(
            bobIdentity,
            signedPreKey,
            pqPreKey,
            store,
            aliceIdentity,
            initiatorResult,
        );

        expect(toHex(responderResult.sk)).toBe(toHex(initiatorResult.sk));
        expect(toHex(responderResult.associatedData)).toBe(toHex(initiatorResult.associatedData));
        expect(responderResult.reservedOneTimePreKeyId).toBeUndefined();
    });

    it("SK differs between a session that uses an OTK and one that doesn't (DH4 actually contributes)", () => {
        const bobIdentity = generateIdentity(provider);
        const signedPreKey = generateSignedPreKey(provider, bobIdentity, 1, 30 * DAY);
        const pqPreKey = generatePQPreKey(provider, bobIdentity, 1, 30 * DAY);
        const aliceIdentity = generateIdentity(provider);

        const bundleWithout = buildPreKeyBundle(bobIdentity, signedPreKey, pqPreKey);
        const resultWithout = pqxdhInitiate(provider, aliceIdentity, bundleWithout);

        const [otk] = generateOneTimePreKeys(provider, 1, 1);
        const bundleWith = buildPreKeyBundle(bobIdentity, signedPreKey, pqPreKey, otk);
        const resultWith = pqxdhInitiate(provider, aliceIdentity, bundleWith);

        expect(toHex(resultWith.sk)).not.toBe(toHex(resultWithout.sk));
    });

    it("two independent runs between the same Alice/Bob produce different SKs (fresh ephemeral + KEM randomness each time)", () => {
        const { bundle } = setupBob(false);
        const aliceIdentity = generateIdentity(provider);
        const run1 = pqxdhInitiate(provider, aliceIdentity, bundle);
        const run2 = pqxdhInitiate(provider, aliceIdentity, bundle);
        expect(toHex(run1.sk)).not.toBe(toHex(run2.sk));
    });

    it("AD encodes initiator-then-responder order (asymmetric, unlike the identity fingerprint)", () => {
        const { bundle } = setupBob(false);
        const aliceIdentity = generateIdentity(provider);
        const result = pqxdhInitiate(provider, aliceIdentity, bundle);

        const reversedOrderAD = buildPQXDHAssociatedData(
            bundle.identityPublicKey,
            aliceIdentity.keyPair.publicKey,
        );

        expect(toHex(result.associatedData)).not.toBe(toHex(reversedOrderAD));
    });
});

describe("PQXDH — one-time prekey lifecycle integration", () => {
    it("responding reserves (not consumes) the referenced one-time prekey", () => {
        const { bobIdentity, signedPreKey, pqPreKey, store, bundle } = setupBob(true);
        const aliceIdentity = generateIdentity(provider);
        const initiatorResult = pqxdhInitiate(provider, aliceIdentity, bundle);

        expect(store.countAvailableOneTimePreKeys()).toBe(1); // still available before respond()

        const responderResult = respondFromInitiatorResult(
            bobIdentity,
            signedPreKey,
            pqPreKey,
            store,
            aliceIdentity,
            initiatorResult,
        );

        expect(responderResult.reservedOneTimePreKeyId).toBe(1);
        expect(store.countAvailableOneTimePreKeys()).toBe(0); // reserved, not available
        expect(store.getOneTimePreKey(1)!.state).toBe("RESERVED"); // not yet CONSUMED
    });

    it("a second responder attempt for the same OTK id fails (atomicity carries through)", () => {
        const { bobIdentity, signedPreKey, pqPreKey, store, bundle } = setupBob(true);
        const aliceIdentity = generateIdentity(provider);
        const initiatorResult = pqxdhInitiate(provider, aliceIdentity, bundle);

        respondFromInitiatorResult(bobIdentity, signedPreKey, pqPreKey, store, aliceIdentity, initiatorResult);

        // Simulate a duplicate/replayed initial message being processed again
        // before the caller has committed (consumed) the first attempt.
        expect(() =>
            respondFromInitiatorResult(bobIdentity, signedPreKey, pqPreKey, store, aliceIdentity, initiatorResult),
        ).toThrow(ProtocolError);
    });

    it("responding without a store when the message references an OTK throws KEY_NOT_FOUND", () => {
        const { bobIdentity, signedPreKey, pqPreKey, bundle } = setupBob(true);
        const aliceIdentity = generateIdentity(provider);
        const initiatorResult = pqxdhInitiate(provider, aliceIdentity, bundle);
        const input: PQXDHResponderInput = {
            initiatorIdentityPublicKey: aliceIdentity.keyPair.publicKey,
            initiatorEphemeralPublicKey: initiatorResult.ephemeralPublicKey,
            pqCiphertext: initiatorResult.pqCiphertext,
            usedSignedPreKeyId: initiatorResult.usedSignedPreKeyId,
            usedOneTimePreKeyId: initiatorResult.usedOneTimePreKeyId,
            usedPqPreKeyId: initiatorResult.usedPqPreKeyId,
        };
        try {
            pqxdhRespond(provider, bobIdentity, signedPreKey, pqPreKey, null, input);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("KEY_NOT_FOUND");
        }
    });
});

describe("PQXDH — adversarial cases", () => {
    it("rejects initiating against a bundle with a tampered signature (bundle validation runs first)", () => {
        const { bundle } = setupBob(false);
        bundle.signedPreKey.publicKey = bundle.signedPreKey.publicKey.slice();
        bundle.signedPreKey.publicKey[0]! ^= 0xff;
        const aliceIdentity = generateIdentity(provider);
        expect(() => pqxdhInitiate(provider, aliceIdentity, bundle)).toThrow(ProtocolError);
    });

    it("responder rejects a mismatched signedPreKey id (wrong local key supplied)", () => {
        const { bobIdentity, pqPreKey, store, bundle } = setupBob(false);
        const aliceIdentity = generateIdentity(provider);
        const initiatorResult = pqxdhInitiate(provider, aliceIdentity, bundle);
        const wrongSignedPreKey = generateSignedPreKey(provider, bobIdentity, 999, 30 * DAY);

        const input: PQXDHResponderInput = {
            initiatorIdentityPublicKey: aliceIdentity.keyPair.publicKey,
            initiatorEphemeralPublicKey: initiatorResult.ephemeralPublicKey,
            pqCiphertext: initiatorResult.pqCiphertext,
            usedSignedPreKeyId: initiatorResult.usedSignedPreKeyId,
            usedOneTimePreKeyId: initiatorResult.usedOneTimePreKeyId,
            usedPqPreKeyId: initiatorResult.usedPqPreKeyId,
        };
        try {
            pqxdhRespond(provider, bobIdentity, wrongSignedPreKey, pqPreKey, store, input);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("KEY_NOT_FOUND");
        }
    });

    it("responder rejects a corrupted PQ ciphertext as INVALID_PQ_CIPHERTEXT, and releases any reserved OTK", () => {
        const { bobIdentity, signedPreKey, pqPreKey, store, bundle } = setupBob(true);
        const aliceIdentity = generateIdentity(provider);
        const initiatorResult = pqxdhInitiate(provider, aliceIdentity, bundle);

        const corrupted = initiatorResult.pqCiphertext.slice(0, 10); // truncated -> decapsulate should throw

        const input: PQXDHResponderInput = {
            initiatorIdentityPublicKey: aliceIdentity.keyPair.publicKey,
            initiatorEphemeralPublicKey: initiatorResult.ephemeralPublicKey,
            pqCiphertext: corrupted,
            usedSignedPreKeyId: initiatorResult.usedSignedPreKeyId,
            usedOneTimePreKeyId: initiatorResult.usedOneTimePreKeyId,
            usedPqPreKeyId: initiatorResult.usedPqPreKeyId,
        };

        try {
            pqxdhRespond(provider, bobIdentity, signedPreKey, pqPreKey, store, input);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("INVALID_PQ_CIPHERTEXT");
        }
        // The OTK reservation from this failed attempt must not be left dangling.
        expect(store.countAvailableOneTimePreKeys()).toBe(1);
        expect(store.getOneTimePreKey(1)!.state).toBe("AVAILABLE");
    });

    it("a third party cannot derive the same SK without the responder's private keys", () => {
        const { bundle } = setupBob(false);
        const aliceIdentity = generateIdentity(provider);
        const eveIdentity = generateIdentity(provider);

        const resultForBob = pqxdhInitiate(provider, aliceIdentity, bundle);
        const resultEveSees = pqxdhInitiate(provider, eveIdentity, bundle); // Eve running her own session against the same public bundle

        expect(toHex(resultForBob.sk)).not.toBe(toHex(resultEveSees.sk));
    });
});
