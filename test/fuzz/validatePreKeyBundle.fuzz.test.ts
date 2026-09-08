import { describe, it, expect } from "vitest";
import fc from "fast-check";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey } from "../../src/prekeys/pqPrekey.js";
import { generateOneTimePreKeys } from "../../src/prekeys/oneTimePrekeys.js";
import { buildPreKeyBundle } from "../../src/prekeys/buildPreKeyBundle.js";
import { validatePreKeyBundle } from "../../src/prekeys/validateBundle.js";
import { InMemoryPrekeyStore } from "../../src/prekeys/InMemoryPrekeyStore.js";
import { SessionManager, type LocalPrekeyLookup } from "../../src/session/SessionManager.js";
import { ProtocolError } from "../../src/errors.js";
import type { PreKeyBundle } from "../../src/prekeys/PreKeyBundle.js";
import type { SignedPreKey, PQPreKey } from "../../src/prekeys/types.js";

const provider = new NobleCryptoProvider();
const DAY = 24 * 60 * 60 * 1000;

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
    const [otk] = generateOneTimePreKeys(provider, 1, 1);
    otkStore.addOneTimePreKeys([otk!]);
    const bundle = buildPreKeyBundle(identity, signedPreKey, pqPreKey, otk);
    const manager = new SessionManager(provider, identity, otkStore, lookup);
    return { identity, bundle, manager, otkStore };
}

function makeValidBundle(): PreKeyBundle {
    const identity = generateIdentity(provider);
    const spk = generateSignedPreKey(provider, identity, 1, 30 * DAY);
    const pqk = generatePQPreKey(provider, identity, 1, 30 * DAY);
    const otk = generateOneTimePreKeys(provider, 1, 1)[0];
    return buildPreKeyBundle(identity, spk, pqk, otk);
}

/** Deep-clone a bundle so mutating the clone never touches the original fixture. */
function cloneBundle(bundle: PreKeyBundle): PreKeyBundle {
    return {
        protocolVersion: bundle.protocolVersion,
        identityPublicKey: bundle.identityPublicKey.slice(),
        signedPreKey: { ...bundle.signedPreKey, publicKey: bundle.signedPreKey.publicKey.slice(), signature: bundle.signedPreKey.signature.slice() },
        oneTimePreKey: bundle.oneTimePreKey
            ? { ...bundle.oneTimePreKey, publicKey: bundle.oneTimePreKey.publicKey.slice() }
            : undefined,
        pqPreKey: { ...bundle.pqPreKey, publicKey: bundle.pqPreKey.publicKey.slice(), signature: bundle.pqPreKey.signature.slice() },
    };
}

// Deliberately excludes "oneTimePreKey.publicKey" — see the dedicated
// describe block below for why that field is NOT expected to be rejected
// by validatePreKeyBundle, and what actually protects it instead.
const signedByteField = fc.constantFrom(
    "identityPublicKey",
    "signedPreKey.publicKey",
    "signedPreKey.signature",
    "pqPreKey.publicKey",
    "pqPreKey.signature",
) satisfies fc.Arbitrary<string>;

function corruptByteField(bundle: PreKeyBundle, field: string, byteIndex: number, xorMask: number): void {
    const target =
        field === "identityPublicKey"
            ? bundle.identityPublicKey
            : field === "signedPreKey.publicKey"
              ? bundle.signedPreKey.publicKey
              : field === "signedPreKey.signature"
                ? bundle.signedPreKey.signature
                : field === "pqPreKey.publicKey"
                  ? bundle.pqPreKey.publicKey
                  : field === "pqPreKey.signature"
                    ? bundle.pqPreKey.signature
                    : bundle.oneTimePreKey?.publicKey;
    if (!target || target.length === 0) return;
    target[byteIndex % target.length]! ^= xorMask || 1;
}

/**
 * Fuzzing the prekey bundle validation pipeline (Phase 4/28.3): a
 * bundle is exactly the kind of structured, attacker-controlled input a
 * malicious or compromised prekey server could serve. Rather than the
 * handful of hand-picked single-field-tampered cases in
 * preKeyBundle.test.ts, this randomly corrupts a random byte in a random
 * field across many trials and checks one property: `validatePreKeyBundle`
 * only ever succeeds silently or throws a classified `ProtocolError` — a
 * single flipped bit anywhere must never be silently accepted, and nothing
 * should escape as an unclassified exception.
 */
describe("Fuzz: validatePreKeyBundle on randomly corrupted bundles", () => {
    it(
        "a single corrupted byte in any SIGNED key/signature field is always rejected with a classified ProtocolError",
        () => {
            // Each run generates a fresh identity + signed/PQ prekey pair
            // (ML-KEM-1024 keygen is the costly part), so numRuns is kept
            // modest and the test given explicit headroom over vitest's
            // default 5s timeout — under full-suite parallel load this
            // reliably takes longer than it does in isolation.
            fc.assert(
                fc.property(
                    signedByteField,
                    fc.integer({ min: 0, max: 1567 }),
                    fc.integer({ min: 1, max: 255 }),
                    (field, byteIndex, xorMask) => {
                        const bundle = cloneBundle(makeValidBundle());
                        corruptByteField(bundle, field, byteIndex, xorMask);
                        try {
                            validatePreKeyBundle(provider, bundle);
                            // Only acceptable if the corruption happened to
                            // land past the field's actual length and get
                            // modulo'd back to a byte XORed with a mask
                            // that... never actually happens given
                            // corruptByteField always flips a real byte in
                            // range — so reaching here is a genuine bypass.
                            return false;
                        } catch (e) {
                            return e instanceof ProtocolError;
                        }
                    },
                ),
                { numRuns: 150 },
            );
        },
        20_000,
    );

    it("a mutated protocolVersion is always rejected with a classified ProtocolError", () => {
        fc.assert(
            fc.property(fc.integer({ min: -1000, max: 1000 }).filter((v) => v !== 1), (badVersion) => {
                const bundle = cloneBundle(makeValidBundle());
                bundle.protocolVersion = badVersion;
                try {
                    validatePreKeyBundle(provider, bundle);
                    return false;
                } catch (e) {
                    return e instanceof ProtocolError;
                }
            }),
            { numRuns: 200 },
        );
    });

    it("mutated ids (negative, non-integer, unsafe) are always rejected with a classified ProtocolError", () => {
        fc.assert(
            fc.property(fc.oneof(fc.integer({ max: -1 }), fc.float().filter((f) => !Number.isInteger(f))), (badId) => {
                const bundle = cloneBundle(makeValidBundle());
                bundle.signedPreKey.id = badId;
                try {
                    validatePreKeyBundle(provider, bundle);
                    return false;
                } catch (e) {
                    return e instanceof ProtocolError;
                }
            }),
            { numRuns: 200 },
        );
    });

    it("sanity check: the unmodified fixture always validates (fuzz harness isn't accidentally testing against a broken fixture)", () => {
        for (let i = 0; i < 20; i++) {
            expect(() => validatePreKeyBundle(provider, makeValidBundle())).not.toThrow();
        }
    });
});

/**
 * FINDING from the fuzz run above: corrupting `oneTimePreKey.publicKey`
 * (unlike every other key/signature field) is NOT caught by
 * `validatePreKeyBundle`. This is by design, not a gap to fix here —
 * `PreKeyBundle`'s wire shape (see PreKeyBundle.ts) never carries a
 * signature over the one-time prekey at all, matching real X3DH/PQXDH
 * bundle formats where OPKs are one-time, individually unsigned, and
 * their compromise is bounded by that. `validateKeyLengths`/
 * `validateKeyEncodings` still catch a wrong-length or all-zero OTK — what
 * they cannot catch is "a different-but-otherwise-well-formed" 32 bytes,
 * because there is no signature to check it against at this layer.
 *
 * What actually protects it: PQXDH's DH4 = DH(EK_A, OPK_B) (see the
 * PQXDHInitiator.ts/PQXDHResponder.ts doc comments). Alice computes DH4
 * using whatever public key was in the bundle; Bob computes his mirror of
 * DH4 using his own stored PRIVATE key for that OTK id, never Alice's
 * bundle bytes. A corrupted OTK public key makes Alice's DH4 diverge from
 * Bob's, so the derived SK diverges, so Bob's AEAD decrypt of the initial
 * message fails — the same "no partial state on a failed initial message"
 * path already covered in SessionManager.test.ts's Phase 5.3 tests. This
 * test proves that chain end to end instead of just asserting it in prose.
 */
describe("Fuzz: a corrupted one-time prekey — not caught by validatePreKeyBundle, but never leads to a wrongly-established session", () => {
    it("validatePreKeyBundle accepts a bundle with a corrupted (but well-formed) OTK public key", () => {
        const bob = makeParty();
        const bundle = cloneBundle(bob.bundle);
        corruptByteField(bundle, "oneTimePreKey.publicKey", 0, 1);
        expect(() => validatePreKeyBundle(provider, bundle)).not.toThrow();
    });

    it(
        "...but Alice establishing a session against that corrupted bundle always fails on Bob's side, with no session left registered and the OTK released back to AVAILABLE",
        () => {
            fc.assert(
                fc.property(fc.integer({ min: 0, max: 31 }), fc.integer({ min: 1, max: 255 }), (byteIndex, xorMask) => {
                    const alice = makeParty();
                    const bob = makeParty();
                    const corruptedBundle = cloneBundle(bob.bundle);
                    corruptByteField(corruptedBundle, "oneTimePreKey.publicKey", byteIndex, xorMask);

                    const { envelope } = alice.manager.createSession(corruptedBundle, new Uint8Array([1, 2, 3]));
                    try {
                        bob.manager.receiveMessage(envelope);
                        return false; // must never succeed — SK diverged on the two sides
                    } catch (e) {
                        if (!(e instanceof ProtocolError)) return false;
                        if (bob.manager.getSession(envelope.sessionId) !== undefined) return false;
                        if (bob.otkStore.getOneTimePreKey(1)?.state !== "AVAILABLE") return false;
                        return true;
                    }
                }),
                { numRuns: 60 },
            );
        },
        20_000,
    );
});
