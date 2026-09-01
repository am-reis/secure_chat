import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey } from "../../src/prekeys/pqPrekey.js";
import { generateOneTimePreKeys } from "../../src/prekeys/oneTimePrekeys.js";
import { buildPreKeyBundle } from "../../src/prekeys/buildPreKeyBundle.js";
import {
    validatePreKeyBundle,
    validateProtocolVersion,
    validateKeyLengths,
    validateKeyEncodings,
    validateIdentifiers,
} from "../../src/prekeys/validateBundle.js";
import { ProtocolError } from "../../src/errors.js";
import type { PreKeyBundle } from "../../src/prekeys/PreKeyBundle.js";

const provider = new NobleCryptoProvider();
const DAY = 24 * 60 * 60 * 1000;

function makeValidBundle(withOneTime = true): PreKeyBundle {
    const identity = generateIdentity(provider);
    const spk = generateSignedPreKey(provider, identity, 1, 30 * DAY);
    const pqk = generatePQPreKey(provider, identity, 1, 30 * DAY);
    const otk = withOneTime ? generateOneTimePreKeys(provider, 1, 1)[0] : undefined;
    return buildPreKeyBundle(identity, spk, pqk, otk);
}

describe("buildPreKeyBundle", () => {
    it("produces a bundle that passes full validation", () => {
        const bundle = makeValidBundle();
        expect(() => validatePreKeyBundle(provider, bundle)).not.toThrow();
    });

    it("produces a bundle that validates without a one-time prekey (Bob may be out of OPKs)", () => {
        const bundle = makeValidBundle(false);
        expect(bundle.oneTimePreKey).toBeUndefined();
        expect(() => validatePreKeyBundle(provider, bundle)).not.toThrow();
    });

    it("sets the current protocol version", () => {
        const bundle = makeValidBundle();
        expect(bundle.protocolVersion).toBe(1);
    });

    it("never includes a privateKey field anywhere in the bundle", () => {
        const bundle = makeValidBundle();
        const json = JSON.stringify(bundle, (_key, value) =>
            value instanceof Uint8Array ? Array.from(value) : value,
        );
        expect(json).not.toMatch(/"privateKey"/);
    });
});

describe("validatePreKeyBundle — happy path", () => {
    it("accepts a genuinely valid bundle", () => {
        expect(() => validatePreKeyBundle(provider, makeValidBundle())).not.toThrow();
    });
});

describe("validatePreKeyBundle — adversarial cases", () => {
    it("rejects an unsupported protocol version", () => {
        const bundle = { ...makeValidBundle(), protocolVersion: 999 };
        expect(() => validatePreKeyBundle(provider, bundle)).toThrow(ProtocolError);
        try {
            validatePreKeyBundle(provider, bundle);
        } catch (e) {
            expect((e as ProtocolError).code).toBe("UNSUPPORTED_VERSION");
        }
    });

    it("rejects a truncated identity public key", () => {
        const bundle = makeValidBundle();
        bundle.identityPublicKey = bundle.identityPublicKey.slice(0, 16);
        expect(() => validatePreKeyBundle(provider, bundle)).toThrow(ProtocolError);
    });

    it("rejects a truncated signed prekey signature", () => {
        const bundle = makeValidBundle();
        bundle.signedPreKey.signature = bundle.signedPreKey.signature.slice(0, 10);
        try {
            validatePreKeyBundle(provider, bundle);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("INVALID_FORMAT");
        }
    });

    it("rejects a tampered signed prekey public key (signature no longer matches)", () => {
        const bundle = makeValidBundle();
        const tampered = bundle.signedPreKey.publicKey.slice();
        tampered[0]! ^= 0xff;
        bundle.signedPreKey.publicKey = tampered;
        try {
            validatePreKeyBundle(provider, bundle);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("INVALID_SIGNATURE");
        }
    });

    it("rejects a tampered PQ prekey public key (signature no longer matches)", () => {
        const bundle = makeValidBundle();
        const tampered = bundle.pqPreKey.publicKey.slice();
        tampered[0]! ^= 0xff;
        bundle.pqPreKey.publicKey = tampered;
        try {
            validatePreKeyBundle(provider, bundle);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("INVALID_SIGNATURE");
        }
    });

    it("rejects a bundle signed by a different identity (key substitution attack)", () => {
        const attacker = generateIdentity(provider);
        const bundle = makeValidBundle();
        bundle.identityPublicKey = attacker.keyPair.publicKey; // swap identity, keep the original signature
        try {
            validatePreKeyBundle(provider, bundle);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("INVALID_SIGNATURE");
        }
    });

    it("rejects a signed prekey signature cross-substituted from the PQ prekey", () => {
        const bundle = makeValidBundle();
        bundle.signedPreKey.signature = bundle.pqPreKey.signature; // same identity, wrong domain
        try {
            validatePreKeyBundle(provider, bundle);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("INVALID_SIGNATURE");
        }
    });

    it("rejects an all-zero signed prekey public key", () => {
        const bundle = makeValidBundle();
        bundle.signedPreKey.publicKey = new Uint8Array(32); // right length, all zero
        try {
            validatePreKeyBundle(provider, bundle);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("INVALID_FORMAT");
        }
    });

    it("rejects a negative signedPreKey.id cleanly (not as an unclassified crash)", () => {
        const bundle = makeValidBundle();
        bundle.signedPreKey.id = -1;
        try {
            validatePreKeyBundle(provider, bundle);
            expect.unreachable();
        } catch (e) {
            expect(e).toBeInstanceOf(ProtocolError);
            expect((e as ProtocolError).code).toBe("INVALID_FORMAT");
        }
    });

    it("stops at the first failing check and does not run later checks", () => {
        // Bad protocol version AND a bad signature — should fail on version first.
        const bundle = makeValidBundle();
        bundle.protocolVersion = 42;
        bundle.signedPreKey.signature = new Uint8Array(64); // also garbage
        try {
            validatePreKeyBundle(provider, bundle);
            expect.unreachable();
        } catch (e) {
            expect((e as ProtocolError).code).toBe("UNSUPPORTED_VERSION");
        }
    });
});

describe("individual validation functions", () => {
    it("validateProtocolVersion is independently callable", () => {
        expect(() => validateProtocolVersion(makeValidBundle())).not.toThrow();
        expect(() => validateProtocolVersion({ ...makeValidBundle(), protocolVersion: 7 })).toThrow(
            ProtocolError,
        );
    });

    it("validateKeyLengths is independently callable", () => {
        const bundle = makeValidBundle();
        expect(() => validateKeyLengths(bundle)).not.toThrow();
    });

    it("validateKeyEncodings is independently callable", () => {
        const bundle = makeValidBundle();
        expect(() => validateKeyEncodings(bundle)).not.toThrow();
    });

    it("validateIdentifiers rejects a non-integer id", () => {
        const bundle = makeValidBundle();
        bundle.pqPreKey.id = 1.5;
        expect(() => validateIdentifiers(bundle)).toThrow(ProtocolError);
    });
});
