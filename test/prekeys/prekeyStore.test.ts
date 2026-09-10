import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateOneTimePreKeys } from "../../src/prekeys/oneTimePrekeys.js";
import { InMemoryPrekeyStore } from "../../src/prekeys/InMemoryPrekeyStore.js";

const provider = new NobleCryptoProvider();
const makeStore = () => new InMemoryPrekeyStore(provider.secureErase.bind(provider));
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");

describe("generateOneTimePreKeys", () => {
    it("generates the requested count with sequential ids", () => {
        const keys = generateOneTimePreKeys(provider, 5, 100);
        expect(keys.map((k) => k.id)).toEqual([100, 101, 102, 103, 104]);
        expect(keys.every((k) => k.state === "AVAILABLE")).toBe(true);
    });

    it("every key is unique", () => {
        const keys = generateOneTimePreKeys(provider, 20, 0);
        const publicKeys = new Set(keys.map((k) => toHex(k.publicKey)));
        expect(publicKeys.size).toBe(20);
    });

    it("rejects an invalid count", () => {
        expect(() => generateOneTimePreKeys(provider, -1, 0)).toThrow(RangeError);
        expect(() => generateOneTimePreKeys(provider, 1.5, 0)).toThrow(RangeError);
    });

    it("returns an empty array for count 0", () => {
        expect(generateOneTimePreKeys(provider, 0, 0)).toEqual([]);
    });
});

describe("InMemoryPrekeyStore — lifecycle", () => {
    it("newly added keys are AVAILABLE and countable", () => {
        const store = makeStore();
        store.addOneTimePreKeys(generateOneTimePreKeys(provider, 3, 1));
        expect(store.countAvailableOneTimePreKeys()).toBe(3);
    });

    it("rejects adding a key with a colliding id", () => {
        const store = makeStore();
        store.addOneTimePreKeys(generateOneTimePreKeys(provider, 1, 1));
        expect(() => store.addOneTimePreKeys(generateOneTimePreKeys(provider, 1, 1))).toThrow();
    });

    it("reserve transitions AVAILABLE -> RESERVED and returns the key material", () => {
        const store = makeStore();
        const [key] = generateOneTimePreKeys(provider, 1, 1);
        store.addOneTimePreKeys([key!]);

        const reserved = store.reserveOneTimePreKey(1);
        expect(reserved).not.toBeNull();
        expect(reserved!.state).toBe("RESERVED");
        expect(toHex(reserved!.privateKey)).toBe(toHex(key!.privateKey));
        expect(store.countAvailableOneTimePreKeys()).toBe(0);
    });

    it("CRITICAL: a second reservation of the same id fails (atomicity — never hand the same key to two sessions)", () => {
        const store = makeStore();
        store.addOneTimePreKeys(generateOneTimePreKeys(provider, 1, 1));

        const first = store.reserveOneTimePreKey(1);
        const second = store.reserveOneTimePreKey(1);

        expect(first).not.toBeNull();
        expect(second).toBeNull();
    });

    it("reserving a nonexistent id returns null", () => {
        const store = makeStore();
        expect(store.reserveOneTimePreKey(999)).toBeNull();
    });

    it("consume transitions RESERVED -> CONSUMED and erases the stored private key", () => {
        const store = makeStore();
        store.addOneTimePreKeys(generateOneTimePreKeys(provider, 1, 1));
        store.reserveOneTimePreKey(1);
        store.consumeOneTimePreKey(1);

        const after = store.getOneTimePreKey(1);
        expect(after!.state).toBe("CONSUMED");
        expect(after!.privateKey.every((b) => b === 0)).toBe(true);
    });

    it("consuming a key that was never reserved throws (cannot skip the reservation step)", () => {
        const store = makeStore();
        store.addOneTimePreKeys(generateOneTimePreKeys(provider, 1, 1));
        expect(() => store.consumeOneTimePreKey(1)).toThrow();
    });

    it("consuming an already-consumed key throws (Invariant 5: cannot reuse a consumed key)", () => {
        const store = makeStore();
        store.addOneTimePreKeys(generateOneTimePreKeys(provider, 1, 1));
        store.reserveOneTimePreKey(1);
        store.consumeOneTimePreKey(1);
        expect(() => store.consumeOneTimePreKey(1)).toThrow();
    });

    it("release transitions RESERVED -> AVAILABLE, allowing a later reservation", () => {
        const store = makeStore();
        store.addOneTimePreKeys(generateOneTimePreKeys(provider, 1, 1));
        store.reserveOneTimePreKey(1);
        store.releaseOneTimePreKey(1);

        expect(store.countAvailableOneTimePreKeys()).toBe(1);
        const reservedAgain = store.reserveOneTimePreKey(1);
        expect(reservedAgain).not.toBeNull();
        expect(reservedAgain!.state).toBe("RESERVED");
    });

    it("releasing a key that isn't RESERVED throws", () => {
        const store = makeStore();
        store.addOneTimePreKeys(generateOneTimePreKeys(provider, 1, 1));
        expect(() => store.releaseOneTimePreKey(1)).toThrow(); // still AVAILABLE
    });

    it("released keys retain usable (non-erased) private key material", () => {
        const store = makeStore();
        const [key] = generateOneTimePreKeys(provider, 1, 1);
        store.addOneTimePreKeys([key!]);
        store.reserveOneTimePreKey(1);
        store.releaseOneTimePreKey(1);

        const reReserved = store.reserveOneTimePreKey(1);
        expect(toHex(reReserved!.privateKey)).toBe(toHex(key!.privateKey));
    });

    it("getOneTimePreKey returns a defensive copy, not a live reference", () => {
        const store = makeStore();
        store.addOneTimePreKeys(generateOneTimePreKeys(provider, 1, 1));
        const copy = store.getOneTimePreKey(1)!;
        const originalFirstByte = copy.publicKey[0];
        // Flip the byte rather than pin it to a fixed value: the key is
        // randomly generated, so asserting against a hardcoded 0xff was
        // flaky (~1/256 chance the random byte already was 0xff, making
        // the mutation a no-op and the assertion fail on an unrelated
        // coincidence, not a real live-reference bug).
        copy.publicKey[0] = originalFirstByte ^ 0xff;
        const copy2 = store.getOneTimePreKey(1)!;
        expect(copy2.publicKey[0]).toBe(originalFirstByte);
    });

    it("getOneTimePreKey returns undefined for a nonexistent id", () => {
        const store = makeStore();
        expect(store.getOneTimePreKey(42)).toBeUndefined();
    });

    it("countAvailableOneTimePreKeys reflects mixed states correctly", () => {
        const store = makeStore();
        store.addOneTimePreKeys(generateOneTimePreKeys(provider, 5, 1));
        store.reserveOneTimePreKey(1);
        store.reserveOneTimePreKey(2);
        store.consumeOneTimePreKey(2);
        // id 1: RESERVED, id 2: CONSUMED, ids 3-5: AVAILABLE
        expect(store.countAvailableOneTimePreKeys()).toBe(3);
    });
});
