import { describe, it, expect } from "vitest";
import {
    encodeApplicationContent,
    decodeApplicationContent,
    buildDeliveryReceipt,
    buildReadReceipt,
    buildAttachmentContent,
    type TextContent,
} from "../../src/receipts/applicationContent.js";
import { encryptAttachment, decryptAttachment } from "../../src/attachments/attachmentCrypto.js";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey } from "../../src/prekeys/pqPrekey.js";
import { buildPreKeyBundle } from "../../src/prekeys/buildPreKeyBundle.js";
import { InMemoryPrekeyStore } from "../../src/prekeys/InMemoryPrekeyStore.js";
import { SessionManager, type LocalPrekeyLookup } from "../../src/session/SessionManager.js";
import type { SignedPreKey, PQPreKey } from "../../src/prekeys/types.js";
import type { PreKeyBundle } from "../../src/prekeys/PreKeyBundle.js";

const provider = new NobleCryptoProvider();
const toHex = (b: Uint8Array) => Buffer.from(b).toString("hex");
const rand = (n: number) => crypto.getRandomValues(new Uint8Array(n));

describe("ApplicationContent — encode/decode round trip", () => {
    it("round-trips TEXT content", () => {
        const original: TextContent = { kind: "TEXT", text: "hello, world" };
        const decoded = decodeApplicationContent(encodeApplicationContent(original));
        expect(decoded).toEqual(original);
    });

    it("round-trips TEXT content containing unicode", () => {
        const original: TextContent = { kind: "TEXT", text: "héllo 👋 世界" };
        const decoded = decodeApplicationContent(encodeApplicationContent(original));
        expect(decoded).toEqual(original);
    });

    it("round-trips a DELIVERY_RECEIPT", () => {
        const original = buildDeliveryReceipt(
            { ratchetPublicKey: rand(32), previousChainLength: 0, messageNumber: 3 },
            1_700_000_000_000,
        );
        const decoded = decodeApplicationContent(encodeApplicationContent(original));
        expect(decoded.kind).toBe("DELIVERY_RECEIPT");
        if (decoded.kind !== "TEXT") {
            expect(toHex(decoded.acknowledgedRatchetPublicKey)).toBe(toHex(original.acknowledgedRatchetPublicKey));
            expect(decoded.acknowledgedMessageNumber).toBe(3);
            expect(decoded.timestamp).toBe(1_700_000_000_000);
        }
    });

    it("round-trips a READ_RECEIPT", () => {
        const original = buildReadReceipt({ ratchetPublicKey: rand(32), previousChainLength: 1, messageNumber: 7 });
        const decoded = decodeApplicationContent(encodeApplicationContent(original));
        expect(decoded.kind).toBe("READ_RECEIPT");
        if (decoded.kind !== "TEXT") {
            expect(decoded.acknowledgedMessageNumber).toBe(7);
        }
    });

    it("defaults the receipt timestamp to now when not specified", () => {
        const before = Date.now();
        const receipt = buildDeliveryReceipt({ ratchetPublicKey: rand(32), previousChainLength: 0, messageNumber: 0 });
        const after = Date.now();
        expect(receipt.timestamp).toBeGreaterThanOrEqual(before);
        expect(receipt.timestamp).toBeLessThanOrEqual(after);
    });

    it("round-trips an ATTACHMENT descriptor (Phase 24)", () => {
        const encrypted = encryptAttachment(provider, new TextEncoder().encode("attachment bytes"), "image/png");
        const original = buildAttachmentContent({ objectId: "obj-42", ...encrypted });
        const decoded = decodeApplicationContent(encodeApplicationContent(original));

        expect(decoded.kind).toBe("ATTACHMENT");
        if (decoded.kind === "ATTACHMENT") {
            expect(decoded.descriptor.objectId).toBe("obj-42");
            expect(toHex(decoded.descriptor.encryptionKey)).toBe(toHex(encrypted.encryptionKey));
            expect(toHex(decoded.descriptor.hash)).toBe(toHex(encrypted.hash));
            expect(decoded.descriptor.size).toBe(encrypted.size);
            expect(decoded.descriptor.mimeType).toBe("image/png");
        }
    });

    it("throws cleanly on non-JSON bytes", () => {
        expect(() => decodeApplicationContent(new Uint8Array([0xff, 0x00, 0xab]))).toThrow();
    });

    it("throws on an unknown content kind", () => {
        const bytes = new TextEncoder().encode(JSON.stringify({ kind: "SOMETHING_ELSE" }));
        expect(() => decodeApplicationContent(bytes)).toThrow();
    });
});

describe("Receipts as ordinary encrypted messages (Phase 26)", () => {
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
        const DAY = 24 * 60 * 60 * 1000;
        const identity = generateIdentity(provider);
        const signedPreKey = generateSignedPreKey(provider, identity, 1, 30 * DAY);
        const pqPreKey = generatePQPreKey(provider, identity, 1, 30 * DAY);
        const otkStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
        const lookup = new MapPrekeyLookup();
        lookup.addSignedPreKey(signedPreKey);
        lookup.addPQPreKey(pqPreKey);
        const bundle: PreKeyBundle = buildPreKeyBundle(identity, signedPreKey, pqPreKey);
        const manager = new SessionManager(provider, identity, otkStore, lookup);
        return { identity, bundle, manager };
    }

    it("a delivery receipt travels through a real session exactly like any other message", () => {
        const alice = makeParty();
        const bob = makeParty();

        const { session: aliceSession, envelope: init } = alice.manager.createSession(
            bob.bundle,
            encodeApplicationContent({ kind: "TEXT", text: "hi bob" }),
        );
        const { plaintext: bobReceivedInit } = bob.manager.receiveMessage(init);
        const receivedContent = decodeApplicationContent(bobReceivedInit);
        expect(receivedContent).toEqual({ kind: "TEXT", text: "hi bob" });

        // Bob acknowledges Alice's message with a delivery receipt, sent as
        // an ordinary encrypted MESSAGE — no special protocol path.
        const receipt = buildDeliveryReceipt(init.ratchetHeader);
        const receiptEnvelope = bob.manager.sendMessage(init.sessionId, encodeApplicationContent(receipt));
        const { plaintext: aliceReceivedReceipt } = alice.manager.receiveMessage(receiptEnvelope);
        const decodedReceipt = decodeApplicationContent(aliceReceivedReceipt);

        expect(decodedReceipt.kind).toBe("DELIVERY_RECEIPT");
        if (decodedReceipt.kind !== "TEXT") {
            expect(toHex(decodedReceipt.acknowledgedRatchetPublicKey)).toBe(
                toHex(init.ratchetHeader.ratchetPublicKey),
            );
            expect(decodedReceipt.acknowledgedMessageNumber).toBe(init.ratchetHeader.messageNumber);
        }
        void aliceSession;
    });

    it("an attachment descriptor travels through a real session, and the recipient can decrypt the referenced blob (Phase 24)", () => {
        const alice = makeParty();
        const bob = makeParty();

        // Out of band: Alice encrypts the attachment and "uploads" the
        // ciphertext (simulated by just holding onto the bytes), getting
        // back an objectId from the storage backend.
        const encrypted = encryptAttachment(provider, new TextEncoder().encode("cat.jpg bytes"), "image/jpeg");
        const uploadedBlob = encrypted.ciphertext; // what a real storage backend would hold
        const descriptor = { objectId: "storage-object-123", ...encrypted };

        const { envelope: init } = alice.manager.createSession(
            bob.bundle,
            encodeApplicationContent(buildAttachmentContent(descriptor)),
        );
        const { plaintext } = bob.manager.receiveMessage(init);
        const received = decodeApplicationContent(plaintext);

        expect(received.kind).toBe("ATTACHMENT");
        if (received.kind === "ATTACHMENT") {
            expect(received.descriptor.objectId).toBe("storage-object-123");
            // Bob "downloads" uploadedBlob using the objectId, then decrypts
            // it with the key/hash carried inside the (already
            // ratchet-authenticated) descriptor.
            const decrypted = decryptAttachment(provider, received.descriptor, uploadedBlob);
            expect(new TextDecoder().decode(decrypted)).toBe("cat.jpg bytes");
        }
    });

    it("plain Uint8Array plaintext (no ApplicationContent wrapper) continues to work unchanged", () => {
        const alice = makeParty();
        const bob = makeParty();
        const { envelope } = alice.manager.createSession(bob.bundle, new TextEncoder().encode("raw bytes, no wrapper"));
        const { plaintext } = bob.manager.receiveMessage(envelope);
        expect(new TextDecoder().decode(plaintext)).toBe("raw bytes, no wrapper");
    });
});
