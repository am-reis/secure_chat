import { describe, it, expect } from "vitest";
import { NobleCryptoProvider } from "../../src/crypto/NobleCryptoProvider.js";
import { generateIdentity } from "../../src/identity/identity.js";
import { generateSignedPreKey } from "../../src/prekeys/signedPrekey.js";
import { generatePQPreKey } from "../../src/prekeys/pqPrekey.js";
import { generateOneTimePreKeys } from "../../src/prekeys/oneTimePrekeys.js";
import { buildPreKeyBundle } from "../../src/prekeys/buildPreKeyBundle.js";
import { InMemoryPrekeyStore } from "../../src/prekeys/InMemoryPrekeyStore.js";
import { SessionManager, type LocalPrekeyLookup } from "../../src/session/SessionManager.js";
import {
    encodeApplicationContent,
    decodeApplicationContent,
    buildDeliveryReceipt,
    buildAttachmentContent,
} from "../../src/receipts/applicationContent.js";
import { encryptAttachment, decryptAttachment } from "../../src/attachments/attachmentCrypto.js";
import type { SignedPreKey, PQPreKey } from "../../src/prekeys/types.js";

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

/**
 * Backs the "Structured content: receipts and attachments" section of
 * docs/integration-guide.md. `SessionManager` only ever sees opaque
 * `Uint8Array` plaintext (Invariant 10) — everything here is a thin
 * encode/decode layer OVER that, entirely optional, living in the
 * application, not the protocol core.
 */
describe("Integration guide — receipts and attachments as ApplicationContent", () => {
    function makeParty() {
        const provider = new NobleCryptoProvider();
        const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;
        const identity = generateIdentity(provider);
        const signedPreKey = generateSignedPreKey(provider, identity, 1, THIRTY_DAYS);
        const pqPreKey = generatePQPreKey(provider, identity, 1, THIRTY_DAYS);
        const [otk] = generateOneTimePreKeys(provider, 1, 1);
        const otkStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
        otkStore.addOneTimePreKeys([otk!]);
        const lookup = new MapPrekeyLookup();
        lookup.addSignedPreKey(signedPreKey);
        lookup.addPQPreKey(pqPreKey);
        const bundle = buildPreKeyBundle(identity, signedPreKey, pqPreKey, otk);
        const manager = new SessionManager(provider, identity, otkStore, lookup);
        return { provider, bundle, manager };
    }

    it("a text message wrapped in ApplicationContent, and a delivery receipt acknowledging it, both travel as ordinary encrypted messages", () => {
        const alice = makeParty();
        const bob = makeParty();

        // Every plaintext argument to createSession/sendMessage is just
        // bytes — ApplicationContent is an application-level convention
        // for giving those bytes a `kind`, nothing SessionManager knows
        // about or requires.
        const { envelope: init } = alice.manager.createSession(
            bob.bundle,
            encodeApplicationContent({ kind: "TEXT", text: "hi bob" }),
        );
        const { plaintext: bobPlaintext } = bob.manager.receiveMessage(init);
        const bobContent = decodeApplicationContent(bobPlaintext);
        expect(bobContent).toEqual({ kind: "TEXT", text: "hi bob" });

        // Bob acknowledges it — a receipt identifies which message it's
        // acknowledging by the SAME (ratchetPublicKey, messageNumber) pair
        // that already is a message's identity at the protocol level, so
        // there's no separate id scheme to invent.
        const receipt = buildDeliveryReceipt(init.ratchetHeader);
        const receiptEnvelope = bob.manager.sendMessage(init.sessionId, encodeApplicationContent(receipt));
        const { plaintext: aliceReceivedReceipt } = alice.manager.receiveMessage(receiptEnvelope);
        const decodedReceipt = decodeApplicationContent(aliceReceivedReceipt);

        expect(decodedReceipt.kind).toBe("DELIVERY_RECEIPT");
        if (decodedReceipt.kind === "DELIVERY_RECEIPT") {
            expect(decodedReceipt.acknowledgedMessageNumber).toBe(init.ratchetHeader.messageNumber);
        }
    });

    it("an attachment: encrypt the blob under its own key, send only the descriptor, decrypt after 'download'", () => {
        const alice = makeParty();
        const bob = makeParty();

        // The "upload" step (getting bytes to whatever object-storage
        // backend the app uses) is NOT part of this library — see the
        // integration guide's "what you build yourself" section. Here,
        // `uploadedBlob` stands in for wherever `encrypted.ciphertext`
        // actually ends up.
        const encrypted = encryptAttachment(alice.provider, new TextEncoder().encode("cat.jpg bytes"), "image/jpeg");
        const uploadedBlob = encrypted.ciphertext;
        const descriptor = { objectId: "object-storage-key-123", ...encrypted };

        // The descriptor (key + hash + size + mimeType + objectId) is what
        // actually travels through the encrypted channel — the object
        // storage system itself only ever sees ciphertext.
        const { envelope: init } = alice.manager.createSession(
            bob.bundle,
            encodeApplicationContent(buildAttachmentContent(descriptor)),
        );
        const { plaintext } = bob.manager.receiveMessage(init);
        const received = decodeApplicationContent(plaintext);

        expect(received.kind).toBe("ATTACHMENT");
        if (received.kind === "ATTACHMENT") {
            // Bob "downloads" uploadedBlob using received.descriptor.objectId,
            // then decrypts with the key carried inside the
            // already-ratchet-authenticated descriptor.
            const decrypted = decryptAttachment(bob.provider, received.descriptor, uploadedBlob);
            expect(new TextDecoder().decode(decrypted)).toBe("cat.jpg bytes");
        }
    });
});
