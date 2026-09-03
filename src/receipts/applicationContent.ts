import { bytesToHex, hexToBytes } from "../encoding/canonical.js";
import type { RatchetHeader } from "../ratchet/types.js";

/**
 * Phase 26: "Optional for the first version. Define DELIVERY_RECEIPT,
 * READ_RECEIPT. Both are ordinary encrypted Double Ratchet messages. Do
 * not use transport metadata as delivery/read receipts."
 *
 * SessionManager (Phase 9) deliberately knows nothing about content
 * structure — it only ever sees opaque plaintext bytes (Invariant 10).
 * Receipts need SOME way to be distinguished from ordinary text within
 * that same opaque plaintext, so this module adds one small, OPTIONAL
 * layer on top: applications that want receipts (or any other structured
 * content) can encode an `ApplicationContent` value and pass the resulting
 * bytes as the plaintext argument to `sessionManager.sendMessage`, then
 * decode whatever comes back from `receiveMessage`. Nothing here changes
 * SessionManager's own API or behavior — plain `Uint8Array` plaintext
 * without this wrapper continues to work exactly as before.
 *
 * A receipt identifies which message it's acknowledging by the same
 * (ratchetPublicKey, messageNumber) pair that is a message's logical
 * identity (Phase 15) — sessionId isn't included because the receipt
 * itself travels inside the same session it's acknowledging a message
 * from, so the channel already establishes that context.
 */

export interface TextContent {
    kind: "TEXT";
    text: string;
}

export interface DeliveryReceiptContent {
    kind: "DELIVERY_RECEIPT";
    acknowledgedRatchetPublicKey: Uint8Array;
    acknowledgedMessageNumber: number;
    timestamp: number;
}

export interface ReadReceiptContent {
    kind: "READ_RECEIPT";
    acknowledgedRatchetPublicKey: Uint8Array;
    acknowledgedMessageNumber: number;
    timestamp: number;
}

export type ApplicationContent = TextContent | DeliveryReceiptContent | ReadReceiptContent;

interface WireTextContent {
    kind: "TEXT";
    text: string;
}
interface WireReceiptContent {
    kind: "DELIVERY_RECEIPT" | "READ_RECEIPT";
    acknowledgedRatchetPublicKey: string;
    acknowledgedMessageNumber: number;
    timestamp: number;
}

/**
 * JSON encoding, same rationale as the transport envelope codec: this is
 * plaintext that only exists INSIDE an already-AEAD-authenticated channel
 * (SessionManager's own ciphertext already provides integrity), so it
 * doesn't need canonical/unambiguous byte encoding the way a signed or
 * AEAD-associated-data structure does — it only needs to decode correctly.
 */
export function encodeApplicationContent(content: ApplicationContent): Uint8Array {
    let wire: WireTextContent | WireReceiptContent;
    if (content.kind === "TEXT") {
        wire = { kind: "TEXT", text: content.text };
    } else {
        wire = {
            kind: content.kind,
            acknowledgedRatchetPublicKey: bytesToHex(content.acknowledgedRatchetPublicKey),
            acknowledgedMessageNumber: content.acknowledgedMessageNumber,
            timestamp: content.timestamp,
        };
    }
    return new TextEncoder().encode(JSON.stringify(wire));
}

export function decodeApplicationContent(bytes: Uint8Array): ApplicationContent {
    let wire: WireTextContent | WireReceiptContent;
    try {
        wire = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
        throw new Error("ApplicationContent payload is not valid JSON (malformed or corrupted)");
    }
    if (wire.kind === "TEXT") {
        return { kind: "TEXT", text: wire.text };
    }
    if (wire.kind === "DELIVERY_RECEIPT" || wire.kind === "READ_RECEIPT") {
        return {
            kind: wire.kind,
            acknowledgedRatchetPublicKey: hexToBytes(wire.acknowledgedRatchetPublicKey),
            acknowledgedMessageNumber: wire.acknowledgedMessageNumber,
            timestamp: wire.timestamp,
        };
    }
    throw new Error(`Unknown ApplicationContent kind: ${(wire as { kind?: unknown }).kind}`);
}

export function buildDeliveryReceipt(acknowledged: RatchetHeader, timestamp: number = Date.now()): DeliveryReceiptContent {
    return {
        kind: "DELIVERY_RECEIPT",
        acknowledgedRatchetPublicKey: acknowledged.ratchetPublicKey,
        acknowledgedMessageNumber: acknowledged.messageNumber,
        timestamp,
    };
}

export function buildReadReceipt(acknowledged: RatchetHeader, timestamp: number = Date.now()): ReadReceiptContent {
    return {
        kind: "READ_RECEIPT",
        acknowledgedRatchetPublicKey: acknowledged.ratchetPublicKey,
        acknowledgedMessageNumber: acknowledged.messageNumber,
        timestamp,
    };
}
