/**
 * Public entrypoint. Everything a consuming application needs is
 * re-exported from here — internal implementation modules (the Double
 * Ratchet's own primitives, PQXDH's raw initiator/responder, the KDF
 * chain, prekey signing internals, MockWakuNetwork's seeded RNG, and the
 * low-level outbox plumbing `sendMessageDurably`/`resumePendingOutbox`
 * already wrap) are deliberately NOT exported here. That's not an
 * oversight — it's the same boundary Invariant 10 already draws inside
 * the library itself ("the application never directly manipulates
 * ratchet state"), extended to the package boundary: if it's not exported
 * from here, it was never meant to be consumer-facing.
 *
 * See docs/getting-started.md and docs/integration-guide.md for how these
 * pieces fit together.
 */

// --- Crypto -----------------------------------------------------------
export type { CryptoProvider } from "./crypto/CryptoProvider.js";
export { NobleCryptoProvider, CryptoError } from "./crypto/NobleCryptoProvider.js";
export type { KeyPair, IdentityKeyPair, KemKeyPair, KemEncapsulationResult } from "./crypto/types.js";

// --- Identity -----------------------------------------------------------
export { generateIdentity, computeIdentityId } from "./identity/identity.js";
export type { Identity, PublicIdentity } from "./identity/types.js";
export { toPublicIdentity } from "./identity/types.js";
export { computeIdentityFingerprint } from "./identity/fingerprint.js";
export type { IdentityFingerprint } from "./identity/fingerprint.js";

// --- Prekeys -----------------------------------------------------------
export {
    generateSignedPreKey,
    verifySignedPreKey,
    isExpired as isSignedPreKeyExpired,
} from "./prekeys/signedPrekey.js";
export { generatePQPreKey, verifyPQPreKey, isExpired as isPQPreKeyExpired } from "./prekeys/pqPrekey.js";
export { generateOneTimePreKeys } from "./prekeys/oneTimePrekeys.js";
export { buildPreKeyBundle } from "./prekeys/buildPreKeyBundle.js";
export { InMemoryPrekeyStore } from "./prekeys/InMemoryPrekeyStore.js";
export type { PrekeyStore } from "./prekeys/PrekeyStore.js";
export type { SignedPreKey, PQPreKey, OneTimePreKey, OneTimePreKeyState } from "./prekeys/types.js";
export type { PreKeyBundle } from "./prekeys/PreKeyBundle.js";
export { CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS } from "./prekeys/PreKeyBundle.js";
export { validatePreKeyBundle } from "./prekeys/validateBundle.js";

// --- Session --------------------------------------------------------------
export { SessionManager } from "./session/SessionManager.js";
export type { LocalPrekeyLookup } from "./session/SessionManager.js";
export type {
    Session,
    SessionId,
    MessageEnvelope,
    SessionInitEnvelope,
    MessageEnvelopeData,
    SessionResetEnvelope,
    AnyEnvelope,
} from "./session/types.js";
export { sendMessageDurably, resumePendingOutbox } from "./session/durableMessaging.js";

// --- Persistence ------------------------------------------------------
export { saveSession, loadSession, deleteSession, listSessionIds } from "./persistence/encryptedStorage.js";
export { InMemoryKeyValueStore } from "./persistence/InMemoryKeyValueStore.js";
export { StaticMasterKeyProvider } from "./persistence/StaticMasterKeyProvider.js";
export type { SerializedSession, RawKeyValueStore, MasterKeyProvider } from "./persistence/types.js";

// --- Transport ----------------------------------------------------------
export type { WakuTransport, WakuMessage, PublishOptions, RetrieveHistoryOptions } from "./transport/WakuTransport.js";
export { MAX_WAKU_MESSAGE_SIZE } from "./transport/WakuTransport.js";
export { MockWakuTransport } from "./transport/MockWakuTransport.js";
export { MockWakuNetwork } from "./transport/MockWakuNetwork.js";
export type { FaultInjectionConfig } from "./transport/MockWakuNetwork.js";
export { RealWakuTransport } from "./transport/RealWakuTransport.js";
export type { RealWakuTransportOptions } from "./transport/RealWakuTransport.js";
export { WakuMessagingClient } from "./transport/WakuMessagingClient.js";
export type { WakuMessagingClientOptions } from "./transport/WakuMessagingClient.js";
export { sessionInitContentTopic, messageContentTopic, sessionResetContentTopic } from "./transport/contentTopics.js";
export { encodeEnvelope, decodeEnvelope } from "./transport/protoEnvelopeCodec.js";

// --- Receipts and attachments (ApplicationContent) ---------------------
export type { ApplicationContent, TextContent, DeliveryReceiptContent, ReadReceiptContent, AttachmentContent } from "./receipts/applicationContent.js";
export {
    encodeApplicationContent,
    decodeApplicationContent,
    buildDeliveryReceipt,
    buildReadReceipt,
    buildAttachmentContent,
} from "./receipts/applicationContent.js";
export type { AttachmentDescriptor } from "./attachments/types.js";
export { encryptAttachment, decryptAttachment } from "./attachments/attachmentCrypto.js";
export type { EncryptedAttachment } from "./attachments/attachmentCrypto.js";

// --- Ratchet (types only — the application never manipulates ratchet
// state directly, Invariant 10, but a RatchetHeader IS part of a receipt's
// public shape, so its type needs to be visible to callers of
// buildDeliveryReceipt/buildReadReceipt) --------------------------------
export type { RatchetHeader } from "./ratchet/types.js";

// --- Errors ---------------------------------------------------------------
export { ProtocolError } from "./errors.js";
export type { ProtocolErrorCode } from "./errors.js";

// --- Encoding (small helpers useful for logging/displaying ids) --------
export { bytesToHex, hexToBytes } from "./encoding/canonical.js";
