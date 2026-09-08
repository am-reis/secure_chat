/**
 * Phase 24 (Attachments). "Do not put large attachments directly into
 * encrypted messaging envelopes. Instead: encrypt the attachment under its
 * own random key, upload the encrypted blob to object storage, and send an
 * encrypted attachment descriptor [through the Double Ratchet channel]."
 *
 * `objectId` is deliberately NOT produced by this module — it's whatever
 * identifier the (out-of-scope, application-supplied) object storage
 * backend hands back after the caller uploads `EncryptedAttachment.ciphertext`
 * there. This module only does the encrypt/decrypt/verify half; upload and
 * download are storage-backend integration, same as real Waku integration
 * is a separate, later concern from the protocol core (see WakuTransport.ts).
 */
export interface AttachmentDescriptor {
    objectId: string;
    encryptionKey: Uint8Array;
    hash: Uint8Array;
    size: number;
    mimeType: string;
}
