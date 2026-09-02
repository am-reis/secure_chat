/**
 * The plain, JSON-safe projection of a Session for storage (Phase 13's
 * PersistentSession, adapted to hex-string encoding so it survives
 * JSON.stringify without a custom serializer). All Uint8Array fields are
 * hex strings here.
 *
 * Deliberately does NOT include the local identity's private key, or any
 * other part of `Identity` beyond a reference id — session persistence and
 * identity persistence are separate concerns (an identity is long-lived and
 * shared across many sessions; duplicating its private key into every
 * session record would multiply the attack surface for no benefit). The
 * caller supplies the real `Identity` object when deserializing.
 */
export interface SerializedSession {
    stateVersion: number; // schema version for this record shape, independent of protocolVersion
    protocolVersion: number;
    sessionId: string;
    localIdentityId: string;
    remoteIdentityPublicKey: string;
    associatedData: string;
    createdAt: number;

    // Double Ratchet state (Phase 6), hex-encoded field by field.
    ratchetPublicKey: string;
    ratchetPrivateKey: string;
    remoteRatchetPublicKey: string | null;
    rootKey: string;
    sendingChainKey: string | null;
    receivingChainKey: string | null;
    sendingMessageNumber: number;
    receivingMessageNumber: number;
    previousSendingChainLength: number;
    skippedMessageKeys: Array<{ index: string; key: string }>;
}

/**
 * Low-level byte storage, independent of both the crypto layer and any
 * particular backend (disk, IndexedDB, SQLite, ...). Async because a real
 * backend's I/O will be — unlike PrekeyStore (Phase 3), whose atomicity
 * requirement forced a synchronous contract, nothing here needs that.
 */
export interface RawKeyValueStore {
    get(key: string): Promise<Uint8Array | undefined>;
    set(key: string, value: Uint8Array): Promise<void>;
    delete(key: string): Promise<void>;
    list(prefix?: string): Promise<string[]>;
}

/**
 * Sources the symmetric key used to encrypt session records at rest. On
 * desktop this should be backed by Electron's `safeStorage` (itself backed
 * by the OS keychain — Keychain/DPAPI/libsecret); that binding is desktop-
 * shell code, deliberately outside this portable core package. Whatever
 * implementation is used, the returned key must be 32 bytes.
 */
export interface MasterKeyProvider {
    getMasterKey(): Promise<Uint8Array>;
}
