import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import type { Identity } from "../identity/types.js";
import type { Session } from "../session/types.js";
import { bytesToHex, hexToBytes } from "../encoding/canonical.js";
import { ProtocolError } from "../errors.js";
import { serializeSession, deserializeSession } from "./serialize.js";
import type { RawKeyValueStore, MasterKeyProvider, SerializedSession } from "./types.js";

const SESSION_KEY_PREFIX = "session:";

function storageKey(sessionId: Uint8Array): string {
    return SESSION_KEY_PREFIX + bytesToHex(sessionId);
}

/**
 * Encrypt a serialized session record. The plaintext is a JSON encoding of
 * `SerializedSession` (a local storage format — this is not a wire
 * structure exchanged with a remote party, so JSON's lack of canonical
 * byte-for-byte determinism doesn't matter here the way it would for a
 * signed structure). The session id is used as AEAD associated data,
 * binding the ciphertext to the specific record it's stored under — an
 * attacker with raw access to the underlying key-value store cannot swap
 * which encrypted blob lives under which session's storage key without the
 * swap being detected as an authentication failure on load.
 */
export function encryptSessionRecord(
    provider: CryptoProvider,
    masterKey: Uint8Array,
    sessionId: Uint8Array,
    serialized: SerializedSession,
): Uint8Array {
    const plaintext = new TextEncoder().encode(JSON.stringify(serialized));
    return provider.aeadEncrypt(masterKey, plaintext, sessionId);
}

export function decryptSessionRecord(
    provider: CryptoProvider,
    masterKey: Uint8Array,
    sessionId: Uint8Array,
    ciphertext: Uint8Array,
): SerializedSession {
    let plaintext: Uint8Array;
    try {
        plaintext = provider.aeadDecrypt(masterKey, ciphertext, sessionId);
    } catch {
        throw new ProtocolError("Failed to decrypt session record (wrong key or corrupted/tampered data)", "STORAGE_FAILURE");
    }
    try {
        return JSON.parse(new TextDecoder().decode(plaintext)) as SerializedSession;
    } catch {
        throw new ProtocolError("Session record decrypted but is not valid JSON", "STORAGE_FAILURE");
    }
}

export async function saveSession(
    store: RawKeyValueStore,
    provider: CryptoProvider,
    masterKeyProvider: MasterKeyProvider,
    session: Session,
): Promise<void> {
    const masterKey = await masterKeyProvider.getMasterKey();
    const serialized = serializeSession(session);
    const ciphertext = encryptSessionRecord(provider, masterKey, session.sessionId, serialized);
    await store.set(storageKey(session.sessionId), ciphertext);
}

/**
 * Returns undefined if no record exists for this session id (not found is
 * not an error — a fresh session simply hasn't been saved yet). Throws if a
 * record exists but fails to decrypt or doesn't match `localIdentity`.
 */
export async function loadSession(
    store: RawKeyValueStore,
    provider: CryptoProvider,
    masterKeyProvider: MasterKeyProvider,
    sessionId: Uint8Array,
    localIdentity: Identity,
): Promise<Session | undefined> {
    const ciphertext = await store.get(storageKey(sessionId));
    if (!ciphertext) return undefined;

    const masterKey = await masterKeyProvider.getMasterKey();
    const serialized = decryptSessionRecord(provider, masterKey, sessionId, ciphertext);
    return deserializeSession(serialized, localIdentity);
}

export async function deleteSession(store: RawKeyValueStore, sessionId: Uint8Array): Promise<void> {
    await store.delete(storageKey(sessionId));
}

export async function listSessionIds(store: RawKeyValueStore): Promise<Uint8Array[]> {
    const keys = await store.list(SESSION_KEY_PREFIX);
    return keys.map((k) => hexToBytes(k.slice(SESSION_KEY_PREFIX.length)));
}
