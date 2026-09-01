import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import type { Identity } from "../identity/types.js";
import { signPrekeyPayload, verifyPrekeySignature } from "./signing.js";
import type { PQPreKey } from "./types.js";

const PQ_PREKEY_DOMAIN = new TextEncoder().encode("secure-messaging/pq-prekey/v1");

export function generatePQPreKey(
    provider: CryptoProvider,
    identity: Identity,
    id: number,
    ttlMs: number,
): PQPreKey {
    const { publicKey, privateKey } = provider.generateKemKeyPair();
    const createdAt = Date.now();
    const expiresAt = createdAt + ttlMs;
    const signature = signPrekeyPayload(
        provider,
        identity.keyPair.privateKey,
        PQ_PREKEY_DOMAIN,
        id,
        publicKey,
    );
    return { id, publicKey, privateKey, signature, createdAt, expiresAt };
}

export function verifyPQPreKey(
    provider: CryptoProvider,
    identityPublicKey: Uint8Array,
    prekey: Pick<PQPreKey, "id" | "publicKey" | "signature">,
): boolean {
    return verifyPrekeySignature(
        provider,
        identityPublicKey,
        PQ_PREKEY_DOMAIN,
        prekey.id,
        prekey.publicKey,
        prekey.signature,
    );
}

export function isExpired(prekey: Pick<PQPreKey, "expiresAt">, now: number = Date.now()): boolean {
    return now >= prekey.expiresAt;
}
