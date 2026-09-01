import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import type { Identity } from "../identity/types.js";
import { signPrekeyPayload, verifyPrekeySignature } from "./signing.js";
import type { SignedPreKey } from "./types.js";

const SIGNED_PREKEY_DOMAIN = new TextEncoder().encode("secure-messaging/signed-prekey/v1");

/**
 * Generate a new signed EC prekey, owned by `identity`. Per Phase 3.1: never
 * delete the currently active signed prekey until its replacement is safely
 * deployed — that lifecycle rule belongs to whatever stores/publishes these
 * (later phase), not to this pure generation function.
 */
export function generateSignedPreKey(
    provider: CryptoProvider,
    identity: Identity,
    id: number,
    ttlMs: number,
): SignedPreKey {
    const { publicKey, privateKey } = provider.generateX25519KeyPair();
    const createdAt = Date.now();
    const expiresAt = createdAt + ttlMs;
    const signature = signPrekeyPayload(
        provider,
        identity.keyPair.privateKey,
        SIGNED_PREKEY_DOMAIN,
        id,
        publicKey,
    );
    return { id, publicKey, privateKey, signature, createdAt, expiresAt };
}

/**
 * Verify a signed prekey against the claimed owner's identity public key.
 * Checks the signature only — expiry is a separate, deliberately distinct
 * check (see `isExpired`) so callers can decide whether an expired-but-
 * validly-signed prekey should be rejected outright or just deprioritized.
 */
export function verifySignedPreKey(
    provider: CryptoProvider,
    identityPublicKey: Uint8Array,
    prekey: Pick<SignedPreKey, "id" | "publicKey" | "signature">,
): boolean {
    return verifyPrekeySignature(
        provider,
        identityPublicKey,
        SIGNED_PREKEY_DOMAIN,
        prekey.id,
        prekey.publicKey,
        prekey.signature,
    );
}

export function isExpired(prekey: Pick<SignedPreKey, "expiresAt">, now: number = Date.now()): boolean {
    return now >= prekey.expiresAt;
}
