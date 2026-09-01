import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import type { Identity } from "../identity/types.js";
import type { SignedPreKey, PQPreKey } from "../prekeys/types.js";
import type { PrekeyStore } from "../prekeys/PrekeyStore.js";
import { concatBytes } from "../encoding/canonical.js";
import { ProtocolError } from "../errors.js";
import { pqxdhKdf } from "./params.js";
import { buildPQXDHAssociatedData } from "./associatedData.js";

export interface PQXDHResponderInput {
    initiatorIdentityPublicKey: Uint8Array;
    initiatorEphemeralPublicKey: Uint8Array;
    pqCiphertext: Uint8Array;
    usedSignedPreKeyId: number;
    usedOneTimePreKeyId: number | undefined;
    usedPqPreKeyId: number;
}

export interface PQXDHResponderResult {
    sk: Uint8Array;
    associatedData: Uint8Array;
    /**
     * If a one-time prekey was referenced, its id — now RESERVED, not yet
     * CONSUMED. Per Phase 5.3, Bob must not permanently commit session
     * state (which includes consuming the OPK) until AFTER the initial
     * message has been successfully authenticated/decrypted. That step
     * happens once Phase 6 (Double Ratchet) exists to actually attempt the
     * decryption — the caller MUST call `store.consumeOneTimePreKey(id)` on
     * success or `store.releaseOneTimePreKey(id)` on failure using this id.
     */
    reservedOneTimePreKeyId: number | undefined;
}

/**
 * PQXDHResponder — Phase 5.3. Bob has no signature to verify here (the real
 * PQXDH spec's responder flow performs no signature checks — mutual
 * authentication comes from both sides successfully deriving the same SK
 * from DH values only each of them could compute, not from a signature on
 * the initial message). Bob's job: look up the referenced local prekeys,
 * atomically reserve the one-time prekey if referenced, run the mirrored DH
 * + KEM decapsulation + KDF, and return SK/AD.
 *
 * `signedPreKey` and `pqPreKey` are the caller's own already-looked-up local
 * records matching the ids Alice referenced — this function doesn't own
 * prekey storage/lookup itself, only the one-time prekey pool's atomicity
 * (via `oneTimePreKeyStore`), consistent with Phase 3's PrekeyStore scope.
 */
export function pqxdhRespond(
    provider: CryptoProvider,
    responderIdentity: Identity,
    signedPreKey: Pick<SignedPreKey, "id" | "privateKey">,
    pqPreKey: Pick<PQPreKey, "id" | "privateKey">,
    oneTimePreKeyStore: PrekeyStore | null,
    input: PQXDHResponderInput,
): PQXDHResponderResult {
    if (signedPreKey.id !== input.usedSignedPreKeyId) {
        throw new ProtocolError(
            `Signed prekey id mismatch: expected ${input.usedSignedPreKeyId}, have ${signedPreKey.id}`,
            "KEY_NOT_FOUND",
        );
    }
    if (pqPreKey.id !== input.usedPqPreKeyId) {
        throw new ProtocolError(
            `PQ prekey id mismatch: expected ${input.usedPqPreKeyId}, have ${pqPreKey.id}`,
            "KEY_NOT_FOUND",
        );
    }

    let reservedOtkPrivateKey: Uint8Array | null = null;
    let reservedOtkId: number | undefined;
    if (input.usedOneTimePreKeyId !== undefined) {
        if (!oneTimePreKeyStore) {
            throw new ProtocolError(
                "Initial message references a one-time prekey but no PrekeyStore was provided",
                "KEY_NOT_FOUND",
            );
        }
        const reserved = oneTimePreKeyStore.reserveOneTimePreKey(input.usedOneTimePreKeyId);
        if (!reserved) {
            throw new ProtocolError(
                `One-time prekey ${input.usedOneTimePreKeyId} is unavailable (already used or unknown)`,
                "KEY_NOT_FOUND",
            );
        }
        reservedOtkPrivateKey = reserved.privateKey;
        reservedOtkId = reserved.id;
    }

    try {
        const responderX25519Private = provider.x25519PrivateFromIdentity(responderIdentity.keyPair.privateKey);
        const initiatorX25519Public = provider.x25519PublicFromIdentity(input.initiatorIdentityPublicKey);

        // Mirrors of Alice's DH1..DH4, computed from Bob's side of each pair.
        const dh1 = provider.x25519(signedPreKey.privateKey, initiatorX25519Public); // DH(IK_A, SPK_B)
        const dh2 = provider.x25519(responderX25519Private, input.initiatorEphemeralPublicKey); // DH(EK_A, IK_B)
        const dh3 = provider.x25519(signedPreKey.privateKey, input.initiatorEphemeralPublicKey); // DH(EK_A, SPK_B)
        const dh4 = reservedOtkPrivateKey
            ? provider.x25519(reservedOtkPrivateKey, input.initiatorEphemeralPublicKey) // DH(EK_A, OPK_B)
            : null;

        let sharedSecret: Uint8Array;
        try {
            sharedSecret = provider.kemDecapsulate(pqPreKey.privateKey, input.pqCiphertext);
        } catch {
            throw new ProtocolError("PQ ciphertext decapsulation failed", "INVALID_PQ_CIPHERTEXT");
        }

        const km = dh4
            ? concatBytes(dh1, dh2, dh3, dh4, sharedSecret)
            : concatBytes(dh1, dh2, dh3, sharedSecret);
        const sk = pqxdhKdf(provider, km);

        const associatedData = buildPQXDHAssociatedData(
            input.initiatorIdentityPublicKey,
            responderIdentity.keyPair.publicKey,
        );

        provider.secureErase(responderX25519Private);
        provider.secureErase(dh1);
        provider.secureErase(dh2);
        provider.secureErase(dh3);
        if (dh4) provider.secureErase(dh4);
        provider.secureErase(sharedSecret);

        return { sk, associatedData, reservedOneTimePreKeyId: reservedOtkId };
    } catch (err) {
        // Per Phase 5.3: do not permanently mutate session state before
        // authentication succeeds. We can't know here whether the eventual
        // DR decryption (a later phase) will succeed, but if SK/AD
        // derivation itself fails, there's no path to success at all —
        // release the reservation immediately rather than leaving it
        // dangling as RESERVED until some future cleanup.
        if (reservedOtkId !== undefined && oneTimePreKeyStore) {
            oneTimePreKeyStore.releaseOneTimePreKey(reservedOtkId);
        }
        throw err;
    }
}
