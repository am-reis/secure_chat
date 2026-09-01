import type { Identity } from "../identity/types.js";
import type { SignedPreKey, PQPreKey, OneTimePreKey } from "./types.js";
import { CURRENT_PROTOCOL_VERSION, type PreKeyBundle } from "./PreKeyBundle.js";

/**
 * Project local (private-key-bearing) prekey records into the public-only
 * wire bundle. Like `toPublicIdentity`, this function's whole purpose is to
 * be the one narrow place private key material could leak from if this were
 * done carelessly — it only ever reads `.publicKey`/`.id`/`.signature` off
 * its inputs, never `.privateKey`.
 */
export function buildPreKeyBundle(
    identity: Identity,
    signedPreKey: SignedPreKey,
    pqPreKey: PQPreKey,
    oneTimePreKey?: OneTimePreKey,
): PreKeyBundle {
    const bundle: PreKeyBundle = {
        protocolVersion: CURRENT_PROTOCOL_VERSION,
        identityPublicKey: identity.keyPair.publicKey,
        signedPreKey: {
            id: signedPreKey.id,
            publicKey: signedPreKey.publicKey,
            signature: signedPreKey.signature,
        },
        pqPreKey: {
            id: pqPreKey.id,
            publicKey: pqPreKey.publicKey,
            signature: pqPreKey.signature,
        },
    };
    if (oneTimePreKey) {
        bundle.oneTimePreKey = { id: oneTimePreKey.id, publicKey: oneTimePreKey.publicKey };
    }
    return bundle;
}
