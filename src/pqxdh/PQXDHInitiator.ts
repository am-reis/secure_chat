import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import type { Identity } from "../identity/types.js";
import type { PreKeyBundle } from "../prekeys/PreKeyBundle.js";
import { validatePreKeyBundle } from "../prekeys/validateBundle.js";
import { concatBytes } from "../encoding/canonical.js";
import { pqxdhKdf } from "./params.js";
import { buildPQXDHAssociatedData } from "./associatedData.js";

/**
 * Everything Alice needs to hand off to whatever initializes the Double
 * Ratchet and assembles the wire envelope (a later phase — see the module
 * doc note below). Deliberately does NOT include any Double Ratchet state;
 * per Phase 5's "do not mix PQXDH state with Double Ratchet state," this
 * module's job stops here.
 */
export interface PQXDHInitiatorResult {
    /** The 32-byte session key. Becomes the Double Ratchet's initial root key in a later phase — never used directly as a message-encryption key. */
    sk: Uint8Array;
    /** AD = EncodeEC(IKA) || EncodeEC(IKB), for identity-binding. */
    associatedData: Uint8Array;
    /** Alice's freshly generated ephemeral public key EKA — must be sent to Bob in the initial message. */
    ephemeralPublicKey: Uint8Array;
    /** The ML-KEM-1024 ciphertext CT encapsulating the PQ shared secret against Bob's PQ prekey — must be sent to Bob. */
    pqCiphertext: Uint8Array;
    /** Identifiers for which of Bob's prekeys were used, so Bob knows which private keys to load. */
    usedSignedPreKeyId: number;
    usedOneTimePreKeyId: number | undefined;
    usedPqPreKeyId: number;
}

/**
 * PQXDHInitiator — Phase 5.1. Alice validates Bob's bundle, performs the
 * classical DH operations and PQ encapsulation, and derives SK via the
 * exact PQXDH KDF construction (params.ts).
 *
 *   DH1 = DH(IK_A, SPK_B)
 *   DH2 = DH(EK_A, IK_B)
 *   DH3 = DH(EK_A, SPK_B)
 *   DH4 = DH(EK_A, OPK_B)               (only if Bob's bundle had a one-time prekey)
 *   (CT, SS) = ML-KEM-1024.Encapsulate(PQPK_B)
 *   SK = KDF(DH1 || DH2 || DH3 [|| DH4] || SS)
 *
 * Per spec §3.3: "After calculating SK, Alice deletes her ephemeral private
 * key, the DH outputs and the shared secret SS" — done here, inside this
 * function, before returning.
 */
export function pqxdhInitiate(
    provider: CryptoProvider,
    initiatorIdentity: Identity,
    bundle: PreKeyBundle,
): PQXDHInitiatorResult {
    // Phase 4.1: never proceed with an unvalidated bundle.
    validatePreKeyBundle(provider, bundle);

    const ephemeral = provider.generateX25519KeyPair();

    // IK_A must act as an X25519 DH key here even though it's stored as an
    // Ed25519 keypair (see identity/types.ts's note on the dual-use design).
    const initiatorX25519Private = provider.x25519PrivateFromIdentity(initiatorIdentity.keyPair.privateKey);
    const responderX25519Public = provider.x25519PublicFromIdentity(bundle.identityPublicKey);

    const dh1 = provider.x25519(initiatorX25519Private, bundle.signedPreKey.publicKey); // DH(IK_A, SPK_B)
    const dh2 = provider.x25519(ephemeral.privateKey, responderX25519Public); // DH(EK_A, IK_B)
    const dh3 = provider.x25519(ephemeral.privateKey, bundle.signedPreKey.publicKey); // DH(EK_A, SPK_B)
    const dh4 = bundle.oneTimePreKey
        ? provider.x25519(ephemeral.privateKey, bundle.oneTimePreKey.publicKey) // DH(EK_A, OPK_B)
        : null;

    const { ciphertext, sharedSecret } = provider.kemEncapsulate(bundle.pqPreKey.publicKey);

    const km = dh4
        ? concatBytes(dh1, dh2, dh3, dh4, sharedSecret)
        : concatBytes(dh1, dh2, dh3, sharedSecret);
    const sk = pqxdhKdf(provider, km);

    const associatedData = buildPQXDHAssociatedData(initiatorIdentity.keyPair.publicKey, bundle.identityPublicKey);

    // Spec §3.3: delete the ephemeral private key, the DH outputs, and SS.
    // We also erase the derived X25519 identity scalars, which are just as
    // secret as the long-term private key they were derived from.
    provider.secureErase(ephemeral.privateKey);
    provider.secureErase(initiatorX25519Private);
    provider.secureErase(dh1);
    provider.secureErase(dh2);
    provider.secureErase(dh3);
    if (dh4) provider.secureErase(dh4);
    provider.secureErase(sharedSecret);

    return {
        sk,
        associatedData,
        ephemeralPublicKey: ephemeral.publicKey,
        pqCiphertext: ciphertext,
        usedSignedPreKeyId: bundle.signedPreKey.id,
        usedOneTimePreKeyId: bundle.oneTimePreKey?.id,
        usedPqPreKeyId: bundle.pqPreKey.id,
    };
}
