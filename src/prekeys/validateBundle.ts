import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import { KEY_LENGTHS } from "../crypto/constants.js";
import { ProtocolError } from "../errors.js";
import { verifySignedPreKey } from "./signedPrekey.js";
import { verifyPQPreKey } from "./pqPrekey.js";
import { SUPPORTED_PROTOCOL_VERSIONS, type PreKeyBundle } from "./PreKeyBundle.js";

/** Phase 27: reject anything not in our currently-supported version set outright — never silently coerce or ignore a version mismatch. */
export function validateProtocolVersion(bundle: PreKeyBundle): void {
    if (!SUPPORTED_PROTOCOL_VERSIONS.has(bundle.protocolVersion)) {
        throw new ProtocolError(
            `Unsupported protocol version: ${bundle.protocolVersion}`,
            "UNSUPPORTED_VERSION",
        );
    }
}

/** Structural check: every key/signature field must be exactly the byte length its type requires. Cheap — runs before any signature math. */
export function validateKeyLengths(bundle: PreKeyBundle): void {
    const checks: Array<[boolean, string]> = [
        [bundle.identityPublicKey.length === KEY_LENGTHS.ed25519PublicKey, "identityPublicKey"],
        [bundle.signedPreKey.publicKey.length === KEY_LENGTHS.x25519PublicKey, "signedPreKey.publicKey"],
        [bundle.signedPreKey.signature.length === KEY_LENGTHS.ed25519Signature, "signedPreKey.signature"],
        [bundle.pqPreKey.publicKey.length === KEY_LENGTHS.mlKem1024PublicKey, "pqPreKey.publicKey"],
        [bundle.pqPreKey.signature.length === KEY_LENGTHS.ed25519Signature, "pqPreKey.signature"],
    ];
    if (bundle.oneTimePreKey) {
        checks.push([
            bundle.oneTimePreKey.publicKey.length === KEY_LENGTHS.x25519PublicKey,
            "oneTimePreKey.publicKey",
        ]);
    }
    for (const [ok, field] of checks) {
        if (!ok) {
            throw new ProtocolError(`Invalid key length for field: ${field}`, "INVALID_FORMAT");
        }
    }
}

/**
 * Cheap sanity check on key encodings: reject obviously-garbage (all-zero)
 * key/signature material. This is intentionally NOT full curve-point
 * validation — that happens for free, and more rigorously, when these keys
 * are actually used in `verify()`/`x25519()`/`kemEncapsulate()` during
 * Phase 5 (those calls reject invalid points internally). This check exists
 * to catch obviously-corrupted or uninitialized data cheaply, before
 * spending a signature verification on it — it is a tripwire, not the only
 * line of defense.
 */
export function validateKeyEncodings(bundle: PreKeyBundle): void {
    const isAllZero = (bytes: Uint8Array) => bytes.every((b) => b === 0);
    const fields: Array<[Uint8Array, string]> = [
        [bundle.identityPublicKey, "identityPublicKey"],
        [bundle.signedPreKey.publicKey, "signedPreKey.publicKey"],
        [bundle.signedPreKey.signature, "signedPreKey.signature"],
        [bundle.pqPreKey.publicKey, "pqPreKey.publicKey"],
        [bundle.pqPreKey.signature, "pqPreKey.signature"],
    ];
    if (bundle.oneTimePreKey) {
        fields.push([bundle.oneTimePreKey.publicKey, "oneTimePreKey.publicKey"]);
    }
    for (const [bytes, field] of fields) {
        if (isAllZero(bytes)) {
            throw new ProtocolError(`Field is all-zero (invalid): ${field}`, "INVALID_FORMAT");
        }
    }
}

/** Verify the signed EC prekey's signature against the bundle's identity key. */
export function verifyBundleSignedPreKey(provider: CryptoProvider, bundle: PreKeyBundle): void {
    let ok: boolean;
    try {
        ok = verifySignedPreKey(provider, bundle.identityPublicKey, bundle.signedPreKey);
    } catch {
        // Anything that goes wrong while attempting verification (e.g. a
        // malformed field the encoder rejects) is still "this signature
        // could not be validated" from the caller's point of view — it
        // must surface as a classified ProtocolError, never an
        // unclassified crash (Phase 17: every failure has an explicit
        // classification).
        ok = false;
    }
    if (!ok) {
        throw new ProtocolError("Signed prekey signature verification failed", "INVALID_SIGNATURE");
    }
}

/** Verify the signed PQ prekey's signature against the bundle's identity key. */
export function verifyBundlePQPreKey(provider: CryptoProvider, bundle: PreKeyBundle): void {
    let ok: boolean;
    try {
        ok = verifyPQPreKey(provider, bundle.identityPublicKey, bundle.pqPreKey);
    } catch {
        ok = false;
    }
    if (!ok) {
        throw new ProtocolError("PQ prekey signature verification failed", "INVALID_SIGNATURE");
    }
}

/** Sanity-check id fields: must be safe non-negative integers. */
export function validateIdentifiers(bundle: PreKeyBundle): void {
    const isValidId = (id: number) => Number.isInteger(id) && id >= 0 && Number.isSafeInteger(id);
    if (!isValidId(bundle.signedPreKey.id)) {
        throw new ProtocolError(`Invalid signedPreKey.id: ${bundle.signedPreKey.id}`, "INVALID_FORMAT");
    }
    if (!isValidId(bundle.pqPreKey.id)) {
        throw new ProtocolError(`Invalid pqPreKey.id: ${bundle.pqPreKey.id}`, "INVALID_FORMAT");
    }
    if (bundle.oneTimePreKey && !isValidId(bundle.oneTimePreKey.id)) {
        throw new ProtocolError(
            `Invalid oneTimePreKey.id: ${bundle.oneTimePreKey.id}`,
            "INVALID_FORMAT",
        );
    }
}

/**
 * Full bundle validation pipeline (Phase 4.1). The spec lists six checks;
 * this runs `validateIdentifiers` before the two signature verifications
 * rather than strictly last as literally listed, because Phase 22's general
 * principle ("perform cheap structural validation before expensive
 * cryptographic processing") applies here too — id sanity is a cheap
 * structural check like the others, and running it first means a malformed
 * id gets a clean INVALID_FORMAT rejection instead of surfacing only as a
 * side effect of the signature check failing. Reject the entire bundle on
 * the first failing check — this throws (rather than silently continuing)
 * so a caller can never accidentally use a partially-validated bundle.
 */
export function validatePreKeyBundle(provider: CryptoProvider, bundle: PreKeyBundle): void {
    validateProtocolVersion(bundle);
    validateKeyLengths(bundle);
    validateKeyEncodings(bundle);
    validateIdentifiers(bundle);
    verifyBundleSignedPreKey(provider, bundle);
    verifyBundlePQPreKey(provider, bundle);
}
