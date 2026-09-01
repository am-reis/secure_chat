import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import { concatBytes } from "../encoding/canonical.js";

/**
 * PQXDH parameters (spec §2.1). These are the four application-chosen
 * values that get folded into the KDF's `info` string, so a KDF output
 * computed under one parameter choice can never collide with one computed
 * under a different choice (different app, different curve, different
 * hash, different KEM).
 */
const PQXDH_APP_INFO = "SecureMessagingProtocol"; // must be ASCII, spec requires >= 8 bytes
const PQXDH_CURVE_LABEL = "CURVE25519";
const PQXDH_HASH_LABEL = "SHA-512";
const PQXDH_PQKEM_LABEL = "ML-KEM-1024";

const KDF_INFO_STRING = [PQXDH_APP_INFO, PQXDH_CURVE_LABEL, PQXDH_HASH_LABEL, PQXDH_PQKEM_LABEL].join(
    "_",
);
const KDF_INFO_BYTES = new TextEncoder().encode(KDF_INFO_STRING);

/**
 * F: 32 bytes of 0xFF for curve25519 (57 for curve448, not used here).
 * Prepended to the key material before HKDF, exactly as in XEdDSA — this
 * ensures the leading bytes of the HKDF input can never be misinterpreted
 * as a valid scalar or curve point encoding by anything that might later
 * try to reinterpret the raw bytes. This is not decoration; skipping it
 * would be exactly the kind of "ad-hoc HKDF(DH1||DH2||DH3||SS)" simplification
 * the spec explicitly forbids.
 */
const F_PREFIX = new Uint8Array(32).fill(0xff);

/** HKDF salt: all-zero, length equal to the hash output length (SHA-512 = 64 bytes). */
const ZERO_SALT_SHA512 = new Uint8Array(64);

const KDF_OUTPUT_LENGTH = 32;

/**
 * KDF(KM) from PQXDH spec §2.2, reproduced exactly:
 *   ikm  = F || KM
 *   salt = 64 zero bytes (hash output length for SHA-512)
 *   info = "{app}_{curve}_{hash}_{pqkem}"
 *   output = 32 bytes
 *
 * KM is the concatenation of the DH outputs and the KEM shared secret —
 * built by the caller (PQXDHInitiator/PQXDHResponder), not this function,
 * since the exact concatenation order (DH1||DH2||DH3[||DH4]||SS) depends on
 * whether a one-time prekey was used.
 */
export function pqxdhKdf(provider: CryptoProvider, km: Uint8Array): Uint8Array {
    const ikm = concatBytes(F_PREFIX, km);
    const prk = provider.hkdfExtract(ZERO_SALT_SHA512, ikm);
    return provider.hkdfExpand(prk, KDF_INFO_BYTES, KDF_OUTPUT_LENGTH);
}
