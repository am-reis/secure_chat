import { canonicalEncodeFields, encodeUint32BE } from "../encoding/canonical.js";
import type { RatchetHeader } from "./types.js";

/**
 * CONCAT(ad, header) — real spec §3.1: "Encodes a message header into a
 * parseable byte sequence, prepends the ad byte sequence, and returns the
 * result... a length value should be prepended to ensure the output is
 * parseable as a unique pair (ad, header)."
 *
 * canonicalEncodeFields already length-prefixes every field, so the
 * "unique pair" parseability requirement is satisfied directly — this is
 * exactly the ambiguity problem that module was built to prevent (Phase 4).
 * `ad` is passed through as an opaque already-encoded blob (e.g. PQXDH's
 * own AD, itself already domain-separated) — this function doesn't need to
 * know or care what's inside it.
 */
const MESSAGE_AD_DOMAIN = new TextEncoder().encode("secure-messaging/dr-message-ad/v1");

export function buildMessageAssociatedData(ad: Uint8Array, header: RatchetHeader): Uint8Array {
    return canonicalEncodeFields(
        MESSAGE_AD_DOMAIN,
        ad,
        header.ratchetPublicKey,
        encodeUint32BE(header.previousChainLength),
        encodeUint32BE(header.messageNumber),
    );
}
