import type { Identity } from "../identity/types.js";
import type { Session } from "../session/types.js";
import type { DoubleRatchetState } from "../ratchet/types.js";
import { bytesToHex, hexToBytes } from "../encoding/canonical.js";
import { ProtocolError } from "../errors.js";
import type { SerializedSession } from "./types.js";

export const CURRENT_SESSION_STATE_VERSION = 1;

export function serializeSession(session: Session): SerializedSession {
    const r = session.ratchetState;
    const skippedMessageKeys: Array<{ index: string; key: string }> = [];
    for (const [index, key] of r.skippedMessageKeys) {
        skippedMessageKeys.push({ index, key: bytesToHex(key) });
    }

    return {
        stateVersion: CURRENT_SESSION_STATE_VERSION,
        protocolVersion: session.protocolVersion,
        sessionId: bytesToHex(session.sessionId),
        localIdentityId: bytesToHex(session.localIdentity.identityId),
        remoteIdentityPublicKey: bytesToHex(session.remoteIdentityPublicKey),
        associatedData: bytesToHex(session.associatedData),
        createdAt: session.createdAt,

        ratchetPublicKey: bytesToHex(r.DHs.publicKey),
        ratchetPrivateKey: bytesToHex(r.DHs.privateKey),
        remoteRatchetPublicKey: r.DHr ? bytesToHex(r.DHr) : null,
        rootKey: bytesToHex(r.rootKey),
        sendingChainKey: r.sendingChainKey ? bytesToHex(r.sendingChainKey) : null,
        receivingChainKey: r.receivingChainKey ? bytesToHex(r.receivingChainKey) : null,
        sendingMessageNumber: r.sendingMessageNumber,
        receivingMessageNumber: r.receivingMessageNumber,
        previousSendingChainLength: r.previousSendingChainLength,
        skippedMessageKeys,
    };
}

/**
 * `localIdentity` is supplied by the caller, not reconstructed from the
 * record (see types.ts's note on why identity private keys aren't
 * duplicated into session records). Throws if the supplied identity's
 * identityId doesn't match what the session was actually established
 * under — loading a session against the wrong local identity would
 * silently produce a ratchet state that can never successfully
 * encrypt/decrypt anything, which is a confusing failure to debug; failing
 * fast here is much clearer.
 */
export function deserializeSession(serialized: SerializedSession, localIdentity: Identity): Session {
    if (bytesToHex(localIdentity.identityId) !== serialized.localIdentityId) {
        throw new ProtocolError(
            "Supplied identity does not match the identity this session was established under",
            "SESSION_STATE_CORRUPTED",
        );
    }
    if (serialized.stateVersion !== CURRENT_SESSION_STATE_VERSION) {
        throw new ProtocolError(
            `Unsupported session record stateVersion: ${serialized.stateVersion}`,
            "SESSION_STATE_CORRUPTED",
        );
    }

    const skippedMessageKeys = new Map<string, Uint8Array>();
    for (const { index, key } of serialized.skippedMessageKeys) {
        skippedMessageKeys.set(index, hexToBytes(key));
    }

    const ratchetState: DoubleRatchetState = {
        DHs: {
            publicKey: hexToBytes(serialized.ratchetPublicKey),
            privateKey: hexToBytes(serialized.ratchetPrivateKey),
        },
        DHr: serialized.remoteRatchetPublicKey ? hexToBytes(serialized.remoteRatchetPublicKey) : null,
        rootKey: hexToBytes(serialized.rootKey),
        sendingChainKey: serialized.sendingChainKey ? hexToBytes(serialized.sendingChainKey) : null,
        receivingChainKey: serialized.receivingChainKey ? hexToBytes(serialized.receivingChainKey) : null,
        sendingMessageNumber: serialized.sendingMessageNumber,
        receivingMessageNumber: serialized.receivingMessageNumber,
        previousSendingChainLength: serialized.previousSendingChainLength,
        skippedMessageKeys,
    };

    return {
        sessionId: hexToBytes(serialized.sessionId),
        protocolVersion: serialized.protocolVersion,
        localIdentity,
        remoteIdentityPublicKey: hexToBytes(serialized.remoteIdentityPublicKey),
        associatedData: hexToBytes(serialized.associatedData),
        ratchetState,
        createdAt: serialized.createdAt,
    };
}
