import type { CryptoProvider } from "../crypto/CryptoProvider.js";
import type { Identity } from "../identity/types.js";
import type { PreKeyBundle } from "../prekeys/PreKeyBundle.js";
import { CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS } from "../prekeys/PreKeyBundle.js";
import type { SignedPreKey, PQPreKey } from "../prekeys/types.js";
import type { PrekeyStore } from "../prekeys/PrekeyStore.js";
import { pqxdhInitiate } from "../pqxdh/PQXDHInitiator.js";
import { pqxdhRespond, type PQXDHResponderInput } from "../pqxdh/PQXDHResponder.js";
import { ratchetInitAlice, ratchetInitBob, ratchetEncrypt, ratchetDecrypt } from "../ratchet/DoubleRatchet.js";
import { bytesToHex } from "../encoding/canonical.js";
import { ProtocolError } from "../errors.js";
import { buildSessionAssociatedData } from "./associatedData.js";
import { signSessionReset, verifySessionReset } from "./reset.js";
import type {
    Session,
    SessionId,
    MessageEnvelope,
    SessionInitEnvelope,
    MessageEnvelopeData,
    SessionResetEnvelope,
} from "./types.js";

/**
 * Bob-side lookup for his own local signed/PQ prekey records by id
 * (SessionManager doesn't own that storage — see Phase 3/4's existing
 * modules — it just needs to find the right one to respond with).
 */
export interface LocalPrekeyLookup {
    getSignedPreKey(id: number): SignedPreKey | undefined;
    getPQPreKey(id: number): PQPreKey | undefined;
}

/**
 * SessionManager (Phase 9's MessagingSession, Phase 14's session lifecycle,
 * Phase 16's idempotent init handling, Phase 23's session-lookup routing —
 * combined, since in this implementation they're one small enough surface
 * to not warrant splitting into separate classes yet). In-memory only
 * (Phase 33's first milestone); Phase 13's encrypted-at-rest persistence is
 * a distinct later concern that can wrap this without changing its logic.
 *
 * The application only ever sees plaintext in and MessageEnvelope out (or
 * vice versa) — it never touches DoubleRatchetState, PQXDH's SK, or any
 * other cryptographic internals directly (Invariant 10).
 */
export class SessionManager {
    private readonly sessions = new Map<string, Session>();

    constructor(
        private readonly provider: CryptoProvider,
        private readonly localIdentity: Identity,
        private readonly oneTimePreKeyStore: PrekeyStore,
        private readonly localPrekeys: LocalPrekeyLookup,
    ) {}

    getSession(sessionId: SessionId): Session | undefined {
        return this.sessions.get(bytesToHex(sessionId));
    }

    /**
     * Register an already-established Session directly — e.g. one loaded
     * from persistent storage (Phase 13) rather than created via
     * `createSession`/`receiveMessage` in this process. Throws if a session
     * with the same id is already registered, to avoid silently clobbering
     * live in-memory ratchet state with a possibly-stale loaded copy.
     */
    restoreSession(session: Session): void {
        const key = bytesToHex(session.sessionId);
        if (this.sessions.has(key)) {
            throw new ProtocolError(
                "A session with this id is already registered in this SessionManager",
                "SESSION_STATE_CORRUPTED",
            );
        }
        this.sessions.set(key, session);
    }

    /**
     * Alice's flow: run PQXDH against Bob's bundle, initialize the Double
     * Ratchet (Bob's SPK becomes his initial ratchet public key — real DR
     * spec §7.1), and immediately encrypt `initialPlaintext` as the first
     * ratchet message, bundled into one SESSION_INIT envelope Alice sends
     * to Bob. (Retransmitting this exact envelope if it's lost, per Phase
     * 16, is the caller's concern — this method is naturally idempotent
     * to call again since it always mints a fresh sessionId/ephemeral key,
     * i.e. it's Bob's receiving side that needs the idempotency guard, not
     * this one; see receiveMessage.)
     */
    createSession(
        remoteBundle: PreKeyBundle,
        initialPlaintext: Uint8Array,
    ): { session: Session; envelope: SessionInitEnvelope } {
        const pqxdhResult = pqxdhInitiate(this.provider, this.localIdentity, remoteBundle);
        const sessionId = this.provider.randomBytes(32);

        const ratchetState = ratchetInitAlice(this.provider, pqxdhResult.sk, remoteBundle.signedPreKey.publicKey);
        this.provider.secureErase(pqxdhResult.sk); // consumed into the root key; no longer needed

        const associatedData = buildSessionAssociatedData(
            CURRENT_PROTOCOL_VERSION,
            pqxdhResult.associatedData,
            sessionId,
        );

        const session: Session = {
            sessionId,
            protocolVersion: CURRENT_PROTOCOL_VERSION,
            localIdentity: this.localIdentity,
            remoteIdentityPublicKey: remoteBundle.identityPublicKey,
            associatedData,
            ratchetState,
            createdAt: Date.now(),
        };

        const { header, ciphertext } = ratchetEncrypt(this.provider, ratchetState, initialPlaintext, associatedData);

        const envelope: SessionInitEnvelope = {
            type: "SESSION_INIT",
            protocolVersion: CURRENT_PROTOCOL_VERSION,
            sessionId,
            senderIdentityPublicKey: this.localIdentity.keyPair.publicKey,
            ephemeralPublicKey: pqxdhResult.ephemeralPublicKey,
            pqCiphertext: pqxdhResult.pqCiphertext,
            signedPreKeyId: pqxdhResult.usedSignedPreKeyId,
            oneTimePreKeyId: pqxdhResult.usedOneTimePreKeyId,
            pqPreKeyId: pqxdhResult.usedPqPreKeyId,
            ratchetHeader: header,
            ciphertext,
        };

        this.sessions.set(bytesToHex(sessionId), session);
        return { session, envelope };
    }

    /** Bob's flow, or either party receiving an ordinary MESSAGE. Dispatches per Phase 22/23's routing. */
    receiveMessage(envelope: MessageEnvelope): { session: Session; plaintext: Uint8Array } {
        // Cheap structural validation before any cryptographic work (Phase 22).
        if (!SUPPORTED_PROTOCOL_VERSIONS.has(envelope.protocolVersion)) {
            throw new ProtocolError(
                `Unsupported protocol version: ${envelope.protocolVersion}`,
                "UNSUPPORTED_VERSION",
            );
        }

        const existing = this.sessions.get(bytesToHex(envelope.sessionId));

        if (envelope.type === "MESSAGE") {
            // Phase 23: "Unknown session + ordinary MESSAGE -> Reject. Never
            // automatically create a session from an arbitrary encrypted message."
            if (!existing) {
                throw new ProtocolError("Unknown session for MESSAGE envelope", "UNKNOWN_SESSION");
            }
            return this.decryptOnExistingSession(existing, envelope);
        }

        // envelope.type === "SESSION_INIT"
        if (existing) {
            // Phase 16: a retransmitted initial message must converge on the
            // SAME session, not create a second one. We don't re-run PQXDH
            // or re-touch the prekey store at all — route straight to the
            // ordinary decrypt path. If this really is an exact duplicate of
            // an already-consumed message #0, the ratchet's own replay
            // protection (proven in the Double Ratchet test suite) rejects
            // it the same way any other replay would be rejected.
            return this.decryptOnExistingSession(existing, envelope);
        }
        return this.processNewSessionInit(envelope);
    }

    /** Convenience wrapper: encrypt an application message for an already-established session. */
    sendMessage(sessionId: SessionId, plaintext: Uint8Array): MessageEnvelopeData {
        const session = this.getSession(sessionId);
        if (!session) {
            throw new ProtocolError("Unknown session", "UNKNOWN_SESSION");
        }
        const { header, ciphertext } = ratchetEncrypt(
            this.provider,
            session.ratchetState,
            plaintext,
            session.associatedData,
        );
        return {
            type: "MESSAGE",
            protocolVersion: session.protocolVersion,
            sessionId: session.sessionId,
            ratchetHeader: header,
            ciphertext,
        };
    }

    /**
     * Phase 19: destroy local session state — root key, both chain keys,
     * the DH ratchet private key, and every stored skipped message key —
     * when cryptographic state is uncertain (storage corruption, device
     * restore, excessive skipped-message state, explicit user action).
     * Per Phase 32 Invariant 6 ("old message keys are deleted") and
     * Invariant 7 ("ratchet private keys are never serialized into logs"),
     * this zeroes the material via `secureErase` rather than just dropping
     * the map entry and leaving it to the GC.
     *
     * Returns a SESSION_RESET envelope, signed with the long-term identity
     * key so the peer can verify it really came from them — signing here
     * cannot itself fail because of the corruption being reset from, since
     * it depends on none of the state above. Sending it is the caller's
     * concern (see WakuMessagingClient.resetSession); this method only
     * touches local state.
     */
    resetSession(sessionId: SessionId): SessionResetEnvelope {
        const key = bytesToHex(sessionId);
        const session = this.sessions.get(key);
        if (!session) {
            throw new ProtocolError("Unknown session", "UNKNOWN_SESSION");
        }

        const signature = signSessionReset(
            this.provider,
            this.localIdentity.keyPair.privateKey,
            session.protocolVersion,
            sessionId,
        );

        this.destroySessionState(session);
        this.sessions.delete(key);

        return {
            type: "SESSION_RESET",
            protocolVersion: session.protocolVersion,
            sessionId,
            signature,
        };
    }

    /**
     * Peer-initiated reset (Phase 19): the remote party has signaled that
     * their side of this session is gone. Verified against the identity key
     * already on file for this session — never destroy live session state
     * on the strength of an unauthenticated request, the same DoS concern
     * Phase 23 raises for auto-creating a session from an arbitrary
     * message, mirrored here for destruction. An unknown sessionId throws
     * rather than silently no-oping: there's nothing to destroy, and no
     * identity key on file to verify against even if there were.
     *
     * On a failed signature check, session state is left untouched — same
     * "failed authentication must not mutate state" invariant Phase 6/32
     * apply everywhere else in this protocol.
     */
    receiveSessionReset(envelope: SessionResetEnvelope): void {
        if (!SUPPORTED_PROTOCOL_VERSIONS.has(envelope.protocolVersion)) {
            throw new ProtocolError(
                `Unsupported protocol version: ${envelope.protocolVersion}`,
                "UNSUPPORTED_VERSION",
            );
        }

        const key = bytesToHex(envelope.sessionId);
        const session = this.sessions.get(key);
        if (!session) {
            throw new ProtocolError("Unknown session for SESSION_RESET envelope", "UNKNOWN_SESSION");
        }

        const valid = verifySessionReset(
            this.provider,
            session.remoteIdentityPublicKey,
            envelope.protocolVersion,
            envelope.sessionId,
            envelope.signature,
        );
        if (!valid) {
            throw new ProtocolError("Invalid signature on SESSION_RESET envelope", "INVALID_SIGNATURE");
        }

        this.destroySessionState(session);
        this.sessions.delete(key);
    }

    private destroySessionState(session: Session): void {
        const state = session.ratchetState;
        this.provider.secureErase(state.rootKey);
        this.provider.secureErase(state.DHs.privateKey);
        if (state.sendingChainKey) this.provider.secureErase(state.sendingChainKey);
        if (state.receivingChainKey) this.provider.secureErase(state.receivingChainKey);
        for (const messageKey of state.skippedMessageKeys.values()) {
            this.provider.secureErase(messageKey);
        }
        state.skippedMessageKeys.clear();
    }

    private decryptOnExistingSession(
        session: Session,
        envelope: SessionInitEnvelope | MessageEnvelopeData,
    ): { session: Session; plaintext: Uint8Array } {
        const plaintext = ratchetDecrypt(
            this.provider,
            session.ratchetState,
            envelope.ratchetHeader,
            envelope.ciphertext,
            session.associatedData,
        );
        return { session, plaintext };
    }

    /** Bob's fresh-session flow (Phase 5.3 + Phase 23's "Unknown session + SESSION_INIT"). */
    private processNewSessionInit(envelope: SessionInitEnvelope): { session: Session; plaintext: Uint8Array } {
        const signedPreKey = this.localPrekeys.getSignedPreKey(envelope.signedPreKeyId);
        if (!signedPreKey) {
            throw new ProtocolError(`Unknown signed prekey id: ${envelope.signedPreKeyId}`, "KEY_NOT_FOUND");
        }
        const pqPreKey = this.localPrekeys.getPQPreKey(envelope.pqPreKeyId);
        if (!pqPreKey) {
            throw new ProtocolError(`Unknown PQ prekey id: ${envelope.pqPreKeyId}`, "KEY_NOT_FOUND");
        }

        const responderInput: PQXDHResponderInput = {
            initiatorIdentityPublicKey: envelope.senderIdentityPublicKey,
            initiatorEphemeralPublicKey: envelope.ephemeralPublicKey,
            pqCiphertext: envelope.pqCiphertext,
            usedSignedPreKeyId: envelope.signedPreKeyId,
            usedOneTimePreKeyId: envelope.oneTimePreKeyId,
            usedPqPreKeyId: envelope.pqPreKeyId,
        };

        // pqxdhRespond reserves (doesn't consume) any referenced one-time
        // prekey, and releases it itself if SK/AD derivation fails — see
        // PQXDHResponder.ts. What's left to us: commit (consume) on a
        // successful decrypt, or release on a failed one.
        const pqxdhResult = pqxdhRespond(
            this.provider,
            this.localIdentity,
            signedPreKey,
            pqPreKey,
            this.oneTimePreKeyStore,
            responderInput,
        );

        const ratchetState = ratchetInitBob(this.provider, pqxdhResult.sk, {
            publicKey: signedPreKey.publicKey,
            privateKey: signedPreKey.privateKey,
        });
        this.provider.secureErase(pqxdhResult.sk);

        const associatedData = buildSessionAssociatedData(
            envelope.protocolVersion,
            pqxdhResult.associatedData,
            envelope.sessionId,
        );

        let plaintext: Uint8Array;
        try {
            plaintext = ratchetDecrypt(
                this.provider,
                ratchetState,
                envelope.ratchetHeader,
                envelope.ciphertext,
                associatedData,
            );
        } catch (err) {
            // Phase 5.3: "do not permanently mutate session state before
            // authentication succeeds." Release the OTK reservation and do
            // NOT register a session — there is no partial session left
            // dangling from a failed initial message.
            if (pqxdhResult.reservedOneTimePreKeyId !== undefined) {
                this.oneTimePreKeyStore.releaseOneTimePreKey(pqxdhResult.reservedOneTimePreKeyId);
            }
            throw err;
        }

        // Success: commit. Consume the OTK now (Invariant 5: a consumed
        // one-time prekey can never be reused) and register the session.
        if (pqxdhResult.reservedOneTimePreKeyId !== undefined) {
            this.oneTimePreKeyStore.consumeOneTimePreKey(pqxdhResult.reservedOneTimePreKeyId);
        }

        const session: Session = {
            sessionId: envelope.sessionId,
            protocolVersion: envelope.protocolVersion,
            localIdentity: this.localIdentity,
            remoteIdentityPublicKey: envelope.senderIdentityPublicKey,
            associatedData,
            ratchetState,
            createdAt: Date.now(),
        };
        this.sessions.set(bytesToHex(envelope.sessionId), session);

        return { session, plaintext };
    }
}
