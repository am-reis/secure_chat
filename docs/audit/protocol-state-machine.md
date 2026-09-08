# Protocol State Machine

Phase 31, item 3 of [docs/spec.md](../spec.md). Four related but distinct
state machines exist in this protocol at different layers — conflating
them (e.g. treating "session established" and "message delivered" as the
same kind of state) is a common source of confusion this document tries
to head off by keeping them clearly separate.

## 1. Session state — deliberately binary, no partial states

```
                    createSession()  or  successful
                    processing of a SESSION_INIT
   NON-EXISTENT ─────────────────────────────────► ESTABLISHED
        ▲                                                │
        │                                                │
        └──────── resetSession() / verified ──────────────┘
                   receiveSessionReset()
```

A session is either **NON-EXISTENT** (no entry in `SessionManager`'s
internal map for that `sessionId`) or **ESTABLISHED** (a full `Session`
object, ratchet initialized, registered). There is no third,
partially-established state reachable from outside the process — this is
a deliberate structural property, not an incidental one:

- **`createSession` (Alice)**: runs the entire PQXDH handshake and
  ratchet initialization, then registers the session — all inside one
  synchronous call. There is no "handshake sent, awaiting confirmation"
  intermediate state Alice's own `SessionManager` tracks; the moment
  `createSession` returns, the session is fully ESTABLISHED on her side
  (though see §2 below — "established" doesn't yet mean "can send and
  receive both directions").
- **`receiveMessage` with a `SESSION_INIT` for an unknown session
  (Bob)**: either the initial message decrypts successfully and the
  session transitions straight to ESTABLISHED with the OTK committed, or
  it doesn't and *nothing* is registered — the reserved one-time prekey
  is released, no partial `Session` object exists anywhere
  (`SessionManager.processNewSessionInit`, Phase 5.3, proven in
  `test/session/SessionManager.test.ts`). There is no failed/pending
  session left over to clean up later.
- **A repeated `SESSION_INIT` for an already-ESTABLISHED session**
  (Phase 16 — the retransmission case) does not create a second session
  or move anything to a third state; it's routed straight to the
  existing session's ordinary decrypt path, converging on the one
  session that already exists.
- **`resetSession`/`receiveSessionReset`** (Phase 19) move an
  ESTABLISHED session directly back to NON-EXISTENT — full destruction,
  not a third "resetting" state. A verified, authenticated
  `receiveSessionReset` is the only way an external message can move a
  session backward to NON-EXISTENT; an unauthenticated one leaves the
  session exactly where it was (see §3 — this is enforced at the routing
  layer before the session-state transition is even considered).

## 2. Per-session ratchet state — field validity over time

Within an ESTABLISHED session, `DoubleRatchetState`'s fields aren't all
meaningful from the moment of establishment — this is the layer where
"established" and "fully bidirectional" are different things:

| Field | Alice, immediately after `createSession` | Bob, immediately after processing `SESSION_INIT` |
|---|---|---|
| `DHs` | Alice's freshly generated ratchet keypair | Bob's SPK keypair (his PQXDH signed prekey, reused as his *initial* ratchet keypair per the real Double Ratchet spec §7.1 — not a freshly generated one) |
| `DHr` | Bob's SPK public key | `null` |
| `rootKey` | Set (from `KDF_RK` off PQXDH's `SK`) | Set (same derivation, Bob's side) |
| `sendingChainKey` | Set — **Alice can send immediately** | `null` — **`ratchetEncrypt` throws if called before Bob receives and processes Alice's first message and performs his own first DH ratchet step** |
| `receivingChainKey` | `null` until Bob's first reply arrives | Set (from processing Alice's first message) |

Bob's inability to send until he's received something from Alice first is
structural (`state.sendingChainKey === null` throws,
`src/ratchet/DoubleRatchet.ts:107`), not a policy choice enforced
elsewhere — this matches the real Double Ratchet spec's own asymmetric
initialization (Alice as the initiator gets a head start on her sending
chain; Bob's sending chain only exists once he's ratcheted forward off
Alice's first message).

**Every ratchet field transition** from that point forward — DH ratchet
steps, chain advances, skipped-key accumulation — goes through the
clone-then-commit pattern documented in the cryptographic design
document and `docs/security-invariants.md` (Invariant 4): a working
clone is mutated freely, but only committed back onto the live session
state after the AEAD check on the current operation actually succeeds.
There is no reachable intermediate/torn state between "before this
operation" and "after this operation fully succeeded."

## 3. Envelope routing — Phase 22's pipeline, as actually implemented

```
raw bytes
   │
   ▼
decodeEnvelope()              ── malformed protobuf, or ENVELOPE_TYPE_UNSPECIFIED
   │                              → throws INVALID_FORMAT, nothing further happens
   ▼
protocol version check         ── not in SUPPORTED_PROTOCOL_VERSIONS
   │                              → throws UNSUPPORTED_VERSION
   ▼
session lookup (by sessionId)
   │
   ├── type = MESSAGE, session unknown ──────► throws UNKNOWN_SESSION (§1's invariant:
   │                                             never auto-create from an arbitrary message)
   ├── type = MESSAGE, session known ────────► ratchetDecrypt on the existing session
   │
   ├── type = SESSION_INIT, session known ───► routed to the SAME decrypt path as MESSAGE
   │                                             (Phase 16 convergence — §1 above)
   ├── type = SESSION_INIT, session unknown ─► full PQXDH responder flow (§1's second bullet)
   │
   ├── type = SESSION_RESET, session unknown ► throws UNKNOWN_SESSION (nothing to reset,
   │                                             and no identity key on file to verify against)
   └── type = SESSION_RESET, session known ──► signature verified against the identity
                                                 already on file; valid → destroy (§1); invalid →
                                                 throws INVALID_SIGNATURE, session left untouched
```

Cheap structural checks (decode, version) always run before any
cryptographic work — Phase 22's own stated principle, and the reason
`decodeEnvelope`/version-checking are fuzzed independently of the full
session-processing path (`test/fuzz/`).

At the transport-client layer (`WakuMessagingClient`), every one of these
throw paths is caught and routed to `onError`, never left to crash
message processing for anything else on the same content topic — see
`docs/integration-guide.md`'s transport section for the practical
consequence (a client's own published message coming back to itself and
failing to decrypt is exactly this path, routed to `onError` as expected
noise).

## 4. Application-level message delivery states — specified, not implemented

`docs/spec.md`'s Phase 25 defines a delivery-state model:

```
CREATED → ENCRYPTED → QUEUED → PUBLISHED → RECEIVED → DECRYPTED → ACKNOWLEDGED
```

**This is not implemented as tracked state anywhere in this codebase** —
there is no `MessageState` type, no field on any object that holds one of
these values. It's a conceptual model `docs/spec.md` specifies for
whatever *application* is built on top of this protocol core to
implement, not something `SessionManager` or `WakuMessagingClient` track
internally. Worth stating explicitly rather than leaving an auditor to
search for it and conclude either that it's missing by accident or that
it must be hiding somewhere non-obvious: it isn't implemented, on
purpose, at this layer — the closest this codebase comes is:

- **`ENCRYPTED`**: the return value of `sessionManager.sendMessage`/
  `createSession`.
- **`PUBLISHED`**: `transport.publish` resolving — which Phase 25 itself
  is explicit does **not** mean `RECEIVED`: "do not treat successful
  Waku publication as successful recipient delivery... a transport-level
  acknowledgement means the transport accepted the message. It does not
  prove that the intended recipient received or decrypted it."
- **`DECRYPTED`**: the recipient's `receiveMessage` returning
  successfully.
- **`ACKNOWLEDGED`**: Phase 26's delivery/read receipts
  (`src/receipts/applicationContent.ts`) — themselves ordinary encrypted
  messages, exactly as Phase 25 requires ("if delivery receipts are
  implemented, they must themselves be encrypted application messages").

`CREATED` and `QUEUED` have no equivalent at all in this codebase — an
application tracking the full Phase 25 state machine needs to add that
tracking itself.
