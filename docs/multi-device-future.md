# Multi-Device — Deferred to a Future Version

**Status: not designed, not implemented.** This document exists so the
decision to defer isn't silently lost — it records the need, the two
proven real-world models to build on, and what this codebase already has
in place for it, without committing to a design before it's actually
scheduled.

## Why this isn't built yet

`docs/spec.md` lists "Multi-device" as implementation-order item 23, but —
unlike every other item, which gets its own detailed `## Phase N` section —
it has no design content anywhere in the spec: no data structures, no
flows, no requirements. Building it now would mean inventing a
security-sensitive protocol extension from scratch rather than implementing
one that's been reviewed. Two mature, public implementations already exist
and should be learned from rather than reinvented — see below.

## What "multi-device" means concretely

Right now, this codebase's `SessionManager` (and the `Identity` it's built
on) implicitly assumes one identity == one device. Multi-device means Alice
can have the same identity active on her phone, laptop, and tablet
simultaneously, and:

- A message Bob sends to Alice needs to reach *all* of her devices, not
  just whichever one established the session.
- Alice's own devices need to stay in sync with each other (a message she
  sends from her laptop should show up as sent on her phone too).
- A new device needs a way to be authorized ("linked") to an existing
  identity, and a lost/compromised device needs a way to be revoked without
  anyone being able to silently add a rogue device in its place.

## The two proven models

### Signal — the Sesame algorithm

Signal's own multi-device session-management layer, specified publicly at
[signal.org/docs/specifications/sesame](https://signal.org/docs/specifications/sesame/).
Key points, useful because they map unusually cleanly onto structures this
codebase already has:

- **Per-user vs. per-device identity keys** — Sesame explicitly supports
  both, but per-device keys isolate a compromise to one device rather than
  the whole account. (Signal itself and WhatsApp — see below — both now use
  per-device keys in practice.)
- **`UserRecord` → `DeviceRecord` → sessions.** Each device tracks, per
  contact, one `DeviceRecord` per one of the contact's devices; each
  `DeviceRecord` holds **one active session plus an ordered list of
  inactive sessions**. A `DeviceRecord` in this design is, functionally,
  almost exactly this codebase's existing `Session` type
  (`src/session/types.ts`) — Sesame's contribution is the bookkeeping layer
  *around* multiple sessions, not a different session primitive.
- **Fan-out, not group crypto.** Sending to a contact means: fetch their
  current device list, and for each non-stale device with an active
  session, **encrypt once per device using that device's own Double Ratchet
  session** (falling back to a fresh X3DH/PQXDH handshake for a device with
  no session yet). There is no shared group key or single "multi-device
  ciphertext" — every device pair still gets its own ordinary 1:1 session.
  This is the single most important takeaway for this codebase: **nothing
  about `SessionManager`, PQXDH, or the Double Ratchet itself needs to
  change.** Multi-device is an orchestration layer *above*
  `SessionManager`, the same relationship `WakuMessagingClient` already has
  to it.
- **Session convergence.** If two devices end up with mismatched
  active/inactive sessions (e.g. both initiated a handshake to the other
  around the same time), decrypting a message on an inactive session
  promotes it back to active, demoting whatever was active before. Both
  sides converge on the same session pair once each has sent and received
  at least one message on it.
- **Device-list discovery is pull-based, piggybacked on sending.** The
  sender includes its believed device list when submitting to the server;
  the server corrects it (removed devices → mark stale; new devices → the
  sender fetches their prekey bundles and creates new sessions) and the
  sender retries. No separate device-list subscription protocol.
- **Stale device records** (removed devices) are kept for a bounded
  `MAXLATENCY` window rather than deleted immediately, so a message
  encrypted just before removal can still be decrypted by a device that's
  slow to fetch its mailbox.

### WhatsApp — per-device keys with explicit linking signatures

WhatsApp's own account of their 2021 multi-device redesign:
[engineering.fb.com/2021/07/14/security/whatsapp-multi-device](https://engineering.fb.com/2021/07/14/security/whatsapp-multi-device/).
Same fan-out philosophy as Sesame (encrypt once per device, N pairwise
sessions), with two details worth carrying over specifically:

- **Explicit mutual signing on device linking.** When a new companion
  device is linked (via QR code), the *primary* device signs the new
  device's public identity key (an "Account Signature"), and the *new*
  device signs the primary's public identity key back (a "Device
  Signature"). Only once both signatures exist is the new device trusted
  by anyone. This is a clean, small, directly-reusable pattern for this
  codebase: it's the exact same domain-separated-signature shape already
  used for signed prekeys (`src/prekeys/signing.ts`) and session resets
  (`src/session/reset.ts`) — a `LINK_DEVICE` payload signed by both sides,
  with its own domain-separation label, would fit the existing pattern
  with no new cryptographic primitive.
- **Server-side device list per account, with user-visible management.**
  Users can see all linked devices and remotely revoke ("log out") any of
  them. Whatever this project ends up using for device-list storage (a
  server, or a Waku content topic analogous to how prekey bundles would
  need their own discovery mechanism — see below), it needs an equivalent
  user-facing revocation path, not just an internal data structure.

## What this codebase already has ready to build on

- `SessionManager` is already a clean 1:1 session primitive — exactly what
  both models fan out over. No changes needed there for multi-device
  itself.
- The domain-separated Ed25519 signing pattern
  (`src/prekeys/signing.ts`, `src/session/reset.ts`) is the right shape for
  a `LINK_DEVICE`/`REVOKE_DEVICE` payload — same reasoning both those
  modules already document: identity-key signatures that don't depend on
  any particular session's (possibly-uncertain) ratchet state.
- `PreKeyBundle` per device already works unmodified — each device
  publishes its own bundle, exactly as WhatsApp's and Sesame's per-device
  model requires.

## What's genuinely new work, not yet started

- A device-list data structure and its storage/sync mechanism (the biggest
  open design question — this project has no server component today, so
  "where does the device list live" needs an answer: a Waku content topic
  per identity, similar to how prekey bundle discovery itself is also not
  yet built — see the README's protocol-readiness notes — or some other
  mechanism).
- The fan-out orchestration layer itself (something like Sesame's
  `UserRecord`/`DeviceRecord`, sitting above `SessionManager` the way
  `WakuMessagingClient` does).
- `LINK_DEVICE`/`REVOKE_DEVICE` signed payloads and the pairing flow (QR
  code or equivalent) that produces them.
- Stale-session/stale-device pruning policy (Sesame's `MAXLATENCY` window
  is a reasonable starting point).
- Own-account sync (a device seeing what a user's *other* devices sent) —
  this is Sesame's "include the sender's own UserID in the fan-out" trick,
  which also needs deciding whether it's in scope for v1 of multi-device
  here.

None of this should start until it's actually scheduled and reviewed as its
own design — this document is the starting point for that conversation,
not a plan already in motion.
