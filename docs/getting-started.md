# Getting Started

This is the shortest path from "I have this package installed" to "two
identities have exchanged encrypted messages." It covers the in-memory core
only — no persistence, no transport, no error handling beyond the happy
path. See [docs/integration-guide.md](integration-guide.md) for all of
that once this makes sense.

Every snippet below is the *actual, tested* code in
[`test/examples/quickstart.test.ts`](../test/examples/quickstart.test.ts) —
run `npm test -- quickstart` yourself to see it pass. This guide narrates
that file; it doesn't duplicate it as untested prose.

## Install

```bash
npm install secure-messaging-protocol
```

Everything importable lives on the single package entrypoint —
`import { ... } from "secure-messaging-protocol"` — see `src/index.ts` for
the full exported surface (and its own doc comment for why some internals,
like the raw Double Ratchet/PQXDH functions, are deliberately *not*
exported: the application is never meant to touch ratchet state directly).
This isn't just asserted — it's verified by actually packing the library
(`npm pack`), installing the tarball into a separate scratch project, and
running the exact flow below against the installed package, not just
against source within this repo.

## The mental model, in one paragraph

You generate an `Identity` (a long-term keypair) and a `PreKeyBundle` (a
small set of medium-term/one-time public keys, signed by your identity).
Someone else fetches your bundle from wherever you published it — **this
library does not do that part; see "What this library does not do" in the
[integration guide](integration-guide.md)** — and passes it to
`createSession`, which runs a full PQXDH handshake and encrypts a first
message in one call. You feed the resulting envelope into your own
`SessionManager.receiveMessage`, and from that point on both sides just
call `sendMessage`/`receiveMessage` for ordinary messages. A
`SessionManager` owns all the sessions for **one** identity, in memory,
transport-agnostic — it never sends anything over a network itself.

## Step 1 — Bob generates an identity and publishes a bundle

```ts
import {
    NobleCryptoProvider,
    generateIdentity,
    generateSignedPreKey,
    generatePQPreKey,
    generateOneTimePreKeys,
    buildPreKeyBundle,
    InMemoryPrekeyStore,
} from "secure-messaging-protocol";

const provider = new NobleCryptoProvider();
const THIRTY_DAYS = 30 * 24 * 60 * 60 * 1000;

const bobIdentity = generateIdentity(provider);
const bobSignedPreKey = generateSignedPreKey(provider, bobIdentity, /* id */ 1, THIRTY_DAYS);
const bobPqPreKey = generatePQPreKey(provider, bobIdentity, /* id */ 1, THIRTY_DAYS);
const [bobOneTimePreKey] = generateOneTimePreKeys(provider, /* startId */ 1, /* count */ 1);

const bobOneTimePreKeyStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
bobOneTimePreKeyStore.addOneTimePreKeys([bobOneTimePreKey]);

const bobBundle = buildPreKeyBundle(bobIdentity, bobSignedPreKey, bobPqPreKey, bobOneTimePreKey);
```

Some things worth knowing already at this point:

- `bobIdentity.keyPair.privateKey` must never leave Bob's device. Everything
  you'd ever transmit is already separated out into `bobBundle`, which is
  public-key-only by construction.
- The one-time prekey is *optional* — `buildPreKeyBundle(bobIdentity, bobSignedPreKey, bobPqPreKey)`
  (no fourth argument) is valid if Bob has run out of one-time prekeys.
  PQXDH still works without one; it's one fewer DH term in the handshake.
- `generateOneTimePreKeys` takes a *count* — generate a batch (dozens,
  typically) up front, not one at a time, and replenish before you run out.
  This library doesn't decide replenishment policy for you.
- IDs (`1` above) are yours to assign and must be unique per key type per
  identity — `InMemoryPrekeyStore`/`MapPrekeyLookup` below key on them.

## Step 2 — Bob's SessionManager needs to find its own prekeys by id

`SessionManager` doesn't own prekey storage — it asks a small interface,
`LocalPrekeyLookup`, to look up *Bob's own* signed/PQ prekeys by the id a
`SESSION_INIT` references (so it can respond to a handshake). A `Map` is
enough for a single-identity app:

```ts
import { SessionManager, type LocalPrekeyLookup, type SignedPreKey, type PQPreKey } from "secure-messaging-protocol";

class MapPrekeyLookup implements LocalPrekeyLookup {
    private readonly signed = new Map<number, SignedPreKey>();
    private readonly pq = new Map<number, PQPreKey>();
    addSignedPreKey(k: SignedPreKey) { this.signed.set(k.id, k); }
    addPQPreKey(k: PQPreKey) { this.pq.set(k.id, k); }
    getSignedPreKey(id: number) { return this.signed.get(id); }
    getPQPreKey(id: number) { return this.pq.get(id); }
}

const bobPrekeyLookup = new MapPrekeyLookup();
bobPrekeyLookup.addSignedPreKey(bobSignedPreKey);
bobPrekeyLookup.addPQPreKey(bobPqPreKey);

const bobManager = new SessionManager(provider, bobIdentity, bobOneTimePreKeyStore, bobPrekeyLookup);
```

## Step 3 — Alice generates her own identity

```ts
const aliceIdentity = generateIdentity(provider);
const aliceOneTimePreKeyStore = new InMemoryPrekeyStore(provider.secureErase.bind(provider));
const alicePrekeyLookup = new MapPrekeyLookup(); // empty here — Alice isn't receiving a SESSION_INIT in this example
const aliceManager = new SessionManager(provider, aliceIdentity, aliceOneTimePreKeyStore, alicePrekeyLookup);
```

Alice doesn't need any prekeys of her own to *start* a conversation —
prekeys are only consumed by whoever is on the receiving end of a fresh
handshake. She'd still generate a full bundle of her own (repeat Step 1)
so other people can start conversations with *her*.

## Step 4 — Alice establishes a session and sends the first message

```ts
const utf8 = (s: string) => new TextEncoder().encode(s);

const { session: aliceSession, envelope: sessionInit } = aliceManager.createSession(
    bobBundle,
    utf8("hi bob, this is alice"),
);
```

One call does the entire PQXDH handshake *and* encrypts the first
plaintext — there's no separate "connect" step. `sessionInit` is a
`SessionInitEnvelope`: everything Bob needs to both complete the handshake
and decrypt this first message. It's what you'd hand to your transport
layer to actually deliver (see the [integration guide](integration-guide.md)).

## Step 5 — Bob receives it

```ts
const { session: bobSession, plaintext: bobReceived } = bobManager.receiveMessage(sessionInit);
// text(bobReceived) === "hi bob, this is alice"
```

`receiveMessage` recognizes this is a `SESSION_INIT` for a session it
doesn't know yet, runs the responder side of PQXDH, and decrypts the first
message — also in one call. `bobSession.sessionId` and
`bobSession.associatedData` now equal `aliceSession`'s — that equality
*is* what "the session is established" means concretely, and it's worth
asserting in your own integration tests the same way
`test/examples/quickstart.test.ts` does.

## Step 6 — Ordinary messages after that

```ts
const bobReply = bobManager.sendMessage(sessionInit.sessionId, utf8("hi alice, bob here"));
const { plaintext: aliceReceived } = aliceManager.receiveMessage(bobReply);
// text(aliceReceived) === "hi alice, bob here"

const aliceSecondMessage = aliceManager.sendMessage(aliceSession.sessionId, utf8("how are you?"));
const { plaintext: bobReceivedSecond } = bobManager.receiveMessage(aliceSecondMessage);
// text(bobReceivedSecond) === "how are you?"
```

Symmetric from here — `sendMessage(sessionId, plaintext)` on the sending
side, `receiveMessage(envelope)` on the receiving side, in either
direction, indefinitely.

## What you have *not* built yet

This whole example lives in memory and never leaves the process. That's
deliberate — it's this library's own "first milestone" (see
`docs/spec.md`'s Phase 33). Before this is a real app, you still need, in
roughly this order:

1. **A way to get `bobBundle` from Bob to Alice.** Not built by this
   library — see the integration guide.
2. **Persistence**, if a session needs to survive a restart — and the one
   safety rule that goes with it (`sendMessageDurably`, not `sendMessage`,
   once a session is persisted). This is the single most important thing
   to read before shipping anything real — see the integration guide's
   first section.
3. **A transport** — `MockWakuTransport` for local dev, `RealWakuTransport`
   for production, both behind the same interface your application code
   never needs to know about.

Continue to [docs/integration-guide.md](integration-guide.md).
