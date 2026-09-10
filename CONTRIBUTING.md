# Contributing

This is currently a solo project — the repo is public
(`github.com/am-reis/secure_chat`) with CI and a docs site, but there's
just one maintainer and no external contributors yet. (A `git bundle`
sync path for working across machines without pushing also still exists
— see `../pull_from_git_bundle.sh` — independent of the GitHub remote,
not a replacement for it.) The conventions below are worth keeping even
solo, since they're what makes the commit history and README useful as
documentation.

## Setup

```bash
npm install
npm run typecheck      # tsc --noEmit, src + test
npm test                # vitest run
npm run proto:generate  # regenerate envelope.pb.{js,d.ts} after editing envelope.proto
```

Both `typecheck` and `test` should pass before any commit. No network
access is required to run the tests.

## Ground rules

- **Read [docs/spec.md](docs/spec.md) first.** It defines the protocol and
  the implementation order (Phase 33). Don't start with the UI, Waku
  integration, or persistence ahead of the core protocol — the spec is
  explicit about why.
- **No hand-rolled cryptography.** Wrap audited libraries
  (`@noble/*` currently) through `CryptoProvider` — no custom KDFs, curve
  arithmetic, or signature schemes. See [SECURITY.md](SECURITY.md).
- **Every phase gets a real test, not just a happy path.** Look at
  `test/ratchet/DoubleRatchet.test.ts` or
  `test/session/sessionReset.test.ts` for the bar: adversarial cases
  (tampering, replay, unauthenticated triggers) alongside the
  straightforward round-trip.
- **Domain-separate every signature.** If you add a new signed payload
  type, give it its own domain-separation label (see
  `src/prekeys/signing.ts`, `src/session/reset.ts`) so a signature valid in
  one context can never be replayed as valid in another.
- **Fail closed.** A failed AEAD decrypt, bad signature, or malformed
  envelope must never partially mutate state. If you're touching anything
  in `src/ratchet/` or `src/session/`, check what happens to state on the
  error path, not just the success path.
- **`secureErase` consumed secrets.** Root keys, chain keys, DH private
  keys — once a value is superseded or no longer needed, zero it rather
  than letting it sit for the GC.

## Commit conventions (from the existing history)

- Conventional-commit-style prefixes: `feat(<area>): ...`,
  `fix(<area>): ...`, `test(<area>): ...`, `docs: ...`, `chore: ...`.
- Reference the spec phase in the subject when the commit implements one,
  e.g. `feat(session): SESSION_RESET (Phase 19)`.
- A `feat`/`fix` commit that changes behavior described in the README is
  normally followed by a separate `docs: update README for Phase N` commit
  — keeps the README's Status section accurate without bloating the code
  commit's diff.
- When a bug is found and fixed, add a regression test in the same or a
  follow-up commit, and note the *why* (not just the *what*) either in the
  commit message or the README — see the two `ratchetInitBob` aliasing
  bugs in [CHANGELOG.md](CHANGELOG.md) for the level of detail that's
  actually useful later.
- Update [CHANGELOG.md](CHANGELOG.md) under `## Unreleased` for
  user-visible changes; fold it into a dated phase entry once the work is
  actually landed and stable.

## Branching and releases

See [docs/git-workflow.md](docs/git-workflow.md) for the full branching
model (`main`/`develop`/`feature`/`release`/`hotfix`), SemVer policy, and
step-by-step recipes for cutting a release or shipping a hotfix. Short
version: don't commit feature work directly to `main` — branch from
`develop`.
