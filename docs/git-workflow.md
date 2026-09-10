# Git Workflow: Branching, Versioning, Releases, Hotfixes

This project didn't have a formal branch/release strategy until now —
every commit landed directly on `main`. That was fine for a single
contributor building the protocol core in one continuous pass, but it
stops scaling the moment there's more than one thing in flight at once,
or a bug needs fixing in something already "released" while unrelated new
work is in progress. This document is the strategy going forward, and
[CLAUDE.md](../CLAUDE.md) carries the short operational version of it so
it's actually followed automatically rather than just written down once.

## Two version numbers, not one

This project has two independent things called "version," and conflating
them is a real mistake to avoid:

- **Package version** (`package.json`'s `"version"`, git tags `vX.Y.Z`) —
  ordinary SemVer for this npm package as a whole: its public API surface
  (`src/index.ts`), its behavior, its dependencies.
- **Protocol version** (`CURRENT_PROTOCOL_VERSION` in
  `src/prekeys/PreKeyBundle.ts`, checked via `SUPPORTED_PROTOCOL_VERSIONS`
  everywhere an envelope/bundle crosses a trust boundary) — the
  wire-level cryptographic parameter set two peers must agree on to talk
  to each other at all (Phase 27 of `docs/spec.md`).

A protocol version bump is very likely a package MAJOR bump (it changes
wire compatibility, which is about as breaking as an API gets). The
reverse isn't true: this package can go from `0.3.0` to `0.4.0` — new
features, new exported functions, even a `1.0.0` after the security audit
— without the protocol itself changing at all. **Never bump
`CURRENT_PROTOCOL_VERSION` as a side effect of an unrelated package
release, and never assume a package version bump implies wire
compatibility changed.** Phase 35 (post-quantum ratcheting) and Phase 36
(prekey bundle discovery) are both explicitly specced as landing under a
*new* `protocolVersion`, not a silent change to the current one — see
`docs/spec.md`.

## SemVer policy while this is pre-audit (`0.y.z`)

Per SemVer itself, `0.y.z` means "anything may change" — which happens to
also be the right honest signal for this project's actual state: **not
production ready, not yet audited** (see [SECURITY.md](../SECURITY.md)).
Concretely:

- **MINOR** (`0.1.0` → `0.2.0`): a new phase/feature lands (matches this
  project's existing CHANGELOG granularity — one phase, one MINOR bump,
  as a rule of thumb, though several small phases can ship together in
  one release).
- **PATCH** (`0.2.0` → `0.2.1`): bug fixes, docs, non-behavioral changes,
  hotfixes.
- **`1.0.0` is reserved** for after a real third-party security audit
  (Phase 31 of `docs/spec.md`) — don't cross that line casually just
  because a lot has accumulated. Crossing it is a statement about audit
  status, not feature completeness.

## Branches

```
main        ── always releasable; only advances via a release/* or hotfix/* merge, never a direct commit
  │
develop     ── integration branch; where finished feature work accumulates and gets validated together
  │              before being cut into a release. This is this project's answer to "staging" — there's
  │              no deployed staging environment for a library, so develop is where things are proven
  │              out together before main sees them.
  │
feature/*   ── one feature/phase, branched from develop, merged back into develop when done
release/*   ── cut from develop when preparing a release; final stabilization, version bump, changelog
hotfix/*    ── cut from a tag on main, for an urgent fix to something already released
```

- **`feature/<short-name>`** — branch from `develop`. For anything more
  than a trivial fix: a new phase, a new doc, a dependency bump. Merge
  back into `develop` (not `main`) when it's done, tests pass, and
  CHANGELOG's `## Unreleased` section has an entry. Trivial changes
  (a typo fix, a one-line doc correction) can go straight to `develop`
  without a feature branch — don't force ceremony where it doesn't earn
  its cost.
- **`release/vX.Y.0`** — branch from `develop` when `develop` has
  accumulated enough to ship. On this branch: bump `package.json`'s
  `version`, fold `## Unreleased` CHANGELOG entries into a dated/versioned
  section, do any final stabilization (nothing new — this branch doesn't
  grow features). When ready: merge into `main`, tag, merge back into
  `develop` (so `develop` picks up the version bump and changelog
  finalization too), delete the release branch.
- **`hotfix/vX.Y.Z`** — branch from the exact tag on `main` you're fixing
  (not from `develop`, which may already have unrelated unreleased work
  on it). Fix, test, bump the PATCH version, merge into **both** `main`
  and `develop`, tag, delete the branch.
- **`main`** — every commit reachable from `main` is something that was
  tagged, or is about to be. Never commit feature work directly here.
- **`claude/protocol-foundation`** — this predates the strategy above and
  serves a different purpose: it's the branch `../pull_from_git_bundle.sh`
  fetches from `../gitbundle/secure-messaging-foundation.bundle` to sync
  this repo across machines. It is **not** part of the release-branching
  model — don't treat it as `develop` or `main`'s equivalent. Updating it
  (re-exporting a bundle from wherever `main` currently is) is a separate,
  manual action for whoever manages the cross-machine sync, orthogonal to
  everything above.

## Recipes

**Starting a feature:**
```bash
git checkout develop
git pull                      # once a remote exists; no-op today
git checkout -b feature/session-reset
# ... work, commit per CONTRIBUTING.md's conventions ...
git checkout develop
git merge --no-ff feature/session-reset
git branch -d feature/session-reset
```

**Cutting a release:**
```bash
git checkout develop
git checkout -b release/v0.2.0
# bump package.json's "version" to 0.2.0
# fold CHANGELOG's ## Unreleased entries into a dated ## v0.2.0 section
git commit -am "chore(release): v0.2.0"
git checkout main
git merge --no-ff release/v0.2.0
git tag -a v0.2.0 -m "v0.2.0 — <one-line summary>"
git checkout develop
git merge --no-ff release/v0.2.0
git branch -d release/v0.2.0
```

**Applying a hotfix to something already released:**
```bash
git checkout -b hotfix/v0.2.1 v0.2.0        # branch from the TAG, not develop
# fix, test, bump package.json's "version" to 0.2.1
git commit -am "fix: <what broke>"
git checkout main
git merge --no-ff hotfix/v0.2.1
git tag -a v0.2.1 -m "v0.2.1 — <what this fixes>"
git checkout develop
git merge --no-ff hotfix/v0.2.1              # develop must not miss the fix
git branch -d hotfix/v0.2.1
```

## Tags

Annotated tags only (`git tag -a`, never lightweight `git tag`) — an
annotated tag carries a message, a tagger, and a date, which a lightweight
tag doesn't; that message is where "what's in this release" lives at a
glance (`git show v0.2.0`). Tag format: `vX.Y.Z`, always on `main`, always
right after the merge that completes a release or hotfix.

## CI and npm publishing

Two GitHub Actions workflows automate the checks/release steps above —
neither replaces the recipes; they run alongside them.

- **`.github/workflows/ci.yml`** — every push to `main`/`develop` and
  every PR against them: typecheck, test, build, a `npm publish --dry-run`
  sanity check, and a real packaging smoke test (pack the tarball, install
  it into a genuinely separate temp project, import from the published
  entrypoint, and check every expected export exists). That last step is
  not decorative — it's the exact class of check that caught a real bug
  before this package ever shipped (`tsc` alone doesn't copy
  `envelope.pb.js`/`.d.ts` into `dist/`; see `CHANGELOG.md`). Runs on a
  Node 20 + Node 22 matrix, since `package.json`'s `engines` field claims
  `>=20` — verified, not just asserted.
- **`.github/workflows/release.yml`** — triggered by pushing a `vX.Y.Z`
  tag. A `verify` job re-runs the same checks on the exact tagged commit
  (never trust that CI already passed on some earlier commit on the
  branch — the tag is what's about to ship) and confirms the tag matches
  `package.json`'s version. Only if that passes does a `publish` job
  become runnable — and it's gated behind the `npm-publish` GitHub
  Environment's required reviewers: a human has to click approve before
  `npm publish` actually runs, every release, on purpose, for a public,
  installable package. Publishing uses `--provenance` (cryptographic
  attestation that the published package really was built by this
  workflow, from this commit — npm's supply-chain-security feature), and
  the job also creates a GitHub Release from the annotated tag's own
  message.

**One-time manual setup this requires** (can't be done from a workflow
file or from here — needs the repo owner's GitHub/npm account access):

1. On npmjs.com: generate an **Automation**-type access token (Account →
   Access Tokens → Generate New Token → Automation — this type is meant
   for CI and isn't blocked by 2FA-per-publish the way a normal token is).
2. In the GitHub repo: **Settings → Secrets and variables → Actions →
   New repository secret**, name it `NPM_TOKEN`, paste the token from
   step 1.
3. In the GitHub repo: **Settings → Environments → New environment**,
   name it exactly `npm-publish` (must match `release.yml`'s
   `environment:` value), and add at least one required reviewer under
   "Deployment protection rules" — this is what actually makes step 3 of
   the release workflow a manual gate; the environment name alone does
   nothing without a reviewer configured.

Until all three exist, `release.yml`'s `publish` job will fail (missing
`NPM_TOKEN`) or never even show up as awaiting approval (missing
environment) — `ci.yml` and the `verify` job of `release.yml` work fine
without any of this, since neither actually publishes anything.

## Commit conventions

Unchanged — see [CONTRIBUTING.md](../CONTRIBUTING.md): conventional
prefixes (`feat`/`fix`/`test`/`docs`/`chore`), reference the spec phase
when implementing one, a `docs:` follow-up commit for README updates
rather than bloating the feature commit's diff.

## Now that a remote exists

The repo is hosted at `github.com/am-reis/secure_chat`. Everything above
still holds as the local-first recipe; going forward, `feature/*`
branches should get pushed and merged via pull request rather than a
local `git merge` where practical, and `develop`/`main` should eventually
be branch-protected (no direct pushes, only merges of reviewed PRs and of
`release/*`/`hotfix/*` branches) once that's set up in the repo's
settings — not yet configured as of this writing. Nothing about the
branch model itself needs to change to add that.
