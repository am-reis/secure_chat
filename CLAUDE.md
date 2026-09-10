# Project instructions for Claude

Secure Messaging Protocol — a transport-agnostic PQXDH + Double Ratchet
protocol core, per `docs/spec.md`. Pre-audit, not production ready (see
`SECURITY.md`). Start with [docs/getting-started.md](docs/getting-started.md)
if you need to understand what this codebase actually does before making
changes to it.

## Git workflow — read this before committing anything

Full detail and recipes: [docs/git-workflow.md](docs/git-workflow.md).
The operational rules, so they're actually followed rather than just
documented:

- **Never commit feature work directly to `main`.** `main` only advances
  via merging a `release/*` or `hotfix/*` branch, immediately followed by
  an annotated tag. If you're about to run `git commit` and `git branch
  --show-current` says `main`, stop and check out `develop` (or a
  `feature/*` branch off it) first — unless you are specifically in the
  middle of the release/hotfix recipe below.
- **Day-to-day work happens on `develop`** (or a `feature/<name>` branch
  off it for anything non-trivial, merged back into `develop` when done).
  `develop` is this project's "staging" — where work accumulates and gets
  validated together before a release, since there's no deployed staging
  environment for a library.
- **Two independent version numbers exist — do not conflate them.**
  `package.json`'s SemVer version (`v0.y.z` while pre-audit; `1.0.0` is
  reserved for after the security audit) is NOT the same thing as
  `CURRENT_PROTOCOL_VERSION` (the wire-level protocol version peers must
  agree on). A package release does not imply a protocol version change,
  and a protocol version change (Phase 27's versioning discipline) is a
  MAJOR package bump. See `docs/git-workflow.md`'s "Two version numbers"
  section before touching either.
- **Releases**: cut `release/vX.Y.0` from `develop`, bump
  `package.json`, fold `CHANGELOG.md`'s `## Unreleased` into a dated
  section, merge to `main`, tag (`git tag -a vX.Y.0 -m "..."`, always
  annotated), merge back into `develop`, delete the release branch. Full
  recipe in `docs/git-workflow.md`.
- **Hotfixes**: branch from the exact tag on `main` (not from `develop`,
  which may have unrelated unreleased work on it), fix, bump PATCH, merge
  into both `main` and `develop`, tag, delete the branch.
- **`claude/protocol-foundation` is not part of this branching model.**
  It's the export branch `../pull_from_git_bundle.sh` syncs across
  machines — leave it alone unless the user specifically asks about
  cross-machine sync.
- **Never run `npm publish` (or `npm publish --dry-run`'s non-dry-run
  cousin) directly.** This package publishes publicly to npm exclusively
  through `.github/workflows/release.yml`, gated behind the `npm-publish`
  GitHub Environment's required-reviewer approval — that gate is the
  whole point (a human approves every release of an installable public
  package). `npm publish --dry-run` is fine any time (it never actually
  publishes); the real command is not, ever, run locally or by me. See
  `docs/git-workflow.md`'s "CI and npm publishing" section.

## Other conventions (already established, don't relitigate)

- Commit message conventions, the phase-based CHANGELOG discipline, and
  the general engineering ground rules (no hand-rolled crypto, fail
  closed, domain-separated signatures, `secureErase` consumed secrets):
  [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
- Every non-trivial claim about this codebase's behavior should be
  verified (read the source, run the test), not assumed from memory —
  this applies doubly to external library/protocol details (this
  project's own standard: PQXDH/Double Ratchet specs and `@waku/sdk`'s
  actual API were fetched and verified before being relied on, not
  reconstructed from training data).
- `npm run typecheck && npm test` clean before any commit. `npm run
  build` (which also copies `envelope.pb.js`/`.d.ts` into `dist/` —
  `tsc` alone won't) before verifying anything packaging-related.
