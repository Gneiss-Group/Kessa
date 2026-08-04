# Branching, commits, and releases

How work gets from an idea to a tagged artifact. Kessa is solo-maintained and
[not yet accepting external code](../CONTRIBUTING.md), so these rules are sized
for one maintainer plus review agents, but they are written to survive a second
contributor without being rewritten.

## Branches

**`main` is always releasable.** It is the only long-lived branch. There is no
`develop`, no release branch, and no maintenance branch until a released version
actually needs a fix that `main` has moved past.

**Work happens on short-lived branches off `main`,** merged back by pull request
and deleted afterwards. Short means days. A branch that lives long enough to need
a merge from `main` twice is a branch that should have been split.

Branch names are `type/short-description`, using the same types as the commit
convention below:

```
feat/status-list-caching
fix/proxy-seq-collision
sec/r2-01-issuance-signature-scope
docs/branching-standard
chore/bump-go-1.27
```

**Nothing is pushed directly to `main`: including releases.** The version bump
lands through a pull request like everything else (see [Releasing](#releasing)),
so `main` needs no bypass for any workflow, and the commit that lands is the
GitHub-signed squash-merge commit.

### Protecting `main`

[`CODEOWNERS`](../CODEOWNERS) declares the verifier and its Apache-tier
dependency closure as owner-reviewed, but a `CODEOWNERS` file only *declares*:
enforcement comes from branch protection, which is repository configuration and
is not carried by anything in this tree. The intended settings for `main`:

- require a pull request before merging
- require review from code owners
- require the **CI** workflow to pass
- require signed commits (the release lands via a squash-merge, which GitHub signs)
- disallow force pushes and deletion

No bypass is needed: the release does not push to `main`, it opens a PR you
squash-merge (see [Releasing](#releasing)).

## Commits

Kessa uses [Conventional Commits](https://www.conventionalcommits.org). This is
not a style preference: the release pipeline reads the commit history to decide
whether the next version is a patch, a minor, or a major, and to write the
release notes. An unconventional subject line does not break the release, it
lands under "Other changes", but it does forfeit its say in the version number.

```
<type>(<optional scope>)<optional !>: <subject>

<optional body>

<optional footer, e.g. BREAKING CHANGE: ...>
```

Types in use:

| Type | For | Version effect |
|------|-----|----------------|
| `feat` | a new capability | minor |
| `fix` | a defect fixed | patch |
| `sec` | a security finding closed | patch (minor if it changes behaviour) |
| `perf` | a performance change with no behaviour change | patch |
| `docs` | documentation only | patch |
| `test` | tests only | patch |
| `refactor` | no behaviour change | patch |
| `build`, `ci`, `chore` | tooling, pipeline, housekeeping | patch |

A `!` after the type, or a `BREAKING CHANGE:` footer, marks a breaking change.
Both are read by [`scripts/release/next-version.sh`](../scripts/release/next-version.sh).

Subjects are imperative and specific: `fix(enforce): bind PrevHash into the
approval signature`, not `fix bug`. A commit that closes a security finding names
it: `sec(export): bind entry count and log tip into the envelope signature
(R2-02)`.

## Versioning

Kessa follows [semantic versioning](https://semver.org). The version lives in
exactly one place: the `Version` constant in
[`internal/version`](../internal/version/version.go), and the git tag is `v`
plus that constant. Every binary prints it:

```sh
kessa --version        # kessa 0.0.1 (commit 1a2b3c4d5e6f, go1.26.3)
```

The commit is stamped by the Go toolchain, not by us, and a binary built from a
tree with uncommitted changes says `-dirty`. A build with no VCS information says
`unknown` rather than guessing.

**Pre-1.0 rule.** Kessa is `0.x`: the interfaces are not declared stable, so a
breaking change cannot consume the major version. It bumps the **minor** instead
and is listed under **Breaking changes** in the release notes and
[`CHANGELOG.md`](../CHANGELOG.md). Below 1.0 the version number is not the
breaking-change signal; that section is.

| | Breaking | `feat` | anything else |
|---|---|---|---|
| **≥ 1.0.0** | major | minor | patch |
| **< 1.0.0** | minor | minor | patch |

**What forces a bump beyond the commit types:** a change to a golden fixture. The
goldens freeze the audit export format, so a golden that moved means the format
moved, and the release pipeline refuses to call that a patch.

## Releasing

Releases are **manual and owner-only**. There is no release on push to `main`: a
release is a claim about an artifact somebody will download and trust, and
nothing should be able to make that claim as a side effect of a merge.

Before starting, run the same gate locally, so a refusal costs seconds instead of
a workflow run:

```sh
make release-check
```

A release runs in **two phases**, so that (like every other change) it reaches
`main` through a reviewed pull request and never a direct push.

**Phase 1: prepare** ([`release.yml`](../.github/workflows/release.yml), the
**Release (prepare)** workflow). Run it from the Actions tab, on `main`, with:

- **bump**: `auto` (derive from the commits), or `patch`/`minor`/`major` to force
- **fixtures_reviewed**: check only if a golden changed and you have read the diff
- **dry_run**: on by default: computes the version and notes, pushes nothing

It confirms you are the owner on `main`, runs the full gate again (`gofmt`, SPDX,
`go vet`, the licence boundary, the race tests, the demo: [`scripts/ci/gate.sh`](../scripts/ci/gate.sh)),
runs the **golden-fixture guard** (below), derives the next version, refuses a
patch release if a golden moved, then writes the version constant and the
changelog onto a `release/vX.Y.Z` branch and pushes it. It prints a one-click
**PR link** (repository policy disables Actions-authored PRs, so you open it).

**You** then open that PR, let CI pass, and **squash-merge** it. GitHub creates
and signs the squash commit, which is how it satisfies the require-signed-commits
rule with no signing key on any runner. The commit subject carries the marker
`build(release): vX.Y.Z`.

**Phase 2: publish** ([`release-publish.yml`](../.github/workflows/release-publish.yml),
the **Release (publish)** workflow). It fires automatically on the merge, detects
the release from that marker (confirming the version matches the source constant
and no such tag exists yet), runs the gate and the fixture guard **again** on the
merged commit, then tags `vX.Y.Z`, cross-compiles the licence-split bundles,
signs them with build provenance, and publishes the GitHub release. An ordinary
push to `main` matches nothing and is a no-op; `workflow_dispatch` with an
explicit version is the manual recovery path.

A **dry run** in phase 1 stops before the branch is pushed, so you can preview the
version and notes without creating anything.

### The golden-fixture guard

[`scripts/release/fixture-guard.sh`](../scripts/release/fixture-guard.sh) is the
check that exists because of what Kessa claims rather than because of how it is
built. The goldens in `testdata/` are what the tests compare against, so a golden
that changes quietly is the one change that can invalidate the project's central
claim while every test still passes. Before a release it asks:

1. **Do the goldens reproduce from source?** `make fixtures` must be a no-op in
   git. A golden that cannot be regenerated is one somebody edited by hand, which
   is the same shape as one somebody tampered with.
2. **Does the v2 golden still verify clean?** An evidence-carrying export must
   `PASS` with every verdict re-derived.
3. **Does the v1 golden still refuse to pass?** An evidence-free export must come
   back `DOWNGRADED` with a non-zero exit. "Integrity-only reads as a clean pass"
   is exactly the failure that fixture is there to catch.
4. **If a golden moved since the last release**, was the format change recorded
   in the format-history record (`CHANGELOG.md`; see
   [`scripts/release/fixture-guard.sh`](../scripts/release/fixture-guard.sh)), and
   did a human tick `fixtures_reviewed`? The Makefile has always said regenerating
   a golden requires an entry; this is that rule with teeth.

### Release artifacts

Two bundles per platform, split along the licence boundary rather than by
convenience:

| Bundle | Contains | Licence |
|--------|----------|---------|
| `kessa_<version>_<os>_<arch>` | `kessa` (the independent verifier), `kessa-shadow` | Apache-2.0 |
| `kessa-server_<version>_<os>_<arch>` | `kessa-issuer`, `kessa-proxy`, `kessa-agent` | AGPL-3.0-only |

Shipping them in one archive would hand the AGPL to someone who only wanted the
verifier, which is the thing the two-tier model exists to avoid. Linux, macOS
(both architectures) and Windows amd64; every archive is listed in `SHA256SUMS`.

Phase 2 also builds two **container images** (same licence split), pushed to
GHCR: `kessa` (the verifier, Apache-2.0) and `kessa-proxy` (the sidecar,
AGPL-3.0-only). Both are multi-arch (linux amd64 + arm64), built `FROM`
distroless/static as nonroot from the Dockerfiles in [`docker/`](../docker), with
an SBOM and a signed provenance attestation. The image build runs only after the
archive publish succeeds, so images never ship from a release the gate rejected.

### If a release goes wrong

Phase 1 only pushes a `release/*` branch, and phase 2 tags and publishes as its
last steps, so a failure before then leaves no trace beyond a red workflow run
and (at worst) an unmerged release branch to delete. Fix and re-run. If phase 2's
auto-detect misses (the marker was edited off the squash commit), run **Release
(publish)** manually with the version. After publishing, do not move or delete a
tag: cut the next patch release instead. A tag that once pointed at one artifact
and now points at another is precisely the kind of quiet substitution this
project exists to make detectable.
