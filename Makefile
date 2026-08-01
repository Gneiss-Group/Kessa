# Kessa — build / test / demo
#
# The verifier (cmd/verify, built as `kessa`) is the spine: it must stay a
# standalone, near-stdlib binary. Keep its dependency set sacred.

GO      ?= go
BINDIR  ?= bin

.PHONY: all build test test-race-condition test-fast vet license-check fixtures demo stories stories-capture stories-images verify version release-version release-check release-artifacts clean test-enclave-signed

all: build

# build compiles every command into ./bin. The verifier lives at cmd/verify but
# ships as `kessa` — the artifact a skeptical evaluator downloads and runs.
build: verify
	@mkdir -p $(BINDIR)
	$(GO) build -o $(BINDIR)/kessa-issuer ./cmd/issuer
	@for d in proxy agent shadow; do \
		if ls cmd/$$d/*.go >/dev/null 2>&1; then $(GO) build -o $(BINDIR)/kessa-$$d ./cmd/$$d; fi \
	done
	@echo "built into $(BINDIR)/"

# test runs the suite under the race detector. It is NOT a separate optional
# target, and that is deliberate (security review round 2, R2-04): the proxy
# mutates a hash-chained log and an evidence map, so "does it race?" is a
# correctness question about the enforcement path, not a performance one. The
# round-2 data race — two concurrent decisions landing at the same Seq, the
# second silently overwriting the first and leaving an executed consequential
# action with no audit entry at all — was invisible to a bare `go test` and was
# found only by running -race by hand. A defect class that only one flag can see
# belongs behind the flag everyone runs.
test: test-race-condition

# test-race-condition runs the suite under Go's data-race detector (`go test
# -race`). Named in full so "race" is unambiguous: this is about concurrent
# read/write races on shared state, nothing else.
test-race-condition:
	$(GO) test -race ./...

# test-fast drops the race detector. For a quick inner-loop run only; it is not
# what a change should be merged on.
test-fast:
	$(GO) test ./...

vet:
	$(GO) vet ./...

# test-enclave-signed runs the Secure Enclave PERSISTENCE tests, which need a
# code-signed binary with a keychain-access-group entitlement (see
# docs/enclave-runbook.md). The interop tests run unsigned via `go test`; this
# target is only for the persistence path. Requires a real Apple Development
# identity (ad-hoc signing cannot carry the restricted entitlement).
#
#   make test-enclave-signed SIGN_IDENTITY="Apple Development: you@example.com (TEAMID)"
#
# Set the entitlement's access group to <TeamID>.com.gneiss.kessa in
# build/enclave.entitlements first.
test-enclave-signed:
	@test -n "$(SIGN_IDENTITY)" || { echo "set SIGN_IDENTITY (see docs/enclave-runbook.md)"; exit 2; }
	@mkdir -p $(BINDIR)
	CGO_ENABLED=1 $(GO) test -c -o $(BINDIR)/enclave.test ./internal/signer/enclave
	codesign --force --sign "$(SIGN_IDENTITY)" --entitlements build/enclave.entitlements $(BINDIR)/enclave.test
	$(BINDIR)/enclave.test -test.v

# license-check enforces the open/paid license boundary: no Apache-tier package
# may import an AGPL-tier package, or the copyleft goes viral into the permissive
# verifier. This is the guardrail that keeps the two-tier model honest.
license-check:
	@bash scripts/license-check.sh

# fixtures regenerates the did:web testdata from fixed seeds, then the golden
# audit exports. Regenerating a golden is a deliberate act: it means the frozen
# export format changed, and it needs an entry in the format-history record
# (CHANGELOG.md; see scripts/release/fixture-guard.sh) saying what changed and why.
#
# Both goldens were regenerated once, together, when the round-2 fixes
# finalized the evidence format's contents pre-release (no version bump: the
# evidence envelope is v2, its contents settled before release). The entry payload
# changed shape, so the v1 golden moved too — it no longer has its old job of
# proving the evidence fields left v1
# hashing untouched, because this change did not leave it untouched. It now
# freezes the integrity-only envelope path under the current entry encoding.
fixtures:
	$(GO) run ./scripts/genfixtures ./testdata/dids
	$(GO) test ./internal/audit  -run TestGoldenExport   -update
	$(GO) test ./internal/export -run TestGoldenV2Export -update

# demo drives all seven scenarios end to end through the real binaries and hands
# the result to the independent verifier. Deterministic: fixed seeds, timestamps,
# and nonces; localhost only.
demo: build
	@bash scripts/demo.sh

# stories drives the reporting-agent user stories end to end through the real
# binaries and narrates each ALLOW/DENY. These are the corporate-workflow
# scenarios the images in docs/assets/stories/ are rendered from. Deterministic;
# localhost only. See docs/stories.md.
stories: build
	@bash scripts/stories/run.sh

# stories-capture is `stories` plus a machine-readable capture of every verbatim
# outcome to scripts/stories/out/runs.tsv, the single source of truth the story
# images are rendered from, so no image can claim an outcome the binaries did not
# produce. The renderer (docs/stories.md) consumes that file.
stories-capture: build
	@bash scripts/stories/run.sh --capture

# stories-images captures real outcomes and renders the story cards from them
# into docs/assets/stories/. The renderer is deterministic: same capture in,
# byte-for-byte same SVG out, so re-running is a no-op in git unless a scenario
# actually changed.
stories-images: stories-capture
	$(GO) run ./scripts/stories/render.go scripts/stories/out/runs.tsv docs/assets/stories

# verify builds the independent verifier as the standalone `kessa` binary. Its
# dependency set is sacred: stdlib + our own packages, no server code, no policy
# engine. `go build ./cmd/verify` must stay auditable in one sitting.
verify:
	@mkdir -p $(BINDIR)
	$(GO) build -o $(BINDIR)/kessa ./cmd/verify
	@echo "built $(BINDIR)/kessa"

# ---- versioning and release -------------------------------------------------
#
# The version lives in exactly one place: the Version constant in
# internal/version. Every binary prints it via --version, the git tag is v plus
# it, and the release workflow is the only thing that moves it. See
# docs/branching.md for when the number goes up and by how much.

# version prints the version this tree would release as.
version:
	@bash scripts/release/version.sh

# release-version rewrites the version constant. For repairing a mistake by
# hand; the ordinary path is the Release workflow, which derives the number from
# the commit history rather than trusting anyone to pick it.
#
#   make release-version V=0.2.0
release-version:
	@test -n "$(V)" || { echo "usage: make release-version V=x.y.z"; exit 2; }
	@bash scripts/release/version.sh "$(V)"

# release-check runs, locally, exactly what both release phases run before they
# tag anything: the shared gate (scripts/ci/gate.sh — the same script CI runs)
# plus the golden-fixture guard. Run it before starting a release so a refusal
# costs seconds, not a workflow run.
release-check:
	@bash scripts/ci/gate.sh
	@bash scripts/release/fixture-guard.sh

# release-artifacts cross-compiles the licence-split release bundles into
# ./dist for inspection. The workflow runs this same script.
release-artifacts:
	@bash scripts/release/build-artifacts.sh "$$(bash scripts/release/version.sh)" dist

clean:
	rm -rf $(BINDIR) dist
