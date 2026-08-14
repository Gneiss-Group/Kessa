# Session log, 2026-08-14

Covers Kessa `14e5ef5..23d90f8` (PRs #64 through #68, including the v0.1.0
release) and Kessa-tf `79ce45c..bad461d` (PRs #2 through #5). Picks up where the
previous log stopped, which was Kessa PR #63 and Kessa-tf PR #1.

**A note on the date, because two appear in the artifacts.** Local time was
2026-08-13 PDT for the whole session; the release, the CI logs and the dated
entries written into `UPCOMING.md` in both repositories are stamped 2026-08-14
UTC. This file uses the UTC date to match what is committed. The previous log was
`session-log-2026-08-13.md`, so the names do not collide.

The session began from a pasted list of open items. Verifying that list before
acting on it changed it materially, which is recorded in Part 4.

---

## Part 1: closes and supersedes

### Kessa

- **The release-notes generator truncated multi-line breaking-change footers.**
  Fixed in **#64** (`be43dab`). `notes.sh` collected footers with a line-oriented
  `grep`, so a footer wrapping onto a second line contributed only its first line.

  This was not a pending defect. It had already shipped: the published v0.0.1
  `CHANGELOG.md` entry read `Signer.Public() and did.ResolveKey now return
  crypto.PublicKey;`, ending on a semicolon with the rest of the footer
  discarded, and the same truncated text is in that release's GitHub body. It
  survived review because a truncated footer still reads like a terse note.

  The deliverable was the test, not the one-line change. `scripts/release/
  notes_test.go` asserts on the LAST words of a footer, never the first, because
  asserting the first line passes against the implementation being replaced.
  Verified by reverting the collector: three of five tests fail, and the two that
  hold either way are the single-line and no-breaking-change guards. A new
  `scripts/release` package means `go test ./...` picks them up with no wiring.

  The v0.0.1 changelog entry was repaired in the same PR, byte-identical to what
  the fixed generator now emits for that range. The published GitHub release body
  was deliberately left alone: it is a point-in-time artifact and editing it after
  the fact makes the record less trustworthy.

- **`loadJSON` in `cmd/issuer` ignored unknown fields.** Fixed in **#65**
  (`4428e5c`). Worth noting this item had never been written into `UPCOMING.md`;
  it existed only in a planning document outside the repository, which is the
  failure mode PR #55's convention exists to prevent.

  The item as originally stated was aimed at the wrong half. `Keystore` is a map
  and a map has no unknown fields, so `DisallowUnknownFields` is a no-op on two of
  the four call sites. The real target is `Spec` and its nested structs, where a
  misspelled `extraPrincipals` parsed cleanly, yielded an empty slice, and
  published a root with the enforcement point silently absent. Required fields
  already have a backstop in `Spec.validate`; optional ones have none.

  `internal/config.DecodeStrict` was split out of `Load` so the mechanism is
  shared rather than copied, letting the issuer use its own error wording. A test
  asserts out loud that the keystore path is unaffected, because the natural
  reading of "JSON parsing is now strict" is that it closed the hole
  `keystore.Principals` exists for, and it did not.

- **A latent ordering defect in `main`.** Fixed in **#66** (`89bf6ed`). Surfaced
  by CI on #65, which touches neither the proxy nor the sink.

  `TestRun_BatchProducesExport` asserted the audit-sink log held records in file
  order. `enforce.forward` dispatches each record on its own goroutine and states
  that concurrent requests may arrive out of order, which is the R2-03 shape: a
  slow or hung sink must never stall enforcement. The test encoded a guarantee the
  design explicitly declines to give.

  Reproduced on `main` at `be43dab` with none of #65's changes present: 0 failures
  in 200 runs at `-count=200 -p 1`, and **36 failures in 60 runs** at
  `-cpu=1,2,8`. Invisible unless the machine is busy. The reordering went into the
  `readJSONL` helper rather than the one call site, and it does not weaken the
  sequence check, since sorting reorders records without renumbering them.

- **v0.1.0 released** (**#67**, `2ef0e7b`), and it is the first release to run the
  full two-phase path unattended. Phase 1 derived `0.0.2 -> 0.1.0` and pushed a
  signed branch; the squash-merge signed the landing commit; phase 2 fired on its
  own because the marker matched `build(release): v0.1.0 (#67)`, suffix included.
  22 assets, 11 `.intoto.jsonl`, all three images published.

  All three v0.0.1 defects stayed fixed, verified rather than assumed: the release
  commit is `{"verified": true, "reason": "valid"}`, phase 2 recognised its own
  marker, and the release body uses `gh attestation verify` rather than the
  non-existent `gh attest verify`.

### Kessa-tf

- **The repository had no CI.** Closed in **#3** (`cf0b61b`). One workflow running
  `tofu fmt -check -recursive` and `tofu validate`, the latter on the module and
  on `examples/evaluation` separately, because the example is its own root module
  and the top-level run does not descend into it.

  OpenTofu is installed by hand rather than with `opentofu/setup-opentofu`,
  because the organisation runs Actions with `allowed_actions=selected` and an
  action outside that list dies as `startup_failure` at 0s with no logs. The
  install is pinned to a SHA-256 that was verified against the published archive
  rather than transcribed.

  The first run was checked for vacuity rather than trusted: the checksum gate
  fired, and both root modules reported `Success! The configuration is valid`.

- **Never applied against a released image.** Closed in **#4** (`d413379`).
  `examples/evaluation` applied end to end against the published v0.1.0 proxy
  digest, resolved anonymously from GHCR, with artifacts published by the released
  issuer image at the same version, so nothing in the path was built locally.

  Verified by use rather than exit code, because "Apply complete" is the exact
  message this module once printed while leaving the old proxy running: `GET /tip`
  returned a real `enforce.Tip`, and a full MCP `tools/list` advertised both
  `kessa/tip` and `kessa/enforce`.

- **The macOS `signer_socket` belief became a finding.** Closed as a question in
  **#4**. The conclusion held; the reasoning behind it was wrong.

  A host-created unix socket IS visible in the container over a bind mount, but
  `connect()` fails with `EOPNOTSUPP`. It is not a uid problem, which is what the
  entry guessed: root and a matching uid fail identically, and both fail at
  `connect()`, so the peer-uid gate is never reached and `container_user` cannot
  help. A socket created INSIDE the container on the same mount works, so the
  mount is not the limit either. Only host-to-container fails, which is exactly
  the topology the brokered path requires.

  The claim was narrowed to what was measured: this says nothing about Linux with
  native Docker, which remains untested and is expected to work.

---

## Part 2: new open items

- **Kessa: a version is written two ways, and one of them cannot change**
  (**#68**, `23d90f8`, in `UPCOMING.md`). The git tag is `v0.1.0`; the version
  constant, `--version` output and the image tag are bare `0.1.0`.

  Recorded rather than normalised because it cannot be normalised: this is a
  public Go module and Go requires `vX.Y.Z` tags, so dropping the prefix would
  make the module unfetchable at a version. Registries take the opposite
  convention. Both sides are right and neither is free to move.

  The cost is diagnostic, not cosmetic: a wrong-form pull returns 404, and GHCR
  returns 404 for a package you may not see, so the wrong spelling is
  indistinguishable from a permissions problem. That happened while resolving the
  v0.1.0 digest and briefly looked like a visibility regression.

  **The recommendation is stated and NOT taken:** say it once where someone is
  about to type a tag (the release body and `docker/README.md`) rather than only
  in a comment beside the code that adds the prefix.

- **Kessa-tf: the repository has no tags, so the module cannot be pinned to a
  version** (**#5**, `b8e7335`). The cheap item that the registry question was
  hiding. With zero tags the only pin is a commit SHA, and the README's quickstart
  showed the unpinned form, floating on `main`. That is the same mistake the
  module refuses to let anyone make with the image it runs, where `var.image` is
  regex-checked to require a digest.

  Tagging needs no rename, no public repository and no registry. **The version is
  now decided, `v0.0.1`, and the tag is not created.** See Part 5.

- **Kessa-tf: registry publication, demoted to a nice-to-have** (**#5**). Still
  undecided, but no longer implying a path to anything. Requirements were checked
  rather than assumed: public repository, a name matching
  `terraform-<PROVIDER>-<NAME>`, at least one semver tag, a non-empty description,
  standard structure. The repository has the structure and none of the rest, so
  publishing means renaming it.

  Two facts are recorded without being acted on. The rename cost curve is real but
  hangs off an optional decision. And the convention names the PROVIDER while a
  second target is already anticipated (a host process, not a cluster), which
  cannot live in a repository named for Docker, so publication implies one
  repository per target.

- **Kessa-tf: Terraform verification shelved, with a named trigger** (**#5**,
  `cbd6aca`). Everything was run under OpenTofu 1.12.5, never under `terraform`.
  Deliberately shelved. The trigger is named rather than left to judgement,
  because a shelved item with no trigger is an abandoned one: a user saying they
  run `terraform`, publication to the Terraform Registry, or the claim being
  repeated somewhere with more reach than the repository.

  The middle trigger is a stated coupling: publishing to the Terraform Registry is
  what would manufacture the demand, so it cannot also be the thing waiting for
  it.

- **Standing-rule candidate, now DECIDED but not written.** See Part 5. #66 is a
  shape the standards document does not currently name: **a test asserting a
  guarantee the system explicitly disclaims.** It is distinct from the
  "check that does not fire" family, where a check passes vacuously. Here the test
  demands more than the contract offers, so it passes almost always and fails
  intermittently under load, which reads as flake rather than as a wrong
  assertion.

---

## Part 3: documentation drift found and fixed

- **`CHANGELOG.md`, Kessa, v0.0.1 breaking-changes section.** Claimed
  `Signer.Public() and did.ResolveKey now return crypto.PublicKey;`, ending
  mid-sentence on a semicolon. The rest of the footer, naming the
  `Credential.HolderKey` shape change and the regenerated v2 golden, was absent.
  Repaired in **#64**. The GitHub release body carrying the same truncation was
  deliberately left alone.

- **Kessa-tf `README.md`, open-items pointer.** Claimed "this repository has no CI
  and no branch protection." CI has existed since #3, and branch protection is
  plan-blocked rather than missing: the API returns 403, "Upgrade to GitHub Pro or
  make this repository public." Fixed in **#5**.

- **Kessa-tf `README.md` and `variables.tf`, the brokered path.** Claimed the
  macOS behaviour was "unverified" and "may not work there," attributing the risk
  to uid translation. Both the status and the mechanism were wrong: it does not
  work, and uid translation is not why. Fixed in **#4** in three places, because
  readers arrive at different ones.

- **Kessa-tf `README.md`, quickstart module source.** Showed
  `source = "github.com/Gneiss-Group/Kessa-tf"` with no `?ref=`, floating on the
  default branch, immediately above instructions to pin the image by digest. The
  module contradicting itself in its own README. Fixed in **#5**.

- **Kessa-tf `UPCOMING.md`, rulesets entry.** Contained a sentence I truncated
  when writing it ("re-derived later under some:"). Fixed in **#4**.

- **Kessa-tf `UPCOMING.md`, registry entry.** Described publication as a
  discoverability win against a maintenance surface, which implied it was on a
  path somewhere. It is not: a module needs no registry to be consumed. Demoted in
  **#5**, with the single genuine functional difference stated (a registry source
  can express a version constraint; a git source must pin exactly).

- **Outside the repositories: two memory files carrying four stale claims**, all
  the same shape, a caveat written as a future risk, resolved later, never
  revisited. **Two of the four were caught by the maintainer, not by me**, which
  is worth recording: I was reading them as current and would have kept doing so.

  In `release-pipeline-v001-lessons.md`:

  1. **"Phase 1 signing is still unproven until v0.0.2."** The note predicted its
     own expiry and then sat unrevisited after v0.0.2 shipped. Corrected to
     proven, verified rather than asserted: the v0.0.2 tag commit reports
     `{"verified": true, "reason": "valid"}` from the GitHub API and every asset
     carries its `.intoto.jsonl`. The one failed prepare run on that release is
     now explained in place, since it was the likely source of the doubt: it was
     not signing, it was `gh api` writing its 404 body to stdout so a `-z` test
     never fired, and it is already fixed in `release.yml`.
  2. **"A NEW GHCR package name will default private and needs a manual UI
     flip."** Corrected per the maintainer: a one-time fix was applied. Re-verified
     anonymously, all three packages return HTTP 200. The note now says not to
     raise this as a pre-release chore.

  In `kessa-tf-status.md`:

  3. **"No CI and no rulesets is the main gap before going public."** CI has
     existed since #3, and rulesets are plan-blocked rather than pending.
  4. **"The brokered `signer_socket` path is UNTESTED on macOS, where uid
     translation may break sockets over bind mounts."** Both halves wrong now:
     tested, does not work, and uid translation is not the mechanism.

  `MEMORY.md`'s index lines for both files were rewritten to match, and the
  v0.1.0 unattended-release result was added to the pipeline note so the next
  release is not budgeted for manual recovery.

  **The pattern is worth carrying to the master handoff.** All four read as
  current until checked, and two survived because nobody went back after the
  triggering event. If the handoff contains similar "unproven until X" or "still
  needs Y" phrasing, it is worth sweeping for the same shape rather than trusting
  it.

---

## Part 4: the pasted list, as corrected by checking it

Recorded because the corrections changed what got worked on, and a reconciliation
pass should see the reasoning rather than just the outcome.

- **Three items filed as "not yet actioned" were already fully recorded** in
  Kessa's `UPCOMING.md`: durability off by default (lines 182 onward, with both
  prerequisites named), the still-software brokered key, and the peer-uid topology
  constraint, which already named the Terraform module as affected. Acting on them
  would have been duplication. Nothing was done, deliberately.

- **The changelog item was filed as low priority, "check at next release."** It
  was already broken in published output and sat on the critical path: cutting
  v0.1.0 was what unblocked the Terraform verification, and cutting it with the
  generator in that state would have published two more truncated notes.

- **The rulesets item was not a task anyone could pick up.** Reclassified in #3
  from outstanding work to a go-public checklist item, with the rules to apply
  named while there is no time pressure.

- **The lenient-JSON item was aimed at the wrong half**, as described in Part 1.

- **A new blocker was found that the list did not contain:** the CI job's obvious
  implementation would have died as `startup_failure` at 0s with no logs, because
  `opentofu/setup-opentofu` is not on the organisation's action allowlist.

---

## Part 5: decisions taken this session, one implemented and one not

Both were decided after the last PR of the main body merged. The tag was then
implemented; the standing rule was not. Read the status on each rather than
assuming from the heading.

- **Add a standing rule for assertions that outrun the contract.** Decided: yes,
  it earns a rule. **Not written.** It belongs in `docs/go-standards.md` beside
  the existing "validate before the side effect" and coverage-check rules.

  The shape, from #66: **a test may only assert what the system promises.** Where
  a component documents a weaker guarantee than a test relies on, the test is
  wrong even while it passes, and it will fail on timing rather than on
  behaviour. That failure reads as flake, so the likely response is a re-run
  rather than a read, which is what makes it worth a standing rule rather than a
  one-off fix.

  Distinguish it from the neighbouring rule when writing it up: the
  "check that does not fire" family passes VACUOUSLY, testing nothing. This one
  demands MORE than the contract offers. Both produce a green build that means
  less than it appears to, from opposite directions.

  The instance to cite is `TestRun_BatchProducesExport`, which asserted file
  order from a sink whose own comment says concurrent requests may arrive out of
  order. Worth citing the measurement too, since it is what makes the case: 0
  failures in 200 runs unloaded, 36 in 60 at `-cpu=1,2,8`.

  One open question for whoever writes it: whether the rule should also require
  that a documented non-guarantee be greppable from the test, so the next reader
  can find the contract that governs the assertion. That is a suggestion, not
  part of the decision.

- **Kessa-tf's first tag is `v0.0.1`. DONE.** Created, signed, pushed, and
  reported by GitHub as `{"verified": true, "reason": "valid"}`. Tag object
  `4790f135`, pointing at commit `5e651c6`, whose README pins to `v0.0.1`, so the
  self-reference inside the tag is correct. Kessa-tf **#6** made the README change
  and the tag went on its merge commit, in that order deliberately: tagging first
  would have frozen a README saying no tag exists.

  `0.0.1` rather than matching Kessa's `0.1.0`: the module versions independently
  of the engine, and matching numbers would imply a coupling that does not exist.
  It also states the truth about maturity, which is that the module has been
  applied end to end exactly once. The leading `v` is a choice, not a requirement:
  nothing forces it here, unlike Kessa, which is a Go module whose tags must be
  `vX.Y.Z` for the toolchain to resolve them.

  **Two things learned by testing the result, both worth carrying forward.**

  1. `git tag -v` exits 1 locally, which looks like a signing failure and is not.
     The tag object does carry an SSH signature; `gpg.ssh.allowedSignersFile` is
     not configured, so git has no trust list to check it against. GitHub verifies
     independently. Do not read that exit code as unsigned.
  2. **The README's documented source form does not work while the repository is
     private,** found by running the quickstart's exact line rather than assuming.
     The `github.com/...` shorthand resolves to HTTPS, which cannot authenticate
     against a private repository, and fails with `could not read Username for
     'https://github.com'`. The tag is fine: `git ls-remote` over SSH returns
     `4790f135`, and the SSH module source initialises cleanly. Recorded in
     Kessa-tf **#7**, which keeps the HTTPS form primary (correct for the
     repository this is meant to become) and gives the SSH form for today.

     Same shape as the image-tag 404 in Part 2: an error naming a username prompt
     says nothing about visibility, so it misroutes the diagnosis toward local git
     misconfiguration. Delete that note at go-public.

---

## Standing rules touched

- **"Validate before the side effect"** (`docs/go-standards.md`, line 78) was
  applied directly in Kessa-tf's new CI workflow: the OpenTofu archive's checksum
  is verified BEFORE unpacking, since a checksum checked after the binary is
  already extracted and on PATH is a check that runs after the thing it guards
  against. Stated in a comment at the point of use.

- **The never-exercised-gate class was closed out by exercise rather than
  extended.** The release-manager guard and phase 2's marker pattern, both of
  which failed at v0.0.1 because nothing had ever run through them, were confirmed
  working by cutting a real release.

- No changes were made to `docs/go-standards.md` or `docs/security-review.md` this
  session.

---

**This digest needs a manual reconciliation pass against the master handoff.**
That document lives outside both repositories and is not visible from here, so
nothing above has been checked against it. Part 2's open items and Part 4's
corrections are the parts most likely to disagree with what the handoff currently
says.

**One item in Part 5 will be lost if this file is deleted before it is acted on:
the standing rule.** It exists nowhere but here. The `v0.0.1` decision was
implemented and is now recoverable from git; the rule is not in
`docs/go-standards.md` and is not in any commit.

Part 3's closing note applies to the handoff itself: four stale claims were found
this session, all reading as current until checked, and two of them survived
because nobody went back after the event that resolved them. The handoff is older
than any of them.
