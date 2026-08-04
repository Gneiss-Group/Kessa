<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Changelog

Kessa follows [semantic versioning](https://semver.org). Releases are cut by
hand from `main` (see [`docs/branching.md`](docs/branching.md)); the sections
below are generated from the commit history by the release workflow, so this
file records what was released rather than what someone remembered to write
down.

Kessa is pre-1.0: the interfaces are not yet declared stable, so a breaking
change bumps the **minor** version and is called out under **Breaking changes**
in the release it lands in. That section, not the version number, is the signal
to read before upgrading.

## Export format history

The audit export is the artifact with a compatibility promise attached, so its
shape is recorded here rather than only in the code. This section is the record
[`scripts/release/fixture-guard.sh`](scripts/release/fixture-guard.sh) requires
an entry in whenever a frozen golden moves, since regenerating a golden means the
format changed. It sits above the release sections because it is not tied to any
one release, and it predates all of them.

**Nothing has been released yet**, so there are no release sections below. The
format history exists anyway: `v2` is what the verifier reads today, and a reader
should be able to learn why there is a `v1` without going to the source.

| Version | Status | What it is |
|---|---|---|
| `kessa-audit-export/v1` | superseded, still readable | Integrity-only. Carries entries and their hash chain, no evidence. The verifier reads it and returns **DOWNGRADED** with a non-zero exit: never a clean pass, because there is nothing to re-derive a verdict from. |
| `kessa-audit-export/v2` | **current** | Self-contained evidence envelope: entries plus the deduplicated, content-addressed credential set (each credential with its issuer proof) and the signed policy the verifier re-runs. One file, no companion artifacts. |

There is no `v3`, and no second shape of `v2` was ever published.

**Round 2 of the security review changed what several signing inputs cover**, and
those changes are format-affecting: the issuance signature now covers the whole
credential rather than an enumerated field list (R2-01); the envelope signature
now covers the entry count and log tip (R2-02); the entry payload carries a
status-checked hop count rather than a boolean assertion. They were finalized
**pre-release**, so the evidence format settles at `v2` with those contents
rather than minting a `v3` for a `v2` nobody ever received.

The trade that makes acceptable, stated rather than left implicit: an export from
an intermediate pre-round-2 build would carry the same `v2` label with different
signed contents, so it fails at hash and signature re-derivation rather than at a
clean version refusal. That is only acceptable because no such export exists
outside regenerable goldens. Once a version ships, this option is gone and a
format change means a new version string.

The authoritative statement of the current format is
[`internal/export`](internal/export/export.go); the findings behind the round-2
changes are in the [security review record](docs/security-review.md).

<!-- releases below; newest first -->
