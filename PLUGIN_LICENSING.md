<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Plugin Licensing: Intent Statement (Not Yet in Effect)

Kessa's core is licensed `AGPL-3.0-only`. We intend to add a Section 7
additional-permission clause (the same mechanism used by GNU Classpath and
OpenJDK) designating specific plugin interfaces, starting with `auditsink`, as
independent modules, so that implementations of those interfaces can be licensed
under terms of the plugin author's choosing without inheriting the AGPL.

**This permission has not yet been added to the [`LICENSE`](LICENSE) file** and
is pending review by counsel. Until it is formally added, the plain, unmodified
terms of `AGPL-3.0-only` govern the entire repository, including the interfaces
named below.

Currently intended designated interfaces:

- [`auditsink`](auditsink/), already shipped `Apache-2.0`, standard-library
  only, with zero internal dependencies.

This list is illustrative of intent, not a legal carve-out. Treat it as a
roadmap item, not a license term, until this document is superseded by actual
clause text in `LICENSE`.

## Why state this at all

A Section 7 additional permission only *grants* rights beyond the base license;
it never restricts anything. It is therefore safe to add later without
invalidating anything released under the plain `AGPL-3.0-only` text today. Early
adopters and forks simply receive fewer permissions than later ones will, which
is a normal state for an unfinished license grant.

What would not be safe is publishing draft or informal-sounding exception
language in the `LICENSE` file itself, since that is the one document downstream
users are entitled to rely on verbatim. So the intent is recorded here, in a
document that is explicitly not a license term, rather than there.
