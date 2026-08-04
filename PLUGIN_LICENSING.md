<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Plugin Licensing: Current State and Intended Addition

Kessa's core is licensed `AGPL-3.0-only`. Designated plugin interfaces are
licensed permissively. There are two separate grants here, and only one of
them is fully in place today.

## In effect now: the interface files

The files of a designated plugin interface are licensed `Apache-2.0`, and their
SPDX headers are authoritative. That grant applies today: you may copy, vendor,
or relicense the interface code under Apache-2.0 terms.

Which packages those are is not written down here. It is written in the source,
by the `//kessa:plugin-interface` marker, whose syntax and meaning are defined in
[`LICENSING.md`](LICENSING.md). This document deliberately maintains no list. A
list in prose is a second place to remember, and the failure mode is silent: the
day someone adds a plug point and forgets to amend the file, the document says
the designated set is smaller than it is, and nothing reports the discrepancy.
The marker cannot drift from the code because it *is* the code, and
[`scripts/license-check.sh`](scripts/license-check.sh) fails the build on a
package that is shaped like a plug point but carries no marker.

To see the current designated set, read the generated
[`NOTICE.md`](NOTICE.md), or run:

```bash
grep -rl '//kessa:plugin-interface' --include='*.go' .
```

## Not yet granted: the combination

Whether an independent implementation of a designated interface, compiled
together with the AGPL core, is covered by the core's copyleft is a separate
question that the interface licence does not answer.

We intend to answer it with a Section 7 additional-permission clause, the same
mechanism used by the GNU Classpath exception (OpenJDK) and the GCC Runtime
Library exception, designating the marked interfaces as independent modules so
that implementations may be licensed under terms of the plugin author's choosing.

**That clause is not in [`LICENSE`](LICENSE) yet, and it is not in effect.** Its
text is gated on formal written sign-off from Canada-competent counsel, which has
not been recorded. Until it lands, the AGPL-3.0 terms govern the combined binary
in full, including any plugin compiled into it. Treat the mechanism described here
as a roadmap item until it is superseded by actual clause text in `LICENSE`.

## The condition, which is the whole point

The permission, once granted, will be conditional, and the condition is what
keeps it from swallowing the copyleft:

> The exception applies only to code that interacts with the AGPL core
> **exclusively through a designated interface.** Code that reaches around the
> interface into the core's internals is not covered by it, and the combined work
> is then governed by AGPL-3.0 in full.

This is a boundary a plugin author relies on, so it is enforced in code rather
than described in prose. A marked package may depend on nothing but the standard
library and other marked packages: if it could import the core, then implementing
its interface would link the core for everybody, and the condition would be
unsatisfiable no matter how carefully a plugin author behaved.
`scripts/license-check.sh` fails the build if a marked package reaches outside
that closure, and [`internal/licensing`](internal/licensing/) tests that the check
actually rejects such a tree, including by deleting the guard and confirming the
tree then passes.

## Why this can only loosen

A Section 7 additional permission grants rights beyond the base licence and
never restricts anything. Adding it later cannot narrow what is released
today. Early adopters and forks receive fewer permissions than later ones
will, which is the normal state of an unfinished grant, and no future
version of this file can take back a grant already made.

The same holds for the marker. Marking a package is a grant going forward; it
does not reach back, and unmarking one cannot retract what a previous release
already conveyed.
