<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Plugin Licensing: Current State and Intended Addition

Kessa's core is licensed `AGPL-3.0-only`. Designated plugin interfaces are
licensed permissively. There are two separate grants here, and only one of
them is fully in place today.

## In effect now: the interface files

[`auditsink`](auditsink/) is licensed `Apache-2.0`, standard-library only,
with zero internal dependencies. The SPDX headers in those files are
authoritative and that grant applies today. You may copy, vendor, or
relicense the interface code under Apache-2.0 terms.

## Not yet granted: the combination

Whether an independent implementation of a designated interface, compiled
together with the AGPL core, is covered by the core's copyleft is a separate
question that the interface licence does not answer.

We intend to answer it with a Section 7 additional-permission clause (the
same mechanism used by GNU Classpath and OpenJDK), designating specific
interfaces as independent modules so that implementations may be licensed
under terms of the plugin author's choosing. That clause has not yet been
added to the [`LICENSE`](LICENSE) file and is pending review by counsel.

Currently intended designated interfaces: `auditsink`.

This list is a statement of intent, not a legal carve-out. Treat it as a
roadmap item until it is superseded by actual clause text in `LICENSE`.

## Why this can only loosen

A Section 7 additional permission grants rights beyond the base licence and
never restricts anything. Adding it later cannot narrow what is released
today. Early adopters and forks receive fewer permissions than later ones
will, which is the normal state of an unfinished grant, and no future
version of this file can take back a grant already made.
