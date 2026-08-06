<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# NOTICE

**Generated file. Do not edit by hand.** Run `make notice` after adding or
removing a designated plug point; `scripts/license-check.sh` fails the build if
this file and the source disagree.

This is the licence bundle for a compiled Kessa binary. If you convey one, to a
customer, inside an appliance, or as part of a hosted service the AGPL's network
clause reaches, this file plus the referenced texts is what the recipient is
owed. Full licence texts live in [`LICENSES/`](LICENSES/); this file states which
one governs what.

## 1. The core: AGPL-3.0-only

Copyright (c) 2026 Gneiss Group Inc.

Kessa's core is licensed under the GNU Affero General Public License, version 3,
with no "or later" option ([`LICENSES/AGPL-3.0-only.txt`](LICENSES/AGPL-3.0-only.txt)).
Conveying a binary obliges you to offer the corresponding source for the core and
for any modifications you made to AGPL-licensed files, and, if you make it
available to users over a network, to offer that source to those users.

A separate commercial licence is available for organizations that cannot meet
these terms: <sales@gneiss-group.com>.

## 2. Additional permission under Section 7

**This permission is in effect.** Its authoritative text is the section headed
`KESSA ADDITIONAL PERMISSION UNDER SECTION 7` at the end of [`LICENSE`](LICENSE),
reproduced here in full so that a recipient of a binary holds it without needing
the source tree. If the two ever differ, `LICENSE` governs.

In short: an independent implementation of a designated interface (section 3) may
be conveyed under its author's own terms, even when linked into the same binary as
the AGPL core, **provided it interacts with the core exclusively through a
designated interface.** Code that reaches around the interface into the core's
internals is not covered, and the combined work is then governed by AGPL-3.0 in
full. This is the mechanism used by the GNU Classpath exception (OpenJDK) and the
GCC Runtime Library Exception. Reviewed by Canada-competent counsel, 2026-08-05.

The permission does not weaken the AGPL in respect of the core. Section 13's
network clause continues to apply to a modified Program in full.

### 0. Definitions

"The Program" has the meaning given in the GNU Affero General Public License,
version 3 ("the AGPL"), and refers to Kessa as conveyed by Gneiss Group Inc.

"Designation Marker" means the character sequence `//kessa:plugin-interface`
appearing on a line of its own in a source file of the Program.

"Designated Interface" means each exported interface type declared in a source
file of the Program that bears the Designation Marker, together with the data
types that the methods of such an interface accept as parameters or return, as
those files stand in the version of the Program you received.

"Independent Implementation" means a work that implements one or more Designated
Interfaces and that is not derived from the Program otherwise than through
Designated Interfaces.

"Combined Work" means a work formed by combining or linking the Program, or a
modified version of it, with one or more Independent Implementations.

### 1. Grant

As an additional permission under section 7 of the AGPL, the copyright holders of
the Program give you permission to convey a Combined Work, and to license the
Independent Implementations contained in it under terms of your choice, without
those terms being required to comply with the AGPL, provided that the condition in
section 2 is satisfied.

This permission does not alter your obligations under the AGPL in respect of the
Program itself. The Program, and any modifications you make to it, remain governed
by the AGPL in full, including the requirement in section 13 of the AGPL to offer
the Corresponding Source to users interacting with a modified Program remotely
over a network.

### 2. Condition

The permission in section 1 applies to an Independent Implementation only if that
Independent Implementation interacts with the Program exclusively through
Designated Interfaces.

An Independent Implementation does not interact with the Program exclusively
through Designated Interfaces if it reads, calls, links against, or otherwise
depends upon any part of the Program other than a Designated Interface (excluding
the standard library of the programming language), whether directly or through an
intermediary work supplied for that purpose.

### 3. Effect of failing the condition

If the condition in section 2 is not satisfied in respect of an Independent
Implementation, the permission in section 1 does not apply to any Combined Work
containing that Independent Implementation, and the AGPL applies to that Combined
Work as a whole and to all of its parts, without regard to this additional
permission.

### 4. Designation

The set of Designated Interfaces is determined solely by the presence of the
Designation Marker in the source of the version of the Program you received. No
other document, list, or statement determines that set, and where any such
document conflicts with the source, the source governs.

The copyright holders may add or remove Designation Markers in later versions of
the Program. Any such change operates only in respect of the versions in which it
appears, and does not affect any permission already granted in respect of a
version previously conveyed.

### 5. Extension and removal

If you modify the Program, you may extend this additional permission to your
version, but you are not obliged to do so. As provided by section 7 of the AGPL,
you may remove this additional permission from a copy of the Program, or from any
part of it, that you convey.

## 3. Designated plug points

Each package below carries the `//kessa:plugin-interface` marker in the file that
declares its interface, which is what places it within the additional permission
in section 2. Each is also permissively licensed in its own right, independently
of that permission, and each is verified by
[`scripts/license-check.sh`](scripts/license-check.sh) to depend on nothing but
the standard library and other designated packages, so implementing one never
requires linking the AGPL core.

**This list is generated from the markers and is informational.** Section 4 of the
permission is explicit that the source governs: if this list and the marked files
ever disagree, the marked files win.

### `github.com/Gneiss-Group/Kessa/auditsink`

Package auditsink defines the seam for forwarding Kessa audit records to an external destination, a local file, stdout, a log shipper, eventually a SIEM.

Licensed under `Apache-2.0` ([`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt)).

> Copyright (c) 2026 Gneiss Group Inc.
>
> Licensed under the Apache License, Version 2.0 (the "License"); you may
> not use these files except in compliance with the License. You may obtain
> a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
>
> Unless required by applicable law or agreed to in writing, software
> distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
> WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
> License for the specific language governing permissions and limitations
> under the License.

## 4. Third-party components

Kessa's core module declares no third-party Go dependencies: the entire tree
builds against the standard library. If you vendor, fork, or link additional
components into your build, their notices are yours to add here.
