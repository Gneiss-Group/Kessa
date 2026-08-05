#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
# SPDX-License-Identifier: Apache-2.0
#
# gen-notice.sh: build NOTICE.md, the licence bundle that ships with a binary.
#
# Anyone who conveys a compiled Kessa binary has to hand the recipient three
# things: the AGPL-3.0 text for the core, the Section 7 additional permission
# that carves out the designated plug points, and the permissive notice for each
# designated component. That is a list which changes whenever a plug point is
# added, so it is generated from the markers in the source rather than typed:
# a NOTICE that a human maintains is a NOTICE that describes last quarter's
# binary. scripts/license-check.sh runs this with --check, so the committed file
# cannot drift from the tree it describes.
#
# Usage:  scripts/gen-notice.sh           write NOTICE.md
#         scripts/gen-notice.sh --check   fail if NOTICE.md is out of date
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MOD="$(go list -m)"
OUT="$ROOT/NOTICE.md"

# Anchored exactly as in license-check.sh: the marker designates only when it is a
# directive on its own line, never when a file merely quotes it. The two scripts
# must agree on what "designated" means, or the notice describes a different set
# than the one the check enforces, which is the drift this file exists to prevent.
MARKER_RE='^//kessa:plugin-interface[[:space:]]*$'
HEADER_LINES=10

marked=""
for p in $(go list ./... | sed "s|^$MOD/*||"); do
  d="$(go list -f '{{.Dir}}' "$MOD/$p")"
  grep -qlE "$MARKER_RE" "$d"/*.go 2>/dev/null && marked="$marked $p"
done
marked="$(printf '%s\n' $marked | sort)"

render() {
  cat <<'HEADER'
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
these terms. Contact Gneiss Group Inc.

## 2. Additional permission under Section 7 (PENDING)

> **This section is a placeholder, and the permission it describes is NOT YET IN
> EFFECT.** The clause text is lawyer-gated and has not been drafted or applied
> to [`LICENSE`](LICENSE). Until it appears here and in `LICENSE`, the AGPL-3.0
> terms in section 1 govern the combined binary in full, including any plugin
> compiled into it. Do not rely on the exception described below; it is recorded
> so this file's structure is final and so a reader can see what is coming.
>
> When granted, the permission will designate the plug points listed in section 3
> as independent modules, so that an independent implementation of one may be
> conveyed under its author's own terms even when linked into the same binary as
> the AGPL core. The permission is conditional: it applies only to code that
> interacts with the core exclusively through a designated interface. Code that
> reaches around the interface into the core's internals is not covered, and the
> combined work reverts to AGPL-3.0 in full. This is the mechanism used by the
> GNU Classpath exception and the GCC Runtime Library exception.
>
> See [`PLUGIN_LICENSING.md`](PLUGIN_LICENSING.md) for status.

## 3. Designated plug points

Each package below carries the `//kessa:plugin-interface` marker in the file that
declares its interface. Each is permissively licensed today, independently of the
pending permission in section 2, and each is verified by
[`scripts/license-check.sh`](scripts/license-check.sh) to depend on nothing but
the standard library and other designated packages, so implementing one never
requires linking the AGPL core.

HEADER

  if [ -z "$marked" ]; then
    echo "*No designated plug points in this tree.*"
  else
    for p in $marked; do
      d="$(go list -f '{{.Dir}}' "$MOD/$p")"
      spdx="$(head -"$HEADER_LINES" "$d"/*.go |
        grep -o 'SPDX-License-Identifier:[[:space:]]*[A-Za-z0-9.+-]*' |
        sed 's/SPDX-License-Identifier:[[:space:]]*//' | sort -u | head -1)"
      echo "### \`$MOD/$p\`"
      echo
      echo "$(go list -f '{{.Doc}}' "$MOD/$p")"
      echo
      echo "Licensed under \`$spdx\` ([\`LICENSES/$spdx.txt\`](LICENSES/$spdx.txt))."
      echo
      echo "> Copyright (c) 2026 Gneiss Group Inc."
      echo ">"
      echo "> Licensed under the Apache License, Version 2.0 (the \"License\"); you may"
      echo "> not use these files except in compliance with the License. You may obtain"
      echo "> a copy of the License at http://www.apache.org/licenses/LICENSE-2.0"
      echo ">"
      echo "> Unless required by applicable law or agreed to in writing, software"
      echo "> distributed under the License is distributed on an \"AS IS\" BASIS, WITHOUT"
      echo "> WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the"
      echo "> License for the specific language governing permissions and limitations"
      echo "> under the License."
      echo
    done
  fi

  cat <<'FOOTER'
## 4. Third-party components

Kessa's core module declares no third-party Go dependencies: the entire tree
builds against the standard library. If you vendor, fork, or link additional
components into your build, their notices are yours to add here.
FOOTER
}

if [ "${1:-}" = "--check" ]; then
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  render >"$tmp"
  if ! diff -q "$OUT" "$tmp" >/dev/null 2>&1; then
    echo "NOTICE DRIFT: NOTICE.md does not match the designated set in the source."
    echo "  The bundle a recipient is handed would name the wrong components."
    echo "  Run 'make notice' and commit the result."
    diff -u "$OUT" "$tmp" | head -40 || true
    exit 1
  fi
  exit 0
fi

render >"$OUT"
echo "wrote $OUT"
