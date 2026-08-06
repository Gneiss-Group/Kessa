#!/usr/bin/env bash
# License boundary guardrail.
#
# Two boundaries are enforced here, and they are not the same boundary.
#
# The TIER boundary is the two-tier model in LICENSING.md: the permissive
# (Apache-2.0) tier is every package that has no AGPL-tier package anywhere in its
# dependency closure and performs no enforcement action. If an Apache-tier package
# imports an AGPL-3.0-only package, the copyleft goes viral into the permissive
# tier and the "anyone can run and trust the verifier" guarantee silently breaks.
#
# The PLUG-POINT boundary is narrower and newer: a designated plugin interface is
# the seam the Section 7 additional permission is written against, and that
# permission only fires for code that talks to the core exclusively through the
# seam. A designated package that reaches into the core makes the designation
# false, because implementing its interface would then force an importer to link
# the core. See PLUGIN_LICENSING.md for the mechanism and LICENSING.md for the
# marker's canonical definition.
#
# Neither boundary is checked against a hardcoded package list. Tier comes from
# each file's SPDX header and designation comes from the in-code marker, both of
# which live in the source they describe: a list in this file is a second place to
# remember, and the thing about a second place is that one of them goes stale
# without saying so. Every check below starts from the complete set (go list
# ./...) and excludes explicitly, per the standing rule in docs/go-standards.md.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# The module under test is the one in the working directory, not a baked-in
# constant, so the guardrail test can run this script against a synthesized
# fixture module and observe it fail. A check nobody can watch fail is a check
# nobody knows works.
MOD="$(go list -m)"

# The designation marker. Written as a Go directive comment (no space after the
# slashes) so gofmt treats it as a directive and keeps it attached to the
# declaration rather than reflowing it into prose.
#
# MARKER_RE anchors it to the start of a line with nothing following, which is
# what makes it a directive rather than a mention. A file that merely talks about
# the marker, in prose, in a string literal, in this comment, does not thereby
# designate its package: a designation you can trigger by quoting it is not a
# designation. MARKER is kept for messages, so operators see the literal text.
MARKER='//kessa:plugin-interface'
MARKER_RE='^//kessa:plugin-interface[[:space:]]*$'

# Every marked file must also carry a notice pointing at the permission. This is a
# licensing requirement rather than a house style rule, so arguing it away in
# review is not one of the available moves.
#
# The reasoning is worth keeping next to the check: the marker travels with the
# file when someone copies it out of the distribution, but LICENSE does not. A
# detached file carrying a designation with no legal context behind it is worse
# than an undesignated one, because it reads as a grant nobody can locate. The
# notice is a pointer, never a reproduction of the clause: two copies of operative
# text is how they come to disagree.
#
# Anchored for the same reason as MARKER_RE. A file that quotes this notice, as
# internal/licensing's fixtures do, must not thereby appear to carry it.
POINTER_RE='^// ADDITIONAL PERMISSION:'

fail=0
note() { echo "$@"; }

# ---------------------------------------------------------------------------
# Derive the package set, and each package's tier, from the source itself.
# ---------------------------------------------------------------------------

all_pkgs="$(go list ./... | sed "s|^$MOD/*||" | sed 's|^$|.|')"

pkg_dir() { go list -f '{{.Dir}}' "$MOD/${1#./}" 2>/dev/null || go list -f '{{.Dir}}' ./"$1"; }

# Tier of a package: the single SPDX identifier shared by every Go file in its
# directory. Globbing the directory rather than asking go list for GoFiles is
# deliberate: a file excluded by a build tag still carries a licence, and a file
# nobody compiles today is exactly the file that gets missed.
#
# Only the file's header is read (HEADER_LINES), because that is what an SPDX
# header IS: the REUSE spec puts it in a comment at the top. Scanning whole files
# instead would let any string literal mentioning an identifier reclassify the
# package around it, which is not hypothetical: internal/licensing's test builds
# fixture files out of header constants, and an unanchored scan read that package
# as split-tier the first time this ran.
HEADER_LINES=10
spdx_of_file() {
  head -"$HEADER_LINES" "$1" | grep -o 'SPDX-License-Identifier:[[:space:]]*[A-Za-z0-9.+-]*' |
    sed 's/SPDX-License-Identifier:[[:space:]]*//' | head -1
}

tier_of() {
  local dir="$1" f id ids=""
  for f in "$dir"/*.go; do
    [ -e "$f" ] || continue
    id="$(spdx_of_file "$f")"
    if [ -z "$id" ]; then
      note "UNLICENSED FILE: $f carries no SPDX-License-Identifier in its first $HEADER_LINES lines."
      fail=1
      continue
    fi
    ids="$ids$id
"
  done
  ids="$(printf '%s' "$ids" | sort -u)"
  case "$(printf '%s' "$ids" | tr '\n' ' ')" in
    'Apache-2.0') echo apache ;;
    'AGPL-3.0-only') echo agpl ;;
    '') echo none ;;
    *) echo "mixed:$(printf '%s' "$ids" | tr '\n' ',')" ;;
  esac
}

# Two parallel "key<TAB>value" tables rather than associative arrays: macOS ships
# bash 3.2, contributors run this gate locally, and a check that only runs on the
# maintainer's machine is a check the next contributor discovers by breaking it.
TIER_TABLE=""
DIR_TABLE=""
lookup() { printf '%s\n' "$2" | awk -F'\t' -v k="$1" '$1==k {print $2; exit}'; }

apache_pkgs=""
agpl_pkgs=""
for p in $all_pkgs; do
  d="$(pkg_dir "$p")"
  DIR_TABLE="$DIR_TABLE$p	$d
"
  t="$(tier_of "$d")"
  case "$t" in
    apache) apache_pkgs="$apache_pkgs $p" ;;
    agpl) agpl_pkgs="$agpl_pkgs $p" ;;
    none)
      note "UNLICENSED PACKAGE: '$p' has no SPDX-License-Identifier on any Go file."
      note "  Every file states its own tier; a package that states none is a package nobody classified."
      fail=1
      ;;
    *)
      note "SPLIT-TIER PACKAGE: '$p' mixes SPDX identifiers (${t#mixed:})."
      note "  A package is one tier. Split it, or correct the headers that disagree."
      fail=1
      ;;
  esac
  TIER_TABLE="$TIER_TABLE$p	$t
"
done

# ---------------------------------------------------------------------------
# 1. No Apache-tier package may import an AGPL-tier package.
# ---------------------------------------------------------------------------
for p in $apache_pkgs; do
  deps="$(go list -deps "$MOD/$p" 2>/dev/null || true)"
  for a in $agpl_pkgs; do
    if printf '%s\n' "$deps" | grep -qxF "$MOD/$a"; then
      note "LICENSE VIOLATION: Apache package '$p' imports AGPL package '$a'"
      fail=1
    fi
  done
done

# ---------------------------------------------------------------------------
# Designated plug points: which packages carry the marker, and where.
# ---------------------------------------------------------------------------
marked_pkgs=""
marker_files_of() { grep -lE "$MARKER_RE" "$(lookup "$1" "$DIR_TABLE")"/*.go 2>/dev/null || true; }
for p in $all_pkgs; do
  [ -n "$(marker_files_of "$p")" ] && marked_pkgs="$marked_pkgs $p"
done

# Does a package export at least one interface type? go doc rather than a grep
# over the source: it renders grouped type declarations as individual entries and
# omits unexported ones, so `type ( Foo interface{...} )` is not a hole.
exports_interface() {
  go doc "$MOD/$1" 2>/dev/null | grep -qE '^type [A-Z][A-Za-z0-9_]* interface'
}

for p in $marked_pkgs; do
  # 2. A designated package is permissively licensed, or the designation promises
  #    something its own files contradict.
  if [ "$(lookup "$p" "$TIER_TABLE")" != apache ]; then
    note "BAD DESIGNATION: '$p' carries $MARKER but is not Apache-tier ($(lookup "$p" "$TIER_TABLE"))."
    note "  A plug point a third party cannot implement freely is not a plug point."
    fail=1
  fi

  # 3. The marker sits on the file that DECLARES the interface, not on one that
  #    implements or imports it. Otherwise the boundary is wherever someone last
  #    pasted a comment.
  if ! exports_interface "$p"; then
    note "BAD DESIGNATION: '$p' carries $MARKER but exports no interface type."
    note "  The marker designates an interface boundary; there is no interface here."
    fail=1
  fi
  for f in $(marker_files_of "$p"); do
    if ! grep -qE '(^|[[:space:]])[A-Z][A-Za-z0-9_]*[[:space:]]+interface[[:space:]]*\{' "$f"; then
      note "MISPLACED MARKER: $f carries $MARKER but declares no exported interface type."
      note "  Move it to the file that declares the interface. A marker on an"
      note "  implementation file designates the implementation, which is backwards."
      fail=1
    fi
    # BEGIN GUARDRAIL notice
    if ! grep -qE "$POINTER_RE" "$f"; then
      note "MARKED FILE WITHOUT ITS PERMISSION NOTICE: $f"
      note "  A marked file must also carry a comment beginning '// ADDITIONAL PERMISSION:'"
      note "  pointing at the clause in LICENSE. The marker travels when this file is"
      note "  copied out of the distribution; LICENSE does not. Without the notice, the"
      note "  copy carries a designation whose grant the reader cannot locate."
      note "  Point at the clause, never reproduce it: see auditsink/auditsink.go."
      fail=1
    fi
    # END GUARDRAIL notice
  done

  # 4. THE GUARDRAIL. The Section 7 permission is conditional on the plugin
  #    reaching the core only through the designated interface. Mechanically that
  #    means a designated package's own closure may contain nothing but the
  #    standard library and other designated packages: if it imports the core,
  #    then every implementation of its interface links the core too, the
  #    condition is unsatisfiable, and the combined binary falls back to plain
  #    AGPL-3.0 copyleft over the whole thing. This is the code-level enforcement
  #    of the legal boundary, and it is the one check here that, if it stops
  #    firing, costs a plugin author their licence rather than costing us a
  #    tidiness point.
  #
  #    The sentinels below are a mutation point, not decoration:
  #    internal/licensing/guardrail_test.go deletes the lines between them and
  #    re-runs the check against a deliberately violating tree, so the test is
  #    observed to fail with its guard removed rather than assumed to. Keep them.
  # BEGIN GUARDRAIL closure
  for dep in $(go list -deps "$MOD/$p" 2>/dev/null | grep "^$MOD/" || true); do
    rel="${dep#"$MOD"/}"
    [ "$rel" = "$p" ] && continue
    if ! printf '%s\n' $marked_pkgs | grep -qxF "$rel"; then
      note "GUARDRAIL VIOLATION: designated plug point '$p' depends on '$rel',"
      note "  which is not itself a designated plug point. The Section 7 exception"
      note "  is conditioned on reaching the core only through the designated"
      note "  interface; this dependency means implementing '$p' links the core,"
      note "  so the exception cannot fire and the combined binary is plain AGPL."
      fail=1
    fi
  done
  # END GUARDRAIL closure
done

# ---------------------------------------------------------------------------
# 5. Fail closed on a plug point that forgot the marker.
#
# A package is plug-point-SHAPED when a third party could implement against it:
# permissively licensed, importable from outside the module (so not internal/,
# which the Go toolchain already walls off), not a command, and exporting an
# interface type for someone to implement. Shaped-but-unmarked is the silent
# failure this check exists for: it would otherwise pass as ordinary Apache-tier
# code, sit outside the guardrail above, and be free to grow a dependency on the
# core that nothing would report.
#
# Sentinels as above: this block is stripped by the guardrail test to confirm the
# undesignated-plug-point case fails for the reason claimed.
# ---------------------------------------------------------------------------
# BEGIN GUARDRAIL designation
for p in $apache_pkgs; do
  case "$p" in internal/* | */internal/*) continue ;; esac
  [ "$(go list -f '{{.Name}}' "$MOD/$p" 2>/dev/null)" = main ] && continue
  exports_interface "$p" || continue
  if ! printf '%s\n' $marked_pkgs | grep -qxF "$p"; then
    note "UNDESIGNATED PLUG POINT: '$p' is externally importable, Apache-tier, and"
    note "  exports an interface type, so it is shaped like a plug point but carries"
    note "  no $MARKER. Either add the marker (and accept the"
    note "  stdlib-plus-designated-packages-only rule it enforces), or move the"
    note "  interface under internal/ so it is not an external seam."
    fail=1
  fi
done
# END GUARDRAIL designation

# ---------------------------------------------------------------------------
# 6. The distributed notice bundle must match the designated set it describes.
# ---------------------------------------------------------------------------
if [ -x "$ROOT/scripts/gen-notice.sh" ] && [ "$ROOT" = "$PWD" ]; then
  "$ROOT/scripts/gen-notice.sh" --check || fail=1
fi

if [ "$fail" -eq 0 ]; then
  n_all="$(printf '%s\n' $all_pkgs | wc -l | tr -d ' ')"
  n_marked="$(printf '%s' "$marked_pkgs" | wc -w | tr -d ' ')"
  echo "license-check: OK: no Apache-tier package imports an AGPL-tier one;"
  echo "               $n_all packages classified from their own SPDX headers;"
  echo "               $n_marked designated plug point(s), each stdlib-only in closure"
fi
exit "$fail"
