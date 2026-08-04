#!/usr/bin/env bash
# License boundary guardrail.
#
# The permissive (Apache-2.0) tier is every package that (a) has no AGPL-tier
# package anywhere in its dependency closure, and (b) performs no enforcement
# action. If any Apache-tier package imports an AGPL-3.0-only package, the
# copyleft goes viral into the permissive tier and the "anyone can run and trust
# the verifier" guarantee silently breaks. This check fails the build if that
# ever happens. See LICENSING.md for the tier test itself.
#
# It ALSO fails if any package in the module is in neither list. A package's tier
# is a deliberate licensing decision, and a package nobody classified is a package
# nobody checked: before this check existed, adding a new package simply excluded
# it from the guardrail with no signal at all.
set -euo pipefail

MOD="github.com/Gneiss-Group/Kessa"

# Permissive tier: the verifier and everything it can reach, the designated
# plug-point seams, and passive tools that classify without enforcing.
APACHE_PKGS=(
  pkg/types
  internal/did internal/signer internal/signer/enclave internal/signerd internal/audit internal/macaroon
  internal/status internal/vc internal/credential internal/chain
  internal/policy internal/export internal/shadow internal/version
  auditsink cmd/verify cmd/shadow scripts/genfixtures scripts/stories
)
# Protective tier: anything that issues authority or decides whether a real
# action may proceed, plus the benchmarks that link it.
AGPL_PKGS=(
  internal/enforce internal/keystore internal/enroll cmd/proxy cmd/issuer cmd/agent perf
)

fail=0

# 1. No Apache-tier package may import an AGPL-tier package.
for p in "${APACHE_PKGS[@]}"; do
  deps="$(go list -deps "$MOD/$p" 2>/dev/null || true)"
  for a in "${AGPL_PKGS[@]}"; do
    if printf '%s\n' "$deps" | grep -qxF "$MOD/$a"; then
      echo "LICENSE VIOLATION: Apache package '$p' imports AGPL package '$a'"
      fail=1
    fi
  done
done

all_pkgs="$(go list ./... | sed "s|^$MOD/||")"

# 2. Every package in the module must be classified into exactly one tier.
for p in $all_pkgs; do
  in_apache=0; in_agpl=0
  for a in "${APACHE_PKGS[@]}"; do [ "$a" = "$p" ] && in_apache=1; done
  for a in "${AGPL_PKGS[@]}"; do [ "$a" = "$p" ] && in_agpl=1; done
  if [ "$in_apache" -eq 0 ] && [ "$in_agpl" -eq 0 ]; then
    echo "UNCLASSIFIED PACKAGE: '$p' is in neither tier list, so nothing checks it."
    echo "  Add it to APACHE_PKGS or AGPL_PKGS below (LICENSING.md states the test)."
    fail=1
  fi
  if [ "$in_apache" -eq 1 ] && [ "$in_agpl" -eq 1 ]; then
    echo "DOUBLE-CLASSIFIED PACKAGE: '$p' appears in both tier lists."
    fail=1
  fi
done

# 3. The lists must not name packages that no longer exist, or they rot silently.
for p in "${APACHE_PKGS[@]}" "${AGPL_PKGS[@]}"; do
  if ! printf '%s\n' $all_pkgs | grep -qxF "$p"; then
    echo "STALE ENTRY: tier list names '$p', which is not a package in this module."
    fail=1
  fi
done

if [ "$fail" -eq 0 ]; then
  echo "license-check: OK: no Apache-tier package imports an AGPL-tier package;"
  echo "               all $(printf '%s\n' $all_pkgs | wc -l | tr -d ' ') packages classified"
fi
exit "$fail"
