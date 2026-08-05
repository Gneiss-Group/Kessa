// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

// Package licensing holds no code. It exists to give the licence guardrail a
// test home inside the module.
//
// The boundary the Section 7 additional permission is written against is
// enforced by scripts/license-check.sh, a shell script, and a legal boundary
// asserted only in prose is a boundary that has never been tried. The test
// beside this file builds throwaway modules that violate the boundary in each
// way that matters and watches the script reject them, then deletes the script's
// guard and watches the same trees pass, so the test is known to test something.
//
// This package is deliberately passive: it classifies and inspects, it gates
// nothing, so it sits in the permissive tier per the test in LICENSING.md.
package licensing
