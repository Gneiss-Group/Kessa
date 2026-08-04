// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
)

// A parser for the subset of TOML that REUSE.toml uses, which is a `version` key
// and a list of [[annotations]] blocks carrying `path`, `SPDX-FileCopyrightText`,
// and `SPDX-License-Identifier`.
//
// Hand-written rather than pulled from a module, for the reason in main.go's doc
// comment. The subset is small and this file is the whole cost of avoiding a
// dependency: if REUSE.toml ever needs real TOML, that is the moment to revisit
// the trade, not before.
//
// The rule that keeps this honest: it FAILS on anything it does not understand.
// A parser that skips unrecognized input is the exact shape docs/go-standards.md
// warns about, a check that passes without checking, and here it would be worse
// than useless: REUSE's `precedence` key changes which statement wins, so
// silently ignoring it would make this program's central claim wrong while it
// reported OK.

func parseREUSE(path string) ([]annotation, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var (
		anns    []annotation
		cur     *annotation
		pending string // a statement still accumulating across lines (an open array)
		lineNo  int
		stmtNo  int
	)

	flush := func() error {
		stmt := strings.TrimSpace(pending)
		pending = ""
		if stmt == "" {
			return nil
		}
		key, value, ok := strings.Cut(stmt, "=")
		if !ok {
			return fmt.Errorf("%s:%d: not a key/value statement: %q", path, stmtNo, stmt)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch key {
		case "version":
			if cur != nil {
				return fmt.Errorf("%s:%d: version must be top level, not inside [[annotations]]", path, stmtNo)
			}
			return nil
		case "path", "SPDX-FileCopyrightText", "SPDX-License-Identifier":
			if cur == nil {
				return fmt.Errorf("%s:%d: %q outside any [[annotations]] block", path, stmtNo, key)
			}
		case "precedence":
			return fmt.Errorf("%s:%d: this file sets `precedence`, which changes which licence\n"+
				"  statement wins when two disagree. scripts/reusecheck deliberately treats a\n"+
				"  disagreement as an error rather than resolving one, so it cannot honour this\n"+
				"  key. Decide which behaviour you want and teach the checker, do not leave both.",
				path, stmtNo)
		default:
			return fmt.Errorf("%s:%d: unknown key %q. This parser covers the subset REUSE.toml\n"+
				"  uses here and fails on the rest on purpose, so an unsupported key cannot be\n"+
				"  silently ignored. Extend scripts/reusecheck if the key is intended.",
				path, stmtNo, key)
		}

		values, err := parseValue(value)
		if err != nil {
			return fmt.Errorf("%s:%d: %s: %w", path, stmtNo, key, err)
		}
		switch key {
		case "path":
			cur.paths = append(cur.paths, values...)
		case "SPDX-FileCopyrightText":
			if len(values) != 1 {
				return fmt.Errorf("%s:%d: SPDX-FileCopyrightText takes one string", path, stmtNo)
			}
			cur.copyright = values[0]
		case "SPDX-License-Identifier":
			if len(values) != 1 {
				return fmt.Errorf("%s:%d: SPDX-License-Identifier takes one string", path, stmtNo)
			}
			cur.license = values[0]
		}
		return nil
	}

	closeBlock := func() error {
		if cur == nil {
			return nil
		}
		switch {
		case len(cur.paths) == 0:
			return fmt.Errorf("%s: [[annotations]] block %d has no path", path, cur.block)
		case cur.license == "":
			return fmt.Errorf("%s: [[annotations]] block %d has no SPDX-License-Identifier", path, cur.block)
		case cur.copyright == "":
			return fmt.Errorf("%s: [[annotations]] block %d has no SPDX-FileCopyrightText", path, cur.block)
		}
		anns = append(anns, *cur)
		cur = nil
		return nil
	}

	for _, raw := range strings.Split(string(data), "\n") {
		lineNo++
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" && pending == "" {
			continue
		}

		// A statement continues while its array is still open.
		if pending != "" {
			pending += " " + strings.TrimSpace(line)
			if balanced(pending) {
				if err := flush(); err != nil {
					return nil, err
				}
			}
			continue
		}

		if strings.TrimSpace(line) == "[[annotations]]" {
			if err := closeBlock(); err != nil {
				return nil, err
			}
			cur = &annotation{block: len(anns) + 1}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(line), "[") {
			return nil, fmt.Errorf("%s:%d: unsupported table %q; only [[annotations]] is handled",
				path, lineNo, strings.TrimSpace(line))
		}

		stmtNo = lineNo
		pending = strings.TrimSpace(line)
		if balanced(pending) {
			if err := flush(); err != nil {
				return nil, err
			}
		}
	}
	if pending != "" {
		return nil, fmt.Errorf("%s: unterminated value at end of file", path)
	}
	if err := closeBlock(); err != nil {
		return nil, err
	}
	if len(anns) == 0 {
		return nil, fmt.Errorf("%s: no [[annotations]] blocks found; expected at least one", path)
	}
	return anns, nil
}

// stripComment removes a trailing TOML comment, respecting quoted strings so a
// '#' inside a path is not treated as one.
func stripComment(line string) string {
	inStr := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			inStr = !inStr
		case '#':
			if !inStr {
				return line[:i]
			}
		}
	}
	return line
}

// balanced reports whether every '[' opened in the statement has been closed,
// ignoring brackets inside strings.
func balanced(s string) bool {
	depth, inStr := 0, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			inStr = !inStr
		case '[':
			if !inStr {
				depth++
			}
		case ']':
			if !inStr {
				depth--
			}
		}
	}
	return depth == 0
}

// parseValue reads a quoted string or an array of them.
func parseValue(v string) ([]string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil, fmt.Errorf("empty value")
	}
	if !strings.HasPrefix(v, "[") {
		s, err := unquote(v)
		if err != nil {
			return nil, err
		}
		return []string{s}, nil
	}
	if !strings.HasSuffix(v, "]") {
		return nil, fmt.Errorf("array is not closed")
	}
	inner := strings.TrimSpace(v[1 : len(v)-1])
	if inner == "" {
		return nil, nil
	}

	var out []string
	var cur strings.Builder
	inStr := false
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case c == '"':
			inStr = !inStr
			cur.WriteByte(c)
		case c == ',' && !inStr:
			s, err := unquote(strings.TrimSpace(cur.String()))
			if err != nil {
				return nil, err
			}
			out = append(out, s)
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if rest := strings.TrimSpace(cur.String()); rest != "" {
		s, err := unquote(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

func unquote(s string) (string, error) {
	if len(s) < 2 || !strings.HasPrefix(s, `"`) || !strings.HasSuffix(s, `"`) {
		return "", fmt.Errorf("expected a quoted string, got %q", s)
	}
	return s[1 : len(s)-1], nil
}
