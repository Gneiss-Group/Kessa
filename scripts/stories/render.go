// SPDX-FileCopyrightText: 2026 Gneiss Group Inc.
// SPDX-License-Identifier: Apache-2.0

// render.go turns the captured story outcomes (scripts/stories/out/runs.tsv)
// into the SVG story cards under docs/assets/stories/. It is deterministic and
// standard-library only: same input, byte-for-byte same output, no timestamps,
// no random ids. Run it via `make stories-images`.
//
//	go run ./scripts/stories/render.go <runs.tsv> <out-dir>
//
// Each card is a two-lane contrast: the same agent under the same grant, one
// request that lands (green) and one that is stopped (amber), each rendered
// from the verbatim agent line so no card can claim an outcome the binaries did
// not produce.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// lineRe parses an agent line: "ALLOW  data.read -> datalake:finance/revenue  (reason)".
// The reason is matched greedily to the final ')'; reasons carry commas and
// quotes but never parentheses.
var lineRe = regexp.MustCompile(`^(ALLOW|DENY)\s+(\S+) -> (\S+)\s+\((.*)\)$`)

type attempt struct {
	decision string // ALLOW | DENY
	typ      string // action type, e.g. data.read
	target   string // resource identifier
	reason   string // verbatim reason
}

func (a attempt) allowed() bool { return a.decision == "ALLOW" }

// lane is one row of a card: a plain-English intent, plus the id whose captured
// outcome fills the rest of the throughline.
type lane struct {
	id     string
	intent string
}

type card struct {
	file  string
	tag   string // property, e.g. "LEAST AUTHORITY"
	title string
	allow lane
	deny  lane
}

// The shared setup line, learned once by the reader.
const subtitle = "Dana's revenue-pack agent · granted: READ finance/revenue · READ/WRITE finance-reporting workbook"

var cards = []card{
	{
		file:  "story-a-least-authority-read.svg",
		tag:   "LEAST AUTHORITY",
		title: "An agent reads only the data it was granted",
		allow: lane{id: "A-allow", intent: "Pulls the revenue figures it was asked for"},
		deny:  lane{id: "A-deny", intent: "Reaches for another team's data"},
	},
	{
		file:  "story-b-least-authority-write.svg",
		tag:   "LEAST AUTHORITY",
		title: "An agent writes only inside its own workspace",
		allow: lane{id: "B-allow", intent: "Writes the pack into its own workbook"},
		deny:  lane{id: "B-deny", intent: "Tries to write into the exec-board space"},
	},
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go run ./scripts/stories/render.go <runs.tsv> <out-dir>")
		os.Exit(2)
	}
	runs, err := parse(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "render:", err)
		os.Exit(1)
	}
	outDir := os.Args[2]
	for _, c := range cards {
		a, ok := runs[c.allow.id]
		b, ok2 := runs[c.deny.id]
		if !ok || !ok2 {
			fmt.Fprintf(os.Stderr, "render: %s: missing captured outcome for %s/%s\n", c.file, c.allow.id, c.deny.id)
			os.Exit(1)
		}
		svg := renderCard(c, a, b)
		path := filepath.Join(outDir, c.file)
		if err := os.WriteFile(path, []byte(svg), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "render:", err)
			os.Exit(1)
		}
		fmt.Println("wrote", path)
	}
}

func parse(path string) (map[string]attempt, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]attempt{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		id, rest, ok := strings.Cut(line, "\t")
		if !ok {
			return nil, fmt.Errorf("no tab in line: %q", line)
		}
		m := lineRe.FindStringSubmatch(rest)
		if m == nil {
			return nil, fmt.Errorf("unparseable agent line for %q: %q", id, rest)
		}
		out[id] = attempt{decision: m[1], typ: m[2], target: m[3], reason: m[4]}
	}
	return out, sc.Err()
}

// ---- palette (reuses the README's mermaid colors) -------------------------

const (
	cardBG   = "#12241c"
	nodeBG   = "#1a3a2e"
	chipBG   = "#0d1a14"
	textCol  = "#eef4f0"
	mutedCol = "#9db8ab"
	hairline = "#2d6a4f"

	greenFill   = "#2d6a4f"
	greenStroke = "#40916c"
	greenBright = "#52b788"
	amberFill   = "#3a2a1a"
	amberStroke = "#8a5a2d"
	amberBright = "#c98a4b"
)

// ---- geometry -------------------------------------------------------------

const (
	W       = 1040
	H       = 560
	laneH   = 176
	lane1Y  = 168
	lane2Y  = lane1Y + laneH + 8
	reqX    = 40
	reqW    = 250
	gateX   = 330
	gateW   = 150
	outX    = 520
	outW    = 480
	nodeTop = 42 // node box offset from lane top (below the intent caption)
	nodeH   = 118
)

func renderCard(c card, a, b attempt) string {
	var s strings.Builder
	fmt.Fprintf(&s, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" font-family="ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif">`, W, H)
	s.WriteString("\n")

	// card
	fmt.Fprintf(&s, `<rect x="0" y="0" width="%d" height="%d" rx="18" fill="%s"/>`, W, H, cardBG)
	s.WriteString("\n")

	// header
	fmt.Fprintf(&s, `<text x="40" y="56" fill="%s" font-size="27" font-weight="700">%s</text>`, textCol, esc(c.title))
	s.WriteString("\n")
	// property tag pill (width approximated from the label length)
	tagW := 10*len([]rune(c.tag)) + 20
	fmt.Fprintf(&s, `<rect x="40" y="72" width="%d" height="22" rx="11" fill="none" stroke="%s"/>`, tagW, greenStroke)
	fmt.Fprintf(&s, `<text x="%d" y="87" fill="%s" font-size="11" font-weight="700" letter-spacing="1.2">%s</text>`, 40+11, greenBright, esc(c.tag))
	s.WriteString("\n")
	// wordmark
	fmt.Fprintf(&s, `<text x="%d" y="52" fill="%s" font-size="15" font-weight="700" text-anchor="end" letter-spacing="0.5">kessa</text>`, W-40, mutedCol)
	fmt.Fprintf(&s, `<text x="%d" y="88" fill="%s" font-size="11" text-anchor="end">enforcement point</text>`, W-40, mutedCol)
	s.WriteString("\n")
	// subtitle
	fmt.Fprintf(&s, `<text x="40" y="127" fill="%s" font-size="13">%s</text>`, mutedCol, esc(subtitle))
	s.WriteString("\n")
	// divider
	fmt.Fprintf(&s, `<line x1="40" y1="146" x2="%d" y2="146" stroke="%s" stroke-opacity="0.5"/>`, W-40, hairline)
	s.WriteString("\n")

	s.WriteString(renderLane(lane1Y, c.allow.intent, a))
	s.WriteString(renderLane(lane2Y, c.deny.intent, b))

	s.WriteString("</svg>\n")
	return s.String()
}

func renderLane(y int, intent string, at attempt) string {
	var s strings.Builder
	fill, stroke, bright := amberFill, amberStroke, amberBright
	if at.allowed() {
		fill, stroke, bright = greenFill, greenStroke, greenBright
	}

	// lane panel + left accent bar
	fmt.Fprintf(&s, `<rect x="24" y="%d" width="%d" height="%d" rx="12" fill="#ffffff" fill-opacity="0.02" stroke="%s" stroke-opacity="0.25"/>`, y, W-48, laneH, stroke)
	fmt.Fprintf(&s, `<rect x="24" y="%d" width="6" height="%d" rx="3" fill="%s"/>`, y, laneH, bright)
	s.WriteString("\n")

	// intent caption (the plain-English throughline start)
	fmt.Fprintf(&s, `<text x="%d" y="%d" fill="%s" font-size="14" font-weight="600">%s</text>`, reqX, y+28, textCol, esc(intent))
	s.WriteString("\n")

	nodeY := y + nodeTop

	// REQUEST node
	node(&s, reqX, nodeY, reqW, nodeH, nodeBG, "#ffffff", 0.06)
	label(&s, reqX+14, nodeY+20, "REQUEST")
	fmt.Fprintf(&s, `<text x="%d" y="%d" fill="%s" font-size="17" font-family="ui-monospace, SFMono-Regular, Menlo, monospace" font-weight="600">%s</text>`, reqX+14, nodeY+52, textCol, esc(at.typ))
	for i, ln := range wrapPath(at.target, 28) {
		fmt.Fprintf(&s, `<text x="%d" y="%d" fill="%s" font-size="12.5" font-family="ui-monospace, SFMono-Regular, Menlo, monospace">%s</text>`, reqX+14, nodeY+76+i*17, mutedCol, esc(ln))
	}

	// arrow REQUEST -> GATE
	arrow(&s, reqX+reqW+4, nodeY+nodeH/2, gateX-4, nodeY+nodeH/2)

	// GATE node
	node(&s, gateX, nodeY, gateW, nodeH, chipBG, stroke, 1.0)
	shield(&s, gateX+gateW/2, nodeY+40, bright)
	fmt.Fprintf(&s, `<text x="%d" y="%d" fill="%s" font-size="12.5" font-weight="600" text-anchor="middle">kessa-proxy</text>`, gateX+gateW/2, nodeY+78, textCol)
	fmt.Fprintf(&s, `<text x="%d" y="%d" fill="%s" font-size="10.5" text-anchor="middle">verifies the grant</text>`, gateX+gateW/2, nodeY+96, mutedCol)

	// arrow GATE -> OUTCOME
	arrow(&s, gateX+gateW+4, nodeY+nodeH/2, outX-4, nodeY+nodeH/2)

	// OUTCOME: badge + wrapped reason
	badgeW := 92
	fmt.Fprintf(&s, `<rect x="%d" y="%d" width="%d" height="30" rx="15" fill="%s" stroke="%s"/>`, outX, nodeY+2, badgeW, fill, stroke)
	glyph := "✗" // deny
	if at.allowed() {
		glyph = "✓"
	}
	fmt.Fprintf(&s, `<text x="%d" y="%d" fill="%s" font-size="15" font-weight="700" text-anchor="middle" letter-spacing="0.5">%s %s</text>`, outX+badgeW/2, nodeY+23, "#ffffff", glyph, at.decision)
	s.WriteString("\n")
	for i, ln := range wrap(at.reason, 64) {
		fmt.Fprintf(&s, `<text x="%d" y="%d" fill="%s" font-size="12" font-family="ui-monospace, SFMono-Regular, Menlo, monospace">%s</text>`, outX, nodeY+56+i*17, textCol, esc(ln))
	}
	s.WriteString("\n")
	return s.String()
}

func node(s *strings.Builder, x, y, w, h int, fill, stroke string, strokeOp float64) {
	fmt.Fprintf(s, `<rect x="%d" y="%d" width="%d" height="%d" rx="10" fill="%s" stroke="%s" stroke-opacity="%.2f"/>`+"\n", x, y, w, h, fill, stroke, strokeOp)
}

func label(s *strings.Builder, x, y int, t string) {
	fmt.Fprintf(s, `<text x="%d" y="%d" fill="%s" font-size="10" font-weight="700" letter-spacing="1.5">%s</text>`+"\n", x, y, mutedCol, esc(t))
}

func arrow(s *strings.Builder, x1, y1, x2, y2 int) {
	fmt.Fprintf(s, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="2"/>`, x1, y1, x2-8, y2, hairline)
	fmt.Fprintf(s, `<path d="M %d %d l -9 -5 l 0 10 z" fill="%s"/>`+"\n", x2, y2, hairline)
}

// shield draws a small rounded shield glyph centered at (cx, top+..).
func shield(s *strings.Builder, cx, top int, col string) {
	fmt.Fprintf(s, `<path d="M %d %d l 13 5 l 0 10 q 0 11 -13 17 q -13 -6 -13 -17 l 0 -10 z" fill="none" stroke="%s" stroke-width="2"/>`+"\n", cx, top, col)
}

// ---- text helpers ---------------------------------------------------------

// wrap breaks s into lines of at most n runes, splitting on spaces and
// hard-splitting any single token longer than n.
func wrap(s string, n int) []string {
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, word := range strings.Fields(s) {
		for len([]rune(word)) > n {
			r := []rune(word)
			flush()
			out = append(out, string(r[:n]))
			word = string(r[n:])
		}
		switch {
		case cur.Len() == 0:
			cur.WriteString(word)
		case len([]rune(cur.String()))+1+len([]rune(word)) <= n:
			cur.WriteString(" ")
			cur.WriteString(word)
		default:
			flush()
			cur.WriteString(word)
		}
	}
	flush()
	return out
}

// wrapPath breaks a resource identifier (no spaces) into lines of at most n
// runes, preferring to break after '/' so a path segment is never split
// mid-word unless a single segment is itself longer than n.
func wrapPath(s string, n int) []string {
	var segs []string
	start := 0
	for i, r := range s {
		if r == '/' {
			segs = append(segs, s[start:i+1])
			start = i + 1
		}
	}
	segs = append(segs, s[start:])

	var out []string
	cur := ""
	for _, seg := range segs {
		for len([]rune(seg)) > n { // a single segment longer than the line
			r := []rune(seg)
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			out = append(out, string(r[:n]))
			seg = string(r[n:])
		}
		if len([]rune(cur))+len([]rune(seg)) <= n {
			cur += seg
		} else {
			if cur != "" {
				out = append(out, cur)
			}
			cur = seg
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

func esc(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}
