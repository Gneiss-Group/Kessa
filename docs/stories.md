# User stories: what Kessa does for real work

The technical docs prove *how* Kessa enforces delegated authority. These stories
show *why an environment is safer for it*, in the shape a non-specialist reads:

> a person asks an agent to do a job -> the agent makes a request -> the request
> passes through enforcement -> the job either goes through, or is stopped, and
> you can see exactly why.

Every outcome below is produced by the real binaries, not narrated by hand. The
driver is [`scripts/stories/run.sh`](../scripts/stories/run.sh) (`make stories`),
which mints a real delegation chain, starts a real enforcement proxy over a real
data-governance policy, and drives a real agent through each attempt. The images
in [`docs/assets/stories/`](assets/stories/) are rendered from the verbatim
ALLOW/DENY lines that run captures. **No image may claim an outcome the binaries
did not produce.** That is the whole point, and it is the same discipline as the
tamper-demo GIF ([docs/demo.md](demo.md)).

## The cast, and the grant

One workflow anchors both stories, so a reader learns the setup once.

- **Dana** is an FP&A analyst. She wants a *revenue-pack agent* that assembles the
  weekly numbers: pull the finance figures, drop them into her team's workbook.
- **Acme Finance** is Dana's org. Authority flows **Dana -> Acme Finance -> the
  agent**, narrowing at every hop (this is Kessa's core rule; see the README).
- The agent ends up holding a credential scoped to exactly two things:
  - **READ** the finance revenue dataset `datalake:finance/revenue`
  - **READ/WRITE** the finance-reporting workbook `o365:finance-reporting/weekly.xlsx`
- **Acme's DLP proxy** is the enforcement point every action passes through.

The scope is not documentation or a dashboard setting: it is the delegation
chain in [`scripts/stories/spec.json`](../scripts/stories/spec.json) (hop 1 bounds
the verbs to `data.read,file.write,file.share`; hop 2 bounds the resources to the
two identifiers above). The environment's policy
([`examples/policies/data-governance.json`](../examples/policies/data-governance.json))
is permissive by default and adds one hard rule (no deletion of source data), so
in these two stories all the safety comes from what the agent was *delegated* --
which is exactly the property they are meant to teach.

> **One honest modelling note.** Kessa's caveat engine matches fields with
> `== != <= < >= > in`, and there is no path-prefix or glob operator. So "the
> agent's corner of Office 365" is modelled as a **named resource identifier**
> matched exactly (or by an `in` set), not a wildcard path like `/sites/finance/*`.
> The stories are faithful to what the code enforces; they are not pretending the
> engine has a matcher it does not.

## The two stories

Each proves the same safety property -- **least authority** -- from a different
angle, and each is a contrast: the same agent, the same grant, one request that
lands and one that is stopped, with the real reason attached. That contrast is
the message: the guardrail is invisible when work is in-bounds and decisive when
it is not.

### Story A -- an agent reads only the data it was granted

The agent reads the dataset it was scoped to, and is stopped the instant it
reaches for another team's data. Not "the agent was trained not to," but "the
agent's credential does not carry that authority, and the proxy checks."

```
ALLOW  data.read -> datalake:finance/revenue  (routine reporting action within policy)
DENY   data.read -> datalake:hr/payroll  (action exceeds delegated authority: macaroon: caveat "target in datalake:finance/revenue,o365:finance-reporting/weekly.xlsx" unsatisfied: target="datalake:hr/payroll")
```

Rendered: [`docs/assets/stories/story-a-least-authority-read.svg`](assets/stories/story-a-least-authority-read.svg).

### Story B -- an agent writes only inside its own workspace

The mirror of A, on the write side. The agent writes its own workbook, and is
stopped when it tries to write into the exec-board workspace. A compromised or
confused agent cannot use "write a spreadsheet" as a foothold into places it was
never given.

```
ALLOW  file.write -> o365:finance-reporting/weekly.xlsx  (routine reporting action within policy)
DENY   file.write -> o365:exec-board/summary.xlsx  (action exceeds delegated authority: macaroon: caveat "target in datalake:finance/revenue,o365:finance-reporting/weekly.xlsx" unsatisfied: target="o365:exec-board/summary.xlsx")
```

Rendered: [`docs/assets/stories/story-b-least-authority-write.svg`](assets/stories/story-b-least-authority-write.svg).

### Deliberately not (yet) a story: human-in-the-loop

Kessa's enforcement primitive for consequential actions is real and tested (a
consequential action is denied until a valid, action-bound human approval is
presented; see `make demo` scenario 3 and `internal/enforce`). But the
*experience* around it -- suspending a request, routing it to an escalation
point, and binding that person's approval back to the exact pending item -- does
not exist yet. Surfacing a "waits for a human" story now would imply a workflow
we do not ship, so it is intentionally left out until that mechanism is built.

## Where the images live

- **`docs/assets/stories/`** holds the committed, rendered cards (one SVG per
  story). These are what the README and decks embed.
- **`scripts/stories/`** holds everything that produces them: the chain
  `spec.json` and mock `keystore.json`, the driver `run.sh`, and the renderer
  `render.go`. The policy is in `examples/policies/data-governance.json`.
  `scripts/stories/out/` is the regenerable capture and is git-ignored.

## How the images are generated

Two deterministic steps, both `make` targets:

1. **Capture.** `make stories-capture` runs the scenarios through the real
   binaries and writes `scripts/stories/out/runs.tsv`: one line per attempt,
   `id <TAB> verbatim-agent-line` (ids `A-allow`, `A-deny`, `B-allow`, `B-deny`).
   This file is the single source of truth for what the images may say.
2. **Render.** `make stories-images` runs the capture, then
   [`scripts/stories/render.go`](../scripts/stories/render.go) -- a standalone,
   standard-library-only Go program -- parses `runs.tsv` and writes the two SVG
   cards. It embeds no timestamps or random ids, so re-running is a no-op in git
   unless a scenario actually changed.

Each card is a two-lane contrast (allow lane green, deny lane amber) laid out as
a left-to-right throughline: **intent -> request -> enforcement -> outcome**,
with the request and the verbatim reason set in a monospace face so they read as
the literal CLI strings they are. The palette reuses the README's mermaid colors,
so the whole project reads as one system.

The acceptance test is simple: change a scenario in `run.sh`, re-run
`make stories-images`, and the card's text changes to match with no hand-editing.
Do not edit the `.svg` files directly.

## Regenerating

```sh
make stories           # narrate the run (no files written)
make stories-capture   # + write scripts/stories/out/runs.tsv
make stories-images    # + render docs/assets/stories/*.svg
```

Deterministic throughout: fixed seeds, a fixed `--now`, fixed nonces, localhost
only. Nothing of ours is trusted as a service at any point.
