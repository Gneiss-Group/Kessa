# Demo: tamper-evident verification

The GIF in the README (`docs/assets/demo.gif`) shows the independent verifier in
two acts. First it re-derives every verdict from an exported audit log and prints
`VERDICT: PASS`. Then the same command runs again after a single character is
flipped in the signed log, and it prints `VERDICT: FAIL`, failing at exactly the
tampered entry and marking every entry after the break `UNVERIFIED`.

The point the GIF makes: the two runs are the *same command*. Only one byte of
the export changed between them. Nothing of ours is trusted as a service; the
verdict is re-derived from the files alone.

## Regenerating it

From the repo root:

```
vhs docs/demo.tape
```

Requirements: [vhs](https://github.com/charmbracelet/vhs), a Go toolchain, `curl`,
and `perl`. The recording is deterministic (fixed seeds, timestamp, and nonces),
so it is stable from run to run.

## How it is wired

- `docs/demo.tape` is the vhs script. The build and setup run off-camera; the
  recording is the two `kessa verify` invocations around a one-line tamper.
- `scripts/verify-scene.sh` builds the binaries and produces a persistent,
  independently-verifiable export: `export.json` plus the published `public/` DID
  documents and signed status list. Unlike `scripts/demo.sh`, it leaves its
  artifacts on disk so the tamper step has a real file to edit.
- The colored `PASS`/`FAIL` comes from `kessa verify --color=always`. By default
  the verifier colorizes only when writing to a real terminal, so pipes, tests,
  and the golden fixtures stay byte-for-byte plain. `always` and `never` are
  explicit overrides; `NO_COLOR` is honored under `auto`.

## Why tampering an input fixture would not show this

Editing an *input* (say `scripts/demo/spec.json`) and re-running would not
produce a failure: the issuer would simply re-sign everything consistently and
the verifier would pass. The failure only appears when a *signed output* is
altered after the fact, which is the adversary the design names (a dishonest
enforcement point, or anyone who edits the export later). That is why the demo
tampers the exported audit log, not a fixture the pipeline re-signs.
