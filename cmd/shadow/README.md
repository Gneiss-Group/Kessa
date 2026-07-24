# `kessa-shadow` — passive policy evaluation

Runs the real classifier over actions and reports what a policy **would** gate,
without enforcing anything. It exists for one workflow: tune a policy before you
turn on enforcement.

```
kessa-shadow -policy <file> -export  <file> [-format json|text] [-out <file>]
kessa-shadow -policy <file> -actions <file> [-format json|text] [-out <file>]
```

## What this tool is not

It performs no enforcement of any kind: no proof of possession, no live
revocation check, no human approval, no signed audit log.

**It does not verify exports.** In `-export` mode no signature is checked, no DID
is resolved, and no hash chain is walked. The file is read at face value purely as
a source of recorded actions. `kessa-shadow` is not a substitute for `kessa
verify` and carries none of its guarantees. If the question is whether an export
is authentic, run the verifier.

Its output is a stream of **predictions**, which are not verdicts: unsigned,
un-chained, and never accepted as input by the verifier. A prediction deliberately
carries no `allowed` field, because in a classifier result that would mean only
"no rule forbids this", not "this would be permitted"; real authorization also
requires satisfied caveats, an unrevoked chain, proof of possession, and, for a
consequential action, a human approval. None of those are evaluated here.

## The two modes

**`-export`, replay.** Reads actions recorded in an audit export. The full action
is carried verbatim, including its attributes, so classification is exact.
Because the export also carries each entry's real recorded decision, this mode
reports a predicted-vs-actual diff for free.

**`-actions`, hand-authored.** Reads one JSON action per line, in the same shape
used everywhere else in the system. This is the path for a deployment that does
not exist yet: write a few representative actions and see how a candidate policy
classifies them. A malformed line is skipped with a warning naming the line
number, and the run continues; the final count of skipped lines goes to stderr.

## Reading the diff

Agreement compares **consequentiality only**. An action a policy allows can still
be denied at enforcement time for reasons policy does not decide: exceeding
delegated authority, a revoked hop in the chain, a failed proof of possession.
Counting those as policy disagreements would make the headline number wrong, so
they are not counted.

Disagreements are broken down by direction, and the two are not equally serious:

- **Under-predicted.** The candidate policy says routine where enforcement
  treated the action as consequential. This is the direction that matters: the
  policy under test would let something through unapproved that the recorded
  policy gated.
- **Over-predicted.** The candidate says consequential where enforcement treated
  it as routine. That is extra approval traffic, not a safety regression.

## Posture

Nothing to configure. A policy file carries its own `default` block, so shadow
mode picks up deny-list or allow-list posture from the file itself. Shadow-testing
a candidate allow-list policy before committing to it is just running it. See
[`internal/policy/README.md`](../../internal/policy/README.md) for what posture
means.
