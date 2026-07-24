# Kessa Documentation

The **code and the top-level [`README`](../README.md) are the source of truth for
how the system behaves today.** The documents here are the record of how it was
reviewed and hardened, plus the material for running the demo.

## How the project is built

| Document | What it is |
|----------|------------|
| [Go standards](go-standards.md) | The rules this codebase is written to, including the ones that exist because of what the verifier claims. |
| [Branching, commits, and releases](branching.md) | Short-lived branches off `main`, Conventional Commits, semantic versioning, and the manual owner-only release. |

## Security review

Kessa was put through two adversarial review rounds (self-run AI red-team passes,
**not a third-party audit**); all findings are closed. A single **consolidated
security-review document** is being prepared and will be linked here, replacing
the earlier round-by-round working notes.

For the precise, current statement of what a clean verdict proves and does not,
see [what a clean verdict actually
proves](how-it-works.md#what-a-clean-verdict-actually-proves) and [Known
limits](../README.md#known-limits) in the top-level README.

## Demo and user stories

| Document | What it is |
|----------|------------|
| [Demo](demo.md) | How the README's GIF is built and regenerated. |
| [Stories](stories.md) | The corporate-workflow user stories, driven end to end through the real binaries. |

One clarification worth keeping in view until the consolidated document lands:
the policy layer is a **hand-rolled, standard-library rule evaluator** behind an
`Evaluator` interface — not OPA, Rego, or Cedar. Adopting one of those is an open
question, not a shipped feature; see [`UPCOMING.md`](../UPCOMING.md).
