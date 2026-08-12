# Kessa Documentation

The **code and the top-level [`README`](../README.md) are the source of truth for
how the system behaves today.** The documents here are the reference material:
how the system is built, how its signing backends work, and how to run the demo.

## How the project is built

| Document | What it is |
|----------|------------|
| [Go standards](go-standards.md) | The rules this codebase is written to, including the ones that exist because of what the verifier claims. |
| [Branching, commits, and releases](branching.md) | Short-lived branches off `main`, Conventional Commits, semantic versioning, and the manual owner-only release. |

## Integrating

| Document | What it is |
|----------|------------|
| [The MCP-native listener](mcp.md) | The revision spoken, what every request must carry, the two reserved tools, and the errors a client will see. Read this before pointing an MCP client at the proxy. |

## Keys, devices, and signing

| Document | What it is |
|----------|------------|
| [Signing backends](signer.md) | The `Signer` seam: the software keystore, the macOS Secure Enclave backend, the hardware gate, and a blunt list of what is *not* true yet. Read §6 before trusting any hardware claim. |
| [Enrollment](enrollment.md) | How a device gets its own key and its own credential, and why per-device credentials make revocation symmetric. |
| [Configuration](configuration.md) | The `serve` config file: why it exists, why it and the command line are mutually exclusive, and what an absent field means. |
| [Signing daemon](daemon.md) | The long-running signer: its socket, permissions, and trust boundary. |
| [Enclave runbook](enclave-runbook.md) | Reproducing the Secure Enclave path on real hardware, including the code-signing and entitlement setup it requires. |

## Security review

Kessa has been put through multiple adversarial review rounds (self-run AI
red-team passes, **not a third-party audit**); all findings are closed. The
[security review record](security-review.md) is the public register: what each
round covered, when, every finding raised, and where it stands. It records that a
finding existed and was closed without reproducing the mechanism; the
round-by-round working notes are not published.

For the precise, current statement of what a clean verdict proves and does not,
see [what a clean verdict actually
proves](how-it-works.md#what-a-clean-verdict-actually-proves) and [Known
limits](../README.md#known-limits) in the top-level README.

## Demo and user stories

| Document | What it is |
|----------|------------|
| [Demo](demo.md) | How the README's GIF is built and regenerated. |
| [Stories](stories.md) | The corporate-workflow user stories, driven end to end through the real binaries. |

One clarification worth keeping in view: the policy layer is a **hand-rolled,
standard-library rule evaluator** behind an `Evaluator` interface, not OPA, Rego,
or Cedar. Adopting one of those is an open question, not a shipped feature; see
[`UPCOMING.md`](../UPCOMING.md).
