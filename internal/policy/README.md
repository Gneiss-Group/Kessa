# `internal/policy` — writing a policy

A policy answers one question about an action: **is it routine, or is it
consequential?** Consequential actions demand a live revocation check and a human
approval before the proxy will allow them; routine ones do not. Policy answers
nothing else. It knows nothing about delegated authority, revocation state, or
proof of possession, and it is never on its own an authorization. The enforcement
proxy composes it with those checks (see `internal/enforce`).

"Consequential" is **environment-defined**. The same $500 transfer is routine in
one deployment and gated in another. That is why policies are versioned files
rather than code, and why the file itself travels inside the signed audit export.

---

## The shape of a policy

```json
{
  "version": "commerce-security-v1",
  "rules": [
    { "name": "...", "when": [ ...conditions... ], "consequential": true, "reason": "..." }
  ],
  "default": { "allowed": true, "consequential": false, "reason": "..." }
}
```

**Rules are evaluated top to bottom, and the first match wins.** A rule fires when
*every* condition in its `when` list holds (logical AND). When a rule fires, its
verdict is the decision and no later rule is consulted, so order matters and
`deny` rules belong at the top.

Each rule sets two independent things:

| Field | Meaning |
|---|---|
| `deny: true` | A hard denial. Authority is never even consulted. |
| `consequential: true` | Allowed, but only with a live status check **and** a human approval. |
| `consequential: false` | Allowed as routine, asserted explicitly. |

**`default` is what happens when no rule matches at all.** It is not a fallback
detail; it is the whole of a deployment's *posture*. It is required: a policy that
omits it is rejected at load, because an absent default would silently deny every
unmatched action with no stated reason. A `reason` is required for the same
purpose, since every decision the system records should be able to explain itself.
Those two requirements are independent, so writing out a blank-reason deny-all
explicitly is rejected just as an omitted block is.

Conditions match against a flattened view of the action (`types.Action.Context()`).
Reserved names are `action.type`, `target`, and `expiry`; any other field name
resolves against the action's `attributes`. Operators are `==`, `!=`, `<=`, `<`,
`>=`, `>`, and `in` (a comma-separated set). Ordering operators work on numbers
and on RFC3339 timestamps.

---

## Two postures, one mechanism

Deny-list and allow-list are not two features. They are the same evaluator with a
different `default`:

|  | `default` | Rules assert | Unmatched action |
|---|---|---|---|
| **Deny-list** (default posture) | `{"allowed": true, "consequential": false}` | `consequential: true` for risky cases | routine, proceeds without approval |
| **Allow-list** | `{"allowed": true, "consequential": true}` | `consequential: false` for narrow safe cases | consequential, requires human approval |

Worked examples of both ship in `examples/policies/`:

- [`commerce-security.json`](../../examples/policies/commerce-security.json), deny-list posture.
- [`commerce-security-allowlist.json`](../../examples/policies/commerce-security-allowlist.json), allow-list posture, same domain.

Note that in **both** postures `default.allowed` is `true`. Setting
`allowed: false` is a third, much stricter thing: a closed world in which an
unmatched action is denied outright and *cannot be approved at all*, because a
policy hard-deny short-circuits before the approval flow is ever reached. That is
a legitimate configuration, but it is not allow-list posture, and it is not what
"default-consequential" means.

### Which posture should a deployment run?

Allow-list is the stricter posture and is the safer default for a high-consequence
environment, at the cost of more approval traffic: every action you have not
explicitly characterised as routine will interrupt a human.

Allow-list also **fails in the safer direction.** A condition whose field is
absent from the action never matches, so a rule that is wrong (a typo'd field
name, a mis-specified threshold) quietly does nothing and the action falls through
to `default`. Under deny-list posture that means a broken gating rule **fails
open**: the action is treated as routine and proceeds unapproved. Under allow-list
posture the same broken rule **fails closed**: the action falls to
default-consequential and gets held for approval. A policy-authoring mistake
becomes an interruption rather than an unreviewed action.

That is an argument for allow-list, not a substitute for testing your policy.
Both example policies have unit tests in `policy_test.go`; do the same for yours.

---

## Posture is not a claim, it is evidence

The policy file is carried inside the signed audit export and is content-addressed
as `PolicyID`. That hash covers the `default` block, so the posture a deployment
was running is bound into the export's envelope signature *and* pinned into every
individual audit entry. An independent verifier re-derives each verdict from that
carried policy, and a substituted policy fails verification.

This means "we run allow-list posture" is a property a reader of an export can
check, not a claim they have to take on trust. The mechanism and its adversarial
tests live in
[`internal/export/trustboundary_test.go`](../export/trustboundary_test.go).

One consequence worth knowing: because posture is inside the hash, **changing it
changes the `PolicyID`**. That is correct and intended, since a deployment that
switched posture mid-stream should not look identical to one that did not, but it
does mean entries classified under the old policy and the new one cannot share a
single export.
