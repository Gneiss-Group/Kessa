# Working in this repository

## House style

**Never use em dashes (`—`). Not in code, comments, documentation, commit
messages, PR descriptions, or chat.** There is no exception and no context where
one is acceptable.

Use instead, whichever fits:

| Instead of an em dash | Use |
|---|---|
| joining a clause that continues the thought | a comma |
| introducing an explanation, definition, or list | a colon |
| joining two independent clauses | a semicolon |
| an aside that interrupts the sentence | parentheses |

This is enforced, not merely requested: `scripts/ci/gate.sh` fails the build on
any em dash in a tracked file, so the rule holds without anyone having to
remember it. The one exception is `LICENSE` and `LICENSES/`, which are
third-party legal text and are never edited.

En dashes (`–`) are not used either. Write ranges with a plain hyphen (`F1-F10`)
or with "to".

## Why this is written down

The rule was stated many times across sessions and kept coming back, because it
lived only in conversation. Preferences that are not written into the repository
decay to zero. If you find yourself about to type an em dash, the sentence wants
a comma, a colon, or a rewrite.
