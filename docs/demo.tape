# Kessa tamper-detection demo, as a reproducible recording.
#
# Regenerate the GIF with, from the repo root:
#
#     vhs docs/demo.tape
#
# Needs: vhs (github.com/charmbracelet/vhs), a Go toolchain, curl, and perl.
# The scene is built by scripts/verify-scene.sh, which leaves a persistent,
# independently-verifiable export on disk so the tamper step has something real
# to edit. Everything is deterministic (fixed seeds, timestamp, nonces), so the
# recording is stable across runs.

Output "docs/assets/demo.gif"

Set Shell bash
Set FontSize 18
Set Width 1600
Set Height 450
Set Padding 28
Set Margin 18
Set BorderRadius 10
Set WindowBar Colorful
Set Theme "Dracula"
Set TypingSpeed 25ms
Set WaitTimeout 180s

# --- hidden setup: build + generate a persistent, verifiable export ----------
Hide
Type "scripts/verify-scene.sh /tmp/kessa-demo" Enter
Wait+Screen /scene ready/
Type "export PATH=$PWD/bin:$PATH; source /tmp/kessa-demo/verify-env.sh; cd /tmp/kessa-demo; clear" Enter
Sleep 1s
Show

# --- Act 1: an independent verifier re-derives every verdict from files -------
Type "# Given only the exported files, an independent verifier re-derives every verdict:" Enter
Sleep 800ms
Type "kessa verify --export export.json --dids $DIDS --status $STATUS --color=always | grep -E '^  (entry|VERDICT)'" Enter
Sleep 3200ms

# --- the tamper: one character in the signed audit log -----------------------
Type "# A tamperer flips ONE character in the signed log:  acct/999  ->  acct/evil" Enter
Sleep 700ms
Type "perl -i -pe 's{acct/999}{acct/evil}' export.json" Enter
Sleep 1000ms

# --- Act 2: same command, one byte different ---------------------------------
Type "kessa verify --export export.json --dids $DIDS --status $STATUS --color=always | grep -E '^  (entry|VERDICT)'" Enter
Sleep 4000ms
