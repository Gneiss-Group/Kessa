<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# On-device signing daemon

`kessa-issuer daemon` is the on-device key custodian (§2a, B3): it holds the
device's signing key(s) and brokers signatures over a local Unix domain socket,
the same shape as `ssh-agent`/`gpg-agent`. A client: `kessa-agent`, or anything
that needs to sign as an on-device principal: connects to the socket and gets a
`signer.Signer` whose private key **never leaves the daemon**.

The daemon is backend-agnostic: it brokers whatever `signer.Signer` it holds. It
can broker software keys (a keystore) on macOS and Linux, and enrolled Secure
Enclave keys (`internal/signer/enclave`) loaded by keychain tag from the
enrollment mapping. Both are the same `signer.Signer` seam.

## Running it

Two key sources, which imply different **policies**:

```bash
# Non-production / routine: software keys, brokered as ROUTINE (PoP) keys.
kessa-issuer daemon --keystore ~/.kessa/keystore.json

# Production: load enrolled Secure Enclave keys as APPROVAL-capable keys.
kessa-issuer daemon --mapping ~/.kessa/enrollment-map.json
```

- `--keystore` keys are brokered as **Routine** (proof-of-possession). A software
  key is acceptable here: a PoP signature is bound by the proxy to one action at
  one chain slot.
- `--attestation-key <DID>` (repeatable) reclassifies one of those keystore keys
  as an **Attestation** key: an enforcement point's own audit-signing key, which
  is what `kessa-proxy serve --signer-sock` asks the daemon for. Also software-
  permitted, and the distinction is not a security boundary: it is so the key
  table below says which key attests a log and which proves possession. A named
  DID the keystore does not hold is refused rather than ignored, because ignoring
  it would broker the intended key as `Routine` and still report success.
- Entries in a keystore file whose key is not a DID (the shipped fixtures carry a
  `_comment` documenting that the file is mock key management) are skipped rather
  than treated as principals. They were not, until 2026-08-11, which is why the
  daemon could not load either keystore in this repository.
- `--mapping` loads each non-revoked enrolled key by its keychain tag and brokers
  it as an **Approval**-capable key (the employee key issues and approves). These
  **must be hardware-backed**: the daemon refuses to start if a mapping entry is a
  software key (`--software-key` enrollment), and `signerd.NewKeys` refuses any
  approval key that is not Secure-Enclave-backed (R4-02). This keeps the
  human-approval control an OS-enforced per-use gesture, never an unenforced
  convention. `--mapping` requires a build with the Enclave backend
  (`darwin && cgo`).
- At least one of `--keystore` / `--mapping` is required; both may be combined.
- `--sock <path>` overrides the socket location. Default:
  `$XDG_RUNTIME_DIR/kessa/issuer.sock` when set (systemd user services set it),
  otherwise `~/.kessa/issuer.sock`.
- The daemon creates the socket's parent directory `0700` and the socket `0600`,
  refuses to start if a live daemon already owns the path, and clears a stale
  socket left by a previous run.
- **Give the socket a directory of its own.** The daemon creates that directory
  `0700` when it is absent, and when it already exists it *checks* the mode
  rather than changing it: `0700` is accepted, anything else is refused with the
  remedy. It will not widen or narrow a directory it did not create, because the
  socket's parent is frequently a shared path and tightening one reaches well
  beyond the daemon (`--sock /tmp/kessa.sock` would have meant chmod'ing `/tmp`).
  Both defaults above already nest under a `kessa` directory for this reason, and
  `--check-config` reports which of the two cases a given `sock` falls into.

> **Why the policy split (R4-02):** the daemon signs whatever bytes an authorized
> (same-uid) client sends; it does not yet distinguish a PoP sign from an approval
> sign at the operation level (that op-level policy is future work). Until then,
> the integrity of "a human deliberately approved this" rests on the approval key
> being an Enclave **Biometric** key, so the OS demands a gesture per signature.
> The `--mapping` hardware requirement is what makes that a code-enforced floor
> rather than an assumption.

## Using it from the agent

```bash
kessa-agent attempt --agent-sock ~/.kessa/issuer.sock \
  --chain chain.json --type payment.transfer --target acct/999 --approver <human-did>
```

With `--agent-sock`, the agent fetches its actor (and approver) key from the
daemon instead of a local keystore; `--keystore` is not needed. Everything
downstream is identical: the socket-backed signer is a drop-in `signer.Signer`.

## Using it from the proxy

```bash
kessa-issuer daemon --keystore keystore.json \
  --attestation-key did:web:localhost:proxies:gatekeeper --sock /run/kessa/s

kessa-proxy serve --signer-sock /run/kessa/s \
  --enforcement-point did:web:localhost:proxies:gatekeeper \
  --policy policy.json --dids ./public
```

`serve` takes exactly one of `--keystore` and `--signer-sock`, never both and
never neither: defaulting either way would pick a key custody model on the
operator's behalf, and the two differ in whether the enforcement point's private
key is in the proxy's process at all. With `--signer-sock` it is not; the proxy
holds no key material and every audit entry and export envelope is signed over
the socket.

`Dial` round-trips immediately to confirm the daemon holds that DID, so a missing
daemon, or one holding the wrong key, is a **startup** failure. A proxy that
started and could not sign would already have accepted traffic it cannot record.

**Deployment consequence of the peer-uid gate below:** the proxy must run as the
*same uid* as the daemon and be able to reach the socket's path. Same host, or
same pod with a shared volume and one uid, not two unrelated service accounts.

Batch mode (`kessa-proxy run`) deliberately has no `--signer-sock`. It needs the
keystore regardless, to mint each fixture request's proof-of-possession and
approval, so brokering only the enforcement point's key there would swap one of
three keys for a daemon and leave the other two as seeds in a file.

## Access control

Two independent gates protect the socket, both enforced without any shared secret:

1. **Filesystem**: `0700` directory + `0600` socket, so only the owner can open it.
2. **Peer credential**: every connection's peer uid is checked (`SO_PEERCRED` on
   Linux, `LOCAL_PEERCRED` on macOS) and refused unless it matches the daemon
   owner. If the peer's identity cannot be established, the connection is refused
   (fail closed).

The private key never crosses the socket in either direction; only signatures and
public keys do.

## Running as a background service

Templates are provided so the daemon survives logout/reboot. Both run as the
**user** (not root/system), keeping key material and the socket user-owned.

- **macOS (launchd):** [`build/launchd/com.gneiss.kessa.issuer.plist`](../build/launchd/com.gneiss.kessa.issuer.plist)
- **Linux (systemd user unit):** [`build/systemd/kessa-issuer.service`](../build/systemd/kessa-issuer.service)

Each template carries its own install steps in a header comment. Fleet-scale
rollout across many machines is deliberately out of scope here (that is the paid
tier per §2b); these templates cover a single machine keeping the daemon running.

## Windows

Not supported yet (§2 defers it). The transport is a `net.Listener`/`net.Conn`, so
a Windows named-pipe listener plus a peer-credential equivalent are the drop-in
points when it is built; nothing in the protocol changes.
