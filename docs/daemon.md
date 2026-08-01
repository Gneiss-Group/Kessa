<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# On-device signing daemon

`kessa-issuer daemon` is the on-device key custodian (§2a, B3): it holds the
device's signing key(s) and brokers signatures over a local Unix domain socket,
the same shape as `ssh-agent`/`gpg-agent`. A client — `kessa-agent`, or anything
that needs to sign as an on-device principal — connects to the socket and gets a
`signer.Signer` whose private key **never leaves the daemon**.

The daemon is backend-agnostic: it brokers whatever `signer.Signer` it holds. It
runs today with software keys (a keystore) on macOS and Linux; the hardware path
(a Secure Enclave-held key, `internal/signer/enclave`) is the same seam and slots
in behind this command once enrollment (B4) mints one.

## Running it

```bash
kessa-issuer daemon --keystore ~/.kessa/keystore.json
```

- `--sock <path>` overrides the socket location. Default:
  `$XDG_RUNTIME_DIR/kessa/issuer.sock` when set (systemd user services set it),
  otherwise `~/.kessa/issuer.sock`.
- The daemon creates the socket's parent directory `0700` and the socket `0600`,
  refuses to start if a live daemon already owns the path, and clears a stale
  socket left by a previous run.

## Using it from the agent

```bash
kessa-agent attempt --agent-sock ~/.kessa/issuer.sock \
  --chain chain.json --type payment.transfer --target acct/999 --approver <human-did>
```

With `--agent-sock`, the agent fetches its actor (and approver) key from the
daemon instead of a local keystore; `--keystore` is not needed. Everything
downstream is identical — the socket-backed signer is a drop-in `signer.Signer`.

## Access control

Two independent gates protect the socket, both enforced without any shared secret:

1. **Filesystem** — `0700` directory + `0600` socket, so only the owner can open it.
2. **Peer credential** — every connection's peer uid is checked (`SO_PEERCRED` on
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
