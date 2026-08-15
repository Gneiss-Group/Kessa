<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Configuration files

`kessa-proxy serve` and `kessa-issuer daemon` each take their configuration
either from flags or from a JSON file. Not both.

```sh
kessa-proxy serve      --config /etc/kessa/proxy.json
kessa-issuer daemon    --config /etc/kessa/daemon.json
```

Worked examples: [`examples/proxy-config.json`](../examples/proxy-config.json)
and [`examples/issuer-daemon-config.json`](../examples/issuer-daemon-config.json).

The rules below are the same for both commands, and the mechanics behind them
live in one place ([`internal/config`](../internal/config)) rather than being
implemented twice. The schemas themselves differ, because what is required, and
what an absent field means, is a question about the command.

## Why a config file exists

Configuration and invocation used to be the same channel, and they collided.

A container image's `CMD` carries the bind flags the image needs. Supplying
`--policy`, `--dids` and the rest means overriding the command, and `docker run`
**replaces** the `CMD` rather than adding to it. So every real invocation had to
restate a bind posture it never intended to change, and forgetting to was a
refused start. This repository's own proxy image shipped unstartable for months
for exactly that reason.

With a config file, configuration arrives through the file and the command line
keeps only what genuinely varies per invocation.

## The file and the command line are mutually exclusive

Passing `--config` together with any flag the schema also covers is **refused**,
naming every offending flag. There is no precedence rule, because the two sources
are never both allowed to speak.

```
kessa-proxy: --config supplies the whole configuration, so these flags cannot also be given: --http-addr
  Put their values in the config file, or drop --config to configure entirely by flag.
```

Two alternatives were considered and rejected. *Flags override the file* is the
conventional choice, but it lets whatever someone slipped into a launcher script
silently override the reviewed, version-controlled artifact. *File overrides
flags, with a warning* leaves the process running under a posture nobody
intended, and a warning printed on every start is wallpaper inside a week in a
deployment where nobody is watching stderr. Refusal is the only form of "loud"
that survives being unattended.

**The escape hatch is not a flag.** To run without the file, do not pass
`--config`. That covers the emergency case: the file is wrong, the service will
not start, so start it the old way while the file gets fixed.

**Which flags are refused is derived from the schema**, not from a list kept
beside it. A flag is refused if and only if a schema field carries its name. So
flags with no schema field stay usable alongside `--config`: `--now`,
`--version`, `--help`, and `--check-config` itself.

`--now` is outside the schema **deliberately**. It fixes the audit timestamp for
reproducible fixture runs, and exposing a test seam as operator-facing surface
would be a category error. It is not an omission, and it should not be added.

## Absent means off

For `http_addr`, `mcp_addr` and `audit_log`, a field the file omits is **off**,
not "on with the flag default". Explicit configuration beats implicit defaults,
and you cannot misspell your way into absence: an unknown field is refused
outright, so the only route to an absent field is genuinely omitting it.

**This inverts three fields relative to the flag defaults.** `--http-addr`,
`--mcp-addr` and `--audit-log` all default to *on*, so absence in the file means
the opposite of absence on the command line. Since the two sources are never
mixed, you are always in one world or the other, but `--help` will keep showing
the flag defaults and they do not describe the file.

`audit_wal` is the exception and is **required**: see below.

**Every listener cannot be off.** A configuration enabling neither listener is
refused rather than started. Closing one listener is still the supported way to
shed a protocol; closing the last one leaves a chokepoint nothing can reach,
which used to exit 0 and was therefore indistinguishable from a healthy run.

## Schema: `kessa-proxy serve`

| Field | Required | Notes |
|---|---|---|
| `comment` | no | Accepted and ignored. JSON has no comments; this is a declared field, not a tolerated unknown key. |
| `policy` | **yes** | Path to the policy file. |
| `dids` | **yes** | Directory of published `did:web` documents. Local only, no network resolution. |
| `enforcement_point.did` | **yes** | This enforcement point's DID. |
| `enforcement_point.key` | **yes** | Exactly one of `broker_socket` or `mock_keystore`. |
| `http_addr` | no | Absent or empty disables the HTTP listener. |
| `mcp_addr` | no | Absent or empty disables the MCP-native listener. |
| `allow_unauthenticated_remote` | no | Required to bind a non-loopback address. Adds no authentication; records that you accepted its absence. |
| `export` | no | Where to write the accumulated export on shutdown. |
| `audit_log` | no | `""` or absent disables forwarding, `-` is stdout, otherwise a path. Best-effort and lossy by design. |
| `audit_wal` | **yes** | A path enables the durable write-ahead log; `null` disables it. No default in either direction. |
| `status` | no | Object mapping a published status-list URL to the local file serving it. |

### `enforcement_point.key` is tagged

```json
"enforcement_point": {
  "did": "did:web:localhost:proxies:gatekeeper",
  "key": { "broker_socket": "/run/kessa/issuer.sock" }
}
```

`broker_socket` points at a running [`kessa-issuer daemon`](daemon.md): the
private key stays in the daemon and never enters the proxy's process. Note the
daemon's peer-uid gate means the proxy must run as the daemon's owner uid and be
able to reach the socket's path.

`mock_keystore` points at a JSON file holding the seed in the clear. Evaluation
only.

The nesting is deliberate: it makes "both set" and "neither set" malformed shapes
rather than well-formed shapes rejected afterwards.

### `audit_wal` is required, in both directions

It is the only field where "off" means the process **promises less about what it
recorded** rather than merely doing less. With durability off, an allowed action
can be returned and then lost in a crash.

So it has no default. Give a path, or give `null` to say explicitly that this
deployment runs without durability. Omitting it is an error, and so is `""`,
which would be "off" implied rather than stated.

Whether durability should default *on* is a separate, tracked question
([`UPCOMING.md`](../UPCOMING.md)): it needs a WAL benchmark first, and it has to
change the flag path at the same time.

## Schema: `kessa-issuer daemon`

| Field | Required | Notes |
|---|---|---|
| `comment` | no | Accepted and ignored, as above. |
| `sock` | **yes** | The Unix socket to listen on. See below. |
| `keystore` | no | Software keys brokered as ROUTINE (proof-of-possession). |
| `mapping` | no | Enrolled Secure Enclave keys, brokered as APPROVAL-capable. |
| `attestation_keys` | no | Array of DIDs from `keystore` to broker as ATTESTATION keys instead of routine ones. |

At least one of `keystore` and `mapping` is required: a daemon with no key source
has nothing to broker. `attestation_keys` requires `keystore`, and a DID it names
that the keystore does not hold is refused rather than ignored, because ignoring
it would broker the intended key as `routine` and still report success.

### `sock` is required, for a different reason than `audit_wal`

There is no "off" for a socket: a daemon that binds nothing cannot serve. What
absence would inherit is the **flag's** default, which is derived from the
environment (`$XDG_RUNTIME_DIR`, else `$HOME`). So an omitted `sock` would put the
socket wherever the invoking shell happened to point, and a config file exists to
describe a deployment completely.

It also has to agree with the proxy's `enforcement_point.key.broker_socket`, which
is always a literal path. Letting one side be environment-derived and the other
literal is a silent mismatch: the daemon comes up on a path the proxy is not
looking at, and the proxy fails at startup pointing at a socket that does not
exist.

Note the daemon's peer-uid gate: the proxy must run as the daemon's owner uid and
be able to reach that path. In containers that means one uid and a shared volume,
not two service accounts. See [the signing daemon](daemon.md).

## Checking a config before you start

```sh
kessa-proxy serve --config /etc/kessa/proxy.json --check-config
```

This validates and exits without binding, creating, or serving anything. It is a
**prefix of the real startup path**, not a second opinion about it, so it cannot
drift into a different definition of "valid" than the one `serve` enforces.

It goes as deep as the environment allows and **reports which depth it reached**,
because a bare "OK" would be misleading: most of what breaks a real start lives
in the files the config names and the daemon it points at, not in its syntax.

```
kessa-proxy: checked /etc/kessa/proxy.json
  schema           OK  parsed, no unknown fields, required fields present
  listeners        OK  127.0.0.1:8181
  policy           OK  loaded and parsed from the path named
  DID trust root   OK  /etc/kessa/dids is a readable directory
  status lists     OK  1 parsed, sized and self-signature checked
                       (revocation AUTHORITY is per-credential, checked at request time)
  signing daemon   OK  answered on /run/kessa/issuer.sock and holds this enforcement point's key

Checked to depth 3 (live). This configuration should start here.
```

A config naming a `mock_keystore` has no daemon to reach, so it reports depth 2
and says so rather than claiming a depth it did not get to.

**The status-list line says three things and deliberately stops there.** Each
list is parsed, checked against the herd-privacy floor, and checked to carry a
valid signature by the DID it names *for itself*. What that does not establish is
**authority**: who is entitled to publish revocations for a given credential is
named by that credential, not by the list ([R6-01](security-review.md)), so it
cannot be known until a request carries one. A list that is internally consistent
and signed by the wrong party passes here and is refused at request time, which
is why the line names the check rather than saying "signature-checked" and
leaving a reader to assume it covered the question that matters.

`kessa-issuer daemon --check-config` works the same way and stops immediately
before it binds its socket. It tops out at **depth 2** and states that, rather
than inventing a third: the daemon dials nothing, so its equivalent of a live
check would be binding, which is the side effect the check exists to avoid. What
it does reach is worth having: the key set is built and `signerd.NewKeys` has
already refused a software key offered for the approval role, so the printed key
table shows which key attests a log and which proves possession.

Exit status is 0 only when everything it checked passed. An unreachable signing
daemon is a failure, not a caveat: it means this configuration will not start
here.
