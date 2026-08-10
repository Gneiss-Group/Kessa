<!-- SPDX-FileCopyrightText: 2026 Gneiss Group Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The MCP-native listener

Kessa's proxy serves two listeners into one enforcement engine. This document
covers the MCP-native one, so that a client can be pointed at it correctly the
first time rather than by being rejected until it guesses right.

**Nothing here is a second enforcement path.** Every request this listener
accepts becomes the same `Proxy.Handle` / `Proxy.Tip` call the generic HTTP
listener makes, and every reply is the same result translated back out. The
guarantees live in the engine; this is an adapter.

## The revision, stated plainly

| | |
|---|---|
| Revision spoken | **`2026-07-28`** (final) |
| Other revisions accepted | **None.** There is no negotiation and no fallback |
| Transport | Streamable HTTP, JSON-RPC 2.0 |
| Default address | `127.0.0.1:8182` (`--mcp-addr`, empty disables the listener) |

The single-revision rule is deliberate rather than unfinished. MCP is under fast
revision, and accepting two revisions at once would mean two sets of header and
`_meta` semantics reaching one enforcement call. When the listener moves, it
moves wholesale.

A running proxy prints the revision in its startup banner. A client that gets it
wrong is answered with JSON-RPC `-32022` on an HTTP 400, whose `error.data`
carries `{"supported": ["2026-07-28"]}`. That is the authoritative answer at
runtime; this table is here so you do not have to provoke it.

## What every request must carry

This revision is **stateless**: there are no sessions and no `initialize`
handshake, so each request carries its own protocol context. All of the
following are required, and a request missing any of them is refused.

**Headers**

| Header | On | Must equal |
|---|---|---|
| `MCP-Protocol-Version` | every request | the `_meta` protocol version below |
| `Mcp-Method` | every request | the body's `method` |
| `Mcp-Name` | requests naming a tool | the tool named in `params` |

These mirror body fields so an intermediary can route without parsing the body.
That is exactly why a header disagreeing with its body field is **refused**
(`-32020`, HTTP 400) rather than ignored: tolerating a disagreement would let a
gateway send one thing to a rate limiter and another to the chokepoint. A header
value that is not plain ASCII may be sent Base64-encoded between `=?base64?` and
`?=`, and is decoded before the comparison.

**`params._meta`**

| Field | Type |
|---|---|
| `io.modelcontextprotocol/protocolVersion` | string |
| `io.modelcontextprotocol/clientCapabilities` | object (a JSON `null` is refused) |

**Transport conditions**

`Content-Type: application/json` is required. The body is capped at 1 MiB.
Cross-origin requests are refused. Top-level JSON-RPC arrays (batches) are
refused: this revision requires a POST body to be a single message.

## Methods and tools

`ping`, `tools/list`, and `tools/call` are implemented. Anything else, including
`initialize`, is HTTP 404 with `-32601`. The status code is load-bearing: it is
how a client tells a modern server that does not implement a method from a
legacy server that does not host this endpoint at all.

Rather than exposing the guarded tools by name, the listener exposes two
reserved tools that carry Kessa's existing wire protocol:

| Tool | Arguments | Returns | HTTP equivalent |
|---|---|---|---|
| `kessa/tip` | none | the `Tip` a caller binds its proof of possession and approval to | `GET /tip` |
| `kessa/enforce` | an `enforce.Request` | the `enforce.Result` | `POST /enforce` |

**`kessa/tip` is not optional.** A proof of possession is bound to the position
the entry will occupy, so a client cannot construct a valid `kessa/enforce`
request without reading the tip first. A stale tip is refused with the position
and the retry named, because the proxy cannot distinguish a stale proof from a
forged one and does not pretend to.

Every successful result carries `resultType: "complete"` and the server's
identity under `_meta.io.modelcontextprotocol/serverInfo`, which is how a
stateless client learns who answered without a handshake.

## Notifications

A message with no `id` is a notification: it is answered with HTTP 202 and no
body. An explicit `null` id is neither a request nor a notification and is
refused (`-32600`, HTTP 400).

Worth knowing precisely, because it looks like a gap and is not one: a
notification is acknowledged **without** the header and `_meta` validation
above. This revision defines no client-to-server notifications over Streamable
HTTP and states no header requirements for one, so refusing on an unstated rule
would be inventing spec. The 202 is written before dispatch, so no method is
invoked and no enforcement path is reached. The transport conditions (origin,
content type, body cap) still apply.

## Errors you can expect to see

| Code | HTTP | Meaning |
|---|---|---|
| `-32020` | 400 | a request-metadata header disagrees with the body |
| `-32022` | 400 | unsupported protocol version; `data.supported` names what is |
| `-32600` | 400 | not a valid JSON-RPC request (bad `jsonrpc`, null id, batch) |
| `-32601` | 404 | unknown method |
| `-32602` | 400 | required `_meta` field missing or of the wrong type |
| `-32700` | 400 | parse error |

Errors about the **call** rather than the envelope (an unknown tool name, or
arguments that will not parse) are returned on an HTTP 200, as JSON-RPC
requires.

## Before you deploy this

The listener binds loopback by default. A non-loopback bind is refused unless
`--allow-unauthenticated-remote` is passed, and that flag adds no
authentication: it records that you accepted its absence. **Neither listener has
caller authentication**, which is an open question rather than an oversight; see
[`UPCOMING.md`](../UPCOMING.md).

The transport is a documented mock (plain JSON over HTTP, no mTLS). This is an
evaluation and development endpoint, not a production-hardened one. See [Known
limits](../README.md#known-limits).
