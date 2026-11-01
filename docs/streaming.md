# WebSocket and server-sent events

Streaming is opt-in for a site's existing proxy routes. Denials, exact local
publications and configured redirects retain their priority; an Upgrade request
cannot turn a static or denied URL into a proxy tunnel. The only upstream remains
the configured numeric loopback HTTP endpoint.

```kdl
site "app.example" {
    tls "auto"
    reverse-proxy "127.0.0.1:3000"
    deny "/admin"
    proxy-path "/chat"
    proxy-path "/events"
    proxy-stream "websocket"
    proxy-stream "sse"
    proxy-limit "connections" "2"
    proxy-limit "streams" "8"
    // Optional; enable only for applications reviewed for compression risks.
    websocket-compression "permessage-deflate"
    websocket-origin "https://console.example"
    proxy-limit "stream-upload" "16MiB"
    proxy-limit "stream-download" "64MiB"
    proxy-timeout "stream-idle" "30s"
    proxy-timeout "stream-total" "300s"
}
```

Both stream types are disabled by default. Each `proxy-stream` value may appear
once. Stream budget directives require at least one enabled stream type and an
upstream. `generate` preserves both opt-ins and every budget. All changes are
compiled and activated through the same immutable configuration mechanism.

## Handshake and routing

For WebSocket, PathWard requires HTTP/1.1 GET, no request body or prefetched client
frames, a canonical 16-byte base64 key, version 13 and matching WebSocket Upgrade /
Connection fields. It regenerates the upstream handshake alongside the existing
trusted forwarding fields. Duplicate request fields, other Upgrade protocols,
CONNECT and connection options that nominate arbitrary headers are rejected.

If Origin is present, it must exactly match the canonical external origin
(`https://app.example` for TLS, or the direct HTTP listener's origin including its
nondefault port), or an explicitly configured `websocket-origin`. Up to 16 unique
additional origins are allowed. Each must be a lowercase ASCII http/https origin
with a DNS-style hostname and optional canonical nondefault port (1–65535).
Paths, queries, fragments, userinfo, wildcard, `null`, IPv6 literals and trailing
slashes/dots are rejected. No suffix matching or URL decoding occurs. Noncanonical
or unlisted origins receive 403 before upstream contact. See
[RFC 6454 §7](https://www.rfc-editor.org/rfc/rfc6454.html#section-7).

An absent Origin is permitted for non-browser clients. Origin is not authentication:
the upstream must still authorize users, cookies, operations and application-specific
path aliases. This allowlist affects only WebSocket handshakes, not CORS or SSE.
Removing an origin affects new handshakes; already established connections keep
running under their captured policy until expiry or shutdown.

Before sending 101 downstream, PathWard checks the HTTP version, status,
Upgrade/Connection pair, challenge response and any selected subprotocol.
The selection must be one of at most 16 distinct offered tokens (64 bytes each).
A 101 containing Content-Length, Transfer-Encoding or an unapproved extension is rejected.
Unsolicited 101 responses cannot start a tunnel. Non-101 responses retain ordinary
bounded HTTP handling, so application rejections can reach the client.

Compression is disabled by default. `websocket-compression "permessage-deflate"`
requires WebSocket opt-in and enables a restricted, end-to-end negotiation profile:
**both `server_no_context_takeover` and `client_no_context_takeover` are required**.
PathWard emits a canonical offer only when a compatible client offer exists.
The common `permessage-deflate; client_max_window_bits` browser offer is supported.
Optional client window bits may be absent, valueless or 15. Offers requiring
server window bits or other parameters are not selected. Upstream selection must
contain exactly permessage-deflate and the two valueless reset parameters; unknown,
unsolicited, duplicate or additional selections fail with 502 before downstream 101.
The upstream may decline compression. No raw extension field is forwarded.

Extension parsing is limited to 4096 bytes, eight alternatives and four unique
parameters each. Token or quoted-token values are accepted; escaping and broader
quoted-string syntax are deliberately rejected. Unsupported well-formed offers
are ignored, while malformed/duplicate parameters cause 400. This is a bounded
subset of [RFC 7692 §7.1](https://www.rfc-editor.org/rfc/rfc7692.html#section-7.1),
not support for every extension or compression profile.

The relay does not compress, decompress or inspect frames. RSV1 and compressed
payloads pass unchanged; **caps measure compressed wire bytes, not expanded sizes**.
Endpoints must cap decompressed messages and CPU usage. History reset reduces
cross-message compression exposure but does not remove same-message secret/data
compression side channels. Keep compression disabled when the application cannot
safely combine secrets and attacker-controlled content; see
[RFC 7692 §8](https://www.rfc-editor.org/rfc/rfc7692.html#section-8).
No compression library was added. The challenge continues to use existing `ring`
SHA-1 solely for [RFC 6455 §4](https://www.rfc-editor.org/rfc/rfc6455.html#section-4).

After successful Upgrade, frames are opaque bytes relayed in both directions,
including bytes arriving with the upstream handshake. Ping/pong, close frames,
fragmentation and application binary/text payloads pass unchanged. Endpoint frame
parsers remain responsible for masking, opcodes, UTF-8 and message validation.
PathWard does not synthesize frames, inspect messages or implement subprotocols.
EOF drains queued bytes and closes the transport; it does not promise TCP half-close
semantics or a synthesized WebSocket close handshake.

## SSE delivery and failures after commitment

With SSE enabled, a non-HEAD 200 response with Content-Type `text/event-stream`
may stream after its head passes the normal syntax, duplicate-header and framing
checks. Parameters on the media type are allowed. Encoded/compressed SSE responses
are refused; `identity` is accepted. Content-Length, strict chunked encoding and
connection-close bodies are supported. HEAD and non-200 responses keep ordinary
HTTP semantics. POST/fetch consumers can stream too, within the ordinary request
body limit. Last-Event-ID, authentication and cookie fields use existing forwarding
rules. SSE event bytes are neither decoded nor rewritten; the application must
produce valid UTF-8 events as described in the
[HTML event stream specification](https://html.spec.whatwg.org/multipage/server-sent-events.html).

Downstream SSE always uses chunked HTTP/1.1 framing. Data is flushed as it becomes
available, without waiting for an event boundary or the full upstream body.
Bounded incremental parsing removes upstream chunk framing; chunk extensions and
trailers remain unsupported. The decoder verifies cumulative payload bounds and
fixed-length completion. Large fixed Content-Length values are refused before
committing the response.

A later invalid/truncated chunk, capacity violation, timeout, disconnect or stop
closes the transport. It never appends a second HTTP error response after 200/101.
A failed SSE stream omits the terminal zero chunk. Clients must handle incomplete
responses and reconnect according to their application semantics; an interrupted
stream does not imply an application operation was rolled back. Standard browser
EventSource reconnection is described in the linked HTML specification.

## Finite resources and shutdown

| Setting | Default | Hard range |
| --- | --- | --- |
| `proxy-limit "streams"` | `8` | 1–16 per hostname |
| `proxy-limit "stream-upload"` | `16MiB` | 1 B–1024 MiB |
| `proxy-limit "stream-download"` | `64MiB` | 1 B–1024 MiB |
| `proxy-timeout "stream-idle"` | `30s` | 100 ms–300 s; no greater than stream-total |
| `proxy-timeout "stream-total"` | `300s` | At least stream-idle; at most 3600 s |

Units follow [ordinary proxy budgets](routing-and-limits.md): B/KiB/MiB and ms/s,
canonical nonnegative integers without implicit units. The upload/download caps
count cumulative post-Upgrade wire bytes for WebSocket, including frame overhead.
SSE counts decoded HTTP body bytes; it retains the ordinary request-body cap.
These are whole-session limits, not frame/event sizes or bandwidth rates.

Ordinary request-body/connect/response-head/total budgets still bound handshake
preparation. Stream lifetime starts when the valid streaming response head is
received. Idle time measures no successful relay read/write; reads on one side do
not make buffers unbounded when the other side stalls. Total lifetime never
resets, even with heartbeat traffic. Before hostname selection, the existing
fixed unauthenticated head/TLS budgets apply; a smaller service deadline is checked
once the host can be selected. Error responses retain the one-second write budget.

There are at most **16 reserved/active streams per Server**, **eight per transport
peer** (IPv4-mapped addresses normalized; IPv6 grouped by /64), and the configured
per-host stream cap. Counts include queued handoffs and are shared across reload
and rollback generations. A full quota returns 503 before downstream success.
WebSocket reserves capacity before connecting upstream. SSE is identified from its
upstream response, so a capacity rejection can occur after an upstream operation
has executed. There are no automatic retries; clients must account for side effects.

Four ordinary HTTP workers and 16 fixed stream workers have separate bounded
queues. After handshake validation, a single-owner socket/TLS object and owned
quota leases move to a stream worker. The ordinary per-service `connections` cap,
pre-handshake admission permit and per-peer dispatch slot are released at handoff.
Thus established streams cannot occupy all ordinary workers. A single host may
still consume all stream capacity when configured for 16 and reached by multiple
peers; this is a resource bound, not a fair per-host scheduler. The peer cap uses
the transport address, never forwarded headers; users behind NAT share a cap.

Pre-handshake global 12/per-peer six admission, token buckets, pending queue eight
and dispatch limits remain unchanged. The combined bound is 12 ordinary/admitted
plus 16 reserved or established streams (upstream sockets and monitors are separate).
The process allocates 20 serving threads even without active streams. This remains
a small bounded server, not an event-loop runtime for thousands of streams.

Candidate preparation does not modify active caps. Only successful configuration
commit installs new limits. Admission checks both the captured and current host
caps; lowering a cap blocks new reservations until enough old streams finish.
Existing streams are not evicted. Disabling all stream types installs a zero live
cap; rollback reuses counts rather than resetting them. Completion, failed
handshake, failed handoff and shutdown release leases by ownership. The connection
metric's owner moves with the socket, avoiding gaps or double counting at handoff.

Each WebSocket direction buffers at most 16 KiB of pending payload; SSE uses one 16 KiB
input buffer and one output fragment with bounded chunk framing. TLS plaintext
output buffering is explicitly capped at 32 KiB for streaming. TLS records and
allocator capacity and socket/kernel buffers add overhead. Backpressure stops further reads into an
occupied buffer. The worker owns TLS state in both directions; no thread, task,
queue is spawned per stream; each stream still owns its client and upstream sockets. Nonblocking I/O polls with a five-millisecond
sleep when no relay progress is made. Choose limits for the deployed memory,
latency and concurrency requirements and measure real application behavior.

Reload does not revoke established streams. Their endpoint and limits stay pinned
to the captured snapshot until EOF, timeout or shutdown. Drain/restart when
immediate revocation is needed. Shutdown signals and `begin_shutdown` are checked
in the relay loop, so established streams do not wait for their full configured
lifetime to expire. Stop closes transports; WebSocket clients may see abnormal
closure and SSE clients an incomplete response. Handshakes, ordinary HTTP and
blocking OS/storage calls retain their existing shutdown constraints. SSE client
disconnection is detected on a subsequent write or by a deadline, not by a
separate disconnect watcher.

Existing telemetry records completion/failure and total request duration. It does
not yet export per-service or per-stream gauges, close reasons, or incremental
byte counters. Application probes, reconnect testing, external alerts and load
rehearsal remain necessary before migration.

## Audit and proof boundary

No external dependency, Cargo feature/manifest/lockfile or vendored-source change is
required. Core/configuration/server external package counts remain 0/8/104.
The latest RustSec/graph scan is recorded in
[server/audit-result.json](../server/audit-result.json). Source review covers
handshake header ownership, canonical nonce encoding, Origin/subprotocol policy,
chunk parser boundaries, partial nonblocking writes and flushes, TLS record
ownership, fixed buffers, quota lifetime and cancellation. RFC HTTP framing rules
remain the baseline in [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3).

[StreamingProofs.lean](../proofs/StreamingProofs.lean) now contains 36 statements,
bringing the full axiom audit to **221**. Charon/Aeneas extracts the actual
dependency-free Rust request/response upgrade gates, SSE selection, cumulative byte
arithmetic, idle/total validity, continuation, global/peer/service admission,
Origin decision and deflate selection gates. Proofs establish no unrequested
upgrade or HTTP framing on an accepted 101, bodyless upgrade requests, bounded
sums, stop/expiry refusal, global 16/peer eight/captured-and-live service bounds,
foreign-Origin allowlist necessity, and explicit opt-in/offered compression with
both history resets and valid parameters.

The HTTP/KDL parsers and field wiring, SHA-1/base64 adapter, TLS, socket scheduling,
extension and Origin parsing, worker handoff, SSE incremental decoder and RAII/Mutex lifetimes remain reviewed/tested trusted
code. Lean does not prove WebSocket application semantics, TLS, actual elapsed
time, every byte copy or end-to-end protocol correctness. TCP/TLS tests cover
prefetched/bidirectional data, invalid handshakes, early SSE delivery, split chunks,
capacity violations, timeout/stop, reload accounting and partial writes/flushes.

The capacity/extension change was reviewed for permit ownership on every early
return, poisoned/closed queue behavior, shutdown and worker-start failure cleanup,
configuration serialization, exact Origin comparison, offer-to-response binding,
header ownership and integer/count bounds. Tests cover eight mixed live streams
plus ordinary HTTP, a Linux release test of 16 communicating relays across two peers,
peer/global quota exhaustion, generation-shared caps,
compressed RSV1 bytes in both directions, declined/unsolicited/unsafe compression,
Origin near-misses/revocation and policy-preserving configuration generation.
