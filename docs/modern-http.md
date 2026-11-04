# Connection reuse, multiplexing and bounded compression

The ordinary execution path now polls network waits cooperatively on four fixed
threads (at most 64 tasks on each). Incomplete heads and finite downstream writes
use the existing I/O reactor; request-body reads, upstream connect/head/body waits
and TLS handshakes yield to other tasks. Local filesystem operations and bounded
compression still execute synchronously. This is not a guarantee against a hung
filesystem. WebSocket and HTTP/1 SSE retain the separate 16-thread stream pool.

Global/per-peer admission, rate credits and cross-generation service limits still
apply. `capacity "shared-nat"` is necessary for a 24-client workload; the standard
12/6 active limits deliberately remain conservative. Per-service `connections`
now accepts 1–64 (default 2). Before an upstream side effect, a request can wait
cooperatively for at most one second for service and byte reservations, within
its existing total deadline. No upstream request is retried. Raising concurrency
also requires appropriate request/response caps. Request storage is charged
before upstream contact; response storage uses validated framing before allocation
(see below). HTTP/2/3 additionally reserve bounded input translation buffers.
Unknown-length responses retain their configured maximum and may exhaust credit.
Multiplexed streams may wait up to five seconds for common admission/input
credit, with at most 64 admission waiters process-wide and 32 streams per
connection. Waiting for admission reserves no body/response buffer and consumes
no active permit. Input credit is acquired before allocating a body. Shutdown
and the existing request deadlines still terminate waits; no upstream replay
occurs. Remote HTTP/2 CANCEL/NO_ERROR resets are recorded as peer cancellation,
while unexplained closure and other protocol errors remain failures.
When this queue is full, HTTP/2 keeps further streams within its existing
advertised 32-stream/window bounds and drives existing I/O instead of producing
an immediate REFUSED_STREAM retry storm. This wait is also capped at five
seconds. GOAWAY starts after 68 requests or 115 seconds, leaving room for one
32-stream window already in flight; the actual admission gate still enforces
100 requests and a 120-second new-admission window, and shutdown never admits new requests.
Normal retirement preserves accepted responses within their own deadlines.
The five-second idle flush interval starts again after a task finishes, because
queuing the final DATA frame is not the same as transmitting it. Explicit server
shutdown retains a separate, non-renewable five-second drain limit. A 3,850-second
connection backstop covers the last admission at 120s, 5s admission wait, 120s
response preparation, 3,600s maximum stream duration and 5s final flushing.
This does not extend any request or stream deadline.
The pending remote-reset queue is distinct from the 32 live-stream window:
reset streams release protocol concurrency before their queued heads are consumed.
The library drives input before returning queued heads, so TCP/TLS coalescing can
combine several legitimate cancellation windows. This queue is capped at 100,
matching the connection's request-admission ceiling; the 101st unconsumed reset
closes it. Locally retained resets stay capped at 32 and internal error resets
at eight. This increases bounded header retention: 100 × 16 KiB is about 1.56 MiB
per connection before library/allocator overhead, versus 0.5 MiB for 32. Across
256 admitted connections this portion can reach 400 MiB; it is not covered by
the separate response-byte credit pool or a proof of process RSS. Keep a process
memory limit and resource monitoring; no claim of unchanged worst-case memory is
made. The active-stream, admission, body, rate, request-age and lifetime limits
are unchanged. Explicit CANCEL/NO_ERROR is
checked before admission, after waiting, before the common responder and before
response headers. Cancellation observed before starting the responder prevents
upstream contact; cancellation after upstream work begins cannot undo that work.
An observed peer cancellation is not misreported as a local API error.
Native TLS tests cover both the full-window reload and the excess-reset refusal.

Example additions to an existing, explicitly scoped site:

```kdl
capacity "shared-nat"
site "app.example" {
    tls "auto"
    reverse-proxy "127.0.0.1:3000"
    proxy-limit "connections" "32"
    proxy-limit "request-body" "64KiB"
    proxy-limit "response-body" "1MiB"
    encode "gzip,zstd"
}
```

These caps must match the application, not be copied blindly. Encoding is also
valid on a static site and survives managed configuration generation/reload.

## Connection protocols

- HTTP/1.1 finite responses support sequential reuse when the client explicitly
  sends `Connection: keep-alive`. Missing/close headers, errors, redirects and
  upgrades can close. No pipelining is supported. A connection is limited to 100
  exchanges, 120 seconds lifetime and five seconds idle. Reuse charges another
  rate credit and takes a fresh configuration snapshot. Response framing is
  complete before the next request is dispatched; POST is never replayed.
- Normal TLS advertises `h2` and `http/1.1`. HTTP/2 uses at most 32 streams per
  connection, a 16 KiB header-list/stream window, 4 KiB HPACK table, 65,535-byte
  connection window, bounded resets and 16 KiB send buffers. Each stream charges
  the common admission/byte/service gates. GOAWAY bounds request count and new-admission age; separate closure rules
  bound idle flushing and shutdown. Large files and SSE stream in bounded chunks.
- `serve-tls ... --experimental-http3` also binds UDP at exactly the TCP TLS
  address/port. It uses the same dynamic certificate and policy snapshots, and
  emits same-origin `Alt-Svc: h3=":PORT"; ma=60` on finite TLS responses. TCP
  fallback remains available. Open UDP separately in the deployment firewall.
  HTTP/3 is opt-in because the selected upstream `h3` implementation is still
  described as experimental, not because its tests are optional.
- HTTP/3 bounds request streams to 32, peer-created unidirectional streams to
  three concurrent/eight total, headers to 16 KiB decoded/32 KiB raw, and control
  streams to 64 KiB total each. Raw request frame bytes are bounded before library
  buffering, then extended to twice the accepted body cap plus 32 KiB. QUIC
  windows, crypto buffers, pending handshakes and send buffers are explicitly
  finite. DATAGRAM/WebTransport/extended CONNECT are disabled.
- WebSockets continue over HTTP/1.1 Upgrade. RFC 8441/9220 extended CONNECT is
  not advertised. Upstreams remain numeric loopback HTTP/1, without pooling,
  HTTPS, remote DNS or upstream HTTP/2/3.

The adapters retain the raw path/query, validate `:authority` against SNI, reject
ambiguous Host/content-length/hop fields and trailers, then call the same policy
and confined file responder. A stream snapshots policy before its body; reload
changes subsequent requests, while existing requests retain their admitted
snapshot. Decoding a transport header never grants a file by itself.

## QUIC address changes and early data

QUIC migration is enabled. Quinn performs path validation; PathWard keeps the
original normalized peer key for the entire connection. Active/rate/byte leases
and regenerated X-Forwarded-For therefore retain the **initial peer address**
after an IP/port move. Migration cannot get new admission credit by changing IP.
This sacrifices current-path IP logging to preserve the abuse boundary. This
attribution must be understood by upstream applications that use client IP.

TLS 1.3 resumption uses a 256-entry in-memory, stateful session cache and two
single-use tickets per successful connection. No resumption secrets are persisted;
restart loses tickets and falls back to a full handshake. Resumption authenticates
with the cached session; it does not exchange a fresh certificate. The server
also checks SNI, negotiated h3 and its currently valid certificate identity on
connection entry and during serving. TCP TLS resumption remains disabled. The existing
persist-before-activate ACME path supplies updated certificates to both transports.

Only anonymous, bodyless GET/HEAD for an explicitly published static resource can
receive an application response before handshake completion. Cookie,
Authorization, any query string, proxy routes (including GET), redirects and
unpublished resources are rejected with 425 before contacting an upstream.
`Early-Data: 1` received through any transport enforces the same restriction;
other values are rejected. After completion a client may retry a 425 request;
PathWard itself never repeats it. Application replay safety does not rely only
on the TLS ticket cache or assume that GET proxy endpoints are side-effect free.

An attacker can still replay a permitted anonymous static read; admission/rate
and resource limits apply, and such reads must be safe to repeat. The Lean result
is this application-level gate, not a proof of TLS/QUIC cryptography, distributed
anti-replay or Quinn's path-validation implementation.

`quic_path_changes_total`, `early_static_total` and `early_rejected_total` expose
fixed-cardinality counters. A path-change counter is not an audit trail of IPs.

## HTTP compression

`encode "gzip"`, `"zstd"`, or `"gzip,zstd"` is opt-in per site. Negotiation checks
bounded Accept-Encoding/q values, exclusions and identity refusal. Only successful
GET/HEAD text/JS/JSON/XML/SVG/Wasm representations of 1 KiB–4 MiB are considered.
Cookie/Authorization/query, Set-Cookie/private responses, Range, existing encoding,
and request/response no-transform exclude compression. SSE, mutations and large
files stay uncompressed. Request/upstream decompression is not implemented.

Compression has a 16 MiB logical workspace reservation, fixed low effort, and an
output cap no larger than the original. It is used only when saving over 32 bytes.
Content-Length and Vary are updated; transformed strong ETags become weak;
representation digests and Accept-Ranges are removed. HEAD uses the matching
static representation length; Range serves identity bytes. Logical reservations
do not prove allocator/RSS, native codec memory or OS buffer bounds. Sensitive
content without any of these signals must not opt into compression.

## Verification and dependency boundary

The extracted Rust gates cover reuse/draining/credit, task and multiplex limits,
encoding exclusions, early-read authorization and raw wire arithmetic. The project
now audits **382 named Lean statements and helper lemmas**, with no new axioms or proof holes. The
zero-dependency core remains zero-dependency. Parser adapters, asynchronous
scheduling, TLS/QUIC/HPACK/QPACK/codecs, RAII, allocator and Linux remain reviewed
and tested trusted code, not a proved server.

Real socket tests exercise 24 simultaneous blocked upstreams, 100 framed HTTP/1
exchanges with policy reload, TLS HTTP/2 compression and incremental SSE, QUIC
migration with original-peer forwarding, and actual TLS resumption. The early-data
test withholds client Finished/1-RTT packets, duplicates captured 0-RTT datagrams,
checks 425/no upstream side effect and one confirmed retry. Linux also tests an
early static response and revocation on that reused connection. Packet duplication
is not an exhaustive cross-connection replay attack test. Linux confinement,
load/fairness/capacity/delivery, local-CA renewal and overlap soak remain CI gates.

The reviewed server graph contains **156 external package versions**, plus three
local packages (core, config and the existing attributed rustls-acme fork), up
from 104 external versions. The increase is 52 all-target versions, including
platform/build dependencies, not 52 new application APIs. Direct additions:

| Purpose | Pinned packages |
| --- | --- |
| HTTP/2/types/buffers | h2 0.4.20, http 1.5.0, bytes 1.12.1 |
| HTTP/3/QUIC | h3 0.0.8, h3-quinn 0.0.10, quinn 0.11.12 |
| QUIC executor/I/O traits | tokio 1.54.1, rt/net/time/io-util only |
| gzip/zstd | flate2 1.1.10 (miniz_oxide), zstd 0.14.3 |

No Axum/Hyper/Tower layer was added. Async-io/futures-lite already existed. Quinn
uses the existing ring provider; no second crypto engine, platform verifier,
qlog, QUIC datagrams or Tokio multithread runtime. zstd defaults are disabled:
no dictionaries/legacy/multithread/bindgen; zstd-sys compiles bundled Zstandard
1.5.7 C through the existing build toolchain. This is an added native-code trust
boundary. Do not set `ZSTD_SYS_USE_PKG_CONFIG` in the reviewed build environment.
flate2 uses the Rust miniz_oxide backend. Production only encodes; test decoders
are not network request paths.

Focused source review covered header buffering before decoded-size enforcement,
connection/stream credit retention, shutdown and failed handshakes, stream resets,
SSE incremental output, compression size/validator transitions, QUIC paths and
Rustls stateful ticket consumption. Raw H3 receive guards were added because the
library's decoded field limit alone did not bound pre-decode frame accumulation.
Quinn's server confirmation adapter also checks completion plus absence of a
close reason: the selected protocol version's `accepted_0rtt` flag is client-only
and is false on successful server handshakes despite the wrapper's documentation.
The real resumption test covers this integration detail.

The fresh [machine-readable RustSec scan](modern-http-audit.json) records the
exact manifests, lockfiles, reviewed graph and database revision. All profiles
passed without ignored advisories, known vulnerabilities or informational/yanked
warnings. This and the focused review are not a full line-by-line dependency
audit or a guarantee against undiscovered vulnerabilities.

Sources: [h2](https://docs.rs/h2/0.4.20/h2/),
[h3 experimental status](https://docs.rs/crate/h3/0.0.8),
[Quinn Connecting](https://docs.rs/quinn/0.11.12/quinn/struct.Connecting.html),
[HTTP early-data rules](https://www.rfc-editor.org/rfc/rfc8470.html),
[flate2](https://docs.rs/flate2/1.1.10/flate2/),
[zstd](https://docs.rs/zstd/0.14.3/zstd/).

Public-CA/public-network verification, an interactive 24-browser rehearsal of
these new protocols and actual network-switch tests on production-like mobile
paths are separate deployment gates. Local loopback results do not establish
those outcomes. Do not switch production solely because unit tests are green.

The local `soak_server` can enable `PATHWARD_TEST_H2_DIAGNOSTICS=1` to distinguish
pending-reset and internal-reset limits. Its subscriber accepts only two h2 WARN
targets, emits at most 16 fixed-category records, and discards all formatted
messages. It does not subscribe to request/header/frame or span fields. The
`tracing-core` development dependency was already present with identical features
in the reviewed graph; no package or production dependency was added.

The reload regression also exercises two separate 32-stream cancellation waves
while all 64 global pending slots are held. Previously cancelled requests waited
for admission and blocked later reloads until h2's pending-reset limit closed the
connection. Waits now poll cancellation first and drop their leases when it wins.
A connection can hold one unadmitted head within its existing 32-stream window,
so cancelled heads can drain without global queue credit. It allocates no request
body or response/service lease at this stage. The original head-accept time is
retained across the wait. A single TLS record with 64 cancelled requests is now
a regression case; 101 unconsumed reset pairs still trigger the finite limit.
The two-wave regression now separates cancellation windows by only 5 ms.
The old one-head-per-2-ms loop reproducibly exceeded that reset queue; the
adapter now consumes at most 32 ready steps before yielding, and checks
cancellation before the connection retirement/refusal gate. It polls existing
tasks between heads. The later real-browser test still reached the 32-reset
queue under coalesced windows, so the separately bounded queue is now 100 as
reviewed above. No request data is logged; fixed events distinguish the connection
window gate from a held-head deadline.

`CancellationProofs` checks the extracted held-head decision and the 32-slot
invariant over a finite transition model. It does not prove the async adapter,
Atomic accounting or Drop execution. The complete theorem/axiom inventory and
remaining proof goals are tracked in `proofs/registry.json` and
`proofs/roadmap.json`, with freshness checked by `make proof-check`.

## Retirement and empty preconnections (2026-11-04)

The native HTTP/2 regression starts a valid slow upstream request, retires the
connection using more than 68 requests, then delays the upstream reply a further
6.5 seconds. The old adapter truncated it. The new adapter completes its status
and exact body, and preserves the existing overload/cancellation bounds. This
also covers the final queued DATA frame, not merely the task's return value.
The shared HTTP/2/3 close decision is extracted and proved in CancellationProofs.
Protocol libraries, fair polling and the physical delivery remain trusted.

A TLS connection that sends no HTTP/2 plaintext before EOF or the five-second
preface deadline is counted in `h2_idle_preface_eof_total` or
`h2_idle_preface_timeout_total`. No HTTP request existed to count as failed.
The adapter records only a boolean indicating whether a plaintext byte arrived.
A partial preface still fails; other I/O/protocol errors are unchanged. Actual
TLS tests cover empty EOF, empty timeout and one-byte truncated preface.
No request URL, header or body is added to logging; no dependency is added.

A proxy with a multi-megabyte input cap no longer reserves that cap for an HTTP/2
request whose END_STREAM flag already proves the input is empty. Missing
Content-Length or GET alone does not establish emptiness. The 24-way real TLS
regression uses a 3 MiB cap and waits for every upstream request before replying.
Nonempty and unknown-length inputs retain their existing byte-credit checks.

## Framed response storage and HEAD compatibility (2026-11-04)

A high configured response limit must not reserve that maximum for every tiny
asset. Before connecting, the adapter reserves the actual framed request length
and bounded metadata. After validating the response headers, it reserves twice
the declared body length plus 256 KiB, before body allocation. Unknown-length
responses still reserve twice the configured limit. A fixed five-second wait
cannot exceed the existing total response deadline. Cancellation drops the wait
and its request/service leases. No upstream request is retried: exhaustion or
failure after an upstream mutation may still fail its response, as with an I/O
failure; it does not roll back the mutation. Maximum body size and global/peer
credit caps are unchanged. The extracted storage gate proves both-copy coverage,
a 64 MiB body bound and safe 64-bit accounting. Allocator/runtime refinement is
still a trusted boundary. The real TLS regression admits 24 upstream requests
before any replies, with a 3 MiB input and 32 MiB output limit.

HEAD always chooses an empty downstream body. Some upstreams send a body even
for HEAD errors. The one-exchange upstream socket is dropped, including any
prefetched bytes; it is never reused or interpreted as a second response. The
native regression includes a fake second response in that prefix and verifies
that none reaches the client. Non-HEAD 204/304 responses with prefetched bytes
remain errors; ambiguous lengths and other framing checks are unchanged.
ProxyProofs checks the actual extracted body-mode selector.

## Unadmitted cancellation accounting (2026-11-04)

A pending head already cancelled before dispatch consumes no successful-admission
credit. Counting those discarded heads toward 100 caused normal reloads to
prematurely refuse later asset requests. The admission count now advances only
when the head obtains the bounded pending lease and is dispatched. Its existing
100-request/120-second cap and 68-request retirement threshold remain. Requests
cancelled after dispatch still consume admission credit.

Discarded unadmitted heads have an independent finite lifetime allowance: at most
256, only while connection age is below 120 seconds. Exceeding it closes the
connection with a fixed diagnostic event. The 100-entry unconsumed-reset queue
and all active/global/body limits remain. The extracted `cancel_slot` gate proves
the discard and age bounds plus safe counter increment. It does not prove every
executor transition. A real TLS regression completes 48 requests, fills all 64
global pending slots, cancels two windows of 32 and then serves a new request.
The prior counter implementation fails this regression; the corrected one passes.

## Connection retirement telemetry (2026-11-04)

A late stream at the connection's 100-request/120-second/stop boundary receives
HTTP/2 REFUSED_STREAM before the responder is dispatched. This is distinct from
global/peer admission exhaustion and can be retried by a conforming client on a
new connection. It now increments `h2_retired_streams_total` and emits the fixed
`h2_retired_stream` event, instead of mislabeling it `global_active`. Genuine
queue expiry and common admission failures retain their existing failure counters.
No limit or reset behavior is relaxed by this telemetry correction.

The extracted gate proves that, with a free live-stream slot, a refusal means a
count/age/stop boundary. A native TLS client deliberately ignores retirement and
sends 101 POSTs: exactly 100 reach the upstream, and request 101 receives
REFUSED_STREAM without a side effect. Browser acceptance requires no failed
mutation/transport or inconsistent state, no real capacity refusal/5xx/log loss,
and separately reports these protocol retirements and peer cancellations. A
zero-retirement-refusal result is not required; no harness mutation is retried.

## Idle retirement grace (2026-11-04)

A real TLS regression exposed an idle-close ordering error: after five quiet
seconds the adapter began graceful retirement and immediately applied those
same five seconds to the close gate. It could drop the socket before polling h2
to transmit GOAWAY. The regression fails on the prior implementation with EOF
before any GOAWAY, and passes after the correction.

The extracted close gate now takes both quiet time and time since retirement
began. Normal forced closure requires both to be at least five seconds and no
active task or held head. Explicit server shutdown keeps its independent five
second deadline; per-request budgets and the connection backstop are unchanged.
`CancellationProofs.retirement_grace_starts_at_retirement` proves that earlier
idle time cannot satisfy that grace period. This predicate proof does not prove
socket scheduling, delivery of GOAWAY, or arbitrary client retry behavior.

TLS failure diagnostics now retain only fixed phase/reason labels, received-byte
counts and elapsed time. Peer-supplied errors, URLs, SNI, headers and keys are
never formatted. The browser acceptance trial is still required after this fix.
