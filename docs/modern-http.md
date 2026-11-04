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
also requires appropriate request/response caps: reservations include the request
cap, twice the response cap and 256 KiB; HTTP/2/3 additionally reserve bounded
input translation buffers. Large configured maxima can legitimately cause 503.
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
100 requests and 120 seconds, and shutdown never admits new requests.

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
  the common admission/byte/service gates. GOAWAY/closure bounds request count,
  lifetime and draining. Large files and SSE stream in bounded chunks.
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
restart loses tickets and falls back to a full handshake. Certificate identity,
validity and ALPN are checked on resumed connections as well. The existing
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
now audits **323 named Lean statements**, with no new axioms or proof holes. The
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
