# Bounded local reverse proxy

Current transport/concurrency additions are described in [Modern HTTP](modern-http.md).
The dated results and earlier limits below describe their recorded revisions.

PathWard can delegate an entire configured hostname to one explicitly selected
local HTTP application. It can also coexist with explicit local and denied routes
using [mixed routing and per-service limits](routing-and-limits.md). This is not a claim of Caddy
feature parity. Existing static sites still require exact publication grants.

```kdl
site "app.example" {
    tls "auto"
    reverse-proxy "127.0.0.1:3000"
    header "*" "x-frame-options" "DENY"
    header "*" "strict-transport-security" "max-age=86400"
}
```

Use the ordinary `serve-http` loopback command for evaluation, or `serve-tls` with
its private ACME cache and explicit CA terms acceptance for TLS. For example,
with your application already listening on 127.0.0.1:3000:

```sh
server/target/release/pathward-server serve-http examples/Proxy.kdl 127.0.0.1:8080
curl -H 'Host: app.example' http://127.0.0.1:8080/api/
```

`check` validates the configuration; it does **not** probe the upstream. Server
readiness measures the frontend/configuration/certificate, not application health.
Probe a representative application URL separately before switching traffic.

## Delegation and trust

- Only canonical `127.0.0.1:PORT` and `[::1]:PORT` are accepted, with nonzero ports.
  No DNS, URLs, remote/private-network addresses, credentials, redirects followed,
  retries, connection pooling, CONNECT tunnels or socket paths are used.
- Mixed sites select denials before local publications/redirects, then the proxy.
  `proxy-path` optionally restricts its subtrees. Selected local failures never
  fall back to the proxy; upstream failures never fall back to files. The automatic
  plaintext-to-HTTPS redirect uses the fixed configured hostname.
- In a whole-host site with no local/deny/scope declarations, this delegates
  **every admitted URL and method** on that hostname to the app,
  including encoded, hidden or dot-component paths. The raw origin-form target
  and body bytes are preserved. The application owns authentication, authorization,
  normalization and routing. PathWard's static-file allowlist is not an application
  authorization policy. Only delegate a service intended for public exposure;
  loopback restriction does not make an administrative service safe to publish.
- Targets must start with one slash, contain at most 8192 printable ASCII bytes,
  and contain no raw fragment marker, backslash, whitespace or controls. Percent
  escapes are preserved without decoding or validating their meaning. Scoped
  response-header matching is exact on the raw path before `?`; use `header "*"`
  for protections that must cover every spelling accepted by the application.
- Host selection and TLS SNI/Host agreement precede forwarding. Host is rebuilt
  from the validated configured name. An explicit nondefault port is preserved
  in both Host and X-Forwarded-Host, including anonymous resource probes. It must
  match the trusted frontend port; omitted and scheme-default ports have no suffix.
  This lets applications validate an origin such as `http://app.example:8080`.
  The extracted Rust policy and six Lean statements prove that a nonzero suffix
  can only be the validated explicit frontend port, and prove omission, mismatch
  rejection, default-port normalization and totality. String formatting remains
  a tested adapter. Incoming `Forwarded`, all `X-Forwarded-*`,
  `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL` and `Proxy` are removed. PathWard
  generates X-Forwarded-Host/Proto/Port from the validated frontend authority and
  transport, and X-Forwarded-For from the actual socket peer. There is no trusted
  proxy-chain setting. Configure the app to trust only these regenerated fields
  from this service; other application-defined identity headers are not trusted
  or interpreted by PathWard.
- End-to-end Authorization, Cookie, Origin and application headers are preserved.
  Hop-by-hop fields are stripped. Requests with Connection tokens other than
  `close`/`keep-alive` are rejected; response Connection-nominated fields are
  removed. Via is appended in both directions; a request naming `pathward` in
  its Via chain receives 508. Nested PathWard proxy chains are not supported.
- Configured security response headers override matching upstream values.
  `nosniff` is forced, Server/Alt-Svc are stripped, and HSTS is never emitted on
  plaintext. Separate Set-Cookie fields are preserved. Application response
  status, redirects, content type, validators and cache policy otherwise belong
  to the application; PathWard does not rewrite cookies/Location or cache content.

## Protocol and resource limits

| Resource / behavior | Current limit |
| --- | --- |
| Client protocol | HTTP/1.1, one exchange per connection |
| Methods | GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS |
| Request framing | One canonical Content-Length; default 1 MiB, configurable up to 16 MiB |
| Request body deadline | Default 5 seconds including HTTP head reception; excludes TLS/ready queue |
| Upstream connect | Default 2 seconds, within total exchange budget |
| Successful exchange | Default 15 seconds including HTTP head reception through downstream writes; excludes TLS/ready queue |
| Error response | At most 1 additional second to report failure |
| Upstream protocol | HTTP/1.0 or HTTP/1.1, final 200–599 response |
| Response framing | One Content-Length, finite chunked, or connection-close |
| Response body | Default 8 MiB, configurable up to 64 MiB, including decoded chunks |
| Parsed client/upstream heads | 16 KiB / 32 fields each; individual values ≤4096 bytes |
| Parsed header values | Printable ASCII; duplicate names rejected except response Set-Cookie |
| Concurrency | Default 2 active proxy exchanges per host; existing global/per-peer gates |

Request Transfer-Encoding, Expect and Trailer are rejected. Upgrade is accepted
only through the opt-in [WebSocket handshake](streaming.md). Other informational
responses, chunk extensions and trailers remain unsupported. OPTIONS with Max-Forwards zero is answered locally; positive values
are decremented. HEAD/204/304 never forward a body. A 205 with a body is rejected.
Metadata Content-Length on HEAD/304 also follows the configured response bound.
The [limits guide](routing-and-limits.md) specifies the allowed budgets and units.

For ordinary HTTP, the full request is buffered before connecting and the full
upstream response is validated before downstream success headers are emitted.
Opt-in WebSocket/SSE validates the head before committing, then relays with bounded
buffers; a later error closes the connection as described in the streaming guide. Invalid/truncated or
oversized upstream messages receive generic 502; upstream timeout receives 504.
Standard surrounding header whitespace is trimmed by the parser. Regenerated
forwarding/Via fields and configured response headers can make outgoing heads
larger than the input-head limit; both additions remain bounded by input/config
limits. No request is automatically retried, including after a POST may have reached the
application. A lost response therefore does not imply a failed application write.
Late surplus bytes cannot become another exchange because sockets are not reused.
A slow downstream can still interrupt delivery after validation.

Buffered HTTP data uses the shared [delivery reservation budget](delivery.md),
with a separate bound on request data per worker. WebSocket/SSE adds finite streaming
budgets, backpressure, cancellation and a 16-stream global quota. Slow ordinary
applications can still occupy the shared workers. Backend-aware admission and
real application load tests remain required before migration.

## Reload and publication generation

A request captures one immutable configuration snapshot before reading its head.
Its upstream and response-header rules stay in that generation through completion,
including when a reload commits concurrently. New requests use the new snapshot.
Existing generation, expected-digest, persistence-before-activation and draining
checks also apply to proxy configurations. As with static requests, reload does
not revoke an already captured request. Drain before revoking active access.

`generate` preserves proxy policies/budgets when updating a static manifest,
including a mixed site with a root. It refuses rootless publication targets.
Connection accounting persists across reload and rollback; the captured and live
caps both apply to admission. No automatic upstream health/parity validation is
added to managed activation.

## Source, dependency and proof audit

No runtime, development or build dependencies were added. Manifests, lockfiles,
features and vendored dependency sources match the preceding release: the core
has zero external packages, configuration has eight, and the server has 104.
The fresh RustSec scan and graph comparison have no findings or warnings; the
record is [server/audit-result.json](../server/audit-result.json). This is an
advisory scan plus integration source review, not proof of dependency correctness.

The review covered the only upstream connect boundary, raw request serialization,
body framing/size arithmetic, absolute deadlines (including interrupted reads),
status bounds used by telemetry, hop/forwarded fields, duplicate Set-Cookie,
plaintext HSTS suppression, literal-host redirects and generation capture.
Framing and intermediary handling were checked against
[RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3) and
[RFC 9110 §7.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6).
The intentionally smaller interoperability profile is listed above.

[ProxyProofs.lean](../proofs/ProxyProofs.lean) adds 29 audited statements, bringing
the original proxy milestone total to 153; the mixed-routing extension raises it to 185 and streaming to 221. Charon/Aeneas extracts the actual dependency-free Rust predicates:
site-mode/root requirements, exact loopback endpoint/port admission, method/status ranges,
request/response framing gates, bounded target grammar, hop/forwarding exclusions,
header-value control exclusion and plaintext HSTS suppression. Totality covers
these public predicates, including indexing bounds. Existing generation-switch
proofs are unchanged and continue to apply to the shared commit gates.

KDL parsing and the SocketAddr round trip, httparse, std/TCP/TLS, byte copying,
chunk decoding, timeout syscalls, response serialization and Arc/RwLock snapshot
handling remain audited/tested trusted code. There is no end-to-end formal theorem
about HTTP exchanges, application security or the operating system. CI compares
regenerated extraction and rejects proof escapes or nonstandard axioms.

TCP/TLS regression tests exercise body preservation, trusted forwarding, response
framing errors before commitment, cookies, HTTP→HTTPS redirects, Host checks,
absolute slow-response deadlines and concurrent upstream/header reload. Linux
also exercises static→proxy→static switching without filesystem fallback. The
ordinary Linux file, managed deployment, TLS/ACME and soak suites remain required.

## Next priorities

1. Inventory the real applications' routes, auth, upload sizes, cookies, redirects,
   SSE and WebSocket requirements; rehearse against those applications in isolation.
2. Rehearse the implemented opt-in WebSocket/SSE paths, finite budgets, stop/reconnect
   behavior and the 16-stream quota against real applications. Restricted compression
   and explicit Origin allowlists are implemented; general streaming remains separate.
3. Add application-aware readiness/failure telemetry and backend load testing.
   Mixed routing and per-service limits are implemented in the linked guide.
   HTTP/2/keep-alive and remote HTTPS upstreams need their own
   transport/trust review.

Deployment-specific public DNS/443/CA validation, service ownership and external
alerts remain required as recorded in [production readiness](production-readiness.md).
