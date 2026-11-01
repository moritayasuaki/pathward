# Bounded local reverse proxy

PathWard can delegate an entire configured hostname to one explicitly selected
local HTTP application. This is the first proxy milestone, not a claim of Caddy
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
- `reverse-proxy` is mutually exclusive with `root`, `publish`, `redirect` and
  `redirect-prefix` in that site. Other sites may remain static. An upstream 404
  or failure never falls back to a file. The automatic plaintext-to-HTTPS redirect
  remains available for proxy sites and uses the fixed configured hostname.
- This delegates **every admitted URL and method** on that hostname to the app,
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
  from the validated configured name. Incoming `Forwarded`, all `X-Forwarded-*`,
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
| Request framing | One canonical Content-Length; at most 1 MiB |
| Request body deadline | 5 seconds from acceptance, including queue/TLS/head |
| Upstream connect | At most 2 seconds, within total exchange budget |
| Total exchange | 15 seconds from acceptance through downstream writes |
| Upstream protocol | HTTP/1.0 or HTTP/1.1, final 200–599 response |
| Response framing | One Content-Length, finite chunked, or connection-close |
| Response body | At most 8 MiB, including cumulative decoded chunks |
| Headers | 16 KiB / 32 fields each direction; individual values ≤4096 bytes |
| Header values | Printable ASCII; duplicate names rejected except response Set-Cookie |
| Concurrency | Existing four workers, bounded queue and per-peer admission gates |

Request Transfer-Encoding, Expect, Upgrade and Trailer are rejected. There are no
WebSockets, SSE/streaming responses, informational responses, chunk extensions or
trailers. OPTIONS with Max-Forwards zero is answered locally; positive values
are decremented. HEAD/204/304 never forward a body. A 205 with a body is rejected.
Metadata Content-Length on HEAD/304 is also subject to the 8 MiB bound.

The full request is buffered before connecting, and the full upstream response
is validated before downstream success headers are emitted. Invalid/truncated or
oversized upstream messages receive generic 502; upstream timeout receives 504.
No request is automatically retried, including after a POST may have reached the
application. A lost response therefore does not imply a failed application write.
Late surplus bytes cannot become another exchange because sockets are not reused.
A slow downstream can still interrupt delivery after validation.

Buffered data is bounded per worker, but this is not streaming and large or slow
applications can occupy the shared workers. Backend-aware admission, streaming
backpressure and real application load tests are still required before migration.

## Reload and publication generation

A request captures one immutable configuration snapshot before reading its head.
Its upstream and response-header rules stay in that generation through completion,
including when a reload commits concurrently. New requests use the new snapshot.
Existing generation, expected-digest, persistence-before-activation and draining
checks also apply to proxy configurations. As with static requests, reload does
not revoke an already captured request. Drain before revoking active access.

`generate` preserves other proxy sites when updating a static manifest and refuses
a proxy site as its publication target. An administrator can explicitly switch a
site between static and proxy modes through a complete configuration reload. The
compiler rejects mixed modes before any snapshot is installed. No automatic
upstream health/parity validation is added to managed activation.

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
the total to 153. Charon/Aeneas extracts the actual dependency-free Rust predicates:
exclusive site modes, exact loopback endpoint/port admission, method/status ranges,
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
2. Add a separately reviewed streaming/WebSocket design with cancellation, bounded
   buffering, graceful drain and appropriate per-service limits. Do not route an
   application that requires these through the current implementation.
3. Add application-aware readiness/failure telemetry and backend load testing;
   define routing precedence before allowing static files and proxy routes within
   the same hostname. HTTP/2/keep-alive and remote HTTPS upstreams need their own
   transport/trust review.

Deployment-specific public DNS/443/CA validation, service ownership and external
alerts remain required as recorded in [production readiness](production-readiness.md).
