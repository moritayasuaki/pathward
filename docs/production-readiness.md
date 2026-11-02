# Production readiness

PathWard now has a verified policy core, KDL configuration compiler, and a minimal
Linux HTTP/1.1 static server with TLS/ACME, private key persistence and automatic
renewal, atomic config reload, graceful shutdown and operational telemetry. HTTP file serving stays loopback-only; explicit TLS mode can bind public TLS
and optional redirect-only plaintext listeners. It is not yet a complete Caddy replacement.

## Implemented

- Mixed denial/local/redirect/proxy routing with explicit scopes, final local
  failures, per-host time/body/concurrency budgets and cross-generation admission.
  [Routing, limits and audit](routing-and-limits.md).

- Explicit whole-host reverse proxy to a numeric loopback HTTP application, with
  bounded body buffering, strict framing, regenerated forwarding fields, TLS/Host
  checks and atomic upstream/header reload. No added dependencies; 29 new extracted
  Lean statements. [Guide, source audit and limits](reverse-proxy.md).

- P0.1: automatic HTTP→HTTPS and configured exact/component-prefix 301/308
  redirects to configured hosts, with validated query preservation.
- P0.2: allowlisted scoped response headers, including CSP/HSTS; framing/control
  injection rejected and HSTS suppressed on plaintext.
- P0.3: explicit-manifest generation, serving-opener file preflight, private Unix
  control socket, expected generation/digest activation, durable restore/stop on
  failure and checked rollback. No recursive publication or automatic release GC.
- P0.4: shared global/per-peer concurrency/rate gates, bounded peer table,
  deterministic 100,000-input HTTP mutation corpus and bounded Linux load tests.
  [Guide](production-basics.md), [risk assessment](deployment-risk.md),
  [integration and extracted-proof audit](production-basics-audit.md).

- Transactional publication/root reload, failure retention and fixed identity;
  SIGTERM/SIGINT draining, bounded redacted JSON logging, loopback-only health,
  readiness and Prometheus metrics. [Operation and limits](runtime.md).
- Extracted generation-switch and readiness contracts with failure/stop/overflow
  proofs and native Linux signal/concurrency regression tests.

- TLS 1.2/1.3 with configured SNI and Host agreement, isolated TLS-ALPN-01,
  private 0700/0600 account/certificate storage, atomic durable writes, fixed-origin
  bounded ACME requests, automatic renewal, expiry refusal and restart reuse.
- Additional extracted Lean contracts for TLS identity, secret metadata,
  persist-before-activation and renewal arithmetic; local Pebble lifecycle tests.

- GET/HEAD over HTTP/1.1, exact virtual-host and publication selection, unchanged
  path bytes, separately validated/ignored queries, and no fallback/index grants.
- Linux descriptor-based file opening with `openat2` confinement, symlink/mount
  rejection, O_PATH type checks, checked procfs reopening, regular/single-link/
  size policy and stable inode selection. There is no fallback on unsupported OSes.
- Strict request framing, one request per connection, bounded headers, four fixed
  workers, eight queued accepted sockets, total socket deadlines and bounded file
  copying. See the [HTTP guide](http-serving.md) for exact limits and assumptions.
- Additional Lean proofs for the pure request/dispatch/file-metadata decisions.
  The parser, adapters, std and Linux kernel are reviewed/tested trusted code.

The [completed one-hour overlap soak](soak-testing.md) exercised configuration churn,
rollback and real local ACME renewals under slow-peer load, with resource and
content-consistency assertions. The 2026-11-01 review-fix run passed 57,598
ordinary-load requests, 36,010 fresh post-commit probes (including 7,202 revoked-URL
checks), and 80 renewals. Public Host ports are validated independently of internal
forwarding ports, and final RSS growth is asserted before reporting success.
The current axiom audit covers 275 statements. The dispatcher prevents a single peer from
occupying all workers while retaining queued CA validation connections.

## Still required before public production serving

1. **Deployment-specific certificate operation.** Test staging with the real DNS,
   TCP/443 path, service UID, clock and durable storage. Monitor redacted renewal/
   expiry events externally. ARI, Retry-After handling, in-order badNonce retries,
   revocation/OCSP, contact updates and key rollover are absent. One certificate
   covers all configured sites; separate per-site issuance is not implemented.
   HTTP-01/DNS-01 and wildcard domains are absent.
2. **Deployment and content ownership.** Enforce a service-owned configuration,
   roots and key store, with least privilege. Use trusted local filesystems and
   immutable releases; the current opener does not make concurrent file writes
   immutable or prove inode-content provenance. Root identity is pinned until
   successful reload or restart. Configure process/supervisor resource budgets, especially for blocking
   filesystem I/O that socket deadlines cannot interrupt. Review the chosen
   deployment filesystem and kernel/seccomp/procfs setup.
3. **Operations integration.** Connect the implemented JSON logs and loopback
   metrics to a collector, alert manager and service supervisor. Choose expiry,
   overload, reload-failure and missing-file/error thresholds; test alerts and
   forced-stop behavior. Managed startup/activation and server `check` preflight
   files; ordinary SIGHUP validates roots/rules and denies missing files per request.
   Host/ACME identity changes require restart.
4. **Load and protocol hardening.** Perform broader coverage-guided fuzzing,
   prolonged race/stress testing and realistic throughput/slow-storage testing.
   Evaluate the explicit [capacity profiles](nat-capacity.md) and
   [24-browser rehearsal](browser-capacity.md) against same-NAT
   clients, cold assets and reconnect bursts; neither profile establishes an
   application user-count guarantee. Add bandwidth fairness where needed. Keep-alive and HTTP/2 still require separate protocol/resource review.
   Opt-in WebSocket/SSE is implemented with bounded buffers and cancellation;
   realistic application streaming load/reconnect tests remain required. The bounded
   local proxy regenerates forwarding fields and does not trust incoming chains. IPv6 transport is supported for loopback binding,
   but configured authorities remain DNS-style names rather than IPv6 literals.
5. **Deployment-specific HTTP parity.** Single byte ranges, conditional requests,
   weak metadata validators, typed cache policies and explicit directory URLs are
   implemented; see [site compatibility](site-compatibility.md). Check the actual
   manifest, runtime-generated assets and legacy URLs. Multipart ranges, strong
   If-Range validation, implicit indexes, broader encoded/Unicode static paths and
   HTTP compression remain unsupported.

The [TLS integration audit](tls-audit.md) records how the actual implementation
addresses the historical candidate findings without using its high-level runtime.
The [HTTP/file audit](http-audit.md) remains relevant to confinement. A clean
advisory scan does not replace integration review.

## Deliberate limitations

No upstream health checks, general-purpose streaming, arbitrary WebSocket extensions,
context-takeover compression, automatic load balancing,
remote HTTPS upstreams, authentication, wildcard
domains, environment expansion, includes, directory grants or implicit indexes.
The KDL profile supports ordinary quoted values and line comments, with 1 MiB,
16 sites and 4096 exact mappings per site. Explicit directory URLs are supported;
static publication/redirect paths remain ASCII and reject percent encoding and hidden components.
Files are limited to 1 GiB. See [site compatibility](site-compatibility.md) for
single byte ranges, cache policies and explicit resource discovery routes.
Unicode filenames and broader KDL syntax remain unsupported.

The [isolated migration rehearsal](staging-rehearsal.md) now exercises real Linux
filesystem storage, resource-limited supervision, actual static content/security
headers and Caddy rollback. Shared proxy replacement remains blocked until actual application requirements
and the [proxy limitations](reverse-proxy.md) are reconciled and rehearsed. The next
milestone is deployment-specific public DNS/443 and CA validation with a dedicated
service UID, external collectors/alerts and an explicitly reviewed route scope.

The [streaming guide and audit](streaming.md) records the WebSocket/SSE opt-ins,
global 16/per-peer eight stream caps, finite session budgets and trusted implementation boundary.
