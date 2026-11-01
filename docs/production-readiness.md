# Production readiness

PathWard now has a verified policy core, KDL configuration compiler, and a minimal
Linux HTTP/1.1 static server with TLS/ACME, private key persistence and automatic
renewal, atomic config reload, graceful shutdown and operational telemetry. HTTP file serving stays loopback-only; explicit TLS mode can bind public TLS
and optional redirect-only plaintext listeners. It is not yet a complete Caddy replacement.

## Implemented

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
The current axiom audit covers 124 statements. The dispatcher prevents a single peer from
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
   Tune the fixed connection/rate limits and add bandwidth fairness where needed. Keep-alive, HTTP/2, proxy
   integration and forwarded headers require separate protocol review; none is
   enabled in the minimal server. IPv6 transport is supported for loopback binding,
   but configured authorities remain DNS-style names rather than IPv6 literals.
5. **HTTP functionality.** Add reviewed ranges,
   conditional caching/ETags, suitable cache policies and broader URL support for any legacy redirects.
   Current responses use no-store, fixed content types and no compression. A
   Range header does not activate partial serving, and conditional fields do not
   activate cache validators.

The [TLS integration audit](tls-audit.md) records how the actual implementation
addresses the historical candidate findings without using its high-level runtime.
The [HTTP/file audit](http-audit.md) remains relevant to confinement. A clean
advisory scan does not replace integration review.

## Deliberate limitations

No reverse proxying, upstream health checks, WebSockets, authentication, wildcard
domains, environment expansion, includes, directory grants or implicit indexes.
The KDL profile supports ordinary quoted values and line comments, with 64 KiB,
16 sites and 256 exact mappings per site. Paths remain ASCII and reject percent
encoding, hidden components and trailing slashes other than `/`. Files are limited
to 64 MiB. Larger sites, Unicode filenames, directory URLs and broader KDL syntax
need explicit policy/resource extensions.

The [isolated migration rehearsal](staging-rehearsal.md) now exercises real Linux
filesystem storage, resource-limited supervision, actual static content/security
headers and Caddy rollback. Shared proxy replacement remains blocked. The next
milestone is deployment-specific public DNS/443 and CA validation with a dedicated
service UID, external collectors/alerts and an explicitly reviewed route scope.
