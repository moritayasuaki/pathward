# Production readiness

PathWard now has a verified policy core, KDL configuration compiler, and a minimal
Linux HTTP/1.1 static server with TLS/ACME, private key persistence and automatic
renewal. Plain HTTP stays loopback-only; explicit TLS mode can bind a public
interface. It is not yet a complete Caddy replacement.

## Implemented

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

## Still required before public production serving

1. **Deployment-specific certificate operation.** Test staging with the real DNS,
   TCP/443 path, service UID, clock and durable storage. Monitor redacted renewal/
   expiry events externally. ARI, Retry-After handling, in-order badNonce retries,
   revocation/OCSP, contact updates and key rollover are absent. One certificate
   covers all configured sites; separate per-site issuance is not implemented.
   HTTP-01/DNS-01, wildcard domains and automatic HTTP redirects are absent.
2. **Deployment and content ownership.** Enforce a service-owned configuration,
   roots and key store, with least privilege. Use trusted local filesystems and
   immutable releases; the current opener does not make concurrent file writes
   immutable or prove inode-content provenance. Root identity is pinned until
   restart. Configure process/supervisor resource budgets, especially for blocking
   filesystem I/O that socket deadlines cannot interrupt. Review the chosen
   deployment filesystem and kernel/seccomp/procfs setup.
3. **Operations.** Add atomic config reload with last-known-good behavior,
   signal-driven graceful draining, structured logs, health/metrics and useful
   renewal/file-error alerts without exposing secrets. The library has a shutdown
   flag; the CLI currently exits directly on ordinary process signals. Missing
   files are denied per request rather than exhaustively opened at startup.
4. **Load and protocol hardening.** Perform broader coverage-guided fuzzing,
   prolonged race/stress testing and realistic throughput/slow-storage testing.
   Add per-client/rate/bandwidth fairness where needed. Keep-alive, HTTP/2, proxy
   integration and forwarded headers require separate protocol review; none is
   enabled in the minimal server. IPv6 transport is supported for loopback binding,
   but configured authorities remain DNS-style names rather than IPv6 literals.
5. **HTTP functionality.** Add reviewed ranges,
   conditional caching/ETags, suitable cache policies and any required redirects.
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

The next deployment milestone is one reviewed Linux staging deployment, followed
by reload, signal draining and operational monitoring.
