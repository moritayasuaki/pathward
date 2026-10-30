# Production readiness

PathWard now has a verified policy core, KDL configuration compiler, and a minimal
Linux HTTP/1.1 static server. The server deliberately listens only on loopback;
TLS/ACME does not run. It is not yet a complete Caddy replacement.

## Implemented in this milestone

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

1. **TLS/ACME and public authority policy.** Implement SNI/Host consistency,
   configured-domain-only issuance, private/crash-safe account and certificate
   persistence, renewal polling, expiry alerts and restart/staging tests. Review
   ACME response-size/deadline limits and trusted HTTPS endpoints. The current
   `tls "auto"` declaration is inactive. The path policy rejects `/.well-known`;
   HTTP-01 needs a dedicated checked handler, or use reviewed TLS-ALPN-01 support.
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
5. **HTTP functionality needed by the actual sites.** Add reviewed ranges,
   conditional caching/ETags, suitable cache policies and any required redirects.
   Current responses use no-store, fixed content types and no compression. A
   Range header does not activate partial serving, and conditional fields do not
   activate cache validators. The existing sites' redirects/bookmarks must be
   preserved explicitly during migration; this project does not modify hamazon.is.

The historical [TLS candidate audit](dependency-audit.md) still has open ACME,
TLS-handshake and HTTP/2 findings. The minimal HTTP/file adapter has its own
[audit](http-audit.md), with a smaller dependency graph. A clean advisory scan
does not replace integration review.

## Deliberate limitations

No reverse proxying, upstream health checks, WebSockets, authentication, wildcard
domains, environment expansion, includes, directory grants or implicit indexes.
The KDL profile supports ordinary quoted values and line comments, with 64 KiB,
16 sites and 256 exact mappings per site. Paths remain ASCII and reject percent
encoding, hidden components and trailing slashes other than `/`. Files are limited
to 64 MiB. Larger sites, Unicode filenames, directory URLs and broader KDL syntax
need explicit policy/resource extensions.

The next deployment milestone is TLS/ACME with private durable key storage,
followed by reload and operational tooling on one reviewed Linux deployment.
