# Production readiness

PathWard currently provides a path authorization core, a KDL configuration
compiler, and a check/resolve CLI. It has no HTTP listener, file-serving adapter,
TLS stack integration, certificate issuance, or reload loop. It cannot replace
Caddy in production yet. These are concrete implementation gaps, including
security boundaries that the current Lean proofs do not cover.

## Required before serving real traffic

1. **HTTP dispatch tied to the original request.** Validate request-target syntax,
   methods (initially GET/HEAD), Host/authority and SNI consistency. Select only a
   configured host. Pass the original undecoded path to the verified lookup before
   nesting, rewriting, fallback, percent decoding or implicit indexes. Define
   query handling and ensure every serving route enforces authorization. Unknown
   hosts and denied paths must terminate dispatch. Bound HTTP/1 parser resources
   and explicitly decide whether to enable HTTP/2, whose code is present in the
   reviewed candidate graph.
2. **Filesystem confinement and correct responses.** Open only the declared file
   under its site's root, using a reviewed descriptor-relative strategy on the
   chosen OS, or a separately justified immutable resource map. Address symlinks,
   lookup races, hard links, mounts, aliases, regular-file checks, permissions and
   combined path limits. A canonicalize/check/open sequence is insufficient.
   Add race/integration tests. Define content types, safe response headers, HEAD,
   errors, ranges and conditional requests without alternate unverified paths.
3. **TLS/ACME that actually runs.** `tls "auto"` currently records intent only.
   Implement account/certificate persistence, renewal polling, restart behavior,
   staging tests, expiry alerts and configured-domain-only issuance. Store keys
   outside the public tree with private permissions and crash-safe writes. Review
   ACME response-size/deadline limits and trusted HTTPS endpoints. The current
   path grammar rejects `/.well-known`; HTTP-01 needs a narrowly scoped dedicated
   challenge handler, or choose a reviewed TLS-ALPN-01 strategy.
4. **Resource and time budgets.** Bound open connections, concurrent TLS handshakes,
   header/body sizes, total handshake/body/response times, per-client work and
   file-transfer resources. A request middleware timeout does not cover TLS, and
   an idle timeout does not bound a slowly progressing peer. Load-test slow clients
   and exhaustion behavior with the actual adapter and deployment stack size.
5. **Operations and deploy safety.** Add atomic configuration replacement with
   last-known-good behavior on invalid reload; keep config/roots/key material under
   explicit ownership and permission rules. Implement graceful draining/shutdown,
   structured access/error logs without secrets, health checks, metrics and renewal
   failure alerts. Validate startup files and recovery from failed deployments.
   Pin/review a current production Rust toolchain separately from the extraction
   nightly, and maintain automated dependency/security updates.

The [server dependency audit](dependency-audit.md) has the source-level evidence
and unresolved findings for these adapters. A zero-finding advisory scan does
not close them. The [KDL audit](kdl-audit.md) separately describes the configuration
parser and proof boundaries.

## Compatibility/features to decide before replacing Caddy

- Existing redirects and legacy project/document URL behavior are not implemented.
  Migration must preserve them explicitly; no hamazon.is hosting files are changed
  by this project.
- Reverse proxying, upstream health checks, WebSockets, streaming, authentication,
  compression and cache policies are not implemented.
- No wildcard domains, environment expansion, includes, directory publishing or
  implicit index files. These omissions keep grants explicit; add only if needed
  with a reviewed policy and tests.
- Current paths are ASCII and reject percent encoding, hidden components and
  trailing slashes other than `/`. Unicode filenames, directory URLs, and larger
  sites need a deliberate policy extension. Limits are 64 KiB of configuration,
  16 sites and 256 exact mappings per site.
- The KDL profile supports ordinary quoted values and line comments only; full KDL
  syntax would require a different resource strategy or parser hardening.

The next practical milestone is a minimal static-file server on one declared
platform, with the first four boundaries enforced and tested, followed by reload
and operational tooling. Adding all optional Caddy features is a separate scope.
