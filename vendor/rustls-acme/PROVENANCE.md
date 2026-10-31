# Narrow low-level rustls-acme fork

Derived from rustls-acme **0.15.4**, upstream commit
`b74626e54e16019a3056a7421caf1ebb68553b2f`, distributed under Apache-2.0 OR MIT.
The original licenses are retained. Only upstream `src/acme.rs` and `src/jose.rs`
are carried forward. This is a maintained local fork, not the unmodified release.

Upstream: https://github.com/FlorianUekermann/rustls-acme/tree/b74626e54e16019a3056a7421caf1ebb68553b2f

The original ACME/JOSE signing and protocol structures are retained. Changes:

- Replace `ClientConfig` arguments with an origin-bound `HttpsClient`.
- Replace the unbounded async-web-client helper with a bounded, verified HTTPS
  transport. Every discovered URL must match the configured origin, responses
  have an 8 KiB header / 64-field / 1 MiB body cap, and each request has a total
  30-second deadline. No redirects, compression, chunk extensions or trailers.
- Remove response-body debug logging. Return RNG and challenge-key errors rather
  than unwrapping. Reject duplicate identity-bearing response headers.
- Supply only ring cryptography. The smaller manifest omits upstream high-level
  caches, acceptors, runtime adapters, renewal state and their dependencies.

PathWard owns the descriptor-based private cache, certificate validation and
persist-before-activation renewal state in its server crate. Neither this fork
nor cryptography/TLS/parsers are formally verified. The root audit inventories
all transitive dependencies and hashes **every file** in this directory. Any
source change requires an explicit reviewed inventory refresh. The isolated
unmodified upstream candidate is also scanned for RustSec advisories by name and
version; local patches are reviewed separately, never treated as advisory fixes
without evidence. The fork adds a maintenance obligation on upgrades.

See ../../docs/tls-audit.md for the source review, limitations and regression tests.

Original shipped file SHA-256 (formatting is adjusted in the fork):

- `src/acme.rs`: `353db1080dfadfb4d59dd2a22ca674b0b45531594ec9fb20e4274a7c9ccd5d74`
- `src/jose.rs`: `8e654ceffda809e3137bbc932f721393927613121249d658a7d9fc94040fe56e`
- `LICENSE-APACHE`: `a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2`
- `LICENSE-MIT`: `23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3`
