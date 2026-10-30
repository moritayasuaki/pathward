# Server dependency audit — 2026-10-30

## Decision and scope

`std`, `axum`, `tower-http`, `rustls`, and `rustls-acme` are permitted for the
future server, subject to the integration requirements below. **This is a
dependency and focused source review, not approval to expose a server yet.**
There is no server in this revision. The proved `pathward` core still has zero
external dependencies, and its Lean statements do not extend to these libraries.

The isolated [candidate manifest](../audit/server-stack/Cargo.toml), its
[lockfile](../audit/server-stack/Cargo.lock), and its
[reviewed graph](../audit/server-stack/reviewed-graph.json) make the scope concrete.
The graph includes **163 external package versions, 161 distinct names**, across
all target platforms, including build dependencies and procedural macros. This
is not the number of libraries linked into a particular server binary.

| Component | Reviewed version | Explicit features |
| --- | --- | --- |
| `std` / toolchain | Rust 1.98.1 for this build | Built-in; absent from Cargo.lock |
| `axum` | 0.8.9 | `http1`, `tokio`, `original-uri` |
| `tower-http` | 0.7.1 | `fs`, `limit`, `timeout`, `trace` |
| `rustls` | 0.23.46 | `ring`, `std`, `tls12` |
| `rustls-acme` | 0.15.4 | `axum`, `ring`, `tls12`, `webpki-roots` |

All four third-party direct dependencies set `default-features = false` and
have exact version requirements. `fs` is included to review a possible static
file adapter; it is not a decision that `ServeDir` is a confinement boundary.
Compression, decompression, multipart, WebSockets, and Rustls certificate
compression are not enabled. The selected cryptography provider is `ring`
0.17.14, with no `aws-lc-rs`/`aws-lc-sys` in this graph. This avoids building two
providers; it does not establish that ring is safer, and gives up the default
AWS-LC post-quantum preference. Reconsider that tradeoff before deployment.

## Automated findings

`cargo-audit 0.22.2`, installed with `--locked --no-default-features`, checked
the core lockfile and the entire candidate lockfile against RustSec, including
yanked-package checks, with no ignored advisories or platform/severity filters.
**Known vulnerabilities: 0. Informational/yanked warnings: 0.** The historical
[machine-readable result](../audit/server-stack/audit-result.json) records the
database revision, time, tool version, and manifest/lockfile SHA-256 hashes.
The initial RustSec database contained 1,395 advisories at commit
`2295466c4e9df26647fd67d8fa1c705ac2fc7f81`.

This result is dated, not a guarantee about undiscovered vulnerabilities or
future advisory updates. A fresh `make dependency-audit` fetches the official
database, refuses warnings, and refuses a changed graph until it is reviewed.
The graph records resolved features, license declarations, build scripts, and
procedural macros. A declaration inventory is not a line-by-line source audit or
a legal review of every distributed file.

Recent certificate-verification advisories were checked explicitly:

- `rustls-webpki` resolves to **0.103.16**, containing the fix for
  [RUSTSEC-2026-0382](https://rustsec.org/advisories/RUSTSEC-2026-0382).
- `webpki-roots` resolves to **1.0.11**, past the 1.0.10 fix for
  [RUSTSEC-2026-0381](https://rustsec.org/advisories/RUSTSEC-2026-0381).
- `h2` resolves to **0.4.20** and is included in the scan, even though HTTP/2
  was not requested directly from Axum.

## Integration findings

These are observed upstream behaviors and requirements for PathWard's future
integration, not claims of newly discovered upstream vulnerabilities. They
remain open because a server adapter has not been implemented.

### PW-A01 — Authorize the original bytes before routing transformations

`ServeDir::build_and_validate_path` percent-decodes and iterates filesystem path
components, ignoring `CurDir`. Its defaults can append `index.html`, and a
fallback may run even for invalid paths. Axum nesting can strip a URI prefix;
its path-parameter extraction decodes parameters. Those semantics are broader
than the proved core's raw-byte, exact-match contract.

Authorize the original request path at the outermost boundary, before nesting,
normalization, decoding, fallback dispatch, or index selection. Do not authorize
an extracted `Path` parameter. An allowlisted URL must map to one explicit
resource; a denial must terminate dispatch. Query handling and method/authority
validation must be explicit. Required integration tests include encoded dots
and slashes, double slashes, nested routes, implicit index files, trailing dots,
and fallback bypass attempts.

Sources: [ServeDir path construction](https://github.com/tower-rs/tower-http/blob/c9414514a421b07b6520e040a3fd6a579b0c5e1b/tower-http/src/services/fs/serve_dir/mod.rs),
[fallbacks](https://github.com/tower-rs/tower-http/blob/c9414514a421b07b6520e040a3fd6a579b0c5e1b/tower-http/src/services/fs/serve_dir/future.rs),
[Axum OriginalUri](https://github.com/tokio-rs/axum/blob/c59208c86fded335cd85e388030ad59347b0e5ae/axum/src/extract/original_uri.rs),
[Axum path extraction](https://github.com/tokio-rs/axum/blob/c59208c86fded335cd85e388030ad59347b0e5ae/axum/src/extract/path/mod.rs).

### PW-A02 — File serving still needs confinement

The default `TokioBackend` uses `tokio::fs::File::open` and path-based metadata.
Lexical validation does not prevent following a symlink outside a document root,
nor does a separate canonicalize/check/open sequence remove lookup races.
Do not expose a mutable directory tree using this as the only boundary.
Use a separately reviewed descriptor-relative open strategy or a trusted,
immutable resource mapping, and address symlinks, hard links, mount boundaries,
and platform-specific aliases. Test filesystem races in that implementation.

Source: [TokioBackend](https://github.com/tower-rs/tower-http/blob/c9414514a421b07b6520e040a3fd6a579b0c5e1b/tower-http/src/services/fs/serve_dir/backend.rs).

### PW-A03 — ACME cache needs private storage and crash-safe writes

`DirCache::write` calls `create_dir_all` and `std::fs::write`. The reviewed source
does not explicitly set private directory/file modes, avoid symlink following,
or atomically replace the file. Certificate caching includes the private key;
account caching also contains key material. File names are hashes, not access
control. With an ordinary Unix umask, privacy must not be assumed.

Keep cache data outside the public tree, in a service-owned directory with
mode 0700, and create key files with mode 0600 (equivalent ACLs elsewhere).
An eventual adapter must validate ownership, reject unsafe existing paths,
prevent untrusted replacement, and use atomic writes with appropriate durability.
Do not rely solely on process-global umask or apply chmod only after creation.
Both account and certificate cache persistence must be tested across restart
and interrupted writes; renewal errors must be observable without logging keys.

Sources: [DirCache](https://github.com/FlorianUekermann/rustls-acme/blob/b74626e54e16019a3056a7421caf1ebb68553b2f/src/caches/dir.rs),
[certificate serialization and renewal](https://github.com/FlorianUekermann/rustls-acme/blob/b74626e54e16019a3056a7421caf1ebb68553b2f/src/state.rs).

### PW-A04 — ACME acceptor requires its own connection budget

`rustls-acme::AxumAcceptor` polls ACME/TLS handshakes without a deadline in that
adapter. `axum-server` spawns a task that awaits the configured acceptor; its
different `RustlsAcceptor` type has a default handshake timeout, which must not
be assumed to apply to the ACME adapter. Tower request timeouts run too late to
cover a stalled TLS handshake.

Bound concurrent accepted connections and handshakes, enforce a total handshake
deadline around the ACME acceptor, and test peers that send partial ClientHello
messages. Separately bound HTTP headers, body bytes, total body transfer time,
response time, and graceful shutdown. Idle timeouts alone do not bound slow
clients that continually make small amounts of progress.

Sources: [AxumAcceptor](https://github.com/FlorianUekermann/rustls-acme/blob/b74626e54e16019a3056a7421caf1ebb68553b2f/src/axum.rs),
[server accept loop](https://github.com/programatik29/axum-server/blob/0d0e181093d5683858a858921deffa0e739f61a0/src/server.rs),
[separate RustlsAcceptor](https://github.com/programatik29/axum-server/blob/0d0e181093d5683858a858921deffa0e739f61a0/src/tls_rustls/mod.rs).

### PW-A05 — ACME HTTP responses are not size-bounded by the wrapper

The reviewed `https_helper::https` reads the response with `read_to_string`
without a byte cap or an explicit request deadline. Its HTTP transport also
supports plain HTTP, despite the helper's name. A malicious/misconfigured ACME
endpoint, or an untrusted directory URL, therefore must not be treated as safe
configuration.

Only administrator-controlled HTTPS directory endpoints and approved domains
may be configured. Never derive issuance domains from arbitrary Host/SNI input.
Preserve normal certificate/hostname verification. Before enabling automated
issuance, supply a reviewed response-size/deadline strategy (upstream support,
a narrowly maintained patch, or an isolated worker with enforceable resource
budgets), and validate endpoints learned from the ACME directory. An outer
timeout alone does not cap memory. Keep polling the renewal state and monitor
failure/expiry. Use staging for tests; do not issue production certificates as
part of dependency audit.

Sources: [HTTPS helper](https://github.com/FlorianUekermann/rustls-acme/blob/b74626e54e16019a3056a7421caf1ebb68553b2f/src/https_helper.rs),
[HTTP transport scheme handling](https://github.com/FlorianUekermann/async-web-client/blob/6ffbbf72030c2d3304f2b343b75e7d66a6a8af0b/src/http/request_native.rs),
[ACME configuration](https://github.com/FlorianUekermann/rustls-acme/blob/b74626e54e16019a3056a7421caf1ebb68553b2f/src/config.rs).

### PW-A06 — Feature unification brings in HTTP/2

The resolved `rustls-acme/axum` → `axum-server` → `hyper-util` graph enables
Hyper's HTTP/2 support and `h2` even with only `axum/http1` selected. The inventory
checks the resolved graph, not only the direct manifest. Either explicitly
configure HTTP/1-only dispatch and ALPN, or review/test HTTP/2 stream, flow-control,
header, and reset limits. Advertising only `http/1.1` in ALPN is not by itself
a proof that an auto-detecting HTTP server refuses HTTP/2 bytes.

Source: [axum-server manifest](https://github.com/programatik29/axum-server/blob/0d0e181093d5683858a858921deffa0e739f61a0/Cargo.toml)
and the committed resolved graph.

### PW-A07 — Standard library, cryptography, and build tools remain trusted

`std` is a Rust toolchain component, not a crate that `cargo audit` scans here.
This review checked the official Rust release notes and security announcements;
it did not audit the implementation of the standard library or OS. Rust 1.98.1
includes the earlier Cargo registry extraction/authentication fixes described
in the [Rust 1.96 release](https://blog.rust-lang.org/2026/05/28/Rust-1.96.0/).
Rust 1.99.1 is available and includes an x86_64 FFI-Boolean miscompilation fix;
use a separately pinned, reviewed current toolchain for the future server.
The proof extractor remains on its compatible nightly, a distinct trust boundary.
See [official release notes](https://doc.rust-lang.org/releases.html).

The ring provider includes native code/build scripts. Neither `forbid(unsafe_code)`
in PathWard nor the Lean proofs certify that provider, Tokio, Hyper, Rustls,
the compiler, or OS. No third-party TLS verifier, permissive certificate verifier,
TLS key logging, or 0-RTT policy is approved by this review. Dependencies and
procedural macros also execute code during builds; the inventory is not a
malware scan. The proof-tool graph (Lean/Aeneas/Mathlib) is documented separately
in the main README and is outside this Cargo lockfile audit.

## Configuration dependency profile

The actual KDL configuration adapter now has a separate 8-package graph and
[focused parser audit](kdl-audit.md). `make dependency-audit` checks both profiles
and the zero-dependency core; a change to either reviewed graph fails the gate.
The 163-package server fixture described above is still not linked into the CLI.

## Reproducing and updating the audit

```sh
make dependency-audit-setup  # Explicitly install pinned cargo-audit under .tools/.
make dependency-audit        # Fresh RustSec + yanked checks; network required.
make dependency-check       # Compile the fixture with --locked.
make check                  # Verify the Rust/Lean core and KDL adapter.
```

Local validation passed: the candidate compiled on macOS ARM64 with Rust 1.98.1;
`make check` passed all Rust tests, extraction comparison, Lean proofs, and axiom
checks. Two negative checks also passed in disposable copies: substituting known
vulnerable `rustls-webpki` 0.103.15 caused the RustSec gate to fail, and modifying
the manifest without updating the reviewed graph caused the graph gate to fail.
The shipped lockfile retained 0.103.16 throughout.

The candidate is a dependency fixture, not a server executable. The separate
GitHub Actions job runs the dependency audit before compiling it on pushes and
pull requests. Audit failure fails that job. No advisory is currently waived.

For an upgrade, update exact direct versions/features and the candidate lockfile,
review the package/source/feature/license/build-script diff, rerun focused source
review and integration tests as relevant, then regenerate `reviewed-graph.json`
using `graph_snapshot` in `scripts/dependency_audit.py`. Run the audit and copy
`.tools/dependency-audit-latest.json` to the committed historical result. A green
scan does not close PW-A01–PW-A07; those require implementation-specific review.
