# PathWard

A small Rust path authorization and publication-rule compiler, with Lean proofs
tied to the Rust implementation through Charon and Aeneas extraction. A separate
KDL configuration crate turns explicit site declarations into checked rules.
A separate Linux HTTP/1.1 server serves those rules with descriptor-based file
opening, rustls TLS, private ACME key storage and automatic certificate renewal.
Explicit whole-host delegation to a bounded local HTTP reverse proxy is also available.

The Rust library has **zero external dependencies**, uses `no_std`, forbids
`unsafe`, allocates nothing, and performs no I/O. Verification tools are separate
development dependencies; they are not linked into the library.

## KDL configuration

```kdl
site "example.com" {
    root "/srv/www"
    publish "/" "index.html"
    publish "/style.css" "assets/style.css"
    tls "auto"
}
```

```sh
make config-setup
cargo run --offline --locked --manifest-path config/Cargo.toml -- check examples/Pathward.kdl
cargo run --offline --locked --manifest-path config/Cargo.toml -- resolve examples/Pathward.kdl example.com /style.css
```

Only listed URL-to-file pairs resolve. Unknown settings, duplicate decoded URLs,
unsafe paths or invalid sites reject the whole configuration. `tls "auto"` is
activated by the explicit `serve-tls` command, with a dedicated private cache.

The [configuration guide](docs/configuration.md) describes the restricted KDL 2
profile and limits. The [parser/dependency audit](docs/kdl-audit.md) records the
8 external packages used by this separate adapter, source-review findings and
input guards. The dependency-free core remains separate. Lean proves the actual
Rust rule compiler and lookup; the KDL parser and AST/schema bridge are audited
and tested, not formally verified. See [production gaps](docs/production-readiness.md)
before planning deployment or a Caddy migration.

## HTTP serving (Linux)

```sh
make server-setup
make server-build
server/target/release/pathward-server serve-http examples/Pathward.kdl 127.0.0.1:8080
curl -H 'Host: example.com' http://127.0.0.1:8080/
```

Prepare the configured root/files first. Linux 5.6+ and trusted procfs are required;
there is no file-opening fallback on other platforms. The explicit HTTP mode
accepts loopback listeners only, supports GET/HEAD for static sites, bounds connection/head/write
resources, and never serves an unlisted URL. File resolution rejects symlinks,
mount crossings below the root, special files and observed multiple hard links.

Read the [HTTP guide](docs/http-serving.md), [historical HTTP audit](docs/http-audit.md),
and [remaining production gaps](docs/production-readiness.md).

The [isolated Caddy migration rehearsal](docs/staging-rehearsal.md) covers same-port
TLS handoff, concurrent managed reload/ACME renewal and verified Caddy rollback.
It does not approve replacing a shared proxy deployment.

## Local application proxy

```kdl
site "app.example" {
    tls "auto"
    reverse-proxy "127.0.0.1:3000"
}
```

This explicitly delegates the entire hostname to one numeric loopback endpoint,
with bounded request/response buffering and regenerated forwarding headers.
Use [mixed routing and per-service limits](docs/routing-and-limits.md) to combine
denied subtrees, explicit local files and proxy scopes, with bounded service budgets.
See the [proxy guide and audit](docs/reverse-proxy.md) for the trust boundary,
Lean proofs and limits. Opt in to [WebSocket/SSE streaming](docs/streaming.md) with
bounded buffers, session budgets and shutdown cancellation.

## TLS and automatic renewal

```sh
server/target/release/pathward-server serve-tls /etc/pathward/Pathward.kdl \
  /var/lib/pathward/staging --accept-terms --acme staging --listen 0.0.0.0:8443
```

The cache parent must already be trusted and service-owned; PathWard creates the
private 0700 leaf and 0600 account/certificate records. Public TCP/443 must reach
the TLS listener for TLS-ALPN-01. The command defaults to staging and requires
explicit CA terms acceptance; select production with a separate persistent cache.
No live certificate or deployment is created by tests.

Certificates renew in the final third of lifetime. The worker checks keys, exact
configured SANs and validity, persists before activation, preserves the valid old
identity on failure, and rejects expired identities on new handshakes. SNI must
be configured and HTTP Host must match it. See [operation](docs/tls-serving.md)
and [TLS/key-storage audit](docs/tls-audit.md) for limits and trust assumptions.

The actual server has **104 crates.io package versions plus one small attributed
rustls-acme fork** across all targets (90 crates.io versions plus the fork in the
Linux normal/build graph). No Axum, Tower, Tokio, Hyper or HTTP/2 stack is linked.
The verified core remains zero-dependency. The fork and every transitive/build
package are included in the reviewed inventory; this is not a full source proof.

## Runtime operation

SIGHUP atomically reloads publications, redirects, headers and pinned roots; failed reloads retain the
active configuration. SIGTERM/SIGINT drain active connections. Runtime events are
redacted JSON on stderr; optional `--monitor 127.0.0.1:9090` exposes health,
readiness and Prometheus metrics. Host/ACME identity changes require restart.
See [operation](docs/runtime.md) and [source/proof audit](docs/runtime-audit.md).

The four production basics add optional HTTP→HTTPS and configured 301/308
redirects, bounded CSP/HSTS and other approved headers, explicit-manifest KDL
generation, file preflight, private local activation/rollback with generation and
SHA-256 checks, and connection/rate admission limits. There are no added packages.
Read the [operator guide](docs/production-basics.md),
[P0.3 risk assessment](docs/deployment-risk.md) and
[integration/Lean audit](docs/production-basics-audit.md).

The [continuous soak guide](docs/soak-testing.md) describes overlapping managed
releases, real local ACME renewals, adversarial slow peers, resource checks and
worker fairness. The revised one-hour run passed 57,598 ordinary-load requests,
36,010 fresh post-commit probes, 3,601 managed commits and 80 renewals. The final
RSS growth check and durable restart reuse passed. `make soak` defaults to one
uninterrupted hour on Linux; `make soak-check` exercises the test oracles.

## Server dependencies

Future proxy integration may use `std`, `axum`, `tower-http`, `rustls`, and `rustls-acme`
after audit. The [dated dependency audit](docs/dependency-audit.md) records a
fixed candidate graph, RustSec results, source-review findings, and requirements
for safely connecting it to the proved core. The candidate is isolated under
`audit/server-stack`; it does not add dependencies to the core; the actual TLS implementation has its own smaller, independently locked graph. Dependencies and their integration are outside the current Lean proof.

Run `make dependency-audit-setup` once, then `make dependency-audit` to check the
reviewed graph against fresh RustSec advisories and yanked packages. Both commands
need network access. `make dependency-check` compiles the candidate. The existing
`make check` verifies the Rust/Lean core, configuration and HTTP adapter; CI runs both tracks.

## Policy

Input is the **raw, undecoded URL path**, as bytes. Query strings and fragments
are not accepted by this API. The caller must supply exactly the path that will
be used for dispatch, without decoding or normalizing it before or after checking.

- Length: 1–4096 bytes, starting with `/`.
- `/` is a valid path, but must still be explicitly published.
- Other paths have nonempty `/`-separated components.
- Components start and end with ASCII letters, digits, `_`, or `-`.
- Dots are allowed only inside components, e.g. `main.min.js` or `file..txt`.
- Percent escapes, backslashes, non-ASCII bytes, controls, spaces, queries,
  fragments, empty components, trailing slashes, and dot-prefixed components
  are rejected. Nothing is decoded, repaired, or silently canonicalized.
- Authorization is byte-for-byte, case-sensitive membership in an explicit
  allowlist. No prefix rules, wildcards, directory grants, or implicit index files.
- An invalid path is denied even if it appears in the allowlist.
- At most 256 allowlist entries. A larger list is rejected in its entirety.
  Lookup uses bounded recursion (at most 257 calls); path scanning and byte
  comparison use loops. This avoids a nested-borrow loop limitation in Aeneas.

```rust
use pathward::is_public;

let published: &[&[u8]] = &[b"/", b"/index.html", b"/assets/main.js"];
assert!(is_public(b"/assets/main.js", published));
assert!(!is_public(b"/assets/main.js.bak", published));
assert!(!is_public(b"/assets/../secret", published));
assert!(!is_public(b"/%2e%2e/secret", published));
```

This intentionally accepts a small URL language. International filenames,
percent-encoded names, and directory URLs need a future, explicitly verified
extension to the policy.

## Scope and trust boundary

The core is a lexical authorization and rule-compilation library. Its output is
a decision or relative target, not a capability to an opened file. The separate
Linux HTTP adapter applies descriptor-based confinement as described in its
audit; those OS operations are not included in the Lean proofs.
Filesystem confinement requires a separate implementation that handles symlinks,
mount points, hard links, platform-specific filename aliases, and races during
lookup. An allowlisted URL must map only to its intended resource.

HTTP parsing, proxy behavior, TLS, authentication, OS behavior, side channels,
and denial of service of a complete server are outside the formal proof.
The request-target parser must preserve the raw path and fail closed on invalid
syntax. Every serving route must actually enforce this decision.

The verification boundary includes the Rust compiler/MIR frontend, Charon,
Aeneas and its models of Rust operations, the Lean kernel, and the native
compiler/toolchain used to build the deployed library. A machine-checked theorem
about extracted Rust semantics is not a claim that this entire toolchain or an
eventual server is formally verified.

## Development

Install Rust through rustup, Lean's elan toolchain manager, Python 3.9+, Git,
curl, and a tar implementation with zstd support. Linux also needs a C compiler
for Lean's development tools. The pinned binary setup supports Linux x86-64,
Linux ARM64, and macOS ARM64.

```sh
make setup  # Explicit network access and development-tool installation.
make check  # Core/config/server tests and lints, extraction comparison, Lean build, axiom audit.
```

`make setup` installs Cargo hax 0.4.2 under ignored `.tools/` using a pinned
SHA-256. Hax's checksum-verified tool manifest installs Charon
`nightly-2026.09.02` and Aeneas `build-183e4f0` (source commit
`183e4f0642e5f261f89215549366043a9a3d72ff`). We use those tools directly;
neither `hax-lib` nor `hax-lean` is required. Rust 1.98.1 is used for ordinary
checks; Charon requires `nightly-2026-08-18` with `rustc-dev`. Proofs use
Lean 4.31.0 and the pinned Aeneas library, including Mathlib and its transitive
development dependencies recorded in `proofs/lake-manifest.json`.

`make setup` also fetches the separately locked KDL/HTTP dependencies and installs
Rust 1.99.1 for HTTP server builds; checks then use `--offline --locked` and install
no packages. The extractor and original core toolchain remain pinned separately.

These are significant **verification dependencies**, despite the Rust library
having no runtime, build, or test crate dependencies. They stay out of the
distributed Rust library. The setup changes no default toolchain.

After changing the Rust core, run `make extract`, adapt the proofs, then run
`make check`. Checks reject a stale extracted model, extraction warnings,
proof holes, unexpected axioms, and any added Rust dependency. The generated
[Lean model](proofs/Generated/Pathward.lean) must not be hand edited.

## Verified properties

The [proofs](proofs/PathwardProofs.lean) establish:

| Theorem | Guarantee about the extracted Rust implementation |
| --- | --- |
| `valid_path_eq` | Validation terminates without a modeled panic and equals the bounded path state machine. |
| `same_path_eq` | Comparison terminates without a modeled panic and is exactly byte-list equality. |
| `is_public_eq`, `authorization_iff` | Authorization is exactly the count limit, valid path, and exact allowlist membership together. |
| `authorization_total` | Every input returns a Boolean; no modeled panic or divergence. |
| `deny_unlisted`, `deny_invalid` | Unlisted and invalid paths cannot be published. |
| `published_rooted` | An authorized path starts with `/`. |
| `published_no_traversal` | No authorized path has a component beginning with `.`, including `.` and `..`. |
| `published_bytes_safe` | No authorized path contains percent, backslash, controls, non-ASCII, query, or fragment bytes. |
| `no_empty_component`, `no_trailing_dot` | Canonical paths exclude double slashes and a final dot. |

The [rule compiler proofs](proofs/RulesProofs.lean) additionally establish:

| Theorem | Guarantee about the extracted Rust implementation |
| --- | --- |
| `compile_contract` | Success iff there are 1–256 valid URL/relative-target pairs with distinct URL bytes; the returned slice is exactly the input. |
| `compile_total`, `lookup_total` | Compilation and lookup return without a modeled panic or divergence. |
| `compiled_lookup_iff` | A successfully compiled table resolves exactly its declared URL-to-target pairs. |
| `lookup_safe` | Even lookup on an uncompiled table cannot return a noncanonical URL or target, or an undeclared pair. |
| `target_not_absolute`, `resolved_target_no_traversal` | Returned targets are relative and have no dot-prefixed/traversal components. |

The KDL adapter calls this compiler before exposing immutable site tables, and
uses the proved lookup for resolution. The parser, schema adaptation, host
selection and memory allocation remain outside the extracted Rust model.

The [serving proofs](proofs/ServingProofs.lean) extend the extracted model to
literal raw-path/query splitting, GET/HEAD and host gating, HEAD's no-body grant,
and file metadata admission (regular, single-link, bounded size, identical
pinned/reopened inode). The axiom audit covers 221 statements. Linux resolution,
procfs reopening, HTTP/KDL parsing and actual writes to the socket remain trusted
integration code, with focused reviews and Linux tests.

The [response](proofs/ResponseProofs.lean) and [release](proofs/ReleaseProofs.lean)
proofs add safe header values, fixed-host redirect admission, component-boundary
routing, exact manifest-entry mapping, durable/prepared commit prerequisites and
connection-admission bounds. The staging migration gate requires unchanged
inspected inputs, candidate/parity evidence, a fallback and isolation; its proofs
do not extend to the OS handoff. Public authority-port proofs fix TLS/redirect ports
at 443/80 independently of internal forwarding ports and reject explicit mismatches
and zero-port endpoints. The adapters establishing the inputs to these gates
remain reviewed/tested code; filesystem durability and whole-server availability
are not proved.

The loop/recursion proofs explicitly establish slice indexing bounds and
non-overflowing index increments. The Rust semantics modeled by Aeneas do not
model exhaustion of the native machine's stack. Lookup is bounded to at most
257 recursive calls; deployment still needs an adequate stack.

The axiom audit permits only Lean's standard `propext`, `Classical.choice`, and
`Quot.sound`. No `sorry`, custom security axiom, or native-evaluation proof is
used. The definitions of the policy and the toolchain trust boundary still
need review; a proved policy can be unsuitable for a particular server.

## Rust-only checks

Core-only Rust checks work offline and fetch no crates:

```sh
cargo test --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo fmt --check
```

The security tests include an attack corpus, exact-match and length boundaries,
all single-byte inputs, every word of length up to five over eleven byte-class
representatives, and deterministic arbitrary-byte samples checked against an
independent component-based grammar.

The configuration adapter has its own `make config-check` target (offline after
`make config-setup`), including malformed-input, isolation and limit tests.

License: [MIT](LICENSE).

The TLS extension in [TlsProofs.lean](proofs/TlsProofs.lean) proves exact SNI/Host
identity, private-file admission, no unpersisted/expired activation and total
renewal arithmetic. Metadata, clock, certificate-name/key checks and durable-write
results are adapter inputs. Lean does not establish TLS cryptography, parser/OS
correctness, renewal liveness or whole-server resource bounds.
