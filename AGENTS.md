# PathWard

- This is a separate Rust server project; do not modify hamazon.is hosting from here.
- The user permits std, axum, tower-http, rustls, and rustls-acme, with dependency audits.
- KDL 2 is the chosen configuration format. Read docs/configuration.md and docs/kdl-audit.md before extending its syntax or dependency graph. Preserve the iterative surface guard and bounded reader.
- Keep the proved core dependency-free. Place server integration in a separate crate and explicitly review any change to this boundary.
- Use narrow features, commit Cargo.lock, and audit transitive/build dependencies too. Do not enable full/default feature bundles without review.
- Read docs/http-serving.md and docs/http-audit.md before changing HTTP or file I/O. Keep the verified grant before the only serving-file open; preserve Linux openat2 restrictions, the O_PATH pin, checked procfs reopening, and no weaker fallback.
- HTTP-only mode is loopback-only. TLS/ACME requires a separately reviewed implementation. Server builds use pinned Rust 1.99.1; keep extraction on its compatible toolchain.
- Read docs/dependency-audit.md before implementing TLS/proxy features. Its open integration findings are not closed by a clean RustSec scan.
- Never describe KDL/HTTP parsing, TLS, ACME, std, Linux filesystem confinement or dependency code as Lean-proved. The pure serving/metadata decisions are proved; their OS/adapter inputs and effects are trusted.
- For core changes, regenerate the Lean extraction, update proofs, and run make check.
- For dependency/feature changes, review and refresh the audit fixture and evidence; run make dependency-audit and make dependency-check before publishing. HTTP/file changes also require Linux native tests, the private-namespace mount test and release CLI smoke test in CI.
- Tool installation belongs in explicit setup targets; keep caches and temporary output out of Git.
