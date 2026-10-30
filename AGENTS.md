# PathWard

- This is a separate Rust server project; do not modify hamazon.is hosting from here.
- The user permits std, axum, tower-http, rustls, and rustls-acme, with dependency audits.
- KDL 2 is the chosen configuration format. Read docs/configuration.md and docs/kdl-audit.md before extending its syntax or dependency graph. Preserve the iterative surface guard and bounded reader.
- Keep the proved core dependency-free. Place server integration in a separate crate and explicitly review any change to this boundary.
- Use narrow features, commit Cargo.lock, and audit transitive/build dependencies too. Do not enable full/default feature bundles without review.
- Read docs/dependency-audit.md before implementing the server. Its open integration findings are not closed by a clean RustSec scan.
- Never describe the KDL parser/schema adapter, HTTP, TLS, ACME, std, filesystem confinement, or dependency code as covered by the current Lean proofs.
- For core changes, regenerate the Lean extraction, update proofs, and run make check.
- For dependency/feature changes, review and refresh the audit fixture and evidence; run make dependency-audit and make dependency-check before publishing.
- Tool installation belongs in explicit setup targets; keep caches and temporary output out of Git.
