# PathWard

A small Rust path authorization core, with Lean proofs tied to the Rust
implementation through Charon and Aeneas extraction. The first building block
for a minimal web server.

The Rust library has **zero external dependencies**, uses `no_std`, forbids
`unsafe`, allocates nothing, and performs no I/O. Verification tools are separate
development dependencies; they are not linked into the library.

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

This is a lexical authorization library, **not a filesystem sandbox or web
server**. Its output is a Boolean decision, not a capability to an opened file.
Filesystem confinement requires a separate implementation that handles symlinks,
mount points, hard links, platform-specific filename aliases, and races during
lookup. An allowlisted URL must map only to its intended resource.

HTTP parsing, proxy behavior, TLS, authentication, OS behavior, side channels,
and denial of service of a complete server are outside this first milestone.
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
make check  # Rust tests/lints, fresh extraction comparison, Lean build, axiom audit.
```

`make setup` installs Cargo hax 0.4.2 under ignored `.tools/` using a pinned
SHA-256. Hax's checksum-verified tool manifest installs Charon
`nightly-2026.09.02` and Aeneas `build-183e4f0` (source commit
`183e4f0642e5f261f89215549366043a9a3d72ff`). We use those tools directly;
neither `hax-lib` nor `hax-lean` is required. Rust 1.98.1 is used for ordinary
checks; Charon requires `nightly-2026-08-18` with `rustc-dev`. Proofs use
Lean 4.31.0 and the pinned Aeneas library, including Mathlib and its transitive
development dependencies recorded in `proofs/lake-manifest.json`.

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

The loop/recursion proofs explicitly establish slice indexing bounds and
non-overflowing index increments. The Rust semantics modeled by Aeneas do not
model exhaustion of the native machine's stack. Lookup is bounded to at most
257 recursive calls; deployment still needs an adequate stack.

The axiom audit permits only Lean's standard `propext`, `Classical.choice`, and
`Quot.sound`. No `sorry`, custom security axiom, or native-evaluation proof is
used. The definitions of the policy and the toolchain trust boundary still
need review; a proved policy can be unsuitable for a particular server.

## Rust-only checks

Rust-only checks work offline and fetch no crates:

```sh
cargo test --offline --locked
cargo clippy --offline --locked --all-targets -- -D warnings
cargo fmt --check
```

The security tests include an attack corpus, exact-match and length boundaries,
all single-byte inputs, every word of length up to five over eleven byte-class
representatives, and deterministic arbitrary-byte samples checked against an
independent component-based grammar.

License: [MIT](LICENSE).
