# KDL configuration

PathWard reads a deliberately restricted profile of **KDL 2**, then compiles
explicit URL-to-file declarations through the dependency-free, Lean-verified
Rust rule compiler. The CLI validates and resolves rules; it does not serve files
or obtain certificates. The separate [Linux HTTP server](http-serving.md) can now
serve these rules on loopback; [TLS mode](tls-serving.md) adds ACME. See [audit](kdl-audit.md) and [deployment gaps](production-readiness.md).

```kdl
// Only these URLs are public. Japanese text is also allowed in comments.
site "example.com" {
    root "/srv/www"
    publish "/" "index.html"
    publish "/style.css" "assets/style.css"
    tls "auto"
}
```

Here `/style.css` maps to `assets/style.css` under the declared root; the URL
`/assets/style.css` remains private. `/` has an explicit index mapping, with no
implicit index or directory publishing. `tls "auto"` selects automatic TLS when started with `serve-tls`. The configuration
CLI still only validates/resolves; the server command takes a private cache path,
CA environment and explicit terms acceptance. `serve-http` remains loopback-only.

## Try it

From the repository root:

```sh
make config-setup  # Explicit fetch of the pinned parser dependencies, once.
cargo run --offline --locked --manifest-path config/Cargo.toml -- check examples/Pathward.kdl
cargo run --offline --locked --manifest-path config/Cargo.toml -- resolve examples/Pathward.kdl example.com /style.css
```

The check prints `OK: 1 site(s), 2 publication(s)`. Resolution prints:

```text
root: /srv/www
file: assets/style.css
```

Unknown hosts, unpublished/invalid URLs, invalid configuration, and I/O errors
exit nonzero. Syntax/schema errors include a one-based line and character column.
The configuration-only CLI does not test filesystem existence, permissions, symlinks,
DNS, certificate eligibility, or root confinement.

## Schema

| Node | Meaning | Required constraints |
| --- | --- | --- |
| `site "host" { ... }` | Independent virtual-host table | 1–16 sites; unique lowercase ASCII DNS-style hostname, no port, scheme, wildcard, trailing dot, or empty label |
| `root "/absolute/path"` | Unix document root declaration | Exactly one for static sites, absent for proxy sites; canonical absolute path, including `/` |
| `publish "/url" "relative/file"` | One exact URL-to-target pair | 0–256 per site; zero requires a redirect or proxy mode; duplicate URLs rejected even when targets are identical |
| `reverse-proxy "127.0.0.1:3000"` | Whole-host delegation to local HTTP app | One numeric loopback endpoint; mutually exclusive with root, publications and configured redirects; see [proxy guide](reverse-proxy.md) |
| `tls "auto"` | Automatic TLS policy | Exactly one per site; only `auto` is accepted |

Hostname labels contain ASCII letters, digits, and hyphens, start/end with a
letter or digit, and have at most 63 bytes; the complete hostname has at most 253.
This syntactic check permits single labels and numeric labels. It does not
establish DNS ownership or ACME eligibility. Host lookup is exact; there is no
default host, wildcard, lowercasing, or port stripping in this API. The HTTP adapter validates Host/authority before choosing the host; the TLS
adapter also requires SNI consistency.

Static publication/redirect paths follow the [core policy](../README.md#policy): 1–4096 bytes, ASCII,
starting with `/`; components start/end with alphanumeric, `_`, or `-`, with
interior dots allowed. Relative file paths use the same component grammar and
are 1–4095 bytes. Absolute targets, `.`/`..`, hidden components, empty components,
percent escapes, backslashes, trailing slashes/dots, and controls are rejected.
Roots use the absolute URL grammar as a conservative Unix lexical grammar.
The Linux opener uses descriptor-relative lookup and handles filesystem-specific
component/permission errors by denying the request. The separate server `check`
command preflights files through this opener. Configuration-only checking
does not perform that filesystem lookup.

Bounded `redirect`, `redirect-prefix` and `header` declarations are described in
[production basics](production-basics.md); prefix matching applies only to redirects,
never file grants. There are no includes, environment substitutions, globs,
rewrites or implicit file grants. Proxy delegation is explicit and site-wide. Directive order does not change lookup.
A duplicate root/TLS declaration or any unknown setting is an error. If any site
is invalid, compilation returns no configuration, including no earlier sites.

## Supported KDL surface

The entire UTF-8 document is limited to **65,536 bytes**. A bounded reader stops
after one byte beyond that limit; callers of the string API already own their
input allocation. A linear, nonrecursive preflight admits only:

- Bare node names `site`, `root`, `publish`, `tls`, `redirect`, `redirect-prefix`,
  `header` and `reverse-proxy`, with the validated schemas.
- Ordinary, single-line double-quoted strings. Literal characters inside values
  must be printable ASCII. Standard simple KDL escapes and valid `\u{...}` scalar
  escapes are accepted, then decoded by the pinned upstream KDL parser. The
  decoded values must still satisfy the schema and ASCII path/host policy.
- Spaces and tabs between names/arguments; all eight KDL newline sequences;
  semicolon or newline node terminators. Each directive must have a terminator
  before `}`. A top-level closing brace may be followed by EOF.
- `//` line comments, including Unicode text. Comment/newline handling uses the
  same newline set as KDL, so a Unicode newline cannot hide a following directive.
- A single children level (sites only); at most 16 sites and 355 directives per
  site before the upstream parser runs. Compilation separately enforces 256 URLs,
  64 redirects, 32 headers, one root, one TLS directive and one proxy directive, subject to mode exclusivity.

Raw/multiline strings, block comments, slashdash (`/-`), quoted node names,
properties, type annotations, bare arguments, line continuations, BOM, and other
Unicode spaces are not supported. They are rejected, not removed or silently
interpreted. Use `//` to comment out a line. The preflight does not rewrite input;
accepted input is parsed explicitly with `KdlDocument::parse_v2`, without v1
fallback. This is a restricted KDL profile, not a full KDL implementation.

KDL escapes are decoded once. For example, `"/a"` and `"/\u{61}"` declare the
same URL and therefore conflict. URL percent escapes are never decoded.

## Rust API and verification boundary

```rust
use pathward_config::ParsedConfig;

let parsed = ParsedConfig::parse(include_str!("../../examples/Pathward.kdl"))?;
let compiled = parsed.compile()?;
let site = compiled.site("example.com").expect("configured host");
assert_eq!(site.resolve(b"/style.css"), Some("assets/style.css"));
assert_eq!(site.resolve(b"/unlisted"), None);
```

`ParsedConfig` owns the AST and decoded strings. `CompiledConfig` borrows them;
keep the parsed value alive while using the compiled configuration. Fields are
private, and published tables are exposed only as shared slices. The adapter
builds each table, calls `pathward::rules::compile`, and moves that same vector
into the compiled site without adding or changing entries. `resolve` calls the
verified `pathward::rules::lookup`.

Lean verifies the extracted Rust compiler/lookup on those byte declarations:
whole-table validity, duplicate rejection, unchanged declarations, and exact
resolution of the declared pairs. The preflight, upstream parser, AST-to-byte
adapter, host dispatch, `Vec` allocation/movement, and Rust string conversion are
reviewed/tested trusted code. **There is no end-to-end Lean theorem from arbitrary
KDL text to a served file.** The separate HTTP/Linux adapter is reviewed and tested, with additional pure
serving decisions verified in Lean; OS operations remain trusted. See [HTTP serving](http-serving.md) and [TLS/ACME](tls-serving.md).
