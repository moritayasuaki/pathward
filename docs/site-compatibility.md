# Bounded website compatibility

## Directory URLs and publication capacity

An explicit `publish "/guide/" "guide/index.html"` now serves a directory URL.
It remains a byte-for-byte URL grant: `/guide`, `/guide//`, and other children
are not aliases and do not inherit permission. Use an explicit same-host
`redirect "/guide" "docs.example" "/guide/" "308"` if desired. Prefix redirects
preserve a terminal slash and the query. Prefix source/destination stems must
not end in `/` (the destination `/` is the strip-prefix case).

URL recognition accepts a single final separator. File targets still require a
complete nonempty relative file name; dot components, hidden components, escapes,
backslashes, empty interior components and trailing dots remain forbidden.
There is no directory discovery, implicit index, or decoding.

A site can contain at most 4,096 explicit publications; the complete KDL input,
configuration reads, managed activation messages and manifest input are bounded
at 1 MiB. Parsing retains its iterative surface preflight. Compilation has a
bounded quadratic duplicate check; request lookup remains bounded and exact.
The 4,096/4,097 boundary and a 1,500-entry generated configuration are tested.

The extracted Rust recognizer/compiler proofs retain exact allowlist lookup,
no traversal, safe relative targets and atomic generation replacement. Additional
statements establish that a final URL separator is accepted after a complete
component, while a file target ending in a separator is rejected. Linux I/O and
the KDL parser remain trusted adapters, not covered by an end-to-end theorem.

## Static representations

Regular, single-link static files are admitted up to **1 GiB**. The reopened
constrained descriptor is read with a fixed 16 KiB buffer, a 120-second total
transfer deadline and five-second write deadlines. Shutdown is observed between
chunks. Do not modify published inodes in place: prepare a release and atomically
replace it, as required by the existing file-storage trust boundary.

Single byte ranges support closed, open-ended and suffix forms, with 206 and 416
responses. HEAD ignores Range. Unknown units, malformed/overflowing inputs and
multipart ranges are ignored and receive a full response; multipart output is
not implemented. Preconditions are evaluated before selecting a range, and an
unpublished/denied URL cannot obtain validators or a conditional success.

ETag is an opaque **weak metadata validator**, with Last-Modified from the opened
descriptor. If-Match, If-Unmodified-Since, If-None-Match and If-Modified-Since use
[HTTP conditional precedence](https://www.rfc-editor.org/rfc/rfc9110.html#section-13.2.2).
If-Range cannot establish strong byte identity with these validators and therefore
receives the full representation. Do not treat this metadata hash as a content
hash. A trusted publisher's concurrent in-place writes remain outside the proof.

Cache defaults to no-store. Examples:

```kdl
cache "*" "no-cache"
cache-prefix "/assets" "public,max-age=31536000,immutable"
cache "/assets/current.json" "no-cache"
```

Scopes are global (`*`), exact, or explicit component-prefix. The most specific
scope wins, with exact preceding prefix at equal length. Only canonical typed
values are emitted: no-store, no-cache, or public,max-age=N with optional
`,immutable`; N is at most one year. Immutable requires positive age. These
policies apply only after static authorization, not to proxy responses. Errors
and Authorization/Cookie requests always use no-store. Operators must not reuse
an immutable URL for new content. Changing policy cannot revoke copies already
stored in remote caches; use versioned URLs for sensitive release transitions.

The extracted content gates prove interval bounds without arithmetic overflow,
conditional precedence, and exclusion of unpublished, credential-bearing and
error responses from shared freshness. Header parsers/serialization and I/O are
bounded tested adapters. PEM, signatures, ZIP and PowerShell MIME mappings are
included alongside existing HTML/CSS/JavaScript/PDF/WASM support.
