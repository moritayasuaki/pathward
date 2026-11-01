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

## Explicit upstream routes

```kdl
site "app.example" {
    tls "auto"
    reverse-proxy "127.0.0.1:3000"
    proxy-route "/v1/feedback" "127.0.0.1:3002"
    proxy-resource "/v1/rooms" "12" "127.0.0.1:3000,127.0.0.1:3001"
    header-prefix "/v1" "x-robots-tag" "noindex, nofollow"
    header-query "room" "x-robots-tag" "noindex, nofollow"
}
```

Routes match whole path components, longest prefix first. At most 64 explicit
routes and 32 distinct numeric loopback endpoints per resource rule are accepted.
A resource collection uses the default upstream. An identifier must contain
exactly the declared 1–64 lowercase hexadecimal characters. Denials, publications
and redirects still take precedence. Slash variants of a published URL remain
reserved to the local route, while the actual file grant requires exact bytes.

Resource discovery is opt-in and requires an application contract: anonymous
`GET /prefix/id` must safely distinguish missing resources (404) from owned
resources (2xx, 401, 403 or 410). Each probe has an empty body and contains no
client credentials, query or headers. Only a probe's 404 permits the next probe.
Other statuses, malformed heads, connection failures and timeouts stop discovery.
All missing returns 404. The original request is validated and its bounded body
read before discovery; it is sent once to the selected owner and is never retried,
including after a subsequent 404 or transport failure. Discovery and forwarding
share one service permit, original total deadline and immutable configuration
snapshot. This is not transparent compatibility with an arbitrary application's
404-fallback middleware. Resource identifiers must be unique across backends;
collisions choose the first owning backend. There is no ownership cache.

Header scopes choose one value per name: query rules, exact paths, longest path
prefix, then the global rule. Equal matching query rules choose the last one.
Query keys containing `%` or `+` conservatively match query rules, avoiding a
noindex bypass from application-specific decoding; this can apply a header more
widely. Values in query rules must be suitable for this overinclusive behavior.
The existing header-name/value safety gate remains mandatory.

## Verification and dependency review

No runtime dependency, feature or lockfile was added. Core policies remain free
of external dependencies; the KDL stack has eight and the server 104 external
locked packages. A fresh RustSec scan also checks the 163-package candidate stack.
Parser changes retain flat, bounded KDL preflight, exact argument counts and
canonical numeric loopback endpoints. Publication duplicate validation remains
quadratic but is capped at 4096 entries per site and 1 MiB of input.

Lean verifies the current Rust extraction, including range bounds without wrap,
conditional precedence, restrictions on shared caches, read-only/bodyless/anonymous
probe gates, bounded candidate counts, 404-only discovery continuation and terminal
authorization/gone statuses. The complete axiom audit covers 252 statements.
Socket orchestration, header parsing, filesystem metadata and application ownership
semantics are tested/audited adapters, outside those proofs. The discovery gate's
GET/credential flags are tied to the fixed constructed probe in that adapter.

Active static responses receive a five-second drain window after they observe
shutdown, capped by their original total deadline. A write already in progress
retains its five-second deadline; stopping acceptance does not truncate a small
active response immediately. Linux signal/drain integration tests cover this.
