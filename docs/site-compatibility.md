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
