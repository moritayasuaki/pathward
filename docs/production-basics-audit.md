# Production basics audit — 2026-10-31

Scope: P0.1 redirects, P0.2 response headers, P0.3 explicit generation and managed
activation/rollback, P0.4 admission limits and bounded adversarial tests. The
[risk assessment](deployment-risk.md) was written before implementation. This is
an implementation review, not an independent penetration test or a proof of the
whole server. See [operator instructions](production-basics.md).

## Dependencies and parser

No Cargo manifests, lockfiles or vendored dependency source change in this
extension. Core: zero dependencies, no allocation/I/O, `no_std`, forbidden unsafe.
KDL adapter: the same eight external package versions. Server: the same 104
crates.io versions plus the attributed rustls-acme fork (90 plus fork in the Linux
normal/build graph). Existing `ring` supplies SHA-256; existing `rustix` and the
private store supply filesystem operations. Limits, Unix protocol, rendering,
token buckets and mutation tests use std; no CLI, HTTP, rate-limit, hashing,
filesystem-walker or fuzzing package was added.

The fresh full graph audit, including the isolated future stack candidate, found
no RustSec advisories, unmaintained/unsound warnings or yanked packages against
RustSec database `2295466c4e9df26647fd67d8fa1c705ac2fc7f81`.
The machine-readable report is [server/audit-result.json](../server/audit-result.json).
The pinned reviewed inventories and earlier KDL/TLS audits remain applicable.

The pre-parser now accepts lowercase-hyphen directive names and exactly four
quoted arguments for redirects / three for headers. Its 64 KiB/16-site/one-level
bounds remain. Site directive cap is 354 (256 publications, 64 redirects, 32
headers, root and TLS); compilation enforces each individual cap. Header decoded
value/aggregate limits prevent response growth. All destination hosts must be
configured; duplicates and publication/redirect overlap fail the whole compile.
KDL output is escaped, deterministically rendered and reparsed through this same
bounded compiler. Upstream parsing, schema/host-set iteration, formatting and
allocation are audited/tested adapters, not extracted Lean code.

## Response integration review

Only the gate's seven lowercase response names can be added. Values are rechecked
at emission, excluding CR/LF/control injection and forbidden framing headers.
The server supplies status, Content-Length, Connection and Location itself.
This follows [HTTP/1.1 framing requirements](https://www.rfc-editor.org/rfc/rfc9112.html#name-message-body-length).
HTTPS locations consist of the literal scheme, a configured validated DNS host,
a canonical destination and unchanged validated query. No raw Host authority,
absolute request target, arbitrary scheme or port reaches this construction.
See [Location semantics](https://www.rfc-editor.org/rfc/rfc9110.html#name-location).

One request pins one snapshot containing root, publications, redirects and headers.
The redirect-only plaintext listener never enters the file-open path. Shared
admission permits cover both listeners, including TLS handshake and queued work.
Header semantics (e.g. a CSP that allows too much), routing cycles and the content
at a configured destination remain operator responsibilities.

## Deployment integration review

Explicit manifest entries alone feed the generated-rule gate; no recursive
filesystem discovery occurs. Optional `/` alias requires a listed target. The
exact output is recompiled and unsafe files are opened only through the existing
serving opener. Candidate preflight and subsequent serving use the **same pinned
root descriptors**, avoiding a separate check/open-root race. Files themselves
must remain immutable; the SHA-256 is a configuration digest, not a content hash.

A serial lock covers managed activation and the entire SIGHUP read/prepare/commit
sequence, preventing a stale SIGHUP read from overtaking a newer activation.
Expected generation/digest and out-of-band durable-file mismatch fail closed.
Private control and ACME directories are excluded from all candidate public roots,
including SIGHUP. Managed storage uses the existing no-follow, service-owned
0700/0600, single-link, fsync+rename private-store implementation. No public path
is used for backups or temporary files.

Durable-save failures may occur after rename: the transaction restores old bytes
on any write/commit error, and stops serving if restoration also fails. The
pre-attempt backup is intentionally a single slot. Disk/memory atomicity, process
scheduling and fsync durability are not proved. Restart opens/checks the durable
configuration; a crash between save and commit can activate the new config on
restart. Status reads generation/digest from one snapshot; successful replies
report the exact committed generation and candidate digest. A lost reply remains
ambiguous and requires status inspection.

The private Unix socket has no shell, path-based command, TCP endpoint or error
body reflection. Request header ≤160 ASCII bytes, candidate ≤64 KiB, one serial
command/connection, five-second total receive and one-second reply budget. The
client has a 30-second send/receive budget. Regular-file I/O can block separately.
Directory locking excludes a second managed server; restart removes only a socket
with expected ownership/mode, and cleanup verifies inode/device before unlinking.
Same-UID/root processes and trusted parent directories remain a boundary, not an
adversarial multi-user capability protocol.

## Extracted proofs

Charon/Aeneas extracts the actual Rust functions in `src/response.rs` and
`src/release.rs`; generated Lean is not handwritten. New
[ResponseProofs](../proofs/ResponseProofs.lean) and
[ReleaseProofs](../proofs/ReleaseProofs.lean) establish:

- Exact safe header-name/value policy and absence of control bytes.
- Redirect status/host equality/host-byte/target validation and control-byte
  exclusion; exact/component-boundary routing, with modeled totality.
- Generated mapping target equals its explicit entry, normal URL equals that
  entry with leading slash, and root alias obeys its explicit special case.
- Commit requires the expected digest, prepared and persisted flags, and no
  draining; stale/unpersisted/draining commits are refused.
- Admission requires non-draining, global count <12, peer count <2 and positive
  tokens; no exhausted-token admission. All gates return without modeled panic.

Together with the existing generation CAS/readiness/path/rule/TLS/file contracts,
102 statements are included in the axiom audit. Only standard Lean axioms are
allowed; proof holes, custom axioms, native-evaluation escapes and stale extracted
models fail checks. The full KDL-to-socket path, manifest membership iteration,
configured-host lookup, prefix concatenation, header serialization, locks,
filesystem/kernel, crypto, token refill and actual scheduling remain trusted
integration code. Lean does not prove a filesystem transaction, content
confidentiality, certificate renewal liveness or denial-of-service availability.

## Validation

`make check` covers Rust tests/lints, extraction equality, Lean builds and axiom
audit; `make dependency-audit` checks the frozen graph against fresh advisories.
Linux CI additionally covers native openat2 and local Pebble ACME/renewal tests,
HTTP/HTTPS redirects and header integration, simultaneous expected-revision
activation, unsafe/missing file rejection, rollback and SIGKILL/restart reuse.
Injected post-rename storage failures exercise both restore and stop behavior.

Admission unit tests cover counts, token refill, /64 and mapped-address keys,
map cap/eviction and draining. The release smoke load test exercises slow peers,
healthy-peer progress, per-peer rate exhaustion/refill, 20 bounded bursts,
telemetry and shutdown. The std-only mutation example parses 100,000 inputs,
including malformed framing/queries and arbitrary bytes, with no panic and no
extra publication grants. These are bounded regression tests, not coverage-guided
fuzzing or a long-duration soak. Deployment-specific load, supervision, external
alerts and realistic storage tests remain required before replacing Caddy.
