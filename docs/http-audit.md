# HTTP/file adapter audit — 2026-10-30

This is the historical HTTP-only milestone. The later [TLS audit](tls-audit.md)
records the current dependency graph and additional controls.

## Scope and dependency result

The actual HTTP server is a separate crate using std threads/TCP, the existing KDL
adapter, `httparse` 1.10.1, `httpdate` 1.0.3 and Linux-only `rustix` 1.1.6. It does
not link the 163-package Axum/TLS candidate. The verified `pathward` core remains
zero-dependency, no_std and free of unsafe code and I/O.

The [manifest](../server/Cargo.toml), [lockfile](../server/Cargo.lock),
[reviewed graph](../server/reviewed-graph.json) and
[audit result](../server/audit-result.json) record **17 external package versions
across all target platforms**, including the 8 already used by configuration.
The Linux x86-64 normal/build graph has 12 external package versions. This count
includes build dependencies and is not a count of linked runtime libraries.

| New direct dependency | Enabled features | Review scope |
| --- | --- | --- |
| httparse 1.10.1 | No default/optional features | Request parser, defaults, newline/header behavior, buffer/unsafe boundary, build script |
| httpdate 1.0.3 | No optional features or dependencies | Date formatting and SystemTime range/panic preconditions |
| rustix 1.1.6 | Default disabled; explicit `fs`, `std` | Linux raw syscall wrapper, flags, owned descriptor lifetimes, backend selection/build probes |

New transitive package versions are bitflags 2.13.2, linux-raw-sys 0.12.1, errno
0.3.14, libc 0.2.191, windows-sys 0.61.2 and windows-link 0.2.1. The last four
remain in the all-target lockfile/inventory even though the ordinary Linux raw
backend does not build them. The optional memchr package is also present in the
lockfile but absent from this Linux normal/build tree. There are no procedural macros in this server graph.
Build scripts in the all-target graph are httparse, rustix, num-traits and libc;
compiler-capability probes and target selection remain build-time trusted code.
The machine inventory includes declared licenses and resolved features. This is
not a line-by-line audit of every transitive package or a distribution legal audit.

`httparse`'s std feature is disabled, which its build script uses to disable SIMD.
Its scalar parser still contains unsafe code; our `forbid(unsafe_code)` does not
certify dependencies. Rustix's Linux raw backend also uses unsafe syscall bindings.
No Tokio runtime, Hyper, TLS provider or C crypto build is added to this milestone.

`cargo-audit 0.22.2` checked core, configuration, HTTP server and the older server
candidate against the fresh official RustSec database, with yanked checks and no
advisory ignores, platform filters or severity exemptions. **0 known vulnerabilities;
0 advisory/yanked warnings.** The database revision in this dated result is
`2295466c4e9df26647fd67d8fa1c705ac2fc7f81` (1,395 advisories). A clean scan is not
proof that the parser, OS adapter or dependencies have no unknown defects.

Production-server builds/checks use pinned **Rust 1.99.1**, including the current
x86_64 FFI-bool fix; the verified core's normal checks remain pinned to 1.98.1 and
its compatible extraction nightly. std is audited as a toolchain boundary, not
as a Cargo crate. Source: [official release notes](https://doc.rust-lang.org/releases.html#version-1991-2026-10-15).
`make dependency-audit` refuses unreviewed manifest, lockfile or resolved-graph
changes. Only the two explicitly enumerated local crates are accepted as local
dependencies; arbitrary local or Git sources are rejected.

## Findings and controls

### PW-H01 — Parser tolerance is broader than this server's request contract

The reviewed httparse request code can skip initial empty lines and recognize
bare-LF line endings. Its defaults reject request-side obsolete header folding
and invalid header skipping, but parser defaults alone are not a complete framing
policy. PathWard adds explicit CRLF/request-line validation, caps the buffer and
header array, and requires a complete parse consuming the entire buffer. It
requires one Host, no transfer coding, no request body and at most one canonical
Content-Length: 0. Expect/Upgrade/Trailer and unsupported Connection tokens fail.
No parser recovery or lenient option is enabled.

One request is dispatched per connection, followed by close. Already-buffered
trailing bytes fail validation; later pipeline bytes are never dispatched. This
reduces ambiguous message framing but is not a proof about a future proxy chain.
Reverse-proxy normalization, forwarded authority or TLS SNI are not implemented.

The raw borrowed request target goes to the extracted Rust `serving::authorize`
function. It validates the method and exact selected host, takes only the literal
prefix before the first `?`, validates query bytes, and uses the existing exact
rule lookup. Percent escapes, slash normalization, implicit indexes and fallback
file dispatch are absent. File I/O is reachable only after this grant.

Sources: [httparse parser/defaults](https://github.com/seanmonstar/httparse/blob/9f29e79f9832dbd0ae5220acb17c1866745bdecd/src/lib.rs),
[build script](https://github.com/seanmonstar/httparse/blob/9f29e79f9832dbd0ae5220acb17c1866745bdecd/build.rs),
[HTTP/1.1 framing specification](https://www.rfc-editor.org/rfc/rfc9112.html).

### PW-H02 — Resolve beneath an opened root in one kernel lookup

The Linux adapter pins the configured root with symlinks forbidden, then uses
openat2 on that descriptor with BENEATH, NO_SYMLINKS, NO_MAGICLINKS and NO_XDEV.
The final target is initially opened with O_PATH, so a FIFO/device is not opened
for data I/O before its type is checked. Only regular, single-link files no larger
than 64 MiB are admitted. The pinned inode is reopened through trusted procfs
while the pin remains alive; the extracted metadata policy checks type, link
count, size and identical device/inode/size on the readable descriptor.

This avoids the canonicalize/check/open race and does not follow a replacement
symlink after authorization. NO_XDEV also rejects bind mounts below the root,
even when they use the same underlying filesystem. Unsupported syscalls, missing
procfs and resolution errors fail closed, with no fallback or weaker retry.

The trusted kernel supplies these semantics. Lean proves the metadata decision
and dispatch contracts, **not Linux path resolution, fstat, procfs or file I/O**.
The root's identity is the descriptor pinned at startup, not a pathname that is
re-resolved after a deployment rename. Arbitrary writes to allowed file content,
hard-link creation/removal after the observations, malicious filesystems and
privileged namespace mutation remain outside the guarantee. The full assumptions
are in [HTTP serving](http-serving.md#file-opening-strategy-and-trust-assumptions).

Sources: [Linux openat2 documentation](https://man7.org/linux/man-pages/man2/openat2.2.html),
[Linux O_PATH and procfs reopening](https://man7.org/linux/man-pages/man2/open.2.html),
[rustix safe wrapper](https://github.com/bytecodealliance/rustix/blob/4a563ad698b2c20ff848515821023d2265a788d0/src/fs/openat2.rs),
[raw Linux syscall implementation](https://github.com/bytecodealliance/rustix/blob/4a563ad698b2c20ff848515821023d2265a788d0/src/backend/linux_raw/fs/syscalls.rs).

### PW-H03 — Limit resources at the socket boundary

Four workers and eight queued accepted sockets replace unbounded spawning. A
request head is at most 16 KiB/32 fields. Its five-second deadline starts at accept,
including queue time. Each response write recomputes a ten-second total deadline;
small progress does not reset the budget. Oversized/ambiguous inputs are denied,
and excess accepted connections are closed. File copying uses a fixed 16 KiB
buffer and the admitted length, so later growth cannot extend the response.

Blocking filesystem operations cannot be forcibly timed out by std socket timeouts.
Use trusted local storage and service supervision. CPU/bandwidth fairness,
per-client rate limiting and external alert integration remain deployment work.
Signal-driven shutdown, reload and telemetry are now covered in
[the runtime audit](runtime-audit.md). Plain HTTP is loopback-only, and startup
logs identify whether TLS mode is enabled.

### PW-H04 — Prevent date-formatting panics and reflected response metadata

httpdate's SystemTime conversion rejects pre-epoch or year-10000-and-later dates.
The adapter checks this range before formatting; an unusable system clock omits
Date. Only fixed status phrases/content types and numeric lengths enter response
headers. Request paths, Host values and filesystem error messages are not echoed
in HTTP responses. All error bodies are empty, including HEAD errors.

Source: [httpdate conversion](https://github.com/pyfisch/httpdate/blob/638da761065df8b67282b0a1d139c0a7e4a02429/src/date.rs).

## Lean evidence and validation scope

[ServingProofs.lean](../proofs/ServingProofs.lean) proves actual extracted Rust:

- Path/query splitting terminates without modeled panics and returns the unchanged
  path prefix, at the first question mark, with count/byte validation.
- Authorization requires GET/HEAD, identical host bytes and a successful exact rule
  lookup; unknown methods/hosts cannot receive a grant.
- Every granted target satisfies the canonical relative-target policy and comes
  from the selected table. HEAD grants cannot request a response body.
- The file-admission Boolean is exactly the regular-file/single-link/size/same-inode
  contract, with total modeled execution and device/inode/size preservation.

Together with existing rule-compiler proofs, the axiom audit now checks **41**
statements and allows only standard Lean `propext`, `Classical.choice`, `Quot.sound`.
No proof holes, custom security axioms or native-evaluation proof are used. Core
changes require a fresh Charon/Aeneas extraction; CI rejects model drift.

Portable checks exercise malformed/framing inputs, exhaustive single-byte head
mutations, URL/method/host decisions, query splitting, file metadata decisions
and a slow-progress socket deadline. Linux tests exercise real GET/HEAD, host
isolation, encoded/traversal denials, resource limits, hard links, symlinks,
FIFO/socket/directory rejection, size limits, pinned roots and repeated rename
races. A separate CI test uses an isolated mount namespace for an actual bind
mount. The release CLI is also smoke-tested over TCP.

These are focused source reviews and bounded adversarial tests, not a continuous
coverage-guided fuzzing campaign, exhaustive race exploration or formal proof of
the whole server. OS/compiler/extractor, HTTP/KDL adapters, response serialization,
thread scheduling, allocation and dependencies remain trusted. Preserve these
boundaries and re-review them when adding TLS, proxying, keep-alive or new paths.
