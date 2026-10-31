# KDL parser and dependency audit — 2026-10-30

This records the KDL milestone. The later HTTP/file adapter and expanded serving
proofs are documented in [HTTP audit](http-audit.md); the KDL proof boundary below
remains unchanged.

## Scope and result

This revision adds `pathward-config` as a separate crate, with `kdl = "=6.7.1"`,
`default-features = false`, and only `span` explicitly enabled. The proved
`pathward` core still has **zero external dependencies**. The configuration crate
has **8 external package versions**, including transitive/build dependencies.
There are no procedural macros in this resolved configuration graph.

The review used the shipped crate source, its pinned upstream commit, the
[KDL 2 specification](https://kdl.dev/spec/), and resolved Cargo metadata. It
covers parser control flow, string decoding, recovery, feature selection, schema
adaptation, and the call boundary into the verified compiler. It is a focused
source review and dependency inventory, not a full source audit of every
transitive dependency or a formal proof of the parser.

| Package | Version | Role / enabled features |
| --- | --- | --- |
| kdl | 6.7.1 | AST/parser; `span` only |
| winnow | 0.7.15 | Parser combinators; `alloc`, `default`, `std`, `unstable-recover` |
| miette | 7.6.0 | Error spans; no optional features |
| memchr | 2.8.3 | Byte scanning; `alloc`, `std` |
| num-traits | 0.2.19 | Numeric parsing support; `default`, `std`; build script |
| autocfg | 1.5.1 | Build dependency for compiler capability probes |
| unicode-width | 0.1.14 | Diagnostic widths; `default`, `cjk` |
| cfg-if | 1.0.5 | Conditional compilation |

Default bundles on the direct KDL dependency are disabled, including serde;
v1/v1-fallback and fancy diagnostic rendering are absent. Upstream transitive
feature defaults are recorded rather than assumed absent. The only build script
is num-traits' compiler-probing build; autocfg is a build dependency, not an
additional runtime parser. KDL/miette declare Apache-2.0; the complete declared
license inventory is in the graph. This is not a legal review of every file.

`cargo-audit 0.22.2` checked the core, configuration and server-candidate lockfiles
against the official RustSec database, including yanked checks, without advisory
ignores or platform/severity exclusions. **0 known vulnerabilities; 0 warnings.**
The database had 1,395 advisories at revision
`2295466c4e9df26647fd67d8fa1c705ac2fc7f81` during this audit. Results are dated;
unknown defects and future advisories remain possible.

Evidence: [manifest](../config/Cargo.toml), [lockfile](../config/Cargo.lock),
[reviewed graph](../config/reviewed-graph.json),
[machine-readable result](../config/audit-result.json).
`make dependency-audit` refreshes advisories and rejects unreviewed manifest,
lockfile, source, feature, license, build-script or macro changes. The existing
163-package server candidate remains isolated and is not linked into the
configuration CLI.

## Findings and mitigations

### PW-K01 — Bound parser recursion before invoking it

The reviewed parser recursively handles children and slashdash entries.
`commented_block` also recurses after each `*` or `/` character, even in a flat
block comment. `document` can call itself after error recovery on unexpected
trailing input. Thus a byte limit or a brace/nesting count alone is an inadequate
stack bound for adversarial KDL.

PathWard's [surface preflight](../config/src/surface.rs) is iterative and admits
only the documented small grammar, before any upstream parse. It validates
quoted strings and escapes, directive arities, delimiters, newline/comment
boundaries, a single site-child level, and count limits. It excludes block
comments, slashdash and malformed structural layouts; it does not send rejected
input to KDL. The 64 KiB size limit applies before AST construction. The same
input then reaches the actual KDL 2 parser, which remains responsible for
string decoding and AST construction. Neither pass rewrites the configuration.

This mitigation depends on agreement between the preflight and pinned parser;
re-review both when extending syntax or upgrading KDL. It is tested and source
reviewed, not a proof of native-stack or heap consumption. No claim is made that
unrestricted upstream parsing is suitable for attacker-controlled documents.

Sources: [document recovery and node parser](https://github.com/kdl-org/kdl-rs/blob/8dac0428c75e09d22078b3a1703c70bb0912392d/src/v2_parser.rs#L261),
[block comments](https://github.com/kdl-org/kdl-rs/blob/8dac0428c75e09d22078b3a1703c70bb0912392d/src/v2_parser.rs#L1681).

### PW-K02 — Reject ambiguity and do not publish partial results

The public upstream parse reports errors rather than returning its recovery AST
as success. PathWard additionally rejects unknown nodes, properties, type tags,
non-string arguments, duplicate host/root/TLS declarations, and duplicate decoded
URLs. There is no last-wins merge, environment expansion or include mechanism.
The typed rule compiler accepts only 1–256 canonical URL/relative-target pairs
with distinct URL bytes. If any site fails, no compiled configuration is returned.

Escapes are decoded by KDL once; validation and duplicate detection operate on
the decoded bytes. The preflight accepts only valid simple/Unicode escapes;
encoded dot segments, controls and non-ASCII decoded paths still fail the
verified lexical checks. Host selection has no fallback. Root paths are lexical
Unix declarations; no file is opened during compilation.

Source: [parse result/error handling and escape decoder](https://github.com/kdl-org/kdl-rs/blob/8dac0428c75e09d22078b3a1703c70bb0912392d/src/v2_parser.rs).

### PW-K03 — Keep the proof claim at the actual extracted boundary

The new Rust functions are extracted from MIR by Charon/Aeneas alongside the
original path core. CI compares a fresh extraction with the committed generated
model and checks the Lean proofs. The compiler returns the original slice on
success, and its contract proves validity, size bounds and pairwise-distinct URLs.
`compiled_lookup_iff` proves exact correspondence between successful resolution
and declarations accepted by the compiler. There are no synthesized grants.
Relative targets cannot start with `/` or contain hidden/traversal components.
Compiler and lookup return without a modeled panic or divergence.

[RulesProofs.lean](../proofs/RulesProofs.lean) contains the new proofs. The axiom
audit at this milestone checked 24 exported security statements, admitting only Lean's standard
`propext`, `Classical.choice`, and `Quot.sound`; no proof holes or custom security
axioms. Native stack exhaustion is outside Aeneas' modeled execution semantics.
Compiler duplicate checking is O(n²), lookup O(n), each with at most 256 rules.

KDL, the preflight, the AST/schema bridge, host selection, allocation, std,
compiler/extraction tools and OS remain trusted. Immutable private compiled-site
fields and a review of the same-vector transfer connect the adapter to the
proved functions; this transfer is not itself extracted. This is not a proof
from arbitrary KDL bytes through HTTP dispatch and filesystem opening.

### PW-K04 — Enforce bounded and explicit configuration loading

`ParsedConfig::read` reads at most 65,537 bytes, rejects oversize and non-UTF-8
input, and only then parses. The string API checks the same cap before parsing.
Limits are 16 sites, one children level, and 256 publications per site. File I/O
can still block on a pipe/device or slow storage; a service must load trusted
configuration from a controlled file and define load/reload time budgets.
The configuration crate itself does not own reload or filesystem policy; the server
now implements these at its [runtime boundary](runtime.md).

## Validation and remaining work

`make check` covers core/parser tests, lints, extraction freshness, Lean builds,
and the axiom audit. Configuration tests include exact host/URL isolation,
decoded duplicate collisions, all-or-nothing failure, unknown schema rejection,
limits at and beyond the boundaries, KDL newline agreement (including Unicode
newlines in comments), malformed escapes, unsupported syntax, large flat comments,
long malformed documents and deeply nested input. A deterministic malformed
corpus is exercised; this is not a continuous fuzzing campaign. Core target tests
also compare 111,111 short representative strings against an independent grammar.
The CLI is smoke-tested for accepted and denied resolutions.

Before deployment, implement the missing server boundaries in
[production readiness](production-readiness.md), preserve the raw-path contract,
and add differential/property fuzzing for the guard/parser boundary in an
isolated process with memory/time/stack budgets. Parser or dependency upgrades
require a refreshed source review and graph snapshot, not just a clean scan.

```sh
make config-setup
make check
make dependency-audit-setup  # Explicit tool installation, once.
make dependency-audit
make dependency-check
```
