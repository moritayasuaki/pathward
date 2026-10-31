# Runtime integration audit — 2026-10-31

## Dependency change

The server adds exactly two crates.io package versions: `signal-hook 0.4.5`
(default features disabled) and `signal-hook-registry 1.4.8`. The existing libc and
errno versions are reused. errno becomes reachable in the Linux normal graph
through the registry, so that target gains three reachable package versions. The server inventory is 104 crates.io versions plus the
local attributed ACME fork across all targets; the Linux normal/build graph has
90 crates.io versions plus the fork. Core remains zero-dependency, config remains
8 external packages. Logging, metrics, snapshots and their synchronization use
std; there is no tracing/Prometheus runtime, HTTP framework or async executor
addition. No new proc macro is enabled.

Reviewed package source: signal-hook Cargo manifests, build.rs, flag registration,
low-level registry re-export; signal-hook-registry registration, errno guard,
POSIX sigaction dispatcher, previous-handler chaining, atomic action ownership and
unregistration. `flag::register` captures an Arc<AtomicBool> and only stores true
with SeqCst from the signal handler. Parsing, locks, filesystem/network I/O and
logging happen on ordinary threads. The configured signals are HUP/TERM/INT,
never synchronous fatal signals. The registry uses unsafe FFI and internal shared
ownership; it remains part of the trusted computing base, not Lean-verified code.

signal-hook has a build script, but with the selected empty feature set its main
is empty: the optional C siginfo extractor and cc build feature are disabled.
The registry has no build script or macro. CLI handlers are installed before
workers and removed only on process exit; unregistration does not restore default
handlers, so the public Signals wrapper is intended for the one CLI lifetime,
not temporary masking or arbitrary coexistence with another signal framework.
Dependencies/versions/features/build scripts remain checked by reviewed-graph.json
and Cargo.lock, not a floating latest-version claim.

A fresh official RustSec scan of all three lockfiles reports zero vulnerabilities
and warnings, with no ignored advisories, severity or target filters. The exact
DB revision and complete reports are in server/audit-result.json. This is a dated
advisory scan plus focused source/integration review, not an absence-of-bugs proof.

References: [pinned flag API/source](https://docs.rs/signal-hook/0.4.5/src/signal_hook/flag.rs.html),
[registry source](https://docs.rs/signal-hook-registry/1.4.8/src/signal_hook_registry/lib.rs.html),
[signal-hook features](https://docs.rs/crate/signal-hook/0.4.5/features).

## Security decisions and correspondence

The actual Rust functions `runtime::commit_generation` and `runtime::ready` are
extracted through the pinned Charon/Aeneas path. RuntimeProofs adds 13 theorem
audits, taking the complete audit to 70 statements. The commit contract is total
and increments exactly when the candidate is prepared, identity matches, private
storage is isolated, the expected generation is current, shutdown has not begun,
and the u64 generation is not exhausted. Failed, stale, draining, mismatched,
unprepared, unsafe-storage and exhausted transactions retain the current value.
Readiness cannot be true while draining or when TLS lacks a valid certificate.
No proof holes, additional axioms or opaque executable substitutions are used.

The adapter's candidate constructor owns copies of already-compiled host and
publication bytes and opens all roots before commit. It serializes preparations,
uses one RwLock write section to replace the Arc snapshot and generation, and calls
the extracted decision again inside that section. Request dispatch clones one Arc
before parsing; every lookup and root open uses that same snapshot. No lock spans
request I/O. Invalid parse/schema/root opens return without an active-state write.
TLS host sets are fixed and roots are rechecked against the same cache pathname;
certificate renewal continues independently for that unchanged set.

The booleans in the extracted contract are adapter facts. Lean does **not** prove
KDL parsing, std Arc/RwLock, signal delivery, scheduler fairness, OS filesystem
isolation, certificate cryptography, log persistence or socket deadline accuracy.
The lock-to-snapshot integration and byte copies are source-reviewed and tested.
Shutdown and reload racing are ordered by the state lock; an atomic stop flag is
also sampled under that lock, but a later signal cannot undo a completed commit.
Already dispatched requests may finish on older snapshots. Trusted local storage,
configuration ownership, procfs and mount assumptions remain unchanged.

## Regression coverage

- Pure Rust boundary matrix covers all decision flags, stale generations and
  u64 exhaustion, including the extracted readiness gate.
- Linux tests trigger reload during a request's first read and check it retains
  both its old publication and root. Concurrent readers/reloads never combine
  targets from one generation with a root from another. Missing/symlink roots,
  changed host sets, private-cache overlap and draining preserve the active state.
- Linux monitoring tests check missing/valid/expired certificate readiness,
  draining, no key/path/domain disclosure and rejection of public monitoring binds.
- The release CLI test sends actual SIGHUP, SIGTERM and SIGINT. It checks successful
  switches, invalid KDL/root/host/FIFO rejection and recovery, completed active
  requests, discarded queued requests, timed-out incomplete headers, exit code 0,
  readiness/metrics and structured logs without private queries.
- A full logging queue drops without blocking. Existing HTTP framing, descriptor
  attacks, TLS/SNI/ALPN and local Pebble issuance/renewal/persistence tests remain in
  CI, as do extraction freshness, Lean builds and axiom audits.

Operational limits and collector setup are documented in [runtime.md](runtime.md).
