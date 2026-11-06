# Publication/retention review — 2026-11-06

Scope: the new administrator-crate publication, confined I/O, collection and CLI
modules; their calls to the existing codec/storage/system adapters; generated
Lean contracts; and the isolated native VM fixture/controller. This is a focused
source review and adversarial testing, not a claim of an independent external
security audit or full implementation verification.

## Dependencies

No package/version/lockfile changes. The native graph still contains 36 external
packages across all platforms. `rustix` 1.1.6 gains only its `time` feature:
`clock_gettime(CLOCK_MONOTONIC)` supplies elapsed time, paired with the Linux boot
ID so values from another boot cannot authorize a publication. The existing
filesystem feature supplies `openat2`; no new unsafe code is introduced here.
`serde_json` is accessed through the existing 1 MiB duplicate-key-rejecting
visitor. Existing `ring` SHA-256 checks content/record equality, not signatures.

`docs/native-publication-audit.json` records the fresh all-target RustSec scan,
reviewed feature graph and exact manifest/lockfile hashes. Findings and warnings
are zero, with no ignored advisories. Build tools and legacy fixtures are distinct
from the new runtime dependency graph.

## Findings addressed during implementation

- Comparing device numbers alone misses bind mounts on the same filesystem.
  Linux descendant opens now require `openat2` with `BENEATH`, `NO_SYMLINKS`,
  `NO_MAGICLINKS`, and `NO_XDEV`; failure is an error, with no permissive fallback.
  The reviewed source base can be a mount root. The VM binds another directory
  inside a source tree and verifies refusal.
- The old bridge trusted a cached manifest without re-reading its files. The
  Rust path checks exact membership, metadata and SHA-256 before reuse.
- A monotonic timestamp alone can coincide after a restart. Receipts now bind
  the boot ID and require strict `switch_started < observed <= now` ordering.
  Expected file maps are compared exactly after policy selection and synthetic
  file expansion. Duplicate keys/manifest paths fail closed.
- A Caddy-active result does not establish a PathWard revision. The native
  publisher/ack command refuses that case; an outer Caddy integration retains
  responsibility for its own public HTTP checks.
- Collection does not trust a previous mark pass after state changes. It holds
  the administrator lock and repeats current/boot/gate/health/job/inventory
  checks. It moves only checksum-listed members into a private request-specific
  trash directory and revalidates every remaining member on retry.

## Remaining boundaries

Source releases must be immutable after publication; source account compromise
can change their content. Administrator-owned policy, numeric service UID,
executables and unit configuration are trust roots. Other `current` writers must
join the per-source lock; the filesystem has no general atomic symlink CAS.
Receipts linearize at the bridge's observation and cannot freeze future changes.

Linux/openat2, shared locks, hashes, JSON interpretation, systemd observations and
fsync/rename durability remain implementation assumptions. The proof models do
not establish their correctness. Missing/ambiguous generation references stop
collection rather than being guessed. External helpers, original resources and
public snapshots are retained; their automatic cleanup is outside this collector.
