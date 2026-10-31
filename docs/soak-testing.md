# Continuous pre-production soak

The extended test runs the real Linux server, private managed configuration
socket, TLS listener, HTTP redirect listener, reload worker, monitoring and ACME
worker together. A local pinned Pebble CA issues 60-second certificates using
real TLS-ALPN-01 validation; no public CA, production host, DNS or deployment is
modified. The test driver only accepts a localhost CA origin. The shipped CLI's
fixed staging/production origins are unchanged.

## Reproduction

On Linux 5.6+ with trusted procfs and local storage:

```sh
make server-setup acme-test-setup  # Explicit pinned development dependency setup.
make soak                       # 3600 seconds, report .tools/soak-latest.json.
make soak SOAK_SECONDS=120 SOAK_REPORT=.tools/soak-short.json
```

The duration accepts 120–86400 seconds. Initial issuance and cleanup add time.
Reports and temporary private keys stay outside Git/public content. The
`Extended soak` workflow runs two-minute calibration followed by one uninterrupted
hour; its ten-minute checkpoints inspect the same process, without restarting it.
The normal workflow also runs the two-minute overlap regression. Both workflows
use the existing pinned checkout action and test CA; no new action/package is
introduced. Final reports are printed into the Actions job logs.

## Workload and assertions

- Four clients offer a combined 16 requests/second with independent transport
  addresses. HTTPS GET/HEAD for two virtual hosts, configured redirects, plaintext
  HTTPS redirects, raw queries, unlisted/traversal requests and SNI/Host mismatches
  are checked against exact expected status, header and content combinations.
- A separate peer repeatedly opens six incomplete TLS/HTTP exchanges across both
  listeners, holding them for 1.5 seconds. Normal requests must continue to finish.
- Managed activation/rollback runs about once per second. Both sites' roots,
  filenames, response headers and redirect targets switch together. Opposite
  roots contain sentinel content at the wrong filename, detecting mixed snapshots.
  Explicitly unlisted secret sentinels must never appear in a response.
- Stale-generation and private-control-root candidates are repeatedly rejected,
  with active generation/digest unchanged. SIGHUP reloads overlap the traffic,
  managed switches and renewal. Logs count commits while an ACME order is active;
  overlap is asserted, not inferred from having started two threads.
- TLS clients validate the local issuer, hostname and time on every TLS request.
  Renewed public certificate fingerprints are counted; readiness, expiration,
  ACME errors and log loss are checked continuously. Private file modes and
  single-link metadata are checked after the run.
- `/proc` samples server RSS, FD count and thread count every two seconds. The
  gate allows at most 128 MiB RSS, 128 FDs and 32 threads, with median final RSS no
  more than 16 MiB above the 20–40-second warm window. Latency histograms are bounded.
- Completion requires zero ordinary request errors, at least 10 completed
  requests/second, sustained switch/rollback progress, multiple real renewals and
  observed configuration commits during issuance. The server then drains and
  restarts, reusing the exact durable certificate and account.

This is a regression/soak workload, not a maximum-throughput benchmark. It does
not simulate many distributed attackers, public-network failures, long CA outages,
clock jumps, slow/hung disks, machine power loss, or a deployment's actual content
and network. Files are immutable throughout. Platform-specific capacity and
supervisor/alert behavior still need a staging test on the deployment host.

## Findings and corrections

The baseline at `db30db7` (production code `f42f33b`) reproduces starvation: six
slow connections from one peer occupy all four FIFO workers, and a healthy peer
times out at 1.5 seconds. See the [baseline Linux run](https://github.com/moritayasuaki/pathward/actions/runs/41190712869).

The corrected bounded queue keeps the admission limits (12 global / six per peer,
8/second per peer, 64/second global), but dispatches at most **two running jobs per
peer** and four globally. It skips temporarily ineligible peers while preserving
FIFO order within each peer, wakes on completion, and discards queued work on
shutdown. A third CA validation connection waits for a worker slot instead of
being refused; ACME receives no exemption. IPv4-mapped and IPv6 /64 keys are shared
between admission and dispatch. This prevents one peer monopolizing all workers;
it does not prove availability against multiple peers or OS scheduling delays.

Review also found that global-capacity rejections could insert new peer-table
entries. Global capacity/token/draining checks now run before insertion, so denied
new peers cannot fill the table while all slots are busy. Unit tests retain the
existing table cap/eviction checks and reproduce this denied-insertion case.

The actual Rust dispatch gate is extracted through Charon/Aeneas. Five additional
Lean statements prove exact eligibility, per-peer/global bounds after admission
to a worker, draining rejection and modeled totality; the axiom audit now covers
107 statements. Queue locking, lease cleanup, actual thread scheduling, filesystem
I/O and TLS are reviewed/tested integration code. No whole-server liveness or
OS/cryptographic correctness theorem is claimed.

No runtime, dev or build crate was added; the core stays zero-dependency. The
Python harness uses stdlib, the test driver reuses existing Rust dependencies,
and the queue uses std Mutex/Condvar/VecDeque. The fresh graph/RustSec audit found
no advisories/warnings against database
`2295466c4e9df26647fd67d8fa1c705ac2fc7f81`; see
[the machine-readable audit](../server/audit-result.json).

The test result will be recorded after the uninterrupted run completes; a short
calibration success alone does not establish the one-hour result.
