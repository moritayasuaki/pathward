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
- After **every acknowledged** activation or rollback, the switching thread
  opens ten new TLS connections before its next switch: GET/HEAD `/`, the new
  published URL, the revoked URL, and the configured redirect, for each host.
  Expected content/headers/redirects come from the acknowledged configuration
  digest, not the response's release header. Revoked URLs must return 404; the
  status digest must remain unchanged through these probes. Concurrent requests
  that began before a switch may still finish on their old coherent snapshot.
  Rollback acknowledgements must match the previous successful release.
- Traffic alternates omitted Host ports with explicit public 443/80 while the
  actual sockets use ephemeral internal ports. Initial negative probes reject
  internal/wrong ports even with a forged X-Forwarded-Port header.
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
  A final sample is taken before stopping the server, and the final RSS growth
  and resource ceilings are checked again **before writing any passed report**.
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

## Review follow-up — 2026-11-01

The public-port adapter previously compared Host ports with the internal socket
port. Valid `Host: example.com:443` behind 443→8443 forwarding (and :80 behind
80→8080) received 400. The adapter now calls the extracted `authority_port` and
`authority_port_allowed` gates. Nine new Lean statements establish TLS/redirect
port selection independent of the internal port, exact optional-port matching,
zero-port rejection and totality. The axiom audit covers 116 statements. Header
parsing and selecting trusted transport-mode inputs remain tested adapter code.
No forwarded header affects endpoint selection, and wrong explicit ports still
fail closed. Native Linux response tests and the actual local-CA TLS lifecycle
exercise the adapter, in addition to the soak.

The review also found two test blind spots: coherent responses from a stale
release passed the concurrent-load oracle, and the final minute's RSS growth
was reported without an end-of-run assertion. The acknowledged-release probes
and final resource gate above close these gaps. `make soak-check` runs five
stdlib-only regressions that reject stale content/headers/redirects, retained
revoked URLs, missing samples and final-minute growth above 16 MiB. It is part
of both `make check` and `make soak`. These were test weaknesses, not observed
stale serving or a measured memory leak in the preceding one-hour run.

No package, feature, lockfile or vendored source changed. Fresh dependency
graph/RustSec audit results remain in `server/audit-result.json`. The earlier
one-hour record below is retained as historical evidence; new results are
recorded separately below.

## Completed review-fix one-hour run — 2026-11-01

The [revised one-hour Linux run](https://github.com/moritayasuaki/pathward/actions/runs/41289195101)
passed all six checkpoints, final resource validation, graceful shutdown and
durable restart reuse at source `c72fc5bc7f989ed226682b043eec731e7176ee69`.
The same source passed [full Linux integration, Lean and dependency CI](https://github.com/moritayasuaki/pathward/actions/runs/41289195140),
including mount confinement, CLI/admission tests, actual TLS-ALPN-01 renewal and
persistence-failure tests, and the new public-port cases. Its two-minute overlap
test passed 121 commits, 1,210 acknowledged-release probes and 242 revoked-URL
checks. The five oracle regressions also passed on Linux.

The [machine-readable one-hour record](soak-result-2026-11-01.json) contains the
original report and workflow links. The runtime and test sources in this record
are unchanged by the later documentation/result commit.

| Observation | Result |
| --- | --- |
| Uninterrupted offered-load duration | 3600 seconds; report elapsed 3602.509 seconds includes shutdown/restart |
| Verified ordinary-load requests | 57,598, including 21,600 expected denials |
| Fresh requests after acknowledged switches | 36,010 across both hosts; all 3,601 acknowledged switches checked |
| Revoked-URL checks | 7,202; included in the fresh-request count |
| Total verified requests / unexpected failures | 93,608 / 0 |
| Managed commits / rollbacks | 3,601 / 900; rollbacks are included in commits |
| SIGHUP signals / stale-command and private-root rejections | 328 / 721 each |
| Commits observed during an active ACME order | 617; includes SIGHUP commits |
| Certificates observed / renewals after initial issuance | 81 / 80 |
| ACME errors, log drops, 5xx, ordinary request I/O errors | 0 |
| Slow-peer connection cycles | 2,182 |
| Ordinary-load latency p50 / p95 / p99 bucket upper bounds | 50 / 100 / 100 ms; histogram excludes the fresh switch probes |
| RSS peak / final median growth from warm window | 6,720 KiB (6.56 MiB) / 224 KiB; final gate passed |
| FDs peak / threads | 26 / 12; thread count stayed constant |
| Graceful shutdown | 0.414 seconds |
| Exact durable certificate and account reused after restart | Passed |

Environment: GitHub-hosted Ubuntu 24.04 x86-64, reported kernel
`Linux-7.0.0-1017-azure`, glibc 2.39, pinned local Pebble CA. This is the same
bounded regression workload with additional verification traffic, not a
maximum-throughput benchmark. Partial attacker TLS failures and intentional
configuration rejections are expected. Final metrics are the last periodic
scrape; controller counters continue through completion. The real-host,
network/storage-failure and operational limits described above still apply.

## Completed one-hour run — 2026-10-31

The [extended Linux run](https://github.com/moritayasuaki/pathward/actions/runs/41191573153)
passed every 10-minute checkpoint and the final shutdown/restart checks at source
commit `ea1914f2014fc81e58375c444342f35e1981bfe4`. The same source also passed
[the full Rust/Lean/ACME/dependency CI](https://github.com/moritayasuaki/pathward/actions/runs/41191573115).
The [machine-readable result](soak-result-2026-10-31.json) preserves the final
reported counters and histogram, with links to the original job logs.

| Observation | Result |
| --- | --- |
| Uninterrupted offered-load duration | 3600 seconds; report elapsed 3602.732 seconds includes shutdown/restart |
| Verified requests (including expected denials) | 57,604; zero unexpected failures/content combinations |
| Managed configuration commits / rollbacks | 3,601 / 900; rollback commits are included in the commit count |
| SIGHUP reload signals | 328 |
| Rejected stale / private-root updates | 721 / 721 |
| Commits observed during an active ACME order | 612 |
| Certificates observed / renewals after initial issuance | 81 / 80 |
| ACME errors, log drops, 5xx responses | 0 / 0 / 0 |
| Slow-connection cycles | 2,182 (six incomplete TLS/HTTP connections per cycle) |
| Request latency histogram p50 / p95 / p99 upper bounds | 50 / 100 / 100 ms; all observed requests were in buckets ≤100 ms |
| Server RSS peak / final median growth from warm window | 6,736 KiB (6.58 MiB) / 240 KiB |
| FDs peak / threads | 27 / 12; thread count stayed constant |
| Graceful shutdown | 0.464 seconds |
| Restart with exact durable certificate and same account | Passed |

The test ran on a GitHub-hosted Ubuntu 24.04 x86-64 runner; the reported kernel
was `Linux-7.0.0-1017-azure` with glibc 2.39. TLS handshake errors from deliberately
incomplete attacker connections and rejection counters for deliberately invalid
configuration commands are expected. They are not ordinary request/ACME failures.
`final_metrics` is the last periodic scrape, while controller/log counters are
collected through the end of load, so their final counts can differ by the last
few operations. Histogram bounds are not exact percentile measurements.

This result establishes that this workload passed on this source/environment.
It does not establish absence of all leaks or availability under arbitrary load,
and does not replace a staging test with the deployment's content, filesystem,
network, access rate and supervision.
