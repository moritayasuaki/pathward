# Explicit capacity for shared NAT

The optional first top-level KDL directive selects a finite startup profile:

```kdl
capacity "shared-nat"
site "app.example" {
    tls "auto"
    reverse-proxy "127.0.0.1:3000"
}
```

Omission or `capacity "standard"` retains the original limits. Unknown values,
duplicates, nested blocks and a directive after a site are rejected. This applies
to the whole Server, including plaintext redirects and TLS validation, before
Host selection. It is not a per-host policy or an authentication mechanism.

| Admission resource | Standard | Shared NAT |
| --- | ---: | ---: |
| Global admitted/queued connections | 12 | 256 |
| Per-peer admitted/queued connections | 6 | 192 |
| Pending dispatch queue | 8 | 252 |
| Global connections/second | 64 | 512 |
| Global burst | 128 | 512 |
| Per-peer connections/second | 8 | 256 |
| Per-peer burst | 16 | 384 |

Both profiles retain four ordinary workers, at most two running jobs per peer,
256 peer-table entries, the existing socket deadlines and independent service
and streaming budgets. IPv6 peers share a /64; mapped IPv4 shares its IPv4 key.
Forwarded headers never select an admission identity. The larger queue stores
owned sockets/permits, not parsed request bodies. It does not create a thread per
connection, increase ordinary response buffers, or promise that queued work will
finish before its original deadline. Kernel socket buffers add deployment-specific
memory overhead. Keep process/FD/memory/CPU limits and measure their effects.

The larger peer burst accommodates a reviewed 24-client cold-asset workload;
it also permits a larger unauthenticated burst. Select it only after assessing
the deployment. It is not a guarantee of 24 users for every application, network,
storage device or workload. Distributed floods can still consume global budgets.
The scheduler leaves workers available to other peers, including CA validation;
that is not an availability guarantee under arbitrary load.

The browser-reload revision raises the shared-NAT refill rates from
128/64 to 512/256 global/per-peer connections per second. A 24-browser
game reload produced repeated image fetches over several seconds, beyond the
earlier one-off asset burst and 700 ms polling simulation. The old profile
exhausted peer credit even with normal browser caching. This quadruples the allowed
sustained unauthenticated connection rate. Admitted/queued limits also grow from
192/144 to 256/192 globally/per peer, with a 252-socket queue, to allow
old and new browser connections to overlap on reload. This adds 64 globally
admitted sockets (33%); peer occupancy still cannot consume the whole global
budget. Burst credit, workers, body limits and deadlines remain unchanged. A deterministic 20-second
200-request/second peer wave also checks progress for an independent 100-request/
second peer. This regression is a capacity envelope, not a browser model.

Capacity changes require a restart. Both SIGHUP and managed activation reject a
different profile before committing; managed activation rejects it before writing
current/previous configuration. Rollback follows the same rule. Token credit,
queued work and admission counts are not reset by ordinary config changes.
The publication generator preserves the chosen profile. Changing only file grants,
routes or headers keeps the usual transactional reload behavior.

Metrics expose `pathward_admission_{global,peer,queue}_limit`,
`pathward_admission_{global,peer}_rate`, and
`pathward_admission_{global,peer}_burst` as fixed gauges. Existing aggregate and
reason-specific rejection counters remain unchanged. No peer or request labels
are added.

## Verification and audit scope

The actual Rust extraction supplies profile bounds, rejection classification and
the startup-identity comparison. Seventeen additional Lean statements establish
finite capacity/credit arithmetic, queue-plus-workers consistency, a strictly
smaller peer cap, equivalence of the standard profile to the old gate, drain and
exhausted-credit rejection, bounded diagnostic codes, totality and unchanged
capacity on accepted reload. The complete audit contains 275 statements. This
does not formally verify the KDL adapter, locks, sockets, clocks or OS resources.

KDL surface review covers one optional flat node before the bounded site list,
one decoded string argument, canonical enum matching and fail-closed handling of
duplicates, malformed/nested/unknown settings. Generator and both activation
paths preserve or check the capacity identity. Native Linux tests cover rejection
before durable writes, 24 simultaneous clients, the 192-peer bound, healthy-peer
progress behind slow sockets and shutdown. The existing standard-profile tests
remain in CI. No package, feature, manifest, lockfile or vendored source changes
are required.

Application capacity must be reported separately from synthetic regression tests:
record the fixture hashes, source/binary identity, client count and source-IP
grouping, concurrency and polling schedule, cold/warm cache behavior, reconnected
clients, failures without automatic POST retry, certificate changes, config
commits during actual ACME orders, latency and resource ceilings. Local-CA and
loopback results do not establish public-network or public-CA behavior.

The subsequent [real-browser rehearsal](browser-capacity.md) exercises actual UI
entry and repeated reloads, and explains why this profile now has additional
headroom. The historical protocol-client results below used the original smaller
shared-NAT limits; they do not retroactively validate the new bounds.

## Completed application capacity rehearsal — 2026-11-02

The [sanitized result](nat-capacity-result-2026-11-02.json) records a 24-user target
on a private Linux staging instance with two independently launched room-server
versions, synthetic rooms and captured public frontend assets. No production
rooms, photos, configuration or listeners were changed. The test used only Python
stdlib clients and existing reviewed binaries; application code/assets are not
included in this repository.

The original standard gate was the bottleneck. With the application's 700 ms
polling interval, 12 users behind one address completed 170/336 requests and
24 completed 169/672. The rejected connections were classified as `peer_rate`.
The same 24 users with distinct source addresses completed 672/672. Six users
completed a short 168/168 comparison, but the initial burst makes that result
insufficient to establish sustained six-user capacity.

| Workload | Standard baseline | Shared-NAT candidate |
| --- | ---: | ---: |
| 12 users, same address, short polling comparison | 170/336 | 336/336 |
| 24 users, same address, short polling comparison | 169/672 | 672/672 |
| 24 users, distinct addresses | 672/672 | 672/672 |
| 24 cold entries, six concurrent asset connections per client | 20/384 | 384/384 |
| 24 synchronized reconnecting clients | 105/408, 12 s offered | 2,040/2,040, 60 s offered |
| 24 users, six active game rooms, 480 s offered polling | Not run | 16,440/16,440 |

The baseline used HTTP without reload or CA traffic. Its binary source was
`5713fab73b89ab66244432a9ddc12be5ce57128b`; all production sources/manifests/lockfiles
match merged main `56b1f7662a538b5b5383ba5245afb21591573f5f`. The candidate used TLS
with chain/hostname verification and overlapping configuration/ACME work. The
baseline cold phase joined existing rooms; the candidate created six new rooms
and joined three guests to each. These are diagnostic workload comparisons, not
identical transport-latency benchmarks. No POST was retried.

Candidate runtime source `b2ade498c707d0871b6acff5cdbcf781d144938c` passed
[Linux integration, Lean and dependency CI](https://github.com/moritayasuaki/pathward/actions/runs/41380338321).
The [exact-source artifact](https://github.com/moritayasuaki/pathward/actions/runs/41380338214)
and every binary were SHA-256 checked before use. Its 628.623-second report
contains 20,712 successful phase requests, 306 acknowledged configuration
switches, 15 observed certificates (initial issuance plus 14 renewals), and 40
configuration commits during an actual ACME order. Switching alternated public
roots, response headers and backend discovery order. Every acknowledged release
was checked with a fresh marker/header request and a denied private canary;
authenticated polls checked room identity, actor identity and monotonic revision.

Admission rejection, queue overload, request I/O error, 5xx, ACME error and log
drop counters stayed at zero. The 306 expected 404s were private-canary checks;
44 rejected profile-changing activations preserved the generation, digest and
durable configuration. Startup-inclusive TLS errors were 24 while the readiness
client waited for the first certificate; each measured phase's TLS error delta
was zero. Those startup errors are retained in the result, not reported as zero.

Steady-game polling p95 was 22.674 ms; synchronized reconnect p95 was 299.568 ms.
All 24 cold entries completed within 6.993 seconds; individual cold-request p95
was 1,619.824 ms. Each cold client fetched the root, JS, CSS and twelve sprite
sheets with no browser cache before its create/join request. Asset hashes and
four members per room were verified before starting games.

The entire isolated process group (clients, both backends, CA and PathWard) shared
one CPU core's quota, 512 MiB memory and 256 tasks. Sampled cgroup peak memory was
91.13 MiB; this is the last observed lifetime peak before unit cleanup. Across
627 one-second PathWard samples, peak RSS was 16,856 KiB, FDs 112 and threads 28.
Median RSS grew by 52 KiB between the 100–160 s and 550–610 s windows; median FDs
remained 13. All child processes exited zero, both temporary units became inactive,
and the owned private directory, including test keys, was removed. Production
Caddy configuration hash, adapted routes, service PIDs and TCP listeners matched
their pre-test inventory.

This establishes the requested polling/cold-entry/reconnect target in the measured
environment. It is not 24 interactive browser renderers, public-network latency,
public-CA issuance, maximum throughput or a long-duration endurance run. The local
CA used real TLS-ALPN-01 validation with 60-second certificates. WebSocket/SSE
quotas remain 16 globally and eight per peer; this test makes no 24-stream claim.
Public TLS/CA validation and deployment-specific operational/recovery checks
remain production migration gates.
