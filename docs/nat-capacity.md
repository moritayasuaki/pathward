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
| Global admitted/queued connections | 12 | 192 |
| Per-peer admitted/queued connections | 6 | 144 |
| Pending dispatch queue | 8 | 188 |
| Global connections/second | 64 | 128 |
| Global burst | 128 | 512 |
| Per-peer connections/second | 8 | 64 |
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
before durable writes, 24 simultaneous clients, the 144-peer bound, healthy-peer
progress behind slow sockets and shutdown. The existing standard-profile tests
remain in CI. No package, feature, manifest, lockfile or vendored source changes
are required.

Application capacity must be reported separately from synthetic regression tests:
record the fixture hashes, source/binary identity, client count and source-IP
grouping, concurrency and polling schedule, cold/warm cache behavior, reconnected
clients, failures without automatic POST retry, certificate changes, config
commits during actual ACME orders, latency and resource ceilings. Local-CA and
loopback results do not establish public-network or public-CA behavior.
