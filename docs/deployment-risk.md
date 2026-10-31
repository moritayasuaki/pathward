# P0.3 deployment risk assessment — 2026-10-31

This assessment precedes implementation of the four production basics. The
highest risks are accidental publication and a deployment reporting success while
the durable configuration and active server disagree. The design keeps the
existing no-symlink file policy; it does not follow a `current` link.

| Risk | Severity | Required mitigation |
| --- | --- | --- |
| Recursively generating grants publishes secrets/build debris | Critical | Read an explicit bounded file manifest; never discover files recursively. Reject hidden/traversal/duplicate entries. Root aliases require an explicit listed index. |
| A reviewed config grants a different file or extra URL | Critical | Deterministic rendering, round-trip compilation, extracted generation gate tying each mapping to its exact manifest entry; preserve other sites and policies. |
| Symlink/hardlink or pathname replacement escapes the release | Critical | Use the same pinned-root/openat2/metadata gate for preflight and serving. No weaker deploy opener. Keep release directories immutable and service controlled. |
| Concurrent deploy overwrites a newer release | High | Require an expected active configuration SHA-256, serialize reload/deploy, compare under the commit lock, and acknowledge the resulting generation/revision. |
| Crash or fsync failure splits durable and active state | High | Save the pre-attempt config, durably replace the managed config before activation. Restore the old durable config on failure; stop serving if recovery fails. On restart validate the last durable config. |
| Rollback resurrects missing/unsafe files | High | Treat rollback as another checked transaction, with the same expected revision, root/file/identity/isolation checks. |
| A local control endpoint becomes a remote administration API | Critical | Optional Unix socket inside a service-owned 0700 directory, socket 0600, directory lock, bounded protocol/deadline. No TCP administration or shell execution. Same UID/root remain trusted. |
| Private config, backup or ACME keys become public | Critical | Keep managed control storage and ACME cache disjoint from every candidate public root. Reuse audited descriptor-relative 0600 storage. |
| In-place content edits bypass config review | High | Config revision identifies configuration bytes, not immutable file contents. Require immutable versioned release directories; no claim that file metadata establishes content provenance. |
| Old requests or old releases vanish during switch | Medium | Pin the complete old snapshot until its requests finish. Never automatically delete release directories; retention/GC is an administrator operation. |

The manifest author decides what is public: a valid name such as `secret.txt`
cannot be identified as confidential from its spelling. Generation does not
replace review of the explicit manifest. It does not copy/build content, install
packages, run hooks, change DNS, or modify another web server.

A disk rename and an in-memory pointer cannot be one atomic OS transaction.
During a successful switch, the new durable config can precede the live commit;
a crash then restarts from that new, validated config. An acknowledgement is sent
only after both steps succeed. A lost acknowledgement requires querying status,
not blindly replaying an update. The backup is the config before the most recent
attempt, not an unlimited release history. Filesystem durability and process
scheduling remain OS assumptions, outside Lean.

Implementation order: (1) fixed-origin HTTPS redirects, (2) bounded safe response
headers, (3) check/generate/managed activation/rollback, (4) connection admission,
rate control and adversarial load tests. The new pure security gates will be
extracted from Rust and proved in Lean; adapters will have Linux regression tests.
