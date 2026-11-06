# Durable boot selection and interrupted writes

The recovery executable is a separate, dependency-free Rust binary. The stdlib
Python adapter in `deploy/pathward_recovery.py` calls its extracted decisions.
It does not depend on the candidate HTTP/TLS runtime being able to start.
The deployment repository owns the concrete service names and sealed plan.

An immutable, private plan pins the transaction, recovery executable, candidate
files, old configuration and validation commands. A separately stored journal
contains a canonical JSON payload and SHA-256 checksum. Root ownership, private
modes, single-link regular files, no-follow opens, size limits and duplicate-key
rejection are checked. SHA-256 detects corruption; it does not authenticate a
root attacker who can rewrite the plan, executable or service definitions.

On cold boot, a valid matching committed record and a validated candidate select
the new service. Missing, truncated, checksum-invalid, stale-transaction or
pending records select the separately verified old service. Neither verified
target, or an invalid plan/executable, causes startup to fail closed. Temporary
files are never promoted. Even a complete orphaned commit file is ignored.

The writer creates a unique private sibling, writes and fsyncs it, renames it,
and fsyncs the parent. A killed writer can leave harmless orphans; these cannot
block later writes as the old fixed `.next` name did. Record writes and program/
unit installation share the reviewed replacement primitive. A crash before
directory synchronization can recover the prior or new record; corruption or
loss of the journal falls back through the independent plan. Media loss of both
plan and verified old configuration is not recoverable by this mechanism.

`pathward-recovery.service` is persistent and orders both public services after
boot arbitration. Start gates check a private permit bound to the plan and the
current boot ID. Conflicting service units prevent the old and new listeners
from remaining active together. The arbiter queues its selected service with
`--no-block` so that a dependency waiting for the arbiter does not deadlock it.
Enablement symlinks are not the source of truth. A same-boot trial has its own
short-lived permit; it cannot authorize the candidate after a cold boot.

The read-only `ExecStartPre=+... allow-*` gate runs as root because the plan and
permit are private. Only this pre-start check gets the prefix; the actual
server retains its dedicated unprivileged user and sandbox. The gate validates
the sealed plan and invokes only the checked, dependency-free decision binary.
The VM fixtures also run as an unprivileged user so this boundary is exercised.

`OnFailure` can recover to verified old configuration after actual candidate
startup failure. This requires the new permit from this boot/plan, observed
failed service state, and a verified old configuration. Rollback intent is
persisted before changing services. The ordinary delayed watchdog still
preserves a matching committed transaction. No availability or bounded recovery
time is proved when validators, the OS, storage or the old service fail.
The ordered candidate/bridge stop has a separate 300-second wait (covering the
140-second public-server and 90-second bridge grace periods), and the fallback
unit allows 480 seconds overall. A stop timeout never publishes an OLD permit.
Deployments with longer stop sequences must review these bounds before use.

The hosting adapter installs the disabled candidate's gate first, then durable
boot units and their enablement link, and only then Caddy's gate. The active
old service remains the fallback during initial preparation. Updating an
already installed boot arbiter is a separate migration and is rejected by the
initial installer; see `RECOVERY-UPGRADE` in the proof roadmap. This is a
candidate implementation, not an update to an existing production installation.

## Proof and test boundaries

`RecoveryProofs` proves the actual Rust selection, exclusive start permission,
stale-boot/stale-plan rejection, trial deadline, and verified-failure fallback
conditions. The storage model separately proves that staging and file fsync
alone cannot promote a commit; only a committed visible/durable name can select
the verified candidate. OS durability, JSON/checksum interpretation, Python
control flow and systemd scheduling remain explicit trusted boundaries.

`make recovery-check` kills real writer processes at all six persistence
boundaries, rejects every truncated prefix and malformed/linked record, checks
stale permits, and exercises the actual decision binary over all Boolean inputs.
`scripts/reboot_vm.py` is an opt-in test using preinstalled QEMU and a disposable
Ubuntu Minimal 24.04 image. It has no virtual NIC, never installs host packages,
and only kills QEMU processes it started. It exercises real systemd cold boots,
hard power cuts before/after rename and fsync, a torn journal, failed candidate
startup, and an invalid plan. The services are isolated HTTP fixtures, not a
production-site compatibility or public-CA test.

The fixture image is the official amd64 20261105 release, SHA-256
`406630c08b5e545fcc7209854b129d47e3af822db128c9f19336593b5a2d3fe0`.
VM results are recorded separately after execution. Production Rust dependencies
are unchanged; the new decision binary has zero external dependencies. The
latest [audit record](boot-recovery-audit.json) covers all four existing profiles.

Primary references: [systemd unit dependencies](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html),
[Ubuntu image and checksums](https://cloud-images.ubuntu.com/minimal/releases/noble/release/),
[NoCloud local configuration](https://docs.cloud-init.io/en/latest/reference/datasources/nocloud.html).
