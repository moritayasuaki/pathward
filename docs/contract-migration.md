# Native service-role and startup-contract migration

`admin/` builds `pathward-admin`, a Rust administrator and boot-recovery program.
It imports a stable, completed PR #15 managed guard and can then change service
names, OLD/NEW roles, unit definitions and `simple`, `exec` or `notify` startup.
Migration drains all affected services before changing their contracts. Plan a
maintenance interval: this operation has a deliberate service interruption.

The new migration, gates, watchdog and boot/failure recovery do not invoke
Python. The legacy helper and records are retained as evidence; its systemd
units are masked and its generation pointer becomes an unsupported-schema
tombstone so old administrator/update/GC commands fail closed.
[Native publication and retention](native-publication.md) now supplies the Rust
bridge, publisher and bounded collection of retired native/legacy generations.
Existing installations need a reviewed service/publisher migration; initial
provisioning and historical verification/tooling still use Python. Do not delete
preserved source plans, resources, engines or transactions manually.

## Reviewed inputs and commands

The CLI requires Linux root. Every mutation shares the existing
`/run/pathward-migration.lock`; `gate` is read-only and needs no lock. Review a
private JSON input and retain its SHA-256 independently, then run:

```
pathward-admin --root /opt/pathward-native prepare /root/role-input.json INPUT_SHA256
pathward-admin --root /opt/pathward-native apply REQUEST_SHA256
pathward-admin --root /opt/pathward-native status
```

Preparation prints `PREPARED_NATIVE_REQUEST` and the exact sealed request hash.
It does not stop a service or install systemd definitions. Retry `apply` with the
same root/hash after interruption. A different current parent rejects a stale
request. A completed retry checks the loaded contract, service state and health
without restarting the listener. `recover` is an explicit recovery operation;
`boot`, `fallback` and `watchdog` are installed systemd entry points.

The first input contains `source_legacy: {store, plan, sha256, health: {old, new}}`.
The source must have a matching managed generation, completion receipt, private
journal, current-boot permit, installed links, stable service states and a
successful health check. Existing unit fragments and declared resources are
captured; only the reviewed legacy recovery drop-ins are accepted. Later inputs
use `source_current: REQUEST_SHA256` and derive the source from that completed
native transaction.
Original legacy resource hashes are checked before capture and remain pinned;
reviewing a target never authorizes replacing the source's expected hashes.

`target` contains `selected: "new"` and two roles `old` and `new`. Each role has:

- `units`: one to three unit names, each mapped to `{path, sha256}` for a reviewed
  template. Names are literal `.service` names; aliases and templates are refused.
- `files`: absolute path to SHA-256 mappings for the application executables,
  configuration and validation programs. Live systemd unit paths are excluded:
  their full contents are already captured in the immutable request.
- `check`: an argument array for bounded configuration validation.
- `health`: an argument array for bounded running-service validation.

Programs are executed directly, without a shell. Inputs must be root-owned,
non-writable by others and available on the root mount. The request and state
are private, bounded, checksummed JSON; duplicate keys and malformed envelopes
are rejected. Hashing uses the exact opened file, and preparation flushes both
the inode and every ancestor name. Both source and target unit sets are checked
by `systemd-analyze verify` before a request can be applied.

There is one application command per unit. `forking`, startup/cleanup hooks,
alternate roots and delegated cgroups are refused. The installed gate runs
before application code and forces control-group termination. Startup/stop
deadlines are bounded; arbitrary systemd contracts are not silently accepted.
All resource dependencies must be declared and validators must be reviewed.
Unit definitions and application/validator programs are trusted not to control
undeclared services or resources; this is not a general systemd policy sandbox.
The lifetime union is bounded to 24 service names per native store.

## Ordering and recovery

1. Persist the source/target request, executable and active request pointer.
2. Persist and enable independent native boot recovery, failure recovery and
   watchdog definitions. Existing source service processes remain active.
3. Install and read back native gates for all affected loaded services, closing
   legacy automatic/socket activation paths before draining.
4. Record the incomplete operation, arm the watchdog, revoke the boot permit,
   stop every affected service and verify no active/transitioning state or job
   remains. Failure to drain prevents any contract replacement.
5. Fence the legacy administrator. Install gates before changed unit fragments,
   reload systemd and verify its loaded gate arguments/drop-in paths.
6. Publish a trial permit for only the target primary role. Start that role;
   require exclusive service state, health, fallback validation and loaded
   contract agreement before durably recording completion.

A boot before durable completion restores the independently captured source.
A completed boot selects the verified target primary; startup failure selects
the verified target fallback, with the preserved source as the last verified
alternative. No valid alternative means no start authority. A permit is bound
to this boot, request, role membership, phase and installed contract. Unit files
may be partly replaced after a power loss: recovery repairs the complete set
before publishing another permit.

The systemd watchdog first runs after 180 seconds and retries every 60 seconds
while armed. It can recover an incomplete operation after the administrator
process exits. It cannot undo a committed transaction. The shared lock prevents
it racing a live administrator; OS scheduling and real-time restoration bounds
are not formally proved. A boot does not reuse volatile permits from `/run`.
Failure callbacks retry shared-lock contention after two seconds; malformed
records or a deliberately held recovery do not request that retry. The callback
uses `Type=exec` and a bounded runtime because systemd 255 refuses forced exit
status retries for oneshot services. Native engine replacement is intentionally
refused by this migration: upgrading that pinned executable needs a separate
reviewed handoff.

## Evidence and trust boundaries

`make admin-check` uses real files, actual Rust predicates and process SIGKILLs,
with service commands modelled separately. `scripts/reboot_vm.py --role-contract`
uses an existing pinned NIC-free Ubuntu image, real systemd, native fixture and
guest binaries, plus the old helper only to establish the migration source.
The fixture covers role reversal, startup mode change, renamed roles, cold-boot
recovery, primary failure, partial writes, stale requests and denied retired
starts. No host service or production file is changed by the VM controller.

`ContractMigrationProofs` contains 27 extracted Rust contracts/lemmas and eight
transition-model statements. Partial installation is explicitly modelled;
installation needs revoked permits and drained services. Every model prefix,
including process exit and reboot, preserves contract/permit agreement and the
source/rescue resources. These are not full proofs of the Rust filesystem/JSON/
systemd adapter. Trust boundaries include compiler/extraction, declared resource
completeness, systemd's reported state and loaded definitions, the shared lock,
root ownership, SHA-256, fsync and the physical storage device.

The administrator reuses pinned `serde`, `serde_json`, `ring` and `rustix` from
the existing reviewed server graph: 36 resolved external packages across all
platforms, no new package versions, fewer enabled features. The proved Rust core
remains dependency-free. Reviewed graph and RustSec results are recorded in
`admin/reviewed-graph.json` and `docs/contract-migration-audit.json`.

Systemd semantics were checked against the official
[service manual](https://www.freedesktop.org/software/systemd/man/255/systemd.service.html)
and [systemctl manual](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html).
Native file locking follows the documented [Rust File API](https://doc.rust-lang.org/std/fs/struct.File.html).
