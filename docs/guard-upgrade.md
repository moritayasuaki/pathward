# Recovery guard updates and interrupted retries

`deploy/pathward_guard_upgrade.py` updates an existing schema-1 recovery guard
without stopping listeners, changing enablement, or writing the application
journal, plan or boot permit. It uses Python's standard library and the
dependency-free `pathward-recovery upgrade` decision CLI.

The administrator supplies reviewed, root-owned helper files and independently
retained SHA-256 digests. A hash pins reviewed code; it does not prove arbitrary
Python code safe. The plan, its decision kernel, service names and generated
unit contract must remain the same. Upgrades to a different plan/contract are
refused. Use a separate migration for those changes.
Candidate source is compiled directly from verified bytes: timestamp/size-matching
Python bytecode caches cannot substitute different code for the pinned source.

## Durable layout and ordering

The private store contains content-addressed helper blobs, immutable generation
directories, a `current` symlink, and an informational `last-applied.json` receipt.
Every generation includes its epoch, parent identity, pinned plan/helper, and
the complete boot/fallback unit and both start gates. Old generations and
original helper releases are retained. There is deliberately no automatic GC.

Preparation copies and verifies the helper, validates the compatible unit text,
fsyncs all generation files/directories, and writes a sealed request. Existing
generations must match exactly. Temporary staging directories left by a killed
writer are ignored. Preparation does not modify installed service paths.

Applying the request holds the same administrator lock used by migration and
recovery. Its retained hash and envelope are checked against the same private
inode read, with trusted ancestors, so a later pathname replacement cannot
substitute different decoded content. It requires a stable terminal transaction
with the matching boot
permit and service states. Pending cutover/rollback, missing verification,
changed units, stale base or competing target identities are rejected.

For a legacy direct-file installation, the first pointer names an exact copy of
the old definitions. Installed paths are converted one at a time to links via
that pointer. Any interrupted mixture therefore still has the old content.
Only after every link is durable may `current` advance to the ready next
generation by one atomic rename and directory fsync. The old generation is
never overwritten. An interrupted activation may recover the old or new
pointer, both complete. Missing/corrupt authoritative state is not guessed
from the completion receipt.

`daemon-reload` follows activation, and loaded command definitions must contain
the expected helper and plan digest before recording completion. Loaded old
definitions remain usable during this interval because they reference retained
immutable helpers under the same plan/permit contract. A reload failure leaves
the new durable pointer in place; repeating the same request finishes reload
and the receipt instead of rolling back. An already superseded request cannot
replace a later generation, even when its receipt is missing or torn.

## Administrator interface

Run `python3 -I deploy/pathward_guard_upgrade.py prepare --help` for the required
paths and hashes. The store and service directory must be root-controlled;
all supplied paths must be absolute. The decision binary must include the
`upgrade` operation; this can be separate from the unchanged kernel in the
existing recovery plan. Preserve the existing helper and its parent release.
The store must be on the root mount with no symlink ancestors; separate and
bind mounts are rejected because linked unit definitions must be readable while
systemd constructs boot jobs. This follows the [systemd linked-unit rules](https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html).
Executable and plan paths also require administrator-controlled ancestors.
Writable non-sticky ancestors and symlink ancestors are rejected before helper
import or execution; retaining a file hash alone would not prevent path replacement.

`prepare` takes `--store`, `--units`, `--plan`, `--plan-sha`, `--legacy-helper`,
`--legacy-sha`, `--candidate`, `--candidate-sha`, `--kernel`, `--kernel-sha` and
`--request`. It prints `PREPARED_GUARD_UPGRADE <request-sha256>`. Retain that hash
independently. `apply --request <same-private-request> --sha256 <retained-hash>`
prints `APPLIED_GUARD_UPGRADE` only after pointer readback, reload and validation.

After interruption, use that same `apply` request and hash, including after
reboot. Do not generate a fresh request merely to retry: that would describe a
new transition. A stable state must be restored first if application recovery
is still in progress. A different administrator update may make the old request
stale; rejection then requires inspection of the current generation.

The site-specific adapter must recognize the managed current generation when
checking its recovery preflight. Its store location is deployment-owned. This
repository supplies the generic protocol, not a production installation step.

## Proof, audit and isolation

`GuardUpgradeProofs` checks twelve extracted Rust contracts/lemmas and eight
transition-model statements: readiness, exact successor, overflow rejection,
identity conflict/stale rejection, finish-only retry, monotonic epochs, and
application-state preservation across finite interrupted prefixes. The model
counts epochs at durable/acknowledged boundaries. An unsynced pointer observation
is not an acknowledgement: a power cut after rename may recover the base or
target. A separate model theorem checks that either result uses a complete
bundle and preserves application state; receipt writes never decide selection.
The model
assumes durable immutable bundles and atomic pointer replacement; Python/OS/
systemd refinement is still `DEPLOY-CRASH` work. SHA-256 collision resistance,
root-controlled ancestors, trusted code and cooperative administrator locking
remain boundaries, not Lean axioms silently added to a theorem.

`make recovery-check` includes process-kill injection at every recorded write,
adoption, activation, reload and receipt boundary. It exercises the real Rust
CLI and real files while mocking service commands. It also covers competing
requests, missing receipts, stale retries, corrupt members and pending trials.

`scripts/reboot_vm.py --guard-upgrade` uses the existing pinned, NIC-free Ubuntu
image and a verified CI Linux decision binary. It checks actual systemd,
unprivileged loopback listeners, five hard-power-cut boundaries, retry after
reboot, stale/corrupt candidate rejection, and retry after a reload failure.
It covers stable OLD and committed NEW, including a clean reboot in NEW.
Service PID and application files must remain unchanged during each live update.
Host packages are not installed and host/production services are not changed.

No Rust/Python dependency was added. New subprocesses use fixed argv without a
shell; decisions come from the pinned Rust executable. Plan/request reads use
private checked envelopes, no-follow regular-file checks and bounded JSON from
the existing adapter. Unexpected links/members, modified sources, unsupported
unit contracts and failed durability checks abort activation. Physical media
failure, root compromise, full-disk recovery and safe old-generation GC require
separate operational work.
