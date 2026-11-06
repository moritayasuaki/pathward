# Recovery-plan handoff and old-generation collection

`deploy/pathward_plan_migration.py` changes the plan used by an existing managed
guard without restarting its listeners. The new plan may use another reviewed
decision executable, transaction, journal, permit and sealed configurations.
Service names, OLD/NEW roles and the schema-1 unit contract must remain unchanged.
Different roles/contracts need a separate migration. Python standard library
only; the decision executable still has zero external Rust dependencies.

## Plan handoff

Both plans and their reviewed helper implementations remain available. The
target journal and boot permit must be separate from the source records and
from programs/configuration; they cannot live inside the guard/unit store.
The target's `state_seed` supplies deployment metadata. Preparation pins the
source journal and sets the target phase/transaction/plan-hash binding from
verified data. The hosting adapter must follow the active plan's journal after
handoff, rather than continuing to write the old journal.

`prepare-migration` takes `--store`, `--units`, `--plan`, `--plan-sha`,
`--candidate`, `--candidate-sha`, `--kernel`, `--kernel-sha`, and `--request`.
It stages a compatible generation and prints the sealed request hash. Retain
that hash independently. `apply-migration --request <same-file> --sha256 <hash>`
uses the shared administrator lock and can be retried after interruption.

Apply first rejects a stale source/target identity. It verifies stable service
state and unchanged source journal, creates the independent target records,
then requires both plans to select the same running service and retain a
verified OLD fallback. Only then may the epoch advance and the current pointer
switch atomically. Reload/readback and a completion receipt follow. Loaded old
definitions and new definitions authorize the same service during the overlap.
Source records, kernels and plans are not overwritten. A missing/torn target
record or changed application is not guessed from a receipt. Recovery must
settle first; a superseded or changed request is rejected.

## Collection

Collection is deliberately separate from migration. It requires a matching
completion receipt from an earlier boot, a valid current boot permit, verified
service state, matching loaded guard definitions, and no jobs for the affected
units. [systemctl's filtered job listing](https://www.freedesktop.org/software/systemd/man/latest/systemctl.html)
checks those units without being blocked by unrelated system jobs. A receipt
written only after retry in this boot requires another reboot; missing or
invalid receipt data cannot authorize cleanup.

`prepare-gc` takes `--store`, `--units`, `--kernel`, `--kernel-sha`, `--request`,
optional repeated `--keep <generation-id>`, and `--limit 1..8` (default 8).
`apply-gc --request <same-file> --sha256 <hash>` repeats the completion fence and
recomputes protection before deleting anything. The pinned current generation
must still be current. A new generation invalidates the old cleanup request.

Always retain current and immediate parent, prepared current/future epochs,
explicit keeps, and managed-store references of retained plans. Scan references
transitively and retain every helper used by any surviving generation. A new
prepared reference between planning and execution blocks deletion. Each bounded
batch can retire only older, unprotected, content-addressed generations and
their otherwise-unused helper blobs. Original releases, plans, journals,
kernels, secrets and public files outside the store are never deleted.

Members move into a request-specific private `trash` directory before removal.
The request pins manifests/unit content, so retry can verify and finish a
partially removed tree even after its manifest has gone. Unexpected members,
links or conflicting source/trash names fail closed. Missing already-collected
members are harmless. The current pointer is untouched. Staging orphans and
completion records are retained for explicit administrative inspection, not
silently swept. Plans must declare dependencies explicitly and application
programs must not hide dependencies inside this private guard store.

## Proof and validation scope

`PlanMigrationProofs` adds 14 contracts/lemmas for extracted Rust gates and 11
model statements. They prove refusal on shared records, changed roles,
disagreement, missing fallback, same-boot/incomplete/busy cleanup, protected or
external objects; handoff preservation through interrupted prefixes; protected
root preservation, transitive marking and idempotent removal.

These are not a proof of all Python/systemd behavior. Trusted boundaries include
reviewed helper semantics, correct service/boot observation, declared reference
completeness, administrator locking, SHA-256, atomic rename/fsync and storage.
Both old and new complete pointer outcomes are permitted at an unsynced crash
boundary. There are no custom Lean axioms or proof holes.

`make recovery-check` uses real files, Rust CLI decisions and SIGKILL at each
reported migration/deletion boundary. `scripts/reboot_vm.py --plan-migration`
uses a disposable NIC-free Linux VM with real systemd. Supply the pinned base
image, a verified Linux `--kernel-binary`, optional reviewed old
`--initial-kernel-binary`, and a fresh `--output` directory. The guest covers OLD
and committed NEW handoffs, changed decision binaries, six hard power cuts,
one clean reboot, reload failure, too-early cleanup rejection, future-generation
retention and retry after partial deletion. This harness changes no host or
production services.
