# Administrator decision protocol

`pathward-server cutover-policy OP ARGS...` is a read-only command. It returns
exactly `ALLOW\n` or `DENY\n` with exit status 0. Malformed requests fail with a
nonzero exit status and no stdout. It performs no deployment, file writes,
network access, or privilege escalation.

| Operation | Arguments | Permission condition |
| --- | --- | --- |
| `stop-old` | pending armed preflight unchanged | All four are true |
| `window` | same-boot started-ns now-ns | Same boot, nondecreasing clock, elapsed strictly below 900 seconds |
| `commit` | awaiting verified window armed | All four are true |
| `disarm` | committed persisted-epoch current-epoch | Committed, matching epochs, current epoch nonzero |
| `watchdog` | committed prepared restored | All three are false |

Booleans are exactly `0` or `1`. Integers are canonical ASCII decimal `u64`
values: no sign, whitespace, leading zero, or overflow. Unknown operations and
extra arguments are rejected. `scripts/cutover_policy_smoke.py` exercises the
actual executable, including the deadline, reboot, stale epoch, and malformed
input cases. The protocol parser is tested, not extracted into Lean.

The command calls [the extracted Rust gates](../src/cutover.rs), with contracts
in [CutoverProofs](../proofs/CutoverProofs.lean). `ALLOW` only evaluates supplied
observations; it does not authenticate the caller or prove those observations.
The administrator adapter must use a sealed, independently verified binary,
hold an exclusive transaction lock, observe the real watchdog and services,
compare the boot ID, retain one monotonic start time, and require exact output.
Missing binaries, subprocess errors, and malformed replies must fail closed;
there is no independent Python policy fallback.

Order: persist pending intent, arm and verify the independent rollback timer,
then stop the old service. Verify the candidate before commit. Check the commit
window again after service enablement, durably write the matching commit record,
and only then disarm the timer. A delayed watchdog must re-read the record under
the same lock and preserve a committed transaction. External verification is
an operator prerequisite; the Boolean `verified` is not a signed attestation.

The process-failure model assumes atomic durable records and an independent
watchdog. It proves guard coverage and matching commit identity through any
finite sequence of the modeled transitions. It does **not** prove host reboot
recovery, partial storage writes, systemd boot ordering, Python implementation
refinement, or successful restoration of an unavailable old service. These
remain in `DEPLOY-CRASH` in the [roadmap](../proofs/roadmap.json). Manual rollback
is deliberately outside the automatic-watchdog theorem.

The hosting-specific adapter and its release packaging belong to the deployment
repository. A running release without this command must not receive the updated
adapter alone. Updating source and proving these gates does not update an
already installed administrator program.

The decision executable is also a recovery dependency: if it cannot run, the
adapter must leave the guard armed and report failure. Proving or improving
availability in that case is part of `DEPLOY-CRASH`; the pure gates alone do not
establish recovery availability.
