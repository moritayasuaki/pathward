# Native preparation / wrapper review

Focused review of `bootstrap.rs`, `provision.rs`, `publisher.rs`, the new CLI,
bounded process capture and their use of existing storage/publication adapters.
This is source review and adversarial testing, not an independent audit or a
full-system formal verification claim.

No manifest, lockfile, dependency version or feature changes. The administrator
graph retains 36 external packages across all targets; the proved core has zero.
`native-bootstrap-audit.json` records the fresh RustSec scan with no findings,
warnings or ignored advisories.

The first-install input and copied members are root-owned and checksum-bound.
Existing programs are never replaced with different content. Public code and
private service state have distinct permissions. Only a check-only command runs
in preflight, under the reviewed service restrictions and an isolated network.
Rescue enablement is durable before initial gates; the current source receives
the only permit. Retry is bound to the original input and recovery request.
Public preparation also compares the exact host/address inventory with the system
resolver and requires an explicit free-space reserve before installation. The
isolated test bypass is rejected if any interface other than loopback exists.

Publication data never selects an arbitrary destination: its complete expected
description must match root-owned profile data and live routing/process identity.
SSH arguments are restricted and are not evaluated from package content. No
uploaded helper is executed. Public verification disables curl config/proxies,
requires HTTP 200 with exact body hashes for published files, does not follow
redirects, and retains normal TLS verification. Extra cross-site checks can
require exact redirect headers or a private-path 404; duplicate or different
headers fail. Loopback HTTP is explicit and constrained to high ports.

Backups and transaction intent precede live writes; resources precede HTML.
Rollback rechecks backend identity and each current file, and only restores this
operation's bytes. It refuses stale process identities and later edits. Immutable
asset collisions and unknown backend URLs fail before live mutation. An unfinished
transaction fences subsequent uploads. All writers must use the same profile and
source locks; privileged/cooperating-writer assumptions are documented explicitly.
The default executable observation is `/proc/PID/exe`. An explicit systemd
observation profile can support separate service identities; it checks one loaded
ExecStart and sealed files, but does not attest the current process image.
An explicit `current` deployment alias is resolved only as `releases/NAME` under
its reviewed base. The working directory and executable must correspond to the
pinned concrete release. The reference is included in repeated identity checks;
publication never follows this alias for destination writes.

Residual risks include administrator or deployment-account compromise, mutable
source releases, OS command behavior, filesystem durability, health-check adequacy,
public DNS/CA reachability, and changes immediately after an observation. A backend
restarted during a partial update requires operator reconciliation. The source
model proofs do not eliminate these adapter/OS assumptions. Existing production
profiles and entry points must be migrated as a coordinated reviewed change.
