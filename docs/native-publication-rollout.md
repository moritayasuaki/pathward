# Coordinated publication bridge rollout

This migration replaces a legacy publication bridge while the HTTP/TLS server
and application backends keep running. Only the two bridge units enter the
recovery engine's unit universe. A committed reverse migration makes the legacy
bridge primary again, including after reboot. Neither direction requests ACME
certificates, restarts application backends, or changes listening ports.

The administrator reviews a private input and SHA-256, then uses:

```
pathward-admin --root /opt/private-publication-recovery bridge-prepare INPUT SHA256
pathward-admin --root /opt/private-publication-recovery bridge-native INPUT SHA256
pathward-admin --root /opt/private-publication-recovery bridge-legacy INPUT SHA256
```

`bridge-prepare` requires already installed root-owned binaries, profiles, old
and new policies and unit templates. The initial account identity is pinned;
new snapshot and publisher work directories get explicit unprivileged owners.
Preparation requires a reviewed free-space reserve of at least 128 MiB, checks
the existing service UID/GID, and verifies the new unit runs as that account.
It builds snapshots using the retained server binary and repeats that build
under the actual new unit restrictions with networking disabled. Preparation
then installs the existing durable recovery protocol without starting the new
bridge. It can be retried with the same immutable input. The input format and a
complete isolated fixture are in `admin/examples/support/bridge_vm.rs`.

Both contracts seal the publisher config and the private
`publication-fence.json` record. They name exactly one bridge unit each. Old and
new roles include their checked resources and a `bridge-health CONFIG MODE`
command. Health waits for a fresh receipt, checks all configured public roots and
rechecks bridge identity. Health checks must avoid pinning mutable page hashes
that would prevent later legitimate publication or reboot recovery.

Do not put live service files below `/etc/systemd/system` in a role's `files`
map, including a retained HTTP server outside the migration's unit universe.
The recovery engine intentionally rejects them. A retained service's content
can instead be checked by the role's validator: seal an immutable SHA-256
manifest and `/usr/bin/sha256sum`, and use its strict check command. This does
not add the retained service to the units being stopped or replaced. The
administrator-owned system directories and absence of stop propagation must
also be reviewed before migration; hashing is not a service dependency audit.

A deployment handoff incorrectly classified a retained live service as a
sealed resource. Preparation refused it after creating private snapshot/work
directories, while the original bridge and application processes stayed up.
The earlier route replay did not cover this deployment-specific resource map.
The regression fixture now reproduces that refusal, retries the corrected
contract in the same recovery store without replacing the publication lock,
and rejects changed retained-service bytes before switching. Corrected inputs
and manifests use new filenames; already installed runtime/profile files must
remain byte-identical. This retry is valid only before an initial request has
been bound. `initial.json` continues to reject a different initial request.

The existing role engine seals regular executable files. A narrowly reviewed
`executable_aliases` map supports an existing interpreter entry such as
`/usr/bin/python3` pointing directly to a sealed `/usr/bin/python3.12`. The alias
must be owned by the administrator, have trusted ancestors and match the exact
single-hop target; arbitrary link chains and unsealed targets are rejected.
The operating system's interpreter libraries remain trusted dependencies for
the retained legacy fallback.

## Publication exclusion and compatibility

The root-owned publisher config's `rollout` object declares `lock`,
`legacy_unit`, `native_unit`, `legacy_policy_sha256` and `native_policy_sha256`.
Each profile declares `legacy_lock: {path, owner}`. The private recovery fence
record is `{schema: 1, lock, writers: [{path, owner}, ...]}`. Existing lock inodes
are never replaced. Shared native publication leases exclude administrator
changes. The administrator also takes every existing legacy writer lock; a
native writer takes its own legacy lock. Contention refuses the operation
before service or public-file changes. Boot recovery and failure recovery use
the same fencing path.

These are advisory locks for the reviewed, cooperative deployment tools. A
deployment account with direct filesystem write access can ignore its own lock;
this is not protection from a malicious administrator or deployment account.
Retire historical deployment bundles that check bridge identity before taking
their writer lock without checking it again. Such an already-running writer is
outside this cooperative protocol. A reviewed legacy entry must observe bridge
identity while holding its existing lock and refuse a changed identity.

Native mode uses a separate **schema 2 hosting policy** and separate snapshot
state. The legacy policy stays schema 1. The routes must be equal after removing
the version and the explicit, reviewed directory-index order. The distinct
policy digest makes the existing legacy reader reject native receipts.
**Receipt schema 2 alone does not fence an old reader that ignores its schema.**
The old bridge and old local entry points remain available for rollback.

`pathward-publish mode --config CONFIG --profile PROFILE` returns either native
or legacy only when exactly one bridge is active and its receipt is recent,
belongs to that policy and was observed after the bridge's process start.
Legacy receipts must live under volatile `/run`; native receipts also carry the
current boot ID. The wrapper fails closed during transition or ambiguous/stale
state. It never silently chooses legacy after an SSH or observation failure.

Native descriptions bind policy, boot ID, process ID and start time. Switching
away and back or restarting the bridge invalidates a previously staged upload,
even when the public content is unchanged. The final public verification also
checks that process epoch before acknowledging success. A failed publication
retains the existing conditional rollback protections.

## Reviewed site differences

The profile's optional `index` must match its hosting policy. HTTP verification
checks the declared root file at both `/` and its file URL, preserving a custom
standalone entry point. Optional `reviewed_assets` allows only exact named
`.pem`, `.sig`, `.ps1` or `.traineddata` public assets explicitly present in that
site's `public_paths`. It never relaxes traversal or private-directory checks;
an unlisted file or unsupported extension remains refused. This is path/type
authorization, not a content classifier for private information.
Dependency license documents below `licenses/` may use conventional extensionless
LICENSE/NOTICE/COPYING/ATTRIBUTION names, including their `.txt`/`.md` forms,
`LICENSE-*` and `*-LICENSE`.
Interior `+` characters in versioned directory names are allowed. This does not
allow server source, private directories, dot segments or symlinks. Reviewed
immutable prefixes apply to static releases as well as backend assets.

Administrator-owned source trees stay administrator-owned. They use the separate
`manual_profiles` map, with a release profile whose workspace is the private
recovery root. The administrator first installs a reviewed ready release and
public SHA-256 manifest, then runs:

```
pathward-admin --root STORE manual-publish CONFIG PROFILE EXPECT NEXT MANIFEST SHA256
```

The command takes the same exclusive administrator lease, verifies the native
bridge epoch, exact manifest and current-release expectation, and verifies the
public response before accepting the publication. Failure uses the existing
conditional rollback. An unprivileged `describe` or `apply` cannot use a manual
profile. `mode` may inspect it without granting publication access. These
operations do not execute a helper from the uploaded release.
The cooperative Lean model includes this exclusive action without a bridge
epoch change; exclusion and epoch monotonicity hold for every modeled
interleaving including manual publication. Content changes remain subject to
the existing manifest/current-release comparison and conditional rollback.

Backend profiles can bind the service's environment using
`environment_sha256` instead of storing its text in public profile metadata.
The digest and exact `properties.Environment` are mutually exclusive. Executable,
unit, routing, isolation, PID and start time checks remain in effect.

## Verification boundary

The new extracted Rust decisions and Lean model are recorded in
`BootstrapProofs.lean` and the generated theorem registry. The cooperative
interleaving model proves exclusion and monotone epochs; its epoch is an abstract
generation, represented operationally by boot/process/start-time identity.
OS lock semantics, stable inodes, PID 1, clock observations, cryptography,
HTTP, SSH and the complete I/O-to-model correspondence remain assumptions.
Deployment-specific handoff generation and checksum validators are also outside
the extracted proof boundary. The preparation correction changes neither the
Rust runtime nor a proved predicate; its evidence is the generator regression
and Linux preparation/recovery tests, not an additional formal guarantee.

The NIC-free VM scenario accepts separately reviewed legacy bridge/reader and
retained server binaries. It records their hashes, exercises nine fixture hosts,
native publication, legacy-reader rejection, both writer locks, failed candidate
health, unchanged application PIDs, a hard power cut during unit replacement,
retry, stale upload rejection and reboot after committed rollback. A separate
deployment-specific rehearsal must check the real host routes and permissions.
Optional `--replay-policy` and `--replay-inventory` inputs replay reviewed routes
and public filenames against the retained server, using synthetic file contents.
The legacy and native builders must produce equal URL maps and configuration
directives. This checks route compatibility, not the original content bytes.

The [2026-11-07 Linux VM report](native-publication-rollout-vm.json) passed with
fixture source `874af0895321a823a20754b314d85a9090591585`: nine fixture hosts,
eight ordinary publications and one administrator-only publication, rejected
candidate health, both lock classes, one hard power cut, interrupted retry and
a further reboot after durable rollback. Application PIDs stayed unchanged
within each boot. The reviewed deployment replay covered nine hosts and 683
source filenames, with equal routes and URL-to-file maps. The VM had no network
interface. It also passed the rejected initial resource map, same-store retry
with an unchanged lock inode, and retained-service drift refusal. The three
administrator/hosting/publisher executables are byte-identical to runtime source
`5c44c935f1e980f9c4d146d991510cb196ff2257`; their hashes are in the report.
The later proof change includes administrator publication in the model.
This run also retains the old installed administrator when adding the corrected
publisher as a separately sealed resource. The candidate publisher is byte-identical
to runtime source `b38b98c44abd91fa27067d4d0549fba61b2039a0`.

Production acceptance is tracked separately from this generic VM result. Keep
the sealed legacy runtime for rollback. Updates to sealed OS executables or
service definitions need a reviewed recovery-contract migration; ordinary
package upgrades must not silently invalidate boot recovery. Automatic snapshot
retention and complete I/O-to-model refinement remain open work.

## Versioned publisher corrections

Backend authority files may reside under private components such as a user
service in `.config/systemd/user`. They are verified separately from public
source trees. The pinned-resource verifier follows no path-component links,
rejects special files and multiple hard links, bounds reads, checks descriptor
identity before/after hashing and requires the configured SHA-256. It returns
neither bytes nor a descriptor to the publication pipeline. Public traversal
continues to reject hidden path components.

A new text-license exception is limited to known LICENSE/NOTICE/COPYING/
ATTRIBUTION names with `.txt` or `.md` under `licenses/`; ordinary server source
files remain refused. `AuthorityProofs.lean` proves the extracted resource and
new license-exception decisions. String classification, kernel behavior and the
full I/O refinement remain outside that proof.

For an installed contract, do not overwrite its sealed publisher executable.
Install the corrected publisher at a new immutable path, add its digest to both
roles, and use the retained administrator to commit that resource addition.
The profiles, policy, bridge binaries and legacy resource hashes stay unchanged.
Only after acceptance should the client entry point select the new executable.
Update the local transfer executable as well as the remote publisher: local
package preparation runs the same public-asset checks. A corrected remote
`describe` alone does not fix an older client's text-license refusal. Verify
the local-to-remote path with a private `--stage-only yes` upload, check its
hashes and remove that test upload without applying it to the public tree.
The optional VM `--retained-bundle` uses the reviewed old administrator, bridge
and publisher, reproduces the private-resource refusal, then invokes that old
administrator to bind a candidate publisher. It tests the text license, rejects
a staged upload from before the migration, and continues through publication,
rollback and reboot. The updated scenario passed all three boots with fixture
source `874af0895321a823a20754b314d85a9090591585`. Its first attempt exposed a
fixture assertion that expected stderr from a helper that deliberately suppresses
it; the corrected fixture captures only the bounded expected diagnostic. No
production command-capture behavior was changed. Both clean verification/audit
workflows for the candidate runtime passed, including full extraction and Lean.
