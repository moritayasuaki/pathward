# Native initial preparation and publication wrappers

The `pathward-admin provision` command replaces first-install Python execution.
`pathward-publish` replaces local upload and remote publication wrappers. Their
runtime uses Rust, with the existing reviewed administrator crate dependencies.
The HTTP server still consumes KDL; these JSON files are root-owned administrative
inventories, not a replacement for the server configuration language.

## First preparation

An administrator supplies a root-owned, private JSON input and its independently
retained SHA-256. Its schema is demonstrated by
`admin/examples/bootstrap_vm_guest.rs`:

- `schema: 1`, a new absolute `installation` directory and dedicated `account`.
- `network: "public"` and `expected_addresses`: an exact map of every configured
  host to reviewed IP addresses. The bounded system resolver response must match.
  The test-only `network: "isolated"` scope requires the host to have only `lo`.
- `minimum_free_bytes`: an explicit installation reserve of at least 128 MiB,
  checked against available filesystem space before mutation.
- `members`: exactly `pathward-server`, `pathward-hosting`, `pathward-publish`
  and `hosting.json`, each with an absolute root-owned `source` and SHA-256.
- `contract`: the reviewed old/new unit templates, sealed resources, check and
  health commands described in `contract-migration.md`, selecting `new` as the
  eventual target. All installed members must occur in the new resource map.

Parent directories already exist on the root filesystem. The installation is
publicly traversable; its `state` is service-owned 0700, and `receipts` is
service-owned 0755. The account has a non-login shell and that exact state home.
Existing accounts, files or state with different identities are refused.

```
sudo pathward-admin --root /opt/pathward-native provision /private/input.json SHA256
```

The source must be enabled, active and have exactly the reviewed unit definitions
without unmanaged drop-ins; candidate units must initially be absent. Preparation
copies and rechecks sealed binaries, creates the account/directories, builds
snapshots as the service user, initializes and checks the managed control, and
runs the server's check command under each candidate service's inherited
restrictions with `PrivateNetwork=yes`. Application commands, runtime-directory
cleanup and public certificate requests are not run by these check units.

The native recovery request and boot recovery are durable before gates or
candidate definitions appear. The source application is not stopped or restarted;
the candidate never receives a permit. Success prints `PREPARED_ONLY`. Retrying
the same reviewed input is supported, including after partial writes/reboot.
Different manifests cannot take over the interrupted installation. `initialize`
is the lower-level entry point when resources/account/control were prepared
independently; it accepts `source_fresh` and `target` contracts.

An explicit later `apply REQUEST` performs the service transition under the
existing native recovery protocol. Existing guarded installations use contract
migration, not fresh provisioning. Public DNS, live public-CA reachability and
external compatibility checks remain deployment acceptance steps; an isolated
configuration check does not establish them.

## Publication profiles

A root-owned publisher JSON file has `schema: 1`, `hosting_policy`, `receipt`,
numeric `receipt_owner`, and a `profiles` map keyed by hosting-policy site IDs.
Each profile specifies `kind`, `work`, `host`, `origin` and `checks` (URL paths to
expected SHA-256). The public origin must match the hosting host. HTTPS is used
normally; plain HTTP is accepted only for explicit high-port loopback fixtures.
Redirects, proxies, ambient curl configuration and TLS-verification bypasses are
not accepted by the HTTP checker. It hashes bounded response bodies and checks
every published file plus configured health/content checks inside rollback scope.
Optional `extra_checks` retain cross-site, redirect and private-path checks: each
entry declares `origin`, `host`, `path`, expected `status` (200/308/404), optional
`sha256`, and optional exact single-valued lowercase `headers`. Without a digest,
HTTP 200 must have a nonempty body. There are at most 128 extra checks; output and
body sizes are bounded. Configure all existing checks when migrating a portal;
another site's failed check also triggers the publishing site's rollback.

`release` profiles publish immutable `releases/ID/public` directories using the
native receipt and current-link protocol. `backend` profiles update the existing
server's exact `public` or `dist` subtree; they additionally require:

- Exact `unit`, `manager` (`system` or `user`), `executable`, `root`, and default
  loopback `upstream` matching the hosting policy.
- Reviewed systemd `properties`, including `WorkingDirectory`, `Environment`,
  `FragmentPath`, `NoNewPrivileges=yes` and relevant isolation properties.
- `sealed_files` covering the executable and unit definition.
- Optional `release_base` when WorkingDirectory is its `current` link. Only a
  relative `releases/NAME` reference is accepted; `root` and the sealed executable
  still name the concrete reviewed release. Optional `exec_start` may name the
  corresponding `current` executable alias. A changed reference, escaping link
  or different executable is rejected, and the observed reference is bound into
  the upload description and subsequent identity checks.
- `immutable_prefixes` and `additive_prefixes`. Unknown routes are refused unless
  their explicit prefix is allowed. Existing immutable or content-hashed assets
  cannot change. Omitted older assets remain available for existing browser tabs.

PID and process start time must remain unchanged throughout backend publication.
The running executable is checked through `/proc`. A reviewed
`executable_observation: "systemd"` profile can instead check the loaded, single
`ExecStart` executable when a separate service identity restricts `/proc` access.
This relies on systemd's observed startup command, not a measurement of the
process's current executable; PID/start-time stability and sealed-file checks
still apply. Assets are copied before HTML,
with the root HTML last. Private backups and a durable pending transaction precede
every live mutation. Public checks run before a completion record is issued.

```
pathward-publish upload --remote deploy@example.test \
  --binary /opt/pathward/release/pathward-publish \
  --config /etc/pathward/publisher.json --profile portal \
  --source public --files public-files.txt
```

The local command validates/copies the public tree, obtains a current remote
description over SSH, transfers only data with rsync, and invokes an already
installed native executable. It uploads no Python helper or executable code.
Only SSH/rsync may inherit the caller's existing `SSH_AUTH_SOCK`; administrator
and service commands retain their cleared environment. No credentials are part
of the package or profile.
`--stage-only yes` transfers without activation. SHA-256 manifests, links,
hardlinks, traversal, private-directory names, unsupported types, file counts and
capacity are checked. Limits remain 4096 files, 1 GiB/file and 2 GiB/package.

Offline-tested packages can add `--offline-report reports/split.json
--zip-report reports/zip.json`. `release.json` must exactly match the successful
offline report and file sizes/hashes, and its ZIP hash must match a passed ZIP
report. Build metadata is excluded from publication. `check-package` performs
this check locally without SSH. Ordinary development/build checks remain separate.

After an interrupted backend command, use `recover --config ... --profile ...
--operation ID`. Recovery only restores bytes still equal to this transaction's
write, with a verified backup and the same backend identity. It preserves later
edits and refuses a changed/restarted backend; that situation needs explicit
operator reconciliation. A pending operation blocks subsequent publication.
Static release recovery likewise refuses to overwrite a newer current link.
Workspace/upload counts are bounded and retained for review; this command does
not implement automatic deletion of historical backups or public snapshots.

## Migration, evidence and trust

Install the native bridge, publisher, root-owned profile data and recovery
resources together through the [coordinated rollout](native-publication-rollout.md).
Its mode selector and shared/legacy locks preserve the old entry points for
rollback while rejecting cross-generation publication. Existing processes are
changed only through an explicit administrator operation.
Site build tools, extraction/audit tooling and legacy fixtures
are separate Python users, not called by the new publication runtime.

The VM scenario is `scripts/native-publication-vm.mjs --scenario bootstrap` with
the existing pinned Ubuntu image and verified CI bundle. It installs from a fresh
unguarded source, cuts VM power during gate installation, resumes preparation,
publishes static/backend files, rejects failed public checks, kills an unprivileged
publisher mid-update and retries recovery, then restarts the committed host.
The source code contains the precise assertions; the PR records the observed run.

`BootstrapProofs.lean` proves extracted decision functions and separate preparation
and file-restore models. It does not verify JSON, copying, SSH, curl, systemd, the
kernel, storage durability or the correspondence of every adapter to the model.
No new Rust dependencies or features are introduced. Existing OS `systemd`,
`getent`, `useradd`, `runuser`, SSH, rsync and curl (7.83+ for `header_json`) are explicit trusted executables;
the RustSec report covers Rust packages, not those OS packages. Production OS
security updates and reviewed tool configuration remain required operational work.
