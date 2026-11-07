# Native publication and retention

`pathward-hosting` replaces the hosting bridge and publication acknowledgement
runtime with Rust. `pathward-admin gc-*` replaces collection of retired native
requests and the **tombstoned** legacy Python guard generations. These operations
use the existing administrator dependencies; the only feature change is
`rustix/time` for a monotonic clock. The authorization core still has no external
dependencies. New runtime and VM driver code contains no Python.

## Publishing

Build with `make admin-build`. Install the binary and reviewed policy as root;
run the bridge as the dedicated service account. Use
`deploy/pathward-hosting.service.in`, substituting absolute paths to the reviewed
hosting and server binaries. The bridge state and server control directories
must be separate, service-owned 0700 directories; the receipt directory is
service-owned 0755. The JSON receipt is 0644 and contains no private file content.

The hosting policy accepts schema 1 or 2 JSON, an administrative inventory used to
generate the existing KDL server configuration. It contains `capacity:
"shared-nat"` and 1–16 sites with `id`, `host`, `source_base`, `index`,
`public_paths`, `synthetic_files` and reviewed `directives`. `source_base: null`
supports proxy/redirect-only sites. `public_paths: null` selects the confined
source tree; a list selects only those URLs. Synthetic files are explicit policy
additions. `directory_indexes` makes directory-index precedence explicit,
defaulting to `["index.html", "index.txt"]`. Translate any former site-specific
index exception into this field before changing the bridge.

```
pathward-hosting build --policy /etc/pathward/hosting.json \
  --state /var/lib/pathward/snapshots --binary /opt/pathward/pathward-server
pathward-hosting reconcile --policy /etc/pathward/hosting.json \
  --state /var/lib/pathward/snapshots --binary /opt/pathward/pathward-server \
  --control /var/lib/pathward/control \
  --receipt /run/pathward-hosting/receipt.json --watch
```

The bridge descriptor-walks source directories without following symlinks,
rejects hard links, special files and mount crossings inside a release, streams
bounded copies, checks inode identity before/after copying, syncs the complete
private tree and atomically promotes it. Limits are 4096 files/URLs, 1 GiB per
file, 2 GiB per snapshot and 8 GiB per bridge state. Cached snapshots are verified
again, including file membership and hashes. This deliberately costs I/O during
reconciliation; large releases should be measured before choosing a watch period.
Never mutate an already published release in place.

Server validation precedes the generation/digest CAS. The bridge checks the
resulting revision and source links again before publishing its receipt.
Receipts include the boot ID and monotonic observation time. A publisher requires
the same policy, boot, source, config digest and **exact selected file-digest
map**, with an observation strictly after the update started. This confirms a
particular observed revision; it does not prevent a later administrator update.

Prepare a unique `releases/NAME/public` tree and a manifest whose lines are
`SHA256  public/relative-file`. With the numeric service UID supplied explicitly:

```
pathward-hosting publish --policy /etc/pathward/hosting.json \
  --receipt /run/pathward-hosting/receipt.json --receipt-owner 991 \
  --profile portal --expect releases/OLD --reference releases/NEW \
  --manifest /private/staging/public.sha256
```

The publisher owns the source base, verifies and syncs the ready tree, holds its
per-source publication lock, checks the previous link, replaces it atomically,
waits for the bridge and confirms routing. On failure it restores the previous
link only if its own link is still current, then waits for the restoration.
All writers of `current` must use this same command/lock. `begin` and `ack` also
exist for reviewed integrations that retain their own transaction protocol;
`ack --stamp` consumes the JSON returned by `begin`. Publishers must read the
service UID from administrator-controlled configuration, not a public receipt.
`publish`/`ack` require an active PathWard receipt. `begin` may identify Caddy
routing for an outer integration, but Caddy-only publication still needs its
existing public HTTP verification; this command never reports it as a PathWard
acknowledgement. `.nojekyll` manifest metadata is ignored and never published.

Do not run the Python and Rust bridges together. Receipt schema 2 alone does not
reject legacy readers that ignore it. A distinct schema 2 hosting policy digest,
coordinated writer locks and a service-contract migration must
update the bridge, publisher entry points, policy and recovery resources
together. [Native initial preparation and publication wrappers](native-bootstrap.md)
also cover the former initial preparation and upload/HTTP-verification runtime.
Legacy migration fixtures and build/proof tooling remain separate Python users.
See [coordinated rollout and rollback](native-publication-rollout.md) for an
existing deployment. Deployments still require their own reviewed administrator
handoff; committing the code alone does not change a running bridge.

## Collecting retired generations

All native administrator operations share the same administrator lock. First
record a stable, verified terminal request and its exact inventory:

```
pathward-admin --root /opt/pathward-native gc-observe
```

After a real host restart, and only while that same request is still current:

```
pathward-admin --root /opt/pathward-native gc-plan
pathward-admin --root /opt/pathward-native gc-apply REVIEWED_REQUEST_SHA256
```

`gc-plan` accepts optional explicit `native-DIGEST` / `legacy-DIGEST` pins and
writes a checksum-bound `collection-DIGEST.json`. Review its paths and members
before applying the printed identity. Each request collects at most eight
generations. It preserves the current and immediate parent requests, every
nonterminal/prepared native request, the imported legacy generation and its
parent, future legacy generations, explicit pins and their transitive declared
managed-store references. Ambiguous embedded references fail closed.

Apply repeats the service/gate/job, boot, current-generation, observation and
inventory checks. Exact members are renamed to request-specific private trash;
both directories are synced before any unlink. Every partial deletion can be
retried with the same request. Unknown, changed or linked members are refused.
Historical parent identifiers in old transaction metadata are audit provenance;
only the immediate current parent and actual resource references pin storage.

External plans, helpers (including legacy Python helper blobs), server releases,
keys, journals and public snapshots are never deleted. The retired helper store
cannot grow through the tombstoned legacy updater. Snapshot automatic collection
still needs a server-coordinated reader/rollback lifetime protocol; the bridge
fails closed at its retention limits. Native requests are capped at 128 entries.
Interrupted unsealed staging directories are quarantined for separate review.
The pinned native recovery executable itself cannot yet be updated in place.

## Evidence and limits

Rust tests cover confined copies, stale/conflicting receipts and activation,
private-file exclusion, cache tampering, interrupted writes and collection retry.
`scripts/native-publication-vm.mjs` boots the pinned Ubuntu image without a NIC,
using CI-produced binaries. It runs the bridge/server as an unprivileged account,
publishes over real managed control and loopback HTTP, reboots, and hard-cuts
collection after rename, unlink and partial completion-record writing. The
historical Python guard runs only to establish the legacy starting fixture;
native migration then tombstones it before subsequent boots/collection.

`PublicationProofs.lean` proves the extracted Rust decision contracts and a
separate interrupted-trash transition model. The filesystem traversal, JSON
parser, hashes, systemd observations, process locking and OS/fsync guarantees are
reviewed/tested adapter assumptions, not a full implementation refinement proof.
No custom Lean axioms or proof holes are introduced. See the generated
`proofs/registry.json`, `proofs/roadmap.json` and the Japanese proof tour.
