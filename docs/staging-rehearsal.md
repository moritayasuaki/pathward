# Isolated migration rehearsal

The rehearsal exercises a **reviewed static subset**, not a replacement of a
shared Caddy deployment. `scripts/staging_rehearsal.py` runs installed Caddy and
PathWard in turn on the **same loopback TLS and HTTP ports**, verifies the actual
copied public files and security headers, and restores Caddy after startup failure
and forced candidate termination. It is a test controller, not a production
failover daemon. The public CA, DNS, public 80/443 and system Caddy service are
never changed by this controller.

## Completed run — 2026-11-01

[Machine-readable results](staging-result-2026-11-01.json) record a 180-second
calibration and a 300-second final run on the existing Ubuntu 24.04.5 host,
Linux 6.8.0-147, ext4, NTP synchronized, with Caddy 2.11.7 built using Go 1.26.10.
The fixture copied 12 approved files (922,508 bytes) and the actual five security
header values into the private test area. The shared Caddy inventory had nine
host names, six file-server handlers and 44 reverse-proxy handler occurrences;
these are configuration-handler counts, not 44 independently tested services.

The final run passed 1,048 background TLS requests and 192 explicit GET/HEAD file
checks, 473 configuration changes, 48 stale-CAS rejections and 48 monitoring
checks. There were eight certificate activations (initial issuance plus seven
renewals), with 66 config commits while an ACME order was active. Steady-state
errors were **zero**. Peak PathWard RSS was 6,600 KiB, with 15 FDs and 12 threads.

| Final handoff | Stop-to-ready time |
| --- | ---: |
| Caddy → PathWard | 0.274 s |
| PathWard → Caddy | 0.383 s |
| Candidate startup failure → verified Caddy | 0.414 s |
| Caddy → PathWard again | 0.225 s |
| Candidate SIGKILL → verified Caddy | 0.181 s |

Four background probes failed **during transitions** in the final run. The
calibration's slowest handoff was **1.140 s** with seven transition failures.
Plan for an interruption; the smaller final timings are not an availability SLA.
Both injected failures recovered to verified Caddy content and security headers.
The production Caddy PID, binary and config hashes, 31 TCP listeners, release
symlink and approved content stayed unchanged. Production HTTPS still returned
200. All staging listeners, disposable keys and fixtures were removed.

The compatibility issue fixed in this change was XML delivery: `.xml` previously
used `application/octet-stream`; it now uses `application/xml; charset=utf-8`.
Caddy's equivalent `text/xml; charset=utf-8` spelling is the only accepted MIME
difference. The migration decision and monitored handoff were also added to
prevent unchecked cutover. Runtime dependencies were not added.

The binaries came from commit `82121686d9064d5cebf032aeaa19d70b48ec7d1f`
([Linux build](https://github.com/moritayasuaki/pathward/actions/runs/41296522340));
the final harness is `af57cc0dfa53dac86ea6c1abc858c9a630d9ccdc`
([Linux integration and Lean CI](https://github.com/moritayasuaki/pathward/actions/runs/41297521102)).
The Rust source, extracted model and proofs are identical between those commits.
The report pins the ZIP, executable and harness digests. Local `make check` and
the refreshed dependency audit passed; RustSec DB
`2295466c4e9df26647fd67d8fa1c705ac2fc7f81` reported no findings/warnings.

## Inputs and isolation

Use a Linux host with the production kernel/filesystem and an existing reviewed
Caddy installation. Create a private 0700 working directory outside all served
roots. Resolve the approved immutable content release explicitly; provide its
reviewed manifest with one filename per line. The copier never discovers files
or reuses hard links, rejects symlink components and special/multi-link files,
and limits the fixture to 240 files and 128 MiB. This copier assumes a trusted,
immutable source; its pathname checks are not a substitute for the production
server's descriptor-based opener against hostile concurrent writers.

The fixture adds two explicitly published release markers and two unlisted
canaries. All content, private control sockets, ACME state, Caddy storage and test
keys live below private temporary directories. Only the approved manifest's
content is copied. Report hashes identify content without including its bytes.
Use `--headers security-headers.json` to supply the actual approved CSP, HSTS,
Referrer-Policy, X-Frame-Options and Permissions-Policy; all five names are required.
The script also verifies `nosniff` and absence of the Server banner.

Both servers listen on 127.0.0.1 only. The Caddy instance has `admin off`,
`auto_https off`, explicit ephemeral test certificates, private XDG/storage paths
and HTTP/1.1 only. It never loads the system Caddyfile. The PathWard local-CA driver
uses the real serving, managed-release, TLS, ACME, monitoring and shutdown code;
the production CLI retains its fixed public CA origins. Neither public trust nor
real DNS/443 reachability is established by this test. Test keys are disposable.
Core dumps are disabled. The driver leaves procfs descriptor inspection available
for the unprivileged resource sampler; the production CLI additionally disables
process dumpability.

Run the **whole controller and its children** under a bounded user systemd unit,
for example CPUQuota=50%, MemoryMax=512M, TasksMax=128, NoNewPrivileges=yes,
UMask=0077, LimitCORE=0, RuntimeMaxSec=900, TimeoutStopSec=20 and
KillMode=control-group. Set TMPDIR to the private working directory. Verify the
properties actually took effect. These are test budgets, not production sizing.
Record the system Caddy PID/config/binary hash, public listeners and release
symlinks before and after the run. Do not reload that service to perform this test.

## Build and run

No Rust or Python runtime package is added. Existing pinned `make server-setup`
and `make acme-test-setup` are explicit setup steps. Build on a Linux build host,
not a production service account:

```sh
cargo +1.99.1 build --offline --locked --release --manifest-path server/Cargo.toml --bins --examples
python3 scripts/acme_integration.py --rehearsal \
  --content /srv/releases/approved-v1/public --manifest /private/public-files.txt \
  --headers /private/security-headers.json --seconds 300 --report /private/result.json
```

For a host without Rust, `.github/workflows/staging-build.yml` produces the CLI,
local-CA driver, migration gate and pinned Pebble binary on Ubuntu 24.04. Check
the workflow's commit, ZIP digest, exact archive entries, `SOURCE_COMMIT`, and
**every** entry in `SHA256SUMS` before installing into the private test directory.
Keep the binaries at the paths above and Pebble at `.tools/pebble/pebble`. The
artifact contains no SSH credentials, site content, certificates or private keys.
The binary build commit and final harness hash must be recorded with the result;
this is a digest-checked artifact transfer, not a reproducible-build attestation.

## Checks and failure semantics

1. Generate publications with the production manifest generator and preflight
   each release through the production safe opener. Initialize private managed
   state. Validate a separate Caddy configuration with the installed Caddy binary.
2. Prewarm PathWard with real local TLS-ALPN-01 validation by pinned Pebble. Then
   run Caddy on the same listeners. Verify both against explicit body/length,
   GET/HEAD, root-alias, redirect/query and security-header expectations. XML MIME
   types `application/xml` and `text/xml` are treated as equivalent; all other
   content-type differences fail. This is deliberately scoped parity: caching,
   compression, HTTP/2 and unsupported URLs are not silently accepted as migrated.
3. Before stopping Caddy, invoke the extracted Rust migration gate. SHA-256 binds
   inspected binaries, Caddy/configuration inputs, managed config, listener plan
   and both releases' published content. A changed digest, failed candidate
   preflight/parity, missing fallback or absent isolation refuses the handoff.
   A trusted owner must keep these inputs immutable between the recheck and use.
4. Run verified TLS load while switching releases with CAS. Check the exact
   acknowledged marker, header and revoked URL on fresh connections, stale-CAS
   rejection, ACME/order overlap, certificate validity, readiness, metrics, logs,
   private 0700/0600 single-link storage and RSS/FD/thread bounds.
5. Return to Caddy, deliberately fail candidate startup and restore Caddy, then
   switch again and inject SIGKILL into **only the owned candidate process**.
   Detect its exit and restore/check Caddy. Failures after promotion also enter
   the controller's fallback cleanup. Finally stop the isolated Caddy and verify
   that the staging listeners disappeared. This cleanup intentionally leaves no
   persistent staging service; the production Caddy was running throughout.

Steady-state errors fail the rehearsal. Requests during listener stop/start are
counted separately as transition errors, and each handoff records stop-to-ready
elapsed time. This procedure has an interruption window; it does **not** claim
zero downtime or preserve connections across a crashed process. Requests were
sampled every 250 ms, so zero sampled failures would not prove no interruption.
A supervisor must still handle controller/host death; the Python fallback is not
an OS-level transactional handoff.

## Formal scope and dependency audit

The extracted `release::migration_allowed` has eight audited Lean statements:
exact contract, totality, stale-input rejection, unready-candidate rejection,
parity-failure rejection, rollback requirement and isolation requirement. Together
with the previous policy/compiler/opening/TLS/reload/header/release statements,
the axiom audit now checks **124** statements. These are proofs of the pure Rust
predicates, conditional on truthful adapter evidence. Python, SHA-256 observation,
filesystem immutability, Caddy, systemd, networking, TLS cryptography and the OS
handoff are reviewed/tested trust boundaries, not end-to-end Lean proofs.

Runtime manifests, lockfiles and vendored code are unchanged: core 0 external
packages, KDL adapter 8, server 104. The unused server candidate remains 163.
The latest RustSec scan is recorded alongside the result. The rehearsal uses only
Python's standard library and existing Caddy/OpenSSL/systemd, plus the previously
pinned Pebble v2.10.1 test dependency. It installs no server packages or services.

One **build-only** action was added: `actions/upload-artifact` v7.0.2 at
`cf430e030ddbb5b0abf93d22962f4752f3646cd9`. Review covered its official action
metadata, upload and input paths, upload scope and workflow permissions. The
workflow is read-only, does not persist checkout credentials, uploads only the
explicit bundle, excludes hidden files, fails on missing files and expires the
artifact after seven days. This is a focused integration review, not a formal
verification or full audit of bundled JavaScript dependencies. Installed Caddy is
an unchanged comparison dependency; its binary and build identity are recorded.
The official upload-action advisory page had no published advisories at review
time. The latest reviewed Caddy advisory, GHSA-8qx7-j2v2-x6q5, affects versions
through 2.11.4 and is fixed in 2.11.5; the comparison binary is 2.11.7. This does
not constitute a new complete scan of every Go dependency in that existing binary.

Primary references: [Caddy command validation](https://caddyserver.com/docs/command-line),
[Caddy global options](https://caddyserver.com/docs/caddyfile/options),
[systemd resource controls](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html),
[pinned upload action](https://github.com/actions/upload-artifact/tree/cf430e030ddbb5b0abf93d22962f4752f3646cd9),
[upload-action advisories](https://github.com/actions/upload-artifact/security/advisories),
[Caddy advisory](https://github.com/caddyserver/caddy/security/advisories/GHSA-8qx7-j2v2-x6q5).

## Public migration remains blocked

The shared configuration inspected for this rehearsal contains reverse proxies,
rewrites, request-body policies, compression and several static roots/hosts.
PathWard cannot replace that entire configuration. Also review legacy directory
URLs, encoded/Unicode paths, implicit indexes, cross-host redirect destinations,
caching and ranges individually; manifest coverage alone is insufficient.

Before any public switch, separately validate the dedicated service UID and
ownership, real DNS/public TCP/443, public-CA staging issuance, external alert
collection and rollback at the actual network entry point. Versioned release
paths must be explicit: following a mutable `current` symlink is deliberately
incompatible with the safe opener. This rehearsal uses copies on the same real
filesystem and an existing unprivileged UID, not a dedicated production service
identity. The production process and its certificates remain untouched.
