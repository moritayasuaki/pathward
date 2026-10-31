# Redirects, headers and managed releases

These four production basics add no packages. The core remains dependency-free.
Read the [deployment risk assessment](deployment-risk.md) and
[integration/proof audit](production-basics-audit.md) before operating the managed
mode. Linux 5.6+, trusted procfs/local storage and a dedicated service UID remain
required. None of these commands builds, copies or deletes a release directory.

## HTTPS and configured redirects

```kdl
site "example.com" {
    root "/srv/pathward/releases/v1"
    tls "auto"
    publish "/" "index.html"
    publish "/guide" "guide.html"
    redirect "/old" "example.com" "/guide" "308"
    redirect-prefix "/docs" "example.com" "/guide" "301"
    header "*" "content-security-policy" "default-src 'self'; object-src 'none'; base-uri 'none'"
    header "*" "strict-transport-security" "max-age=31536000"
    header "*" "referrer-policy" "no-referrer"
    header "/guide" "referrer-policy" "same-origin"
}
```

Append `--http-listen 0.0.0.0:8080` to `serve-tls` and forward public TCP/80 to
that address. The optional public plaintext listener only issues same-host HTTPS
308 redirects; it never serves a file. TLS and redirect listeners share one
bounded worker pool. Ordinary `serve-http` remains loopback-only. Public TCP/443
must reach the TLS listener for certificates and HTTPS. Redirect destinations
always use the public HTTPS default port, even when local listeners use 8080/8443.

Configured redirects accept four quoted arguments: source path, destination DNS
host, destination path and status (`"301"` or `"308"`). Every destination host
must occur in the same compiled configuration. Absolute URL arguments, userinfo,
ports and arbitrary schemes are refused. Cross-host redirects therefore need a
second configured site (and that site's ACME identity). Redirect-only sites may
omit publications but still require `root` and `tls`.

`redirect` matches exactly. `redirect-prefix` matches its source or descendants
at a `/` component boundary, preserving the suffix; the longest match wins.
A destination `/` joins the suffix without a double slash. Prefix source `/`,
duplicate sources, direct self redirects, and publications overlapped by a
redirect are rejected. Multi-rule/cross-host redirect cycles are not detected;
review the complete routing graph. There are at most 64 redirects per site.

GET and HEAD preserve the original validated query bytes. Invalid paths/queries
cannot produce a Location header; unknown Host or SNI/Host mismatch is refused.
Host input is never copied into the destination authority. Existing strict path
rules still apply: no encoded path characters, Unicode paths or trailing slash
except `/`. This does not yet cover every Caddy legacy-URL configuration.

## Response headers

`header SCOPE NAME VALUE` uses `"*"` for all paths or an exact canonical path.
An exact-path value overrides the same wildcard header. Duplicate scope/name
pairs are rejected. Allowed lowercase names are `content-security-policy`,
`strict-transport-security`, `referrer-policy`, `permissions-policy`,
`x-frame-options`, `x-robots-tag`, and `link`. No custom framing, Host, Location,
Connection, Set-Cookie or Content-Length directives are accepted.

Values must be 1–4096 printable ASCII bytes; CR, LF, NUL, tabs and non-ASCII are
rejected after KDL escape decoding. There are at most 32 declarations and 8192
aggregate serialized header bytes per site. The gate checks header syntax, not the
browser semantics of a CSP or HSTS value. Review those values for your site.
Headers apply to known-site 200/301/308/404 responses. Early parse/method/host/TLS
identity rejections use fixed generic headers. HSTS is emitted only on TLS
responses. Existing `nosniff`, `no-store` and connection-close behavior remains.

## Explicit generation and preflight

Prepare immutable versioned directories separately. A manifest contains one
canonical relative filename per line, for example:

```text
index.html
assets/site.css
```

No globs, recursion, comments, blank lines or inferred index files. Hidden names,
traversal, duplicate entries and absolute paths are rejected. Each entry yields
one exact `/<filename>` mapping. `--index index.html` explicitly adds `/` and
requires that filename to be in the manifest. The 256-publication limit includes
that alias. The generator replaces only the selected site's root/publications,
preserves other sites and all headers/redirects, and round-trips its KDL output
through the compiler. It does not discover whether an explicitly listed ordinary
filename contains secrets: reviewing the manifest is essential.

```sh
pathward-server generate base.kdl example.com /srv/pathward/releases/v2 \
  public-files.txt --index index.html > candidate.kdl
pathward-server check candidate.kdl --cache /var/lib/pathward/acme
```

The server's `check` compiles the complete config, pins roots, opens every
published target through the serving opener and prints the configuration SHA-256
and mapping count. It detects missing, symlink, special, multi-link and oversized
files. It does not verify DNS, certificates, content hashes, content provenance
or future immutability. The older `pathward-config check` remains syntax/schema
only. Configuration and manifest input are capped at 64 KiB.

## Managed activation and rollback

Create trusted service-owned parent directories first. Initialize a new private
control directory from a checked config, then start serving its managed file:

```sh
pathward-server init /var/lib/pathward/control initial.kdl
pathward-server serve-tls /var/lib/pathward/control/.config \
  /var/lib/pathward/acme --accept-terms --acme staging \
  --listen 0.0.0.0:8443 --http-listen 0.0.0.0:8080 \
  --control-dir /var/lib/pathward/control --monitor 127.0.0.1:9090
```

Use a separate persistent ACME cache when moving from staging to production.
The control directory is 0700; `.config`, `.previous` and `control.sock` are 0600.
It is exclusively locked, cannot overlap public roots or the ACME cache, and
rejects unsafe existing ownership/modes/symlinks. Commands use this local Unix
socket; there is no TCP admin endpoint. Root and processes with the service UID
are trusted. Keep the directory's pathname stable while serving.

```sh
pathward-server status --control-dir /var/lib/pathward/control
# Paste the exact GENERATION:SHA256 returned above after reviewing the candidate.
pathward-server activate --control-dir /var/lib/pathward/control \
  --expect GENERATION:SHA256 candidate.kdl
pathward-server status --control-dir /var/lib/pathward/control
pathward-server rollback --control-dir /var/lib/pathward/control \
  --expect CURRENT_GENERATION:CURRENT_SHA256
```

Both updates require the expected active generation and configuration digest;
stale concurrent commands fail. Generation starts at 1 after each process
restart; this is an active-process concurrency guard, not a globally unique
release identity. The digest covers configuration bytes, **not file contents**.
Keep release directories immutable and re-query status after a restart or lost
acknowledgement. Never interpret a client timeout as proof that no commit happened.

A transaction serializes with SIGHUP, rejects out-of-band managed-file edits,
checks the unchanged host set and private-directory exclusion, prepares a new
snapshot, and opens every candidate publication through that snapshot's pinned
roots. It saves the pre-attempt config, durably replaces `.config`, then commits
one complete runtime snapshot and acknowledges the resulting generation/digest.
Existing requests may finish using their pinned old snapshot.

If the durable write or commit fails, the old durable config is restored. If
restoration fails, serving stops and emits `deployment_recovery_failed`. Inspect
and repair storage before a supervisor restarts it. A crash between successful
durable write and memory commit restarts from the new durable config. OS storage
semantics remain trusted; this is not an atomic disk-and-memory transaction.
Restart revalidates the durable config/files and removes only a validated stale
socket. The backup represents the state before the most recent attempt; even a
failed attempt can replace an older backup. Rollback is another fully checked
transaction and requires the old release files to remain present and safe.

Do not directly edit managed files or combine managed activation with a separate
SIGHUP publication workflow. SIGHUP is retained and serialized, but has no durable
backup transaction or exhaustive file preflight. It checks roots, schema and
private-directory isolation. Managed activation is the intended deploy path.
No release directory is deleted automatically; retain old releases until requests
and any planned rollback no longer need them. Host additions/removals and
listener/ACME identity changes still require a restart.

## Admission limits and test scope

Before TLS work, one shared gate limits active plus queued connections to 12 and
each peer to 6. Token buckets allow 8 admissions/second per peer (burst 16) and
64/second globally (burst 128). Tokens count connections, including invalid TLS or
HTTP attempts. IPv4-mapped IPv6 shares its IPv4 key; IPv6 peers share a /64 key.
The peer table holds at most 256 keys, evicting inactive keys after 60 seconds
when full. If it has no evictable entry, an unknown peer is refused. Denied
connections close immediately without HTTP output. Permits release on every
queue/error/connection exit. The bounded dispatcher runs at most two jobs per
peer and four globally, allowing another peer's queued work to bypass a busy
peer. A third validation connection may wait; no ACME exemption is used. These are fixed limits in this release. Six per peer accommodates ordinary
parallel HTTP/1.1 clients and simultaneous CA validation probes. All traffic,
including ACME validation, remains subject to the same global and peer gates.

This protects worker/memory budgets but does not guarantee availability against
distributed floods, SYN traffic, table exhaustion, bandwidth or slow storage.
NAT clients share one budget. Health/metrics use a separate loopback listener;
`pathward_admission_rejected_total` reports gate rejections. Process/network
budgets, supervision and deployment-specific alerts remain necessary.

Linux CI runs a bounded burst/slow-client/healthy-peer/rate-refill test, managed
CLI concurrency/unsafe-file/rollback/forced-restart tests, local ACME lifecycle
checks, and 100,000 deterministic mutated HTTP inputs. Mutation tests are not
coverage-guided fuzzing, and the burst test is not a prolonged production soak.
Run broader fuzzing, realistic throughput and long-duration storage/race tests
before migration. See [remaining production work](production-readiness.md).

See [continuous overlap soak testing](soak-testing.md) for the extended workload
and the worker-starvation correction.
