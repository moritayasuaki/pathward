# TLS/ACME integration audit — 2026-10-31

## 2026-11-05: bounded dual-stack connection fallback

A production-host read-only probe found the first resolved IPv6 address still
unconnected after 31 seconds, while the following IPv4 address connected in
5 ms. The previous `async_net::TcpStream::connect(hostname)` tried addresses
sequentially, so the 30-second request budget expired before IPv4 was attempted.
The failed cutover made two 30-second ACME attempts and restored the prior server.

The reviewed fork now interleaves address families and starts up to eight distinct
DNS-provided endpoints, 250 ms apart. It holds at most eight candidate addresses
per family while selecting and at most eight connect futures. A successful TCP
connection cancels the losing futures; TLS still authenticates the original
configured CA hostname before any ACME payload is sent. No redirect or origin
policy is relaxed. DNS, TCP, TLS, request writing and response reading share the
same 30-second deadline; starting a candidate does not renew that deadline.

The scheduling follows the staggered-connection principle in
[RFC 8305 section 5](https://www.rfc-editor.org/rfc/rfc8305.html#section-5), but
uses the system resolver and does not claim the RFC's full asynchronous DNS or
NAT64 behavior. A broken host IPv6 route remains an operational issue to repair.
No external package or dependency feature was added.

Regression tests cover a permanently pending first address followed by a real
working TCP endpoint, immediate refusal followed by success, cancellation of all
live attempts at the request deadline, the eight-attempt gate, family diversity,
duplicate removal, and preservation of verified TLS and slow-response deadlines.
Failures now log fixed request-stage/transport-stage categories and HTTP status,
without response bodies, account URLs, nonces, credentials, or raw I/O text.

These async/OS adapters remain outside Lean extraction. The 397 existing theorem
statements retain their scope; connection scheduling and Drop correspondence are
tracked as `ACME-CONNECT` in the proof roadmap, not counted as proved.
`acme_probe production|staging` performs only directory GET and nonce HEAD with
the same client. It never creates an account, order, cache or certificate.

## Original integration review

The dependency-free extracted Rust core now also checks SNI/Host identity,
private-file metadata, certificate activation and renewal deadlines. TLS,
cryptography, ACME, certificate parsers, filesystem operations and time inputs
remain trusted, reviewed and tested adapters. See [operation](tls-serving.md).

The actual server's reviewed inventory contains 104 crates.io package versions
plus one attributed local rustls-acme fork; the Linux normal/build tree contains
90 crates.io package versions plus the fork. All target-specific and build
packages are scanned. The verified core still has zero external dependencies.
No Axum, Tower, Tokio, Hyper, AWS-LC or HTTP/2 stack is linked. Direct dependencies
use exact versions and disabled default feature bundles; the complete resolved
transitive feature/build/macro/license inventory is committed.

The focused source review covers rustls 0.23.46's Acceptor, SNI and ALPN handling,
TLS record limits, ServerConfig, certificate key/name checks and time selection;
rustls-acme 0.15.4's ACME requests and JOSE signatures; rcgen 0.13.2's P-256
key/CSR/challenge extension generation; pem 3.0.6 and x509-parser 0.18.1's
bounded-input decoding and validity/SAN adaptation; rustix 1.1.6's openat2,
flock, renameat, fsync and process protections. This is not a complete source
audit or malware scan of every transitive crate.

`cargo-audit 0.22.2` checked all profiles against official RustSec revision
`2295466c4e9df26647fd67d8fa1c705ac2fc7f81` (1,395 advisories), with yanked checks,
no ignores and no platform/severity exemptions: zero known vulnerabilities and
zero warnings. See [machine evidence](../server/audit-result.json). A clean scan
is dated evidence, not a security guarantee. std/compiler/OS are outside RustSec.

## Integration controls

- The upstream high-level DirCache and renewal/acceptor state are omitted. The
  local fork retains only low-level ACME/JOSE and licenses, with an origin-bound,
  bounded HTTPS helper. [Provenance](../vendor/rustls-acme/PROVENANCE.md) records
  the base and changes. All vendored bytes are hashed by the audit gate.
- Only configured domains enter the fixed SAN order. SNI/Host cannot request
  certificates. Unknown/missing SNI fails; Host must equal SNI and selected host.
  ACME-only ALPN completes validation without entering HTTP. TLS 1.2/1.3 only;
  resumption, tickets and early data are disabled. HTTP/2 is not advertised.
- ACME requests validate every URL against the original HTTPS authority before
  DNS/TCP, including directory/authorization/order/finalize/certificate URLs.
  Web PKI verification is retained, redirects are rejected, and errors never
  log CA bodies, JWS payloads, cache contents or keys. The CLI exposes only fixed
  Let's Encrypt staging/production origins; custom trust is library/test-only.
- The helper caps response headers at 8 KiB/64 fields, decoded bodies at 1 MiB,
  URLs at 4096 bytes and request bodies at 64 KiB. It enforces a 30-second total
  request deadline. Chunk lengths have bounded syntax and checked aggregate
  lengths; CL/TE ambiguity, compression, trailers and chunk extensions fail.
  The upstream async-http-codec's unchecked chunk arithmetic is not linked.
- One worker handles one order at a time, with 10-minute total order budget,
  bounded poll/auth counts, 60-second to one-hour failure backoff, and continuous
  lifecycle polling. Issuance uses fresh P-256 keys; the account key is durable
  before any network request. Cache corruption/unsafe permissions fail startup.
- Cache access uses trusted ancestor directories and a pinned 0700 service-owned
  directory, exclusive nonblocking directory flock, O_PATH/openat2 pinning,
  no-follow/same-inode 0600 single-link regular-file checks, and 1 MiB read caps.
  Writes use an exclusive 0600 staging inode, fsync, renameat and directory fsync.
  Published targets cannot name the hidden cache files; cache/root overlap also
  fails. Existing unsafe permissions are rejected, never silently repaired.
- Candidate certificates must have the requested exact SAN set, matching private
  key, bounded chain and current validity. The same key+chain bytes are durable
  before atomic in-memory replacement. Failures preserve the active old identity;
  expired/not-yet-valid identities are refused on new handshakes. CA signature
  trust comes from the authenticated configured ACME channel; the server does
  not implement a second public-chain verifier (staging/private CAs differ).

## Proof and test boundary

The actual Rust decisions are freshly extracted through Charon/Aeneas and checked
in [TlsProofs.lean](../proofs/TlsProofs.lean), alongside existing path/rule/serving
proofs. The 70-statement audit permits only standard Lean axioms, with no holes.
Proofs establish exact identity/metadata/activation contracts, no unpersisted or
expired activation, total renewal arithmetic and retry at expiration. They do
not prove cryptography, that OS fsync reached stable media, parser correctness,
clock correctness, liveness of the worker, native resource exhaustion or the
entire KDL-to-TLS execution.

Portable tests cover actual TLS handshakes, SNI/ALPN rejection, handshake deadline,
key/SAN mismatches, bounded HTTP response parsing, URL-origin controls, CA certificate verification
and a real slow-body total request deadline. Linux
CI additionally covers private cache modes/locking/restart/partial writes,
symlinks/hardlinks/special files, old-or-new atomic visibility, real HTTPS serving,
TLS-ALPN-01, short-certificate renewal, restart reuse and persistence failure.
A pinned, checksum-verified Pebble v2.10.1 runs only on loopback with ephemeral test
roots; no production or staging certificate is issued by tests. Public CA behavior
and internet reachability are deployment checks, not established by these tests.

## Remaining trust and operational limits

ring contains native code; Rustls, ASN.1/PEM/JSON/HTTP parsers, six procedural-macro
packages, build scripts, DNS, storage and system clock remain trusted. The fork
must be reviewed on upstream security updates. Secret memory copies are not all
zeroized or locked against swap; files are permission-protected, not encrypted.
The CLI disables dumpability/core dumps before loading keys. Run as a dedicated
unprivileged UID on trusted local storage, with encrypted disks/backups as needed.
Root/same-UID attackers and malicious mount namespaces are outside this boundary.
Blocking DNS resolver work and filesystem calls cannot always be forcibly
cancelled; network/async deadlines do not prove a global OS scheduling bound.

ARI, Retry-After-aware scheduling, in-order badNonce retry, revocation/OCSP,
contact updates, account rollover, DNS-01/HTTP-01, per-site certificate separation,
and external alert delivery remain future work. Publication/root reload, signal
draining and loopback metrics are implemented; see the [runtime audit](runtime-audit.md). The
fallback renewal schedule starts in the last third of lifetime; failures emit
redacted status events and exponential retry. Client-visible unavailability after
expiry is intentional. Existing established connections are not revoked at expiry.

Primary references: [rustls source](https://github.com/rustls/rustls),
[ACME RFC 8555](https://www.rfc-editor.org/rfc/rfc8555),
[TLS-ALPN-01 RFC 8737](https://www.rfc-editor.org/rfc/rfc8737),
[openat2](https://man7.org/linux/man-pages/man2/openat2.2.html),
[fsync](https://man7.org/linux/man-pages/man2/fsync.2.html),
[Pebble](https://github.com/letsencrypt/pebble/tree/v2.10.1).
