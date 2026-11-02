# HTTP serving and Linux file opening

The `pathward-server` crate implements a deliberately small **HTTP/1.1, loopback-only**
static server, with a separate [bounded reverse-proxy mode](reverse-proxy.md).
The behavior below describes static sites. It uses the existing KDL configuration and verified publication
rules. GET and HEAD work; TLS/ACME does not run. This milestone is suitable for
local evaluation, not a complete replacement for Caddy. See the
[HTTP/file audit](http-audit.md) and [remaining production work](production-readiness.md).

## Run on Linux

Linux 5.6+ with `openat2` available and an ordinary trusted procfs mounted at
`/proc` is required. There is no weaker fallback on an old kernel, a restrictive
seccomp profile, macOS, Windows, or a system without usable procfs. Linux x86-64
is exercised by CI; local macOS runs portable tests and cross-checks Linux code.

```sh
make server-setup  # Explicit Rust 1.99.1/tool dependency setup.
make server-build
server/target/release/pathward-server serve-http examples/Pathward.kdl 127.0.0.1:8080
```

The example root is `/srv/www`: create that directory and its declared files,
or change `root` in a private configuration file. No repository or live hosting
files are deployed by these commands. Test with the configured hostname:

```sh
curl -H 'Host: example.com' http://127.0.0.1:8080/
curl -I -H 'Host: example.com' http://127.0.0.1:8080/style.css
```

`serve-http` explicitly selects plaintext HTTP. The address defaults to
`127.0.0.1:8080`; literal loopback IPv4/IPv6 addresses are accepted. Port `0`
selects an ephemeral port, printed at startup. Non-loopback addresses are rejected
before the CLI binds. In this HTTP-only mode, the CLI explicitly
reports that automatic TLS is not active. Nothing is automatically exposed on
ports 80/443 or deployed to an existing host.

## HTTP behavior

- HTTP/1.1 only, strict CRLF and request-line spacing. GET/HEAD only; other methods
  receive 405 with `Allow: GET, HEAD`. HEAD has the same successful Content-Length
  as GET and no body. All error responses have zero-length bodies.
- Exactly one Host header. Hostnames are ASCII DNS-style names, folded to
  lowercase for exact configured-host selection. An optional decimal port must
  match the listener's actual port; missing ports are accepted. IP-literal IPv6
  Host values, wildcard/trailing-dot hosts, malformed ports and duplicate Host
  fields are rejected. Unknown configured-host matches receive 421.
- The request target is origin-form only. The verified core takes the byte prefix
  before the first `?` without rewriting or percent decoding. The query may contain
  visible ASCII except `#`, is ignored for authorization, and is never forwarded
  or executed. Total target limit is 8192 bytes; the path still follows the
  original 4096-byte canonical grammar. Invalid/unpublished paths receive 404.
- There are no router fallbacks, implicit indexes, prefix grants, redirects,
  directory listings or path-based file service. Only the explicit declared
  relative target is passed to the file opener after the verified grant.
- Request bodies are not supported. Transfer-Encoding, Trailer, Upgrade and
  Expect are rejected. Content-Length may be absent or a single canonical `0`;
  duplicate lengths and other values are rejected. Unsupported Connection tokens
  are rejected. `Forwarded`/`X-Forwarded-*` are ignored, not trusted for routing.
- One response per connection, always `Connection: close`. Bytes already read
  after the complete head are rejected. If later pipelined bytes arrive after
  processing starts, they are never dispatched as another request.
- Common static content types, `X-Content-Type-Options: nosniff`, Date and exact
  Content-Length are emitted. Unknown extensions use `application/octet-stream`.
  Responses use `Cache-Control: no-store`. Range and conditional caching semantics
  are not implemented; their fields do not create alternate serving paths.

The parser and HTTP framing adapter are source-reviewed and tested. The Lean
proofs cover the extracted pure dispatch decisions, not the complete HTTP parser,
response serialization, socket implementation or connection scheduler.

## File-opening strategy and trust assumptions

1. Startup pins each configured absolute document root as a directory descriptor.
   `openat2` rejects symlinks in every root component. A root may itself be on a
   deliberately configured filesystem; mounts below it are not granted.
2. The relative target is revalidated, then opened with `O_PATH` and
   `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`.
   This asks the kernel to enforce containment, including resolution races, in
   one lookup. There is no canonicalize/check/open sequence or retry with weaker
   flags. Kernel errors, including uncertainty during a rename race, deny access.
3. Descriptor metadata must describe a regular file, exactly one hard link, and
   a size no greater than **1 GiB**. O_PATH does not first open a FIFO/device for
   data I/O. A symlink descriptor that Linux can return with O_PATH/NOFOLLOW also
   fails the regular-file check.
4. While retaining the pinned descriptor, the adapter reopens its inode through
   the process's trusted `/proc/self/fd/N` entry with RDONLY/CLOEXEC/NONBLOCK. It
   checks descriptor metadata again. The verified policy requires the same
   device/inode/size and the same regular-file/link-count/size constraints.
   The original attacker-controlled target path is never opened again.
5. GET reads from this descriptor, not a freshly resolved path. It transmits at
   most the admitted size; growth is not appended, and truncation closes the
   response. HEAD opens and checks the same resource but sends no file data.

All PathWard crates forbid their own unsafe code. Rustix, std and the Linux
kernel implement the descriptor operations and remain trusted. Procfs and the
mount namespace must be controlled by the service administrator; this is not a
boundary against a privileged process that can replace procfs or inspect/change
the server's descriptor table or memory.

Use service-controlled **local regular files and directories**. Confinement does
not establish file-content provenance or immutability: someone who can write an
allowed file can replace its content, and a privileged writer can change mounts.
A link count of one at the two observations is a policy check, not a proof that
an inode has never had another name or cannot be linked later. Do not grant an
untrusted uploader write access to a published tree. In-place concurrent writes
can change bytes during a response; publish immutable releases or separately
coordinate writers. Content snapshots/hashes are not implemented.

The root descriptor is a capability to the directory opened at startup. Renaming
or replacing the configured root pathname does not retarget the running server;
it continues to use the original directory until successful reload or restart. File descriptors also
retain their admitted inode across later renames. Plan deployments accordingly.

## Resource bounds

| Resource | Bound |
| --- | --- |
| Request head | 16 KiB, at most 32 headers |
| Request target | 8192 bytes including query |
| File size | 1 GiB at admission |
| Ordinary handlers | 4 fixed threads; one separate input/output thread |
| Admitted ordinary connections | 12 standard / 256 shared-NAT, including input, queue and output |
| Request-head deadline | 5 seconds for header collection; separate 5-second ready queue |
| Static response deadline | 120 seconds total; 5 seconds without output progress |
| Error response deadline | 1 second |
| Body-copy buffer | 16 KiB per active response |

The accept loop has at most one additional socket while enqueueing; the kernel
also owns its bounded listen backlog. There is no per-request thread creation. See [staged delivery](delivery.md) for
retained-response byte bounds, shutdown and TLS phase accounting.
The write deadline is not reset by small successful writes. Filesystem lookup,
metadata and read syscalls on a blocked device/FUSE/network filesystem cannot be
interrupted by these socket deadlines. Slow/untrusted storage is outside this
implementation's hard-time guarantee; use trusted local storage and an external
service supervisor. Comprehensive throughput/per-client limits are still absent.

`Server::serve` accepts a programmatic shutdown flag. The CLI now connects
SIGTERM/SIGINT to draining and SIGHUP to atomic publication/root reload. Structured
logs and optional loopback monitoring are described in [runtime operation](runtime.md).

## Verification

`make check` checks the core, configuration and server; it regenerates and compares
the actual Rust extraction and checks Lean proofs/246 axiom-audited statements.
On Linux, server tests exercise real TCP serving, virtual-host isolation,
GET/HEAD/query behavior, malformed framing, limits, excess connections, symlinks,
hard links, special files, pinned roots and directory/symlink replacement races.
`python3 scripts/linux_mount_check.py` additionally runs the bind-mount regression
as root in a private mount namespace; it is intended for the disposable Linux CI
runner. `python3 scripts/http_smoke.py` tests the built release CLI.

Linux behavior is not emulated by the macOS stub: unsupported platforms return
an error. The kernel's confinement guarantees are exercised by integration tests
and source/API review, not asserted as Lean theorems about the OS.

TLS is available through the separate explicit [TLS/ACME mode](tls-serving.md).
Its adapter reuses the same HTTP framing, verified grants and file opener.

## Production basics extension

See [production basics](production-basics.md) for response headers, configured
redirects, managed deployment preflight/activation/rollback, and the additional
global/per-peer connection and rate gates. The TLS mode can optionally bind a
public plaintext redirect-only listener; HTTP file serving stays loopback-only.
