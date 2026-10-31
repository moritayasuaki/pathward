# TLS and automatic certificates

PathWard serves HTTP/1.1 through rustls on Linux 5.6+ and continuously obtains and
renews certificates with ACME TLS-ALPN-01. Existing KDL `tls "auto"` declarations
are activated by `serve-tls`; `serve-http` remains explicitly loopback-only.

```sh
make server-setup
make server-build
# Parent directory must already exist, belong to root/service UID, and be private
# or non-group/world-writable. The final cache directory is created as 0700.
server/target/release/pathward-server serve-tls /etc/pathward/Pathward.kdl \
  /var/lib/pathward/staging --accept-terms --acme staging \
  --listen 0.0.0.0:8443 --contact mailto:admin@example.com
```

Configure DNS for every site and forward public TCP/443 directly to this TLS
listener (8443 in the example). TLS-ALPN-01 cannot pass through a proxy that
terminates TLS. Optional `--http-listen 0.0.0.0:8080` adds a redirect-only public
HTTP listener; forward TCP/80 there. See [redirect operation](production-basics.md).
DNS-01 and HTTP-01 are not implemented. No deployment, DNS mutation, firewall change or public issuance is
performed by building/testing this repository.

Staging is the default and its certificates are not publicly trusted. After
validating the setup, select `--acme production` with a **separate** private cache
such as `/var/lib/pathward/production`. `--accept-terms` explicitly accepts the
selected CA's subscriber terms. Do not use a disposable cache in production.
The directory binds to the CA, sorted configured domains and contact; changing
that identity requires a separate directory. Host/ACME identity changes require restart; publications, roots, headers and
redirects support transactional reload. The initial implementation uses one SAN certificate/account for all
1–16 configured DNS domains, so these domains share an identity and public CT
visibility. Issuance requires control of every domain.

The process must be able to read configuration/content and own its private cache;
run under a dedicated unprivileged service UID. Choose an unprivileged listener
and use administrator-managed port forwarding or socket capabilities. Do not run
the whole service as root merely to bind 443. Cache ancestors must be service/root
owned, without group/other write permission; root-owned sticky temporary
directories are permitted for tests. No symlink components or public-root overlap.
Existing directory/file modes must be exactly 0700/0600. Use trusted local storage,
trusted procfs/mount namespace and a reliable synchronized system clock.

Account and certificate private keys are stored in hidden single-link regular
files, with bounded reads, no-follow descriptor resolution, exclusive process
locking and atomic durable replacement. The complete certificate key+chain is
one record. Interrupted writes leave either the old or new record; a validated
private incomplete staging inode is removed on restart. Storage errors fail
closed. Permission protection is not at-rest encryption or protection from root,
same-UID processes, malicious backups, swap or hardware failure.

One ACME worker polls continuously, renews in the last third of certificate
lifetime and retries failures with exponential delay (60 seconds to one hour).
It persists the account before contacting the CA and each checked certificate
before activation. A valid cached certificate serves immediately after restart.
If renewal fails, the valid old identity stays active. Missing/expired identities
refuse ordinary TLS handshakes while ACME validation remains available. A failed
write cannot activate a new identity. The CLI emits redacted lifecycle/failure
events on stderr; connect these to your supervisor's alerting. No automatic
external notification is configured by PathWard.

TLS requires configured SNI; HTTP Host must agree with SNI. Only HTTP/1.1 is
supported (TLS ALPN `http/1.1`, or absent ALPN for ordinary clients). ACME-only
`acme-tls/1` connections never reach file serving. TLS 1.2/1.3 use the ring provider;
TLS 1.0/1.1, session resumption/tickets and 0-RTT are disabled. Handshakes have a
5-second total deadline including queue time and a 128 KiB input limit. The
existing four workers/eight queued connections bound handshake and serving
concurrency; HTTP adds its existing header/write limits. [Admission gates](production-basics.md#admission-limits-and-test-scope) now bound
per-peer concurrency and rate before TLS. Sustained denial-of-service protection
still requires deployment controls.

See [audit and proof boundaries](tls-audit.md) and
[remaining deployment work](production-readiness.md). To reproduce the local CA
test, explicitly run `make acme-test-setup` then `make acme-integration` on Linux.

For SIGHUP reload, SIGTERM/SIGINT draining, redacted JSON logging and the optional
loopback `--monitor` endpoints, see [runtime operation](runtime.md). Hostname and
ACME identity changes require restart; root/publication changes can be reloaded.
