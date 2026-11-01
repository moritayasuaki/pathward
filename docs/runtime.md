# Reload, shutdown, logs and monitoring

On Linux, both CLI serving modes install SIGHUP, SIGTERM and SIGINT handlers before
starting worker threads. Existing KDL files continue to work. The later
[production basics](production-basics.md) extension adds headers/redirects and an
optional private managed activation/rollback workflow.

```sh
pathward-server serve-http /etc/pathward/Pathward.kdl 127.0.0.1:8080 \
  --monitor 127.0.0.1:9090
# Or append --monitor 127.0.0.1:9090 to the existing serve-tls command.
kill -HUP "$PATHWARD_PID"
kill -TERM "$PATHWARD_PID"
```

## Transactional reload

Publish a complete KDL file by writing a temporary file in the same trusted
directory and atomically renaming it over the configured pathname, then send
SIGHUP. Keep the configuration and its parent directories writable only by the
service administrator. The CLI pins one descriptor with O_PATH/NOFOLLOW, rejects nonregular/oversized
inputs before data opening, reopens through trusted procfs with NONBLOCK and an
inode identity check, and retains the 1 MiB parser limit.
Concurrent in-place writes are not a supported configuration publication method.
Symlink configuration files are refused. Trusted local filesystem operations can
still block in the kernel; NONBLOCK does not time-limit regular-file I/O.

The reload worker serializes and coalesces signals. It parses and compiles the
whole candidate, checks the unchanged host set and exclusion of private ACME
and managed control storage, then pins every candidate document root with the existing no-symlink
opener. It commits one immutable snapshot (owned host/rule/redirect/header bytes plus pinned root
descriptors) under a short write lock. Any parse, schema, identity, isolation,
root-open, generation-overflow or draining failure retains the current generation.
Successful no-op reloads also increment the generation, starting from 1.

Every dispatched HTTP request clones exactly one snapshot before reading its
headers. Its host selection, publication lookup and file open all use that
snapshot. Requests already in progress may finish with the previous rules after a
reload, including a removed publication. Queued connections choose the current
snapshot when their worker starts HTTP processing. Reload is not immediate
revocation of active requests or already established TLS sessions. At most four
requests retain old snapshots; repeated signals cannot create an unbounded
queue of configurations. Old root descriptors close when their last request ends.

**Reloadable:** exact publications, redirects, headers and document roots, including replacing a root
pathname with another directory. Missing published files are still denied at
request time; reload validates roots and rules, not every file's contents.

**Restart required:** adding/removing/changing hostnames, listener and monitoring
addresses, ACME directory/contact/cache identity and other CLI options. Host order
may change. The fixed domain set keeps every reloaded publication aligned with
the existing certificate/ACME identity; this release does not implement a
multi-certificate or domain-change transaction. Use a fresh bound cache when
changing ACME identity, as described in the TLS guide. Library users must pass the
same validated cache pathname to `Server::new_with_cache` and `Manager::new`.

## Graceful shutdown

SIGTERM/SIGINT set an atomic flag. The accept loop closes the serving listener,
marks the server draining, discards queued sockets, and joins the four ordinary and 16 stream
workers. Established streams have separate global/peer/host leases and release
ordinary admission/dispatch slots at handoff. The bounded dispatcher runs at most two jobs per peer, skips busy peers
without dropping their queued work, and wakes waiting workers during shutdown.
Active HTTP/TLS exchanges finish under their existing total deadlines:
5 seconds for TLS handshake, 5 seconds for HTTP headers, 10 seconds for a
response, or 1 second for an error. New reload commits are refused after the
server enters draining; a concurrent signal is sampled again inside the commit
lock. The ACME worker cancels its pending asynchronous order, clears challenges,
and exits. Durable private-key writes already running finish normally. The
monitor stays available during network draining, with readiness returning 503.

A Server instance has one serving lifetime. Construct a new instance for a
restart. Repeated termination signals do not bypass cleanup. Configure an external
supervisor stop timeout (for example 30 seconds with default budgets, or at
least 130 seconds with the maximum proxy total, on trusted local storage) and a
final forced-stop policy. Socket budgets cannot interrupt stuck filesystem/DNS
work or prove an OS scheduling bound; there is no unconditional process-exit
latency guarantee. Errors spawning service workers also stop/join already started
background workers.

## Logs

Runtime logs are newline-delimited JSON on stderr: `listening`, `request`,
`reload_committed`, `reload_rejected`, `draining`, `stopped`, certificate states
and ACME attempt/success/failure events. Fields contain only fixed event names and
numeric/boolean values: timestamp, generation, status, completed body bytes,
duration, port, and event-specific value (ACME retry seconds on failures).
Requests that fail I/O use status 0 and completed body bytes 0; partial response
bytes are not counted. Startup argument/configuration failures can emit a plain
error diagnostic before logging starts.

No URL, query, Host/SNI, client address, headers, filesystem path, configuration
text, private key, certificate PEM, ACME response body or account identifier is
recorded in runtime logs. Request fields cannot inject log records. A dedicated
writer consumes a 256-record bounded queue; producers drop excess records without
blocking serving, and `pathward_log_dropped_total` reports that loss. Broken stderr
also leads to drops. Logging is best effort: pending records may be lost at exit,
and logging failure does not take down file serving. Collect/rotate stderr through
the service supervisor; no log file dependency or automatic external delivery is
introduced.

## Read-only monitoring

`--monitor IP:PORT` is optional and accepts only literal loopback IPs, with port 0
supported. It uses a separate listener and one worker, a 500 ms total read/write
budget, bounded existing HTTP parsing, and one request per connection. It has no
reload/administration endpoint, filesystem access, credentials or configuration
output. Do not expose it through an untrusted reverse proxy; loopback is not an
authentication boundary between local users. Only GET and exact targets work;
query strings and other paths are not matched. With IPv6 loopback transport use
`Host: localhost`, since the shared parser rejects IPv6-literal authorities.

| Endpoint | Behavior |
| --- | --- |
| `/healthz` | 200 while the monitoring worker answers, including draining |
| `/readyz` | 200 only while serving, not draining, and (in TLS mode) a currently valid certificate is installed; otherwise 503 |
| `/metrics` | Prometheus text format with fixed metric names and bounded status-class labels |

Metrics include accepted/active/overloaded connections, completed responses,
request I/O and handshake errors, completed body bytes, reload successes/errors,
configuration generation, admission rejections, ACME attempts/activations/errors, dropped logs, readiness,
draining, TLS enablement and certificate presence/not-before/not-after UNIX times.
Counters reset on process restart; a scrape is a collection of atomic observations,
not a transaction across all counters. Readiness does not check every file or
predict successful future renewal. A removed/unreadable file remains a 404.

Connect a local Prometheus-compatible collector and external alert manager. Useful
conditions include `pathward_ready == 0`, growth in reload/ACME/I/O error counters,
log drops/overload, and `pathward_certificate_not_after_seconds - time()` below a
deployment-specific margin while TLS is enabled and a certificate is present.
No email, webhook, paging account or live monitoring service is configured here.

See the [runtime audit](runtime-audit.md) for the dependency review, tests and
precise Lean proof boundary.

Proxy route/body/time budgets are captured with the request snapshot. Per-host
connection accounting survives reload and rollback and applies both captured
and current caps; see [routing and limits](routing-and-limits.md).

Opt-in WebSocket/SSE relays observe shutdown without waiting for their full
session lifetime. Established streams close their transports on stop; clients
must reconnect and may see an abnormal/incomplete close. Ordinary HTTP and
handshakes retain their existing drain budgets. See [streaming](streaming.md).
