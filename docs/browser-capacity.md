# Real-browser capacity rehearsal

The shared-NAT profile needed additional headroom for 24 simultaneous browser
reloads. Its old 64-per-peer / 128-global connection refill rates covered the
protocol-client workload, but actual browser reloads produced a multi-second
asset-response wave. One measured second reached 184 completed requests.
Ordinary application polling was about 34 requests/second. A single cold asset
burst followed by polling did not represent this workload.

The new opt-in profile allows 256 refill credits/second per peer and 512 globally,
with unchanged bursts of 384/512. Admitted and queued sockets are capped at
192 per peer and 256 globally, with a 252-socket dispatch queue. Four workers,
two running jobs per peer, 256 peer-table entries, service/stream limits, body
bounds and deadlines are unchanged. The standard profile is unchanged.

This permits four times the previous sustained unauthenticated connection rate
and 64 additional globally admitted sockets (33%). A peer still cannot occupy
all admission slots or all workers. More queued sockets consume kernel memory;
these changes are finite capacity limits, not a denial-of-service guarantee.
An existing deployment selecting `shared-nat` receives the new bounds on upgrade
and restart. Ordinary reload cannot change the profile or refill admission credit.

## Scope and method

The rehearsal uses the installed Chrome 156.0.8078.79 in its unified headless
mode, controlled through CDP with Node built-ins. Twenty-four independent browser
contexts have separate cookies, storage and caches. All pages report visible;
background timer/renderer throttling is disabled to represent active users.
The normal browser profile is never opened. No browser automation package is
installed. This is one client machine, not 24 independent physical devices.

All application requests go through an SSH loopback tunnel to a private Linux
staging service, appearing as one source IP. The final functional run enables
SSH transport compression; this is not PathWard HTTP compression or a public-link
performance benchmark. The application uses captured public
frontend files and two separately launched backend versions with synthetic state
and empty private-photo storage. Six rooms are created through the actual UI,
with one host and three guests in each; all 24 actor IDs must be distinct.
Hosts start games and open a cell. Every participant's rendered board is checked
for agreement within its room. Participants send 24 comments simultaneously.
No create/join/command POST is retried by the test driver.

The initial navigation starts with empty per-context caches. Reconnect tests use
synchronized ordinary page reloads with browser caching enabled. Network URL
blocking confines page traffic to staging without Fetch request interception.
An earlier interception-based diagnostic was retained separately; the original
failure was also reproduced without interception before changing the server.

Configuration churn alternates static roots, response headers and discovery
candidate order. Each acknowledged activation must return the matching marker
and header on a fresh request, and the private canary must remain 404. Attempts
to change the capacity profile must preserve generation, digest and durable
configuration. Browser response checks require stable room/actor identities,
monotonic revisions, four members per room and the configured generation header.
Only synthetic room identifiers are inspected; bearer tokens and response bodies
are not saved in the report.

Admission rejection, overload, request I/O error, 5xx and lost-log counters must
remain zero. Navigation cancellations are recorded separately from empty-response
or connection failures. A response body invalidated by a new document loader is
recorded as a CDP navigation diagnostic; other verification errors fail the test.
Browser counters and server counters are reported separately: browser cache and
request cancellation mean they are not interchangeable request totals.

The entire server group has CPUQuota=100%, MemoryMax=512M and TasksMax=128.
One-second samples enforce PathWard RSS <256 MiB, at most 32 threads and 512 FDs.
The browser harness caps summed process RSS at 12 GiB and stops if OS-reported
free memory falls below 15%. Summed Chrome RSS double-counts shared memory; it
is not unique physical memory usage. Production Caddy/config/routes/service PIDs
and TCP listeners are compared before and after cleanup.

## Retained comparison runs

| Candidate | Peer/global rate per second | Peer/global sockets | Outcome on synchronized reload |
| --- | --- | --- | --- |
| Previous shared-NAT profile | 64 / 128 | 144 / 192 | 1,746 peer-rate rejections; 125 browser empty responses |
| First rate increase | 128 / 256 | 144 / 192 | 17 peer-occupancy rejections; 2 browser empty responses |
| Added overlap capacity | 128 / 256 | 192 / 256 | First reload passed; second had 18 peer-rate rejections and 1 empty response |

These are separate observed runs, not a controlled throughput benchmark or an
exhaustive capacity search. All used 24 contexts and six synthetic rooms. The
original failure was reproduced with ordinary caching and no Fetch interception.
Do not treat the diagnostic `failures` array alone as a pass: network error counts
and server rejection counters are independently checked.

An additional final-code attempt kept browser transport/rejection counters at
zero, but its driver stopped when a monitor scrape through the same bulk-transfer
SSH connection disconnected. The monitoring listener has a 500 ms deadline;
SSH congestion is a plausible explanation, not a proven server defect. Subsequent
runs scrape directly on the Linux host over a separate SSH connection, preserve
scrape errors and reject stale samples. The interrupted attempt is not reported
as a completed pass. Its bounded service later expired while awaiting operator
input. A separate cold-start attempt exceeded the driver's 45-second UI wait
while fixture transfer also used the network. That incomplete attempt is retained;
a later cold-start wait was bounded at 240 seconds with no fixture transfer.
That run still measured about 224 seconds for a JavaScript response at the browser,
while server-side writes completed promptly with zero rejection/I/O counters. It
was stopped during room setup, not counted as a pass. The slow shared test link
therefore remains a limitation even without fixture transfer; final functional
verification uses SSH compression and public-network performance remains unproven.

## Regression, proof and audit

A deterministic admission regression offers 200 requests/second from one peer
for 20 seconds while another peer offers 100/second. Exhaustion/refill tests still
assert the finite credit boundary. Linux tests fill the 252-socket queue, reject
one more entry, verify the 192-peer bound and check unrelated-peer progress.
The browser replay remains necessary; this synthetic envelope is not a browser.

The actual Rust constants and gates are re-extracted with Charon/Aeneas. All
275 audited Lean statements must pass with no proof holes or nonstandard axioms,
including the updated finite capacity/refill arithmetic, queue-plus-workers
identity, strict peer/global inequality, exact rejection classification,
standard-profile equivalence and capacity preservation on accepted reload.
These do not prove the browser, KDL parser, clocks, socket queues, OS, ACME CA or
complete deployment correct.

No package, feature, manifest, lockfile or vendored dependency was changed.
The reviewed graphs remain core 0, configuration 8, server 104 and unused
candidate 163 external packages. The refreshed [RustSec record](../server/audit-result.json)
uses database `e52a8212cbf9b915380afd9534da050d6f5d9af1` with no findings or warnings.
The source review covered the opt-in rate/occupancy increases, conservative
bucket accounting, queue capacity, metric derivation, immutable profile and
preservation of the existing worker/service/stream boundaries. Test tooling uses
preinstalled Chrome/Node/Python and no added package; this is not a full source
or vulnerability audit of those installed tools.

## Public TLS is a separate gate

This browser run uses HTTP over SSH. It does not establish public-network TLS,
public-CA issuance, public certificate renewal or browser/certificate-update overlap.
Linux CI separately runs real local-CA TLS-ALPN-01 issuance, renewal, persistence,
restart and overlapping configuration changes. Neither replaces a public-CA test.

The deployment operator is responsible for administrator commands. A private
single-host certificate-probe configuration preflights the actual 13 portal files
and current security headers; it is not a complete multi-host migration config.
Its administrator preparation does not stop the shared server or issue a certificate.
Any public-port probe requires an agreed interruption window, an independent
rollback watchdog, dedicated service ownership, separate staging/production CA
stores and an external chain/hostname check. The ordinary public certificate
renewal interval is not shortened by changing the production clock.

HTTP compression is also absent: large JavaScript payloads and repeated image
fetches need measurement on the actual public connection against the existing
server before accepting cold-entry and reconnect latency.

Full replacement remains gated on all current host/route/header/publication
policies, deployment ownership, real-entry-point recovery and external alerts.
One inspected long-response upstream allows six concurrent connections; the
current PathWard service maximum is three. This difference and shared-worker
occupancy must be resolved or explicitly accepted before full migration.

Primary browser references: [Chrome Headless](https://developer.chrome.com/docs/automation-and-testing/headless),
[CDP Target](https://chromedevtools.github.io/devtools-protocol/tot/Target/),
[CDP Network](https://chromedevtools.github.io/devtools-protocol/tot/Network/).
