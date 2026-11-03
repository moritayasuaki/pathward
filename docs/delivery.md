# Bounded input and downstream delivery

The cold-browser rehearsal exposed ordinary workers waiting on incomplete heads
and slow downstream image transfers. A queued request could then reach a worker
after its five-second header deadline had already expired. Admission headroom
alone did not correct this scheduling problem.

One fixed input/output thread now collects bounded HTTP heads and writes completed
ordinary responses using nonblocking sockets. Four ordinary workers still perform
strict parsing, policy selection, confined file opening, TLS handshakes and
upstream exchanges; at most two such jobs run per transport peer. No dependency,
per-connection thread, mutation retry or unbounded queue is added.

## Ownership, limits and deadlines

- Ordinary admission leases cover input collection, ready queue, upstream work
  and downstream delivery. Limits remain 12 global / 6 peer in the standard
  profile and 256 / 192 in shared-NAT. Established streams retain their separate
  16-slot pool and independent quotas.
- HTTP heads remain at most 16 KiB, with five seconds from plaintext acceptance
  or completed TLS. Idle preconnections close silently on expiry; partial heads
  get 408. A complete head has five seconds to reach a worker, otherwise 503
  before upstream contact. Neither phase restarts on incremental progress.
- TLS handshakes retain five seconds from TCP acceptance, including their queue.
  Service request/total budgets include HTTP head reception but exclude the ready
  queue and TLS phase. This is an intentional change from acceptance-based HTTP
  service accounting, not an extension without a finite bound.
- Completed proxy responses retain validated bytes, serialized headers, original
  total deadline and generation. Their upstream/service permit is released, while
  ordinary admission and byte leases remain until output finishes or fails.
- Response reservations are capped at 256 MiB globally and 192 MiB per canonical
  peer. Before upstream contact, reserve twice the configured response cap plus
  256 KiB. Body builders allocate their validated maximum once; conversion to an
  exact boxed slice releases unused capacity before the reservation shrinks.
  A refused reservation returns 503 without sending even a mutation upstream.
- File responses retain an already-confined file descriptor, range offset/count,
  serialized headers and generation. They never re-open a pathname after reload.
  Their reservation covers 256 KiB head allowance plus a 16 KiB file chunk.
- Each polling pass writes at most one 16 KiB chunk per connection. Output has a
  five-second idle budget and its existing absolute total budget. Shutdown caps
  remaining downstream delivery at five seconds and discards unfinished input.
  TLS plaintext offsets advance only after successful writes; pending encrypted
  bytes and close-notify finish before ownership is dropped.

The byte budget is shared across every configuration generation. Lowering a
service limit does not erase old reservations. `connections_active` now counts
all admitted input, queued and delivering connections, plus established streams;
it is no longer bounded by the four ordinary worker threads.

The byte proof describes logical reservations. Request bodies, headers being
parsed, TLS/allocator metadata, stacks and kernel buffers need additional memory.
Capacity refusal is conservative: a request may be refused based on its configured
maximum even if its eventual response would be small.

## Verification and reviewed boundary

`DeliveryProofs.lean` checks the four actual extracted Rust gates for reservation
limits/overflow, draining, non-increasing reservation shrink, absolute phase
expiry and idle-versus-partial timeout classification. The axiom audit contains
289 named proofs across the project. It does not prove the reactor's scheduling,
RAII/Mutex implementation, allocator, clock, TLS or filesystem.

Source review covers ownership transfers on every failure path, lease retention
across reload, allocation-before-shrink order, pre-mutation capacity refusal,
buffered-head preservation, partial writes, TLS socket mode transitions, thread
startup failure and bounded shutdown. `scripts/delivery_smoke.py` exercises 24
unread multi-megabyte responses from one IP, concurrent mutations without retry,
reload header/body consistency, old-generation byte reservations and shutdown.
Rust tests cover exact byte ceilings, lease release and prefetched bodies larger
than the parser's old read chunk. Existing Linux/TLS/stream/ACME tests remain gates.

This change does not add HTTP keepalive, HTTP/2/3, HTTP compression, asynchronous
upstreams or a larger per-service upstream cap. A stalled request body/upstream
still occupies an ordinary worker until its bounded deadline. File open/read and
metadata syscalls can block on unhealthy storage, including the 16 KiB read in
the output loop; trusted local storage and an external supervisor remain required.

The runtime commit `92a6bf1` passed [Linux CI](https://github.com/moritayasuaki/pathward/actions/runs/41498881113),
including HTTP/stream regression, TLS-ALPN issuance, renewal/restart/persistence
failure, overlapping ACME/release churn, RustSec and all Lean proofs.
Final adapter review also corrected a timeout race: if the transport deadline
expires just after the input phase check, a partial head still receives 408 rather
than silently closing. The socket regression now checks partial-head expiry and
silent idle-preconnection expiry. The extracted classification gate is unchanged.
The browser report below identifies the preceding `92a6bf1` binary; this small
follow-up has not been given a new full browser acceptance run.

## Real-browser result — 2026-11-03

**Acceptance remains failed.** The [sanitized result](delivery-browser-result-2026-11-03.json)
records 24 independent cold-cache Chrome contexts over independent SSH SOCKS
paths, sharing one server source address. All six room creations returned 201,
but all 18 guest joins aborted at the application's ten-second deadline. Nine
asset requests and three polls had empty responses; three polls had socket-not-
connected errors. Six actors/six rooms were verified. Neither synchronized reload
wave was reached, and no mutation was retried.

The private UI driver stopped once while inspecting a navigating guest document;
guest entry resumed without repeating room creation. The next diagnostic guarded
the absent document body. This interruption remains part of the recorded trial.

The last browser-phase monitor sample had zero admission refusals, queue overload,
I/O errors, 5xx and log drops. The entire server log contains no 408. These counters
do not negate the browser failures: input can expire before a request is observed,
and a completed socket write does not prove delivery to the browser. In particular,
the new five-second empty-preconnection close and the SSH transport need targeted
connection-lifecycle tracing before the empty responses can be attributed.

The bounded remote controller subsequently completed 1,475 configuration switches,
210 rejected capacity changes and 1,475 marker/private checks without a recorded
policy failure. This includes remote-only activity after browser failure, not
75 minutes of successful interactive load. Sampled PathWard peaks were 64,208 KiB
RSS, 26 threads and 68 descriptors. All four owned child processes exited zero;
production configuration, adapted routes, service PIDs and TCP listeners matched
their pre-test inventory.

A separate Caddy 2.11.7 diagnostic used the same public asset fixture, cold Chrome
contexts and SSH topology, with HTTP/1.1 and no compression. Six creates and 14 of
18 joins returned 201; four joins aborted, leaving 20 verified actors. For one
aborted join, no `requestWillBeSentExtraInfo` event was observed; three had that
network-stack metadata event. Its presence/absence is not proof of wire delivery
or non-delivery. Successful joins had up to 5.130 seconds before send and 9.741
seconds before response headers in CDP `ResourceTiming`.
Both Caddy children exited zero and the production inventory again matched.

This establishes that the available browser/link path also reaches the client
deadline with Caddy. It is not a throughput comparison: Caddy used one upstream,
no configuration churn and the corrected snapshot guard. It does not explain away
PathWard's empty responses or prove that HTTP/2 would fix every failure.

Before migration, trace connection lifetime and browser queue/send/receive timing
on PathWard, implement/review connection reuse and HTTP/2 as appropriate, and
repeat cold entry plus both reload waves. HTTP compression may reduce JavaScript
traffic but will not remove the already-compressed sprite workload. Public-link
TLS/CA and production cutover remain separate pending gates; the current draft
must not be promoted on the basis of green CI alone.
