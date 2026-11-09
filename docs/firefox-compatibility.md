# Firefox multiplexed transport compatibility

Firefox 159.0.1 sent `te: trailers` on an ordinary HTTP/2 navigation. The
deployed adapter rejected all TE fields and returned status 400 with an empty
body, leaving a blank page. Fresh Firefox profiles reproduced this twice;
restricting the test profile to HTTP/1.1 loaded the same public page. A single
HTTP/2 request with that header also reproduced the rejection. Chrome-only
testing did not expose the difference.

[RFC 9113 §8.2.2](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.2.2) and
[RFC 9114 §4.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2) permit
this specific TE value. It advertises support for response trailers; it does
not change request framing or require the server to send trailers.

The shared adapter now accepts the eight-byte token in every ASCII casing,
checks the extracted byte policy, and removes the field before the HTTP/1
parser and proxy. Empty values, other codings, lists, parameters, whitespace,
duplicates and forbidden connection fields remain refused. Actual request
trailers and declared/actual body-length mismatches are rejected before the
responder. Admission, publication, routing and byte limits remain applicable.

An interrupted-trailer regression also exposed a cancellation defect in the
locked `h3-quinn 0.0.10` adapter: a pending read owns the receive stream, while
`stop_sending` and `recv_id` unwrap its empty slot. Our bounded adapter caches
the immutable stream ID and drops the owned pending read when cancelling.
Quinn's receive-stream destructor stops unread input. A cancelled bidirectional
wrapper also drops its send half; subsequent operations fail without dereferencing
the removed stream. No dependency or lockfile changes are required.

## Validation

- Firefox 159.0.1 on macOS: fresh profiles loaded the fixture page and image
  twice over each of HTTP/2 and HTTP/3, with status 200 and the expected protocol.
  See `firefox-compatibility-browser.json`; Android remains a deployment check.
- All 256 ASCII casings of the TE token, rejected alternatives and duplicates.
- Real TLS HTTP/2: 24 multiplexed requests with TE, gzip, SSE and cancellation;
  the upstream never receives TE and request trailers do not reach it.
- Real HTTP/3: TE with zstd and address migration, request-trailer refusal,
  interrupted input followed by another request on the same connection, and
  early proxy refusal.
- A deterministic pending-read ownership test checks cancellation, stable ID,
  immediate destruction and repeated cancellation without a panic.
- Eight Lean statements cover exact normalized-token acceptance, the upstream
  prohibition, body-length agreement, request-trailer refusal and totality.
  The adapter's ASCII conversion, HTTP libraries, executor and destructors are
  tested integration boundaries, not proven end to end.
- The existing locked dependency graphs are unchanged. RustSec audit on
  2026-11-09, database `899077d9d471b9fd3dbf4b2faea8ef26e83692e8`, found no
  vulnerabilities or warnings in any of the five audited profiles.

## Repeatable browser check

Build the server's test executable with
`cargo +1.99.1 test --offline --locked --manifest-path server/Cargo.toml --lib --no-run`.
Then run `node scripts/firefox_smoke.mjs FIREFOX SERVER_TEST_BINARY` with an
existing Firefox executable and the printed `pathward_server-*` test path.
No browser or package is installed by this script.

The ignored fixture runs only on loopback, creates an ephemeral test key in
memory, and exits after at most 60 seconds. Fresh profiles use local app-data
overrides. The HTTP/2 SOCKS adapter accepts only the fixture authority;
HTTP/3 uses a Firefox test mapping to the local UDP port. Test sessions allow
the fixture's self-signed certificate; public-site certificate verification
and installed browser profiles are not changed. Each protocol must load the
page and image twice with the expected protocol, title and status. The test
prints the private result directory and closes its own processes and sockets.

The production configuration and executable are not changed by these tests.
Deployment and a final check on the affected Android device are separate
acceptance steps. Desktop Firefox reproduction is not an Android-device test.
