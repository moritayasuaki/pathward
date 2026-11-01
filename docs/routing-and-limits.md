# Mixed routing and per-service limits

A site can now combine denied subtrees, explicitly published local files,
configured redirects and one loopback HTTP upstream. One hostname is one proxy
service: every `proxy-path` in that site shares its upstream and budgets.

```kdl
site "app.example" {
    tls "auto"
    root "/srv/public"
    publish "/robots.txt" "robots.txt"
    publish "/sitemap.xml" "sitemap.xml"
    deny "/admin"
    deny "/internal"
    redirect "/old" "app.example" "/new" "308"
    reverse-proxy "127.0.0.1:3000"
    proxy-path "/api"
    proxy-path "/new"
    proxy-limit "request-body" "16KiB"
    proxy-limit "response-body" "8MiB"
    proxy-limit "connections" "2"
    proxy-timeout "request-body" "5s"
    proxy-timeout "connect" "3s"
    proxy-timeout "response-head" "70s"
    proxy-timeout "total" "90s"
    header "*" "x-frame-options" "DENY"
}
```

Create the declared files before server preflight/managed activation. `root` is
required for publications. It does not grant directory access. Configuration-only
checking does not open files or test upstream health. These directives add no
parser library or dependencies.

## Selection is final

After Host and TLS identity validation, the order is:

1. Invalid routing spelling or a matched `deny` → reject.
2. Explicit publication → GET/HEAD through the existing verified grant and Linux
   file opener. Missing files, symlinks, wrong methods and other local failures
   are final responses; they never retry through the proxy.
3. Configured redirect → the existing fixed-host, checked redirect serializer.
   A serialization/method failure is final, with no proxy fallback.
4. Matched proxy scope → the configured loopback upstream.
5. No selected route → 404.

Directive order does not change this precedence. Denial can deliberately shadow
a publication or redirect. Publication/redirect overlap remains a configuration
error. Denial also precedes the optional automatic HTTP→HTTPS redirect: a denied
URL is not redirected to HTTPS. Configured redirects retain the existing
bodyless GET/HEAD policy; automatic redirects for selected proxy requests can
preserve the supported proxy methods with 308.

`deny "/admin"` rejects `/admin`, `/admin/` and descendants such as `/admin/users`,
but not `/administrator`. `proxy-path` uses the same component-boundary subtree
matching. `/` explicitly selects all routable paths. Matching is ASCII,
case-sensitive and does not inspect the query. There are at most 64 distinct
`deny` declarations and 64 distinct `proxy-path` declarations per site.

Without `proxy-path`, the upstream is the fallback for otherwise unmatched
admitted paths. With one or more `proxy-path` declarations, no other path is
proxied. With no upstream, proxy scopes and budget directives are errors.

## Routing spellings and application boundary

A site containing any publication, redirect, denial or proxy scope uses a strict
routing spelling: the existing canonical ASCII path grammar, plus one optional
final slash. Hidden/dot components, duplicate slashes, percent escapes in the
path, semicolons, backslashes and non-ASCII path bytes are rejected. This avoids
routing one byte spelling while a backend decodes it into another protected path.
Queries may contain percent escapes and are forwarded unchanged; they cannot
select another route. Malformed transport targets receive 400 on proxy sites;
noncanonical routing paths and explicit denials receive generic 404.

The final slash is removed **only for route comparison**. For `/robots.txt/`, a
publication of `/robots.txt` reserves the local route, but the file authorizer
still checks the original target and returns 404. It never grants an alias or
falls through. Proxy requests retain their original target bytes, including a
permitted final slash and query.

An existing whole-host proxy with no route declarations keeps its broader raw
path behavior. Adding a route declaration intentionally enables strict routing
for the entire site. Check application URLs before enabling it. This milestone
does not support encoded/Unicode routing paths, path rewriting, query matchers or
multiple upstream services under one hostname.

Denial is a byte-path routing policy, not application authentication. A backend
that aliases case variants, rewrites routes or dispatches by query/body must apply
its own authorization. Do not delegate administrative services or assume a
single path rule can describe application-specific aliases. Existing request
header sanitization and trusted forwarding regeneration still apply.

## Proxy budgets

| Directive | Default | Accepted range / units |
| --- | --- | --- |
| `proxy-limit "request-body"` | `1MiB` | `0B` through `16MiB` |
| `proxy-limit "response-body"` | `8MiB` | `0B` through `64MiB` |
| `proxy-limit "connections"` | `2` | Integer 1–3 |
| `proxy-timeout "request-body"` | `5s` | 100ms–30s; no greater than total |
| `proxy-timeout "connect"` | `2s` | 50ms–10s; no greater than total |
| `proxy-timeout "response-head"` | `10s` | At least 100ms; no greater than total |
| `proxy-timeout "total"` | `15s` | 100ms–120s |

Sizes require `B`, `KiB` or `MiB`; durations require `ms` or `s`. Values are
canonical nonnegative decimal integers, with no fractions, signs, leading zeroes
or implicit units. Overflow, duplicate/unknown settings and inconsistent budgets
reject the entire candidate. A smaller total may require explicitly reducing
its phase budgets as well.

Request time runs from socket acceptance through the complete request, including
queue/TLS/head time. The global five-second initial head/TLS budgets remain in
force before host selection; increasing a service body budget does not extend
those unauthenticated stages. A complete prefetched body is checked against the
request deadline too. The connect budget starts at connect. The response-head
budget starts after the upstream request write. Every operation is also bounded
by the total deadline from acceptance; successful reads/writes do not reset it.
After receiving the head, response-body reads and downstream writes share the
remaining total budget. An error response has up to one additional second.

Request capacity failure returns 413 before upstream contact. Invalid/oversized
upstream content returns 502 before success headers; timeout returns 408 for the
request or 504 for the upstream. Content-Length, cumulative decoded chunks and
connection-close responses all use the configured response bound, including
metadata Content-Length on HEAD/304. Ambiguous framing remains forbidden. There
are no automatic retries. [WebSocket/SSE](streaming.md) has separate explicit
opt-ins and finite session budgets.

The connection setting counts the whole proxy exchange from request-body
consumption through downstream output. Exhaustion returns 503 immediately; there
is no service wait queue or upstream attempt. The existing four-worker/global/
per-peer limits remain independent upper bounds. Three is a hard service maximum, so a single proxy service cannot hold
all four workers. Static traffic or multiple busy services can still occupy all
workers. These settings do not increase worker count or change static file
limits (64 MiB and the existing write budget).

## Reload, rollback and resource consequences

Routes, target endpoint, body limits and time budgets are captured together in
one immutable request snapshot. Existing requests retain that policy. Reload is
not immediate revocation; drain active requests when removing access.

Connection accounting is shared by hostname across all generations, including
upstream changes and switching to/from static mode. Candidate preparation never
changes the active cap. Successful SIGHUP or managed activation installs the cap
at the snapshot commit point; failed persistence leaves it unchanged. Rollback
uses the same mechanism. Admission requires space under **both** the captured and
currently installed cap. Reducing a limit does not terminate active exchanges,
but it blocks new ones while their shared count is at or above the new cap.
Removing the upstream disables new admissions from captured old proxy snapshots.
A poisoned budget fails closed.

`generate` can update the static manifest of a mixed site with an existing root.
It preserves denials, proxy scopes, upstream and every budget, then recompiles the
complete result. It cannot turn a rootless proxy into a file publication site.
Managed file preflight and expected generation/digest checks remain unchanged.

Buffering stays finite but increasing limits has a real memory cost. At hard
limits, four workers can retain approximately 320 MiB of request/response payload
alone, plus allocator/TLS/runtime overhead. Choose lower limits for the deployed
memory budget. Longer requests also lengthen graceful drain. If using the full
120-second total, allow at least 130 seconds in the supervisor on trusted local
storage, and retain an explicit forced-stop policy for stalled OS/storage calls.
This is not a guarantee of wall-clock process termination.

Readiness still describes the frontend/certificate, not the upstream application.
Service saturation appears as a 503 in existing aggregate telemetry; per-service
labels/alerts and active backend health checks are not implemented. Add an
external application probe before migration.

## Audit and formal boundary

Manifests, lockfiles, dependency features and vendored sources are unchanged.
Fresh reviewed-graph/RustSec checks report zero findings or warnings; external
package counts remain core 0, configuration 8, server 104. The scan record is
[server/audit-result.json](../server/audit-result.json). Source review covered KDL
units/overflow, route precedence, unchanged file grants, framing/cumulative bounds,
absolute deadline edges and the two runtime commit paths. The relevant protocol
framing baseline remains [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3).

[RoutingProofs.lean](../proofs/RoutingProofs.lean) adds 32 audited statements,
bringing that milestone to 185; the streaming extension brings the total to 221. Proofs apply to extracted Rust route selection,
canonical stem/unchanged-or-final-slash shape, admitted path bytes, subtree
boundary, body/chunk bounds, dynamic-limit framing, time bounds and admission
under captured/live connection caps. The earlier exclusive-mode theorem is
replaced by the actual mixed-mode requirement that publications have a root.
Existing generation/persistence/stop proofs remain active.

The KDL parser, schema-to-field wiring, socket timing, byte copying, Linux file
operations and Mutex/Arc lifetime handling remain reviewed/tested trusted code;
Lean does not prove thread scheduling, actual elapsed time, application semantics
or end-to-end HTTP safety. Rust/TCP tests cover the corresponding adapters.
Linux tests additionally cover mixed local files with no fallback, durable
activation failure and rollback while an old upstream connection remains active.

Established WebSocket/SSE sessions use the separate `proxy-limit "streams"`
budget (default eight, range 1–16). Ordinary `connections` capacity is released at
stream handoff; see [streaming admission](streaming.md#finite-resources-and-shutdown).
