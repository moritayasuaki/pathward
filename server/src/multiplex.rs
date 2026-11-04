//! Multiplexed transport adapters share the exact publication/proxy responder.
use crate::{
    Handoff, ResponseHandoff, Server, admission, async_http, delivery,
    http::{self, Transport},
    observe,
    runtime::Snapshot,
    streaming,
    tls::TlsTransport,
};
use bytes::Bytes;
use std::{
    future::Future,
    io::{self, Read, Write},
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

// A last admission before 120s may wait 5s, use a 120s response budget,
// then carry a stream for at most 3600s. Five seconds remain for final flushing.
// Per-request/stream deadlines still apply; this is only a connection backstop.
pub(crate) const CONNECTION_CEILING: Duration = Duration::from_secs(3850);
#[derive(Default)]
pub(crate) struct Retirement {
    began: Option<Instant>,
    stopped: Option<Instant>,
}
impl Retirement {
    pub fn begin(&mut self) -> bool {
        if self.began.is_some() {
            false
        } else {
            self.began = Some(Instant::now());
            true
        }
    }
    pub fn stopping(&mut self) {
        self.stopped.get_or_insert_with(Instant::now);
    }
    pub fn retiring(&self) -> bool {
        self.began.is_some()
    }
    pub fn close(&self, active: usize, held: bool, idle_since: Instant) -> bool {
        let elapsed = |at: Option<Instant>| {
            at.map_or(0, |t| t.elapsed().as_millis().min(u64::MAX as u128) as u64)
        };
        pathward::delivery::retirement_close(
            self.retiring(),
            elapsed(Some(idle_since)),
            active as u64,
            held,
            self.stopped.is_some(),
            elapsed(self.stopped),
        )
    }
}

/// Tokio traits only: h2 does not require a second executor. A readiness timer
/// wakes the existing bounded cooperative executor when the socket would block.
pub(crate) struct Io<T> {
    inner: T,
    wake: Option<async_io::Timer>,
    read_seen: Option<Arc<AtomicBool>>,
}
impl<T> Io<T> {
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            wake: None,
            read_seen: None,
        }
    }
    fn with_read_observer(mut self, seen: Arc<AtomicBool>) -> Self {
        self.read_seen = Some(seen);
        self
    }
    fn wait(&mut self, cx: &mut Context<'_>) {
        let timer = self
            .wake
            .get_or_insert_with(|| async_io::Timer::after(Duration::from_millis(2)));
        if Pin::new(timer).poll(cx).is_ready() {
            self.wake = None;
            cx.waker().wake_by_ref();
        }
    }
}
impl<T: Read + Unpin> tokio::io::AsyncRead for Io<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.inner.read(out.initialize_unfilled()) {
            Ok(n) => {
                if n > 0
                    && let Some(seen) = &self.read_seen
                {
                    seen.store(true, Ordering::Relaxed);
                }
                out.advance(n);
                Poll::Ready(Ok(()))
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                self.wait(cx);
                Poll::Pending
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}
impl<T: Write + Unpin> tokio::io::AsyncWrite for Io<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.inner.write(b) {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                self.wait(cx);
                Poll::Pending
            }
            r => Poll::Ready(r),
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.inner.flush() {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                self.wait(cx);
                Poll::Pending
            }
            r => Poll::Ready(r),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
fn failure() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "multiplexed HTTP")
}
#[derive(Debug)]
pub(crate) struct H2Failure {
    pub reason: Option<u32>,
    pub remote: bool,
    pub reset: bool,
    pub goaway: bool,
    pub library: bool,
    pub limit: Option<&'static str>,
}
impl std::fmt::Display for H2Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HTTP/2 transport failure")
    }
}
impl std::error::Error for H2Failure {}
fn h2_error(e: h2::Error) -> io::Error {
    #[cfg(test)]
    eprintln!(
        "h2 reason={:?} remote={} reset={} goaway={} library={} io={}",
        e.reason(),
        e.is_remote(),
        e.is_reset(),
        e.is_go_away(),
        e.is_library(),
        e.is_io()
    );
    if e.is_io() {
        return e.into_io().unwrap_or_else(failure);
    }
    if e.is_remote()
        && e.is_reset()
        && matches!(e.reason(), Some(h2::Reason::CANCEL | h2::Reason::NO_ERROR))
    {
        return io::ErrorKind::ConnectionAborted.into();
    }
    // Only classify the three fixed upstream library limit identifiers. Never
    // retain or log the formatted error or any remote GOAWAY debug data.
    let limit =
        if e.is_library() && e.is_go_away() && e.reason() == Some(h2::Reason::ENHANCE_YOUR_CALM) {
            let diagnostic = e.to_string();
            if diagnostic.contains("too_many_internal_resets") {
                Some("internal_resets")
            } else if diagnostic.contains("too_many_resets") {
                Some("pending_resets")
            } else if diagnostic.contains("too_many_data_frames") {
                Some("data_frames")
            } else {
                Some("other")
            }
        } else {
            None
        };
    io::Error::new(
        io::ErrorKind::InvalidData,
        H2Failure {
            reason: e.reason().map(u32::from),
            remote: e.is_remote(),
            reset: e.is_reset(),
            goaway: e.is_go_away(),
            library: e.is_library(),
            limit,
        },
    )
}
async fn h2_reset(sender: &mut h2::server::SendResponse<Bytes>) -> io::Result<()> {
    match futures_lite::future::poll_once(futures_lite::future::poll_fn(|cx| sender.poll_reset(cx)))
        .await
    {
        None => Ok(()),
        Some(Ok(h2::Reason::CANCEL | h2::Reason::NO_ERROR)) => {
            Err(io::ErrorKind::ConnectionAborted.into())
        }
        Some(Ok(_)) => Err(failure()),
        Some(Err(e)) => Err(h2_error(e)),
    }
}
/// Dropping a wait after observed cancellation releases its owned leases.
/// In particular, cancelled requests must not occupy the whole admission queue
/// until its timeout while another reload fills h2's pending-reset queue.
async fn while_h2_open<T>(
    sender: &mut h2::server::SendResponse<Bytes>,
    future: impl Future<Output = T>,
) -> io::Result<T> {
    futures_lite::future::or(
        async {
            let error = match futures_lite::future::poll_fn(|cx| sender.poll_reset(cx)).await {
                Ok(h2::Reason::CANCEL | h2::Reason::NO_ERROR) => {
                    io::ErrorKind::ConnectionAborted.into()
                }
                Ok(_) => failure(),
                Err(e) => h2_error(e),
            };
            Err(error)
        },
        async { Ok(future.await) },
    )
    .await
}
/// A separate, process-wide queue bounds streams waiting for admission. It
/// cannot consume all active permits or reserve all response-buffer credit.
pub struct Pending<'a>(&'a std::sync::atomic::AtomicU64);
impl Drop for Pending<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
pub fn pending(server: &Server) -> Option<Pending<'_>> {
    server
        .pending_requests
        .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
            pathward::delivery::task_slot(n).then(|| n + 1)
        })
        .ok()?;
    Some(Pending(&server.pending_requests))
}
pub async fn admit(
    admission: &Arc<admission::Admission>,
    peer: IpAddr,
    shutdown: &AtomicBool,
    deadline: Instant,
    _pending: Pending<'_>,
) -> Result<admission::Permit, admission::Rejection> {
    let mut last = admission::Rejection::GlobalActive;
    loop {
        if shutdown.load(Ordering::Acquire) {
            return Err(admission::Rejection::Draining);
        }
        if Instant::now() >= deadline {
            return Err(last);
        }
        match admission.acquire(peer, false) {
            Ok(p) => return Ok(p),
            Err(e) => last = e,
        }
        async_http::pause().await;
    }
}
pub async fn input_lease(
    budget: &delivery::Budget,
    peer: IpAddr,
    amount: u64,
    shutdown: &AtomicBool,
    deadline: Instant,
) -> Option<delivery::Lease> {
    loop {
        if shutdown.load(Ordering::Acquire) || Instant::now() >= deadline {
            return None;
        }
        if let Some(lease) = budget.reserve(peer, amount, false) {
            return Some(lease);
        }
        async_http::pause().await;
    }
}
pub async fn bounded<T>(deadline: Instant, f: impl Future<Output = T>) -> io::Result<T> {
    let delay = http::remaining(deadline)?;
    futures_lite::future::race(async { Ok(f.await) }, async {
        async_io::Timer::after(delay).await;
        Err(io::ErrorKind::TimedOut.into())
    })
    .await
}

pub struct RequestHead {
    pub wire: Vec<u8>,
    pub length: Option<u64>,
    pub limit: u64,
    pub generation: u64,
    snapshot: Arc<Snapshot>,
    pub started: Instant,
    pub body_ms: u64,
}
/// Reject transport-only fields and ambiguous authorities before translating
/// the library's parsed message to the existing strict raw-target parser.
pub fn request_head(
    server: &Server,
    parts: http_types::request::Parts,
    sni: &str,
    port: u16,
) -> Result<RequestHead, u16> {
    if parts.method == http_types::Method::CONNECT {
        return Err(405);
    }
    if parts.uri.scheme_str() != Some("https") {
        return Err(400);
    }
    let authority = parts.uri.authority().ok_or(400u16)?.as_str();
    let target = parts.uri.path_and_query().ok_or(400u16)?.as_str();
    if parts.headers.len() >= http::MAX_HEADERS {
        return Err(431);
    }
    let mut raw = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\n",
        parts.method, target, authority
    );
    let mut length = None;
    let mut names = std::collections::BTreeSet::new();
    for (name, value) in &parts.headers {
        let name = name.as_str();
        if !names.insert(name) {
            return Err(400);
        }
        let value = std::str::from_utf8(value.as_bytes()).map_err(|_| 400u16)?;
        if name == "host" {
            if !value.eq_ignore_ascii_case(authority) {
                return Err(400);
            }
            continue;
        }
        if matches!(
            name,
            "connection"
                | "proxy-connection"
                | "keep-alive"
                | "upgrade"
                | "transfer-encoding"
                | "te"
                | "trailer"
        ) {
            return Err(400);
        }
        if name == "content-length" {
            if length.is_some() {
                return Err(400);
            }
            length = Some(http::decimal(value.as_bytes()).ok_or(400u16)?);
            continue;
        }
        if !pathward::response::visible(value.as_bytes()) {
            return Err(400);
        }
        raw.push_str(&format!("{name}: {value}\r\n"));
    }
    raw.push_str("\r\n");
    if raw.len() > http::MAX_HEAD_BYTES {
        return Err(431);
    }
    let req = http::parse_framed(
        raw.as_bytes(),
        pathward::response::authority_port(port, true, false),
    )
    .map_err(|e| e.0)?;
    let (generation, snapshot) = {
        let s = server.state.read().map_err(|_| 503u16)?;
        (s.generation, s.snapshot.clone())
    };
    let site = snapshot
        .sites
        .iter()
        .find(|s| s.host == req.host)
        .ok_or(421u16)?;
    if !pathward::tls::identity_allowed(sni.as_bytes(), req.host.as_bytes(), site.host.as_bytes()) {
        return Err(421);
    }
    let limit = if site.route(req.target) == pathward::routing::Route::Proxy {
        site.limits.request_bytes
    } else {
        0
    };
    if length.is_some_and(|n| n > limit) {
        return Err(if limit == 0 { 400 } else { 413 });
    }
    let body_ms = site.limits.body_ms;
    Ok(RequestHead {
        body_ms,
        wire: raw.into_bytes(),
        length,
        limit,
        generation,
        snapshot,
        started: Instant::now(),
    })
}
struct Memory {
    input: io::Cursor<Vec<u8>>,
    output: Vec<u8>,
    port: u16,
    peer: IpAddr,
}
impl Read for Memory {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.input.read(b)
    }
}
impl Write for Memory {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.len() > delivery::HEAD_BYTES.saturating_sub(self.output.len()) {
            return Err(failure());
        }
        self.output.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Transport for Memory {
    fn deadline(&mut self, d: Instant) -> io::Result<()> {
        http::remaining(d).map(|_| ())
    }
    fn local_port(&self) -> io::Result<u16> {
        Ok(self.port)
    }
    fn peer_ip(&self) -> Option<IpAddr> {
        Some(self.peer)
    }
}
pub enum Body {
    Empty,
    Finite(delivery::Prepared),
    Events {
        events: streaming::Events,
        _global: streaming::Permit,
        _service: crate::runtime::ServicePermit,
    },
}
impl Body {
    pub fn deadline(&self) -> Instant {
        match self {
            Self::Finite(p) => p.deadline_at(),
            Self::Events { events, .. } => events.deadline(),
            Self::Empty => Instant::now() + Duration::from_secs(5),
        }
    }
    pub async fn next(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self {
            Self::Empty => Ok(None),
            Self::Finite(p) => p.next_chunk(),
            Self::Events { events, .. } => events.next().await,
        }
    }
    pub fn sent(&mut self) {
        if let Self::Events { events, .. } = self {
            events.sent();
        }
    }
}
pub struct Response {
    pub head: http_types::Response<()>,
    pub body: Body,
    pub status: u16,
}
fn response_head(raw: &[u8]) -> io::Result<http_types::Response<()>> {
    let mut fields = [httparse::EMPTY_HEADER; 128];
    let mut parsed = httparse::Response::new(&mut fields);
    if !matches!(parsed.parse(raw),Ok(httparse::Status::Complete(n)) if n==raw.len()) {
        return Err(failure());
    }
    let mut response = http_types::Response::builder()
        .status(parsed.code.ok_or_else(failure)?)
        .body(())
        .map_err(|_| failure())?;
    for h in parsed.headers {
        if pathward::proxy::hop_header(h.name.to_ascii_lowercase().as_bytes()) {
            continue;
        }
        response.headers_mut().append(
            http_types::HeaderName::from_bytes(h.name.as_bytes()).map_err(|_| failure())?,
            http_types::HeaderValue::from_bytes(h.value).map_err(|_| failure())?,
        );
    }
    Ok(response)
}
pub fn rejection(status: u16) -> Response {
    Response {
        head: response_head(http::response_head(status, 0, "text/plain").as_bytes())
            .expect("constant rejection headers"),
        body: Body::Empty,
        status,
    }
}
#[allow(clippy::too_many_arguments)]
pub async fn respond(
    server: &Server,
    mut request: RequestHead,
    body: Vec<u8>,
    sni: &str,
    port: u16,
    peer: IpAddr,
    budget: &delivery::Budget,
    shutdown: &AtomicBool,
    early: bool,
) -> io::Result<Response> {
    request.wire.truncate(request.wire.len() - 2);
    request
        .wire
        .extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    request.wire.extend_from_slice(&body);
    drop(body);
    let mut memory = Memory {
        input: io::Cursor::new(request.wire),
        output: Vec::new(),
        port,
        peer,
    };
    let mut handoff = ResponseHandoff {
        prepared: None,
        budget,
        peer,
        reuse: false,
        head_validated: true,
        early,
        http3_port: server.http3_port.load(Ordering::Acquire),
    };
    let (status, _) = Server::respond_async(
        &request.snapshot,
        &mut memory,
        request.started,
        Some(sni),
        false,
        &server.stream_quota,
        &|| shutdown.load(Ordering::Acquire) || server.is_draining(),
        Some(&mut handoff),
    )
    .await?;
    let body = match handoff.prepared {
        Some(Handoff::Output(mut prepared)) => {
            memory.output = prepared.take_head();
            Body::Finite(prepared)
        }
        Some(Handoff::Stream(prepared)) => Body::Events {
            events: streaming::Events::new(prepared.live, prepared.limits)?,
            _global: prepared._global,
            _service: prepared._service,
        },
        None => Body::Empty,
    };
    Ok(Response {
        head: response_head(&memory.output)?,
        body,
        status,
    })
}

#[allow(clippy::too_many_arguments)]
async fn exchange(
    server: &Server,
    req: http_types::Request<h2::RecvStream>,
    mut sender: h2::server::SendResponse<Bytes>,
    sni: &str,
    port: u16,
    peer: IpAddr,
    budget: &delivery::Budget,
    shutdown: &AtomicBool,
    waiting: Pending<'_>,
    admission: &Arc<admission::Admission>,
    began: Instant,
) {
    let mut generation = server.generation();
    let mut phase = observe::TransportStage::Admission;
    let result = async {
        h2_reset(&mut sender).await?;
        let _permit = match while_h2_open(
            &mut sender,
            admit(
                admission,
                peer,
                shutdown,
                began + delivery::QUEUE_BUDGET,
                waiting,
            ),
        )
        .await?
        {
            Ok(p) => p,
            Err(reason) => {
                server.observe.admission_rejected(reason);
                sender.send_reset(h2::Reason::REFUSED_STREAM);
                return Err(io::ErrorKind::WouldBlock.into());
            }
        };
        h2_reset(&mut sender).await?;
        phase = observe::TransportStage::Input;
        let (parts, mut data) = req.into_parts();
        let mut request = match request_head(server, parts, sni, port) {
            Ok(r) => r,
            Err(status) => return send_h2(rejection(status), &mut sender).await,
        };
        // END_STREAM is a framing fact, not an inference from GET or a missing
        // Content-Length. No body credit is needed for a completed empty input.
        if data.is_end_stream() && request.length.is_none() {
            request.length = Some(0);
        }
        generation = request.generation;
        let Some(_input) = while_h2_open(
            &mut sender,
            input_lease(
                budget,
                peer,
                3 * request.length.unwrap_or(request.limit) + delivery::HEAD_BYTES as u64,
                shutdown,
                began + delivery::QUEUE_BUDGET,
            ),
        )
        .await?
        else {
            return send_h2(rejection(503), &mut sender).await;
        };
        let mut body = Vec::with_capacity(request.length.unwrap_or(request.limit) as usize);
        let deadline = began + Duration::from_millis(request.body_ms);
        loop {
            let next = bounded(deadline, data.data()).await?;
            let Some(chunk) = next else { break };
            let chunk = chunk.map_err(h2_error)?;
            if !pathward::routing::chunk_fits(
                body.len() as u64,
                chunk.len() as u64,
                request.length.unwrap_or(request.limit),
            ) {
                return send_h2(rejection(413), &mut sender).await;
            }
            body.extend_from_slice(&chunk);
            data.flow_control()
                .release_capacity(chunk.len())
                .map_err(h2_error)?;
        }
        if bounded(deadline, data.trailers())
            .await?
            .map_err(h2_error)?
            .is_some()
            || request.length.is_some_and(|n| n != body.len() as u64)
        {
            return send_h2(rejection(400), &mut sender).await;
        }
        h2_reset(&mut sender).await?;
        phase = observe::TransportStage::Responder;
        let response = while_h2_open(
            &mut sender,
            respond(
                server, request, body, sni, port, peer, budget, shutdown, false,
            ),
        )
        .await??;
        phase = observe::TransportStage::Output;
        send_h2(response, &mut sender).await
    }
    .await;
    if result.is_err() {
        sender.send_reset(h2::Reason::CANCEL);
    }
    let result = result.map_err(|e| observe::stage_error(e, phase));
    server.observe.request(generation, began.elapsed(), &result);
}
async fn send_h2(
    mut response: Response,
    sender: &mut h2::server::SendResponse<Bytes>,
) -> io::Result<(u16, u64)> {
    h2_reset(sender).await?;
    let mut stream = sender
        .send_response(response.head, false)
        .map_err(h2_error)?;
    let mut total = 0;
    while let Some(data) = response.body.next().await? {
        let mut bytes = Bytes::from(data);
        let deadline = response
            .body
            .deadline()
            .min(Instant::now() + Duration::from_secs(5));
        while !bytes.is_empty() {
            stream.reserve_capacity(bytes.len());
            let capacity = bounded(
                deadline,
                futures_lite::future::poll_fn(|cx| stream.poll_capacity(cx)),
            )
            .await?;
            // h2 returns None for a closed send side before exposing its reset
            // reason through poll_capacity. Preserve a verified peer cancel;
            // an unexplained closure remains a protocol failure.
            let capacity = match capacity {
                Some(result) => result.map_err(h2_error)?,
                None => {
                    return Err(
                        match futures_lite::future::poll_once(futures_lite::future::poll_fn(|cx| {
                            stream.poll_reset(cx)
                        }))
                        .await
                        {
                            Some(Ok(h2::Reason::CANCEL | h2::Reason::NO_ERROR)) => {
                                io::ErrorKind::ConnectionAborted.into()
                            }
                            Some(Err(e)) => h2_error(e),
                            _ => failure(),
                        },
                    );
                }
            };
            let count = capacity.min(bytes.len());
            if count == 0 {
                continue;
            }
            stream
                .send_data(bytes.split_to(count), false)
                .map_err(h2_error)?;
            total += count as u64;
        }
        response.body.sent();
    }
    stream.send_data(Bytes::new(), true).map_err(h2_error)?;
    Ok((response.status, total))
}
#[allow(clippy::too_many_arguments)]
pub async fn serve_h2(
    server: &Server,
    mut transport: TlsTransport,
    accepted: Instant,
    permit: admission::Permit,
    _active: observe::Active,
    admission: &Arc<admission::Admission>,
    budget: &delivery::Budget,
    shutdown: &AtomicBool,
) -> io::Result<()> {
    let sni = transport.sni.clone();
    let port = transport.local_port()?;
    let peer = permit.peer();
    transport.deadline(accepted + CONNECTION_CEILING)?;
    let read_seen = Arc::new(AtomicBool::new(false));
    let connection = bounded(
        Instant::now() + Duration::from_secs(5),
        h2::server::Builder::new()
            .max_concurrent_streams(32)
            .initial_window_size(16384)
            .initial_connection_window_size(65535)
            .max_header_list_size(http::MAX_HEAD_BYTES as u32)
            .header_table_size(4096)
            .max_send_buffer_size(16384)
            .max_concurrent_reset_streams(32)
            // Reset streams no longer count against the advertised live window.
            // h2 polls the wire before returning queued heads, so coalesced
            // reload windows can exceed 32 even when no live window does.
            // Bound this distinct queue by the 100-request admission ceiling.
            .max_pending_accept_reset_streams(100)
            .max_local_error_reset_streams(Some(8))
            .handshake::<_, Bytes>(Io::new(transport).with_read_observer(read_seen.clone())),
    )
    .await
    .and_then(|result| result.map_err(h2_error));
    let mut connection = match connection {
        Ok(connection) => connection,
        Err(e)
            if !read_seen.load(Ordering::Relaxed)
                && matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::UnexpectedEof
                ) =>
        {
            // TLS preconnections with no HTTP/2 bytes never created a request.
            // Partial prefaces and all other errors remain transport failures.
            server
                .observe
                .h2_idle_closed(e.kind() == io::ErrorKind::TimedOut);
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    let mut tasks: Vec<Pin<Box<dyn Future<Output = ()> + '_>>> = Vec::new();
    let mut count = 0;
    let mut idle = Instant::now();
    let mut retirement = Retirement::default();
    let mut held = None;
    let mut burst = 0;
    loop {
        let stopping = shutdown.load(Ordering::Acquire) || server.is_draining();
        if stopping {
            retirement.stopping();
        }
        if !retirement.retiring()
            && (stopping
                // Leave one advertised window for requests already in flight
                // while the two-stage HTTP/2 GOAWAY completes. The actual
                // admission gate below still enforces 100 / 120 seconds.
                || count >= 68
                || accepted.elapsed() >= Duration::from_secs(115)
                || (tasks.is_empty() && held.is_none() && idle.elapsed() >= Duration::from_secs(5)))
        {
            connection.graceful_shutdown();
            retirement.begin();
        }
        if retirement.close(tasks.len(), held.is_some(), idle) {
            return Ok(());
        }
        // One held head is part of the same 32-stream window, not an admitted
        // task. It lets us consume cancelled heads even when the global queue
        // is full. No body, response credit or service permit is allocated here.
        let mut progressed = false;
        let incoming = if pathward::delivery::head_slot(tasks.len() as u64, held.is_some()) {
            futures_lite::future::poll_once(connection.accept()).await
        } else {
            match futures_lite::future::poll_once(futures_lite::future::poll_fn(|cx| {
                connection.poll_closed(cx)
            }))
            .await
            {
                Some(Ok(())) => return Ok(()),
                Some(Err(e)) => {
                    return Err(observe::connection_error(
                        h2_error(e),
                        tasks.len() as u64 + u64::from(held.is_some()),
                        count,
                    ));
                }
                None => None,
            }
        };
        match incoming {
            Some(Some(Ok((req, response)))) => {
                count += 1;
                idle = Instant::now();
                progressed = true;
                // A reset can already be queued with this head. Observe it
                // before applying any refusal policy, including retirement.
                held = Some((req, response, Instant::now()));
            }
            Some(Some(Err(e))) => {
                return Err(observe::connection_error(
                    h2_error(e),
                    tasks.len() as u64,
                    count,
                ));
            }
            Some(None) => return Ok(()),
            None => {}
        }
        if let Some((req, mut response, began)) = held.take() {
            let cancelled = h2_reset(&mut response).await.err();
            match pathward::delivery::held_action(
                cancelled.is_some(),
                began.elapsed().as_millis().min(u64::MAX as u128) as u64,
            ) {
                pathward::delivery::HeldAction::Discard => {
                    progressed = true;
                    let result = Err(observe::stage_error(
                        cancelled.expect("verified discard requires observed cancellation"),
                        observe::TransportStage::Admission,
                    ));
                    server
                        .observe
                        .request(server.generation(), began.elapsed(), &result);
                }
                pathward::delivery::HeldAction::Expire => {
                    progressed = true;
                    server
                        .observe
                        .event("h2_head_wait_expired", server.generation(), count);
                    server
                        .observe
                        .admission_rejected(admission::Rejection::GlobalActive);
                    response.send_reset(h2::Reason::REFUSED_STREAM);
                    connection.graceful_shutdown();
                    retirement.begin();
                }
                pathward::delivery::HeldAction::TryAdmission => {
                    if !pathward::delivery::multiplex_slot(
                        tasks.len() as u64,
                        count - 1,
                        accepted.elapsed().as_millis().min(u64::MAX as u128) as u64,
                        shutdown.load(Ordering::Acquire) || server.is_draining(),
                    ) {
                        progressed = true;
                        server.observe.event(
                            "h2_stream_window_exhausted",
                            server.generation(),
                            count,
                        );
                        server
                            .observe
                            .admission_rejected(admission::Rejection::GlobalActive);
                        response.send_reset(h2::Reason::REFUSED_STREAM);
                        connection.graceful_shutdown();
                        retirement.begin();
                    } else if let Some(waiting) = pending(server) {
                        tasks.push(Box::pin(exchange(
                            server, req, response, &sni, port, peer, budget, shutdown, waiting,
                            admission, began,
                        )));
                    } else {
                        held = Some((req, response, began));
                    }
                }
            }
        }
        let mut i = 0;
        while i < tasks.len() {
            if futures_lite::future::poll_once(tasks[i].as_mut())
                .await
                .is_some()
            {
                drop(tasks.swap_remove(i));
                progressed = true;
                idle = Instant::now();
            } else {
                i += 1;
            }
        }
        // Drain a bounded batch of already-ready heads/resets before sleeping.
        // One head per 2ms lets separate legitimate cancellation windows pile
        // up in h2's pending-reset queue. Its separate finite cap remains.
        if progressed && burst < 31 {
            burst += 1;
        } else {
            burst = 0;
            async_http::pause().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    fn identity() -> (Arc<crate::tls::Identity>, Arc<rustls::ClientConfig>) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["app.example".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let bytes = format!("{}{}", key.serialize_pem(), cert.pem());
        let identity = Arc::new(crate::tls::Identity::new(
            vec!["app.example".into()],
            Some(
                crate::tls::Certificate::parse(bytes.as_bytes(), &["app.example".into()]).unwrap(),
            ),
        ));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let mut client = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        client.alpn_protocols = vec![b"h2".to_vec()];
        (identity, Arc::new(client))
    }
    #[test]
    fn h2_idle_prefaces_are_counted_but_partial_prefaces_remain_errors() {
        let config = pathward_config::ParsedConfig::parse(
            "site \"app.example\" {\ntls \"auto\"\nreverse-proxy \"127.0.0.1:9\"\n}",
        )
        .unwrap();
        let server = Server::new(&config.compile().unwrap()).unwrap();
        let (identity, client) = identity();
        let tls = crate::tls::TlsServer::new(identity).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let serving = scope.spawn(|| server.serve_tls(listener, &stop, &tls));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                for (partial, notify) in [(false, true), (false, false), (true, true)] {
                    let socket = TcpStream::connect(address).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(8)))
                        .unwrap();
                    let connection = rustls::ClientConnection::new(
                        client.clone(),
                        rustls::pki_types::ServerName::try_from("app.example").unwrap(),
                    )
                    .unwrap();
                    let mut socket = rustls::StreamOwned::new(connection, socket);
                    while socket.conn.is_handshaking() {
                        socket.conn.complete_io(&mut socket.sock).unwrap();
                    }
                    if partial {
                        socket.write_all(b"P").unwrap();
                    }
                    if notify {
                        socket.conn.send_close_notify();
                        socket.flush().unwrap();
                    }
                    let mut bytes = [0; 256];
                    let until = Instant::now() + Duration::from_secs(8);
                    loop {
                        assert!(Instant::now() < until);
                        match socket.read(&mut bytes) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                }
                let until = Instant::now() + Duration::from_secs(1);
                loop {
                    let metrics = server.observe.metrics(1, true, false, true, None);
                    if metrics.contains("pathward_request_io_errors_total 1\n") {
                        assert!(
                            metrics.contains("pathward_h2_idle_preface_timeout_total 1\n"),
                            "{metrics}"
                        );
                        assert!(
                            metrics.contains("pathward_h2_idle_preface_eof_total 1\n"),
                            "{metrics}"
                        );
                        break;
                    }
                    assert!(Instant::now() < until, "{metrics}");
                    std::thread::sleep(Duration::from_millis(2));
                }
            }));
            stop.store(true, Ordering::Release);
            serving.join().unwrap().unwrap();
            if let Err(p) = result {
                std::panic::resume_unwind(p);
            }
        });
    }
    #[test]
    fn admission_and_input_waits_release_capacity_without_reserving_the_queue() {
        let p = pathward_config::ParsedConfig::parse(
            "site \"app.example\" {\ntls \"auto\"\nreverse-proxy \"127.0.0.1:9000\"\n}",
        )
        .unwrap();
        let server = Server::new(&p.compile().unwrap()).unwrap();
        let mut queue: Vec<_> = (0..64).map(|_| pending(&server).unwrap()).collect();
        assert!(pending(&server).is_none());
        drop(queue.pop());
        assert!(pending(&server).is_some());
        drop(queue);
        let budget = delivery::Budget::default();
        let peer = "127.0.0.1".parse().unwrap();
        let held = budget.reserve(peer, 201326592, false).unwrap();
        let stop = AtomicBool::new(false);
        futures_lite::future::block_on(async {
            let waiting = input_lease(
                &budget,
                peer,
                262144,
                &stop,
                Instant::now() + Duration::from_secs(1),
            );
            let release = async {
                async_io::Timer::after(Duration::from_millis(50)).await;
                drop(held);
            };
            let (lease, ()) = futures_lite::future::zip(waiting, release).await;
            assert!(lease.is_some());
            drop(lease);
            assert!(
                input_lease(&budget, peer, 1, &stop, Instant::now())
                    .await
                    .is_none()
            );
            let admission = Arc::new(admission::Admission::new(false));
            let leases: Vec<_> = (0..6)
                .map(|_| admission.acquire(peer, false).unwrap())
                .collect();
            let waiting = admit(
                &admission,
                peer,
                &stop,
                Instant::now() + Duration::from_secs(1),
                pending(&server).unwrap(),
            );
            let release = async {
                async_io::Timer::after(Duration::from_millis(50)).await;
                drop(leases);
            };
            let (permit, ()) = futures_lite::future::zip(waiting, release).await;
            assert!(permit.is_ok());
            drop(permit);
            assert_eq!(server.pending_requests.load(Ordering::Acquire), 0);
            assert!(
                admit(
                    &admission,
                    peer,
                    &stop,
                    Instant::now(),
                    pending(&server).unwrap()
                )
                .await
                .is_err()
            );
            assert_eq!(server.pending_requests.load(Ordering::Acquire), 0);
        });
    }
    #[test]
    fn cancelled_admission_releases_queue_before_capacity_or_timeout() {
        let config = pathward_config::ParsedConfig::parse(
            "site \"app.example\" {\ntls \"auto\"\nreverse-proxy \"127.0.0.1:9\"\n}",
        )
        .unwrap();
        let server = Server::new(&config.compile().unwrap()).unwrap();
        let admission = Arc::new(admission::Admission::new(false));
        let peer = "127.0.0.1".parse().unwrap();
        let _held: Vec<_> = (0..6)
            .map(|_| admission.acquire(peer, false).unwrap())
            .collect();
        let stop = AtomicBool::new(false);
        let released = AtomicBool::new(false);
        let (client_io, server_io) = tokio::io::duplex(65536);
        futures_lite::future::block_on(async {
            bounded(Instant::now() + Duration::from_secs(3), async {
                futures_lite::future::zip(async {
                    let mut connection = h2::server::handshake(server_io).await.unwrap();
                    let (_request, mut sender) = connection.accept().await.unwrap().unwrap();
                    let began = Instant::now();
                    let waiting = pending(&server).unwrap();
                    futures_lite::future::race(async {
                        futures_lite::future::poll_fn(|cx| connection.poll_closed(cx)).await.unwrap();
                        panic!("connection closed before cancellation was consumed");
                    }, async {
                        let result = while_h2_open(&mut sender, admit(
                            &admission, peer, &stop, began + delivery::QUEUE_BUDGET, waiting,
                        )).await;
                        assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::ConnectionAborted));
                        let polled = std::cell::Cell::new(false);
                        let again = while_h2_open(&mut sender, async { polled.set(true); 1 }).await;
                        assert!(matches!(again, Err(e) if e.kind() == io::ErrorKind::ConnectionAborted));
                        assert!(!polled.get(), "observed cancellation must win even against ready work");
                        assert!(began.elapsed() < Duration::from_secs(1));
                        assert_eq!(server.pending_requests.load(Ordering::Acquire), 0);
                        assert!(admission.acquire(peer, false).is_err());
                        released.store(true, Ordering::Release);
                    }).await;
                }, async {
                    let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
                    futures_lite::future::race(async { let _ = connection.await; }, async {
                        let (_response, mut outgoing) = client.send_request(
                            http_types::Request::builder().uri("https://app.example/").body(()).unwrap(), true,
                        ).unwrap();
                        while server.pending_requests.load(Ordering::Acquire) == 0 { async_http::pause().await; }
                        outgoing.send_reset(h2::Reason::CANCEL);
                        while !released.load(Ordering::Acquire) { async_http::pause().await; }
                    }).await;
                }).await;
                assert!(released.load(Ordering::Acquire));
            }).await.unwrap();
        });
    }
    fn h2_cancel_window(raw_resets: u32) {
        let excess = raw_resets > 100;
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        backend.set_nonblocking(true).unwrap();
        let config = pathward_config::ParsedConfig::parse(&format!("capacity \"shared-nat\"\nsite \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{}\"\n}}", backend.local_addr().unwrap())).unwrap();
        let server = Server::new(&config.compile().unwrap()).unwrap();
        let (identity, client) = identity();
        let tls = crate::tls::TlsServer::new(identity).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let serving = scope.spawn(|| server.serve_tls(listener, &stop, &tls));
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let socket = TcpStream::connect(address).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let connection = rustls::ClientConnection::new(
                    client,
                    rustls::pki_types::ServerName::try_from("app.example").unwrap(),
                )
                .unwrap();
                let mut socket = rustls::StreamOwned::new(connection, socket);
                while socket.conn.is_handshaking() {
                    socket.conn.complete_io(&mut socket.sock).unwrap();
                }
                if raw_resets != 0 {
                    let _held: Vec<_> = (0..64).map(|_| pending(&server).unwrap()).collect();
                    // Coalescing separate cancellation windows in one TLS record
                    // must not change their validity. The 101st pending reset
                    // still trips the finite library queue ceiling.
                    let mut wire = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec();
                    fn frame(wire: &mut Vec<u8>, kind: u8, flags: u8, id: u32, body: &[u8]) {
                        wire.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
                        wire.extend_from_slice(&[kind, flags]);
                        wire.extend_from_slice(&id.to_be_bytes());
                        wire.extend_from_slice(body);
                    }
                    frame(&mut wire, 4, 0, 0, &[]);
                    // HPACK indexed GET, https, /; literal indexed :authority.
                    let mut headers = vec![0x82, 0x87, 0x84, 0x01, 11];
                    headers.extend_from_slice(b"app.example");
                    for n in 0..raw_resets {
                        let id = 2 * n + 1;
                        frame(&mut wire, 1, 5, id, &headers);
                        frame(&mut wire, 3, 0, id, &8u32.to_be_bytes());
                    }
                    frame(&mut wire, 6, 0, 0, b"reload64");
                    socket.write_all(&wire).unwrap();
                    socket.flush().unwrap();
                    for _ in 0..120 {
                        let mut head = [0u8; 9];
                        socket.read_exact(&mut head).unwrap();
                        let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
                        assert!(length <= 16384);
                        let mut body = vec![0u8; length];
                        socket.read_exact(&mut body).unwrap();
                        if head[3] == 6 && head[4] == 1 && body == b"reload64" {
                            assert!(!excess, "excess reset queue was accepted");
                            return;
                        }
                        if head[3] == 7 {
                            assert!(excess, "coalesced reload windows were rejected");
                            assert_eq!(&body[4..8], &11u32.to_be_bytes());
                            assert_eq!(&body[8..], b"too_many_resets");
                            return;
                        }
                    }
                    panic!("unconsumed reset ceiling was not enforced");
                }
                socket.sock.set_nonblocking(true).unwrap();
                futures_lite::future::block_on(async {
                    bounded(Instant::now() + Duration::from_secs(8), async {
                        let (mut client, connection) =
                            h2::client::handshake(Io::new(socket)).await.unwrap();
                        futures_lite::future::race(
                            async {
                                let outcome = connection.await;
                                assert!(excess, "connection closed during reload: {outcome:?}");
                            },
                            async {
                                let mut held = Vec::new();
                                while held.len() < 64 {
                                    if let Some(p) = pending(&server) {
                                        held.push(p);
                                    } else {
                                        async_http::pause().await;
                                    }
                                }
                                for wave in 0..2 {
                                    let mut requests = Vec::new();
                                    for _ in 0..32 {
                                        client = client.ready().await.unwrap();
                                        requests.push(
                                            client
                                                .send_request(
                                                    http_types::Request::builder()
                                                        .uri("https://app.example/")
                                                        .body(())
                                                        .unwrap(),
                                                    true,
                                                )
                                                .unwrap(),
                                        );
                                    }
                                    // Headers arrive while the application queue is full;
                                    // then a reload cancels the in-flight browser window.
                                    async_io::Timer::after(Duration::from_millis(if wave == 0 {
                                        150
                                    } else {
                                        5
                                    }))
                                    .await;
                                    for (_, stream) in &mut requests {
                                        stream.send_reset(h2::Reason::CANCEL);
                                    }
                                    drop(requests);
                                    async_io::Timer::after(Duration::from_millis(5)).await;
                                }
                                drop(held);
                                client = client.ready().await.unwrap();
                                let (response, _) = client
                                    .send_request(
                                        http_types::Request::builder()
                                            .uri("https://other.example/")
                                            .body(())
                                            .unwrap(),
                                        true,
                                    )
                                    .unwrap();
                                assert_eq!(
                                    response
                                        .await
                                        .expect("reload poisoned subsequent request")
                                        .status(),
                                    421
                                );
                            },
                        )
                        .await;
                    })
                    .await
                    .unwrap();
                });
            }));
            if result.is_ok() && !excess {
                let metrics = server.observe.metrics(1, true, false, true, None);
                assert!(
                    metrics.contains("pathward_request_io_failures_total{reason=\"other\"} 0\n"),
                    "{metrics}"
                );
            }
            stop.store(true, Ordering::Release);
            serving.join().unwrap().unwrap();
            if let Err(p) = result {
                std::panic::resume_unwind(p);
            }
            assert_eq!(
                backend.accept().unwrap_err().kind(),
                io::ErrorKind::WouldBlock,
                "cancelled pending request reached upstream"
            );
        });
    }
    #[test]
    fn h2_reload_drains_repeated_cancel_windows_while_queue_is_full() {
        h2_cancel_window(0);
    }
    #[test]
    fn h2_coalesced_cancel_windows_survive_one_tls_record() {
        h2_cancel_window(64);
    }
    #[test]
    fn h2_unconsumed_reset_abuse_is_still_bounded() {
        h2_cancel_window(101);
    }
    #[test]
    fn h2_retirement_finishes_in_flight_window_without_refusal_storm() {
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        let (retired, retiring) = std::sync::mpsc::channel();
        let config = pathward_config::ParsedConfig::parse(&format!(
            "site \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{}\"\nproxy-timeout \"response-head\" \"30s\"\nproxy-timeout \"total\" \"45s\"\n}}", backend.local_addr().unwrap()
        ))
        .unwrap();
        let server = Server::new(&config.compile().unwrap()).unwrap();
        let (identity, client) = identity();
        let tls = crate::tls::TlsServer::new(identity).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let serving = scope.spawn(|| server.serve_tls(listener, &stop, &tls));
            let origin = scope.spawn(move || {
                backend.set_nonblocking(true).unwrap();
                let until = Instant::now() + Duration::from_secs(12);
                let mut socket = loop {
                    match backend.accept() {
                        Ok((socket, _)) => break socket,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < until, "missing slow origin request");
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).unwrap();
                    head.push(byte[0]);
                    assert!(head.len() < 16384);
                }
                retiring.recv_timeout(Duration::from_secs(12)).unwrap();
                std::thread::sleep(Duration::from_millis(6500));
                socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nslow",
                    )
                    .unwrap();
            });
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let socket = TcpStream::connect(address).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let connection = rustls::ClientConnection::new(
                    client,
                    rustls::pki_types::ServerName::try_from("app.example").unwrap(),
                )
                .unwrap();
                let mut socket = rustls::StreamOwned::new(connection, socket);
                while socket.conn.is_handshaking() {
                    socket.conn.complete_io(&mut socket.sock).unwrap();
                }
                socket.sock.set_nonblocking(true).unwrap();
                futures_lite::future::block_on(async {
                    bounded(Instant::now() + Duration::from_secs(25), async {
                        let (client, connection) =
                            h2::client::handshake(Io::new(socket)).await.unwrap();
                        let (_, completed) = futures_lite::future::zip(
                            async {
                                connection.await.unwrap();
                            },
                            async {
                                let mut held = Vec::new();
                                while held.len() < 64 {
                                    if let Some(slot) = pending(&server) {
                                        held.push(slot);
                                    } else {
                                        async_http::pause().await;
                                    }
                                }
                                let mut client = client.ready().await.unwrap();
                                let (request, _) = client
                                    .send_request(
                                        http_types::Request::builder()
                                            .uri("https://other.example/")
                                            .body(())
                                            .unwrap(),
                                        true,
                                    )
                                    .unwrap();
                                let began = Instant::now();
                                let ((), response) = futures_lite::future::zip(
                                    async {
                                        async_io::Timer::after(Duration::from_millis(150)).await;
                                        drop(held);
                                    },
                                    request,
                                )
                                .await;
                                let response = response.expect("bounded queue burst was reset");
                                assert!(began.elapsed() >= Duration::from_millis(150));
                                assert_eq!(response.status(), 421);
                                let mut body = response.into_body();
                                while let Some(data) = body.data().await {
                                    let data = data.unwrap();
                                    body.flow_control().release_capacity(data.len()).unwrap();
                                }
                                let mut client = client.ready().await.unwrap();
                                let (slow, _) = client
                                    .send_request(
                                        http_types::Request::builder()
                                            .uri("https://app.example/slow")
                                            .body(())
                                            .unwrap(),
                                        true,
                                    )
                                    .unwrap();
                                let slow_started = Instant::now();
                                let mut client = Some(client);
                                let mut completed = 1;
                                for _ in 0..8 {
                                    let mut requests = Vec::new();
                                    for _ in 0..24 {
                                        let Some(c) = client.take() else {
                                            break;
                                        };
                                        let Ok(mut c) = c.ready().await else {
                                            break;
                                        };
                                        match c.send_request(
                                            http_types::Request::builder()
                                                .uri("https://other.example/")
                                                .body(())
                                                .unwrap(),
                                            true,
                                        ) {
                                            Ok((response, _)) => requests.push(response),
                                            Err(_) => break,
                                        }
                                        client = Some(c);
                                    }
                                    for request in requests {
                                        let response = request
                                            .await
                                            .expect("accepted in-flight response was reset");
                                        assert_eq!(response.status(), 421);
                                        let mut body = response.into_body();
                                        while let Some(data) = body.data().await {
                                            let data = data.unwrap();
                                            body.flow_control()
                                                .release_capacity(data.len())
                                                .unwrap();
                                        }
                                        completed += 1;
                                    }
                                    if client.is_none() {
                                        break;
                                    }
                                }
                                drop(client);
                                retired.send(()).unwrap();
                                let response = slow
                                    .await
                                    .expect("normal GOAWAY truncated an accepted slow response");
                                assert_eq!(response.status(), 200);
                                let mut body = response.into_body();
                                let mut received = Vec::new();
                                while let Some(data) = body.data().await {
                                    let data = data.unwrap();
                                    received.extend_from_slice(&data);
                                    body.flow_control().release_capacity(data.len()).unwrap();
                                }
                                assert_eq!(received, b"slow");
                                assert!(slow_started.elapsed() >= Duration::from_secs(6));
                                completed + 1
                            },
                        )
                        .await;
                        assert!((68..=100).contains(&completed), "{completed}");
                    })
                    .await
                    .unwrap();
                });
                let metrics = server.observe.metrics(1, true, false, true, None);
                assert!(
                    metrics.contains("pathward_admission_rejected_total 0\n"),
                    "{metrics}"
                );
                assert!(
                    metrics.contains("pathward_request_io_errors_total 0\n"),
                    "{metrics}"
                );
            }));
            stop.store(true, Ordering::Release);
            serving.join().unwrap().unwrap();
            origin.join().unwrap();
            if let Err(p) = result {
                std::panic::resume_unwind(p);
            }
        });
    }
    #[test]
    fn real_tls_h2_multiplexes_24_waits_compression_and_streams_sse() {
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        let config=pathward_config::ParsedConfig::parse(&format!("capacity \"shared-nat\"\nsite \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{}\"\nproxy-limit \"connections\" \"32\"\nproxy-limit \"request-body\" \"3MiB\"\nproxy-limit \"response-body\" \"32MiB\"\nproxy-stream \"sse\"\nencode \"gzip,zstd\"\n}}",backend.local_addr().unwrap())).unwrap();
        let server = Server::new(&config.compile().unwrap()).unwrap();
        let (identity, client) = identity();
        let tls = crate::tls::TlsServer::new(identity).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = AtomicBool::new(false);
        std::thread::scope(|scope| {
            let serving = scope.spawn(|| server.serve_tls(listener, &stop, &tls));
            let origin=scope.spawn(|| {
                backend.set_nonblocking(true).unwrap();
                let accept=|| {let until=Instant::now()+Duration::from_secs(8);loop {match backend.accept(){Ok((s,_))=>{s.set_nonblocking(false).unwrap();return s;},Err(e) if e.kind()==io::ErrorKind::WouldBlock=>{assert!(Instant::now()<until,"missing origin request");std::thread::sleep(Duration::from_millis(2));},Err(e)=>panic!("{e}")}}};
                let mut pending=Vec::new();
                for _ in 0..24 {let mut s=accept();http::read_head(&mut s,Instant::now()+Duration::from_secs(3)).unwrap();pending.push(s);}
                for mut s in pending {s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8192\r\n\r\n").unwrap();s.write_all(&[b'x';8192]).unwrap();}
                let mut s=accept();let req=http::read_head(&mut s,Instant::now()+Duration::from_secs(3)).unwrap();assert!(req.starts_with(b"GET /events "));
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n9\r\ndata: a\n\n\r\n").unwrap();
                std::thread::sleep(Duration::from_millis(500));
                s.write_all(b"9\r\ndata: b\n\n\r\n0\r\n\r\n").unwrap();
                let mut s=accept();let req=http::read_head(&mut s,Instant::now()+Duration::from_secs(3)).unwrap();assert!(req.starts_with(b"GET /cancel "));
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 131072\r\n\r\n").unwrap();
                s.write_all(&[b'x';131072]).unwrap();
            });
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let socket = TcpStream::connect(address).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let connection = rustls::ClientConnection::new(
                    client,
                    rustls::pki_types::ServerName::try_from("app.example").unwrap(),
                )
                .unwrap();
                let mut socket = rustls::StreamOwned::new(connection, socket);
                while socket.conn.is_handshaking() {
                    socket.conn.complete_io(&mut socket.sock).unwrap();
                }
                assert_eq!(socket.conn.alpn_protocol(), Some(b"h2".as_slice()));
                socket.sock.set_nonblocking(true).unwrap();
                futures_lite::future::block_on(async {
                    bounded(Instant::now() + Duration::from_secs(15), async {
                        let (mut client, connection) =
                            h2::client::handshake(Io::new(socket)).await.unwrap();
                        futures_lite::future::race(
                            async {
                                connection.await.unwrap();
                                panic!("early h2 close");
                            },
                            async {
                                let mut pending = Vec::new();
                                for _ in 0..24 {
                                    client = client.ready().await.unwrap();
                                    let req = http_types::Request::builder()
                                        .uri("https://app.example/")
                                        .header("accept-encoding", "gzip")
                                        .body(())
                                        .unwrap();
                                    let (r, _) = client.send_request(req, true).unwrap();
                                    pending.push(r);
                                }
                                for r in pending {
                                    let response = r.await.unwrap();
                                    assert_eq!(response.status(), 200);
                                    assert_eq!(response.headers()["content-encoding"], "gzip");
                                    let mut body = response.into_body();
                                    let mut bytes = Vec::new();
                                    while let Some(b) = body.data().await {
                                        let b = b.unwrap();
                                        body.flow_control().release_capacity(b.len()).unwrap();
                                        bytes.extend_from_slice(&b);
                                    }
                                    let mut decoded = Vec::new();
                                    flate2::read::GzDecoder::new(bytes.as_slice())
                                        .read_to_end(&mut decoded)
                                        .unwrap();
                                    assert_eq!(decoded, vec![b'x'; 8192]);
                                }
                                client = client.ready().await.unwrap();
                                let (r, _) = client
                                    .send_request(
                                        http_types::Request::builder()
                                            .uri("https://app.example/events")
                                            .body(())
                                            .unwrap(),
                                        true,
                                    )
                                    .unwrap();
                                let mut body = r.await.unwrap().into_body();
                                let before = Instant::now();
                                let first = body.data().await.unwrap().unwrap();
                                assert_eq!(&first[..], b"data: a\n\n");
                                assert!(before.elapsed() < Duration::from_millis(400));
                                body.flow_control().release_capacity(first.len()).unwrap();
                                let second = body.data().await.unwrap().unwrap();
                                assert_eq!(&second[..], b"data: b\n\n");
                                body.flow_control().release_capacity(second.len()).unwrap();
                                while let Some(last) = body.data().await {
                                    assert!(last.unwrap().is_empty());
                                }
                                client = client.ready().await.unwrap();
                                let (r, mut outgoing) = client.send_request(http_types::Request::builder().uri("https://app.example/cancel").body(()).unwrap(), true).unwrap();
                                let response = r.await.unwrap(); assert_eq!(response.status(), 200);
                                outgoing.send_reset(h2::Reason::CANCEL); drop(response);
                                let until=Instant::now()+Duration::from_secs(2);
                                loop {
                                    let metrics=server.observe.metrics(1,true,false,true,None);
                                    if metrics.contains("pathward_request_io_failures_total{reason=\"connection_aborted\"} 1\n") { break; }
                                    assert!(Instant::now()<until,"remote reset classification: {metrics}");
                                    async_http::pause().await;
                                }
                                client = client.ready().await.unwrap();
                                let (r, _) = client
                                    .send_request(
                                        http_types::Request::builder()
                                            .uri("https://other.example/")
                                            .body(())
                                            .unwrap(),
                                        true,
                                    )
                                    .unwrap();
                                assert_eq!(r.await.unwrap().status(), 421);
                            },
                        )
                        .await;
                    })
                    .await
                    .unwrap();
                });
            }));
            stop.store(true, Ordering::Release);
            serving.join().unwrap().unwrap();
            origin.join().unwrap();
            if let Err(p) = result {
                std::panic::resume_unwind(p);
            }
        });
    }
}
