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

/// Tokio traits only: h2 does not require a second executor. A readiness timer
/// wakes the existing bounded cooperative executor when the socket would block.
pub(crate) struct Io<T> {
    inner: T,
    wake: Option<async_io::Timer>,
}
impl<T> Io<T> {
    pub fn new(inner: T) -> Self {
        Self { inner, wake: None }
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
fn h2_error(e: h2::Error) -> io::Error {
    if e.is_io() {
        return e.into_io().unwrap_or_else(failure);
    }
    if e.is_remote()
        && e.is_reset()
        && matches!(e.reason(), Some(h2::Reason::CANCEL | h2::Reason::NO_ERROR))
    {
        return io::ErrorKind::ConnectionAborted.into();
    }
    failure()
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
) {
    let began = Instant::now();
    let mut generation = server.generation();
    let result = async {
        let _permit = match admit(
            admission,
            peer,
            shutdown,
            began + delivery::QUEUE_BUDGET,
            waiting,
        )
        .await
        {
            Ok(p) => p,
            Err(reason) => {
                server.observe.admission_rejected(reason);
                sender.send_reset(h2::Reason::REFUSED_STREAM);
                return Err(io::ErrorKind::WouldBlock.into());
            }
        };
        let (parts, mut data) = req.into_parts();
        let request = match request_head(server, parts, sni, port) {
            Ok(r) => r,
            Err(status) => return send_h2(rejection(status), &mut sender).await,
        };
        generation = request.generation;
        let Some(_input) = input_lease(
            budget,
            peer,
            3 * request.length.unwrap_or(request.limit) + delivery::HEAD_BYTES as u64,
            shutdown,
            began + delivery::QUEUE_BUDGET,
        )
        .await
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
        let response = respond(
            server, request, body, sni, port, peer, budget, shutdown, false,
        )
        .await?;
        send_h2(response, &mut sender).await
    }
    .await;
    if result.is_err() {
        sender.send_reset(h2::Reason::CANCEL);
    }
    server.observe.request(generation, began.elapsed(), &result);
}
async fn send_h2(
    mut response: Response,
    sender: &mut h2::server::SendResponse<Bytes>,
) -> io::Result<(u16, u64)> {
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
    transport.deadline(accepted + Duration::from_secs(125))?;
    let mut connection = bounded(
        Instant::now() + Duration::from_secs(5),
        h2::server::Builder::new()
            .max_concurrent_streams(32)
            .initial_window_size(16384)
            .initial_connection_window_size(65535)
            .max_header_list_size(http::MAX_HEAD_BYTES as u32)
            .header_table_size(4096)
            .max_send_buffer_size(16384)
            .max_concurrent_reset_streams(32)
            .max_pending_accept_reset_streams(8)
            .max_local_error_reset_streams(Some(8))
            .handshake::<_, Bytes>(Io::new(transport)),
    )
    .await?
    .map_err(h2_error)?;
    let mut tasks: Vec<Pin<Box<dyn Future<Output = ()> + '_>>> = Vec::new();
    let mut count = 0;
    let mut idle = Instant::now();
    let mut drain = None;
    loop {
        if drain.is_none()
            && (shutdown.load(Ordering::Acquire)
                || server.is_draining()
                || !pathward::delivery::reuse_allowed(
                    count.max(1),
                    accepted.elapsed().as_millis().min(u64::MAX as u128) as u64,
                    true,
                    false,
                )
                || (tasks.is_empty() && idle.elapsed() >= Duration::from_secs(5)))
        {
            connection.graceful_shutdown();
            drain = Some(Instant::now() + Duration::from_secs(5));
        }
        if drain.is_some_and(|d| Instant::now() >= d) {
            return Ok(());
        }
        match futures_lite::future::poll_once(connection.accept()).await {
            Some(Some(Ok((req, mut response)))) => {
                count += 1;
                idle = Instant::now();
                let permit = if pathward::delivery::multiplex_slot(
                    tasks.len() as u64,
                    count - 1,
                    accepted.elapsed().as_millis().min(u64::MAX as u128) as u64,
                    drain.is_some(),
                ) {
                    pending(server)
                } else {
                    None
                };
                match permit {
                    Some(waiting) => tasks.push(Box::pin(exchange(
                        server, req, response, &sni, port, peer, budget, shutdown, waiting,
                        admission,
                    ))),
                    None => {
                        server
                            .observe
                            .admission_rejected(admission::Rejection::GlobalActive);
                        response.send_reset(h2::Reason::REFUSED_STREAM);
                        connection.graceful_shutdown();
                        drain = Some(Instant::now() + Duration::from_secs(5));
                    }
                }
            }
            Some(Some(Err(e))) => return Err(h2_error(e)),
            Some(None) => return Ok(()),
            None => {}
        }
        let mut i = 0;
        while i < tasks.len() {
            if futures_lite::future::poll_once(tasks[i].as_mut())
                .await
                .is_some()
            {
                drop(tasks.swap_remove(i));
                idle = Instant::now();
            } else {
                i += 1;
            }
        }
        async_http::pause().await;
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
    fn real_tls_h2_multiplexes_24_waits_compression_and_streams_sse() {
        let backend = TcpListener::bind("127.0.0.1:0").unwrap();
        let config=pathward_config::ParsedConfig::parse(&format!("capacity \"shared-nat\"\nsite \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{}\"\nproxy-limit \"connections\" \"32\"\nproxy-limit \"request-body\" \"4KiB\"\nproxy-limit \"response-body\" \"256KiB\"\nproxy-stream \"sse\"\nencode \"gzip,zstd\"\n}}",backend.local_addr().unwrap())).unwrap();
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
