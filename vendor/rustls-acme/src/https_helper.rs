//! Bounded HTTP/1.1 client: fixed HTTPS origin, verified TLS, no redirects.
use futures_lite::{AsyncRead, AsyncReadExt, AsyncWriteExt, future};
use futures_rustls::{TlsConnector, pki_types::ServerName, rustls::ClientConfig};
use http::{Method, Response, Uri};
use pathward::connection;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    task::Poll,
    time::{Duration, Instant},
};
use thiserror::Error;

pub const MAX_BODY: usize = 1_048_576;
const MAX_HEAD: usize = 8192;
const REQUEST_BUDGET: Duration = Duration::from_secs(30);
const MAX_CONNECT_ATTEMPTS: usize = 8;
const CONNECT_DELAY: Duration = Duration::from_millis(250);

#[derive(Clone, Copy)]
struct RequestClock {
    started: Instant,
    deadline: Instant,
    budget_ns: u64,
}

impl RequestClock {
    fn new(budget: Duration) -> io::Result<Self> {
        let budget_ns = u64::try_from(budget.as_nanos()).map_err(|_| invalid())?;
        if !connection::request_live(0, budget_ns) {
            return Err(invalid());
        }
        let started = Instant::now();
        let deadline = started.checked_add(budget).ok_or_else(invalid)?;
        Ok(Self {
            started,
            deadline,
            budget_ns,
        })
    }

    fn elapsed_ns(self) -> u64 {
        u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn live(self) -> bool {
        connection::request_live(self.elapsed_ns(), self.budget_ns)
    }

    fn success(self) -> bool {
        connection::success_allowed(self.elapsed_ns(), self.budget_ns)
    }
}

/// Retain resolver order within each family, alternate families, and cap both
/// storage and attempts. A long IPv6 prefix must not hide the first IPv4 result.
fn candidates(addresses: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    let mut first_v6 = None;
    for address in addresses {
        first_v6.get_or_insert(address.is_ipv6());
        let family = if address.is_ipv6() { &mut v6 } else { &mut v4 };
        if connection::candidate_slot(family.len() as u64) && !family.contains(&address) {
            family.push(address);
        }
    }
    let (mut first, mut other) = if first_v6 == Some(true) {
        (v6.into_iter(), v4.into_iter())
    } else {
        (v4.into_iter(), v6.into_iter())
    };
    let mut result = Vec::new();
    for index in 0..MAX_CONNECT_ATTEMPTS {
        let next = if index % 2 == 0 {
            first.next().or_else(|| other.next())
        } else {
            other.next().or_else(|| first.next())
        };
        let Some(address) = next else { break };
        result.push(address);
    }
    result
}

/// No worker is detached. Returning a winner or dropping the enclosing request
/// drops every losing connect future/socket. The enclosing request owns the
/// fixed DNS + TCP + TLS + response deadline; new attempts cannot renew it.
async fn connect_candidates<T, F, Fut>(
    addresses: Vec<SocketAddr>,
    delay: Duration,
    clock: RequestClock,
    mut connect: F,
) -> io::Result<T>
where
    F: FnMut(SocketAddr) -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    if addresses.is_empty() || addresses.len() > MAX_CONNECT_ATTEMPTS {
        return Err(invalid());
    }
    let total = addresses.len() as u64;
    let mut remaining = addresses.into_iter();
    let mut attempts: Vec<Option<Pin<Box<Fut>>>> = Vec::new();
    let mut timer = Box::pin(async_io::Timer::after(Duration::ZERO));
    let mut expiry = Box::pin(async_io::Timer::at(clock.deadline));
    let mut last_error = None;
    future::poll_fn(|cx| {
        if !clock.live() || expiry.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::ErrorKind::TimedOut.into()));
        }
        for attempt in &mut attempts {
            if let Some(pending) = attempt {
                match pending.as_mut().poll(cx) {
                    Poll::Ready(Ok(stream)) => {
                        // A Future may monopolize a poll until after the deadline.
                        // Even then, a late ready value must not beat the timer.
                        return Poll::Ready(if clock.success() {
                            Ok(stream)
                        } else {
                            Err(io::ErrorKind::TimedOut.into())
                        });
                    }
                    Poll::Ready(Err(error)) => {
                        last_error = Some(error);
                        *attempt = None;
                    }
                    Poll::Pending => {}
                }
            }
        }
        if connection::launch_allowed(
            total,
            attempts.len() as u64,
            clock.elapsed_ns(),
            clock.budget_ns,
            timer.as_mut().poll(cx).is_ready(),
        ) {
            let Some(address) = remaining.next() else {
                return Poll::Ready(Err(invalid()));
            };
            attempts.push(Some(Box::pin(connect(address))));
            // Restart only the launch spacing, never the overall request budget.
            timer.as_mut().get_mut().set_after(delay);
            cx.waker().wake_by_ref();
        }
        if remaining.len() == 0 && attempts.iter().all(Option::is_none) {
            return Poll::Ready(Err(last_error.take().unwrap_or_else(invalid)));
        }
        Poll::Pending
    })
    .await
}

fn phase_name(phase: &AtomicU8) -> &'static str {
    match phase.load(Ordering::Relaxed) {
        0 => "dns",
        1 => "connect",
        2 => "tls",
        3 => "write",
        _ => "response",
    }
}

/// The origin is supplied by trusted startup configuration, never a CA response.
/// Every discovered URL must retain this exact scheme, hostname and port.
#[derive(Debug)]
pub struct HttpsClient {
    tls: Arc<ClientConfig>,
    authority: String,
    host: String,
    port: u16,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "ACME transport policy")
}

impl HttpsClient {
    pub fn new(directory: &str, tls: Arc<ClientConfig>) -> io::Result<Self> {
        let uri: Uri = directory.parse().map_err(|_| invalid())?;
        let authority = uri.authority().ok_or_else(invalid)?.as_str().to_owned();
        let host = uri.host().ok_or_else(invalid)?.to_owned();
        if uri.scheme_str() != Some("https")
            || authority.contains('@')
            || host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err(invalid());
        }
        let port = uri.port_u16().unwrap_or(443);
        if port == 0 {
            return Err(invalid());
        }
        let client = Self {
            tls,
            authority,
            host,
            port,
        };
        client.check_url(directory)?;
        Ok(client)
    }
    pub fn check_url(&self, url: &str) -> io::Result<Uri> {
        if url.len() > 4096 || !url.bytes().all(|b| (0x21..=0x7e).contains(&b)) || url.contains('#')
        {
            return Err(invalid());
        }
        let uri: Uri = url.parse().map_err(|_| invalid())?;
        if uri.scheme_str() != Some("https")
            || uri.authority().map(|a| a.as_str()) != Some(self.authority.as_str())
        {
            return Err(invalid());
        }
        Ok(uri)
    }
}

pub(crate) async fn https(
    client: &Arc<HttpsClient>,
    url: impl AsRef<str>,
    method: Method,
    body: Option<String>,
) -> Result<Response<String>, HttpsRequestError> {
    https_budget(client, url.as_ref(), method, body, REQUEST_BUDGET).await
}

async fn https_budget(
    client: &Arc<HttpsClient>,
    url: &str,
    method: Method,
    body: Option<String>,
    budget: Duration,
) -> Result<Response<String>, HttpsRequestError> {
    let uri = client.check_url(url)?;
    let body = body.unwrap_or_default();
    if body.len() > 65_536 || !matches!(method, Method::HEAD | Method::GET | Method::POST) {
        return Err(invalid().into());
    }
    let phase = AtomicU8::new(0);
    let clock = RequestClock::new(budget)?;
    let operation = async {
        let addresses = async_net::resolve((client.host.as_str(), client.port)).await?;
        phase.store(1, Ordering::Relaxed);
        let tcp = connect_candidates(
            candidates(addresses),
            CONNECT_DELAY,
            clock,
            async_net::TcpStream::connect,
        )
        .await?;
        phase.store(2, Ordering::Relaxed);
        let name = ServerName::try_from(client.host.clone()).map_err(|_| invalid())?;
        let mut stream = TlsConnector::from(client.tls.clone())
            .connect(name, tcp)
            .await?;
        let path = uri.path_and_query().map_or("/", |p| p.as_str());
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: PathWard/0.1 rustls-acme/0.15.4\r\nContent-Type: application/jose+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            client.authority,
            body.len()
        );
        phase.store(3, Ordering::Relaxed);
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body.as_bytes()).await?;
        stream.flush().await?;
        phase.store(4, Ordering::Relaxed);
        read_response(&mut stream, method == Method::HEAD).await
    };
    let response = future::or(
        async {
            operation.await.map_err(|source| {
                if source.kind() == io::ErrorKind::TimedOut {
                    HttpsRequestError::Timeout {
                        phase: phase_name(&phase),
                    }
                } else {
                    HttpsRequestError::Transport {
                        phase: phase_name(&phase),
                        source,
                    }
                }
            })
        },
        async {
            async_io::Timer::at(clock.deadline).await;
            Err(HttpsRequestError::Timeout {
                phase: phase_name(&phase),
            })
        },
    )
    .await?;
    if !clock.success() {
        return Err(HttpsRequestError::Timeout {
            phase: phase_name(&phase),
        });
    }
    if !response.status().is_success() {
        return Err(HttpsRequestError::Non2xxStatus {
            status_code: response.status().as_u16(),
        });
    }
    Ok(response)
}

async fn line<R: AsyncRead + Unpin>(input: &mut R, cap: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while bytes.len() < cap {
        let mut byte = [0];
        input.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len() - 2);
            return Ok(bytes);
        }
        if byte[0] == b'\n' {
            return Err(invalid());
        }
    }
    Err(invalid())
}

/// Public for the fork's deterministic protocol regression tests.
#[doc(hidden)]
pub async fn read_response<R: AsyncRead + Unpin>(
    input: &mut R,
    head_only: bool,
) -> io::Result<Response<String>> {
    let mut head = Vec::new();
    loop {
        let next = line(input, MAX_HEAD - head.len()).await?;
        head.extend_from_slice(&next);
        head.extend_from_slice(b"\r\n");
        if next.is_empty() {
            break;
        }
        if head.len() >= MAX_HEAD {
            return Err(invalid());
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut headers);
    if parsed.parse(&head).map_err(|_| invalid())? != httparse::Status::Complete(head.len())
        || parsed.version != Some(1)
    {
        return Err(invalid());
    }
    let status = parsed.code.ok_or_else(invalid)?;
    let mut response = Response::builder().status(status);
    let mut length = None;
    let mut chunked = false;
    for h in parsed.headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() || h.value.is_empty() || !h.value.iter().all(u8::is_ascii_digit) {
                return Err(invalid());
            }
            let value = std::str::from_utf8(h.value)
                .map_err(|_| invalid())?
                .parse::<usize>()
                .map_err(|_| invalid())?;
            if value > MAX_BODY {
                return Err(invalid());
            }
            length = Some(value);
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !h.value.eq_ignore_ascii_case(b"chunked") {
                return Err(invalid());
            }
            chunked = true;
        } else if h.name.eq_ignore_ascii_case("content-encoding")
            && !h.value.eq_ignore_ascii_case(b"identity")
        {
            return Err(invalid());
        }
        response = response.header(h.name, h.value);
    }
    if length.is_some() && chunked {
        return Err(invalid());
    }
    let mut body = Vec::new();
    if !head_only && status != 204 {
        if let Some(size) = length {
            body.resize(size, 0);
            input.read_exact(&mut body).await?;
        } else if chunked {
            loop {
                let size_line = line(input, 128).await?;
                // Extensions are unnecessary for ACME; fail closed instead of parsing them.
                if size_line.is_empty()
                    || size_line.len() > 8
                    || !size_line.iter().all(u8::is_ascii_hexdigit)
                {
                    return Err(invalid());
                }
                let size = usize::from_str_radix(
                    std::str::from_utf8(&size_line).map_err(|_| invalid())?,
                    16,
                )
                .map_err(|_| invalid())?;
                if size > MAX_BODY - body.len() {
                    return Err(invalid());
                }
                if size == 0 {
                    if !line(input, MAX_HEAD).await?.is_empty() {
                        return Err(invalid());
                    }
                    break;
                }
                let offset = body.len();
                body.resize(offset + size, 0);
                input.read_exact(&mut body[offset..]).await?;
                let mut crlf = [0; 2];
                input.read_exact(&mut crlf).await?;
                if crlf != *b"\r\n" {
                    return Err(invalid());
                }
            }
        } else {
            input
                .take((MAX_BODY + 1) as u64)
                .read_to_end(&mut body)
                .await?;
            if body.len() > MAX_BODY {
                return Err(invalid());
            }
        }
    }
    response
        .body(String::from_utf8(body).map_err(|_| invalid())?)
        .map_err(|_| invalid())
}

#[derive(Error, Debug)]
pub enum HttpsRequestError {
    #[error("ACME {phase} request deadline")]
    Timeout { phase: &'static str },
    #[error("ACME {phase} transport failure")]
    Transport {
        phase: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("ACME transport error: {0}")]
    Io(#[from] io::Error),
    #[error("ACME HTTP status {status_code}")]
    Non2xxStatus { status_code: u16 },
    #[error("ACME HTTP construction error")]
    Http,
}
impl From<http::Error> for HttpsRequestError {
    fn from(_: http::Error) -> Self {
        Self::Http
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_rustls::rustls::{
        self, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    };
    use std::{net::TcpListener, thread, time::Instant};

    #[test]
    fn candidates_are_bounded_distinct_and_preserve_both_families() {
        let v4: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let mut input: Vec<SocketAddr> = (1..=40)
            .map(|i| format!("[2001:db8::{i:x}]:443").parse().unwrap())
            .collect();
        input.push(v4);
        let selected = candidates(input.clone());
        assert_eq!(selected.len(), MAX_CONNECT_ATTEMPTS);
        assert_eq!(selected[0], input[0]);
        assert_eq!(selected[1], v4);
        for (i, addr) in selected.iter().enumerate() {
            assert!(input.contains(addr));
            assert!(!selected[..i].contains(addr));
        }
        input.insert(0, v4);
        assert_eq!(candidates(input)[..2], [v4, selected[0]]);
        assert_eq!(candidates([v4; 32]), [v4]);
        assert!(candidates([]).is_empty());
    }

    #[test]
    fn a_stalled_first_address_does_not_block_a_working_address() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let working = listener.local_addr().unwrap();
        let stalled: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        let start = Instant::now();
        let result = future::block_on(future::or(
            connect_candidates(
                vec![stalled, working],
                CONNECT_DELAY,
                RequestClock::new(REQUEST_BUDGET).unwrap(),
                |addr| async move {
                    if addr == stalled {
                        future::pending::<()>().await;
                    }
                    async_net::TcpStream::connect(addr).await
                },
            ),
            async {
                async_io::Timer::after(Duration::from_secs(3)).await;
                Err(invalid())
            },
        ))
        .unwrap();
        assert_eq!(result.peer_addr().unwrap(), working);
        assert!(start.elapsed() >= CONNECT_DELAY);
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn early_failure_is_not_a_winner_and_first_success_stops_launching() {
        use std::cell::Cell;
        let addresses = (1..=4)
            .map(|p| SocketAddr::from(([127, 0, 0, 1], p)))
            .collect::<Vec<_>>();
        for first_fails in [false, true] {
            let launched = Cell::new(0);
            let result = future::block_on(connect_candidates(
                addresses.clone(),
                Duration::from_millis(5),
                RequestClock::new(REQUEST_BUDGET).unwrap(),
                |addr| {
                    launched.set(launched.get() + 1);
                    async move {
                        if first_fails && addr.port() == 1 {
                            Err(io::ErrorKind::ConnectionRefused.into())
                        } else {
                            Ok(addr.port())
                        }
                    }
                },
            ))
            .unwrap();
            assert_eq!(result, if first_fails { 2 } else { 1 });
            assert_eq!(launched.get(), usize::from(result));
        }
    }

    #[test]
    fn deadline_cancels_all_attempts_and_overlimit_never_dials() {
        use std::{cell::Cell, rc::Rc};
        struct Held(Rc<Cell<usize>>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.set(self.0.get() - 1);
            }
        }
        let live = Rc::new(Cell::new(0));
        let launched = Cell::new(0);
        let addresses = (1..=MAX_CONNECT_ATTEMPTS)
            .map(|p| SocketAddr::from(([127, 0, 0, 1], p as u16)))
            .collect::<Vec<_>>();
        let result = future::block_on(future::or(
            connect_candidates(
                addresses.clone(),
                Duration::from_millis(5),
                RequestClock::new(REQUEST_BUDGET).unwrap(),
                |_| {
                    live.set(live.get() + 1);
                    launched.set(launched.get() + 1);
                    assert!(live.get() <= MAX_CONNECT_ATTEMPTS);
                    let held = Held(live.clone());
                    async move {
                        let _held = held;
                        future::pending::<io::Result<()>>().await
                    }
                },
            ),
            async {
                async_io::Timer::after(Duration::from_millis(100)).await;
                Err(io::Error::from(io::ErrorKind::TimedOut))
            },
        ));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(launched.get() > 1 && launched.get() <= MAX_CONNECT_ATTEMPTS);
        assert_eq!(live.get(), 0);
        for rejected in [Vec::new(), vec![addresses[0]; MAX_CONNECT_ATTEMPTS + 1]] {
            assert!(
                future::block_on(connect_candidates(
                    rejected,
                    CONNECT_DELAY,
                    RequestClock::new(REQUEST_BUDGET).unwrap(),
                    |_| {
                        panic!("invalid candidate count must not dial");
                        #[allow(unreachable_code)]
                        future::ready(Ok::<(), io::Error>(()))
                    }
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn deadline_wins_over_a_late_ready_value_and_prevents_new_dials() {
        use std::cell::Cell;
        let addresses = vec![SocketAddr::from(([127, 0, 0, 1], 1)); 2];
        let launched = Cell::new(0);
        let clock = RequestClock::new(Duration::from_millis(10)).unwrap();
        let result = future::block_on(connect_candidates(
            addresses.clone(),
            Duration::ZERO,
            clock,
            |_| {
                launched.set(launched.get() + 1);
                async {
                    thread::sleep(Duration::from_millis(30));
                    Ok(())
                }
            },
        ));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(launched.get(), 1);
        let result = future::block_on(connect_candidates(addresses, Duration::ZERO, clock, |_| {
            panic!("expired request cannot dial");
            #[allow(unreachable_code)]
            future::ready(Ok::<(), io::Error>(()))
        }));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(RequestClock::new(Duration::ZERO).is_err());
        assert!(RequestClock::new(Duration::from_secs(31)).is_err());
    }

    #[test]
    fn success_drops_all_losing_futures_before_returning() {
        use std::{cell::Cell, rc::Rc};
        struct Held(Rc<Cell<usize>>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.set(self.0.get() - 1);
            }
        }
        let live = Rc::new(Cell::new(0));
        let addresses = (1..=4)
            .map(|p| SocketAddr::from(([127, 0, 0, 1], p)))
            .collect();
        let result = future::block_on(connect_candidates(
            addresses,
            Duration::from_millis(5),
            RequestClock::new(REQUEST_BUDGET).unwrap(),
            |addr| {
                live.set(live.get() + 1);
                let held = Held(live.clone());
                async move {
                    let _held = held;
                    if addr.port() < 3 {
                        future::pending::<()>().await;
                    }
                    Ok(addr.port())
                }
            },
        ))
        .unwrap();
        assert_eq!(result, 3);
        assert_eq!(live.get(), 0);
    }

    #[test]
    fn verified_tls_and_total_deadline_cover_a_slow_response_body() {
        for trust in [false, true] {
            let key = rcgen::KeyPair::generate().unwrap();
            let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
                .unwrap()
                .self_signed(&key)
                .unwrap();
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let server = ServerConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![cert.der().clone()],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
                )
                .unwrap();
            let mut roots = RootCertStore::empty();
            if trust {
                roots.add(cert.der().clone()).unwrap();
            }
            let client = ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!(
                "https://localhost:{}/directory",
                listener.local_addr().unwrap().port()
            );
            let client = Arc::new(HttpsClient::new(&url, Arc::new(client)).unwrap());
            let worker = thread::spawn(move || {
                use std::io::{Read, Write};
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let conn = ServerConnection::new(Arc::new(server)).unwrap();
                let mut stream = StreamOwned::new(conn, socket);
                let mut bytes = [0; 4096];
                if stream.read(&mut bytes).is_err() {
                    assert!(!trust);
                    return;
                }
                assert!(trust);
                if stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 500\r\n\r\n")
                    .is_err()
                {
                    return;
                }
                for _ in 0..30 {
                    if stream.write_all(b"a").and_then(|_| stream.flush()).is_err() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(25));
                }
            });
            let start = Instant::now();
            let result = future::block_on(https_budget(
                &client,
                &url,
                Method::GET,
                None,
                Duration::from_millis(300),
            ));
            if trust {
                assert!(matches!(
                    result,
                    Err(HttpsRequestError::Timeout { phase: "response" })
                ));
            } else {
                assert!(result.is_err());
            }
            assert!(start.elapsed() < Duration::from_secs(2));
            worker.join().unwrap();
        }
    }
}
