//! Bounded HTTP/1.1 client: fixed HTTPS origin, verified TLS, no redirects.
use futures_lite::{AsyncRead, AsyncReadExt, AsyncWriteExt, future};
use futures_rustls::{TlsConnector, pki_types::ServerName, rustls::ClientConfig};
use http::{Method, Response, Uri};
use std::{io, sync::Arc, time::Duration};
use thiserror::Error;

pub const MAX_BODY: usize = 1_048_576;
const MAX_HEAD: usize = 8192;
const REQUEST_BUDGET: Duration = Duration::from_secs(30);

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
    let operation = async {
        let tcp = async_net::TcpStream::connect((client.host.as_str(), client.port)).await?;
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
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(body.as_bytes()).await?;
        stream.flush().await?;
        read_response(&mut stream, method == Method::HEAD).await
    };
    let response = future::or(operation, async {
        async_io::Timer::after(budget).await;
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "ACME request deadline",
        ))
    })
    .await?;
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
                assert!(
                    matches!(result,Err(HttpsRequestError::Io(e)) if e.kind()==io::ErrorKind::TimedOut)
                );
            } else {
                assert!(result.is_err());
            }
            assert!(start.elapsed() < Duration::from_secs(2));
            worker.join().unwrap();
        }
    }
}
