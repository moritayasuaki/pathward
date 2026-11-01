//! Strict adapter around httparse. Raw request targets are never decoded.
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub trait Transport: Read + Write {
    fn deadline(&mut self, deadline: Instant) -> io::Result<()>;
    fn local_port(&self) -> io::Result<u16>;
    fn nonblocking(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "stream transport",
        ))
    }
    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        None
    }
}
impl Transport for TcpStream {
    fn nonblocking(&mut self) -> io::Result<()> {
        self.set_nonblocking(true)
    }
    fn deadline(&mut self, deadline: Instant) -> io::Result<()> {
        let left = remaining(deadline)?;
        self.set_read_timeout(Some(left))?;
        self.set_write_timeout(Some(left))
    }
    fn local_port(&self) -> io::Result<u16> {
        Ok(self.local_addr()?.port())
    }
    fn peer_ip(&self) -> Option<std::net::IpAddr> {
        self.peer_addr().ok().map(|a| a.ip())
    }
}

pub const MAX_HEAD_BYTES: usize = 16_384;
pub const MAX_HEADERS: usize = 32;
pub const READ_BUDGET: Duration = Duration::from_secs(5);
pub const WRITE_BUDGET: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejection(pub u16);

pub struct Request<'a> {
    pub method: &'a [u8],
    pub target: &'a [u8],
    pub host: String,
    pub headers: Vec<httparse::Header<'a>>,
    pub content_length: u64,
    pub upgrade: bool,
}

fn authority(value: &[u8], authority_port: u16) -> Result<String, Rejection> {
    let value = std::str::from_utf8(value).map_err(|_| Rejection(400))?;
    let (host, port) = value
        .split_once(':')
        .map_or((value, None), |(h, p)| (h, Some(p)));
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
        || !host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.as_bytes()[0].is_ascii_alphanumeric()
                && label.as_bytes()[label.len() - 1].is_ascii_alphanumeric()
        })
    {
        return Err(Rejection(400));
    }
    let explicit = if let Some(port) = port {
        if port.is_empty()
            || port.len() > 5
            || port.starts_with('0')
            || !port.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(Rejection(400));
        }
        Some(port.parse::<u16>().map_err(|_| Rejection(400))?)
    } else {
        None
    };
    if !pathward::response::authority_port_allowed(explicit, authority_port) {
        return Err(Rejection(400));
    }
    Ok(host.to_ascii_lowercase())
}

/// `authority_port` is the trusted external port, not necessarily the socket port.
pub fn parse(head: &[u8], authority_port: u16) -> Result<Request<'_>, Rejection> {
    let req = parse_framed(head, authority_port)?;
    if req.content_length != 0 || req.upgrade {
        return Err(Rejection(400));
    }
    Ok(req)
}

pub(crate) fn decimal(value: &[u8]) -> Option<u64> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value[0] == b'0')
        || !value.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

/// Only the proxy dispatch path may consume a nonempty body. Static/monitor
/// callers keep using parse(), which refuses every nonzero Content-Length.
pub(crate) fn parse_framed(head: &[u8], authority_port: u16) -> Result<Request<'_>, Rejection> {
    if head.len() > MAX_HEAD_BYTES {
        return Err(Rejection(431));
    }
    if !head.ends_with(b"\r\n\r\n") || head.starts_with(b"\r\n") {
        return Err(Rejection(400));
    }
    for (i, &byte) in head.iter().enumerate() {
        if (byte == b'\n' && (i == 0 || head[i - 1] != b'\r'))
            || (byte == b'\r' && head.get(i + 1) != Some(&b'\n'))
        {
            return Err(Rejection(400));
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(head) {
        Ok(httparse::Status::Complete(n)) if n == head.len() => {}
        Err(httparse::Error::TooManyHeaders) => return Err(Rejection(431)),
        _ => return Err(Rejection(400)),
    }
    if req.version != Some(1) {
        return Err(Rejection(505));
    }
    let method = req.method.ok_or(Rejection(400))?.as_bytes();
    let target = req.path.ok_or(Rejection(400))?.as_bytes();
    // Refuse parser leniency about request-line spacing and leading empty lines.
    let line = head.split(|&b| b == b'\r').next().ok_or(Rejection(400))?;
    let mut words = line.split(|&b| b == b' ');
    if words.next() != Some(method)
        || words.next() != Some(target)
        || words.next() != Some(b"HTTP/1.1")
        || words.next().is_some()
        || !target.starts_with(b"/")
    {
        return Err(Rejection(400));
    }
    let mut host = None;
    let mut content_length = None;
    let mut upgrade = None;
    let mut connection = None;
    for h in req.headers.iter() {
        if !h
            .value
            .iter()
            .all(|b| (0x20..=0x7e).contains(b) || *b == b'\t')
        {
            return Err(Rejection(400));
        }
        if h.name.eq_ignore_ascii_case("host") {
            if host.is_some() {
                return Err(Rejection(400));
            }
            host = Some(authority(h.value, authority_port)?);
        } else if h.name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(Rejection(400));
            }
            content_length = Some(decimal(h.value).ok_or(Rejection(400))?);
        } else if ["transfer-encoding", "trailer"]
            .iter()
            .any(|name| h.name.eq_ignore_ascii_case(name))
        {
            return Err(Rejection(400));
        } else if h.name.eq_ignore_ascii_case("expect") {
            return Err(Rejection(417));
        } else if h.name.eq_ignore_ascii_case("upgrade") {
            if upgrade.replace(h.value).is_some() {
                return Err(Rejection(400));
            }
        } else if h.name.eq_ignore_ascii_case("connection") && connection.replace(h.value).is_some()
        {
            return Err(Rejection(400));
        }
    }
    let upgrade = if let Some(value) = upgrade {
        if !value.eq_ignore_ascii_case(b"websocket") || !connection.is_some_and(upgrade_connection)
        {
            return Err(Rejection(400));
        }
        true
    } else {
        if connection.is_some_and(|v| {
            !v.eq_ignore_ascii_case(b"close") && !v.eq_ignore_ascii_case(b"keep-alive")
        }) {
            return Err(Rejection(400));
        }
        false
    };
    Ok(Request {
        method,
        target,
        host: host.ok_or(Rejection(400))?,
        headers: req.headers.to_vec(),
        content_length: content_length.unwrap_or(0),
        upgrade,
    })
}

pub(crate) fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "connection deadline"))
}

pub fn read_head(stream: &mut impl Transport, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut data = Vec::with_capacity(MAX_HEAD_BYTES);
    let mut chunk = [0; 1024];
    loop {
        stream.deadline(deadline)?;
        let limit = chunk.len().min(MAX_HEAD_BYTES - data.len());
        if limit == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "header limit"));
        }
        let n = match stream.read(&mut chunk[..limit]) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "incomplete request",
            ));
        }
        let start = data.len().saturating_sub(3);
        data.extend_from_slice(&chunk[..n]);
        if data[start..].windows(4).any(|w| w == b"\r\n\r\n") {
            return Ok(data); // Caller separates any prefetched body or rejects it.
        }
    }
}

pub fn write_all(
    stream: &mut impl Transport,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        stream.deadline(deadline)?;
        let n = match stream.write(bytes) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "closed connection",
            ));
        }
        bytes = &bytes[n..];
    }
    stream.flush()?;
    Ok(())
}

pub fn content_type(target: &str) -> &'static str {
    match target.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "xml" => "application/xml; charset=utf-8",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/vnd.microsoft.icon",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "zip" => "application/zip",
        "pem" => "application/x-x509-ca-cert",
        "sig" => "application/pgp-signature",
        "ps1" => "application/x-powershell",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

pub fn response_head(status: u16, length: u64, content_type: &str) -> String {
    let reason = match status {
        200 => "OK",
        206 => "Partial Content",
        304 => "Not Modified",
        412 => "Precondition Failed",
        416 => "Range Not Satisfiable",
        301 => "Moved Permanently",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        508 => "Loop Detected",
        _ => "Internal Server Error",
    };
    let date = date_header();
    let allow = if status == 405 {
        "Allow: GET, HEAD\r\n"
    } else {
        ""
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n{date}Content-Length: {length}\r\nContent-Type: {content_type}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n{allow}\r\n"
    )
}

pub(crate) fn date_header() -> String {
    let now = std::time::SystemTime::now();
    now.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .filter(|d| d.as_secs() < 253_402_300_800)
        .map(|_| format!("Date: {}\r\n", httpdate::fmt_http_date(now)))
        .unwrap_or_default()
}

/// Only these connection options are accepted on the WebSocket handshake.
/// In particular, the peer cannot nominate Host or security fields for removal.
pub(crate) fn upgrade_connection(value: &[u8]) -> bool {
    let Ok(value) = std::str::from_utf8(value) else {
        return false;
    };
    let mut upgrade = false;
    let mut keep = false;
    for v in value.split(',').map(str::trim) {
        if v.eq_ignore_ascii_case("upgrade") && !upgrade {
            upgrade = true;
        } else if v.eq_ignore_ascii_case("keep-alive") && !keep {
            keep = true;
        } else {
            return false;
        }
    }
    upgrade
}
