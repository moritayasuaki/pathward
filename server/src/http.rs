//! Strict adapter around httparse. Raw request targets are never decoded.
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub trait Transport: Read + Write {
    fn deadline(&mut self, deadline: Instant) -> io::Result<()>;
    fn local_port(&self) -> io::Result<u16>;
}
impl Transport for TcpStream {
    fn deadline(&mut self, deadline: Instant) -> io::Result<()> {
        let left = remaining(deadline)?;
        self.set_read_timeout(Some(left))?;
        self.set_write_timeout(Some(left))
    }
    fn local_port(&self) -> io::Result<u16> {
        Ok(self.local_addr()?.port())
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
}

fn authority(value: &[u8], local_port: u16) -> Result<String, Rejection> {
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
    if let Some(port) = port
        && (port.is_empty()
            || port.len() > 5
            || port.starts_with('0')
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().ok() != Some(local_port))
    {
        return Err(Rejection(400));
    }
    Ok(host.to_ascii_lowercase())
}

pub fn parse(head: &[u8], local_port: u16) -> Result<Request<'_>, Rejection> {
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
    let mut content_length = false;
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
            host = Some(authority(h.value, local_port)?);
        } else if h.name.eq_ignore_ascii_case("content-length") {
            if content_length || h.value != b"0" {
                return Err(Rejection(400));
            }
            content_length = true;
        } else if ["transfer-encoding", "trailer", "upgrade"]
            .iter()
            .any(|name| h.name.eq_ignore_ascii_case(name))
        {
            return Err(Rejection(400));
        } else if h.name.eq_ignore_ascii_case("expect") {
            return Err(Rejection(417));
        } else if h.name.eq_ignore_ascii_case("connection")
            && !h.value.eq_ignore_ascii_case(b"close")
            && !h.value.eq_ignore_ascii_case(b"keep-alive")
        {
            return Err(Rejection(400));
        }
    }
    Ok(Request {
        method,
        target,
        host: host.ok_or(Rejection(400))?,
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
            return Ok(data); // parse rejects any bytes after the first complete head.
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
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "ico" => "image/vnd.microsoft.icon",
        "pdf" => "application/pdf",
        "wasm" => "application/wasm",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

pub fn response_head(status: u16, length: u64, content_type: &str) -> String {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        417 => "Expectation Failed",
        421 => "Misdirected Request",
        431 => "Request Header Fields Too Large",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Internal Server Error",
    };
    let now = std::time::SystemTime::now();
    let date = now
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .filter(|d| d.as_secs() < 253_402_300_800)
        .map(|_| format!("Date: {}\r\n", httpdate::fmt_http_date(now)))
        .unwrap_or_default();
    let allow = if status == 405 {
        "Allow: GET, HEAD\r\n"
    } else {
        ""
    };
    format!(
        "HTTP/1.1 {status} {reason}\r\n{date}Content-Length: {length}\r\nContent-Type: {content_type}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nCache-Control: no-store\r\n{allow}\r\n"
    )
}
