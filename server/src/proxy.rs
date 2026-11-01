//! Bounded, one-exchange HTTP/1 proxy to a configured numeric loopback address.
//! No DNS, pooling, retries, redirects, arbitrary tunnels or decompression.
use crate::http::{self, Rejection, Request, Transport};
use crate::streaming::{self, Live, Mode};
use pathward::proxy as policy;
use pathward_config::ProxyLimits;
use std::{
    collections::BTreeSet,
    io::{self, Read},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

pub(crate) struct Response {
    pub status: u16,
    pub length: Option<u64>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub live: Option<Live>,
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid upstream response")
}
fn failure(e: io::Error) -> Rejection {
    Rejection(
        if matches!(
            e.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            504
        } else {
            502
        },
    )
}
fn token(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}
fn field_value(value: &[u8]) -> bool {
    value.len() <= 4096 && pathward::response::visible(value)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn forward(
    upstream: SocketAddr,
    req: &Request<'_>,
    prefetched: &[u8],
    client: &mut impl Transport,
    accepted: Instant,
    encrypted: bool,
    external_port: u16,
    limits: ProxyLimits,
    origins: &[String],
    routes: &[UpstreamRoute],
) -> Result<Response, Rejection> {
    if !limits.valid() {
        return Err(Rejection(502));
    }
    let body_deadline = accepted + Duration::from_millis(limits.body_ms);
    http::remaining(body_deadline).map_err(|_| Rejection(408))?;
    if !policy::method_allowed(req.method) {
        return Err(Rejection(405));
    }
    if !policy::target_allowed(req.target) {
        return Err(Rejection(400));
    }
    let upgrade = streaming::request(
        req,
        prefetched.len(),
        limits.websocket,
        limits.deflate,
        origins,
        encrypted,
        external_port,
    )?;
    // Repeat the extraction-backed gate at the only connect call's boundary.
    if !policy::endpoint_allowed(upstream.ip().to_string().as_bytes(), upstream.port())
        || upstream.port() == client.local_port().map_err(|_| Rejection(502))?
    {
        return Err(Rejection(502));
    }
    if !pathward::routing::request_framing(req.content_length, limits.request_bytes, false, false) {
        return Err(Rejection(413));
    }
    if prefetched.len() as u64 > req.content_length {
        return Err(Rejection(400));
    }
    let mut seen = BTreeSet::new();
    let mut forwarded = Vec::new();
    let mut via = String::new();
    let mut local_options = false;
    for h in &req.headers {
        let name = h.name.to_ascii_lowercase();
        if !seen.insert(name.clone()) || !field_value(h.value) {
            return Err(Rejection(400));
        }
        if name == "via" {
            let value = std::str::from_utf8(h.value).map_err(|_| Rejection(400))?;
            // Bounded loop defense, in addition to refusing our own listening port.
            if value
                .split(|c: char| c.is_ascii_whitespace() || c == ',')
                .any(|s| s.eq_ignore_ascii_case("pathward"))
            {
                return Err(Rejection(508));
            }
            via.push_str(value);
            via.push_str(", ");
            continue;
        }
        if name == "max-forwards" && req.method == b"OPTIONS" {
            let n = http::decimal(h.value).ok_or(Rejection(400))?;
            if n == 0 {
                local_options = true;
            } else {
                forwarded.push((name, (n - 1).to_string()));
            }
            continue;
        }
        if !streaming::websocket_field(&name) && policy::request_header(name.as_bytes(), h.value) {
            forwarded.push((
                name,
                std::str::from_utf8(h.value)
                    .map_err(|_| Rejection(400))?
                    .to_owned(),
            ));
        }
    }
    if local_options {
        return Ok(Response {
            status: 204,
            live: None,
            length: None,
            body: Vec::new(),
            headers: vec![(
                "allow".into(),
                "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS".into(),
            )],
        });
    }
    let mut body = Vec::with_capacity(req.content_length as usize);
    body.extend_from_slice(prefetched);
    let mut buffer = [0u8; 16_384];
    while (body.len() as u64) < req.content_length {
        client.deadline(body_deadline).map_err(|_| Rejection(408))?;
        let size = buffer.len().min(req.content_length as usize - body.len());
        let n = match client.read(&mut buffer[..size]) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                return Err(Rejection(
                    if matches!(
                        e.kind(),
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                    ) {
                        408
                    } else {
                        400
                    },
                ));
            }
            Ok(0) => return Err(Rejection(400)),
            Ok(n) => n,
        };
        body.extend_from_slice(&buffer[..n]);
    }
    http::remaining(body_deadline).map_err(|_| Rejection(408))?;
    let deadline = accepted + Duration::from_millis(limits.total_ms);
    let upstream = select_upstream(
        upstream,
        routes,
        req,
        client.local_port().map_err(|_| Rejection(502))?,
        encrypted,
        external_port,
        deadline,
        limits,
    )?;
    let timeout = http::remaining(deadline)
        .map_err(failure)?
        .min(Duration::from_millis(limits.connect_ms));
    let mut socket = TcpStream::connect_timeout(&upstream, timeout).map_err(failure)?;
    let method = std::str::from_utf8(req.method).map_err(|_| Rejection(400))?;
    let target = std::str::from_utf8(req.target).map_err(|_| Rejection(400))?;
    let mut head = format!("{method} {target} HTTP/1.1\r\nHost: {}\r\n", req.host);
    if let Some(ws) = &upgrade {
        head.push_str(&format!("Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n", ws.key));
        if ws.deflate {
            head.push_str(&format!(
                "Sec-WebSocket-Extensions: {}\r\n",
                streaming::DEFLATE
            ));
        }
        if !ws.protocols.is_empty() {
            head.push_str(&format!(
                "Sec-WebSocket-Protocol: {}\r\n",
                ws.protocols.join(", ")
            ));
        }
    } else {
        head.push_str(&format!(
            "Connection: close\r\nContent-Length: {}\r\n",
            body.len()
        ));
    }
    for (name, value) in forwarded {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    via.push_str("1.1 pathward");
    head.push_str(&format!("Via: {via}\r\nX-Forwarded-Host: {}\r\nX-Forwarded-Proto: {}\r\nX-Forwarded-Port: {external_port}\r\n",req.host, if encrypted {"https"} else {"http"}));
    if let Some(peer) = client.peer_ip() {
        head.push_str(&format!("X-Forwarded-For: {peer}\r\n"));
    }
    head.push_str("\r\n");
    http::write_all(&mut socket, head.as_bytes(), deadline).map_err(failure)?;
    http::write_all(&mut socket, &body, deadline).map_err(failure)?;
    // Ordinary bodies are validated in full; opt-in streams validate their head
    // before commitment and close on later errors without a second HTTP response.
    receive(
        socket,
        req.method == b"HEAD",
        deadline,
        deadline.min(Instant::now() + Duration::from_millis(limits.head_ms)),
        limits,
        upgrade.as_ref(),
    )
    .map_err(failure)
}

struct Wire {
    socket: TcpStream,
    prefix: Vec<u8>,
    offset: usize,
    deadline: Instant,
}
impl Wire {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.offset < self.prefix.len() {
            http::remaining(self.deadline)?;
            let n = out.len().min(self.prefix.len() - self.offset);
            out[..n].copy_from_slice(&self.prefix[self.offset..self.offset + n]);
            self.offset += n;
            Ok(n)
        } else {
            loop {
                self.socket.deadline(self.deadline)?;
                match self.socket.read(out) {
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    result => return result,
                }
            }
        }
    }
    fn exact(&mut self, out: &mut [u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < out.len() {
            let n = self.read(&mut out[offset..])?;
            if n == 0 {
                return Err(invalid());
            }
            offset += n;
        }
        Ok(())
    }
    fn line(&mut self) -> io::Result<Vec<u8>> {
        let mut line = Vec::new();
        loop {
            if line.len() >= 128 {
                return Err(invalid());
            }
            let mut byte = [0];
            self.exact(&mut byte)?;
            line.push(byte[0]);
            if line.ends_with(b"\r\n") {
                line.truncate(line.len() - 2);
                return Ok(line);
            }
            if byte[0] == b'\n' {
                return Err(invalid());
            }
        }
    }
    fn unused(&self) -> bool {
        self.offset != self.prefix.len()
    }
}

fn receive(
    mut socket: TcpStream,
    head_only: bool,
    deadline: Instant,
    head_deadline: Instant,
    limits: ProxyLimits,
    upgrade: Option<&streaming::Upgrade>,
) -> io::Result<Response> {
    let limit = limits.response_bytes;
    let raw = http::read_head(&mut socket, head_deadline)?;
    http::remaining(head_deadline)?;
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(invalid)?
        + 4;
    let (head, prefix) = raw.split_at(end);
    for (i, &byte) in head.iter().enumerate() {
        if (byte == b'\n' && (i == 0 || head[i - 1] != b'\r'))
            || (byte == b'\r' && head.get(i + 1) != Some(&b'\n'))
        {
            return Err(invalid());
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; http::MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    if !matches!(response.parse(head),Ok(httparse::Status::Complete(n)) if n==head.len()) {
        return Err(invalid());
    }
    let version = response.version.ok_or_else(invalid)?;
    if version > 1
        || !head.starts_with(if version == 1 {
            b"HTTP/1.1 "
        } else {
            b"HTTP/1.0 "
        })
    {
        return Err(invalid());
    }
    let status = response.code.ok_or_else(invalid)?;
    if !policy::status_allowed(status) && status != 101 {
        return Err(invalid());
    }
    let mut length = None;
    let mut chunked = false;
    let mut nominated = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for h in response.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        if (!seen.insert(name.clone()) && name != "set-cookie") || !field_value(h.value) {
            return Err(invalid());
        }
        match name.as_str() {
            "content-length" => {
                length = Some(http::decimal(h.value).ok_or_else(invalid)?);
            }
            "transfer-encoding" => {
                if version == 0 || !h.value.eq_ignore_ascii_case(b"chunked") {
                    return Err(invalid());
                }
                chunked = true;
            }
            "trailer" => return Err(invalid()),
            "upgrade" if status != 101 => return Err(invalid()),
            "connection" => {
                for item in std::str::from_utf8(h.value)
                    .map_err(|_| invalid())?
                    .split(',')
                {
                    let item = item.trim();
                    if !token(item) {
                        return Err(invalid());
                    }
                    nominated.insert(item.to_ascii_lowercase());
                }
            }
            _ => {}
        }
    }
    let event_type = response.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("content-type")
            && std::str::from_utf8(h.value).is_ok_and(|v| {
                v.split(';')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .eq_ignore_ascii_case("text/event-stream")
            })
    });
    let encoded = response.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("content-encoding")
            && !h.value.eq_ignore_ascii_case(b"identity")
    });
    if limits.sse && !head_only && status == 200 && event_type && encoded {
        return Err(invalid());
    }
    let mode = if status == 101 {
        Some(streaming::response_upgrade(
            upgrade,
            version,
            status,
            response.headers,
            length.is_some(),
            chunked,
        )?)
    } else if upgrade.is_none()
        && pathward::streaming::sse_response(limits.sse, head_only, status, event_type, encoded)
    {
        if encoded
            || nominated.contains("content-type")
            || (length.is_some() && chunked)
            || length.is_some_and(|n| {
                !pathward::streaming::bytes_fit(0, n, limits.stream_download_bytes)
            })
        {
            return Err(invalid());
        }
        Some(Mode::Sse { length, chunked })
    } else {
        if !pathward::routing::response_framing(length, limit, chunked, false)
            || (status == 204 && (length.is_some() || chunked))
        {
            return Err(invalid());
        }
        None
    };
    let mut outgoing = Vec::new();
    let mut via = String::new();
    for h in response.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        if nominated.contains(&name) || streaming::websocket_field(&name) {
            continue;
        }
        let value = std::str::from_utf8(h.value)
            .map_err(|_| invalid())?
            .to_owned();
        if name == "via" {
            via.push_str(&value);
            via.push_str(", ");
        } else if !policy::hop_header(name.as_bytes()) && name != "content-length" {
            outgoing.push((name, value));
        }
    }
    via.push_str(if version == 1 {
        "1.1 pathward"
    } else {
        "1.0 pathward"
    });
    outgoing.push(("via".to_owned(), via));
    if let Some(mode) = mode {
        return Ok(Response {
            status,
            length: None,
            headers: outgoing,
            body: Vec::new(),
            live: Some(Live::new(mode, socket, prefix.to_vec())),
        });
    }
    let mut wire = Wire {
        socket,
        prefix: prefix.to_vec(),
        offset: 0,
        deadline,
    };
    let mut body = Vec::new();
    let bodyless = head_only || status == 204 || status == 304;
    let declared = if bodyless {
        if wire.unused() {
            return Err(invalid());
        }
        length
    } else if chunked {
        loop {
            let line = wire.line()?;
            if line.is_empty() || line.len() > 16 || !line.iter().all(u8::is_ascii_hexdigit) {
                return Err(invalid());
            }
            let count = u64::from_str_radix(std::str::from_utf8(&line).map_err(|_| invalid())?, 16)
                .map_err(|_| invalid())?;
            if count == 0 {
                if !wire.line()?.is_empty() {
                    return Err(invalid());
                }
                break;
            }
            if !pathward::routing::chunk_fits(body.len() as u64, count, limit) {
                return Err(invalid());
            }
            let old = body.len();
            body.resize(old + count as usize, 0);
            wire.exact(&mut body[old..])?;
            let mut crlf = [0; 2];
            wire.exact(&mut crlf)?;
            if crlf != *b"\r\n" {
                return Err(invalid());
            }
        }
        if wire.unused() {
            return Err(invalid());
        }
        Some(body.len() as u64)
    } else if let Some(n) = length {
        body.resize(n as usize, 0);
        wire.exact(&mut body)?;
        if wire.unused() {
            return Err(invalid());
        }
        Some(n)
    } else {
        let mut buffer = [0u8; 16_384];
        loop {
            let n = wire.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            if !pathward::routing::chunk_fits(body.len() as u64, n as u64, limit) {
                return Err(invalid());
            }
            body.extend_from_slice(&buffer[..n]);
        }
        Some(body.len() as u64)
    };
    if status == 205 && !body.is_empty() {
        return Err(invalid());
    }
    http::remaining(deadline)?;
    Ok(Response {
        status,
        live: None,
        length: declared,
        headers: outgoing,
        body,
    })
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;

/// Owned by the same immutable snapshot as publication and admission rules.
pub(crate) struct UpstreamRoute {
    pub prefix: String,
    pub width: usize,
    pub candidates: Vec<SocketAddr>,
}

#[allow(clippy::too_many_arguments)]
fn select_upstream(
    default: SocketAddr,
    routes: &[UpstreamRoute],
    req: &Request<'_>,
    local_port: u16,
    encrypted: bool,
    external_port: u16,
    deadline: Instant,
    limits: ProxyLimits,
) -> Result<SocketAddr, Rejection> {
    let path = &req.target[..pathward::serving::path_length(req.target)];
    let route = routes
        .iter()
        .filter(|r| pathward::routing::subtree(path, r.prefix.as_bytes()))
        .max_by_key(|r| r.prefix.len());
    let endpoint = |addr: SocketAddr| {
        if policy::endpoint_allowed(addr.ip().to_string().as_bytes(), addr.port())
            && addr.port() != local_port
        {
            Ok(addr)
        } else {
            Err(Rejection(502))
        }
    };
    let Some(route) = route else {
        return endpoint(default);
    };
    if route.width == 0 {
        if route.candidates.len() != 1 {
            return Err(Rejection(502));
        }
        return endpoint(route.candidates[0]);
    }
    // The collection belongs to the configured default (e.g. POST creation).
    if path == route.prefix.as_bytes() {
        return endpoint(default);
    }
    let tail = &path[route.prefix.len() + 1..];
    let key = tail.split(|b| *b == b'/').next().unwrap_or(b"");
    let resource = route.width <= 64
        && key.len() == route.width
        && key
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b));
    if !pathward::upstream::probe_allowed(true, 0, false, resource, route.candidates.len() as u64) {
        return Err(Rejection(404));
    }
    let key = std::str::from_utf8(key).map_err(|_| Rejection(404))?;
    // Construct from trusted host and validated path only. Client headers, query,
    // body, cookies, authorization and the original method are never copied.
    let probe = format!(
        "GET {}/{key} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: 0\r\nVia: 1.1 pathward\r\nX-Forwarded-Host: {}\r\nX-Forwarded-Proto: {}\r\nX-Forwarded-Port: {external_port}\r\n\r\n",
        route.prefix,
        req.host,
        req.host,
        if encrypted { "https" } else { "http" }
    );
    for (index, &candidate) in route.candidates.iter().enumerate() {
        endpoint(candidate)?;
        let timeout = http::remaining(deadline)
            .map_err(failure)?
            .min(Duration::from_millis(limits.connect_ms));
        let mut socket = TcpStream::connect_timeout(&candidate, timeout).map_err(failure)?;
        let head_deadline = deadline.min(Instant::now() + Duration::from_millis(limits.head_ms));
        http::write_all(&mut socket, probe.as_bytes(), head_deadline).map_err(failure)?;
        let status = probe_status(&mut socket, head_deadline).map_err(failure)?;
        if pathward::upstream::probe_owned(status) {
            return Ok(candidate);
        }
        let remaining = (route.candidates.len() - index - 1) as u64;
        if pathward::upstream::probe_next(status, remaining) {
            continue;
        }
        return Err(Rejection(if status == 404 { 404 } else { 502 }));
    }
    Err(Rejection(404))
}

fn probe_status(socket: &mut TcpStream, deadline: Instant) -> io::Result<u16> {
    let raw = http::read_head(socket, deadline)?;
    http::remaining(deadline)?;
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(invalid)?
        + 4;
    let head = &raw[..end];
    for (i, &b) in head.iter().enumerate() {
        if (b == b'\n' && (i == 0 || head[i - 1] != b'\r'))
            || (b == b'\r' && head.get(i + 1) != Some(&b'\n'))
        {
            return Err(invalid());
        }
    }
    let mut headers = [httparse::EMPTY_HEADER; http::MAX_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    if !matches!(response.parse(head),Ok(httparse::Status::Complete(n)) if n == head.len())
        || !(head.starts_with(b"HTTP/1.1 ") || head.starts_with(b"HTTP/1.0 "))
    {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    let mut length = false;
    let mut encoding = false;
    for h in response.headers {
        let name = h.name.to_ascii_lowercase();
        if !token(&name)
            || !field_value(h.value)
            || (!seen.insert(name.clone()) && name != "set-cookie")
        {
            return Err(invalid());
        }
        if name == "content-length" {
            http::decimal(h.value).ok_or_else(invalid)?;
            length = true;
        }
        if name == "transfer-encoding" {
            if !h.value.eq_ignore_ascii_case(b"chunked") {
                return Err(invalid());
            }
            encoding = true;
        }
    }
    if length && encoding {
        return Err(invalid());
    }
    response.code.ok_or_else(invalid)
}
