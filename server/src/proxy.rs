//! Bounded, one-exchange HTTP/1 proxy to a configured numeric loopback address.
//! No DNS, pooling, retries, redirects, tunnels or automatic decompression.
use crate::http::{self, Rejection, Request, Transport};
use pathward::proxy as policy;
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
) -> Result<Response, Rejection> {
    if !policy::method_allowed(req.method) {
        return Err(Rejection(405));
    }
    if !policy::target_allowed(req.target) {
        return Err(Rejection(400));
    }
    // Repeat the extraction-backed gate at the only connect call's boundary.
    if !policy::endpoint_allowed(upstream.ip().to_string().as_bytes(), upstream.port())
        || upstream.port() == client.local_port().map_err(|_| Rejection(502))?
    {
        return Err(Rejection(502));
    }
    if !policy::request_framing(req.content_length, false, false) {
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
        if policy::request_header(name.as_bytes(), h.value) {
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
        client
            .deadline(accepted + http::READ_BUDGET)
            .map_err(|_| Rejection(408))?;
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
    let deadline = accepted + http::READ_BUDGET + http::WRITE_BUDGET;
    let timeout = http::remaining(deadline)
        .map_err(failure)?
        .min(Duration::from_secs(2));
    let mut socket = TcpStream::connect_timeout(&upstream, timeout).map_err(failure)?;
    let method = std::str::from_utf8(req.method).map_err(|_| Rejection(400))?;
    let target = std::str::from_utf8(req.target).map_err(|_| Rejection(400))?;
    let mut head = format!(
        "{method} {target} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Length: {}\r\n",
        req.host,
        body.len()
    );
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
    // The entire upstream response is validated before committing downstream headers.
    receive(socket, req.method == b"HEAD", deadline).map_err(failure)
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

fn receive(mut socket: TcpStream, head_only: bool, deadline: Instant) -> io::Result<Response> {
    let raw = http::read_head(&mut socket, deadline)?;
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
    if !policy::status_allowed(status) {
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
            "trailer" | "upgrade" => return Err(invalid()),
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
    if !policy::response_framing(length, chunked, false)
        || (status == 204 && (length.is_some() || chunked))
    {
        return Err(invalid());
    }
    let mut outgoing = Vec::new();
    let mut via = String::new();
    for h in response.headers.iter() {
        let name = h.name.to_ascii_lowercase();
        if nominated.contains(&name) {
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
            if count > policy::MAX_RESPONSE_BODY - body.len() as u64 {
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
            if body.len() + n > policy::MAX_RESPONSE_BODY as usize {
                return Err(invalid());
            }
            body.extend_from_slice(&buffer[..n]);
        }
        Some(body.len() as u64)
    };
    if status == 205 && !body.is_empty() {
        return Err(invalid());
    }
    Ok(Response {
        status,
        length: declared,
        headers: outgoing,
        body,
    })
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod tests;
