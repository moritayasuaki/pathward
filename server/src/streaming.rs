//! Bounded nonblocking relay. TLS stays owned by the same worker in both directions.
use crate::http::{self, Rejection, Request, Transport};
use pathward::streaming as gate;
use pathward_config::ProxyLimits;
use std::{
    collections::BTreeSet,
    io::{self, Read, Write},
    net::TcpStream,
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
pub(crate) struct Quota(Mutex<u64>);
pub(crate) struct Permit<'a>(&'a Quota);
impl Quota {
    pub fn acquire(&self, stopped: bool) -> Option<Permit<'_>> {
        let mut active = self.0.lock().ok()?;
        if !gate::admission(*active, stopped) {
            return None;
        }
        *active += 1;
        Some(Permit(self))
    }
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        if let Ok(mut n) = self.0.0.lock() {
            *n = n.saturating_sub(1);
        }
    }
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid stream")
}
fn blocked(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
fn token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}
pub(crate) fn websocket_field(name: &str) -> bool {
    name.starts_with("sec-websocket-")
}

pub(crate) struct Upgrade {
    pub key: String,
    pub protocols: Vec<String>,
    pub accept: String,
}
fn key_valid(s: &[u8]) -> bool {
    s.len() == 24
        && &s[22..] == b"=="
        && b"AQgw".contains(&s[21])
        && s[..21]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(b))
}
fn accept_key(key: &str) -> String {
    // RFC 6455's fixed SHA-1 challenge, not a signature or password hash.
    let input = format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, input.as_bytes());
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(28);
    for c in digest.as_ref().chunks(3) {
        let a = c[0] as usize;
        let b = c.get(1).copied().unwrap_or(0) as usize;
        let d = c.get(2).copied().unwrap_or(0) as usize;
        out.push(B64[a >> 2] as char);
        out.push(B64[((a & 3) << 4) | (b >> 4)] as char);
        out.push(if c.len() > 1 {
            B64[((b & 15) << 2) | (d >> 6)] as char
        } else {
            '='
        });
        out.push(if c.len() > 2 {
            B64[d & 63] as char
        } else {
            '='
        });
    }
    out
}
pub(crate) fn request(
    req: &Request<'_>,
    prefetched: usize,
    enabled: bool,
    encrypted: bool,
    port: u16,
) -> Result<Option<Upgrade>, Rejection> {
    if !req.upgrade {
        if req
            .headers
            .iter()
            .any(|h| websocket_field(&h.name.to_ascii_lowercase()))
        {
            return Err(Rejection(400));
        }
        return Ok(None);
    }
    let mut seen = BTreeSet::new();
    let mut key = "";
    let mut version = false;
    let mut origin = true;
    let mut protocols = Vec::new();
    let scheme = if encrypted { "https" } else { "http" };
    let default = if encrypted { 443 } else { 80 };
    let expected_origin = if port == default {
        format!("{scheme}://{}", req.host)
    } else {
        format!("{scheme}://{}:{port}", req.host)
    };
    for h in &req.headers {
        let name = h.name.to_ascii_lowercase();
        if !seen.insert(name.clone()) {
            return Err(Rejection(400));
        }
        let value = std::str::from_utf8(h.value).map_err(|_| Rejection(400))?;
        match name.as_str() {
            "sec-websocket-key" => key = value,
            "sec-websocket-version" => version = value == "13",
            "origin" => origin = value == expected_origin,
            "sec-websocket-protocol" => {
                for p in value.split(',').map(str::trim) {
                    if p.len() > 64
                        || !token(p)
                        || protocols.len() == 16
                        || protocols.iter().any(|s| s == p)
                    {
                        return Err(Rejection(400));
                    }
                    protocols.push(p.to_owned());
                }
            }
            // Never forward offers; compression/extensions are not negotiated.
            "sec-websocket-extensions" => {}
            _ if websocket_field(&name) => return Err(Rejection(400)),
            _ => {}
        }
    }
    if !origin {
        return Err(Rejection(403));
    }
    if !gate::upgrade_request(
        enabled,
        req.method == b"GET",
        req.content_length,
        prefetched as u64,
        req.upgrade,
        version,
        key_valid(key.as_bytes()),
        origin,
    ) {
        return Err(Rejection(400));
    }
    Ok(Some(Upgrade {
        key: key.to_owned(),
        accept: accept_key(key),
        protocols,
    }))
}

pub(crate) enum Mode {
    WebSocket {
        accept: String,
        protocol: Option<String>,
    },
    Sse {
        length: Option<u64>,
        chunked: bool,
    },
}
pub(crate) fn response_upgrade(
    request: Option<&Upgrade>,
    version: u8,
    status: u16,
    headers: &[httparse::Header<'_>],
    length: bool,
    transfer: bool,
) -> io::Result<Mode> {
    let Some(request) = request else {
        return Err(invalid());
    };
    let get = |name: &str| {
        headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value)
    };
    let upgraded = get("upgrade").is_some_and(|v| v.eq_ignore_ascii_case(b"websocket"))
        && get("connection").is_some_and(http::upgrade_connection);
    let accepted = get("sec-websocket-accept") == Some(request.accept.as_bytes());
    let protocol = get("sec-websocket-protocol")
        .map(|v| std::str::from_utf8(v).map(str::to_owned))
        .transpose()
        .map_err(|_| invalid())?;
    let offered = protocol
        .as_ref()
        .is_none_or(|p| request.protocols.contains(p));
    let extensions = get("sec-websocket-extensions").is_some();
    if !gate::upgrade_response(
        true,
        version == 1,
        status,
        upgraded,
        accepted,
        offered,
        extensions,
        length,
        transfer,
    ) || get("sec-websocket-version").is_some()
        || get("sec-websocket-key").is_some()
        || get("content-encoding").is_some()
    {
        return Err(invalid());
    }
    Ok(Mode::WebSocket {
        accept: request.accept.clone(),
        protocol,
    })
}

pub(crate) struct Live {
    pub mode: Mode,
    socket: TcpStream,
    prefix: Vec<u8>,
    started: Instant,
}
impl Live {
    pub fn new(mode: Mode, socket: TcpStream, prefix: Vec<u8>) -> Self {
        Self {
            mode,
            socket,
            prefix,
            started: Instant::now(),
        }
    }
    pub fn run(
        self,
        client: &mut impl Transport,
        limits: ProxyLimits,
        stopping: &dyn Fn() -> bool,
    ) -> io::Result<u64> {
        client.nonblocking()?;
        self.socket.set_nonblocking(true)?;
        match self.mode {
            Mode::WebSocket { .. } => relay(
                self.socket,
                self.prefix,
                client,
                limits,
                self.started,
                stopping,
            ),
            Mode::Sse { length, chunked } => events(
                self.socket,
                self.prefix,
                client,
                limits,
                self.started,
                stopping,
                Decoder::new(length, chunked, limits.stream_download_bytes),
            ),
        }
    }
}

struct Clock {
    started: Instant,
    progress: Instant,
    limits: ProxyLimits,
}
impl Clock {
    fn new(started: Instant, limits: ProxyLimits) -> Self {
        Self {
            started,
            progress: started,
            limits,
        }
    }
    fn check(&self, client: &mut impl Transport, stopping: &dyn Fn() -> bool) -> io::Result<()> {
        let ms = |d: Duration| d.as_millis().min(u64::MAX as u128) as u64;
        let stopped = stopping();
        if !gate::running(
            stopped,
            ms(self.started.elapsed()),
            ms(self.progress.elapsed()),
            self.limits.stream_idle_ms,
            self.limits.stream_total_ms,
        ) {
            return Err(io::Error::new(
                if stopped {
                    io::ErrorKind::Interrupted
                } else {
                    io::ErrorKind::TimedOut
                },
                "stream ended",
            ));
        }
        client.deadline(
            (self.started + Duration::from_millis(self.limits.stream_total_ms))
                .min(self.progress + Duration::from_millis(self.limits.stream_idle_ms)),
        )
    }
    fn tick(&mut self, progress: bool) {
        if progress {
            self.progress = Instant::now();
        } else {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
#[derive(Default)]
struct Pending {
    bytes: Vec<u8>,
    offset: usize,
}
impl Pending {
    fn empty(&self) -> bool {
        self.bytes.is_empty()
    }
    fn write(&mut self, sink: &mut impl Write) -> io::Result<bool> {
        if self.empty() {
            return Ok(false);
        }
        let mut progress = false;
        if self.offset < self.bytes.len() {
            match sink.write(&self.bytes[self.offset..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => {
                    self.offset += n;
                    progress = true;
                }
                Err(e) if blocked(&e) => return Ok(false),
                Err(e) => return Err(e),
            }
        }
        if self.offset == self.bytes.len() {
            match sink.flush() {
                Ok(()) => {
                    self.bytes.clear();
                    self.offset = 0;
                }
                Err(e) if blocked(&e) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(progress)
    }
}
fn read_into(
    source: &mut impl Read,
    pending: &mut Pending,
    used: &mut u64,
    cap: u64,
    eof: &mut bool,
) -> io::Result<bool> {
    if !pending.empty() || *eof {
        return Ok(false);
    }
    let mut bytes = [0u8; 16384];
    match source.read(&mut bytes) {
        Ok(0) => {
            *eof = true;
            Ok(false)
        }
        Ok(n) => {
            if !gate::bytes_fit(*used, n as u64, cap) {
                return Err(invalid());
            }
            *used += n as u64;
            pending.bytes.extend_from_slice(&bytes[..n]);
            Ok(true)
        }
        Err(e) if blocked(&e) => Ok(false),
        Err(e) => Err(e),
    }
}
fn relay(
    mut socket: TcpStream,
    prefix: Vec<u8>,
    client: &mut impl Transport,
    limits: ProxyLimits,
    started: Instant,
    stopping: &dyn Fn() -> bool,
) -> io::Result<u64> {
    if !gate::bytes_fit(0, prefix.len() as u64, limits.stream_download_bytes) {
        return Err(invalid());
    }
    let mut down = Pending {
        bytes: prefix,
        offset: 0,
    };
    let mut up = Pending::default();
    let (mut uploaded, mut downloaded) = (0, down.bytes.len() as u64);
    let (mut client_eof, mut upstream_eof) = (false, false);
    let mut clock = Clock::new(started, limits);
    loop {
        clock.check(client, stopping)?;
        let mut progress = up.write(&mut socket)? | down.write(client)?;
        if (client_eof || upstream_eof) && up.empty() && down.empty() {
            return Ok(downloaded);
        }
        progress |= read_into(
            client,
            &mut up,
            &mut uploaded,
            limits.stream_upload_bytes,
            &mut client_eof,
        )?;
        progress |= read_into(
            &mut socket,
            &mut down,
            &mut downloaded,
            limits.stream_download_bytes,
            &mut upstream_eof,
        )?;
        clock.tick(progress);
    }
}

#[derive(Debug)]
enum Phase {
    Length(u64),
    Close,
    Size(Vec<u8>),
    Data(u64),
    Cr,
    Lf,
    EndCr,
    EndLf,
    Done,
}
struct Decoder {
    phase: Phase,
    used: u64,
    cap: u64,
}
impl Decoder {
    fn new(length: Option<u64>, chunked: bool, cap: u64) -> Self {
        Self {
            phase: if chunked {
                Phase::Size(Vec::new())
            } else if let Some(n) = length {
                if n == 0 {
                    Phase::Done
                } else {
                    Phase::Length(n)
                }
            } else {
                Phase::Close
            },
            used: 0,
            cap,
        }
    }
    fn done(&self) -> bool {
        matches!(self.phase, Phase::Done)
    }
    fn eof(&self) -> bool {
        self.done() || matches!(self.phase, Phase::Close)
    }
    fn step<'a>(&mut self, input: &'a [u8]) -> io::Result<(usize, &'a [u8])> {
        if input.is_empty() {
            return Ok((0, input));
        }
        match &mut self.phase {
            Phase::Length(left) | Phase::Data(left) => {
                let n = (*left).min(input.len() as u64) as usize;
                if !gate::bytes_fit(self.used, n as u64, self.cap) {
                    return Err(invalid());
                }
                *left -= n as u64;
                self.used += n as u64;
                if *left == 0 {
                    self.phase = if matches!(self.phase, Phase::Length(_)) {
                        Phase::Done
                    } else {
                        Phase::Cr
                    };
                }
                Ok((n, &input[..n]))
            }
            Phase::Close => {
                if !gate::bytes_fit(self.used, input.len() as u64, self.cap) {
                    return Err(invalid());
                }
                self.used += input.len() as u64;
                Ok((input.len(), input))
            }
            Phase::Size(line) => {
                if line.len() == 18 {
                    return Err(invalid());
                }
                line.push(input[0]);
                if input[0] == b'\n' {
                    if !line.ends_with(b"\r\n") {
                        return Err(invalid());
                    }
                    let digits = &line[..line.len() - 2];
                    if digits.is_empty()
                        || digits.len() > 16
                        || !digits.iter().all(u8::is_ascii_hexdigit)
                    {
                        return Err(invalid());
                    }
                    let n = u64::from_str_radix(
                        std::str::from_utf8(digits).map_err(|_| invalid())?,
                        16,
                    )
                    .map_err(|_| invalid())?;
                    if !gate::bytes_fit(self.used, n, self.cap) {
                        return Err(invalid());
                    }
                    self.phase = if n == 0 { Phase::EndCr } else { Phase::Data(n) };
                }
                Ok((1, &input[..0]))
            }
            Phase::Cr | Phase::Lf | Phase::EndCr | Phase::EndLf => {
                let cr = matches!(self.phase, Phase::Cr | Phase::EndCr);
                if input[0] != if cr { b'\r' } else { b'\n' } {
                    return Err(invalid());
                }
                self.phase = match self.phase {
                    Phase::Cr => Phase::Lf,
                    Phase::Lf => Phase::Size(Vec::new()),
                    Phase::EndCr => Phase::EndLf,
                    _ => Phase::Done,
                };
                Ok((1, &input[..0]))
            }
            Phase::Done => Err(invalid()),
        }
    }
}
#[allow(clippy::too_many_arguments)]
fn events(
    mut socket: TcpStream,
    mut input: Vec<u8>,
    client: &mut impl Transport,
    limits: ProxyLimits,
    started: Instant,
    stopping: &dyn Fn() -> bool,
    mut decoder: Decoder,
) -> io::Result<u64> {
    let mut offset = 0;
    let mut out = Pending::default();
    let mut clock = Clock::new(started, limits);
    let mut eof = false;
    let mut terminal = false;
    loop {
        clock.check(client, stopping)?;
        let mut progress = out.write(client)?;
        if out.empty() {
            if terminal {
                return Ok(decoder.used);
            }
            if decoder.done() || eof {
                if offset != input.len() || !decoder.eof() {
                    return Err(invalid());
                }
                out.bytes.extend_from_slice(b"0\r\n\r\n");
                terminal = true;
            } else if offset < input.len() {
                let (n, bytes) = decoder.step(&input[offset..])?;
                offset += n;
                if !bytes.is_empty() {
                    write!(out.bytes, "{:x}\r\n", bytes.len())?;
                    out.bytes.extend_from_slice(bytes);
                    out.bytes.extend_from_slice(b"\r\n");
                }
                // Parsing buffered framing is not network activity.
                if progress {
                    clock.progress = Instant::now();
                }
                continue;
            } else {
                input.resize(16384, 0);
                match socket.read(&mut input) {
                    Ok(n) => {
                        input.truncate(n);
                        offset = 0;
                        eof = n == 0;
                        progress |= n > 0;
                    }
                    Err(e) if blocked(&e) => {
                        input.clear();
                        offset = 0;
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        clock.tick(progress);
    }
}

#[cfg(test)]
#[path = "streaming_tests.rs"]
mod tests;
