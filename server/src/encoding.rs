//! Opt-in bounded representation compression. No request or upstream decoding.
use crate::{delivery::Budget, http::Request};
use std::{
    io::{self, Write},
    net::IpAddr,
};
pub const WORKSPACE: u64 = 8 * 1024 * 1024;
fn bad() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "encoding negotiation")
}
fn q(s: &str) -> Option<u16> {
    let (whole, fraction) = s.split_once('.').unwrap_or((s, ""));
    if fraction.len() > 3 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    match whole {
        "0" => Some(fraction.parse::<u16>().unwrap_or(0) * 10u16.pow((3 - fraction.len()) as u32)),
        "1" if fraction.bytes().all(|b| b == b'0') => Some(1000),
        _ => None,
    }
}
fn negotiate(req: &Request<'_>, mode: u8) -> io::Result<u8> {
    let mut found = req
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("accept-encoding"));
    let Some(h) = found.next() else {
        return Ok(0);
    };
    if found.next().is_some() || h.value.len() > 1024 {
        return Err(bad());
    }
    let value = std::str::from_utf8(h.value).map_err(|_| bad())?;
    if value.is_empty() {
        return Ok(0);
    }
    let mut qualities = std::collections::BTreeMap::new();
    for entry in value.split(',') {
        let mut parts = entry.trim().split(';');
        let name = parts.next().unwrap().trim().to_ascii_lowercase();
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
        {
            return Err(bad());
        }
        let quality = match parts.next() {
            Some(p) => q(p.trim().strip_prefix("q=").ok_or_else(bad)?).ok_or_else(bad)?,
            None => 1000,
        };
        if parts.next().is_some() || qualities.insert(name, quality).is_some() {
            return Err(bad());
        }
    }
    let wildcard = qualities.get("*").copied();
    let gzip = if mode & 1 != 0 {
        qualities.get("gzip").copied().or(wildcard).unwrap_or(0)
    } else {
        0
    };
    let zstd = if mode & 2 != 0 {
        qualities.get("zstd").copied().or(wildcard).unwrap_or(0)
    } else {
        0
    };
    let identity = qualities
        .get("identity")
        .copied()
        .unwrap_or(if wildcard == Some(0) { 0 } else { 1000 });
    if zstd > 0 && zstd >= gzip && zstd >= identity {
        Ok(2)
    } else if gzip > 0 && gzip >= identity {
        Ok(1)
    } else if identity > 0 {
        Ok(0)
    } else {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "no acceptable representation",
        ))
    }
}
fn fields(head: &str) -> impl Iterator<Item = (&str, &str)> {
    head.split("\r\n")
        .filter_map(|line| line.split_once(':').map(|(n, v)| (n, v.trim())))
}
pub fn vary(head: String) -> String {
    let mut values = Vec::new();
    let mut result = String::new();
    for line in head.split("\r\n").filter(|l| !l.is_empty()) {
        if let Some((n, v)) = line.split_once(':')
            && n.eq_ignore_ascii_case("vary")
        {
            values.extend(v.split(',').map(|v| v.trim().to_owned()));
        } else {
            result.push_str(line);
            result.push_str("\r\n");
        }
    }
    if !values
        .iter()
        .any(|v| v == "*" || v.eq_ignore_ascii_case("accept-encoding"))
    {
        values.push("Accept-Encoding".into());
    }
    result.push_str(&format!("Vary: {}\r\n\r\n", values.join(", ")));
    result
}
pub fn candidate(mode: u8, req: &Request<'_>, head: &str, size: u64) -> io::Result<u8> {
    if mode == 0 {
        return Ok(0);
    }
    let sensitive = req.target.contains(&b'?')
        || req.headers.iter().any(|h| {
            matches!(
                h.name.to_ascii_lowercase().as_str(),
                "authorization" | "cookie"
            )
        })
        || fields(head).any(|(n, v)| {
            n.eq_ignore_ascii_case("set-cookie")
                || (n.eq_ignore_ascii_case("cache-control")
                    && v.split(',').any(|x| {
                        x.trim()
                            .split('=')
                            .next()
                            .unwrap_or("")
                            .eq_ignore_ascii_case("private")
                    }))
        });
    let range = req
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("range"))
        || fields(head).any(|(n, _)| n.eq_ignore_ascii_case("content-range"));
    let encoded = fields(head).any(|(n, _)| n.eq_ignore_ascii_case("content-encoding"));
    let no_transform = req.headers.iter().any(|h| {
        h.name.eq_ignore_ascii_case("cache-control")
            && std::str::from_utf8(h.value).is_ok_and(|v| {
                v.split(',')
                    .any(|x| x.trim().eq_ignore_ascii_case("no-transform"))
            })
    }) || fields(head).any(|(n, v)| {
        n.eq_ignore_ascii_case("cache-control")
            && v.split(',')
                .any(|x| x.trim().eq_ignore_ascii_case("no-transform"))
    });
    let text = fields(head).any(|(n, v)| {
        n.eq_ignore_ascii_case("content-type") && {
            let mime = v
                .split(';')
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            matches!(
                mime.as_str(),
                "text/html"
                    | "text/plain"
                    | "text/css"
                    | "text/javascript"
                    | "application/javascript"
                    | "application/json"
                    | "application/xml"
                    | "text/xml"
                    | "image/svg+xml"
                    | "application/wasm"
            )
        }
    });
    let status = head
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if status != 200 && status != 206 {
        return Ok(0);
    }
    let eligible = pathward::delivery::encode_allowed(
        mode != 0,
        size,
        status,
        req.method == b"GET" || req.method == b"HEAD",
        sensitive,
        range,
        encoded,
        no_transform,
        text,
    );
    // Unsupported or unsafe representations cannot silently violate identity;q=0.
    negotiate(req, if eligible { mode } else { 0 })
}
struct Limited {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for Limited {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.len() > self.limit - self.bytes.len() {
            return Err(io::ErrorKind::FileTooLarge.into());
        }
        self.bytes.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn compress(mode: u8, input: &[u8]) -> io::Result<Vec<u8>> {
    let output = Limited {
        bytes: Vec::with_capacity(input.len()),
        limit: input.len(),
    };
    if mode == 1 {
        let mut encoder = flate2::write::GzEncoder::new(output, flate2::Compression::fast());
        encoder.write_all(input)?;
        Ok(encoder.finish()?.bytes)
    } else {
        let mut encoder = zstd::stream::write::Encoder::new(output, 1)?;
        encoder.window_log(20)?;
        encoder.set_pledged_src_size(Some(input.len() as u64))?;
        encoder.write_all(input)?;
        Ok(encoder.finish()?.bytes)
    }
}
pub fn transform(
    mode: u8,
    req: &Request<'_>,
    head: &mut String,
    body: &mut Vec<u8>,
) -> io::Result<()> {
    let selected = candidate(mode, req, head, body.len() as u64)?;
    *head = vary(std::mem::take(head));
    if selected == 0 {
        return Ok(());
    }
    let output = match compress(selected, body) {
        Ok(data) if data.len() + 32 < body.len() => data,
        _ => {
            negotiate(req, 0)?;
            return Ok(());
        }
    };
    let mut new = String::new();
    for line in head.split("\r\n").filter(|l| !l.is_empty()) {
        if let Some((n, v)) = line.split_once(':') {
            match n.to_ascii_lowercase().as_str() {
                "content-length" => {
                    new.push_str(&format!("Content-Length: {}\r\n", output.len()));
                    continue;
                }
                "etag" if !v.trim().starts_with("W/") => {
                    new.push_str(&format!("ETag: W/{}\r\n", v.trim()));
                    continue;
                }
                "digest" | "content-digest" | "repr-digest" | "content-md5" | "accept-ranges" => {
                    continue;
                }
                _ => {}
            }
        }
        new.push_str(line);
        new.push_str("\r\n");
    }
    new.push_str(&format!(
        "Content-Encoding: {}\r\n\r\n",
        if selected == 1 { "gzip" } else { "zstd" }
    ));
    *head = new;
    *body = output;
    Ok(())
}
pub fn apply(
    mode: u8,
    req: &Request<'_>,
    head: &mut String,
    body: &mut Vec<u8>,
    budget: &Budget,
    peer: IpAddr,
    draining: bool,
) -> io::Result<()> {
    if mode == 0 {
        return Ok(());
    }
    *head = vary(std::mem::take(head));
    if candidate(mode, req, head, body.len() as u64)? != 0 {
        if let Some(_lease) = budget.reserve(peer, WORKSPACE, draining) {
            transform(mode, req, head, body)?;
        } else {
            negotiate(req, 0)?;
        }
    }
    Ok(())
}

pub fn rejection(e: &io::Error) -> u16 {
    if e.kind() == io::ErrorKind::Unsupported {
        406
    } else {
        400
    }
}
pub fn identity(req: &Request<'_>) -> io::Result<()> {
    negotiate(req, 0).map(|_| ())
}

pub fn validate(req: &Request<'_>, mode: u8) -> io::Result<()> {
    if mode == 0 {
        return Ok(());
    }
    negotiate(
        req,
        if req.method == b"GET" || req.method == b"HEAD" {
            mode
        } else {
            0
        },
    )
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    fn request(extra: &str) -> Vec<u8> {
        format!("GET /asset.js HTTP/1.1\r\nHost: example.com\r\n{extra}\r\n").into_bytes()
    }
    fn head() -> String {
        "HTTP/1.1 200 OK\r\nContent-Type: text/javascript\r\nContent-Length: 8192\r\nETag: \"v1\"\r\nVary: Origin\r\nAccept-Ranges: bytes\r\n\r\n".into()
    }
    #[test]
    fn roundtrips_and_changes_validator_framing_and_vary() {
        for (name, mode) in [("gzip", 1), ("zstd", 2)] {
            let wire = request(&format!("Accept-Encoding: {name}\r\n"));
            let req = crate::http::parse(&wire, 80).unwrap();
            let mut h = head();
            let mut b = vec![b'x'; 8192];
            transform(mode, &req, &mut h, &mut b).unwrap();
            let mut decoded = Vec::new();
            if mode == 1 {
                flate2::read::GzDecoder::new(&b[..])
                    .read_to_end(&mut decoded)
                    .unwrap();
            } else {
                decoded = zstd::stream::decode_all(&b[..]).unwrap();
            }
            assert_eq!(decoded, vec![b'x'; 8192]);
            assert!(h.contains(&format!("Content-Encoding: {name}\r\n")));
            assert!(h.contains(&format!("Content-Length: {}\r\n", b.len())));
            assert!(h.contains("ETag: W/\"v1\"\r\n"));
            assert!(h.contains("Vary: Origin, Accept-Encoding\r\n"));
            assert!(!h.contains("Accept-Ranges"));
            let canonical = vary(h);
            assert_eq!(vary(canonical.clone()), canonical);
        }
    }
    #[test]
    fn negotiation_exclusion_precedence_and_limits() {
        for (value, expected) in [
            ("gzip, zstd", 2),
            ("gzip;q=0, *;q=1", 2),
            ("zstd;q=0, gzip", 1),
            ("gzip;q=0.5", 0),
            ("identity;q=0, gzip;q=0.5", 1),
            ("", 0),
            ("br", 0),
        ] {
            let wire = request(&format!("Accept-Encoding: {value}\r\n"));
            assert_eq!(
                negotiate(&crate::http::parse(&wire, 80).unwrap(), 3).unwrap(),
                expected
            );
        }
        for value in [
            "gzip;q=1.01",
            "gzip;q=.5",
            "gzip;q=0.1234",
            "gzip, gzip",
            "gzip;q=1;x=1",
        ] {
            let wire = request(&format!("Accept-Encoding: {value}\r\n"));
            assert!(negotiate(&crate::http::parse(&wire, 80).unwrap(), 3).is_err());
        }
        let wire = request("Accept-Encoding: *;q=0\r\n");
        assert_eq!(
            rejection(&negotiate(&crate::http::parse(&wire, 80).unwrap(), 3).unwrap_err()),
            406
        );
    }
    #[test]
    fn sensitive_partial_encoded_and_unbounded_responses_are_never_transformed() {
        for extra in [
            "Cookie: s=private\r\n",
            "Authorization: Bearer private\r\n",
            "Range: bytes=0-1\r\n",
            "Cache-Control: no-transform\r\n",
        ] {
            let wire = request(&format!("Accept-Encoding: gzip, zstd\r\n{extra}"));
            assert_eq!(
                candidate(3, &crate::http::parse(&wire, 80).unwrap(), &head(), 8192).unwrap(),
                0
            );
        }
        let wire = request("Accept-Encoding: gzip\r\n");
        let req = crate::http::parse(&wire, 80).unwrap();
        for field in [
            "Set-Cookie: s=private",
            "Content-Encoding: gzip",
            "Cache-Control: private=\"field\"",
            "Cache-Control: public, no-transform",
            "Content-Range: bytes 0-8191/9000",
        ] {
            let h = head().replace("\r\n\r\n", &format!("\r\n{field}\r\n\r\n"));
            assert_eq!(candidate(3, &req, &h, 8192).unwrap(), 0);
        }
        for size in [0, 1023, 1048577, u64::MAX] {
            assert_eq!(candidate(3, &req, &head(), size).unwrap(), 0);
        }
        let wire = request("Accept-Encoding: gzip\r\n");
        let wire = String::from_utf8(wire)
            .unwrap()
            .replace("asset.js ", "asset.js?secret=1 ");
        assert_eq!(
            candidate(
                3,
                &crate::http::parse(wire.as_bytes(), 80).unwrap(),
                &head(),
                8192
            )
            .unwrap(),
            0
        );
    }
}
