use crate::Server;
use pathward_config::ParsedConfig;
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

fn config(upstream: SocketAddr, marker: &str) -> ParsedConfig {
    ParsedConfig::parse(&format!("site \"app.example\" {{\ntls \"auto\"\nreverse-proxy \"{upstream}\"\nheader \"*\" \"x-robots-tag\" \"{marker}\"\nheader \"*\" \"x-frame-options\" \"DENY\"\nheader \"*\" \"strict-transport-security\" \"max-age=60\"\n}}\n")).unwrap()
}
fn with_proxy(upstream: SocketAddr, test: impl FnOnce(SocketAddr, &Server)) {
    let config = config(upstream, "version-a");
    let server = Server::new(&config.compile().unwrap()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        let serving = s.spawn(|| server.serve(listener, &stop));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| test(addr, &server)));
        stop.store(true, Ordering::Release);
        serving.join().unwrap().unwrap();
        if let Err(e) = result {
            std::panic::resume_unwind(e)
        }
    });
}
fn exchange(addr: SocketAddr, request: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    s.write_all(request).unwrap();
    let mut output = Vec::new();
    if let Err(e) = s.read_to_end(&mut output) {
        assert_eq!(e.kind(), std::io::ErrorKind::ConnectionReset);
    }
    output
}
fn read_request(mut s: &TcpStream) -> Vec<u8> {
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut data = Vec::new();
    let mut b = [0; 2048];
    loop {
        let n = s.read(&mut b).unwrap();
        assert!(n > 0);
        data.extend_from_slice(&b[..n]);
        assert!(data.len() < 2 * 1024 * 1024);
        if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = std::str::from_utf8(&data[..end]).unwrap();
            let length = head
                .lines()
                .find_map(|l| l.strip_prefix("Content-Length: "))
                .unwrap()
                .parse::<usize>()
                .unwrap();
            if data.len() >= end + 4 + length {
                assert_eq!(data.len(), end + 4 + length);
                return data;
            }
        }
    }
}
fn one_response(reply: &[u8], request: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = upstream.local_addr().unwrap();
    std::thread::scope(|s| {
        let origin = s.spawn(|| {
            let (mut stream, _) = upstream.accept().unwrap();
            let req = read_request(&stream);
            stream.write_all(reply).unwrap();
            req
        });
        let mut response = Vec::new();
        with_proxy(address, |addr, _| response = exchange(addr, request));
        (response, origin.join().unwrap())
    })
}
const GET: &[u8] = b"GET /api/ HTTP/1.1\r\nHost: app.example\r\n\r\n";

#[test]
fn post_preserves_raw_target_and_binary_body_and_rebuilds_authority_and_forwarding() {
    let body = b"a\0b\r\nGET /admin HTTP/1.1\r\n";
    let mut request=format!("POST /api/%E6%97%A5/?q=%2f HTTP/1.1\r\nHost: APP.EXAMPLE\r\nContent-Length: {}\r\nAuthorization: Bearer test-only\r\nCookie: session=test-only\r\nForwarded: host=evil;proto=https\r\nX-Forwarded-For: 203.0.113.8\r\nX-Forwarded-Proto: https\r\nX-Forwarded-Host: evil.example\r\nX-Forwarded-Port: 443\r\nX-Forwarded-Client-Cert: forged\r\nX-Real-IP: forged\r\nProxy: http://evil.example\r\nProxy-Authorization: secret\r\nTE: trailers\r\nConnection: keep-alive\r\n\r\n",body.len()).into_bytes();
    request.extend_from_slice(body);
    let (response,wire)=one_response(b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\nSet-Cookie: a=1; Secure\r\nSet-Cookie: b=2; HttpOnly\r\nX-Frame-Options: SAMEORIGIN\r\nStrict-Transport-Security: max-age=999\r\nServer: internal\r\nAlt-Svc: h3=\":9090\"\r\nConnection: close, X-Internal\r\nX-Internal: secret\r\n\r\nOK",&request);
    let end = wire.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let h = String::from_utf8(wire[..end].to_vec())
        .unwrap()
        .to_ascii_lowercase();
    assert!(h.starts_with("post /api/%e6%97%a5/?q=%2f http/1.1\r\n"));
    assert!(h.contains("host: app.example\r\n"));
    assert!(h.contains("authorization: bearer test-only\r\n"));
    assert!(h.contains("cookie: session=test-only\r\n"));
    assert!(h.contains("x-forwarded-for: 127.0.0.1\r\n"));
    assert!(h.contains("x-forwarded-proto: http\r\n"));
    assert!(h.contains("x-forwarded-host: app.example\r\n"));
    assert!(h.contains("via: 1.1 pathward\r\n"));
    assert!(h.contains("connection: close\r\n"));
    for forbidden in [
        "evil",
        "203.0.113.8",
        "forged",
        "proxy:",
        "proxy-authorization:",
        "\r\nte:",
        "keep-alive",
    ] {
        assert!(!h.contains(forbidden), "{h}");
    }
    assert_eq!(&wire[end..], body);
    let text = String::from_utf8(response).unwrap();
    assert!(text.starts_with("HTTP/1.1 201 "));
    assert!(text.ends_with("\r\n\r\nOK"));
    assert!(text.contains("set-cookie: a=1; Secure\r\nset-cookie: b=2; HttpOnly\r\n"));
    assert!(text.contains("x-frame-options: DENY\r\n"));
    for forbidden in [
        "SAMEORIGIN",
        "strict-transport-security:",
        "internal",
        "alt-svc:",
        "Server:",
        "x-internal:",
    ] {
        assert!(!text.contains(forbidden), "{text}");
    }
}
#[test]
fn finite_chunked_and_close_delimited_responses_are_reframed_once() {
    for upstream in [
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n"
            .as_slice(),
        b"HTTP/1.0 200 OK\r\n\r\nhello",
    ] {
        let (r, _) = one_response(upstream, GET);
        let s = String::from_utf8(r).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 "));
        assert!(s.contains("Content-Length: 5\r\n"));
        assert!(s.ends_with("\r\n\r\nhello"));
        assert!(!s.to_lowercase().contains("transfer-encoding"));
    }
}
#[test]
fn bad_upstream_framing_never_commits_a_partial_success() {
    let cases: &[&[u8]] = &[
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 8388609\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nContent-Length: 01\r\n\r\nx",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n800001\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;ext=value\r\nx\r\n0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Late: value\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTrailer: X-Late\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        b"HTTP/1.1 103 Early Hints\r\n\r\n",
        b"HTTP/1.1 999 Surprise\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-A: a\0b\r\n\r\n",
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 205 Reset Content\r\nContent-Length: 1\r\n\r\nx",
    ];
    for reply in cases {
        let (r, _) = one_response(reply, GET);
        assert!(r.starts_with(b"HTTP/1.1 502 "), "{r:?}");
        assert!(r.ends_with(b"\r\n\r\n"));
    }
}
#[test]
fn head_and_conditional_responses_never_copy_a_body() {
    for (response, req, expected) in [
        (
            b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n".as_slice(),
            b"HEAD / HTTP/1.1\r\nHost: app.example\r\n\r\n".as_slice(),
            200,
        ),
        (
            b"HTTP/1.1 304 Not Modified\r\nContent-Length: 1234\r\nETag: \"v1\"\r\n\r\n",
            GET,
            304,
        ),
        (b"HTTP/1.1 204 No Content\r\n\r\n", GET, 204),
    ] {
        let (r, _) = one_response(response, req);
        let text = String::from_utf8(r).unwrap();
        assert!(text.starts_with(&format!("HTTP/1.1 {expected} ")));
        assert!(text.ends_with("\r\n\r\n"));
        if expected != 204 {
            assert!(text.contains("Content-Length: 1234\r\n"));
        } else {
            assert!(!text.contains("Content-Length:"));
        }
    }
}
#[test]
fn rejected_requests_do_not_contact_an_upstream() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    with_proxy(listener.local_addr().unwrap(), |addr, _| {
        for (method, path, host, extra, status) in [
            (
                "POST",
                "/",
                "app.example",
                "Content-Length: 1048577\r\n",
                413,
            ),
            (
                "POST",
                "/",
                "app.example",
                "Content-Length: 0\r\nContent-Length: 0\r\n",
                400,
            ),
            (
                "POST",
                "/",
                "app.example",
                "Transfer-Encoding: chunked\r\n",
                400,
            ),
            ("POST", "/", "app.example", "Expect: 100-continue\r\n", 417),
            ("GET", "/", "app.example", "Connection: X-Secret\r\n", 400),
            ("GET", "/", "app.example", "Upgrade: websocket\r\n", 400),
            ("CONNECT", "/", "app.example", "", 405),
            ("TRACE", "/", "app.example", "", 405),
            ("GET", "//evil.example/", "app.example", "", 400),
            ("GET", "/a\\b", "app.example", "", 400),
            ("GET", "/a#b", "app.example", "", 400),
            ("GET", "/", "unknown.example", "", 421),
            ("GET", "/", "app.example", "Via: 1.1 pathward\r\n", 508),
            ("GET", "/", "app.example", "X-A: 1\r\nx-a: 2\r\n", 400),
            (
                "GET",
                "/",
                "app.example",
                "Content-Length: 0\r\n\r\nGET /second HTTP/1.1\r\n",
                400,
            ),
        ] {
            let r = exchange(
                addr,
                format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n{extra}\r\n").as_bytes(),
            );
            assert!(
                r.starts_with(format!("HTTP/1.1 {status} ").as_bytes()),
                "{method} {extra:?}: {r:?}"
            );
            assert!(
                listener.accept().is_err(),
                "upstream contacted for a rejected request"
            );
            std::thread::sleep(Duration::from_millis(130));
        }
    });
}
#[test]
fn reload_pins_one_upstream_and_header_generation_for_each_request() {
    let a = TcpListener::bind("127.0.0.1:0").unwrap();
    let b = TcpListener::bind("127.0.0.1:0").unwrap();
    let baddr = b.local_addr().unwrap();
    with_proxy(a.local_addr().unwrap(), |addr, server| {
        std::thread::scope(|scope| {
            let pending = scope.spawn(|| exchange(addr, GET));
            let (mut old, _) = a.accept().unwrap();
            let _ = read_request(&old);
            let newer = config(baddr, "version-b");
            server
                .reload(&newer.compile().unwrap(), &AtomicBool::new(false))
                .unwrap();
            let fresh = scope.spawn(|| exchange(addr, GET));
            let (mut new, _) = b.accept().unwrap();
            let _ = read_request(&new);
            new.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nB")
                .unwrap();
            drop(new);
            let r = String::from_utf8(fresh.join().unwrap()).unwrap();
            assert!(r.ends_with("\r\n\r\nB") && r.contains("x-robots-tag: version-b\r\n"));
            old.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA")
                .unwrap();
            drop(old);
            let r = String::from_utf8(pending.join().unwrap()).unwrap();
            assert!(r.ends_with("\r\n\r\nA") && r.contains("x-robots-tag: version-a\r\n"));
        })
    });
}
#[test]
fn split_request_body_and_options_max_forwards() {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    with_proxy(upstream.local_addr().unwrap(), |addr, _| {
        std::thread::scope(|s| {
            let client = s.spawn(|| {
                let mut c = TcpStream::connect(addr).unwrap();
                c.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
                c.write_all(
                    b"PATCH /api/ HTTP/1.1\r\nHost: app.example\r\nContent-Length: 4\r\n\r\nab",
                )
                .unwrap();
                std::thread::sleep(Duration::from_millis(30));
                c.write_all(b"cd").unwrap();
                let mut out = Vec::new();
                c.read_to_end(&mut out).unwrap();
                out
            });
            let (mut backend, _) = upstream.accept().unwrap();
            let req = read_request(&backend);
            assert!(req.ends_with(b"\r\n\r\nabcd"));
            backend
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .unwrap();
            drop(backend);
            assert!(client.join().unwrap().starts_with(b"HTTP/1.1 204 "));
            upstream.set_nonblocking(true).unwrap();
            let r = exchange(
                addr,
                b"OPTIONS /api HTTP/1.1\r\nHost: app.example\r\nMax-Forwards: 0\r\n\r\n",
            );
            assert!(r.starts_with(b"HTTP/1.1 204 "));
            assert!(upstream.accept().is_err());
        })
    });
}
#[test]
fn unavailable_upstream_is_a_generic_bad_gateway() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    with_proxy(address, |addr, _| {
        let r = exchange(addr, GET);
        assert!(r.starts_with(b"HTTP/1.1 502 "));
        assert!(r.ends_with(b"\r\n\r\n"));
    });
}

#[test]
fn real_tls_sets_trusted_forwarding_and_plaintext_only_redirects_proxy_targets() {
    use crate::tls::{Certificate, Identity, TlsServer};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName,
    };
    use std::sync::Arc;
    let backend = TcpListener::bind("127.0.0.1:0").unwrap();
    let parsed = config(backend.local_addr().unwrap(), "tls-proxy");
    let server = Server::new(&parsed.compile().unwrap()).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["app.example".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let pem = format!("{}{}", key.serialize_pem(), cert.pem());
    let names = vec!["app.example".to_owned()];
    let identity = Arc::new(Identity::new(
        names.clone(),
        Some(Certificate::parse(pem.as_bytes(), &names).unwrap()),
    ));
    let tls = TlsServer::new(identity).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let mut client =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    client.alpn_protocols = vec![b"http/1.1".to_vec()];
    let client = Arc::new(client);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let redirect = TcpListener::bind("127.0.0.1:0").unwrap();
    let plain = redirect.local_addr().unwrap();
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let worker =
            scope.spawn(|| server.serve_tls_with_redirect(listener, redirect, &stop, &tls));
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let upstream=scope.spawn(||{
                let (mut s,_)=backend.accept().unwrap();let req=read_request(&s);
                s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nStrict-Transport-Security: max-age=999\r\n\r\nOK").unwrap();req
            });
            let mut s = TcpStream::connect(address).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let conn =
                ClientConnection::new(client.clone(), ServerName::try_from("app.example").unwrap())
                    .unwrap();
            let mut tls_client = StreamOwned::new(conn, &mut s);
            tls_client.write_all(b"POST /api/ HTTP/1.1\r\nHost: app.example:443\r\nContent-Length: 2\r\nX-Forwarded-Proto: http\r\n\r\nok").unwrap();
            let mut response = Vec::new();
            tls_client.read_to_end(&mut response).unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200 ") && response.ends_with(b"OK"));
            let text = String::from_utf8(response).unwrap();
            assert!(text.contains("strict-transport-security: max-age=60\r\n"));
            assert!(!text.contains("max-age=999"));
            let req = String::from_utf8(upstream.join().unwrap()).unwrap();
            assert!(
                req.contains("X-Forwarded-Proto: https\r\n")
                    && req.contains("X-Forwarded-Port: 443\r\n")
                    && req.contains("X-Forwarded-For: 127.0.0.1\r\n")
            );
            for (host, status) in [
                ("unknown.example".to_owned(), 421),
                (format!("app.example:{}", address.port()), 400),
            ] {
                let socket = TcpStream::connect(address).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let conn = ClientConnection::new(
                    client.clone(),
                    ServerName::try_from("app.example").unwrap(),
                )
                .unwrap();
                let mut tls_client = StreamOwned::new(conn, socket);
                tls_client
                    .write_all(format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
                    .unwrap();
                let mut out = Vec::new();
                tls_client.read_to_end(&mut out).unwrap();
                assert!(out.starts_with(format!("HTTP/1.1 {status} ").as_bytes()));
            }
            let out=exchange(plain,b"POST /api/%2f/?q=a%20b HTTP/1.1\r\nHost: app.example:80\r\nContent-Length: 0\r\n\r\n");
            let out = String::from_utf8(out).unwrap();
            assert!(out.starts_with("HTTP/1.1 308 "));
            assert!(out.contains("Location: https://app.example/api/%2f/?q=a%20b\r\n"));
            assert!(!out.contains("strict-transport-security:"));
            backend.set_nonblocking(true).unwrap();
            assert!(backend.accept().is_err());
        }));
        stop.store(true, Ordering::Release);
        worker.join().unwrap().unwrap();
        if let Err(error) = result {
            std::panic::resume_unwind(error)
        }
    });
}

use super::{failure, receive};
use crate::http::Rejection;
use std::time::Instant;
#[test]
fn a_slow_upstream_body_cannot_reset_the_total_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    std::thread::scope(|scope| {
        let peer = scope.spawn(|| {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n")
                .unwrap();
            for _ in 0..20 {
                if socket.write_all(b"x").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(40));
            }
        });
        let start = Instant::now();
        let error = receive(client, false, start + Duration::from_millis(150))
            .err()
            .unwrap();
        assert_eq!(failure(error), Rejection(504));
        assert!(start.elapsed() < Duration::from_millis(600));
        peer.join().unwrap();
    });
}
